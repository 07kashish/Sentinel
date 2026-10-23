"""Start a real MinIO server for the DR drill, or say precisely why it could not.

WHY A REAL OBJECT STORE AND NOT A STUB
---------------------------------------
The claim under test is "the WAL archive survives loss of the database node",
and the mechanism is an `archive_command` that pushes each completed segment to
object storage over the network. A stub that writes to a directory would exercise
none of the parts that can actually fail: SigV4 signing, HTTP status handling,
the read-back verification, and the fact that recovery can reach the archive when
the database's own disk is gone.

WHAT THIS IS HONEST ABOUT
-------------------------
MinIO started here runs on **the same host** as the PostgreSQL data directory.
That makes it a separate STORAGE SERVICE reached over TCP with S3 semantics --
which is what the archive path needs to be exercised against -- but it is NOT a
separate physical failure domain. A drill run through it proves the archive
mechanism works and that recovery needs nothing from the database's data
directory; it does not prove survival of a datacentre. Every report generated
through this harness says so in its own `unverified` field rather than leaving a
reader to infer it.
"""

from __future__ import annotations

import os
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from shutil import which

ACCESS_KEY = "sentineldrill"
SECRET_KEY = "sentineldrillsecret"

__all__ = ["MinioUnavailableHere", "RunningMinio", "start_minio"]


class MinioUnavailableHere(RuntimeError):
    """No object store could be started. Callers record UNVERIFIED, not a number."""


@dataclass
class RunningMinio:
    endpoint: str
    bucket: str
    access_key: str
    secret_key: str
    data_dir: str
    version: str
    _process: subprocess.Popen | None = None

    def env(self, cluster: str = "drill") -> dict[str, str]:
        """The environment `deploy/wal-archive/wal_s3.py` reads."""
        return {
            "SENTINEL_WAL_S3_ENDPOINT": self.endpoint,
            "SENTINEL_WAL_S3_BUCKET": self.bucket,
            "SENTINEL_WAL_S3_ACCESS_KEY": self.access_key,
            "SENTINEL_WAL_S3_SECRET_KEY": self.secret_key,
            "SENTINEL_WAL_S3_REGION": "us-east-1",
            "SENTINEL_WAL_S3_CLUSTER": cluster,
            # Localhost is a private destination and `HardenedHttpClient` refuses
            # those by default -- correctly, since the default posture must be
            # SSRF-safe. A local drill is the documented exception.
            "SENTINEL_WAL_S3_ALLOW_PRIVATE": "true",
        }

    def stop(self) -> None:
        if self._process is None:
            return
        self._process.terminate()
        try:
            self._process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self._process.kill()


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def start_minio(
    data_dir: Path, bucket: str = "sentinel-wal", bind: str = "127.0.0.1"
) -> RunningMinio:
    """Start `minio server` and create the bucket by making its directory.

    MinIO's filesystem backend maps a bucket to a top-level directory, so the
    bucket is created before the server starts rather than through a separate
    `mc mb` round-trip -- one fewer binary the drill depends on being installed.
    """
    binary = which("minio") or which("minio.exe")
    if binary is None:
        raise MinioUnavailableHere(
            "`minio` is not on PATH, so no S3-compatible endpoint can be started "
            "here. Install it (scoop install minio) or point the drill at a real "
            "object store."
        )

    data_dir = Path(data_dir)
    (data_dir / bucket).mkdir(parents=True, exist_ok=True)
    port = _free_port()
    console_port = _free_port()

    # `bind` exists so the drill can take the object store OFF loopback.
    # Binding to a real interface (e.g. 192.168.1.12) means PostgreSQL's
    # archive_command reaches the store through the NIC, the routing table and a
    # real TCP path rather than through the loopback shortcut. That is a
    # STRICTLY WEAKER claim than "separate failure domain" -- it is still one
    # host, and `docs/OPERATIONS.md` says so -- but it removes one
    # specific shortcut, and the difference is worth being able to measure.

    environment = {
        **os.environ,
        "MINIO_ROOT_USER": ACCESS_KEY,
        "MINIO_ROOT_PASSWORD": SECRET_KEY,
        # Off: the drill reads its own report, not a browser.
        "MINIO_BROWSER": "off",
    }
    process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
        [
            binary, "server", str(data_dir),
            "--address", f"{bind}:{port}",
            "--console-address", f"127.0.0.1:{console_port}",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        env=environment,
    )

    endpoint = f"http://{bind}:{port}"
    deadline = time.time() + 60
    while time.time() < deadline:
        if process.poll() is not None:
            raise MinioUnavailableHere(
                f"minio exited immediately with code {process.returncode}"
            )
        try:
            with socket.create_connection((bind, port), timeout=1):
                break
        except OSError:
            time.sleep(0.25)
    else:
        process.kill()
        raise MinioUnavailableHere(
            f"minio did not accept connections on {endpoint} within 60s"
        )

    version = subprocess.run(  # noqa: S603 - fixed argv
        [binary, "--version"], capture_output=True, text=True, check=False
    ).stdout.strip().splitlines()
    return RunningMinio(
        endpoint=endpoint,
        bucket=bucket,
        access_key=ACCESS_KEY,
        secret_key=SECRET_KEY,
        data_dir=str(data_dir),
        version=version[0] if version else "unknown",
        _process=process,
    )
