#!/usr/bin/env python3
"""Continuous WAL-archive PITR drill (real archive_mode, real recovery).

WHY THIS EXISTS SEPARATELY FROM `run_dr_postgres_pitr_drill.py`
---------------------------------------------------------------
That script measures a `pg_dump`-style round-trip: read the rows out, delete
them, write them back. It is a real measurement, but of a different thing. A
dump is a point-in-time snapshot taken while you are watching; its RPO is 0
because the "failure" happens after the backup, by construction.

The stated target -- RPO <= 5 minutes for a continuously running system -- is a
claim about *continuous archiving*: how much committed data is lost when the
server dies without warning and the only recovery material is a base backup plus
whatever WAL segments reached the archive. That number is not 0 and cannot be,
because the segment currently being written has not been archived yet. Measuring
it requires actually killing a server and actually replaying WAL.

So this drill:

  1. initdb, then turn on `wal_level=replica` + `archive_mode=on` with a real
     `archive_command` that copies completed segments to an archive directory.
  2. `pg_basebackup` -- the restore baseline.
  3. Write batches, forcing segment switches between them so some batches are
     archived and the last one is not.
  4. Kill the server with `pg_ctl stop -m immediate` (SIGQUIT equivalent: no
     checkpoint, no clean shutdown, no final archive). This is the failure.
  5. Recover TWICE from base backup + archive alone, with the crashed data
     directory left untouched:
       (A) to a `recovery_target_time` between two archived batches, to prove
           point-in-time selection actually works -- rows after the target must
           be ABSENT. A restore that simply replays everything is not PITR.
       (B) to the latest point the archive can reach, to measure the true
           data-loss window: last commit before the crash minus last commit
           recoverable. That difference is the RPO.

Exits 2 and records status=UNVERIFIED rather than inventing numbers if the
embedded server cannot be started.

Usage:
  PYTHONPATH=. python scripts/run_dr_postgres_wal_pitr_drill.py
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
OUT = ROOT / "reports" / "dr_postgres_wal_pitr_drill.json"
#: `--archive-to s3` writes here. A third record, because it answers a third
#: question: not "how much is lost in a crash" but "is any of it still reachable
#: once the database's own disk is gone".
S3_OUT = ROOT / "reports" / "dr_postgres_wal_pitr_s3_drill.json"
#: `--quiet` writes here instead, so the two measurements cannot overwrite each
#: other. They answer different questions: the default run measures RPO when
#: write volume is what rotates segments, the quiet run measures it when
#: `archive_timeout` is the only thing that does.
QUIET_OUT = ROOT / "reports" / "dr_postgres_wal_pitr_quiet_drill.json"

#: Matches `archive_timeout` in docker-compose.yml. The drill is only evidence
#: for the deployment if it exercises the value the deployment actually sets.
DEFAULT_ARCHIVE_TIMEOUT_SECONDS = 60
#: Rows per batch in quiet mode: small enough that a 16 MB segment never fills,
#: so the timeout is provably the only thing causing a switch.
QUIET_ROWS_PER_BATCH = 20

#: Batches written after the base backup. Each is followed by a forced segment
#: switch except the last, which is deliberately left in an unarchived segment
#: so the measured RPO reflects a real crash rather than a clean shutdown.
BATCHES = 4
ROWS_PER_BATCH = 200
TARGET_BATCH = 2  # recover to just after this batch in run (A)

RPO_TARGET_SECONDS = 300
RTO_TARGET_SECONDS = 1800


def _step(msg: str) -> None:
    """Progress to stderr. A drill that hangs must say where."""
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


def _bin(name: str) -> str:
    configured = os.environ.get("SENTINEL_TEST_PG_BIN", "").strip()
    if configured:
        root = Path(configured).resolve()
    else:
        import pgserver
        root = Path(pgserver.__file__).parent / "pginstall" / "bin"
    exe = root / name
    if os.name == "nt":
        exe = exe.with_suffix(".exe")
    if not exe.exists():
        raise FileNotFoundError(f"PostgreSQL tool unavailable: {name}: {exe}")
    return str(exe)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _run(args: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        args, capture_output=True, text=True, check=False, **kw
    )


def _must(args: list[str], what: str, **kw) -> subprocess.CompletedProcess:
    proc = _run(args, **kw)
    if proc.returncode != 0:
        raise RuntimeError(f"{what} failed ({proc.returncode}):\n{proc.stdout}\n{proc.stderr}")
    return proc


def _write_archiver(scripts_dir: Path) -> tuple[Path, Path]:
    """A Python archive/restore pair.

    Shelling out to `copy` on Windows and `cp` elsewhere would need two different
    conf strings and careful quoting; one script that both ends call is easier to
    read and behaves identically on either platform. The archiver refuses to
    overwrite an existing segment, which is what the PostgreSQL manual requires
    of an `archive_command` -- silently clobbering an archived segment is how an
    archive stops being a recovery source.
    """
    scripts_dir.mkdir(parents=True, exist_ok=True)
    archiver = scripts_dir / "wal_archive.py"
    archiver.write_text(
        "import os, shutil, sys\n"
        "src, dest = sys.argv[1], sys.argv[2]\n"
        "if os.path.exists(dest):\n"
        "    sys.exit(1)\n"
        "tmp = dest + '.part'\n"
        "shutil.copyfile(src, tmp)\n"
        "os.replace(tmp, dest)\n",
        encoding="utf-8",
    )
    restorer = scripts_dir / "wal_restore.py"
    restorer.write_text(
        "import os, shutil, sys\n"
        "src, dest = sys.argv[1], sys.argv[2]\n"
        "if not os.path.exists(src):\n"
        "    sys.exit(1)\n"
        "shutil.copyfile(src, dest)\n",
        encoding="utf-8",
    )
    return archiver, restorer


def _q(path: Path | str) -> str:
    """Quote a path for postgresql.conf. Forward slashes work on both platforms."""
    return '"' + str(path).replace("\\", "/") + '"'


def _start(pgdata: Path, port: int, logfile: Path, timeout: int = 120) -> None:
    """Start a cluster and wait for it to accept connections.

    Deliberately NOT `capture_output=True`: `pg_ctl start` leaves a detached
    postgres holding whatever handles it inherited, so a captured pipe never
    reaches EOF and the wait never returns. The server's own `-l` logfile is the
    diagnostic channel, and it is read back on failure.
    """
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [
            _bin("pg_ctl"), "-D", str(pgdata), "-l", str(logfile), "-w",
            "-t", str(timeout), "-o", f"-p {port}", "start",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    if proc.returncode != 0:
        log = logfile.read_text(encoding="utf-8", errors="replace") if logfile.exists() else "<no log>"
        raise RuntimeError(
            f"pg_ctl start ({pgdata.name}) failed ({proc.returncode}); server log:\n{log}"
        )


def _psql_value(port: int, sql: str, dbname: str = "postgres") -> str:
    proc = _must(
        [
            _bin("psql"), "-h", "127.0.0.1", "-p", str(port), "-U", "postgres",
            "-d", dbname, "-tAc", sql,
        ],
        f"psql: {sql[:60]}",
    )
    return proc.stdout.strip()


def _recover(
    *,
    base: Path,
    workdir: Path,
    label: str,
    archive: Path,
    restorer: Path,
    target_time: str | None,
    restore_command: str | None = None,
) -> tuple[Path, int, float]:
    """Copy the base backup, point it at the archive, recover, return (dir, port, seconds).

    The crashed cluster is never touched: recovery starts from the base backup
    and the archive only, which is the situation a real region loss leaves you in.
    """
    started = time.perf_counter()
    restored = workdir / f"restored_{label}"
    if restored.exists():
        shutil.rmtree(restored)
    shutil.copytree(base, restored)
    port = _free_port()

    conf = [
        "restore_command = '"
        + (
            restore_command
            or f"{_q(sys.executable)} {_q(restorer)} {_q(archive)}/%f %p"
        )
        + "'",
        "recovery_target_action = 'promote'",
        "hot_standby = on",
        "archive_mode = off",
    ]
    if target_time is not None:
        conf.append(f"recovery_target_time = '{target_time}'")
        conf.append("recovery_target_inclusive = on")
    with (restored / "postgresql.auto.conf").open("a", encoding="utf-8") as fh:
        fh.write("\n# --- PITR drill ---\n" + "\n".join(conf) + "\n")
    # The signal file is what makes this archive recovery rather than a plain start.
    (restored / "recovery.signal").write_text("", encoding="utf-8")

    _step(f"  {label}: starting restored cluster")
    _start(restored, port, workdir / f"{label}.log")
    # Wait for promotion: while in recovery the cluster answers, but has not yet
    # finished applying the archive, so reading the table too early under-reports.
    # A refused connection here is not a failure to recover. While the cluster
    # applies archived WAL and then promotes, it can decline connections for a
    # moment, and treating the first refusal as fatal aborted a drill that was
    # in fact recovering correctly. The loop still has a deadline, so a cluster
    # that genuinely never promotes is still reported rather than waited on
    # forever -- and the server's own log is attached when that happens.
    deadline = time.time() + 180
    while time.time() < deadline:
        try:
            if _psql_value(port, "SELECT pg_is_in_recovery()") == "f":
                break
        except RuntimeError:
            pass
        time.sleep(0.5)
    else:
        log_path = workdir / f"{label}.log"
        log = (
            log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
            if log_path.exists()
            else "<no log>"
        )
        raise RuntimeError(f"{label}: never left recovery; server log tail:\n{log}")
    return restored, port, time.perf_counter() - started


def _stop(pgdata: Path, mode: str = "fast") -> None:
    _run([_bin("pg_ctl"), "-D", str(pgdata), "-m", mode, "-w", "-t", "60", "stop"])


def _busy_write_phase(conn) -> list[dict]:
    """The original workload: enough writes that forced switches rotate segments.

    Every batch but the last is pushed into the archive by an explicit
    `pg_switch_wal()`. The last one is deliberately left in the open segment --
    that is the data the crash is meant to cost.
    """
    marks: list[dict] = []
    for batch in range(1, BATCHES + 1):
        _step(f"batch {batch}")
        for row in range(ROWS_PER_BATCH):
            conn.execute(
                "INSERT INTO sentinel_pitr_probe (batch, payload) VALUES (%s, %s)",
                (batch, f"batch-{batch}-row-{row}"),
            )
        last_at = conn.execute(
            "SELECT max(written_at)::text FROM sentinel_pitr_probe WHERE batch=%s",
            (batch,),
        ).fetchone()[0]
        marks.append({"batch": batch, "last_commit_at": last_at})
        if batch < BATCHES:
            conn.execute("SELECT pg_switch_wal()")
            time.sleep(1.0)  # let the archiver drain
    return marks


def _quiet_write_phase(conn, archive: Path, archive_timeout: int) -> dict:
    """Low-traffic workload where `archive_timeout` is the only segment rotator.

    The default drill calls `pg_switch_wal()` between batches, so it measures how
    much data a crash costs a system busy enough to rotate segments by itself.
    That is the flattering case. A quiet system fills a 16 MB segment slowly --
    an idle Sentinel might take hours -- and everything committed into that open
    segment is lost on a crash, however long ago it was written.

    `archive_timeout` is the setting that bounds this, and the sequence below is
    built to prove it does rather than assume it:

      1. Write batch 1, then wait past the timeout **issuing no writes at all**.
         The archive gaining a segment during that silence is the evidence: only
         the timeout could have caused it.
      2. Write batch 2 into the now-open segment, then wait until just before
         the next timeout would fire, and crash there. That is the worst moment
         to lose a node, so the RPO it yields is the worst case rather than a
         lucky one.
    """
    marks: list[dict] = []
    for row in range(QUIET_ROWS_PER_BATCH):
        conn.execute(
            "INSERT INTO sentinel_pitr_probe (batch, payload) VALUES (%s, %s)",
            (1, f"quiet-batch-1-row-{row}"),
        )
    marks.append(
        {
            "batch": 1,
            "last_commit_at": conn.execute(
                "SELECT max(written_at)::text FROM sentinel_pitr_probe WHERE batch=1"
            ).fetchone()[0],
        }
    )

    segments_before = len(list(archive.glob("0*")))
    deadline = time.perf_counter() + archive_timeout + 30
    _step("quiet: idling with NO writes, waiting for archive_timeout to force a switch")
    switch_at: float | None = None
    while time.perf_counter() < deadline:
        if len(list(archive.glob("0*"))) > segments_before:
            switch_at = time.perf_counter()
            break
        time.sleep(0.5)
    segments_after = len(list(archive.glob("0*")))
    if switch_at is None:
        # Do not fabricate a worst case from a cycle that never happened.
        _step("quiet: archive_timeout did NOT force a switch; reporting that")
        switch_at = time.perf_counter()
    else:
        _step(f"quiet: timeout forced a switch after {archive_timeout}s of silence")

    for row in range(QUIET_ROWS_PER_BATCH):
        conn.execute(
            "INSERT INTO sentinel_pitr_probe (batch, payload) VALUES (%s, %s)",
            (2, f"quiet-batch-2-row-{row}"),
        )
    marks.append(
        {
            "batch": 2,
            "last_commit_at": conn.execute(
                "SELECT max(written_at)::text FROM sentinel_pitr_probe WHERE batch=2"
            ).fetchone()[0],
        }
    )

    # Crash just BEFORE the next timeout fires: the worst case, not the average.
    #
    # The margin is measured from the OBSERVED switch above, not from when the
    # idle loop happened to finish. A first attempt at this timed the wait from
    # the end of the sleep, landed two seconds the wrong side of the next
    # timeout, and reported an RPO of 0 -- the favourable half of the cycle
    # dressed up as the general case.
    elapsed_since_switch = time.perf_counter() - switch_at
    remaining = max(1.0, archive_timeout - elapsed_since_switch - 15)
    _step(f"quiet: holding {remaining:.0f}s so the crash lands just BEFORE the next switch")
    time.sleep(remaining)

    return {
        "rows_per_batch": QUIET_ROWS_PER_BATCH,
        "archive_timeout_seconds": archive_timeout,
        "segments_archived_before_idle": segments_before,
        "segments_archived_after_idle": segments_after,
        # The whole point. False means archive_timeout did nothing and the RPO
        # below is not attributable to it.
        "timeout_forced_switch_with_no_writes": segments_after > segments_before,
        "marks": marks,
    }


def _unverified(reason: str, out: Path = OUT) -> int:
    payload = {
        "ok": False,
        "status": "UNVERIFIED",
        "precondition": reason,
        "targets": {"rpo_seconds": RPO_TARGET_SECONDS, "rto_seconds": RTO_TARGET_SECONDS},
        "measured": None,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 2


def main() -> int:  # noqa: PLR0915 - a drill is a linear script; splitting it hides the sequence
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--quiet",
        action="store_true",
        help=(
            "low-traffic run: no forced pg_switch_wal(), so archive_timeout is "
            "the only thing rotating segments. Writes to a separate record."
        ),
    )
    parser.add_argument(
        "--out",
        default="",
        help=(
            "where to write the evidence JSON. Defaults to the committed file "
            "for this mode; pass a temporary path from automated runs so the "
            "recorded baseline is not rewritten."
        ),
    )
    parser.add_argument(
        "--archive-timeout",
        type=int,
        default=DEFAULT_ARCHIVE_TIMEOUT_SECONDS,
        help="archive_timeout in seconds; 0 leaves it unset (default 60, matching compose)",
    )
    parser.add_argument(
        "--object-store-bind",
        default="127.0.0.1",
        help=(
            "interface the local MinIO binds to. Default 127.0.0.1 (loopback). "
            "Give a real interface address to take the archive path off "
            "loopback -- still ONE HOST, but through the NIC and routing table "
            "rather than a kernel shortcut."
        ),
    )
    parser.add_argument(
        "--object-store-url",
        default=None,
        help=(
            "use an EXISTING S3 endpoint instead of starting MinIO here. This "
            "is how a genuine site-loss drill is run: point it at a bucket in a "
            "different datacentre/region and the archive is no longer sharing a "
            "failure domain with the database. Credentials come from "
            "SENTINEL_WAL_S3_ACCESS_KEY / _SECRET_KEY / _BUCKET."
        ),
    )
    parser.add_argument(
        "--archive-to",
        choices=("local", "s3"),
        default="local",
        help=(
            "where completed segments go. `local` is docker-compose.yml's current "
            "behaviour: a directory beside pgdata, which does not survive loss of "
            "the node. `s3` archives to an S3-compatible object store over the "
            "network via deploy/wal-archive/wal_s3.py, and DESTROYS the data "
            "directory before recovering, so nothing can silently be read from it."
        ),
    )
    args = parser.parse_args()
    # `--out` overrides the mode-derived default.
    #
    # WHY THIS EXISTS: the default paths are COMMITTED evidence files, and the
    # test that exercises this drill used to invoke it with no override -- so
    # every test run rewrote the recorded baseline and produced a spurious git
    # diff. An artifact that changes on every run cannot serve as a baseline,
    # which is the whole point of committing it.
    #
    # The drill now writes wherever it is told; the committed file is what a
    # deliberate operator run produced, and a test run goes to a temporary path.
    out = (
        Path(args.out).resolve()
        if args.out
        else (
            S3_OUT
            if args.archive_to == "s3"
            else (QUIET_OUT if args.quiet else OUT)
        )
    )
    target_batch = 1 if args.quiet else TARGET_BATCH

    try:
        import psycopg  # noqa: F401
    except ImportError:
        return _unverified("psycopg not installed", out)
    try:
        _bin("initdb")
    except Exception as exc:  # noqa: BLE001 - reported, not raised
        return _unverified(f"embedded postgres binaries unavailable: {exc}", out)

    work = Path(tempfile.mkdtemp(prefix="sentinel_wal_pitr_"))
    pgdata = work / "pgdata"
    archive = work / "wal_archive"
    base = work / "basebackup"
    archive.mkdir()
    archiver, restorer = _write_archiver(work / "bin")
    primary_port = _free_port()
    started_all = time.perf_counter()

    # ── object-storage archiving ─────────────────────────────────────────────
    minio = None
    archive_target: dict = {
        "kind": "local_directory",
        "path": str(archive),
        "failure_domain": (
            "SAME HOST AND SAME DISK as pgdata. This is docker-compose.yml's "
            "current shape and is why the gate row reads fail."
        ),
    }
    wal_s3 = ROOT / "deploy" / "wal-archive" / "wal_s3.py"
    if args.archive_to == "s3":
        from _minio_harness import MinioUnavailableHere, start_minio

        if args.object_store_url:
            # An externally-provided endpoint. Nothing is started or stopped
            # here, and the drill makes no claim about where it lives -- the
            # operator running it knows, and records it in the report.
            import os as _os

            missing = [
                name
                for name in (
                    "SENTINEL_WAL_S3_ACCESS_KEY",
                    "SENTINEL_WAL_S3_SECRET_KEY",
                    "SENTINEL_WAL_S3_BUCKET",
                )
                if not _os.environ.get(name)
            ]
            if missing:
                return _unverified(
                    f"--object-store-url given but {', '.join(missing)} unset", out
                )
            external_endpoint = args.object_store_url
        else:
            try:
                minio = start_minio(work / "minio", bind=args.object_store_bind)
            except MinioUnavailableHere as exc:
                return _unverified(f"no S3-compatible object store: {exc}", out)
            external_endpoint = None
        # `archive_command` and `restore_command` are run by the postgres backend,
        # which inherits the environment `pg_ctl` was started with -- which is
        # this process's. Configuration therefore goes in os.environ and never on
        # the command line, where it would be visible in `SHOW archive_command`
        # and in pg_settings to anyone who can connect.
        if external_endpoint is not None:
            os.environ["SENTINEL_WAL_S3_ENDPOINT"] = external_endpoint
            os.environ.setdefault("SENTINEL_WAL_S3_CLUSTER", "drill")
            os.environ.setdefault("SENTINEL_WAL_S3_REGION", "us-east-1")
        else:
            os.environ.update(minio.env(cluster="drill"))
        os.environ["PYTHONPATH"] = str(ROOT)

        # HOW FAR OFF THE DATABASE'S FAILURE DOMAIN THE ARCHIVE ACTUALLY IS.
        # Three distinguishable topologies, and the report must not blur them:
        #
        #   loopback   MinIO on 127.0.0.1. Same host, same kernel, and the TCP
        #              never reaches a NIC. Proves the S3 protocol path works.
        #   interface  MinIO bound to a real interface address. Same host still,
        #              but through the NIC and the routing table. Strictly more
        #              than loopback, strictly less than a separate host.
        #   external   An endpoint this drill did not start. Whether that is a
        #              separate host, region or planet is the operator's
        #              knowledge, not the drill's, so it is recorded as
        #              "operator-supplied" and claims nothing further.
        if external_endpoint is not None:
            endpoint, topology = external_endpoint, "external"
            failure_domain = (
                "An OPERATOR-SUPPLIED endpoint that this drill did not start. "
                "The drill cannot tell whether it is a separate host, rack, "
                "availability zone or region, so it claims nothing about that -- "
                "record the topology alongside this result."
            )
        elif args.object_store_bind != "127.0.0.1":
            endpoint, topology = minio.endpoint, "same_host_real_interface"
            failure_domain = (
                f"MinIO bound to {args.object_store_bind}, a real interface, so "
                "the archive path goes through the NIC and the routing table "
                "rather than the loopback shortcut. STILL ONE HOST: this does "
                "NOT demonstrate site loss. It removes one shortcut, nothing more."
            )
        else:
            endpoint, topology = minio.endpoint, "same_host_loopback"
            failure_domain = (
                "A separate storage SERVICE reached over TCP with S3 semantics, "
                "and recovery here is performed after the data directory has been "
                "deleted -- so nothing in this run comes from the database's own "
                "disk. It is NOT a separate physical failure domain: MinIO runs "
                "on this same host, over loopback. See the `unverified` field."
            )

        archive_target = {
            "kind": "s3_object_store",
            "endpoint": endpoint,
            "topology": topology,
            "bucket": (
                os.environ.get("SENTINEL_WAL_S3_BUCKET")
                if external_endpoint is not None
                else minio.bucket
            ),
            "server": "operator-supplied" if external_endpoint is not None else minio.version,
            "adapter": "sentinel.infrastructure.persistence.objectstore.S3ObjectStore",
            "command": "deploy/wal-archive/wal_s3.py",
            "proves_node_loss": True,
            "proves_site_loss": topology == "external",
            "failure_domain": failure_domain,
        }

    try:
        _step("initdb")
        _must(
            [
                _bin("initdb"), "-D", str(pgdata), "-U", "postgres",
                "--auth=trust", "--encoding=UTF8", "--no-sync",
            ],
            "initdb",
        )
        # Continuous archiving, switched on before the base backup so that every
        # segment the backup does not contain is recoverable from the archive.
        archive_command = (
            f"{_q(sys.executable)} {_q(wal_s3)} archive %p %f"
            if args.archive_to == "s3"
            else f"{_q(sys.executable)} {_q(archiver)} %p {_q(archive)}/%f"
        )
        with (pgdata / "postgresql.conf").open("a", encoding="utf-8") as fh:
            fh.write(
                "\n# --- continuous WAL archiving (DR drill) ---\n"
                "listen_addresses = '127.0.0.1'\n"
                "wal_level = replica\n"
                "archive_mode = on\n"
                f"archive_command = '{archive_command}'\n"
                "max_wal_senders = 4\n"
                "wal_keep_size = 64MB\n"
                + (
                    f"archive_timeout = {args.archive_timeout}s\n"
                    if args.archive_timeout > 0
                    else "# archive_timeout deliberately unset for this run\n"
                )
            )
        _step("start primary")
        _start(pgdata, primary_port, work / "primary.log")

        dsn = f"postgresql://postgres@127.0.0.1:{primary_port}/postgres"
        import psycopg

        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute(
                "CREATE TABLE sentinel_pitr_probe ("
                "id serial PRIMARY KEY, batch int NOT NULL, payload text NOT NULL, "
                "written_at timestamptz NOT NULL DEFAULT now())"
            )

        _step("pg_basebackup")
        _must(
            [
                _bin("pg_basebackup"), "-D", str(base), "-h", "127.0.0.1",
                "-p", str(primary_port), "-U", "postgres", "-X", "stream", "-c", "fast",
            ],
            "pg_basebackup",
        )

        # ── the running system ───────────────────────────────────────────────
        quiet_detail: dict | None = None
        with psycopg.connect(dsn, autocommit=True) as conn:
            if args.quiet:
                quiet_detail = _quiet_write_phase(conn, archive, args.archive_timeout)
                batch_marks = quiet_detail.pop("marks")
            else:
                batch_marks = _busy_write_phase(conn)
            total_rows = conn.execute(
                "SELECT count(*) FROM sentinel_pitr_probe"
            ).fetchone()[0]
            last_commit_before_crash = conn.execute(
                "SELECT max(written_at)::text FROM sentinel_pitr_probe"
            ).fetchone()[0]

        _step("writes done")
        if args.archive_to == "s3":
            assert minio is not None
            archived_before_crash = sorted(
                p.name
                for p in (Path(minio.data_dir) / minio.bucket / "drill" / "wal").glob("0*")
            )
        else:
            archived_before_crash = sorted(p.name for p in archive.glob("0*"))

        # ── the failure ──────────────────────────────────────────────────────
        # -m immediate: no checkpoint, no clean shutdown, no final archive push.
        _step("crash")
        crash_started = time.perf_counter()
        _must([_bin("pg_ctl"), "-D", str(pgdata), "-m", "immediate", "-w", "-t", "60", "stop"],
              "pg_ctl stop -m immediate")
        crash_seconds = time.perf_counter() - crash_started

        # ── loss of the database node ────────────────────────────────────────
        # In the local run the crashed directory is merely left untouched. That
        # is enough to show recovery does not *use* it, but not that it could not.
        # In the S3 run the data directory AND the local archive directory are
        # DELETED, so any dependency on either is a hard failure rather than a
        # subtle one. This is the specific thing the failing gate row asks about:
        # the node is gone, is the archive still a recovery source?
        node_loss: dict | None = None
        restore_command = None
        if args.archive_to == "s3":
            pgdata_bytes = sum(
                f.stat().st_size for f in pgdata.rglob("*") if f.is_file()
            )
            shutil.rmtree(pgdata, ignore_errors=True)
            shutil.rmtree(archive, ignore_errors=True)
            node_loss = {
                "data_directory_deleted": not pgdata.exists(),
                "data_directory_bytes_destroyed": pgdata_bytes,
                "local_archive_directory_deleted": not archive.exists(),
                "note": (
                    "Recovery below reads the base backup and the OBJECT STORE "
                    "only. Neither the crashed data directory nor any local "
                    "archive directory exists at this point."
                ),
            }
            restore_command = f"{_q(sys.executable)} {_q(wal_s3)} restore %f %p"
            _step(f"destroyed pgdata ({pgdata_bytes} bytes) and local archive dir")

        # ── (A) point-in-time selection ──────────────────────────────────────
        # Target just after batch `target_batch`. Batches above it must NOT appear.
        #
        # The nudge past the commit is only safe when later WAL exists in the
        # archive to replay through. In a quiet run the crash deliberately leaves
        # the following batch unarchived, so the archive ENDS at this commit, and
        # asking for a target 250 ms later makes recovery fail outright:
        #
        #   FATAL: recovery ended before configured recovery target was reached
        #
        # That is a real property of PITR worth knowing -- you cannot recover to
        # a point past your last archived segment -- but here it would just be a
        # broken drill, so the quiet run targets the commit itself and relies on
        # `recovery_target_inclusive` to include it.
        target_dt = datetime.fromisoformat(batch_marks[target_batch - 1]["last_commit_at"])
        nudge = timedelta(0) if args.quiet else timedelta(milliseconds=250)
        target_time = (target_dt + nudge).isoformat()
        _step("recover A (pitr)")
        pitr_dir, pitr_port, pitr_seconds = _recover(
            base=base, workdir=work, label="pitr", archive=archive,
            restorer=restorer, target_time=target_time,
            restore_command=restore_command,
        )
        pitr_max_batch = int(_psql_value(pitr_port, "SELECT coalesce(max(batch),0) FROM sentinel_pitr_probe"))
        pitr_rows = int(_psql_value(pitr_port, "SELECT count(*) FROM sentinel_pitr_probe"))
        _stop(pitr_dir)

        # ── (B) latest recoverable → the real RPO ────────────────────────────
        _step("recover B (latest)")
        latest_dir, latest_port, latest_seconds = _recover(
            base=base, workdir=work, label="latest", archive=archive,
            restorer=restorer, target_time=None,
            restore_command=restore_command,
        )
        latest_rows = int(_psql_value(latest_port, "SELECT count(*) FROM sentinel_pitr_probe"))
        latest_commit = _psql_value(
            latest_port, "SELECT coalesce(max(written_at)::text,'') FROM sentinel_pitr_probe"
        )
        latest_max_batch = int(
            _psql_value(latest_port, "SELECT coalesce(max(batch),0) FROM sentinel_pitr_probe")
        )
        _stop(latest_dir)

        rpo_seconds = (
            datetime.fromisoformat(last_commit_before_crash)
            - datetime.fromisoformat(latest_commit)
        ).total_seconds() if latest_commit else None
        rows_lost = total_rows - latest_rows

        pitr_selective = pitr_max_batch == target_batch
        ok = (
            pitr_selective
            and rpo_seconds is not None
            and rpo_seconds <= RPO_TARGET_SECONDS
            and latest_seconds <= RTO_TARGET_SECONDS
        )

        payload = {
            "ok": bool(ok),
            "status": (
                "measured_continuous_wal_archive_to_object_storage"
                if args.archive_to == "s3"
                else (
                    "measured_continuous_wal_archive_quiet"
                    if args.quiet
                    else "measured_continuous_wal_archive"
                )
            ),
            "precondition": None,
            "archive_target": archive_target,
            "node_loss": node_loss,
            "unverified": (
                [
                    "The object store runs on the SAME HOST as the database. This "
                    "run proves the archive path works over the S3 protocol and "
                    "that recovery needs nothing from the database's data "
                    "directory -- the directory was deleted before recovery -- but "
                    "it does NOT prove survival of a datacentre, region or "
                    "availability zone. That needs a remote bucket and is stated "
                    "as unverified for the same reason the kind/Helm row is.",
                    "No cross-region replication, object-lock or lifecycle policy "
                    "is exercised. Those are bucket-side configuration and are "
                    "documented in docs/OPERATIONS.md, not measured here.",
                ]
                if args.archive_to == "s3"
                else None
            ),
            "targets": {"rpo_seconds": RPO_TARGET_SECONDS, "rto_seconds": RTO_TARGET_SECONDS},
            "workload": {
                "mode": "quiet" if args.quiet else "busy",
                "quiet_detail": quiet_detail,
                "batches": len(batch_marks),
                "rows_per_batch": QUIET_ROWS_PER_BATCH if args.quiet else ROWS_PER_BATCH,
                "total_rows_committed": total_rows,
                "wal_segments_archived_before_crash": len(archived_before_crash),
                "batch_marks": batch_marks,
                "last_commit_before_crash": last_commit_before_crash,
                "crash_mode": "pg_ctl stop -m immediate (no checkpoint, no final archive)",
                "crash_seconds": round(crash_seconds, 4),
            },
            "measured": {
                # (B): what a crash actually costs with archive-only recovery.
                "experimental_rpo_seconds": (
                    round(rpo_seconds, 4) if rpo_seconds is not None else None
                ),
                "rows_lost_to_unarchived_segment": rows_lost,
                "last_recoverable_commit": latest_commit,
                "latest_recovery_max_batch": latest_max_batch,
                # RTO here is restore + replay + promote, measured, for this size.
                "experimental_rto_seconds": round(latest_seconds, 4),
                "pitr_recovery_seconds": round(pitr_seconds, 4),
                # (A): PITR really selected a point, rather than replaying all.
                "pitr_target_time": target_time,
                "pitr_target_batch": target_batch,
                "pitr_observed_max_batch": pitr_max_batch,
                "pitr_rows_at_target": pitr_rows,
                "pitr_selected_point_in_time": pitr_selective,
                "notes": (
                    "Continuous archive_mode=on with a real archive_command; "
                    "recovery from base backup + archived WAL only. "
                    + (
                        "Segments were pushed to an S3-compatible object store over "
                        "TCP, and the data directory was DELETED before recovery, so "
                        "nothing here came from the database's own disk."
                        if args.archive_to == "s3"
                        else "Crashed data directory untouched. Single node, local "
                        "disk: NOT a cross-region failover measurement."
                    )
                ),
            },
            "meets_rpo_target": bool(rpo_seconds is not None and rpo_seconds <= RPO_TARGET_SECONDS),
            "meets_rto_target": bool(latest_seconds <= RTO_TARGET_SECONDS),
            "total_drill_seconds": round(time.perf_counter() - started_all, 4),
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(json.dumps(payload, indent=2))
        if not pitr_selective:
            print(
                f"VERIFY FAILED: PITR to {target_time} returned batches up to "
                f"{pitr_max_batch}, expected {target_batch}",
                file=sys.stderr,
            )
            return 1
        return 0
    except Exception as exc:  # noqa: BLE001 - a failed drill reports, never invents
        return _unverified(f"{type(exc).__name__}: {exc}", out)
    finally:
        for d in (pgdata, work / "restored_pitr", work / "restored_latest"):
            if d.exists():
                _stop(d, "immediate")
        if minio is not None:
            minio.stop()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
