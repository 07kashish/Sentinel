"""Fuzz the running API from its own OpenAPI schema, and record what happened.

WHAT THIS IS
------------
Schema-driven DAST. It starts the real ASGI app, reads `/openapi.json` from the
running service, and generates requests from that schema -- including the
malformed, out-of-range and wrong-type inputs a hand-written test suite does
not think to write. The checks that matter here are:

  * `not_a_server_error` -- a 5xx means the input reached something that did not
    expect it. A 400 is the API working; a 500 is the API surprised.
  * `ignored_auth` -- schemathesis re-sends each request WITHOUT credentials and
    fails if the response is the same. That is the check that catches a route
    which declares a capability and does not enforce it, which no amount of
    reading the decorator can prove.

Mirrors the `dast` job in ci.yml rather than inventing a configuration.

WHY IT STARTS ITS OWN SERVER
-----------------------------
The gate is about the RUNNING service, not the app object. An in-process
TestClient skips the ASGI server, the HTTP parser and the middleware ordering
that a real request passes through, and those are where several of the
interesting failures live.

WHAT IT DOES NOT PROVE
----------------------
That the deployed system is safe. There is no ingress, no TLS termination, no
load balancer and no second replica here, and the fuzzer only reaches what the
schema describes -- an endpoint missing from the OpenAPI document is invisible
to it. A pass means "the documented surface did not 500 and did not serve
unauthenticated callers", which is worth having and is not a penetration test.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


OUT = ROOT / "release" / "gates" / "gate_dast.json"

#: A key with the shape production demands (>=32 chars), for a throwaway
#: database that is deleted afterwards. Not a secret: it authenticates nothing
#: outside this process and the DAST job in ci.yml uses the same pattern.
DAST_KEY = "dast-local-key-material-32characters"
DAST_METRICS_TOKEN = "dast-local-metrics-token-32-characters"


def _echo(message: str) -> None:
    """Write to stdout without dying on the console codepage.

    The scanner's summary contains emoji. On a cp1252 console `print`
    raises UnicodeEncodeError, which killed this script AFTER the artifact
    was written -- reporting a non-zero exit for a gate that had passed.
    """
    stream = sys.stdout
    encoding = getattr(stream, "encoding", None) or "utf-8"
    stream.write(
        message.encode(encoding, errors="replace").decode(encoding) + chr(10)
    )


def _find_cli() -> str | None:
    """The schemathesis CLI, on PATH or beside this interpreter.

    `pip install` puts console scripts in the Scripts/bin directory next to the
    interpreter that ran it, and that directory is frequently NOT on PATH --
    especially on Windows and inside a shell that did not activate the
    environment. Looking only at PATH reported "not installed" for a tool that
    was installed, which would have left the gate UNVERIFIED for the wrong
    reason: a missing scanner and a missing PATH entry are not the same fact.
    """
    found = shutil.which("schemathesis") or shutil.which("st")
    if found:
        return found
    beside = Path(sys.executable).parent
    for folder in (beside / "Scripts", beside / "bin", beside):
        for name in ("schemathesis.exe", "schemathesis", "st.exe", "st"):
            candidate = folder / name
            if candidate.is_file():
                return str(candidate)
    return None


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _wait_for(url: str, *, timeout: float = 60.0) -> bool:
    """Block until the server answers, or give up.

    A fuzzer pointed at a port nothing is listening on reports a connection
    error for every case and exits non-zero -- which would look exactly like a
    security finding.
    """
    import urllib.error
    import urllib.request

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2):  # noqa: S310 - localhost
                return True
        except (urllib.error.URLError, OSError):
            time.sleep(0.5)
    return False


def main() -> int:
    cli = _find_cli()
    if cli is None:
        raise SystemExit(
            "schemathesis is not installed, so NO artifact is written and the "
            "gate stays UNVERIFIED -- the accurate report for a scan nobody "
            "ran. `pip install schemathesis==4.23.0`."
        )

    port = _free_port()
    database = ROOT / f".dast-{port}.db"
    env = {
        **os.environ,
        "PYTHONPATH": str(ROOT),
        "SENTINEL_ENV": "development",
        "SENTINEL_API_KEYS": f"dast:{DAST_KEY}:admin",
        "SENTINEL_DB_PATH": str(database),
        "SENTINEL_METRICS_TOKEN": DAST_METRICS_TOKEN,
        # The docs route is what the fuzzer reads the schema from.
        "SENTINEL_EXPOSE_API_DOCS": "true",
        # schemathesis prints a Unicode banner and Windows pipes default to
        # cp1252, which raised UnicodeEncodeError before a single request was
        # generated. The scanner then exited non-zero and this script filed a
        # FAIL -- a console encoding bug recorded as a security finding.
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
    }

    # MIGRATE FIRST. `build_container` calls `verify(pool)` and refuses to
    # serve against a schema it did not expect -- deliberately, and that
    # refusal is itself tested. Without this the server exits before it
    # binds, and the fuzzer sees a dead port, which is indistinguishable
    # from a scan that ran and found nothing.
    setup = subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, "-m", "sentinel.interface.cli", "migrate"],
        cwd=str(ROOT), env=env, capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=False,
    )
    if setup.returncode != 0:
        database.unlink(missing_ok=True)
        detail = (setup.stdout + setup.stderr)[-1200:]
        raise SystemExit(
            "could not migrate the throwaway database, so nothing was "
            "fuzzed and no artifact is written:\n" + detail
        )

    server = subprocess.Popen(  # noqa: S603 - fixed argv
        [
            sys.executable, "-m", "uvicorn",
            "sentinel.interface.asgi:create_application",
            "--factory", "--host", "127.0.0.1", "--port", str(port),
            "--log-level", "warning",
        ],
        cwd=str(ROOT), env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        encoding="utf-8", errors="replace",
    )

    started = datetime.now(timezone.utc)
    try:
        schema = f"http://127.0.0.1:{port}/openapi.json"
        if not _wait_for(schema):
            server.kill()
            output = (server.stdout.read() if server.stdout else "")[-2000:]
            raise SystemExit(
                "the API never came up, so nothing was fuzzed and no artifact "
                f"is written. A scan that could not connect is UNVERIFIED, not "
                f"a pass:\n{output}"
            )

        result = subprocess.run(  # noqa: S603 - fixed argv
            [
                cli, "run", schema,
                "--wait-for-schema", "30",
                "--header", f"Authorization: Bearer {DAST_KEY}",
                "--checks", "not_a_server_error,ignored_auth",
                "--phases", "examples,coverage,fuzzing",
                "--mode", "all",
                "--max-examples", "5",
                "--rate-limit", "5/s",
                "--generation-database", ":memory:",
                "--max-response-time", "3",
            ],
            cwd=str(ROOT), env=env, capture_output=True, text=True,
        # DECODED AS UTF-8 EXPLICITLY. `text=True` uses the locale codec,
        # which is cp1252 here, and the scanner emits UTF-8 -- so the reader
        # thread raised UnicodeDecodeError and `output` came back empty.
        #
        # That is worse than cosmetic. The crash-detector below asks whether
        # the output contains "Failures:", and an empty string does not. A
        # real finding would have been misread as a scanner crash and
        # SUPPRESSED -- no artifact, gate UNVERIFIED, defect invisible.
        encoding="utf-8", errors="replace",
            timeout=2400, check=False,
        )
        exit_code = result.returncode
        output = (result.stdout or "") + (result.stderr or "")
    finally:
        server.terminate()
        try:
            server.wait(timeout=15)
        except subprocess.TimeoutExpired:
            server.kill()
        database.unlink(missing_ok=True)
        for suffix in ("-wal", "-shm"):
            Path(str(database) + suffix).unlink(missing_ok=True)

    # A SCANNER THAT CRASHED DID NOT FIND ANYTHING.
    #
    # schemathesis exits 1 for findings AND for its own errors, and the two
    # mean opposite things: one is the API failing a check, the other is the
    # tool never getting far enough to check. Filing the second as FAIL
    # invents a security finding; filing it as PASS hides that nothing ran.
    # Neither is right, so a crash writes NO artifact and the gate stays
    # UNVERIFIED -- the accurate word for a scan that did not happen.
    #
    # Recognised by the scanner reporting a Python traceback of its own
    # rather than a findings summary. This happened on the first real run:
    # a UnicodeEncodeError in the banner, before any request was generated.
    crashed = exit_code != 0 and (
        "Traceback (most recent call last)" in output
        and "schemathesis" in output
        and "Failures:" not in output
    )
    if crashed:
        OUT.unlink(missing_ok=True)
        Path(str(OUT) + ".provenance.json").unlink(missing_ok=True)
        _echo(chr(10).join(output.splitlines()[-20:]))
        raise SystemExit(
            "the scanner itself crashed, so nothing was fuzzed. No artifact "
            "was written and the gate stays UNVERIFIED: a tool that failed to "
            "run is not a security finding, and recording it as one would "
            "invent a defect that does not exist."
        )

    ok = exit_code == 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(
            {
                "gate": "dast",
                "ok": ok,
                "exit_code": exit_code,
                "summary": (
                    "dast: schemathesis found no server error and no ignored "
                    "authentication across the documented surface"
                    if ok
                    else f"dast: schemathesis exited {exit_code}"
                ),
                "command": [
                    cli, "run", "<schema>", "--checks",
                    "not_a_server_error,ignored_auth", "--phases",
                    "examples,coverage,fuzzing", "--mode", "all",
                ],
                "command_rationale": (
                    "mirrors the dast job in ci.yml. `ignored_auth` is the "
                    "check worth having: it re-sends every request WITHOUT "
                    "credentials and fails if the answer is unchanged, which "
                    "catches a route that declares a capability and does not "
                    "enforce it -- something reading the decorator cannot prove."
                ),
                "does_not_prove": (
                    "That the deployed system is safe. No ingress, no TLS "
                    "termination, no load balancer, no second replica. The "
                    "fuzzer reaches only what the OpenAPI document describes, "
                    "so an endpoint missing from the schema is invisible to it. "
                    "This is not a penetration test."
                ),
                "output_tail": "\n".join(output.splitlines()[-40:]),
                "environment": {
                    "platform": platform.platform(),
                    "python": platform.python_version(),
                },
                "started_at": started.isoformat(),
                "finished_at": datetime.now(timezone.utc).isoformat(),
            },
            indent=2, sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    # Printed through the same replace-on-error path the capture uses. The
    # scanner's summary contains emoji, this console is cp1252, and the
    # script died on its own success message after the artifact was already
    # written -- a non-zero exit for a gate that passed.
    _echo(chr(10).join(output.splitlines()[-25:]))
    _echo(f"{chr(10)}{'PASS' if ok else 'FAIL'} -> {OUT.relative_to(ROOT)}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
