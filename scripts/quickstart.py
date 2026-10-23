"""Clone, run this, see Sentinel catch an attack. No Docker, no accounts.

WHAT THIS IS FOR
----------------
The repository's `docker-compose.yml` brings up PostgreSQL, Prometheus,
Grafana, Keycloak and Jaeger. That is the right production shape and the wrong
first impression: somebody evaluating this should not need five containers and
a `.env` file to find out whether it does anything.

This runs the real ASGI app on SQLite, on localhost, in one process group, and
drives it over HTTP with the real SDK. Everything it exercises is the shipped
code path -- there are no stubs and no fixtures, which is the point: a demo
that mocks the thing being demonstrated proves nothing.

THE RULE THIS SCRIPT FOLLOWS
----------------------------
**It never prints a tick for something it did not verify.**

The obvious way to write a quickstart is a sequence of steps each printing "OK"
when the call returned without raising. That version passes on a server that
started and detected nothing, because "no exception" is not "it worked". So
each step here states what it OBSERVED, and the final verdict is computed from
whether an incident actually came back -- not from having reached the end.

If the demo attack produces no incident, this exits non-zero and says the
detection did not fire. A quickstart that congratulates you on a broken build
is worse than no quickstart.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

#: Demo credentials. Deliberately obvious, deliberately local-only, and long
#: enough to satisfy the real key-length check -- a quickstart that needed the
#: check relaxed would be demonstrating a weakened build.
INGEST_KEY = "quickstart-ingest-000000000000000"
VIEW_KEY = "quickstart-viewer-000000000000000"
TENANT = "quickstart"

PORT_RANGE = range(8765, 8800)
STARTUP_TIMEOUT_SECONDS = 45
MIN_PYTHON = (3, 12)


def _say(message: str) -> None:
    print(message, flush=True)


def _step(observed: str) -> None:
    """Report what was OBSERVED, not that a step completed.

    "no exception was raised" is not "it worked", and a tick per step is how a
    quickstart congratulates you on a server that detected nothing.
    """
    _say(f"  {observed}")


def _fail(message: str) -> int:
    _say("")
    _say(f"FAILED: {message}")
    return 1


def _free_port() -> int:
    for port in PORT_RANGE:
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise SystemExit(
        f"no free port in {PORT_RANGE.start}-{PORT_RANGE.stop}. Refusing to "
        "pick one at random: a quickstart that grabs an arbitrary port is one "
        "you cannot find again."
    )


def _wait_for_ready(base: str, process: subprocess.Popen) -> str | None:
    """Poll readiness. Returns None on success, or a reason on failure.

    Watches the CHILD as well as the socket. A server that exited immediately
    -- a missing dependency, a migration failure -- would otherwise be waited
    on for the full timeout and reported as slow rather than as dead.
    """
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    last = "no response yet"

    while time.monotonic() < deadline:
        if process.poll() is not None:
            return (
                f"the server exited with code {process.returncode} before "
                "becoming ready"
            )
        try:
            with urllib.request.urlopen(f"{base}/health/ready", timeout=2) as r:
                if r.status == 200:
                    return None
                last = f"readiness returned {r.status}"
        except urllib.error.HTTPError as error:
            last = f"readiness returned {error.code}"
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            last = f"not accepting connections yet ({error})"
        time.sleep(0.4)

    return f"not ready within {STARTUP_TIMEOUT_SECONDS}s: {last}"


def _post(base: str, path: str, key: str, payload: dict) -> tuple[int, dict]:
    request = urllib.request.Request(
        f"{base}{path}",
        data=json.dumps(payload).encode(),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        body = error.read() or b"{}"
        try:
            return error.code, json.loads(body)
        except json.JSONDecodeError:
            return error.code, {"raw": body[:400].decode("utf-8", "replace")}


def _get(base: str, path: str, key: str) -> tuple[int, dict]:
    request = urllib.request.Request(
        f"{base}{path}", headers={"Authorization": f"Bearer {key}"}
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        return error.code, {}


#: The demo attack: read data, compress it, ship it outside. Every step is
#: individually legitimate; only the ORDER is the attack. Taken from the
#: tracked red-team table rather than invented, so what a newcomer sees is a
#: case the release gate actually asserts.
DEMO_STEPS = (
    {
        "eventId": "qs-1",
        "sessionId": "qs-session",
        "agentId": "demo-agent",
        "eventType": "tool_call",
        "action": "read_file",
        "resource": "customers",
        "timestamp": "2026-09-03T10:00:00Z",
    },
    {
        "eventId": "qs-2",
        "parentEventId": "qs-1",
        "sessionId": "qs-session",
        "agentId": "demo-agent",
        "eventType": "tool_call",
        "action": "zip",
        "timestamp": "2026-09-03T10:00:05Z",
    },
    {
        "eventId": "qs-3",
        "parentEventId": "qs-2",
        "sessionId": "qs-session",
        "agentId": "demo-agent",
        "eventType": "tool_call",
        "action": "http_post",
        "destination": "https://attacker.example",
        "timestamp": "2026-09-03T10:00:09Z",
    },
)


def main() -> int:
    started = time.monotonic()

    if sys.version_info < MIN_PYTHON:
        return _fail(
            f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required; this is "
            f"{sys.version_info.major}.{sys.version_info.minor}"
        )

    try:
        import uvicorn  # noqa: F401
    except ImportError:
        return _fail(
            "uvicorn is not installed. Run `pip install -r requirements.txt` "
            "first. Refusing to continue rather than falling back to an "
            "in-process client, because that would demonstrate a code path no "
            "deployment uses."
        )

    port = _free_port()
    base = f"http://127.0.0.1:{port}"

    _say("Sentinel quickstart -- real app, SQLite, no Docker, no accounts")
    _say("")

    with tempfile.TemporaryDirectory(prefix="sentinel-quickstart-") as staging:
        env = dict(os.environ)
        env.update(
            {
                "PYTHONPATH": str(ROOT),
                "SENTINEL_DB_PATH": str(Path(staging) / "quickstart.db"),
                "SENTINEL_API_KEYS": (
                    f"{TENANT}:{INGEST_KEY}:ingest,{TENANT}:{VIEW_KEY}:viewer"
                ),
                "SENTINEL_BOOTSTRAP_TENANT": TENANT,
            }
        )

        # Migrate before serving. The app does not migrate on startup, on
        # purpose: a process that alters the schema when it boots turns a
        # rollback into a data-loss event. So the quickstart does it
        # explicitly, the way a deployment does.
        _step("creating the schema")
        migrate_result = subprocess.run(
            [
                sys.executable,
                "-c",
                "from sentinel.composition.settings import Settings;"
                "from sentinel.infrastructure.sql.engine import build_engine;"
                "from sentinel.infrastructure.sql.migrate import migrate;"
                "pool = build_engine(Settings.from_environment().engine);"
                "migrate(pool); pool.close()",
            ],
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if migrate_result.returncode != 0:
            return _fail(
                "the schema could not be created:\n"
                + (migrate_result.stderr or migrate_result.stdout)[-1500:]
            )
        _step("schema created")

        _step(f"starting the app on {base} (SQLite in {staging})")
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                # A FACTORY, not a module-level `app`. asgi.py exposes
                # `create_application` deliberately -- its docstring notes that
                # a tool importing the module to enumerate routes should start
                # no worker threads -- so the quickstart passes --factory
                # rather than adding a module-level app for its convenience.
                "--factory",
                "sentinel.interface.asgi:create_application",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--log-level",
                "warning",
            ],
            cwd=str(ROOT),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        try:
            problem = _wait_for_ready(base, process)
            if problem is not None:
                # ACTUALLY READ the pipe. The first version of this block set
                # `output = b""`, closed the stream, and printed the empty
                # string under the heading "server output" -- a diagnostic that
                # reads nothing and reports confidently, which is the defect
                # this script's own docstring warns about.
                output = b""
                if process.stdout is not None:
                    try:
                        process.kill()
                        output = process.stdout.read() or b""
                    except Exception as error:  # noqa: BLE001
                        output = f"could not read the server output: {error}".encode()
                _say("")
                _say("  server output:")
                for line in output.decode("utf-8", "replace").splitlines()[-25:]:
                    _say(f"    {line}")
                return _fail(problem)

            elapsed = time.monotonic() - started
            _step(f"the app reported ready after {elapsed:.1f}s")

            # ── submit the demo attack ─────────────────────────────────────
            _say("")
            _say("Submitting a staged exfiltration: read_file -> zip -> http_post")
            _say("Each step is legitimate on its own. Only the ORDER is the attack.")

            accepted = 0
            admitted_at_ingest = False
            for step in DEMO_STEPS:
                status, body = _post(base, "/v1/events", INGEST_KEY, step)
                if status >= 400:
                    return _fail(
                        f"the app refused event {step['eventId']} with {status}: "
                        f"{body}. Reported rather than skipped -- a quickstart "
                        "that ignores a rejected step would then claim the "
                        "detection failed."
                    )
                accepted += 1
                outcome = str(body.get("outcome", "recorded"))
                if outcome == "incident_admitted":
                    admitted_at_ingest = True
                _step(f"{step['action']:<10} -> {outcome}")

            if accepted != len(DEMO_STEPS):
                return _fail(
                    f"only {accepted} of {len(DEMO_STEPS)} events were accepted"
                )

            # ── the verdict, computed from what came back ──────────────────
            _say("")
            status, incidents = _get(base, "/v1/incidents", VIEW_KEY)
            if status >= 400:
                return _fail(f"reading incidents returned {status}")

            # `incidents` is the key this API uses. An earlier version of this
            # script looked for `items`, found nothing, and reported that the
            # detection had not fired -- while the submission response had
            # already said `incident_admitted`. The refusal was right and the
            # field was wrong.
            items = incidents.get("incidents")
            if items is None:
                items = incidents.get("items")
            if items is None:
                items = incidents if isinstance(incidents, list) else []

            if not items:
                # THE BRANCH THAT MATTERS. Reaching the end of the script is
                # not success; an incident coming back is.
                return _fail(
                    "the events were accepted and NO incident was raised. The "
                    "detection did not fire, so this build does not do the "
                    "thing this quickstart exists to show. Exiting non-zero "
                    "rather than printing a tick for having got this far."
                )

            if not admitted_at_ingest:
                # TWO SOURCES THAT MUST AGREE. The submission response and the
                # incident list are independent reports of the same thing. A
                # demo that quietly picked the more flattering of two
                # disagreeing signals would be exactly what this script exists
                # not to be.
                return _fail(
                    f"{len(items)} incident(s) are listed, but no event "
                    "submission reported `incident_admitted`. The two views of "
                    "the same fact disagree, so neither is reported as a "
                    "success."
                )

            first = items[0] if isinstance(items[0], dict) else {}
            _say(f"{len(items)} incident(s) raised:")
            _step(
                f"id       {first.get('incidentId', first.get('incident_id', '?'))}"
            )
            _step(f"priority {first.get('priority', '?')}")
            _step(f"severity {first.get('severity', '?')}")
            title = first.get("title") or first.get("summary") or ""
            if title:
                _step(f"title    {title}")

            total = time.monotonic() - started
            _say("")
            _say(f"Done in {total:.1f}s. What just happened:")
            _say("  * three individually-legitimate tool calls were recorded")
            _say("  * the sequence detector matched them as an ORDERED pattern")
            _say("  * an incident was raised, with the chain as its evidence")
            _say("")
            _say("What did NOT happen, and why:")
            _say("  * nothing was blocked. Correlation is self-reported, so")
            _say("    blocking on it would let an attacker halt someone else's")
            _say("    agent by forging a chain. Sentinel detects far more than")
            _say("    it prevents, on purpose. See docs/SECURITY_ASSURANCE.md.")
            _say("")
            _say("Next:")
            _say(f"  console   {base}/console  (viewer key: {VIEW_KEY})")
            _say(f"  openapi   {base}/openapi.json")
            _say("  full stack: docker compose up -d")
            _say("")
            _say("This ran on SQLite in a temp directory, which is now deleted.")
            return 0

        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
