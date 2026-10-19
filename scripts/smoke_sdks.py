#!/usr/bin/env python3
"""Run the Python client SDK against a real, locally started Sentinel.

Starts the service the way `try_sentinel.py` does (temporary directory, SQLite,
fresh keys, enforcement on), loads the sample policy, then runs one
journey through `sentinel.sdk.remote.SentinelClient`:
allow, require approval, refused before approval, approve, execute once, replay
refused, bad key is no decision. Exit code 0 only if it passes.

WHY THIS EXISTS. Every SDK test used a fake transport, and a fake accepts
anything. The first live run found the Python client sending three things the
real routes reject or ignore (an object-shaped authorization, a `trustLevel`,
and arguments tucked inside metadata), so bound execution through the SDK had
never worked against a real server. A wire contract is only tested on a wire.
"""
from __future__ import annotations

import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ROLES = ("viewer", "ingest", "analyst", "admin")


PYTHON_JOURNEY = r"""
import json, os, urllib.request
from sentinel.sdk.models import Decision
from sentinel.sdk.remote import SentinelClient, SentinelRefused, SentinelUnavailable
base = os.environ["SMOKE_BASE"]
client = SentinelClient(base_url=base, api_key=os.environ["SMOKE_INGEST"])
agent = "agent:py-sdk-smoke"
out = {}
ordinary = client.check(agent_id=agent, tool="echo", action="read", resource="/docs/readme.md", arguments={"q": "hello"})
out["ordinary"] = ordinary.decision.value
assert ordinary.consulted
change = dict(agent_id=agent, tool="echo", action="update", resource="/protected-change/prod/config/py-sdk", arguments={"rps": 450})
pending = client.check(**change)
assert pending.decision is Decision.REQUIRE_APPROVAL and pending.authorization and pending.authorization.token
out["pending"] = pending.decision.value
try:
    client.execute(**change, authorization=pending.authorization); raise AssertionError("executed before approval")
except SentinelRefused:
    pass
request = urllib.request.Request(base + "/v1/authorizations/" + pending.authorization.authorization_id + "/decide", method="POST",
    data=json.dumps({"decision": "approve", "reason": "python sdk live smoke"}).encode(),
    headers={"Authorization": "Bearer " + os.environ["SMOKE_ANALYST"], "Content-Type": "application/json"})
assert urllib.request.urlopen(request, timeout=20).status == 200
done = client.execute(**change, authorization=pending.authorization)
out["executed"] = {"tool": done.tool, "hasReceipt": bool(done.receipt)}
try:
    client.execute(**change, authorization=pending.authorization); raise AssertionError("replay executed")
except SentinelRefused:
    out["replayRefused"] = True
try:
    SentinelClient(base_url=base, api_key="not-a-real-key-000000000000000000000000").check(agent_id=agent, action="read")
    raise AssertionError("a wrong key produced a decision")
except SentinelUnavailable:
    out["badKeyIsNoDecision"] = True
print(json.dumps(out))
"""


def main() -> int:
    with tempfile.TemporaryDirectory() as work:
        keys = {role: f"smoke-{role}-{secrets.token_hex(20)}" for role in ROLES}
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        env = {name: value for name, value in os.environ.items() if not name.startswith("SENTINEL_")}
        env.update(PYTHONPATH=str(ROOT), SENTINEL_DB_PATH=str(Path(work) / "smoke.sqlite"),
                   SENTINEL_API_KEYS=",".join(f"smoke:{keys[role]}:{role}" for role in ROLES),
                   SENTINEL_PROTECT_ENFORCE="true", SENTINEL_PROTECTION_MODE="protect")
        subprocess.run([sys.executable, "-m", "sentinel.interface.cli", "migrate"], env=env, cwd=ROOT, check=True, capture_output=True)
        server = subprocess.Popen([sys.executable, "-m", "uvicorn", "sentinel.interface.asgi:create_application", "--factory",
                                   "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"], env=env, cwd=ROOT,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        base = f"http://127.0.0.1:{port}"
        try:
            for _ in range(150):
                try:
                    urllib.request.urlopen(base + "/health/live", timeout=2)
                    break
                except OSError:
                    time.sleep(0.2)
            seed = subprocess.run([sys.executable, str(ROOT / "scripts/seed_console_demo.py"), "--base", base], capture_output=True, text=True,
                                  env=dict(env, SENTINEL_DEMO_INGEST_KEY=keys["ingest"], SENTINEL_DEMO_ANALYST_KEY=keys["analyst"],
                                           SENTINEL_DEMO_ADMIN_KEY=keys["admin"]))
            if seed.returncode != 0:
                print("the sample policy did not load:", seed.stderr[-400:], file=sys.stderr)
                return 1
            python = subprocess.run([sys.executable, "-c", PYTHON_JOURNEY], cwd=ROOT, capture_output=True, text=True, timeout=120,
                                    env=dict(env, SMOKE_BASE=base, SMOKE_INGEST=keys["ingest"], SMOKE_ANALYST=keys["analyst"]))
            print("python live:", python.stdout.strip() or "(no output)")
            if python.returncode != 0:
                print(python.stderr[-2500:], file=sys.stderr)
                return python.returncode
            return 0
        finally:
            server.terminate()
            try:
                server.wait(timeout=15)
            except subprocess.TimeoutExpired:
                server.kill()


if __name__ == "__main__":
    raise SystemExit(main())
