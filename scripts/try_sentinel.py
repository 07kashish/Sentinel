#!/usr/bin/env python3
"""Run Sentinel on your own laptop for a trial: one command, nothing leaves the machine.

    python scripts/try_sentinel.py            # start; Ctrl-C stops it

What it does, in order:
  1. creates `./.sentinel-trial/` (mode 0700) with a SQLite database and four
     freshly generated keys (viewer, ingest, analyst, admin) for a tenant `trial`;
  2. migrates the schema;
  3. serves the API and console on http://127.0.0.1:<port>/console.

The admin key is printed once so you can sign in; it is also in
`.sentinel-trial/keys.env`. This is a development posture: one process, SQLite,
no TLS, enforcement on. It is for trying the product, not for running it.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ROLES = ("viewer", "ingest", "analyst", "admin")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--advisor-cli", default="", help="absolute path of a signed-in advisor CLI (e.g. ~/.local/bin/agy)")
    parser.add_argument("--advisor-model", default="", help="model name for --advisor-cli (see `agy models`)")
    parser.add_argument("--check", action="store_true", help="start, verify, then stop (used by the test)")
    args = parser.parse_args(argv)

    home = ROOT / ".sentinel-trial"
    home.mkdir(mode=0o700, exist_ok=True)
    keys_file = home / "keys.env"
    if keys_file.exists():
        keys = dict(line.strip().split("=", 1) for line in keys_file.read_text().splitlines() if "=" in line)
    else:
        keys = {role: f"trial-{role}-{secrets.token_hex(20)}" for role in ROLES}
        fd = os.open(keys_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write("".join(f"{role}={key}\n" for role, key in keys.items()))

    env = {name: value for name, value in os.environ.items() if not name.startswith("SENTINEL_")}
    env.update(PYTHONPATH=str(ROOT), SENTINEL_DB_PATH=str(home / "sentinel.sqlite"),
               SENTINEL_API_KEYS=",".join(f"trial:{keys[role]}:{role}" for role in ROLES),
               SENTINEL_PROTECT_ENFORCE="true", SENTINEL_PROTECTION_MODE="protect")
    if args.advisor_cli:
        env.update(SENTINEL_ADVISOR_CLI_COMMAND=str(Path(args.advisor_cli).expanduser()),
                   SENTINEL_ADVISOR_MODEL=args.advisor_model)


    subprocess.run([sys.executable, "-m", "sentinel.interface.cli", "migrate"], env=env, cwd=ROOT, check=True)
    server = subprocess.Popen([sys.executable, "-m", "uvicorn", "sentinel.interface.asgi:create_application", "--factory",
                               "--host", "127.0.0.1", "--port", str(args.port), "--log-level", "warning"], env=env, cwd=ROOT)
    base = f"http://127.0.0.1:{args.port}"
    try:
        for _ in range(150):
            if server.poll() is not None:
                print("the service exited during start-up; see the messages above", file=sys.stderr)
                return 1
            try:
                urllib.request.urlopen(base + "/health/live", timeout=2)
                break
            except OSError:
                time.sleep(0.2)
        print(f"\nSentinel is running.\n  console : {base}/console\n  sign in : paste the admin key below as the operator token\n"
              f"  admin   : {keys['admin']}\n  all keys: {keys_file}\n  stop    : Ctrl-C\n")
        if args.check:
            request = urllib.request.Request(base + "/v1/dashboard", headers={"Authorization": "Bearer " + keys["viewer"]})
            with urllib.request.urlopen(request, timeout=20) as response:
                json.load(response)
            print("dashboard available to the viewer")
            return 0
        server.wait()
    except KeyboardInterrupt:
        pass
    finally:
        server.terminate()
        try:
            server.wait(timeout=15)
        except subprocess.TimeoutExpired:
            server.kill()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
