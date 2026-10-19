#!/usr/bin/env python3
"""Run the Postgres PITR drill against an embedded pgserver (keeps server alive)."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pgserver

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    data = Path(tempfile.mkdtemp(prefix="sentinel_pitr_live_"))
    server = pgserver.get_server(data)
    try:
        uri = server.get_uri()
        env = os.environ.copy()
        env["SENTINEL_TEST_POSTGRES_DSN"] = uri
        env["PYTHONPATH"] = str(ROOT)
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "run_dr_postgres_pitr_drill.py")],
            cwd=str(ROOT),
            env=env,
            check=False,
        )
        return int(proc.returncode)
    finally:
        server.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
