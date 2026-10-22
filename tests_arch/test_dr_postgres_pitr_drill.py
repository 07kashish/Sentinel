"""Postgres PITR drill script honesty (no fabricated RPO without DSN)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_postgres_pitr_drill_script_unverifiable_without_dsn(tmp_path, monkeypatch):
    monkeypatch.delenv("SENTINEL_TEST_POSTGRES_DSN", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "reports").mkdir()
    script = ROOT / "scripts" / "run_dr_postgres_pitr_drill.py"
    proc = subprocess.run(
        [sys.executable, str(script)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    out = json.loads(
        (tmp_path / "reports" / "dr_postgres_pitr_drill.json").read_text(encoding="utf-8")
    )
    assert out["status"] == "UNVERIFIED"
    assert out["measured"] is None
    assert "SENTINEL_TEST_POSTGRES_DSN" in out["precondition"]
