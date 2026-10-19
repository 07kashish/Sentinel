"""Refuse empty load-bearing modules (F-4 integrity gate)."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "sentinel"
bad = sorted(p for p in ROOT.rglob("*.py") if p.stat().st_size == 0)
if bad:
    rel = [str(p.relative_to(ROOT.parent)) for p in bad]
    print("empty modules:", ", ".join(rel), file=sys.stderr)
    sys.exit(1)
print("ok: no empty modules under sentinel/")
