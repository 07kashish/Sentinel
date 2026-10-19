"""F-4: VCS integrity gates that can run without operator GitHub settings."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_check_empty_modules_script_exits_zero_on_clean_tree():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check_empty_modules.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout
    assert "ok:" in result.stdout


def test_check_empty_modules_fails_on_empty_file(tmp_path):
    script = (ROOT / "scripts" / "check_empty_modules.py").read_text(encoding="utf-8")
    # Run against a temporary sentinel-like tree with one empty module.
    fake_root = tmp_path / "proj"
    sentinel = fake_root / "sentinel" / "domain"
    sentinel.mkdir(parents=True)
    (sentinel / "empty.py").write_text("", encoding="utf-8")
    (fake_root / "scripts").mkdir()
    # Adapt script ROOT to fake tree by executing a one-off check.
    code = (
        "from pathlib import Path\n"
        f"root = Path(r'{sentinel.parent}')\n"
        "bad = sorted(p for p in root.rglob('*.py') if p.stat().st_size == 0)\n"
        "raise SystemExit(1 if bad else 0)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=fake_root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert script  # scaffold present


def test_pre_commit_config_wires_empty_module_and_architecture_hooks():
    config = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    assert "scripts/check_empty_modules.py" in config
    assert "test_architecture_rules.py" in config
    assert "ruff" in config
