"""The actual build-input gate must reject planted secrets without disclosure."""
import json
from pathlib import Path

import pytest

from scripts.check_container_context import allowed, dockerignore, inspect


@pytest.mark.parametrize("name", [
    ".env", "random-new-file.txt", "sentinel/nested/.env.prod",
    "sentinel/.venv/lib/credentials.py", "scripts/scratch.db", "sentinel/cache.pkl",
    "evaluation/.cache/customer.json", "../sentinel/x.py", "/sentinel/x.py",
])
def test_unapproved_inputs_are_rejected(name):
    assert not allowed(name)


def test_source_with_planted_credential_fails_without_disclosing_value(tmp_path):
    source = tmp_path / "sentinel"
    source.mkdir()
    canary = "AKIA" + "Q7ZP3M9XK2VL8RTN"
    (source / "bad.py").write_text("key = '" + canary + "'\n")
    result = inspect(tmp_path, require_complete=False)
    assert not result["passed"]
    assert result["findings"][0]["rule"] == "aws-access-key-id"
    assert canary not in json.dumps(result)


def test_symlink_is_refused_without_reading_its_target(tmp_path):
    source = tmp_path / "sentinel"
    source.mkdir()
    (source / "external.py").symlink_to(tmp_path / "absent-private-file")
    result = inspect(tmp_path, require_complete=False)
    assert not result["passed"]
    assert result["scanned"] == 0
    assert result["findings"] == [{"path": "sentinel/external.py", "rule": "symlink-refused"}]


def test_clean_runtime_source_passes(tmp_path):
    source = tmp_path / "sentinel"
    source.mkdir()
    (source / "__init__.py").write_text('"""Sentinel."""\n')
    result = inspect(tmp_path, require_complete=False)
    assert result["passed"]
    assert result["scanned"] == 1


def test_partial_context_cannot_pass_the_build_gate(tmp_path):
    result = inspect(tmp_path)
    assert not result["passed"]
    assert any(f["path"] == "sentinel/composition/container.py" for f in result["findings"])


def test_docker_manifest_includes_every_runtime_module():
    root = Path(__file__).resolve().parents[1]
    assert (root / ".dockerignore").read_text() == dockerignore(root)
