"""The blind-evaluation protocol refuses every way of not being blind."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from evaluation.run_blind import MIN_CASES, BlindProtocolError, load_cases, run, seal


def _corpus(tmp_path: Path, *, malicious: int = 30, benign: int = 30) -> Path:
    lines = []
    for index in range(malicious):
        lines.append({"id": f"m{index}", "label": "malicious", "class": "credential-file-read", "payload": {
            "agentId": "a", "eventType": "tool_call", "tool": "fs", "action": "read_file",
            "resource": "/home/user/.aws/credentials", "arguments": {"path": "/home/user/.aws/credentials"}}})
    for index in range(benign):
        lines.append({"id": f"b{index}", "label": "benign", "class": "ordinary-read", "payload": {
            "agentId": "a", "eventType": "tool_call", "tool": "fs", "action": "read_file",
            "resource": f"/srv/app/readme-{index}.md", "arguments": {"path": f"/srv/app/readme-{index}.md"}}})
    path = tmp_path / "corpus.jsonl"
    path.write_text("\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8")
    return path


def test_a_sealed_corpus_runs_once_and_reports_intervals(tmp_path):
    corpus, out = _corpus(tmp_path), tmp_path / "blind"
    sealed = seal(corpus, by="R. Auditor, Example Assurance Ltd", out=out)
    assert "payload" not in sealed.read_text(encoding="utf-8"), "the seal must not contain the corpus"
    result = run(corpus, out=out, require_committed_seal=False)
    assert result["blind"] is True and result["run_number"] == 1
    assert result["recall"]["trials"] == 30 and len(result["recall"]["wilson95"]) == 2
    assert result["benign_false_positive_rate"]["trials"] == 30
    assert result["recall_by_class"]["credential-file-read"]["trials"] == 30
    assert result["policy"]["digest"] and result["commit"]


def test_a_second_run_is_refused_unless_acknowledged_and_then_says_so(tmp_path):
    corpus, out = _corpus(tmp_path), tmp_path / "blind"
    seal(corpus, by="R. Auditor, Example Assurance Ltd", out=out)
    run(corpus, out=out, require_committed_seal=False)
    with pytest.raises(BlindProtocolError, match="no longer blind"):
        run(corpus, out=out, require_committed_seal=False)
    again = run(corpus, out=out, require_committed_seal=False, acknowledge_rerun=True)
    assert again["blind"] is False and again["run_number"] == 2


def test_an_unsealed_or_edited_corpus_is_refused(tmp_path):
    corpus, out = _corpus(tmp_path), tmp_path / "blind"
    with pytest.raises(BlindProtocolError, match="no seal"):
        run(corpus, out=out, require_committed_seal=False)
    seal(corpus, by="R. Auditor, Example Assurance Ltd", out=out)
    corpus.write_text(corpus.read_text(encoding="utf-8").replace('"benign"', '"malicious"', 1), encoding="utf-8")
    with pytest.raises(BlindProtocolError, match="no seal"):
        run(corpus, out=out, require_committed_seal=False)


def test_an_uncommitted_seal_is_refused_by_default(tmp_path):
    corpus, out = _corpus(tmp_path), tmp_path / "blind"
    seal(corpus, by="R. Auditor, Example Assurance Ltd", out=out)
    with pytest.raises(BlindProtocolError, match="not committed"):
        run(corpus, out=out)


def test_a_corpus_too_small_or_one_sided_is_refused(tmp_path):
    with pytest.raises(BlindProtocolError, match=str(MIN_CASES)):
        load_cases(_corpus(tmp_path, malicious=5, benign=5))
    with pytest.raises(BlindProtocolError):
        load_cases(_corpus(tmp_path, malicious=60, benign=0))


def test_a_corpus_is_sealed_once_and_by_someone_named(tmp_path):
    corpus, out = _corpus(tmp_path), tmp_path / "blind"
    with pytest.raises(BlindProtocolError, match="--by"):
        seal(corpus, by="me", out=out)
    seal(corpus, by="R. Auditor, Example Assurance Ltd", out=out)
    with pytest.raises(BlindProtocolError, match="sealed once"):
        seal(corpus, by="R. Auditor, Example Assurance Ltd", out=out)
