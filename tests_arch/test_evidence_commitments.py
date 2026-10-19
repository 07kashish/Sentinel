"""Receipts reach the transparency log, and a bundle verifies without Sentinel.

Before this, the log and its proofs were served and nothing in the running
service ever appended to it. These tests hold the chain end to end: an
execution produces a receipt, maintenance commits it exactly once, the export
carries the receipt with its proof, and the STANDALONE verifier -- loaded
from its file, importing nothing from `sentinel` -- accepts it and rejects an
altered receipt, a foreign receipt and a rewritten log.
"""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest

from sentinel.domain.transparency import InclusionProof, verify_inclusion
from sentinel.infrastructure.sql.evidence_commitments import RECEIPT_FIELDS, SqlEvidenceCommitments, receipt_leaf
from sentinel.infrastructure.sql.transparency_store import SqlTransparencyStore
from tests_arch.test_execution_contract import ANALYST, GLOBEX_INGEST, _evaluate, _execute, _h, _make

ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "standard" / "execution-passport-v1" / "verify_evidence_bundle.py"


def _verifier():
    spec = importlib.util.spec_from_file_location("verify_evidence_bundle", VERIFIER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def app(tmp_path, engine_config, monkeypatch):
    harness = _make(tmp_path, engine_config, monkeypatch, enforce=True)
    try:
        yield harness
    finally:
        harness.container.close()


def _run(harness, count: int, key=None) -> None:
    for index in range(count):
        kwargs = {"key": key} if key else {}
        token = _evaluate(harness, arguments={"value": f"v{index}"}, **kwargs).json()["authorization"]["token"]
        assert _execute(harness, token, arguments={"value": f"v{index}"}, **kwargs).status_code == 200


def _bundle(harness) -> dict:
    response = harness.client.get("/v1/evidence/export", headers=_h(ANALYST))
    assert response.status_code == 200, response.text
    return response.json()


def test_receipts_are_committed_once_and_the_bundle_verifies_offline(app):
    _run(app, 5)
    evidence: SqlEvidenceCommitments = app.container.evidence
    assert evidence.pending("acme") == 5
    assert _bundle(app)["entries"] == [] and _bundle(app)["receipts_not_yet_committed"] == 5

    assert evidence.commit_pending("acme", at="2026-09-20T00:00:00+00:00") == 5
    assert evidence.commit_pending("acme", at="2026-09-20T00:00:01+00:00") == 0, "a receipt was committed twice"
    assert SqlTransparencyStore(pool=app.container.pool).size("acme") == 5

    bundle = _bundle(app)
    assert [e["sequence"] for e in bundle["entries"]] == [0, 1, 2, 3, 4]
    assert bundle["tree_size"] == 5 and bundle["receipts_not_yet_committed"] == 0
    verifier = _verifier()
    assert verifier.verify(bundle) == []
    assert verifier.verify(bundle, trusted_root=bundle["root"], trusted_size=5) == []
    # The domain verifier and the standalone one agree, entry by entry.
    for entry in bundle["entries"]:
        proof = InclusionProof(index=entry["proof"]["index"], tree_size=entry["proof"]["tree_size"],
                               path=tuple(bytes.fromhex(h) for h in entry["proof"]["path"]))
        assert verify_inclusion(digest=bytes.fromhex(entry["leaf_digest"]), proof=proof,
                                root=bytes.fromhex(bundle["root"])) is None


def test_the_verifier_imports_nothing_from_sentinel():
    source = VERIFIER.read_text(encoding="utf-8")
    assert "import sentinel" not in source and "from sentinel" not in source
    assert tuple(_verifier().FIELDS) == RECEIPT_FIELDS, "the offline verifier hashes different fields than the service"


def test_an_altered_receipt_a_foreign_receipt_and_a_rewritten_log_all_fail(app):
    _run(app, 3)
    app.container.evidence.commit_pending("acme", at="2026-09-20T00:00:00+00:00")
    bundle, verifier = _bundle(app), _verifier()
    trusted = (bundle["root"], bundle["tree_size"])

    altered = copy.deepcopy(bundle)
    altered["entries"][1]["receipt"]["outcome"] = "refused"
    assert any("altered" in f for f in verifier.verify(altered))

    foreign = copy.deepcopy(bundle)
    foreign["entries"][0]["receipt"]["receipt_id"] = "receipt-invented"
    foreign["entries"][0]["leaf_digest"] = receipt_leaf("acme", foreign["entries"][0]["receipt"]).hex()
    assert any("does not reach" in f for f in verifier.verify(foreign))

    _run(app, 1)  # the log grows; an old trusted root no longer equals the new one
    app.container.evidence.commit_pending("acme", at="2026-09-20T00:01:00+00:00")
    grown = _bundle(app)
    assert verifier.verify(grown) == []
    assert any("not the trusted one" in f for f in verifier.verify(grown, trusted_root=trusted[0], trusted_size=trusted[1]))


def test_a_tenant_exports_only_its_own_evidence(app):
    _run(app, 2)
    _run(app, 1, key=GLOBEX_INGEST)
    for tenant in ("acme", "globex"):
        app.container.evidence.commit_pending(tenant, at="2026-09-20T00:00:00+00:00")
    bundle = _bundle(app)
    assert bundle["tenant_id"] == "acme" and len(bundle["entries"]) == 2
    assert "globex" not in json.dumps(bundle)


def test_the_maintenance_loop_commits_without_being_asked(app):
    from sentinel.domain.primitives import TenantId
    from sentinel.interface.worker import MaintenanceLoop

    _run(app, 2)
    loop = MaintenanceLoop(app.container, tenants=lambda: [TenantId("acme")], interval_seconds=30.0)
    totals = loop.run_once()
    assert totals["receipts_committed"] == 2
    assert _bundle(app)["receipts_not_yet_committed"] == 0


def test_the_bundle_says_when_no_root_is_held_outside_this_environment(app):
    _run(app, 1)
    app.container.evidence.commit_pending("acme", at="2026-09-20T00:00:00+00:00")
    bundle = _bundle(app)
    assert bundle["independently_anchored"] is False
    assert "outside this environment" in bundle["note"]
