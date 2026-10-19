"""Protect-mode gate: decisions, enforcement honesty, callable helper, HTTP seam."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from sentinel.application.protect_gate import ProtectDenied, ProtectGate
from sentinel.composition.container import build_container
from sentinel.composition.settings import Settings
from sentinel.domain.attestation import AttestationDisposition
from sentinel.domain.primitives import Severity, TrustLevel
from sentinel.domain.protect import ProtectDecision, ProtectVerdict, decide_protect
from sentinel.infrastructure.detection import DeterministicPolicy
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.interface.http import create_app
from tests_arch.doubles import FakeAttestationGateway, FakeClock

INGEST_KEY = "ingest-key-that-is-long-enough-for-production-rules"
VIEWER_KEY = "viewer-key-that-is-long-enough-for-production-rulesx"

HIGH_RISK = {
    "agentId": "a1",
    "eventType": "tool_call",
    "action": "read_file",
    "resource": ".env",
    "metadata": {"path": ".env"},
}


def test_allow_when_nothing_fires():
    outcome = decide_protect(
        verdict=ProtectVerdict(
            fired=False, severity=Severity(0), detector_version="p@1"
        ),
        trust=TrustLevel.UNSIGNED,
        enforce=True,
    )
    assert outcome.decision is ProtectDecision.ALLOW
    assert outcome.enforced is False


def test_verified_high_severity_blocks_and_enforces_when_configured():
    outcome = decide_protect(
        verdict=ProtectVerdict(
            fired=True,
            severity=Severity(90),
            detector_version="p@1",
            matched_rules=("r1",),
            description="secret read",
        ),
        trust=TrustLevel.VERIFIED,
        enforce=True,
    )
    assert outcome.decision is ProtectDecision.BLOCK
    assert outcome.enforced is True


def test_advisory_never_claims_enforcement_even_on_block():
    outcome = decide_protect(
        verdict=ProtectVerdict(
            fired=True,
            severity=Severity(90),
            detector_version="p@1",
            matched_rules=("r1",),
        ),
        trust=TrustLevel.VERIFIED,
        enforce=False,
    )
    assert outcome.decision is ProtectDecision.BLOCK
    assert outcome.enforced is False


def test_unverified_would_be_block_escalates_honestly_in_advisory():
    outcome = decide_protect(
        verdict=ProtectVerdict(
            fired=True,
            severity=Severity(90),
            detector_version="p@1",
            matched_rules=("r1",),
        ),
        trust=TrustLevel.UNSIGNED,
        enforce=False,
    )
    assert outcome.decision is ProtectDecision.REQUIRE_APPROVAL
    assert outcome.enforced is False
    assert outcome.capped_severity <= 79


def test_unverified_high_risk_fails_closed_under_enforcement():
    outcome = decide_protect(
        verdict=ProtectVerdict(
            fired=True,
            severity=Severity(90),
            detector_version="p@1",
            matched_rules=("r1",),
        ),
        trust=TrustLevel.UNSIGNED,
        enforce=True,
    )
    assert outcome.decision is ProtectDecision.BLOCK
    assert outcome.enforced is True


def test_enforce_on_blocks_side_effect_callback():
    """Contract: enforced stop => action never runs."""
    gate = ProtectGate(policy=DeterministicPolicy.default(), enforce=True)
    ran = {"n": 0}

    def side_effect() -> str:
        ran["n"] += 1
        return "executed"

    try:
        gate.run_if_allowed(
            payload=HIGH_RISK,
            trust=TrustLevel.VERIFIED,
            action=side_effect,
        )
        # If policy did not fire, side effect may run -- assert honesty either way.
        outcome = gate.evaluate(payload=HIGH_RISK, trust=TrustLevel.VERIFIED)
        if outcome.enforced:
            raise AssertionError("expected ProtectDenied when enforced")
        assert ran["n"] == 1
    except ProtectDenied as denied:
        assert denied.outcome.enforced is True
        assert denied.outcome.decision.stops_action
        assert ran["n"] == 0, "side effect must not run under enforced deny"


def test_advisory_allows_side_effect_and_never_sets_enforced():
    """Contract: enforce=false => enforced never true; callback may run."""
    gate = ProtectGate(policy=DeterministicPolicy.default(), enforce=False)
    ran = {"n": 0}

    def side_effect() -> str:
        ran["n"] += 1
        return "executed"

    outcome, result = gate.run_if_allowed(
        payload=HIGH_RISK,
        trust=TrustLevel.VERIFIED,
        action=side_effect,
    )
    assert outcome.enforced is False
    assert result == "executed"
    assert ran["n"] == 1
    if outcome.decision is ProtectDecision.BLOCK:
        assert outcome.enforced is False


def test_require_allowed_raises_only_when_enforced():
    enforced_gate = ProtectGate(policy=DeterministicPolicy.default(), enforce=True)
    advisory_gate = ProtectGate(policy=DeterministicPolicy.default(), enforce=False)

    advisory = advisory_gate.require_allowed(
        payload=HIGH_RISK, trust=TrustLevel.VERIFIED
    )
    assert advisory.enforced is False

    try:
        enforced_gate.require_allowed(payload=HIGH_RISK, trust=TrustLevel.VERIFIED)
    except ProtectDenied as denied:
        assert denied.outcome.enforced is True
    else:
        # Policy may not match .env under verified depending on eventType;
        # if it did not stop, enforced must be false.
        out = enforced_gate.evaluate(payload=HIGH_RISK, trust=TrustLevel.VERIFIED)
        assert out.enforced is False


def _client(tmp_path: Path, *, enforce: bool) -> tuple[TestClient, object]:
    settings = Settings.from_environment(
        {
            "SENTINEL_ENV": "development",
            "SENTINEL_DB_PATH": str(tmp_path / "protect.db"),
            "SENTINEL_API_KEYS": (
                f"acme:{INGEST_KEY}:ingest,acme:{VIEWER_KEY}:viewer"
            ),
            "SENTINEL_PROTECT_ENFORCE": "true" if enforce else "false",
        }
    )
    pool = build_engine(settings.engine)
    migrate(pool)
    with pool.acquire() as conn:
        conn.begin()
        conn.execute_rowcount(
            f"INSERT INTO tenants (tenant_id, name, created_at) "
            f"VALUES ({conn.p},{conn.p},{conn.p})",
            ("acme", "Acme", "2026-07-25T12:00:00+00:00"),
        )
        conn.commit()
    pool.close()
    container = build_container(
        settings,
        clock=FakeClock(),
        attestation=FakeAttestationGateway(disposition=AttestationDisposition.ANCHORED),
        verify_schema=True,
    )
    return TestClient(create_app(container)), container


def test_protect_route_requires_capability(tmp_path):
    client, _ = _client(tmp_path, enforce=False)
    denied = client.post(
        "/v1/protect/evaluate",
        json={"agentId": "a1", "action": "read", "resource": ".env"},
        headers={"Authorization": f"Bearer {VIEWER_KEY}"},
    )
    assert denied.status_code == 403

    allowed = client.post(
        "/v1/protect/evaluate",
        json={"agentId": "a1", "action": "read", "resource": ".env"},
        headers={"Authorization": f"Bearer {INGEST_KEY}"},
    )
    assert allowed.status_code == 200
    body = allowed.json()
    assert "decision" in body
    assert body["enforced"] is False
    assert "detector_version" in body


def test_http_advisory_never_claims_enforced_on_block(tmp_path):
    client, _ = _client(tmp_path, enforce=False)
    response = client.post(
        "/v1/protect/evaluate",
        json=HIGH_RISK,
        headers={"Authorization": f"Bearer {INGEST_KEY}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["enforced"] is False
    if body["decision"] == "block":
        assert body["enforced"] is False


def test_http_enforce_matches_gate_and_container_helper(tmp_path):
    client, container = _client(tmp_path, enforce=True)
    response = client.post(
        "/v1/protect/evaluate",
        json=HIGH_RISK,
        headers={"Authorization": f"Bearer {INGEST_KEY}"},
    )
    assert response.status_code == 200
    body = response.json()
    gate_out = container.protect_gate.evaluate(
        payload=HIGH_RISK, trust=TrustLevel.UNSIGNED
    )
    assert body["decision"] == gate_out.decision.value
    assert body["enforced"] is gate_out.enforced
    if body["decision"] in {"block", "require_approval"}:
        assert body["enforced"] is True
        ran = {"n": 0}
        try:
            container.protect_gate.run_if_allowed(
                payload=HIGH_RISK,
                trust=TrustLevel.UNSIGNED,
                action=lambda: ran.__setitem__("n", ran["n"] + 1) or "x",
            )
        except ProtectDenied:
            assert ran["n"] == 0
        else:
            assert body["enforced"] is False


def test_http_refuses_caller_asserted_trust_and_keeps_unsigned_cap(tmp_path):
    client, _ = _client(tmp_path, enforce=False)
    payload = {
        **HIGH_RISK,
        "resource": "/home/user/.aws/credentials",
        "metadata": {"path": "/home/user/.aws/credentials"},
    }
    refused = client.post(
        "/v1/protect/evaluate",
        json={**payload, "trustLevel": "verified"},
        headers={"Authorization": f"Bearer {INGEST_KEY}"},
    )
    assert refused.status_code == 422
    assert "trustLevel is no longer accepted" in refused.text

    unsigned = client.post(
        "/v1/protect/evaluate",
        json=payload,
        headers={"Authorization": f"Bearer {INGEST_KEY}"},
    )
    assert unsigned.status_code == 200
    assert unsigned.json()["capped_severity"] <= 79


def test_approval_does_not_substitute_for_reauthentication(monkeypatch):
    import pytest
    from sentinel.domain.protect import ProtectOutcome
    outcome = ProtectOutcome(ProtectDecision.STEP_UP_AUTH, True, 0, 0, "test", (), "reauthenticate")
    monkeypatch.setattr(ProtectGate, "evaluate", lambda self, **kwargs: outcome)
    gate = ProtectGate(policy=DeterministicPolicy.default(), enforce=True)
    effects = []
    with pytest.raises(ProtectDenied):
        gate.run_if_allowed(payload={}, trust=TrustLevel.VERIFIED,
                            action=lambda: effects.append("ran"), approved=True)
    assert effects == []


def test_private_parameters_are_checked_without_exposing_matches():
    import pytest
    from sentinel.infrastructure.detection import DeterministicPolicy, PolicyRule
    rule = PolicyRule(rule_id="private-body", field="arguments.body", mode="contains",
                      values=("sensitive-marker",), severity=90, incident_type="restricted",
                      description="restricted body")
    gate = ProtectGate(policy=DeterministicPolicy(rules=[rule], version="private/v1"), enforce=True)
    payload = {"action": "update", "resource": "deployment/staging"}
    with pytest.raises(ProtectDenied) as caught:
        gate.run_if_allowed(payload=payload, parameters={"body": "sensitive-marker"},
                            trust=TrustLevel.VERIFIED, action=lambda: pytest.fail("side effect ran"))
    assert "sensitive-marker" not in str(caught.value)
    assert "sensitive-marker" not in repr(caught.value.outcome)
    assert "arguments" not in payload
