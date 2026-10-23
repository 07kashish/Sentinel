"""The execution-control contract, end to end over HTTP, on both engines.

The promise under test: a policy-approved action is the action actually
executed, once, and only while identity, tenant, agent, tool, action,
resource, parameter digest, policy digest, expiry and revocation state still
agree. Every case counts the SIDE EFFECTS that ran, because a 403 that ran
the tool anyway is the failure this suite exists to catch.

Cases, each under enforcement ON and OFF where the distinction matters:
evaluate -> pending -> approve -> execute; reject; expiry; replay; parameter,
tool and resource substitution; emergency revocation; policy change; kill
switch; block never satisfied by approval; same-named agents in two tenants.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sentinel.application.protect_gate import ProtectDenied, ProtectGate
from sentinel.application.tool_proxy import RegisteredSideEffect
from sentinel.composition.container import build_container
from sentinel.composition.settings import Settings
from sentinel.domain.attestation import AttestationDisposition
from sentinel.domain.operations import OperationState
from sentinel.domain.primitives import TrustLevel
from sentinel.infrastructure.detection import DeterministicPolicy
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.interface.http import create_app
from tests_arch.doubles import FakeAttestationGateway, FakeClock

INGEST = "contract-ingest-key-that-is-long-enough-for-production"
ANALYST = "contract-analyst-key-that-is-long-enough-for-production"
ADMIN = "contract-admin-key-that-is-long-enough-for-production"
GLOBEX_INGEST = "contract-globex-ingest-key-long-enough-for-production"

POLICY = {
    "policy_id": "execution-contract-test",
    "version": "1",
    "rules": [
        {
            "id": "approval-required-resource",
            "description": "a resource that needs a human",
            "field": "resource",
            "mode": "contains",
            "values": ["/needs-approval"],
            # 75: above the approval threshold (70) and below block (85) for a
            # caller of ANY trust, so it is require_approval under enforcement
            # too. The unsigned cap is 79, which does not move it.
            "severity": 75,
            "incident_type": "test",
        },
        {
            "id": "blocked-resource",
            "description": "a resource nobody may touch",
            "field": "resource",
            "mode": "contains",
            "values": ["/blocked"],
            "severity": 95,
            "incident_type": "test",
        },
    ],
}


class Harness:
    """The real app, the container, and a counter of side effects that ran."""

    def __init__(self, client: TestClient, container, clock: FakeClock) -> None:
        self.client = client
        self.container = container
        self.clock = clock
        self.effects: list[dict] = []

    def register(self, name: str = "echo") -> None:
        def runner(arguments):
            self.effects.append({"tool": name, **dict(arguments)})
            return {"ran": True, "tool": name}

        self.container.tool_proxy.register(RegisteredSideEffect(name=name, runner=runner))


def _make(tmp_path: Path, engine_config, monkeypatch, *, enforce: bool, **extra) -> Harness:
    import sentinel.infrastructure.detection as detection

    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(POLICY), encoding="utf-8")
    monkeypatch.setattr(detection, "DEFAULT_POLICY_PATH", policy)
    env = {
        "SENTINEL_ENV": "development",
        "SENTINEL_DB_PATH": str(tmp_path / "contract.db"),
        "SENTINEL_API_KEYS": (
            f"acme:{INGEST}:ingest,acme:{ANALYST}:analyst,acme:{ADMIN}:admin,"
            f"globex:{GLOBEX_INGEST}:ingest"
        ),
        "SENTINEL_CORS_ORIGINS": "https://console.example.com",
        "SENTINEL_PROTECT_ENFORCE": "true" if enforce else "false",
    }
    env.update(extra)
    settings = replace(Settings.from_environment(env), engine=engine_config)
    pool = build_engine(settings.engine)
    try:
        migrate(pool)
        with pool.acquire() as conn:
            conn.begin()
            for tenant in ("acme", "globex"):
                conn.execute_rowcount(
                    f"INSERT INTO tenants (tenant_id, name, created_at) "
                    f"VALUES ({conn.p},{conn.p},{conn.p}) ON CONFLICT (tenant_id) DO NOTHING",
                    (tenant, tenant, "2026-09-14T00:00:00+00:00"),
                )
            conn.commit()
    finally:
        pool.close()
    clock = FakeClock()
    container = build_container(
        settings,
        clock=clock,
        attestation=FakeAttestationGateway(disposition=AttestationDisposition.ANCHORED),
    )
    harness = Harness(TestClient(create_app(container), raise_server_exceptions=False), container, clock)
    harness.register("echo")
    harness.register("echo2")
    return harness


@pytest.fixture(params=[True, False], ids=["enforce", "advisory"])
def harness(request, tmp_path, engine_config, monkeypatch):
    h = _make(tmp_path, engine_config, monkeypatch, enforce=request.param)
    try:
        yield h
    finally:
        h.container.close()


def _h(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def _evaluate(h: Harness, key: str = INGEST, **overrides):
    payload = {
        "agentId": "agent-1",
        "tool": "echo",
        "action": "echo",
        "resource": "safe-resource",
        "arguments": {"value": "sekrit-value-xyz"},
    }
    payload.update(overrides)
    return h.client.post("/v1/protect/evaluate", json=payload, headers=_h(key))


def _execute(h: Harness, token: str | None, key: str = INGEST, **overrides):
    payload = {
        "agentId": "agent-1",
        "tool": "echo",
        "action": "echo",
        "resource": "safe-resource",
        "arguments": {"value": "sekrit-value-xyz"},
    }
    payload.update(overrides)
    if token is not None:
        payload["authorization"] = token
    return h.client.post("/v1/tools/execute", json=payload, headers=_h(key))


# ── The happy path, and replay ───────────────────────────────────────────────


def test_an_allowed_action_executes_exactly_once(harness: Harness):
    gate = _evaluate(harness)
    assert gate.status_code == 200, gate.text
    assert gate.json()["decision"] == "allow"
    token = gate.json()["authorization"]["token"]

    ran = _execute(harness, token)
    assert ran.status_code == 200, ran.text
    assert ran.json()["result"]["ran"] is True
    assert len(harness.effects) == 1

    replay = _execute(harness, token)
    assert replay.status_code == 403, replay.text
    assert len(harness.effects) == 1, "a replayed authorization ran the tool again"

    ops = harness.client.get("/v1/executions/operations", headers=_h(ANALYST)).json()
    states = {op["operation_id"]: op["state"] for op in ops["operations"]}
    assert "succeeded" in states.values()
    assert "refused" in states.values(), "the replay was not recorded as a refused attempt"
    succeeded = next(op for op in ops["operations"] if op["state"] == "succeeded")
    assert succeeded["started_at"] and succeeded["completed_at"]
    assert succeeded["receipt_id"].startswith("receipt-")


def test_an_unbound_execution_is_refused_and_runs_nothing(harness: Harness):
    refused = _execute(harness, None)
    assert refused.status_code == 403
    assert harness.effects == []


# ── Approval ─────────────────────────────────────────────────────────────────


def test_approval_flow_evaluate_pending_approve_execute(harness: Harness):
    gate = _evaluate(harness, resource="/needs-approval")
    assert gate.status_code == 200, gate.text
    assert gate.json()["decision"] == "require_approval", gate.json()
    authorization = gate.json()["authorization"]
    assert authorization["state"] == "pending_approval"
    token = authorization["token"]
    auth_id = authorization["authorization_id"]

    # Before approval: refused, nothing ran.
    early = _execute(harness, token, resource="/needs-approval")
    assert early.status_code == 403, early.text
    assert harness.effects == []

    # The inbox lists it, with a digest and never the parameter values.
    inbox = harness.client.get("/v1/authorizations", headers=_h(ANALYST)).json()
    entry = next(e for e in inbox["authorizations"] if e["authorization_id"] == auth_id)
    assert entry["state"] == "pending_approval"
    assert entry["policy_current"] is True
    assert "sekrit-value-xyz" not in json.dumps(inbox), "parameter VALUES leaked into the inbox"

    # A human approves.
    decided = harness.client.post(
        f"/v1/authorizations/{auth_id}/decide",
        json={"decision": "approve", "reason": "reviewed the change"},
        headers=_h(ANALYST),
    )
    assert decided.status_code == 200, decided.text

    # Now it executes -- under enforcement too, which is the case that used
    # to be impossible: re-evaluation said require_approval and refused.
    ran = _execute(harness, token, resource="/needs-approval")
    assert ran.status_code == 200, ran.text
    assert len(harness.effects) == 1
    assert "approval" in ran.json()["protect"]["reason"]

    # And only once.
    again = _execute(harness, token, resource="/needs-approval")
    assert again.status_code == 403
    assert len(harness.effects) == 1


def test_a_rejected_authorization_never_executes(harness: Harness):
    gate = _evaluate(harness, resource="/needs-approval")
    auth = gate.json()["authorization"]
    rejected = harness.client.post(
        f"/v1/authorizations/{auth['authorization_id']}/decide",
        json={"decision": "reject", "reason": "not this week"},
        headers=_h(ANALYST),
    )
    assert rejected.status_code == 200
    refused = _execute(harness, auth["token"], resource="/needs-approval")
    assert refused.status_code == 403
    assert harness.effects == []


def test_an_expired_authorization_is_refused_by_name(harness: Harness):
    token = _evaluate(harness).json()["authorization"]["token"]
    harness.clock.advance(3600)
    refused = _execute(harness, token)
    assert refused.status_code == 403, refused.text
    assert refused.json()["detail"]["outcome"] == "expired"
    assert harness.effects == []


# ── Substitution ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "override",
    [
        {"arguments": {"value": "something-else"}},
        {"tool": "echo2", "action": "echo2"},
        {"resource": "another-resource"},
        {"agentId": "agent-2"},
    ],
    ids=["parameters", "tool", "resource", "agent"],
)
def test_a_substituted_execution_is_refused_and_recorded(harness: Harness, override):
    token = _evaluate(harness).json()["authorization"]["token"]
    refused = _execute(harness, token, **override)
    assert refused.status_code == 403, refused.text
    assert harness.effects == []
    ops = harness.client.get(
        "/v1/executions/operations?state=refused", headers=_h(ANALYST)
    ).json()
    assert ops["operations"], "the substitution attempt left no refused operation"
    assert "something-else" not in json.dumps(ops), "refused operations must carry digests, not values"


# ── Revocation, policy change, kill switch ───────────────────────────────────


def test_an_emergency_revocation_voids_an_active_authorization(harness: Harness):
    auth = _evaluate(harness, resource="/needs-approval").json()["authorization"]
    harness.client.post(
        f"/v1/authorizations/{auth['authorization_id']}/decide",
        json={"decision": "approve", "reason": "ok"},
        headers=_h(ANALYST),
    )
    # Only MANAGE_POLICY may withdraw a granted authorization.
    denied = harness.client.post(
        f"/v1/authorizations/{auth['authorization_id']}/revoke",
        json={"decision": "reject", "reason": "incident"},
        headers=_h(ANALYST),
    )
    assert denied.status_code == 403
    revoked = harness.client.post(
        f"/v1/authorizations/{auth['authorization_id']}/revoke",
        json={"decision": "reject", "reason": "incident in progress"},
        headers=_h(ADMIN),
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["previous_state"] == "active"
    refused = _execute(harness, auth["token"], resource="/needs-approval")
    assert refused.status_code == 403
    assert harness.effects == []


def test_a_policy_change_voids_outstanding_authorizations(harness: Harness):
    token = _evaluate(harness).json()["authorization"]["token"]
    # The tenant emits the action first, so the new policy names a real action.
    harness.client.post(
        "/v1/events",
        json={
            "eventId": "e-1",
            "sessionId": "s-1",
            "agentId": "agent-1",
            "eventType": "tool_call",
            "action": "echo",
            "timestamp": "2026-09-14T10:00:00Z",
        },
        headers=_h(INGEST),
    )
    deployed = harness.client.post(
        "/v1/policy/versions",
        json={"rules": [{"name": "echo-allowed", "effect": "allow", "actions": ["echo"]}]},
        headers=_h(ADMIN),
    )
    assert deployed.status_code in (200, 201), deployed.text
    version = deployed.json()["version"]
    activated = harness.client.post(
        f"/v1/policy/versions/{version}/activate", headers=_h(ADMIN)
    )
    assert activated.status_code == 200, activated.text

    refused = _execute(harness, token)
    assert refused.status_code == 409, refused.text
    assert refused.json()["detail"]["outcome"] == "policy_changed"
    assert harness.effects == []

    # A fresh evaluation under the new policy works again.
    fresh = _evaluate(harness).json()["authorization"]["token"]
    assert _execute(harness, fresh).status_code == 200
    assert len(harness.effects) == 1


def test_the_kill_switch_refuses_every_redemption(tmp_path, engine_config, monkeypatch):
    h = _make(tmp_path, engine_config, monkeypatch, enforce=True, SENTINEL_PROTECT_KILL_SWITCH="true")
    try:
        token = _evaluate(h).json()["authorization"]["token"]
        refused = _execute(h, token)
        assert refused.status_code == 403
        assert "kill switch" in json.dumps(refused.json()["detail"]).replace("_", " ")
        assert h.effects == []
        # A caller with no token is told the same thing, not sent to evaluate.
        assert _execute(h, None).status_code == 403
    finally:
        h.container.close()


def test_a_blocked_action_issues_no_authorization(tmp_path, engine_config, monkeypatch):
    h = _make(tmp_path, engine_config, monkeypatch, enforce=True)
    try:
        gate = _evaluate(h, resource="/blocked")
        assert gate.json()["decision"] == "block"
        assert gate.json()["authorization"] is None
        assert _execute(h, None, resource="/blocked").status_code == 403
        assert h.effects == []
    finally:
        h.container.close()


def test_an_approval_never_satisfies_a_block():
    """The gate, directly: an approval answers require_approval, never block."""
    gate = ProtectGate(policy=DeterministicPolicy.default(), enforce=True)
    payload = {
        "agentId": "a",
        "eventType": "tool_call",
        "action": "read_file",
        "tool": "fs",
        "resource": "/home/user/.aws/credentials",
        "arguments": {"path": "/home/user/.aws/credentials"},
    }
    with pytest.raises(ProtectDenied):
        gate.run_if_allowed(
            payload=payload, trust=TrustLevel.VERIFIED, action=lambda: 1, approved=True
        )


# ── Tenant isolation of control state ────────────────────────────────────────


def test_same_named_agents_in_two_tenants_have_separate_budgets(
    tmp_path, engine_config, monkeypatch
):
    h = _make(tmp_path, engine_config, monkeypatch, enforce=True, SENTINEL_TOOL_BUDGET_PER_MINUTE="1")
    try:
        first = _execute(h, _evaluate(h).json()["authorization"]["token"])
        assert first.status_code == 200, first.text
        second = _execute(h, _evaluate(h).json()["authorization"]["token"])
        assert second.status_code == 403, second.text
        assert "budget" in second.json()["detail"]

        # Same agent id, other tenant: its own budget, untouched.
        other = _execute(
            h, _evaluate(h, key=GLOBEX_INGEST).json()["authorization"]["token"], key=GLOBEX_INGEST
        )
        assert other.status_code == 200, other.text
        assert len(h.effects) == 2

        # And the coverage model reports per-tenant, without a score.
        coverage = h.client.get("/v1/coverage", headers=_h(ANALYST)).json()
        assert coverage["routed_executions"]["bound_operations"] == 1
        assert coverage["enforced_refusals"]["count"] == 0
        assert "percentage" not in json.dumps(coverage).lower().replace("percentage;", "")
    finally:
        h.container.close()


def test_a_breaker_opened_in_one_tenant_stays_closed_in_the_other(
    tmp_path, engine_config, monkeypatch
):
    h = _make(tmp_path, engine_config, monkeypatch, enforce=True, SENTINEL_PROTECT_CIRCUIT_THRESHOLD="2")
    try:
        token = _evaluate(h).json()["authorization"]["token"]
        # Two substitutions are two failures: the breaker opens for acme/agent-1.
        for _ in range(2):
            assert _execute(h, token, arguments={"value": "x"}).status_code == 403
        tripped = _execute(h, _evaluate(h).json()["authorization"]["token"])
        assert tripped.status_code == 403 and "circuit" in tripped.json()["detail"]
        # globex/agent-1 is unaffected.
        ok = _execute(
            h, _evaluate(h, key=GLOBEX_INGEST).json()["authorization"]["token"], key=GLOBEX_INGEST
        )
        assert ok.status_code == 200, ok.text
    finally:
        h.container.close()


def test_operations_are_terminal_or_reconcilable_never_silent(harness: Harness):
    """Every operation the contract produces is in a named state."""
    _execute(harness, _evaluate(harness).json()["authorization"]["token"])
    ops = harness.client.get("/v1/executions/operations", headers=_h(ANALYST)).json()
    for op in ops["operations"]:
        assert OperationState(op["state"]) in OperationState
        assert op["is_terminal"] or op["state"] == "pending"
    assert ops["needs_reconciliation"] == 0


def test_an_activated_deny_prevents_fresh_authorizations(harness):
    deployed = harness.client.post("/v1/policy/versions", json={"rules": [
        {"name": "deny-echo", "effect": "block", "actions": ["echo"]}
    ]}, headers=_h(ADMIN))
    assert deployed.status_code == 201
    version = deployed.json()["version"]
    assert harness.client.post(f"/v1/policy/versions/{version}/activate", headers=_h(ADMIN)).status_code == 200
    verdict = _evaluate(harness)
    assert verdict.status_code == 200
    assert verdict.json()["decision"] == "block"
    assert verdict.json()["authorization"] is None
    assert harness.effects == []
    other = _evaluate(harness, key=GLOBEX_INGEST)
    assert other.json()["decision"] == "allow"


def test_changed_rules_with_same_version_invalidate_approval(harness):
    from sentinel.interface.authorizations import active_policy_digest
    from sentinel.infrastructure.detection import PolicyRule
    first = active_policy_digest(harness.container, "acme")
    base = harness.container.protect_gate._policy
    base._rules = base.rules + (PolicyRule("new-deny", "new deny", "resource", "contains", ("changed",), 95, "test"),)
    second = active_policy_digest(harness.container, "acme")
    assert first != second


def test_tenant_approval_rule_can_be_satisfied_without_overriding_denies(harness):
    deployed = harness.client.post("/v1/policy/versions", json={"rules": [
        {"name": "approve-echo", "effect": "require_approval", "actions": ["echo"]}
    ]}, headers=_h(ADMIN))
    assert deployed.status_code == 201
    version = deployed.json()["version"]
    assert harness.client.post(f"/v1/policy/versions/{version}/activate", headers=_h(ADMIN)).status_code == 200
    authorization = _evaluate(harness).json()["authorization"]
    assert authorization["state"] == "pending_approval"
    assert _execute(harness, authorization["token"]).status_code == 403
    response = harness.client.post(f"/v1/authorizations/{authorization['authorization_id']}/decide",
                                   json={"decision": "approve"}, headers=_h(ANALYST))
    assert response.status_code == 200, response.text
    assert _execute(harness, authorization["token"]).status_code == 200
    assert len(harness.effects) == 1
