"""What an approver sees, who may approve, and how many it takes.

An approver shown a digest approves a digest. These tests hold the inbox to:
the exact change with every secret redacted, the affected resource, impact,
the rule that asked, remaining time -- and hold the decision to separation of
duties, a quorum of DISTINCT approvers, and a refusal to record an approval
that could never be redeemed.
"""

from __future__ import annotations

import json

import pytest

from sentinel.domain.change_summary import MAX_FIELDS, summarise_change
from tests_arch.test_execution_contract import ADMIN, ANALYST, INGEST, _evaluate, _execute, _h, _make

# Derived, so no credential-shaped literal sits in the tree for a scanner to find.
SECRET = "hunter2-" + "Zx9Qm4Lp7Vt2" + "Ks8Rw3Ny6Bd1"
CHANGE = {
    "verb": "update", "kind": "deployment", "namespace": "prod", "name": "payments",
    "body": {
        "metadata": {"name": "payments", "namespace": "prod", "uid": "u-123", "resourceVersion": "41"},
        "spec": {"replicas": 3, "template": {"spec": {"containers": [{
            "name": "api", "image": "registry.example/payments:1.4.2",
            "env": [{"name": "DB_PASSWORD", "value": SECRET}],
            "args": ["--token=" + SECRET],
        }]}}},
    },
}


# ── The summary itself ───────────────────────────────────────────────────────


def test_the_summary_shows_the_change_and_none_of_its_secrets():
    summary = summarise_change(tool="kubernetes_api", action="kubernetes_api",
                               resource="deployments/prod/payments", parameters=CHANGE)
    text = json.dumps(summary)
    assert SECRET not in text
    assert summary["headline"] == "update deployment prod/payments"
    assert summary["target_precondition"] == {"uid": "u-123", "resourceVersion": "41"}
    shown = {f["path"]: f["value"] for f in summary["fields"]}
    assert shown["body.spec.replicas"] == "3"
    assert shown["body.spec.template.spec.containers[0].image"] == "registry.example/payments:1.4.2"
    assert shown["body.spec.template.spec.containers[0].env[0].value"].startswith("[redacted str")
    assert shown["body.spec.template.spec.containers[0].args[0]"].startswith("[redacted str")
    assert summary["redacted"] >= 2


@pytest.mark.parametrize("parameters", [
    {"kind": "secret", "verb": "create", "namespace": "prod", "body": {"data": {"tls.key": "c2VjcmV0"}, "stringData": {"p": "x"}}},
    {"config": {"note": "Zx9Qm4Lp7Vt2" + "Ks8Rw3Ny6Bd1Hc5Gj0"}},
    {"headers": {"Authorization": "Bearer abc.def.ghi"}, "url": "https://example.com/a?token=abc"},
])
def test_secret_shaped_values_are_never_displayed(parameters):
    summary = summarise_change(tool="t", action="a", resource="r", parameters=parameters)
    for field in summary["fields"]:
        if field["type"] == "str" and field["path"] not in {"kind", "verb", "namespace"}:
            assert field["value"].startswith("[redacted"), field


def test_a_large_change_is_capped_and_says_so():
    summary = summarise_change(tool="t", action="a", resource="r",
                               parameters={"items": [{"n": i} for i in range(200)]})
    assert len(summary["fields"]) == MAX_FIELDS
    assert summary["fields_total"] == 200 and summary["fields_truncated"] == 200 - MAX_FIELDS


def test_an_unrecognised_action_is_not_described_as_safe():
    summary = summarise_change(tool="custom", action="frobnicate", resource="thing", parameters={"x": 1})
    assert summary["impact"]["tier"] == "unclassified"


# ── The inbox over HTTP ──────────────────────────────────────────────────────


@pytest.fixture
def app(tmp_path, engine_config, monkeypatch):
    harness = _make(tmp_path, engine_config, monkeypatch, enforce=True)
    try:
        yield harness
    finally:
        harness.container.close()


def _pending(harness, **overrides):
    gate = _evaluate(harness, resource="/needs-approval", **overrides)
    assert gate.json()["decision"] == "require_approval", gate.text
    return gate.json()["authorization"]


def test_the_inbox_shows_the_redacted_change_the_reason_and_the_time_left(app):
    auth = _pending(app, arguments={"value": SECRET, "replicas": 3})
    inbox = app.client.get("/v1/authorizations", headers=_h(ANALYST)).json()
    entry = next(e for e in inbox["authorizations"] if e["authorization_id"] == auth["authorization_id"])
    assert SECRET not in json.dumps(inbox) and auth["token"] not in json.dumps(inbox)
    assert {f["path"]: f["value"] for f in entry["change"]["fields"]}["replicas"] == "3"
    assert entry["why"]["policy_decision"] == "require_approval"
    assert "approval-required-resource" in json.dumps(entry["why"]["matched_rules"])
    assert 0 < entry["expires_in_seconds"] <= 300 and entry["policy_current"] is True
    assert entry["approvals"] == {"required": 1, "received": 0, "approvers": [], "remaining": 1}
    detail = app.client.get(f"/v1/authorizations/{auth['authorization_id']}", headers=_h(ANALYST))
    assert detail.status_code == 200 and detail.json()["change"] == entry["change"]


def test_an_expired_request_cannot_be_approved(app):
    auth = _pending(app)
    app.clock.advance(3600)
    refused = app.client.post(f"/v1/authorizations/{auth['authorization_id']}/decide",
                              json={"decision": "approve", "reason": "late"}, headers=_h(ANALYST))
    assert refused.status_code == 409 and refused.json()["detail"]["outcome"] == "expired"


# ── Separation of duties and quorum ──────────────────────────────────────────


def test_the_requester_may_not_approve_their_own_request(app):
    auth = _pending(app, key=ADMIN)          # an admin key asks...
    own = app.client.post(f"/v1/authorizations/{auth['authorization_id']}/decide",
                          json={"decision": "approve", "reason": "mine"}, headers=_h(ADMIN))
    assert own.status_code == 403 and own.json()["detail"]["outcome"] == "separation_of_duties"
    other = app.client.post(f"/v1/authorizations/{auth['authorization_id']}/decide",
                            json={"decision": "approve", "reason": "reviewed"}, headers=_h(ANALYST))
    assert other.status_code == 200 and other.json()["state"] == "active"


def test_a_quorum_needs_distinct_approvers_and_nothing_runs_before_it(tmp_path, engine_config, monkeypatch):
    harness = _make(tmp_path, engine_config, monkeypatch, enforce=True, SENTINEL_APPROVAL_QUORUM="2")
    try:
        auth = _pending(harness)
        url = f"/v1/authorizations/{auth['authorization_id']}/decide"
        first = harness.client.post(url, json={"decision": "approve", "reason": "one"}, headers=_h(ANALYST))
        assert first.status_code == 200, first.text
        assert first.json()["outcome"] == "approval_recorded" and first.json()["approvals"]["remaining"] == 1
        assert _execute(harness, auth["token"], resource="/needs-approval").status_code == 403
        assert harness.effects == [], "a partially approved authorization ran"

        again = harness.client.post(url, json={"decision": "approve", "reason": "twice"}, headers=_h(ANALYST))
        assert again.status_code == 409 and again.json()["detail"]["outcome"] == "already_approved_by_you"

        second = harness.client.post(url, json={"decision": "approve", "reason": "two"}, headers=_h(ADMIN))
        assert second.status_code == 200 and second.json()["state"] == "active"
        assert _execute(harness, auth["token"], resource="/needs-approval").status_code == 200
        assert len(harness.effects) == 1
    finally:
        harness.container.close()


def test_an_ingest_key_cannot_approve(app):
    auth = _pending(app)
    refused = app.client.post(f"/v1/authorizations/{auth['authorization_id']}/decide",
                              json={"decision": "approve", "reason": "self-service"}, headers=_h(INGEST))
    assert refused.status_code == 403
