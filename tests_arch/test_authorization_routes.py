"""HTTP authorization issuance and redemption for bound execution."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sentinel.composition.container import build_container
from sentinel.composition.settings import Settings
from sentinel.domain.attestation import AttestationDisposition
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.interface.http import create_app
from tests_arch.doubles import FakeAttestationGateway, FakeClock

INGEST_KEY = "auth-ingest-key-that-is-long-enough-for-production"
ANALYST_KEY = "auth-analyst-key-that-is-long-enough-for-production"


@pytest.fixture
def app(tmp_path: Path, engine_config, monkeypatch):
    """The real app with a temporary policy file, not the missing checkout one."""
    import sentinel.infrastructure.detection as detection

    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "policy_id": "authorization-route-test",
                "version": "1",
                "rules": [
                    {
                        "id": "approval-required-resource",
                        "description": "approval resource",
                        "field": "resource",
                        "mode": "contains",
                        "values": ["/needs-approval"],
                        "severity": 90,
                        "incident_type": "test",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(detection, "DEFAULT_POLICY_PATH", policy)

    settings = Settings.from_environment(
        {
            "SENTINEL_ENV": "development",
            "SENTINEL_DB_PATH": str(tmp_path / "authorizations.db"),
            "SENTINEL_API_KEYS": (
                f"acme:{INGEST_KEY}:ingest,"
                f"acme:{ANALYST_KEY}:analyst"
            ),
            "SENTINEL_CORS_ORIGINS": "https://console.example.com",
            "SENTINEL_PROTECT_ENFORCE": "false",
        }
    )
    from dataclasses import replace

    settings = replace(settings, engine=engine_config)
    pool = build_engine(settings.engine)
    try:
        migrate(pool)
        with pool.acquire() as conn:
            conn.begin()
            conn.execute_rowcount(
                f"INSERT INTO tenants (tenant_id, name, created_at) "
                f"VALUES ({conn.p},{conn.p},{conn.p})",
                ("acme", "Acme", "2026-09-11T00:00:00+00:00"),
            )
            conn.commit()
    finally:
        pool.close()

    container = build_container(
        settings,
        clock=FakeClock(),
        attestation=FakeAttestationGateway(
            disposition=AttestationDisposition.ANCHORED
        ),
    )
    try:
        yield TestClient(create_app(container), raise_server_exceptions=False)
    finally:
        container.close()


def _auth_headers(key: str = INGEST_KEY) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def _evaluate(client: TestClient, **overrides):
    payload = {
        "agentId": "agent-1",
        "tool": "echo",
        "action": "echo",
        "resource": "safe-resource",
        "arguments": {"value": "approved"},
    }
    payload.update(overrides)
    return client.post(
        "/v1/protect/evaluate", json=payload, headers=_auth_headers()
    )


def test_protect_evaluate_issues_an_authorization_that_execute_redeems(app):
    issued = _evaluate(app)
    assert issued.status_code == 200, issued.text
    authorization = issued.json()["authorization"]
    assert authorization["state"] == "active"
    assert authorization["tool_identity"] == "echo"

    executed = app.post(
        "/v1/tools/execute",
        json={
            "agentId": "agent-1",
            "tool": "echo",
            "action": "echo",
            "resource": "safe-resource",
            "arguments": {"value": "approved"},
            "authorization": authorization["token"],
        },
        headers=_auth_headers(),
    )
    assert executed.status_code == 200, executed.text
    body = executed.json()
    assert body["result"] == {"echo": {"value": "approved"}}
    assert body["receipt"]["authorization_digest"] == authorization["digest"]


def test_execute_refuses_when_arguments_do_not_match_the_authorization(app):
    authorization = _evaluate(app).json()["authorization"]
    refused = app.post(
        "/v1/tools/execute",
        json={
            "agentId": "agent-1",
            "tool": "echo",
            "action": "echo",
            "resource": "safe-resource",
            "arguments": {"value": "changed"},
            "authorization": authorization["token"],
        },
        headers=_auth_headers(),
    )
    assert refused.status_code == 403
    assert "does not match its authorization" in refused.text


def test_require_approval_authorization_activates_only_after_decision(app):
    issued = _evaluate(app, resource="/needs-approval")
    assert issued.status_code == 200, issued.text
    authorization = issued.json()["authorization"]
    assert authorization["state"] == "pending_approval"

    pending = app.post(
        "/v1/tools/execute",
        json={
            "agentId": "agent-1",
            "tool": "echo",
            "action": "echo",
            "resource": "/needs-approval",
            "arguments": {"value": "approved"},
            "authorization": authorization["token"],
        },
        headers=_auth_headers(),
    )
    assert pending.status_code == 403
    assert "awaiting approval" in pending.text

    decided = app.post(
        f"/v1/authorizations/{authorization['authorization_id']}/decide",
        json={"decision": "approve", "reason": "ticket-1"},
        headers=_auth_headers(ANALYST_KEY),
    )
    assert decided.status_code == 200, decided.text
    assert decided.json()["state"] == "active"

    executed = app.post(
        "/v1/tools/execute",
        json={
            "agentId": "agent-1",
            "tool": "echo",
            "action": "echo",
            "resource": "/needs-approval",
            "arguments": {"value": "approved"},
            "authorization": authorization["token"],
        },
        headers=_auth_headers(),
    )
    assert executed.status_code == 200, executed.text
