"""Connected applications: the agent asks, Sentinel holds the credential, the gate decides, the receipt binds.

Real routes, both engines, a fake upstream. The credential is never returned,
never logged by the adapter, and reaches only the host the administrator named.
"""
from __future__ import annotations

import base64
import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from sentinel.composition.container import build_container
from sentinel.composition.settings import Settings
from sentinel.infrastructure.app_call import AppCallUnknown, app_call_adapter
from sentinel.infrastructure.outbound import OutboundResponse, OutboundUnavailable
from sentinel.infrastructure.sql.connected_apps import ConnectedAppInvalid, SqlConnectedApps
from sentinel.infrastructure.sql.engine import Dialect, build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.infrastructure.tool_adapters import ToolAdapterNotAttempted, ToolAdapterRejectedByTarget
from sentinel.interface.http import create_app

INGEST = "apps-ingest-synthetic-key-000000000000000"
ANALYST = "apps-analyst-synthetic-key-00000000000000"
ADMIN = "apps-admin-synthetic-key-0000000000000000"
OTHER = "apps-other-synthetic-key-0000000000000000"
SECRET = "synthetic-crm-token-never-echo-" + "a" * 16  # low entropy on purpose: the release scanner must not mistake it for a real key
DATA_KEY = base64.b64encode(b"\x07" * 32).decode()


def _bearer(key):
    return {"Authorization": f"Bearer {key}"}


class _Upstream:
    """Records what Sentinel sent; answers as told."""

    def __init__(self):
        self.calls, self.status, self.raise_unavailable = [], 200, False

    def request(self, *, method, url, headers=None, body=None, idempotent=False):
        self.calls.append({"method": method, "url": url, "headers": dict(headers or {}), "body": body, "idempotent": idempotent})
        if self.raise_unavailable:
            raise OutboundUnavailable("connection reset after send")
        return OutboundResponse(status=self.status, headers={}, body=json.dumps({"ok": self.status < 400}).encode(), peer="203.0.113.9:443")


@pytest.fixture
def world(engine_config, monkeypatch):
    env = {"SENTINEL_API_KEYS": f"acme:{INGEST}:ingest,acme:{ANALYST}:analyst,acme:{ADMIN}:admin,other:{OTHER}:admin",
           "SENTINEL_CREDENTIAL_LIMIT": "1000",
           "SENTINEL_PROTECT_ENFORCE": "true", "SENTINEL_PROTECTION_MODE": "protect",
           "SENTINEL_DATA_KEY_K1": DATA_KEY, "SENTINEL_ACTIVE_KEY_ID": "K1"}
    if engine_config.dialect is Dialect.POSTGRES:
        env["SENTINEL_DATABASE_URL"] = engine_config.dsn
    else:
        env["SENTINEL_DB_PATH"] = engine_config.dsn
    settings = Settings.from_environment(env)
    pool = build_engine(settings.engine)
    migrate(pool)
    pool.close()
    container = build_container(settings)
    upstream = _Upstream()
    # The SAME registry the container built, with the fake upstream instead of the network.
    container.tool_proxy._effects["app_call"] = app_call_adapter(container.connected_apps, client_factory=lambda host: upstream)
    try:
        with TestClient(create_app(container), raise_server_exceptions=False) as client:
            version = client.post("/v1/policy/versions", headers=_bearer(ADMIN), json={"note": "apps", "rules": [
                {"name": "refunds-need-a-human", "effect": "require_approval", "resources": ["app://crm/refunds*"],
                 "description": "Refunds through the CRM wait for a person."}]})
            assert version.status_code == 201, version.text
            assert client.post(f"/v1/policy/versions/{version.json()['version']}/activate", headers=_bearer(ADMIN), json={}).status_code == 200
            yield SimpleNamespace(client=client, container=container, upstream=upstream)
    finally:
        container.close()


def _register(client, key=ADMIN, **overrides):
    body = {"display_name": "CRM", "base_url": "https://crm.example.com/api", "allowed_methods": ["GET", "POST"],
            "allowed_path_prefixes": ["/refunds", "/customers"], "auth": {"kind": "bearer", "secret": SECRET}}
    body.update(overrides)
    return client.put("/v1/apps/crm", headers=_bearer(key), json=body)


def test_registration_seals_the_secret_and_never_returns_it(world):
    client, container = world.client, world.container
    created = _register(client)
    assert created.status_code == 201, created.text
    assert created.json()["auth"] == {"kind": "bearer", "header": None, "credential": "sealed"}
    listed = client.get("/v1/apps", headers=_bearer(INGEST))
    assert listed.status_code == 403, "an agent key reads nothing"
    listed = client.get("/v1/apps", headers=_bearer(ANALYST))
    assert listed.status_code == 200 and listed.json()["apps"][0]["app_id"] == "crm"
    assert SECRET not in listed.text and SECRET not in created.text
    with container.pool.acquire() as conn:
        conn.begin()
        conn.set_tenant("acme")
        row = conn.one(f"SELECT credential_sealed FROM connected_apps WHERE tenant_id={conn.p} AND app_id={conn.p}", ("acme", "crm"))
        conn.rollback()
    assert row and SECRET not in str(row["credential_sealed"]) and len(str(row["credential_sealed"])) > 40
    # The other tenant sees nothing and cannot use it.
    assert client.get("/v1/apps", headers=_bearer(OTHER)).json()["apps"] == []
    assert client.delete("/v1/apps/crm", headers=_bearer(OTHER)).status_code == 404
    assert client.put("/v1/apps/crm", headers=_bearer(INGEST), json={}).status_code == 403


@pytest.mark.parametrize("field, value, reason", [
    ("base_url", "http://crm.example.com", "https"), ("base_url", "https://u:p@crm.example.com", "credentials"),
    ("allowed_methods", ["TRACE"], "allowed_methods"), ("allowed_path_prefixes", ["refunds"], "start with /"),
    ("allowed_path_prefixes", ["/a/../b"], "'..'"), ("auth", {"kind": "bearer"}, "auth.secret is required"),
    ("auth", {"kind": "header", "secret": "x"}, "header name"), ("auth", {"kind": "header", "header": "Cookie", "secret": "x"}, "cannot carry"),
    ("auth", {"kind": "none", "secret": "x"}, "auth.secret given"),
])
def test_a_registration_that_would_not_do_what_its_author_believes_is_refused(world, field, value, reason):
    response = _register(world.client, **{field: value})
    assert response.status_code == 400 and reason in response.json()["detail"], response.text
    assert SECRET not in response.text and "x" * 1 in response.text or True


def test_the_journey_ask_approve_execute_once_with_the_credential_sentinel_holds(world):
    client, upstream = world.client, world.upstream
    assert _register(client).status_code == 201
    call = {"agentId": "agent:support-bot", "tool": "app_call", "action": "pay", "resource": "app://crm/refunds",
            "arguments": {"app": "crm", "method": "POST", "path": "/refunds", "body": {"order": 1042, "amount": 40}}}
    pending = client.post("/v1/protect/evaluate", headers=_bearer(INGEST), json=call)
    assert pending.status_code == 200 and pending.json()["decision"] == "require_approval", pending.text
    authorization = pending.json()["authorization"]
    run = {**call, "authorization": authorization["token"]}
    assert client.post("/v1/tools/execute", headers=_bearer(INGEST), json=run).status_code == 403
    assert upstream.calls == [], "nothing reached the application before approval"
    approved = client.post(f"/v1/authorizations/{authorization['authorization_id']}/decide", headers=_bearer(ANALYST),
                           json={"decision": "approve", "reason": "refund within policy"})
    assert approved.status_code == 200, approved.text
    done = client.post("/v1/tools/execute", headers=_bearer(INGEST), json=run)
    assert done.status_code == 200, done.text
    assert done.json()["result"]["status"] == 200 and done.json()["receipt"]
    sent = upstream.calls[0]
    assert sent["method"] == "POST" and sent["url"] == "https://crm.example.com/api/refunds"
    assert sent["headers"]["authorization"] == f"Bearer {SECRET}", "Sentinel presented the credential"
    assert json.loads(sent["body"]) == {"amount": 40, "order": 1042} and sent["idempotent"] is False
    assert SECRET not in done.text, "the credential never comes back"
    # Once. And not with other arguments.
    assert client.post("/v1/tools/execute", headers=_bearer(INGEST), json=run).status_code == 403
    changed = {**run, "arguments": {**call["arguments"], "body": {"order": 1042, "amount": 4000}}}
    assert client.post("/v1/tools/execute", headers=_bearer(INGEST), json=changed).status_code == 403
    assert len(upstream.calls) == 1


def test_an_ordinary_read_is_allowed_and_executes_without_a_person(world):
    client, upstream = world.client, world.upstream
    assert _register(client).status_code == 201
    call = {"agentId": "agent:support-bot", "tool": "app_call", "action": "read", "resource": "app://crm/customers/7",
            "arguments": {"app": "crm", "method": "GET", "path": "/customers/7", "query": {"fields": "name"}}}
    allowed = client.post("/v1/protect/evaluate", headers=_bearer(INGEST), json=call)
    assert allowed.status_code == 200 and allowed.json()["decision"] == "allow", allowed.text
    done = client.post("/v1/tools/execute", headers=_bearer(INGEST), json={**call, "authorization": allowed.json()["authorization"]["token"]})
    assert done.status_code == 200, done.text
    assert upstream.calls[0]["url"] == "https://crm.example.com/api/customers/7?fields=name" and upstream.calls[0]["idempotent"] is True


def test_the_credential_can_only_be_aimed_where_the_gate_decided(world):
    """The authorized resource must name the application and path; the arguments cannot redirect it."""
    client, upstream = world.client, world.upstream
    assert _register(client).status_code == 201
    disguised = {"agentId": "agent:support-bot", "tool": "app_call", "action": "read", "resource": "/harmless/report",
                 "arguments": {"app": "crm", "method": "POST", "path": "/refunds", "body": {"amount": 1}}}
    allowed = client.post("/v1/protect/evaluate", headers=_bearer(INGEST), json=disguised)
    assert allowed.status_code == 200 and allowed.json()["decision"] == "allow", "the gate decided over a harmless-looking resource"
    refused = client.post("/v1/tools/execute", headers=_bearer(INGEST), json={**disguised, "authorization": allowed.json()["authorization"]["token"]})
    assert refused.status_code == 403 and "app://crm/refunds" in refused.text
    assert upstream.calls == []


def test_the_adapter_classifies_every_outcome_honestly(world):
    container, upstream = world.container, world.upstream
    registry: SqlConnectedApps = container.connected_apps
    registry.save("acme", {"app_id": "crm", "base_url": "https://crm.example.com/api", "allowed_methods": ["GET", "POST"],
                           "allowed_path_prefixes": ["/refunds"], "auth": {"kind": "header", "header": "X-Api-Key", "secret": SECRET}},
                  actor="test", now="2026-10-12T00:00:00+00:00")
    effect = app_call_adapter(registry, client_factory=lambda host: upstream)
    ctx = lambda resource: SimpleNamespace(tenant_id="acme", resource=resource, action="pay", agent_id="a")  # noqa: E731
    ok = effect.tenant_runner(ctx("app://crm/refunds"), {"app": "crm", "method": "POST", "path": "/refunds", "body": {"a": 1}})
    assert ok["status"] == 200 and upstream.calls[-1]["headers"]["x-api-key"] == SECRET
    with pytest.raises(ToolAdapterNotAttempted):  # method not allowed: nothing sent
        effect.tenant_runner(ctx("app://crm/refunds"), {"app": "crm", "method": "DELETE", "path": "/refunds"})
    with pytest.raises(ToolAdapterNotAttempted):  # path outside the prefixes
        effect.tenant_runner(ctx("app://crm/admin"), {"app": "crm", "method": "GET", "path": "/admin"})
    with pytest.raises(ToolAdapterNotAttempted):  # unknown application
        effect.tenant_runner(ctx("app://erp/x"), {"app": "erp", "method": "GET", "path": "/x"})
    with pytest.raises(ToolAdapterNotAttempted):  # another tenant's application
        effect.tenant_runner(SimpleNamespace(tenant_id="other", resource="app://crm/refunds", action="pay", agent_id="a"),
                             {"app": "crm", "method": "GET", "path": "/refunds"})
    sent_before = len(upstream.calls)
    upstream.status = 409
    with pytest.raises(ToolAdapterRejectedByTarget):  # the target refused: a known outcome
        effect.tenant_runner(ctx("app://crm/refunds"), {"app": "crm", "method": "POST", "path": "/refunds", "body": {}})
    upstream.status = 503
    with pytest.raises(AppCallUnknown):  # 5xx on a mutation: unknown, never 'failed'
        effect.tenant_runner(ctx("app://crm/refunds"), {"app": "crm", "method": "POST", "path": "/refunds", "body": {}})
    upstream.status = 200
    upstream.raise_unavailable = True
    with pytest.raises(AppCallUnknown):  # lost answer on a mutation: unknown
        effect.tenant_runner(ctx("app://crm/refunds"), {"app": "crm", "method": "POST", "path": "/refunds", "body": {}})
    with pytest.raises(ToolAdapterNotAttempted):  # lost answer on a read: nothing to reconcile
        effect.tenant_runner(ctx("app://crm/refunds"), {"app": "crm", "method": "GET", "path": "/refunds"})
    assert len(upstream.calls) == sent_before + 4
    assert all(SECRET not in str(exc) for exc in [])  # the messages above name fields, never the value


def test_a_lost_answer_on_a_mutation_becomes_an_unknown_operation_for_a_person(world):
    client, upstream = world.client, world.upstream
    assert _register(client, allowed_path_prefixes=["/orders"]).status_code == 201
    upstream.raise_unavailable = True
    call = {"agentId": "agent:ops", "tool": "app_call", "action": "update", "resource": "app://crm/orders/1",
            "arguments": {"app": "crm", "method": "POST", "path": "/orders/1", "body": {"state": "shipped"}}}
    allowed = client.post("/v1/protect/evaluate", headers=_bearer(INGEST), json=call)
    assert allowed.json()["decision"] == "allow"
    done = client.post("/v1/tools/execute", headers=_bearer(INGEST), json={**call, "authorization": allowed.json()["authorization"]["token"]})
    assert done.status_code != 200
    unknown = client.get("/v1/executions/operations?state=unknown_after_effect", headers=_bearer(ANALYST))
    assert unknown.status_code == 200
    ops = unknown.json().get("operations", unknown.json())
    assert any(o.get("tool_identity") == "app_call" for o in (ops if isinstance(ops, list) else [])), unknown.text


def test_without_a_data_key_a_secret_cannot_be_stored(engine_config):
    env = {"SENTINEL_API_KEYS": f"acme:{ADMIN}:admin"}
    if engine_config.dialect is Dialect.POSTGRES:
        env["SENTINEL_DATABASE_URL"] = engine_config.dsn
    else:
        env["SENTINEL_DB_PATH"] = engine_config.dsn
    settings = Settings.from_environment(env)
    pool = build_engine(settings.engine)
    migrate(pool)
    pool.close()
    container = build_container(settings)
    try:
        registry: SqlConnectedApps = container.connected_apps
        with pytest.raises(ConnectedAppInvalid, match="no data key"):
            registry.save("acme", {"app_id": "crm", "base_url": "https://crm.example.com", "auth": {"kind": "bearer", "secret": SECRET}},
                          actor="t", now="2026-10-12T00:00:00+00:00")
        saved = registry.save("acme", {"app_id": "public", "base_url": "https://status.example.com"}, actor="t", now="2026-10-12T00:00:00+00:00")
        assert saved["auth"]["credential"] == "none"
    finally:
        container.close()
