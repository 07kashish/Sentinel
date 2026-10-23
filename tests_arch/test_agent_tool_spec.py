"""The OpenAPI tool definition agent platforms import: derived from the app, and true on the real routes."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sentinel.composition.container import build_container
from sentinel.composition.settings import Settings
from sentinel.infrastructure.sql.engine import Dialect, build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.interface.http import create_app

ROOT = Path(__file__).resolve().parent.parent
SPEC = json.loads((ROOT / "docs/integrations/sentinel-agent-tool.openapi.json").read_text(encoding="utf-8"))
INGEST = "spec-ingest-synthetic-key-000000000000000"
ANALYST = "spec-analyst-synthetic-key-00000000000000"
ADMIN = "spec-admin-synthetic-key-0000000000000000"
CHECK = SPEC["paths"]["/v1/protect/evaluate"]["post"]
EXECUTE = SPEC["paths"]["/v1/tools/execute"]["post"]


def _bearer(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


def _body(operation: dict, **values) -> dict:
    """A request carrying ONLY fields the document offers, and all the ones it requires."""
    schema = operation["requestBody"]["content"]["application/json"]["schema"]
    assert set(values) <= set(schema["properties"]), "the test sent a field the document does not offer"
    assert set(schema["required"]) <= set(values)
    return values


def test_the_committed_document_is_what_the_application_yields():
    done = subprocess.run([sys.executable, str(ROOT / "scripts/build_agent_tool_spec.py"), "--check"], capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr[-600:]


def test_the_document_is_importable_and_offers_no_way_to_assert_trust():
    assert SPEC["openapi"] == "3.1.0" and SPEC["servers"][0]["url"].startswith("https://")
    assert SPEC["components"]["securitySchemes"]["sentinelKey"] == {
        "type": "http", "scheme": "bearer", "description": SPEC["components"]["securitySchemes"]["sentinelKey"]["description"]}
    assert CHECK["operationId"] == "checkAction" and EXECUTE["operationId"] == "executeApprovedAction"
    for operation in (CHECK, EXECUTE):
        assert len(operation["description"]) <= 300 and operation["security"] == [{"sentinelKey": []}]
        schema = operation["requestBody"]["content"]["application/json"]["schema"]
        assert schema["additionalProperties"] is False
        assert all(prop.get("description") for prop in schema["properties"].values())
    assert CHECK["x-openai-isConsequential"] is False and EXECUTE["x-openai-isConsequential"] is True
    assert "trustLevel" not in json.dumps(SPEC) and "trust_level" not in json.dumps(SPEC)
    refused = subprocess.run([sys.executable, str(ROOT / "scripts/build_agent_tool_spec.py"), "--server", "http://sentinel.example", "--check"],
                             capture_output=True, text=True, timeout=120)
    assert refused.returncode == 2 and "https" in refused.stderr


@pytest.fixture
def gate(engine_config):
    env = {"SENTINEL_API_KEYS": f"acme:{INGEST}:ingest,acme:{ANALYST}:analyst,acme:{ADMIN}:admin",
           "SENTINEL_CREDENTIAL_LIMIT": "1000",
           "SENTINEL_PROTECT_ENFORCE": "true", "SENTINEL_PROTECTION_MODE": "protect"}
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
        with TestClient(create_app(container), raise_server_exceptions=False) as client:
            version = client.post("/v1/policy/versions", headers=_bearer(ADMIN), json={"note": "spec test", "rules": [
                {"name": "changes-need-a-human", "effect": "require_approval", "resources": ["/protected-change/*"],
                 "description": "Any change under /protected-change/ waits for a person."}]})
            assert version.status_code == 201, version.text
            assert client.post(f"/v1/policy/versions/{version.json()['version']}/activate", headers=_bearer(ADMIN), json={}).status_code == 200
            yield client
    finally:
        container.close()


def test_a_platform_following_the_document_completes_the_journey(gate):
    decisions = set(CHECK["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["decision"]["enum"])
    # An ordinary read: a decision from the documented vocabulary.
    ordinary = gate.post("/v1/protect/evaluate", headers=_bearer(INGEST),
                         json=_body(CHECK, agentId="agent:gpt", tool="echo", action="read", resource="/docs/readme", arguments={"q": "x"}))
    assert ordinary.status_code == 200 and ordinary.json()["decision"] in decisions
    # A protected change, sending EVERY field the document offers.
    change = dict(agentId="agent:gpt", tool="echo", action="update", resource="/protected-change/prod/pricing", arguments={"price": 12})
    pending = gate.post("/v1/protect/evaluate", headers=_bearer(INGEST), json=_body(CHECK, destination="", **change))
    assert pending.status_code == 200 and pending.json()["decision"] == "require_approval"
    authorization = pending.json()["authorization"]
    assert authorization["token"] and authorization["authorization_id"]
    run = _body(EXECUTE, authorization=authorization["token"], **change)
    assert gate.post("/v1/tools/execute", headers=_bearer(INGEST), json=run).status_code == 403, "ran before anyone approved"
    approved = gate.post(f"/v1/authorizations/{authorization['authorization_id']}/decide", headers=_bearer(ANALYST),
                         json={"decision": "approve", "reason": "spec journey"})
    assert approved.status_code == 200, approved.text
    done = gate.post("/v1/tools/execute", headers=_bearer(INGEST), json=run)
    assert done.status_code == 200, done.text
    documented = set(EXECUTE["responses"]["200"]["content"]["application/json"]["schema"]["properties"])
    assert {"tool", "result", "protect", "receipt"} <= documented and done.json()["receipt"]
    assert gate.post("/v1/tools/execute", headers=_bearer(INGEST), json=run).status_code == 403, "the approval ran twice"
    changed = {**run, "arguments": {"price": 9999}}
    assert gate.post("/v1/tools/execute", headers=_bearer(INGEST), json=changed).status_code == 403


def test_no_key_and_an_asserted_trust_are_both_refused(gate):
    body = _body(CHECK, agentId="agent:gpt", tool="echo", action="read")
    assert gate.post("/v1/protect/evaluate", json=body).status_code == 401
    assert gate.post("/v1/protect/evaluate", headers=_bearer(INGEST), json={**body, "trustLevel": "verified"}).status_code == 422


def test_the_older_format_copy_differs_only_in_how_it_says_nullable():
    older = json.loads((ROOT / "docs/integrations/sentinel-agent-tool.openapi-3.0.json").read_text(encoding="utf-8"))
    assert older["openapi"] == "3.0.3" and '"null"' not in json.dumps(older)
    assert set(older["paths"]) == set(SPEC["paths"])
    for path, item in SPEC["paths"].items():
        new, old = item["post"], older["paths"][path]["post"]
        assert old["operationId"] == new["operationId"] and old["description"] == new["description"]
        assert old["requestBody"] == new["requestBody"], "request bodies use no 3.1-only feature and must be identical"
    receipt = older["paths"]["/v1/tools/execute"]["post"]["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["receipt"]
    assert receipt["type"] == "object" and receipt["nullable"] is True
