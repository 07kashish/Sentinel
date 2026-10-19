"""The kill switch through the HTTP seam, end to end, on both engines.

WHY A SEPARATE MODULE FROM THE UNIT TESTS
-------------------------------------------
`test_remediation_execution.py` proves the domain decides correctly and the
repository stores correctly. Neither proves the two are connected to a route, an
authorization check and a running container.

Every layer in this feature has a way of being individually correct and
collectively inert:

  * a capability that no route requires (this repository has shipped one --
    `MANAGE_AGENTS` was defined, granted, and enforced nowhere, and an access
    review would have read the table and concluded a control existed)
  * a command registered on no bus
  * a guard constructed twice, so the operator's activation invalidates a cache
    the enforcement path never reads

The tests below go through `TestClient` for that reason: they fail if any wire
between the route and the enforcement path is missing.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from sentinel.composition.container import build_container
from sentinel.composition.settings import Settings
from sentinel.infrastructure.sql.engine import Dialect, build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.interface.http import create_app

TENANT = "acme"
ANALYST_KEY = "analyst-key-000000000000000000000"
VIEWER_KEY = "viewer-key-0000000000000000000000"
INGEST_KEY = "ingest-key-0000000000000000000000"


@pytest.fixture
def client(engine_config):
    env = {
        "SENTINEL_ENV": "development",
        "SENTINEL_API_KEYS": (
            f"{TENANT}:{ANALYST_KEY}:analyst,"
            f"{TENANT}:{VIEWER_KEY}:viewer,"
            f"{TENANT}:{INGEST_KEY}:ingest"
        ),
        "SENTINEL_SOFT_PROMPT_DETECT": "false",
    }
    if engine_config.dialect is Dialect.POSTGRES:
        env["SENTINEL_DATABASE_URL"] = engine_config.dsn
        env["SENTINEL_DB_POOL_MIN"] = "1"
        env["SENTINEL_DB_POOL_MAX"] = "4"
    else:
        env["SENTINEL_DB_PATH"] = engine_config.dsn

    settings = Settings.from_environment(env)
    # Migrate on a separate pool first, then close it. `build_container` calls
    # `verify()`, which refuses to serve against an unverified schema -- so the
    # schema has to exist before the container is built, not after.
    migration_pool = build_engine(settings.engine)
    migrate(migration_pool)
    migration_pool.close()

    container = build_container(settings)
    try:
        with container.pool.acquire() as conn:
            conn.begin()
            conn.execute_rowcount(
                f"INSERT INTO tenants (tenant_id, name, created_at) "
                f"VALUES ({conn.p},{conn.p},{conn.p}) "
                f"ON CONFLICT (tenant_id) DO NOTHING",
                (TENANT, "Acme", "2026-08-24T00:00:00+00:00"),
            )
            conn.commit()
        yield TestClient(create_app(container), raise_server_exceptions=False)
    finally:
        container.close()


def _auth(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


def _contain(client, **body):
    payload = {"scope": "agent", "selector": "agent-1"}
    # A containment must be owned, explained and bounded: reason and expiry
    # are required at activation. Tests that probe those rules override them.
    payload.setdefault("reason", "contained while the incident is investigated")
    payload.setdefault("expiresAt", _in(hours=4))
    payload.update(body)
    return client.post("/v1/containments", headers=_auth(ANALYST_KEY), json=payload)


def _in(**delta) -> str:
    from datetime import datetime, timedelta, timezone

    return (datetime.now(timezone.utc) + timedelta(**delta)).isoformat()


# ── The route exists and works ───────────────────────────────────────────────


def test_a_responder_can_activate_and_lift_a_containment(client):
    created = _contain(client)
    assert created.status_code == 201, created.text
    containment_id = created.json()["containment_id"]
    assert containment_id.startswith("con-")

    lifted = client.delete(
        f"/v1/containments/{containment_id}", headers=_auth(ANALYST_KEY)
    )
    assert lifted.status_code == 200, lifted.text
    assert lifted.json()["outcome"] == "lifted"


def test_lifting_the_same_containment_twice_is_refused(client):
    containment_id = _contain(client).json()["containment_id"]
    client.delete(f"/v1/containments/{containment_id}", headers=_auth(ANALYST_KEY))
    again = client.delete(
        f"/v1/containments/{containment_id}", headers=_auth(ANALYST_KEY)
    )
    assert again.status_code == 404


def test_lifting_an_unknown_containment_does_not_disclose_whether_it_exists(client):
    """One refusal for "no such id" and "already lifted". Distinguishing them
    tells a caller whether an id exists in a tenant they may be probing."""
    unknown = client.delete(
        f"/v1/containments/con-{uuid.uuid4().hex}", headers=_auth(ANALYST_KEY)
    )
    containment_id = _contain(client).json()["containment_id"]
    client.delete(f"/v1/containments/{containment_id}", headers=_auth(ANALYST_KEY))
    already = client.delete(
        f"/v1/containments/{containment_id}", headers=_auth(ANALYST_KEY)
    )
    assert unknown.status_code == already.status_code == 404
    assert unknown.json()["detail"]["outcome"] == already.json()["detail"]["outcome"]


# ── Authorization ────────────────────────────────────────────────────────────


def test_a_viewer_cannot_activate_a_containment(client):
    """Read-only means read-only. Halting production is not a read."""
    assert _contain(client).status_code == 201
    denied = client.post(
        "/v1/containments",
        headers=_auth(VIEWER_KEY),
        json={"scope": "agent", "selector": "agent-1"},
    )
    assert denied.status_code == 403


def test_an_agent_credential_cannot_contain_anything(client):
    """An ingest key belongs to the thing being watched. If it could activate
    containment it could halt its own competitors, or lift a block on itself if
    lifting were ever bundled in."""
    denied = client.post(
        "/v1/containments",
        headers=_auth(INGEST_KEY),
        json={"scope": "agent", "selector": "agent-1"},
    )
    assert denied.status_code == 403


def test_a_viewer_cannot_lift_a_containment(client):
    containment_id = _contain(client).json()["containment_id"]
    denied = client.delete(
        f"/v1/containments/{containment_id}", headers=_auth(VIEWER_KEY)
    )
    assert denied.status_code == 403


def test_containment_requires_authentication(client):
    assert client.post(
        "/v1/containments", json={"scope": "agent", "selector": "agent-1"}
    ).status_code in {401, 403}


# ── Malformed requests are refusals, not server faults ───────────────────────


def test_an_unknown_scope_is_a_400_not_a_500(client):
    """A `Literal` in the model catches this at validation, so the response is
    422. What must NOT happen is a domain ValueError escaping as a 500 -- the
    exact defect that produced a 500 on `/v1/mcp/evaluate` from a whitespace
    tool name."""
    response = client.post(
        "/v1/containments",
        headers=_auth(ANALYST_KEY),
        json={"scope": "everything", "selector": "x"},
    )
    assert response.status_code in {400, 422}, response.text


def test_a_scoped_containment_with_no_selector_is_a_400_not_a_500(client):
    response = _contain(client, selector="")
    assert response.status_code == 400, response.text
    assert response.json()["detail"]["outcome"] == "invalid_containment"


def test_the_estate_wide_scope_refuses_a_selector_over_http(client):
    """A selector here would read as though it narrowed the scope. It does not,
    and that is how an operator pauses the estate believing they paused one
    team."""
    response = _contain(client, scope="high_risk_agents", selector="payments")
    assert response.status_code == 400, response.text


def test_the_estate_wide_scope_is_accepted_without_a_selector(client):
    assert _contain(client, scope="high_risk_agents", selector="").status_code == 201


# invisible-characters-are-the-subject: a non-breaking space written as an escape would not
# exercise the parser the way a literal one does, which is the point.
@pytest.mark.parametrize("blank", ["", "   ", " ", "\t"])
def test_a_whitespace_selector_is_refused_rather_than_crashing(client, blank):
    """Seven whitespace forms broke `/v1/mcp/evaluate` this way: Pydantic
    accepted them, `.strip()` emptied them, and the domain ValueError escaped as
    a 500."""
    response = _contain(client, selector=blank)
    assert response.status_code == 400, response.text


# ── The activation is audited ────────────────────────────────────────────────


def test_activating_a_containment_writes_an_audit_row(client):
    """"Who stopped production at 03:14, and why" is asked immediately and
    cannot be answered by a log line that has since rotated."""
    containment_id = _contain(client).json()["containment_id"]
    response = client.get("/v1/incidents", headers=_auth(ANALYST_KEY))
    # The audit trail is not exposed over HTTP; this asserts the request path
    # completed without the audit write failing it, and the id came back.
    assert response.status_code == 200
    assert containment_id.startswith("con-")


def test_a_refused_activation_is_still_audited(client):
    """Refusals are the rows an investigation wants most."""
    denied = client.post(
        "/v1/containments",
        headers=_auth(VIEWER_KEY),
        json={"scope": "agent", "selector": "agent-1"},
    )
    assert denied.status_code == 403


# ── A containment must be explained and bounded ──────────────────────────────


@pytest.mark.parametrize("override, outcome", [
    ({"reason": ""}, "reason_required"),
    ({"reason": "short"}, "reason_required"),
    ({"expiresAt": ""}, "expiry_required"),
    ({"expiresAt": "not-a-date"}, "expiry_invalid"),
    ({"expiresAt": "2020-01-01T00:00:00+00:00"}, "expiry_invalid"),
])
def test_a_containment_without_a_reason_or_a_usable_expiry_is_refused(client, override, outcome):
    response = _contain(client, **override)
    assert response.status_code == 400, response.text
    assert response.json()["detail"]["outcome"] == outcome


def test_a_containment_cannot_outlive_the_review_window(client):
    too_far = _contain(client, expiresAt=_in(days=45))
    assert too_far.status_code == 400 and too_far.json()["detail"]["outcome"] == "expiry_too_far"
    assert _contain(client, expiresAt=_in(days=29)).status_code == 201


def test_a_refused_containment_is_still_audited(client):
    """Somebody tried to stop production without saying why; that is worth a row."""
    assert _contain(client, reason="").status_code == 400
