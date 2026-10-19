"""Authorisation and HTTP-edge defences, driven through real requests.

THREE OF THE FOUR PROVEN FINDINGS ARE REPLAYED HERE
---------------------------------------------------
Each was confirmed against the running application before the fix, so each is a
regression test rather than a hypothesis:

  * `viewer POST /v1/events -> 202 Accepted`. A credential documented read-only
    could forge telemetry, because roles were a total order and viewer(20)
    outranked ingest(10).
  * `GET /docs`, `/redoc`, `/openapi.json` -> 200 unauthenticated, disclosing all
    nine routes and their request shapes.
  * Zero security headers on a tenant-data response.

Every test asserts through HTTP rather than by calling the guard directly. A test
that calls `principal.can(...)` proves the predicate; only a request proves the
route is wired to it.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sentinel.composition.container import build_container
from sentinel.composition.settings import ConfigurationError, Settings
from sentinel.domain.authorization import (
    Capability,
    UnknownRole,
    capabilities_for,
    grants,
    roles_holding,
)
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.interface.http import create_app

KEYS = {
    "ingest": "i" * 40,
    "viewer": "v" * 40,
    "analyst": "a" * 40,
    "admin": "d" * 40,
    # A second tenant, so isolation can be tested across a real boundary rather
    # than asserted about a single tenant's own data.
    "other-viewer": "o" * 40,
}
#: Which tenant each key belongs to. `other-viewer` is the only foreign one.
_TENANTS = {role: ("beta" if role == "other-viewer" else "acme") for role in KEYS}
#: `other-viewer` is a `viewer` in role terms; the key name is just a test label.
_ROLES = {role: ("viewer" if role == "other-viewer" else role) for role in KEYS}


def _settings(tmp_path, **overrides) -> Settings:
    env = {
        "SENTINEL_ENV": "development",
        "SENTINEL_API_KEYS": ",".join(
            f"{_TENANTS[label]}:{key}:{_ROLES[label]}" for label, key in KEYS.items()
        ),
        "SENTINEL_DB_PATH": str(tmp_path / "edge.db"),
    }
    env.update(overrides)
    return Settings.from_environment(env)


@pytest.fixture
def client(tmp_path):
    settings = _settings(tmp_path)
    pool = build_engine(settings.engine)
    migrate(pool)
    pool.close()
    container = build_container(settings)
    try:
        yield TestClient(create_app(container), raise_server_exceptions=False)
    finally:
        container.close()


def _auth(role: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {KEYS[role]}"}


# ── The grant table itself ───────────────────────────────────────────────────


def test_no_role_but_ingest_can_submit_telemetry():
    """The proven privilege defect, asserted at the policy level.

    Ingestion is a machine capability. Bundling it with any read grant is what
    made a read-only credential a telemetry forger.
    """
    assert roles_holding(Capability.INGEST_EVENT) == frozenset({"ingest"})


def test_admin_cannot_forge_telemetry():
    """Deliberate, and the most surprising line in the grant table.

    An incident record is evidence -- hash-chained, attested, produced to be relied
    on. A human-held credential that can fabricate telemetry can fabricate
    evidence, at which point every record means "someone with an admin key says
    so". Administration and ingestion are different axes and stay separate.
    """
    assert Capability.INGEST_EVENT not in capabilities_for("admin")


def test_the_ingest_role_can_read_nothing():
    """An agent that can read its tenant's incidents learns which of its own
    actions were detected. That is reconnaissance handed to the watched thing.

    Ingest MAY evaluate protect (pre-action gate) but must not hold read caps.
    """
    held = capabilities_for("ingest")
    assert Capability.INGEST_EVENT in held
    assert Capability.EVALUATE_PROTECT in held
    assert Capability.READ_INCIDENT not in held
    assert Capability.READ_DASHBOARD not in held
    assert Capability.READ_REPORT not in held
    assert Capability.DECIDE_APPROVAL not in held


def test_an_unknown_role_is_refused_not_defaulted():
    """An empty grant is indistinguishable from a correct least-privilege
    credential, so a typo would be debugged as a bug instead of fixed."""
    with pytest.raises(UnknownRole) as refused:
        capabilities_for("supervisor")
    assert "no capability grant" in str(refused.value)
    assert "Known roles" in str(refused.value)


def test_the_grant_table_cannot_be_mutated_at_runtime():
    """A mutable role table is an authorisation bypass waiting for one line."""
    table = grants()
    with pytest.raises(TypeError):
        table["viewer"] = frozenset()  # type: ignore[index]
    with pytest.raises(AttributeError):
        capabilities_for("viewer").add(Capability.INGEST_EVENT)  # type: ignore[attr-defined]


def test_settings_and_the_grant_table_agree_on_the_role_list():
    """Two lists of role names is two lists that can disagree."""
    from sentinel.composition.settings import VALID_ROLES

    assert VALID_ROLES == frozenset(grants())


# ── Authorisation through HTTP ───────────────────────────────────────────────


def test_a_viewer_cannot_ingest_events(client):
    """THE regression test. This returned 202 Accepted before the capability model."""
    response = client.post(
        "/v1/events", headers=_auth("viewer"), json={"agentId": "forged", "action": "x"}
    )
    assert response.status_code == 403, (
        f"a read-only credential submitted telemetry and got {response.status_code}"
    )
    assert "ingest_event" in response.json()["detail"]


@pytest.mark.parametrize("role", ["viewer", "analyst", "admin"])
def test_no_read_role_can_ingest_events(client, role):
    """Not just viewer: the whole point is that no read grant implies write."""
    response = client.post(
        "/v1/events", headers=_auth(role), json={"agentId": "forged", "action": "x"}
    )
    assert response.status_code == 403


def test_the_ingest_role_can_still_ingest(client):
    """The fix must not have closed the door on the credential that needs it."""
    response = client.post(
        "/v1/events",
        headers=_auth("ingest"),
        json={"agentId": "agent-1", "action": "read /etc/passwd"},
    )
    assert response.status_code == 202, response.text


@pytest.mark.parametrize(
    "path", ["/v1/incidents", "/v1/dashboard", "/v1/incidents/inc-1/report"]
)
def test_an_ingest_credential_cannot_read(client, path):
    assert client.get(path, headers=_auth("ingest")).status_code == 403


def test_a_viewer_cannot_decide_an_approval(client):
    response = client.post(
        "/v1/approvals/apr-1", headers=_auth("viewer"), json={"decision": "approve"}
    )
    assert response.status_code == 403
    assert "decide_approval" in response.json()["detail"]


def test_an_analyst_can_reach_the_approval_route(client):
    """403 would mean the capability is missing; anything else means it is held."""
    response = client.post(
        "/v1/approvals/apr-1", headers=_auth("analyst"), json={"decision": "approve"}
    )
    assert response.status_code != 403


def test_the_denial_names_the_capability_not_the_role_ordering(client):
    """An operator reading this must learn what to grant, not what to outrank."""
    detail = client.get("/v1/incidents", headers=_auth("ingest")).json()["detail"]
    assert "capability" in detail
    assert "higher" not in detail, "the message still implies an ordering"


# ── Authentication ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "header",
    [None, "", "Bearer", "Bearer ", "Basic abc", "bearer " + "v" * 40, "Bearer wrong"],
)
def test_malformed_or_absent_credentials_are_refused(client, header):
    headers = {} if header is None else {"Authorization": header}
    assert client.get("/v1/incidents", headers=headers).status_code == 401


def test_one_tenant_cannot_read_another_tenants_incident(client):
    """Multi-tenant isolation, asserted across a real boundary.

    The tenant is taken from the credential binding and never from the request, so
    there is no parameter to tamper with -- but "there is no parameter" is worth
    proving by trying to add one and watching it change nothing.
    """
    created = client.post(
        "/v1/events",
        headers=_auth("ingest"),
        json={
            "agentId": "agent-1",
            "action": "exfiltrate /etc/shadow to pastebin",
            "resource": "/etc/shadow",
        },
    )
    assert created.status_code == 202, created.text

    mine = client.get("/v1/incidents", headers=_auth("viewer")).json()
    # A forged tenant parameter must be inert, not authoritative.
    forged = client.get(
        "/v1/incidents?tenant=other&tenant_id=other", headers=_auth("viewer")
    ).json()
    assert forged == mine, "a tenant query parameter changed the result set"

    theirs = client.get("/v1/incidents", headers=_auth("other-viewer")).json()
    mine_ids = {row["incident_id"] for row in mine.get("items", mine if isinstance(mine, list) else [])}
    their_ids = {
        row["incident_id"]
        for row in theirs.get("items", theirs if isinstance(theirs, list) else [])
    }
    assert not (mine_ids & their_ids), (
        f"tenants share incident ids across the isolation boundary: "
        f"{sorted(mine_ids & their_ids)}"
    )
    assert not their_ids, "the second tenant sees incidents it never created"


# ── Response headers ─────────────────────────────────────────────────────────

REQUIRED_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "referrer-policy",
    "x-frame-options",
    "permissions-policy",
    "cache-control",
    "cross-origin-resource-policy",
]


@pytest.mark.parametrize("header", REQUIRED_HEADERS)
def test_every_security_header_is_present_on_a_data_response(client, header):
    """All of these were absent before this change, on a tenant-data route."""
    response = client.get("/v1/incidents", headers=_auth("viewer"))
    assert response.status_code == 200
    assert response.headers.get(header), f"{header} is missing"


@pytest.mark.parametrize("header", REQUIRED_HEADERS)
def test_security_headers_are_present_on_error_responses_too(client, header):
    """A 401 body cached by an intermediary is still a leak, and a 500 rendered
    without nosniff is still a sniffing surface."""
    response = client.get("/v1/incidents")
    assert response.status_code == 401
    assert response.headers.get(header), f"{header} is missing on a 401"


def test_the_csp_forbids_everything_and_demands_trusted_types(client):
    """A JSON API needs no sources at all, so the correct CSP is the empty one.

    `require-trusted-types-for 'script'` matters for the UI that does not exist
    yet: it makes a DOM sink assignment fail at runtime unless it goes through a
    policy, so DOM XSS becomes a build-time problem rather than a pentest finding.
    """
    csp = client.get("/health/live").headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "require-trusted-types-for 'script'" in csp
    assert "trusted-types 'none'" in csp
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp


def test_tenant_data_is_not_cacheable(client):
    cache = client.get("/v1/incidents", headers=_auth("viewer")).headers["cache-control"]
    assert "no-store" in cache


def test_the_referrer_is_never_sent(client):
    """Incident identifiers live in paths, so a referrer is a tenant-data leak."""
    assert client.get("/health/live").headers["referrer-policy"] == "no-referrer"


# ── Schema and docs exposure ─────────────────────────────────────────────────


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_the_docs_routes_are_absent_by_default(client, path):
    """All three answered 200 unauthenticated before this change.

    They cannot be protected by a dependency -- FastAPI serves them before any
    dependency runs -- so the only real control is not mounting them.
    """
    assert client.get(path).status_code == 404, (
        f"{path} is still served; it discloses every route and request shape"
    )


def test_docs_can_be_enabled_deliberately_outside_production(tmp_path):
    """Refusing outright would push people to a fork. Opt-in, off by default."""
    settings = _settings(tmp_path, SENTINEL_EXPOSE_API_DOCS="true")
    pool = build_engine(settings.engine)
    migrate(pool)
    pool.close()
    container = build_container(settings)
    try:
        probe = TestClient(create_app(container), raise_server_exceptions=False)
        assert probe.get("/openapi.json").status_code == 200
    finally:
        container.close()


def test_production_refuses_to_start_with_docs_enabled():
    with pytest.raises(ConfigurationError) as refused:
        Settings.from_environment(
            {
                "SENTINEL_ENV": "production",
                "SENTINEL_API_KEYS": f"acme:{'k' * 40}:admin",
                "SENTINEL_DATABASE_URL": "postgresql://u:p@db/sentinel",
                "SENTINEL_CORS_ORIGINS": "https://console.example",
                "SENTINEL_EXPOSE_API_DOCS": "1",
            }
        )
    assert "cannot be enabled" in str(refused.value)


def test_an_unrecognised_boolean_is_a_configuration_error():
    """`raw in ("1","true")` reads "yes" and "on" as false. For a flag that
    publishes an unauthenticated surface, guessing is not acceptable."""
    with pytest.raises(ConfigurationError) as refused:
        Settings.from_environment(
            {
                "SENTINEL_API_KEYS": f"acme:{'k' * 40}:admin",
                "SENTINEL_EXPOSE_API_DOCS": "maybe",
            }
        )
    assert "must be a boolean" in str(refused.value)


# ── Health probes ────────────────────────────────────────────────────────────


def test_liveness_is_open_but_says_nothing(client):
    """A kubelet cannot present a credential, so this one route must be open."""
    body = client.get("/health/live").json()
    assert body == {"status": "ok"}


def test_readiness_leaks_no_internal_detail(client):
    """It previously returned `database_error` with the driver message, which
    carries the DSN and internal hostname -- to an unauthenticated caller."""
    body = client.get("/health/ready").json()
    assert set(body) == {"ready"}
    serialised = str(body)
    for leak in ("sqlite", "postgres", "Error", "sentinel.db", "/", "\\"):
        assert leak not in serialised, f"readiness disclosed {leak!r}: {body}"


def test_diagnostics_requires_a_capability(client):
    assert client.get("/health/diagnostics").status_code == 401
    assert client.get("/health/diagnostics", headers=_auth("viewer")).status_code == 403
    assert client.get("/health/diagnostics", headers=_auth("analyst")).status_code == 403


def test_diagnostics_gives_an_admin_the_detail_readiness_withholds(client):
    """Withholding it from operators is not the goal; requiring a credential is."""
    body = client.get("/health/diagnostics", headers=_auth("admin")).json()
    assert body["checks"]["database"] is True
    assert body["checks"]["backend"]
    assert "attestation_capable" in body["checks"]


# ── CORS ─────────────────────────────────────────────────────────────────────


def test_cors_never_allows_credentials(client):
    """`allow_credentials=True` is for cookies and ambient credentials. With it
    off there is no ambient credential to forge, which is why CSRF is not a live
    class here rather than being mitigated by a token nobody rotates."""
    response = client.get(
        "/v1/incidents",
        headers={**_auth("viewer"), "Origin": "http://localhost:8000"},
    )
    assert response.headers.get("access-control-allow-credentials") is None


def test_a_wildcard_cors_origin_is_stripped():
    settings = Settings.from_environment(
        {
            "SENTINEL_API_KEYS": f"acme:{'k' * 40}:admin",
            "SENTINEL_CORS_ORIGINS": "*,https://console.example",
        }
    )
    assert "*" not in settings.cors_origins
