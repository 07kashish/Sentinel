"""The analysis surface: reachable, read-only, and honest about its inputs.

WHY THESE ROUTES CAME BEFORE ANY CONSOLE PAGE
-----------------------------------------------
`mcp_estate` and `blast_radius` compute findings nothing else in the system can,
and nothing could reach them. A capability with no HTTP surface is a capability
an operator does not have, and a console page cannot call what does not exist.

THE TWO HONEST-INPUT PROBLEMS THESE TESTS HOLD
------------------------------------------------
Both endpoints are missing a data source this build does not have, and both say
so in their response rather than approximating.

Shadow-server detection needs per-server usage; this build records MCP calls in
the execution graph instead. Passing an approximation would make
`unused_enrolment` fire for every server and `shadow_server` for none — a report
confidently wrong in both directions.

Blast radius needs declared asset sensitivity; there is no declaration store. The
caller supplies declarations, and `coverage` reports how much of the estate they
actually covered — so a request with none returns score 0 AND coverage 0, which
reads as "nobody has classified this", not "this agent is safe".
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sentinel.composition.container import build_container
from sentinel.composition.settings import Settings
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.interface.http import create_app

KEY = "k" * 40


def _settings_for(engine_config) -> Settings:
    """This module's keys on whichever backend the parametrisation selected."""
    env = {
        "SENTINEL_ENV": "development",
        "SENTINEL_API_KEYS": f"acme:{KEY}:admin",
    }
    if engine_config.dialect.name == "POSTGRES":
        env["SENTINEL_DATABASE_URL"] = engine_config.dsn
        env["SENTINEL_DB_POOL_MIN"] = "1"
        env["SENTINEL_DB_POOL_MAX"] = "4"
    else:
        env["SENTINEL_DB_PATH"] = engine_config.dsn
    return Settings.from_environment(env)


@pytest.fixture
def client(engine_config):
    """A real container on a migrated database, on BOTH engines.

    Parametrised rather than SQLite-only because everything these routes report
    is read back out of SQL. `list_servers` and `list_grants` are the two calls
    that feed them, and a reader that returns rows on SQLite and nothing under
    PostgreSQL's row-level security would make both endpoints answer "no
    findings" -- the failure mode that is indistinguishable from a clean estate.
    """
    settings = _settings_for(engine_config)
    pool = build_engine(settings.engine)
    migrate(pool)
    with pool.acquire() as conn:
        conn.begin()
        conn.execute_rowcount(
            f"INSERT INTO tenants (tenant_id, name, created_at) "
            f"VALUES ({conn.p},{conn.p},{conn.p})",
            ("acme", "Acme", "2026-08-30T12:00:00+00:00"),
        )
        conn.commit()
    pool.close()

    container = build_container(settings)
    try:
        yield TestClient(create_app(container)), container
    finally:
        container.close()


def _auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {KEY}"}


# ── the routes exist and are reachable ───────────────────────────────────────


def test_the_mcp_estate_is_reachable(client):
    http, _container = client
    response = http.get("/v1/analysis/mcp-estate", headers=_auth())
    assert response.status_code == 200
    assert "findings" in response.json()


def test_blast_radius_is_reachable(client):
    http, _container = client
    response = http.post(
        "/v1/analysis/blast-radius/finance-agent",
        headers=_auth(),
        json={"declarations": []},
    )
    assert response.status_code == 200
    assert "score" in response.json()


def test_both_routes_require_a_capability(client):
    http, _container = client
    assert http.get("/v1/analysis/mcp-estate").status_code == 401
    assert (
        http.post(
            "/v1/analysis/blast-radius/a", json={"declarations": []}
        ).status_code
        == 401
    )


# ── the estate view says what it could not see ───────────────────────────────


def test_the_estate_view_says_where_its_usage_data_comes_from_and_what_it_cannot_see(client):
    """With no proxied traffic it finds nothing, and says that is not an all-clear."""
    http, _container = client
    body = http.get("/v1/analysis/mcp-estate", headers=_auth()).json()
    assert body["observed_servers"] == 0
    assert "THROUGH Sentinel's proxy" in body["observed_source"]
    assert "not that none exist" in body["observed_source"]


def test_a_refused_call_to_an_unenrolled_server_is_reported_as_a_shadow_server(client):
    """The proxy audits the calls it REFUSES. That row is what a shadow server
    looks like from here, and it used to be thrown away by passing observed=()."""
    from sentinel.infrastructure.persistence.audit import Outcome
    from sentinel.domain.primitives import TenantId

    http, container = client
    for agent in ("agent-a", "agent-a", "agent-b"):
        container.security_audit.record(
            tenant=TenantId("acme"), actor="key:test", action="mcp.proxy", resource_type="mcp_server",
            resource_id="never-enrolled-server", outcome=Outcome.DENIED,
            detail={"agent_id": agent, "reason": "server_not_enrolled"},
        )
    body = http.get("/v1/analysis/mcp-estate", headers=_auth()).json()
    assert body["observed_servers"] == 1
    shadows = [f for f in body["findings"] if f["kind"] == "shadow_mcp_server"]
    assert shadows and "never-enrolled-server" in str(shadows[0])
    assert http.get("/v1/analysis/mcp-estate?days=0", headers=_auth()).status_code == 422


def test_a_cross_server_collision_is_reported_through_the_route(client):
    """The finding that motivated `mcp_estate`, end to end."""
    from sentinel.domain.mcp import McpServerIdentity, McpServerTrust

    http, container = client
    registry = container.mcp_registry
    for server_id in ("trusted-fs", "newcomer"):
        identity = McpServerIdentity(
            tenant_id="acme",
            server_id=server_id,
            endpoint=f"https://{server_id}.internal",
            trust=McpServerTrust.ENROLLED,
        )
        registry.record(identity)
        registry.pin(identity, {"read_file": "f" * 64})

    body = http.get("/v1/analysis/mcp-estate", headers=_auth()).json()
    kinds = {f["kind"] for f in body["findings"]}
    assert "cross_server_tool_collision" in kinds


def test_the_estate_view_changes_nothing(client):
    """It reports collisions; it does not block them. A collision between two
    legitimately enrolled servers is a configuration problem, and blocking both
    would take out the trusted one alongside the impostor.
    """
    from sentinel.domain.mcp import McpServerIdentity, McpServerTrust

    http, container = client
    identity = McpServerIdentity(
        tenant_id="acme",
        server_id="s1",
        endpoint="https://s1.internal",
        trust=McpServerTrust.ENROLLED,
    )
    container.mcp_registry.record(identity)

    http.get("/v1/analysis/mcp-estate", headers=_auth())
    after = container.mcp_registry.lookup("acme", "s1")
    assert after.trust is McpServerTrust.ENROLLED


# ── blast radius is honest about its declarations ────────────────────────────


def test_no_declarations_gives_zero_score_and_zero_coverage(client):
    """THE reading that matters. Score 0 with coverage 0 says "nobody has
    classified this estate", not "this agent is safe".
    """
    http, container = client
    container.agent_capabilities.grant(
        "acme", "finance-agent", frozenset({"db://customers"})
    )

    body = http.post(
        "/v1/analysis/blast-radius/finance-agent",
        headers=_auth(),
        json={"declarations": []},
    ).json()
    assert body["score"] == 0
    assert body["coverage"] == 0.0
    assert "not as 'this agent is safe'" in body["declaration_source"]


def test_a_declared_restricted_asset_raises_the_score(client):
    http, container = client
    container.agent_capabilities.grant(
        "acme", "finance-agent", frozenset({"db://customers"})
    )

    body = http.post(
        "/v1/analysis/blast-radius/finance-agent",
        headers=_auth(),
        json={
            "declarations": [
                {
                    "asset": "db://customers",
                    "sensitivity": "restricted",
                    "declared_by": "alice",
                    "production": True,
                }
            ]
        },
    ).json()
    assert body["score"] > 0
    assert body["coverage"] == 1.0


def test_an_unrecognised_sensitivity_is_reported_not_dropped(client):
    """A silently discarded declaration means an asset the caller believes is
    classified is not, and coverage would then overstate the assessment.
    """
    http, container = client
    container.agent_capabilities.grant(
        "acme", "finance-agent", frozenset({"db://customers"})
    )

    body = http.post(
        "/v1/analysis/blast-radius/finance-agent",
        headers=_auth(),
        json={
            "declarations": [
                {
                    "asset": "db://customers",
                    "sensitivity": "extremely-secret",
                    "declared_by": "alice",
                }
            ]
        },
    ).json()
    assert body["rejected_declarations"]
    assert body["coverage"] == 0.0


def test_a_declaration_without_an_author_is_refused_by_the_schema(client):
    """Sensitivity is declared rather than inferred precisely so somebody is
    accountable. An API that defaulted the author would make every declaration
    anonymous.
    """
    http, _container = client
    response = http.post(
        "/v1/analysis/blast-radius/finance-agent",
        headers=_auth(),
        json={
            "declarations": [
                {"asset": "db://customers", "sensitivity": "restricted"}
            ]
        },
    )
    assert response.status_code == 422


def test_declarations_are_carried_in_the_body_not_the_query_string(client):
    """"Which of our assets are RESTRICTED" is not a sentence that belongs in an
    access log, which is where a query string ends up.
    """
    import inspect

    from sentinel.interface import analysis_routes

    source = inspect.getsource(analysis_routes)
    assert '@app.post("/v1/analysis/blast-radius/{agent_id}")' in source
    assert '@app.get("/v1/analysis/blast-radius' not in source


def test_the_analysis_surface_is_tenant_scoped(client):
    """An analyst reading the estate sees their own tenant's servers. The
    principal supplies the tenant; the request cannot.
    """
    import inspect

    from sentinel.interface import analysis_routes

    source = inspect.getsource(analysis_routes)
    assert 'tenant = str(principal.tenant)' in source
    assert "tenant_id=body" not in source
