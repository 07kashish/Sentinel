"""These routes exist because five domain modules had no callers at all.

`ai_bom`, `exposure_graph`, `transparency`, `attack_campaign` and the GitHub
discovery connector were written, tested and committed with ZERO references
from anywhere else in the system. Every test passed and no operator could
reach any of them.

This repository's own history names that failure -- "Phase 4 shipped five
correct components of which four were unreachable, and every unit test passed
throughout". So these tests drive the REAL app through a real client: a unit
test of a route function would have passed for the unreachable version too.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sentinel.composition.container import build_container
from sentinel.composition.settings import Settings
from sentinel.infrastructure.sql.engine import Dialect, build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.interface.http import create_app

TENANT = "acme"
INGEST_KEY = "estate-ingest-00000000000000000000"
VIEW_KEY = "estate-viewer-00000000000000000000"


@pytest.fixture()
def client(engine_config):
    """Parametrised over BOTH engines, per the architecture rule.

    `tests_arch/conftest.py` explains why that is not optional: the retention
    sweep once passed on SQLite while deleting nothing on PostgreSQL, and a
    SQLite-only test cannot see that class of bug. These routes read through
    `inventory.list_profiles`, which is SQL, so the rule applies squarely.
    """
    env = {
        "SENTINEL_ENV": "development",
        "SENTINEL_API_KEYS": (
            f"{TENANT}:{INGEST_KEY}:ingest,{TENANT}:{VIEW_KEY}:viewer"
        ),
        # Off by default, and correctly so -- a production deployment should
        # not publish its own attack surface. Enabled here because a test that
        # asserts a route is discoverable has to look at the document where
        # discovery happens.
        "SENTINEL_EXPOSE_API_DOCS": "true",
    }
    if engine_config.dialect is Dialect.POSTGRES:
        env["SENTINEL_DATABASE_URL"] = engine_config.dsn
        env["SENTINEL_DB_POOL_MIN"] = "1"
        env["SENTINEL_DB_POOL_MAX"] = "4"
    else:
        env["SENTINEL_DB_PATH"] = engine_config.dsn

    settings = Settings.from_environment(env)
    pool = build_engine(settings.engine)
    migrate(pool)
    pool.close()

    container = build_container(settings)
    try:
        with container.pool.acquire() as conn:
            conn.begin()
            conn.execute_rowcount(
                f"INSERT INTO tenants (tenant_id, name, created_at) "
                f"VALUES ({conn.p},{conn.p},{conn.p}) "
                f"ON CONFLICT (tenant_id) DO NOTHING",
                (TENANT, "Acme", "2026-09-03T00:00:00+00:00"),
            )
            conn.commit()
        yield TestClient(create_app(container), raise_server_exceptions=False)
    finally:
        container.close()


def _ingest(client, **overrides):
    event = {
        "eventId": "e1",
        "sessionId": "s1",
        "agentId": "worker",
        "eventType": "tool_call",
        "action": "read_file",
        "resource": "customers",
        "timestamp": "2026-09-03T10:00:00Z",
    }
    event.update(overrides)
    return client.post(
        "/v1/events",
        json=event,
        headers={"Authorization": f"Bearer {INGEST_KEY}"},
    )


def _view(client, path):
    return client.get(path, headers={"Authorization": f"Bearer {VIEW_KEY}"})


# ── reachability: the whole reason this file exists ─────────────────────────


@pytest.mark.parametrize(
    "path",
    [
        "/v1/estate/ai-bom",
        "/v1/estate/ai-bom/cyclonedx",
        "/v1/estate/exposure",
        "/v1/estate/adoption",
    ],
)
def test_every_new_capability_is_actually_reachable(client, path):
    """A route that returns 404 is a capability nobody has.

    Driven through the real app rather than by calling the route function,
    because calling the function would have passed for the unreachable version
    too.
    """
    response = _view(client, path)

    assert response.status_code == 200, (
        f"{path} returned {response.status_code}; the capability is not wired"
    )


def test_the_reach_route_is_reachable(client):
    response = _view(client, "/v1/estate/exposure/reach/worker?target=customers")

    assert response.status_code == 200


def test_the_routes_appear_in_the_openapi_document(client):
    """So they are discoverable rather than folklore."""
    paths = client.get("/openapi.json").json()["paths"]

    for path in (
        "/v1/estate/ai-bom",
        "/v1/estate/ai-bom/cyclonedx",
        "/v1/estate/exposure",
    ):
        assert path in paths, f"{path} is missing from the OpenAPI document"


# ── authorization ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "path",
    ["/v1/estate/ai-bom", "/v1/estate/exposure"],
)
def test_an_unauthenticated_caller_is_refused(client, path):
    assert client.get(path).status_code in {401, 403}


def test_an_ingest_credential_cannot_read_the_estate(client):
    """An ingest key writes events. It must not be able to enumerate the
    estate, or a compromised agent credential becomes a reconnaissance tool.
    """
    response = client.get(
        "/v1/estate/ai-bom", headers={"Authorization": f"Bearer {INGEST_KEY}"}
    )

    assert response.status_code == 403


# ── the honesty properties, over HTTP ────────────────────────────────────────


def test_the_ai_bom_leads_with_its_completeness_verdict(client):
    """A reader who stops after two lines must not stop before the line that
    says whether to trust the rest.
    """
    body = _view(client, "/v1/estate/ai-bom").json()

    assert next(iter(body)) == "completeness"


def test_the_ai_bom_from_this_build_is_never_complete(client):
    """Only one source is consulted here, so COMPLETE would be a claim that
    there are no models, servers or skills anywhere else in the estate.
    """
    assert _ingest(client).status_code == 202

    body = _view(client, "/v1/estate/ai-bom").json()

    assert body["completeness"] != "complete"
    assert body["sources"][0]["coverage"]["unreachable"], (
        "the single-source limitation is not recorded, so an empty document "
        "would read as a clean estate"
    )


def test_the_ai_bom_names_what_it_did_not_consult(client):
    """"Coverage partial" is a shrug. The reason has to say which sources were
    not read, or nobody can act on it.
    """
    body = _view(client, "/v1/estate/ai-bom").json()
    reason = body["sources"][0]["coverage"]["unreachable"][0]["reason"]

    for missing in ("Cloud accounts", "model", "repositories"):
        assert missing.lower() in reason.lower()


def test_an_empty_estate_reports_unusable_rather_than_complete(client):
    """No events ingested, so `examined` is zero -- and a denominator of zero
    makes no absence informative.

    `unusable` rather than `partial` is the stronger and more honest answer: it
    says the document knows NOTHING about this estate, which is different from
    "we saw part of it". I first asserted `partial` here and the module was
    right; a zero denominator is not a partial measurement, it is the absence
    of one.
    """
    body = _view(client, "/v1/estate/ai-bom").json()

    assert body["component_count"] == 0
    assert body["completeness"] == "unusable"
    # `limits` explains how to read an unusable document. Checked here because
    # this is the one verdict a reader is most likely to skim past.
    assert "UNUSABLE" in body["limits"]


def test_observing_one_agent_moves_the_verdict_from_unusable_to_partial(client):
    """The distinction that matters: "we have no idea" versus "we saw part".

    Both produce a document; only one of them supports any conclusion, and a
    reader has to be able to tell which they are holding.
    """
    before = _view(client, "/v1/estate/ai-bom").json()["completeness"]
    assert _ingest(client).status_code == 202
    after = _view(client, "/v1/estate/ai-bom").json()["completeness"]

    assert before == "unusable"
    assert after == "partial"


def test_an_observed_agent_appears_in_the_ai_bom(client):
    """The route must actually read stored state, not return a fixed shape."""
    assert _ingest(client).status_code == 202

    body = _view(client, "/v1/estate/ai-bom").json()

    identifiers = [c["identifier"] for c in body["components"]]
    assert "worker" in identifiers


def test_an_observed_credential_becomes_a_bom_component(client):
    """The link a permission system cannot show: which credential an agent's
    traffic arrived under.
    """
    assert _ingest(client, credentialRef="cred-abc").status_code == 202

    body = _view(client, "/v1/estate/ai-bom").json()
    kinds = {c["kind"] for c in body["components"]}

    assert "agent" in kinds


def test_nothing_from_this_build_is_ever_attested(client):
    """Nothing binds a digest to what ran. OBSERVED is the strongest honest
    level, and claiming more would make the provenance census fiction.
    """
    assert _ingest(client).status_code == 202

    body = _view(client, "/v1/estate/ai-bom").json()

    assert body["provenance_census"]["attested"] == 0


def test_the_cyclonedx_export_admits_it_is_unvalidated(client):
    """Over HTTP, where a procurement team will actually receive it."""
    body = _view(client, "/v1/estate/ai-bom/cyclonedx").json()
    properties = {p["name"]: p["value"] for p in body["metadata"]["properties"]}

    assert body["specVersion"] == "1.6"
    assert properties["sentinel:schema_validated"] == "false"
    # `unusable` on an empty estate, `partial` once something is observed.
    # Either way it is never `complete`, which is the claim that would matter.
    assert properties["sentinel:completeness"] in {"unusable", "partial"}


# ── the exposure graph, over HTTP ────────────────────────────────────────────


def test_the_exposure_graph_leads_with_coverage(client):
    body = _view(client, "/v1/estate/exposure").json()

    assert next(iter(body)) == "coverage"
    assert body["coverage"]["is_partial"] is True


def test_the_graph_records_that_it_sees_observed_traffic_only(client):
    """An agent holding a grant it never exercised has no edge here. Unsaid,
    the absence of a path reads as isolation.
    """
    body = _view(client, "/v1/estate/exposure").json()
    reason = body["coverage"]["unscanned"][0]["reason"]

    assert "OBSERVED" in reason
    assert "never exercised" in reason


def test_an_ingested_event_becomes_an_edge(client):
    assert _ingest(client).status_code == 202

    body = _view(client, "/v1/estate/exposure").json()

    assert body["edge_count"] > 0
    assert all(e["basis"] == "observed" for e in body["edges"])


def test_a_negative_reach_answer_from_this_build_is_unknown_not_isolated(client):
    """THE property. This build sees observed traffic only, so it cannot
    assert that nothing connects two things -- and "not_reachable" is the most
    reassuring thing a graph can say.
    """
    assert _ingest(client).status_code == 202

    body = _view(
        client, "/v1/estate/exposure/reach/worker?target=nothing-like-this"
    ).json()

    assert body["verdict"] == "unknown"
    assert body["path"] is None


def test_a_positive_reach_answer_is_reachable_and_carries_its_path(client):
    """A found path needs no caveat: partial coverage cannot invent one."""
    assert _ingest(client).status_code == 202

    body = _view(client, "/v1/estate/exposure/reach/worker?target=customers").json()

    assert body["verdict"] == "reachable"
    assert body["path"]["nodes"][0] == "worker"


def test_the_reach_response_states_why_a_negative_is_unknown(client):
    body = _view(client, "/v1/estate/exposure/reach/a?target=b").json()

    assert "unknown" in body["limits"]
    assert "unexercised grant" in body["limits"]


def test_the_reach_route_requires_a_target(client):
    """A reachability question with no destination is not a question."""
    response = _view(client, "/v1/estate/exposure/reach/worker")

    assert response.status_code == 422


def test_the_verdict_is_a_string_and_not_a_status_code(client):
    """Encoding the verdict as 200-vs-404 would collapse the three-valued
    answer into a boolean at the HTTP layer, which is exactly what the domain
    refuses to do.
    """
    for target in ("customers", "nothing-like-this"):
        response = _view(client, f"/v1/estate/exposure/reach/worker?target={target}")
        assert response.status_code == 200
        assert response.json()["verdict"] in {
            "reachable",
            "not_reachable",
            "unknown",
        }


# ── tenant isolation ─────────────────────────────────────────────────────────


def test_the_estate_is_scoped_to_the_credential_and_not_the_request(client):
    """Tenant comes from the credential. A route that accepted it from a query
    string would let any key read any estate.
    """
    assert _ingest(client).status_code == 202

    body = _view(client, "/v1/estate/ai-bom").json()

    assert body["tenant"] == TENANT
    assert body["sources"][0]["coverage"]["scope"] == [f"tenant:{TENANT}"]


# ── the node-kind mapping must stay total ────────────────────────────────────


def test_every_observed_edge_kind_has_an_exposure_node_kind():
    """A new edge kind falling through to RESOURCE would make it invisible to
    every credential-sharing question, silently.
    """
    from sentinel.domain.inventory import ObservedEdgeKind
    from sentinel.interface.estate_routes import _NODE_KIND

    missing = [kind for kind in ObservedEdgeKind if kind not in _NODE_KIND]
    assert not missing, f"unmapped observed edge kinds: {missing}"


def test_a_credential_edge_maps_to_a_credential_node():
    """The mapping that makes `principals_sharing` work at all."""
    from sentinel.domain.exposure_graph import NodeKind
    from sentinel.domain.inventory import ObservedEdgeKind
    from sentinel.interface.estate_routes import _NODE_KIND

    assert _NODE_KIND[ObservedEdgeKind.CREDENTIAL] is NodeKind.CREDENTIAL


def test_the_attack_campaign_is_deliberately_not_served(client):
    """It is a build-time artifact bound to a commit. Serving it from a running
    process would let a reader mistake "the campaign passed on some build" for
    "the campaign passed on THIS build".
    """
    paths = client.get("/openapi.json").json()["paths"]

    assert not any("campaign" in path for path in paths)


# ── the adoption funnel, over HTTP ───────────────────────────────────────────


def test_an_untouched_tenant_reports_unknown_rather_than_zero_usage(client):
    """"Nothing connected" and "connected and idle" are the same counts and
    opposite facts. A funnel that scored this as 0% would point a decision the
    wrong way.
    """
    body = _view(client, "/v1/estate/adoption").json()

    assert body["stage"] == "unknown"
    assert "NOT a measurement of zero usage" in body["evidence"]


def test_one_ingested_event_moves_the_tenant_onto_the_funnel(client):
    assert _ingest(client).status_code == 202

    body = _view(client, "/v1/estate/adoption").json()

    assert body["stage"] in {"ingesting", "detecting"}
    assert body["counts"]["agents_observed"] == 1


def test_the_route_names_the_counts_it_did_not_measure(client):
    """THE honesty property for this route.

    Passing the raised count as the triaged count would report a 100% triage
    rate for a tenant that has opened nothing -- the most flattering error
    this funnel could make. Zero plus a named gap is the honest alternative.
    """
    body = _view(client, "/v1/estate/adoption").json()
    gaps = " ".join(body["counts_not_measured_by_this_build"])

    assert "incidents_triaged" in gaps
    assert "100% triage" in gaps
    assert "containments_activated" in gaps
    assert "observation_window_days" in gaps


def test_no_engagement_rate_is_quoted_when_the_window_is_unknown(client):
    """A rate over an unknown period is not a rate."""
    body = _view(client, "/v1/estate/adoption").json()

    assert body["engagement_rate"] is None
    assert body["rate_refusal_reason"]


def test_an_ingest_credential_cannot_read_the_adoption_funnel(client):
    """Which agents exist and how often they act is the most sensitive
    telemetry in a security deployment.
    """
    response = client.get(
        "/v1/estate/adoption", headers={"Authorization": f"Bearer {INGEST_KEY}"}
    )

    assert response.status_code == 403
