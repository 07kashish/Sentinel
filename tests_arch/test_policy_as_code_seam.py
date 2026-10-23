"""Policy-as-code and tenant settings through the HTTP seam, on both engines.

WHY THIS EXISTS SEPARATELY FROM THE DOMAIN TESTS
--------------------------------------------------
`test_enterprise_controls.py` proves the rules are right. This proves they are
reachable, authorized, persisted and reversible.

The gap between those two is where Phase 4 spent a full cycle: four components
that were individually correct and collectively inert. The specific things that
can still go wrong here, each with a test below:

  * a policy stored but never activatable, so deployment is one-way
  * a rollback that takes a different code path from deployment and is therefore
    only exercised on the night it is needed
  * a simulation that quietly activates what it was asked to preview
  * `validate` bypassed on one of the two write paths, so a malformed policy
    reaches storage through the door nobody tested
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
ADMIN_KEY = "admin-key-00000000000000000000000"
ANALYST_KEY = "analyst-key-000000000000000000000"


@pytest.fixture
def client(engine_config):
    env = {
        "SENTINEL_ENV": "development",
        "SENTINEL_API_KEYS": (
            f"{TENANT}:{ADMIN_KEY}:admin,{TENANT}:{ANALYST_KEY}:analyst"
        ),
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
                (TENANT, "Acme", "2026-08-24T00:00:00+00:00"),
            )
            conn.commit()
        yield TestClient(create_app(container), raise_server_exceptions=False)
    finally:
        container.close()


def _auth(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


def _document(name: str = "block-exfil", effect: str = "block", **kw) -> dict:
    rule = {
        "name": name,
        "effect": effect,
        "actions": kw.pop("actions", ["read_file"]),
    }
    rule.update(kw)
    return {"rules": [rule], "note": "test"}


def _deploy(client, document=None) -> int:
    response = client.post(
        "/v1/policy/versions", headers=_auth(ADMIN_KEY), json=document or _document()
    )
    assert response.status_code == 201, response.text
    return response.json()["version"]


# ── Validation happens on every write path ───────────────────────────────────


def test_a_valid_policy_validates(client):
    response = client.post(
        "/v1/policy/validate", headers=_auth(ADMIN_KEY), json=_document()
    )
    assert response.status_code == 200, response.text
    assert response.json()["valid"] is True


def test_a_catch_all_block_is_refused_by_validate(client):
    """A rule with no selectors matches every event. As a BLOCK that is an
    estate-wide outage in a document that reviews cleanly."""
    response = client.post(
        "/v1/policy/validate",
        headers=_auth(ADMIN_KEY),
        json={"rules": [{"name": "everything", "effect": "block"}]},
    )
    assert response.status_code == 400, response.text


def test_the_same_malformed_policy_is_refused_by_deploy(client):
    """`validate` must run on BOTH write paths. A malformed policy reaching
    storage through the door nobody tested is the whole failure mode of
    "never silently apply malformed policies"."""
    response = client.post(
        "/v1/policy/versions",
        headers=_auth(ADMIN_KEY),
        json={"rules": [{"name": "everything", "effect": "block"}]},
    )
    assert response.status_code == 400, response.text


def test_a_malformed_policy_is_a_400_not_a_500(client):
    """A domain refusal escaping as a server fault is a defect this codebase has
    shipped before, on `/v1/mcp/evaluate`."""
    response = client.post(
        "/v1/policy/versions",
        headers=_auth(ADMIN_KEY),
        json={"rules": [{"name": "x", "effect": "block", "minSeverity": 100}]},
    )
    assert response.status_code == 400, response.text


# ── Deploy, activate, roll back ──────────────────────────────────────────────


def test_a_deployed_version_is_not_active_until_activated(client):
    """Storing is reviewable and reversible; activating changes what the estate
    enforces. Collapsing them would mean the only way to review a policy is to
    run it."""
    version = _deploy(client)
    history = client.get("/v1/policy/versions", headers=_auth(ADMIN_KEY)).json()
    assert history["active_version"] is None
    assert [v["version"] for v in history["versions"]] == [version]


def test_activating_a_version_makes_it_the_active_one(client):
    version = _deploy(client)
    response = client.post(
        f"/v1/policy/versions/{version}/activate", headers=_auth(ADMIN_KEY)
    )
    assert response.status_code == 200, response.text
    history = client.get("/v1/policy/versions", headers=_auth(ADMIN_KEY)).json()
    assert history["active_version"] == version


def test_rolling_back_is_the_same_call_with_an_older_version(client):
    """There is no separate rollback path, so there is nothing that can be
    correct for deployment and wrong for rollback."""
    first = _deploy(client)
    second = _deploy(client, _document(name="second", actions=["write_file"]))
    client.post(f"/v1/policy/versions/{second}/activate", headers=_auth(ADMIN_KEY))
    assert (
        client.get("/v1/policy/versions", headers=_auth(ADMIN_KEY)).json()[
            "active_version"
        ]
        == second
    )

    rolled_back = client.post(
        f"/v1/policy/versions/{first}/activate", headers=_auth(ADMIN_KEY)
    )
    assert rolled_back.status_code == 200
    assert (
        client.get("/v1/policy/versions", headers=_auth(ADMIN_KEY)).json()[
            "active_version"
        ]
        == first
    )


def test_exactly_one_version_is_active_after_a_rollback(client):
    """Two active versions would be two answers to "what does this estate
    enforce"."""
    first = _deploy(client)
    second = _deploy(client, _document(name="second", actions=["write_file"]))
    client.post(f"/v1/policy/versions/{second}/activate", headers=_auth(ADMIN_KEY))
    client.post(f"/v1/policy/versions/{first}/activate", headers=_auth(ADMIN_KEY))

    history = client.get("/v1/policy/versions", headers=_auth(ADMIN_KEY)).json()
    assert history["active_version"] == first
    assert len(history["versions"]) == 2


def test_activating_an_unknown_version_is_a_404(client):
    assert (
        client.post("/v1/policy/versions/999/activate", headers=_auth(ADMIN_KEY)).status_code
        == 404
    )


def test_a_stored_version_keeps_its_digest(client):
    """Rollback returns to the bytes that were reviewed. A version rewritten in
    place would make "roll back to version 3" mean something different
    tomorrow."""
    version = _deploy(client)
    first = client.get("/v1/policy/versions", headers=_auth(ADMIN_KEY)).json()
    # Re-deploying the same document produces a NEW version, never a rewrite.
    _deploy(client)
    second = client.get("/v1/policy/versions", headers=_auth(ADMIN_KEY)).json()

    original = next(v for v in first["versions"] if v["version"] == version)
    still_there = next(v for v in second["versions"] if v["version"] == version)
    assert original["digest"] == still_there["digest"]


# ── Diff ─────────────────────────────────────────────────────────────────────


def test_a_diff_reports_what_changed_between_two_versions(client):
    first = _deploy(client)
    second = _deploy(client, _document(name="second", actions=["write_file"]))
    diff = client.get(
        f"/v1/policy/diff?base={first}&target={second}", headers=_auth(ADMIN_KEY)
    )
    assert diff.status_code == 200, diff.text
    body = diff.json()
    assert body["added"] == ["second"]
    assert body["removed"] == ["block-exfil"]


def test_a_diff_against_an_unknown_version_is_a_404(client):
    version = _deploy(client)
    assert (
        client.get(
            f"/v1/policy/diff?base={version}&target=999", headers=_auth(ADMIN_KEY)
        ).status_code
        == 404
    )


# ── Section 30: simulation ───────────────────────────────────────────────────


def test_simulation_reports_the_section_30_fields(client):
    version = _deploy(client)
    response = client.post(
        f"/v1/policy/versions/{version}/simulate", headers=_auth(ADMIN_KEY)
    )
    assert response.status_code == 200, response.text
    body = response.json()
    for field in (
        "events_evaluated",
        "would_allow",
        "would_block",
        "would_require_approval",
        "potential_false_positives",
        "affected_agents",
        "affected_workflows",
    ):
        assert field in body, f"simulation is missing {field}"


def test_a_simulation_declares_itself_an_estimate(client):
    version = _deploy(client)
    body = client.post(
        f"/v1/policy/versions/{version}/simulate", headers=_auth(ADMIN_KEY)
    ).json()
    assert body["is_estimate"] is True
    assert body["estimate_caveat"]


def test_simulating_does_not_activate_the_candidate(client):
    """The candidate is never activated -- that is the entire point of asking
    what it would have done."""
    version = _deploy(client)
    client.post(f"/v1/policy/versions/{version}/simulate", headers=_auth(ADMIN_KEY))
    history = client.get("/v1/policy/versions", headers=_auth(ADMIN_KEY)).json()
    assert history["active_version"] is None


def test_simulating_an_unknown_version_is_a_404(client):
    assert (
        client.post(
            "/v1/policy/versions/999/simulate", headers=_auth(ADMIN_KEY)
        ).status_code
        == 404
    )


# ── Authorization ────────────────────────────────────────────────────────────


def test_an_analyst_cannot_deploy_a_policy(client):
    """A policy change is durable and silent, and a permissive one can sit
    undetected for months. Different failure shape from containment, different
    grant."""
    assert (
        client.post(
            "/v1/policy/versions", headers=_auth(ANALYST_KEY), json=_document()
        ).status_code
        == 403
    )


def test_an_analyst_cannot_activate_a_policy(client):
    version = _deploy(client)
    assert (
        client.post(
            f"/v1/policy/versions/{version}/activate", headers=_auth(ANALYST_KEY)
        ).status_code
        == 403
    )


def test_an_analyst_cannot_read_the_policy_history(client):
    """Which rules a tenant runs is a map of exactly what they do and do not
    detect."""
    assert (
        client.get("/v1/policy/versions", headers=_auth(ANALYST_KEY)).status_code == 403
    )


def test_policy_management_requires_authentication(client):
    assert client.get("/v1/policy/versions").status_code in {401, 403}


# ── Integer bounds: the fuzzer found this, twice removed ─────────────────────
#
# `GET /v1/policy/diff?base=531&target=32454664555118788771577856` returned 500
# on main. An unbounded `int` parameter reached the SQL layer, SQLite refused an
# integer wider than 64 bits, and the OverflowError escaped as a server fault.
#
# Two things are worth recording about how it was found. It is the IDENTICAL bug
# this codebase already fixed once, on SCIM's `startIndex` -- so the class was
# known and I reintroduced it in new code. And the red-team suite's
# `test_no_attack_ever_returns_a_server_error` did not catch it, because that
# test only drives the ingest endpoint. A claim that "no attack returns a 5xx"
# is only as wide as the surface it actually visits.


@pytest.mark.parametrize(
    "version",
    [
        32454664555118788771577856,  # the value schemathesis generated
        2**63,                        # one past a signed 64-bit column
        2**64,
        0,                            # versions start at 1
        -1,
    ],
    ids=["fuzzer_value", "past_int64", "past_uint64", "zero", "negative"],
)
def test_an_out_of_range_policy_version_is_refused_not_a_server_error(client, version):
    """422 from the schema, never a 500 from the database driver."""
    responses = {
        "diff": client.get(
            f"/v1/policy/diff?base=1&target={version}", headers=_auth(ADMIN_KEY)
        ),
        "activate": client.post(
            f"/v1/policy/versions/{version}/activate", headers=_auth(ADMIN_KEY)
        ),
        "simulate": client.post(
            f"/v1/policy/versions/{version}/simulate", headers=_auth(ADMIN_KEY)
        ),
    }
    for route, response in responses.items():
        assert response.status_code < 500, (
            f"{route} returned {response.status_code} for version={version}"
        )


def test_an_out_of_range_simulation_window_is_refused(client):
    """`days` is bounded at the schema as well as clamped in the handler. The
    clamp alone left the OpenAPI document claiming any integer is acceptable,
    which is what sends a fuzzer looking for the edge."""
    version = _deploy(client)
    for days in (0, -1, 10**18):
        response = client.post(
            f"/v1/policy/versions/{version}/simulate?days={days}",
            headers=_auth(ADMIN_KEY),
        )
        assert response.status_code < 500, f"days={days} produced {response.status_code}"


def test_a_valid_version_still_works_after_the_bounds_were_added(client):
    """The bound must not have made every request 422. A fix that refuses
    everything passes the regression test and breaks the feature."""
    first = _deploy(client)
    second = _deploy(client, _document(name="second", actions=["write_file"]))
    assert (
        client.get(
            f"/v1/policy/diff?base={first}&target={second}", headers=_auth(ADMIN_KEY)
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/v1/policy/versions/{first}/activate", headers=_auth(ADMIN_KEY)
        ).status_code
        == 200
    )
