"""An auditor can now ask this deployment whether it rewrote its own log.

Until the log had storage that question could not be asked. These tests drive
the real app, because a unit test of a route function passes just as well for a
route nobody registered -- which had already happened to five modules in this
codebase.

Most of the effort goes on one property: every response must say whether it is
independently verifiable, and must say NO while no root has been published
somewhere outside the operator's control. A proof served without that caveat
reads as evidence when it is the operator vouching for themselves.
"""

from __future__ import annotations

import hashlib

import pytest
from fastapi.testclient import TestClient

from sentinel.composition.container import build_container
from sentinel.composition.settings import Settings
from sentinel.infrastructure.sql.engine import Dialect, build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.interface.http import create_app

TENANT = "acme"
INGEST_KEY = "trans-ingest-000000000000000000000"
VIEW_KEY = "trans-viewer-000000000000000000000"
NOW = "2026-09-03T10:00:00Z"


def _d(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


@pytest.fixture()
def app(engine_config):
    env = {
        "SENTINEL_ENV": "development",
        "SENTINEL_API_KEYS": (
            f"{TENANT}:{INGEST_KEY}:ingest,{TENANT}:{VIEW_KEY}:viewer"
        ),
        "SENTINEL_SOFT_PROMPT_DETECT": "false",
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
                (TENANT, "Acme", NOW),
            )
            conn.commit()
        yield container, TestClient(
            create_app(container), raise_server_exceptions=False
        )
    finally:
        container.close()


def _view(client, path):
    return client.get(path, headers={"Authorization": f"Bearer {VIEW_KEY}"})


def _seed(container, count: int) -> None:
    for index in range(count):
        container.transparency.append(TENANT, digest=_d(f"p{index}"), at=NOW)


# ── reachability ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "path",
    [
        "/v1/transparency/root",
        "/v1/transparency/published",
    ],
)
def test_the_transparency_surface_is_reachable(app, path):
    _, client = app

    assert _view(client, path).status_code == 200


def test_the_routes_appear_in_the_openapi_document(app):
    _, client = app
    paths = client.get("/openapi.json").json()["paths"]

    for path in (
        "/v1/transparency/root",
        "/v1/transparency/inclusion/{index}",
        "/v1/transparency/consistency",
        "/v1/transparency/published",
    ):
        assert path in paths, f"{path} is missing from the OpenAPI document"


def test_no_route_can_append_to_the_log(app):
    """Appending is a consequence of recording an execution. A POST here would
    let anyone holding the ingest credential write history -- and that is the
    credential an agent holds.
    """
    _, client = app
    paths = client.get("/openapi.json").json()["paths"]

    for path, methods in paths.items():
        if "transparency" in path:
            assert set(methods) <= {"get"}, f"{path} accepts {set(methods)}"


def test_an_ingest_credential_cannot_read_the_log(app):
    """The log records which executions happened. A compromised agent
    credential must not be able to enumerate them.
    """
    _, client = app
    response = client.get(
        "/v1/transparency/root",
        headers={"Authorization": f"Bearer {INGEST_KEY}"},
    )

    assert response.status_code == 403


def test_an_unauthenticated_caller_is_refused(app):
    _, client = app

    assert client.get("/v1/transparency/root").status_code in {401, 403}


# ── the root ─────────────────────────────────────────────────────────────────


def test_an_empty_log_returns_the_defined_empty_root(app):
    """Defined rather than null, so an operator cannot claim a fresh start to
    explain a deletion: the root they published earlier was not this one.
    """
    from sentinel.domain.transparency import empty_root

    _, client = app
    body = _view(client, "/v1/transparency/root").json()

    assert body["tree_size"] == 0
    assert body["root"] == empty_root().hex()


def test_the_root_changes_when_a_leaf_is_appended(app):
    container, client = app
    before = _view(client, "/v1/transparency/root").json()["root"]
    _seed(container, 1)
    after = _view(client, "/v1/transparency/root").json()

    assert after["root"] != before
    assert after["tree_size"] == 1


def test_the_root_survives_a_rebuild_from_storage(app):
    """The property the storage exists for: a root computed now must equal one
    computed from the same leaves later.
    """
    container, client = app
    _seed(container, 6)

    first = _view(client, "/v1/transparency/root").json()["root"]
    second = _view(client, "/v1/transparency/root").json()["root"]

    assert first == second


# ── inclusion ────────────────────────────────────────────────────────────────


def test_an_inclusion_proof_is_served_and_verifies(app):
    from sentinel.domain.transparency import InclusionProof, verify_inclusion

    container, client = app
    _seed(container, 9)

    body = _view(client, "/v1/transparency/inclusion/4").json()
    proof = InclusionProof(
        index=body["proof"]["index"],
        tree_size=body["proof"]["tree_size"],
        path=tuple(bytes.fromhex(h) for h in body["proof"]["path"]),
    )

    assert (
        verify_inclusion(
            digest=bytes.fromhex(body["digest"]),
            proof=proof,
            root=bytes.fromhex(body["root"]),
        )
        is None
    )


def test_an_index_outside_the_log_is_a_404_not_an_empty_proof(app):
    """An empty proof is a document that verifies against nothing and reads
    like an answer.
    """
    container, client = app
    _seed(container, 3)

    response = _view(client, "/v1/transparency/inclusion/99")

    assert response.status_code == 404
    assert "outside a log of 3" in response.json()["detail"]


def test_an_inclusion_proof_on_an_empty_log_is_a_404(app):
    _, client = app

    assert _view(client, "/v1/transparency/inclusion/0").status_code == 404


# ── consistency: the route that catches a rewrite ───────────────────────────


def test_a_consistency_proof_is_served_and_verifies(app):
    from sentinel.domain.transparency import verify_consistency

    container, client = app
    _seed(container, 4)
    earlier = _view(client, "/v1/transparency/root").json()
    _seed(container, 7)

    body = _view(client, "/v1/transparency/consistency?old_size=4").json()

    assert body["consistent"] is True
    assert body["old_root"] == earlier["root"]
    assert (
        verify_consistency(
            old_root=bytes.fromhex(body["old_root"]),
            old_size=body["old_size"],
            new_root=bytes.fromhex(body["new_root"]),
            new_size=body["new_size"],
            proof=tuple(bytes.fromhex(h) for h in body["proof"]),
        )
        is None
    )


def test_a_claimed_earlier_size_larger_than_the_log_is_refused(app):
    """A log never shrinks, so this is either a corrupted record of the old
    size or evidence of a rewrite -- and both deserve to be seen.
    """
    container, client = app
    _seed(container, 3)

    response = _view(client, "/v1/transparency/consistency?old_size=50")

    assert response.status_code == 404
    assert "never shrinks" in response.json()["detail"]


def test_old_size_is_required_and_must_be_positive(app):
    """Consistency with size zero is trivially true for every log, so serving
    it would be issuing a proof that means nothing.
    """
    _, client = app

    assert _view(client, "/v1/transparency/consistency").status_code == 422
    assert (
        _view(client, "/v1/transparency/consistency?old_size=0").status_code == 422
    )


# ── the limit, served with every response ───────────────────────────────────


@pytest.mark.parametrize(
    "path",
    [
        "/v1/transparency/root",
        "/v1/transparency/inclusion/0",
        "/v1/transparency/consistency?old_size=1",
    ],
)
def test_every_proof_says_it_is_not_independently_verifiable(app, path):
    """THE property. No root has been published, so every one of these is the
    operator describing their own log -- and the payload must say so, because
    the payload is what a consumer receives.
    """
    container, client = app
    _seed(container, 4)

    body = _view(client, path).json()

    assert body["independently_verifiable"] is False
    assert "proves nothing about that party" in body["warning"]


def test_the_reason_names_what_is_missing(app):
    """"Not verifiable" is a shrug. "No root has been published for size 4" is
    something an operator can act on.
    """
    container, client = app
    _seed(container, 4)

    body = _view(client, "/v1/transparency/root").json()

    assert "no root has been published for tree size 4" in body["reason"]


def test_publishing_to_a_sink_with_a_reference_flips_the_flag(app):
    """The positive case must be reachable, or the flag is always false and
    stops being read.
    """
    container, client = app
    _seed(container, 2)
    root = container.transparency.load(TENANT).root().hex()
    container.transparency.record_publication(
        TENANT,
        tree_size=2,
        root_hash=root,
        at=NOW,
        sink="s3-object-lock",
        external_reference="version-id-abc",
    )

    body = _view(client, "/v1/transparency/root").json()

    assert body["independently_verifiable"] is True
    assert "version-id-abc" in body["reason"]
    assert "warning" not in body


def test_a_publication_with_no_external_reference_stays_unverifiable(app):
    """A sink name with nothing to check is a claim, not evidence -- and this
    is the shape a half-configured sink produces.
    """
    container, client = app
    _seed(container, 2)
    container.transparency.record_publication(
        TENANT,
        tree_size=2,
        root_hash=container.transparency.load(TENANT).root().hex(),
        at=NOW,
        sink="s3-object-lock",
        external_reference="",
    )

    body = _view(client, "/v1/transparency/root").json()

    assert body["independently_verifiable"] is False
    assert "not something a third party can check" in body["reason"]


def test_verifiability_is_read_from_publications_and_not_configuration(app):
    """A configured sink that has never successfully published is not a
    published root, and reporting the configuration would report an intention.
    """
    container, client = app
    _seed(container, 3)

    # Publication recorded for a DIFFERENT size than the current one.
    container.transparency.record_publication(
        TENANT,
        tree_size=1,
        root_hash="a" * 64,
        at=NOW,
        sink="s3-object-lock",
        external_reference="ref",
    )

    body = _view(client, "/v1/transparency/root").json()

    assert body["independently_verifiable"] is False, (
        "a publication at another size was treated as covering this one"
    )


# ── the published list ───────────────────────────────────────────────────────


def test_the_published_list_counts_verifiable_roots_separately(app):
    """The count that matters is the verifiable one, not the total -- a list of
    ten self-served roots is not ten pieces of evidence.
    """
    container, client = app
    container.transparency.record_publication(
        TENANT, tree_size=1, root_hash="a" * 64, at=NOW
    )
    container.transparency.record_publication(
        TENANT,
        tree_size=2,
        root_hash="b" * 64,
        at=NOW,
        sink="s3-object-lock",
        external_reference="ref",
    )

    body = _view(client, "/v1/transparency/published").json()

    assert body["total_count"] == 2
    assert body["independently_verifiable_count"] == 1
    assert "not total_count" in body["limits"]


def test_an_empty_published_list_says_what_that_means(app):
    _, client = app
    body = _view(client, "/v1/transparency/published").json()

    assert body["published"] == []
    assert body["independently_verifiable_count"] == 0
    assert "vouching for itself" in body["limits"]


# ── tenant scoping ───────────────────────────────────────────────────────────


def test_the_log_served_is_the_credentials_tenant(app):
    """Tenant comes from the credential. A route that took it from a query
    string would let any key read any log.
    """
    container, client = app
    container.transparency.append("globex", digest=_d("theirs"), at=NOW)

    body = _view(client, "/v1/transparency/root").json()

    assert body["tree_size"] == 0, "another tenant's leaf appeared in this log"
