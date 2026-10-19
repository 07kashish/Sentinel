"""Storage is what makes a transparency root mean anything.

Without it a root describes whatever was in one process's memory, and "is this
the same history you showed me last week" cannot be asked at all.

So these tests are mostly about the two ways storage could betray the log: a
leaf being overwritten (which would let an operator rewrite history AND still
produce a verifying proof, because the thing the proof is checked against
changed too), and a second root being recorded at a size already published
(which is a fork).

Parametrised over both engines. `tests_arch/conftest.py` explains why that is
not optional: the retention sweep once passed on SQLite while deleting nothing
on PostgreSQL, and the primary-key behaviour this module depends on is exactly
the kind of thing that differs.
"""

from __future__ import annotations

import hashlib

import pytest

from sentinel.domain.transparency import verify_consistency, verify_inclusion
from sentinel.infrastructure.sql.engine import Dialect, build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.infrastructure.sql.transparency_store import (
    PublishedRoot,
    SqlTransparencyStore,
    TransparencyStoreConflict,
)

TENANT = "acme"
OTHER = "globex"
NOW = "2026-09-03T10:00:00Z"


def _d(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


@pytest.fixture()
def store(engine_config):
    from sentinel.composition.settings import Settings

    env = {"SENTINEL_ENV": "development"}
    if engine_config.dialect is Dialect.POSTGRES:
        env["SENTINEL_DATABASE_URL"] = engine_config.dsn
        env["SENTINEL_DB_POOL_MIN"] = "1"
        env["SENTINEL_DB_POOL_MAX"] = "4"
    else:
        env["SENTINEL_DB_PATH"] = engine_config.dsn

    settings = Settings.from_environment(env)
    pool = build_engine(settings.engine)
    migrate(pool)
    try:
        for tenant in (TENANT, OTHER):
            with pool.acquire() as conn:
                conn.begin()
                conn.execute_rowcount(
                    f"INSERT INTO tenants (tenant_id, name, created_at) "
                    f"VALUES ({conn.p},{conn.p},{conn.p}) "
                    f"ON CONFLICT (tenant_id) DO NOTHING",
                    (tenant, tenant, NOW),
                )
                conn.commit()
        yield SqlTransparencyStore(pool=pool)
    finally:
        pool.close()


# ── the log survives the process ─────────────────────────────────────────────


def test_an_empty_log_has_size_zero(store):
    assert store.size(TENANT) == 0


def test_appended_leaves_come_back_in_order(store):
    """ORDER BY sequence, always. A log rebuilt in insertion order would be a
    different tree the moment the storage engine reordered a page, and every
    previously issued proof would stop verifying for no explicable reason.
    """
    for index in range(5):
        store.append(TENANT, digest=_d(f"p{index}"), at=NOW)

    log = store.load(TENANT)

    assert log.size == 5
    assert log.entries == tuple(_d(f"p{i}") for i in range(5))


def test_sequences_are_assigned_consecutively_from_zero(store):
    assert [
        store.append(TENANT, digest=_d(f"p{i}"), at=NOW) for i in range(3)
    ] == [0, 1, 2]


def test_a_reloaded_log_produces_the_same_root(store):
    """The property everything else rests on: a root computed after a restart
    must equal the one computed before it.
    """
    for index in range(7):
        store.append(TENANT, digest=_d(f"p{index}"), at=NOW)

    assert store.load(TENANT).root() == store.load(TENANT).root()


def test_an_inclusion_proof_verifies_against_the_stored_log(store):
    for index in range(9):
        store.append(TENANT, digest=_d(f"p{index}"), at=NOW)

    log = store.load(TENANT)
    proof = log.inclusion_proof(4)

    assert (
        verify_inclusion(digest=log.entries[4], proof=proof, root=log.root())
        is None
    )


def test_a_consistency_proof_spans_a_restart(store):
    """THE question a transparency log exists to answer.

    `up_to` rebuilds the earlier tree from the SAME leaves rather than trusting
    a stored root -- which is the only honest way to do it, because a stored
    root is the operator's assertion and the leaves are the evidence.
    """
    for index in range(4):
        store.append(TENANT, digest=_d(f"p{index}"), at=NOW)
    earlier = store.load(TENANT)

    for index in range(4, 11):
        store.append(TENANT, digest=_d(f"p{index}"), at=NOW)
    later = store.load(TENANT)

    assert (
        verify_consistency(
            old_root=earlier.root(),
            old_size=earlier.size,
            new_root=later.root(),
            new_size=later.size,
            proof=later.consistency_proof(earlier.size),
        )
        is None
    )


def test_up_to_rebuilds_the_earlier_tree_exactly(store):
    for index in range(6):
        store.append(TENANT, digest=_d(f"p{index}"), at=NOW)

    truncated = store.load(TENANT, up_to=3)

    assert truncated.size == 3
    assert truncated.entries == tuple(_d(f"p{i}") for i in range(3))


# ── append-only, enforced by the database ───────────────────────────────────


def test_the_store_offers_no_way_to_delete_or_update_a_leaf(store):
    """Not a convention. There is no method, and adding one would require
    writing SQL that does not exist in the module.

    A store that could overwrite a leaf would let an operator rewrite history
    and then produce a CONSISTENT-looking log from the new state -- the proof
    would verify, because the thing it was checked against had changed too.
    """
    for forbidden in ("delete", "update", "remove", "truncate", "rewrite", "set"):
        assert not hasattr(store, forbidden), (
            f"{forbidden} exists, so history can be rewritten"
        )


def test_a_leaf_that_is_not_a_sha256_digest_is_refused(store):
    with pytest.raises(ValueError) as raised:
        store.append(TENANT, digest=b"short", at=NOW)

    assert "32-byte" in str(raised.value)


def test_the_module_states_why_overwriting_would_be_worse_than_it_sounds():
    import inspect

    from sentinel.infrastructure.sql import transparency_store

    doc = " ".join((inspect.getdoc(transparency_store) or "").split())

    assert "APPEND-ONLY IS THE DATABASE'S PROPERTY" in doc
    assert "the thing it was checked against had changed too" in doc


# ── publication, and the sink that decides whether it matters ───────────────


def test_a_published_root_records_where_it_went(store):
    store.append(TENANT, digest=_d("p0"), at=NOW)
    log = store.load(TENANT)
    store.record_publication(
        TENANT,
        tree_size=log.size,
        root_hash=log.root().hex(),
        at=NOW,
        sink="s3-object-lock",
        external_reference="version-id-abc",
    )

    published = store.published_roots(TENANT)

    assert len(published) == 1
    assert published[0].sink == "s3-object-lock"
    assert published[0].external_reference == "version-id-abc"


def test_a_root_with_no_sink_is_not_independently_verifiable():
    """The question that decides whether the log is evidence or decoration.

    A root served only by the party that wrote the log proves nothing about
    that party, and the field says so rather than leaving it to be inferred
    from an absence.
    """
    assert not PublishedRoot(
        tree_size=1, root_hash="ab", published_at=NOW
    ).is_independently_verifiable


def test_a_sink_that_returned_no_reference_is_not_verifiable_either():
    """A sink name with nothing to check is a claim, not evidence."""
    assert not PublishedRoot(
        tree_size=1,
        root_hash="ab",
        published_at=NOW,
        sink="s3-object-lock",
        external_reference="   ",
    ).is_independently_verifiable


def test_a_sink_with_a_reference_is_verifiable():
    """The positive case must exist, or the flag is always False and nobody
    reads it.
    """
    assert PublishedRoot(
        tree_size=1,
        root_hash="ab",
        published_at=NOW,
        sink="s3-object-lock",
        external_reference="version-id-abc",
    ).is_independently_verifiable


def test_republishing_the_same_root_is_a_no_op(store):
    """Republishing after a transient sink failure is ordinary and must not
    raise, or an operator retrying a failed publication corrupts the record.
    """
    store.append(TENANT, digest=_d("p0"), at=NOW)
    root = store.load(TENANT).root().hex()

    store.record_publication(TENANT, tree_size=1, root_hash=root, at=NOW)
    store.record_publication(TENANT, tree_size=1, root_hash=root, at=NOW)

    assert len(store.published_roots(TENANT)) == 1


def test_publishing_a_different_root_at_the_same_size_is_refused(store):
    """A FORK, not a race. No retry is the right response to one.

    Recording both would leave a reader with two roots for one size and no way
    to know which history was served to whom.
    """
    store.append(TENANT, digest=_d("p0"), at=NOW)
    store.record_publication(TENANT, tree_size=1, root_hash="a" * 64, at=NOW)

    with pytest.raises(TransparencyStoreConflict) as raised:
        store.record_publication(TENANT, tree_size=1, root_hash="b" * 64, at=NOW)

    message = str(raised.value)
    assert "FORK" in message
    assert "not a race" in message


def test_published_roots_come_back_in_size_order(store):
    for size, digest in ((1, "a"), (2, "b"), (3, "c")):
        store.record_publication(
            TENANT, tree_size=size, root_hash=digest * 64, at=NOW
        )

    assert [r.tree_size for r in store.published_roots(TENANT)] == [1, 2, 3]


# ── tenant isolation ─────────────────────────────────────────────────────────


def test_one_tenants_leaves_are_invisible_to_another(store):
    """A cross-tenant WRITE would let one tenant append to another's log, and
    every consistency proof after that point would fail for a reason the
    victim could not explain.
    """
    store.append(TENANT, digest=_d("mine"), at=NOW)
    store.append(TENANT, digest=_d("mine-2"), at=NOW)

    assert store.size(OTHER) == 0
    assert store.load(OTHER).size == 0


def test_two_tenants_keep_independent_sequences(store):
    """Sequences are per tenant. Sharing a counter would leak one tenant's
    volume to another and gap their sequence for no visible reason.
    """
    assert store.append(TENANT, digest=_d("a"), at=NOW) == 0
    assert store.append(OTHER, digest=_d("b"), at=NOW) == 0
    assert store.append(TENANT, digest=_d("c"), at=NOW) == 1


def test_one_tenants_published_roots_are_invisible_to_another(store):
    store.record_publication(TENANT, tree_size=1, root_hash="a" * 64, at=NOW)

    assert store.published_roots(OTHER) == ()


def test_two_tenants_can_publish_at_the_same_tree_size(store):
    """The fork check is per tenant. Sharing it would make one tenant's
    publication block another's for no reason.
    """
    store.record_publication(TENANT, tree_size=1, root_hash="a" * 64, at=NOW)
    store.record_publication(OTHER, tree_size=1, root_hash="b" * 64, at=NOW)

    assert len(store.published_roots(TENANT)) == 1
    assert len(store.published_roots(OTHER)) == 1


def test_the_tables_are_tenant_scoped_in_the_protected_set():
    """Declared, not just filtered in the query. A WHERE clause is the
    application's promise; RLS is the database's.
    """
    from sentinel.infrastructure.sql.schema import PROTECTED_TABLES

    assert "transparency_leaves" in PROTECTED_TABLES
    assert "transparency_roots" in PROTECTED_TABLES
