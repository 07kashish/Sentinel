"""Tenant isolation with the application's own WHERE clause taken away.

THE RESIDUAL THIS CLOSES
------------------------
`docs/SECURITY.md`, Enterprise CISO:

    **Residual concern, not fixed:** isolation is enforced in application SQL,
    not by PostgreSQL row-level security. A single missing predicate would bleed.

Two things about that entry were wrong, and correcting both is the point of this
file.

First, RLS was in fact already implemented -- `sentinel/infrastructure/sql/schema.py`
issues `ENABLE`/`FORCE ROW LEVEL SECURITY` and a `USING`/`WITH CHECK` policy for
every table in `PROTECTED_TABLES`, and `migrate.py` applies it at versions 2, 4,
6, 8 and 10. The prose describing it as absent was stale.

Second, and more importantly, the test the same document cites as its evidence --
`test_tenant_isolation_is_enforced_by_the_real_database` -- **did not exist in
the tree**. Neither did `tests/test_failure_classes_are_structural.py`, also
cited there. A document naming a test that cannot be run is the same defect class
as the F-4 "protection was applied" claim that this project retracted: a
statement of evidence with no command behind it. So the test now exists, under
the name the document used.

WHAT MAKES THIS DIFFERENT FROM THE EXISTING RLS TESTS
------------------------------------------------------
`tests_arch/test_sql_infrastructure.py` already proves an UNSCOPED connection
reads nothing, and that a scoped read returns one tenant's rows. But its scoped
read still carries `WHERE tenant_id = ?`, so it cannot distinguish "RLS worked"
from "the predicate worked". Every test here deliberately OMITS the application
predicate, which is the only way to observe the defence-in-depth layer on its
own -- and it is precisely the situation a forgotten predicate creates in
production.

THE SUPERUSER TRAP
------------------
A PostgreSQL superuser bypasses RLS even with FORCE, which would make every
assertion below pass vacuously. `test_the_application_role_is_not_a_superuser`
runs first in spirit and is asserted explicitly, so this file cannot become
decorative the way it would if someone pointed it at a `postgres` DSN.
"""

from __future__ import annotations

import pytest

from sentinel.domain.errors import TransientFailure
from sentinel.infrastructure.sql.engine import Dialect
from sentinel.infrastructure.sql.schema import PROTECTED_TABLES, WORKER_SCOPED_TABLES

TENANT_A = "acme"
TENANT_B = "globex"
SHARED_ID = "inc-same-id-in-both-tenants"


def _write_incident(pool, tenant: str, incident_id: str) -> None:
    with pool.acquire() as conn:
        p = conn.p
        conn.begin()
        conn.set_tenant(tenant)
        conn.execute_rowcount(
            f"INSERT INTO incidents (tenant_id, incident_id, state, facts_json, "
            f"version, execution_epoch, created_at, updated_at) "
            f"VALUES ({p},{p},'received','{{}}',1,0,{p},{p})",
            (tenant, incident_id, "2026-08-18T00:00:00+00:00", "2026-08-18T00:00:00+00:00"),
        )
        conn.commit()


@pytest.fixture
def both_tenants(migrated_pool):
    """The same incident id under two tenants. Runs on BOTH engines."""
    _write_incident(migrated_pool, TENANT_A, SHARED_ID)
    _write_incident(migrated_pool, TENANT_B, SHARED_ID)
    _write_incident(migrated_pool, TENANT_B, "inc-b-secret")
    return migrated_pool


# ── The named test the review cites ──────────────────────────────────────────


def test_tenant_isolation_is_enforced_by_the_real_database(both_tenants, engine_config):
    """The same incident id exists under two tenants and each sees only its own.

    This is the test `docs/SECURITY.md` claimed as evidence. It is run
    against a real PostgreSQL server, and against SQLite, from the same source.
    """
    for tenant, expected in ((TENANT_A, 1), (TENANT_B, 2)):
        with both_tenants.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)
            rows = conn.execute(
                f"SELECT incident_id FROM incidents WHERE tenant_id={p}", (tenant,)
            )
            conn.commit()
        assert len(rows) == expected, f"{tenant} saw {len(rows)} incidents"

    # And the shared id resolves differently per tenant, which is the property a
    # single global id space would destroy.
    with both_tenants.acquire() as conn:
        p = conn.p
        conn.begin()
        conn.set_tenant(TENANT_A)
        rows = conn.execute(
            f"SELECT tenant_id FROM incidents WHERE tenant_id={p} AND incident_id={p}",
            (TENANT_A, SHARED_ID),
        )
        conn.commit()
    assert [r["tenant_id"] for r in rows] == [TENANT_A]
    assert engine_config.dialect in (Dialect.SQLITE, Dialect.POSTGRES)


# ── The sibling: the application predicate deliberately removed ──────────────


def test_rls_alone_blocks_the_leak_with_the_application_predicate_removed(
    both_tenants, engine_config
):
    """`SELECT * FROM incidents` -- no WHERE at all -- on a scoped connection.

    This is exactly what a forgotten `tenant_id = ?` produces. On PostgreSQL the
    policy must still bound the result to one tenant. On SQLite there is no such
    layer and the query returns everything, which is asserted rather than skipped:
    a silent skip here would let a reader believe both engines are protected.
    """
    with both_tenants.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT_A)
        rows = conn.execute("SELECT tenant_id, incident_id FROM incidents")
        conn.commit()

    tenants_seen = {str(r["tenant_id"]) for r in rows}
    if engine_config.dialect is Dialect.POSTGRES:
        assert tenants_seen == {TENANT_A}, (
            f"a query with NO application predicate returned rows for {tenants_seen}. "
            "Row-level security is not enforcing on its own, so the only thing "
            "standing between tenants is a WHERE clause a developer must remember."
        )
        assert len(rows) == 1
    else:
        # SQLite has no row-level security. Stated, not skipped.
        assert tenants_seen == {TENANT_A, TENANT_B}
        assert len(rows) == 3


def test_rls_alone_blocks_a_cross_tenant_update_with_no_predicate(
    both_tenants, engine_config
):
    """The write half. `USING` governs reads; `WITH CHECK` governs writes.

    An unpredicated UPDATE is the more dangerous forgotten-clause bug, because it
    corrupts rather than merely discloses. Under RLS it must touch only the
    bound tenant's rows.
    """
    with both_tenants.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT_A)
        affected = conn.execute_rowcount("UPDATE incidents SET state='failed'")
        conn.commit()

    with both_tenants.acquire() as conn:
        p = conn.p
        conn.begin()
        conn.set_tenant(TENANT_B)
        states = {
            str(r["state"])
            for r in conn.execute(
                f"SELECT state FROM incidents WHERE tenant_id={p}", (TENANT_B,)
            )
        }
        conn.commit()

    if engine_config.dialect is Dialect.POSTGRES:
        assert affected == 1, f"an unpredicated UPDATE touched {affected} rows"
        assert states == {"received"}, (
            f"tenant B's incidents were modified by tenant A's UPDATE: {states}"
        )
    else:
        assert affected == 3
        assert states == {"failed"}


def test_rls_alone_blocks_a_cross_tenant_delete_with_no_predicate(
    both_tenants, engine_config
):
    """The worst forgotten clause of the three: `DELETE FROM incidents`.

    This is not hypothetical for this codebase. The retention sweep shipped
    exactly this shape -- an unpredicated DELETE on a pooled connection -- and
    on PostgreSQL it removed nothing at all because RLS bounded it to a tenant
    context that was never set. The same mechanism that made that sweep a no-op
    is what stops this from being a cross-tenant wipe.
    """
    with both_tenants.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT_A)
        deleted = conn.execute_rowcount("DELETE FROM incidents")
        conn.commit()

    with both_tenants.acquire() as conn:
        p = conn.p
        conn.begin()
        conn.set_tenant(TENANT_B)
        remaining = len(
            conn.execute(f"SELECT 1 FROM incidents WHERE tenant_id={p}", (TENANT_B,))
        )
        conn.commit()

    if engine_config.dialect is Dialect.POSTGRES:
        assert deleted == 1
        assert remaining == 2, "tenant B's incidents were deleted by tenant A"
    else:
        assert deleted == 3
        assert remaining == 0


def test_a_write_cannot_be_attributed_to_another_tenant(both_tenants, engine_config):
    """`WITH CHECK`: bound to A, inserting a row labelled B must be refused.

    Without this, a compromised or buggy caller could plant rows in another
    tenant's space even while reads were correctly bounded -- isolation in one
    direction only, which is not isolation.
    """
    if engine_config.dialect is not Dialect.POSTGRES:
        pytest.skip("SQLite has no WITH CHECK; the application predicate is all there is")

    with pytest.raises(TransientFailure) as raised:  # noqa: PT012 - the block is the subject
        with both_tenants.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(TENANT_A)
            conn.execute_rowcount(
                f"INSERT INTO incidents (tenant_id, incident_id, state, facts_json, "
                f"version, execution_epoch, created_at, updated_at) "
                f"VALUES ({p},{p},'received','{{}}',1,0,{p},{p})",
                (TENANT_B, "inc-planted", "2026-08-18T00:00:00+00:00", "2026-08-18T00:00:00+00:00"),
            )
            conn.commit()

    assert "policy" in str(raised.value).lower() or "row-level" in str(raised.value).lower(), (
        f"the cross-tenant insert failed, but not on the RLS policy: {raised.value}"
    )


# ── The assertions that stop this file becoming decorative ───────────────────


def test_the_application_role_is_not_a_superuser(both_tenants, engine_config):
    """A superuser bypasses FORCE RLS, making every test above pass vacuously.

    This is the single assumption the whole file rests on, so it is checked
    against the server rather than assumed from the fixture's intent.
    """
    if engine_config.dialect is not Dialect.POSTGRES:
        pytest.skip("no roles on SQLite")

    with both_tenants.acquire() as conn:
        conn.begin()
        row = conn.one("SELECT current_user AS u, usesuper AS s FROM pg_user "
                       "WHERE usename = current_user")
        conn.commit()
    assert row is not None
    assert not row["s"], (
        f"the application is connected as superuser {row['u']!r}. FORCE row-level "
        "security does not apply to superusers, so every isolation assertion in "
        "this file would pass without the policies existing at all."
    )


def test_every_protected_table_actually_carries_a_forced_policy(
    both_tenants, engine_config
):
    """The DDL is `IF NOT EXISTS`-shaped; confirm the server agrees it ran.

    `PROTECTED_TABLES` is a declaration. This asks PostgreSQL's own catalogue
    whether each of those tables has `relrowsecurity` AND `relforcerowsecurity`
    set and at least one policy attached -- so a migration that silently did not
    apply is a failure here rather than a discovery in production.
    """
    if engine_config.dialect is not Dialect.POSTGRES:
        pytest.skip("SQLite has no row-level security to interrogate")

    with both_tenants.acquire() as conn:
        conn.begin()
        rows = conn.execute(
            "SELECT c.relname AS t, c.relrowsecurity AS enabled, "
            "c.relforcerowsecurity AS forced, "
            "(SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid) AS policies "
            "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'public' AND c.relkind = 'r'"
        )
        conn.commit()

    state = {str(r["t"]): (bool(r["enabled"]), bool(r["forced"]), int(r["policies"])) for r in rows}
    # Exactly one policy -- tenant isolation -- except on the tables the worker
    # scans across tenants, which carry the worker-scope policy as well.
    # EXACTLY two there, not "at least": a third policy would be one nobody
    # here can account for.
    unprotected = [
        table
        for table in PROTECTED_TABLES
        if state.get(table) != (True, True, 2 if table in WORKER_SCOPED_TABLES else 1)
    ]
    assert not unprotected, (
        f"these tables are in PROTECTED_TABLES but the server does not report "
        f"ENABLE + FORCE + the expected policy count for them: "
        f"{ {t: state.get(t) for t in unprotected} }"
    )


def test_no_tenant_owned_table_was_left_out_of_the_protected_set(
    both_tenants, engine_config
):
    """A new table with a `tenant_id` column must not be able to skip the policy.

    The declaration and the schema are two places the truth is written, and this
    is the check that they agree. `tenants` and `webauthn_challenges` are the two
    documented exclusions: the first is the directory used to ESTABLISH a scope,
    the second is issued before the caller is known.
    """
    if engine_config.dialect is not Dialect.POSTGRES:
        pytest.skip("catalogue query is PostgreSQL-specific")

    documented_exclusions = {"tenants", "webauthn_challenges"}
    with both_tenants.acquire() as conn:
        conn.begin()
        rows = conn.execute(
            "SELECT table_name FROM information_schema.columns "
            "WHERE table_schema='public' AND column_name='tenant_id'"
        )
        conn.commit()

    with_tenant_column = {str(r["table_name"]) for r in rows}
    missing = with_tenant_column - set(PROTECTED_TABLES) - documented_exclusions
    assert not missing, (
        f"these tables have a tenant_id column but no row-level-security policy: "
        f"{sorted(missing)}. Add them to PROTECTED_TABLES, or document the "
        "exclusion here with the reason."
    )


# ── The worker scope: cross-tenant on purpose, and ONLY when declared ────────


def _enqueue(pool, tenant: str, work_id: str) -> None:
    with pool.acquire() as conn:
        p = conn.p
        conn.begin()
        conn.set_tenant(tenant)
        conn.execute_rowcount(
            f"INSERT INTO work_queue (tenant_id, work_id, incident_id, shard, priority, "
            f"payload_json, state, attempts, lease_epoch, available_at, enqueued_at) "
            f"VALUES ({p},{p},{p},0,2,'{{}}','pending',0,0,{p},{p})",
            (tenant, work_id, f"inc-{work_id}", "2026-08-18T00:00:00+00:00", "2026-08-18T00:00:00+00:00"),
        )
        conn.commit()


def test_every_worker_scoped_table_is_also_tenant_protected():
    """The worker policy is an ADDITION to isolation, never a substitute."""
    assert set(WORKER_SCOPED_TABLES) <= set(PROTECTED_TABLES)


def test_a_tenant_scoped_connection_without_worker_scope_cannot_see_another_tenants_queue(
    migrated_pool, engine_config
):
    """The queue carries a second policy. It must not have loosened the first.

    A connection bound to tenant A, with NO application predicate and no
    worker scope declared, must see only A's queue rows. If the worker policy
    admitted rows on its own -- a predicate that matched an unset setting, say
    -- this is where it would show.
    """
    _enqueue(migrated_pool, TENANT_A, "w-a")
    _enqueue(migrated_pool, TENANT_B, "w-b")

    with migrated_pool.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT_A)
        rows = conn.execute("SELECT tenant_id, work_id FROM work_queue")
        conn.commit()

    seen = {str(r["tenant_id"]) for r in rows}
    if engine_config.dialect is Dialect.POSTGRES:
        assert seen == {TENANT_A}, (
            f"a tenant-scoped connection saw queue rows for {seen}; the worker-scope "
            "policy is admitting rows to a transaction that never declared the scope"
        )
    else:
        assert seen == {TENANT_A, TENANT_B}


def test_an_unscoped_connection_still_sees_no_queue_rows(migrated_pool, engine_config):
    """Neither setting established: the fail-closed default is unchanged."""
    if engine_config.dialect is not Dialect.POSTGRES:
        pytest.skip("SQLite has no row-level security to interrogate")
    _enqueue(migrated_pool, TENANT_A, "w-a")

    with migrated_pool.acquire() as conn:
        conn.begin()
        rows = conn.execute("SELECT work_id FROM work_queue")
        conn.commit()
    assert rows == []


def test_the_worker_scope_sees_every_tenants_queue_rows_and_nothing_else(
    migrated_pool, engine_config
):
    """Declared scope: the queue is visible across tenants, `incidents` is not.

    The second half is the one that matters. If `set_worker_scope` were a
    general bypass, every table would open up with it; it must open exactly the
    tables in WORKER_SCOPED_TABLES.
    """
    if engine_config.dialect is not Dialect.POSTGRES:
        pytest.skip("SQLite has no row-level security to interrogate")
    _enqueue(migrated_pool, TENANT_A, "w-a")
    _enqueue(migrated_pool, TENANT_B, "w-b")
    _write_incident(migrated_pool, TENANT_A, "inc-a")

    with migrated_pool.acquire() as conn:
        conn.begin()
        conn.set_worker_scope()
        queue = conn.execute("SELECT tenant_id FROM work_queue")
        incidents = conn.execute("SELECT tenant_id FROM incidents")
        conn.commit()

    assert {str(r["tenant_id"]) for r in queue} == {TENANT_A, TENANT_B}
    assert incidents == [], (
        "the worker scope opened `incidents`; it must admit only WORKER_SCOPED_TABLES"
    )


def test_the_worker_scope_does_not_outlive_its_transaction(migrated_pool, engine_config):
    """Transaction-local, like the tenant context. A pooled connection that
    carried the scope into its next borrower would hand a request handler a
    cross-tenant view of the queue."""
    if engine_config.dialect is not Dialect.POSTGRES:
        pytest.skip("SQLite has no row-level security to interrogate")
    _enqueue(migrated_pool, TENANT_A, "w-a")

    with migrated_pool.acquire() as conn:
        conn.begin()
        conn.set_worker_scope()
        assert len(conn.execute("SELECT work_id FROM work_queue")) == 1
        conn.commit()
        # Same connection, next transaction, nothing declared.
        conn.begin()
        rows = conn.execute("SELECT work_id FROM work_queue")
        conn.commit()
    assert rows == []
