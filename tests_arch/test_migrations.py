"""Migrations: ordered, idempotent, resumable, and honest about the version.

WHY THIS MODULE EXISTS
----------------------
`migration_tests` was a required release gate with nothing behind it. Not a
failing suite -- no suite at all. The gate reported UNVERIFIED forever, which is
the correct word for "nobody checked" and a poor thing to ship a schema on.

Migrations are the one subsystem where a mistake is not recoverable by
redeploying. A wrong authorization decision can be re-made; a table dropped by a
migration that ran twice cannot be un-dropped. So the properties here are about
what happens when the process does NOT go cleanly: a re-run, a partial
application, a database ahead of the build.

Run on BOTH engines. SQLite and PostgreSQL disagree about DDL transactionality,
identifier quoting, and what `IF NOT EXISTS` covers, and a migration correct on
one can be a no-op or an error on the other. That asymmetry is the reason the
`engine_config` fixture exists at all.
"""

from __future__ import annotations

import pytest

from sentinel.infrastructure.sql.engine import Dialect, build_engine
from sentinel.infrastructure.sql.migrate import (
    CURRENT_VERSION,
    MIGRATIONS,
    SchemaOutOfDate,
    migrate,
    verify,
)


@pytest.fixture
def pool(engine_config):
    engine = build_engine(engine_config)
    try:
        yield engine
    finally:
        engine.close()


def _version(pool) -> int:
    with pool.acquire() as conn:
        conn.begin()
        row = conn.one("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations")
        conn.commit()
    return int(row["v"])


# ── the ledger is well-formed ────────────────────────────────────────────────


def test_versions_are_unique_and_strictly_increasing():
    """Two migrations sharing a number means one silently never runs.

    `migrate` skips anything `<= current`, so a duplicate 27 applies whichever
    comes first in the tuple and passes over the other with no error. The
    database then reports version 27 while missing half of it.
    """
    versions = [version for version, _desc, _fn in MIGRATIONS]
    assert versions == sorted(versions), "MIGRATIONS is not in ascending order"
    assert len(versions) == len(set(versions)), (
        f"duplicate migration versions: "
        f"{sorted({v for v in versions if versions.count(v) > 1})}"
    )


def test_current_version_is_the_last_migration():
    """`verify` compares against CURRENT_VERSION at startup.

    If it drifted below the highest migration, a freshly migrated database
    would report a version higher than the build expects and `verify` would
    refuse to start -- on a database that is correct.
    """
    assert CURRENT_VERSION == max(v for v, _d, _f in MIGRATIONS)


def test_every_migration_has_a_description():
    """The description is what an operator reads in a failed deploy."""
    undescribed = [v for v, desc, _fn in MIGRATIONS if not desc.strip()]
    assert not undescribed, f"migrations with no description: {undescribed}"


# ── applying them ────────────────────────────────────────────────────────────


def test_a_fresh_database_reaches_the_current_version(pool):
    assert migrate(pool) == CURRENT_VERSION
    assert _version(pool) == CURRENT_VERSION


def test_migrate_is_idempotent(pool):
    """THE property that matters for a re-run.

    Two replicas starting together, a retried deploy, an operator running the
    command twice -- all of these call `migrate` against a database that is
    already current. It must be a no-op, not a second application.
    """
    migrate(pool)
    before = _version(pool)
    assert migrate(pool) == before
    assert _version(pool) == before


def test_a_partially_migrated_database_resumes_rather_than_restarting(pool):
    """Each migration commits its own version row, so an interrupted run
    resumes from the last COMPLETE one.

    Modelled by rewinding the ledger: the tables exist, but the recorded
    version says they do not. That is exactly the state a crash between
    `apply()` and the `INSERT` leaves behind, and re-running must converge
    rather than fail on an object that is already there.
    """
    migrate(pool)
    with pool.acquire() as conn:
        conn.begin()
        conn.execute_rowcount(
            f"DELETE FROM schema_migrations WHERE version > {conn.p}",
            (CURRENT_VERSION - 3,),
        )
        conn.commit()

    assert migrate(pool) == CURRENT_VERSION
    assert _version(pool) == CURRENT_VERSION


def test_verify_accepts_a_current_database(pool):
    migrate(pool)
    assert verify(pool) == CURRENT_VERSION


def test_verify_refuses_a_database_behind_the_build(pool):
    """A build that started against an old schema fails on the first query that
    touches a missing column -- in a request, not at boot. `verify` moves that
    failure to startup, and this is the test that it actually fires.
    """
    migrate(pool)
    with pool.acquire() as conn:
        conn.begin()
        conn.execute_rowcount(
            f"DELETE FROM schema_migrations WHERE version > {conn.p}",
            (CURRENT_VERSION - 1,),
        )
        conn.commit()

    with pytest.raises(SchemaOutOfDate) as raised:
        verify(pool)
    # The message must name both numbers and the command. "Schema out of date"
    # sends an operator to read the source during an incident.
    message = str(raised.value)
    assert str(CURRENT_VERSION) in message
    assert "migrate" in message


def test_verify_refuses_an_empty_database(pool):
    """Version 0 is not "new", it is "not migrated". Starting against it would
    fail on the first statement.
    """
    with pytest.raises(SchemaOutOfDate):
        verify(pool)


def test_verify_refuses_a_database_AHEAD_of_the_build(pool):
    """The rollback case, and the one people forget.

    A deploy is rolled back while the database keeps the newer schema. The old
    build then reads tables whose columns have moved underneath it. `verify`
    compares for EQUALITY rather than `>=` precisely so this stops at boot.
    """
    migrate(pool)
    with pool.acquire() as conn:
        conn.begin()
        conn.execute_rowcount(
            f"INSERT INTO schema_migrations (version, applied_at) "
            f"VALUES ({conn.p},{conn.p})",
            (CURRENT_VERSION + 1, "2026-09-01T00:00:00+00:00"),
        )
        conn.commit()

    with pytest.raises(SchemaOutOfDate):
        verify(pool)


# ── what the migrations produced ─────────────────────────────────────────────


def test_the_tables_the_application_needs_exist_after_migrating(pool):
    """A spot check that migrating produced a usable schema, not just a
    version row.

    `_applied_version` creates `schema_migrations` on its own, so a migration
    set that did nothing at all would still leave a database reporting the
    current version. The version number alone proves nothing.
    """
    migrate(pool)
    expected = (
        "tenants",
        "incidents",
        "agents",
        "schema_migrations",
        "a2a_agent_cards",
        "mcp_servers",
    )
    with pool.acquire() as conn:
        conn.begin()
        for table in expected:
            # One indexed read per table. A missing table raises rather than
            # returning empty, which is the distinction being checked.
            conn.one(f"SELECT COUNT(*) AS n FROM {table}")
        conn.commit()


def test_row_level_security_is_on_after_a_fresh_migration(engine_config, pool):
    """v27 forces RLS. A fresh database must not be weaker than an upgraded one.

    The two paths differ: an upgrade runs `_apply_rls` as a migration step,
    while a fresh install runs `_create_baseline` and then the same step. A
    baseline that created tables without the policy, followed by a step that
    was skipped as already-applied, would leave a new deployment unprotected --
    the failure mode being checked.
    """
    if engine_config.dialect is not Dialect.POSTGRES:
        pytest.skip("SQLite has no row-level security to interrogate")

    migrate(pool)
    with pool.acquire() as conn:
        conn.begin()
        rows = conn.execute(
            "SELECT relname, relrowsecurity, relforcerowsecurity "
            "FROM pg_class WHERE relname = 'incidents'"
        )
        conn.commit()

    record = list(rows)[0]
    assert record["relrowsecurity"], "RLS is not enabled on incidents"
    assert record["relforcerowsecurity"], (
        "RLS is enabled but not FORCED, so the owning role bypasses it -- which "
        "is the role the application connects as in many deployments"
    )
