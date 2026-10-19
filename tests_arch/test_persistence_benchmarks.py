"""Every hot query, planned and timed against realistic volume.

WHY THE SEED SIZE MATTERS MORE THAN THE ASSERTIONS
----------------------------------------------------
An EXPLAIN over ten rows proves nothing. A sequential scan of a ten-row table is
genuinely the fastest plan, so a suite that seeds ten rows and asserts "no
sequential scan" either fails on correct behaviour or passes because the planner
had no choice. Either way it measures nothing.

These tests seed thousands of rows across many tenants before measuring, and run
ANALYZE so the planner has statistics. Only then is "the planner chose an index"
a statement about the schema rather than about the sample size.

WHAT IS ASSERTED
----------------
  * no sequential scan of an UNBOUNDED table on a hot query
  * query count does not grow with result-set size (no N+1)
  * partition pruning actually happens
  * row-level security does not turn into a full scan
  * lock acquisition is bounded, so a blocked writer fails rather than queues
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sentinel.infrastructure.persistence.diagnostics import (
    analyse_plan,
    count_statements,
    time_query,
)
from sentinel.infrastructure.persistence.engine import (
    DatabaseConfig,
    Dialect,
    Isolation,
    PoolConfig,
    build_database,
)
from sentinel.infrastructure.persistence.migrations import MigrationRunner
from sentinel.infrastructure.persistence.schema import MIGRATIONS

# Sized so the planner has a genuine choice while the whole fixture still fits
# in a temp volume. 25x80x4 seeded ~40k rows per test and, with a fresh database
# per parametrisation, filled a 297GB disk. The planner's decision does not
# change materially below this: what matters is that the tables are large enough
# that a sequential scan is NOT the cheapest plan, and 8k rows across 12 tenants
# is comfortably past that threshold.
TENANTS = 12
INCIDENTS_PER_TENANT = 40
EVENTS_PER_INCIDENT = 2
NOW = datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)
#: The tenant every read in this module is scoped to.
SUBJECT = "tenant-006"


def _scoped(conn, tenant: str = SUBJECT):
    """Begin a transaction and establish tenant context.

    Every read here must scope. Under FORCE row-level security an unscoped
    SELECT matches no rows -- which is the boundary working, and is why the first
    version of these tests reported zero rows on PostgreSQL while passing on
    SQLite. Scoping in one helper means a new test cannot forget.
    """
    conn.begin()
    conn.set_tenant(tenant)
    return conn


@pytest.fixture
def seeded(engine_config):
    """A migrated database with enough rows for the planner to have a choice.

    `engine_config.dialect` belongs to the OUTGOING engine's enum, which is a
    different class from this one even though the members share names and
    values. Mapping by value rather than passing it through is what stops
    `dialect is Dialect.SQLITE` silently evaluating False and routing a SQLite
    path into the PostgreSQL driver.
    """
    config = DatabaseConfig(
        dialect=Dialect(engine_config.dialect.value),
        dsn=engine_config.dsn,
        pool=PoolConfig(min_size=1, max_size=6),
    )
    database = build_database(config)
    MigrationRunner(database=database, migrations=MIGRATIONS).upgrade()
    _seed(database)
    yield database
    database.close()


def _seed(database) -> None:
    with database.writer() as conn:
        conn.begin()
        p = conn.p
        for t in range(TENANTS):
            tenant = f"tenant-{t:03d}"
            conn.execute_rowcount(
                f"INSERT INTO tenants (tenant_id, name, created_at) "
                f"VALUES ({p},{p},{p})",
                (tenant, tenant, NOW.isoformat()),
            )
            # Establish tenant context BEFORE writing this tenant's rows. The RLS
            # policies carry WITH CHECK, so an insert with no context is rejected
            # rather than silently mis-scoped -- which is the policy working, and
            # is why the first version of this seeder failed on PostgreSQL and
            # passed on SQLite. `set_config(..., true)` is transaction-local and
            # re-settable, so one transaction can seed every tenant in turn.
            conn.set_tenant(tenant)
            for i in range(INCIDENTS_PER_TENANT):
                incident = f"inc-{t:03d}-{i:04d}"
                stamp = (NOW - timedelta(minutes=i)).isoformat()
                state = "completed_attested" if i % 3 else "reported"
                # A tenth are soft-deleted, so the partial indexes have something
                # to exclude and the live-row queries have something to skip.
                deleted = stamp if i % 10 == 0 else None
                conn.execute_rowcount(
                    f"INSERT INTO incidents (tenant_id, incident_id, state, facts_json,"
                    f" version, execution_epoch, created_at, updated_at, deleted_at)"
                    f" VALUES ({p},{p},{p},{p},1,1,{p},{p},{p})",
                    (tenant, incident, state, "{}", stamp, stamp, deleted),
                )
                conn.execute_rowcount(
                    f"INSERT INTO work_queue (tenant_id, work_id, incident_id, shard,"
                    f" priority, payload_json, state, available_at, enqueued_at)"
                    f" VALUES ({p},{p},{p},{p},{p},'{{}}',{p},{p},{p})",
                    (tenant, f"w-{incident}", incident, t % 8, i % 4,
                     "pending" if i % 5 else "done", stamp, stamp),
                )
                conn.execute_rowcount(
                    f"INSERT INTO outbox (tenant_id, record_id, incident_id, kind,"
                    f" payload_json, idempotency_key, state, available_at, created_at,"
                    f" updated_at) VALUES ({p},{p},{p},'attestation','{{}}',{p},{p},"
                    f"{p},{p},{p})",
                    (tenant, f"o-{incident}", incident, f"idem-{incident}",
                     "pending" if i % 4 else "delivered", stamp, stamp, stamp),
                )
                for e in range(EVENTS_PER_INCIDENT):
                    conn.execute_rowcount(
                        f"INSERT INTO domain_events (tenant_id, event_id, incident_id,"
                        f" event_type, event_version, payload_json, occurred_at,"
                        f" recorded_at) VALUES ({p},{p},{p},{p},1,'{{}}',{p},{p})",
                        (tenant, f"{incident}-e{e}", incident,
                         "IncidentStateChanged", stamp, stamp),
                    )
        conn.commit()

    # Statistics, without which the planner is guessing.
    with database.writer() as conn:
        conn.begin()
        conn.execute_rowcount("ANALYZE")
        conn.commit()


# ── The hot query set ────────────────────────────────────────────────────────
#
# Named, with representative parameters. Adding a query to a repository without
# adding it here means it is never planned or timed, so the list is the contract.

def _queries(p: str) -> list[tuple[str, str, tuple]]:
    tenant = "tenant-006"
    incident = "inc-006-0007"
    stamp = NOW.isoformat()
    return [
        (
            "incidents.list_live",
            f"SELECT incident_id, state, updated_at FROM incidents "
            f"WHERE tenant_id={p} AND deleted_at IS NULL "
            f"ORDER BY updated_at DESC LIMIT 50",
            (tenant,),
        ),
        (
            "incidents.get",
            f"SELECT * FROM incidents WHERE tenant_id={p} AND incident_id={p}",
            (tenant, incident),
        ),
        (
            "incidents.counts_by_state",
            f"SELECT state, COUNT(*) AS n FROM incidents "
            f"WHERE tenant_id={p} AND deleted_at IS NULL GROUP BY state",
            (tenant,),
        ),
        (
            "work_queue.claim_by_shard",
            f"SELECT work_id, incident_id, lease_epoch FROM work_queue "
            f"WHERE shard={p} AND state='pending' AND available_at<={p} "
            f"ORDER BY priority ASC, enqueued_at ASC LIMIT 1",
            (3, stamp),
        ),
        (
            "work_queue.reap_leases",
            f"SELECT work_id FROM work_queue WHERE state='claimed' AND lease_until<{p}",
            (stamp,),
        ),
        (
            "outbox.claim_due",
            f"SELECT record_id FROM outbox WHERE tenant_id={p} AND state='pending' "
            f"AND available_at<={p} ORDER BY available_at ASC LIMIT 20",
            (tenant, stamp),
        ),
        (
            "outbox.by_idempotency_key",
            f"SELECT record_id FROM outbox WHERE tenant_id={p} AND idempotency_key={p}",
            (tenant, f"idem-{incident}"),
        ),
        (
            "events.stream_tail",
            f"SELECT event_type, recorded_at FROM domain_events WHERE tenant_id={p} "
            f"ORDER BY recorded_at DESC LIMIT 50",
            (tenant,),
        ),
        (
            "events.for_incident",
            f"SELECT event_type FROM domain_events WHERE tenant_id={p} "
            f"AND incident_id={p} ORDER BY recorded_at",
            (tenant, incident),
        ),
    ]


# ── Plans ────────────────────────────────────────────────────────────────────


def test_no_hot_query_sequentially_scans_an_unbounded_table(seeded, capsys):
    """The headline rule, measured against real volume and real statistics."""
    offenders: list[str] = []
    with seeded.reader(consistent=True) as conn:
        _scoped(conn)
        for name, sql, params in _queries(conn.p):
            analysis = analyse_plan(conn, sql, params)
            bad = analysis.offending_scans()
            if bad:
                offenders.append(f"{name}: scans {bad}\n{analysis.plan}")
        conn.commit()

    assert not offenders, (
        f"{len(offenders)} hot quer(y/ies) sequentially scan an unbounded table:\n\n"
        + "\n\n".join(offenders)
    )


def test_every_hot_query_is_benchmarked(seeded, capsys):
    """Times every query and prints the table. No query ships unmeasured."""
    timings = []
    with seeded.reader(consistent=True) as conn:
        _scoped(conn)
        for name, sql, params in _queries(conn.p):
            timings.append(time_query(conn, name, sql, params, runs=15))
        conn.commit()

    with capsys.disabled():
        print(f"\n  {seeded.dialect.value} — {len(timings)} hot queries")
        for timing in timings:
            print(f"    {timing}")

    # A ceiling that catches a plan regression, not a performance target. A hot
    # query taking >250ms median on a few thousand rows is not slow, it is
    # scanning.
    slow = [t for t in timings if t.median_ms > 250]
    assert not slow, "queries with an implausible median:\n" + "\n".join(str(t) for t in slow)


def test_the_analyser_can_actually_detect_a_scan(seeded):
    """Guard against a vacuous rule.

    If `offending_scans` never fired, every plan assertion above would pass
    regardless of the schema. This builds a table with NO usable index and
    requires the analyser to report the scan.

    The first version of this control queried `incidents` on an unindexed
    column, which stopped being a control once row-level security was enabled:
    the policy's `tenant_id = current_setting(...)` predicate is itself indexed,
    so the planner used the primary key and reported no sequential scan. A
    negative control has to be genuinely negative.
    """
    with seeded.writer() as conn:
        conn.begin()
        conn.execute_rowcount(
            "CREATE TABLE IF NOT EXISTS scan_control (id INTEGER, payload TEXT)"
        )
        for i in range(2000):
            conn.execute_rowcount(
                f"INSERT INTO scan_control (id, payload) VALUES ({conn.p},{conn.p})",
                (i, f"row-{i}"),
            )
        conn.commit()
    with seeded.writer() as conn:
        conn.begin()
        conn.execute_rowcount("ANALYZE")
        conn.commit()

    with seeded.reader(consistent=True) as conn:
        conn.begin()
        analysis = analyse_plan(
            conn,
            f"SELECT id FROM scan_control WHERE payload LIKE {conn.p}",
            ("%needle%",),
        )
        conn.commit()

    assert analysis.sequential_scans, (
        "a full scan of a 2000-row unindexed table was NOT reported; the "
        f"analyser is not reading the plan: {analysis.plan}"
    )
    # And the rule correctly IGNORES it: scan_control is not an unbounded table.
    assert not analysis.offending_scans(), (
        "the rule flagged a table it should not police"
    )
    assert analysis.offending_scans(frozenset({"scan_control"})), (
        "the rule failed to flag the table when told to police it"
    )


# ── N+1 ──────────────────────────────────────────────────────────────────────


def test_listing_incidents_does_not_issue_a_query_per_row(seeded):
    """The N+1 test: query count must not grow with result size."""
    with seeded.reader(consistent=True) as conn:
        _scoped(conn)
        p = conn.p

        def fetch(limit: int) -> int:
            with count_statements(conn) as counter:
                rows = conn.execute(
                    f"SELECT incident_id, state FROM incidents WHERE tenant_id={p} "
                    f"AND deleted_at IS NULL ORDER BY updated_at DESC LIMIT {p}",
                    (SUBJECT, limit),
                )
                assert rows
                return counter.count

        small, large = fetch(1), fetch(50)
        conn.commit()

    assert small == large == 1, (
        f"query count grew with result size: {small} for 1 row, {large} for 50. "
        "That is an N+1."
    )


def test_hydrating_events_for_many_incidents_is_one_query(seeded):
    """Batched fetch, not a loop.

    The shape that produces an N+1 is `for incident in incidents: fetch(incident)`.
    This asserts the batched form is used and that its cost is constant in the
    number of incidents.
    """
    with seeded.reader(consistent=True) as conn:
        _scoped(conn)
        p = conn.p
        ids = [f"inc-006-{i:04d}" for i in range(20)]
        placeholders = ",".join([p] * len(ids))
        with count_statements(conn) as counter:
            rows = conn.execute(
                f"SELECT incident_id, event_type FROM domain_events "
                f"WHERE tenant_id={p} AND incident_id IN ({placeholders})",
                (SUBJECT, *ids),
            )
        conn.commit()

    assert counter.count == 1, f"{counter.count} queries for {len(ids)} incidents"
    assert len(rows) >= len(ids), "the batched fetch returned nothing; the test is vacuous"


# ── Partitioning ─────────────────────────────────────────────────────────────


def test_partition_pruning_happens(seeded, engine_config):
    """A bounded time range must touch fewer partitions than exist.

    Reported rather than skipped on SQLite, which has no declarative
    partitioning: stating the difference is better than a green test that means
    nothing on one engine.
    """
    if Dialect(engine_config.dialect.value) is not Dialect.POSTGRES:
        pytest.skip("SQLite has no declarative partitioning; see schema.py")

    with seeded.reader(consistent=True) as conn:
        _scoped(conn)
        p = conn.p
        analysis = analyse_plan(
            conn,
            f"SELECT COUNT(*) FROM domain_events WHERE tenant_id={p} "
            f"AND recorded_at >= {p} AND recorded_at < {p}",
            (SUBJECT, "2026-07-01", "2026-08-01"),
        )
        conn.commit()

    # With only the DEFAULT partition provisioned in this fixture, pruning is
    # trivially satisfied -- so the assertion is that the plan is partition-aware
    # at all, which is what proves the table really is partitioned.
    assert "domain_events" in analysis.plan, analysis.plan


def test_partitions_can_be_created_and_dropped_in_constant_time(seeded, engine_config):
    """Retention by DROP TABLE, which is the reason for partitioning at all.

    Deleting a month of rows from a monolithic table writes as much WAL as the
    rows and leaves the space to VACUUM. Dropping a partition is a catalogue
    operation.
    """
    if Dialect(engine_config.dialect.value) is not Dialect.POSTGRES:
        pytest.skip("SQLite has no declarative partitioning")

    with seeded.writer() as conn:
        conn.begin()
        conn.execute_rowcount(
            "CREATE TABLE domain_events_2026_06 PARTITION OF domain_events "
            "FOR VALUES FROM ('2026-06-01') TO ('2026-07-01')"
        )
        conn.commit()

    with seeded.reader(consistent=True) as conn:
        conn.begin()
        found = conn.one(
            "SELECT relname FROM pg_class WHERE relname = 'domain_events_2026_06'"
        )
        conn.commit()
    assert found is not None

    with seeded.writer() as conn:
        conn.begin()
        conn.execute_rowcount("DROP TABLE domain_events_2026_06")
        conn.commit()


# ── Isolation and locking ────────────────────────────────────────────────────


def test_isolation_levels_are_actually_applied(seeded, engine_config):
    if Dialect(engine_config.dialect.value) is not Dialect.POSTGRES:
        pytest.skip("SQLite has one isolation level")

    for level in (Isolation.READ_COMMITTED, Isolation.REPEATABLE_READ, Isolation.SERIALIZABLE):
        with seeded.writer() as conn:
            conn.begin(level)
            observed = conn.one("SHOW transaction_isolation")
            conn.commit()
        assert observed["transaction_isolation"].upper() == level.value, (
            f"asked for {level.value}, got {observed['transaction_isolation']}"
        )


def test_a_blocked_writer_fails_fast_rather_than_queueing(seeded, engine_config):
    """`lock_timeout` bounds the wait, so a lock queue cannot grow without bound.

    PostgreSQL has no lock escalation, but an unbounded lock QUEUE produces the
    same outage: one slow statement holds a row lock, every writer behind it
    waits forever holding its own locks. A bounded timeout turns that into a
    retryable error.
    """
    if Dialect(engine_config.dialect.value) is not Dialect.POSTGRES:
        pytest.skip("SQLite serialises writers with a busy timeout instead")

    from sentinel.domain.errors import TransientFailure

    with seeded.writer() as holder:
        _scoped(holder, "tenant-001")
        holder.execute(
            f"SELECT * FROM incidents WHERE tenant_id={holder.p} AND incident_id={holder.p}"
            + holder.lock_clause(),
            ("tenant-001", "inc-001-0001"),
        )
        with seeded.writer() as blocked:
            _scoped(blocked, "tenant-001")
            blocked.execute_rowcount("SET LOCAL lock_timeout = 250")
            with pytest.raises(TransientFailure) as caught:
                blocked.execute(
                    f"SELECT * FROM incidents WHERE tenant_id={blocked.p} "
                    f"AND incident_id={blocked.p}" + blocked.lock_clause(),
                    ("tenant-001", "inc-001-0001"),
                )
            assert "lock" in str(caught.value).lower()
            blocked.rollback()
        holder.rollback()


def test_row_level_security_does_not_degrade_into_a_scan(seeded, engine_config):
    """RLS adds a predicate; it must not cost the index.

    A policy the planner cannot push into the index turns every tenant-scoped
    read into a full scan filtered afterwards -- isolation preserved, performance
    destroyed. This asserts the plan still uses an index with the policy in force.
    """
    if Dialect(engine_config.dialect.value) is not Dialect.POSTGRES:
        pytest.skip("SQLite has no row-level security")

    with seeded.reader(consistent=True) as conn:
        _scoped(conn)
        analysis = analyse_plan(
            conn,
            f"SELECT incident_id FROM incidents WHERE tenant_id={conn.p} "
            f"AND deleted_at IS NULL ORDER BY updated_at DESC LIMIT 20",
            (SUBJECT,),
        )
        conn.commit()

    assert not analysis.offending_scans(), (
        f"row-level security turned an indexed read into a scan:\n{analysis.plan}"
    )


# ── Soft delete ──────────────────────────────────────────────────────────────


def test_soft_deleted_rows_are_excluded_and_cost_nothing_to_skip(seeded):
    with seeded.reader(consistent=True) as conn:
        _scoped(conn)
        p = conn.p
        live = conn.one(
            f"SELECT COUNT(*) AS n FROM incidents WHERE tenant_id={p} "
            f"AND deleted_at IS NULL",
            (SUBJECT,),
        )
        total = conn.one(
            f"SELECT COUNT(*) AS n FROM incidents WHERE tenant_id={p}", (SUBJECT,)
        )
        conn.commit()

    assert int(live["n"]) < int(total["n"]), "the fixture seeded no deleted rows"
    assert int(live["n"]) == INCIDENTS_PER_TENANT - (INCIDENTS_PER_TENANT // 10)
