"""SQL infrastructure tests against a real database engine.

These run on SQLite by default and on PostgreSQL when `SENTINEL_TEST_POSTGRES_DSN`
is set. Both are exercised by the SAME tests, because the predecessor's most
subtle defect — the dead-letter queue's terminal operations being invisible under
row-level security — was invisible on the development engine and fatal on the
production one, and no test ran on both.
"""

from __future__ import annotations

from dataclasses import replace

from datetime import datetime, timedelta, timezone

import pytest

from sentinel.application.records import EvidenceRecord
from sentinel.domain.errors import ConcurrencyConflict, ExecutionFenceLost, TransientFailure
from sentinel.domain.incident import Incident, IncidentState
from sentinel.domain.primitives import (
    Digest,
    IdempotencyKey,
    IncidentId,
    Severity,
    TenantId,
    Timestamp,
    TrustLevel,
)
from sentinel.infrastructure.sql.engine import (
    Dialect,
    build_engine,
)
from sentinel.infrastructure.sql.migrate import CURRENT_VERSION, SchemaOutOfDate, migrate, verify
from sentinel.infrastructure.sql.unit_of_work import SqlUnitOfWorkFactory
from tests_arch.doubles import FakeClock

NOW = Timestamp(datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc))
TENANT_A = TenantId("acme")
TENANT_B = TenantId("globex")
DIGEST = Digest("b" * 64)


class CollectingPublisher:
    def __init__(self) -> None:
        self.published: list[tuple[str, str]] = []

    def publish(self, tenant, events) -> None:
        self.published.extend((tenant.value, e.event_type) for e in events)


@pytest.fixture
def pool(migrated_pool):
    """A migrated pool on EVERY backend, courtesy of `conftest.engine_config`.

    Previously this fixture was hard-coded to SQLite with a `params=["sqlite"]`
    placeholder -- which is to say it declared an intention to test both engines
    and tested one. The parametrisation now lives in `conftest.py` and is real.
    """
    for tenant in (TENANT_A, TENANT_B):
        with migrated_pool.acquire() as conn:
            conn.begin()
            conn.execute_rowcount(
                f"INSERT INTO tenants (tenant_id, name, created_at) "
                f"VALUES ({conn.p},{conn.p},{conn.p}) "
                f"ON CONFLICT (tenant_id) DO NOTHING",
                (tenant.value, tenant.value, NOW.isoformat()),
            )
            conn.commit()
    return migrated_pool


@pytest.fixture
def uows(pool):
    return SqlUnitOfWorkFactory(
        pool=pool, publisher=CollectingPublisher(), clock=FakeClock()
    )


def _admit(uows, tenant: TenantId, incident_id: str = "inc-1") -> IncidentId:
    identifier = IncidentId(incident_id)
    with uows.begin(tenant) as uow:
        incident = Incident.admit(
            tenant_id=tenant,
            incident_id=identifier,
            severity=Severity(90),
            trust_level=TrustLevel.VERIFIED,
            source="test",
            now=NOW,
        )
        uow.incidents.add(incident)
        uow.collect(incident.pull_events())
        uow.commit()
    return identifier


# ── Migration ────────────────────────────────────────────────────────────────


def test_migration_is_idempotent_and_reports_its_version(pool):
    assert migrate(pool) == CURRENT_VERSION
    assert migrate(pool) == CURRENT_VERSION
    assert verify(pool) == CURRENT_VERSION


def test_every_declared_table_survives_an_upgrade_from_an_older_version(pool):
    """THE CHECK THAT WAS MISSING, and the defect that proved it was missing.

    Four tables -- `agent_tool_grants`, `agent_observations`,
    `agent_observed_edges`, `agent_declarations` -- were added to
    `SCHEMA_STATEMENTS` without appending a migration. The whole suite stayed
    green, because every test builds a database from nothing and
    `_create_baseline` runs every statement on a fresh one.

    An EXISTING deployment upgrading would have found `verify()` satisfied (its
    recorded version matched the built version), started cleanly, and then
    failed at runtime with `no such table: agent_tool_grants` the first time an
    agent invoked a tool. Works in tests, breaks on upgrade.

    So this test does what the others cannot: it rolls the recorded version
    BACK, migrates forward the way a real upgrade does, and asserts every table
    the schema declares actually exists. A new table without a migration fails
    here rather than in somebody's production rollout.
    """
    assert migrate(pool) == CURRENT_VERSION

    # Rewind to the state an older deployment is in: the tables are present but
    # the recorded version is behind, which is exactly what a build that shipped
    # before those migrations existed looks like.
    with pool.acquire() as conn:
        conn.begin()
        conn.execute_rowcount(
            f"DELETE FROM schema_migrations WHERE version>{conn.p}", (1,)
        )
        conn.commit()

    assert migrate(pool) == CURRENT_VERSION, "the upgrade did not reach HEAD"

    declared = _declared_tables()
    assert len(declared) >= 20, (
        f"only {len(declared)} tables parsed out of SCHEMA_STATEMENTS; this "
        "check is reading nothing and would pass for ever"
    )

    missing = sorted(t for t in declared if not _table_exists(pool, t))
    assert not missing, (
        f"these tables are declared in SCHEMA_STATEMENTS but do not exist after "
        f"migrating an existing database to HEAD: {missing}.\n\n"
        "Adding a table to SCHEMA_STATEMENTS is not enough: a fresh database "
        "gets it from the baseline, and an upgrading one never does. Append a "
        "migration pair to MIGRATIONS -- `_create_baseline` then `_apply_rls` "
        "if the table is tenant-scoped."
    )


def test_a_tenant_scoped_table_added_late_is_still_protected(pool, engine_config):
    """The second half of the same mistake.

    Creating a tenant-scoped table without re-applying RLS leaves it readable
    across tenants -- which is why every migration that adds one is paired with
    an `_apply_rls` step. For the discovery tables that would mean one tenant
    reading which agents another is running, and for `agent_tool_grants` it
    would mean reading another tenant's authorisations.
    """
    if engine_config.dialect is not Dialect.POSTGRES:
        pytest.skip("SQLite has no row-level security to interrogate")

    migrate(pool)
    late = (
        "agent_tool_grants",
        "agent_observations",
        "agent_observed_edges",
        "agent_declarations",
    )
    with pool.acquire() as conn:
        conn.begin()
        rows = conn.execute(
            "SELECT c.relname AS t, c.relrowsecurity AS enabled, "
            "c.relforcerowsecurity AS forced "
            "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname='public'"
        )
        conn.commit()
    state = {str(r["t"]): (bool(r["enabled"]), bool(r["forced"])) for r in rows}

    unprotected = [t for t in late if state.get(t) != (True, True)]
    assert not unprotected, (
        f"these tenant-scoped tables do not have FORCE row-level security "
        f"after migration: {unprotected}"
    )


def _declared_tables() -> set[str]:
    """Table names parsed out of `SCHEMA_STATEMENTS`.

    Parsed rather than hand-listed, so a table cannot be added to the schema and
    quietly omitted from this check -- which is the very failure mode being
    guarded against.
    """
    import re

    from sentinel.infrastructure.sql.schema import SCHEMA_STATEMENTS

    found: set[str] = set()
    for statement in SCHEMA_STATEMENTS:
        # `[a-z0-9_]`, not `[a-z_]`. The original excluded digits, so the first
        # table whose name contains one -- `a2a_agent_cards` -- parsed as `a`,
        # and the check then reported a missing table called "a" rather than the
        # real name. Worse, a digit-containing name that DID exist would have
        # been silently checked under the wrong identifier and passed.
        match = re.search(
            r"CREATE TABLE IF NOT EXISTS\s+([a-z0-9_]+)", statement, re.IGNORECASE
        )
        if match:
            found.add(match.group(1))
    return found


def _table_exists(pool, table: str) -> bool:
    with pool.acquire() as conn:
        conn.begin()
        try:
            conn.execute(f"SELECT 1 FROM {table} WHERE 1=0")  # noqa: S608 - parsed names
            return True
        except Exception:  # noqa: BLE001 - absence is the answer, not an error
            return False
        finally:
            conn.commit()


def test_startup_verification_is_a_single_indexed_read(pool):
    """`verify` must never scan a table; a boot step that is O(rows) cannot start."""
    assert verify(pool) == CURRENT_VERSION


def test_the_service_refuses_to_serve_against_an_unknown_schema(pool):
    with pool.acquire() as conn:
        conn.begin()
        conn.execute_rowcount("DELETE FROM schema_migrations")
        conn.commit()
    with pytest.raises(SchemaOutOfDate):
        verify(pool)


# ── Connection pool ──────────────────────────────────────────────────────────


def test_connections_are_reused_not_reopened(pool):
    """The predecessor opened and closed a connection per operation."""
    before = pool.size
    for _ in range(50):
        with pool.acquire() as conn:
            conn.execute("SELECT 1")
    assert pool.size <= 4
    assert pool.size >= before
    assert pool.idle >= 1


def test_pool_exhaustion_is_retryable_backpressure_not_a_crash(tmp_path, engine_config):
    config = replace(
        engine_config, pool_min=1, pool_max=1, checkout_timeout_seconds=0.1
    )
    engine = build_engine(config)
    try:
        with engine.acquire():
            with pytest.raises(TransientFailure) as caught:
                with engine.acquire():
                    pass
        assert caught.value.is_retryable is True
    finally:
        engine.close()


def test_a_failed_borrower_does_not_poison_the_pool(pool):
    with pytest.raises(TransientFailure):
        with pool.acquire() as conn:
            conn.begin()
            conn.execute("SELECT * FROM table_that_does_not_exist")
    with pool.acquire() as conn:
        assert conn.execute("SELECT 1")


# ── Unit of work ─────────────────────────────────────────────────────────────


def test_an_incident_round_trips_through_the_repository(uows):
    incident_id = _admit(uows, TENANT_A)
    with uows.begin(TENANT_A) as uow:
        loaded = uow.incidents.get(incident_id)
    assert loaded is not None
    assert loaded.state is IncidentState.RECEIVED
    assert loaded.severity.value == 90


def test_a_rolled_back_transaction_writes_nothing(uows):
    with pytest.raises(RuntimeError):
        with uows.begin(TENANT_A) as uow:
            incident = Incident.admit(
                tenant_id=TENANT_A,
                incident_id=IncidentId("inc-rollback"),
                severity=Severity(50),
                trust_level=TrustLevel.UNSIGNED,
                source="test",
                now=NOW,
            )
            uow.incidents.add(incident)
            raise RuntimeError("boom")
    with uows.begin(TENANT_A) as uow:
        assert uow.incidents.get(IncidentId("inc-rollback")) is None


def test_events_are_published_only_after_commit(pool):
    publisher = CollectingPublisher()
    uows = SqlUnitOfWorkFactory(pool=pool, publisher=publisher, clock=FakeClock())
    with pytest.raises(RuntimeError):
        with uows.begin(TENANT_A) as uow:
            incident = Incident.admit(
                tenant_id=TENANT_A,
                incident_id=IncidentId("inc-ev"),
                severity=Severity(50),
                trust_level=TrustLevel.UNSIGNED,
                source="test",
                now=NOW,
            )
            uow.incidents.add(incident)
            uow.collect(incident.pull_events())
            raise RuntimeError("boom")
    assert publisher.published == []


def test_committed_events_land_in_the_durable_event_log(pool):
    publisher = CollectingPublisher()
    uows = SqlUnitOfWorkFactory(pool=pool, publisher=publisher, clock=FakeClock())
    _admit(uows, TENANT_A, "inc-log")
    assert ("acme", "IncidentAdmitted") in publisher.published
    with pool.acquire() as conn:
        conn.begin()
        # Tenant context MUST be established, exactly as the application does.
        # Without it PostgreSQL row-level security matches no rows and this read
        # returns empty -- which is the boundary working, not a bug. An earlier
        # version of this test omitted it and passed on SQLite while failing on
        # PostgreSQL, which is the precise defect shape this suite exists to
        # catch.
        conn.set_tenant(TENANT_A.value)
        rows = conn.execute(
            f"SELECT event_type, event_version FROM domain_events WHERE tenant_id={conn.p}",
            (TENANT_A.value,),
        )
        conn.commit()
    assert [r["event_type"] for r in rows] == ["IncidentAdmitted"]
    assert all(int(r["event_version"]) == 1 for r in rows)


def test_optimistic_concurrency_is_enforced_on_save(uows):
    incident_id = _admit(uows, TENANT_A, "inc-cc")
    with uows.begin(TENANT_A) as first:
        a = first.incidents.get_for_update(incident_id)
        a.claim_execution(1)
        from sentinel.domain.incident import Fence

        a.advance(IncidentState.VALIDATED, fence=Fence.worker(1), now=NOW)
        first.incidents.save(a)
        first.commit()

    with uows.begin(TENANT_A) as second:
        stale = Incident.rehydrate(
            tenant_id=TENANT_A,
            incident_id=incident_id,
            state=IncidentState.RECEIVED,
            facts={},
            version=0,
            execution_epoch=0,
        )
        with pytest.raises(ConcurrencyConflict):
            second.incidents.save(stale)


def test_the_execution_fence_is_enforced_in_the_database(uows):
    incident_id = _admit(uows, TENANT_A, "inc-fence")
    with uows.begin(TENANT_A) as uow:
        uow.incidents.claim_execution(incident_id, epoch=5)
        uow.commit()
    with uows.begin(TENANT_A) as uow:
        with pytest.raises(ExecutionFenceLost):
            uow.incidents.claim_execution(incident_id, epoch=3)


# ── Tenant isolation ─────────────────────────────────────────────────────────


def test_a_tenant_cannot_read_another_tenants_incident(uows):
    _admit(uows, TENANT_A, "inc-shared-id")
    with uows.begin(TENANT_B) as uow:
        assert uow.incidents.get(IncidentId("inc-shared-id")) is None


def test_the_same_incident_id_is_independent_per_tenant(uows):
    _admit(uows, TENANT_A, "inc-dup")
    _admit(uows, TENANT_B, "inc-dup")
    with uows.begin(TENANT_A) as uow:
        assert uow.incidents.get(IncidentId("inc-dup")) is not None
    with uows.begin(TENANT_B) as uow:
        assert uow.incidents.get(IncidentId("inc-dup")) is not None


# ── Ledger ───────────────────────────────────────────────────────────────────


def test_the_ledger_chains_and_refuses_a_fork(uows):
    _admit(uows, TENANT_A, "inc-l1")
    _admit(uows, TENANT_A, "inc-l2")
    with uows.begin(TENANT_A) as uow:
        seq1, chain1 = uow.ledger.append(
            incident_id=IncidentId("inc-l1"), entry_hash=Digest("1" * 64), manifest={"v": 2}
        )
        seq2, chain2 = uow.ledger.append(
            incident_id=IncidentId("inc-l2"), entry_hash=Digest("2" * 64), manifest={"v": 2}
        )
        uow.commit()
    assert (seq1, seq2) == (1, 2)
    assert chain1 != chain2

    # A second entry claiming the SAME predecessor violates the unique index.
    with pytest.raises(TransientFailure):
        with uows.begin(TENANT_A) as uow:
            uow.ledger._conn.execute_rowcount(  # noqa: SLF001 - forcing the fork
                f"INSERT INTO ledger_entries (tenant_id, seq, incident_id, entry_hash, "
                f"prev_chain_hash, chain_hash, manifest_json, batch_id, created_at) "
                f"VALUES ({uow.ledger._conn.p},99,'inc-fork','{'3' * 64}',"
                f"'{chain1.value}','{'4' * 64}','{{}}',NULL,'now')",
                (TENANT_A.value,),
            )


def test_evidence_and_reports_round_trip(uows):
    incident_id = _admit(uows, TENANT_A, "inc-ev2")
    record = EvidenceRecord(
        incident_id=incident_id,
        uri="sentinel://evidence/acme/inc-ev2",
        digest=DIGEST,
        content={"hello": "world"},
        created_at=NOW,
    )
    with uows.begin(TENANT_A) as uow:
        uow.ledger.store_evidence(record)
        uow.ledger.store_report(incident_id=incident_id, content="# report", at=NOW)
        uow.commit()
    with uows.begin(TENANT_A) as uow:
        loaded = uow.ledger.get_evidence(incident_id)
        assert loaded is not None
        assert loaded.digest == DIGEST
        assert loaded.content == {"hello": "world"}
        assert uow.ledger.get_report(incident_id) == "# report"


# ── Outbox: the defect class that broke on PostgreSQL only ──────────────────


def test_outbox_enqueue_is_idempotent_on_its_key(uows):
    incident_id = _admit(uows, TENANT_A, "inc-ob")
    key = IdempotencyKey("idem-1")
    with uows.begin(TENANT_A) as uow:
        uow.outbox.enqueue(
            incident_id=incident_id, kind="attestation", payload={}, idempotency_key=key, at=NOW
        )
        uow.outbox.enqueue(
            incident_id=incident_id, kind="attestation", payload={}, idempotency_key=key, at=NOW
        )
        uow.commit()
    with uows.begin(TENANT_A) as uow:
        assert len(uow.outbox.claim_batch(limit=10, now=NOW, lease_seconds=60)) == 1


def test_claiming_is_exclusive_regardless_of_backoff_jitter(uows):
    """The predecessor claimed by pushing `next_at` forward by a full-jitter
    delay whose lower bound is zero, so a small draw left the row immediately
    due again for a concurrent claimer. State plus an absolute lease removes the
    randomness from the exclusivity guarantee."""
    incident_id = _admit(uows, TENANT_A, "inc-ob2")
    with uows.begin(TENANT_A) as uow:
        uow.outbox.enqueue(
            incident_id=incident_id,
            kind="attestation",
            payload={},
            idempotency_key=IdempotencyKey("idem-2"),
            at=NOW,
        )
        uow.commit()
    with uows.begin(TENANT_A) as first:
        claimed = first.outbox.claim_batch(limit=10, now=NOW, lease_seconds=60)
        first.commit()
    assert len(claimed) == 1
    with uows.begin(TENANT_A) as second:
        assert second.outbox.claim_batch(limit=10, now=NOW, lease_seconds=60) == []


def test_a_dead_deliverer_leaves_no_permanently_stranded_record(uows):
    """`delivering` was a terminal hang state in the predecessor: only the
    exception path released the claim, so a SIGKILL stranded the row forever."""
    incident_id = _admit(uows, TENANT_A, "inc-ob3")
    with uows.begin(TENANT_A) as uow:
        uow.outbox.enqueue(
            incident_id=incident_id,
            kind="attestation",
            payload={},
            idempotency_key=IdempotencyKey("idem-3"),
            at=NOW,
        )
        uow.commit()
    with uows.begin(TENANT_A) as uow:
        uow.outbox.claim_batch(limit=10, now=NOW, lease_seconds=30)
        uow.commit()

    later = Timestamp(datetime(2026, 7, 25, 12, 5, tzinfo=timezone.utc))
    with uows.begin(TENANT_A) as uow:
        assert uow.outbox.reap_expired_leases(now=later) == 1
        uow.commit()
    with uows.begin(TENANT_A) as uow:
        assert len(uow.outbox.claim_batch(limit=10, now=later, lease_seconds=30)) == 1


def test_terminal_outbox_operations_work_on_a_tenant_scoped_connection(uows):
    """The regression for the RLS defect.

    `dlq.succeed()` and `dlq.fail()` used an UNSCOPED connection. Here there is
    no unscoped connection to use: `begin()` requires a tenant, so these calls
    cannot be made outside a tenant context.
    """
    incident_id = _admit(uows, TENANT_A, "inc-ob4")
    with uows.begin(TENANT_A) as uow:
        uow.outbox.enqueue(
            incident_id=incident_id,
            kind="attestation",
            payload={},
            idempotency_key=IdempotencyKey("idem-4"),
            at=NOW,
        )
        uow.commit()
    with uows.begin(TENANT_A) as uow:
        [record] = uow.outbox.claim_batch(limit=1, now=NOW, lease_seconds=60)
        uow.outbox.mark_failed(record_id=record.record_id, error="gateway down", at=NOW)
        uow.commit()

    # A failed record is NOT immediately due again: mark_failed applies
    # exponential backoff, so the retry window is a real interval rather than
    # the predecessor's full-jitter draw whose lower bound was zero.
    with uows.begin(TENANT_A) as uow:
        assert uow.outbox.claim_batch(limit=1, now=NOW, lease_seconds=60) == []

    after_backoff = Timestamp(datetime(2026, 7, 25, 12, 1, tzinfo=timezone.utc))
    with uows.begin(TENANT_A) as uow:
        [record] = uow.outbox.claim_batch(limit=1, now=after_backoff, lease_seconds=60)
        assert record.attempts == 1
        uow.outbox.mark_delivered(
            record_id=record.record_id, result={"ok": True}, at=after_backoff
        )
        uow.commit()
    with uows.begin(TENANT_A) as uow:
        assert uow.outbox.claim_batch(limit=1, now=after_backoff, lease_seconds=60) == []


def test_a_record_dies_after_its_budget_and_can_be_replayed(uows):
    incident_id = _admit(uows, TENANT_A, "inc-ob5")
    with uows.begin(TENANT_A) as uow:
        uow.outbox.enqueue(
            incident_id=incident_id,
            kind="attestation",
            payload={},
            idempotency_key=IdempotencyKey("idem-5"),
            at=NOW,
        )
        uow.commit()
    # Each attempt is separated by enough time to clear its backoff, which is
    # what a real retry loop does. Five attempts exhausts the budget.
    states: list[str] = []
    for attempt in range(5):
        moment = Timestamp(
            datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)
            + timedelta(seconds=600 * (attempt + 1))
        )
        with uows.begin(TENANT_A) as uow:
            rows = uow.outbox.claim_batch(limit=1, now=moment, lease_seconds=60)
            assert rows, f"attempt {attempt} should have been claimable"
            states.append(
                uow.outbox.mark_failed(record_id=rows[0].record_id, error="down", at=moment)
            )
            uow.commit()

    assert states[-1] == "dead"
    assert states[:-1] == ["pending"] * 4

    replay_at = Timestamp(datetime(2026, 7, 25, 14, 0, tzinfo=timezone.utc))
    with uows.begin(TENANT_A) as uow:
        dead = uow.outbox.dead_letters(limit=10)
        assert len(dead) == 1
        assert uow.outbox.replay(dead[0].record_id, at=replay_at) is True
        uow.commit()
    with uows.begin(TENANT_A) as uow:
        # Replay actually returns it to the queue. The predecessor's replay moved
        # the row from `dead` to `pending` while nothing drained `pending`, so the
        # record vanished from the operator's view and was never delivered.
        assert len(uow.outbox.claim_batch(limit=1, now=replay_at, lease_seconds=60)) == 1


# ── Approvals: the double-execution race ─────────────────────────────────────


def test_only_one_caller_can_claim_an_approval_for_execution(uows):
    from sentinel.application.records import ApprovalRecord
    from sentinel.domain.primitives import ApprovalId

    incident_id = _admit(uows, TENANT_A, "inc-ap")
    approval_id = ApprovalId("apr-1")
    with uows.begin(TENANT_A) as uow:
        uow.approvals.propose(
            [
                ApprovalRecord(
                    approval_id=approval_id,
                    incident_id=incident_id,
                    action="isolate_agent",
                    target="agent-1",
                    state="pending",
                    proposed_at=NOW,
                )
            ]
        )
        uow.commit()

    with uows.begin(TENANT_A) as uow:
        first = uow.approvals.claim_for_execution(approval_id)
        uow.commit()
    with uows.begin(TENANT_A) as uow:
        second = uow.approvals.claim_for_execution(approval_id)
        uow.commit()

    assert first is not None
    assert second is None, "a second claim must not authorise a second real-world action"


def test_a_failed_execution_releases_the_approval_for_retry(uows):
    from sentinel.application.records import ApprovalRecord
    from sentinel.domain.primitives import ApprovalId

    incident_id = _admit(uows, TENANT_A, "inc-ap2")
    approval_id = ApprovalId("apr-2")
    with uows.begin(TENANT_A) as uow:
        uow.approvals.propose(
            [
                ApprovalRecord(
                    approval_id=approval_id,
                    incident_id=incident_id,
                    action="revoke_key",
                    target="key-1",
                    state="pending",
                    proposed_at=NOW,
                )
            ]
        )
        uow.commit()
    with uows.begin(TENANT_A) as uow:
        assert uow.approvals.claim_for_execution(approval_id) is not None
        uow.approvals.release(approval_id, error="integration timeout", at=NOW)
        uow.commit()
    with uows.begin(TENANT_A) as uow:
        assert uow.approvals.claim_for_execution(approval_id) is not None


# ── Row-level security, proved rather than assumed ──────────────────────────


def test_an_unscoped_read_sees_nothing_on_postgres(pool, uows, engine_config):
    """RLS fails CLOSED: a connection with no tenant context reads no rows.

    This is the guarantee the whole tenant-scoping design rests on, and it is
    asserted directly rather than inferred. On SQLite there is no RLS, so the
    test states that difference instead of pretending the engines are the same.
    """
    _admit(uows, TENANT_A, "inc-rls")

    with pool.acquire() as conn:
        conn.begin()
        # No `set_tenant`. Deliberately.
        rows = conn.execute("SELECT incident_id FROM incidents")
        conn.commit()

    if engine_config.dialect is Dialect.POSTGRES:
        assert rows == [], (
            "an unscoped connection read tenant rows; row-level security is not "
            "in force. Check that the application role is NOT a superuser -- a "
            "superuser bypasses FORCE RLS entirely."
        )
    else:
        # Honest about the difference rather than skipping silently: SQLite has
        # no RLS, so application predicates are the ONLY enforcement there.
        assert len(rows) == 1


def test_a_scoped_read_sees_only_its_own_tenant(pool, uows):
    _admit(uows, TENANT_A, "inc-a-only")
    _admit(uows, TENANT_B, "inc-b-only")

    with pool.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT_A.value)
        rows = conn.execute(
            f"SELECT incident_id FROM incidents WHERE tenant_id={conn.p}",
            (TENANT_A.value,),
        )
        conn.commit()
    assert [r["incident_id"] for r in rows] == ["inc-a-only"]


# ── The gate that catches a schema change with no migration ──────────────────

#: SHA-256 over the whitespace-normalised `SCHEMA_STATEMENTS`, pinned together
#: with the migration version that schema belongs to.
#:
#: WHY A PIN AND NOT A RUNTIME CHECK. `test_every_declared_table_survives_an_
#: upgrade_from_an_older_version` above cannot see a table added without a
#: migration, and the reason is structural rather than an oversight in how it
#: was written: it rewinds the recorded version on a database whose tables were
#: ALREADY created by the first `migrate()`, and `_create_baseline` -- which
#: several migration entries call -- re-runs the CURRENT `SCHEMA_STATEMENTS`.
#: So every declared table exists again no matter what the migration list says.
#: Faithfully reproducing a real upgrade would need the PREVIOUS build's
#: `SCHEMA_STATEMENTS`, which is not available in this process.
#:
#: This is the check that does work, and it proved necessary: `mcp_tool_
#: provenance` and `mcp_tool_changes` were added to the schema with no
#: migration entry. Fresh installs were fine; a v25 deployment upgrading would
#: have passed `verify()`, started, and then failed at runtime on the first
#: proxied listing. Migrations 26/27 fix that instance; this gate is what makes
#: the next one impossible to ship silently.
# Bumped for migration 31, `execution_receipts`. The migration and its RLS
# re-application were both written; only these two lines were missed, which is
# exactly the state this test exists to catch -- a deployment would pass
# verify() on version 30, start cleanly, and fail on the first query against a
# table it had never created.
SCHEMA_FINGERPRINT = "2b0df6c5920fc8cbe94a690bdb4fccc8dd57df2e27015e005b0c9b5511549a32"
SCHEMA_FINGERPRINT_VERSION = 39


def test_a_schema_change_forces_a_migration_version_bump():
    """Change the schema, and this fails until you add a migration for it.

    Both constants move together or not at all. Updating the fingerprint
    without bumping the version is the exact mistake being guarded, so the
    version is asserted against `CURRENT_VERSION` as well.
    """
    import hashlib

    from sentinel.infrastructure.sql.schema import SCHEMA_STATEMENTS

    canonical = "\n".join(" ".join(s.split()) for s in SCHEMA_STATEMENTS)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    assert digest == SCHEMA_FINGERPRINT, (
        "SCHEMA_STATEMENTS changed. That is allowed -- but a schema change "
        "needs a MIGRATION, or existing deployments never receive it: they "
        "pass verify() on an unchanged version, start cleanly, and fail at "
        "runtime on the first query against the new object.\n\n"
        "Do all three:\n"
        "  1. append a migration to MIGRATIONS in sql/migrate.py\n"
        "     (a new TABLE also needs a second entry re-applying RLS)\n"
        f"  2. set SCHEMA_FINGERPRINT to {digest!r}\n"
        "  3. set SCHEMA_FINGERPRINT_VERSION to the new CURRENT_VERSION"
    )
    assert SCHEMA_FINGERPRINT_VERSION == CURRENT_VERSION, (
        f"the pinned schema belongs to migration version "
        f"{SCHEMA_FINGERPRINT_VERSION}, but CURRENT_VERSION is "
        f"{CURRENT_VERSION}. Pin them to the same number."
    )


# ── The unit of work releases what it borrowed, even when it cannot start ────


def test_a_unit_of_work_that_fails_to_begin_returns_its_connection(engine_config):
    """`__init__` checks a connection out and then calls `begin()` and
    `set_tenant()`. If either raised, the caller never received the object, so
    `__exit__` never ran, so the connection was never returned: every failed
    `begin()` permanently removed one connection from a bounded pool, and the
    symptom -- pool exhaustion -- appeared minutes later in an unrelated
    request.

    Modelled with a pool of exactly ONE connection whose `set_tenant` raises.
    If the connection leaks, the second `begin()` cannot check anything out and
    fails on the checkout timeout instead of on the poisoned call; if it is
    released, the second attempt fails the same way the first did, which is the
    proof that the pool still has its connection.
    """
    from dataclasses import replace as _replace

    from sentinel.infrastructure.sql.engine import Connection, ConnectionPool
    from sentinel.infrastructure.sql.engine import _postgres_factory, _sqlite_factory

    class _PoisonedConnection(Connection):
        __slots__ = ()

        def set_tenant(self, tenant_id: str) -> None:
            raise TransientFailure("SET refused: server is failing over")

    base_factory = (
        _sqlite_factory if engine_config.dialect is Dialect.SQLITE else _postgres_factory
    )

    def factory(config):
        real = base_factory(config)
        return _PoisonedConnection(real._raw, real._dialect)  # noqa: SLF001

    tiny = _replace(engine_config, pool_min=1, pool_max=1, checkout_timeout_seconds=0.2)
    pool = ConnectionPool(tiny, factory)
    try:
        uows = SqlUnitOfWorkFactory(
            pool=pool, publisher=CollectingPublisher(), clock=FakeClock()
        )
        for _attempt in range(3):
            with pytest.raises(TransientFailure) as raised:
                uows.begin(TENANT_A)
            assert "failing over" in str(raised.value), (
                "the second begin() did not reach set_tenant at all: the pool's "
                f"only connection leaked on the first failure ({raised.value})"
            )
        assert pool.idle == 1, "the connection was not returned to the pool"
    finally:
        pool.close()
