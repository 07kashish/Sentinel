"""`SENTINEL_RETENTION_DAYS` must actually delete something.

THE DEFECT
----------
The setting was parsed into `Settings.retention_days` and read by no code at all.
The Helm chart set it, and set `SENTINEL_RETENTION_INTERVAL` besides, which
`Settings` did not even parse. `schema.py` opens by explaining that two tables
are partitioned "for retention". `MaintenanceLoop`'s docstring refers to "its
retention job". `inbox` and `replay_nonces` each shipped a purge primitive with a
dedicated index -- `ix_inbox_age`, `ix_nonces_expiry` -- and neither primitive
had a single production caller. `work_queue.complete()` sets `state='done'` and
there is no `DELETE FROM work_queue` anywhere in the tree.

So four tables grew for the life of a deployment while the configuration said
otherwise. These tests hold the sweep to deleting what it should, and -- more
importantly -- to NOT deleting the security record, which is a compliance
decision rather than a disk-space one.

THE SECOND DEFECT, FOUND BECAUSE THESE TESTS ONLY EVER RAN ON SQLITE
---------------------------------------------------------------------
The fix for the above was verified on SQLite and nothing else. On PostgreSQL --
which is what production runs -- the sweep deleted **nothing**, and reported
zero rather than failing:

    before: work_queue = 1  inbox = 1
    sweep reported: {... 'retention_rows_deleted': 0}
    after : work_queue = 1  inbox = 1
    RESULT: DEFECT CONFIRMED

Every swept table is in `PROTECTED_TABLES` under `FORCE ROW LEVEL SECURITY`. The
sweep took a pooled connection and never established a tenant, so
`current_setting('sentinel.tenant_id', true)` was NULL and every DELETE matched
no rows. That is the identical shape of the `delivery_queue` defect this
codebase's own docstrings hold up as the reason the SQL suites are parametrised
over both engines -- and this module was not.

So every test here now runs on BOTH engines. A retention test that only runs on
SQLite cannot see the one failure mode that matters, because SQLite has no
row-level security for the sweep to fall foul of.
"""

from __future__ import annotations

import re
from datetime import timedelta
from pathlib import Path

import pytest

from sentinel.composition.container import build_container
from sentinel.composition.settings import ConfigurationError, Settings
from sentinel.domain.incident import IncidentState
from sentinel.domain.primitives import TenantId, Timestamp
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.infrastructure.sql.retention import (
    APPEND_ONLY_TABLES,
    INCIDENT_CHILD_TABLES,
    SqlRetention,
)
from sentinel.infrastructure.sql.schema import SCHEMA_STATEMENTS
from sentinel.interface.worker import MaintenanceLoop

TENANT = TenantId("acme")
KEY = "r" * 40


#: Passed to every sweep call. The argument is required precisely so that a
#: caller cannot forget the tenant context and get a silent zero on PostgreSQL.
TENANTS = [TENANT]


@pytest.fixture(scope="module")
def retention_postgres_dsn(postgres_admin_dsn, postgres_dsn) -> str | None:
    """ONE PostgreSQL database for this whole module, created once.

    The obvious shape -- `_fresh_database()` per test, as `conftest.engine_config`
    does -- costs a `CREATE DATABASE` plus a full `migrate()` per test. With this
    module parametrised over two engines that is sixty-odd new databases in one
    file, and measured here it did not merely run slowly: the embedded server
    accumulated backends until the run stopped making progress entirely (21
    `postgres.exe` processes, no new test for 3.5 minutes, CPU idle).

    So the database is created once and `_truncate` empties it between tests. The
    isolation that matters for these tests is empty tables, not a private
    catalogue.
    """
    if postgres_dsn is None:
        return None
    from tests_arch.conftest import _fresh_database

    return _fresh_database(postgres_admin_dsn, postgres_dsn)


def _truncate(dsn: str) -> None:
    """Empty every table, so each test starts from the same place.

    `TRUNCATE` rather than `DROP DATABASE`: it is one statement, it keeps the
    schema and the row-level-security policies in place, and it is not subject to
    RLS -- which matters, because a DELETE here would be bounded by the tenant
    context exactly like the sweep under test and could leave rows behind while
    appearing to succeed.
    """
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as conn:
        names = [
            r[0]
            for r in conn.execute(
                "SELECT tablename FROM pg_tables WHERE schemaname='public' "
                "AND tablename <> 'schema_migrations'"
            ).fetchall()
        ]
        if names:
            conn.execute(
                "TRUNCATE " + ", ".join(f'"{n}"' for n in names) + " RESTART IDENTITY"
            )


def _env(engine: str, tmp_path, dsn, **extra) -> dict:
    base = {
        "SENTINEL_ENV": "development",
        "SENTINEL_API_KEYS": f"{TENANT}:{KEY}:admin",
        "SENTINEL_RETENTION_DAYS": "7",
        "SENTINEL_RETENTION_INTERVAL": "1",
        **extra,
    }
    if engine == "sqlite":
        return {**base, "SENTINEL_DB_PATH": str(tmp_path / "retention.db")}
    if dsn is None:
        pytest.skip(
            "no PostgreSQL available: install `pgserver` or set "
            "SENTINEL_TEST_POSTGRES_DSN. Skipping is reported, never silent."
        )
    _truncate(dsn)
    return {**base, "SENTINEL_DATABASE_URL": dsn}


def _build(env: dict):
    settings = Settings.from_environment(env)
    pool = build_engine(settings.engine)
    migrate(pool)
    pool.close()
    return build_container(settings)


@pytest.fixture(params=["sqlite", "postgres"])
def container(request, tmp_path, retention_postgres_dsn):
    """The shipped configuration: incident retention UNSET. Both engines."""
    built = _build(_env(request.param, tmp_path, retention_postgres_dsn))
    try:
        yield built
    finally:
        built.close()


@pytest.fixture(params=["sqlite", "postgres"])
def container_with_incident_retention(request, tmp_path, retention_postgres_dsn):
    """An operator who has set a window and signed for it. Both engines."""
    built = _build(
        _env(
            request.param,
            tmp_path,
            retention_postgres_dsn,
            SENTINEL_INCIDENT_RETENTION_DAYS="30",
        )
    )
    try:
        yield built
    finally:
        built.close()


def _insert(container, sql: str, params: tuple) -> None:
    """Write as the tenant, exactly as the application does.

    `set_tenant` is not optional here: under FORCE RLS the policy's `WITH CHECK`
    half rejects an INSERT whose `tenant_id` does not match the context, so an
    unscoped write fails rather than silently landing somewhere odd.
    """
    with container.pool.acquire() as conn:
        conn.begin()
        conn.set_tenant(str(TENANT))
        conn.execute(sql.replace("?", conn.p), params)
        conn.commit()


def _count(container, table: str) -> int:
    """Count as the tenant. An unscoped count returns 0 on PostgreSQL for every
    protected table, which would make every "it was deleted" assertion pass
    vacuously -- the precise failure this module was rewritten to stop."""
    with container.pool.acquire() as conn:
        conn.begin()
        conn.set_tenant(str(TENANT))
        row = conn.one(f"SELECT COUNT(*) AS n FROM {table}")  # noqa: S608 - fixed names
        conn.commit()
    return int(row["n"])


def _seed(container, *, age_days: int) -> Timestamp:
    """One row in each operational table, `age_days` old."""
    now = container.clock.now()
    old = Timestamp(now.value - timedelta(days=age_days)).isoformat()
    _insert(
        container,
        "INSERT INTO work_queue (tenant_id, work_id, incident_id, shard, priority, "
        "payload_json, state, attempts, enqueued_at, available_at) "
        "VALUES (?,?,?,?,?,?,'done',0,?,?)",
        # `priority` is INTEGER. The previous literal here was the string 'HIGH',
        # which SQLite accepts by dynamic typing and PostgreSQL rejects outright
        # -- another way this file was only ever a SQLite test.
        (str(TENANT), f"w-{age_days}", f"inc-{age_days}", 0, 10, "{}", old, old),
    )
    _insert(
        container,
        "INSERT INTO outbox (tenant_id, record_id, incident_id, kind, payload_json, "
        "idempotency_key, state, attempts, max_attempts, available_at, created_at, updated_at) "
        "VALUES (?,?,?,'webhook','{}',?,'delivered',1,5,?,?,?)",
        (str(TENANT), f"o-{age_days}", f"inc-{age_days}", f"idem-{age_days}", old, old, old),
    )
    _insert(
        container,
        "INSERT INTO inbox (tenant_id, message_id, kind, accepted_at) VALUES (?,?,'work',?)",
        (str(TENANT), f"m-{age_days}", old),
    )
    return now


# ── The regression for the silent-zero defect ────────────────────────────────


def test_the_sweep_reports_what_the_database_actually_lost(container):
    """The sweep's own count must agree with the table, on BOTH engines.

    This is the test that was missing. The previous suite asserted the returned
    counts and asserted the tables were empty -- but only ever on SQLite, where
    both were true. On PostgreSQL both were ALSO self-consistent, at zero: the
    sweep reported deleting nothing and nothing had been deleted, so an assertion
    on the return value alone would have agreed with an assertion on the table
    and both would have been agreeing about a total failure.

    What makes this one bite is `before - after == reported` combined with a
    non-zero `before`: a sweep that deletes nothing now fails the `reported`
    assertion instead of quietly satisfying a pair of consistent zeroes.
    """
    _seed(container, age_days=30)
    before = {t: _count(container, t) for t in ("work_queue", "outbox", "inbox")}
    assert before == {"work_queue": 1, "outbox": 1, "inbox": 1}

    swept = container.retention.sweep(
        now=container.clock.now(), retention_days=7, tenants=TENANTS
    )

    after = {t: _count(container, t) for t in before}
    observed = sum(before[t] - after[t] for t in before)
    assert observed == 3, (
        f"the sweep left rows behind: before={before} after={after}. On PostgreSQL "
        "this is what an unscoped DELETE under FORCE row-level security looks "
        "like -- zero rows matched, no error raised."
    )
    assert swept.total == observed, (
        f"the sweep reported {swept.total} deletions and the database lost "
        f"{observed}. A retention job whose count disagrees with reality is worse "
        "than one that does nothing, because it is believed."
    )


def test_the_sweep_does_not_reach_across_tenants(container):
    """A sweep for tenant A must not delete tenant B's rows.

    Belt and braces again: RLS enforces this on PostgreSQL and the explicit
    `tenant_id = ?` predicate enforces it on SQLite, which has no RLS. Sweeping
    with an empty tenant list is the sharpest version of the question -- it must
    delete nothing at all, rather than everything.
    """
    _seed(container, age_days=30)
    swept = container.retention.sweep(
        now=container.clock.now(), retention_days=7, tenants=[]
    )
    assert swept.work_queue_done == 0
    assert _count(container, "work_queue") == 1, (
        "a sweep with no tenants deleted rows; the statements are not scoped"
    )


# ── What it deletes ──────────────────────────────────────────────────────────


def test_finished_operational_rows_past_the_window_are_deleted(container):
    _seed(container, age_days=30)
    assert _count(container, "work_queue") == 1
    assert _count(container, "outbox") == 1
    assert _count(container, "inbox") == 1

    swept = container.retention.sweep(now=container.clock.now(), retention_days=7, tenants=TENANTS)

    assert swept.work_queue_done == 1
    assert swept.outbox_delivered == 1
    assert swept.inbox_entries == 1
    assert _count(container, "work_queue") == 0
    assert _count(container, "outbox") == 0
    assert _count(container, "inbox") == 0


def test_rows_inside_the_window_are_kept(container):
    _seed(container, age_days=1)
    swept = container.retention.sweep(now=container.clock.now(), retention_days=7, tenants=TENANTS)
    assert swept.total == 0
    assert _count(container, "work_queue") == 1
    assert _count(container, "outbox") == 1
    assert _count(container, "inbox") == 1


def test_unfinished_work_is_never_deleted_however_old(container):
    """Age is not the criterion for pending work -- doing it is.

    A stuck-but-pending item is a bug to investigate, not garbage. Deleting it on
    age would make the queue silently lose work whenever a backlog outlived the
    retention window.
    """
    now = container.clock.now()
    old = Timestamp(now.value - timedelta(days=365)).isoformat()
    _insert(
        container,
        "INSERT INTO work_queue (tenant_id, work_id, incident_id, shard, priority, "
        "payload_json, state, attempts, enqueued_at, available_at) "
        "VALUES (?,?,?,?,?,?,'pending',0,?,?)",
        (str(TENANT), "w-pending", "inc-1", 0, 10, "{}", old, old),
    )
    container.retention.sweep(now=now, retention_days=7, tenants=TENANTS)
    assert _count(container, "work_queue") == 1


def test_expired_nonces_are_purged_on_their_own_expiry(container):
    """The replay guard already refuses them; keeping them only costs space."""
    now = container.clock.now()
    expired = Timestamp(now.value - timedelta(minutes=5)).isoformat()
    live = Timestamp(now.value + timedelta(minutes=5)).isoformat()
    for label, expires in (("gone", expired), ("live", live)):
        _insert(
            container,
            "INSERT INTO replay_nonces (tenant_id, agent, event_digest, seen_at, expires_at) "
            "VALUES (?,?,?,?,?)",
            (str(TENANT), f"0x{label}", f"digest-{label}", now.isoformat(), expires),
        )
    swept = container.retention.sweep(now=now, retention_days=7, tenants=TENANTS)
    assert swept.replay_nonces == 1
    assert _count(container, "replay_nonces") == 1


# ── What it must never delete ────────────────────────────────────────────────


def test_the_security_record_is_never_swept(container):
    """Incident history is a compliance decision, not a disk-space one.

    If this ever needs to change it needs its own setting and a human's
    signature, not a quiet widening of the housekeeping job.
    """
    now = container.clock.now()
    old = Timestamp(now.value - timedelta(days=365)).isoformat()
    _insert(
        container,
        "INSERT INTO incidents (tenant_id, incident_id, state, facts_json, version, "
        "execution_epoch, created_at, updated_at) VALUES (?,?,'received','{}',1,0,?,?)",
        (str(TENANT), "inc-keepme", old, old),
    )
    _insert(
        container,
        "INSERT INTO domain_events (tenant_id, event_id, incident_id, event_type, "
        "event_version, payload_json, occurred_at, recorded_at) "
        "VALUES (?,?,?,'IncidentAdmitted',1,'{}',?,?)",
        (str(TENANT), "ev-keepme", "inc-keepme", old, old),
    )

    container.retention.sweep(now=now, retention_days=1, tenants=TENANTS)

    assert _count(container, "incidents") == 1, "the sweep deleted an incident record"
    assert _count(container, "domain_events") == 1, "the sweep deleted event history"


def test_a_non_positive_window_is_refused(container):
    """Zero would purge the dedup journal and the replay guard while in use."""
    for bad in (0, -1):
        with pytest.raises(ValueError, match="must be positive"):
            container.retention.sweep(now=container.clock.now(), retention_days=bad, tenants=TENANTS)


# ── It is actually wired to something that runs ──────────────────────────────


def test_the_maintenance_loop_runs_the_sweep(container):
    """The primitives existed before and nothing called them. That was the bug."""
    _seed(container, age_days=30)
    loop = MaintenanceLoop(container, tenants=lambda: [TENANT], interval_seconds=60)
    totals = loop.run_once()

    assert totals["retention_rows_deleted"] >= 3
    assert _count(container, "work_queue") == 0
    assert _count(container, "inbox") == 0


def test_the_sweep_is_rate_limited_between_ticks(container):
    """The loop ticks every 30s; retention windows are measured in days."""
    _seed(container, age_days=30)
    loop = MaintenanceLoop(container, tenants=lambda: [TENANT], interval_seconds=60)
    assert loop.run_once()["retention_rows_deleted"] >= 3
    # Immediately again: inside SENTINEL_RETENTION_INTERVAL, so it must not run.
    assert "retention_rows_deleted" not in loop.run_once()


def test_the_chart_interval_setting_is_now_actually_parsed():
    """`SENTINEL_RETENTION_INTERVAL` was set by the chart and read by nobody."""
    settings = Settings.from_environment(
        {
            "SENTINEL_ENV": "development",
            "SENTINEL_API_KEYS": f"{TENANT}:{KEY}:admin",
            "SENTINEL_DB_PATH": ":memory:",
            "SENTINEL_RETENTION_INTERVAL": "1234",
        }
    )
    assert settings.retention_interval_seconds == 1234


def test_retention_is_constructed_by_the_composition_root(container):
    assert isinstance(container.retention, SqlRetention)


# ── Incident history: the second policy, off unless an operator turns it on ──
#
# This is the row `docs/PRODUCTION_READINESS_REPORT.md` carried as "open -- needs
# a human". The human decision is WHICH NUMBER, and that has not been made and is
# not made here. What is implemented is the mechanism plus the guarantee that
# without a number, nothing is deleted.


def _seed_incident(container, *, incident_id: str, state: str, age_days: int) -> None:
    """One terminal-or-not incident with its transitions, events, steps and report."""
    now = container.clock.now()
    old = Timestamp(now.value - timedelta(days=age_days)).isoformat()
    _insert(
        container,
        "INSERT INTO incidents (tenant_id, incident_id, state, facts_json, version, "
        "execution_epoch, created_at, updated_at) VALUES (?,?,?,'{}',1,0,?,?)",
        (str(TENANT), incident_id, state, old, old),
    )
    _insert(
        container,
        "INSERT INTO incident_transitions (tenant_id, incident_id, seq, from_state, "
        "to_state, facts_added, actor, occurred_at) VALUES (?,?,1,'received',?,'{}','test',?)",
        (str(TENANT), incident_id, state, old),
    )
    _insert(
        container,
        "INSERT INTO domain_events (tenant_id, event_id, incident_id, event_type, "
        "event_version, payload_json, occurred_at, recorded_at) "
        "VALUES (?,?,?,'IncidentAdmitted',1,'{}',?,?)",
        (str(TENANT), f"ev-{incident_id}", incident_id, old, old),
    )


def test_incident_history_is_never_touched_while_the_setting_is_unset(container):
    """The shipped default. No window is configured, so nothing may be deleted.

    Age is deliberately absurd -- a year old, terminal, past every plausible
    window -- so that a sweep which reaped on any implicit default would fail
    here rather than pass by luck.
    """
    _seed_incident(
        container, incident_id="inc-old", state=IncidentState.FAILED.value, age_days=365
    )
    assert container.settings.incident_retention_days is None

    swept = container.retention.sweep_incident_history(
        now=container.clock.now(),
        incident_retention_days=container.settings.incident_retention_days,
        tenants=TENANTS,
    )

    assert swept.configured is False
    assert swept.total == 0
    assert _count(container, "incidents") == 1
    assert _count(container, "domain_events") == 1
    assert _count(container, "incident_transitions") == 1


def test_the_maintenance_loop_issues_no_incident_delete_while_unset(container):
    """End to end: the wired-up loop, not just the primitive.

    The retention bug this module exists for was a primitive that worked and had
    no caller. The inverse -- a caller that runs when it must not -- is the
    failure mode that matters for a compliance switch, so it is asserted through
    the same path production uses.
    """
    _seed_incident(
        container, incident_id="inc-old", state=IncidentState.FAILED.value, age_days=365
    )
    loop = MaintenanceLoop(container, tenants=lambda: [TENANT], interval_seconds=60)
    totals = loop.run_once()

    assert "incident_retention_rows_deleted" not in totals
    assert _count(container, "incidents") == 1
    assert _count(container, "domain_events") == 1
    assert _count(container, "incident_transitions") == 1


def test_incident_history_is_deleted_once_a_window_is_configured(
    container_with_incident_retention,
):
    container = container_with_incident_retention
    assert container.settings.incident_retention_days == 30
    _seed_incident(
        container, incident_id="inc-old", state=IncidentState.FAILED.value, age_days=365
    )

    swept = container.retention.sweep_incident_history(
        now=container.clock.now(), incident_retention_days=30, tenants=TENANTS
    )

    assert swept.configured is True
    assert swept.incidents == 1
    assert swept.domain_events == 1
    assert swept.incident_transitions == 1
    assert _count(container, "incidents") == 0
    assert _count(container, "domain_events") == 0
    assert _count(container, "incident_transitions") == 0


def test_incidents_inside_the_window_are_kept(container_with_incident_retention):
    container = container_with_incident_retention
    _seed_incident(
        container, incident_id="inc-recent", state=IncidentState.FAILED.value, age_days=5
    )
    swept = container.retention.sweep_incident_history(
        now=container.clock.now(), incident_retention_days=30, tenants=TENANTS
    )
    assert swept.total == 0
    assert _count(container, "incidents") == 1


def test_no_non_terminal_incident_is_ever_reaped_however_old(
    container_with_incident_retention,
):
    """A stalled pipeline is a bug to investigate, not garbage to collect.

    Covers EVERY non-terminal state in one sweep, read from the enum rather than
    listed, so a state added later is covered without anyone remembering to. That
    includes `attestation_unavailable`, which looks finished and is not, and it
    includes the states a future contributor adds.

    One sweep over all of them rather than one test per state: each
    parametrisation would build a container and, on PostgreSQL, create and
    migrate a fresh database -- roughly half a minute of setup to exercise a
    single WHERE clause. Seeding them together is the same assertion at a
    twenty-fourth of the cost, and it additionally proves the terminal filter
    holds when terminal and non-terminal rows are MIXED, which per-state runs
    never see.
    """
    container = container_with_incident_retention
    non_terminal = sorted(s.value for s in IncidentState if not s.is_terminal)
    assert non_terminal, "the enum has no non-terminal states; this test is vacuous"
    for state in non_terminal:
        _seed_incident(container, incident_id=f"inc-{state}", state=state, age_days=365)
    # One terminal incident alongside them, so the test also shows the sweep is
    # not simply doing nothing.
    _seed_incident(
        container, incident_id="inc-terminal", state=IncidentState.FAILED.value,
        age_days=365,
    )

    swept = container.retention.sweep_incident_history(
        now=container.clock.now(), incident_retention_days=30, tenants=TENANTS
    )

    assert swept.incidents == 1, (
        f"expected exactly the terminal incident to be reaped, got "
        f"{swept.incidents} of {len(non_terminal) + 1}"
    )
    remaining = _count(container, "incidents")
    assert remaining == len(non_terminal), (
        f"{len(non_terminal)} non-terminal incidents were seeded and {remaining} "
        f"survive; the sweep reaped a non-terminal incident. States: {non_terminal}"
    )


def test_the_evidence_ledger_survives_an_incident_history_sweep(
    container_with_incident_retention,
):
    """The commitment outlives the record, on purpose.

    Trimming a hash chain destroys the non-repudiation it exists to provide, so
    an incident may be deleted while its ledger entry, batch, evidence row and
    audit trail all remain. That asymmetry is the point: the ledger still proves
    the incident existed and what its evidence hashed to, without retaining the
    content.
    """
    container = container_with_incident_retention
    now = container.clock.now()
    old = Timestamp(now.value - timedelta(days=365)).isoformat()
    _seed_incident(
        container, incident_id="inc-gone", state=IncidentState.COMPLETED_ATTESTED.value,
        age_days=365,
    )
    _insert(
        container,
        "INSERT INTO ledger_entries (tenant_id, seq, incident_id, entry_hash, "
        "prev_chain_hash, chain_hash, manifest_json, batch_id, created_at) "
        "VALUES (?,1,?,?,?,?,'{}',NULL,?)",
        (str(TENANT), "inc-gone", "e" * 64, "0" * 64, "c" * 64, old),
    )
    _insert(
        container,
        "INSERT INTO evidence (tenant_id, incident_id, uri, digest, content_json, "
        "created_at) VALUES (?,?,'s3://x',?,'{}',?)",
        (str(TENANT), "inc-gone", "d" * 64, old),
    )
    _insert(
        container,
        "INSERT INTO security_audit (tenant_id, seq, actor, action, resource_type, "
        "resource_id, outcome, occurred_at, detail, prev_chain_hash, chain_hash) "
        "VALUES (?,1,'analyst','close','incident',?,'success',?,'{}',?,?)",
        (str(TENANT), "inc-gone", old, "0" * 64, "a" * 64),
    )

    swept = container.retention.sweep_incident_history(
        now=now, incident_retention_days=30, tenants=TENANTS
    )

    assert swept.incidents == 1, "precondition: the incident should have been reaped"
    assert _count(container, "ledger_entries") == 1, "the sweep broke the hash chain"
    assert _count(container, "evidence") == 1, "the sweep deleted committed evidence"
    assert _count(container, "security_audit") == 1, "the sweep trimmed the audit trail"


def test_a_zero_incident_window_is_refused_rather_than_read_as_forever(
    container_with_incident_retention,
):
    """`0` is ambiguous between "delete everything" and "keep everything".

    Both readings are defensible and they are opposites, which is precisely why
    guessing is not allowed. Unset is the only way to say "keep everything".
    """
    for bad in (0, -1):
        with pytest.raises(ValueError, match="must be positive"):
            container_with_incident_retention.retention.sweep_incident_history(
                now=container_with_incident_retention.clock.now(),
                incident_retention_days=bad,
                tenants=TENANTS,
            )


def test_the_setting_defaults_to_unset_and_refuses_zero():
    base = {
        "SENTINEL_ENV": "development",
        "SENTINEL_API_KEYS": f"{TENANT}:{KEY}:admin",
        "SENTINEL_DB_PATH": ":memory:",
    }
    assert Settings.from_environment(base).incident_retention_days is None
    assert (
        Settings.from_environment(
            {**base, "SENTINEL_INCIDENT_RETENTION_DAYS": "400"}
        ).incident_retention_days
        == 400
    )
    with pytest.raises(ConfigurationError, match="Leave it UNSET"):
        Settings.from_environment({**base, "SENTINEL_INCIDENT_RETENTION_DAYS": "0"})
    with pytest.raises(ConfigurationError, match="number of days"):
        Settings.from_environment({**base, "SENTINEL_INCIDENT_RETENTION_DAYS": "ninety"})


def test_the_maintenance_loop_runs_the_incident_sweep_when_configured(
    container_with_incident_retention,
):
    container = container_with_incident_retention
    _seed_incident(
        container, incident_id="inc-old", state=IncidentState.FAILED.value, age_days=365
    )
    loop = MaintenanceLoop(container, tenants=lambda: [TENANT], interval_seconds=60)
    totals = loop.run_once()

    assert totals["incident_retention_rows_deleted"] == 3
    assert _count(container, "incidents") == 0


# ── The gate that makes a NEW table impossible to leave unbounded ────────────


def _schema_tables() -> set[str]:
    pattern = re.compile(r"CREATE TABLE IF NOT EXISTS (\w+)")
    return {
        match.group(1)
        for statement in SCHEMA_STATEMENTS
        for match in [pattern.search(statement)]
        if match
    }


def _reaped_tables() -> set[str]:
    """Every table this module actually issues a DELETE against.

    Read out of the source rather than maintained as a list, because a list would
    be a second declaration that could disagree with the code -- and a stale one
    would report a table as reaped while nothing deleted from it, which is the
    exact condition (`SENTINEL_RETENTION_DAYS` parsed and read by nothing) that
    this whole module was written to fix.

    The regex cannot see the child-table deletes, because those are built from
    `INCIDENT_CHILD_TABLES` rather than written literally -- `DELETE FROM {table}`.
    That constant is therefore unioned in. It is not a second declaration: the
    sweep loops over exactly it, so a table listed there IS deleted from and a
    table deleted from must be there.
    """
    from sentinel.infrastructure.sql import retention

    source = Path(retention.__file__).read_text(encoding="utf-8")
    literal = set(re.findall(r"DELETE FROM (\w+)", source))
    # `{table}` is the loop placeholder, not a table name.
    literal.discard("table")
    return literal | set(INCIDENT_CHILD_TABLES)


def test_every_table_is_either_reaped_or_declared_append_only():
    """A new table must be a decision, not an omission.

    Four tables once grew for the life of a deployment because nobody was ever
    required to say what bounded them. This makes the question unskippable: add a
    table and CI fails until it is either swept here or written into
    `APPEND_ONLY_TABLES` with a reason.

    NOTE ON PROVENANCE: `docs/SECURITY.md` cited this test by name as
    already existing. It did not exist in the tree -- there was no
    `APPEND_ONLY_TABLES` either. It exists now.
    """
    tables = _schema_tables()
    reaped = _reaped_tables()
    declared = set(APPEND_ONLY_TABLES)

    undecided = tables - reaped - declared
    assert not undecided, (
        f"these tables are neither reaped by sentinel/infrastructure/sql/retention.py "
        f"nor declared in APPEND_ONLY_TABLES with a reason: {sorted(undecided)}. "
        "Every table must be one or the other; an unbounded table that nobody "
        "decided about is how the last four got that way."
    )


def test_the_reaped_and_append_only_sets_do_not_overlap():
    """A table cannot be both swept and declared un-sweepable.

    An overlap means the declaration is a lie about what the code does -- and the
    declaration is what a reviewer reads instead of the code.
    """
    overlap = _reaped_tables() & set(APPEND_ONLY_TABLES)
    assert not overlap, (
        f"{sorted(overlap)} are declared append-only AND deleted from by the sweep"
    )


def test_no_declaration_names_a_table_that_does_not_exist():
    """A stale declaration silently exempts nothing and reads as coverage."""
    unknown = set(APPEND_ONLY_TABLES) - _schema_tables()
    assert not unknown, f"APPEND_ONLY_TABLES names non-existent tables: {sorted(unknown)}"


def test_every_append_only_declaration_states_an_actual_reason():
    """"n/a" is how a declaration requirement gets met without a decision.

    The length floor is arbitrary and that is fine: its job is to make the lazy
    path longer than the honest one.
    """
    for table, reason in APPEND_ONLY_TABLES.items():
        assert len(reason) >= 60, (
            f"the append-only reason for {table!r} is {len(reason)} characters: "
            f"{reason!r}. State why the table is bounded or why it must not be "
            "trimmed; a placeholder here defeats the point of the gate."
        )
