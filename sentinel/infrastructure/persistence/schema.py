"""The schema, as an ordered list of migrations.

INDEX DESIGN
------------
Every index here exists for a named query, and every hot query has an index that
serves it. `tests_arch/test_persistence_benchmarks.py` runs EXPLAIN over the real
query set and fails the build on a sequential scan of a table that is not tiny,
so an index that stops being used is caught rather than assumed.

The ordering of composite keys is not arbitrary. `(tenant_id, state,
available_at)` serves `WHERE tenant_id = ? AND state = ? ORDER BY available_at`
as a range scan; `(state, tenant_id, available_at)` would not, because tenant_id
is the equality predicate that must lead for row-level security to prune first.

PARTITIONING
------------
Three tables are append-only, time-ordered and unbounded: `domain_events`,
`incident_transitions` and `audit_log`. They are RANGE-partitioned by month on
PostgreSQL.

The reason is retention, not size. Deleting a month of audit rows from a
monolithic table is a `DELETE` that writes as much WAL as the rows themselves and
leaves the space to `VACUUM`; from a partitioned table it is `DROP TABLE` on one
partition -- constant time, no WAL amplification, no bloat. A retention job that
gets slower as the data it prunes grows is a retention job that eventually stops
running.

SQLite has no declarative partitioning, so those tables are plain there. That
divergence is declared per migration rather than hidden behind a shim.

SOFT DELETE
-----------
Tenant-facing rows carry `deleted_at`. A hard `DELETE` on evidence would break
the ledger's inclusion proofs, and a hard delete on an incident would orphan the
audit trail that explains it. Every read path filters on `deleted_at IS NULL`,
and every index over those tables is PARTIAL on the same predicate -- so the
index contains only live rows and a soft-deleted row costs nothing to skip.

The ledger itself is exempt. It is append-only by definition and its rows are
never deleted, softly or otherwise; erasure there is `redact_evidence`, which
destroys the body and keeps the commitment.
"""

from __future__ import annotations

from sentinel.infrastructure.persistence.engine import Dialect
from sentinel.infrastructure.persistence.migrations import Migration

__all__ = ["MIGRATIONS", "PARTITIONED_TABLES", "PROTECTED_TABLES", "TENANT_SETTING"]

TENANT_SETTING = "sentinel.tenant_id"

#: Tables holding tenant-owned rows. `tenants` is deliberately absent: it is the
#: directory used to ESTABLISH a scope, so scoping it to a context that has not
#: been established yet would deadlock startup.
PROTECTED_TABLES: tuple[str, ...] = (
    "incidents",
    "incident_transitions",
    "evidence",
    "reports",
    "approvals",
    "ledger_entries",
    "ledger_batches",
    "outbox",
    "inbox",
    "execution_steps",
    "work_queue",
    "domain_events",
    "agents",
    "replay_nonces",
    "audit_log",
)

#: RANGE-partitioned by month on PostgreSQL. See the module docstring.
PARTITIONED_TABLES: tuple[str, ...] = (
    "domain_events",
    "incident_transitions",
    "audit_log",
)

_PG = (Dialect.POSTGRES,)
_LITE = (Dialect.SQLITE,)


def _rls(table: str) -> tuple[str, ...]:
    """FORCE row-level security for one table.

    USING and WITH CHECK are BOTH stated. PostgreSQL infers the second from the
    first for a FOR ALL policy, so omitting it happens to work -- but relying on
    an inference for the clause that governs WRITES means a reader has to know
    the inference rule to audit the policy.
    """
    policy = f"{table}_tenant_isolation"
    predicate = f"tenant_id = current_setting('{TENANT_SETTING}', true)"
    return (
        f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY",
        # Without FORCE the table OWNER bypasses the policy, and the application
        # usually is the owner -- which would make all of this decorative.
        f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY",
        f"DROP POLICY IF EXISTS {policy} ON {table}",
        f"CREATE POLICY {policy} ON {table} USING ({predicate}) WITH CHECK ({predicate})",
    )


# ── 001: core tables, portable across both engines ──────────────────────────

_CORE = (
    """
    CREATE TABLE IF NOT EXISTS tenants (
        tenant_id   TEXT PRIMARY KEY,
        name        TEXT NOT NULL,
        created_at  TEXT NOT NULL,
        deleted_at  TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS agents (
        tenant_id   TEXT NOT NULL,
        address     TEXT NOT NULL,
        label       TEXT NOT NULL DEFAULT '',
        enrolled_at TEXT NOT NULL,
        revoked_at  TEXT,
        deleted_at  TEXT,
        PRIMARY KEY (tenant_id, address)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS incidents (
        tenant_id       TEXT NOT NULL,
        incident_id     TEXT NOT NULL,
        state           TEXT NOT NULL,
        facts_json      TEXT NOT NULL,
        version         INTEGER NOT NULL DEFAULT 0,
        execution_epoch INTEGER NOT NULL DEFAULT 0,
        created_at      TEXT NOT NULL,
        updated_at      TEXT NOT NULL,
        deleted_at      TEXT,
        PRIMARY KEY (tenant_id, incident_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS evidence (
        tenant_id        TEXT NOT NULL,
        incident_id      TEXT NOT NULL,
        uri              TEXT NOT NULL,
        digest           TEXT NOT NULL,
        content_json     TEXT,
        -- Set when the body lives in object storage rather than inline. Large
        -- evidence does not belong in a row that every incident read touches.
        blob_key         TEXT,
        -- Compression and encryption are recorded per row, not assumed globally,
        -- so a schema that predates either can still be read.
        codec            TEXT NOT NULL DEFAULT 'identity',
        key_id           TEXT,
        created_at       TEXT NOT NULL,
        redacted_at      TEXT,
        redaction_reason TEXT,
        redacted_by      TEXT,
        deleted_at       TEXT,
        PRIMARY KEY (tenant_id, incident_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS reports (
        tenant_id     TEXT NOT NULL,
        incident_id   TEXT NOT NULL,
        content       TEXT NOT NULL,
        codec         TEXT NOT NULL DEFAULT 'identity',
        created_at    TEXT NOT NULL,
        withdrawn_at  TEXT,
        withdrawn_why TEXT,
        deleted_at    TEXT,
        PRIMARY KEY (tenant_id, incident_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS approvals (
        tenant_id    TEXT NOT NULL,
        approval_id  TEXT NOT NULL,
        incident_id  TEXT NOT NULL,
        action       TEXT NOT NULL,
        target       TEXT NOT NULL,
        state        TEXT NOT NULL,
        proposed_at  TEXT NOT NULL,
        decided_by   TEXT,
        decided_at   TEXT,
        receipt_json TEXT,
        deleted_at   TEXT,
        PRIMARY KEY (tenant_id, approval_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ledger_entries (
        tenant_id       TEXT NOT NULL,
        seq             INTEGER NOT NULL,
        incident_id     TEXT NOT NULL,
        entry_hash      TEXT NOT NULL,
        prev_chain_hash TEXT NOT NULL,
        chain_hash      TEXT NOT NULL,
        manifest_json   TEXT NOT NULL,
        batch_id        TEXT,
        created_at      TEXT NOT NULL,
        PRIMARY KEY (tenant_id, seq)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ledger_batches (
        tenant_id      TEXT NOT NULL,
        batch_id       TEXT NOT NULL,
        merkle_root    TEXT NOT NULL,
        leaf_count     INTEGER NOT NULL,
        root_signature TEXT,
        signer_address TEXT,
        manifest_json  TEXT NOT NULL,
        sealed_at      TEXT NOT NULL,
        anchor_txid    TEXT,
        PRIMARY KEY (tenant_id, batch_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS outbox (
        tenant_id       TEXT NOT NULL,
        record_id       TEXT NOT NULL,
        incident_id     TEXT NOT NULL,
        kind            TEXT NOT NULL,
        payload_json    TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        state           TEXT NOT NULL,
        attempts        INTEGER NOT NULL DEFAULT 0,
        max_attempts    INTEGER NOT NULL DEFAULT 5,
        available_at    TEXT NOT NULL,
        lease_until     TEXT,
        result_json     TEXT,
        last_error      TEXT,
        created_at      TEXT NOT NULL,
        updated_at      TEXT NOT NULL,
        PRIMARY KEY (tenant_id, record_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS inbox (
        tenant_id   TEXT NOT NULL,
        message_id  TEXT NOT NULL,
        kind        TEXT NOT NULL,
        accepted_at TEXT NOT NULL,
        PRIMARY KEY (tenant_id, message_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS execution_steps (
        tenant_id   TEXT NOT NULL,
        incident_id TEXT NOT NULL,
        step        TEXT NOT NULL,
        status      TEXT NOT NULL,
        epoch       INTEGER NOT NULL,
        attempts    INTEGER NOT NULL DEFAULT 0,
        result_json TEXT NOT NULL DEFAULT '{}',
        error       TEXT,
        entered_at  TEXT NOT NULL,
        settled_at  TEXT,
        PRIMARY KEY (tenant_id, incident_id, step)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS work_queue (
        tenant_id    TEXT NOT NULL,
        work_id      TEXT NOT NULL,
        incident_id  TEXT NOT NULL,
        shard        INTEGER NOT NULL,
        priority     INTEGER NOT NULL,
        payload_json TEXT NOT NULL,
        state        TEXT NOT NULL,
        attempts     INTEGER NOT NULL DEFAULT 0,
        lease_epoch  INTEGER NOT NULL DEFAULT 0,
        claimed_by   TEXT,
        lease_until  TEXT,
        available_at TEXT NOT NULL,
        last_error   TEXT,
        enqueued_at  TEXT NOT NULL,
        PRIMARY KEY (tenant_id, work_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS replay_nonces (
        tenant_id    TEXT NOT NULL,
        agent        TEXT NOT NULL,
        event_digest TEXT NOT NULL,
        seen_at      TEXT NOT NULL,
        expires_at   TEXT NOT NULL,
        PRIMARY KEY (tenant_id, agent, event_digest)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS leader_locks (
        job_name    TEXT PRIMARY KEY,
        holder      TEXT NOT NULL,
        acquired_at TEXT NOT NULL
    )
    """,
)


# ── 002/003: append-only tables. Partitioned on PostgreSQL only ─────────────

_APPEND_ONLY_PG = (
    """
    CREATE TABLE IF NOT EXISTS domain_events (
        tenant_id     TEXT NOT NULL,
        event_id      TEXT NOT NULL,
        incident_id   TEXT NOT NULL,
        event_type    TEXT NOT NULL,
        event_version INTEGER NOT NULL,
        payload_json  TEXT NOT NULL,
        occurred_at   TEXT NOT NULL,
        recorded_at   TEXT NOT NULL,
        PRIMARY KEY (tenant_id, recorded_at, event_id)
    ) PARTITION BY RANGE (recorded_at)
    """,
    """
    CREATE TABLE IF NOT EXISTS incident_transitions (
        tenant_id   TEXT NOT NULL,
        incident_id TEXT NOT NULL,
        seq         INTEGER NOT NULL,
        from_state  TEXT,
        to_state    TEXT NOT NULL,
        facts_added TEXT NOT NULL,
        actor       TEXT NOT NULL,
        occurred_at TEXT NOT NULL,
        PRIMARY KEY (tenant_id, occurred_at, incident_id, seq)
    ) PARTITION BY RANGE (occurred_at)
    """,
    # The audit log is hash-chained per tenant: each row commits to its
    # predecessor, so a deletion or reordering is detectable. That is what makes
    # it an audit log rather than a table of rows an administrator can edit.
    """
    CREATE TABLE IF NOT EXISTS audit_log (
        tenant_id       TEXT NOT NULL,
        seq             BIGINT NOT NULL,
        actor           TEXT NOT NULL,
        action          TEXT NOT NULL,
        resource_type   TEXT NOT NULL,
        resource_id     TEXT NOT NULL,
        outcome         TEXT NOT NULL,
        detail_json     TEXT NOT NULL DEFAULT '{}',
        prev_chain_hash TEXT NOT NULL,
        chain_hash      TEXT NOT NULL,
        occurred_at     TEXT NOT NULL,
        PRIMARY KEY (tenant_id, occurred_at, seq)
    ) PARTITION BY RANGE (occurred_at)
    """,
    # A DEFAULT partition catches anything outside the provisioned months, so a
    # late-arriving or clock-skewed row is stored rather than rejected. A missing
    # partition on an append-only table is an outage; a default partition turns
    # it into a slow query that monitoring can find.
    """
    CREATE TABLE IF NOT EXISTS domain_events_default PARTITION OF domain_events DEFAULT
    """,
    """
    CREATE TABLE IF NOT EXISTS incident_transitions_default
        PARTITION OF incident_transitions DEFAULT
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_log_default PARTITION OF audit_log DEFAULT
    """,
)

_APPEND_ONLY_LITE = (
    """
    CREATE TABLE IF NOT EXISTS domain_events (
        tenant_id     TEXT NOT NULL,
        event_id      TEXT NOT NULL,
        incident_id   TEXT NOT NULL,
        event_type    TEXT NOT NULL,
        event_version INTEGER NOT NULL,
        payload_json  TEXT NOT NULL,
        occurred_at   TEXT NOT NULL,
        recorded_at   TEXT NOT NULL,
        PRIMARY KEY (tenant_id, recorded_at, event_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS incident_transitions (
        tenant_id   TEXT NOT NULL,
        incident_id TEXT NOT NULL,
        seq         INTEGER NOT NULL,
        from_state  TEXT,
        to_state    TEXT NOT NULL,
        facts_added TEXT NOT NULL,
        actor       TEXT NOT NULL,
        occurred_at TEXT NOT NULL,
        PRIMARY KEY (tenant_id, occurred_at, incident_id, seq)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_log (
        tenant_id       TEXT NOT NULL,
        seq             INTEGER NOT NULL,
        actor           TEXT NOT NULL,
        action          TEXT NOT NULL,
        resource_type   TEXT NOT NULL,
        resource_id     TEXT NOT NULL,
        outcome         TEXT NOT NULL,
        detail_json     TEXT NOT NULL DEFAULT '{}',
        prev_chain_hash TEXT NOT NULL,
        chain_hash      TEXT NOT NULL,
        occurred_at     TEXT NOT NULL,
        PRIMARY KEY (tenant_id, occurred_at, seq)
    )
    """,
)


# ── 004: indexes. Every one exists for a named query ────────────────────────
#
# Partial indexes (`WHERE deleted_at IS NULL`) contain only live rows, so a
# soft-deleted row costs nothing to skip and the index stays the size of the
# working set rather than the history.

_INDEXES = (
    # `list_incidents`: WHERE tenant_id=? AND deleted_at IS NULL ORDER BY updated_at DESC
    "CREATE INDEX IF NOT EXISTS ix_incidents_live "
    "ON incidents(tenant_id, updated_at DESC) WHERE deleted_at IS NULL",
    # `counts_by_state`: GROUP BY state for one tenant. Index-only on PostgreSQL.
    "CREATE INDEX IF NOT EXISTS ix_incidents_state "
    "ON incidents(tenant_id, state) WHERE deleted_at IS NULL",
    # The queue dispatcher: WHERE shard=? AND state='pending' AND available_at<=?
    # ORDER BY priority, enqueued_at. Shard leads, so a worker scans only its own
    # partition of the keyspace instead of every tenant's.
    "CREATE INDEX IF NOT EXISTS ix_work_dispatch "
    "ON work_queue(shard, state, available_at, priority, enqueued_at)",
    # Lease reaping: WHERE state='claimed' AND lease_until < now
    "CREATE INDEX IF NOT EXISTS ix_work_leases "
    "ON work_queue(state, lease_until)",
    # Outbox dispatch: WHERE tenant_id=? AND state='pending' AND available_at<=?
    "CREATE INDEX IF NOT EXISTS ix_outbox_due "
    "ON outbox(tenant_id, state, available_at)",
    "CREATE INDEX IF NOT EXISTS ix_outbox_leases "
    "ON outbox(state, lease_until)",
    # Idempotency lookup is a UNIQUE constraint, which is also the index that
    # makes the lookup O(log n) -- one object serving correctness and speed.
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_outbox_idempotency "
    "ON outbox(tenant_id, idempotency_key)",
    # A fork is UNSTORABLE: two entries claiming the same predecessor collide.
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_ledger_chain "
    "ON ledger_entries(tenant_id, prev_chain_hash)",
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_ledger_incident "
    "ON ledger_entries(tenant_id, incident_id)",
    # Sealing: WHERE tenant_id=? AND batch_id IS NULL ORDER BY seq
    "CREATE INDEX IF NOT EXISTS ix_ledger_unsealed "
    "ON ledger_entries(tenant_id, seq) WHERE batch_id IS NULL",
    # Approvals awaiting a human: WHERE tenant_id=? AND state='pending'
    "CREATE INDEX IF NOT EXISTS ix_approvals_pending "
    "ON approvals(tenant_id, incident_id, state) WHERE deleted_at IS NULL",
    # Nonce purge: WHERE expires_at < ?
    "CREATE INDEX IF NOT EXISTS ix_nonces_expiry ON replay_nonces(expires_at)",
    # Inbox purge: WHERE accepted_at < ?
    "CREATE INDEX IF NOT EXISTS ix_inbox_age ON inbox(accepted_at)",
    # Per-incident execution history.
    "CREATE INDEX IF NOT EXISTS ix_steps_incident "
    "ON execution_steps(tenant_id, incident_id, status)",
    # Event stream tail: WHERE tenant_id=? ORDER BY recorded_at DESC
    "CREATE INDEX IF NOT EXISTS ix_events_stream "
    "ON domain_events(tenant_id, recorded_at DESC)",
    # Per-incident event history, which the audit view joins on.
    "CREATE INDEX IF NOT EXISTS ix_events_incident "
    "ON domain_events(tenant_id, incident_id, recorded_at)",
    # Transition history for one incident, in order.
    "CREATE INDEX IF NOT EXISTS ix_transitions_incident "
    "ON incident_transitions(tenant_id, incident_id, seq)",
    # Audit queries: by actor, by resource, newest first.
    "CREATE INDEX IF NOT EXISTS ix_audit_actor "
    "ON audit_log(tenant_id, actor, occurred_at DESC)",
    "CREATE INDEX IF NOT EXISTS ix_audit_resource "
    "ON audit_log(tenant_id, resource_type, resource_id, occurred_at DESC)",
)


MIGRATIONS: tuple[Migration, ...] = (
    Migration(
        version=1,
        name="core tables",
        up=_CORE,
        down=tuple(
            f"DROP TABLE IF EXISTS {t}"
            for t in (
                "leader_locks", "replay_nonces", "work_queue", "execution_steps",
                "inbox", "outbox", "ledger_batches", "ledger_entries", "approvals",
                "reports", "evidence", "incidents", "agents", "tenants",
            )
        ),
    ),
    Migration(
        version=2,
        name="append-only tables, range-partitioned by month",
        up=_APPEND_ONLY_PG,
        down=(
            "DROP TABLE IF EXISTS audit_log CASCADE",
            "DROP TABLE IF EXISTS incident_transitions CASCADE",
            "DROP TABLE IF EXISTS domain_events CASCADE",
        ),
        dialects=_PG,
    ),
    Migration(
        version=3,
        name="append-only tables, unpartitioned",
        up=_APPEND_ONLY_LITE,
        down=(
            "DROP TABLE IF EXISTS audit_log",
            "DROP TABLE IF EXISTS incident_transitions",
            "DROP TABLE IF EXISTS domain_events",
        ),
        dialects=_LITE,
    ),
    Migration(
        version=4,
        name="indexes for every hot query",
        up=_INDEXES,
        down=tuple(
            f"DROP INDEX IF EXISTS {name}"
            for name in (
                "ix_incidents_live", "ix_incidents_state", "ix_work_dispatch",
                "ix_work_leases", "ix_outbox_due", "ix_outbox_leases",
                "ux_outbox_idempotency", "ux_ledger_chain", "ux_ledger_incident",
                "ix_ledger_unsealed", "ix_approvals_pending", "ix_nonces_expiry",
                "ix_inbox_age", "ix_steps_incident", "ix_events_stream",
                "ix_events_incident", "ix_transitions_incident", "ix_audit_actor",
                "ix_audit_resource",
            )
        ),
    ),
    Migration(
        version=5,
        name="force row-level security on every tenant-scoped table",
        up=tuple(statement for table in PROTECTED_TABLES for statement in _rls(table)),
        down=tuple(
            f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY" for table in PROTECTED_TABLES
        ),
        dialects=_PG,
    ),
    Migration(
        version=6,
        name="column compression for large text payloads",
        # PostgreSQL stores oversized values out of line and compresses them.
        # EXTENDED is the default for TEXT, so this is explicit rather than
        # novel -- stated so a future column added with PLAIN storage is a
        # visible deviation rather than an accident.
        up=(
            "ALTER TABLE evidence ALTER COLUMN content_json SET STORAGE EXTENDED",
            "ALTER TABLE reports ALTER COLUMN content SET STORAGE EXTENDED",
            "ALTER TABLE domain_events ALTER COLUMN payload_json SET STORAGE EXTENDED",
            "ALTER TABLE outbox ALTER COLUMN payload_json SET STORAGE EXTENDED",
            "ALTER TABLE audit_log ALTER COLUMN detail_json SET STORAGE EXTENDED",
        ),
        down=(),
        dialects=_PG,
    ),
)
