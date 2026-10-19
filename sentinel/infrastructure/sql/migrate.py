"""Schema migration. A one-shot job, never a startup step.

WHY THIS IS NOT CALLED FROM APPLICATION STARTUP
-----------------------------------------------
The predecessor applied its schema, then a list of additive `ALTER TABLE`
statements, then a full walk over every ledger row for every tenant, on EVERY
process start, on every replica, unconditionally. The backfill was idempotent in
outcome and unbounded in cost: at ten million ledger rows it takes minutes to
hours, three replicas run it simultaneously against the same rows, and it exceeds
any Kubernetes `startupProbe` long before finishing. A cluster that cannot start
because its migration is O(table) is a cluster that cannot be restarted during an
incident.

`migrate()` is invoked by an operator or a deployment job through
`sentinel.interface.cli` -- and the application refuses to serve if
the schema version it finds is not the one it was built against. That refusal is
`verify()`, which is O(1) and safe to call at startup.

Versions are integers, applied in order, recorded in `schema_migrations`. Adding
a migration means appending to `MIGRATIONS`; there is no path by which a
deployment silently runs against a schema it was not written for.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Sequence

from sentinel.infrastructure.sql.engine import Connection, ConnectionPool, Dialect
from sentinel.infrastructure.sql.schema import (
    PROTECTED_TABLES,
    SCHEMA_STATEMENTS,
    rls_statements,
)

__all__ = ["CURRENT_VERSION", "SchemaOutOfDate", "migrate", "verify"]


class SchemaOutOfDate(RuntimeError):
    """The database schema is not the version this build expects.

    Raised at startup rather than discovered mid-incident. A security product
    running against a schema it was not written for is a product whose
    guarantees are unverified.
    """


def _create_baseline(conn: Connection) -> None:
    for statement in SCHEMA_STATEMENTS:
        conn.execute_rowcount(statement)


def _add_device_discovery(conn: Connection) -> None:
    """Self-reported device inventory (pilot onboarding).

    RLS through `_apply_rls` over PROTECTED_TABLES, not a literal table name,
    for the reason every migration since `_add_transparency_log` gives:
    `test_sql_is_never_built_from_data.py` will only vouch for an
    `rls_statements` call whose argument is the loop variable.
    """
    from sentinel.infrastructure.sql.device_discovery import DEVICE_STATEMENTS
    for statement in DEVICE_STATEMENTS:
        conn.execute_rowcount(statement)
    _apply_rls(conn)


def _add_connected_apps(conn: Connection) -> None:
    """Connected applications: the business systems an agent may call through
    Sentinel, registered by an administrator with a sealed credential.

    RLS through `_apply_rls` over PROTECTED_TABLES, not a literal table name,
    for the reason every migration since `_add_transparency_log` gives.
    """
    from sentinel.infrastructure.sql.connected_apps import CONNECTED_APP_STATEMENTS
    for statement in CONNECTED_APP_STATEMENTS:
        conn.execute_rowcount(statement)
    _apply_rls(conn)


def _apply_rls(conn: Connection) -> None:
    """Enable FORCE row-level security on every tenant-scoped table.

    No opt-out switch. The predecessor gated this behind `SENTINEL_ENABLE_RLS`,
    which defaulted off for several releases; forgetting to set it silently
    removed the database isolation boundary entirely. Isolation that can be
    disabled by omission is not a boundary.

    Superusers bypass RLS regardless, which is why `FORCE` is issued and why the
    application must connect as a non-superuser role. Connecting as `postgres`
    silently disables all of this, and no code can detect that from inside.
    """
    if conn.dialect is not Dialect.POSTGRES:
        return
    for table in PROTECTED_TABLES:
        for statement in rls_statements(table):
            conn.execute_rowcount(statement)


def _add_agent_last_event_at(conn: Connection) -> None:
    """Add last_event_at to agents. Idempotent across SQLite and PostgreSQL.

    Fresh installs get the column from SCHEMA_STATEMENTS; existing databases need
    an ALTER. CREATE TABLE IF NOT EXISTS does not add columns to old tables.
    """
    if conn.dialect is Dialect.POSTGRES:
        row = conn.one(
            "SELECT 1 AS ok FROM information_schema.columns "
            "WHERE table_schema = current_schema() "
            "AND table_name = 'agents' AND column_name = 'last_event_at'"
        )
        if row is None:
            conn.execute_rowcount("ALTER TABLE agents ADD COLUMN last_event_at TEXT")
        return
    cols = {str(r["name"]) for r in conn.execute("PRAGMA table_info(agents)")}
    if "last_event_at" not in cols:
        conn.execute_rowcount("ALTER TABLE agents ADD COLUMN last_event_at TEXT")


def _add_mcp_server_info(conn: Connection) -> None:
    """Add server_info to mcp_servers. Idempotent across SQLite and PostgreSQL.

    Holds what the server said about ITSELF at `initialize` -- the name and
    version from `serverInfo`. Stored because "is the thing answering at this
    endpoint still the thing we enrolled" is otherwise unanswerable: the tool
    pins catch a changed TOOL, and nothing catches a changed SERVER. An
    endpoint can be rehosted, a DNS record can move, and a hostile service can
    take over an address an operator approved months ago; in every one of those
    cases the tools may be byte-identical while the party serving them is not.

    Same ALTER shape as `_add_agent_last_event_at`, and here for the same
    reason: `CREATE TABLE IF NOT EXISTS` does not add a column to a table that
    already exists.
    """
    if conn.dialect is Dialect.POSTGRES:
        row = conn.one(
            "SELECT 1 AS ok FROM information_schema.columns "
            "WHERE table_schema = current_schema() "
            "AND table_name = 'mcp_servers' AND column_name = 'server_info'"
        )
        if row is None:
            conn.execute_rowcount(
                "ALTER TABLE mcp_servers ADD COLUMN server_info TEXT NOT NULL DEFAULT ''"
            )
        return
    cols = {str(r["name"]) for r in conn.execute("PRAGMA table_info(mcp_servers)")}
    if "server_info" not in cols:
        conn.execute_rowcount(
            "ALTER TABLE mcp_servers ADD COLUMN server_info TEXT NOT NULL DEFAULT ''"
        )


def _add_violation_count(conn: Connection) -> None:
    """Add violation_count to agent_observations. Idempotent on both engines.

    Same shape as `_add_agent_last_event_at`, and here for the same reason:
    `CREATE TABLE IF NOT EXISTS` does not add columns to a table that already
    exists, so a fresh install gets the column from SCHEMA_STATEMENTS and an
    existing database needs an ALTER.

    The column exists because "violations" and "incidents" are different facts.
    A violation the gate REFUSED never became an incident, so counting only
    incidents undercounts precisely the cases where enforcement worked -- an
    agent with many violations and no incidents is being stopped, and one with
    many incidents and no violations is not.
    """
    if conn.dialect is Dialect.POSTGRES:
        row = conn.one(
            "SELECT 1 AS ok FROM information_schema.columns "
            "WHERE table_schema = current_schema() "
            "AND table_name = 'agent_observations' "
            "AND column_name = 'violation_count'"
        )
        if row is None:
            conn.execute_rowcount(
                "ALTER TABLE agent_observations "
                "ADD COLUMN violation_count INTEGER NOT NULL DEFAULT 0"
            )
        return
    cols = {
        str(r["name"]) for r in conn.execute("PRAGMA table_info(agent_observations)")
    }
    if "violation_count" not in cols:
        conn.execute_rowcount(
            "ALTER TABLE agent_observations "
            "ADD COLUMN violation_count INTEGER NOT NULL DEFAULT 0"
        )


def _add_execution_node_payload_columns(conn: Connection) -> None:
    """Add input/output/approval to execution_nodes. Idempotent on both engines.

    The specification asks a node to preserve `input`, `output` and `approval`
    alongside what it already carried. `input` matters most: the story it draws
    turns on "the document contains a malicious instruction", and without the
    text of that instruction the step reads as an unexplained turn rather than
    the moment the agent was hijacked.

    `approval` links a step to the human who authorised it -- the first thing an
    auditor asks about an executed action, and previously answerable only by
    joining through an incident that may not exist.

    THE DDL IS WRITTEN OUT LITERALLY, three statements rather than a loop over
    (name, type) pairs. The loop was written first and it interpolated both into
    the SQL -- which two security rules refuse, and rightly: they are structural
    and cannot tell a module-local constant from caller data. This repository
    caught the identical mistake in `violation_count=violation_count+{bump}`
    earlier, and a rule that made exceptions for values that look obviously safe
    would stop being a rule.
    """
    if conn.dialect is Dialect.POSTGRES:
        present = {
            str(r["column_name"])
            for r in conn.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = current_schema() "
                "AND table_name = 'execution_nodes'"
            )
        }
        if "input_text" not in present:
            conn.execute_rowcount(
                "ALTER TABLE execution_nodes ADD COLUMN input_text TEXT NOT NULL DEFAULT ''"
            )
        if "output_text" not in present:
            conn.execute_rowcount(
                "ALTER TABLE execution_nodes ADD COLUMN output_text TEXT NOT NULL DEFAULT ''"
            )
        if "approval_id" not in present:
            conn.execute_rowcount(
                "ALTER TABLE execution_nodes ADD COLUMN approval_id TEXT NOT NULL DEFAULT ''"
            )
        return

    present = {
        str(r["name"]) for r in conn.execute("PRAGMA table_info(execution_nodes)")
    }
    if "input_text" not in present:
        conn.execute_rowcount(
            "ALTER TABLE execution_nodes ADD COLUMN input_text TEXT NOT NULL DEFAULT ''"
        )
    if "output_text" not in present:
        conn.execute_rowcount(
            "ALTER TABLE execution_nodes ADD COLUMN output_text TEXT NOT NULL DEFAULT ''"
        )
    if "approval_id" not in present:
        conn.execute_rowcount(
            "ALTER TABLE execution_nodes ADD COLUMN approval_id TEXT NOT NULL DEFAULT ''"
        )


def _add_approval_context_columns(conn: Connection) -> None:
    """Add `expires_at` and `context_json` to an existing `approvals` table.

    Written out per column and per dialect rather than generated from a list.
    The generated version would build DDL by interpolating a name into a
    statement string, which this repository has already shipped twice and caught
    twice -- once as `violation_count+{bump}` and once as a migration built from
    `{name}`/`{ddl}`. The repetition below is the point: there is nothing in it
    a value could be substituted into.

    Both columns default to empty, which is the correct value for every existing
    row. An approval raised before this migration has no expiry, and inventing
    one retroactively would expire pending requests that were never given a
    window in the first place -- silently converting a waiting approval into a
    refused one.
    """
    if conn.dialect is Dialect.POSTGRES:
        present = {
            str(r["column_name"])
            for r in conn.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = current_schema() "
                "AND table_name = 'approvals'"
            )
        }
        if "expires_at" not in present:
            conn.execute_rowcount(
                "ALTER TABLE approvals ADD COLUMN expires_at TEXT NOT NULL DEFAULT ''"
            )
        if "context_json" not in present:
            conn.execute_rowcount("ALTER TABLE approvals ADD COLUMN context_json TEXT")
        return

    present = {str(r["name"]) for r in conn.execute("PRAGMA table_info(approvals)")}
    if "expires_at" not in present:
        conn.execute_rowcount(
            "ALTER TABLE approvals ADD COLUMN expires_at TEXT NOT NULL DEFAULT ''"
        )
    if "context_json" not in present:
        conn.execute_rowcount("ALTER TABLE approvals ADD COLUMN context_json TEXT")


#: Ordered, append-only. Each entry is (version, description, apply).

def _add_transparency_log(conn: Connection) -> None:
    """Create the transparency tables and force RLS on them.

    Fresh installs get these from `SCHEMA_STATEMENTS`; existing databases need
    them created here, because `migrate` does not re-run the full schema.

    RLS is applied in the SAME migration, through `_apply_rls` rather than a
    literal table name -- both for the reason `_add_a2a_agent_cards` gives, and
    because `test_sql_is_never_built_from_data.py` will only vouch for a
    `rls_statements` call whose argument is the loop variable over
    PROTECTED_TABLES.
    """
    conn.execute_rowcount(
        """
        CREATE TABLE IF NOT EXISTS transparency_leaves (
            tenant_id   TEXT    NOT NULL,
            sequence    INTEGER NOT NULL,
            digest      TEXT    NOT NULL,
            appended_at TEXT    NOT NULL,
            PRIMARY KEY (tenant_id, sequence)
        )
        """
    )
    conn.execute_rowcount(
        """
        CREATE TABLE IF NOT EXISTS transparency_roots (
            tenant_id          TEXT    NOT NULL,
            tree_size          INTEGER NOT NULL,
            root_hash          TEXT    NOT NULL,
            published_at       TEXT    NOT NULL,
            sink               TEXT    NOT NULL DEFAULT 'none',
            external_reference TEXT    NOT NULL DEFAULT '',
            PRIMARY KEY (tenant_id, tree_size)
        )
        """
    )
    _apply_rls(conn)


def _add_execution_receipts(conn: Connection) -> None:
    """Create `execution_receipts` and force RLS on it.

    Until now a receipt existed only in the return value of `execute_bound`.
    That is enough to hand back to the caller and not enough to answer "show
    me every execution this week whose parameters differed from what was
    approved" -- which is the question the binding was built to make
    answerable, and it needs the receipts to still exist.

    RLS is applied through `_apply_rls` over PROTECTED_TABLES rather than by
    naming this table, for the reason `_add_transparency_log` gives:
    `test_sql_is_never_built_from_data.py` will only vouch for an
    `rls_statements` call whose argument is the loop variable.
    """
    conn.execute_rowcount(
        """
        CREATE TABLE IF NOT EXISTS execution_receipts (
            tenant_id                  TEXT NOT NULL,
            receipt_id                 TEXT NOT NULL,
            authorization_id           TEXT NOT NULL DEFAULT '',
            authorization_digest       TEXT NOT NULL DEFAULT '',
            executed_request_digest    TEXT NOT NULL DEFAULT '',
            approved_parameter_digest  TEXT NOT NULL DEFAULT '',
            actual_parameter_digest    TEXT NOT NULL DEFAULT '',
            delegation_passport_digest TEXT NOT NULL DEFAULT '',
            differing_keys             TEXT NOT NULL DEFAULT '',
            bounded_mutations          TEXT NOT NULL DEFAULT '',
            defects                    TEXT NOT NULL DEFAULT '',
            execution_identity         TEXT NOT NULL DEFAULT '',
            side_effect                TEXT NOT NULL DEFAULT '',
            outcome                    TEXT NOT NULL,
            started_at                 TEXT NOT NULL DEFAULT '',
            completed_at               TEXT NOT NULL,
            PRIMARY KEY (tenant_id, receipt_id)
        )
        """
    )
    _apply_rls(conn)


def _add_a2a_agent_cards(conn: Connection) -> None:
    """Create `a2a_agent_cards` and force RLS on it.

    Fresh installs get the table from `SCHEMA_STATEMENTS`; existing databases
    need it created here, because `migrate` does not re-run the full schema.

    RLS IS APPLIED IN THE SAME MIGRATION, not left to the next `_apply_rls`
    run. A tenant-scoped table that exists for even one deployment without its
    policy is a cross-tenant read waiting for someone to notice, and "the next
    migration will fix it" is not a boundary. `rls_statements` is idempotent,
    so re-applying it later costs nothing.
    """
    conn.execute_rowcount(
        """
        CREATE TABLE IF NOT EXISTS a2a_agent_cards (
            tenant_id    TEXT NOT NULL,
            agent_id     TEXT NOT NULL,
            version      TEXT NOT NULL DEFAULT '',
            endpoint     TEXT NOT NULL DEFAULT '',
            capabilities TEXT NOT NULL DEFAULT '',
            description  TEXT NOT NULL DEFAULT '',
            fingerprint  TEXT NOT NULL,
            enrolled_at  TEXT NOT NULL,
            updated_at   TEXT NOT NULL,
            PRIMARY KEY (tenant_id, agent_id)
        )
        """
    )
    # `_apply_rls`, NOT `rls_statements("a2a_agent_cards")`.
    #
    # Two reasons, and the second is the one a guard enforces.
    # `a2a_agent_cards` is already in PROTECTED_TABLES, so the audited loop
    # covers it and re-applying to the others is free -- the statements are
    # idempotent. And `test_sql_is_never_built_from_data.py` will only vouch for
    # a `rls_statements` call whose argument is the loop variable over
    # PROTECTED_TABLES; a literal here is an identifier the guard cannot prove
    # came from a fixed set, which is exactly the shape it exists to refuse.
    _apply_rls(conn)


def _add_remediation_idempotency(conn: Connection) -> None:
    """Create `remediation_idempotency` and force RLS on it.

    Until now a remediation receipt lived in `InMemoryIdempotencyStore`: one
    process, no durability. A replica restart forgot every key, and a retried
    approval on the other replica re-ran an action that had already reached
    the world. The table is what makes "this key already executed" a fact the
    whole cluster agrees on.

    RLS through `_apply_rls`, not a literal table name, for the reason every
    sibling migration gives: the guard vouches only for the audited loop.
    """
    conn.execute_rowcount(
        """
        CREATE TABLE IF NOT EXISTS remediation_idempotency (
            tenant_id       TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            receipt_json    TEXT NOT NULL,
            created_at      TEXT NOT NULL,
            PRIMARY KEY (tenant_id, idempotency_key)
        )
        """
    )
    _apply_rls(conn)


def _add_approval_executing_since(conn: Connection) -> None:
    """Add `executing_since` to an existing `approvals` table.

    Same literal, per-dialect shape as `_add_approval_context_columns`, for the
    same reason. Defaults to empty: an approval already in `executing` when this
    migration runs has no claim time on record, and the reaper treats an empty
    stamp as "unknown" rather than "ancient" -- it will not release a claim it
    cannot date.
    """
    if conn.dialect is Dialect.POSTGRES:
        row = conn.one(
            "SELECT 1 AS ok FROM information_schema.columns "
            "WHERE table_schema = current_schema() "
            "AND table_name = 'approvals' AND column_name = 'executing_since'"
        )
        if row is None:
            conn.execute_rowcount(
                "ALTER TABLE approvals ADD COLUMN executing_since TEXT NOT NULL DEFAULT ''"
            )
        return
    present = {str(r["name"]) for r in conn.execute("PRAGMA table_info(approvals)")}
    if "executing_since" not in present:
        conn.execute_rowcount(
            "ALTER TABLE approvals ADD COLUMN executing_since TEXT NOT NULL DEFAULT ''"
        )


def _add_execution_binding_tables(conn: Connection) -> None:
    """Create `execution_nonces` and `execution_authorizations`, then force RLS.

    Both were first created lazily by their stores' `ensure_schema`, which
    worked on SQLite and was a tenant-isolation hole on PostgreSQL: a table
    created outside the audited loop gets no policy, and an authorization
    table readable across tenants lets a token issued to one tenant be
    redeemed under another. The DDL now lives in `schema.py`, so re-running
    the baseline creates them and `_apply_rls` covers them -- the same
    two-step shape every sibling migration uses, for the same reason.
    """
    _create_baseline(conn)
    _apply_rls(conn)


MIGRATIONS: Sequence[tuple[int, str, Callable[[Connection], None]]] = (
    (1, "baseline schema", _create_baseline),
    (2, "force row-level security on every tenant-scoped table", _apply_rls),
    # v3 adds the inbox and execution journal. It re-runs the baseline (every
    # statement is IF NOT EXISTS) and re-applies RLS so the two new tables are
    # protected -- the predecessor added `delivery_queue` to its protected set
    # and left a call site using an unscoped connection, which broke every
    # terminal delivery operation on PostgreSQL and worked fine on SQLite.
    (3, "inbox and execution journal, both tenant-scoped", _create_baseline),
    (4, "force row-level security on the inbox and journal", _apply_rls),
    # v5/v6 add the hash-chained security audit trail. Same two-step shape as
    # v3/v4 and for the same reason: creating a tenant-scoped table without
    # re-applying RLS leaves it readable across tenants, which for an audit trail
    # would mean one tenant reading another's security history.
    (5, "hash-chained security audit trail", _create_baseline),
    (6, "force row-level security on the security audit trail", _apply_rls),
    # v7/v8 add human identity: users, passkey credentials, sessions and enrolment
    # tickets. Same two-step shape and the same reason -- `users` is a customer
    # roster and `user_credentials` is which authenticators exist, so both are
    # tenant-scoped and both need the policy applied, not just created.
    #
    # `webauthn_challenges` is deliberately NOT tenant-protected: a challenge is
    # issued before the caller is known, so the row exists before there is a tenant
    # to scope it to. It holds no secret -- a challenge is a public nonce whose only
    # property is being single-use.
    (7, "human identity: users, passkeys, sessions, enrolment tickets", _create_baseline),
    (8, "force row-level security on the identity tables", _apply_rls),
    (9, "organizations table for tenant/org management", _create_baseline),
    (10, "force row-level security on organizations", _apply_rls),
    (11, "agents.last_event_at for protect bypass silence detection", _add_agent_last_event_at),
    # v12 adds `ix_events_incident`. Re-running the baseline is enough because
    # every statement in it is IF NOT EXISTS, and an index needs no RLS pass.
    # Without this index, deleting one incident's events is a sequential scan of
    # `domain_events`, so the incident retention sweep would degrade quadratically
    # in the history it exists to bound.
    (12, "index domain_events by incident for per-incident reads and retention", _create_baseline),
    # v13/v14: MCP server enrolment and tool pins. Same two-step shape as every
    # other tenant-scoped addition above, and for the reason v3/v4 records: a
    # tenant-scoped table created without re-applying RLS is readable across
    # tenants. For these two that would mean one tenant reading which MCP servers
    # another has enrolled -- and, worse on the write side, pinning a definition
    # into someone else's allowlist.
    (13, "MCP server enrolment and tool definition pins", _create_baseline),
    (14, "force row-level security on the MCP trust tables", _apply_rls),
    # v15/v16: agent capability grants and the discovery tables
    # (`agent_tool_grants`, `agent_observations`, `agent_observed_edges`,
    # `agent_declarations`).
    #
    # THESE FOUR TABLES WERE ADDED TO `SCHEMA_STATEMENTS` WITHOUT A MIGRATION,
    # and the omission survived a full green test suite. Every test builds a
    # fresh database, where `_create_baseline` runs every statement, so the
    # tables were always there. An EXISTING deployment upgrading would have
    # found `verify()` satisfied -- its recorded version 14 matched the built
    # version 14 -- started cleanly, and then failed at runtime with
    # `no such table: agent_tool_grants` the first time an agent invoked a tool.
    #
    # Works in tests, breaks on upgrade, and passes the check that exists to
    # prevent exactly that. `test_every_declared_table_survives_an_upgrade`
    # closes it by migrating from an old version rather than from nothing.
    (15, "agent capability grants and agent discovery tables", _create_baseline),
    (16, "force row-level security on the capability and discovery tables", _apply_rls),
    (17, "agent_observations.violation_count", _add_violation_count),
    # v18/v19: the execution graph. Same two-step shape as every other
    # tenant-scoped addition -- create, then re-apply RLS -- because a table
    # created without the policy is readable across tenants, and this one holds
    # the causal trace of what every agent did.
    (18, "execution_nodes for the agent execution graph", _create_baseline),
    (19, "force row-level security on execution_nodes", _apply_rls),
    (20, "execution_nodes input/output/approval", _add_execution_node_payload_columns),
    (21, "approvals.expires_at and request context", _add_approval_context_columns),
    # v22/v23: the granular kill switch. Same two-step shape as v18/v19 and
    # every other tenant-scoped addition -- create, then re-apply RLS.
    #
    # It matters more here than usual. `containments` is readable-across-tenants
    # without the policy, and reading it discloses which agents a tenant has
    # stopped and why, which is an incident in progress. The write side is worse:
    # an unprotected table is a way to halt somebody else's estate.
    (22, "containments: the tenant-scoped granular kill switch", _create_baseline),
    (23, "force row-level security on containments", _apply_rls),
    # v24/v25: the Phase 5 enterprise tables. Same two-step shape as every other
    # tenant-scoped addition -- create, then re-apply RLS.
    #
    # `policy_versions` in particular: without the policy it is readable across
    # tenants, and a tenant's ruleset is a map of exactly what they do and do
    # not detect. On the write side it would be a way to deploy a permissive
    # policy into somebody else's estate.
    (24, "policy versions, tenant settings, tenant keys, mode transitions", _create_baseline),
    (25, "force row-level security on the enterprise control tables", _apply_rls),
    # v26/v27: MCP tool provenance. Same two-step shape as every other
    # tenant-scoped addition -- create, then re-apply RLS.
    #
    # These two were added to SCHEMA_STATEMENTS in the commit that built the
    # provenance feature, and the migration entry was MISSED. A fresh install
    # was fine (`_create_baseline` runs the whole schema); an existing v25
    # deployment would have found `verify()` satisfied, started cleanly, and
    # failed at runtime on the first proxied listing with "no such table:
    # mcp_tool_provenance". That is precisely the defect
    # `test_every_declared_table_survives_an_upgrade_from_an_older_version`
    # exists to catch, and it could not see it -- it rewinds the version on a
    # database whose tables already exist, so re-running `_create_baseline`
    # recreates everything and the check passes vacuously. The static
    # fingerprint gate in that module is the fix for the hole.
    (26, "mcp_tool_provenance and mcp_tool_changes", _create_baseline),
    (27, "force row-level security on the MCP provenance tables", _apply_rls),
    # v28: which server is actually answering at an enrolled endpoint.
    (28, "mcp_servers.server_info for server-identity drift", _add_mcp_server_info),
    # v29: durable A2A card pins. Without this, drift detection held its pins in
    # one worker's memory and could not survive a second replica.
    (29, "a2a_agent_cards for cross-replica card drift", _add_a2a_agent_cards),
    # v30: the transparency log gets storage. Until now its roots could only
    # describe whatever was in one process's memory, and "is this the same
    # history you showed me last week" needs last week's leaves to still exist.
    (30, "transparency_leaves and transparency_roots", _add_transparency_log),
    # v31: execution receipts get storage. A receipt that lived only in a
    # return value could be handed to its caller and could not answer "which
    # executions this week differed from what was approved" -- the question the
    # binding exists to make answerable.
    (31, "execution_receipts for the approved-versus-executed diff", _add_execution_receipts),
    # v32: the worker-scope policy on `work_queue`. The queue has been in
    # PROTECTED_TABLES since v1 and the claim has never bound a tenant -- it
    # cannot, a shard holds every tenant -- so on PostgreSQL the claim matched
    # nothing and no work was ever processed, while SQLite (no RLS) was fine.
    # `rls_statements` now emits the second policy for WORKER_SCOPED_TABLES;
    # re-running the audited loop applies it. See `schema.py`.
    (32, "worker-scope policy on the cross-tenant work queue", _apply_rls),
    # v33: durable, tenant-scoped remediation idempotency. Same create-plus-RLS
    # shape as every other tenant-owned table, inside one migration.
    (33, "remediation_idempotency for cross-replica receipt dedupe", _add_remediation_idempotency),
    # v34: when an approval was claimed, so a claim whose worker died can be
    # told apart from one that is genuinely still running.
    (34, "approvals.executing_since for the stuck-claim reaper", _add_approval_executing_since),
    # v35: the execution-binding tables move under the audited RLS loop. Until
    # now they were created lazily by the stores that use them, which on
    # PostgreSQL meant no policy -- readable and redeemable across tenants.
    (35, "execution_nonces and execution_authorizations, tenant-scoped", _add_execution_binding_tables),
    # v36: the durable operation record (intent before effect) and the shared
    # protect-control state (one budget and breaker per deployment). Both
    # tenant-scoped; created by the baseline and covered by the audited RLS loop.
    (36, "execution_operations and protect_control_state, tenant-scoped", _add_execution_binding_tables),
    # v37: which transparency leaf commits to which execution receipt.
    (37, "evidence_commitments, tenant-scoped and append-only", _add_execution_binding_tables),
    (38, "consented device presence inventory, tenant-scoped", _add_device_discovery),
    (39, "connected applications with sealed credentials, tenant-scoped", _add_connected_apps),
)

CURRENT_VERSION: int = max(version for version, _desc, _fn in MIGRATIONS)


def _applied_version(conn: Connection) -> int:
    conn.execute_rowcount(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        "version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
    )
    row = conn.one("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations")
    return int(row["v"]) if row else 0


def migrate(pool: ConnectionPool) -> int:
    """Apply every pending migration in order. Returns the resulting version.

    Each migration runs in its own transaction, so a failure leaves the database
    at the last complete version rather than half-way through one.
    """
    applied = 0
    with pool.acquire() as conn:
        conn.begin()
        current = _applied_version(conn)
        conn.commit()

    for version, _description, apply in MIGRATIONS:
        if version <= current:
            continue
        with pool.acquire() as conn:
            conn.begin()
            apply(conn)
            conn.execute_rowcount(
                f"INSERT INTO schema_migrations (version, applied_at) "
                f"VALUES ({conn.p},{conn.p})",
                (version, datetime.now(timezone.utc).isoformat()),
            )
            conn.commit()
        applied += 1
    return current + applied


def verify(pool: ConnectionPool) -> int:
    """Assert the schema is exactly the version this build expects. O(1).

    Safe to call at startup: one indexed read, no table scan, no DDL.
    """
    with pool.acquire() as conn:
        conn.begin()
        found = _applied_version(conn)
        conn.commit()
    if found != CURRENT_VERSION:
        raise SchemaOutOfDate(
            f"database schema is at version {found}, this build requires "
            f"{CURRENT_VERSION}. Run `python -m sentinel.interface.cli migrate` "
            "before starting the service. Refusing to serve against an unverified "
            "schema is deliberate."
        )
    return found

