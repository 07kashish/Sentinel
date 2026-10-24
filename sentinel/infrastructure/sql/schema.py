"""Schema definition and row-level-security policy, owned in one place.

WHY THE DDL IS HERE AND NOWHERE ELSE
------------------------------------
Schema split across modules is how a table ends up existing in one deployment and
not another. The predecessor had already learned this once and consolidated its
DDL, then added `_ADDITIVE_COLUMNS` -- a tuple of `(table, column, ddl)` triples
applied at boot -- plus a `_backfill_ledger_predecessors()` walk over every
ledger row for every tenant, also at boot, on every replica, unconditionally.

At ten million ledger rows that boot step is unbounded, three replicas run it
simultaneously against the same rows, and it exceeds any Kubernetes
`startupProbe` long before it finishes. A migration is a one-shot job, not a
startup step. `sentinel/infrastructure/sql/migrate.py` owns that; this module
only declares the target shape.

ROW-LEVEL SECURITY
------------------
`USING` and `WITH CHECK` are BOTH specified explicitly. PostgreSQL infers
`WITH CHECK` from `USING` for `FOR ALL` policies, so omitting it happens to work
-- but relying on an inference for the clause that governs writes is the kind of
implicit correctness this architecture is organised against. Stating both means a
reader does not have to know the inference rule to audit the policy.

`current_setting(..., true)` returns NULL when the context is unset, so a
connection that never established a tenant sees nothing rather than raising -- it
fails closed and silently empty, which is why `UnitOfWorkFactory.begin()` makes
the tenant a required argument. There is no way to obtain a connection without
scoping it.

THE WORKER SCOPE: THE ONE DELIBERATE CROSS-TENANT READ
-------------------------------------------------------
`work_queue` is sharded by tenant hash precisely so that a worker can claim
with ONE query across every tenant in its shard. That query has no tenant to
bind, and under the tenant policy alone it matched nothing: the queue was
protected, the claim was unscoped, and on PostgreSQL no work was ever claimed
while every SQLite test passed -- the exact defect `PROTECTED_TABLES` warns
about, reproduced on the table it names.

Silently exempting the queue from RLS would be the wrong fix: a queue row
carries an incident id and a payload, and an unprotected queue is a
cross-tenant read of what every tenant is currently doing. Instead the tables
in `WORKER_SCOPED_TABLES` carry a SECOND policy that admits a row when the
transaction has declared `sentinel.worker_scope = 'all'` -- a separate,
transaction-local setting that only `Connection.set_worker_scope()` writes and
only the queue's cross-tenant statements call. A tenant-scoped connection that
never set it is bounded exactly as before; the scope is explicit, per
transaction, and reverts at commit like the tenant context does.
"""

from __future__ import annotations

from typing import Final

from sentinel.infrastructure.sql.schema_registries import REGISTRY_STATEMENTS
from sentinel.infrastructure.sql.schema_execution import EXECUTION_STATEMENTS, EXECUTION_TABLES
from sentinel.infrastructure.sql.connected_apps import CONNECTED_APP_STATEMENTS
from sentinel.infrastructure.sql.device_discovery import DEVICE_STATEMENTS
__all__ = [
    "PROTECTED_TABLES",
    "SCHEMA_STATEMENTS",
    "TENANT_SETTING",
    "WORKER_SCOPED_TABLES",
    "WORKER_SCOPE_SETTING",
    "rls_statements",
]
TENANT_SETTING: Final = "sentinel.tenant_id"

#: The transaction-local setting that admits a cross-tenant scan. Its only legal
#: value is `'all'`, and the only writer is `Connection.set_worker_scope()`.
WORKER_SCOPE_SETTING: Final = "sentinel.worker_scope"

#: Tables the worker must scan ACROSS tenants and which therefore carry the
#: worker-scope policy in addition to tenant isolation. Deliberately tiny: the
#: outbox, inbox and journal are all read inside a tenant-scoped unit of work
#: and need nothing here. Every table listed must ALSO be in PROTECTED_TABLES --
#: the worker policy is an addition to isolation, never a replacement for it.
WORKER_SCOPED_TABLES: Final[tuple[str, ...]] = ("work_queue",)

#: Tables holding tenant-owned rows. `tenants` is deliberately absent: it is the
#: directory used to ESTABLISH a scope, so scoping it to a context that has not
#: been established yet would deadlock startup. Every other table is protected,
#: including the queues -- the predecessor protected `delivery_queue` and then
#: called it from an unscoped connection, which made every terminal DLQ
#: operation invisible on PostgreSQL and worked fine on SQLite.
PROTECTED_TABLES: Final[tuple[str, ...]] = (
    "incidents",
    "incident_transitions",
    "evidence",
    "reports",
    "approvals",
    # A containment is a tenant's kill switch. Unprotected it would be both
    # readable across tenants -- disclosing which agents someone has stopped and
    # why, which is an incident in progress -- and writable, which is a way to
    # halt another tenant's estate.
    "containments",
    # Enterprise controls. All four are tenant-owned and all four disclose
    # something across a boundary if unprotected: which policy a tenant runs is
    # a map of what they do and do not detect, their retention window is a
    # compliance posture, and their key state is whether their data is readable.
    "policy_versions",
    "tenant_settings",
    "tenant_key_versions",
    "mode_transitions",
    "ledger_entries",
    "ledger_batches",
    "outbox",
    "inbox",
    "execution_steps",
    "work_queue",
    "domain_events",
    "agents",
    "replay_nonces",
    # Execution binding: a nonce ledger or authorization table readable across
    # tenants lets one tenant's token be resolved or replayed under another.
    "execution_nonces",
    "execution_authorizations",
    # Intent/outcome record and shared budget/breaker state (schema_execution.py).
    *EXECUTION_TABLES,
    "device_discovery", "connected_apps",
    "security_audit",
    # Human identity. `users` most of all: a cross-tenant read here is a customer
    # roster, and `user_credentials` is which authenticators exist.
    "users",
    "user_credentials",
    "user_sessions",
    "enrolment_tickets",
    "organizations",
    # MCP server enrolment and tool pins. A pin is a security decision about one
    # tenant's servers: which MCP servers are trusted, and what their tools were
    # when an operator approved them. A cross-tenant read here tells an attacker
    # which servers to impersonate; a cross-tenant WRITE would let one tenant pin
    # a hostile definition into another tenant's allowlist.
    "mcp_servers",
    "a2a_agent_cards",
    # The transparency log. Tenant-scoped for the obvious reason and one less
    # obvious: a cross-tenant WRITE here would let one tenant append to
    # another's log, and every consistency proof after that point would fail
    # for a reason the victim could not explain.
    "transparency_leaves",
    "transparency_roots",
    # Execution receipts: a cross-tenant WRITE would let one tenant fabricate
    # another's record of a substituted execution, the record binding exists for.
    "execution_receipts",
    "mcp_tool_pins",
    # Tool provenance and change history. Provenance rows say which definition
    # versions a server has actually served this tenant and when; change rows
    # are the durable record of every observed drift. Cross-tenant reads here
    # disclose which tools a victim's agents use; cross-tenant writes would let
    # one tenant fabricate another's forensic history.
    "mcp_tool_provenance",
    "mcp_tool_changes",
    "agent_tool_grants",
    "agent_observations",
    "agent_observed_edges",
    "agent_declarations",
    "execution_nodes",
    # Remediation idempotency. A receipt says which real-world action ran under
    # which key; a cross-tenant READ discloses what has been done to another
    # tenant's estate, and a cross-tenant WRITE would let one tenant plant a
    # "already executed" receipt that suppresses another's containment.
    "remediation_idempotency",
)


_CORE_STATEMENTS: Final[tuple[str, ...]] = (
    # ── Governance ───────────────────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS tenants (
        tenant_id   TEXT PRIMARY KEY,
        name        TEXT NOT NULL,
        created_at  TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS agents (
        tenant_id  TEXT NOT NULL,
        address    TEXT NOT NULL,
        label      TEXT NOT NULL DEFAULT '',
        enrolled_at TEXT NOT NULL,
        last_event_at TEXT,
        revoked_at TEXT,
        PRIMARY KEY (tenant_id, address)
    )
    """,
    # ── Incident aggregate ───────────────────────────────────────────────────
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
        PRIMARY KEY (tenant_id, incident_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_incidents_state ON incidents(tenant_id, state, updated_at)",
    "CREATE INDEX IF NOT EXISTS ix_incidents_updated ON incidents(tenant_id, updated_at)",
    """
    CREATE TABLE IF NOT EXISTS incident_transitions (
        tenant_id    TEXT NOT NULL,
        incident_id  TEXT NOT NULL,
        seq          INTEGER NOT NULL,
        from_state   TEXT,
        to_state     TEXT NOT NULL,
        facts_added  TEXT NOT NULL,
        actor        TEXT NOT NULL,
        occurred_at  TEXT NOT NULL,
        PRIMARY KEY (tenant_id, incident_id, seq)
    )
    """,
    # ── Evidence and ledger ──────────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS evidence (
        tenant_id        TEXT NOT NULL,
        incident_id      TEXT NOT NULL,
        uri              TEXT NOT NULL,
        digest           TEXT NOT NULL,
        content_json     TEXT,
        created_at       TEXT NOT NULL,
        redacted_at      TEXT,
        redaction_reason TEXT,
        redacted_by      TEXT,
        PRIMARY KEY (tenant_id, incident_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS reports (
        tenant_id     TEXT NOT NULL,
        incident_id   TEXT NOT NULL,
        content       TEXT NOT NULL,
        created_at    TEXT NOT NULL,
        withdrawn_at  TEXT,
        withdrawn_why TEXT,
        PRIMARY KEY (tenant_id, incident_id)
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
    # A fork is UNSTORABLE: two entries claiming the same predecessor collide.
    """
    CREATE UNIQUE INDEX IF NOT EXISTS ux_ledger_chain
        ON ledger_entries(tenant_id, prev_chain_hash)
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS ux_ledger_incident
        ON ledger_entries(tenant_id, incident_id)
    """,
    "CREATE INDEX IF NOT EXISTS ix_ledger_unsealed ON ledger_entries(tenant_id, batch_id, seq)",
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
    # ── Approvals ────────────────────────────────────────────────────────────
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
        -- When this request stops being executable. An approval with no expiry
        -- is a standing authorization to act on production: approved three
        -- months after it was raised, against an estate that has changed, it
        -- still fires. The window is what makes it a decision about a situation
        -- rather than a permanent grant.
        expires_at   TEXT NOT NULL DEFAULT '',
        -- The section-32 request context: risk factors, execution graph session,
        -- business impact, recommended decision. JSON because it is read whole
        -- by a human and never filtered on -- an approver opens one request and
        -- reads all of it.
        context_json TEXT,
        -- When `claim_for_execution` moved this row to `executing`. Empty
        -- otherwise. The maintenance loop's reaper compares it against the
        -- queue lease: a worker that died between the claim and the outcome
        -- left an approval nobody can decide, and without this timestamp there
        -- was no way to tell "executing for two seconds" from "executing since
        -- last Tuesday".
        executing_since TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (tenant_id, approval_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_approvals_state ON approvals(tenant_id, state)",
    "CREATE INDEX IF NOT EXISTS ix_approvals_incident ON approvals(tenant_id, incident_id)",
    # ── Enterprise controls: policy-as-code, residency, retention, keys ──────
    """
    CREATE TABLE IF NOT EXISTS policy_versions (
        tenant_id   TEXT NOT NULL,
        version     INTEGER NOT NULL,
        digest      TEXT NOT NULL,
        rules_json  TEXT NOT NULL,
        created_by  TEXT NOT NULL,
        created_at  TEXT NOT NULL,
        note        TEXT NOT NULL DEFAULT '',
        -- Exactly one active version per tenant, enforced by the repository's
        -- conditional UPDATE rather than by a partial index, because the two
        -- engines spell partial indexes differently and a constraint that
        -- exists on one engine only is worse than one that exists on neither.
        active      INTEGER NOT NULL DEFAULT 0,
        activated_at TEXT NOT NULL DEFAULT '',
        activated_by TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (tenant_id, version)
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_policy_active ON policy_versions(tenant_id, active)",
    """
    CREATE TABLE IF NOT EXISTS tenant_settings (
        tenant_id            TEXT NOT NULL,
        region               TEXT NOT NULL DEFAULT 'us',
        protection_mode      TEXT NOT NULL DEFAULT 'monitor',
        events_days          INTEGER NOT NULL DEFAULT 90,
        incidents_days       INTEGER NOT NULL DEFAULT 365,
        raw_payloads_days    INTEGER NOT NULL DEFAULT 30,
        evidence_days        INTEGER NOT NULL DEFAULT 365,
        execution_nodes_days INTEGER NOT NULL DEFAULT 90,
        updated_at           TEXT NOT NULL DEFAULT '',
        updated_by           TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (tenant_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS tenant_key_versions (
        tenant_id   TEXT NOT NULL,
        version     INTEGER NOT NULL,
        -- A REFERENCE, never material. See `domain/keys.py`: a vendor holding
        -- the bytes can decrypt after revocation whatever its state says.
        key_ref     TEXT NOT NULL,
        state       TEXT NOT NULL,
        provider    TEXT NOT NULL DEFAULT 'vendor',
        created_at  TEXT NOT NULL,
        revoked_at  TEXT NOT NULL DEFAULT '',
        revoked_by  TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (tenant_id, version)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS mode_transitions (
        tenant_id   TEXT NOT NULL,
        seq         INTEGER NOT NULL,
        from_mode   TEXT NOT NULL,
        to_mode     TEXT NOT NULL,
        changed_by  TEXT NOT NULL,
        changed_at  TEXT NOT NULL,
        reason      TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (tenant_id, seq)
    )
    """,
    # ── Containment: the granular kill switch ────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS containments (
        tenant_id      TEXT NOT NULL,
        containment_id TEXT NOT NULL,
        scope          TEXT NOT NULL,
        selector       TEXT NOT NULL,
        created_by     TEXT NOT NULL,
        created_at     TEXT NOT NULL,
        reason         TEXT NOT NULL DEFAULT '',
        expires_at     TEXT NOT NULL DEFAULT '',
        revoked_at     TEXT NOT NULL DEFAULT '',
        revoked_by     TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (tenant_id, containment_id)
    )
    """,
    # Active containments are read on the enforcement path, so the index covers
    # the filter that path uses. Without it, every contained request scans every
    # containment the tenant has ever created, including revoked ones.
    "CREATE INDEX IF NOT EXISTS ix_containments_active "
    "ON containments(tenant_id, revoked_at, scope)",
    # ── Outbox (a real one: separate dispatcher, leased delivery) ────────────
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
    CREATE UNIQUE INDEX IF NOT EXISTS ux_outbox_idempotency
        ON outbox(tenant_id, idempotency_key)
    """,
    "CREATE INDEX IF NOT EXISTS ix_outbox_due ON outbox(tenant_id, state, available_at)",
    # ── Inbox: at-most-once ACCEPTANCE of an at-least-once delivery ─────────
    #
    # The unique primary key IS the deduplication. Checking-then-inserting would
    # hand two workers racing the same redelivery a False each and let both run;
    # the insert itself is the claim, and exactly one of them wins it.
    """
    CREATE TABLE IF NOT EXISTS inbox (
        tenant_id   TEXT NOT NULL,
        message_id  TEXT NOT NULL,
        kind        TEXT NOT NULL,
        accepted_at TEXT NOT NULL,
        PRIMARY KEY (tenant_id, message_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_inbox_age ON inbox(accepted_at)",
    # ── Execution journal: the authority on what this system has DONE ───────
    #
    # Distinct from the incident lifecycle, which is the authority on what is
    # TRUE. Both commit together. The predecessor inferred execution history from
    # lifecycle state, which is an approximation that fails for every step that
    # performs work without producing a transition.
    """
    CREATE TABLE IF NOT EXISTS execution_steps (
        tenant_id    TEXT NOT NULL,
        incident_id  TEXT NOT NULL,
        step         TEXT NOT NULL,
        status       TEXT NOT NULL,
        epoch        INTEGER NOT NULL,
        attempts     INTEGER NOT NULL DEFAULT 0,
        result_json  TEXT NOT NULL DEFAULT '{}',
        error        TEXT,
        entered_at   TEXT NOT NULL,
        settled_at   TEXT,
        PRIMARY KEY (tenant_id, incident_id, step)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_steps_incident
        ON execution_steps(tenant_id, incident_id, status)
    """,
    # ── Work queue, sharded ──────────────────────────────────────────────────
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
    # The dispatch index. Shard leads so a worker's claim is a single ranged
    # scan over its shard key range (the table is not partitioned), rather than the fan-out that
    # opened one connection PER TENANT on every poll.
    """
    CREATE INDEX IF NOT EXISTS ix_work_dispatch
        ON work_queue(shard, state, available_at, priority, enqueued_at)
    """,
    # ── Domain event log ─────────────────────────────────────────────────────
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
        PRIMARY KEY (tenant_id, event_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_events_stream ON domain_events(tenant_id, recorded_at)",
    # Added with the incident retention policy. The primary key is
    # (tenant_id, event_id), so "every event for this incident" -- which is both
    # the analyst's per-incident read and the retention sweep's delete -- had no
    # index at all and was a sequential scan of the whole table. For a sweep that
    # runs once per doomed incident that is quadratic in history size, i.e. the
    # retention job gets slower exactly as the thing it exists to bound grows.
    "CREATE INDEX IF NOT EXISTS ix_events_incident "
    "ON domain_events(tenant_id, incident_id)",
    # ── Replay defence ───────────────────────────────────────────────────────
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
    "CREATE INDEX IF NOT EXISTS ix_nonces_expiry ON replay_nonces(expires_at)",
    # ── Human identity ───────────────────────────────────────────────────────
    #
    # No password column, deliberately and permanently. Authentication is a passkey;
    # see sentinel/domain/identity.py for why a password store is not being added.
    #
    # A suspended user is kept rather than deleted: removing the row destroys the
    # audit trail's ability to name who did something, and "who was this actor"
    # asked six months later is exactly what the trail exists to answer.
    """
    CREATE TABLE IF NOT EXISTS users (
        tenant_id     TEXT NOT NULL,
        user_id       TEXT NOT NULL,
        email         TEXT NOT NULL,
        display_name  TEXT NOT NULL DEFAULT '',
        role          TEXT NOT NULL,
        state         TEXT NOT NULL DEFAULT 'invited',
        totp_secret   TEXT,
        created_at    TEXT NOT NULL,
        updated_at    TEXT NOT NULL,
        external_id   TEXT,
        PRIMARY KEY (tenant_id, user_id)
    )
    """,
    # Email uniqueness is PER TENANT, not global: two customers may legitimately
    # employ the same person, and a global constraint would leak that they both do.
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email ON users(tenant_id, email)",
    # SCIM looks users up by externalId, which the directory owns.
    "CREATE INDEX IF NOT EXISTS ix_users_external ON users(tenant_id, external_id)",
    #
    # One row per registered authenticator. `public_key_cose` holds the bytes the
    # authenticator sent, hex-encoded -- not re-encoded, because a round trip through
    # a decoder is an opportunity to change bytes a signature is verified against.
    """
    CREATE TABLE IF NOT EXISTS user_credentials (
        tenant_id        TEXT NOT NULL,
        credential_id    TEXT NOT NULL,
        user_id          TEXT NOT NULL,
        public_key_cose  TEXT NOT NULL,
        algorithm        INTEGER NOT NULL,
        sign_count       INTEGER NOT NULL DEFAULT 0,
        aaguid           TEXT NOT NULL DEFAULT '',
        label            TEXT NOT NULL DEFAULT '',
        created_at       TEXT NOT NULL,
        last_used_at     TEXT,
        PRIMARY KEY (tenant_id, credential_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_credentials_user ON user_credentials(tenant_id, user_id)",
    #
    # Sessions are opaque and server-side so they can be REVOKED, which a JWT cannot
    # be. Only the digest is stored: a session table holding live tokens is a
    # credential store, and one SELECT would be every logged-in user.
    """
    CREATE TABLE IF NOT EXISTS user_sessions (
        tenant_id      TEXT NOT NULL,
        session_id     TEXT NOT NULL,
        user_id        TEXT NOT NULL,
        token_digest   TEXT NOT NULL,
        created_at     TEXT NOT NULL,
        last_seen_at   TEXT NOT NULL,
        stepped_up_at  TEXT,
        revoked_at     TEXT,
        user_agent     TEXT NOT NULL DEFAULT '',
        source_address TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (tenant_id, session_id)
    )
    """,
    # The lookup on every authenticated request is by digest, so it must be indexed
    # and unique -- two sessions sharing a digest would be a collision the code below
    # resolves arbitrarily.
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_sessions_digest ON user_sessions(token_digest)",
    "CREATE INDEX IF NOT EXISTS ix_sessions_user ON user_sessions(tenant_id, user_id)",
    #
    # Single-use, short-lived permission to attach a first credential. The weakest
    # credential in the system, because it may travel over a channel nobody controls,
    # and therefore the most constrained.
    """
    CREATE TABLE IF NOT EXISTS enrolment_tickets (
        tenant_id    TEXT NOT NULL,
        ticket_id    TEXT NOT NULL,
        user_id      TEXT NOT NULL,
        token_digest TEXT NOT NULL,
        issued_at    TEXT NOT NULL,
        issued_by    TEXT NOT NULL,
        redeemed_at  TEXT,
        PRIMARY KEY (tenant_id, ticket_id)
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_tickets_digest ON enrolment_tickets(token_digest)",
    #
    # Challenges, so a WebAuthn ceremony's challenge is single-use and server-issued.
    # Without this table a challenge is whatever the client says it is, and every
    # assertion is replayable.
    """
    CREATE TABLE IF NOT EXISTS webauthn_challenges (
        tenant_id  TEXT NOT NULL,
        challenge  TEXT NOT NULL,
        purpose    TEXT NOT NULL,
        user_id    TEXT,
        issued_at  TEXT NOT NULL,
        consumed_at TEXT,
        PRIMARY KEY (challenge)
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_challenges_issued ON webauthn_challenges(issued_at)",
    """
    CREATE TABLE IF NOT EXISTS organizations (
        tenant_id  TEXT NOT NULL PRIMARY KEY,
        org_id     TEXT NOT NULL UNIQUE,
        name       TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    # ── Security audit trail ─────────────────────────────────────────────────
    #
    # Append-only and hash-chained: each row commits to the previous row's digest,
    # so deleting or editing an entry breaks verification from that point on. A
    # log an attacker can edit after the fact is not an audit trail, and an
    # ordinary table with an UPDATE grant is exactly that.
    #
    # `seq` is per-tenant and dense, which is what makes a DELETED row detectable:
    # a gap is evidence. An auto-increment shared across tenants would let one
    # tenant's write rate reveal another's activity, and a sparse sequence makes
    # deletion invisible.
    #
    # No ON DELETE CASCADE from tenants, deliberately. Removing a tenant must not
    # silently remove the record of what was done to it.
    """
    CREATE TABLE IF NOT EXISTS security_audit (
        tenant_id       TEXT NOT NULL,
        seq             INTEGER NOT NULL,
        actor           TEXT NOT NULL,
        action          TEXT NOT NULL,
        resource_type   TEXT NOT NULL,
        resource_id     TEXT NOT NULL,
        outcome         TEXT NOT NULL,
        occurred_at     TEXT NOT NULL,
        detail          TEXT NOT NULL DEFAULT '{}',
        prev_chain_hash TEXT NOT NULL,
        chain_hash      TEXT NOT NULL,
        PRIMARY KEY (tenant_id, seq)
    )
    """,
    # Partial-free and cheap: the two queries an investigation actually runs are
    # "what happened to this resource" and "what did this actor do".
    "CREATE INDEX IF NOT EXISTS ix_audit_resource ON security_audit"
    "(tenant_id, resource_type, resource_id, seq)",
    "CREATE INDEX IF NOT EXISTS ix_audit_actor ON security_audit(tenant_id, actor, seq)",
    # ── Remediation idempotency ──────────────────────────────────────────────
    #
    # Durable and tenant-scoped. The predecessor held these receipts in ONE
    # PROCESS'S MEMORY, so a replica restart -- or a retry landing on the other
    # replica -- re-executed an action that had already reached the world.
    # `receipt_json` is the full receipt, replayed verbatim with the flag set.
    """
    CREATE TABLE IF NOT EXISTS remediation_idempotency (
        tenant_id       TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        receipt_json    TEXT NOT NULL,
        created_at      TEXT NOT NULL,
        PRIMARY KEY (tenant_id, idempotency_key)
    )
    """,
    # ── Execution binding: single-use nonces and issued authorizations ──────
    #
    # `execution_nonces` is the shared `NonceLedger`: a row is a nonce that has
    # been BURNED. Single-use holds across every replica because the primary
    # key makes a second INSERT a constraint violation rather than a race.
    # `claimed_at` is evidence, not a key -- a ledger that could not say WHEN a
    # nonce was burned could not answer a replay investigation.
    #
    # `execution_authorizations` holds what `/v1/protect/evaluate` issued, so
    # `/v1/tools/execute` can redeem an opaque token under the authenticated
    # tenant. Only the token's DIGEST is stored; the secret half travels with
    # the caller and never lands in a row.
    #
    # Both were first created lazily from their stores' `ensure_schema`. They
    # live here now so the audited RLS loop covers them: a table created
    # outside `PROTECTED_TABLES` is readable across tenants on PostgreSQL, and
    # an authorization table readable across tenants is a way to redeem
    # somebody else's decision.
    """
    CREATE TABLE IF NOT EXISTS execution_nonces (
        tenant_id  TEXT NOT NULL,
        nonce      TEXT NOT NULL,
        claimed_at TEXT NOT NULL,
        PRIMARY KEY (tenant_id, nonce)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS execution_authorizations (
        tenant_id        TEXT NOT NULL,
        authorization_id TEXT NOT NULL,
        nonce            TEXT NOT NULL,
        token_digest     TEXT NOT NULL,
        state            TEXT NOT NULL,
        document         TEXT NOT NULL,
        issued_at        TEXT NOT NULL,
        expires_at       TEXT NOT NULL,
        approved_by      TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (tenant_id, authorization_id)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_execution_authorizations_expiry
        ON execution_authorizations (tenant_id, expires_at)
    """,
    # ── Leader election ──────────────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS leader_locks (
        job_name    TEXT PRIMARY KEY,
        holder      TEXT NOT NULL,
        acquired_at TEXT NOT NULL
    )
    """,
    # ── Schema version, so migration is a decision and not a guess ──────────
    """
    CREATE TABLE IF NOT EXISTS schema_migrations (
        version    INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL
    )
    """,
)


def rls_statements(table: str) -> tuple[str, ...]:
    """DDL enabling row-level security for one table. Idempotent.

    For a table in `WORKER_SCOPED_TABLES` this ALSO emits the worker-scope
    policy, so the two are applied by the same audited loop in `migrate.py`
    and a queue table can never carry one without the other.
    """
    policy = f"{table}_tenant_isolation"
    predicate = f"tenant_id = current_setting('{TENANT_SETTING}', true)"
    statements = (
        f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY",
        # Without FORCE the table OWNER bypasses the policy, and the application
        # is usually the owner -- which would make all of this decorative.
        f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY",
        f"DROP POLICY IF EXISTS {policy} ON {table}",
        # USING governs reads and the visibility half of writes; WITH CHECK
        # governs what may be written. Both stated, neither inferred.
        f"CREATE POLICY {policy} ON {table} "
        f"USING ({predicate}) WITH CHECK ({predicate})",
    )
    if table in WORKER_SCOPED_TABLES:
        statements += _worker_scope_statements(table)
    return statements


def _worker_scope_statements(table: str) -> tuple[str, ...]:
    """The second, PERMISSIVE policy on a worker-scanned table. Idempotent.

    PostgreSQL ORs permissive policies together, so a row is visible when
    EITHER the tenant context matches it OR the transaction has declared the
    worker scope. The predicate compares against a literal: the setting has
    exactly one meaningful value, and a policy that admitted any non-empty
    string would admit a typo.
    """
    policy = f"{table}_worker_scope"
    predicate = f"current_setting('{WORKER_SCOPE_SETTING}', true) = 'all'"
    return (
        f"DROP POLICY IF EXISTS {policy} ON {table}",
        f"CREATE POLICY {policy} ON {table} "
        f"USING ({predicate}) WITH CHECK ({predicate})",
    )


#: THE ONE APPLICATION SITE. `migrate.py` iterates this and nothing else, so the
#: registry DDL living in a sibling module does not create a second place where
#: schema is applied -- which is the failure `schema.py`'s docstring warns about.
SCHEMA_STATEMENTS: Final[tuple[str, ...]] = (
    _CORE_STATEMENTS + REGISTRY_STATEMENTS + EXECUTION_STATEMENTS + DEVICE_STATEMENTS + CONNECTED_APP_STATEMENTS
)
