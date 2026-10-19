"""DDL for the execution-control tables: operations and shared protect controls.

A sibling of `schema_registries.py` for the same reason it exists: `schema.py`
reached the module-size fitness limit. These statements are joined into
`SCHEMA_STATEMENTS` there, which remains THE ONE application site; nothing
here is applied independently, and both tables are in `PROTECTED_TABLES`.
"""

from __future__ import annotations

from typing import Final

__all__ = ["EXECUTION_STATEMENTS", "EXECUTION_TABLES"]

EXECUTION_STATEMENTS: Final[tuple[str, ...]] = (
    # ── Execution operations: intent before effect, outcome after ───────────
    #
    # A receipt is written after the side effect returns, so a crash between
    # the effect and the receipt leaves a change in the world with no record.
    # The operation row is written BEFORE the effect as `pending` and moved to
    # a terminal state afterwards; a row still pending past its deadline is
    # moved to `unknown_after_effect` by the maintenance loop, which is the
    # honest state and the one a reconciler must look at. Digests only.
    """
    CREATE TABLE IF NOT EXISTS execution_operations (
        tenant_id                       TEXT NOT NULL,
        operation_id                    TEXT NOT NULL,
        agent_identity                  TEXT NOT NULL,
        tool_identity                   TEXT NOT NULL,
        action                          TEXT NOT NULL,
        target_resource                 TEXT NOT NULL,
        parameter_digest                TEXT NOT NULL,
        state                           TEXT NOT NULL,
        started_at                      TEXT NOT NULL,
        completed_at                    TEXT NOT NULL DEFAULT '',
        authorization_id                TEXT NOT NULL DEFAULT '',
        receipt_id                      TEXT NOT NULL DEFAULT '',
        downstream_idempotency_key      TEXT NOT NULL DEFAULT '',
        downstream_supports_idempotency INTEGER NOT NULL DEFAULT 0,
        error                           TEXT NOT NULL DEFAULT '',
        result_digest                   TEXT NOT NULL DEFAULT '',
        reconciled_by                   TEXT NOT NULL DEFAULT '',
        reconciled_at                   TEXT NOT NULL DEFAULT '',
        reconciliation_note             TEXT NOT NULL DEFAULT '',
        attributes_json                 TEXT NOT NULL DEFAULT '{}',
        PRIMARY KEY (tenant_id, operation_id)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_execution_operations_state
        ON execution_operations (tenant_id, state, started_at)
    """,
    # ── Shared protect controls: one budget and one breaker per deployment ──
    #
    # One row per (tenant, agent). Every change is a conditional UPDATE under
    # a row lock, so two replicas cannot both consume the last unit of budget.
    # Tenant-scoped: a same-named agent in another tenant has its own row.
    """
    CREATE TABLE IF NOT EXISTS protect_control_state (
        tenant_id            TEXT NOT NULL,
        agent_id             TEXT NOT NULL,
        window_start         TEXT NOT NULL,
        budget_used          INTEGER NOT NULL DEFAULT 0,
        consecutive_failures INTEGER NOT NULL DEFAULT 0,
        circuit_opened_at    TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (tenant_id, agent_id)
    )
    """,
    # ── Evidence commitments ─────────────────────────────────────────────────
    # Which transparency-log leaf commits to which execution receipt. Written
    # in the SAME transaction as the leaf, so a receipt is committed exactly
    # once and an export can hand a verifier the receipt, its leaf and its
    # position together. Append-only: never reaped, like the leaves themselves.
    """
    CREATE TABLE IF NOT EXISTS evidence_commitments (
        tenant_id     TEXT NOT NULL,
        receipt_id    TEXT NOT NULL,
        leaf_digest   TEXT NOT NULL,
        sequence      INTEGER NOT NULL,
        committed_at  TEXT NOT NULL,
        PRIMARY KEY (tenant_id, receipt_id)
    )
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS ux_evidence_commitments_sequence
        ON evidence_commitments (tenant_id, sequence)
    """,
)

#: Tenant-scoped tables this module owns; `schema.PROTECTED_TABLES` splices it in.
EXECUTION_TABLES = ("execution_operations", "protect_control_state", "evidence_commitments")
