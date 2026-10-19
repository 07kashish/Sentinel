"""Durable execution operations: intent before effect, outcome after.

Tenant-scoped, in `PROTECTED_TABLES`, with the same explicit `tenant_id`
predicate every other store carries so SQLite -- which has no row-level
security -- is scoped by the same statement PostgreSQL is.

Two writes per operation, in two transactions ON PURPOSE. The intent commits
before the effect runs; the outcome commits after. Putting both in one
transaction would hold a database transaction open across a network call to a
third party, and would also make the intent disappear on rollback -- which is
precisely the row that has to survive when the outcome cannot be written.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Mapping, Sequence

from sentinel.domain.errors import TransientFailure
from sentinel.domain.operations import (
    TERMINAL_STATES,
    ExecutionOperation,
    OperationState,
)
from sentinel.infrastructure.sql.engine import ConnectionPool

__all__ = ["OperationConflict", "SqlOperationStore"]


class OperationConflict(RuntimeError):
    """An operation id already exists with a different intent."""


_COLUMNS: tuple[str, ...] = (
    "operation_id",
    "agent_identity",
    "tool_identity",
    "action",
    "target_resource",
    "parameter_digest",
    "state",
    "started_at",
    "completed_at",
    "authorization_id",
    "receipt_id",
    "downstream_idempotency_key",
    "downstream_supports_idempotency",
    "error",
    "result_digest",
    "reconciled_by",
    "reconciled_at",
    "reconciliation_note",
    "attributes_json",
)
_COLUMN_LIST = ", ".join(_COLUMNS)


@dataclass(frozen=True, slots=True)
class SqlOperationStore:
    pool: ConnectionPool

    # ── Intent ───────────────────────────────────────────────────────────────

    def begin(self, tenant: str, operation: ExecutionOperation) -> None:
        """Record the INTENT. Must commit before the effect is invoked.

        An operation id that already exists with the same digest is a retry
        of the same intent and is accepted as a no-op; one with a different
        digest is a conflict, because reusing an operation id for a different
        action would let a later record overwrite the evidence of an earlier one.
        """
        import json

        if operation.state is not OperationState.PENDING:
            raise ValueError("an operation begins in the pending state")
        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)
            existing = conn.one(
                f"SELECT parameter_digest, state FROM execution_operations "
                f"WHERE tenant_id={p} AND operation_id={p}",
                (tenant, operation.operation_id),
            )
            if existing is not None:
                conn.commit()
                if str(existing["parameter_digest"]) != operation.parameter_digest:
                    raise OperationConflict(
                        f"operation {operation.operation_id!r} already exists for a "
                        "different parameter digest; refusing to overwrite its intent"
                    )
                return
            placeholders = ", ".join([p] * (len(_COLUMNS) + 1))
            conn.execute_rowcount(
                f"INSERT INTO execution_operations (tenant_id, {_COLUMN_LIST}) "
                f"VALUES ({placeholders})",
                (
                    tenant,
                    operation.operation_id,
                    operation.agent_identity,
                    operation.tool_identity,
                    operation.action,
                    operation.target_resource,
                    operation.parameter_digest,
                    operation.state.value,
                    operation.started_at,
                    operation.completed_at,
                    operation.authorization_id,
                    operation.receipt_id,
                    operation.downstream_idempotency_key,
                    1 if operation.downstream_supports_idempotency else 0,
                    operation.error,
                    operation.result_digest,
                    operation.reconciled_by,
                    operation.reconciled_at,
                    operation.reconciliation_note,
                    json.dumps(dict(operation.attributes), sort_keys=True),
                ),
            )
            conn.commit()

    # ── Outcome ──────────────────────────────────────────────────────────────

    def complete(
        self,
        tenant: str,
        operation_id: str,
        *,
        state: OperationState,
        completed_at: str,
        receipt_id: str = "",
        result_digest: str = "",
        error: str = "",
    ) -> bool:
        """Move a pending operation to a terminal state. Once.

        Conditional on `state='pending'`, so a reconciler and a late worker
        cannot both claim to have decided it. Returns False when nothing was
        pending -- the caller must treat that as "somebody else already
        recorded an outcome", never as success.
        """
        if state not in TERMINAL_STATES:
            raise ValueError(f"{state.value!r} is not a terminal state")
        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)
            affected = conn.execute_rowcount(
                f"UPDATE execution_operations SET state={p}, completed_at={p}, "
                f"receipt_id={p}, result_digest={p}, error={p} "
                f"WHERE tenant_id={p} AND operation_id={p} AND state={p}",
                (
                    state.value,
                    completed_at,
                    receipt_id,
                    result_digest,
                    error[:2000],
                    tenant,
                    operation_id,
                    OperationState.PENDING.value,
                ),
            )
            conn.commit()
        return affected == 1

    def record_refusal(self, tenant: str, operation: ExecutionOperation) -> None:
        """A refused attempt, recorded whole: it never had a pending phase."""
        import json

        if operation.state is not OperationState.REFUSED:
            raise ValueError("record_refusal takes a refused operation")
        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)
            placeholders = ", ".join([p] * (len(_COLUMNS) + 1))
            try:
                conn.execute_rowcount(
                    f"INSERT INTO execution_operations (tenant_id, {_COLUMN_LIST}) "
                    f"VALUES ({placeholders})",
                    (
                        tenant,
                        operation.operation_id,
                        operation.agent_identity,
                        operation.tool_identity,
                        operation.action,
                        operation.target_resource,
                        operation.parameter_digest,
                        operation.state.value,
                        operation.started_at,
                        operation.completed_at,
                        operation.authorization_id,
                        operation.receipt_id,
                        "",
                        0,
                        operation.error[:2000],
                        "",
                        "",
                        "",
                        "",
                        json.dumps(dict(operation.attributes), sort_keys=True),
                    ),
                )
            except TransientFailure:
                # A duplicate refusal id (a retry of the same refused request)
                # is not worth failing the refusal over; the first record stands.
                conn.rollback()
                return
            conn.commit()

    # ── Reconciliation ───────────────────────────────────────────────────────

    def mark_stale_pending_unknown(
        self, tenant: str, *, now: datetime, pending_deadline_seconds: int
    ) -> int:
        """Every `pending` operation older than the deadline becomes UNKNOWN.

        The deadline is the longest an effect could plausibly still be
        running. Past it, the only honest statement is that the outcome was
        never recorded; whether the effect happened is for a human or a
        downstream lookup to establish. Returns the number moved.
        """
        cutoff = (now - timedelta(seconds=pending_deadline_seconds)).isoformat()
        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)
            moved = conn.execute_rowcount(
                f"UPDATE execution_operations SET state={p}, completed_at={p}, "
                f"error={p} WHERE tenant_id={p} AND state={p} AND started_at<{p}",
                (
                    OperationState.UNKNOWN_AFTER_EFFECT.value,
                    now.isoformat(),
                    "outcome was not recorded before the pending deadline",
                    tenant,
                    OperationState.PENDING.value,
                    cutoff,
                ),
            )
            conn.commit()
        return moved

    def reconcile(
        self,
        tenant: str,
        operation_id: str,
        *,
        resolved_state: OperationState,
        by: str,
        at: str,
        note: str,
    ) -> bool:
        """A human or a downstream lookup settles an UNKNOWN operation.

        Only `unknown_after_effect` rows can be reconciled, and only to
        `succeeded` or `failed`: reconciling to anything else would let a
        reconciler erase the fact that the outcome was once unknown, and that
        fact is what an investigation needs.
        """
        if resolved_state not in {OperationState.SUCCEEDED, OperationState.FAILED}:
            raise ValueError("an unknown outcome reconciles to succeeded or failed")
        if not note.strip():
            raise ValueError("reconciliation requires a note saying how the outcome was established")
        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)
            affected = conn.execute_rowcount(
                f"UPDATE execution_operations SET state={p}, reconciled_by={p}, "
                f"reconciled_at={p}, reconciliation_note={p} "
                f"WHERE tenant_id={p} AND operation_id={p} AND state={p}",
                (
                    resolved_state.value,
                    by,
                    at,
                    note[:2000],
                    tenant,
                    operation_id,
                    OperationState.UNKNOWN_AFTER_EFFECT.value,
                ),
            )
            conn.commit()
        return affected == 1

    def note_reconcile_attempt(self, tenant: str, operation_id: str, *, attempts: int, note: str) -> None:
        """Count an automatic lookup that could not settle the outcome."""
        import json

        current = self.get(tenant, operation_id)
        if current is None or current.state is not OperationState.UNKNOWN_AFTER_EFFECT:
            return
        attributes = {**dict(current.attributes), "reconcile_attempts": int(attempts),
                      "reconcile_last_note": note[:500]}
        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)
            conn.execute_rowcount(
                f"UPDATE execution_operations SET attributes_json={p} "
                f"WHERE tenant_id={p} AND operation_id={p} AND state={p}",
                (json.dumps(attributes, sort_keys=True), tenant, operation_id,
                 OperationState.UNKNOWN_AFTER_EFFECT.value),
            )
            conn.commit()

    # ── Reads ────────────────────────────────────────────────────────────────

    def get(self, tenant: str, operation_id: str) -> ExecutionOperation | None:
        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)
            row = conn.one(
                f"SELECT {_COLUMN_LIST} FROM execution_operations "
                f"WHERE tenant_id={p} AND operation_id={p}",
                (tenant, operation_id),
            )
            conn.commit()
        return self._hydrate(tenant, row) if row else None

    def list(
        self,
        tenant: str,
        *,
        states: Sequence[OperationState] = (),
        limit: int = 100,
    ) -> list[ExecutionOperation]:
        """Operations newest first, optionally restricted to some states.

        One bound parameter per state and one query per state rather than a
        dynamically sized `IN (...)`: the SQL text stays a fixed string the
        guard tests can prove interpolates only placeholders and constants.
        """
        wanted = list(states) or list(OperationState)
        out: list[ExecutionOperation] = []
        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)
            for state in wanted:
                rows = conn.execute(
                    f"SELECT {_COLUMN_LIST} FROM execution_operations "
                    f"WHERE tenant_id={p} AND state={p} "
                    f"ORDER BY started_at DESC LIMIT {p}",
                    (tenant, state.value, int(limit)),
                )
                out.extend(self._hydrate(tenant, row) for row in rows)
            conn.commit()
        out.sort(key=lambda op: op.started_at, reverse=True)
        return out[: int(limit)]

    def counts(self, tenant: str) -> dict[str, int]:
        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)
            rows = conn.execute(
                f"SELECT state, COUNT(*) AS n FROM execution_operations "
                f"WHERE tenant_id={p} GROUP BY state",
                (tenant,),
            )
            conn.commit()
        counts = {s.value: 0 for s in OperationState}
        for row in rows:
            counts[str(row["state"])] = int(row["n"])
        return counts

    @staticmethod
    def _hydrate(tenant: str, row: Mapping[str, Any]) -> ExecutionOperation:
        import json

        try:
            attributes = json.loads(str(row.get("attributes_json") or "{}"))
        except json.JSONDecodeError:
            attributes = {}
        return ExecutionOperation(
            operation_id=str(row["operation_id"]),
            tenant_id=tenant,
            agent_identity=str(row["agent_identity"]),
            tool_identity=str(row["tool_identity"]),
            action=str(row["action"]),
            target_resource=str(row["target_resource"]),
            parameter_digest=str(row["parameter_digest"]),
            state=OperationState(str(row["state"])),
            started_at=str(row["started_at"]),
            completed_at=str(row["completed_at"] or ""),
            authorization_id=str(row["authorization_id"] or ""),
            receipt_id=str(row["receipt_id"] or ""),
            downstream_idempotency_key=str(row["downstream_idempotency_key"] or ""),
            downstream_supports_idempotency=bool(row["downstream_supports_idempotency"]),
            error=str(row["error"] or ""),
            result_digest=str(row["result_digest"] or ""),
            reconciled_by=str(row["reconciled_by"] or ""),
            reconciled_at=str(row["reconciled_at"] or ""),
            reconciliation_note=str(row["reconciliation_note"] or ""),
            attributes=attributes if isinstance(attributes, dict) else {},
        )
