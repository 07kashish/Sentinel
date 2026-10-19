"""SQL execution journal and inbox. Both scoped to the unit of work's tenant.

These are the two tables that turn at-least-once delivery into once-observed
effect:

    inbox    at-most-once ACCEPTANCE  — a redelivered message is recognised
    journal  at-most-once EXECUTION   — a settled step is never re-run

Neither can see the one remaining case: a crash between an external effect and
the journal entry recording it. That gap is closed by the third layer, the
deterministic idempotency key the effect carries, which lets the RECEIVING system
collapse the duplicate. Three layers, because no single one of them is sufficient
and pretending otherwise is how "exactly once" becomes a marketing claim.
"""

from __future__ import annotations

import json
from typing import Any, Mapping

from sentinel.domain.errors import ArtifactMissing, ExecutionFenceLost
from sentinel.domain.execution import (
    StepName,
    StepRecord,
    StepStatus,
    check_step_transition,
)
from sentinel.domain.primitives import IncidentId, MessageId, TenantId, Timestamp
from sentinel.infrastructure.sql.engine import Connection

__all__ = ["SqlExecutionJournal", "SqlInbox"]


class SqlExecutionJournal:
    """The durable record of which steps ran, and what they decided."""

    __slots__ = ("_conn", "_tenant")

    def __init__(self, conn: Connection, tenant: TenantId) -> None:
        self._conn = conn
        self._tenant = tenant

    def _hydrate(self, row: Any) -> StepRecord:
        return StepRecord(
            step=StepName(row["step"]),
            status=StepStatus(row["status"]),
            epoch=int(row["epoch"]),
            attempts=int(row["attempts"]),
            result=json.loads(row["result_json"]) if row["result_json"] else {},
            error=row["error"],
        )

    def load(self, incident_id: IncidentId) -> Mapping[StepName, StepRecord]:
        p = self._conn.p
        rows = self._conn.execute(
            f"SELECT * FROM execution_steps WHERE tenant_id={p} AND incident_id={p}",
            (self._tenant.value, incident_id.value),
        )
        return {StepName(r["step"]): self._hydrate(r) for r in rows}

    def settled_steps(self, incident_id: IncidentId) -> frozenset[StepName]:
        p = self._conn.p
        rows = self._conn.execute(
            f"SELECT step FROM execution_steps WHERE tenant_id={p} AND incident_id={p} "
            f"AND status IN ('completed','compensated')",
            (self._tenant.value, incident_id.value),
        )
        return frozenset(StepName(r["step"]) for r in rows)

    def enter(
        self, incident_id: IncidentId, *, step: StepName, epoch: int, now: Timestamp
    ) -> StepRecord:
        """Mark a step RUNNING at `epoch`. Commits BEFORE the effect is attempted.

        The row is taken under a lock and the transition is checked by the pure
        `check_step_transition`, so an illegal step transition is refused by the
        same rules a unit test exercises without a database.
        """
        p = self._conn.p
        row = self._conn.one(
            f"SELECT * FROM execution_steps WHERE tenant_id={p} AND incident_id={p} "
            f"AND step={p}" + self._conn.lock_clause(),
            (self._tenant.value, incident_id.value, step.value),
        )
        current = StepStatus(row["status"]) if row else None
        check_step_transition(current, StepStatus.RUNNING)

        if row is None:
            self._conn.execute_rowcount(
                f"INSERT INTO execution_steps (tenant_id, incident_id, step, status, "
                f"epoch, attempts, result_json, entered_at) "
                f"VALUES ({p},{p},{p},'running',{p},1,'{{}}',{p})",
                (
                    self._tenant.value,
                    incident_id.value,
                    step.value,
                    epoch,
                    now.isoformat(),
                ),
            )
            return StepRecord(step=step, status=StepStatus.RUNNING, epoch=epoch, attempts=1)

        if int(row["epoch"]) > epoch:
            raise ExecutionFenceLost(
                f"step {step} for incident {incident_id} is held at epoch "
                f"{row['epoch']}; refusing to enter it at the older epoch {epoch}"
            )
        attempts = int(row["attempts"]) + 1
        self._conn.execute_rowcount(
            f"UPDATE execution_steps SET status='running', epoch={p}, attempts={p}, "
            f"error=NULL, entered_at={p} "
            f"WHERE tenant_id={p} AND incident_id={p} AND step={p}",
            (
                epoch,
                attempts,
                now.isoformat(),
                self._tenant.value,
                incident_id.value,
                step.value,
            ),
        )
        return StepRecord(
            step=step, status=StepStatus.RUNNING, epoch=epoch, attempts=attempts
        )

    def settle(
        self,
        incident_id: IncidentId,
        *,
        step: StepName,
        status: StepStatus,
        result: Mapping[str, Any],
        epoch: int,
        now: Timestamp,
        error: str | None = None,
    ) -> None:
        """Record a step's outcome, fenced on `epoch`.

        The `epoch=` predicate in the UPDATE is the fence. A worker whose lease
        was reclaimed mid-step affects zero rows and is told so, rather than
        writing its stale outcome over the top of the worker that now owns the
        step.
        """
        p = self._conn.p
        row = self._conn.one(
            f"SELECT status, epoch FROM execution_steps WHERE tenant_id={p} "
            f"AND incident_id={p} AND step={p}" + self._conn.lock_clause(),
            (self._tenant.value, incident_id.value, step.value),
        )
        if row is None:
            raise ArtifactMissing(
                f"cannot settle step {step} for incident {incident_id}: it was never "
                "entered. A settle without an enter means the durable intent was "
                "skipped, which is the ordering this journal exists to enforce."
            )
        check_step_transition(StepStatus(row["status"]), status)

        affected = self._conn.execute_rowcount(
            f"UPDATE execution_steps SET status={p}, result_json={p}, error={p}, "
            f"settled_at={p} WHERE tenant_id={p} AND incident_id={p} AND step={p} "
            f"AND epoch={p}",
            (
                status.value,
                json.dumps(dict(result), sort_keys=True, default=str),
                error,
                now.isoformat(),
                self._tenant.value,
                incident_id.value,
                step.value,
                epoch,
            ),
        )
        if affected == 0:
            raise ExecutionFenceLost(
                f"step {step} for incident {incident_id} is no longer held at epoch "
                f"{epoch} (now {row['epoch']}); refusing to record its outcome"
            )


class SqlInbox:
    """At-most-once acceptance of an at-least-once delivery."""

    __slots__ = ("_conn", "_tenant")

    def __init__(self, conn: Connection, tenant: TenantId) -> None:
        self._conn = conn
        self._tenant = tenant

    def accept(self, *, message_id: MessageId, kind: str, now: Timestamp) -> bool:
        """Claim a message. False if it was already accepted.

        The INSERT is the claim. `ON CONFLICT DO NOTHING` returning zero rows is
        the deduplication signal, so two workers racing the same redelivery
        cannot both win: the primary key decides, not a read the loser also
        performed.
        """
        p = self._conn.p
        affected = self._conn.execute_rowcount(
            f"INSERT INTO inbox (tenant_id, message_id, kind, accepted_at) "
            f"VALUES ({p},{p},{p},{p}) ON CONFLICT (tenant_id, message_id) DO NOTHING",
            (self._tenant.value, message_id.value, kind, now.isoformat()),
        )
        return affected == 1

    def seen(self, message_id: MessageId) -> bool:
        p = self._conn.p
        return (
            self._conn.one(
                f"SELECT 1 FROM inbox WHERE tenant_id={p} AND message_id={p}",
                (self._tenant.value, message_id.value),
            )
            is not None
        )

    def purge_before(self, *, cutoff: Timestamp) -> int:
        """Drop entries older than the redelivery window.

        The cutoff MUST exceed the queue's maximum redelivery age. Purging too
        eagerly does not fail loudly -- it silently stops deduplicating old
        messages, which is the worst possible failure mode for this table.
        """
        p = self._conn.p
        return self._conn.execute_rowcount(
            f"DELETE FROM inbox WHERE tenant_id={p} AND accepted_at<{p}",
            (self._tenant.value, cutoff.isoformat()),
        )
