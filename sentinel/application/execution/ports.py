"""Ports the execution engine needs: the step journal and the inbox.

Both are deliberately narrow. The journal answers exactly one question -- "has
this step settled, and if so what did it decide?" -- and the inbox answers
exactly one -- "have I already accepted this message?". A port that answers one
question is a port whose implementation can be verified.

WHY THESE ARE SEPARATE FROM THE REPOSITORIES
---------------------------------------------
They participate in the same transaction (they are reached through the unit of
work) but they are not part of the Incident aggregate. The aggregate is the
authority on what is TRUE about an incident; the journal is the authority on what
this system has DONE. Merging them is how the predecessor ended up inferring
execution history from lifecycle state, which is an approximation that fails for
every step that performs work without producing a transition.
"""

from __future__ import annotations

from typing import Any, Mapping, Protocol, runtime_checkable

from sentinel.domain.execution import StepName, StepRecord, StepStatus
from sentinel.domain.primitives import IncidentId, MessageId, Timestamp

__all__ = ["ExecutionJournal", "Inbox"]


@runtime_checkable
class ExecutionJournal(Protocol):
    """The durable record of which steps have run, and what they decided.

    Every method is scoped to the unit of work's tenant. The journal is written
    in the SAME transaction as the lifecycle transition the step produced, so the
    two can never disagree about whether a step happened.
    """

    def load(self, incident_id: IncidentId) -> Mapping[StepName, StepRecord]:
        """Every journal entry for this incident. The engine's whole input.

        Returned as a mapping rather than a list because the engine's only
        question is per-step, and an ordered list invites a caller to re-derive
        ordering that `ExecutionPlan` already owns.
        """
        ...

    def enter(
        self,
        incident_id: IncidentId,
        *,
        step: StepName,
        epoch: int,
        now: Timestamp,
    ) -> StepRecord:
        """Mark a step RUNNING at `epoch`, returning the resulting record.

        Idempotent per (incident, step): re-entering a RUNNING step at a NEWER
        epoch is legal and is how a crashed worker's step is taken over. Entering
        a settled step raises, because the engine should never have asked.

        This write commits BEFORE the step's effect is attempted. That ordering
        is the point: a crash between the mark and the effect leaves a RUNNING
        row, which tells the next worker to reconcile rather than blindly repeat.
        The reverse ordering loses that information entirely.
        """
        ...

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
        """Record a step's outcome. Fenced on `epoch`.

        Raises `ExecutionFenceLost` if a newer epoch has taken the step, so a
        worker whose lease was reclaimed mid-step cannot record an outcome over
        the top of the worker that now owns it.
        """
        ...

    def settled_steps(self, incident_id: IncidentId) -> frozenset[StepName]:
        """Names whose outcome is final. What `ExecutionPlan.next_step` consumes."""
        ...


@runtime_checkable
class Inbox(Protocol):
    """Deduplicates inbound work at the boundary.

    The queue delivers at least once -- that is not a defect, it is the only
    guarantee a durable queue can offer without a distributed transaction with
    its consumer. The inbox is the consumer-side half that turns at-least-once
    delivery into at-most-once ACCEPTANCE, and the journal turns it into
    at-most-once EXECUTION.

    Together those two give effectively-once processing. Note the wording: this
    is not exactly-once *delivery*, which is impossible over an unreliable
    channel. It is exactly-once *effect*, achieved by making redelivery
    observable and every step idempotent.
    """

    def accept(
        self, *, message_id: MessageId, kind: str, now: Timestamp
    ) -> bool:
        """Claim a message. False if it was already accepted.

        The insert IS the claim: a unique constraint on (tenant, message_id) does
        the deduplication, so two workers racing the same redelivery cannot both
        win. Checking-then-inserting would hand both a False and let both run.
        """
        ...

    def seen(self, message_id: MessageId) -> bool: ...

    def purge_before(self, *, cutoff: Timestamp) -> int:
        """Drop entries older than the redelivery window. Returns the count.

        An inbox that grows forever is a table scan waiting to happen. The cutoff
        must exceed the queue's maximum redelivery age or deduplication silently
        stops working for old messages.
        """
        ...
