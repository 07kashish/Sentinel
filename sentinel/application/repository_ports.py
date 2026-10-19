"""The persistence contract: repositories, the unit of work, and its factory.

SPLIT OUT OF `ports.py`, WHICH HAD TWO JOBS
--------------------------------------------
`ports.py` describes the ambient collaborators an application handler needs --
a clock, a logger, an id generator, a model advisor. This module describes how
state is READ AND WRITTEN. They change for different reasons and are read by
different people, and keeping them together took one module past the size at
which it stops having a single reason to change.

`ports.py` re-exports everything here, so every existing import keeps working.

WHY THE UNIT-OF-WORK MEMBERS ARE READ-ONLY PROPERTIES
------------------------------------------------------
A protocol data attribute is mutable, and a mutable member is INVARIANT: an
implementation's `incidents` would have to be exactly an `IncidentRepository`
rather than a subtype, which no real implementation is. Declaring them
read-only makes them covariant and states the correct contract -- nothing
should reassign a unit of work's repositories mid-transaction.

That invariance was invisible for as long as the type_check gate ran only
against `sentinel/domain`.
"""

from __future__ import annotations

from typing import Any, Iterable, Literal, Mapping, Protocol, Sequence, runtime_checkable

from sentinel.domain.events import DomainEvent
from sentinel.domain.incident import Incident
from sentinel.domain.primitives import (
    Address,
    ApprovalId,
    BatchId,
    Digest,
    IdempotencyKey,
    IncidentId,
    MessageId,
    TenantId,
    Timestamp,
)



# ── Supporting record types ──────────────────────────────────────────────────
#
# Deliberately dataclass-free `Protocol`-adjacent plain structures live in
# `sentinel.application.records` so ports stay import-light. These are the
# structural shapes ports exchange.

from sentinel.application.records import (  # noqa: E402  (grouped for readability)
    ApprovalRecord,
    EvidenceRecord,
    OutboxRecord,
)


# ── Infrastructure primitives ────────────────────────────────────────────────
from sentinel.application.execution.ports import ExecutionJournal, Inbox


__all__ = [
    "ApprovalRepository",
    "ContainmentRepository",
    "IncidentRepository",
    "LedgerRepository",
    "OutboxRepository",
    "UnitOfWork",
    "UnitOfWorkFactory",
]


@runtime_checkable
class IncidentRepository(Protocol):
    """The aggregate store. Scoped to one tenant by its unit of work."""

    def get(self, incident_id: IncidentId) -> Incident | None: ...

    def get_for_update(self, incident_id: IncidentId) -> Incident | None:
        """Load under a row lock, for a read-modify-write.

        Separate from `get` because taking a write lock on a read path is a cost
        the caller must opt into deliberately.
        """
        ...

    def add(self, incident: Incident) -> None:
        """Insert a new aggregate. Idempotent on (tenant, incident) by primary key."""
        ...

    def save(self, incident: Incident) -> None:
        """Persist a loaded aggregate with an optimistic version check.

        Raises `ConcurrencyConflict` when the stored version has moved.
        """
        ...

    def claim_execution(self, incident_id: IncidentId, *, epoch: int) -> None:
        """Take the execution fence at `epoch`. Raises `ExecutionFenceLost`."""
        ...

    def exists(self, incident_id: IncidentId) -> bool: ...


@runtime_checkable
class LedgerRepository(Protocol):
    """Append-only evidence chain, plus the sealed Merkle batches over it.

    One write path only. The predecessor had two -- one inside the incident
    aggregate's transaction and one standalone -- so no single point guaranteed
    chain integrity.
    """

    def append(
        self,
        *,
        incident_id: IncidentId,
        entry_hash: Digest,
        manifest: Mapping[str, Any],
    ) -> tuple[int, Digest]:
        """Append a leaf. Returns (sequence, chain_hash). Raises on a fork."""
        ...

    def head(self) -> Digest | None: ...

    def redact_evidence(
        self, *, incident_id: IncidentId, reason: str, actor: str, at: Timestamp
    ) -> bool:
        """Destroy the evidence BODY and leave an auditable tombstone.

        Declared here because `execution/pipeline.py` calls it. The ledger
        commitment and hash chain are untouched, so every inclusion proof still
        verifies and a redaction reports distinctly from tampering.
        """
        ...

    def withdraw_report(
        self, *, incident_id: IncidentId, reason: str, at: Timestamp
    ) -> bool:
        """Mark a report withdrawn, retaining its text.

        A withdrawn report is still evidence of what this system said at the
        time, and an audit trail that deletes its own mistakes is not one.
        """
        ...

    def store_evidence(self, record: EvidenceRecord) -> None: ...

    def get_evidence(self, incident_id: IncidentId) -> EvidenceRecord | None: ...

    def unsealed_entries(self, *, limit: int) -> Sequence[Mapping[str, Any]]:
        """Entries not yet in a batch, oldest first, bounded.

        Bounded because the predecessor's `seal()` loaded every unsealed entry
        for a tenant into memory and Merkle-hashed them in one pass.
        """
        ...

    def seal(
        self,
        *,
        batch_id: BatchId,
        merkle_root: Digest,
        sequences: Sequence[int],
        signature: str | None,
        signer: Address | None,
        manifest: Mapping[str, Any],
        at: Timestamp,
    ) -> None:
        """Claim the entries into a batch atomically. Raises if already sealed."""
        ...

    def store_report(self, *, incident_id: IncidentId, content: str, at: Timestamp) -> None: ...

    def get_report(self, incident_id: IncidentId) -> str | None: ...


@runtime_checkable
class ApprovalRepository(Protocol):
    """Human-approval proposals and their decisions.

    `claim_for_execution` exists because the predecessor's approval gate was a
    check-then-act with an external side effect between the check and the write,
    and no lock: two concurrent decisions both observed `pending` and both
    invoked the real-world remediation. It is the single most safety-critical
    write path in the product and it was the least protected.
    """

    def propose(self, records: Sequence[ApprovalRecord]) -> None: ...

    def get(self, approval_id: ApprovalId) -> ApprovalRecord | None: ...

    def claim_for_execution(self, approval_id: ApprovalId) -> ApprovalRecord | None:
        """Atomically move `pending` -> `executing` under a row lock.

        Returns the claimed record, or None if it was not pending. The external
        effect happens only for the caller that receives a record.
        """
        ...

    def record_outcome(
        self,
        *,
        approval_id: ApprovalId,
        state: str,
        decided_by: str,
        receipt: Mapping[str, Any],
        at: Timestamp,
    ) -> None: ...

    def release(self, approval_id: ApprovalId, *, error: str, at: Timestamp) -> None:
        """Return a claimed-but-failed approval to `pending` for a retry."""
        ...

    def pending_for_incident(self, incident_id: IncidentId) -> Sequence[ApprovalRecord]: ...

    def withdraw(
        self, approval_id: ApprovalId, *, reason: str, at: Timestamp
    ) -> bool:
        """Withdraw a pending approval as part of saga compensation.

        Declared because `execution/pipeline.py` calls it when a step that
        raised an approval is compensated. An approval left pending after its
        originating step was rolled back is an action an analyst can still
        authorise into a world that no longer exists.
        """
        ...


@runtime_checkable
class ContainmentRepository(Protocol):
    """Containment records for one tenant.

    Declared because `UnitOfWork.containments` is used on every activate and
    lift, and the unit-of-work protocol did not mention it -- so a second
    implementation would have omitted it and the containment commands would
    have failed at runtime rather than at type-check time.
    """

    def create(self, containment: Any) -> None: ...

    def revoke(
        self, containment_id: str, *, revoked_by: str, at: str
    ) -> bool: ...

    def active(self, *, now: str) -> tuple[Any, ...]: ...

    def all(self) -> tuple[Any, ...]: ...


class OutboxRepository(Protocol):
    """Durable intent for externally-visible effects.

    A real outbox: the intent is committed with the state change, and a SEPARATE
    dispatcher delivers it. The predecessor wrote the row and then delivered it
    in the same call stack, which is a table shaped like an outbox with none of
    the properties of one -- a worker killed mid-delivery stranded the row in
    `delivering` permanently, because nothing swept it.
    """

    def enqueue(
        self,
        *,
        incident_id: IncidentId,
        kind: str,
        payload: Mapping[str, Any],
        idempotency_key: IdempotencyKey,
        at: Timestamp,
    ) -> IdempotencyKey: ...

    def claim_batch(self, *, limit: int, now: Timestamp, lease_seconds: int) -> Sequence[OutboxRecord]:
        """Claim due records exclusively by moving a lease deadline forward.

        The lease deadline is absolute and monotonic, never a jittered interval.
        The predecessor's delivery queue claimed by pushing `next_at` forward by
        `random.uniform(0, ceiling)` -- full jitter, whose lower bound is zero --
        and documented the result as an exclusive claim. A draw near zero left
        the row immediately due again for a concurrent claimer.
        """
        ...

    def mark_delivered(
        self, *, record_id: MessageId, result: Mapping[str, Any], at: Timestamp
    ) -> None: ...

    def mark_failed(self, *, record_id: MessageId, error: str, at: Timestamp) -> str:
        """Record an attempt. Returns the resulting state: 'pending' or 'dead'."""
        ...

    def reap_expired_leases(self, *, now: Timestamp) -> int:
        """Return records whose deliverer died to `pending`. Returns the count."""
        ...

    def dead_letters(self, *, limit: int) -> Sequence[OutboxRecord]: ...

    def replay(self, record_id: MessageId, *, at: Timestamp) -> bool: ...


# Imported for the UnitOfWork protocol below. Same layer, so this
# crosses no architectural boundary: application/ports.py and
# application/execution/ports.py are peers, and execution/ports.py
# imports only from sentinel.domain, so there is no cycle.


@runtime_checkable
class UnitOfWork(Protocol):
    """One transaction. Owns the repositories that participate in it.

    Repositories are attributes rather than separately-injected objects because
    they must share the transaction; handing them out independently is how two
    "atomic" writes end up in two transactions.
    """

    # READ-ONLY PROPERTIES, NOT PLAIN ANNOTATIONS.
    #
    # A protocol data attribute is mutable, and a mutable member is INVARIANT:
    # the implementation's type would have to match EXACTLY, so
    # `SqlUnitOfWork.incidents: _IncidentRepository` could never satisfy
    # `incidents: IncidentRepository`. That was the whole reason every
    # `build_container` call site failed to type-check.
    #
    # Read-only is also the correct contract: nothing should reassign a unit of
    # work's repositories mid-transaction. An instance attribute set in
    # `__init__` satisfies a read-only property, so implementations are
    # unchanged.

    @property
    def incidents(self) -> IncidentRepository: ...

    @property
    def ledger(self) -> LedgerRepository: ...

    @property
    def approvals(self) -> ApprovalRepository: ...

    @property
    def outbox(self) -> OutboxRepository: ...

    @property
    def journal(self) -> ExecutionJournal:
        """The durable execution journal.

        Declared because the execution engine uses it on every step, and a
        protocol that omitted it described a narrower object than every caller
        requires -- anybody writing a second unit of work would implement the
        four repositories above and hit the shortfall at runtime.
        """
        ...

    @property
    def inbox(self) -> Inbox: ...

    @property
    def containments(self) -> ContainmentRepository:
        """Containment records, used on every activate and lift."""
        ...

    def __enter__(self) -> "UnitOfWork": ...
    def __exit__(
        self, exc_type: Any, exc: Any, tb: Any
    ) -> Literal[False]: ...
    def commit(self) -> None: ...
    def rollback(self) -> None: ...
    def collect(self, events: Iterable[DomainEvent]) -> None:
        """Stage domain events for publication at commit.

        Published inside the committing transaction, so an event describing a
        change that rolled back cannot exist.
        """
        ...


@runtime_checkable
class UnitOfWorkFactory(Protocol):
    """The ONLY way to obtain a transaction — and it requires a tenant."""

    def begin(self, tenant: TenantId) -> UnitOfWork: ...


