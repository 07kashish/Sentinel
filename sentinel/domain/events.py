"""Domain events. What happened, stated by the aggregate that made it happen.

WHY THIS EXISTS
---------------
The predecessor described itself as event-driven and had no events. It had a
point-to-point job queue with exactly one consumer, an "outbox" that was written
and read inside the same call stack, and a dead-letter table whose drain function
had zero callers. Nothing could observe a state change: no webhooks, no SIEM
export, no streaming dashboard (it polled), no audit stream.

Events here are:

  * **Facts, in the past tense.** `EvidenceStored`, not `StoreEvidence`. A
    command may be refused; an event has already happened and cannot be.
  * **Raised by the aggregate**, not by the handler, so an event cannot be
    emitted for a transition that did not occur -- the aggregate is the only
    thing that knows a transition succeeded.
  * **Versioned.** `event_version` is on the envelope from the first release,
    because adding it later means every stored event predates the schema that
    describes it.
  * **Collected, not published, by the aggregate.** Publication happens in the
    same transaction as the state change, through the outbox, so an event cannot
    describe a change that was rolled back.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from sentinel.domain.primitives import (
    Address,
    ApprovalId,
    BatchId,
    Digest,
    IncidentId,
    Priority,
    Severity,
    TenantId,
    Timestamp,
)

__all__ = [
    "ApprovalDecided",
    "ApprovalRequested",
    "AttestationRecorded",
    "BatchSealed",
    "DomainEvent",
    "EvidenceStored",
    "IncidentAdmitted",
    "IncidentClosedWithoutAction",
    "IncidentCompleted",
    "IncidentFailed",
    "IncidentStateChanged",
    "ReportStored",
]


@dataclass(frozen=True, slots=True)
class DomainEvent:
    """Envelope common to every domain event.

    `occurred_at` is supplied by the caller rather than read from a global clock,
    because a domain object that calls `datetime.now()` is not a pure function
    and cannot be tested without freezing time globally.
    """

    tenant_id: TenantId
    incident_id: IncidentId
    occurred_at: Timestamp
    event_version: int = field(default=1, kw_only=True)

    @property
    def event_type(self) -> str:
        """Stable wire name. Derived from the class, so it cannot drift from it."""
        return self.__class__.__name__

    def payload(self) -> Mapping[str, Any]:
        """Serialisable body. Overridden by subclasses that carry data."""
        return {}


@dataclass(frozen=True, slots=True)
class IncidentAdmitted(DomainEvent):
    severity: Severity = field(kw_only=True)
    priority: Priority = field(kw_only=True)
    source: str = field(kw_only=True)
    event_digest: Digest | None = field(default=None, kw_only=True)

    def payload(self) -> Mapping[str, Any]:
        return {
            "severity": self.severity.value,
            "priority": self.priority.value,
            "source": self.source,
            "event_digest": self.event_digest.value if self.event_digest else None,
        }


@dataclass(frozen=True, slots=True)
class IncidentStateChanged(DomainEvent):
    from_state: str = field(kw_only=True)
    to_state: str = field(kw_only=True)
    actor: str = field(kw_only=True)

    def payload(self) -> Mapping[str, Any]:
        return {"from": self.from_state, "to": self.to_state, "actor": self.actor}


@dataclass(frozen=True, slots=True)
class EvidenceStored(DomainEvent):
    evidence_digest: Digest = field(kw_only=True)
    ledger_sequence: int = field(kw_only=True)
    chain_hash: Digest = field(kw_only=True)

    def payload(self) -> Mapping[str, Any]:
        return {
            "evidence_digest": self.evidence_digest.value,
            "ledger_sequence": self.ledger_sequence,
            "chain_hash": self.chain_hash.value,
        }


@dataclass(frozen=True, slots=True)
class ReportStored(DomainEvent):
    report_bytes: int = field(kw_only=True)

    def payload(self) -> Mapping[str, Any]:
        return {"report_bytes": self.report_bytes}


@dataclass(frozen=True, slots=True)
class ApprovalRequested(DomainEvent):
    approval_id: ApprovalId = field(kw_only=True)
    action: str = field(kw_only=True)
    target: str = field(kw_only=True)

    def payload(self) -> Mapping[str, Any]:
        return {
            "approval_id": self.approval_id.value,
            "action": self.action,
            "target": self.target,
        }


@dataclass(frozen=True, slots=True)
class ApprovalDecided(DomainEvent):
    approval_id: ApprovalId = field(kw_only=True)
    decision: str = field(kw_only=True)
    decided_by: str = field(kw_only=True)
    executed: bool = field(kw_only=True)

    def payload(self) -> Mapping[str, Any]:
        return {
            "approval_id": self.approval_id.value,
            "decision": self.decision,
            "decided_by": self.decided_by,
            "executed": self.executed,
        }


@dataclass(frozen=True, slots=True)
class AttestationRecorded(DomainEvent):
    outcome: str = field(kw_only=True)
    anchored: bool = field(kw_only=True)
    transaction_hash: str | None = field(default=None, kw_only=True)
    subject: Address | None = field(default=None, kw_only=True)

    def payload(self) -> Mapping[str, Any]:
        return {
            "outcome": self.outcome,
            "anchored": self.anchored,
            "transaction_hash": self.transaction_hash,
            "subject": self.subject.value if self.subject else None,
        }


@dataclass(frozen=True, slots=True)
class IncidentCompleted(DomainEvent):
    attested: bool = field(kw_only=True)
    final_state: str = field(kw_only=True)

    def payload(self) -> Mapping[str, Any]:
        return {"attested": self.attested, "final_state": self.final_state}


@dataclass(frozen=True, slots=True)
class IncidentFailed(DomainEvent):
    reason: str = field(kw_only=True)

    def payload(self) -> Mapping[str, Any]:
        return {"reason": self.reason}


@dataclass(frozen=True, slots=True)
class IncidentClosedWithoutAction(DomainEvent):
    reason: str = field(kw_only=True)

    def payload(self) -> Mapping[str, Any]:
        return {"reason": self.reason}


@dataclass(frozen=True, slots=True)
class BatchSealed(DomainEvent):
    batch_id: BatchId = field(kw_only=True)
    merkle_root: Digest = field(kw_only=True)
    leaf_count: int = field(kw_only=True)
    signed: bool = field(kw_only=True)

    def payload(self) -> Mapping[str, Any]:
        return {
            "batch_id": self.batch_id.value,
            "merkle_root": self.merkle_root.value,
            "leaf_count": self.leaf_count,
            "signed": self.signed,
        }
