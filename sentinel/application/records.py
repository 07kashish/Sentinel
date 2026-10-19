"""Data structures exchanged across port boundaries.

These are neither domain entities nor infrastructure rows: they are the shapes
adapters and use cases agree on. Keeping them here rather than in `ports.py`
keeps the port module readable, and keeping them out of `sentinel.domain` keeps
the domain free of anything that exists only because there is an adapter.

All frozen. A record that crosses a boundary and is then mutated by the receiver
is a defect the sender cannot see.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from sentinel.domain.primitives import (
    Address,
    ApprovalId,
    Digest,
    IdempotencyKey,
    IncidentId,
    MessageId,
    Severity,
    TenantId,
    Timestamp,
    TrustLevel,
)

__all__ = [
    "ApprovalRecord",
    "DetectionVerdict",
    "EvidenceRecord",
    "ModelAdvice",
    "OutboxRecord",
    "QueuedWork",
    "VerifiedIdentity",
]


@dataclass(frozen=True, slots=True)
class VerifiedIdentity:
    """The result of signature verification.

    `address` is populated ONLY when `trust is VERIFIED`. This is asserted at
    construction rather than left to callers, because the predecessor's
    attestation path had to defend itself against a fabricated identity at the
    point of use (`is_address_shaped(subject_address)`) — a check that belongs
    where the value is made, not where it is read.
    """

    trust: TrustLevel
    reason: str
    address: Address | None = None

    def __post_init__(self) -> None:
        if self.trust is TrustLevel.VERIFIED and self.address is None:
            raise ValueError("a VERIFIED identity must carry the recovered address")
        if self.trust is not TrustLevel.VERIFIED and self.address is not None:
            raise ValueError(
                "only a VERIFIED identity may carry an address; an unverified "
                "address is an invented one"
            )


@dataclass(frozen=True, slots=True)
class DetectionVerdict:
    """What the deterministic policy concluded about one event.

    `severity` here is the RAW policy severity. The trust cap is applied by the
    domain (`Severity.capped_for`), not by the detector, so the cap cannot be
    bypassed by adding a caller that skips the detector.

    Confidence is honest for a hard policy: matched rules → 1.0, no match → 0.0.
    `low_confidence_region` is computed via `compute_low_confidence_region` — True
    for hard 0/1 labels (outside any soft calibrated mid-band).
    """

    fired: bool
    severity: Severity
    incident_type: str
    description: str
    matched_rules: tuple[str, ...] = ()
    detector_version: str = ""
    signals: Mapping[str, Any] = field(default_factory=dict)
    #: Hard label confidence: 1.0 when fired, 0.0 otherwise. Not a soft probability.
    confidence: float = 0.0
    #: Computed: True when confidence is not a soft calibrated mid-band score.
    low_confidence_region: bool = True


@dataclass(frozen=True, slots=True)
class ModelAdvice:
    """The LLM's non-authoritative second opinion.

    `available` is explicit rather than inferred from empty fields, so "the model
    was down" and "the model had nothing to add" are distinguishable in the
    evidence record. Both are legitimate and they mean different things to an
    auditor.
    """

    available: bool
    detail: str
    model_receipt: str = "unknown"
    suggested_priority: str | None = None
    escalation: bool = False
    recommendations: tuple[str, ...] = ()
    reasoning: str = ""

    @classmethod
    def unavailable(cls, reason: str) -> "ModelAdvice":
        return cls(
            available=False,
            detail=f"second opinion unavailable ({reason}); deterministic policy applied",
        )


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """The canonical evidence body plus its integrity digest."""

    incident_id: IncidentId
    uri: str
    digest: Digest
    content: Mapping[str, Any]
    created_at: Timestamp
    redacted_at: Timestamp | None = None
    redaction_reason: str | None = None

    @property
    def is_redacted(self) -> bool:
        return self.redacted_at is not None


@dataclass(frozen=True, slots=True)
class ApprovalRecord:
    """A proposed real-world action awaiting, or having received, a human decision."""

    approval_id: ApprovalId
    incident_id: IncidentId
    action: str
    target: str
    state: str
    proposed_at: Timestamp
    decided_by: str | None = None
    decided_at: Timestamp | None = None
    receipt: Mapping[str, Any] = field(default_factory=dict)
    #: When this request stops being executable. Empty means no expiry.
    #:
    #: An approval without a window is a standing authorization to act on
    #: production. Approved three months after it was raised -- against an estate
    #: that has changed, over an incident long since closed -- it still fires, and
    #: the analyst clicking approve is agreeing to a situation that no longer
    #: exists. The window is what makes it a decision rather than a permanent
    #: grant.
    expires_at: Timestamp | None = None
    #: The section-32 request context: risk factors, execution graph session,
    #: business impact, recommended decision. Read whole by a human.
    context: Mapping[str, Any] = field(default_factory=dict)

    @property
    def is_pending(self) -> bool:
        return self.state == "pending"

    def is_expired(self, now: Timestamp) -> bool:
        """Whether the window has closed.

        Compared on parsed timestamps rather than strings. `Timestamp` orders
        correctly by construction, so this does not inherit the assumption that
        every stored value is UTC with a `Z` suffix.
        """
        return self.expires_at is not None and self.expires_at <= now


@dataclass(frozen=True, slots=True)
class OutboxRecord:
    """A durable intent to perform an externally-visible effect."""

    record_id: MessageId
    tenant_id: TenantId
    incident_id: IncidentId
    kind: str
    payload: Mapping[str, Any]
    idempotency_key: IdempotencyKey
    attempts: int
    max_attempts: int
    state: str
    last_error: str | None = None


@dataclass(frozen=True, slots=True)
class QueuedWork:
    """One claimed unit of pipeline work, carrying its fencing token.

    `lease_epoch` is what makes a stale worker's writes refusable rather than
    merely unlikely. It is threaded from here into `Fence.worker(...)` and every
    repository write.
    """

    work_id: MessageId
    tenant_id: TenantId
    incident_id: IncidentId
    payload: Mapping[str, Any]
    attempts: int
    lease_epoch: int
    claimed_by: str
