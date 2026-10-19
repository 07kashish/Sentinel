"""Value objects. The vocabulary the rest of the system is written in.

WHY THIS EXISTS
---------------
The predecessor architecture passed `tenant_id`, `incident_id`, `digest` and
`address` as bare `str` and `severity` as a bare `int`. Three separate defects in
its recorded history were argument transpositions that were type-correct:
`dlq.enqueue(tenant_id, incident_id, "pipeline", str(e))` against a signature of
`(tenant_id, kind, payload, max_attempts)` put the incident id in `kind` and an
error message in `max_attempts`, making every subsequent retry comparison
meaningless.

The response at the time was a convention -- keyword-only arguments. A convention
is checked by reviewers. These types are checked by the type system: `TenantId`
and `IncidentId` are distinct types, so transposing them is not a subtle bug that
survives to production, it is an error at the call site.

Every type here is frozen, validated on construction, and total: if an instance
exists it is valid, so no consumer needs a defensive check. Construction is the
only place a value can be wrong, which is the only place that has to be right.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Final

__all__ = [
    "Address",
    "AgentId",
    "ApprovalId",
    "BatchId",
    "Digest",
    "IdempotencyKey",
    "IncidentId",
    "MessageId",
    "Priority",
    "Severity",
    "TenantId",
    "Timestamp",
    "TrustLevel",
    "ValueError_",
]

# A domain-level construction failure. Deliberately distinct from builtin
# ValueError so the application layer can map it to a 400 without also mapping
# every incidental library ValueError to a 400 -- the exact conflation that made
# the predecessor's retry taxonomy classify transient JSON decode failures as
# permanent.
class InvalidValue(ValueError):
    """A value object was constructed from input that cannot be valid."""


ValueError_ = InvalidValue  # re-export under a name that cannot shadow builtins


_IDENT_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HEX64_RE: Final = re.compile(r"^[0-9a-f]{64}$")
_ADDRESS_RE: Final = re.compile(r"^0x[0-9a-fA-F]{40}$")


def _identifier(raw: object, field: str) -> str:
    if not isinstance(raw, str):
        raise InvalidValue(f"{field} must be a string, got {type(raw).__name__}")
    value = raw.strip()
    if not _IDENT_RE.match(value):
        raise InvalidValue(
            f"{field} must be 1-128 chars of [A-Za-z0-9._:-] starting alphanumeric, "
            f"got {raw!r}"
        )
    return value


@dataclass(frozen=True, slots=True, order=True)
class TenantId:
    """Identifies one customer. The isolation boundary of the whole system."""

    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _identifier(self.value, "tenant_id"))

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class IncidentId:
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _identifier(self.value, "incident_id"))

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class ApprovalId:
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _identifier(self.value, "approval_id"))

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class BatchId:
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _identifier(self.value, "batch_id"))

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class MessageId:
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _identifier(self.value, "message_id"))

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class AgentId:
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _identifier(self.value, "agent_id"))

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class Digest:
    """A SHA-256 digest, lower-case hex.

    Normalised on construction so two digests that denote the same bytes compare
    equal regardless of the case the producer emitted. The predecessor compared
    digests as raw strings in several places, which is correct only while every
    producer agrees on case.
    """

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str):
            raise InvalidValue(f"digest must be a string, got {type(self.value).__name__}")
        normalised = self.value.strip().lower()
        if not _HEX64_RE.match(normalised):
            raise InvalidValue("digest must be 64 lower-case hex characters (SHA-256)")
        object.__setattr__(self, "value", normalised)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class Address:
    """An secp256k1 account address recovered from a signature.

    Stored checksum-insensitively (lower case) because it is used as an identity
    key. It is NEVER constructed from user-asserted input in this system: the
    only sanctioned source is signature recovery, which is enforced by the
    application layer, not here -- a value object can guarantee shape, not
    provenance.
    """

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str):
            raise InvalidValue(f"address must be a string, got {type(self.value).__name__}")
        normalised = self.value.strip().lower()
        if not _ADDRESS_RE.match(normalised):
            raise InvalidValue("address must be 0x followed by 40 hex characters")
        object.__setattr__(self, "value", normalised)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class IdempotencyKey:
    """Deduplicates an externally-visible side effect.

    This type exists because the predecessor generated an idempotency key,
    persisted it, returned it, and never passed it to the gateway -- the
    parameter existed on `publish_attestation` and the single call site omitted
    it. Making the key a required, typed argument of the outbound port means the
    omission is not expressible.
    """

    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _identifier(self.value, "idempotency_key"))

    def __str__(self) -> str:
        return self.value


class TrustLevel(str, Enum):
    """How much of what an event asserts about itself may be believed."""

    VERIFIED = "verified"
    UNSIGNED = "unsigned"
    INVALID = "invalid"

    @property
    def is_authoritative(self) -> bool:
        """Only a verified event's self-reported claims may drive severity."""
        return self is TrustLevel.VERIFIED


class Priority(str, Enum):
    """Derived from severity. Never set directly, never argued down by input."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# The severity above which an unverified caller's claims are not honoured, and
# the band boundaries. These live together, in the domain, because the
# predecessor kept PROTECT_BLOCK_SEVERITY (85) in the HTTP layer and
# UNVERIFIED_SEVERITY_CAP (79) in the detection layer, and nothing noticed for a
# release that an unsigned event could therefore never reach the block band --
# the strongest of four documented states was arithmetically unreachable.
UNVERIFIED_SEVERITY_CAP: Final = 79
_BANDS: Final = ((85, Priority.CRITICAL), (70, Priority.HIGH), (40, Priority.MEDIUM))


@dataclass(frozen=True, slots=True, order=True)
class Severity:
    """A 0-100 risk score. Zero means "policy found nothing", not "unknown"."""

    value: int

    def __post_init__(self) -> None:
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            raise InvalidValue(f"severity must be an int, got {type(self.value).__name__}")
        if not 0 <= self.value <= 100:
            raise InvalidValue(f"severity must be within 0..100, got {self.value}")

    @property
    def priority(self) -> Priority:
        """The ONE severity -> priority mapping in the system.

        The predecessor had two: `priority_from_severity` in the HTTP layer and
        `priority_for_severity` in the detection layer, the latter documented as
        "the ONLY place this mapping lives". Making it a property of the value
        removes the possibility of a second one existing anywhere.
        """
        for threshold, priority in _BANDS:
            if self.value >= threshold:
                return priority
        return Priority.LOW

    @property
    def is_actionable(self) -> bool:
        return self.value > 0

    def capped_for(self, trust: TrustLevel) -> "Severity":
        """Severity as it may be recorded given how much the source is trusted.

        Applied in the domain rather than at one HTTP route, because in the
        predecessor the cap was enforced on `/events/ingest` and bypassed by the
        five other routes that reached the same pipeline -- so an `ingest`-role
        key could post a client-supplied severity of 100 and manufacture a
        CRITICAL incident.
        """
        if trust.is_authoritative or self.value <= UNVERIFIED_SEVERITY_CAP:
            return self
        return Severity(UNVERIFIED_SEVERITY_CAP)


@dataclass(frozen=True, slots=True, order=True)
class Timestamp:
    """An instant, always timezone-aware and always UTC.

    Naive datetimes are rejected rather than assumed to be UTC. The predecessor
    stored ISO strings produced by `datetime.now(timezone.utc).isoformat()` in
    some places and `time.time()` floats in others, and compared them across
    replicas whose clocks were only as aligned as NTP made them.
    """

    value: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.value, datetime):
            raise InvalidValue(f"timestamp must be a datetime, got {type(self.value).__name__}")
        if self.value.tzinfo is None:
            raise InvalidValue("timestamp must be timezone-aware; naive datetimes are ambiguous")
        object.__setattr__(self, "value", self.value.astimezone(timezone.utc))

    @classmethod
    def parse(cls, raw: str) -> "Timestamp":
        try:
            parsed = datetime.fromisoformat(raw)
        except (TypeError, ValueError) as exc:
            raise InvalidValue(f"not an ISO-8601 timestamp: {raw!r}") from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return cls(parsed)

    def isoformat(self) -> str:
        return self.value.isoformat()

    def __str__(self) -> str:
        return self.isoformat()
