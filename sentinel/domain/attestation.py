"""Attestation outcomes: the three genuinely different things an attempt means.

WHY THIS IS A SEPARATE MODULE
-----------------------------
The predecessor had ONE string, `"Skipped"`, covering two of these three cases:
an agent with no verified identity (permanent -- a retry can never help) and an
unreachable gateway (transient -- a retry very likely helps). Both satisfied the
lifecycle's "attestation_status is non-empty" requirement, so both sent the
incident to COMPLETED with `is_anchored=false`.

A transient RPC outage therefore produced an incident indistinguishable from a
successfully attested one, in a product whose entire proposition is
non-repudiable attestation, at the one moment a buyer needs it.

Separating the vocabulary from the aggregate keeps `incident.py` about the
lifecycle and makes this the one place the distinction is defined. The mapping
from disposition to destination state is total and lives on the outcome, so a
caller never chooses where an attestation sends an incident.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from sentinel.domain.errors import MissingRequiredFact
from sentinel.domain.primitives import Address

__all__ = ["AttestationDisposition", "AttestationOutcome"]


class AttestationDisposition(str, Enum):
    """The three genuinely different things an attestation attempt can mean.

    The predecessor had one string, `"Skipped"`, covering the second and third.
    That conflation is the whole defect: one is a permanent property of the
    incident, the other is a property of the network at one instant.

    Defined above `_REQUIRED_FACTS` because those predicates compare against
    these values -- the fact requirements and the outcome vocabulary are one
    idea and must not be able to drift apart.
    """

    #: An external anchor exists and can be cited.
    ANCHORED = "anchored"

    #: Deterministically impossible for this incident -- no signature-recovered
    #: identity, or no attestation capability configured. A retry cannot help.
    NOT_ANCHORABLE = "not_anchorable"

    #: The gateway could not be reached. A retry may well succeed.
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class AttestationOutcome:
    """The result of one attestation attempt, and where it sends the incident."""

    disposition: AttestationDisposition
    detail: str
    transaction_hash: str | None = None
    subject: Address | None = None

    def __post_init__(self) -> None:
        if not self.detail.strip():
            raise MissingRequiredFact(
                "an attestation outcome must carry a human-readable detail; an "
                "operator reading 'unattested' with no reason cannot act on it"
            )
        if self.disposition is AttestationDisposition.ANCHORED and not self.transaction_hash:
            raise MissingRequiredFact(
                "an ANCHORED outcome must carry the transaction hash that proves it"
            )

    @property
    def is_anchored(self) -> bool:
        return self.disposition is AttestationDisposition.ANCHORED

    @property
    def next_state_name(self) -> str:
        """Where this outcome sends the incident. The mapping is TOTAL.

        Returned as a state name rather than an `IncidentState` so this module
        stays free of the lifecycle -- the aggregate resolves it. A caller cannot
        ask for a completed state while holding an UNAVAILABLE outcome, because
        it does not choose the destination at all.
        """
        return {
            AttestationDisposition.ANCHORED: "attested",
            AttestationDisposition.NOT_ANCHORABLE: "completed_unattested",
            AttestationDisposition.UNAVAILABLE: "attestation_unavailable",
        }[self.disposition]

    def as_facts(self) -> dict[str, Any]:
        return {
            "attestation_outcome": self.disposition.value,
            "attestation_detail": self.detail,
            "transaction_hash": self.transaction_hash,
            "attestation_subject": self.subject.value if self.subject else None,
        }
