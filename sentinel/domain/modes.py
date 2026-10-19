"""Operating modes: what this deployment is currently allowed to do.

    OBSERVE / MONITOR / WARN / PROTECT / LOCKDOWN
    Transitions must be deliberate and audited.
    Do not allow ambiguous mode names.

WHY A MODE IS NOT THE SAME THING AS A DECISION
------------------------------------------------
`ProtectDecision` already has ALLOW, WARN and BLOCK. Those are answers about one
tool call. A mode is a statement about the whole deployment: how much authority
the product has been granted over this estate today.

Keeping them separate is what makes the pair meaningful. A policy can decide
BLOCK while the deployment is in MONITOR, and the correct outcome is a recorded
decision and an unblocked call -- the policy was right and the operator has not
yet handed over enforcement. Collapsing the two would mean the only way to stop
blocking is to weaken the rules, which is how a rollout ends with a detector
nobody trusts.

THE ORDERING IS THE SAFETY PROPERTY
-------------------------------------
Modes are ranked, and `permits` is derived from the rank rather than written out
per mode. A table of independent booleans is where "PROTECT blocks but MONITOR
also blocks" comes from: two people edit two rows months apart and nothing
notices, because no test asserts a relationship that was never expressed.

AMBIGUOUS NAMES ARE REFUSED, WHICH THE SPECIFICATION ASKS FOR DIRECTLY
------------------------------------------------------------------------
`parse_mode` accepts the five names and nothing else -- not "on", not "enabled",
not "enforce", not "true". Each of those has been used in this industry to mean
both "watch" and "block", and a deployment that guesses will guess wrong in
whichever direction is worse. An unrecognised mode is a configuration error at
startup, not a default at runtime.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Final, Mapping

from sentinel.domain.errors import DomainRuleViolated

__all__ = [
    "AmbiguousMode",
    "ModeTransition",
    "ProtectionMode",
    "parse_mode",
]


class AmbiguousMode(DomainRuleViolated):
    """A mode name that is not one of the five. Refused, never defaulted."""

    is_retryable = False


class ProtectionMode(str, Enum):
    """How much authority this deployment has been given.

    Ordered from least to most intervention. The order is load-bearing -- see
    `rank` below -- so inserting a mode means deciding where it sits, which is
    the decision that matters.
    """

    #: Record events. Raise nothing, notify nobody. The mode a deployment sits
    #: in while an operator is still deciding whether the data is trustworthy.
    OBSERVE = "observe"
    #: Record and raise incidents. Still no notification and no enforcement.
    MONITOR = "monitor"
    #: Raise, and notify. The agent's call still proceeds.
    WARN = "warn"
    #: Enforce: a policy decision to block actually blocks.
    PROTECT = "protect"
    #: Enforce, and additionally refuse anything not explicitly permitted.
    #: Reserved for an active incident. Deliberately painful.
    LOCKDOWN = "lockdown"

    @property
    def rank(self) -> int:
        return _RANKS[self]

    @property
    def raises_incidents(self) -> bool:
        return self.rank >= ProtectionMode.MONITOR.rank

    @property
    def notifies(self) -> bool:
        return self.rank >= ProtectionMode.WARN.rank

    @property
    def enforces(self) -> bool:
        """Whether a BLOCK decision actually stops the call.

        The single question the enforcement path asks. Derived from the rank so
        it cannot disagree with the ordering above.
        """
        return self.rank >= ProtectionMode.PROTECT.rank

    @property
    def denies_by_default(self) -> bool:
        """LOCKDOWN only: refuse what is not explicitly permitted.

        Separate from `enforces` because the difference between them is the
        difference between "stop what we judged bad" and "stop everything we
        have not judged". The second is an outage by design, chosen during an
        incident, and it must never be reachable by nudging a threshold.
        """
        return self is ProtectionMode.LOCKDOWN


_RANKS: Final[Mapping[ProtectionMode, int]] = MappingProxyType(
    {
        ProtectionMode.OBSERVE: 0,
        ProtectionMode.MONITOR: 1,
        ProtectionMode.WARN: 2,
        ProtectionMode.PROTECT: 3,
        ProtectionMode.LOCKDOWN: 4,
    }
)

#: Names that mean different things at different vendors and are therefore
#: refused with an explanation rather than mapped to a guess.
#:
#: Every one of these has been used to mean both "watch" and "block". A
#: deployment that guesses will eventually guess in the direction that either
#: leaves an estate unprotected or takes it down.
_AMBIGUOUS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "on": "does it observe or enforce?",
        "off": "does it stop enforcing, or stop recording entirely?",
        "enabled": "does it observe or enforce?",
        "disabled": "does it stop enforcing, or stop recording entirely?",
        "true": "does it observe or enforce?",
        "false": "does it stop enforcing, or stop recording entirely?",
        "enforce": "PROTECT or LOCKDOWN?",
        "block": "PROTECT or LOCKDOWN?",
        "audit": "OBSERVE or MONITOR?",
        "passive": "OBSERVE or MONITOR?",
        "active": "WARN, PROTECT or LOCKDOWN?",
        "strict": "PROTECT or LOCKDOWN?",
    }
)


def parse_mode(raw: str) -> ProtectionMode:
    """Resolve a configured mode name, refusing anything ambiguous.

    Refusal is at startup, where a human is present to fix it, rather than a
    default at runtime where nobody is.
    """
    text = (raw or "").strip().lower()
    if not text:
        raise AmbiguousMode(
            "no protection mode configured; set SENTINEL_PROTECTION_MODE to one "
            "of: " + ", ".join(m.value for m in ProtectionMode)
        )
    for mode in ProtectionMode:
        if text == mode.value:
            return mode
    if text in _AMBIGUOUS:
        raise AmbiguousMode(
            f"protection mode {raw!r} is ambiguous: {_AMBIGUOUS[text]} "
            f"Use one of: " + ", ".join(m.value for m in ProtectionMode)
        )
    raise AmbiguousMode(
        f"unknown protection mode {raw!r}; use one of: "
        + ", ".join(m.value for m in ProtectionMode)
    )


@dataclass(frozen=True, slots=True)
class ModeTransition:
    """A deliberate, attributed change of operating mode.

    The specification asks that transitions be deliberate and audited, so this
    records who and why rather than only what. A mode that changed with no name
    against it is the same problem as an unattributed kill switch: an estate
    stopped being enforced and nobody owns the decision.
    """

    tenant_id: str
    from_mode: ProtectionMode
    to_mode: ProtectionMode
    changed_by: str
    changed_at: str
    reason: str = ""

    def __post_init__(self) -> None:
        if not self.changed_by.strip():
            raise DomainRuleViolated(
                "a mode transition must record who made it; an estate that "
                "stopped being enforced with no name against it has no owner"
            )
        if self.from_mode is self.to_mode:
            raise DomainRuleViolated(
                f"mode is already {self.to_mode.value}; a transition that changes "
                f"nothing would be an audit row implying something happened"
            )
        # A drop in enforcement is the direction that matters, so it must be
        # explained. Raising enforcement is allowed without one: the failure
        # mode of an unexplained tightening is an outage somebody notices
        # immediately, while an unexplained loosening is silent.
        if self.to_mode.rank < self.from_mode.rank and not self.reason.strip():
            raise DomainRuleViolated(
                f"lowering protection from {self.from_mode.value} to "
                f"{self.to_mode.value} requires a reason"
            )

    @property
    def is_reduction(self) -> bool:
        return self.to_mode.rank < self.from_mode.rank

    def as_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "from_mode": self.from_mode.value,
            "to_mode": self.to_mode.value,
            "changed_by": self.changed_by,
            "changed_at": self.changed_at,
            "reason": self.reason,
            "is_reduction": self.is_reduction,
        }
