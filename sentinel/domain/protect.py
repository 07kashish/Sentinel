"""Pre-action protect decisions. Pure domain; no I/O.

WHY THIS EXISTS
---------------
Observe mode records what already happened. Protect mode answers *before* a
side effect: allow, warn, require_approval, or block.

`enforced` is not a synonym for "we returned block". It is true only when this
deployment is configured to treat the decision as a hard gate *and* the decision
is one that stops the action. Advisory deployments always return `enforced=false`,
even on block, so a caller cannot misread a recommendation as interception.

Unverified callers cannot reach severity >=85 through the trust cap (79). A
high-severity rule match on an unverified payload therefore cannot emit a
trust-capped `block` by arithmetic alone -- that was the predecessor's dead
`block` state. Here an unverified match whose *raw* policy severity would have
blocked fails closed to `require_approval` in advisory mode, and to `block` with
`enforced=true` when enforcement is on.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from sentinel.domain.primitives import Severity, TrustLevel

__all__ = [
    "ProtectDecision",
    "ProtectOutcome",
    "ProtectVerdict",
    "decide_protect",
]

_BLOCK_AT = 85
_APPROVAL_AT = 70
_WARN_AT = 40


class ProtectDecision(str, Enum):
    """What the gate concluded. Phase 6 widened this from four to eight.

    The four originals are unchanged in name, value and behaviour, so every
    existing rule, stored outcome and integration keeps working.
    """

    ALLOW = "allow"
    WARN = "warn"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"

    #: Proceed, but the caller must redact the response before the model sees
    #: it. A weaker control than BLOCK and a real one: the difference between an
    #: agent reading a customer table and reading it with the PII columns
    #: removed is the difference between an incident and a Tuesday.
    ALLOW_WITH_REDACTION = "allow_with_redaction"

    #: Stop until the HUMAN re-authenticates. Distinct from REQUIRE_APPROVAL,
    #: which asks a second person; this asks the same person to prove they are
    #: still there. An agent acting on a session nobody is watching is the case
    #: this exists for.
    STEP_UP_AUTH = "step_up_auth"

    #: Stop until a short-lived credential is issued for this specific action.
    #: The alternative to handing an agent a standing production credential and
    #: hoping, which is what most deployments do today.
    REQUIRE_JIT_CREDENTIAL = "require_jit_credential"

    #: Stop AND contain: this is not a request to refuse, it is an actor to
    #: remove. Separate from BLOCK because blocking one call and disabling the
    #: agent are different operator responses, and a gate that could only say
    #: "no" left the second to be noticed by hand.
    CONTAIN = "contain"

    @property
    def stops_action(self) -> bool:
        """Whether the caller must NOT proceed.

        INVERTED DELIBERATELY. This used to be a membership test against the
        decisions that stop; adding a decision and forgetting to list it there
        made it SILENTLY ALLOW -- a new enforcement outcome that enforces
        nothing, which is the worst possible direction for that bug.

        Now the allowlist is the decisions that permit the action, so anything
        added to this enum and not classified stops by default. Fail closed, in
        the one place where failing open is an authorisation bypass.

        `test_every_decision_is_explicitly_classified` makes the omission loud
        rather than merely safe.
        """
        return self not in _PROCEEDS

    @property
    def requires_human(self) -> bool:
        """Stops, and a PERSON must act before it can proceed.

        Distinguished from the JIT case, which a machine can satisfy. An
        operator sizing a rollout needs to know which refusals will page
        somebody and which will resolve themselves.
        """
        return self in {
            ProtectDecision.REQUIRE_APPROVAL,
            ProtectDecision.STEP_UP_AUTH,
            ProtectDecision.CONTAIN,
        }


#: The decisions under which the action MAY proceed. Everything else stops.
#:
#: `ALLOW_WITH_REDACTION` is here because the action happens -- the response is
#: transformed on its way back, not withheld. A caller that treated it as a stop
#: would break every workflow it was meant to keep working, which is how a
#: redaction control ends up switched off.
_PROCEEDS: frozenset[ProtectDecision] = frozenset({
    ProtectDecision.ALLOW,
    ProtectDecision.WARN,
    ProtectDecision.ALLOW_WITH_REDACTION,
})


@dataclass(frozen=True, slots=True)
class ProtectVerdict:
    """Inputs the protect gate needs from detection. Domain-shaped, no adapter types."""

    fired: bool
    severity: Severity
    detector_version: str
    matched_rules: tuple[str, ...] = ()
    description: str = ""


@dataclass(frozen=True, slots=True)
class ProtectOutcome:
    decision: ProtectDecision
    enforced: bool
    severity: int
    capped_severity: int
    detector_version: str
    matched_rules: tuple[str, ...]
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {
            "decision": self.decision.value,
            "enforced": self.enforced,
            "severity": self.severity,
            "capped_severity": self.capped_severity,
            "detector_version": self.detector_version,
            "matched_rules": list(self.matched_rules),
            "reason": self.reason,
        }


def decide_protect(
    *,
    verdict: ProtectVerdict,
    trust: TrustLevel,
    enforce: bool,
) -> ProtectOutcome:
    """Map a deterministic detection verdict to a protect decision.

    `enforce` is a deployment setting, not a caller claim. Callers cannot opt into
    `enforced=true`; only configuration can.
    """
    raw = verdict.severity
    capped = raw.capped_for(trust)
    version = verdict.detector_version
    rules = verdict.matched_rules

    if not verdict.fired or raw.value <= 0:
        return ProtectOutcome(
            decision=ProtectDecision.ALLOW,
            enforced=False,
            severity=raw.value,
            capped_severity=capped.value,
            detector_version=version,
            matched_rules=rules,
            reason="no policy rule matched",
        )

    if raw.value >= _BLOCK_AT and not trust.is_authoritative:
        if enforce:
            return ProtectOutcome(
                decision=ProtectDecision.BLOCK,
                enforced=True,
                severity=raw.value,
                capped_severity=capped.value,
                detector_version=version,
                matched_rules=rules,
                reason=(
                    "unverified high-risk action fails closed under enforcement; "
                    "verified identity is required before this action may proceed"
                ),
            )
        return ProtectOutcome(
            decision=ProtectDecision.REQUIRE_APPROVAL,
            enforced=False,
            severity=raw.value,
            capped_severity=capped.value,
            detector_version=version,
            matched_rules=rules,
            reason=(
                "raw severity would block but identity is unverified; "
                "advisory mode escalates to require_approval rather than claiming block"
            ),
        )

    score = capped.value
    if score >= _BLOCK_AT:
        decision = ProtectDecision.BLOCK
        reason = verdict.description or "policy severity requires block"
    elif score >= _APPROVAL_AT:
        decision = ProtectDecision.REQUIRE_APPROVAL
        reason = verdict.description or "policy severity requires human approval"
    elif score >= _WARN_AT:
        decision = ProtectDecision.WARN
        reason = verdict.description or "policy severity warrants a warning"
    else:
        decision = ProtectDecision.ALLOW
        reason = verdict.description or "policy matched below warn threshold"

    enforced = bool(enforce and decision.stops_action)
    return ProtectOutcome(
        decision=decision,
        enforced=enforced,
        severity=raw.value,
        capped_severity=capped.value,
        detector_version=version,
        matched_rules=rules,
        reason=reason,
    )