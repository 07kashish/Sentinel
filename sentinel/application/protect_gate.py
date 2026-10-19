"""Synchronous protect gate for agents that call Sentinel before a side effect.

WHY THIS IS NOT JUST THE HTTP ROUTE
-----------------------------------
`POST /v1/protect/evaluate` is the network seam. Agents that already hold a
wired container (same process, SDK, or worker) need a callable that:

  1. evaluates the deterministic policy,
  2. returns an honest ProtectOutcome, and
  3. when enforcement is configured, *refuses to run* the side effect.

`enforced=true` without preventing the callback would be marketing theater.
`run_if_allowed` only invokes `action` after `require_allowed` returns; if the
decision is enforced, it raises `ProtectDenied` and never calls `action`.

LIMITATIONS (keep these in the remediation matrix)
--------------------------------------------------
This is still not an inline network interceptor. A process that never calls the
gate, or that catches ProtectDenied and continues, is not stopped on the wire.
Sentinel can only enforce where it is asked.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping, TypeVar

from sentinel.application.ports import DetectionPolicy
from sentinel.domain.errors import DomainRuleViolated
from sentinel.domain.primitives import TrustLevel
from sentinel.domain.policy_as_code import PolicyEffect, PolicyVersion
from sentinel.domain.protect import (
    ProtectDecision,
    ProtectOutcome,
    ProtectVerdict,
    decide_protect,
)

__all__ = ["ProtectDenied", "ProtectGate"]

T = TypeVar("T")


class ProtectDenied(DomainRuleViolated):
    """An enforced protect decision refused the side effect.

    Carries the outcome so callers can audit why without re-running the policy.
    """

    def __init__(self, outcome: ProtectOutcome) -> None:
        self.outcome = outcome
        super().__init__(
            f"protect denied: decision={outcome.decision.value} "
            f"enforced={outcome.enforced}: {outcome.reason}"
        )


class ProtectGate:
    """Evaluate protect policy and optionally block a synchronous side effect."""

    __slots__ = ("_policy", "_enforce", "_tenant_policy")

    def __init__(self, *, policy: DetectionPolicy, enforce: bool,
                 tenant_policy: Callable[[str], PolicyVersion | None] | None = None) -> None:
        self._policy = policy
        self._enforce = bool(enforce)
        self._tenant_policy = tenant_policy

    @property
    def enforce(self) -> bool:
        return self._enforce

    def evaluate(
        self, *, payload: Mapping[str, Any], trust: TrustLevel, tenant_id: str = "",
        parameters: Mapping[str, Any] | None = None,
    ) -> ProtectOutcome:
        # Parameter values are transient input to the local deterministic gate.
        # They are never added to the audit payload or the returned reason.
        evaluation_payload = dict(payload)
        if parameters is not None:
            evaluation_payload["arguments"] = dict(parameters)
        verdict = self._policy.evaluate(payload=evaluation_payload, trust=trust)
        outcome = decide_protect(
            verdict=ProtectVerdict(
                fired=verdict.fired,
                severity=verdict.severity,
                detector_version=verdict.detector_version,
                matched_rules=tuple(verdict.matched_rules),
                description=("matched policy rules: " + ", ".join(verdict.matched_rules))
                            if verdict.fired else "no policy rule matched",
            ),
            trust=trust,
            enforce=self._enforce,
        )
        if not tenant_id or self._tenant_policy is None:
            return outcome
        active = self._tenant_policy(tenant_id)
        if active is None:
            return outcome
        # Preserve the policy language's first-match semantics. A tenant rule
        # can only tighten the deterministic gate, never override its deny.
        rule = next((r for r in active.rules if r.matches(
            action=str(payload.get("action") or payload.get("tool") or ""),
            resource=str(payload.get("resource") or ""),
            destination=str(payload.get("destination") or ""), severity=outcome.severity,
        )), None)
        if rule is None:
            return outcome
        decisions = {PolicyEffect.ALLOW: ProtectDecision.ALLOW,
                     PolicyEffect.WARN: ProtectDecision.WARN,
                     PolicyEffect.REQUIRE_APPROVAL: ProtectDecision.REQUIRE_APPROVAL,
                     PolicyEffect.BLOCK: ProtectDecision.BLOCK}
        rank = {ProtectDecision.ALLOW: 0, ProtectDecision.WARN: 1,
                ProtectDecision.REQUIRE_APPROVAL: 2, ProtectDecision.BLOCK: 3}
        decision = decisions[rule.effect]
        if rank.get(outcome.decision, 4) >= rank[decision]:
            return outcome
        return ProtectOutcome(
            decision=decision, enforced=self._enforce and decision.stops_action,
            severity=outcome.severity, capped_severity=outcome.capped_severity,
            detector_version=outcome.detector_version,
            matched_rules=(*outcome.matched_rules, f"tenant:{active.version}:{rule.name}"),
            reason=f"tenant policy version {active.version}, rule {rule.name}",
        )

    @property
    def policy_digest(self) -> str:
        digest = getattr(self._policy, "digest", None)
        if not callable(digest):
            raise DomainRuleViolated("enforcement policy has no content digest")
        return str(digest())

    def require_allowed(
        self,
        *,
        payload: Mapping[str, Any],
        trust: TrustLevel,
        approved: bool = False,
        tenant_id: str = "",
        parameters: Mapping[str, Any] | None = None,
    ) -> ProtectOutcome:
        """Return the outcome, or raise ProtectDenied when enforcement stops it.

        Advisory mode (enforce=False) never raises here: enforced is always false,
        so blocking labels remain recommendations.

        `approved` is the human decision. A `require_approval` verdict asks for that, so when the caller
        presents an authorization a `DECIDE_APPROVAL` holder activated, that
        verdict is SATISFIED rather than enforced -- otherwise an approved
        action re-evaluates to "requires approval" at execution time and can
        never run under enforcement, which is the defect this parameter closes.
        Step-up authentication requires proof of reauthentication, not approval.
        An approval satisfies nothing stronger: `block` and `contain` are the
        policy saying no regardless of who asks, and they still refuse.
        """
        outcome = self.evaluate(payload=payload, trust=trust, tenant_id=tenant_id, parameters=parameters)
        if outcome.enforced and approved and outcome.decision in _SATISFIED_BY_APPROVAL:
            return ProtectOutcome(
                decision=outcome.decision,
                enforced=False,
                severity=outcome.severity,
                capped_severity=outcome.capped_severity,
                detector_version=outcome.detector_version,
                matched_rules=outcome.matched_rules,
                reason=f"{outcome.reason}; satisfied by a recorded approval",
            )
        if outcome.enforced:
            raise ProtectDenied(outcome)
        return outcome

    def run_if_allowed(
        self,
        *,
        payload: Mapping[str, Any],
        trust: TrustLevel,
        action: Callable[[], T],
        approved: bool = False,
        tenant_id: str = "",
        parameters: Mapping[str, Any] | None = None,
    ) -> tuple[ProtectOutcome, T]:
        """Run `action` only when the gate does not enforce a stop.

        If ProtectDenied is raised, `action` is never invoked. That is the
        contract the integration tests pin.
        """
        outcome = self.require_allowed(payload=payload, trust=trust, approved=approved, tenant_id=tenant_id, parameters=parameters)
        return outcome, action()


#: The verdicts a human approval answers. Everything else stops regardless.
_SATISFIED_BY_APPROVAL = frozenset(
    {ProtectDecision.REQUIRE_APPROVAL}
)
