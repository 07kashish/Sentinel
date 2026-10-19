"""Detonate a skill and ask BOTH questions about what came back.

WHY THIS LAYER EXISTS AT ALL
-----------------------------
The detonation subsystem was complete and unreachable. `Detonator`, `assess`,
`ContainerDetonator` and `TracingContainerDetonator` all had tests and no
production caller -- the same defect `test_components_are_reachable` was
written for after Phase 4 shipped four unwired sections. A sandbox nothing
calls is not a sandbox, and a behaviour catalogue nothing consults is
documentation.

So this is the seam that calls them, and it is registered in the reachability
rule so it cannot quietly become decorative again.

THE TWO QUESTIONS ARE GENUINELY DIFFERENT
------------------------------------------
`assess` asks: does this recording match anything in the catalogue of
dangerous behaviours? Canary exfiltration, credential file reads, persistence,
undeclared network. That is a judgement about the skill.

`compare_trace_to_scope` asks: did the process stay inside what its
authorization actually permitted? That is a judgement about THIS run against
THIS approval, and it is the only one here that does not depend on the caller
having been honest about what it was going to do.

A skill can pass the first and fail the second. Reading one file inside no
catalogue entry is not a dangerous behaviour; reading it when the
authorization named a different directory is a scope violation. Conversely a
skill can fail the first and pass the second, which is the case worth catching
early: authorized to do something, and the something is dangerous.

WHY A NON-TRACING BOUNDARY GETS UNOBSERVED RATHER THAN A PASS
--------------------------------------------------------------
`ContainerDetonator` reports an exit code and two output streams. Nothing in
that can contradict a declaration, so the scope question was never asked --
and `UNOBSERVED` says exactly that. The tempting shape is to omit the scope
verdict when it cannot be produced; an absent verdict reads as a clean one,
and every caller would treat it as such.

WHAT THIS DOES NOT DO
---------------------
It does not admit or reject anything. It produces a `ScopedDetonation`, and
`safe_to_admit` on that type is derived rather than settable -- so an
admission path cannot be handed a pre-decided answer. Nor does it enforce
mid-flight: stopping a syscall as it happens is a seccomp or LSM problem and a
different piece of software.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from sentinel.domain.detonation import (
    DetonationObservation,
    ScopedDetonation,
    assess,
)
from sentinel.domain.observed_binding import (
    AuthorizedScope,
    ObservedVerdict,
)

__all__ = ["SkillDetonationService"]


@dataclass(frozen=True, slots=True)
class SkillDetonationService:
    """Runs a skill in an isolation boundary and judges what came back.

    Frozen and holding only the detonator: it has no state to keep between
    runs, and a service whose members can be reassigned is a global with
    extra steps.
    """

    detonator: Any

    def review(
        self,
        *,
        skill_id: str,
        package: bytes,
        canaries: Mapping[str, str],
        scope: AuthorizedScope,
        declared_destinations: Iterable[str] = (),
    ) -> ScopedDetonation:
        """Detonate once, then judge behaviour AND scope.

        Raises `DetonationUnavailable` when no boundary is configured. That
        propagates deliberately: a caller that received a clean-looking result
        because nothing ran is the exact failure `RefusingDetonator` exists to
        prevent, so this layer does not catch it and substitute an empty
        recording.
        """
        observation, scope_verdict = self._detonate(
            skill_id=skill_id, package=package, canaries=canaries, scope=scope
        )
        verdict = assess(
            observation,
            canaries=canaries,
            declared_destinations=declared_destinations,
        )
        return ScopedDetonation(
            observation=observation, verdict=verdict, scope=scope_verdict
        )

    def _detonate(
        self,
        *,
        skill_id: str,
        package: bytes,
        canaries: Mapping[str, str],
        scope: AuthorizedScope,
    ) -> tuple[DetonationObservation, ObservedVerdict]:
        """Ask for a scope verdict; take UNOBSERVED when the boundary cannot.

        Capability-detected on the METHOD rather than with `isinstance` against
        the protocol. `ScopeObservingDetonator` is runtime-checkable, and a
        runtime-checkable Protocol check passes on the presence of the
        attribute name alone -- so it would agree with a test double that set
        `detonate_observing_scope = None`, and then this would fail on the
        call instead of falling back. `callable` is the property actually
        being relied on.
        """
        observe = getattr(self.detonator, "detonate_observing_scope", None)
        if callable(observe):
            return observe(
                skill_id=skill_id,
                package=package,
                canaries=canaries,
                scope=scope,
            )
        observation = self.detonator.detonate(
            skill_id=skill_id, package=package, canaries=canaries
        )
        return observation, scope.unobserved()
