"""Exhaustive bounded model checking of the execution engine's retry semantics.

WHAT THIS IS, AND WHAT IT IS NOT
---------------------------------
Property-based tests SAMPLE the input space. Hypothesis is very good at finding
counterexamples, but a green run means "no counterexample was found in N tries",
not "none exists".

This is different. It enumerates EVERY reachable state of the engine under an
adversarial environment, up to a bound, and checks the invariants in all of them.
Within the bound the result is a proof by exhaustion: if a violating state were
reachable, it would be in the visited set.

The bound is the honest limit. This verifies "no sequence of at most K adversarial
events reaches a bad state", not "no sequence ever does". K is chosen so the
explored space covers every step of the plan several times over, which is where
the interesting interleavings live.

WHY IT CHECKS REAL CODE
-----------------------
The transition relation is NOT a hand-written model of the rules. It drives the
actual `Incident` aggregate, the actual `ExecutionPlan.next_step`, and the actual
`check_step_transition`. A model that re-implements the rules only proves the
re-implementation is self-consistent -- which is how a model checker gives false
confidence. Here, if the domain's edge table is wrong, this finds it.

THE ENVIRONMENT
---------------
At every state the adversary may choose any of:

  * SUCCEED              the step completes and settles
  * CRASH_AFTER_EFFECT   the external effect lands; nothing records it
  * CRASH_BEFORE_EFFECT  the worker dies before doing anything
  * FAIL_DETERMINISTIC   the step can never succeed; the saga must respond
  * OUTAGE               a transient failure of the external system
  * RECLAIM              a new worker takes the lease at a higher epoch

That set is chosen to include every way the real system can be interrupted, and
crucially includes the two that are indistinguishable from inside the process:
crashing just before and just after an irreversible effect.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Iterator

from sentinel.domain.attestation import AttestationDisposition, AttestationOutcome
from sentinel.domain.errors import (
    DomainRuleViolated,
    ExecutionFenceLost,
    IllegalTransition,
    MissingRequiredFact,
)
from sentinel.domain.execution import (
    ExecutionPlan,
    StepName,
    StepStatus,
    check_step_transition,
    step_idempotency_key,
)
from sentinel.domain.incident import Fence, Incident, IncidentState
from sentinel.domain.primitives import (
    Digest,
    IncidentId,
    Severity,
    TenantId,
    Timestamp,
    TrustLevel,
)

NOW = Timestamp(datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc))
TENANT = TenantId("acme")
INCIDENT = IncidentId("inc-model")
DIGEST = Digest("e" * 64)

__all__ = ["Event", "ModelState", "Violation", "check_model", "explore"]


class Event(str, Enum):
    """Everything the adversarial environment may do at any point."""

    SUCCEED = "succeed"
    CRASH_AFTER_EFFECT = "crash_after_effect"
    CRASH_BEFORE_EFFECT = "crash_before_effect"
    FAIL_DETERMINISTIC = "fail_deterministic"
    OUTAGE = "outage"
    RECLAIM = "reclaim"


@dataclass(frozen=True, slots=True)
class ModelState:
    """One reachable configuration. Frozen and hashable, so it can be visited."""

    incident_state: IncidentState
    #: (step name, status) pairs, sorted — the journal.
    journal: tuple[tuple[str, str], ...]
    epoch: int
    #: Distinct external effect keys applied so far. The exactly-once observable.
    effect_keys: tuple[str, ...]
    #: Which durable artifacts exist.
    has_evidence: bool
    has_report: bool
    attestation_outcome: str | None

    def journal_map(self) -> dict[str, str]:
        return dict(self.journal)


@dataclass(frozen=True, slots=True)
class Violation:
    """A reachable state that breaks an invariant, with the path that reached it."""

    invariant: str
    state: ModelState
    path: tuple[str, ...]

    def __str__(self) -> str:
        return (
            f"{self.invariant}\n"
            f"  reached by: {' -> '.join(self.path) or '(initial)'}\n"
            f"  state: {self.state.incident_state.value}, "
            f"journal={self.state.journal_map()}, "
            f"effects={list(self.state.effect_keys)}"
        )


# ── Invariants, checked in EVERY reachable state ────────────────────────────


def _invariants(state: ModelState) -> Iterator[str]:
    """Yield the name of every invariant this state violates."""

    # 1. An attested state must carry a real anchor. This is the defect the whole
    #    rewrite exists to prevent, stated as a reachability property.
    if state.incident_state.is_attested:
        if state.attestation_outcome != AttestationDisposition.ANCHORED.value:
            yield (
                "ATTESTED_WITHOUT_ANCHOR: an attested state was reached with "
                f"outcome {state.attestation_outcome!r}"
            )

    # 2. A transient outage may never reach a state that CLAIMS SUCCESS.
    #
    #    Stated over the completed states specifically, not over every terminal
    #    state. FAILED is a legitimate destination: a step can suffer an outage
    #    and then fail deterministically, and recording that loudly -- with a
    #    reason -- is correct. The guarantee is that an outage never masquerades
    #    as success, not that it never ends badly.
    #
    #    An earlier version of this invariant said "any terminal state", and the
    #    checker duly reported outage-then-deterministic-failure as a violation.
    #    That was the invariant being wrong, not the engine.
    if state.attestation_outcome == AttestationDisposition.UNAVAILABLE.value and (
        state.incident_state
        in {IncidentState.COMPLETED_ATTESTED, IncidentState.COMPLETED_UNATTESTED}
    ):
        yield (
            "TRANSIENT_OUTAGE_COMPLETED: a gateway outage reached the completed "
            f"state {state.incident_state.value}"
        )

    # 3. Exactly-once effect: at most one distinct key per step.
    if len(set(state.effect_keys)) > 1:
        yield f"DUPLICATE_EFFECT: {sorted(set(state.effect_keys))}"

    # 4. No artifact loss: a state asserting evidence must have it.
    asserts_evidence = state.incident_state in {
        IncidentState.EVIDENCE_STORED,
        IncidentState.REPORTED,
        IncidentState.AWAITING_APPROVAL,
        IncidentState.ATTESTED,
        IncidentState.ATTESTATION_UNAVAILABLE,
        IncidentState.COMPLETED_ATTESTED,
        IncidentState.COMPLETED_UNATTESTED,
    }
    if asserts_evidence and not state.has_evidence:
        yield (
            f"EVIDENCE_LOSS: state {state.incident_state.value} asserts evidence "
            "but none exists"
        )

    asserts_report = state.incident_state in {
        IncidentState.REPORTED,
        IncidentState.AWAITING_APPROVAL,
        IncidentState.ATTESTED,
        IncidentState.ATTESTATION_UNAVAILABLE,
        IncidentState.COMPLETED_ATTESTED,
        IncidentState.COMPLETED_UNATTESTED,
    }
    if asserts_report and not state.has_report:
        yield (
            f"REPORT_LOSS: state {state.incident_state.value} asserts a report "
            "but none exists"
        )

    # 5. Nothing is unwound once the pivot may have fired. A compensated step
    #    alongside an entered pivot means the saga promised an undo it could not
    #    deliver to the external system.
    journal = state.journal_map()
    pivot_entered = journal.get("attest") in {
        StepStatus.RUNNING.value,
        StepStatus.COMPLETED.value,
        StepStatus.COMPENSATING.value,
        StepStatus.COMPENSATED.value,
    }
    if pivot_entered and any(
        status == StepStatus.COMPENSATED.value for status in journal.values()
    ):
        yield (
            "UNWOUND_PAST_PIVOT: a step was compensated after the pivot had been "
            f"entered; journal={journal}"
        )

    # 6. No step is settled twice with a conflicting status, and every status is
    #    one the step machine can actually hold.
    for name, status in state.journal:
        if status not in {s.value for s in StepStatus}:
            yield f"IMPOSSIBLE_STEP_STATUS: {name}={status}"

    # 7. A completed-attested incident must have settled the whole plan.
    if state.incident_state is IncidentState.COMPLETED_ATTESTED:
        settled = {n for n, s in state.journal if s == StepStatus.COMPLETED.value}
        if "attest" not in settled or "complete" not in settled:
            yield (
                "COMPLETED_WITHOUT_SETTLING: reached completed_attested with "
                f"journal {state.journal_map()}"
            )


# ── The transition relation, driving REAL domain objects ────────────────────


@dataclass
class _Sim:
    """A simulated run. Wraps the real aggregate so the rules under test are real."""

    incident: Incident
    journal: dict[str, StepStatus] = field(default_factory=dict)
    epoch: int = 1
    effects: list[str] = field(default_factory=list)
    has_evidence: bool = False
    has_report: bool = False

    def snapshot(self) -> ModelState:
        return ModelState(
            incident_state=self.incident.state,
            journal=tuple(sorted((k, v.value) for k, v in self.journal.items())),
            epoch=self.epoch,
            effect_keys=tuple(sorted(set(self.effects))),
            has_evidence=self.has_evidence,
            has_report=self.has_report,
            attestation_outcome=self.incident.fact("attestation_outcome"),
        )


def _fresh(plan: ExecutionPlan) -> _Sim:
    incident = Incident.admit(
        tenant_id=TENANT,
        incident_id=INCIDENT,
        severity=Severity(90),
        trust_level=TrustLevel.VERIFIED,
        source="model",
        now=NOW,
        facts={"detector_version": "model-1", "signer_address": "0x" + "ab" * 20},
    )
    incident.acquire_execution(1)
    return _Sim(incident=incident)


def _clone(sim: _Sim) -> _Sim:
    """Deep-copy so each branch of the search explores independently."""
    incident = Incident.rehydrate(
        tenant_id=sim.incident.tenant_id,
        incident_id=sim.incident.incident_id,
        state=sim.incident.state,
        facts=dict(sim.incident.facts),
        version=sim.incident.version,
        execution_epoch=sim.incident.execution_epoch,
    )
    return _Sim(
        incident=incident,
        journal=dict(sim.journal),
        epoch=sim.epoch,
        effects=list(sim.effects),
        has_evidence=sim.has_evidence,
        has_report=sim.has_report,
    )


def _settled(sim: _Sim) -> set[StepName]:
    return {
        StepName(name)
        for name, status in sim.journal.items()
        if status in {StepStatus.COMPLETED, StepStatus.COMPENSATED}
    }


def _apply(sim: _Sim, plan: ExecutionPlan, event: Event) -> _Sim | None:
    """Apply one adversarial event. Returns the successor, or None if inapplicable.

    Every lifecycle change goes through the REAL aggregate, so an illegal
    transition raises here exactly as it would in production -- and a raise is
    treated as "the engine refused", not as a model error.
    """
    nxt = _clone(sim)

    if event is Event.RECLAIM:
        nxt.epoch += 1
        try:
            nxt.incident.acquire_execution(nxt.epoch)
        except ExecutionFenceLost:
            return None
        return nxt

    if nxt.incident.is_terminal:
        return None

    step = plan.next_step(_settled(nxt))
    if step is None:
        return None
    name = step.name.value
    fence = Fence.worker(nxt.epoch)

    # Entering the step is itself a durable, checked transition.
    try:
        check_step_transition(nxt.journal.get(name), StepStatus.RUNNING)
    except IllegalTransition:
        return None
    nxt.journal[name] = StepStatus.RUNNING

    if event is Event.CRASH_BEFORE_EFFECT:
        # The row stays RUNNING; nothing else happened.
        return nxt

    if event is Event.CRASH_AFTER_EFFECT:
        if name != "attest":
            return nxt  # only the pivot has an external effect
        nxt.effects.append(
            step_idempotency_key(tenant=TENANT, incident=INCIDENT, step=step.name).value
        )
        return nxt  # journal stays RUNNING: the effect is unrecorded

    if event is Event.OUTAGE:
        if name != "attest":
            return None
        nxt.effects.append(
            step_idempotency_key(tenant=TENANT, incident=INCIDENT, step=step.name).value
        )
        try:
            nxt.incident.record_attestation(
                AttestationOutcome(AttestationDisposition.UNAVAILABLE, "modelled outage"),
                fence=fence,
                now=NOW,
            )
        except (IllegalTransition, MissingRequiredFact, ExecutionFenceLost):
            return None
        return nxt  # deliberately NOT settled

    if event is Event.FAIL_DETERMINISTIC:
        try:
            check_step_transition(nxt.journal[name], StepStatus.FAILED)
        except IllegalTransition:
            return None
        nxt.journal[name] = StepStatus.FAILED
        completed = [
            StepName(n) for n, s in nxt.journal.items() if s is StepStatus.COMPLETED
        ]
        entered = [StepName(n) for n, s in nxt.journal.items() if s.has_run]
        if not plan.has_passed_pivot(entered):
            for undo in plan.compensation_order(completed):
                try:
                    check_step_transition(
                        nxt.journal[undo.value], StepStatus.COMPENSATING
                    )
                    check_step_transition(StepStatus.COMPENSATING, StepStatus.COMPENSATED)
                except IllegalTransition:
                    return None
                nxt.journal[undo.value] = StepStatus.COMPENSATED
                if undo.value == "evidence":
                    nxt.has_evidence = False
                if undo.value == "report":
                    nxt.has_report = False
        try:
            nxt.incident.fail(reason=f"{name} failed", fence=fence, now=NOW)
        except (IllegalTransition, MissingRequiredFact, ExecutionFenceLost):
            return None
        return nxt

    # SUCCEED
    try:
        _advance(nxt, name, fence)
    except (IllegalTransition, MissingRequiredFact, ExecutionFenceLost, DomainRuleViolated):
        return None
    try:
        check_step_transition(nxt.journal[name], StepStatus.COMPLETED)
    except IllegalTransition:
        return None
    nxt.journal[name] = StepStatus.COMPLETED
    return nxt


def _advance(sim: _Sim, name: str, fence: Fence) -> None:
    """The real lifecycle effect of each step succeeding."""
    incident = sim.incident
    if name == "validate":
        incident.advance(IncidentState.VALIDATED, fence=fence, now=NOW)
    elif name == "identity":
        incident.advance(
            IncidentState.IDENTITY_CHECKED,
            fence=fence,
            now=NOW,
            trust_level=incident.trust_level.value,
        )
    elif name == "replay":
        incident.advance(IncidentState.REPLAY_CHECKED, fence=fence, now=NOW)
    elif name == "policy":
        incident.advance(
            IncidentState.POLICY_EVALUATED, fence=fence, now=NOW, detector_version="m"
        )
    elif name == "detect":
        incident.advance(IncidentState.DETECTED, fence=fence, now=NOW)
    elif name == "evidence":
        incident.record_evidence(
            digest=DIGEST,
            uri="sentinel://e",
            ledger_sequence=1,
            chain_hash=DIGEST,
            fence=fence,
            now=NOW,
        )
        sim.has_evidence = True
    elif name == "report":
        incident.record_report(report_bytes=10, fence=fence, now=NOW)
        sim.has_report = True
    elif name == "approvals":
        pass  # nothing proposed: a real, journaled outcome with no transition
    elif name == "attest":
        sim.effects.append(
            step_idempotency_key(
                tenant=TENANT, incident=INCIDENT, step=StepName("attest")
            ).value
        )
        incident.record_attestation(
            AttestationOutcome(
                AttestationDisposition.ANCHORED, "modelled", transaction_hash="0xabc"
            ),
            fence=fence,
            now=NOW,
        )
    elif name == "complete":
        incident.complete(fence=fence, now=NOW)


# ── The search ───────────────────────────────────────────────────────────────


def explore(
    plan: ExecutionPlan, *, max_depth: int, events: tuple[Event, ...] | None = None
) -> tuple[set[ModelState], list[Violation]]:
    """Breadth-first over every reachable state up to `max_depth` events.

    Returns the visited set and every violation found. Exhaustive within the
    bound: a violating state that is reachable in `max_depth` steps WILL appear.
    """
    chosen = events or tuple(Event)
    start = _fresh(plan)
    visited: set[ModelState] = {start.snapshot()}
    violations: list[Violation] = []
    frontier: list[tuple[_Sim, tuple[str, ...]]] = [(start, ())]

    for _depth in range(max_depth):
        nxt_frontier: list[tuple[_Sim, tuple[str, ...]]] = []
        for sim, path in frontier:
            for event in chosen:
                successor = _apply(sim, plan, event)
                if successor is None:
                    continue
                snapshot = successor.snapshot()
                trail = path + (event.value,)
                for broken in _invariants(snapshot):
                    violations.append(Violation(broken, snapshot, trail))
                if snapshot in visited:
                    continue
                visited.add(snapshot)
                nxt_frontier.append((successor, trail))
        frontier = nxt_frontier
        if not frontier:
            break

    return visited, violations


def check_model(plan: ExecutionPlan, *, max_depth: int = 12) -> tuple[int, list[Violation]]:
    visited, violations = explore(plan, max_depth=max_depth)
    return len(visited), violations
