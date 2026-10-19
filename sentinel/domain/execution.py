"""The execution model: durable steps, saga shape, and step-level legality.

WHY THE PREVIOUS ENGINE WAS REPLACED
------------------------------------
Its predecessor decided "has this step already run?" from the INCIDENT STATE. A
stage was skipped when the lifecycle had moved past the state that stage
produces. That is a good approximation and it is not a proof, because it
conflates two different questions:

    "what is true about this incident?"     -- lifecycle state
    "what work has this system performed?"  -- execution history

They are not the same question, and three defects live in the gap:

  * A step that performs work but produces NO transition is invisible to it. The
    approvals step proposes nothing when there is nothing to propose, so the
    lifecycle cannot distinguish "approvals ran and found none" from "approvals
    never ran".
  * A step that produced an EXTERNAL effect and then failed before its transition
    committed looks un-run. Re-running it repeats the effect.
  * A step's result cannot be memoised, so a resumed run must recompute anything
    it needs rather than replaying what was decided the first time.

Here the **journal** is the authority on execution and the **lifecycle** remains
the authority on truth. Both commit in one transaction, so they cannot disagree,
and a step is executed if and only if the journal says it has not been.

SAGA SHAPE, AND WHY IT HAS A PIVOT
-----------------------------------
This pipeline has one genuinely irreversible action: publishing an external
attestation. An anchor cannot be un-published. No compensation exists, and
pretending one does is worse than admitting it.

So the plan is validated against the classical saga shape (Garcia-Molina &
Salem): a sequence of **compensatable** steps, then at most one **pivot**, then
only **retriable** steps.

    compensatable* · pivot? · retriable*

  * Before the pivot, failure unwinds: every completed step is compensated in
    reverse order.
  * The pivot is the point of no return. Once it commits, the saga can only go
    forward.
  * After the pivot, steps must be retried until they succeed. Compensating them
    is not an option because the pivot cannot be undone.

`ExecutionPlan` REFUSES to construct if the ordering is violated, so a plan that
places a compensatable step after the pivot -- which would promise an unwind that
cannot happen -- is not expressible.

PURITY
------
Nothing here performs I/O, reads a clock, or imports outside `sentinel.domain`.
Every rule is a pure function of its arguments and is tested without a fixture.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence

from sentinel.domain.errors import DomainRuleViolated, IllegalTransition
from sentinel.domain.primitives import IdempotencyKey, IncidentId, TenantId

__all__ = [
    "ExecutionPlan",
    "PlanShapeViolation",
    "StepDefinition",
    "StepKind",
    "StepName",
    "StepRecord",
    "StepStatus",
    "check_step_transition",
    "step_idempotency_key",
]


class PlanShapeViolation(DomainRuleViolated):
    """A plan promises an unwind it could not perform, or a step it cannot order."""


@dataclass(frozen=True, slots=True, order=True)
class StepName:
    """Identifies one step within a plan. Part of every idempotency key."""

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str):
            raise DomainRuleViolated(
                f"step name must be a string, got {type(self.value).__name__}"
            )
        cleaned = self.value.strip()
        if not cleaned or not cleaned.replace("_", "").replace("-", "").isalnum():
            raise DomainRuleViolated(
                f"step name must be non-empty alphanumeric with _ or -, got {self.value!r}"
            )
        object.__setattr__(self, "value", cleaned)

    def __str__(self) -> str:
        return self.value


class StepKind(str, Enum):
    """A step's position in the saga, which decides how failure is handled."""

    #: Reversible. On an unrecoverable failure this step is compensated.
    COMPENSATABLE = "compensatable"

    #: The point of no return. Its effect is externally visible and permanent.
    #: At most one per plan; everything before it is compensatable, everything
    #: after it is retriable.
    PIVOT = "pivot"

    #: After the pivot. Must eventually succeed; compensation is not available
    #: because the pivot it would be unwinding cannot itself be undone.
    RETRIABLE = "retriable"


class StepStatus(str, Enum):
    """Where one step is in its own lifecycle.

    A step has a state machine of its own, separate from the incident's. It is
    small, and making it explicit is what stops "started but not finished" being
    represented by the absence of a row -- which is indistinguishable from "never
    started", and is exactly how an external effect gets performed twice.
    """

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    COMPENSATING = "compensating"
    COMPENSATED = "compensated"

    @property
    def is_terminal(self) -> bool:
        return self in {StepStatus.COMPLETED, StepStatus.COMPENSATED}

    @property
    def has_run(self) -> bool:
        """True once the step's effect may have reached the outside world.

        `RUNNING` counts. A step that started and did not report back may have
        succeeded externally, so the engine must reconcile rather than re-execute
        blindly. Treating RUNNING as "not run" is the classic duplicate-effect
        bug.
        """
        return self in {
            StepStatus.RUNNING,
            StepStatus.COMPLETED,
            StepStatus.COMPENSATING,
            StepStatus.COMPENSATED,
        }


_STEP_EDGES: Mapping[StepStatus, frozenset[StepStatus]] = MappingProxyType(
    {
        StepStatus.PENDING: frozenset({StepStatus.RUNNING}),
        # RUNNING -> RUNNING is legal and load-bearing: a worker that crashed
        # mid-step leaves the row RUNNING, and the reclaiming worker re-enters it
        # at a NEW epoch. The epoch is what distinguishes the two, not the status.
        StepStatus.RUNNING: frozenset(
            {StepStatus.RUNNING, StepStatus.COMPLETED, StepStatus.FAILED}
        ),
        StepStatus.FAILED: frozenset({StepStatus.RUNNING, StepStatus.COMPENSATING}),
        StepStatus.COMPLETED: frozenset({StepStatus.COMPENSATING}),
        StepStatus.COMPENSATING: frozenset({StepStatus.COMPENSATED, StepStatus.COMPENSATING}),
        StepStatus.COMPENSATED: frozenset(),
    }
)


def check_step_transition(current: StepStatus | None, to: StepStatus) -> None:
    """Raise unless this step transition is legal. Pure, total, testable."""
    if current is None:
        if to is not StepStatus.RUNNING:
            raise IllegalTransition(
                f"a step must first be entered as {StepStatus.RUNNING.value}, not {to.value}"
            )
        return
    if to not in _STEP_EDGES[current]:
        legal = ", ".join(sorted(s.value for s in _STEP_EDGES[current])) or "(none)"
        raise IllegalTransition(
            f"illegal step transition {current.value} -> {to.value}. Legal: {legal}."
        )


def step_idempotency_key(
    *, tenant: TenantId, incident: IncidentId, step: StepName
) -> IdempotencyKey:
    """The stable key identifying one step's effect, forever.

    DETERMINISTIC and epoch-free. That is the whole point: two different workers
    retrying the same step at different epochs must present the SAME key to an
    external system, or the deduplication the key exists to provide does not
    happen. Including the epoch here would make every retry a fresh effect --
    which is precisely the defect the predecessor shipped, where a key was
    generated, persisted, returned, and never sent.
    """
    return IdempotencyKey(f"idem-{tenant}-{incident}-{step}")


@dataclass(frozen=True, slots=True)
class StepRecord:
    """One journal entry: what this step did, and whether it may be re-entered."""

    step: StepName
    status: StepStatus
    epoch: int
    attempts: int = 0
    result: Mapping[str, Any] = field(default_factory=dict)
    error: str | None = None

    @property
    def is_settled(self) -> bool:
        """True when the engine must NOT execute this step again.

        The single question the engine asks of the journal. A settled step's
        recorded result is replayed; nothing is recomputed and no effect is
        repeated.
        """
        return self.status in {StepStatus.COMPLETED, StepStatus.COMPENSATED}


@dataclass(frozen=True, slots=True)
class StepDefinition:
    """A step's identity and saga role. Behaviour is supplied by the engine.

    Deliberately data-only: the plan can be validated, ordered and reasoned about
    without constructing any handler, which is what lets the shape rules below be
    property-tested over thousands of generated plans in milliseconds.
    """

    name: StepName
    kind: StepKind
    #: A step that produces a durable artifact must say so. The engine refuses to
    #: continue past a step whose artifact its state claims exists but which
    #: cannot be reloaded.
    produces_artifact: bool = False
    #: Compensatable steps must name their compensation. Enforced below.
    compensation: StepName | None = None

    def __post_init__(self) -> None:
        if self.kind is StepKind.COMPENSATABLE and self.compensation is None:
            raise PlanShapeViolation(
                f"step {self.name} is compensatable but names no compensation. A "
                "step that cannot be undone must be declared PIVOT or RETRIABLE, "
                "so the plan describes what will actually happen on failure."
            )
        if self.kind is not StepKind.COMPENSATABLE and self.compensation is not None:
            raise PlanShapeViolation(
                f"step {self.name} is {self.kind.value} but names a compensation. "
                "Only a compensatable step may be unwound; a pivot cannot be "
                "undone and a retriable step must go forward."
            )


class ExecutionPlan:
    """An ordered, shape-validated sequence of steps.

    Immutable. Constructed once and shared; there is nothing to mutate, so it is
    safe to hold on the engine.
    """

    __slots__ = ("_steps", "_by_name", "_pivot_index")

    def __init__(self, steps: Sequence[StepDefinition]) -> None:
        if not steps:
            raise PlanShapeViolation("an execution plan must contain at least one step")

        names = [s.name for s in steps]
        if len(set(names)) != len(names):
            duplicated = sorted({n.value for n in names if names.count(n) > 1})
            raise PlanShapeViolation(
                f"duplicate step names in plan: {', '.join(duplicated)}. Step names "
                "are idempotency keys; two steps sharing one would share an effect."
            )

        pivots = [i for i, s in enumerate(steps) if s.kind is StepKind.PIVOT]
        if len(pivots) > 1:
            raise PlanShapeViolation(
                f"a plan may contain at most one pivot; found {len(pivots)} "
                f"({', '.join(steps[i].name.value for i in pivots)}). Two points of "
                "no return cannot both be the point of no return."
            )
        pivot_index = pivots[0] if pivots else None

        for index, step in enumerate(steps):
            if pivot_index is None:
                if step.kind is StepKind.RETRIABLE:
                    raise PlanShapeViolation(
                        f"step {step.name} is retriable but the plan has no pivot. "
                        "Retriable means 'past the point of no return'; with no "
                        "pivot there is nothing it could be past."
                    )
                continue
            if index < pivot_index and step.kind is not StepKind.COMPENSATABLE:
                raise PlanShapeViolation(
                    f"step {step.name} precedes the pivot but is {step.kind.value}. "
                    "Everything before the pivot must be compensatable, or an "
                    "unwind would stall on a step it cannot undo."
                )
            if index > pivot_index and step.kind is not StepKind.RETRIABLE:
                raise PlanShapeViolation(
                    f"step {step.name} follows the pivot but is {step.kind.value}. "
                    "Nothing after the pivot can be compensated, because the pivot "
                    "itself cannot be undone."
                )

        self._steps: tuple[StepDefinition, ...] = tuple(steps)
        self._by_name: Mapping[StepName, StepDefinition] = MappingProxyType(
            {s.name: s for s in steps}
        )
        self._pivot_index = pivot_index

    # ── Introspection ────────────────────────────────────────────────────────

    @property
    def steps(self) -> tuple[StepDefinition, ...]:
        return self._steps

    @property
    def names(self) -> tuple[StepName, ...]:
        return tuple(s.name for s in self._steps)

    @property
    def pivot(self) -> StepDefinition | None:
        return None if self._pivot_index is None else self._steps[self._pivot_index]

    def get(self, name: StepName) -> StepDefinition:
        try:
            return self._by_name[name]
        except KeyError:
            raise PlanShapeViolation(f"no step named {name} in this plan") from None

    def index_of(self, name: StepName) -> int:
        return self.names.index(name)

    # ── Saga decisions ───────────────────────────────────────────────────────

    def has_passed_pivot(self, entered: Iterable[StepName]) -> bool:
        """True once the point of no return may have been crossed.

        Takes the steps that have RUN -- entered, not merely completed -- and
        that distinction is the whole guarantee.

        A pivot step that was ENTERED and did not report back may have applied
        its irreversible effect: that is precisely the crash-after-effect case,
        where the anchor lands and the process dies before recording it. Its
        journal row reads RUNNING, not COMPLETED.

        Keying this on COMPLETED alone let the saga unwind after an anchor had
        already been published -- compensating work whose irreversible pivot had
        happened, while promising an undo that could never reach the external
        system. The exhaustive model checker found it; no example test had a
        sequence long enough to.

        The safe reading is pessimistic: if the pivot may have fired, the saga
        may only go forward.
        """
        pivot = self.pivot
        return pivot is not None and pivot.name in set(entered)

    def compensation_order(self, completed: Iterable[StepName]) -> tuple[StepName, ...]:
        """Completed compensatable steps, in REVERSE plan order.

        Reverse because a compensation may depend on state a later step consumed;
        unwinding forwards would compensate a dependency before its dependent.

        Steps at or after the pivot are excluded: they have no compensation, and
        `has_passed_pivot` should have prevented this being called at all.
        """
        done = set(completed)
        unwind = [
            step.name
            for step in self._steps
            if step.kind is StepKind.COMPENSATABLE and step.name in done
        ]
        return tuple(reversed(unwind))

    def next_step(self, settled: Iterable[StepName]) -> StepDefinition | None:
        """The first step whose journal entry is not settled.

        Strictly ordered: the engine never skips ahead of an unsettled step, so a
        step can only run once every step before it has a recorded outcome. That
        is what makes "resume" deterministic -- from any journal, exactly one step
        is next.
        """
        done = set(settled)
        for step in self._steps:
            if step.name not in done:
                return step
        return None

    def artifact_steps(self) -> tuple[StepName, ...]:
        return tuple(s.name for s in self._steps if s.produces_artifact)
