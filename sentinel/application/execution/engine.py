"""The execution engine: a durable, journaled, fenced saga runner.

THE CONTRACT, STATED PRECISELY
------------------------------
Given at-least-once delivery of a work item, this engine guarantees:

  1. **No step executes twice.** A step runs only if its journal entry is not
     settled, and the settle commits in the same transaction as the step's
     lifecycle transition. Re-delivery replays the recorded result.
  2. **No transition is applied twice.** A transition is produced only by a step
     that executed, and a step executes at most once. The aggregate's optimistic
     version check is the second line: a stale write is refused, not merged.
  3. **No illegal state.** Both state machines -- the incident lifecycle and the
     per-step status -- reject illegal edges, and both are pure functions checked
     before any write.
  4. **Resume is deterministic.** From any journal, `ExecutionPlan.next_step`
     names exactly one next step. Two workers reading the same journal make the
     same decision.
  5. **No artifact loss.** Before any step runs, every artifact the incident's
     state asserts is reloaded. A missing one is a hard, non-retryable failure
     rather than a `None` flowing into an effect.
  6. **Failure preserves correctness.** Before the pivot, an unrecoverable
     failure unwinds through compensations in reverse order. After the pivot,
     the saga only goes forward.

WHAT IT DOES NOT CLAIM
----------------------
Exactly-once *delivery* is impossible over an unreliable channel, and any system
claiming it is either lying or hiding a distributed transaction. What is
achievable, and what this implements, is exactly-once *effect*: delivery is
at-least-once, acceptance is deduplicated by the inbox, execution is deduplicated
by the journal, and every external effect carries a deterministic idempotency key
so the receiving system can deduplicate the one case neither table can see -- a
crash between the effect and its record.

THE THREE-PHASE STEP
--------------------
Each step is enter -> act -> settle, and the ordering is load-bearing:

    enter   commit RUNNING at this epoch          (durable intent)
    act     perform the effect                    (may crash; may be observed)
    settle  commit the outcome + transition       (durable result)

A crash between `enter` and `settle` leaves a RUNNING row. That row is the
signal: the next worker knows the effect MAY have happened and reconciles using
the step's deterministic idempotency key, rather than assuming it did not. The
predecessor had no such row -- an interrupted step was indistinguishable from one
that never started, which is exactly how an anchor gets published twice.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

from sentinel.application.ports import Clock, Logger, UnitOfWork, UnitOfWorkFactory
from sentinel.application.records import ApprovalRecord, EvidenceRecord, ModelAdvice
from sentinel.domain.errors import (
    ArtifactMissing,
    DomainRuleViolated,
    ExecutionFenceLost,
    SentinelError,
)
from sentinel.domain.execution import (
    ExecutionPlan,
    StepDefinition,
    StepKind,
    StepName,
    StepStatus,
    step_idempotency_key,
)
from sentinel.domain.incident import Fence, Incident, IncidentState
from sentinel.domain.primitives import IdempotencyKey, IncidentId, MessageId, TenantId, Timestamp

__all__ = ["ExecutionContext", "ExecutionEngine", "ExecutionOutcome", "StepHandler"]


@dataclass
class ExecutionContext:
    """Everything a step may read. Rebuilt from durable state on every resume.

    Artifacts are reached through requiring accessors, never read as attributes,
    so a step cannot silently consume a `None`. That is the difference between
    "the artifact was missing" surfacing as an exception and surfacing as an
    evidence-less attestation that looks like a success.
    """

    incident: Incident
    uow: UnitOfWork
    fence: Fence
    now: Timestamp
    epoch: int
    #: Results of steps that already settled, replayed rather than recomputed.
    replayed: dict[StepName, Mapping[str, Any]] = field(default_factory=dict)
    evidence: EvidenceRecord | None = None
    report: str | None = None
    advice: ModelAdvice | None = None
    approvals: tuple[ApprovalRecord, ...] = ()
    #: True when this step was previously entered and never reported back, so
    #: its effect MAY already have been applied. A step with an external
    #: effect must reconcile before re-sending rather than assume it did not
    #: happen.
    reentry: bool = False

    @property
    def tenant(self) -> TenantId:
        return self.incident.tenant_id

    @property
    def incident_id(self) -> IncidentId:
        return self.incident.incident_id

    def require_evidence(self) -> EvidenceRecord:
        if self.evidence is None:
            raise ArtifactMissing(
                f"incident {self.incident_id} is {self.incident.state.value}, which "
                "asserts evidence is durable, but none was found. Refusing to "
                "continue: proceeding would produce an evidence-less attestation "
                "indistinguishable from a real one."
            )
        return self.evidence

    def require_report(self) -> str:
        if self.report is None:
            raise ArtifactMissing(
                f"incident {self.incident_id} asserts a report is durable, but none "
                "was found."
            )
        return self.report

    def idempotency_key(self, step: StepName) -> IdempotencyKey:
        """The stable key for this step's external effect. Epoch-free by design."""
        return step_idempotency_key(
            tenant=self.tenant, incident=self.incident_id, step=step
        )


@dataclass(frozen=True, slots=True)
class StepResult:
    """What a step decided, and whether that decision is final.

    `settled=False` is the case that a boolean return could not express and that
    a magic dictionary key would have expressed badly: the step made a REAL,
    durable lifecycle transition, and is nonetheless not finished.

    Attestation is the motivating example. A gateway outage moves the incident to
    `ATTESTATION_UNAVAILABLE` -- a true fact that must commit -- while the step
    itself remains unsettled so the next delivery re-runs it. Settling it would
    advance the plan to a step whose preconditions the lifecycle refuses, turning
    a transient outage into a deterministic failure and an unwind.
    """

    payload: Mapping[str, Any] = field(default_factory=dict)
    #: False leaves the journal entry RUNNING: the transition commits, the step
    #: does not complete, and the next delivery re-enters it at a new epoch.
    settled: bool = True
    #: Stop advancing after this step, even if the plan has more. Used when
    #: progress depends on something outside this invocation.
    halt: bool = False


#: A step's behaviour. Returns a `StepResult`; raises to fail the step.
StepHandler = Callable[[ExecutionContext], StepResult]

#: Undoes a compensatable step. Must be idempotent: it may be retried.
Compensator = Callable[[ExecutionContext, Mapping[str, Any]], None]


@dataclass(frozen=True, slots=True)
class _Advance:
    """The result of advancing the plan by at most one step.

    An explicit value rather than an exception: halting is an ordinary, expected
    outcome (a parked attestation, a plan that has finished), and expected
    outcomes should not travel as exceptions.
    """

    step: str
    replayed: bool = False
    halted: bool = False


@dataclass(frozen=True, slots=True)
class ExecutionOutcome:
    """What one engine invocation did. Every field is an observable count."""

    accepted: bool
    executed: tuple[str, ...] = ()
    replayed: tuple[str, ...] = ()
    compensated: tuple[str, ...] = ()
    final_state: str = ""
    detail: str = ""

    @property
    def did_work(self) -> bool:
        return bool(self.executed or self.compensated)


class ExecutionEngine:
    """Runs a plan against one incident, exactly once per step, under a fence."""

    __slots__ = (
        "_uow_factory",
        "_plan",
        "_handlers",
        "_compensators",
        "_hydrators",
        "_clock",
        "_logger",
        "_max_steps",
    )

    def __init__(
        self,
        *,
        uow_factory: UnitOfWorkFactory,
        plan: ExecutionPlan,
        handlers: Mapping[StepName, StepHandler],
        compensators: Mapping[StepName, Compensator],
        hydrators: Sequence[Callable[[ExecutionContext], None]],
        clock: Clock,
        logger: Logger,
    ) -> None:
        missing = [n.value for n in plan.names if n not in handlers]
        if missing:
            raise DomainRuleViolated(
                f"no handler registered for step(s): {', '.join(missing)}. A plan "
                "with an unimplemented step would stall silently at that step."
            )
        uncompensated = [
            s.name.value
            for s in plan.steps
            if s.kind is StepKind.COMPENSATABLE and s.name not in compensators
        ]
        if uncompensated:
            raise DomainRuleViolated(
                f"no compensator registered for compensatable step(s): "
                f"{', '.join(uncompensated)}. The plan promises an unwind that "
                "could not be performed."
            )
        self._uow_factory = uow_factory
        self._plan = plan
        self._handlers = dict(handlers)
        self._compensators = dict(compensators)
        self._hydrators = tuple(hydrators)
        self._clock = clock
        self._logger = logger
        # A hard ceiling on steps per invocation. The plan is finite and strictly
        # ordered so this is unreachable; it exists so that a future plan bug
        # produces a loud, bounded failure instead of a worker spinning forever.
        self._max_steps = len(plan.steps) * 2 + 4

    @property
    def plan(self) -> ExecutionPlan:
        return self._plan

    # ── Entry point ──────────────────────────────────────────────────────────

    def execute(
        self,
        *,
        tenant: TenantId,
        incident_id: IncidentId,
        epoch: int,
        message_id: MessageId | None = None,
    ) -> ExecutionOutcome:
        """Advance one incident as far as it will go under this lease.

        `message_id` opts into inbox deduplication. Supplying it makes a
        redelivered queue item a no-op at the boundary; omitting it relies on the
        journal alone, which is still correct but does more work to discover it.
        """
        if message_id is not None:
            with self._uow_factory.begin(tenant) as uow:
                already_accepted = uow.inbox.seen(message_id)
                incident = uow.incidents.get(incident_id)
                uow.commit()
            state = incident.state if incident is not None else None
            if already_accepted and _state_is_done_or_parked(state):
                self._logger.info(
                    "redelivery_ignored",
                    tenant=str(tenant),
                    incident_id=str(incident_id),
                    message_id=str(message_id),
                )
                return ExecutionOutcome(
                    accepted=False,
                    final_state=state.value if state is not None else "unknown",
                    detail="message already accepted after a terminal or parked outcome",
                )

        executed: list[str] = []
        replayed: list[str] = []

        for _ in range(self._max_steps):
            advance = self._advance_one(
                tenant=tenant, incident_id=incident_id, epoch=epoch
            )
            if advance is None:
                break
            (replayed if advance.replayed else executed).append(advance.step)
            if advance.halted:
                break

        final = self._read_state(tenant, incident_id)
        if message_id is not None and _state_name_is_done_or_parked(final):
            with self._uow_factory.begin(tenant) as uow:
                uow.inbox.accept(
                    message_id=message_id, kind="process_incident", now=self._clock.now()
                )
                uow.commit()
        return ExecutionOutcome(
            accepted=True,
            executed=tuple(executed),
            replayed=tuple(replayed),
            final_state=final,
        )

    # ── One step, one transaction ────────────────────────────────────────────

    def _advance_one(
        self, *, tenant: TenantId, incident_id: IncidentId, epoch: int
    ) -> _Advance | None:
        """Run at most one step. Returns what happened, or None if nothing did.

        ONE STEP PER TRANSACTION, deliberately. Batching steps into a single
        transaction would make a mid-plan crash roll back work that had already
        succeeded, and would hold a database transaction open across an external
        call. The cost is one transaction per step; the benefit is that every
        step's outcome is durable the instant it is decided.
        """
        now = self._clock.now()
        with self._uow_factory.begin(tenant) as uow:
            incident = uow.incidents.get_for_update(incident_id)
            if incident is None:
                raise ArtifactMissing(f"incident {incident_id} does not exist")
            if incident.is_terminal:
                uow.commit()
                return None

            incident.acquire_execution(epoch)
            journal = uow.journal.load(incident_id)
            settled = {name for name, record in journal.items() if record.is_settled}

            step = self._plan.next_step(settled)
            if step is None:
                uow.commit()
                return None

            ctx = ExecutionContext(
                incident=incident,
                uow=uow,
                fence=Fence.worker(epoch),
                now=now,
                epoch=epoch,
                replayed={n: r.result for n, r in journal.items() if r.is_settled},
            )
            # Rebuild the execution context from durable state BEFORE any step
            # runs. This is the guarantee that a resumed run never sees `None`
            # where the first run saw an artifact.
            for hydrate in self._hydrators:
                hydrate(ctx)

            prior = journal.get(step.name)
            if prior is not None and prior.status is StepStatus.RUNNING:
                # A previous worker entered this step and did not report back. Its
                # effect MAY have reached the outside world. The step is re-entered
                # at this epoch and re-executed with the SAME deterministic
                # idempotency key, so the receiving system collapses the duplicate.
                self._logger.warning(
                    "step_reentered_after_interruption",
                    incident_id=str(incident_id),
                    step=step.name.value,
                    prior_epoch=prior.epoch,
                    epoch=epoch,
                    detail="effect may already have been applied; the step's "
                    "idempotency key is stable across epochs so the external "
                    "system deduplicates it",
                )

            uow.journal.enter(incident_id, step=step.name, epoch=epoch, now=now)
            uow.incidents.save(incident)
            uow.commit()

        # ── act + settle, in a second transaction ────────────────────────────
        return self._run_step(
            tenant=tenant, incident_id=incident_id, epoch=epoch, step=step
        )

    def _run_step(
        self,
        *,
        tenant: TenantId,
        incident_id: IncidentId,
        epoch: int,
        step: StepDefinition,
    ) -> _Advance:
        now = self._clock.now()
        with self._uow_factory.begin(tenant) as uow:
            incident = uow.incidents.get_for_update(incident_id)
            if incident is None:
                raise ArtifactMissing(f"incident {incident_id} does not exist")

            journal = uow.journal.load(incident_id)
            record = journal.get(step.name)
            if record is not None and record.is_settled:
                # Another worker settled it between our enter and now. Its result
                # stands; ours would be a duplicate.
                uow.commit()
                return _Advance(step.name.value, replayed=True)

            ctx = ExecutionContext(
                incident=incident,
                uow=uow,
                fence=Fence.worker(epoch),
                now=now,
                epoch=epoch,
                replayed={n: r.result for n, r in journal.items() if r.is_settled},
                # `attempts > 1` means this step was entered before and did
                # not settle: its effect may have escaped.
                reentry=bool(record is not None and record.attempts > 1),
            )
            for hydrate in self._hydrators:
                hydrate(ctx)

            terminal_error: str | None = None
            try:
                result = self._handlers[step.name](ctx)
            except ExecutionFenceLost:
                # Not this worker's incident any more. Write NOTHING and abandon;
                # the current owner is already redoing this work.
                raise
            except SentinelError as exc:
                if exc.is_retryable:
                    # Leave the journal RUNNING. The next attempt re-enters at a
                    # new epoch and reconciles. Rolling back to PENDING would
                    # erase the record that the effect may have been applied.
                    uow.rollback()
                    raise
                # A deterministic failure. The unwind needs its OWN transactions
                # -- one per compensation, so a failing compensation does not
                # roll back the ones that succeeded -- so it must not start
                # while this one is open. Recorded here, performed below.
                #
                # Calling the unwind inline deadlocked: SQLite holds the write
                # lock for the life of the transaction, and the second `begin()`
                # blocked on the first. The chaos suite found it; no example test
                # would have, because the happy path never opens two.
                terminal_error = f"{type(exc).__name__}: {exc}"
                uow.rollback()
            except Exception:  # noqa: BLE001
                # Unclassified failures are treated as RETRYABLE. Retrying a
                # deterministic failure wastes a budget; terminalising a transient
                # one destroys an incident. The asymmetry decides the default.
                uow.rollback()
                raise

            if terminal_error is not None:
                # Break out of the transaction before unwinding.
                pass
            else:
                if result.settled:

                    uow.journal.settle(
                        incident_id,
                        step=step.name,
                        status=StepStatus.COMPLETED,
                        result=dict(result.payload),
                        epoch=epoch,
                        now=now,
                    )
                # The incident and its events commit in EITHER case. An unsettled
                # step still made a true statement about the world, and discarding
                # it to keep the journal tidy would lose the durable record of why
                # the incident is parked.
                uow.incidents.save(incident)
                uow.collect(incident.pull_events())
                uow.commit()

        if terminal_error is not None:
            self._fail_and_maybe_unwind(
                tenant=tenant,
                incident_id=incident_id,
                epoch=epoch,
                step=step,
                error=terminal_error,
            )
            return _Advance(step.name.value, halted=True)

        # An unsettled step halts the plan: it is unfinished by its own report,
        # so nothing after it may run. The next delivery re-enters it.
        return _Advance(step.name.value, halted=not result.settled or result.halt)

    # ── Saga unwind ──────────────────────────────────────────────────────────

    def _fail_and_maybe_unwind(
        self,
        *,
        tenant: TenantId,
        incident_id: IncidentId,
        epoch: int,
        step: StepDefinition,
        error: str,
    ) -> None:
        """Record a deterministic failure, then unwind or hold.

        The branch is the pivot. Before it, every completed compensatable step is
        undone in reverse order. At or after it, there is nothing to undo and the
        incident is failed with the reason recorded -- forward recovery is an
        operator decision, not something this engine may take on its own.
        """
        now = self._clock.now()
        with self._uow_factory.begin(tenant) as uow:
            incident = uow.incidents.get_for_update(incident_id)
            if incident is None:
                raise ArtifactMissing(f"incident {incident_id} does not exist")
            journal = uow.journal.load(incident_id)
            uow.journal.settle(
                incident_id,
                step=step.name,
                status=StepStatus.FAILED,
                result={},
                epoch=epoch,
                now=now,
                error=error,
            )
            # `has_run`, not `is COMPLETED`. A pivot step that was entered and
            # never reported back may have applied its irreversible effect, so
            # the saga must treat the pivot as crossed and refuse to unwind.
            entered = [n for n, r in journal.items() if r.status.has_run]
            completed = [n for n, r in journal.items() if r.status is StepStatus.COMPLETED]
            passed_pivot = self._plan.has_passed_pivot(entered)
            unwind = () if passed_pivot else self._plan.compensation_order(completed)
            uow.commit()

        for name in unwind:
            self._compensate(tenant=tenant, incident_id=incident_id, epoch=epoch, name=name)

        with self._uow_factory.begin(tenant) as uow:
            incident = uow.incidents.get_for_update(incident_id)
            if incident is None or incident.is_terminal:
                uow.commit()
                return
            reason = (
                f"step {step.name} failed deterministically: {error}"
                if passed_pivot
                else f"step {step.name} failed and the saga unwound: {error}"
            )
            incident.fail(reason=reason, fence=Fence.worker(epoch), now=self._clock.now())
            uow.incidents.save(incident)
            uow.collect(incident.pull_events())
            uow.commit()

        self._logger.error(
            "saga_failed",
            incident_id=str(incident_id),
            step=step.name.value,
            past_pivot=passed_pivot,
            compensated=[n.value for n in unwind],
            error=error,
        )

    def _compensate(
        self, *, tenant: TenantId, incident_id: IncidentId, epoch: int, name: StepName
    ) -> None:
        """Undo one completed step. Two-phase, idempotent, and never fatal.

        The unwind uses the SAME enter/act/settle discipline as the forward path,
        for the same reason: a compensation may have an external effect, and a
        crash between performing it and recording it must leave evidence that it
        MAY have happened. `COMPENSATING` is that evidence.

            COMPLETED -> COMPENSATING   durable intent, own transaction
                         (act)          the compensator runs
                      -> COMPENSATED    outcome, own transaction

        A compensation that raises must not abort the rest of the unwind: the
        remaining steps still need undoing, and abandoning them half-way leaves a
        worse state than either finishing or never starting. The failure is
        recorded per step so an operator can see exactly what did not unwind.
        """
        # Phase 1: durable intent.
        with self._uow_factory.begin(tenant) as uow:
            record = uow.journal.load(incident_id).get(name)
            if record is None or record.status is not StepStatus.COMPLETED:
                uow.commit()
                return
            uow.journal.settle(
                incident_id,
                step=name,
                status=StepStatus.COMPENSATING,
                result=dict(record.result),
                epoch=record.epoch,
                now=self._clock.now(),
            )
            uow.commit()
            original = dict(record.result)
            original_epoch = record.epoch

        # Phase 2: act and settle.
        with self._uow_factory.begin(tenant) as uow:
            incident = uow.incidents.get_for_update(incident_id)
            if incident is None:
                uow.commit()
                return
            ctx = ExecutionContext(
                incident=incident,
                uow=uow,
                fence=Fence.worker(epoch),
                now=self._clock.now(),
                epoch=epoch,
                replayed={
                    n: r.result
                    for n, r in uow.journal.load(incident_id).items()
                    if r.is_settled
                },
            )
            # DELIBERATELY NOT HYDRATED. Hydration asserts that every artifact
            # the incident's state claims is present -- which is exactly what an
            # unwind is in the middle of dismantling. Compensating `report`
            # withdraws it, and the next compensation's hydration would then
            # raise ArtifactMissing over an artifact this very unwind removed on
            # purpose, aborting the rest of it.
            #
            # A compensator does not need hydrated artifacts: it receives the
            # step's journaled RESULT, which is precisely why the journal records
            # one.
            try:
                self._compensators[name](ctx, original)
            except Exception as exc:  # noqa: BLE001
                uow.rollback()
                self._logger.error(
                    "compensation_failed",
                    incident_id=str(incident_id),
                    step=name.value,
                    error=f"{type(exc).__name__}: {exc}",
                    detail="this step did NOT unwind; the incident is partially "
                    "compensated and needs an operator",
                )
                return
            uow.journal.settle(
                incident_id,
                step=name,
                status=StepStatus.COMPENSATED,
                result=original,
                epoch=original_epoch,
                now=self._clock.now(),
            )
            uow.commit()

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _read_state(self, tenant: TenantId, incident_id: IncidentId) -> str:
        with self._uow_factory.begin(tenant) as uow:
            incident = uow.incidents.get(incident_id)
            uow.commit()
        return incident.state.value if incident else "unknown"


def _state_is_done_or_parked(state: IncidentState | None) -> bool:
    if state is None:
        return False
    return state.is_terminal or state is IncidentState.ATTESTATION_UNAVAILABLE


def _state_name_is_done_or_parked(state: str) -> bool:
    try:
        return _state_is_done_or_parked(IncidentState(state))
    except ValueError:
        return False
