"""Property-based tests: invariants that must hold for EVERY input, not examples.

An example test proves a case. A property test proves a rule, or finds the input
that disproves it. Everything here is a rule the engine's correctness rests on,
stated as a universally quantified claim and checked against generated inputs.

Hypothesis shrinks any counterexample to its minimal form, so a failure here
arrives as the smallest sequence of operations that breaks the invariant rather
than as the 200-step random walk that happened to find it.
"""

from __future__ import annotations

import inspect
from datetime import datetime, timezone

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from sentinel.domain.attestation import AttestationDisposition, AttestationOutcome
from sentinel.domain.errors import (
    ExecutionFenceLost,
    IllegalTransition,
    MissingRequiredFact,
)
from sentinel.domain.execution import (
    ExecutionPlan,
    PlanShapeViolation,
    StepDefinition,
    StepKind,
    StepName,
    StepStatus,
    check_step_transition,
    step_idempotency_key,
)
from sentinel.domain.incident import Fence, Incident, IncidentState, _EDGES
from sentinel.domain.primitives import (
    Digest,
    IncidentId,
    InvalidValue,
    Severity,
    TenantId,
    Timestamp,
    TrustLevel,
    UNVERIFIED_SEVERITY_CAP,
)

NOW = Timestamp(datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc))
TENANT = TenantId("acme")
INCIDENT = IncidentId("inc-1")
DIGEST = Digest("c" * 64)

SETTINGS = settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)

# ── Strategies ───────────────────────────────────────────────────────────────

states = st.sampled_from(list(IncidentState))
step_statuses = st.sampled_from(list(StepStatus))
dispositions = st.sampled_from(list(AttestationDisposition))
severities = st.integers(min_value=0, max_value=100)
trust_levels = st.sampled_from(list(TrustLevel))
epochs = st.integers(min_value=0, max_value=1_000)
step_names = st.builds(StepName, st.from_regex(r"\A[a-z][a-z0-9_]{0,12}\Z", fullmatch=True))


# ── Value-object properties ──────────────────────────────────────────────────


@given(value=severities, trust=trust_levels)
@SETTINGS
def test_capping_is_idempotent_and_never_increases_severity(value, trust):
    """Capping twice equals capping once, and never raises the score.

    A cap that could raise a severity, or that changed on a second application,
    would make an incident's recorded severity depend on how many times the code
    path happened to run.
    """
    original = Severity(value)
    once = original.capped_for(trust)
    twice = once.capped_for(trust)
    assert once.value <= original.value
    assert twice == once


@given(value=severities)
@SETTINGS
def test_an_unverified_source_can_never_reach_critical(value):
    capped = Severity(value).capped_for(TrustLevel.UNSIGNED)
    assert capped.value <= UNVERIFIED_SEVERITY_CAP
    assert capped.priority.value != "CRITICAL"


@given(value=severities)
@SETTINGS
def test_priority_is_monotonic_in_severity(value):
    """A higher severity can never yield a lower priority."""
    order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    lower = Severity(value).priority.value
    higher = Severity(min(100, value + 1)).priority.value
    assert order[higher] >= order[lower]


@given(raw=st.text(min_size=0, max_size=80))
@SETTINGS
def test_digest_construction_is_total(raw):
    """Every input either produces a valid digest or is refused. Never both."""
    try:
        digest = Digest(raw)
    except InvalidValue:
        return
    assert len(digest.value) == 64
    assert digest.value == digest.value.lower()
    assert Digest(digest.value) == digest


# ── Idempotency-key properties ───────────────────────────────────────────────


@given(step=step_names)
@SETTINGS
def test_the_idempotency_key_is_stable_and_cannot_depend_on_an_epoch(step):
    """THE property that makes retry safe at the external boundary.

    Two workers retrying the same step at different epochs must present the SAME
    key, or the receiving system sees two distinct effects. Including the epoch
    is precisely the defect that makes every retry a fresh anchor.

    Stated structurally rather than by substring search: an earlier version of
    this test asserted the epoch did not appear in the key, which is a
    coincidence test -- the key contains "inc-1", so an epoch of 1 "appeared" in
    it and the property failed for a reason that had nothing to do with the
    claim. The real guarantee is that the function CANNOT depend on an epoch,
    because it does not take one.
    """
    assert step_idempotency_key(
        tenant=TENANT, incident=INCIDENT, step=step
    ) == step_idempotency_key(tenant=TENANT, incident=INCIDENT, step=step)
    assert "epoch" not in inspect.signature(step_idempotency_key).parameters


@given(step_a=step_names, step_b=step_names)
@SETTINGS
def test_distinct_steps_never_share_an_idempotency_key(step_a, step_b):
    assume(step_a != step_b)
    assert step_idempotency_key(
        tenant=TENANT, incident=INCIDENT, step=step_a
    ) != step_idempotency_key(tenant=TENANT, incident=INCIDENT, step=step_b)


incident_ids = st.builds(
    IncidentId, st.from_regex(r"\Ainc-[a-z0-9]{1,10}\Z", fullmatch=True)
)


@given(step=step_names, first=incident_ids, second=incident_ids)
@SETTINGS
def test_distinct_incidents_never_share_an_idempotency_key(step, first, second):
    """Generated from a strategy that only produces VALID ids.

    Filtering invalid text with `assume` made Hypothesis discard fifty inputs
    for every nine it kept, which both slows generation and distorts the
    distribution -- the surviving inputs are not a fair sample of the domain.
    Generate what you mean instead of rejecting what you do not.
    """
    assume(first != second)
    assert step_idempotency_key(
        tenant=TENANT, incident=first, step=step
    ) != step_idempotency_key(tenant=TENANT, incident=second, step=step)


# ── Step state-machine properties ────────────────────────────────────────────


@given(current=step_statuses, target=step_statuses)
@SETTINGS
def test_step_transition_check_is_total(current, target):
    """Every pair either transitions or raises. There is no third answer."""
    try:
        check_step_transition(current, target)
    except IllegalTransition:
        return
    assert True


@given(target=step_statuses)
@SETTINGS
def test_a_step_can_only_be_created_as_running(target):
    if target is StepStatus.RUNNING:
        check_step_transition(None, target)
        return
    with pytest.raises(IllegalTransition):
        check_step_transition(None, target)


@given(target=step_statuses)
@SETTINGS
def test_a_settled_step_is_never_re_enterable(target):
    """COMPENSATED is terminal; COMPLETED may only be unwound, never re-run."""
    with pytest.raises(IllegalTransition):
        check_step_transition(StepStatus.COMPENSATED, target)
    if target is not StepStatus.COMPENSATING:
        with pytest.raises(IllegalTransition):
            check_step_transition(StepStatus.COMPLETED, target)


@given(status=step_statuses)
@SETTINGS
def test_has_run_covers_every_status_that_may_have_reached_the_world(status):
    """RUNNING must count as "may have run", or an interrupted effect repeats."""
    if status in {StepStatus.PENDING, StepStatus.FAILED}:
        assert not status.has_run
    else:
        assert status.has_run


# ── Lifecycle properties ─────────────────────────────────────────────────────


@given(state=states)
@SETTINGS
def test_terminal_states_have_no_outgoing_edges(state):
    if state.is_terminal:
        assert _EDGES[state] == frozenset()
    else:
        assert _EDGES[state] != frozenset()


@given(state=states)
@SETTINGS
def test_every_state_is_reachable_from_received(state):
    """No orphan states. An unreachable state is dead code in the domain."""
    seen, frontier = {IncidentState.RECEIVED}, [IncidentState.RECEIVED]
    while frontier:
        current = frontier.pop()
        for nxt in _EDGES[current] | {IncidentState.FAILED}:
            if nxt not in seen:
                seen.add(nxt)
                frontier.append(nxt)
    assert state in seen


@given(state=states)
@SETTINGS
def test_only_an_anchored_state_reports_itself_attested(state):
    assert state.is_attested == (
        state in {IncidentState.ATTESTED, IncidentState.COMPLETED_ATTESTED}
    )


@given(disposition=dispositions)
@SETTINGS
def test_an_attestation_outcome_always_maps_to_exactly_one_state(disposition):
    """The mapping is TOTAL, so no disposition can leave an incident nowhere."""
    outcome = AttestationOutcome(
        disposition,
        "generated",
        transaction_hash="0xabc" if disposition is AttestationDisposition.ANCHORED else None,
    )
    target = IncidentState(outcome.next_state_name)
    assert target in set(IncidentState)
    # The load-bearing claim: only a real anchor may reach a terminal attested
    # state, and a transient outage may reach no terminal state at all.
    if disposition is AttestationDisposition.UNAVAILABLE:
        assert not target.is_terminal
        assert not target.is_attested
    if disposition is AttestationDisposition.NOT_ANCHORABLE:
        assert target.is_terminal
        assert not target.is_attested


@given(epoch=epochs, older=epochs)
@SETTINGS
def test_a_strictly_older_epoch_can_never_write(epoch, older):
    assume(older < epoch)
    incident = Incident.admit(
        tenant_id=TENANT,
        incident_id=INCIDENT,
        severity=Severity(50),
        trust_level=TrustLevel.UNSIGNED,
        source="p",
        now=NOW,
    )
    incident.acquire_execution(epoch)
    with pytest.raises(ExecutionFenceLost):
        incident.advance(IncidentState.VALIDATED, fence=Fence.worker(older), now=NOW)


@given(epoch=epochs)
@SETTINGS
def test_acquiring_the_fence_is_idempotent_at_the_same_epoch(epoch):
    """The property the first implementation lacked, which made step 2 of every
    run refuse the epoch step 1 had just taken."""
    incident = Incident.admit(
        tenant_id=TENANT,
        incident_id=INCIDENT,
        severity=Severity(50),
        trust_level=TrustLevel.UNSIGNED,
        source="p",
        now=NOW,
    )
    assert incident.acquire_execution(epoch) is (epoch > 0)
    assert incident.acquire_execution(epoch) is False
    assert incident.execution_epoch == epoch


# ── Plan-shape properties ────────────────────────────────────────────────────

kinds = st.sampled_from(list(StepKind))


@st.composite
def plans(draw):
    """Generate arbitrary step sequences, valid or not, to test the shape rule."""
    size = draw(st.integers(min_value=1, max_value=6))
    chosen = draw(
        st.lists(kinds, min_size=size, max_size=size)
    )
    steps = []
    for index, kind in enumerate(chosen):
        name = StepName(f"s{index}")
        steps.append(
            StepDefinition(
                name,
                kind,
                compensation=StepName(f"undo{index}")
                if kind is StepKind.COMPENSATABLE
                else None,
            )
        )
    return steps


@given(steps=plans())
@SETTINGS
def test_a_plan_is_accepted_if_and_only_if_it_has_the_saga_shape(steps):
    """compensatable* · pivot? · retriable* — accepted; anything else refused.

    The rule matters because it is what makes the unwind decision total: before
    the pivot every completed step HAS a compensation, so an unwind can always
    finish. A plan violating the shape promises an unwind that would stall.
    """
    kinds_seq = [s.kind for s in steps]
    pivots = [i for i, k in enumerate(kinds_seq) if k is StepKind.PIVOT]
    if len(pivots) > 1:
        valid = False
    elif not pivots:
        valid = all(k is StepKind.COMPENSATABLE for k in kinds_seq)
    else:
        p = pivots[0]
        valid = all(k is StepKind.COMPENSATABLE for k in kinds_seq[:p]) and all(
            k is StepKind.RETRIABLE for k in kinds_seq[p + 1 :]
        )

    if valid:
        plan = ExecutionPlan(steps)
        assert plan.names == tuple(s.name for s in steps)
    else:
        with pytest.raises(PlanShapeViolation):
            ExecutionPlan(steps)


@st.composite
def valid_plans(draw):
    """Generate only plans with the saga shape: compensatable* pivot? retriable*.

    A separate strategy from `plans()`, which deliberately generates invalid
    shapes to test the REFUSAL. Properties about ordering need a plan that
    exists, and filtering `plans()` down to the valid ones discarded five in six.
    """
    before = draw(st.integers(min_value=0, max_value=4))
    has_pivot = draw(st.booleans())
    after = draw(st.integers(min_value=0, max_value=3)) if has_pivot else 0
    steps = [
        StepDefinition(
            StepName(f"c{i}"), StepKind.COMPENSATABLE, compensation=StepName(f"undo{i}")
        )
        for i in range(before)
    ]
    if has_pivot:
        steps.append(StepDefinition(StepName("pivot"), StepKind.PIVOT))
        steps.extend(
            StepDefinition(StepName(f"r{i}"), StepKind.RETRIABLE) for i in range(after)
        )
    assume(steps)
    return steps


@given(steps=valid_plans())
@SETTINGS
def test_compensation_runs_in_reverse_and_only_over_completed_compensatable_steps(steps):
    plan = ExecutionPlan(steps)
    completed = set(plan.names)
    order = plan.compensation_order(completed)

    compensatable = [s.name for s in plan.steps if s.kind is StepKind.COMPENSATABLE]
    assert list(order) == list(reversed(compensatable))
    # Nothing at or after the pivot is ever unwound: it cannot be.
    pivot = plan.pivot
    if pivot is not None:
        assert pivot.name not in order


@given(steps=valid_plans(), subset=st.data())
@SETTINGS
def test_next_step_is_deterministic_and_ordered(steps, subset):
    """From any journal, exactly one step is next, and it is the earliest unsettled.

    This is what makes resume deterministic: two workers reading the same journal
    make the same decision, so a race produces duplicate ATTEMPTS at one step
    (which the journal absorbs) rather than divergent execution.
    """
    plan = ExecutionPlan(steps)
    settled = set(
        subset.draw(st.lists(st.sampled_from(list(plan.names)), unique=True))
    )
    first = plan.next_step(settled)
    second = plan.next_step(settled)
    assert first is second
    if first is None:
        assert settled == set(plan.names)
    else:
        assert first.name not in settled
        earlier = plan.names[: plan.index_of(first.name)]
        assert set(earlier) <= settled


# ── Stateful model: the lifecycle can never be driven into an illegal state ──


class LifecycleModel(RuleBasedStateMachine):
    """Drive an aggregate with arbitrary legal-and-illegal operations.

    The invariants below must hold after EVERY step, whatever sequence
    Hypothesis invents. This is the closest thing to a proof the test suite can
    offer: not "these transitions work" but "no reachable sequence of operations
    produces an impossible state".
    """

    def __init__(self) -> None:
        super().__init__()
        self.incident = Incident.admit(
            tenant_id=TENANT,
            incident_id=INCIDENT,
            severity=Severity(90),
            trust_level=TrustLevel.VERIFIED,
            source="model",
            now=NOW,
        )
        self.epoch = 1
        self.incident.acquire_execution(self.epoch)
        self.transitions = 0

    def _fence(self) -> Fence:
        return Fence.worker(self.epoch)

    # `to_state`, not `target`: Hypothesis reserves `target=` on @rule for
    # Bundles, and a rule parameter named `target` is silently interpreted as one.
    @rule(to_state=st.sampled_from(list(IncidentState)))
    def try_advance(self, to_state):
        before = self.incident.state
        before_version = self.incident.version
        try:
            self.incident.advance(to_state, fence=self._fence(), now=NOW)
        except (IllegalTransition, MissingRequiredFact, ExecutionFenceLost):
            # A refused transition must leave the aggregate completely untouched.
            assert self.incident.state is before
            assert self.incident.version == before_version
            return
        self.transitions += 1

    @rule()
    def try_record_evidence(self):
        try:
            self.incident.record_evidence(
                digest=DIGEST,
                uri="sentinel://e",
                ledger_sequence=1,
                chain_hash=DIGEST,
                fence=self._fence(),
                now=NOW,
            )
        except (IllegalTransition, MissingRequiredFact):
            return
        self.transitions += 1

    @rule(disposition=dispositions)
    def try_attest(self, disposition):
        outcome = AttestationOutcome(
            disposition,
            "model",
            transaction_hash="0xdead" if disposition is AttestationDisposition.ANCHORED else None,
        )
        try:
            self.incident.record_attestation(outcome, fence=self._fence(), now=NOW)
        except (IllegalTransition, MissingRequiredFact):
            return
        self.transitions += 1

    @rule(delta=st.integers(min_value=1, max_value=3))
    def reclaim(self, delta):
        self.epoch += delta
        self.incident.acquire_execution(self.epoch)

    @invariant()
    def state_is_always_a_real_state(self):
        assert self.incident.state in set(IncidentState)

    @invariant()
    def version_matches_the_number_of_applied_transitions(self):
        assert self.incident.version == self.transitions

    @invariant()
    def attested_implies_a_recorded_anchor(self):
        """THE invariant. No sequence may produce an attested state without one."""
        if self.incident.state.is_attested:
            assert (
                self.incident.fact("attestation_outcome")
                == AttestationDisposition.ANCHORED.value
            )

    @invariant()
    def a_completed_state_is_never_reached_from_a_transient_outage(self):
        if self.incident.state is IncidentState.COMPLETED_UNATTESTED:
            assert (
                self.incident.fact("attestation_outcome")
                == AttestationDisposition.NOT_ANCHORABLE.value
            )

    @invariant()
    def terminal_states_stay_terminal(self):
        if self.incident.state.is_terminal:
            assert _EDGES[self.incident.state] == frozenset()


TestLifecycleModel = LifecycleModel.TestCase
TestLifecycleModel.settings = settings(
    max_examples=100, stateful_step_count=30, deadline=None
)
