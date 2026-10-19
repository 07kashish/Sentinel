"""Systematic mutation campaign over the pure domain modules.

Unlike `test_execution_mutation.py`, nothing here is chosen. Every applicable
operator is applied at every applicable site, and the report names the mutants
that SURVIVED — changes to production code that no probe could distinguish from
the real thing.

Surviving mutants are not automatically defects. Some are genuinely equivalent
(a boundary tweak inside a log message), and each survivor recorded in
`KNOWN_SURVIVORS` below carries a written reason. What the threshold prevents is
survivors accumulating silently.
"""

from __future__ import annotations

import types
from pathlib import Path

import pytest

import sentinel
from tests_arch.mutation_runner import run_mutation_campaign

DOMAIN = Path(sentinel.__file__).resolve().parent / "domain"

TARGETS = [
    (DOMAIN / "execution.py", "sentinel.domain.execution"),
    (DOMAIN / "attestation.py", "sentinel.domain.attestation"),
]

#: The floor. A campaign below this means the suite has stopped being able to
#: tell the code from a broken version of it.
MINIMUM_SCORE = 0.85


# ── Probes: pure, fast, and exercising the rules that matter ───────────────


def _probe_step_machine(module: types.ModuleType) -> None:
    """Every step transition rule, checked against the mutant."""
    status = module.StepStatus
    check = module.check_step_transition

    # A step is created only as RUNNING.
    check(None, status.RUNNING)
    for bad in (status.COMPLETED, status.FAILED, status.COMPENSATED, status.PENDING):
        _must_raise(lambda: check(None, bad))

    # A settled step is never re-enterable.
    _must_raise(lambda: check(status.COMPLETED, status.RUNNING))
    _must_raise(lambda: check(status.COMPENSATED, status.RUNNING))
    _must_raise(lambda: check(status.COMPENSATED, status.COMPLETED))

    # A running step may complete, fail, or be re-entered at a new epoch.
    check(status.RUNNING, status.COMPLETED)
    check(status.RUNNING, status.FAILED)
    check(status.RUNNING, status.RUNNING)

    # Unwinding is two-phase.
    check(status.COMPLETED, status.COMPENSATING)
    check(status.COMPENSATING, status.COMPENSATED)
    _must_raise(lambda: check(status.COMPLETED, status.COMPENSATED))

    # `has_run` must cover every status whose effect may have escaped.
    assert not status.PENDING.has_run
    assert not status.FAILED.has_run
    for reached in (
        status.RUNNING,
        status.COMPLETED,
        status.COMPENSATING,
        status.COMPENSATED,
    ):
        assert reached.has_run
    assert status.COMPLETED.is_terminal
    assert status.COMPENSATED.is_terminal
    assert not status.RUNNING.is_terminal


def _probe_plan_shape(module: types.ModuleType) -> None:
    """The saga shape rule, its ordering, and the pivot decision."""
    plan_cls = module.ExecutionPlan
    definition = module.StepDefinition
    kind = module.StepKind
    name = module.StepName

    def comp(label: str):
        return definition(name(label), kind.COMPENSATABLE, compensation=name(f"u{label}"))

    # A well-shaped plan is accepted and ordered.
    plan = plan_cls(
        (
            comp("a"),
            comp("b"),
            definition(name("pivot"), kind.PIVOT),
            definition(name("after"), kind.RETRIABLE),
        )
    )
    assert [n.value for n in plan.names] == ["a", "b", "pivot", "after"]
    assert plan.pivot.name.value == "pivot"

    # Compensation is reverse order, and never touches the pivot or past it.
    order = [n.value for n in plan.compensation_order({name("a"), name("b")})]
    assert order == ["b", "a"]
    assert "pivot" not in order
    assert "after" not in order

    # The pivot is crossed once ENTERED, which is what stops an unwind after an
    # irreversible effect.
    assert plan.has_passed_pivot({name("pivot")})
    assert not plan.has_passed_pivot({name("a"), name("b")})

    # next_step is deterministic and strictly ordered.
    assert plan.next_step(set()).name.value == "a"
    assert plan.next_step({name("a")}).name.value == "b"
    assert plan.next_step(set(plan.names)) is None

    # Shape violations are refused.
    _must_raise(
        lambda: plan_cls(
            (definition(name("pivot"), kind.PIVOT), comp("after"))
        )
    )
    _must_raise(
        lambda: plan_cls(
            (
                definition(name("p1"), kind.PIVOT),
                definition(name("p2"), kind.PIVOT),
            )
        )
    )
    _must_raise(lambda: plan_cls(()))
    _must_raise(lambda: plan_cls((comp("dup"), comp("dup"))))
    # A compensatable step MUST name its compensation.
    _must_raise(lambda: definition(name("x"), kind.COMPENSATABLE))
    # A pivot must NOT.
    _must_raise(
        lambda: definition(name("x"), kind.PIVOT, compensation=name("u"))
    )


def _probe_idempotency_key(module: types.ModuleType) -> None:
    """The key must be stable, and distinct per (tenant, incident, step)."""
    from sentinel.domain.primitives import IncidentId, TenantId

    key = module.step_idempotency_key
    name = module.StepName
    tenant, incident = TenantId("t1"), IncidentId("i1")

    first = key(tenant=tenant, incident=incident, step=name("attest"))
    assert first == key(tenant=tenant, incident=incident, step=name("attest"))
    assert first != key(tenant=tenant, incident=incident, step=name("report"))
    assert first != key(tenant=TenantId("t2"), incident=incident, step=name("attest"))
    assert first != key(tenant=tenant, incident=IncidentId("i2"), step=name("attest"))


def _probe_attestation_outcome(module: types.ModuleType) -> None:
    """The disposition -> destination mapping, and the anchored-hash rule."""
    if not hasattr(module, "AttestationDisposition"):
        return  # this probe applies only to the attestation module
    disposition = module.AttestationDisposition
    outcome = module.AttestationOutcome

    anchored = outcome(disposition.ANCHORED, "ok", transaction_hash="0xabc")
    assert anchored.is_anchored
    assert anchored.next_state_name == "attested"

    unavailable = outcome(disposition.UNAVAILABLE, "down")
    assert not unavailable.is_anchored
    assert unavailable.next_state_name == "attestation_unavailable"

    not_anchorable = outcome(disposition.NOT_ANCHORABLE, "no identity")
    assert not not_anchorable.is_anchored
    assert not_anchorable.next_state_name == "completed_unattested"

    # An anchored outcome MUST carry the hash that proves it.
    _must_raise(lambda: outcome(disposition.ANCHORED, "ok"))
    # Every outcome must carry a human-readable reason.
    _must_raise(lambda: outcome(disposition.UNAVAILABLE, "   "))

    facts = anchored.as_facts()
    assert facts["attestation_outcome"] == "anchored"
    assert facts["transaction_hash"] == "0xabc"


def _probe_step_name(module: types.ModuleType) -> None:
    if not hasattr(module, "StepName"):
        return
    name = module.StepName
    assert name("  attest  ").value == "attest"
    assert name("undo_evidence").value == "undo_evidence"
    for bad in ("", "   ", "has space", "bad!", 42, None):
        _must_raise(lambda b=bad: name(b))


def _probe_step_record(module: types.ModuleType) -> None:
    """`StepRecord`, which the first campaign showed was probed by nothing.

    `is_settled` is the single question the engine asks of the journal -- "must I
    NOT execute this step again?" -- and its membership test survived mutation
    because no probe constructed a record at all.
    """
    if not hasattr(module, "StepRecord"):
        return
    record_cls = module.StepRecord
    status = module.StepStatus
    name = module.StepName

    settled = {status.COMPLETED, status.COMPENSATED}
    for candidate in status:
        record = record_cls(step=name("s"), status=candidate, epoch=1)
        assert record.is_settled == (candidate in settled), (
            f"is_settled disagrees for {candidate.value}"
        )

    # Defaults matter: a record defaulting `attempts` to something other than 0
    # silently changes every retry-budget comparison.
    fresh = record_cls(step=name("s"), status=status.RUNNING, epoch=3)
    assert fresh.attempts == 0
    assert fresh.result == {}
    assert fresh.error is None
    assert fresh.epoch == 3

    # Frozen: a journal entry that a caller can mutate in place is not a record.
    _must_raise(lambda: setattr(fresh, "status", status.COMPLETED))


def _probe_value_semantics(module: types.ModuleType) -> None:
    """Frozen-ness, equality and ordering of the value types.

    The dataclass decorator's `frozen`, `eq` and `order` flags are real
    guarantees -- mutating them survived the first campaign because nothing
    asserted them. `order=True` on StepName is what lets compensation ordering
    and plan comparisons be stable.
    """
    if not hasattr(module, "StepName"):
        return
    name = module.StepName

    first, second = name("alpha"), name("beta")
    assert first == name("alpha")
    assert first != second
    assert first < second, "StepName must be orderable"
    assert sorted([second, first]) == [first, second]
    assert hash(first) == hash(name("alpha"))
    _must_raise(lambda: setattr(first, "value", "changed"))

    if hasattr(module, "StepDefinition"):
        definition = module.StepDefinition
        kind = module.StepKind
        step = definition(name("x"), kind.PIVOT)
        _must_raise(lambda: setattr(step, "name", name("y")))
        assert step == definition(name("x"), kind.PIVOT)


def _probe_plan_boundaries(module: types.ModuleType) -> None:
    """The index comparisons in the plan's shape check, at their boundaries.

    `index < pivot_index` and `index > pivot_index` decide which side of the
    pivot a step is on. Off-by-one there silently permits a compensatable step at
    the pivot's own index, or forbids a legal one.
    """
    plan_cls = module.ExecutionPlan
    definition = module.StepDefinition
    kind = module.StepKind
    name = module.StepName

    def comp(label: str):
        return definition(name(label), kind.COMPENSATABLE, compensation=name(f"u{label}"))

    # Pivot first: nothing before it, everything after must be retriable.
    plan_cls((definition(name("p"), kind.PIVOT), definition(name("r"), kind.RETRIABLE)))
    _must_raise(
        lambda: plan_cls((definition(name("p"), kind.PIVOT), comp("c")))
    )

    # Pivot last: everything before must be compensatable.
    plan_cls((comp("c"), definition(name("p"), kind.PIVOT)))
    _must_raise(
        lambda: plan_cls(
            (definition(name("r"), kind.RETRIABLE), definition(name("p"), kind.PIVOT))
        )
    )

    # A pivot-free plan may contain only compensatable steps.
    plan_cls((comp("a"), comp("b")))
    _must_raise(lambda: plan_cls((definition(name("r"), kind.RETRIABLE),)))

    # A single pivot alone is legal; two are not, at any distance.
    plan_cls((definition(name("p"), kind.PIVOT),))
    _must_raise(
        lambda: plan_cls(
            (
                definition(name("p1"), kind.PIVOT),
                definition(name("r"), kind.RETRIABLE),
                definition(name("p2"), kind.PIVOT),
            )
        )
    )

    # Introspection must agree with the ordering.
    plan = plan_cls((comp("a"), comp("b"), definition(name("p"), kind.PIVOT)))
    assert plan.index_of(name("a")) == 0
    assert plan.index_of(name("p")) == 2
    assert plan.get(name("b")).name.value == "b"
    _must_raise(lambda: plan.get(name("absent")))
    assert plan.artifact_steps() == ()
    assert plan.has_passed_pivot({name("p")})
    assert not plan.has_passed_pivot(set())
    assert plan.compensation_order(set()) == ()


def _must_raise(call) -> None:
    try:
        call()
    except Exception:
        return
    raise AssertionError("expected a refusal, got none")


PROBES = (
    _probe_step_machine,
    _probe_step_record,
    _probe_plan_shape,
    _probe_plan_boundaries,
    _probe_value_semantics,
    _probe_idempotency_key,
    _probe_attestation_outcome,
    _probe_step_name,
)


#: EQUIVALENT MUTANTS: changes that cannot alter behaviour, each with the reason
#: it cannot. Anything that survives and is NOT listed here fails the campaign,
#: so this list cannot grow by accident -- adding to it is a deliberate act with
#: a written justification, which is the only defensible way to handle
#: equivalents. (Detecting them in general is undecidable; the alternative to
#: naming them is a permanently depressed score that nobody reads.)
KNOWN_SURVIVORS: dict[str, str] = {
    # `slots` is a memory layout choice. It changes attribute storage, not any
    # observable behaviour these types promise.
    "sentinel.domain.execution:84 bool (True -> False)":
        "dataclass slots= on StepName: memory layout, not behaviour",
    "sentinel.domain.execution:206 bool (True -> False)":
        "dataclass slots= on StepRecord: memory layout, not behaviour",
    "sentinel.domain.execution:228 bool (True -> False)":
        "dataclass slots= on StepDefinition: memory layout, not behaviour",
    # Text inside an exception message. The raise still happens.
    "sentinel.domain.execution:185 boolop (Or -> And)":
        "the `or '(none)'` fallback formats an error message; the refusal is "
        "unaffected",
    # Line 276 builds the LIST OF NAMES for the duplicate-step error message.
    # The duplicate is already detected by `len(set(names)) != len(names)` on the
    # line above, which raises regardless; these only change which names the
    # message enumerates.
    "sentinel.domain.execution:276 boundary (1 -> 2)":
        "message-only: duplicates are detected by the set-length check above",
    "sentinel.domain.execution:276 boundary (1 -> 0)":
        "message-only: duplicates are detected by the set-length check above",
    "sentinel.domain.execution:276 comparison (Gt -> GtE)":
        "message-only: duplicates are detected by the set-length check above",
    "sentinel.domain.execution:276 comparison (Gt -> Lt)":
        "message-only: duplicates are detected by the set-length check above",
    # `len(pivots) > 2` would let a two-pivot plan past THIS check, but the
    # per-index loop below rejects the second pivot anyway: it sits after
    # pivot_index and is not RETRIABLE. Defence in depth, so the outer check is
    # redundant for exactly this case.
    "sentinel.domain.execution:283 boundary (1 -> 2)":
        "redundant with the per-index kind check, which rejects the second pivot",
    # `pivots[-1]` instead of `pivots[0]`. Reachable only when len(pivots) <= 1,
    # because the check above raises otherwise -- and for a single element the
    # two indices are the same element.
    "sentinel.domain.execution:289 boundary (0 -> -1)":
        "pivots[-1] == pivots[0] whenever len(pivots) <= 1, which the check "
        "above guarantees",
}


@pytest.fixture(scope="module")
def campaign():
    return run_mutation_campaign(TARGETS, PROBES)


def test_the_campaign_evaluates_a_meaningful_number_of_mutants(campaign):
    """Asserts on mutants EVALUATED, not generated.

    An earlier version checked `total`, which counts generated mutants. A loader
    bug meant 58 of 65 never ran, and the campaign cheerfully reported 100% over
    the remaining seven. Counting what was actually evaluated is the difference
    between a mutation score and a number.
    """
    evaluated = campaign.total - campaign.equivalent
    assert evaluated >= 40, (
        f"only {evaluated} of {campaign.total} mutants were evaluated "
        f"({campaign.equivalent} failed to load). {campaign.summary()}"
    )
    assert campaign.equivalent <= campaign.total * 0.15, (
        f"{campaign.equivalent}/{campaign.total} mutants failed to load; the "
        "runner is discarding most of the campaign"
    )


def test_the_mutation_score_meets_the_floor(campaign):
    """Scored against NON-EQUIVALENT mutants.

    Counting documented equivalents as failures produces a score that can never
    reach its target, which is how a mutation score becomes a number everyone
    ignores. Counting them as kills would be dishonest. Excluding them, with
    every exclusion carrying a written reason in `KNOWN_SURVIVORS`, is the only
    version of this metric that stays meaningful — and
    `test_every_survivor_is_accounted_for` is what stops the exclusion list
    becoming a place to hide real gaps.
    """
    evaluated = campaign.total - campaign.equivalent
    unexplained = [m for m in campaign.survived if m.label not in KNOWN_SURVIVORS]
    documented = len(campaign.survived) - len(unexplained)
    non_equivalent = evaluated - documented
    adjusted = campaign.killed / non_equivalent if non_equivalent else 1.0

    assert adjusted >= MINIMUM_SCORE, (
        f"adjusted mutation score {adjusted:.1%} is below the {MINIMUM_SCORE:.0%} "
        f"floor over {non_equivalent} non-equivalent mutants "
        f"(raw {campaign.score:.1%}). {campaign.summary()}\n\n"
        "Unexplained survivors:\n"
        + "\n".join(f"  {m.label}" for m in unexplained[:25])
    )


def test_the_raw_score_stays_visible(campaign):
    """The unadjusted number, so the equivalent list cannot hide a decline.

    If the raw score falls while the adjusted one holds, it means the exclusion
    list is doing the work instead of the probes.
    """
    assert campaign.score >= 0.80, (
        f"raw mutation score {campaign.score:.1%} has fallen far enough that "
        f"`KNOWN_SURVIVORS` is carrying the result. {campaign.summary()}"
    )


def test_every_survivor_is_accounted_for(campaign):
    """A survivor is a change no probe noticed. Each needs a stated reason.

    This is the part that stops a mutation score being a number nobody reads: an
    unexplained survivor fails the build, so the only way to keep the suite green
    is to either kill it or write down why it cannot be killed.
    """
    unexplained = [m for m in campaign.survived if m.label not in KNOWN_SURVIVORS]
    assert not unexplained, (
        f"{len(unexplained)} unexplained surviving mutant(s). Either add a probe "
        f"that kills them, or record why they are equivalent:\n"
        + "\n".join(f"  {m.label}" for m in unexplained[:25])
    )


def test_the_runner_itself_can_report_a_survivor():
    """Guard against a vacuous campaign.

    If every probe were a no-op, the score would be 0% and this would catch it;
    if the runner never loaded a mutant, `total` would be 0 and the first test
    would. This asserts the middle case: a deliberately blind probe lets mutants
    through, so the machinery genuinely distinguishes.
    """
    blind = run_mutation_campaign(TARGETS, probes=(lambda module: None,))
    assert blind.total > 0
    assert blind.killed == 0, "a probe that checks nothing killed a mutant"
    assert len(blind.survived) == blind.total - blind.equivalent


def test_the_campaign_leaves_sys_modules_exactly_as_it_found_it():
    """A leaked mutant poisons every later import in the session.

    If `sentinel.domain.execution` were left absent or replaced, subsequent
    imports would get a fresh, non-identical module -- and enum members and
    isinstance checks would compare unequal across unrelated suites. That
    presents as flakiness a long way from its cause, so it is asserted directly.
    """
    import sys

    before = {module: sys.modules.get(module) for _path, module in TARGETS}
    run_mutation_campaign(TARGETS, PROBES)
    for name, original in before.items():
        assert sys.modules.get(name) is original, (
            f"the campaign left {name} replaced or missing in sys.modules"
        )
