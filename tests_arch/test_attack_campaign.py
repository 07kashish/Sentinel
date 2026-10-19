"""An attack that failed to launch looks exactly like one that was blocked.

Both produce "the bad thing did not happen". A misconfigured harness, an app
that would not start, a typo in a URL, an expired credential -- every one
yields the same observable as a working defence and a report full of green
rows. That is how a red-team exercise becomes a marketing document.

So nearly every test here is one question: can an uninformative outcome be
laundered into a defence?
"""

from __future__ import annotations

import pytest

from sentinel.domain.attack_campaign import (
    MIN_CASES_TO_QUOTE_A_RATE,
    AttackCase,
    AttackOutcome,
    CampaignResult,
    RegressionKind,
    compare_to_baseline,
    summarise,
)


#: What each outcome implies was observed. Kept here so the helper cannot
#: build a case whose summary outcome and graded observations disagree -- the
#: exact inconsistency `case_from_observations` exists to prevent in
#: production code.
_OBSERVED = {
    AttackOutcome.DEFENDED: (True, True),
    AttackOutcome.DETECTED_NOT_PREVENTED: (True, False),
    AttackOutcome.NOTHING_OBSERVED: (False, False),
    AttackOutcome.INCONCLUSIVE: (False, False),
    AttackOutcome.NOT_RUN: (False, False),
}


def _case(
    case_id: str = "c1",
    outcome: AttackOutcome = AttackOutcome.DEFENDED,
    *,
    detection: bool = True,
    prevention: bool = True,
    technique: str = "AML.T0051",
) -> AttackCase:
    observed_detection, observed_prevention = _OBSERVED[outcome]
    return AttackCase(
        case_id=case_id,
        technique=technique,
        outcome=outcome,
        expected_detection=detection,
        expected_prevention=prevention,
        rationale="tracked posture for this technique",
        observed_detection=observed_detection,
        observed_prevention=observed_prevention,
    )


def _result(*cases: AttackCase, **kwargs) -> CampaignResult:
    return CampaignResult(
        commit="abc123", ran_at="2026-09-03T00:00:00Z", cases=cases, **kwargs
    )


def _many(count: int, outcome: AttackOutcome = AttackOutcome.DEFENDED):
    return tuple(_case(f"c{i}", outcome) for i in range(count))


# ── the laundering routes, all closed ────────────────────────────────────────


def test_a_case_that_did_not_run_is_not_a_defence():
    case = _case(outcome=AttackOutcome.NOT_RUN)

    assert not case.is_informative
    assert not case.met_expectation


def test_an_inconclusive_case_is_not_a_defence():
    """The app errored, the harness misfired, the response was unparseable.
    None of that is the product defending itself.
    """
    case = _case(outcome=AttackOutcome.INCONCLUSIVE)

    assert not case.is_informative
    assert not case.met_expectation


def test_no_rate_is_quoted_while_any_case_produced_no_evidence():
    """THE function somebody will want on a slide, and the reason it refuses.

    A rate over an unknown denominator is not a measurement -- it is a shape
    that looks like one.
    """
    cases = _many(MIN_CASES_TO_QUOTE_A_RATE - 1) + (
        _case("broken", AttackOutcome.INCONCLUSIVE),
    )
    result = _result(*cases)

    assert result.defence_rate() is None


def test_the_refusal_names_the_cases_that_broke():
    """An empty cell invites somebody to compute the ratio from the counts,
    which is the exact mistake this module is arranged to prevent.
    """
    result = _result(
        _case("good"), _case("broken-one", AttackOutcome.NOT_RUN)
    )
    reason = result.rate_refusal_reason()

    assert "broken-one" in reason
    assert "failed to launch" in reason
    assert "no rate is quoted" in reason


def test_a_rate_is_quoted_once_there_is_enough_clean_evidence():
    """The refusal must not be so eager that the metric never exists."""
    result = _result(*_many(MIN_CASES_TO_QUOTE_A_RATE))

    assert result.defence_rate() == 1.0


def test_too_few_cases_refuses_even_when_all_are_clean():
    """3/3 is not 100%. It is a very wide interval that reads as certainty."""
    result = _result(*_many(3))

    assert result.defence_rate() is None
    assert "below the" in result.rate_refusal_reason()


def test_the_minimum_matches_the_evaluation_module():
    """Two thresholds for "enough evidence" would drift into disagreeing."""
    # Imported here rather than in the domain module on purpose: the
    # architecture rule points dependencies inward, and sentinel.domain must
    # not reach out to a sibling top-level package. So the constant is
    # duplicated and THIS test is what keeps the two from drifting.
    from evaluation.intervals import MIN_SAMPLES_TO_QUOTE

    assert MIN_CASES_TO_QUOTE_A_RATE == MIN_SAMPLES_TO_QUOTE


def test_uninformative_cases_are_counted_as_unmet_expectations():
    """Filtering them out is how a campaign with half its cases broken reports
    a clean sweep.
    """
    result = _result(_case("a"), _case("b", AttackOutcome.NOT_RUN))

    assert [c.case_id for c in result.unmet_expectations] == ["b"]


def test_the_summary_leads_with_what_is_wrong():
    """A summary opening with the pass count gets quoted without the rest of
    the sentence.
    """
    result = _result(*_many(40), _case("broken", AttackOutcome.INCONCLUSIVE))
    line = summarise(result)

    assert line.startswith("UNVERIFIED")
    assert "no defence rate" in line


def test_the_serialised_form_leads_with_the_refusal_and_the_coverage_gap():
    result = _result(
        _case(), techniques_not_attempted=("AML.T0043",)
    )
    document = result.as_dict()

    assert next(iter(document)) == "rate_refusal_reason"
    assert list(document)[1] == "techniques_not_attempted"


def test_the_uninformative_set_cannot_be_widened_by_a_caller():
    """Widening it is precisely how NOT_RUN would become DEFENDED."""
    from sentinel.domain.attack_campaign import UNINFORMATIVE

    assert isinstance(UNINFORMATIVE, frozenset)
    assert UNINFORMATIVE == {
        AttackOutcome.INCONCLUSIVE,
        AttackOutcome.NOT_RUN,
    }


# ── detection and prevention stay apart ──────────────────────────────────────


def test_detected_but_not_prevented_is_its_own_outcome():
    """Sentinel's real posture for correlation-driven cases.

    Collapsing it into BREACHED makes the product look worse than it is;
    collapsing it into DEFENDED makes it look better. Both are lies and the
    second is the dangerous one.
    """
    case = _case(
        outcome=AttackOutcome.DETECTED_NOT_PREVENTED,
        detection=True,
        prevention=False,
    )

    assert case.is_informative
    assert case.met_expectation


def test_a_case_expecting_prevention_is_not_met_by_detection_alone():
    case = _case(
        outcome=AttackOutcome.DETECTED_NOT_PREVENTED,
        detection=True,
        prevention=True,
    )

    assert not case.met_expectation


def test_preventing_more_than_promised_is_still_a_mismatch():
    """Strict on BOTH axes, matching the pytest gate.

    This test previously asserted the opposite -- that over-prevention is a
    bonus. It is not, and the red-team module says why: a change that starts
    blocking a tracked case must "show up as a diff in this file and get
    argued about, rather than being discovered by a customer whose agent
    stopped working". Grading it as a pass would hide exactly that diff.

    Sentinel deliberately detects far more than it prevents, so a case
    silently moving into the prevented column is a product behaviour change,
    not an improvement in a metric.
    """
    case = _case(
        outcome=AttackOutcome.DEFENDED, detection=True, prevention=False
    )

    assert not case.met_expectation
    assert case.observed_prevention and not case.expected_prevention


def test_a_breach_never_meets_an_expectation_of_detection():
    case = _case(
        outcome=AttackOutcome.NOTHING_OBSERVED, detection=True, prevention=False
    )

    assert not case.met_expectation
    assert case.breached


def test_a_negative_case_that_correctly_does_nothing_is_not_a_breach():
    """The tracked table deliberately contains benign sequences that must NOT
    raise an incident. For those, nothing happening is the desired result.

    Recording it as a breach would print "BREACHED / met expectation" on one
    row, which is either alarming or meaningless depending on which column the
    reader trusts. Hence the observation and the judgement are separate.
    """
    case = _case(
        outcome=AttackOutcome.NOTHING_OBSERVED,
        detection=False,
        prevention=False,
    )

    assert not case.breached
    assert case.met_expectation


def test_an_uninformative_case_is_not_reported_as_a_breach():
    """A case that never ran did not breach anything. It produced no evidence,
    and calling it a breach would be as wrong as calling it a defence.
    """
    for outcome in (AttackOutcome.NOT_RUN, AttackOutcome.INCONCLUSIVE):
        case = _case(outcome=outcome, detection=True, prevention=True)
        assert not case.breached
        assert not case.met_expectation


def test_the_report_counts_breaches_separately_from_unmet_expectations():
    """They differ: a case expecting prevention that was only detected is an
    unmet expectation and not a breach.
    """
    document = _result(
        _case("only-detected", AttackOutcome.DETECTED_NOT_PREVENTED),
        _case("real-breach", AttackOutcome.NOTHING_OBSERVED),
    ).as_dict()

    assert document["unmet_expectation_count"] == 2
    assert document["breached_count"] == 1


def test_expecting_prevention_without_detection_is_refused():
    """An action refused with no record leaves an operator unable to tell the
    refusal happened.
    """
    with pytest.raises(ValueError) as raised:
        _case(detection=False, prevention=True)
    assert "unable to tell" in str(raised.value)


# ── the tracked table's own discipline ───────────────────────────────────────


def test_a_case_with_no_rationale_is_refused():
    """A row expecting no prevention with no stated reason is
    indistinguishable from an oversight, and the value of the table is that a
    deliberate gap and a forgotten one look different.
    """
    with pytest.raises(ValueError) as raised:
        AttackCase(
            case_id="c",
            technique="t",
            outcome=AttackOutcome.NOTHING_OBSERVED,
            expected_detection=False,
            expected_prevention=False,
            rationale="   ",
        )
    assert "oversight" in str(raised.value)


def test_a_case_with_no_technique_is_refused():
    """It could not be counted against a coverage denominator."""
    with pytest.raises(ValueError) as raised:
        _case(technique=" ")
    assert "coverage denominator" in str(raised.value)


def test_a_case_with_no_id_is_refused():
    with pytest.raises(ValueError):
        _case(case_id="  ")


def test_techniques_nobody_attempted_are_carried_in_the_result():
    """Forty passing cases say nothing about the forty-first technique."""
    result = _result(_case(), techniques_not_attempted=("AML.T0043", "ASI10"))

    assert result.as_dict()["techniques_not_attempted"] == [
        "AML.T0043",
        "ASI10",
    ]


def test_the_limits_travel_inside_the_payload():
    """This gets pasted into a slide, and the surrounding caveat is stripped."""
    limits = _result(_case()).as_dict()["limits"]

    assert "NOT defences" in limits
    assert "failed to launch" in limits
    assert "techniques_not_attempted" in limits


# ── regression, which is the point of a ledger ───────────────────────────────


def test_a_lost_defence_is_a_regression():
    """The finding that should stop a release."""
    regressions = compare_to_baseline(
        baseline=(_case("c1", AttackOutcome.DEFENDED),),
        current=(_case("c1", AttackOutcome.DETECTED_NOT_PREVENTED),),
    )

    assert len(regressions) == 1
    assert regressions[0].kind is RegressionKind.DEFENCE_LOST
    assert regressions[0].was is AttackOutcome.DEFENDED


def test_losing_detection_entirely_is_reported_as_such():
    """A case whose recorded posture is detect-but-do-not-prevent, that stops
    detecting.

    The baseline case must have MET its expectation, or the new rule correctly
    declines to call it a regression -- a case that was already failing is real
    but not new, and reporting it every run buries the one that changed.
    """
    posture = dict(detection=True, prevention=False)
    was = _case("c1", AttackOutcome.DETECTED_NOT_PREVENTED, **posture)
    now = _case("c1", AttackOutcome.NOTHING_OBSERVED, **posture)

    assert was.met_expectation and not now.met_expectation
    regressions = compare_to_baseline(baseline=(was,), current=(now,))

    assert regressions[0].kind is RegressionKind.DETECTION_LOST


def test_a_case_deleted_from_the_suite_is_a_regression():
    """Somebody deleting a failing case is exactly what this watches for, so
    silence would defeat the purpose.
    """
    regressions = compare_to_baseline(
        baseline=(_case("c1", AttackOutcome.DEFENDED),), current=()
    )

    assert regressions[0].kind is RegressionKind.EVIDENCE_LOST
    assert regressions[0].now is AttackOutcome.NOT_RUN


def test_a_case_that_stopped_producing_evidence_is_a_regression():
    """The product may be fine. The evidence is not, and treating a broken
    case as unchanged is how a suite quietly stops testing.
    """
    regressions = compare_to_baseline(
        baseline=(_case("c1", AttackOutcome.DEFENDED),),
        current=(_case("c1", AttackOutcome.INCONCLUSIVE),),
    )

    assert regressions[0].kind is RegressionKind.EVIDENCE_LOST


def test_a_negative_case_that_stops_being_falsely_detected_is_not_a_regression():
    """The false positive that corrected this rule.

    `out_of_order_steps_are_not_an_attack` expects NO detection. A contaminated
    baseline recorded it as detected; the fixed run recorded nothing. Ranking
    by defence strength called that DETECTION_LOST -- a fix reported as a
    regression -- because it treated every case as an attack that should be
    stopped.
    """
    negative = dict(detection=False, prevention=False)
    was_wrong = _case("neg", AttackOutcome.DETECTED_NOT_PREVENTED, **negative)
    now_right = _case("neg", AttackOutcome.NOTHING_OBSERVED, **negative)

    assert not was_wrong.met_expectation
    assert now_right.met_expectation
    assert compare_to_baseline(baseline=(was_wrong,), current=(now_right,)) == ()


def test_a_negative_case_that_starts_being_falsely_detected_IS_a_regression():
    """The other direction of the same rule.

    A detector that begins firing on ordinary work is a real regression, and
    the honest posture table is what makes it visible.
    """
    negative = dict(detection=False, prevention=False)
    was_right = _case("neg", AttackOutcome.NOTHING_OBSERVED, **negative)
    now_wrong = _case("neg", AttackOutcome.DETECTED_NOT_PREVENTED, **negative)

    regressions = compare_to_baseline(baseline=(was_right,), current=(now_wrong,))

    assert len(regressions) == 1
    assert regressions[0].case_id == "neg"


def test_a_case_that_was_already_failing_is_not_reported_twice():
    """It did not meet its expectation before and still does not. Real, and
    not NEW -- reporting it as a regression on every run would bury the one
    case that changed this release.
    """
    failing = _case("f", AttackOutcome.NOTHING_OBSERVED, detection=True)

    assert compare_to_baseline(baseline=(failing,), current=(failing,)) == ()


def test_an_improvement_is_not_a_regression():
    assert (
        compare_to_baseline(
            baseline=(_case("c1", AttackOutcome.NOTHING_OBSERVED),),
            current=(_case("c1", AttackOutcome.DEFENDED),),
        )
        == ()
    )


def test_an_unchanged_case_is_not_a_regression():
    assert (
        compare_to_baseline(
            baseline=(_case("c1", AttackOutcome.DEFENDED),),
            current=(_case("c1", AttackOutcome.DEFENDED),),
        )
        == ()
    )


def test_a_case_that_never_produced_evidence_has_nothing_to_regress_from():
    """It was broken before and is informative now: an improvement."""
    assert (
        compare_to_baseline(
            baseline=(_case("c1", AttackOutcome.NOT_RUN),),
            current=(_case("c1", AttackOutcome.NOTHING_OBSERVED),),
        )
        == ()
    )


def test_a_new_case_is_not_a_regression():
    assert (
        compare_to_baseline(
            baseline=(), current=(_case("new", AttackOutcome.NOTHING_OBSERVED),)
        )
        == ()
    )


def test_regressions_are_ordered_deterministically():
    baseline = (
        _case("z", AttackOutcome.DEFENDED),
        _case("a", AttackOutcome.DEFENDED),
    )
    regressions = compare_to_baseline(baseline=baseline, current=())

    assert [r.case_id for r in regressions] == ["a", "z"]


# ── serialisation discipline ─────────────────────────────────────────────────


def test_the_document_contains_no_floats():
    """The canonical JSON form refuses floats, so a campaign result carrying
    one could not be signed -- and a result nobody can sign is one nobody can
    rely on. The rate is emitted as a fixed-precision string.
    """

    def walk(value, path="root"):
        if isinstance(value, float):
            raise AssertionError(f"float at {path}")
        if isinstance(value, dict):
            for key, item in value.items():
                walk(item, f"{path}.{key}")
        elif isinstance(value, (list, tuple)):
            for index, item in enumerate(value):
                walk(item, f"{path}[{index}]")

    walk(_result(*_many(MIN_CASES_TO_QUOTE_A_RATE)).as_dict())


def test_the_rate_is_serialised_as_a_string_when_it_exists():
    document = _result(*_many(MIN_CASES_TO_QUOTE_A_RATE)).as_dict()

    assert document["defence_rate"] == "1.0000"


def test_the_rate_is_null_rather_than_zero_when_refused():
    """Zero would read as "nothing was defended", which is the opposite of
    "we cannot tell".
    """
    document = _result(_case("broken", AttackOutcome.NOT_RUN)).as_dict()

    assert document["defence_rate"] is None


def test_the_census_lists_every_outcome_even_at_zero():
    """A missing key reads as "not measured"."""
    census = _result(_case()).as_dict()["outcome_census"]

    assert set(census) == {o.value for o in AttackOutcome}


def test_the_module_holds_no_mutable_state():
    import types

    from sentinel.domain import attack_campaign

    mutable = [
        name
        for name, value in vars(attack_campaign).items()
        if not name.startswith("__")
        and isinstance(value, (dict, list, set))
        and not isinstance(value, (frozenset, types.MappingProxyType))
    ]
    assert not mutable, f"module-level mutable state: {mutable}"


def test_the_constructor_derives_the_summary_from_the_observations():
    """One place reconciles the two representations, so they cannot disagree."""
    from sentinel.domain.attack_campaign import case_from_observations

    defended = case_from_observations(
        case_id="c",
        technique="t",
        expected_detection=True,
        expected_prevention=True,
        rationale="r",
        detected=True,
        prevented=True,
        errored=False,
    )
    assert defended.outcome is AttackOutcome.DEFENDED
    assert defended.met_expectation


def test_an_error_forces_the_observations_to_false():
    """A crash says nothing about the defences, so the observations must not
    survive as if they were measurements -- a later reader would grade against
    them.
    """
    from sentinel.domain.attack_campaign import case_from_observations

    case = case_from_observations(
        case_id="c",
        technique="t",
        expected_detection=True,
        expected_prevention=True,
        rationale="r",
        detected=True,
        prevented=True,
        errored=True,
    )

    assert case.outcome is AttackOutcome.INCONCLUSIVE
    assert not case.observed_detection
    assert not case.observed_prevention
    assert not case.met_expectation
