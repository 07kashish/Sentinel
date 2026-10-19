"""The sequence detector had no labelled dataset at all.

Its rules were written from reasoning about attacker behaviour -- the right way
to write them, and no way to measure them: a rule set evaluated only against
the examples that inspired it reports its own definition back.

These tests run the REAL detector over the corpus, and spend most of their
effort on the corpus's own honesty: that it is labelled synthetic, that its
hard negatives exist, and that a malicious case is only satisfied by the rule
it names rather than by anything firing.
"""

from __future__ import annotations

import pytest

from evaluation.sequence_corpus import (
    IS_SYNTHETIC,
    SEQUENCE_CASES,
    SequenceCase,
    counts_by_category,
    evaluate,
    summary,
)
from sentinel.domain.execution_graph import ExecutionGraph, ExecutionNode
from sentinel.domain.sequences import detect_sequences


def _detect(actions):
    """Run the real detector over a bare action list.

    Builds the execution graph the detector actually consumes -- evaluating a
    flat list would test a code path no deployment uses.
    """
    nodes = []
    previous = ""
    for index, action in enumerate(actions):
        node_id = f"n{index}"
        nodes.append(
            ExecutionNode(
                tenant_id="eval",
                event_id=node_id,
                agent_id="eval-agent",
                session_id="eval-session",
                parent_id=previous,
                action=action,
                occurred_at=f"2026-09-03T10:{index:02d}:00Z",
            )
        )
        previous = node_id
    graph = ExecutionGraph(
        tenant_id="eval", session_id="eval-session", nodes=tuple(nodes)
    )
    # `.rule.name`, not `.rule`: a SequenceMatch carries the rule OBJECT,
    # and comparing a name string against it silently never matches --
    # every malicious case would report as undetected.
    return [match.rule.name for match in detect_sequences(graph)]


# ── the detector, over the corpus ────────────────────────────────────────────


def test_the_detector_agrees_with_every_label_it_is_expected_to():
    """The regression gate. A rule change that stops matching a trace, or
    starts matching a benign one, fails here.
    """
    outcomes = evaluate(_detect)
    report = summary(outcomes)

    assert not report.unexpected_failures, (
        "cases the detector got wrong that are not marked as known gaps: "
        + ", ".join(o.case.case_id for o in report.unexpected_failures)
        + f"\nper-category: {counts_by_category(outcomes)}"
    )


def test_the_canonical_attacks_are_detected():
    outcomes = {o.case.case_id: o for o in evaluate(_detect)}

    assert outcomes["exfil_canonical"].correct
    assert outcomes["privilege_canonical"].correct


def test_intervening_work_does_not_hide_the_sequence():
    """An attacker with a single unrelated call would otherwise defeat the
    detector.
    """
    outcomes = {o.case.case_id: o for o in evaluate(_detect)}

    assert outcomes["exfil_with_intervening_work"].correct


def test_a_vendor_rename_does_not_defeat_the_detector():
    """`canonical_action` is the part an attacker attacks: a detector matching
    raw action strings loses to `get_secret` instead of `credential_access`.
    """
    outcomes = {o.case.case_id: o for o in evaluate(_detect)}

    assert outcomes["privilege_via_synonyms"].correct


def test_the_wrong_order_is_not_an_attack():
    """A rule that fired here would be matching a set, not a sequence."""
    outcomes = {o.case.case_id: o for o in evaluate(_detect)}

    assert outcomes["wrong_order_upload_first"].correct
    assert outcomes["wrong_order_upload_first"].fired_rules == ()


def test_a_prefix_of_a_rule_does_not_fire_it():
    """Firing on a prefix would flag every backup job."""
    outcomes = {o.case.case_id: o for o in evaluate(_detect)}

    assert outcomes["prefix_only"].fired_rules == ()


def test_ordinary_tool_use_fires_nothing():
    """If this fires, the detector is matching activity rather than pattern."""
    outcomes = {o.case.case_id: o for o in evaluate(_detect)}

    assert outcomes["ordinary_tool_use"].fired_rules == ()


def test_using_a_credential_without_escalating_fires_nothing():
    """Reading a credential and using it is what every deployed agent does
    every minute.
    """
    outcomes = {o.case.case_id: o for o in evaluate(_detect)}

    assert outcomes["login_without_privilege_change"].fired_rules == ()


# ── the known gap, kept rather than deleted ─────────────────────────────────


def test_the_backup_false_positive_is_recorded_as_a_known_gap():
    """THE most likely false positive in production, kept in the corpus.

    A backup writes to object storage, which canonicalises to
    external_upload, so it matches staged_exfiltration. The rule cannot
    distinguish a backup from an exfiltration without knowing the destination
    is the estate's own bucket. Deleting the case would improve the headline
    number and hide the product's most likely operational complaint.
    """
    case = next(c for c in SEQUENCE_CASES if c.case_id == "backup_job")

    assert case.known_gap
    assert not case.malicious
    assert "most likely false positive" in case.rationale


def test_a_known_gap_is_not_counted_as_a_regression():
    """A headline that lumped known gaps in with regressions would hide the
    one that is new.
    """
    outcomes = evaluate(_detect)
    report = summary(outcomes)

    assert report.known_gaps
    assert all(o.case.known_gap for o in outcomes if not o.correct)


# ── the corpus's own discipline ───────────────────────────────────────────────


def test_a_malicious_case_is_only_satisfied_by_the_rule_it_names():
    """"Something should fire" is not a testable expectation.

    A case satisfied by any match would pass while the detector fired for
    entirely the wrong reason -- which is how a rule set drifts into
    recognising the corpus rather than the behaviour.
    """
    from evaluation.sequence_corpus import Outcome

    case = next(c for c in SEQUENCE_CASES if c.malicious)
    wrong_rule = Outcome(case=case, fired_rules=("some_other_rule",))

    assert not wrong_rule.correct


def test_a_malicious_case_must_name_an_expected_rule():
    with pytest.raises(ValueError) as raised:
        SequenceCase(
            case_id="x",
            malicious=True,
            category="c",
            actions=("a",),
            rationale="r",
        )

    assert "not a testable expectation" in str(raised.value)


def test_a_benign_case_naming_a_rule_is_refused():
    with pytest.raises(ValueError) as raised:
        SequenceCase(
            case_id="x",
            malicious=False,
            category="c",
            actions=("a",),
            rationale="r",
            expected_rule="staged_exfiltration",
        )

    assert "contradicts its label" in str(raised.value)


def test_every_case_carries_a_rationale():
    """A labelled corpus whose labels carry no reasoning is a set of
    assertions nobody can argue with, and the argument is where the value is.
    """
    for case in SEQUENCE_CASES:
        assert case.rationale.strip(), case.case_id


def test_a_case_with_no_rationale_is_refused():
    with pytest.raises(ValueError) as raised:
        SequenceCase(
            case_id="x", malicious=False, category="c", actions=("a",), rationale=" "
        )

    assert "nobody can argue with" in str(raised.value)


def test_the_corpus_contains_hard_negatives():
    """Any corpus can flatter a detector by pairing obvious attacks with
    obviously benign traffic. This codebase measured a soft detector firing on
    51.7% of ordinary tool calls -- a corpus without lookalikes would have
    reported it as excellent.
    """
    lookalikes = [c for c in SEQUENCE_CASES if c.category == "benign_lookalike"]

    assert len(lookalikes) >= 4
    assert len(lookalikes) >= len([c for c in SEQUENCE_CASES if c.malicious]), (
        "there are fewer hard negatives than attacks, so the corpus is easier "
        "than the problem"
    )


def test_case_ids_are_unique():
    identifiers = [c.case_id for c in SEQUENCE_CASES]

    assert len(identifiers) == len(set(identifiers))


# ── the synthetic caveat, everywhere it needs to be ─────────────────────────


def test_the_corpus_declares_itself_synthetic():
    """A constant rather than a comment, so nothing can present this as field
    data by omission.
    """
    assert IS_SYNTHETIC is True


def test_the_summary_leads_with_the_synthetic_caveat():
    """This document will be pasted somewhere the surrounding paragraph is
    not.
    """
    document = summary(evaluate(_detect)).as_dict()
    keys = list(document)

    assert keys[0] == "synthetic"
    assert keys[1] == "limits"


def test_the_summary_never_uses_the_word_accuracy_or_recall():
    """Those words carry a claim about generalisation this corpus cannot
    support. "Agreement" is what is actually being counted.
    """
    document = summary(evaluate(_detect)).as_dict()

    assert "corpus_agreement" in document
    for forbidden in ("accuracy", "recall", "precision", "f1"):
        assert forbidden not in document, (
            f"{forbidden!r} appears as a key, which claims generalisation from "
            "a hand-written corpus"
        )


def test_the_limits_say_the_value_is_regression_not_validation():
    limits = summary(evaluate(_detect)).as_dict()["limits"]

    assert "SYNTHETIC CORPUS" in limits
    assert "not a detection rate for production traffic" in limits
    assert "REGRESSION, not validation" in limits
    assert "nobody wrote" in limits


def test_the_module_states_the_corpus_can_be_gamed_by_editing_it():
    """Left unsaid, somebody improves the number by deleting a row."""
    import inspect

    from evaluation import sequence_corpus

    doc = " ".join((inspect.getdoc(sequence_corpus) or "").split())

    assert "gamed by editing the corpus" in doc
    assert "reports its own definition back" in doc


# ── the traces are chained, because the detector reads a graph ──────────────


def test_the_events_are_chained_parent_to_child():
    """An unchained list of events is a SET, and a corpus that submitted one
    would be evaluating a different code path from the one that runs.
    """
    case = next(c for c in SEQUENCE_CASES if len(c.actions) > 2)
    events = case.as_events()

    assert events[0]["parentEventId"] == ""
    for previous, event in zip(events, events[1:]):
        assert event["parentEventId"] == previous["eventId"]


def test_every_case_shares_one_session_per_case():
    """Two cases in one session would let one contaminate the other -- the
    exact defect that made the attack campaign disagree with its own gate.
    """
    sessions = {c.case_id: {e["sessionId"] for e in c.as_events()} for c in SEQUENCE_CASES}

    for case_id, values in sessions.items():
        assert len(values) == 1, case_id
    assert len({next(iter(v)) for v in sessions.values()}) == len(SEQUENCE_CASES)


def test_per_category_failures_are_reported_separately():
    """An overall figure hides a detector that handles exfiltration perfectly
    and privilege escalation not at all.
    """
    from evaluation.sequence_corpus import Outcome

    broken = tuple(
        Outcome(case=case, fired_rules=())
        for case in SEQUENCE_CASES
        if case.malicious
    )

    failures = counts_by_category(broken)
    expected = {case.category for case in SEQUENCE_CASES if case.malicious}
    assert set(failures) == expected


def test_the_module_holds_no_mutable_state():
    import types

    from evaluation import sequence_corpus

    mutable = [
        name
        for name, value in vars(sequence_corpus).items()
        if not name.startswith("__")
        and isinstance(value, (dict, list, set))
        and not isinstance(value, (frozenset, types.MappingProxyType))
    ]
    assert not mutable, f"module-level mutable state: {mutable}"
