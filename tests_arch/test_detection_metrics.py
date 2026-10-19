"""Detection quality cannot be reported as real-world from a synthetic corpus.

WHAT THIS GUARDS
----------------
`REAL_WORLD_DETECTION_METRICS` is an external gate because every number this
system has about detection quality comes from a corpus somebody wrote. The
numbers are real; what they describe is a corpus.

The existing harness says so in a docstring, and a docstring does not travel
with a number into a slide. So the provenance is a FIELD, `real_world` is
derived from it, and `test_no_synthetic_corpus_can_claim_real_world` is the
test that matters most.
"""

from __future__ import annotations

import pytest

from sentinel.domain.detection_metrics import (
    MINIMUM_CORPUS,
    CorpusProvenance,
    DetectionMeasurement,
    measure_detection,
)

BIG = dict(
    true_positives=90,
    false_positives=10,
    true_negatives=880,
    false_negatives=20,
)


def _measure(provenance, **overrides):
    counts = dict(BIG)
    counts.update(overrides)
    return measure_detection(provenance=provenance, **counts)


# ── the claim is gated on provenance ───────────────────────────────────────


@pytest.mark.parametrize(
    "provenance",
    [CorpusProvenance.SYNTHETIC, CorpusProvenance.UNKNOWN, "not-a-provenance"],
)
def test_no_synthetic_corpus_can_claim_real_world(provenance):
    """THE load-bearing test. A high precision on written examples means the
    classifier separates the cases somebody chose.
    """
    measurement = _measure(provenance)

    assert measurement.real_world is False
    assert "describe the corpus" in measurement.claim
    assert "REAL_WORLD_DETECTION_METRICS remains open" in measurement.claim


def test_a_production_labelled_corpus_can():
    """THE control. Without it every assertion above would be satisfied by a
    module that never permits a real-world claim, which would make the field
    decorative.
    """
    measurement = _measure(CorpusProvenance.PRODUCTION_LABELLED)

    assert measurement.real_world is True
    assert "supports a real-world claim" in measurement.claim


def test_unknown_provenance_is_not_silently_treated_as_either():
    """The most dangerous corpus is the one that looks like data and might be
    last year's test set.
    """
    assert CorpusProvenance.UNKNOWN.supports_real_world_claim is False
    assert "might be last year" in CorpusProvenance.UNKNOWN.explanation


def test_an_unrecognised_provenance_becomes_unknown_rather_than_raising():
    """Refusing outright would push a caller toward deleting the field instead
    of recording the doubt.
    """
    measurement = _measure("prod")  # not the enum's spelling

    assert measurement.provenance is CorpusProvenance.UNKNOWN
    assert measurement.real_world is False


# ── a small corpus is not quotable whatever its provenance ────────────────


def test_a_small_production_corpus_still_cannot_be_quoted():
    """Provenance is necessary, not sufficient. Twelve labelled examples from
    production describe twelve events.
    """
    measurement = measure_detection(
        provenance=CorpusProvenance.PRODUCTION_LABELLED,
        true_positives=5,
        false_positives=1,
        true_negatives=5,
        false_negatives=1,
    )

    assert measurement.sufficient is False
    assert measurement.real_world is False
    assert "NOT EXTRAPOLABLE" in measurement.claim


def test_an_insufficient_corpus_still_reports_the_observation_as_a_finding():
    """"NOT QUOTABLE" alone invited dismissing a real signal. A detector
    firing on 26 of 60 ordinary tool names is serious whatever the corpus
    size -- it takes one clear counterexample to show a detector misfires.
    The limit is on EXTRAPOLATION, not on whether the observation counts.
    """
    measurement = measure_detection(
        provenance=CorpusProvenance.SYNTHETIC,
        true_positives=0, false_positives=26,
        true_negatives=34, false_negatives=0,
    )

    assert measurement.sufficient is False
    assert "still a real finding" in measurement.claim
    assert measurement.false_positive_rate == pytest.approx(26 / 60)


def test_the_corpus_floor_is_stated_in_the_refusal():
    measurement = _measure(
        CorpusProvenance.PRODUCTION_LABELLED,
        true_positives=1,
        false_positives=0,
        true_negatives=1,
        false_negatives=0,
    )

    assert str(MINIMUM_CORPUS) in measurement.claim


# ── the rates refuse to invent a number ───────────────────────────────────


def test_precision_over_no_positive_predictions_is_none_not_zero():
    """0/0 as 0.0 reads as a detector that is always wrong and as 1.0 as one
    that is never wrong. Both are inventions, and this codebase has shipped
    the 0/0-as-0-per-cent bug once already.
    """
    measurement = _measure(
        CorpusProvenance.SYNTHETIC,
        true_positives=0,
        false_positives=0,
        true_negatives=900,
        false_negatives=100,
    )

    assert measurement.precision is None
    assert measurement.recall == pytest.approx(0.0)


def test_recall_over_no_actual_positives_is_none():
    measurement = _measure(
        CorpusProvenance.SYNTHETIC,
        true_positives=0,
        false_positives=50,
        true_negatives=950,
        false_negatives=0,
    )

    assert measurement.recall is None


def test_the_false_positive_rate_is_reported_separately_from_precision():
    """Alert fatigue is measured by the false-positive rate, not precision:
    a detector can have excellent precision and still bury an operator if the
    negative class is enormous.
    """
    measurement = _measure(CorpusProvenance.PRODUCTION_LABELLED)

    assert measurement.precision == pytest.approx(0.9)
    assert measurement.false_positive_rate == pytest.approx(10 / 890)
    assert measurement.false_positive_rate != measurement.precision


def test_the_rates_are_computed_from_the_matrix_not_stored():
    measurement = _measure(CorpusProvenance.SYNTHETIC)

    assert measurement.total == 1000
    assert measurement.recall == pytest.approx(90 / 110)


# ── the measurement cannot be handed a verdict ────────────────────────────


def test_real_world_is_derived_and_not_settable():
    """A field would let a report be given the answer it wanted, and this is
    precisely the gate self-assessment cannot close.
    """
    with pytest.raises(TypeError):
        DetectionMeasurement(  # type: ignore[call-arg]
            provenance=CorpusProvenance.SYNTHETIC,
            true_positives=1,
            false_positives=0,
            true_negatives=0,
            false_negatives=0,
            real_world=True,
        )


def test_negative_counts_are_refused():
    with pytest.raises(ValueError):
        DetectionMeasurement(
            provenance=CorpusProvenance.SYNTHETIC,
            true_positives=-1,
            false_positives=0,
            true_negatives=0,
            false_negatives=0,
        )


def test_the_serialised_form_never_reports_the_gate_closed():
    """No code path may mark it closed, and a reader of the artifact needs to
    see that without knowing the rule.
    """
    payload = _measure(CorpusProvenance.PRODUCTION_LABELLED).as_dict()

    assert payload["real_world"] is True
    assert payload["gate"] == "REAL_WORLD_DETECTION_METRICS"
    assert payload["gate_closed"] is False, (
        "even a production-labelled corpus does not close the gate: the "
        "sampling method and the labelling are what a third party checks"
    )


def test_every_provenance_explains_itself():
    for provenance in CorpusProvenance:
        assert len(provenance.explanation) > 60, provenance.name


# ── the harness actually uses it ──────────────────────────────────────────


def test_the_benign_action_harness_attaches_provenance_to_its_artifact():
    """Otherwise this module is decorative -- the defect this codebase has
    now found in the detonation subsystem, the discovery connectors and an
    unreachable trace comparator.

    `test_components_are_reachable.py` only scans `sentinel/`, so a caller
    under `scripts/` satisfies nothing there. This is that guard.
    """
    from pathlib import Path

    source = Path(
        "scripts/measure_benign_tool_call_false_positives.py"
    ).read_text(encoding="utf-8")

    assert "measure_detection" in source
    assert "CorpusProvenance.SYNTHETIC" in source, (
        "the benign-action corpus is hand-written; declaring it synthetic is "
        "the whole point of attaching provenance"
    )
    assert 'payload["provenance"]' in source, (
        "the provenance must reach the ARTIFACT, not just the console: the "
        "artifact is what gets read later"
    )
    assert "measurement.claim" in source


def test_the_benign_corpus_is_declared_synthetic_and_cannot_claim_real_world():
    """The corpus is a vocabulary somebody chose. Whatever its false-positive
    rate, it says nothing about production traffic.
    """
    measurement = measure_detection(
        provenance=CorpusProvenance.SYNTHETIC,
        true_positives=0,
        false_positives=26,
        true_negatives=34,
        false_negatives=0,
    )

    assert measurement.real_world is False
    assert measurement.as_dict()["gate_closed"] is False
