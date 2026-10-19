"""A rate without an interval is a claim the sample cannot support.

THE NUMBER THIS EXISTS FOR
----------------------------
`evaluation/metrics.json` reports `precision: 1.0` from 11 true positives and 0
false positives. Correct, and not what a reader takes from it.

Eleven trials with no failures does not mean "no false positives". It means the
false-positive rate is somewhere below roughly a quarter, at 95% confidence.
Quoted as `1.0`, it becomes "zero false positives" in a slide, then in a
customer conversation — and the first production false positive reads as a
regression rather than as the thing eleven samples never had the power to
exclude.

`test_eleven_out_of_eleven_is_not_certainty` is that case, stated as an
assertion.

WHY NOT THE TEXTBOOK INTERVAL
-------------------------------
p ± 1.96·√(p(1−p)/n) computes a width of **zero** at p = 1.0 — perfect certainty
from perfect results — and produces bounds outside [0, 1] at small n. Both
failures land exactly on this corpus, which is why Wilson is used instead and
why `test_the_interval_at_a_perfect_score_is_not_a_point` pins it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from evaluation.intervals import MIN_SAMPLES_TO_QUOTE, Interval, wilson


# ── the case that motivated the module ───────────────────────────────────────


def test_eleven_out_of_eleven_is_not_certainty():
    """The real numbers from metrics.json. A perfect score on eleven trials
    still admits a substantial failure rate.
    """
    interval = wilson(11, 11)
    assert interval.point == 1.0
    assert interval.lower < 0.80, (
        "eleven successes out of eleven should still admit a materially lower "
        "true rate; an interval that does not say so is not doing its job"
    )
    assert interval.upper == 1.0


def test_the_interval_at_a_perfect_score_is_not_a_point():
    """The normal approximation gives width zero here — perfect certainty from
    perfect results. That is the specific failure Wilson avoids.
    """
    assert wilson(11, 11).width > 0.15


def test_a_small_sample_is_marked_unquotable_however_good_it_looks():
    """11/11 is exactly the shape that reads best and supports least."""
    assert wilson(11, 11).quotable is False
    assert "too small to quote" in wilson(11, 11).reading


def test_a_large_sample_becomes_quotable():
    interval = wilson(950, 1000)
    assert interval.quotable is True
    assert "95% CI" in interval.reading


# ── the interval behaves at the boundaries ───────────────────────────────────


def test_bounds_stay_inside_zero_and_one():
    """The normal approximation produces bounds below 0 and above 1 at small n,
    which are not probabilities.
    """
    for successes, trials in ((0, 3), (3, 3), (1, 2), (0, 1), (1, 1)):
        interval = wilson(successes, trials)
        assert 0.0 <= interval.lower <= interval.upper <= 1.0


def test_zero_successes_does_not_report_a_rate_of_certainly_zero():
    """"We saw no failures" and "failures cannot happen" are different claims."""
    interval = wilson(0, 10)
    assert interval.point == 0.0
    assert interval.upper > 0.2


def test_more_samples_narrow_the_interval():
    assert wilson(90, 100).width > wilson(900, 1000).width


def test_no_trials_is_undefined_rather_than_zero():
    """An undefined rate and a rate known to span everything are different
    statements, and the reading says which.
    """
    interval = wilson(0, 0)
    assert "undefined, not zero" in interval.reading


# ── refusals ─────────────────────────────────────────────────────────────────


def test_more_successes_than_trials_is_refused():
    with pytest.raises(ValueError, match="not a proportion"):
        wilson(12, 11)


def test_negative_counts_are_refused():
    with pytest.raises(ValueError, match="cannot be negative"):
        wilson(-1, 10)


def test_an_unsupported_confidence_level_raises_rather_than_rounding():
    """An interval reported at a level the caller did not ask for is worse than
    no interval.
    """
    with pytest.raises(ValueError, match="not one of"):
        wilson(5, 10, confidence=0.99)


def test_both_supported_levels_work_and_differ():
    ninety = wilson(80, 100, confidence=0.90)
    ninety_five = wilson(80, 100, confidence=0.95)
    assert ninety.width < ninety_five.width


# ── the reading is written for a human ───────────────────────────────────────


def test_every_interval_carries_the_sentence_a_reader_should_take_away():
    """The failure this addresses is HUMAN: the interval exists in the artifact
    and the point estimate is what gets quoted. The honest sentence has to
    travel with the number.
    """
    for successes, trials in ((11, 11), (0, 10), (950, 1000), (0, 0)):
        assert len(wilson(successes, trials).reading) > 20


def test_the_counts_survive_so_a_reader_can_recompute():
    """Trust, but be checkable."""
    document = wilson(11, 11).as_dict()
    assert document["successes"] == 11 and document["trials"] == 11


# ── the published metrics are consistent with this ───────────────────────────


def test_the_shipped_corpus_is_below_the_quotable_threshold():
    """Not a criticism of the corpus — a few dozen hand-written cases are the
    right tool for regression detection. It is a statement about what may be
    SAID: the existing caveat says so in prose, and this says it in the same
    units as the numbers.

    The unit is the DENOMINATOR of each rate, not the corpus total. Precision
    is quoted over the flagged cases, recall over the malicious ones and the
    false-positive rate over the benign ones; the total is the sum of two of
    those and is the denominator of nothing. An earlier version compared the
    total against the threshold, which flipped red when the corpus grew from
    22 to 34 cases while every interval it publishes stayed unquotable.
    """
    metrics = json.loads(
        (Path(__file__).resolve().parents[1] / "evaluation" / "metrics.json").read_text(
            encoding="utf-8"
        )
    )
    corpus = metrics["corpus"]
    assert corpus["malicious"] < MIN_SAMPLES_TO_QUOTE, (
        "the malicious class is large enough to quote recall; decide, do not bypass"
    )
    assert corpus["benign"] < MIN_SAMPLES_TO_QUOTE, (
        "the benign class is large enough to quote a false-positive rate; decide"
    )
    for name, interval in metrics["intervals"].items():
        assert interval["quotable"] is False, (
            f"the published {name} interval claims to be quotable; that is a "
            "decision about corpus independence, not a number to update"
        )

    matrix = metrics["confusion_matrix"]
    precision = wilson(
        matrix["true_positives"],
        matrix["true_positives"] + matrix["false_positives"],
    )
    assert precision.quotable is False, (
        "the shipped corpus became large enough to quote a precision figure. "
        "That is good news and this test now needs a decision, not a bypass: "
        "check the corpus is genuinely independent before quoting anything."
    )


def test_the_published_precision_matches_the_confusion_matrix():
    """A reported metric that does not follow from its own confusion matrix is
    the shape of an unreproducible claim, whatever its value.
    """
    metrics = json.loads(
        (Path(__file__).resolve().parents[1] / "evaluation" / "metrics.json").read_text(
            encoding="utf-8"
        )
    )
    matrix = metrics["confusion_matrix"]
    expected = matrix["true_positives"] / (
        matrix["true_positives"] + matrix["false_positives"]
    )
    assert abs(metrics["precision"] - expected) < 0.001


def test_auc_stays_null_rather_than_fabricated():
    """A hard deterministic policy has no score to rank by. Leaving it null is
    the honest answer; inventing one would be marketing a metric the
    methodology cannot produce.
    """
    metrics = json.loads(
        (Path(__file__).resolve().parents[1] / "evaluation" / "metrics.json").read_text(
            encoding="utf-8"
        )
    )
    assert metrics["auc"] is None
    assert "fabricate" in metrics["auc_notes"]


def test_an_interval_is_immutable():
    """A metric a caller can edit after reading is a metric nobody can cite."""
    interval = wilson(5, 10)
    with pytest.raises(Exception):
        interval.lower = 0.9  # type: ignore[misc]


def test_the_dataclass_exposes_no_setter_shaped_helpers():
    for forbidden in ("update", "set_", "adjust"):
        assert not [n for n in dir(Interval) if n.startswith(forbidden)]
