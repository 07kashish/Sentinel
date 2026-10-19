"""Metrics that cannot flatter themselves.

THE THREE DISHONEST CHARTS THIS REFUSES TO DRAW
------------------------------------------------
  1. `0/0` rendered as 0%. The single most common one, because it looks like a
     good result. An empty denominator is UNMEASURABLE here.
  2. A mean over two samples, presented with a decimal point. Below
     MINIMUM_SAMPLES a central tendency is an anecdote.
  3. "Agents protected" without the coverage ratio beside it -- a number that
     rises with discovery coverage and so measures the sensor rather than the
     protection.

The state machine is what enforces all three: a `Measurement` may carry a
value only when MEASURED, and must carry a reason otherwise. A dashboard that
read the number and ignored the label is the failure being designed out, so the
combination is refused at construction.
"""

from __future__ import annotations

import json

import pytest

from sentinel.domain.value_metrics import (
    MINIMUM_SAMPLES,
    Measurement,
    MetricState,
    measure,
    percentile,
)


def _by_name(report):
    return {metric.name: metric for metric in report.metrics}


# ── the state machine ─────────────────────────────────────────────────────


def test_a_measured_metric_must_carry_a_value():
    with pytest.raises(ValueError) as raised:
        Measurement(name="x", state=MetricState.MEASURED)

    assert "UNMEASURABLE exists for" in str(raised.value)


def test_an_unmeasurable_metric_must_not_carry_a_value():
    """THE property. A dashboard would show the number and ignore the label."""
    with pytest.raises(ValueError) as raised:
        Measurement(
            name="x",
            state=MetricState.UNMEASURABLE,
            value=0,
            reason="too few samples",
        )

    assert "show the number and ignore the label" in str(raised.value)


def test_an_absent_metric_must_say_why():
    """An operator who cannot see why a metric is absent assumes the dashboard
    is broken.
    """
    with pytest.raises(ValueError) as raised:
        Measurement(name="x", state=MetricState.NOT_COLLECTED)

    assert "without a reason" in str(raised.value)


def test_unmeasurable_and_not_collected_are_different_states():
    """One is a statistical limit, the other a missing integration, and the
    remedies differ -- so collapsing them would send somebody to fix the wrong
    thing.
    """
    assert MetricState.UNMEASURABLE is not MetricState.NOT_COLLECTED
    for state in MetricState:
        assert len(state.explanation) > 30, state.name


# ── an empty denominator is never zero per cent ───────────────────────────


def test_a_ratio_over_nothing_is_unmeasurable_not_zero():
    """`0/0` shown as 0% is the single most common dishonest chart, because it
    reads as complete failure when it means no data.
    """
    report = measure(window_days=7, agents_discovered=0, agents_enrolled=0)
    coverage = _by_name(report)["enrolment_coverage"]

    assert coverage.state is MetricState.UNMEASURABLE
    assert coverage.value is None
    assert "no denominator" in coverage.reason


def test_a_ratio_with_a_denominator_is_measured():
    """The control. Without it the test above would pass against a module that
    reported every ratio as unmeasurable.
    """
    report = measure(window_days=7, agents_discovered=10, agents_enrolled=7)
    coverage = _by_name(report)["enrolment_coverage"]

    assert coverage.state is MetricState.MEASURED
    assert coverage.value == 0.7


def test_binding_coverage_over_no_executions_is_unmeasurable():
    """A 0% here would be indistinguishable from a deployment where binding is
    switched off, which is a different problem with a different fix.
    """
    report = measure(window_days=7, executions_total=0, executions_bound=0)
    coverage = _by_name(report)["binding_coverage"]

    assert coverage.state is MetricState.UNMEASURABLE
    assert "binding is off" in coverage.reason


def test_binding_coverage_is_measured_when_executions_exist():
    report = measure(window_days=7, executions_total=100, executions_bound=40)

    assert _by_name(report)["binding_coverage"].value == 0.4


# ── a central tendency needs samples ──────────────────────────────────────


def test_a_median_over_too_few_samples_is_unmeasurable():
    """A mean over two samples is an anecdote with a decimal point."""
    report = measure(window_days=7, approval_wait_seconds=[10.0, 3600.0])
    wait = _by_name(report)["approval_wait_median"]

    assert wait.state is MetricState.UNMEASURABLE
    assert wait.value is None
    assert str(MINIMUM_SAMPLES) in wait.reason
    assert wait.samples == 2


def test_a_median_with_enough_samples_is_measured():
    report = measure(
        window_days=7, approval_wait_seconds=[10, 20, 30, 40, 50]
    )
    wait = _by_name(report)["approval_wait_median"]

    assert wait.state is MetricState.MEASURED
    assert wait.value == 30
    assert wait.samples == 5


def test_no_observations_is_not_collected_rather_than_unmeasurable():
    """Nothing wired to produce it, versus data that cannot support the
    metric. Different remedies.
    """
    report = measure(window_days=7, approval_wait_seconds=[])

    assert _by_name(report)["approval_wait_median"].state is (
        MetricState.NOT_COLLECTED
    )


def test_the_median_is_not_dragged_by_one_weekend():
    """MEDIAN rather than mean, on purpose. An approval that waited a weekend
    drags a mean into uselessness, and the number people want is "how long
    does this usually take".
    """
    report = measure(
        window_days=7,
        approval_wait_seconds=[5, 6, 7, 8, 9, 250_000],
    )
    wait = _by_name(report)["approval_wait_median"]

    assert wait.value is not None
    assert wait.value < 100, "a mean would be about 41,000 here"


# ── percentiles ───────────────────────────────────────────────────────────


def test_a_percentile_is_nearest_rank_not_interpolated():
    """An interpolated p95 over seven samples reports a latency no request
    experienced, and somebody will quote it as one that did.
    """
    values = [1, 2, 3, 4, 5, 6, 7]

    assert percentile(values, 0.95) in values
    assert percentile(values, 1.0) == 7
    assert percentile(values, 0.5) in values


def test_a_percentile_over_nothing_raises_rather_than_returning_zero():
    with pytest.raises(ValueError):
        percentile([], 0.95)


@pytest.mark.parametrize("fraction", [0, -0.1, 1.5])
def test_an_impossible_percentile_is_refused(fraction):
    with pytest.raises(ValueError):
        percentile([1, 2, 3], fraction)


# ── shadow agents, which is the honest framing ────────────────────────────


def test_shadow_agents_is_reported_alongside_discovery():
    """"Agents protected" alone rises with discovery coverage, which measures
    the sensor rather than the protection. The gap is what matters.
    """
    report = measure(window_days=7, agents_discovered=40, agents_enrolled=31)
    metrics = _by_name(report)

    assert metrics["shadow_agents"].value == 9
    assert metrics["enrolment_coverage"].value == 0.775


def test_shadow_agents_never_goes_negative():
    """More enrolled than discovered is a real state -- an agent enrolled by
    hand that the sensor cannot see -- and a negative count would render as a
    nonsense bar.
    """
    report = measure(window_days=7, agents_discovered=3, agents_enrolled=10)

    assert _by_name(report)["shadow_agents"].value == 0


# ── no customer payload reaches a metric ──────────────────────────────────


def test_measure_takes_no_names_resources_or_payloads():
    """These aggregate across tenants. One resource identifier would make a
    chart a cross-tenant disclosure, in an output nobody thinks of as one.
    """
    import inspect

    signature = inspect.signature(measure)
    for name, parameter in signature.parameters.items():
        annotation = str(parameter.annotation)
        assert "str" not in annotation or name == "unit", (
            f"{name}: {annotation} -- a string parameter here is a place a "
            f"tool name, resource or principal could enter an aggregate"
        )


def test_the_serialised_report_carries_no_free_text_from_a_tenant():
    report = measure(
        window_days=7,
        agents_discovered=5,
        agents_enrolled=5,
        executions_total=10,
        executions_bound=10,
        substitutions_refused=1,
    )
    payload = json.dumps(report.as_dict())

    assert "cross-tenant disclosure" in payload
    # Every value is a number, a state name, a unit or a fixed explanation.
    for metric in report.metrics:
        assert isinstance(metric.value, (int, float, type(None)))


# ── the report's shape ────────────────────────────────────────────────────


def test_the_report_separates_measured_from_absent():
    report = measure(window_days=7)

    assert report.measured
    assert report.absent
    assert len(report.measured) + len(report.absent) == len(report.metrics)


def test_the_rendered_report_states_the_reason_for_each_absence():
    """Somebody will read the rendered text and not the dict."""
    rendered = measure(window_days=7).render()

    assert "UNMEASURABLE" in rendered or "NOT_COLLECTED" in rendered
    assert "no denominator" in rendered


def test_an_empty_window_produces_no_measured_ratio():
    """The whole point: a deployment with no data must not present a set of
    zero-per-cent charts that look like failures.
    """
    report = measure(window_days=7)
    ratios = [
        m for m in report.metrics
        if m.unit == "fraction"
    ]

    assert ratios, "control: no ratio metrics found"
    for ratio in ratios:
        assert ratio.state is MetricState.UNMEASURABLE, ratio.name


def test_substitutions_refused_is_reported_with_its_denominator():
    """The one number no competitor can report, and it is meaningless without
    the coverage ratio beside it.
    """
    report = measure(
        window_days=7, executions_total=100, executions_bound=80,
        substitutions_refused=3,
    )
    metrics = _by_name(report)

    assert metrics["substitutions_refused"].value == 3
    assert metrics["substitutions_refused"].samples == 80
    assert metrics["binding_coverage"].value == 0.8
