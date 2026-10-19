"""Product metrics that measure value, and refuse to measure vanity.

WHY THIS MODULE REFUSES SOME NUMBERS
-------------------------------------
The instruction is "measure useful product value, not vanity metrics", and the
difference is not a matter of taste. A vanity metric is one that goes up when
nothing improves, or that cannot go down when something breaks. Three of the
metrics an agent-security product is naturally asked for are exactly that, and
this module reports them as UNMEASURABLE rather than producing a number:

  * "agents protected" over a window where nothing was enrolled. It rises with
    discovery coverage, which is a measure of the sensor rather than of
    protection.
  * "mean time to containment" with fewer than a handful of containments. A
    mean over two samples is an anecdote with a decimal point.
  * any RATE over an empty denominator. `0/0` rendered as 0% is the single most
    common dishonest chart, because it looks like a good result.

`Measurement` is therefore three-valued: a VALUE, or UNMEASURABLE with the
reason, or NOT_COLLECTED when nothing is wired to produce it. A dashboard that
could only show numbers would have to invent one.

WHY NO CUSTOMER PAYLOAD REACHES A METRIC
-----------------------------------------
Every field here is a count, a duration, or a digest. There is no tool name, no
resource, no parameter and no principal -- because these aggregate across
tenants and the moment one carries a resource identifier it becomes a
cross-tenant disclosure in a chart nobody thought of as an output.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping, Sequence

__all__ = [
    "MINIMUM_SAMPLES",
    "Measurement",
    "MetricState",
    "ValueReport",
    "measure",
    "percentile",
]

#: Below this a mean is an anecdote with a decimal point. Five is not a
#: statistical threshold -- it is the smallest number at which a median is not
#: simply one of the two samples -- and it is stated rather than tuned.
MINIMUM_SAMPLES = 5


class MetricState(str, Enum):
    """Whether this metric has a number, and why not if it does not."""

    MEASURED = "measured"
    #: There is data, and it cannot support the metric being asked for.
    UNMEASURABLE = "unmeasurable"
    #: Nothing is wired to produce it. Different from unmeasurable: one is a
    #: statistical limit, the other is a missing integration, and they have
    #: different remedies.
    NOT_COLLECTED = "not_collected"

    @property
    def explanation(self) -> str:
        return _STATE_EXPLANATIONS[self]


_STATE_EXPLANATIONS: Mapping[MetricState, str] = MappingProxyType({
    MetricState.MEASURED: "a value derived from observations in the window",
    MetricState.UNMEASURABLE: (
        "there is data and it cannot support this metric -- most often too few "
        "samples for a central tendency, or an empty denominator. Reported "
        "rather than rendered as zero, because 0/0 shown as 0% looks like a "
        "good result"
    ),
    MetricState.NOT_COLLECTED: (
        "nothing is wired to produce this. Distinct from unmeasurable: that is "
        "a statistical limit and this is a missing integration, and the "
        "remedies differ"
    ),
})


@dataclass(frozen=True, slots=True)
class Measurement:
    """One metric: a value, or the reason there is not one.

    `value` is None unless `state` is MEASURED, enforced in `__post_init__`.
    The combination "UNMEASURABLE with a value" is the shape a dashboard would
    read as a number while the label said otherwise.
    """

    name: str
    state: MetricState
    value: float | int | None = None
    unit: str = ""
    samples: int = 0
    reason: str = ""

    def __post_init__(self) -> None:
        if self.state is MetricState.MEASURED:
            if self.value is None:
                raise ValueError(
                    f"{self.name} is MEASURED with no value. A measured metric "
                    "without a number is the state UNMEASURABLE exists for"
                )
        elif self.value is not None:
            raise ValueError(
                f"{self.name} is {self.state.value} and carries a value of "
                f"{self.value}. A dashboard would show the number and ignore "
                "the label, which is the whole failure this state machine "
                "exists to prevent"
            )
        if self.state is not MetricState.MEASURED and not self.reason.strip():
            raise ValueError(
                f"{self.name} is {self.state.value} without a reason. An "
                "operator who cannot see why a metric is absent assumes the "
                "dashboard is broken"
            )

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "state": self.state.value,
            "value": self.value,
            "unit": self.unit,
            "samples": self.samples,
            "reason": self.reason,
            "state_explanation": self.state.explanation,
        }


def percentile(values: Sequence[float], fraction: float) -> float:
    """Nearest-rank percentile over a sorted copy.

    Nearest-rank rather than interpolated, because an interpolated p95 over
    seven samples reports a latency no request experienced -- and somebody will
    quote it as one that did.
    """
    if not values:
        raise ValueError("no values")
    if not 0 < fraction <= 1:
        raise ValueError(f"fraction={fraction} is not in (0, 1]")
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, round(fraction * len(ordered)) - 1))
    return float(ordered[index])


def _central(
    name: str, values: Sequence[float], *, unit: str
) -> Measurement:
    """A median, or UNMEASURABLE when there are too few samples.

    MEDIAN rather than mean. An approval that waited a weekend drags a mean
    into uselessness, and the number people actually want is "how long does
    this usually take".
    """
    if not values:
        return Measurement(
            name=name,
            state=MetricState.NOT_COLLECTED,
            unit=unit,
            reason="no observations in this window",
        )
    if len(values) < MINIMUM_SAMPLES:
        return Measurement(
            name=name,
            state=MetricState.UNMEASURABLE,
            unit=unit,
            samples=len(values),
            reason=(
                f"{len(values)} sample(s), below the {MINIMUM_SAMPLES} at "
                "which a central tendency is more than an anecdote"
            ),
        )
    return Measurement(
        name=name,
        state=MetricState.MEASURED,
        value=round(statistics.median(values), 2),
        unit=unit,
        samples=len(values),
    )


def _ratio(
    name: str, numerator: int, denominator: int, *, reason_when_empty: str
) -> Measurement:
    """A fraction, or UNMEASURABLE on an empty denominator.

    `0/0` rendered as 0% is the single most common dishonest chart, because it
    looks like a good result. This refuses to produce it.
    """
    if denominator <= 0:
        return Measurement(
            name=name,
            state=MetricState.UNMEASURABLE,
            unit="fraction",
            reason=reason_when_empty,
        )
    return Measurement(
        name=name,
        state=MetricState.MEASURED,
        value=round(numerator / denominator, 4),
        unit="fraction",
        samples=denominator,
    )


@dataclass(frozen=True, slots=True)
class ValueReport:
    """The metrics worth showing, each with its own state."""

    window_days: int
    metrics: tuple[Measurement, ...] = field(default=())

    @property
    def measured(self) -> tuple[Measurement, ...]:
        return tuple(
            m for m in self.metrics if m.state is MetricState.MEASURED
        )

    @property
    def absent(self) -> tuple[Measurement, ...]:
        return tuple(
            m for m in self.metrics if m.state is not MetricState.MEASURED
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "window_days": self.window_days,
            "measured": len(self.measured),
            "absent": len(self.absent),
            "metrics": [m.as_dict() for m in self.metrics],
            "note": (
                "Every metric is a count, a duration or a fraction. No tool "
                "name, resource, parameter or principal appears here: these "
                "aggregate across tenants, and one resource identifier would "
                "make a chart a cross-tenant disclosure."
            ),
        }

    def render(self) -> str:
        lines = [f"window: {self.window_days} day(s)"]
        for metric in self.metrics:
            if metric.state is MetricState.MEASURED:
                lines.append(
                    f"  {metric.name}: {metric.value} {metric.unit} "
                    f"(n={metric.samples})"
                )
            else:
                lines.append(
                    f"  {metric.name}: {metric.state.value.upper()} -- "
                    f"{metric.reason}"
                )
        return "\n".join(lines)


def measure(
    *,
    window_days: int,
    agents_discovered: int = 0,
    agents_enrolled: int = 0,
    mcp_servers_discovered: int = 0,
    tools_discovered: int = 0,
    high_risk_privileges: int = 0,
    unsafe_delegation_paths: int = 0,
    policy_violations: int = 0,
    executions_total: int = 0,
    executions_bound: int = 0,
    substitutions_refused: int = 0,
    approval_wait_seconds: Sequence[float] = (),
    containment_seconds: Sequence[float] = (),
    incidents_investigated: int = 0,
    evidence_verified: int = 0,
    integrations_enabled: int = 0,
) -> ValueReport:
    """Build the report. Every argument is a count or a duration.

    Nothing here takes a name, a resource or a payload. That is not tidiness:
    these aggregate across tenants, and a single resource identifier would
    turn a chart into a cross-tenant disclosure -- in an output nobody thinks
    of as an output.
    """
    metrics: list[Measurement] = [
        Measurement(
            name="agents_discovered",
            state=MetricState.MEASURED,
            value=agents_discovered,
            unit="agents",
            samples=agents_discovered,
        ),
        # THE ratio worth having, and the one most often reported dishonestly.
        # "Agents protected" alone rises with discovery coverage, which
        # measures the sensor rather than the protection.
        _ratio(
            "enrolment_coverage",
            agents_enrolled,
            agents_discovered,
            reason_when_empty=(
                "no agents were discovered in this window, so there is no "
                "denominator. Reported rather than shown as 0%, which would "
                "read as complete failure when it means no data"
            ),
        ),
        Measurement(
            name="shadow_agents",
            state=MetricState.MEASURED,
            value=max(0, agents_discovered - agents_enrolled),
            unit="agents",
            samples=agents_discovered,
        ),
        Measurement(
            name="mcp_servers_discovered",
            state=MetricState.MEASURED,
            value=mcp_servers_discovered,
            unit="servers",
        ),
        Measurement(
            name="tools_discovered",
            state=MetricState.MEASURED,
            value=tools_discovered,
            unit="tools",
        ),
        Measurement(
            name="high_risk_privileges",
            state=MetricState.MEASURED,
            value=high_risk_privileges,
            unit="findings",
        ),
        Measurement(
            name="unsafe_delegation_paths",
            state=MetricState.MEASURED,
            value=unsafe_delegation_paths,
            unit="paths",
        ),
        Measurement(
            name="policy_violations",
            state=MetricState.MEASURED,
            value=policy_violations,
            unit="violations",
        ),
        # The binding metrics. `substitutions_refused` is the one number in
        # this product that no competitor can report, and it is meaningless
        # without the coverage ratio beside it.
        _ratio(
            "binding_coverage",
            executions_bound,
            executions_total,
            reason_when_empty=(
                "no executions were recorded, so there is no denominator. A "
                "0% here would be indistinguishable from a deployment where "
                "binding is off"
            ),
        ),
        Measurement(
            name="substitutions_refused",
            state=MetricState.MEASURED,
            value=substitutions_refused,
            unit="executions",
            samples=executions_bound,
        ),
        _central("approval_wait_median", approval_wait_seconds, unit="seconds"),
        _central("containment_median", containment_seconds, unit="seconds"),
        Measurement(
            name="incidents_investigated",
            state=MetricState.MEASURED,
            value=incidents_investigated,
            unit="incidents",
        ),
        Measurement(
            name="evidence_verified",
            state=MetricState.MEASURED,
            value=evidence_verified,
            unit="passports",
        ),
        Measurement(
            name="integrations_enabled",
            state=MetricState.MEASURED,
            value=integrations_enabled,
            unit="integrations",
        ),
    ]

    return ValueReport(window_days=window_days, metrics=tuple(metrics))
