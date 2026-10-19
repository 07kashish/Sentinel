"""Evaluate an SLO against a measurement window, three-valued.

WHY THIS EXISTS
---------------
`docs/OBSERVABILITY.md` carried an SLI/SLO table whose Status column was
written by hand: **UNVERIFIED**, **MET on PostgreSQL**, **MISSED on SQLite**.
Nothing computed those words. A hand-authored verdict on a generated
measurement is the same defect as a hand-authored count of a generated ledger,
and it drifts in one direction -- nobody forgets to downgrade a MET.

So this computes the verdict from the window, and the window has to be big
enough to support it.

THE WHOLE POINT IS THAT A SHORT WINDOW CANNOT MEET A LONG SLO
--------------------------------------------------------------
A 99.9%/30d availability target permits roughly 43 minutes of downtime per 30
days. A 40-minute run that saw zero failures has observed 6,595 successes and
learned almost nothing: the entire error budget could be spent in a window
longer than the run. Reporting that as MET is the single most misleading thing
this file could do, so `UNMEASURABLE` is a distinct state and a short window
lands there rather than in MET.

`VIOLATED`, by contrast, is available from a short window. One observed
failure rate above the target is a real violation whatever the duration --
falsifying an SLO needs less evidence than confirming one, and treating the
two symmetrically would either hide violations or invent achievements.

WHAT IT DOES NOT DO
-------------------
It does not measure anything. It takes counts and durations that something
else observed and judges them. And it never reads a clock: the window duration
is passed in, because a function that asked the clock how long the run was
would be a function whose verdict changes when you call it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping, Sequence

__all__ = [
    "MINIMUM_SAMPLES",
    "SloKind",
    "SloState",
    "SloTarget",
    "SloVerdict",
    "evaluate_slo",
    "evaluate_all",
]

#: Below this, a ratio or a percentile describes the samples rather than the
#: system. Same threshold and same reasoning as `value_metrics.MINIMUM_SAMPLES`
#: -- and deliberately the same number, because two honesty floors that
#: disagree invite picking whichever one a result needs.
MINIMUM_SAMPLES = 5

#: How much of a target's window a run must cover before an availability
#: verdict of MET means anything. One tenth is already generous and is chosen
#: to be obviously insufficient rather than defensible: the honest reading of
#: any short run is UNMEASURABLE, and this constant exists so the boundary is
#: a stated number rather than a judgement made per report.
MINIMUM_WINDOW_FRACTION = 0.1


class SloKind(str, Enum):
    """What sort of thing is being judged.

    Availability and latency are separated because their evidence
    requirements differ: a ratio target needs a window proportional to its
    own, a percentile target needs enough samples for the percentile to exist.
    """

    AVAILABILITY = "availability"
    LATENCY_PERCENTILE = "latency_percentile"
    ERROR_RATE = "error_rate"


class SloState(str, Enum):
    MET = "met"
    VIOLATED = "violated"
    #: The window cannot support a verdict. NOT a pass, and the reason this
    #: enum has three members rather than two.
    UNMEASURABLE = "unmeasurable"

    @property
    def explanation(self) -> str:
        return _STATE_EXPLANATIONS[self]


_STATE_EXPLANATIONS: Mapping[SloState, str] = MappingProxyType({
    SloState.MET: (
        "the observed value satisfies the target AND the window was long "
        "enough for that to mean something"
    ),
    SloState.VIOLATED: (
        "the observed value does not satisfy the target. Available from a "
        "SHORT window on purpose: falsifying an SLO needs less evidence than "
        "confirming one, so a violation is reported even when a MET could not "
        "have been"
    ),
    SloState.UNMEASURABLE: (
        "the window cannot support a verdict -- too short for the target's own "
        "period, or too few samples for the percentile. Not a pass: a "
        "40-minute run against a 30-day availability target has observed "
        "almost nothing, because the entire error budget could be spent in a "
        "window longer than the run"
    ),
})


@dataclass(frozen=True, slots=True)
class SloTarget:
    """One target, as a number and a period rather than a sentence."""

    name: str
    kind: SloKind
    #: For AVAILABILITY: the required success ratio, e.g. 0.999.
    #: For LATENCY_PERCENTILE: the ceiling in milliseconds.
    #: For ERROR_RATE: the maximum permitted ratio, e.g. 0.01.
    threshold: float
    #: The period the target is stated over, in seconds. Zero means the target
    #: is not stated over a period -- a latency ceiling "at stated load" has
    #: no window, only a sample requirement.
    window_seconds: float = 0.0
    #: Which percentile, for LATENCY_PERCENTILE. 95 means p95.
    percentile: int = 95

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("an SLO with no name cannot be reported against")
        if self.kind is SloKind.AVAILABILITY and not (
            0.0 < self.threshold <= 1.0
        ):
            raise ValueError(
                f"{self.name}: an availability threshold is a ratio in (0, 1], "
                f"not {self.threshold!r}. A target of 99.9 rather than 0.999 "
                "would be trivially satisfied by every possible measurement, "
                "which is worse than having no target"
            )
        if self.kind is SloKind.ERROR_RATE and not (0.0 <= self.threshold < 1.0):
            raise ValueError(
                f"{self.name}: an error-rate threshold is a ratio in [0, 1), "
                f"not {self.threshold!r}"
            )
        if self.kind is SloKind.LATENCY_PERCENTILE and self.threshold <= 0:
            raise ValueError(
                f"{self.name}: a latency ceiling must be positive milliseconds"
            )

    @property
    def budget_seconds(self) -> float:
        """How much failure the target permits over its own window.

        Reported because it is the number that makes a short run's
        uninformativeness obvious: 99.9% over 30 days permits ~2,592 seconds,
        which is longer than most soak runs.
        """
        if self.kind is not SloKind.AVAILABILITY or not self.window_seconds:
            return 0.0
        return self.window_seconds * (1.0 - self.threshold)


@dataclass(frozen=True, slots=True)
class SloVerdict:
    """What the window says about one target."""

    target: SloTarget
    state: SloState
    #: The value observed, when one could be computed. None otherwise -- never
    #: zero, because a zero reads as a measurement.
    observed: float | None = None
    reason: str = ""

    def __post_init__(self) -> None:
        if self.state is SloState.UNMEASURABLE and not self.reason.strip():
            raise ValueError(
                f"{self.target.name}: UNMEASURABLE without a reason reads as a "
                "broken harness rather than an unanswerable question, and an "
                "operator will stop running it"
            )
        if self.state is not SloState.UNMEASURABLE and self.observed is None:
            raise ValueError(
                f"{self.target.name}: a {self.state.value} verdict must carry "
                "the value it was based on, or nobody can check it"
            )

    @property
    def met(self) -> bool:
        """True ONLY for MET. Deliberately false for UNMEASURABLE.

        Derived rather than stored, so a report cannot be handed a verdict it
        preferred -- and so "could not tell" can never be counted as "fine".
        """
        return self.state is SloState.MET

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.target.name,
            "kind": self.target.kind.value,
            "threshold": self.target.threshold,
            "window_seconds": self.target.window_seconds,
            "state": self.state.value,
            "state_explanation": self.state.explanation,
            "met": self.met,
            "observed": self.observed,
            "reason": self.reason,
        }


def _percentile(values: Sequence[float], percentile: int) -> float:
    """Nearest-rank percentile. No interpolation.

    Same choice as `value_metrics.percentile`: an interpolated percentile
    reports a latency no request actually experienced, and the whole point of
    a p95 is that some real request was that slow.
    """
    ordered = sorted(values)
    rank = max(1, min(len(ordered), (percentile * len(ordered) + 99) // 100))
    return ordered[rank - 1]


def evaluate_slo(
    target: SloTarget,
    *,
    successes: int = 0,
    failures: int = 0,
    observed_seconds: float = 0.0,
    latencies_ms: Sequence[float] = (),
    reported_percentile_ms: float | None = None,
    sample_count: int = 0,
) -> SloVerdict:
    """Judge one target against what was observed.

    `observed_seconds` is the duration of the measurement window and is
    REQUIRED for a target stated over a period. It is passed rather than read
    from a clock, because a verdict that changes depending on when you ask is
    not a verdict.

    `reported_percentile_ms` with `sample_count` is the fallback for a
    producer that computed the percentile and did not keep the raw values --
    which is what the real soak artifacts do. The sample count is what makes
    it admissible: the arithmetic is the producer's, but a percentile over
    16,082 samples is a statistic and one over 3 is not. Raw samples win when
    both are present, because this module can then check the arithmetic
    instead of trusting it.
    """
    if target.kind is SloKind.LATENCY_PERCENTILE:
        return _judge_latency(
            target,
            latencies_ms,
            reported_percentile_ms=reported_percentile_ms,
            sample_count=sample_count,
        )
    return _judge_ratio(
        target,
        successes=successes,
        failures=failures,
        observed_seconds=observed_seconds,
    )


def _judge_latency(
    target: SloTarget,
    latencies_ms: Sequence[float],
    *,
    reported_percentile_ms: float | None = None,
    sample_count: int = 0,
) -> SloVerdict:
    provenance = ""
    if len(latencies_ms) >= MINIMUM_SAMPLES:
        # Raw samples: the arithmetic is checked here rather than trusted.
        observed = _percentile(latencies_ms, target.percentile)
    elif reported_percentile_ms is not None and sample_count >= MINIMUM_SAMPLES:
        observed = float(reported_percentile_ms)
        provenance = (
            f" (percentile computed by the producer over {sample_count} "
            "samples; raw values were not retained, so the arithmetic is "
            "trusted and the sample count is what makes it admissible)"
        )
    else:
        available = max(len(latencies_ms), sample_count)
        return SloVerdict(
            target=target,
            state=SloState.UNMEASURABLE,
            reason=(
                f"{available} sample(s), fewer than the {MINIMUM_SAMPLES} "
                f"needed for a p{target.percentile} to describe the system "
                "rather than the samples"
                if available or reported_percentile_ms is not None
                else "no latency samples and no reported percentile"
            ),
        )

    if observed <= target.threshold:
        return SloVerdict(
            target=target,
            state=SloState.MET,
            observed=observed,
            reason=(
                f"p{target.percentile} of {observed:.1f} ms is within the "
                f"{target.threshold:.0f} ms ceiling{provenance}"
            ),
        )
    return SloVerdict(
        target=target,
        state=SloState.VIOLATED,
        observed=observed,
        reason=(
            f"p{target.percentile} of {observed:.1f} ms exceeds the "
            f"{target.threshold:.0f} ms ceiling{provenance}"
        ),
    )


def _judge_ratio(
    target: SloTarget,
    *,
    successes: int,
    failures: int,
    observed_seconds: float,
) -> SloVerdict:
    attempts = successes + failures
    if attempts < MINIMUM_SAMPLES:
        return SloVerdict(
            target=target,
            state=SloState.UNMEASURABLE,
            reason=(
                f"{attempts} attempt(s), fewer than the {MINIMUM_SAMPLES} "
                "needed for a ratio to mean anything. A ratio over an empty "
                "or near-empty denominator rendered as a percentage is the "
                "most quotable wrong number a report can contain"
            ),
        )

    if target.kind is SloKind.AVAILABILITY:
        observed = successes / attempts
        satisfied = observed >= target.threshold
    else:
        observed = failures / attempts
        satisfied = observed <= target.threshold

    if not satisfied:
        # VIOLATED from a short window is CORRECT. Falsifying an SLO needs
        # less evidence than confirming one, and requiring the full window
        # before reporting a violation would hide real breaches behind a
        # duration technicality.
        return SloVerdict(
            target=target,
            state=SloState.VIOLATED,
            observed=observed,
            reason=(
                f"observed {observed:.6f} against a target of "
                f"{target.threshold:.6f}. Reported from a "
                f"{observed_seconds:.0f}s window because a violation is a "
                "violation whatever the duration"
            ),
        )

    # Satisfied -- but only MET if the window can support the claim.
    if target.window_seconds:
        required = target.window_seconds * MINIMUM_WINDOW_FRACTION
        if observed_seconds < required:
            return SloVerdict(
                target=target,
                state=SloState.UNMEASURABLE,
                reason=(
                    f"the window was {observed_seconds:.0f}s against a target "
                    f"period of {target.window_seconds:.0f}s, which permits "
                    f"{target.budget_seconds:.0f}s of failure. The entire "
                    "error budget could be spent in a window longer than this "
                    "run, so observing no failures here is close to no "
                    f"evidence. At least {required:.0f}s is needed before a "
                    "MET means anything"
                ),
            )
    return SloVerdict(target=target, state=SloState.MET, observed=observed)


def evaluate_all(
    targets: Sequence[SloTarget], observations: Mapping[str, Mapping[str, Any]]
) -> tuple[SloVerdict, ...]:
    """Judge every target, and never silently skip one.

    A target with no observation becomes UNMEASURABLE rather than being
    omitted. Omitting it would shorten the report by exactly the SLOs nothing
    was measuring, which is how an unmonitored SLO comes to look satisfied.
    """
    verdicts: list[SloVerdict] = []
    for target in targets:
        seen = observations.get(target.name)
        if seen is None:
            verdicts.append(
                SloVerdict(
                    target=target,
                    state=SloState.UNMEASURABLE,
                    reason=(
                        "nothing in this run produced an observation for this "
                        "target. Reported rather than omitted: a missing SLO "
                        "in a shorter report reads as one fewer thing to worry "
                        "about"
                    ),
                )
            )
            continue
        reported = seen.get("reported_percentile_ms")
        verdicts.append(
            evaluate_slo(
                target,
                successes=int(seen.get("successes", 0) or 0),
                failures=int(seen.get("failures", 0) or 0),
                observed_seconds=float(seen.get("observed_seconds", 0) or 0),
                latencies_ms=tuple(seen.get("latencies_ms", ()) or ()),
                reported_percentile_ms=(
                    float(reported) if reported is not None else None
                ),
                sample_count=int(seen.get("sample_count", 0) or 0),
            )
        )
    return tuple(verdicts)
