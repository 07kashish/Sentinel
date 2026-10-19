"""Phase 12: the interval around a rate, because a point estimate on 22 cases is a claim.

THE PROBLEM WITH `precision: 1.0`
-----------------------------------
`metrics.json` reports precision 1.0 from 11 true positives and 0 false
positives. That number is correct and it is not what a reader takes from it.

Eleven trials with no failures does not mean "no false positives". It means the
false-positive rate is somewhere below roughly 26% with 95% confidence -- the
Wilson interval for 11/11 is about [0.74, 1.00]. Quoted as "precision 1.0", it
becomes "zero false positives" in a slide, and then in a customer conversation,
and the first production false positive reads as a regression rather than as the
thing the sample never had the power to exclude.

The existing corpus caveat says the right thing in prose: "NOT sufficient to
claim a detection rate on production traffic". An interval says it in the same
units as the number, next to the number, where it cannot be dropped when the
figure is copied.

WHY WILSON AND NOT THE NORMAL APPROXIMATION
---------------------------------------------
The textbook interval, p ± 1.96·sqrt(p(1-p)/n), is wrong in exactly the case
this corpus is in. At p = 1.0 it computes a width of ZERO -- it reports perfect
certainty from perfect results -- and at small n it produces bounds below 0 and
above 1, which are not probabilities.

Wilson is well-behaved at the boundaries and at small n, which is the whole
regime here. It is also the interval that makes 11/11 look as uncertain as it
actually is.

NO SCIPY, AND NO TABLE
----------------------
The Wilson bounds are a closed-form expression over the sample and one z-value.
Two z-values are hardcoded, 90% and 95%, because a project that offered
arbitrary confidence levels would need a normal quantile function and this needs
two constants. Asking for a third raises rather than silently rounding to the
nearest available -- an interval reported at a confidence level the caller did
not ask for is worse than no interval.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

__all__ = ["Interval", "MIN_SAMPLES_TO_QUOTE", "Z_SCORES", "wilson"]

#: Two-sided z-values. Two, deliberately -- see the module docstring.
Z_SCORES: Mapping[float, float] = MappingProxyType({0.90: 1.6449, 0.95: 1.9600})

#: Below this many samples, `Interval.quotable` is False. Not a statistical
#: threshold -- there is no n at which an estimate becomes true -- but a
#: reporting one: an interval spanning most of [0, 1] is a number nobody should
#: put in a sentence, and marking it stops a reader having to work that out
#: from the width.
MIN_SAMPLES_TO_QUOTE = 30


@dataclass(frozen=True, slots=True)
class Interval:
    """A rate and the range the sample actually supports."""

    #: Successes and trials, kept so a reader can recompute rather than trust.
    successes: int
    trials: int
    lower: float
    upper: float
    confidence: float

    @property
    def point(self) -> float:
        """The naive rate. The number people quote; here it is one field of five."""
        return self.successes / self.trials if self.trials else 0.0

    @property
    def width(self) -> float:
        return self.upper - self.lower

    @property
    def quotable(self) -> bool:
        """Whether this estimate is worth putting in a sentence.

        False on a small sample regardless of how good the point estimate looks
        -- 11/11 is the case this exists for, and it is exactly the shape that
        reads best and supports least.
        """
        return self.trials >= MIN_SAMPLES_TO_QUOTE

    def as_dict(self) -> dict[str, Any]:
        return {
            "point": round(self.point, 4),
            "lower": round(self.lower, 4),
            "upper": round(self.upper, 4),
            "confidence": self.confidence,
            "successes": self.successes,
            "trials": self.trials,
            "quotable": self.quotable,
            "reading": self.reading,
        }

    @property
    def reading(self) -> str:
        """The sentence a reader should take away, written for them.

        Present because the failure this module addresses is a HUMAN one: the
        interval exists in the artifact and the point estimate is what ends up
        quoted. Writing the honest sentence next to the number is the only way
        it survives being copied.
        """
        if not self.trials:
            return "no trials: this rate is undefined, not zero"
        if not self.quotable:
            return (
                f"{self.successes}/{self.trials} — too small to quote. The true "
                f"rate is between {self.lower:.0%} and {self.upper:.0%} at "
                f"{self.confidence:.0%} confidence, which is most of the range. "
                "Report the sample, not the rate."
            )
        return (
            f"{self.point:.1%} (95% CI {self.lower:.1%}–{self.upper:.1%}, "
            f"n={self.trials})"
        )


def wilson(successes: int, trials: int, *, confidence: float = 0.95) -> Interval:
    """The Wilson score interval for a binomial proportion.

    Chosen over the normal approximation because at p = 1.0 the approximation
    computes a width of ZERO -- perfect certainty from perfect results -- and at
    small n it produces bounds outside [0, 1], which are not probabilities.
    Both failures land squarely on this corpus.
    """
    if trials < 0 or successes < 0:
        raise ValueError("counts cannot be negative")
    if successes > trials:
        raise ValueError(
            f"{successes} successes in {trials} trials is not a proportion; "
            "refusing to compute an interval for an impossible sample"
        )
    if confidence not in Z_SCORES:
        raise ValueError(
            f"confidence {confidence} is not one of {sorted(Z_SCORES)}. "
            "Rounding to the nearest available would report an interval at a "
            "level the caller did not ask for, which is worse than none."
        )

    if trials == 0:
        # Not (0, 1): an undefined rate and a rate known to span everything are
        # different statements, and `reading` says which this is.
        return Interval(
            successes=0, trials=0, lower=0.0, upper=1.0, confidence=confidence
        )

    z = Z_SCORES[confidence]
    p = successes / trials
    denominator = 1 + z**2 / trials
    centre = (p + z**2 / (2 * trials)) / denominator
    margin = (
        z
        * math.sqrt(p * (1 - p) / trials + z**2 / (4 * trials**2))
        / denominator
    )
    return Interval(
        successes=successes,
        trials=trials,
        lower=max(0.0, centre - margin),
        upper=min(1.0, centre + margin),
        confidence=confidence,
    )
