"""Continuous red teaming: campaigns, outcomes, and regression across releases.

THE ONE INVARIANT THAT MATTERS MOST HERE
-----------------------------------------
An attack that FAILED TO LAUNCH looks exactly like an attack that was BLOCKED.

Both produce "the bad thing did not happen". A misconfigured harness, an app
that would not start, a typo in a URL, an expired credential -- every one of
them yields the same observable as a working defence, and every one of them
produces a report full of green rows. That is how a red-team exercise becomes
a marketing document.

So `INCONCLUSIVE` is a first-class outcome, `NOT_RUN` is another, and neither
can be converted into `DEFENDED` anywhere in this module. `defence_rate`
REFUSES to return a number while either is present, rather than quoting a
percentage of the cases that happened to work.

That is the same discipline as `evaluation/intervals.py` refusing to quote a
proportion from fewer than 30 samples: a rate computed over an unknown
denominator is not a measurement, it is a shape that looks like one.

DETECTION AND PREVENTION ARE SEPARATE, AS THEY ARE IN THE PYTEST SUITE
-----------------------------------------------------------------------
`DETECTED_NOT_PREVENTED` exists because that is Sentinel's actual posture for
most correlation-driven cases, deliberately: correlation is self-reported, so
blocking on it would hand an attacker a control they could trigger against
somebody else. Collapsing it into `NOTHING_OBSERVED` would make the product look
worse than it is; collapsing it into `DEFENDED` would make it look better. Both
are lies and the second is the dangerous one.

OBSERVATION AND JUDGEMENT ARE ALSO SEPARATE
-------------------------------------------
`NOTHING_OBSERVED` records what happened; `AttackCase.breached` decides what it
means, by reading the expectation alongside it. The tracked table deliberately
contains NEGATIVE cases -- benign sequences that must not raise an incident --
and for those, nothing happening is the desired result. One enum member doing
both jobs would print "BREACHED / met expectation" on the same row.

WHAT A CAMPAIGN CANNOT TELL YOU
-------------------------------
Coverage. A campaign of forty cases that all pass says nothing about the
technique nobody wrote a case for, so `CampaignResult` carries
`techniques_not_attempted` and the report states it. A red-team result without
a denominator is the same failure as an empty inventory reading as a clean
estate.

RELATIONSHIP TO THE PYTEST RED-TEAM SUITE
------------------------------------------
`tests_arch/test_red_team_suite.py` is the gate: it drives the real HTTP
surface and fails the build on regression. This module is the LEDGER: it turns
those outcomes into a bound artifact that can be compared release to release,
so "we used to prevent that" is a diff rather than a memory.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping, Sequence

__all__ = [
    "MIN_CASES_TO_QUOTE_A_RATE",
    "AttackCase",
    "AttackOutcome",
    "CampaignResult",
    "Regression",
    "RegressionKind",
    "case_from_observations",
    "compare_to_baseline",
    "summarise",
]

#: Below this, a defence rate is a ratio of small integers wearing a percentage
#: sign. 3/3 is not 100% -- it is a very wide interval that reads as certainty.
#: Chosen to match `MIN_SAMPLES_TO_QUOTE` in the evaluation module rather than
#: invented separately, so the two never drift into disagreeing about what
#: counts as enough evidence.
MIN_CASES_TO_QUOTE_A_RATE = 30


class AttackOutcome(str, Enum):
    """What happened when one attack ran.

    Five members, and three of them exist to stop a single conflation: "the bad
    thing did not happen" has several causes and only one of them is a defence.
    """

    #: The action was refused. The attack was stopped.
    DEFENDED = "defended"
    #: An incident was raised and the action still went through. Sentinel's
    #: deliberate posture for correlation-driven cases -- not a failure, and
    #: not a defence either.
    DETECTED_NOT_PREVENTED = "detected_not_prevented"
    #: Nothing was refused and nothing was detected.
    #:
    #: NOT named "breached", because this is an OBSERVATION and whether it is a
    #: breach depends on the expectation. The tracked table deliberately
    #: contains negative cases -- benign sequences that must not raise an
    #: incident -- and for those this is the desired result. See the `breached`
    #: property, which is the judgement.
    NOTHING_OBSERVED = "nothing_observed"
    #: The attack ran and the result cannot be interpreted -- the app errored,
    #: the harness misfired, the response was unparseable. NOT a defence.
    INCONCLUSIVE = "inconclusive"
    #: The case never executed. NOT a defence, and not a gap in the product
    #: either -- a gap in the evidence.
    NOT_RUN = "not_run"


#: Outcomes that say nothing about the product's defences. Named as a set so
#: the several places that must exclude them cannot drift apart, and frozen so
#: no caller can widen it -- widening it is precisely how NOT_RUN would become
#: DEFENDED.
UNINFORMATIVE: frozenset[AttackOutcome] = frozenset(
    {AttackOutcome.INCONCLUSIVE, AttackOutcome.NOT_RUN}
)


class RegressionKind(str, Enum):
    """How a case got worse between two releases."""

    #: Was defended, now is not. The finding that should stop a release.
    DEFENCE_LOST = "defence_lost"
    #: Was at least detected, now nothing notices.
    DETECTION_LOST = "detection_lost"
    #: Ran before, does not run now. The evidence regressed even if the
    #: product did not -- and it is indistinguishable from the product
    #: regressing, which is why it is reported rather than skipped.
    EVIDENCE_LOST = "evidence_lost"


#: How much each outcome is worth as a defence. Used ONLY to decide whether one
#: outcome is worse than another; never averaged, because averaging ordinal
#: labels invents a number.
#:
#: The uninformative outcomes are deliberately absent: comparing them on this
#: scale would place NOT_RUN somewhere relative to DEFENDED, and there is no
#: honest place to put it.
_DEFENCE_RANK: Mapping[AttackOutcome, int] = MappingProxyType(
    {
        AttackOutcome.NOTHING_OBSERVED: 0,
        AttackOutcome.DETECTED_NOT_PREVENTED: 1,
        AttackOutcome.DEFENDED: 2,
    }
)


@dataclass(frozen=True, slots=True)
class AttackCase:
    """One attack, what was expected of it, and what happened.

    `expected_prevention` is recorded separately from the outcome so a case
    that was never meant to be blocked does not read as a failure. A red-team
    table where every row expects prevention is a table nobody should believe.
    """

    case_id: str
    technique: str
    outcome: AttackOutcome
    expected_detection: bool
    expected_prevention: bool
    #: Why prevention is or is not expected. Required: a row expecting no
    #: prevention with no stated reason is indistinguishable from an oversight.
    rationale: str
    detail: str = ""
    #: WHAT WAS ACTUALLY OBSERVED, as two independent facts.
    #:
    #: Kept separate from `outcome` because grading has to compare each against
    #: its expectation STRICTLY. The first version of this module graded from
    #: `outcome` alone and returned True for any informative result when a case
    #: expected neither -- so a benign control case that WAS wrongly detected
    #: reported "ok", while the pytest gate that mirrors this table would have
    #: failed on it. A ledger more lenient than its own gate is worse than none.
    #:
    #: Defaults keep the outcome-only constructor working for callers that only
    #: record a summary; `from_observations` is the honest way to build one.
    observed_detection: bool = False
    observed_prevention: bool = False

    def __post_init__(self) -> None:
        if not self.case_id.strip():
            raise ValueError("an attack case with no id cannot be tracked")
        if not self.technique.strip():
            raise ValueError(
                f"case {self.case_id!r} names no technique, so it cannot be "
                "counted against a coverage denominator"
            )
        if not self.rationale.strip():
            raise ValueError(
                f"case {self.case_id!r} has no rationale. A row expecting no "
                "prevention with no stated reason is indistinguishable from an "
                "oversight, and the whole value of this table is that a "
                "deliberate gap and a forgotten one look different."
            )
        if self.expected_prevention and not self.expected_detection:
            raise ValueError(
                f"case {self.case_id!r} expects prevention without detection. "
                "An action that is refused but produces no record leaves an "
                "operator unable to tell the refusal happened."
            )

    @property
    def is_informative(self) -> bool:
        """Does this case say anything about the product's defences?"""
        return self.outcome not in UNINFORMATIVE

    @property
    def breached(self) -> bool:
        """Nothing happened where something was expected to.

        The JUDGEMENT, kept separate from the observation. A negative case that
        correctly does nothing is not a breach, and conflating the two would
        print "BREACHED / met expectation" on one row.
        """
        return (
            self.outcome is AttackOutcome.NOTHING_OBSERVED
            and self.expected_detection
        )

    @property
    def met_expectation(self) -> bool:
        """Did the product do EXACTLY what this row said it would?

        Strict equality on both axes, matching the pytest gate. Detecting more
        than promised is a failure here, not a bonus: the tracked table
        contains negative cases whose whole purpose is to catch a detector that
        fires on ordinary work, and grading them leniently would delete that
        signal.

        False for every uninformative outcome. A case that did not run did not
        meet its expectation -- it produced no evidence about it, and the
        optimistic reading is the one this module exists to prevent.
        """
        if not self.is_informative:
            return False
        return (
            self.observed_detection == self.expected_detection
            and self.observed_prevention == self.expected_prevention
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "technique": self.technique,
            "outcome": self.outcome.value,
            "expected_detection": self.expected_detection,
            "expected_prevention": self.expected_prevention,
            "is_informative": self.is_informative,
            "observed_detection": self.observed_detection,
            "observed_prevention": self.observed_prevention,
            "breached": self.breached,
            "met_expectation": self.met_expectation,
            "rationale": self.rationale,
            "detail": self.detail,
        }


def case_from_observations(
    *,
    case_id: str,
    technique: str,
    expected_detection: bool,
    expected_prevention: bool,
    rationale: str,
    detected: bool,
    prevented: bool,
    errored: bool,
    detail: str = "",
) -> AttackCase:
    """Build a case from what was observed, deriving the summary outcome.

    The single place the two representations are reconciled, so the
    human-readable `outcome` and the graded booleans cannot disagree.

    `errored` WINS over everything. A crash, an unparseable body or an
    exception says nothing about the product's defences, and the observations
    are forced to False so no later reader can mistake them for measurements.
    """
    if errored:
        outcome = AttackOutcome.INCONCLUSIVE
        detected = False
        prevented = False
    elif prevented:
        outcome = AttackOutcome.DEFENDED
    elif detected:
        outcome = AttackOutcome.DETECTED_NOT_PREVENTED
    else:
        outcome = AttackOutcome.NOTHING_OBSERVED

    return AttackCase(
        case_id=case_id,
        technique=technique,
        outcome=outcome,
        expected_detection=expected_detection,
        expected_prevention=expected_prevention,
        rationale=rationale,
        detail=detail,
        observed_detection=detected,
        observed_prevention=prevented,
    )


@dataclass(frozen=True, slots=True)
class Regression:
    """One case that got worse. The reason this ledger exists."""

    case_id: str
    kind: RegressionKind
    was: AttackOutcome
    now: AttackOutcome

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "kind": self.kind.value,
            "was": self.was.value,
            "now": self.now.value,
        }


@dataclass(frozen=True, slots=True)
class CampaignResult:
    """One campaign against one build, with its own denominator attached."""

    commit: str
    ran_at: str
    cases: tuple[AttackCase, ...]
    #: Techniques nobody wrote a case for. A campaign of forty passing cases
    #: says nothing about the forty-first technique, and a result without this
    #: is the same failure as an empty inventory reading as a clean estate.
    techniques_not_attempted: tuple[str, ...] = ()

    limits: str = field(
        default=(
            "A green row means one attack was stopped, not that the technique "
            "is impossible. INCONCLUSIVE and NOT_RUN are NOT defences: an "
            "attack that failed to launch produces the same observable as one "
            "that was blocked, so `defence_rate` returns None while either is "
            "present rather than quoting a percentage of the cases that "
            "happened to work. Read `techniques_not_attempted` before reading "
            "any total."
        ),
        compare=False,
    )

    def of_outcome(self, outcome: AttackOutcome) -> tuple[AttackCase, ...]:
        return tuple(c for c in self.cases if c.outcome is outcome)

    @property
    def informative(self) -> tuple[AttackCase, ...]:
        return tuple(c for c in self.cases if c.is_informative)

    @property
    def uninformative(self) -> tuple[AttackCase, ...]:
        return tuple(c for c in self.cases if not c.is_informative)

    @property
    def unmet_expectations(self) -> tuple[AttackCase, ...]:
        """Cases where the product did not do what the table said.

        Includes the uninformative ones on purpose. A case that did not run is
        an unmet expectation about the evidence, and filtering it out here is
        how a campaign with half its cases broken reports a clean sweep.
        """
        return tuple(c for c in self.cases if not c.met_expectation)

    def defence_rate(self) -> float | None:
        """The share of informative cases that met their expectation, or None.

        RETURNS NONE, NOT ZERO AND NOT A PARTIAL RATE, when any case is
        uninformative or when there are too few cases to quote. This is the
        function somebody will want to put on a slide, which is exactly why it
        refuses: a rate computed over an unknown denominator is not a
        measurement.

        A float is returned only when it is honestly computable. Callers
        serialising this must not put it in a canonically-signed document --
        the canonical form refuses floats -- which is why `as_dict` emits the
        counts and a REASON instead of a number.
        """
        if self.uninformative:
            return None
        if len(self.cases) < MIN_CASES_TO_QUOTE_A_RATE:
            return None
        met = sum(1 for c in self.cases if c.met_expectation)
        return met / len(self.cases)

    def rate_refusal_reason(self) -> str:
        """Why there is no number, in words a reader can act on.

        An empty cell invites somebody to compute the ratio themselves from the
        counts, which is the mistake this whole module is arranged to prevent.
        """
        if self.uninformative:
            broken = ", ".join(sorted(c.case_id for c in self.uninformative))
            return (
                f"{len(self.uninformative)} of {len(self.cases)} cases produced "
                f"no evidence ({broken}). An attack that failed to launch "
                "produces the same observable as one that was blocked, so no "
                "rate is quoted. Fix the harness, then re-run."
            )
        if len(self.cases) < MIN_CASES_TO_QUOTE_A_RATE:
            return (
                f"{len(self.cases)} cases is below the {MIN_CASES_TO_QUOTE_A_RATE} "
                "needed to quote a proportion. A small ratio reads as certainty "
                "and is a wide interval."
            )
        return ""

    def as_dict(self) -> dict[str, Any]:
        rate = self.defence_rate()
        return {
            # The refusal reason and the coverage gap come first: a reader who
            # stops early must not stop before learning the result is partial.
            "rate_refusal_reason": self.rate_refusal_reason(),
            "techniques_not_attempted": list(self.techniques_not_attempted),
            "commit": self.commit,
            "ran_at": self.ran_at,
            "case_count": len(self.cases),
            "informative_count": len(self.informative),
            "uninformative_count": len(self.uninformative),
            "unmet_expectation_count": len(self.unmet_expectations),
            "breached_count": sum(1 for c in self.cases if c.breached),
            # Emitted as a string with a fixed number of places, never a float.
            # The canonical JSON form refuses floats, and a campaign result
            # that cannot be signed is a campaign result nobody can rely on.
            "defence_rate": None if rate is None else f"{rate:.4f}",
            "outcome_census": {
                outcome.value: len(self.of_outcome(outcome))
                for outcome in AttackOutcome
            },
            "cases": [c.as_dict() for c in self.cases],
            "limits": self.limits,
        }


def compare_to_baseline(
    *,
    baseline: Sequence[AttackCase],
    current: Sequence[AttackCase],
) -> tuple[Regression, ...]:
    """Cases that got worse. The property that makes this a ledger.

    A case present in the baseline and absent from the current run is reported
    as `EVIDENCE_LOST` rather than skipped. It is indistinguishable from the
    product regressing -- somebody deleting a failing case is exactly what this
    is watching for -- so silence would defeat the purpose.

    New cases are not regressions and are not reported here.
    """
    before = {case.case_id: case for case in baseline}
    after = {case.case_id: case for case in current}

    regressions: list[Regression] = []
    for case_id in sorted(before):
        was = before[case_id]
        now = after.get(case_id)

        if now is None:
            regressions.append(
                Regression(
                    case_id=case_id,
                    kind=RegressionKind.EVIDENCE_LOST,
                    was=was.outcome,
                    now=AttackOutcome.NOT_RUN,
                )
            )
            continue

        if now.outcome in UNINFORMATIVE and was.outcome not in UNINFORMATIVE:
            # The product may be fine. The evidence is not, and treating a
            # broken case as unchanged is how a suite quietly stops testing.
            regressions.append(
                Regression(
                    case_id=case_id,
                    kind=RegressionKind.EVIDENCE_LOST,
                    was=was.outcome,
                    now=now.outcome,
                )
            )
            continue

        if was.outcome in UNINFORMATIVE:
            # It produced no evidence before, so there is nothing to regress
            # from. Any informative outcome now is an improvement.
            continue

        # THE COMPARISON IS AGAINST THE EXPECTATION, NOT AGAINST DEFENCE RANK.
        #
        # Ranking by how strong a defence each outcome represents treats every
        # case as an attack that should be stopped. But the tracked table
        # deliberately contains NEGATIVE cases -- benign sequences that must
        # not raise an incident -- and for those, losing detection is the
        # improvement. An earlier version of this function reported exactly
        # that as `DETECTION_LOST`, calling a harness fix a regression.
        #
        # "Met its expectation and no longer does" is one comparison that works
        # for both kinds of case and cannot mistake a fix for a regression.
        if now.met_expectation or not was.met_expectation:
            continue

        # It met the expectation before and does not now. The kind names WHICH
        # way it went, using the defence rank only to distinguish "stopped
        # noticing entirely" from "stopped refusing".
        kind = (
            RegressionKind.DETECTION_LOST
            if now.outcome is AttackOutcome.NOTHING_OBSERVED
            and was.outcome is not AttackOutcome.NOTHING_OBSERVED
            else RegressionKind.DEFENCE_LOST
        )
        regressions.append(
            Regression(
                case_id=case_id, kind=kind, was=was.outcome, now=now.outcome
            )
        )

    return tuple(regressions)


def summarise(result: CampaignResult) -> str:
    """A one-line summary that cannot be mistaken for a clean bill of health.

    Leads with what is wrong. A summary that opened with the pass count would
    be quoted without the rest of the sentence.
    """
    if result.uninformative:
        return (
            f"UNVERIFIED: {len(result.uninformative)} of {len(result.cases)} "
            "attack cases produced no evidence; no defence rate can be quoted"
        )
    unmet = len(result.unmet_expectations)
    if unmet:
        return (
            f"{unmet} of {len(result.cases)} attack cases did not meet their "
            "recorded expectation"
        )
    rate = result.defence_rate()
    if rate is None:
        return (
            f"all {len(result.cases)} cases met expectation, but "
            f"{result.rate_refusal_reason()}"
        )
    return (
        f"all {len(result.cases)} cases met expectation "
        f"({rate:.1%} of the tracked table)"
    )
