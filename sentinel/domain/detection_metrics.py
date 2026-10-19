"""Precision and recall, with the provenance of the corpus attached.

WHY PROVENANCE IS A FIELD AND NOT A FOOTNOTE
---------------------------------------------
`REAL_WORLD_DETECTION_METRICS` is an external gate because every number this
system has about detection quality comes from a corpus somebody wrote. The
numbers are real; what they describe is a corpus. A precision of 0.97 over a
synthetic set says the classifier separates the examples chosen to test it,
which is a different claim from "0.97 of production alerts are true".

The existing harness states that in its docstring. A docstring is not a field:
it does not travel with the number into a slide, a ledger entry or a
conversation with a buyer. So the provenance is carried IN the measurement,
`real_world` is derived from it, and no code path can set `real_world` true
for a synthetic corpus.

THE THREE-VALUED PART
---------------------
`UNKNOWN` provenance exists and is not treated as synthetic-or-better. A
corpus whose origin nobody recorded is the most dangerous kind: it looks like
data, it may be production traffic, and it may be the examples somebody wrote
last year. Reporting it as either would be a guess, so it reports as UNKNOWN
and `real_world` is false.

WHAT THIS DOES NOT DO
---------------------
It does not classify anything and it does not read a corpus. It takes the four
counts of a confusion matrix and judges what may honestly be said about them.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

__all__ = [
    "MINIMUM_CORPUS",
    "CorpusProvenance",
    "DetectionMeasurement",
    "measure_detection",
]

#: Below this many labelled examples, precision and recall describe the corpus
#: rather than the detector. Deliberately larger than the general
#: `MINIMUM_SAMPLES` floor used elsewhere: a ratio needs five samples to mean
#: anything at all, and a detection-quality claim that will be quoted to a
#: buyer needs more than that before it is worth stating.
MINIMUM_CORPUS = 100


class CorpusProvenance(str, Enum):
    """Where the labelled examples came from. The whole point of this module."""

    #: Written to exercise the detector. Numbers are real; they describe the
    #: examples chosen to test it.
    SYNTHETIC = "synthetic"
    #: Sampled from production traffic and labelled by a human reviewing what
    #: actually happened. The only provenance that supports a real-world claim.
    PRODUCTION_LABELLED = "production_labelled"
    #: Nobody recorded where this came from. NOT treated as synthetic and not
    #: treated as production: the most dangerous corpus is the one that looks
    #: like data and might be either.
    UNKNOWN = "unknown"

    @property
    def explanation(self) -> str:
        return _PROVENANCE_EXPLANATIONS[self]

    @property
    def supports_real_world_claim(self) -> bool:
        return self is CorpusProvenance.PRODUCTION_LABELLED


_PROVENANCE_EXPLANATIONS: Mapping[CorpusProvenance, str] = MappingProxyType({
    CorpusProvenance.SYNTHETIC: (
        "examples written to exercise the detector. The numbers are real and "
        "they describe the corpus: a high precision here means the classifier "
        "separates the cases somebody chose, not that production alerts are "
        "mostly true"
    ),
    CorpusProvenance.PRODUCTION_LABELLED: (
        "sampled from production traffic and labelled by a human reviewing "
        "what actually happened. The only provenance that supports a "
        "real-world precision or recall claim"
    ),
    CorpusProvenance.UNKNOWN: (
        "nobody recorded where these examples came from. Reported as unknown "
        "rather than assumed either way, because a corpus that looks like data "
        "and might be last year's test set is the one most likely to be quoted "
        "as production evidence"
    ),
})


@dataclass(frozen=True, slots=True)
class DetectionMeasurement:
    """A confusion matrix, its derived rates, and what may be claimed."""

    provenance: CorpusProvenance
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int

    def __post_init__(self) -> None:
        for name in (
            "true_positives",
            "false_positives",
            "true_negatives",
            "false_negatives",
        ):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} cannot be negative")

    @property
    def total(self) -> int:
        return (
            self.true_positives
            + self.false_positives
            + self.true_negatives
            + self.false_negatives
        )

    @property
    def sufficient(self) -> bool:
        return self.total >= MINIMUM_CORPUS

    @property
    def precision(self) -> float | None:
        """None rather than zero when nothing was predicted positive.

        0/0 rendered as 0.0 reads as a detector that is always wrong; rendered
        as 1.0 it reads as one that is never wrong. Both are inventions, and
        this codebase has already shipped the 0/0-as-0-per-cent bug once.
        """
        predicted = self.true_positives + self.false_positives
        return self.true_positives / predicted if predicted else None

    @property
    def recall(self) -> float | None:
        actual = self.true_positives + self.false_negatives
        return self.true_positives / actual if actual else None

    @property
    def false_positive_rate(self) -> float | None:
        """The number an operator actually feels. Alert fatigue is measured
        here, not in precision."""
        negatives = self.false_positives + self.true_negatives
        return self.false_positives / negatives if negatives else None

    @property
    def real_world(self) -> bool:
        """True ONLY for a sufficient, production-labelled corpus.

        Derived and not settable. A field would let a report be handed the
        answer it wanted, and `REAL_WORLD_DETECTION_METRICS` is precisely the
        gate that self-assessment cannot close.
        """
        return self.provenance.supports_real_world_claim and self.sufficient

    @property
    def claim(self) -> str:
        """The sentence that may honestly be written under these numbers."""
        if not self.sufficient:
            # Carefully worded. "NOT QUOTABLE" alone invites dismissing a real
            # finding: a detector firing on 26 of 60 ordinary tool names is a
            # serious signal whatever the corpus size, and the benign-action
            # harness exists because exactly that was found. The limit is on
            # EXTRAPOLATION, not on whether the observation counts.
            return (
                f"NOT EXTRAPOLABLE: {self.total} labelled example(s), fewer "
                f"than the {MINIMUM_CORPUS} needed before these rates "
                "describe the detector rather than this corpus. The observed "
                "counts are still a real finding about these examples -- a "
                "high false-positive rate on ordinary inputs is evidence even "
                "from a small set, because it takes only one clear "
                "counterexample to show a detector misfires. What cannot be "
                "done is quoting the RATE as the detector's behaviour."
            )
        if self.real_world:
            return (
                "Measured on production traffic labelled by human review. "
                "This supports a real-world claim, and the sampling method "
                "still belongs beside it."
            )
        return (
            f"Measured on a {self.provenance.value} corpus. These numbers "
            "describe the corpus, NOT production behaviour, and "
            "REAL_WORLD_DETECTION_METRICS remains open. Presenting them as "
            "real-world performance would be the misrepresentation that gate "
            "exists to prevent."
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "provenance": self.provenance.value,
            "provenance_explanation": self.provenance.explanation,
            "total": self.total,
            "sufficient": self.sufficient,
            "precision": self.precision,
            "recall": self.recall,
            "false_positive_rate": self.false_positive_rate,
            "real_world": self.real_world,
            "claim": self.claim,
            "gate": "REAL_WORLD_DETECTION_METRICS",
            "gate_closed": False,
        }


def measure_detection(
    *,
    provenance: CorpusProvenance | str,
    true_positives: int,
    false_positives: int,
    true_negatives: int,
    false_negatives: int,
) -> DetectionMeasurement:
    """Build a measurement, refusing an unrecognised provenance.

    An unrecognised string becomes UNKNOWN rather than raising, because a
    corpus with a mistyped provenance is exactly the corpus whose origin is
    unclear -- and refusing to measure it would push a caller toward deleting
    the field instead of recording the doubt.
    """
    if isinstance(provenance, str):
        try:
            provenance = CorpusProvenance(provenance.strip().lower())
        except ValueError:
            provenance = CorpusProvenance.UNKNOWN
    return DetectionMeasurement(
        provenance=provenance,
        true_positives=true_positives,
        false_positives=false_positives,
        true_negatives=true_negatives,
        false_negatives=false_negatives,
    )
