"""Detection evaluation against a labeled corpus.

Council Finding 11: this file used to poll the live API and compute
`detection_accuracy = min(high_risk_count / 7, 1.0) * 100`, where 7 was hardwired
to the demo dataset. It matched no predictions to labels, so a false negative was
unrepresentable, "false positives" were defined without ground truth, and
"latency" was polling wall-time divided by incident count. No number it printed
could support a claim.

This version runs the *actual detection path*
(sentinel.infrastructure.detection.DeterministicPolicy.evaluate)
over `evaluation.corpus`, where every case carries a label, and reports real
confusion-matrix metrics plus per-category recall and per-case latency.

Run:  py evaluation/metrics.py [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Ported from the retired `app.monitoring.rules` to the detection ADAPTER the
# rewritten tree exposes. The gate is unchanged in what it measures: the same
# corpus through the same deterministic rules, so the numbers stay comparable
# across the rewrite. What changed is that the policy is now reached through a
# port, so this script constructs one explicitly instead of importing a
# module-level singleton.
from evaluation.intervals import wilson
from evaluation.corpus import CASES, summary  # noqa: E402
from sentinel.domain.primitives import TrustLevel  # noqa: E402
from sentinel.infrastructure.detection import DeterministicPolicy  # noqa: E402


@dataclass
class Outcome:
    case_id: str
    category: str
    expected: bool
    predicted: bool
    known_gap: bool
    latency_ms: float
    severity: int | None


def run() -> dict:
    outcomes: list[Outcome] = []
    policy = DeterministicPolicy.default()

    # Primary gate corpus remains evaluation.corpus.CASES (CI regression).
    for case in CASES:
        started = time.perf_counter()
        verdict = policy.evaluate(
            payload=case.event, trust=TrustLevel(case.trust_level)
        )
        elapsed_ms = (time.perf_counter() - started) * 1000

        outcomes.append(
            Outcome(
                case_id=case.case_id,
                category=case.category,
                expected=case.malicious,
                predicted=verdict.fired,
                known_gap=case.known_gap,
                latency_ms=elapsed_ms,
                severity=verdict.severity.value if verdict.fired else None,
            )
        )

    tp = sum(1 for o in outcomes if o.expected and o.predicted)
    fp = sum(1 for o in outcomes if not o.expected and o.predicted)
    fn = sum(1 for o in outcomes if o.expected and not o.predicted)
    tn = sum(1 for o in outcomes if not o.expected and not o.predicted)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    by_category: dict[str, dict] = {}
    for category in sorted({o.category for o in outcomes}):
        rows = [o for o in outcomes if o.category == category and o.expected]
        if rows:
            by_category[category] = {
                "malicious_cases": len(rows),
                "detected": sum(1 for o in rows if o.predicted),
                "recall": round(sum(1 for o in rows if o.predicted) / len(rows), 3),
            }

    latencies = [o.latency_ms for o in outcomes]
    missed = [o.case_id for o in outcomes if o.expected and not o.predicted]
    false_alarms = [o.case_id for o in outcomes if not o.expected and o.predicted]
    surprises = [o.case_id for o in outcomes
                 if o.expected and not o.predicted and not o.known_gap]

    # Binary policy emits hard labels. Treat predicted=True as confidence 1.0
    # and False as 0.0 so ECE is computable and honest about being uncalibrated
    # probability estimates (not a soft classifier).
    confidences = [1.0 if o.predicted else 0.0 for o in outcomes]
    ece = _expected_calibration_error(
        [1 if o.expected else 0 for o in outcomes], confidences, n_bins=10
    )

    same_source = _eval_case_list(policy, _same_source_cases())

    primary = {
        "policy": policy.version(),
        "corpus": summary(),
        "confusion_matrix": {
            "true_positives": tp, "false_positives": fp,
            "false_negatives": fn, "true_negatives": tn,
        },
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "false_positive_rate": round(fpr, 3),
        # PHASE 12. The point estimates above are what get quoted; these are
        # what the sample actually supports.
        #
        # `precision: 1.0` from 11 true positives and 0 false positives is
        # correct and is not what a reader takes from it. Eleven trials with no
        # failures does not mean "no false positives" -- it means the rate is
        # somewhere below roughly a quarter at 95% confidence. Quoted as 1.0 it
        # becomes "zero false positives" in a slide, and the first production
        # false positive then reads as a regression rather than as the thing
        # eleven samples never had the power to exclude.
        #
        # `quotable` is false below 30 samples whatever the point estimate
        # looks like, and each interval carries the sentence a reader should
        # take away -- because the failure here is a human one, and the honest
        # wording has to travel with the number when the number is copied.
        "intervals": {
            "precision": wilson(tp, tp + fp).as_dict(),
            "recall": wilson(tp, tp + fn).as_dict(),
            "false_positive_rate": wilson(fp, fp + tn).as_dict(),
        },
        "ece": round(ece, 4),
        "ece_notes": (
            "ECE from hard 0/1 confidences on DeterministicPolicy — not a soft "
            "probabilistic model. Do not claim calibration improvement vs soft classifiers."
        ),
        # F1 deliberately has NO interval. It is a harmonic mean of two
        # proportions, not itself a proportion, so a Wilson interval over it
        # would be a number with the right shape and no meaning. Omitted with
        # the reason rather than approximated.
        "f1_interval_notes": (
            "no interval: F1 is a harmonic mean of two proportions, not a "
            "proportion. Read the precision and recall intervals instead."
        ),
        "auc": None,
        "auc_notes": (
            "AUC not computed for hard deterministic policy on this corpus; "
            "leave null rather than fabricate."
        ),
        "recall_by_category": by_category,
        "latency_ms": {
            "mean": round(statistics.mean(latencies), 3),
            "p95": round(sorted(latencies)[int(len(latencies) * 0.95) - 1], 3),
            "max": round(max(latencies), 3),
        },
        "missed_cases": missed,
        "false_alarm_cases": false_alarms,
        "unexpected_misses": surprises,
        "same_source": same_source,
        "interpretation": (
            "Measured on a small hand-written corpus, NOT production traffic. "
            "Recall here is an upper bound: the corpus contains the evasions we "
            "already know about. Do not quote these figures as a product "
            "detection rate."
        ),
    }
    from evaluation.promotion import PromotionGate

    primary["promotion"] = PromotionGate().evaluate(primary).as_dict()
    return primary


def _same_source_cases():
    from evaluation.same_source_corpus import as_cases

    return as_cases()


def _eval_case_list(policy: DeterministicPolicy, cases) -> dict:
    tp = fp = tn = fn = 0
    for case in cases:
        verdict = policy.evaluate(
            payload=case.event, trust=TrustLevel(case.trust_level)
        )
        if case.malicious and verdict.fired:
            tp += 1
        elif case.malicious and not verdict.fired:
            fn += 1
        elif not case.malicious and verdict.fired:
            fp += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (
        (2 * precision * recall / (precision + recall))
        if (precision + recall)
        else 0.0
    )
    return {
        "total": len(cases),
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "note": "Synthetic same-source metrics; not a production claim.",
    }


def _expected_calibration_error(
    y_true: list[int], y_prob: list[float], *, n_bins: int
) -> float:
    if not y_true:
        return 0.0
    bins = [[] for _ in range(n_bins)]
    for truth, prob in zip(y_true, y_prob):
        idx = min(n_bins - 1, int(prob * n_bins))
        bins[idx].append((truth, prob))
    total = len(y_true)
    ece = 0.0
    for bucket in bins:
        if not bucket:
            continue
        acc = sum(t for t, _ in bucket) / len(bucket)
        conf = sum(p for _, p in bucket) / len(bucket)
        ece += (len(bucket) / total) * abs(acc - conf)
    return ece


def main() -> int:
    ap = argparse.ArgumentParser(description="Evaluate detection against labeled corpus.")
    ap.add_argument("--json", type=str, default="", help="write results to this path")
    ap.add_argument(
        "--record-registry",
        action="store_true",
        help="append measured metrics to evaluation/model_registry.json",
    )
    args = ap.parse_args()

    results = run()
    print(json.dumps(results, indent=2))

    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=2), encoding="utf-8")

    if args.record_registry:
        from evaluation.registry import entry_from_metrics, record_entry

        record_entry(
            entry_from_metrics(
                name="DeterministicPolicy",
                version=str(results["policy"]),
                kind="deterministic_rules",
                metrics={
                    "precision": results["precision"],
                    "recall": results["recall"],
                    "f1": results["f1"],
                    "ece": results["ece"],
                    "auc": results["auc"],
                    "corpus_total": results["corpus"].get("total"),
                },
                notes="Measured by evaluation/metrics.py; F-10 remains OPEN",
            )
        )

    # A regression on a case we did NOT expect to miss fails the run.
    if results["unexpected_misses"]:
        print(f"\nFAIL: unexpected misses: {results['unexpected_misses']}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
