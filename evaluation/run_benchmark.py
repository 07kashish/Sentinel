"""Score detectors against the external third-party benchmark.

Uses the production DeterministicPolicy path, not a reimplemented harness.

Usage:
    py evaluation/run_benchmark.py            # train split (development)
    py evaluation/run_benchmark.py --test     # held-out split (report this)
    py evaluation/run_benchmark.py --test --english
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

# Run by PATH, not as a module, so the repository root is not on sys.path and
# `from evaluation import benchmark` below fails with ModuleNotFoundError.
# `evaluation/metrics.py` has carried this same line for exactly this reason;
# this script did not, so it only ever worked when the caller happened to set
# PYTHONPATH. CI does not, and the step added to regenerate the promotion-floor
# benchmark died on it immediately.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from evaluation import benchmark  # noqa: E402 - after the sys.path fix above
from sentinel.domain.primitives import TrustLevel  # noqa: E402
from sentinel.infrastructure.detection import DeterministicPolicy  # noqa: E402

RESULTS = Path("evaluation/results")


@dataclass
class Confusion:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def fpr(self) -> float:
        d = self.fp + self.tn
        return self.fp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def as_dict(self) -> dict:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "total": self.total,
            "recall": round(self.recall, 4),
            "precision": round(self.precision, 4),
            "fpr": round(self.fpr, 4),
            "f1": round(self.f1, 4),
        }


def _to_payload(case: benchmark.Case) -> dict[str, Any]:
    """Map a benchmark prompt into the event shape production evaluates.

    Prompt text is placed in both `action` and `metadata.prompt` so policy rules
    that scan either field see it — matching how SDK/API events present prompts.
    """
    return {
        "eventId": case.case_id[:16],
        "timestamp": "2026-08-10T00:00:00Z",
        "agentId": "0x" + "be" * 20,
        "source": "benchmark",
        "eventType": "prompt",
        "action": case.text,
        "metadata": {
            "prompt": case.text,
            "benchmark_case": case.case_id,
            "language": case.language,
            "provenance_source": case.source,
        },
    }


def score(cases: list[benchmark.Case]) -> dict:
    policy = DeterministicPolicy.default()
    overall = Confusion()
    by_category: dict[str, Confusion] = defaultdict(Confusion)
    by_language: dict[str, Confusion] = defaultdict(Confusion)
    by_transform: dict[str, Confusion] = defaultdict(Confusion)
    misses: list[dict] = []

    for case in cases:
        payload = _to_payload(case)
        try:
            fired = policy.evaluate(
                payload=payload, trust=TrustLevel.UNSIGNED
            ).fired
        except Exception:  # noqa: BLE001
            fired = False

        is_attack = case.label == "attack"
        for bucket in (
            overall,
            by_category[case.category],
            by_language[case.language],
            by_transform[case.transform],
        ):
            if is_attack and fired:
                bucket.tp += 1
            elif is_attack and not fired:
                bucket.fn += 1
            elif not is_attack and fired:
                bucket.fp += 1
            else:
                bucket.tn += 1

        if is_attack and not fired:
            misses.append(
                {
                    "case_id": case.case_id,
                    "category": case.category,
                    "language": case.language,
                    "transform": case.transform,
                    "excerpt": case.text[:120],
                    "source": case.source,
                }
            )

    return {
        "detector": policy.version(),
        "overall": overall.as_dict(),
        "by_category": {k: v.as_dict() for k, v in sorted(by_category.items())},
        "by_language": {k: v.as_dict() for k, v in sorted(by_language.items())},
        "by_transform": {k: v.as_dict() for k, v in sorted(by_transform.items())},
        "missed_sample": misses[:40],
        "missed_total": len(misses),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--test",
        action="store_true",
        help="score the HELD-OUT split (report this number)",
    )
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--english",
        action="store_true",
        help="restrict to English cases (defensible claim per BENCHMARK.md)",
    )
    args = parser.parse_args()

    split = "test" if args.test else "train"
    cases = [c for c in benchmark.load() if c.split == split]
    if args.english:
        cases = [c for c in cases if c.language == "en"]
    result = score(cases)
    result["split"] = split
    result["n_cases"] = len(cases)
    result["english_only"] = bool(args.english)

    from evaluation.promotion import PromotionGate

    gate_metrics: Mapping[str, Any] = {
        "precision": result["overall"]["precision"],
        "recall": result["overall"]["recall"],
        "ece": None,
        "unexpected_misses": [],
    }
    result["promotion"] = PromotionGate().evaluate(gate_metrics).as_dict()

    RESULTS.mkdir(parents=True, exist_ok=True)
    suffix = split
    if args.english:
        suffix += "_english"
    out = RESULTS / f"benchmark_{suffix}.json"
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    o = result["overall"]
    print(f"\n=== {split.upper()} split — {len(cases)} cases ===")
    print(f"  detector  {result['detector']}")
    print(f"  recall    {o['recall']:.3f}   ({o['tp']} of {o['tp']+o['fn']} attacks caught)")
    print(f"  precision {o['precision']:.3f}")
    print(f"  FPR       {o['fpr']:.3f}   ({o['fp']} of {o['fp']+o['tn']} benign flagged)")
    print(f"  F1        {o['f1']:.3f}")
    print(f"  promotion allowed={result['promotion']['allowed']} reasons={result['promotion']['reasons']}")
    print(f"  wrote {out}")

    if args.test:
        print(
            "\n  NOTE: this was the held-out split. Using it to choose a rule "
            "\n  consumes it as evidence. Tune on train."
        )


if __name__ == "__main__":
    main()
