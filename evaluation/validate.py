"""Leave-one-source-out validation, ROC/AUC and calibration.

WHY THE PREVIOUS NUMBER WAS NOT TRUSTWORTHY
-------------------------------------------
Council v4, unanimously: the English 0.855 "rides an admitted-adjacent source
confound". Attack cases came from Gandalf/MultiJail/deepset; benign cases came
from xquad/synthetic/jackhhao. Because attack and benign text came from
DIFFERENT corpora, a classifier can score well by recognising **which dataset a
string came from** rather than whether it is an attack.

A random train/test split cannot detect this: both halves contain the same
sources, so provenance is a legitimate signal in both.

**Leave-one-source-out (LOSO) can.** Hold out an entire source, train on the
rest, and score only the held-out source. The model has then never seen that
corpus's vocabulary, formatting or authorship. If performance collapses under
LOSO but looks strong under a random split, the random-split number was
measuring provenance.

FAILURE CLASS: **provenance leakage** -- a label that correlates with the origin
of the data rather than with the property being detected. Related to, but
distinct from, the class-language confound already documented in BENCHMARK.md.

WHAT IS REPORTED
----------------
Per fold and in aggregate: precision, recall, FPR, FNR, F1, ROC AUC, average
precision, and a calibration curve (predicted probability vs observed
frequency). Calibration matters operationally: a SOC tuning a threshold needs
"0.9 means about 90% of these are real", and a model can have excellent AUC while
being badly calibrated.

Usage:
    PYTHONPATH=. py evaluation/validate.py
    PYTHONPATH=. py evaluation/validate.py --json
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from evaluation import benchmark

RESULTS = Path("evaluation/results")


def _metrics(y_true: list[int], y_score: list[float], threshold: float) -> dict:
    """Confusion-matrix metrics at a threshold, plus threshold-free ranking."""
    tp = fp = tn = fn = 0
    for truth, score in zip(y_true, y_score):
        predicted = score >= threshold
        if truth and predicted:
            tp += 1
        elif truth and not predicted:
            fn += 1
        elif not truth and predicted:
            fp += 1
        else:
            tn += 1

    def ratio(num: int, den: int) -> float:
        return num / den if den else 0.0

    recall = ratio(tp, tp + fn)
    precision = ratio(tp, tp + fp)
    out = {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "recall": round(recall, 4),
        "precision": round(precision, 4),
        "fpr": round(ratio(fp, fp + tn), 4),
        "fnr": round(ratio(fn, fn + tp), 4),
        "f1": round(2 * precision * recall / (precision + recall), 4)
        if (precision + recall) else 0.0,
    }

    # Ranking quality, independent of the threshold. Only defined when both
    # classes are present -- a fold of one class has no ROC.
    if len(set(y_true)) == 2:
        from sklearn.metrics import average_precision_score, roc_auc_score

        out["roc_auc"] = round(float(roc_auc_score(y_true, y_score)), 4)
        out["average_precision"] = round(float(average_precision_score(y_true, y_score)), 4)
    else:
        out["roc_auc"] = None
        out["average_precision"] = None
        out["note"] = "single-class fold: ROC and AP are undefined"
    return out


def _calibration(y_true: list[int], y_score: list[float], bins: int = 10) -> list[dict]:
    """Predicted probability vs observed frequency, per bin.

    A model can rank perfectly (AUC 1.0) and still be badly calibrated, which
    makes any operator-facing threshold meaningless.
    """
    buckets: dict[int, list[tuple[int, float]]] = defaultdict(list)
    for truth, score in zip(y_true, y_score):
        buckets[min(int(score * bins), bins - 1)].append((truth, score))

    curve = []
    for index in range(bins):
        rows = buckets.get(index, [])
        if not rows:
            continue
        curve.append({
            "bin": f"{index / bins:.1f}-{(index + 1) / bins:.1f}",
            "n": len(rows),
            "mean_predicted": round(sum(s for _, s in rows) / len(rows), 4),
            "observed_positive_rate": round(sum(t for t, _ in rows) / len(rows), 4),
        })
    return curve


def _expected_calibration_error(curve: list[dict]) -> float:
    total = sum(b["n"] for b in curve) or 1
    return round(
        sum(b["n"] * abs(b["mean_predicted"] - b["observed_positive_rate"]) for b in curve)
        / total,
        4,
    )


#: The semantic model this script was written to evaluate NO LONGER EXISTS.
#:
#: It depended on `app.detection.semantic_features.vectorise` -- eighteen
#: interpretable attack-semantic features -- and the `app` package was removed
#: when the codebase moved to the hexagonal `sentinel` layout. No successor was
#: ported: `vectorise` and `semantic_features` appear nowhere in the tree today.
#:
#: Until that import was removed, running this script AT ALL raised
#: `ModuleNotFoundError: No module named 'app.detection'`, because `semantic`
#: was the default model. Shipping a release containing a script that crashes on
#: its own default is the defect this removal closes.
#:
#: WHAT IS LOST, STATED RATHER THAN HIDDEN: the comparison this file argues for.
#: Its thesis is that a low-capacity semantic model resists provenance
#: memorisation where a 200,000-feature n-gram model does not, and that
#: comparison cannot be run until the features are re-implemented. The n-gram
#: model is still worth putting through leave-one-source-out -- LOSO is precisely
#: how its collapse would be demonstrated -- but a strong LOSO result here would
#: be a result about n-grams, not evidence for the semantic claim above.
SEMANTIC_MODEL_UNAVAILABLE: str = (
    "the semantic feature extractor was removed with the `app` package and has "
    "no successor in this tree; only the n-gram model can be validated"
)


def leave_one_source_out(
    cases: list[benchmark.Case], threshold: float = 0.5, model: str = "ngram"
) -> dict:
    """Train on every source but one; score only the held-out source.

    `model` defaults to `ngram` because it is the only model that still exists.
    Asking for `semantic` raises rather than silently falling back: a fallback
    would report an n-gram number under a semantic label, which is worse than
    an error in exactly the way this file's own thesis describes.
    """
    from evaluation.train_classifier import build_pipeline

    if model == "semantic":
        raise NotImplementedError(SEMANTIC_MODEL_UNAVAILABLE)
    if model != "ngram":
        raise ValueError(f"unknown model {model!r}; only 'ngram' is available")

    def build():
        return build_pipeline()

    # Group by ORIGIN, ignoring the "(derived)" suffix so an obfuscated variant
    # is held out with the corpus it came from.
    def origin(case: benchmark.Case) -> str:
        return case.source.replace(" (derived)", "")

    sources = sorted({origin(c) for c in cases})
    folds: dict[str, dict] = {}
    pooled_true: list[int] = []
    pooled_score: list[float] = []

    for held_out in sources:
        train = [c for c in cases if origin(c) != held_out]
        test = [c for c in cases if origin(c) == held_out]
        if not test or len({c.label for c in train}) < 2:
            folds[held_out] = {"skipped": "training set has fewer than two classes"}
            continue

        pipeline = build()
        pipeline.fit([c.text for c in train], [1 if c.label == "attack" else 0 for c in train])

        y_true = [1 if c.label == "attack" else 0 for c in test]
        y_score = [float(p[1]) for p in pipeline.predict_proba([c.text for c in test])]

        fold = _metrics(y_true, y_score, threshold)
        fold["n_test"] = len(test)
        fold["n_train"] = len(train)
        fold["classes_in_fold"] = sorted({c.label for c in test})
        # PER-FOLD calibration, which is the only kind that means anything here.
        # A single-class fold has an observed positive rate of exactly 1.0 or
        # 0.0 in every populated bin, so its "calibration error" is a restatement
        # of the class balance, not a property of the model. It is computed for
        # every fold for completeness and consumed only for the mixed ones.
        fold_curve = _calibration(y_true, y_score)
        fold["calibration"] = fold_curve
        fold["expected_calibration_error"] = _expected_calibration_error(fold_curve)
        folds[held_out] = fold

        pooled_true.extend(y_true)
        pooled_score.extend(y_score)

    # POOLING ACROSS FOLDS IS NOT VALID HERE, and reporting it as a headline
    # would be its own dishonesty.
    #
    # Four of the six sources are SINGLE-CLASS: MultiJail and Gandalf are all
    # attacks, xquad and the synthetic set are all benign. A model produces a
    # different score distribution per fold, so concatenating them mixes
    # populations with different base rates and can invert the ranking. The first
    # run of this reported a pooled AUC of 0.188 -- "worse than random" -- which
    # says more about the pooling than the model.
    #
    # AUC is therefore reported ONLY for folds containing both classes, and the
    # pooled confusion counts are labelled as diagnostic, not as a headline.
    mixed = {
        name: fold for name, fold in folds.items()
        if "skipped" not in fold and fold.get("roc_auc") is not None
    }
    pooled = _metrics(pooled_true, pooled_score, threshold)
    pooled["interpretation"] = (
        "Confusion counts only. ROC/AP pooled across single-class folds are not "
        "meaningful; see per-fold values for mixed-class sources."
    )
    curve = _calibration(pooled_true, pooled_score)
    pooled_ece = _expected_calibration_error(curve)

    # THE SAME OBJECTION THAT DISQUALIFIES POOLED AUC DISQUALIFIES POOLED ECE.
    #
    # The comment above explains at length why ROC/AP must not be pooled across
    # single-class folds -- different populations, different base rates. That
    # argument is not about ROC. It is about the pooling. Calibration compares a
    # predicted probability against an OBSERVED POSITIVE RATE, and in a
    # single-class fold that rate is 1.0 or 0.0 in every bin by construction, so
    # concatenating four single-class folds with two mixed ones produces a
    # number governed by the class balance of the concatenation.
    #
    # This module computed the pooled ECE anyway and returned it as the headline
    # `expected_calibration_error`. That value (0.4836 for the semantic model) is
    # quoted in docs/ADVERSARIAL_REVIEW.md as evidence that "confidence scores
    # cannot be used to set an operational threshold". It is not sound evidence
    # for that claim -- it is the pooling artefact this file already refuses to
    # publish for AUC.
    #
    # So: the pooled figure is KEPT, because deleting it would erase the record,
    # but it is renamed to say what it is, and the headline is now the mean over
    # folds where calibration is a meaningful question at all.
    mixed_eces = [
        fold["expected_calibration_error"]
        for fold in mixed.values()
        if fold.get("expected_calibration_error") is not None
    ]
    return {
        "mixed_class_folds": mixed,
        "cross_source_auc": (
            round(sum(f["roc_auc"] for f in mixed.values()) / len(mixed), 4)
            if mixed else None
        ),
        "model": model,
        "threshold": threshold,
        "sources": sources,
        "folds": folds,
        "pooled": pooled,
        "calibration": curve,
        #: Mean ECE over folds containing BOTH classes. The headline.
        "expected_calibration_error": (
            round(sum(mixed_eces) / len(mixed_eces), 4) if mixed_eces else None
        ),
        "expected_calibration_error_basis": (
            f"mean over {len(mixed_eces)} mixed-class fold(s): "
            f"{sorted(mixed.keys())}. Single-class folds are excluded because "
            "their observed positive rate is 1.0 or 0.0 by construction."
        ),
        "expected_calibration_error_by_fold": {
            name: fold.get("expected_calibration_error")
            for name, fold in folds.items()
            if "skipped" not in fold
        },
        #: Retained for continuity with earlier runs. NOT a headline: see above.
        "expected_calibration_error_pooled_INVALID": pooled_ece,
        "expected_calibration_error_pooled_note": (
            "Pooled across single-class folds. Subject to the same objection this "
            "module documents for pooled ROC/AP. Previously reported as the "
            "headline `expected_calibration_error`; do not cite it as one."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--threshold", type=float, default=0.5)
    # `ngram` is the default because it is the only model that still exists.
    # `semantic` remains a documented choice so the request produces an
    # explanation rather than an "invalid choice" that reads like a typo.
    parser.add_argument("--model", choices=["semantic", "ngram"], default="ngram")
    args = parser.parse_args()

    cases = benchmark.load()
    result = leave_one_source_out(cases, threshold=args.threshold, model=args.model)

    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / f"leave_one_source_out_{args.model}.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8"
    )

    if args.json:
        print(json.dumps(result, indent=2))
        return

    print(f"\n=== LEAVE-ONE-SOURCE-OUT (threshold {args.threshold}) ===")
    print("Each row: the model NEVER saw this corpus during training.\n")
    for name, fold in result["folds"].items():
        if "skipped" in fold:
            print(f"  {name:46} SKIPPED ({fold['skipped']})")
            continue
        auc = fold["roc_auc"]
        print(
            f"  {name:46} recall {fold['recall']:.3f}  fpr {fold['fpr']:.3f}  "
            f"auc {auc if auc is not None else 'n/a':<6} n={fold['n_test']}"
        )

    pooled = result["pooled"]
    print("\n  POOLED across all held-out folds:")
    print(f"    recall    {pooled['recall']:.3f}")
    print(f"    precision {pooled['precision']:.3f}")
    print(f"    FPR       {pooled['fpr']:.3f}")
    print(f"    FNR       {pooled['fnr']:.3f}")
    print(f"    F1        {pooled['f1']:.3f}")
    print(f"    (pooled ROC/AP omitted: {pooled['interpretation']})")
    print(f"\n  Expected calibration error: {result['expected_calibration_error']}")
    print("  (0 = predicted probability matches observed frequency exactly)")
    print("\n  calibration curve:")
    for row in result["calibration"]:
        print(f"    {row['bin']:>9}  n={row['n']:<5} predicted {row['mean_predicted']:.3f}"
              f"  observed {row['observed_positive_rate']:.3f}")


if __name__ == "__main__":
    main()
