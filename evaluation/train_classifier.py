"""Fit the statistical detection layer on the benchmark's TRAIN split ONLY.

The test split is never loaded here. Not filtered after loading -- never loaded.

Usage:  PYTHONPATH=. py evaluation/train_classifier.py
"""

from __future__ import annotations

import hashlib
import json
import pickle
from datetime import datetime, timezone
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from evaluation import benchmark
from evaluation.soft_prompt import DEFAULT_ARTIFACT

OUT = DEFAULT_ARTIFACT
CARD = Path("evaluation/artifacts/soft_prompt_model_card.json")


def build_pipeline() -> Pipeline:
    """Character n-grams: language-agnostic by construction."""
    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer="char_wb",
                    ngram_range=(2, 5),
                    min_df=2,
                    max_features=200_000,
                    sublinear_tf=True,
                    lowercase=True,
                ),
            ),
            (
                "clf",
                LogisticRegression(
                    max_iter=2000,
                    class_weight="balanced",
                    C=1.0,
                ),
            ),
        ]
    )


def main() -> None:
    all_cases = benchmark.load()
    train = [c for c in all_cases if c.split == "train"]
    if not train:
        raise SystemExit("no training cases; run the benchmark builder first")

    texts = [c.text for c in train]
    labels = [1 if c.label == "attack" else 0 for c in train]

    print(
        f"training on {len(train)} TRAIN cases "
        f"({sum(labels)} attack / {len(labels) - sum(labels)} benign)"
    )
    print("test split is NOT loaded in this process")

    pipeline = build_pipeline()
    pipeline.fit(texts, labels)

    fingerprint = hashlib.sha256(
        "".join(sorted(c.case_id for c in train)).encode()
    ).hexdigest()[:16]

    meta = {
        "version": f"charngram-lr@{datetime.now(timezone.utc):%Y%m%d}-{fingerprint}",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "n_train": len(train),
        "n_attack": sum(labels),
        "n_benign": len(labels) - sum(labels),
        "train_fingerprint": fingerprint,
        "sources": [
            s["dataset"] for s in (*benchmark.SOURCES, *benchmark.WIDE_SOURCES)
        ],
        "note": (
            "Trained on the TRAIN split only. Any metric quoted on the TEST "
            "split is out-of-sample with respect to this artifact."
        ),
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("wb") as fh:
        pickle.dump({"pipeline": pipeline, "meta": meta}, fh)

    CARD.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB)  version={meta['version']}")


if __name__ == "__main__":
    main()
