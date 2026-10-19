"""Soft prompt-injection / jailbreak classifier for independent-corpus scoring.

Trained ONLY on the benchmark TRAIN split (see evaluation/train_classifier.py).
Artifact lives under evaluation/artifacts/ — not committed model weights unless
an operator chooses to.

This module is the loader used by evaluation/run_benchmark.py --soft and by
optional runtime SoftPromptDetector. It does not invent labels.
"""

from __future__ import annotations

import pickle
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_ARTIFACT = Path("evaluation/artifacts/soft_prompt_model.pkl")


@dataclass(frozen=True, slots=True)
class SoftPromptClassifier:
    """Char n-gram logistic regression over prompt text."""

    pipeline: Any
    meta: dict[str, Any]
    path: Path

    @classmethod
    def load(cls, path: Path = DEFAULT_ARTIFACT) -> SoftPromptClassifier | None:
        if not path.exists():
            return None
        with path.open("rb") as fh:
            blob = pickle.load(fh)  # noqa: S301 — local artifact from our trainer
        return cls(pipeline=blob["pipeline"], meta=dict(blob.get("meta") or {}), path=path)

    @classmethod
    def load_default(cls) -> SoftPromptClassifier | None:
        return cls.load(DEFAULT_ARTIFACT)

    def predict_proba(self, text: str) -> float:
        proba = self.pipeline.predict_proba([text])[0]
        # class 1 = attack when trained with labels 0/1
        classes = list(getattr(self.pipeline, "classes_", [0, 1]))
        if 1 in classes:
            return float(proba[classes.index(1)])
        return float(proba[-1])
