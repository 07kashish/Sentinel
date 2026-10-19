"""Shadow-mode recording and promotion gate for detection policies.

Promotion is refused unless measured gates pass. Does not invent metrics.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

__all__ = ["PromotionDecision", "PromotionGate", "ShadowRecorder"]


@dataclass(frozen=True, slots=True)
class PromotionDecision:
    allowed: bool
    reasons: tuple[str, ...]
    metrics: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reasons": list(self.reasons),
            "metrics": dict(self.metrics),
        }


class PromotionGate:
    """Refuse promotion when measured metrics fail thresholds."""

    def __init__(
        self,
        *,
        min_precision: float = 0.95,
        min_recall: float = 0.70,
        max_ece: float = 0.35,
        require_empty_unexpected_misses: bool = True,
    ) -> None:
        self.min_precision = min_precision
        self.min_recall = min_recall
        self.max_ece = max_ece
        self.require_empty_unexpected_misses = require_empty_unexpected_misses

    def evaluate(self, metrics: Mapping[str, Any]) -> PromotionDecision:
        reasons: list[str] = []
        precision = float(metrics.get("precision") or 0.0)
        recall = float(metrics.get("recall") or 0.0)
        ece = metrics.get("ece")
        misses = list(metrics.get("unexpected_misses") or [])

        if precision < self.min_precision:
            reasons.append(
                f"precision {precision} < required {self.min_precision}"
            )
        if recall < self.min_recall:
            reasons.append(f"recall {recall} < required {self.min_recall}")
        if ece is not None and float(ece) > self.max_ece:
            reasons.append(f"ece {ece} > max {self.max_ece}")
        if self.require_empty_unexpected_misses and misses:
            reasons.append(f"unexpected_misses not empty: {misses}")
        # Soft classifiers may set auc; hard policy leaves null — do not require AUC.
        return PromotionDecision(
            allowed=not reasons, reasons=tuple(reasons), metrics=dict(metrics)
        )


class ShadowRecorder:
    """Append-only shadow predictions for offline comparison."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def record(self, row: Mapping[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(dict(row), sort_keys=True) + "\n")
