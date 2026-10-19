"""Honest calibration helpers for hard vs soft detection scores."""

from __future__ import annotations

__all__ = ["compute_low_confidence_region"]


def compute_low_confidence_region(confidence: float) -> bool:
    """Return True when confidence is not a soft calibrated mid-band score.

    DeterministicPolicy emits hard 0.0 / 1.0 labels. Those sit outside any
    calibrated (0, 1) probability band, so callers must not treat them as
    soft probabilities. Soft advisors that emit mid-band scores return False.
    """
    c = float(confidence)
    return not (0.0 < c < 1.0)
