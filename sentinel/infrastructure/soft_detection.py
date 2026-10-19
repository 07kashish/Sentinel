"""Soft prompt classifier OR'd with DeterministicPolicy for free-text prompts.

Model loading lives in `evaluation.soft_prompt` (TRAIN-split artifact). This
module never deserialises — it only scores via a callable injected at
composition time, keeping pickle out of `sentinel/`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Mapping

from sentinel.application.calibration import compute_low_confidence_region
from sentinel.application.records import DetectionVerdict
from sentinel.domain.primitives import Severity, TrustLevel
from sentinel.infrastructure.detection import DeterministicPolicy

__all__ = ["DetectionMode", "SoftAugmentedPolicy", "SoftPromptScorer"]


class DetectionMode(str, Enum):
    """Which detector is actually running, as opposed to which one is configured.

    The distinction exists because the failure this names was silent. When the
    soft prompt artifact could not be loaded, composition returned the rules-only
    policy and said nothing, and the deployment kept answering `{"ready": true}`
    while measured independent English recall fell from ~0.855 to ~0.067. Nothing
    in the product surfaced the difference: an operator could only discover it by
    noticing the incidents that were never raised.

    So the mode is a value the composition root computes once and the readiness
    probe reports, and `RULES_ONLY_DEGRADED` is accompanied by a CRITICAL log.
    """

    #: Soft prompt classifier loaded and OR'd with the deterministic rules.
    SOFT_AND_RULES = "soft+rules"
    #: Soft detection was requested but the artifact did not load. Unintended.
    RULES_ONLY_DEGRADED = "rules-only-degraded"
    #: Operator explicitly disabled soft detection. Still rules-only recall, but
    #: a deliberate choice rather than a failure -- distinguished so that the
    #: CRITICAL alert on the degraded mode means something when it fires.
    RULES_ONLY_CONFIGURED = "rules-only-configured"


@dataclass(frozen=True, slots=True)
class SoftPromptScorer:
    """Pure scoring facade — no deserialization."""

    score_fn: Callable[[str], float]
    version: str
    threshold: float = 0.5

    def score(self, text: str) -> float:
        return float(self.score_fn(text))


class SoftAugmentedPolicy:
    """DeterministicPolicy OR soft prompt scorer for free-text prompt fields."""

    __slots__ = ("_base", "_soft")

    def __init__(
        self, *, base: DeterministicPolicy, soft: SoftPromptScorer | None
    ) -> None:
        self._base = base
        self._soft = soft

    def version(self) -> str:
        if self._soft is None:
            return self._base.version()
        return f"{self._base.version()}+soft@{self._soft.version}"

    def evaluate(
        self, *, payload: Mapping[str, Any], trust: TrustLevel
    ) -> DetectionVerdict:
        base = self._base.evaluate(payload=payload, trust=trust)
        if base.fired or self._soft is None:
            return base

        text = _prompt_text(payload)
        if not text or len(text.strip()) < 8:
            return base

        score = self._soft.score(text)
        if score < self._soft.threshold:
            return base

        confidence = float(score)
        low_conf = compute_low_confidence_region(confidence)
        signals = dict(base.signals)
        signals["soft_prompt"] = {
            "fired": True,
            "score": round(score, 4),
            "threshold": self._soft.threshold,
            "version": self._soft.version,
        }
        signals["calibration"] = {
            "confidence": confidence,
            "low_confidence_region": low_conf,
            "note": (
                "soft prompt classifier probability — mid-band scores are "
                "calibrated-region candidates"
            ),
        }
        return DetectionVerdict(
            fired=True,
            severity=Severity(75),
            incident_type="prompt_injection_attempt",
            description=(
                f"soft prompt classifier score {score:.3f} ≥ {self._soft.threshold}"
            ),
            matched_rules=("soft-prompt-classifier",),
            detector_version=self.version(),
            signals=signals,
            confidence=confidence,
            low_confidence_region=low_conf,
        )


def _prompt_text(payload: Mapping[str, Any]) -> str:
    meta = payload.get("metadata")
    if isinstance(meta, Mapping):
        prompt = meta.get("prompt")
        if isinstance(prompt, str) and prompt.strip():
            return prompt
    # THE `action` FALLBACK IS RESTRICTED TO DECLARED PROMPT EVENTS.
    #
    # It used to apply to `tool_call` and to events with NO eventType as well,
    # which meant the classifier spent most of its life judging TOOL NAMES --
    # `read_file`, `http_get` -- as though they were prompts. Measured
    # consequence (F-10 in docs/THREAT_MODEL.md,
    # scripts/measure_benign_tool_call_false_positives.py):
    #
    #     31 of 60 ordinary tool-call actions fired at the shipped 0.5 threshold
    #     http_get 0.709 | write_file 0.657 | db_insert 0.651 | send_email 0.602
    #
    # 51.7% of routine agent activity raised a prompt_injection_attempt
    # incident. Each one wrote across four tables, which is also where the
    # ingest p95 went: 786 ms with the false positives, 58 ms without.
    #
    # WHY THE FEATURE COULD NEVER HAVE WORKED, rather than merely working
    # badly. In `evaluation/corpus.py` the same action string carries both
    # labels: `read_file` is malicious 4 times and benign twice, `http_request`
    # 2 and 2, `benign_lookup` 1 and 1. What separates them is the RESOURCE
    # (`README.md` vs `/root/.aws/credentials`) or the TRUST LEVEL -- never the
    # action. The classifier was being handed a string that does not contain
    # the answer, so no threshold and no amount of retraining could have
    # extracted one. `DeterministicPolicy` decides those cases, on the resource,
    # and is untouched by this.
    #
    # Kept for `eventType == "prompt"`: an event that DECLARES itself a prompt
    # but carries the text in `action` is a real client shape, and dropping it
    # would lose genuine detection. Every prompt case in the corpus supplies
    # `metadata.prompt`, so this path costs nothing there and is retained for
    # callers that do not.
    action = payload.get("action")
    event_type = str(payload.get("eventType") or payload.get("event_type") or "")
    if isinstance(action, str) and event_type == "prompt":
        return action
    return ""
