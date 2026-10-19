"""Deterministic detection. No model is in this decision path.

The severity produced here is RAW. The trust cap is applied by
`Severity.capped_for` inside the aggregate, so a caller that bypasses this
detector still cannot exceed it -- which is exactly what five of the
predecessor's six ingest routes did.

WHY THIS LOADS A FILE
---------------------
The ruleset lives in `config/default_policy.json`, versioned and editable by the
operator, and this module is the engine that runs it. That separation was one of
the genuinely good decisions in the predecessor and is preserved deliberately: a
customer tuning detection must not need to fork the codebase, and a finding must
be traceable to the exact ruleset version that produced it.

An earlier form of this adapter shipped a hard-coded ruleset of my own instead of
loading that file. It looked equivalent and was not: the shipped policy supports
four match modes, nested field paths, event-type scoping and exclusion lists,
and the replacement supported one mode and flat fields. The detection-evaluation
gate in CI caught the regression -- five corpus cases that had been detected
stopped being detected -- which is precisely what that gate exists for.

MATCH MODES
-----------
    contains        any value appears as a substring
    regex           any value matches as a regular expression
    host_endswith   the URL host ends with any value (never a bare substring,
                    so `evil-example.com` cannot match a rule for `example.com`)
    gt              a numeric field exceeds a threshold
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse

from sentinel.application.calibration import compute_low_confidence_region
from sentinel.application.records import DetectionVerdict
from sentinel.domain.action_semantics import enrich_payload
from sentinel.domain.primitives import Severity, TrustLevel

__all__ = ["DeterministicPolicy", "PolicyRule", "PolicyError"]

#: Shipped alongside the code, overridable per deployment.
#: The packaged ruleset, a wheel member, is the fallback; the checkout copy
#: under `config/` wins when present so an operator editing it sees the
#: effect. A test asserts the two are byte-identical so the choice is moot in
#: a clean tree and a clean install starts without a repository around it.
_PACKAGED_POLICY_PATH = Path(__file__).resolve().parent / "default_policy.json"
_CHECKOUT_POLICY_PATH = Path(__file__).resolve().parents[2] / "config" / "default_policy.json"
DEFAULT_POLICY_PATH = (
    _CHECKOUT_POLICY_PATH if _CHECKOUT_POLICY_PATH.is_file() else _PACKAGED_POLICY_PATH
)
MAX_MATCH_TEXT = 64 * 1024


class PolicyError(RuntimeError):
    """The policy file is missing, malformed, or names an unknown match mode.

    Raised at construction rather than at evaluation. A detection product that
    starts with a broken ruleset and discovers it during an incident is worse
    than one that refuses to start.
    """


def _resolve(payload: Mapping[str, Any], path: str) -> Any:
    """Read a dotted field path. `metadata.prompt` reaches into nested dicts."""
    current: Any = payload
    for part in path.split("."):
        if not isinstance(current, Mapping):
            return None
        current = current.get(part)
        if current is None:
            return None
    return current


def _text_values(value: Any) -> tuple[str, ...]:
    """Flatten a matched field into bounded strings, preserving raw semantics."""
    if value is None:
        return ()
    if isinstance(value, str):
        return (value[:MAX_MATCH_TEXT],)
    if isinstance(value, (int, float, bool)):
        return (str(value),)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        out: list[str] = []
        total = 0
        for item in value[:256]:
            for text in _text_values(item):
                remaining = MAX_MATCH_TEXT - total
                if remaining <= 0:
                    return tuple(out)
                out.append(text[:remaining])
                total += len(out[-1])
        return tuple(out)
    if isinstance(value, Mapping):
        return (json.dumps(value, default=str)[:MAX_MATCH_TEXT],)
    return (str(value)[:MAX_MATCH_TEXT],)


def _literal_hint(pattern: str) -> str:
    """A conservative substring pre-check for regex rules.

    Empty means "no useful literal found"; correctness stays with `re`, this is
    only a cheap way not to run regexes over every large field.
    """
    if any(token in pattern for token in ("(?", "|", "[", ")")):
        return ""
    literals = re.findall(r"[A-Za-z0-9_./:@-]{3,}", pattern)
    if not literals:
        return ""
    return max(literals, key=len).lower()


@dataclass(frozen=True, slots=True)
class PolicyRule:
    """One deterministic rule. Reproducible from its version alone."""

    rule_id: str
    description: str
    field: str
    mode: str
    values: tuple[Any, ...]
    severity: int
    incident_type: str
    #: Only these event types are considered. Empty means every type.
    event_types: tuple[str, ...] = ()
    #: Substrings that suppress a match -- `.env.example` is not `.env`.
    exclude: tuple[str, ...] = ()
    #: Rules reading caller-asserted fields are skipped for unverified events.
    requires_verified_identity: bool = False
    mitre: tuple[str, ...] = ()
    owasp_asi: tuple[str, ...] = ()

    def matches(self, payload: Mapping[str, Any], trust: TrustLevel) -> str | None:
        """Return the observed text that fired this rule, or None.

        Returning the OBSERVATION rather than a boolean is what lets an analyst
        see why a rule fired without re-running it.
        """
        if self.requires_verified_identity and not trust.is_authoritative:
            # A rule reading a caller-asserted field is only meaningful when the
            # caller's identity is proven. The predecessor let a self-reported
            # riskScore drive a high-severity incident with no provenance check.
            return None

        if self.event_types:
            observed_type = str(payload.get("eventType") or payload.get("event_type") or "")
            if observed_type not in self.event_types:
                return None

        value = _resolve(payload, self.field)
        if value is None:
            return None

        if self.mode == "gt":
            return self._match_gt(value)

        texts = tuple(unicodedata.normalize("NFKC", text) for text in _text_values(value))
        if not texts:
            return None

        if self.mode == "contains":
            for text in texts:
                lowered = text.lower()
                if any(token.lower() in lowered for token in self.exclude):
                    continue
                for candidate in self.values:
                    if str(candidate).lower() in lowered:
                        return str(candidate)
            return None

        if self.mode == "regex":
            for text in texts:
                lowered = text.lower()
                if any(token.lower() in lowered for token in self.exclude):
                    continue
                for candidate in self.values:
                    pattern = str(candidate)
                    hint = _literal_hint(pattern)
                    if hint and hint not in lowered:
                        continue
                    try:
                        found = re.search(pattern, text, re.IGNORECASE)
                    except re.error as exc:
                        raise PolicyError(
                            f"rule {self.rule_id} has invalid regex {pattern!r}: {exc}"
                        ) from exc
                    if found:
                        return found.group(0)[:200]
            return None

        if self.mode == "host_endswith":
            for text in texts:
                lowered = text.lower()
                if any(token.lower() in lowered for token in self.exclude):
                    continue
                matched = self._match_host(text)
                if matched:
                    return matched
            return None

        raise PolicyError(
            f"rule {self.rule_id} declares unknown match mode {self.mode!r}"
        )

    def _match_gt(self, value: Any) -> str | None:
        try:
            observed = float(value)
        except (TypeError, ValueError):
            # A non-numeric value in a numeric rule is a malformed event, not a
            # detection. Returning None keeps a bad payload from firing a rule.
            return None
        for candidate in self.values:
            if observed > float(candidate):
                return f"{self.field}={observed}"
        return None

    def _match_host(self, text: str) -> str | None:
        """Match on the URL HOST, never a bare substring.

        `evil-example.com` contains `example.com`, so a substring test on a deny
        list is trivially bypassed by registering a lookalike domain. Comparing
        host labels closes that.
        """
        host = (urlparse(text).hostname or text).lower().strip(".")
        for candidate in self.values:
            needle = str(candidate).lower().strip(".")
            if host == needle or host.endswith("." + needle):
                return host
        return None

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "PolicyRule":
        try:
            return cls(
                rule_id=str(raw["id"]),
                description=str(raw.get("description", "")),
                field=str(raw["field"]),
                mode=str(raw["mode"]),
                values=tuple(raw.get("values", ())),
                severity=int(raw["severity"]),
                incident_type=str(raw["incident_type"]),
                event_types=tuple(raw.get("event_types", ())),
                exclude=tuple(raw.get("exclude", ())),
                requires_verified_identity=bool(raw.get("requires_verified_identity", False)),
                mitre=tuple(raw.get("mitre", ())),
                owasp_asi=tuple(raw.get("owasp_asi", ())),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise PolicyError(
                f"malformed policy rule {raw.get('id', '<unnamed>')!r}: {exc}"
            ) from exc


class DeterministicPolicy:
    """Rule evaluation with no model in the decision path."""

    __slots__ = ("_rules", "_version")

    def __init__(self, *, rules: Sequence[PolicyRule], version: str) -> None:
        if not rules:
            raise PolicyError(
                "a detection policy with no rules detects nothing; refusing to "
                "construct one silently"
            )
        self._rules = tuple(rules)
        self._version = version

    def evaluate(self, *, payload: Mapping[str, Any], trust: TrustLevel) -> DetectionVerdict:
        # Semantic enrichment happens HERE, at the single entrance both the
        # ingest path and the protect gate share, so `metadata.semantics` is a
        # field policy rules may match like any other -- and because
        # `enrich_payload` discards any caller-supplied value for that key
        # first, it is a field only `domain/action_semantics.py` can write.
        payload = enrich_payload(payload)
        matched: list[tuple[PolicyRule, str]] = []
        for rule in self._rules:
            observed = rule.matches(payload, trust)
            if observed is not None:
                matched.append((rule, observed))

        if not matched:
            confidence = 0.0
            low_conf = compute_low_confidence_region(confidence)
            return DetectionVerdict(
                fired=False,
                severity=Severity(0),
                incident_type="none",
                description="no policy rule matched",
                detector_version=self._version,
                signals={
                    "policy": {"fired": False, "rules": [], "version": self._version},
                    "calibration": {
                        "confidence": confidence,
                        "low_confidence_region": low_conf,
                        "note": (
                            "hard abstention — absence of a match is not a calibrated "
                            "negative probability"
                        ),
                    },
                },
                confidence=confidence,
                low_confidence_region=low_conf,
            )

        top_rule, _ = max(matched, key=lambda pair: pair[0].severity)
        confidence = 1.0
        low_conf = compute_low_confidence_region(confidence)
        return DetectionVerdict(
            fired=True,
            severity=Severity(top_rule.severity),
            incident_type=top_rule.incident_type,
            description=" | ".join(f"{r.description}: {o}"[:300] for r, o in matched),
            matched_rules=tuple(r.rule_id for r, _ in matched),
            detector_version=self._version,
            signals={
                "policy": {
                    "fired": True,
                    "rules": [r.rule_id for r, _ in matched],
                    "version": self._version,
                    # Carried so a finding can be traced to a framework control
                    # without re-deriving it from the rule id.
                    "mitre": sorted({t for r, _ in matched for t in r.mitre}),
                    "owasp_asi": sorted({t for r, _ in matched for t in r.owasp_asi}),
                },
                "calibration": {
                    "confidence": confidence,
                    "low_confidence_region": low_conf,
                    "note": (
                        "hard positive label from DeterministicPolicy — not a soft "
                        "calibrated probability; ECE uses 0/1 confidences only"
                    ),
                },
            },
            confidence=confidence,
            low_confidence_region=low_conf,
        )

    def version(self) -> str:
        return self._version

    def digest(self) -> str:
        material = {"schema": "sentinel.deterministic-policy/v1", "version": self._version,
                    "rules": [asdict(rule) for rule in self._rules]}
        return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":"),
                                         ensure_ascii=False, allow_nan=False).encode()).hexdigest()

    @property
    def rules(self) -> tuple[PolicyRule, ...]:
        return self._rules

    @classmethod
    def from_file(cls, path: Path) -> "DeterministicPolicy":
        """Load a versioned ruleset. Raises rather than degrading silently."""
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise PolicyError(f"cannot read policy file {path}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise PolicyError(f"policy file {path} is not valid JSON: {exc}") from exc

        raw_rules = document.get("rules")
        if not isinstance(raw_rules, list):
            raise PolicyError(f"policy file {path} has no 'rules' array")

        return cls(
            rules=[PolicyRule.from_mapping(rule) for rule in raw_rules],
            version=f"{document.get('policy_id', 'policy')}@{document.get('version', '0')}",
        )

    @classmethod
    def default(cls) -> "DeterministicPolicy":
        """The shipped ruleset, loaded from `config/default_policy.json`."""
        return cls.from_file(DEFAULT_POLICY_PATH)
