"""Detections derived from the audit trail, not from log scraping.

WHY THIS READS THE AUDIT TABLE
------------------------------
The signals below could be computed by tailing logs, and that is how it is usually
done. It is the wrong source for three reasons that all bite at the same moment:

  * log lines are mutable, so a detection built on them is defeated by editing them
  * they are unordered across replicas, so "five failures in a minute" is a guess
  * they are usually outside retention by the time anyone asks

`security_audit` is append-only, hash-chained, and per-tenant densely sequenced. A
detection computed from it is reproducible months later and an attacker who
tampered with the inputs leaves a broken chain.

WHY THESE THREE SIGNALS
-----------------------
Each one is a shape a single request cannot have, which is the whole reason a
per-request control cannot catch it:

  * **Credential stuffing** -- many `unrecognised_credential` refusals. Rate
    limiting already slows this; detection is what tells someone it happened.
  * **Privilege probing** -- ONE valid credential denied across SEVERAL DISTINCT
    capabilities. This is the signal that matters most here, because it is what a
    stolen `viewer` key looks like in the minutes before the attacker finds
    something it can reach. A single 403 is a misconfigured client; four different
    403s from one key in five minutes is someone mapping their access.
  * **Horizontal enumeration** -- one actor refused across many distinct resource
    ids, which is how a caller walks an id space looking for one it can read.

WHAT THIS DELIBERATELY DOES NOT DO
----------------------------------
It does not block anything. A detector that revokes credentials on a threshold is
a denial-of-service primitive an attacker can aim at a legitimate tenant by
guessing their key prefix. Detections are recorded and surfaced; a human or a
separate policy decides what to do, which is the same separation the remediation
approval path uses and for the same reason.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Mapping, Sequence

from sentinel.domain.primitives import Timestamp

__all__ = ["Detection", "ThreatDetector", "UNAUTHENTICATED_TENANT"]

#: Refusals that happened before a tenant was known are chained here. Kept in sync
#: with `sentinel.interface.http._UNKNOWN_TENANT`; asserted by a test rather than
#: trusted, because two constants that must match are two constants that can drift.
UNAUTHENTICATED_TENANT = "unauthenticated:none"


@dataclass(frozen=True, slots=True)
class Detection:
    """One derived finding. Carries its own evidence, not a pointer to it.

    `sample_seqs` names the audit entries the finding was computed from, so a
    reviewer can verify the conclusion against the chain instead of re-running the
    detector and hoping it is deterministic.
    """

    kind: str
    tenant_id: str
    actor: str
    count: int
    window_seconds: int
    detail: Mapping[str, Any]
    sample_seqs: tuple[int, ...]

    def __str__(self) -> str:
        return (
            f"{self.kind}: actor={self.actor} count={self.count} "
            f"within {self.window_seconds}s ({self.detail})"
        )


@dataclass(frozen=True, slots=True)
class Thresholds:
    """How much of a shape counts as a finding.

    Deliberately low for privilege probing and high for stuffing. A stolen
    credential probing four capabilities is a strong signal from a small number;
    four bad passwords is a Monday morning.
    """

    stuffing_attempts: int = 25
    probing_distinct_capabilities: int = 4
    enumeration_distinct_resources: int = 20
    window_seconds: int = 300


class ThreatDetector:
    """Scans a window of the audit trail and returns findings.

    Stateless and read-only. It takes the tenant list as an argument rather than
    discovering it, so a caller can run it for one tenant during an investigation
    or for all of them on a schedule without the detector knowing the difference.
    """

    __slots__ = ("_pool", "_clock", "_thresholds")

    def __init__(self, *, pool: Any, clock: Any, thresholds: Thresholds | None = None) -> None:
        self._pool = pool
        self._clock = clock
        self._thresholds = thresholds or Thresholds()

    def scan(self, *, tenants: Sequence[str]) -> tuple[Detection, ...]:
        """Findings across the given tenants, plus the unauthenticated chain.

        The unauthenticated chain is always included: credential stuffing lands
        there by definition, because a guessed key has no tenant. A scan that only
        walked real tenants would miss the signal it most needs to find.
        """
        findings: list[Detection] = []
        scanned = list(dict.fromkeys([*tenants, UNAUTHENTICATED_TENANT]))
        for tenant in scanned:
            entries = self._window(tenant)
            if not entries:
                continue
            findings.extend(self._stuffing(tenant, entries))
            findings.extend(self._probing(tenant, entries))
            findings.extend(self._enumeration(tenant, entries))
        return tuple(findings)

    def _window(self, tenant: str) -> list[Mapping[str, Any]]:
        """Denied entries inside the window, oldest first.

        Bounded by time AND by row count. An unbounded read here would mean a
        detector that becomes slower the more it has to detect, which is the wrong
        direction for something that runs while an attack is in progress.
        """
        cutoff = Timestamp(
            self._clock.now().value - timedelta(seconds=self._thresholds.window_seconds)
        )
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant)
            p = conn.p
            rows = conn.execute(
                "SELECT seq, actor, action, resource_type, resource_id, outcome, "
                "occurred_at, detail FROM security_audit "
                f"WHERE tenant_id={p} AND outcome='denied' AND occurred_at>={p} "
                "ORDER BY seq DESC LIMIT 5000",
                (tenant, cutoff.isoformat()),
            )
            conn.commit()
        return [dict(row) for row in reversed(rows)]

    def _stuffing(
        self, tenant: str, entries: list[Mapping[str, Any]]
    ) -> list[Detection]:
        by_actor: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        for entry in entries:
            if _reason(entry) in ("unrecognised_credential", "auth_failure_rate_limited"):
                by_actor[str(entry["actor"])].append(entry)

        findings = []
        for actor, matched in by_actor.items():
            if len(matched) >= self._thresholds.stuffing_attempts:
                findings.append(
                    Detection(
                        kind="credential_stuffing",
                        tenant_id=tenant,
                        actor=actor,
                        count=len(matched),
                        window_seconds=self._thresholds.window_seconds,
                        detail={
                            "paths": sorted({str(e["action"]) for e in matched})[:10],
                            "note": (
                                "many unrecognised credentials from one digest "
                                "prefix; rate limiting slows this, detection is "
                                "what reports it"
                            ),
                        },
                        sample_seqs=tuple(int(e["seq"]) for e in matched[:10]),
                    )
                )
        return findings

    def _probing(self, tenant: str, entries: list[Mapping[str, Any]]) -> list[Detection]:
        """One credential refused across several DISTINCT capabilities.

        Distinctness is what makes this a signal. Twenty refusals for the same
        capability is a broken client retrying; four refusals for four different
        capabilities is someone mapping what a stolen key can reach.
        """
        by_actor: dict[str, set[str]] = defaultdict(set)
        seqs: dict[str, list[int]] = defaultdict(list)
        for entry in entries:
            if entry["resource_type"] != "capability":
                continue
            actor = str(entry["actor"])
            by_actor[actor].add(str(entry["resource_id"]))
            seqs[actor].append(int(entry["seq"]))

        findings = []
        for actor, capabilities in by_actor.items():
            if len(capabilities) >= self._thresholds.probing_distinct_capabilities:
                findings.append(
                    Detection(
                        kind="privilege_probing",
                        tenant_id=tenant,
                        actor=actor,
                        count=len(capabilities),
                        window_seconds=self._thresholds.window_seconds,
                        detail={
                            "capabilities": sorted(capabilities),
                            "note": (
                                "one credential denied across several distinct "
                                "capabilities: the shape of a stolen key being "
                                "mapped, not of a misconfigured client"
                            ),
                        },
                        sample_seqs=tuple(seqs[actor][:10]),
                    )
                )
        return findings

    def _enumeration(
        self, tenant: str, entries: list[Mapping[str, Any]]
    ) -> list[Detection]:
        by_actor: dict[str, set[str]] = defaultdict(set)
        seqs: dict[str, list[int]] = defaultdict(list)
        for entry in entries:
            if entry["resource_type"] == "capability":
                # Capability denials are the probing signal, not this one. Counting
                # them here would make every probing finding also an enumeration
                # finding and halve the value of both.
                continue
            actor = str(entry["actor"])
            by_actor[actor].add(f"{entry['resource_type']}:{entry['resource_id']}")
            seqs[actor].append(int(entry["seq"]))

        findings = []
        for actor, resources in by_actor.items():
            if len(resources) >= self._thresholds.enumeration_distinct_resources:
                findings.append(
                    Detection(
                        kind="resource_enumeration",
                        tenant_id=tenant,
                        actor=actor,
                        count=len(resources),
                        window_seconds=self._thresholds.window_seconds,
                        detail={
                            "sample": sorted(resources)[:10],
                            "note": "one actor refused across many distinct resources",
                        },
                        sample_seqs=tuple(seqs[actor][:10]),
                    )
                )
        return findings


def _reason(entry: Mapping[str, Any]) -> str:
    """The `reason` recorded in the entry's detail, or "" if absent.

    Tolerant of malformed JSON on purpose: a detector that raises on one bad row
    stops detecting, and the row it chokes on is the one an attacker would want it
    to choke on.
    """
    raw = entry.get("detail")
    if not raw:
        return ""
    try:
        parsed = json.loads(raw) if isinstance(raw, str) else dict(raw)
    except (ValueError, TypeError):
        return ""
    return str(parsed.get("reason", "")) if isinstance(parsed, dict) else ""
