"""Agent skills as supply-chain components: provenance, drift, and risk.

WHY SKILLS NEED THEIR OWN MODEL
---------------------------------
`mcp.py` treats an MCP tool definition as a thing whose identity is a
fingerprint, because a tool that changes after approval presents the same NAME
to the same allowlist. A skill -- a plugin, an extension, an installable agent
capability -- is the same problem with a worse blast radius: an MCP tool is a
remote call to a server somebody operates, and a skill is CODE that runs where
the agent runs, with the agent's credentials and the agent's network position.

So a skill gets what a dependency gets: a publisher, a version, an integrity
hash, a declared permission set, and a record of what changed since it was
approved.

WHAT "RISK" MEANS HERE, AND WHAT IT DOES NOT
----------------------------------------------
`assess` returns explainable FACTORS, never a magic number. Every point in the
score names the thing that produced it, because an analyst who cannot see what
contributed cannot tell a genuine finding from a scoring artefact -- and a score
nobody can explain is one nobody acts on.

The factors are properties of the ARTEFACT, not predictions about behaviour.
"This package imports `subprocess`" is a fact. "This package is malicious" is
not something static inspection can say, and this module does not say it.

DRIFT IS THE PRIMARY SIGNAL
---------------------------
A skill that was reviewed and has not changed is a skill somebody looked at. The
same skill at a new version, from a new publisher, or with a permission it did
not previously request, is a NEW artefact wearing an approved name -- and
`compare` exists to say so. `PERMISSION_EXPANDED` and `PUBLISHER_CHANGED` are
rated above `VERSION_CHANGED` for that reason: a version bump is expected, and
the publisher of a package changing underneath a pinned name is how supply-chain
compromise actually looks.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Final, Iterable, Mapping, Sequence

from sentinel.domain.errors import DomainRuleViolated

__all__ = [
    "PERMISSION_WEIGHT",
    "RiskFactor",
    "SkillAssessment",
    "SkillChange",
    "SkillChangeKind",
    "SkillDefinition",
    "SkillRuleViolated",
    "SkillTrust",
    "assess",
    "compare",
    "skill_fingerprint",
]


class SkillRuleViolated(DomainRuleViolated):
    """A skill record was malformed. Not retryable."""

    is_retryable = False


_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@/-]{0,127}$")
_HASH_RE = re.compile(r"^[a-f0-9]{64}$")


class SkillTrust(str, Enum):
    """How this skill came to be present. NOT a judgement about its content.

    `UNKNOWN` is the default and is the one that matters: a skill nobody
    enrolled is a skill nobody reviewed, and it must not silently rate the same
    as one an operator approved.
    """

    UNKNOWN = "unknown"
    ENROLLED = "enrolled"
    APPROVED = "approved"
    BLOCKED = "blocked"


#: Permissions a skill may declare, and what each is worth in the risk score.
#:
#: Ordered by what an attacker gets. `execute_code` is the top of the table
#: because everything else on it is reachable once code runs -- a skill with
#: arbitrary execution has every other permission whether it declared them or
#: not, which is why declaring it is worth more than declaring three others.
#:
#: `MappingProxyType`, not a bare dict: this table decides how dangerous a
#: permission is, and `test_architecture_rules.py` rejects module-level mutable
#: state for exactly this reason.
PERMISSION_WEIGHT: Mapping[str, int] = MappingProxyType({
    "execute_code": 40,
    "read_credentials": 35,
    "write_filesystem": 20,
    "network_egress": 20,
    "read_filesystem": 12,
    "spawn_agent": 25,
    "read_customer_data": 25,
    "modify_policy": 40,
    "send_message": 10,
})

#: The score at or above which a skill is treated as high risk. Named rather
#: than inlined so a policy author and this module cannot disagree about it.
HIGH_RISK_SCORE: Final[int] = 60
CRITICAL_RISK_SCORE: Final[int] = 85


def skill_fingerprint(payload: Mapping[str, Any]) -> str:
    """A stable hash over a skill's identity and reach.

    Covers name, version, publisher, artefact hash and declared permissions.
    Deliberately NOT the description or the display name: a publisher rewording
    a summary would otherwise raise drift nobody can action, which is how a
    drift alert comes to be ignored. Same reasoning as `a2a.card_fingerprint`.
    """
    material = {
        "name": str(payload.get("name") or ""),
        "version": str(payload.get("version") or ""),
        "publisher": str(payload.get("publisher") or "").lower(),
        "artifact_sha256": str(payload.get("artifact_sha256") or ""),
        "permissions": sorted(str(p) for p in (payload.get("permissions") or ())),
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class SkillDefinition:
    """One installable agent capability, as a supply-chain artefact."""

    name: str
    version: str
    publisher: str
    permissions: frozenset[str]
    trust: SkillTrust = SkillTrust.UNKNOWN
    #: SHA-256 of the package bytes. Empty when the artefact was never hashed,
    #: which is itself a finding rather than a neutral absence -- a skill with
    #: no integrity hash is one whose content can change without anything
    #: noticing.
    artifact_sha256: str = ""
    #: Prose from the publisher. NOT fingerprinted, and never trusted: it is
    #: text a model may read, so it belongs on the injection detector's path,
    #: not in an integrity comparison.
    description: str = ""
    #: Network destinations the skill declares it contacts.
    destinations: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not _NAME_RE.fullmatch(str(self.name)):
            raise SkillRuleViolated(f"skill name {self.name!r} is not a valid name")
        if self.artifact_sha256 and not _HASH_RE.fullmatch(self.artifact_sha256):
            raise SkillRuleViolated(
                f"artifact_sha256 {self.artifact_sha256!r} is not a sha256 hex digest"
            )
        unknown = sorted(set(self.permissions) - set(PERMISSION_WEIGHT))
        if unknown:
            # Refused rather than scored as zero. An unrecognised permission
            # scored as harmless is how a skill declares `read_all_secrets` and
            # rates lower than one declaring `send_message`.
            raise SkillRuleViolated(
                f"skill {self.name!r} declares unknown permissions "
                f"{', '.join(unknown)}; known permissions are "
                f"{', '.join(sorted(PERMISSION_WEIGHT))}"
            )

    @property
    def fingerprint(self) -> str:
        return skill_fingerprint(
            {
                "name": self.name,
                "version": self.version,
                "publisher": self.publisher,
                "artifact_sha256": self.artifact_sha256,
                "permissions": sorted(self.permissions),
            }
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "publisher": self.publisher,
            "permissions": sorted(self.permissions),
            "destinations": sorted(self.destinations),
            "trust": self.trust.value,
            "artifact_sha256": self.artifact_sha256,
            "fingerprint": self.fingerprint,
        }


# ── Drift ────────────────────────────────────────────────────────────────────


class SkillChangeKind(str, Enum):
    PUBLISHER_CHANGED = "publisher_changed"
    ARTIFACT_CHANGED = "artifact_changed"
    PERMISSION_EXPANDED = "permission_expanded"
    PERMISSION_REDUCED = "permission_reduced"
    DESTINATION_ADDED = "destination_added"
    VERSION_CHANGED = "version_changed"
    DESCRIPTION_CHANGED = "description_changed"


#: What each change is worth. Not alphabetical and not arbitrary: a publisher
#: changing underneath a pinned name is how supply-chain compromise actually
#: looks, while a version bump is what a maintained package does every week.
#: Rating them equally would bury the first in the noise of the second.
CHANGE_WEIGHT: Mapping[SkillChangeKind, int] = MappingProxyType({
    SkillChangeKind.PUBLISHER_CHANGED: 45,
    SkillChangeKind.PERMISSION_EXPANDED: 35,
    SkillChangeKind.DESTINATION_ADDED: 25,
    SkillChangeKind.ARTIFACT_CHANGED: 20,
    SkillChangeKind.VERSION_CHANGED: 5,
    SkillChangeKind.DESCRIPTION_CHANGED: 5,
    # A skill asking for LESS is not a risk. Reported because it is a change an
    # operator may want to see, and scored at zero because raising risk for an
    # improvement would teach people to ignore the score.
    SkillChangeKind.PERMISSION_REDUCED: 0,
})


@dataclass(frozen=True, slots=True)
class SkillChange:
    kind: SkillChangeKind
    detail: str

    @property
    def weight(self) -> int:
        return CHANGE_WEIGHT[self.kind]

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind.value, "detail": self.detail, "weight": self.weight}


def compare(
    approved: SkillDefinition, observed: SkillDefinition
) -> tuple[SkillChange, ...]:
    """Everything that changed between the approved skill and the present one."""
    if approved.name != observed.name:
        raise SkillRuleViolated(
            f"cannot compare {approved.name!r} with {observed.name!r}; drift is "
            "a property of one skill over time, not of two skills"
        )

    changes: list[SkillChange] = []

    if approved.publisher.lower() != observed.publisher.lower():
        changes.append(
            SkillChange(
                kind=SkillChangeKind.PUBLISHER_CHANGED,
                detail=(
                    f"publisher went from {approved.publisher!r} to "
                    f"{observed.publisher!r}. A pinned name whose publisher "
                    "changed is the shape of a supply-chain takeover."
                ),
            )
        )

    added = sorted(set(observed.permissions) - set(approved.permissions))
    if added:
        changes.append(
            SkillChange(
                kind=SkillChangeKind.PERMISSION_EXPANDED,
                detail=f"now requests {', '.join(added)}, which it did not before",
            )
        )
    removed = sorted(set(approved.permissions) - set(observed.permissions))
    if removed:
        changes.append(
            SkillChange(
                kind=SkillChangeKind.PERMISSION_REDUCED,
                detail=f"no longer requests {', '.join(removed)}",
            )
        )

    new_destinations = sorted(set(observed.destinations) - set(approved.destinations))
    if new_destinations:
        changes.append(
            SkillChange(
                kind=SkillChangeKind.DESTINATION_ADDED,
                detail=f"now contacts {', '.join(new_destinations)}",
            )
        )

    if (
        approved.artifact_sha256
        and observed.artifact_sha256
        and approved.artifact_sha256 != observed.artifact_sha256
    ):
        changes.append(
            SkillChange(
                kind=SkillChangeKind.ARTIFACT_CHANGED,
                detail=(
                    f"package bytes changed: {approved.artifact_sha256[:16]}... "
                    f"-> {observed.artifact_sha256[:16]}..."
                ),
            )
        )

    if approved.version != observed.version:
        changes.append(
            SkillChange(
                kind=SkillChangeKind.VERSION_CHANGED,
                detail=f"version {approved.version!r} -> {observed.version!r}",
            )
        )
    if approved.description != observed.description:
        changes.append(
            SkillChange(
                kind=SkillChangeKind.DESCRIPTION_CHANGED,
                detail="description text changed",
            )
        )

    return tuple(sorted(changes, key=lambda c: (-c.weight, c.kind.value)))


# ── Risk ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class RiskFactor:
    """One contribution to a score, and the reason for it.

    Every factor names WHAT contributed and HOW MUCH. A score whose components
    an analyst cannot see is one they cannot distinguish from a scoring
    artefact, and that is a score nobody acts on.
    """

    name: str
    points: int
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {"factor": self.name, "points": self.points, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class SkillAssessment:
    skill: SkillDefinition
    factors: tuple[RiskFactor, ...]

    @property
    def score(self) -> int:
        # Capped at 100 rather than allowed to run away. An uncapped score makes
        # "very bad" and "catastrophic" indistinguishable at the top, and the
        # decisions above HIGH are the same decisions either way.
        return min(100, sum(f.points for f in self.factors))

    @property
    def severity(self) -> str:
        if self.score >= CRITICAL_RISK_SCORE:
            return "critical"
        if self.score >= HIGH_RISK_SCORE:
            return "high"
        if self.score >= 30:
            return "moderate"
        return "low"

    def as_dict(self) -> dict[str, Any]:
        return {
            "skill": self.skill.as_dict(),
            "score": self.score,
            "severity": self.severity,
            "factors": [f.as_dict() for f in self.factors],
        }


def assess(
    skill: SkillDefinition,
    *,
    changes: Sequence[SkillChange] = (),
    scan_findings: Sequence[Mapping[str, Any]] = (),
    trusted_publishers: Iterable[str] = (),
) -> SkillAssessment:
    """Score one skill from facts about the artefact. No behaviour prediction.

    Every factor is a property something can point at: a declared permission, a
    changed publisher, a static-analysis hit, a missing integrity hash. Nothing
    here claims a skill is malicious, because static inspection cannot say that
    and a control that overclaims gets disbelieved on its first false positive.
    """
    factors: list[RiskFactor] = []
    trusted = {p.strip().lower() for p in trusted_publishers if p.strip()}

    if skill.trust is SkillTrust.BLOCKED:
        factors.append(
            RiskFactor(
                name="blocked",
                points=100,
                reason="an operator blocked this skill",
            )
        )
    elif skill.trust is SkillTrust.UNKNOWN:
        factors.append(
            RiskFactor(
                name="unenrolled",
                points=30,
                reason=(
                    "no enrolment record: a skill nobody registered is a skill "
                    "nobody reviewed"
                ),
            )
        )

    for permission in sorted(skill.permissions):
        weight = PERMISSION_WEIGHT[permission]
        factors.append(
            RiskFactor(
                name=f"permission:{permission}",
                points=weight,
                reason=f"declares the {permission} permission",
            )
        )

    if not skill.artifact_sha256:
        factors.append(
            RiskFactor(
                name="no_integrity_hash",
                points=15,
                reason=(
                    "no artefact hash recorded, so the package content can "
                    "change without anything noticing"
                ),
            )
        )

    if skill.publisher and trusted and skill.publisher.lower() not in trusted:
        factors.append(
            RiskFactor(
                name="untrusted_publisher",
                points=20,
                reason=f"{skill.publisher!r} is not on the trusted-publisher list",
            )
        )

    for change in changes:
        if change.weight:
            factors.append(
                RiskFactor(
                    name=f"drift:{change.kind.value}",
                    points=change.weight,
                    reason=change.detail,
                )
            )

    for finding in scan_findings:
        points = int(finding.get("points", 0) or 0)
        if points:
            factors.append(
                RiskFactor(
                    name=f"scan:{finding.get('rule', 'unknown')}",
                    points=points,
                    reason=str(finding.get("detail", "")),
                )
            )

    return SkillAssessment(
        skill=skill,
        factors=tuple(sorted(factors, key=lambda f: (-f.points, f.name))),
    )
