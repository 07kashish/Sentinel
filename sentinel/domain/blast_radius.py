"""Phase 8: what an agent could reach, and how much that would matter.

TWO QUESTIONS, AND ONLY ONE OF THEM IS COMPUTABLE
---------------------------------------------------
`effective_permissions.compute_effective_reach` answers the first: what can this
agent get to, through grants, delegation, shared credentials and observed
behaviour. That is a graph walk over recorded facts and it is honest.

The second -- how much does that matter -- is NOT computable from the graph.
Whether `db://customers` holds PII is a fact about the business, not about the
topology, and a system that guessed would produce a confident number built on
its own assumption. So sensitivity must be DECLARED, by a human or an
authoritative source, and an undeclared asset scores as UNKNOWN rather than as
harmless.

That distinction runs through the whole module. `BlastRadius.coverage` reports
what fraction of reachable assets have a declaration, because a blast-radius
score over an estate nobody classified is a score about nothing, and a reader
needs to see that before quoting the number.

UNKNOWN IS NOT ZERO
-------------------
An asset with no declaration contributes to `unclassified`, never to the score
as a low value. Scoring it zero would mean an estate with no declarations at all
reports blast radius 0 -- the safest-looking possible answer produced by having
done no work, which is the exact failure this codebase keeps finding.

RECOMMENDATIONS ARE PROPOSALS
-----------------------------
`recommend_reductions` returns suggestions, never applies them. An agent that
runs quarterly has reached nothing this month, and a permission system that
pruned on that basis breaks it on the one day of the year it matters -- the same
reasoning `recommend_least_privilege` already carries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from sentinel.domain.effective_permissions import EffectiveReach, ReachSource

__all__ = [
    "SENSITIVITY_WEIGHT",
    "AssetDeclaration",
    "BlastRadius",
    "CriticalPath",
    "Sensitivity",
    "compute_blast_radius",
]


class Sensitivity(str, Enum):
    """What a human declared about an asset. Never inferred.

    `UNKNOWN` is a real member rather than the absence of one, so an undeclared
    asset is something a report can count and name instead of something that
    quietly does not appear.
    """

    UNKNOWN = "unknown"
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


#: Contribution to the score. `UNKNOWN` is absent on purpose -- an undeclared
#: asset does not contribute a number, it contributes to `unclassified`, and
#: giving it a weight here would be inventing the judgement this module refuses
#: to make.
#:
#: `MappingProxyType`: this decides how serious a reachable asset is, and
#: "any import could edit it" is not a property that table should have.
SENSITIVITY_WEIGHT: Mapping[Sensitivity, int] = MappingProxyType({
    Sensitivity.PUBLIC: 0,
    Sensitivity.INTERNAL: 5,
    Sensitivity.CONFIDENTIAL: 15,
    Sensitivity.RESTRICTED: 30,
})

#: Extra weight where the asset is declared to be in production. Production is a
#: property of the ASSET, declared alongside its sensitivity -- not something
#: guessed from a name containing "prod", which is how a staging database called
#: `prod-mirror` ends up rated as production and a production one called `db-7`
#: does not.
PRODUCTION_MULTIPLIER = 2


@dataclass(frozen=True, slots=True)
class AssetDeclaration:
    """What a human asserted about one asset.

    `declared_by` is required and not defaulted. A declaration with no author is
    one nobody can question later, and the whole reason sensitivity is declared
    rather than inferred is that somebody is accountable for the judgement.
    """

    asset: str
    sensitivity: Sensitivity
    declared_by: str
    production: bool = False
    data_classes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.declared_by.strip():
            raise ValueError(
                f"declaration for {self.asset!r} has no author. Sensitivity is "
                "declared rather than inferred precisely so somebody is "
                "accountable for the judgement; an unattributed declaration is "
                "an inference wearing a human's clothes."
            )

    @property
    def weight(self) -> int:
        base = SENSITIVITY_WEIGHT.get(self.sensitivity, 0)
        return base * PRODUCTION_MULTIPLIER if self.production else base


@dataclass(frozen=True, slots=True)
class CriticalPath:
    """One route from the agent to something that matters, with its weight."""

    asset: str
    sensitivity: Sensitivity
    production: bool
    source: ReachSource
    via: tuple[str, ...]
    weight: int

    @property
    def hops(self) -> int:
        return len(self.via)

    def as_dict(self) -> dict[str, Any]:
        return {
            "asset": self.asset,
            "sensitivity": self.sensitivity.value,
            "production": self.production,
            "source": self.source.value,
            "via": list(self.via),
            "hops": self.hops,
            "weight": self.weight,
        }


@dataclass(frozen=True, slots=True)
class BlastRadius:
    """What one agent could reach, weighted by what humans said it is worth."""

    agent_id: str
    reachable: tuple[str, ...]
    critical_paths: tuple[CriticalPath, ...]
    #: Reachable assets with no declaration. Named, not counted away: these are
    #: the ones somebody has to look at before the score means anything.
    unclassified: tuple[str, ...] = ()
    score: int = 0

    limits: str = field(
        default=(
            "Sensitivity is DECLARED, never inferred. An undeclared asset "
            "counts as unclassified rather than as harmless, so a low score "
            "over a low-coverage estate means 'nobody has classified this', "
            "not 'this agent is safe'. Read `coverage` before quoting `score`."
        ),
        compare=False,
    )

    @property
    def coverage(self) -> float:
        """Fraction of reachable assets that carry a declaration.

        The number to read FIRST. A blast-radius score over an estate nobody
        classified is a score about nothing.
        """
        if not self.reachable:
            return 1.0
        return round(
            (len(self.reachable) - len(self.unclassified)) / len(self.reachable), 4
        )

    @property
    def production_paths(self) -> tuple[CriticalPath, ...]:
        return tuple(p for p in self.critical_paths if p.production)

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "score": self.score,
            "coverage": self.coverage,
            "reachable_count": len(self.reachable),
            "reachable": list(self.reachable),
            "unclassified": list(self.unclassified),
            "critical_paths": [p.as_dict() for p in self.critical_paths],
            "production_path_count": len(self.production_paths),
            "limits": self.limits,
        }


def compute_blast_radius(
    reach: EffectiveReach,
    *,
    declarations: Iterable[AssetDeclaration],
    max_score: int = 100,
) -> BlastRadius:
    """Weight an agent's reach by what humans declared about what it reaches.

    Takes the reach rather than computing it, so the graph walk and the
    valuation stay separable: the walk is a fact about topology and the
    valuation is a set of human judgements, and mixing them would make it
    impossible to re-value an estate without re-walking it.
    """
    declared = {d.asset: d for d in declarations}

    paths: list[CriticalPath] = []
    unclassified: list[str] = []
    for path in reach.paths:
        declaration = declared.get(path.capability)
        if declaration is None:
            unclassified.append(path.capability)
            continue
        if declaration.weight == 0:
            # Declared PUBLIC. Classified, and correctly worth nothing -- which
            # is a different statement from undeclared, and must not be folded
            # into `unclassified` or the coverage figure becomes a lie.
            continue
        paths.append(
            CriticalPath(
                asset=path.capability,
                sensitivity=declaration.sensitivity,
                production=declaration.production,
                source=path.source,
                via=path.via,
                weight=declaration.weight,
            )
        )

    # Weight per ASSET, not per path. An asset reachable three ways is one thing
    # an attacker gets to; summing per path would let a well-connected estate
    # score higher than a dangerous one.
    by_asset: dict[str, int] = {}
    # `critical` rather than `path`: the loop above binds `path` to a ReachPath,
    # and reusing the name for a CriticalPath made two different shapes share
    # one identifier in one function.
    for critical in paths:
        by_asset[critical.asset] = max(
            by_asset.get(critical.asset, 0), critical.weight
        )

    return BlastRadius(
        agent_id=reach.agent_id,
        reachable=tuple(sorted({p.capability for p in reach.paths})),
        critical_paths=tuple(
            sorted(paths, key=lambda p: (-p.weight, p.hops, p.asset))
        ),
        unclassified=tuple(sorted(set(unclassified))),
        score=min(max_score, sum(by_asset.values())),
    )
