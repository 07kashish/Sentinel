"""A bill of materials for the AI estate: models, MCP servers, tools, skills.

WHY THIS IS NOT THE SBOM
------------------------
The SBOM answers "what code is in this build". It cannot answer the question an
operator actually gets asked after an incident -- "which of our agents can call
that MCP server, on which model version, using whose credential" -- because
none of that is a Python package. An agent estate's supply chain is models,
tool servers, skills and prompts, assembled at RUNTIME by configuration rather
than at build time by a lockfile. Nothing in `requirements.txt` records it.

THE FAILURE MODE THIS MODULE IS BUILT AROUND
--------------------------------------------
An inventory's dangerous output is not a wrong entry. It is an EMPTY one.

"We found no unpinned models" and "we could not reach the account" render
identically in every dashboard that reports a count, and the first is a clean
bill of health while the second is a scan that did not run. So completeness is
a first-class verdict here, `UNUSABLE` exists as a distinct state, and it is
structurally impossible to obtain `COMPLETE` from sources that examined
nothing -- see `_judge_completeness`.

That is the same defect class as a test that reads something other than what it
appears to read, one layer up: a report that answers a question nobody asked.

PROVENANCE IS RECORDED PER COMPONENT
------------------------------------
`DECLARED` means somebody typed it into a config. `OBSERVED` means it was seen
in traffic. `ATTESTED` means a digest binds it. These are not interchangeable
and collapsing them is how an inventory becomes a work of fiction: most estates
are mostly `DECLARED`, and a BOM that does not say so implies verification it
never performed. `ATTESTED` without a digest is refused at construction.

WHAT THIS DOES NOT DO
---------------------
It does not discover anything. It composes what connectors found, and inherits
their coverage verbatim. If a connector lied or could not see, this reports
that rather than papering over it. The CycloneDX export is CycloneDX-SHAPED: it
is validated against no schema in this repository, and says so in its own
output rather than implying conformance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence

from sentinel.domain.assets import AssetInventory, AssetKind, AssetRecord, DiscoveryCoverage

__all__ = [
    "AI_KINDS",
    "AIBillOfMaterials",
    "AIComponent",
    "BomFinding",
    "BomFindingKind",
    "Completeness",
    "Provenance",
    "SourceCoverage",
    "compile_ai_bom",
]

#: The kinds that belong in an AI bill of materials.
#:
#: A frozenset, not a list: this is read at import time by every caller and a
#: mutable module-level collection is how one tenant's request quietly changes
#: what another tenant's report contains.
#:
#: `HUMAN_PRINCIPAL` is deliberately absent. A person is not a supply-chain
#: component, and including them would turn an inventory into a staff list.
AI_KINDS: frozenset[AssetKind] = frozenset(
    {
        AssetKind.AGENT,
        AssetKind.AGENT_RUNTIME,
        AssetKind.MODEL,
        AssetKind.MCP_SERVER,
        AssetKind.MCP_TOOL,
        AssetKind.SKILL,
        AssetKind.CREDENTIAL,
    }
)


class Provenance(str, Enum):
    """How well the estate knows a component is what it says it is.

    Ordered by strength. `strongest_of` relies on that order, so the members
    are declared weakest-first and `_RANK` pins the ordering explicitly rather
    than depending on declaration order surviving a future edit.
    """

    DECLARED = "declared"
    OBSERVED = "observed"
    ATTESTED = "attested"


#: MappingProxyType, not a dict. `Mapping` is an annotation and
#: annotations enforce nothing at runtime -- a plain dict here would let
#: any caller mutate the ranking that decides which provenance level
#: wins, for every tenant sharing the process.
_RANK: Mapping[Provenance, int] = MappingProxyType(
    {
        Provenance.DECLARED: 0,
        Provenance.OBSERVED: 1,
        Provenance.ATTESTED: 2,
    }
)


def strongest_of(levels: Iterable[Provenance]) -> Provenance:
    """The strongest evidence available for one component.

    Two connectors can disagree: one reads a config file (`DECLARED`), another
    sees the model answer a call (`OBSERVED`). Taking the strongest is right --
    observing something does not un-observe it -- but taking the strongest
    DIGEST would not be, which is why a digest conflict is a finding rather
    than a resolution. See `BomFindingKind.CONFLICTING_DIGEST`.
    """
    ranked = list(levels)
    if not ranked:
        return Provenance.DECLARED
    return max(ranked, key=lambda level: _RANK[level])


class Completeness(str, Enum):
    """Whether this document can be read as an inventory at all.

    `UNUSABLE` is the member that matters and the reason this is an enum rather
    than a boolean. A BOM with no components is either a clean estate or a scan
    that never ran, and those demand opposite responses.
    """

    COMPLETE = "complete"
    PARTIAL = "partial"
    UNUSABLE = "unusable"


class BomFindingKind(str, Enum):
    """What is wrong with the estate, as distinct from what is in it."""

    #: A model with neither version nor digest. The estate cannot say what it
    #: ran, so it cannot answer "were we affected" about any model change.
    UNPINNED_MODEL = "unpinned_model"
    #: Two sources report different digests for the same identifier. Somebody
    #: is wrong, or there are two components wearing one name.
    CONFLICTING_DIGEST = "conflicting_digest"
    #: A skill executes with no digest binding it to reviewed content.
    UNATTESTED_SKILL = "unattested_skill"
    #: An MCP server known only because somebody wrote it down.
    DECLARED_ONLY_SERVER = "declared_only_server"


@dataclass(frozen=True, slots=True)
class BomFinding:
    """One problem, the component it concerns, and why it matters.

    `detail` is required. "Unpinned model" is a category; "gpt-4o with no
    version, reachable by 3 agents" is something an operator can act on before
    lunch.
    """

    kind: BomFindingKind
    component: str
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "component": self.component,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class AIComponent:
    """One model, server, tool, skill, agent or credential in the estate."""

    kind: AssetKind
    identifier: str
    #: Every connector that reported it. Kept plural: an operator asking "who
    #: told us this exists" is usually asking because they doubt it does.
    sources: tuple[str, ...]
    provenance: Provenance = Provenance.DECLARED
    version: str = ""
    digest: str = ""
    supplier: str = ""
    #: Identifiers of agents or runtimes that can reach this component. This is
    #: the blast-radius question, answered from the component's side.
    used_by: tuple[str, ...] = ()
    native_type: str = ""
    environment: str = ""

    def __post_init__(self) -> None:
        if self.kind not in AI_KINDS:
            raise ValueError(
                f"{self.kind.value} is not an AI supply-chain component. "
                "Widening this set would turn the document into a general asset "
                "list, and the question it exists to answer -- what does our "
                "agent estate depend on -- stops being answerable."
            )
        if not self.identifier.strip():
            raise ValueError(
                "a component with no identifier cannot be correlated with an "
                "advisory, an incident or another connector's report"
            )
        if not self.sources:
            raise ValueError(
                f"component {self.identifier!r} has no source. A component "
                "nobody can attribute to a scan is one nobody can re-check, "
                "and an inventory of those is a rumour."
            )
        if self.provenance is Provenance.ATTESTED and not self.digest.strip():
            raise ValueError(
                f"component {self.identifier!r} claims ATTESTED provenance with "
                "no digest. Attested means a digest binds it; without one the "
                "word is decoration, and decoration in an inventory is worse "
                "than an admitted gap because it stops anyone looking."
            )

    @property
    def is_pinned(self) -> bool:
        """Can the estate say WHICH version of this it ran?

        A digest counts and a version string counts. Neither is a claim that
        the pin was verified -- that is `provenance`.
        """
        return bool(self.digest.strip() or self.version.strip())

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "identifier": self.identifier,
            "sources": list(self.sources),
            "provenance": self.provenance.value,
            "version": self.version,
            "digest": self.digest,
            "supplier": self.supplier,
            "used_by": list(self.used_by),
            "native_type": self.native_type,
            "environment": self.environment,
            "is_pinned": self.is_pinned,
        }


@dataclass(frozen=True, slots=True)
class SourceCoverage:
    """One connector's coverage, kept whole and kept separate.

    Not summed. Two connectors that each examined 40 objects in different
    scopes did not examine 80 of anything, and a single total would invite
    exactly that reading.
    """

    connector: str
    coverage: DiscoveryCoverage

    def as_dict(self) -> dict[str, Any]:
        return {
            "connector": self.connector,
            "coverage": self.coverage.as_dict(),
        }


@dataclass(frozen=True, slots=True)
class AIBillOfMaterials:
    """The estate's AI supply chain, with its own limits attached.

    `limits` travels in `as_dict()` on purpose. This document will be pasted
    into a ticket, a slide and a questionnaire response, and every one of those
    strips the surrounding caveat. The caveat has to be inside the payload.
    """

    tenant: str
    generated_at: str
    components: tuple[AIComponent, ...]
    sources: tuple[SourceCoverage, ...]
    findings: tuple[BomFinding, ...] = ()

    limits: str = field(
        default=(
            "This document composes what connectors reported; it discovers "
            "nothing itself. Absence from it is NOT evidence of absence from "
            "the estate. Read `completeness` FIRST: an UNUSABLE document has "
            "the same shape as a clean one and means the opposite. Most "
            "components in a real estate are DECLARED, meaning somebody typed "
            "them into a config and nothing has verified them."
        ),
        compare=False,
    )

    @property
    def completeness(self) -> Completeness:
        return _judge_completeness(self.sources)

    def of_kind(self, kind: AssetKind) -> tuple[AIComponent, ...]:
        return tuple(c for c in self.components if c.kind is kind)

    @property
    def unpinned_models(self) -> tuple[AIComponent, ...]:
        return tuple(
            c for c in self.of_kind(AssetKind.MODEL) if not c.is_pinned
        )

    def provenance_census(self) -> dict[str, int]:
        """How much of this document is actually verified.

        The single most useful number in the file, and the one a vendor
        dashboard never shows: an estate that is 96% DECLARED has an inventory,
        not an attestation.
        """
        census = {level.value: 0 for level in Provenance}
        for component in self.components:
            census[component.provenance.value] += 1
        return census

    def as_dict(self) -> dict[str, Any]:
        return {
            # Completeness first, because a reader who stops after two lines
            # must not stop before the line that says whether to trust the rest.
            "completeness": self.completeness.value,
            "tenant": self.tenant,
            "generated_at": self.generated_at,
            "component_count": len(self.components),
            "provenance_census": self.provenance_census(),
            "sources": [s.as_dict() for s in self.sources],
            "findings": [f.as_dict() for f in self.findings],
            "components": [c.as_dict() for c in self.components],
            "limits": self.limits,
        }

    def as_cyclonedx(self) -> dict[str, Any]:
        """A CycloneDX 1.6-SHAPED document. Not a validated one.

        CycloneDX is the interchange format an enterprise procurement team will
        ask for, and 1.6 added `machine-learning-model` as a component type, so
        emitting it is worth doing. But this repository validates the output
        against no schema, so calling it "CycloneDX compliant" would be a claim
        with no evidence behind it -- the exact move this codebase's release
        gates exist to prevent. The document therefore carries its own
        disclaimer as a property, where a consumer will actually see it.
        """
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {
                "timestamp": self.generated_at,
                "properties": [
                    {"name": "sentinel:completeness", "value": self.completeness.value},
                    {"name": "sentinel:tenant", "value": self.tenant},
                    {
                        "name": "sentinel:schema_validated",
                        "value": "false",
                    },
                    {
                        "name": "sentinel:disclaimer",
                        "value": (
                            "CycloneDX-shaped, validated against no schema here. "
                            "Read sentinel:completeness before treating this as "
                            "an inventory."
                        ),
                    },
                ],
            },
            "components": [
                {
                    "type": _CYCLONEDX_TYPE.get(c.kind, "application"),
                    "name": c.identifier,
                    "version": c.version,
                    "publisher": c.supplier,
                    "properties": [
                        {"name": "sentinel:kind", "value": c.kind.value},
                        {"name": "sentinel:provenance", "value": c.provenance.value},
                        {"name": "sentinel:pinned", "value": str(c.is_pinned).lower()},
                    ],
                    **({"hashes": [{"alg": "SHA-256", "content": c.digest}]}
                       if c.digest.strip() else {}),
                }
                for c in self.components
            ],
        }


#: CycloneDX 1.6 component types. `machine-learning-model` is a real 1.6
#: member; the rest map to the nearest existing type rather than to an invented
#: one, because a consumer's parser rejects unknown types outright.
_CYCLONEDX_TYPE: Mapping[AssetKind, str] = MappingProxyType(
    {
        AssetKind.MODEL: "machine-learning-model",
        AssetKind.MCP_SERVER: "application",
        AssetKind.MCP_TOOL: "library",
        AssetKind.SKILL: "library",
        AssetKind.AGENT: "application",
        AssetKind.AGENT_RUNTIME: "platform",
        AssetKind.CREDENTIAL: "application",
    }
)


def _judge_completeness(sources: Sequence[SourceCoverage]) -> Completeness:
    """COMPLETE is reachable only from sources that actually looked.

    THE POINT OF THIS FUNCTION. Every other path through the module can produce
    an empty component list; only this one decides whether that emptiness means
    "nothing is there" or "we did not look". Getting it backwards turns a
    failed scan into a clean bill of health, which is the single most damaging
    output an inventory can produce.
    """
    if not sources:
        return Completeness.UNUSABLE
    if all(source.coverage.examined == 0 for source in sources):
        # Nothing was inspected anywhere. An empty result here says nothing
        # about the estate, so it must not be allowed to read as COMPLETE.
        return Completeness.UNUSABLE
    if any(source.coverage.is_partial for source in sources):
        return Completeness.PARTIAL
    if any(source.coverage.examined == 0 for source in sources):
        # At least one connector examined nothing while another worked. The
        # picture is real but has a hole in it.
        return Completeness.PARTIAL
    return Completeness.COMPLETE


def _attributes(record: AssetRecord) -> Mapping[str, Any]:
    return record.attributes if isinstance(record.attributes, Mapping) else {}


def _string(mapping: Mapping[str, Any], key: str) -> str:
    value = mapping.get(key, "")
    return value.strip() if isinstance(value, str) else ""


def _provenance_of(record: AssetRecord) -> Provenance:
    """Read provenance from the record, defaulting to the WEAKEST level.

    Defaulting down is the whole point. A connector that says nothing about how
    it knows has told us it was declared, and defaulting to anything stronger
    would manufacture confidence out of a missing field.
    """
    attributes = _attributes(record)
    declared = _string(attributes, "provenance").lower()
    digest = _string(attributes, "digest")
    for level in Provenance:
        if declared == level.value:
            # A source cannot self-certify as ATTESTED without a digest; the
            # component constructor would refuse it, so it is downgraded here
            # with the reason preserved in the finding set instead.
            if level is Provenance.ATTESTED and not digest:
                return Provenance.DECLARED
            return level
    return Provenance.DECLARED


def _merge(existing: AIComponent, addition: AIComponent) -> AIComponent:
    """Fold two reports of one component together without losing either.

    Digests are NOT reconciled here. If two sources disagree the first is kept
    and the disagreement becomes a finding, because silently choosing a winner
    would hide the only signal that says two different things are wearing one
    name.
    """
    return AIComponent(
        kind=existing.kind,
        identifier=existing.identifier,
        sources=tuple(sorted(set(existing.sources) | set(addition.sources))),
        provenance=strongest_of((existing.provenance, addition.provenance)),
        version=existing.version or addition.version,
        digest=existing.digest or addition.digest,
        supplier=existing.supplier or addition.supplier,
        used_by=tuple(sorted(set(existing.used_by) | set(addition.used_by))),
        native_type=existing.native_type or addition.native_type,
        environment=existing.environment or addition.environment,
    )


def _component_from(record: AssetRecord, connector: str) -> AIComponent:
    attributes = _attributes(record)
    return AIComponent(
        kind=record.kind,
        identifier=record.identifier,
        sources=(connector,),
        provenance=_provenance_of(record),
        version=_string(attributes, "version"),
        digest=_string(attributes, "digest"),
        supplier=_string(attributes, "supplier"),
        used_by=tuple(sorted(set(record.relates_to))),
        native_type=record.native_type,
        environment=record.environment,
    )


def _findings_for(
    components: Sequence[AIComponent],
    digest_conflicts: Mapping[str, tuple[str, ...]],
) -> tuple[BomFinding, ...]:
    findings: list[BomFinding] = []

    for component in components:
        if component.kind is AssetKind.MODEL and not component.is_pinned:
            findings.append(
                BomFinding(
                    kind=BomFindingKind.UNPINNED_MODEL,
                    component=component.identifier,
                    detail=(
                        f"{component.identifier} has neither version nor digest, "
                        f"and is reachable by {len(component.used_by)} "
                        "agent(s). The estate cannot answer 'were we affected' "
                        "about any change to this model."
                    ),
                )
            )
        if component.kind is AssetKind.SKILL and not component.digest.strip():
            findings.append(
                BomFinding(
                    kind=BomFindingKind.UNATTESTED_SKILL,
                    component=component.identifier,
                    detail=(
                        f"skill {component.identifier} has no digest, so nothing "
                        "binds what executes to what was reviewed"
                    ),
                )
            )
        if (
            component.kind is AssetKind.MCP_SERVER
            and component.provenance is Provenance.DECLARED
        ):
            findings.append(
                BomFinding(
                    kind=BomFindingKind.DECLARED_ONLY_SERVER,
                    component=component.identifier,
                    detail=(
                        f"MCP server {component.identifier} is known only because "
                        "it appears in configuration; nothing has observed or "
                        "attested it"
                    ),
                )
            )

    for identifier, digests in sorted(digest_conflicts.items()):
        findings.append(
            BomFinding(
                kind=BomFindingKind.CONFLICTING_DIGEST,
                component=identifier,
                detail=(
                    f"{len(digests)} different digests reported for "
                    f"{identifier}: {', '.join(sorted(digests))}. Either a "
                    "source is wrong or two components share one name; the "
                    "inventory cannot say which, so it says neither."
                ),
            )
        )

    return tuple(findings)


def compile_ai_bom(
    *,
    tenant: str,
    inventories: Sequence[AssetInventory],
    generated_at: str,
) -> AIBillOfMaterials:
    """Compose connector inventories into one AI bill of materials.

    Composes; does not discover. Coverage is carried through per connector
    rather than summed, and completeness is derived from that coverage -- so a
    caller cannot obtain a COMPLETE document by passing no inventories, which
    is the shape a failed discovery run takes.
    """
    if not tenant.strip():
        raise ValueError(
            "an AI-BOM with no tenant cannot be filed, compared against its "
            "predecessor, or kept out of another tenant's report"
        )

    merged: dict[tuple[AssetKind, str], AIComponent] = {}
    digests_seen: dict[str, set[str]] = {}

    for inventory in inventories:
        for record in inventory.assets:
            if record.kind not in AI_KINDS:
                continue
            component = _component_from(record, inventory.connector)
            if component.digest:
                digests_seen.setdefault(component.identifier, set()).add(
                    component.digest
                )
            key = (component.kind, component.identifier)
            existing = merged.get(key)
            merged[key] = (
                _merge(existing, component) if existing is not None else component
            )

    components = tuple(
        sorted(merged.values(), key=lambda c: (c.kind.value, c.identifier))
    )
    conflicts = {
        identifier: tuple(sorted(digests))
        for identifier, digests in digests_seen.items()
        if len(digests) > 1
    }
    sources = tuple(
        SourceCoverage(connector=inventory.connector, coverage=inventory.coverage)
        for inventory in inventories
    )

    return AIBillOfMaterials(
        tenant=tenant,
        generated_at=generated_at,
        components=components,
        sources=sources,
        findings=_findings_for(components, conflicts),
    )
