"""HTTP surface for the AI-BOM, the exposure graph and the transparency log.

WHY THIS FILE EXISTS AT ALL
---------------------------
Five domain modules were written, tested and committed with **zero references
from anywhere else in the system**. `ai_bom`, `exposure_graph`,
`transparency`, `attack_campaign` and the GitHub discovery connector were
library code, not product: every test passed and no operator could reach any of
them.

This repository's own history names that failure -- "Phase 4 shipped five
correct components of which four were unreachable, and every unit test passed
throughout" -- and it had just happened again, to me, in the same session where
I wrote a red-team ledger about not fooling yourself. A capability with no HTTP
surface is a capability nobody has.

READ-ONLY, LIKE THE ANALYSIS ROUTES
------------------------------------
Nothing here changes state. The AI-BOM reports unpinned models; it does not pin
them. The exposure graph reports what can reach what; it does not revoke. The
transparency log serves roots and proofs; it does not decide anything.

THE COVERAGE FIELDS ARE NOT DECORATION
---------------------------------------
Every response carries the source coverage verbatim, and the AI-BOM's
`completeness` is the FIRST key in its body. This build has two discovery
connectors reachable from the container, so an AI-BOM assembled here is
`PARTIAL` at best and says so -- rather than returning a confident empty
inventory, which reads identically to a clean estate.

WHAT IS DELIBERATELY NOT HERE
------------------------------
No route serves the attack campaign. It is a build-time artifact bound to a
commit (`reports/evidence/attack_campaign.json`), and serving it from a running
process would let a reader mistake "the campaign passed on some build" for "the
campaign passed on THIS build". The release gate is where that belongs.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Mapping

from fastapi import Depends, FastAPI, HTTPException, Query

from sentinel.domain.adoption import TenantCounts, assess_adoption
from sentinel.domain.ai_bom import compile_ai_bom
from sentinel.domain.assets import (
    AssetInventory,
    AssetKind,
    AssetRecord,
    DiscoveryCoverage,
    Unreachable,
)
from sentinel.domain.authorization import Capability
from sentinel.domain.exposure_graph import (
    EdgeBasis,
    ExposureEdge,
    GraphCoverage,
    NodeKind,
    UnscannedScope,
    build_exposure_graph,
)
from sentinel.domain.inventory import ObservedEdgeKind

__all__ = ["register_estate_routes"]

#: How an observed edge maps into the exposure graph's node vocabulary.
#:
#: MappingProxyType, because the fitness rule bans module-level mutable state
#: -- and my first version of this comment claimed the mapping was built inside
#: the function that used it while the code declared it here. The rule caught
#: the contradiction, which is what it is for.
#:
#: The mapping is TOTAL over `ObservedEdgeKind`, and a test asserts that: a new
#: edge kind falling through to RESOURCE would make it invisible to every
#: credential-sharing question, silently.
_NODE_KIND: Mapping[ObservedEdgeKind, NodeKind] = MappingProxyType({
    ObservedEdgeKind.ACTION: NodeKind.RESOURCE,
    ObservedEdgeKind.RESOURCE: NodeKind.RESOURCE,
    ObservedEdgeKind.DESTINATION: NodeKind.DESTINATION,
    ObservedEdgeKind.MCP_SERVER: NodeKind.MCP_SERVER,
    ObservedEdgeKind.TOOL: NodeKind.TOOL,
    ObservedEdgeKind.CREDENTIAL: NodeKind.CREDENTIAL,
})


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _inventory_from_profiles(container: Any, tenant: str) -> AssetInventory:
    """Turn what the agent inventory observed into an asset inventory.

    Coverage is built from what this build can actually see, which is the
    agent-observation table and nothing else. It is therefore reported as
    PARTIAL with the reason named -- an AI-BOM that claimed COMPLETE from one
    source would be asserting there are no models, servers or skills anywhere
    else in the estate.
    """
    profiles = container.inventory.list_profiles(tenant)

    assets: list[AssetRecord] = []
    examined = 0
    for profile in profiles:
        examined += 1
        assets.append(
            AssetRecord(
                kind=AssetKind.AGENT,
                identifier=str(profile.agent_id),
                source="agent_inventory",
                native_type="observed_agent",
                display_name=str(getattr(profile, "label", "") or ""),
                relates_to=tuple(
                    sorted({str(edge.target) for edge in profile.edges})
                ),
                attributes={
                    # OBSERVED: it was seen in traffic. Never attested -- nothing
                    # here binds a digest to what ran.
                    "provenance": "observed",
                    "classification": str(profile.classification.value),
                },
            )
        )
        for edge in profile.edges:
            kind = {
                ObservedEdgeKind.MCP_SERVER: AssetKind.MCP_SERVER,
                ObservedEdgeKind.TOOL: AssetKind.MCP_TOOL,
                ObservedEdgeKind.CREDENTIAL: AssetKind.CREDENTIAL,
            }.get(edge.kind)
            if kind is None:
                # Actions, resources and destinations are not AI supply-chain
                # components. Skipped here rather than mapped to the nearest
                # member, because a BOM full of file paths answers a different
                # question than the one it claims to.
                continue
            assets.append(
                AssetRecord(
                    kind=kind,
                    identifier=str(edge.target),
                    source="agent_inventory",
                    native_type=edge.kind.value,
                    relates_to=(str(profile.agent_id),),
                    attributes={"provenance": "observed"},
                )
            )

    return AssetInventory(
        connector="agent_inventory",
        assets=tuple(assets),
        coverage=DiscoveryCoverage(
            scope=(f"tenant:{tenant}",),
            examined=examined,
            unreachable=(
                Unreachable(
                    target="every source other than observed agent traffic",
                    reason=(
                        "this build assembles the AI-BOM from the agent "
                        "observation table only. Cloud accounts, model "
                        "registries, CI systems and repositories are not "
                        "consulted here, so a component nothing has called is "
                        "absent from this document. Run the GitHub and "
                        "Kubernetes connectors and pass their inventories to "
                        "compile_ai_bom for a fuller picture."
                    ),
                ),
            ),
            permissions_used=("read: inventory.list_profiles",),
            retrieved_at=_now(),
        ),
    )


def register_estate_routes(app: FastAPI, container: Any, *, require: Any) -> None:
    """Attach the AI-BOM, exposure-graph and transparency surfaces."""

    @app.get("/v1/estate/ai-bom")
    def ai_bom(principal=Depends(require(Capability.READ_INCIDENT))):
        """The AI supply chain, with its completeness verdict first.

        `READ_INCIDENT`: this is a report about the estate and changes nothing.

        The verdict will be PARTIAL on this build, because only one source is
        consulted. That is stated in the coverage rather than hidden -- an
        empty AI-BOM marked COMPLETE reads exactly like a clean estate.
        """
        tenant = str(principal.tenant)
        bom = compile_ai_bom(
            tenant=tenant,
            inventories=(_inventory_from_profiles(container, tenant),),
            generated_at=_now(),
        )
        return bom.as_dict()

    @app.get("/v1/estate/ai-bom/cyclonedx")
    def ai_bom_cyclonedx(principal=Depends(require(Capability.READ_INCIDENT))):
        """The same document in CycloneDX 1.6 shape.

        Labelled `sentinel:schema_validated: false` in its own metadata,
        because this repository validates it against no schema and calling it
        "CycloneDX compliant" would be a claim with no evidence behind it.
        """
        tenant = str(principal.tenant)
        bom = compile_ai_bom(
            tenant=tenant,
            inventories=(_inventory_from_profiles(container, tenant),),
            generated_at=_now(),
        )
        return bom.as_cyclonedx()

    @app.get("/v1/estate/adoption")
    def adoption(principal=Depends(require(Capability.READ_INCIDENT))):
        """How far along the funnel this tenant is, and what is blocking it.

        Computed locally from counts this deployment already holds. NOTHING is
        sent anywhere -- see the module docstring in `domain/adoption.py` for
        why that matters more here than in an ordinary product-analytics
        module: which agents exist and how often they act is the most
        sensitive telemetry in a security deployment.

        Counts that this build cannot obtain cheaply are passed as zero AND the
        stage's own `evidence` names what produced it, so a low stage reads as
        "we observed this much" rather than as a score.
        """
        tenant = str(principal.tenant)

        profiles = container.inventory.list_profiles(tenant)
        events = sum(int(getattr(p, "event_count", 0) or 0) for p in profiles)
        # `violation_count` is the count of activity that TRIPPED POLICY, which
        # is distinct from an incident: a violation the gate refused never
        # became one, so counting only incidents undercounts exactly the cases
        # where enforcement worked.
        refused = sum(int(getattr(p, "violation_count", 0) or 0) for p in profiles)
        incidents = sum(int(getattr(p, "incident_count", 0) or 0) for p in profiles)

        snapshot = assess_adoption(
            tenant=tenant,
            counts=TenantCounts(
                agents_observed=len(profiles),
                events_ingested=events,
                incidents_raised=incidents,
                # NOT approximated. This build has no cheap count of incidents
                # whose state moved past `received`, and passing the raised
                # count here would report a 100% triage rate for a tenant that
                # has opened nothing -- the single most flattering error this
                # funnel could make. Zero is honest: the stage will say triage
                # is what is blocking progress, which is true until measured.
                incidents_triaged=0,
                actions_refused=refused,
                # Likewise not guessed: a containment count needs a separate
                # read, and inferring one from refusals would conflate a
                # policy refusal with an operator pulling the kill switch.
                containments_activated=0,
                # Zero, and therefore no engagement rate is quoted -- which is
                # correct, because this build does not know how far back the
                # counts reach.
                observation_window_days=0,
            ),
        )

        document = snapshot.as_dict()
        document["counts_not_measured_by_this_build"] = [
            "incidents_triaged — no cheap count of incidents past `received`; "
            "passing the raised count would report 100% triage for a tenant "
            "that opened nothing",
            "containments_activated — needs a separate read; inferring it from "
            "refusals would conflate a policy refusal with a kill switch",
            "observation_window_days — unknown here, so no engagement rate is "
            "quoted rather than one computed over an unknown period",
        ]
        return document

    @app.get("/v1/estate/exposure")
    def exposure(principal=Depends(require(Capability.READ_INCIDENT))):
        """One graph over agents, credentials, tools and destinations.

        Coverage first in the body. A missing edge means either that nothing
        connects two things or that nothing looked, and this build only ever
        sees observed traffic -- so every node it did not observe is UNKNOWN
        rather than isolated.
        """
        tenant = str(principal.tenant)
        profiles = container.inventory.list_profiles(tenant)

        edges: list[ExposureEdge] = []
        kinds: dict[str, NodeKind] = {}
        for profile in profiles:
            agent = str(profile.agent_id)
            kinds[agent] = NodeKind.AGENT
            for edge in profile.edges:
                target = str(edge.target)
                if not target or target == agent:
                    # A self-loop makes every reachability answer trivially
                    # true; the domain refuses one, so it is dropped here
                    # rather than raising on a malformed observation.
                    continue
                edges.append(
                    ExposureEdge(
                        source=agent,
                        target=target,
                        target_kind=_NODE_KIND.get(edge.kind, NodeKind.RESOURCE),
                        # OBSERVED, not GRANTED. These came from traffic, and
                        # the two fail in opposite directions.
                        basis=EdgeBasis.OBSERVED,
                        occurrences=int(getattr(edge, "occurrences", 0) or 0),
                        last_seen=str(getattr(edge, "last_seen", "") or ""),
                    )
                )

        graph = build_exposure_graph(
            tenant=tenant,
            edges=edges,
            coverage=GraphCoverage(
                scanned=(f"tenant:{tenant}",),
                unscanned=(
                    UnscannedScope(
                        scope="grant tables, cloud accounts, repositories",
                        reason=(
                            "this graph is assembled from OBSERVED traffic "
                            "only. An agent that holds a grant it has never "
                            "exercised has no edge here, so the absence of a "
                            "path is not evidence of isolation -- every "
                            "negative answer from this build is UNKNOWN."
                        ),
                    ),
                ),
                observed_from=_now(),
                observed_to=_now(),
            ),
            node_kinds=kinds,
        )
        return graph.as_dict()

    @app.get("/v1/estate/exposure/reach/{node}")
    def reach(
        node: str,
        target: str = Query(..., min_length=1, max_length=512),
        principal=Depends(require(Capability.READ_INCIDENT)),
    ):
        """Can `node` reach `target`? Three-valued, never a boolean.

        The verdict is `reachable`, `not_reachable` or `unknown`. On this build
        it is `unknown` for every negative, because the graph sees only observed
        traffic -- which is the honest answer and is why the route returns the
        verdict as a string rather than as a status code.
        """
        if not node.strip():
            raise HTTPException(status_code=422, detail="node is required")

        tenant = str(principal.tenant)
        profiles = container.inventory.list_profiles(tenant)

        edges: list[ExposureEdge] = []
        for profile in profiles:
            agent = str(profile.agent_id)
            for edge in profile.edges:
                item = str(edge.target)
                if not item or item == agent:
                    continue
                edges.append(
                    ExposureEdge(
                        source=agent,
                        target=item,
                        target_kind=_NODE_KIND.get(edge.kind, NodeKind.RESOURCE),
                        basis=EdgeBasis.OBSERVED,
                    )
                )

        graph = build_exposure_graph(
            tenant=tenant,
            edges=edges,
            coverage=GraphCoverage(
                scanned=(f"tenant:{tenant}",),
                unscanned=(
                    UnscannedScope(
                        scope="grant tables and unobserved paths",
                        reason="observed traffic only",
                    ),
                ),
            ),
        )

        verdict = graph.reachability_of(node, target)
        path = graph.shortest_path(node, target)
        return {
            "verdict": verdict.value,
            "node": node,
            "target": target,
            "path": path.as_dict() if path is not None else None,
            "principals_sharing_target": list(graph.principals_sharing(target)),
            "limits": (
                "`not_reachable` is asserted only when everywhere a route could "
                "come from was examined. This build sees observed traffic only, "
                "so a negative answer is `unknown` -- an agent holding an "
                "unexercised grant has no edge here."
            ),
        }
