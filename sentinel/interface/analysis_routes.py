"""Read-only analysis over what is already stored. No new state, no decisions.

WHY THESE ROUTES EXIST
----------------------
`mcp_estate.py` and `blast_radius.py` compute things no other part of the system
can, and until now nothing could reach them. A capability with no HTTP surface
is a capability an operator does not have -- and a console page cannot call what
does not exist, so these come before any view that would use them.

EVERYTHING HERE IS A GET OR AN EXPLICIT ANALYSIS POST
-------------------------------------------------------
No route here changes anything. The estate view reports collisions and shadow
servers; it does not block them. Blast radius weighs reach; it does not revoke.
That separation is the same one `mcp_estate` documents at the domain level: a
collision between two legitimately enrolled servers is a configuration problem
to resolve deliberately, and blocking both would take out the trusted one
alongside the impostor.

WHY BLAST RADIUS TAKES DECLARATIONS IN THE REQUEST
----------------------------------------------------
Asset sensitivity is declared by a human, and this deployment has no store for
those declarations. The honest options were to invent one, to infer sensitivity
from asset names -- which `blast_radius` refuses by design -- or to accept the
declarations from the caller and say so.

The third is what this does. `coverage` in the response reports what fraction of
reachable assets the caller actually declared, so a request with no declarations
returns a score of zero AND a coverage of zero, which reads correctly as "nobody
has classified this estate" rather than as "this agent is safe".

A persistent declaration store is the obvious next step and is not pretended to
exist.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi import Depends, FastAPI, Query
from pydantic import BaseModel, Field

from sentinel.domain.authorization import Capability
from sentinel.domain.blast_radius import (
    AssetDeclaration,
    Sensitivity,
    compute_blast_radius,
)
from sentinel.domain.effective_permissions import compute_effective_reach
from sentinel.domain.mcp_estate import ObservedServerUse, ServerRecord, assess_estate

__all__ = ["register_analysis_routes"]


class _Declaration(BaseModel):
    """One human judgement about one asset, supplied by the caller.

    `declared_by` is required by the domain model and therefore required here.
    Sensitivity is declared rather than inferred precisely so somebody is
    accountable for the judgement, and an API that defaulted the author would
    make every declaration anonymous.
    """

    asset: str = Field(min_length=1, max_length=512)
    sensitivity: str = Field(max_length=32)
    declared_by: str = Field(min_length=1, max_length=128)
    production: bool = False


class _BlastRadiusRequest(BaseModel):
    declarations: list[_Declaration] = Field(default_factory=list, max_length=500)


def register_analysis_routes(app: FastAPI, container: Any, *, require: Any) -> None:
    """Attach the read-only analysis surface."""

    @app.get("/v1/analysis/mcp-estate")
    def mcp_estate(
        days: int = Query(default=30, ge=1, le=365),
        principal=Depends(require(Capability.READ_INCIDENT)),
    ):
        """Findings no single MCP call can produce.

        `READ_INCIDENT` rather than a management capability: this is a report
        about the estate, and an analyst who can read incidents should be able
        to see that two servers offer the same tool name. It changes nothing.
        """
        tenant = str(principal.tenant)
        registry = container.mcp_registry

        records: list[ServerRecord] = []
        for row in registry.list_servers(tenant):
            server_id = str(row["server_id"])
            # `list_servers` reports a pin COUNT, and collision detection needs
            # the names. One extra read per server, and the server count is
            # bounded by what an operator enrolled by hand.
            identity = registry.lookup(tenant, server_id)
            tools = tuple(registry.pinned(identity)) if identity is not None else ()
            records.append(
                ServerRecord(
                    server_id=server_id,
                    trust=str(row["trust"]),
                    tool_names=tools,
                    endpoint=str(row["endpoint"]),
                )
            )

        # Observed use comes from the audit trail: the wire proxy records every
        # call it handled, including the ones it REFUSED because the server was
        # not enrolled, so a shadow server an agent tried to reach is visible.
        # It was previously left empty because no per-server table existed; the
        # audit rows were that table all along.
        since = (container.clock.now().value - timedelta(days=days)).isoformat()
        used = container.coverage_reader.mcp_server_use(tenant, since=since)
        report = assess_estate(
            enrolled=records,
            observed=[ObservedServerUse(server_id=u["server_id"], agent_ids=u["agent_ids"], call_count=u["call_count"])
                      for u in used],
        )
        return {
            **report.as_dict(),
            "observed_window_days": days,
            "observed_servers": len(used),
            "observed_source": (
                "security_audit rows for mcp.proxy over the window. This is traffic that went "
                "THROUGH Sentinel's proxy, including refused calls to servers nobody enrolled. "
                "An agent that reaches an MCP server directly is invisible here, so an empty "
                "shadow-server list means none were attempted through the proxy, not that none exist."
            ),
        }

    @app.post("/v1/analysis/blast-radius/{agent_id}")
    def blast_radius(
        agent_id: str,
        body: _BlastRadiusRequest,
        principal=Depends(require(Capability.READ_INCIDENT)),
    ):
        """What this agent can reach, weighted by what the caller declared.

        A POST because the declarations are the input. Making it a GET would
        mean putting asset sensitivity in a query string, where it lands in
        access logs -- and "which of our assets are RESTRICTED" is not a
        sentence that belongs in a log line.
        """
        tenant = str(principal.tenant)

        folded: dict[str, list[str]] = {}
        for row in container.agent_capabilities.list_grants(tenant):
            tool = str(row.get("tool_name", ""))
            if tool:
                folded.setdefault(str(row.get("agent_id", "")), []).append(tool)

        reach = compute_effective_reach(
            agent_id, grants={k: tuple(v) for k, v in folded.items()}
        )

        declarations = []
        rejected: list[dict[str, str]] = []
        for entry in body.declarations:
            try:
                sensitivity = Sensitivity(entry.sensitivity.strip().lower())
            except ValueError:
                # Reported, not dropped. A declaration silently discarded means
                # an asset the caller believes is classified is not, and the
                # coverage figure would then overstate how much of the estate
                # has been assessed.
                rejected.append(
                    {
                        "asset": entry.asset,
                        "reason": (
                            f"{entry.sensitivity!r} is not one of "
                            f"{[s.value for s in Sensitivity]}"
                        ),
                    }
                )
                continue
            declarations.append(
                AssetDeclaration(
                    asset=entry.asset,
                    sensitivity=sensitivity,
                    declared_by=entry.declared_by,
                    production=entry.production,
                )
            )

        radius = compute_blast_radius(reach, declarations=declarations)
        return {
            **radius.as_dict(),
            "rejected_declarations": rejected,
            "declaration_source": (
                "SUPPLIED_BY_CALLER — this build has no persistent asset "
                "declaration store. `coverage` reports what fraction of "
                "reachable assets this request classified; a request with no "
                "declarations returns coverage 0, which reads as 'nobody has "
                "classified this estate', not as 'this agent is safe'."
            ),
        }
