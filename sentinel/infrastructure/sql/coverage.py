"""Counts the coverage model needs that no existing store exposes.

Read-only, tenant-scoped with explicit predicates. Kept tiny on purpose: each
method answers one question the coverage route asks, and names the table it
counted so the route can say where the number came from.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sentinel.infrastructure.sql.engine import ConnectionPool

__all__ = ["SqlCoverageReader"]


@dataclass(frozen=True, slots=True)
class SqlCoverageReader:
    pool: ConnectionPool

    def protect_evaluations(self, tenant: str) -> int:
        """How many times the gate was ASKED, from the audit trail."""
        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)
            row = conn.one(
                f"SELECT COUNT(*) AS n FROM security_audit "
                f"WHERE tenant_id={p} AND action={p}",
                (tenant, "protect.evaluate"),
            )
            conn.commit()
        return int(row["n"]) if row else 0

    def agents_with_operations(self, tenant: str) -> set[str]:
        """Agents that have at least one operation, i.e. routed through the gate."""
        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)
            rows = conn.execute(
                f"SELECT DISTINCT agent_identity FROM execution_operations "
                f"WHERE tenant_id={p}",
                (tenant,),
            )
            conn.commit()
        return {str(r["agent_identity"]) for r in rows}

    def mcp_server_use(self, tenant: str, *, since: str) -> list[dict[str, Any]]:
        """Per MCP server: which agents called it through the proxy, and how often.

        Read from the tamper-evident audit trail, where the wire proxy records
        every call it handled -- INCLUDING the ones it refused because the
        server was not enrolled, which is exactly what a shadow server looks
        like from here. It sees only traffic that went through the proxy; an
        agent that talks to an MCP server directly is invisible to this query,
        and the route that uses it says so.
        """
        import json

        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)
            rows = conn.execute(
                f"SELECT resource_id, detail FROM security_audit WHERE tenant_id={p} AND action={p} "
                f"AND resource_type={p} AND occurred_at>={p}",
                (tenant, "mcp.proxy", "mcp_server", since),
            )
            conn.commit()
        use: dict[str, dict[str, Any]] = {}
        for row in rows:
            entry = use.setdefault(str(row["resource_id"]), {"agents": set(), "calls": 0})
            entry["calls"] += 1
            try:
                agent = json.loads(str(row["detail"] or "{}")).get("agent_id")
            except json.JSONDecodeError:
                agent = None
            if agent:
                entry["agents"].add(str(agent))
        return [{"server_id": server, "agent_ids": tuple(sorted(v["agents"])), "call_count": v["calls"]}
                for server, v in sorted(use.items())]
