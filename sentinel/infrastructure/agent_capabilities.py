"""Durable, tenant-scoped agent capability grants.

Grants are an authorisation decision, so they belong in the database rather than
in a process: an in-memory store means replica A permits what replica B refuses,
and which one an agent reaches is a load-balancer detail.

Every query is scoped TWICE -- `set_tenant` for row-level security AND an
explicit `tenant_id` predicate. That is not belt-and-braces: SQLite has no RLS,
so on that engine the predicate is the only tenant boundary. Removing it there
is invisible until a second tenant exists.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sentinel.application.agent_capabilities import AgentCapabilityStore
from sentinel.infrastructure.sql.engine import ConnectionPool

__all__ = ["SqlAgentCapabilities"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SqlAgentCapabilities(AgentCapabilityStore):
    """`agent_tool_grants`, scoped per tenant."""

    __slots__ = ("_pool",)

    def __init__(self, *, pool: ConnectionPool) -> None:
        self._pool = pool

    def granted(self, tenant_id: str, agent_id: str) -> frozenset[str]:
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            p = conn.p
            rows = conn.execute(
                f"SELECT tool_name FROM agent_tool_grants "
                f"WHERE tenant_id={p} AND agent_id={p}",
                (tenant_id, agent_id),
            )
            conn.commit()
        return frozenset(str(r["tool_name"]) for r in rows)

    def grant(self, tenant_id: str, agent_id: str, tools: frozenset[str]) -> None:
        """Add grants. Additive, and idempotent on re-grant.

        Additive rather than replace-the-set, which is the opposite of
        `SqlMcpRegistry.pin`. The two are different decisions: a pin is a
        SNAPSHOT of what a server offered at one moment, so merging would leave a
        stale tool pinned. A grant is a standing authorisation an operator issues
        one at a time, and replacing the set would make `agent-grant X` silently
        revoke every capability granted before it.
        """
        now = _now()
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            p = conn.p
            for tool in sorted(tools):
                # Delete-then-insert rather than ON CONFLICT: the row's only
                # non-key column is `granted_at`, and re-granting an existing
                # capability should refresh when it was decided.
                conn.execute_rowcount(
                    f"DELETE FROM agent_tool_grants WHERE tenant_id={p} "
                    f"AND agent_id={p} AND tool_name={p}",
                    (tenant_id, agent_id, tool),
                )
                conn.execute_rowcount(
                    f"INSERT INTO agent_tool_grants "
                    f"(tenant_id, agent_id, tool_name, granted_at) "
                    f"VALUES ({p},{p},{p},{p})",
                    (tenant_id, agent_id, tool, now),
                )
            conn.commit()

    def revoke(self, tenant_id: str, agent_id: str, tools: frozenset[str]) -> None:
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            p = conn.p
            for tool in sorted(tools):
                conn.execute_rowcount(
                    f"DELETE FROM agent_tool_grants WHERE tenant_id={p} "
                    f"AND agent_id={p} AND tool_name={p}",
                    (tenant_id, agent_id, tool),
                )
            conn.commit()

    def list_grants(self, tenant_id: str) -> tuple[dict[str, object], ...]:
        """Every grant this tenant has issued, for operator reporting.

        Exists so "what can our agents do" is answerable without a database
        session -- the question an auditor asks first and the one an operator
        needs before turning enforcement on.
        """
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            p = conn.p
            rows = conn.execute(
                f"SELECT agent_id, tool_name, granted_at FROM agent_tool_grants "
                f"WHERE tenant_id={p} ORDER BY agent_id, tool_name",
                (tenant_id,),
            )
            conn.commit()
        return tuple(
            {
                "agent_id": str(r["agent_id"]),
                "tool_name": str(r["tool_name"]),
                "granted_at": str(r["granted_at"]),
            }
            for r in rows
        )
