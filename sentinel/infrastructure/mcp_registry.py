"""Durable MCP server trust and tool pins, tenant-scoped.

WHY THIS IS NOT OPTIONAL
------------------------
`InMemoryToolPins` and `InMemoryServerDirectory` are correct and useless in
production for the same reason: they are process-local. A deployment runs
multiple replicas, so an operator who enrols a server through one pod would find
the server still UNKNOWN on the next request that lands on a different pod, and
every pin would vanish on restart. The result is not "slightly degraded" -- it
is a trust decision that appears to have been made and was not, which is the
defect shape this repository has spent a great deal of effort naming.

TENANT SCOPING IS THE POINT, NOT A FORMALITY
--------------------------------------------
Both tables are in `PROTECTED_TABLES` and carry FORCE row-level security, and
every method here calls `conn.set_tenant()` before it reads or writes. That
combination is what makes the isolation real: the predecessor added a table to
the protected set and then queried it from an unscoped connection, which fails
closed on PostgreSQL and passes silently on SQLite. For these two tables the
stakes are specific -- a cross-tenant READ tells an attacker which MCP servers a
victim trusts, and a cross-tenant WRITE pins a hostile tool definition into
someone else's allowlist, which is worse than the read by a wide margin.

WHAT IS STORED AND WHAT IS NOT
------------------------------
Trust and fingerprints. Not tool descriptions: the description is the untrusted,
attacker-controlled text, and storing it would create a second copy to keep in
sync and a tempting place for a future reader to compare against instead of
re-fingerprinting the live definition. The pin is the hash. The live definition
is whatever the server just said. Drift is the comparison between them.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from sentinel.application.mcp_gateway import McpServerDirectory, ToolPinStore
from sentinel.domain.mcp import (
    McpChange,
    McpServerIdentity,
    McpServerTrust,
    McpToolDefinition,
)

__all__ = ["SqlMcpRegistry"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SqlMcpRegistry(ToolPinStore, McpServerDirectory):
    """One object implementing both ports, over `mcp_servers`/`mcp_tool_pins`.

    Kept as one class rather than two because the two tables are written in the
    same operator action -- enrolling a server pins its tools -- and splitting
    them would invite a caller to do one without the other, leaving a server
    marked ENROLLED with nothing pinned. That state is not fatal (the gateway
    refuses an unpinned server unless `require_pin=False`), but it is a
    confusing thing to be able to construct by accident.
    """

    __slots__ = ("_pool",)

    def __init__(self, *, pool: Any) -> None:
        self._pool = pool

    # ── McpServerDirectory ───────────────────────────────────────────────────

    def lookup(self, tenant_id: str, server_id: str) -> McpServerIdentity | None:
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            p = conn.p
            row = conn.one(
                f"SELECT server_id, endpoint, trust FROM mcp_servers "
                f"WHERE tenant_id={p} AND server_id={p}",
                (tenant_id, server_id),
            )
            conn.commit()
        if row is None:
            return None
        return McpServerIdentity(
            tenant_id=tenant_id,
            server_id=str(row["server_id"]),
            endpoint=str(row["endpoint"] or ""),
            # An unrecognised value fails closed rather than raising. A trust
            # column holding something this build does not understand -- a
            # downgrade, a hand-edited row -- must not be read as permission.
            trust=_parse_trust(str(row["trust"])),
        )

    def record(self, server: McpServerIdentity) -> None:
        now = _now()
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(server.tenant_id)
            p = conn.p
            conn.execute_rowcount(
                f"INSERT INTO mcp_servers "
                f"(tenant_id, server_id, endpoint, trust, enrolled_at, updated_at) "
                f"VALUES ({p},{p},{p},{p},{p},{p}) "
                f"ON CONFLICT (tenant_id, server_id) DO UPDATE SET "
                f"endpoint=EXCLUDED.endpoint, trust=EXCLUDED.trust, "
                f"updated_at=EXCLUDED.updated_at",
                (
                    server.tenant_id,
                    server.server_id,
                    server.endpoint,
                    server.trust.value,
                    now,
                    now,
                ),
            )
            conn.commit()

    # ── ToolPinStore ─────────────────────────────────────────────────────────

    def pinned(self, server: McpServerIdentity) -> Mapping[str, str]:
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(server.tenant_id)
            p = conn.p
            rows = conn.execute(
                f"SELECT tool_name, fingerprint FROM mcp_tool_pins "
                f"WHERE tenant_id={p} AND server_id={p}",
                (server.tenant_id, server.server_id),
            )
            conn.commit()
        return {str(r["tool_name"]): str(r["fingerprint"]) for r in rows}

    def pin(self, server: McpServerIdentity, tools: Mapping[str, str]) -> None:
        """Replace the pinned set for one server, in one transaction.

        Replace rather than merge, and atomically, because the pinned set is a
        snapshot of what an operator reviewed at one moment. Merging would leave
        a tool pinned that the operator has since removed from the approved list,
        and doing the delete and the insert in separate transactions would leave
        a window in which the server has NO pins -- which, under `require_pin`,
        turns a re-approval into an outage.
        """
        now = _now()
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(server.tenant_id)
            p = conn.p
            conn.execute_rowcount(
                f"DELETE FROM mcp_tool_pins WHERE tenant_id={p} AND server_id={p}",
                (server.tenant_id, server.server_id),
            )
            for name, fingerprint in tools.items():
                conn.execute_rowcount(
                    f"INSERT INTO mcp_tool_pins "
                    f"(tenant_id, server_id, tool_name, fingerprint, pinned_at) "
                    f"VALUES ({p},{p},{p},{p},{p})",
                    (server.tenant_id, server.server_id, name, fingerprint, now),
                )
            conn.commit()

    # ── Server identity ──────────────────────────────────────────────────────

    def server_info(self, tenant_id: str, server_id: str) -> str:
        """What the server last said about itself, or "" if never observed."""
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            p = conn.p
            row = conn.one(
                f"SELECT server_info FROM mcp_servers "
                f"WHERE tenant_id={p} AND server_id={p}",
                (tenant_id, server_id),
            )
            conn.commit()
        return str(row["server_info"] or "") if row else ""

    def record_server_info(self, tenant_id: str, server_id: str, info: str) -> None:
        """Store the server's self-reported identity.

        Scoped to an EXISTING row rather than upserting: this records what a
        known server said about itself, and a write that could conjure the row
        would be a way to create a server record from a code path that does no
        trust decision at all.
        """
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            p = conn.p
            conn.execute_rowcount(
                f"UPDATE mcp_servers SET server_info={p}, updated_at={p} "
                f"WHERE tenant_id={p} AND server_id={p}",
                (info, _now(), tenant_id, server_id),
            )
            conn.commit()

    # ── Provenance ───────────────────────────────────────────────────────────

    def observe_tools(
        self, server: McpServerIdentity, tools: tuple[McpToolDefinition, ...]
    ) -> None:
        """Record that these definition versions were served, right now.

        One row per (tool, fingerprint): a re-served known version bumps
        `last_seen`/`times_seen`, a NEW version opens a new row and leaves the
        old one intact. That non-destructive shape is the point -- after a rug
        pull the investigation's first artefacts are "when did the old
        definition stop appearing" and "when did the new one start", which are
        exactly `last_seen` of one row and `first_seen` of the other.
        """
        if not tools:
            return
        now = _now()
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(server.tenant_id)
            p = conn.p
            for tool in tools:
                conn.execute_rowcount(
                    f"INSERT INTO mcp_tool_provenance "
                    f"(tenant_id, server_id, tool_name, fingerprint, "
                    f"description_sha256, schema_sha256, first_seen, last_seen, "
                    f"times_seen) "
                    f"VALUES ({p},{p},{p},{p},{p},{p},{p},{p},1) "
                    f"ON CONFLICT (tenant_id, server_id, tool_name, fingerprint) "
                    f"DO UPDATE SET last_seen=EXCLUDED.last_seen, "
                    f"times_seen=mcp_tool_provenance.times_seen+1",
                    (
                        server.tenant_id,
                        server.server_id,
                        tool.name,
                        tool.fingerprint,
                        tool.description_sha256,
                        tool.schema_sha256,
                        now,
                        now,
                    ),
                )
            conn.commit()

    def record_changes(
        self, server: McpServerIdentity, changes: tuple[McpChange, ...]
    ) -> None:
        """Append observed drift to the durable log. Never updates, never dedupes.

        The same drift observed on two calls is two rows on purpose: "the
        hostile definition was served forty times over three days" and "it was
        served once" are different incidents, and a dedupe would flatten them
        into the same record.
        """
        if not changes:
            return
        now = _now()
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(server.tenant_id)
            p = conn.p
            for change in changes:
                conn.execute_rowcount(
                    f"INSERT INTO mcp_tool_changes "
                    f"(tenant_id, server_id, tool_name, kind, pinned_fingerprint, "
                    f"observed_fingerprint, detail, observed_at) "
                    f"VALUES ({p},{p},{p},{p},{p},{p},{p},{p})",
                    (
                        server.tenant_id,
                        server.server_id,
                        change.tool_name,
                        change.kind.value,
                        change.pinned_fingerprint,
                        change.observed_fingerprint,
                        change.detail,
                        now,
                    ),
                )
            conn.commit()

    def tool_provenance(
        self, tenant_id: str, server_id: str
    ) -> tuple[dict[str, object], ...]:
        """Every definition version a server has served, newest last seen first."""
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            p = conn.p
            rows = conn.execute(
                f"SELECT tool_name, fingerprint, description_sha256, "
                f"schema_sha256, first_seen, last_seen, times_seen "
                f"FROM mcp_tool_provenance "
                f"WHERE tenant_id={p} AND server_id={p} "
                f"ORDER BY last_seen DESC, tool_name",
                (tenant_id, server_id),
            )
            conn.commit()
        return tuple(
            {
                "tool_name": str(r["tool_name"]),
                "fingerprint": str(r["fingerprint"]),
                "description_sha256": str(r["description_sha256"]),
                "schema_sha256": str(r["schema_sha256"]),
                "first_seen": str(r["first_seen"]),
                "last_seen": str(r["last_seen"]),
                "times_seen": int(r["times_seen"]),
            }
            for r in rows
        )

    def tool_changes(
        self, tenant_id: str, server_id: str, *, limit: int = 100
    ) -> tuple[dict[str, object], ...]:
        """The drift log for one server, most recent first, bounded."""
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            p = conn.p
            rows = conn.execute(
                f"SELECT tool_name, kind, pinned_fingerprint, "
                f"observed_fingerprint, detail, observed_at "
                f"FROM mcp_tool_changes "
                f"WHERE tenant_id={p} AND server_id={p} "
                f"ORDER BY observed_at DESC LIMIT {p}",
                (tenant_id, server_id, int(limit)),
            )
            conn.commit()
        return tuple(
            {
                "tool_name": str(r["tool_name"]),
                "kind": str(r["kind"]),
                "pinned_fingerprint": str(r["pinned_fingerprint"]),
                "observed_fingerprint": str(r["observed_fingerprint"]),
                "detail": str(r["detail"]),
                "observed_at": str(r["observed_at"]),
            }
            for r in rows
        )

    # ── Operator reporting ───────────────────────────────────────────────────

    def list_servers(self, tenant_id: str) -> tuple[dict[str, object], ...]:
        """Every server this tenant has decided about, with its pin count.

        Exists so "which MCP servers are we talking to" is answerable without a
        database session. A blocked server appears here too: knowing what was
        refused is as operationally useful as knowing what was allowed.
        """
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            p = conn.p
            rows = conn.execute(
                f"SELECT server_id, endpoint, trust, server_info, "
                f"enrolled_at, updated_at "
                f"FROM mcp_servers WHERE tenant_id={p} ORDER BY server_id",
                (tenant_id,),
            )
            pins = conn.execute(
                f"SELECT server_id, tool_name FROM mcp_tool_pins WHERE tenant_id={p}",
                (tenant_id,),
            )
            conn.commit()
        counts: dict[str, int] = {}
        for row in pins:
            key = str(row["server_id"])
            counts[key] = counts.get(key, 0) + 1
        return tuple(
            {
                "server_id": str(r["server_id"]),
                "endpoint": str(r["endpoint"] or ""),
                "trust": _parse_trust(str(r["trust"])).value,
                "pinned_tools": counts.get(str(r["server_id"]), 0),
                "server_info": str(r["server_info"] or ""),
                "enrolled_at": str(r["enrolled_at"]),
                "updated_at": str(r["updated_at"]),
            }
            for r in rows
        )


def _parse_trust(raw: str) -> McpServerTrust:
    """Map a stored trust string to the enum, defaulting to UNKNOWN.

    Deliberately does not raise. A row whose trust value this build does not
    recognise is a row we cannot vouch for, and UNKNOWN is refused by the
    gateway -- so the unrecognised case fails in the safe direction instead of
    taking the whole lookup down.
    """
    try:
        return McpServerTrust(raw)
    except ValueError:
        return McpServerTrust.UNKNOWN
