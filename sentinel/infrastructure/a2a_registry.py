"""Durable A2A agent cards. The store that makes drift detection real.

WHAT THIS REPLACES, AND WHY IT MATTERED
-----------------------------------------
`InMemoryAgentCards` held enrolments and their fingerprint pins in one worker's
memory. In a single-process deployment it worked; in any deployment with a
second replica it silently did not, because a card enrolled through one replica
was invisible to the next. `card_drift` -- the finding that says an agent's
advertised capabilities changed after somebody approved them -- could therefore
not fire at all, and `unenrolled_agent` fired for agents that WERE enrolled,
just not here.

That is the same failure `SqlMcpRegistry` exists to prevent for MCP servers, and
this is the same fix: one row per card, keyed by tenant, behind row-level
security.

THE PIN IS WRITTEN AT ENROLMENT, NOT LATER
--------------------------------------------
`enrol` writes the fingerprint in the same statement as the card. An enrolled
agent whose fingerprint was not recorded could change freely and never trip
drift detection, which would make the whole card mechanism decorative -- so
there is no code path that stores a card without pinning it.

RE-ENROLMENT RE-PINS, DELIBERATELY
------------------------------------
`ON CONFLICT ... DO UPDATE` means enrolling an agent again accepts its current
shape as the new normal. That is the intended operator action -- "I have
reviewed this change" -- and it is why the route requires `manage_policy` rather
than an analyst capability: re-pinning is the one operation that can silence
drift detection permanently.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any, Iterable, Mapping

from sentinel.domain.a2a import AgentCard

__all__ = ["SqlAgentCardRegistry", "SqlTaskLedger"]


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


#: Capabilities are stored as a newline-separated list rather than JSON.
#: A scope is validated by `AgentCard.__post_init__` to `[a-z0-9_:*-]+`, so it
#: can never contain the separator -- which makes the round trip total, and
#: means a malformed row cannot inject a scope by embedding a delimiter the way
#: a comma-separated column would allow.
_SEP = "\n"


class SqlAgentCardRegistry:
    """Tenant-scoped, durable `AgentCardStore`.

    Every method opens its own transaction and sets the tenant, exactly as
    `SqlMcpRegistry` does. A connection that never established a tenant sees
    nothing under RLS rather than raising, so scoping is not optional here.
    """

    __slots__ = ("_pool",)

    def __init__(self, *, pool: Any) -> None:
        self._pool = pool

    def cards(self, tenant_id: str) -> Mapping[str, AgentCard]:
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            p = conn.p
            rows = conn.execute(
                f"SELECT agent_id, version, endpoint, capabilities, description "
                f"FROM a2a_agent_cards WHERE tenant_id={p}",
                (tenant_id,),
            )
            conn.commit()

        found: dict[str, AgentCard] = {}
        for row in rows:
            raw = str(row["capabilities"] or "")
            try:
                found[str(row["agent_id"])] = AgentCard(
                    agent_id=str(row["agent_id"]),
                    version=str(row["version"] or ""),
                    endpoint=str(row["endpoint"] or ""),
                    capabilities=frozenset(
                        s for s in raw.split(_SEP) if s.strip()
                    ),
                    description=str(row["description"] or ""),
                )
            except Exception:  # noqa: BLE001 - one bad row must not blind the rest
                # A row this build cannot parse is SKIPPED, not raised on. It
                # then has no card, so `inspect_chain` reports the agent as
                # UNENROLLED -- which is the fail-closed reading. Raising would
                # let one hand-edited row disable delegation checking for every
                # agent in the tenant.
                continue
        return found

    def pins(self, tenant_id: str) -> Mapping[str, str]:
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            p = conn.p
            rows = conn.execute(
                f"SELECT agent_id, fingerprint FROM a2a_agent_cards WHERE tenant_id={p}",
                (tenant_id,),
            )
            conn.commit()
        return {str(r["agent_id"]): str(r["fingerprint"]) for r in rows}

    def enrol(self, tenant_id: str, card: AgentCard) -> None:
        """Store a card and pin its fingerprint in the same statement."""
        now = _now()
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            p = conn.p
            conn.execute_rowcount(
                f"INSERT INTO a2a_agent_cards "
                f"(tenant_id, agent_id, version, endpoint, capabilities, "
                f"description, fingerprint, enrolled_at, updated_at) "
                f"VALUES ({p},{p},{p},{p},{p},{p},{p},{p},{p}) "
                f"ON CONFLICT (tenant_id, agent_id) DO UPDATE SET "
                f"version=EXCLUDED.version, endpoint=EXCLUDED.endpoint, "
                f"capabilities=EXCLUDED.capabilities, "
                f"description=EXCLUDED.description, "
                f"fingerprint=EXCLUDED.fingerprint, "
                f"updated_at=EXCLUDED.updated_at",
                (
                    tenant_id,
                    card.agent_id,
                    card.version,
                    card.endpoint,
                    _SEP.join(sorted(card.capabilities)),
                    card.description,
                    card.fingerprint,
                    now,
                    now,
                ),
            )
            conn.commit()


class SqlTaskLedger:
    """Durable replay detection for delegation task ids.

    Reuses `replay_nonces`, which already exists for signed-event replay and
    already has the shape this needs: a tenant, an actor, a digest and an
    expiry. A second table holding the same concept would be a second thing to
    retain, sweep and get wrong -- and the retention sweep for this one is
    already written.

    The `agent` column is the NAMESPACE, fixed to `a2a`, and the task id goes in
    `event_digest`. Sharing the table without a namespace would let an A2A task
    id collide with a signed event's digest, which would make a legitimate event
    look like a replayed delegation or the reverse.

    HONEST LIMIT: task ids expire with the retention window. A delegation
    replayed after that window is not detected here -- the same bound
    signed-event replay protection operates under.
    """

    __slots__ = ("_pool", "_window")

    #: The namespace value in the shared table. Not a task id, not an agent.
    NAMESPACE: str = "a2a"

    def __init__(self, *, pool: Any, window_seconds: int = 86_400) -> None:
        self._pool = pool
        self._window = int(window_seconds)

    def seen(self, tenant_id: str) -> Iterable[str]:
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            p = conn.p
            rows = conn.execute(
                f"SELECT event_digest FROM replay_nonces "
                f"WHERE tenant_id={p} AND agent={p}",
                (tenant_id, self.NAMESPACE),
            )
            conn.commit()
        return tuple(str(r["event_digest"]) for r in rows)

    def record(self, tenant_id: str, task_ids: Iterable[str]) -> None:
        # NOT `t`. `test_sql_is_never_built_from_data.py` reserves `t` and
        # `table` as SQL-identifier names and walks every binding of them,
        # requiring the source to be a fixed set of strings. `task_ids` is
        # caller data, so shadowing `t` here made a comprehension that never
        # touches SQL look exactly like one that builds a table name from
        # user input. Renaming is the fix; suppressing the guard is not.
        wanted = [task_id for task_id in task_ids if task_id]
        if not wanted:
            return
        now = _dt.datetime.now(_dt.timezone.utc)
        expires = (now + _dt.timedelta(seconds=self._window)).isoformat()
        stamp = now.isoformat()
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            p = conn.p
            for task_id in wanted:
                conn.execute_rowcount(
                    f"INSERT INTO replay_nonces "
                    f"(tenant_id, agent, event_digest, seen_at, expires_at) "
                    f"VALUES ({p},{p},{p},{p},{p}) "
                    f"ON CONFLICT (tenant_id, agent, event_digest) DO NOTHING",
                    (tenant_id, self.NAMESPACE, task_id, stamp, expires),
                )
            conn.commit()
