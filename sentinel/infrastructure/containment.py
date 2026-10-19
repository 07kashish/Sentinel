"""Persisting and reading the granular kill switch.

READ PATH IS ON EVERY ENFORCEMENT DECISION, SO IT IS CACHED
-------------------------------------------------------------
`active()` is consulted before tool side effects. A database round trip per
decision would put the kill switch's latency into the critical path of every
agent action, which is the fastest way to have it removed from that path by
whoever owns the p95.

The cache is time-bounded and short. `CACHE_TTL_SECONDS` is the worst-case delay
between an operator hitting the switch and it taking effect, so it is chosen as
a security property rather than a performance one: long enough that the store is
not read thousands of times a second, short enough that "I stopped that agent"
is true within a few seconds rather than a few minutes.

Revocation is subject to the same delay in the other direction, which is the
safer direction -- an agent stays contained slightly longer than necessary.

STALE-ON-ERROR, NOT FAIL-OPEN-ON-ERROR
----------------------------------------
`containment.py` explains why an unreadable deny list must not halt the estate.
This module goes one step further: when the store cannot be read and a cached
set is still held, the cached set is used rather than an empty one. A database
blip then leaves existing containments in force instead of briefly lifting every
one of them, which is the failure that would matter -- a transient fault must not
become a window in which a contained agent runs.

The stale read is logged every time, at warning. A kill switch that is quietly
serving old data is a kill switch nobody knows to distrust.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from sentinel.domain.errors import TransientFailure
from sentinel.domain.containment import (
    Containment,
    ContainmentDecision,
    ContainmentScope,
    evaluate_containment,
)

__all__ = [
    "AgentFacts",
    "CACHE_TTL_SECONDS",
    "ContainmentGuard",
    "ContainmentReadUnavailable",
    "SqlContainmentRepository",
]

#: Worst-case seconds between an operator activating a containment and it taking
#: effect. A security parameter, not a tuning knob -- see the module docstring.
CACHE_TTL_SECONDS: float = 5.0


class ContainmentReadUnavailable(TransientFailure):
    """Containment state could not be read and no cached decision set exists."""


@dataclass(frozen=True, slots=True)
class AgentFacts:
    """Operator-owned agent attributes the wider containment scopes read.

    Kept together because they are loaded together and cached together: two
    separate reads on the enforcement path would double its cost for no gain,
    and two separate caches could disagree about the same agent.
    """

    #: agent address -> the operator-assigned label that groups it.
    labels: Mapping[str, str] = field(default_factory=dict)
    #: Agents Sentinel has observed violating policy.
    high_risk: frozenset[str] = frozenset()

    def groups_of(self, agent_id: str) -> tuple[str, ...]:
        label = self.labels.get(agent_id, "")
        return (label,) if label else ()

    def is_high_risk(self, agent_id: str) -> bool:
        return agent_id in self.high_risk


class SqlContainmentRepository:
    """Reads and writes containments for one tenant, inside one transaction."""

    __slots__ = ("_conn", "_tenant")

    def __init__(self, conn: Any, tenant: Any) -> None:
        self._conn = conn
        self._tenant = tenant

    def _hydrate(self, row: Mapping[str, Any]) -> Containment:
        return Containment(
            containment_id=str(row["containment_id"]),
            tenant_id=str(row["tenant_id"]),
            scope=ContainmentScope(str(row["scope"])),
            selector=str(row["selector"] or ""),
            created_by=str(row["created_by"]),
            created_at=str(row["created_at"]),
            reason=str(row["reason"] or ""),
            expires_at=str(row["expires_at"] or ""),
            revoked_at=str(row["revoked_at"] or ""),
            revoked_by=str(row["revoked_by"] or ""),
        )

    def create(self, containment: Containment) -> None:
        """Insert one containment, idempotent on its id.

        `DO NOTHING` rather than an upsert. A containment is an audit record of a
        decision somebody made at a moment; overwriting one would let a second
        call silently rewrite who authorized it and why.
        """
        p = self._conn.p
        self._conn.execute_rowcount(
            f"INSERT INTO containments (tenant_id, containment_id, scope, selector, "
            f"created_by, created_at, reason, expires_at, revoked_at, revoked_by) "
            f"VALUES ({p},{p},{p},{p},{p},{p},{p},{p},{p},{p}) "
            f"ON CONFLICT (tenant_id, containment_id) DO NOTHING",
            (
                self._tenant.value,
                containment.containment_id,
                containment.scope.value,
                containment.selector,
                containment.created_by,
                containment.created_at,
                containment.reason,
                containment.expires_at,
                containment.revoked_at,
                containment.revoked_by,
            ),
        )

    def revoke(self, containment_id: str, *, revoked_by: str, at: str) -> bool:
        """Lift a containment. Returns whether one was actually lifted.

        Conditional on it not already being revoked, so a double-click does not
        rewrite who lifted it and when -- the same reasoning as the approval
        claim, applied to the inverse operation.
        """
        p = self._conn.p
        affected = self._conn.execute_rowcount(
            f"UPDATE containments SET revoked_at={p}, revoked_by={p} "
            f"WHERE tenant_id={p} AND containment_id={p} AND revoked_at=''",
            (at, revoked_by, self._tenant.value, containment_id),
        )
        return affected > 0

    def active(self, *, now: str) -> tuple[Containment, ...]:
        """Every containment still in force.

        Expiry is filtered in Python rather than in SQL. The comparison is
        lexicographic on ISO-8601 strings, which is only sound because every
        timestamp here is UTC with a `Z` suffix -- and keeping that reasoning in
        one place, next to the docstring that states the assumption, beats
        duplicating it into a WHERE clause where it is invisible.
        """
        p = self._conn.p
        rows = self._conn.execute(
            f"SELECT * FROM containments WHERE tenant_id={p} AND revoked_at=''",
            (self._tenant.value,),
        )
        return tuple(
            c for c in (self._hydrate(r) for r in rows) if c.is_active(now)
        )

    def agent_facts(self, *, high_risk_violations: int = 1) -> "AgentFacts":
        """The agent attributes two containment scopes are evaluated against.

        WHY THIS IS READ AND NOT TAKEN FROM THE REQUEST
        -------------------------------------------------
        `AGENT_GROUP` and `HIGH_RISK_AGENTS` need to know which group an agent
        belongs to and whether it is high-risk. The tempting shortcut is to let
        the caller pass them in the event metadata -- and it is a hole, because
        the caller is the agent being contained. An agent that supplies its own
        group membership evades a group containment by omitting it, and one that
        reports its own risk evades the high-risk pause by claiming to be fine.

        So both come from Sentinel's own records:

          * the group is `agents.label`, which an operator sets at enrolment
          * high-risk is `agent_observations.violation_count`, which Sentinel
            increments when IT detects a violation

        Neither is writable by the agent, which is the property that makes the
        two scopes worth having.
        """
        p = self._conn.p
        labels = {
            str(r["address"]): str(r["label"] or "")
            for r in self._conn.execute(
                f"SELECT address, label FROM agents "
                f"WHERE tenant_id={p} AND label<>'' AND revoked_at IS NULL",
                (self._tenant.value,),
            )
        }
        high_risk = frozenset(
            str(r["agent_id"])
            for r in self._conn.execute(
                f"SELECT agent_id FROM agent_observations "
                f"WHERE tenant_id={p} AND violation_count>={p}",
                (self._tenant.value, high_risk_violations),
            )
        )
        return AgentFacts(labels=labels, high_risk=high_risk)

    def all(self) -> tuple[Containment, ...]:
        """Everything, including revoked and expired. The audit view."""
        p = self._conn.p
        rows = self._conn.execute(
            f"SELECT * FROM containments WHERE tenant_id={p} ORDER BY created_at DESC",
            (self._tenant.value,),
        )
        return tuple(self._hydrate(r) for r in rows)


class ContainmentGuard:
    """The enforcement-path view of the kill switch: cached, per tenant.

    Holds no transaction. It is given a factory so the read happens on its own
    short-lived connection rather than joining whatever transaction the caller
    is in -- a containment check must not be able to extend, or be rolled back
    with, the operation it is guarding.
    """

    __slots__ = ("_uow_factory", "_logger", "_ttl", "_lock", "_cache")

    def __init__(
        self, *, uow_factory: Any, logger: Any, ttl_seconds: float = CACHE_TTL_SECONDS
    ) -> None:
        self._uow_factory = uow_factory
        self._logger = logger
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        #: tenant -> (fetched_at_monotonic, containments, agent facts)
        self._cache: dict[str, tuple[float, tuple[Containment, ...], AgentFacts]] = {}

    def invalidate(self, tenant: str) -> None:
        """Drop a tenant's cache so the next check re-reads.

        Called after a containment is created or revoked, which is what makes
        an operator's action take effect immediately in the process that handled
        it rather than after the TTL. Other replicas still wait out the TTL --
        that is what `CACHE_TTL_SECONDS` bounds.
        """
        with self._lock:
            self._cache.pop(tenant, None)

    def _load(self, tenant: Any, now: str) -> tuple[tuple[Containment, ...], AgentFacts]:
        key = str(tenant.value if hasattr(tenant, "value") else tenant)
        with self._lock:
            entry = self._cache.get(key)
        if entry is not None and (time.monotonic() - entry[0]) < self._ttl:
            return entry[1], entry[2]

        try:
            with self._uow_factory.begin(tenant) as uow:
                containments = uow.containments.active(now=now)
                # Loaded in the SAME transaction and cached together. Two
                # reads could see different moments, and a containment
                # evaluated against stale group membership blocks the wrong
                # agent.
                facts = uow.containments.agent_facts()
                uow.commit()
        except Exception as exc:  # noqa: BLE001 - see the module docstring
            if entry is not None:
                self._logger.warning(
                    "containment_read_failed_serving_stale",
                    tenant=key,
                    age_seconds=round(time.monotonic() - entry[0], 2),
                    error=f"{type(exc).__name__}: {exc}",
                )
                return entry[1], entry[2]
            self._logger.error(
                "containment_read_failed_no_cache",
                tenant=key,
                detail=(
                    "the kill switch cannot be read and nothing is cached; "
                    "refusing rather than evaluating against an empty set"
                ),
                error=f"{type(exc).__name__}: {exc}",
            )
            raise ContainmentReadUnavailable(
                f"containment state for tenant {key!r} is unavailable and no "
                "cached value exists"
            ) from exc

        with self._lock:
            self._cache[key] = (time.monotonic(), containments, facts)
        return containments, facts

    def check(
        self,
        tenant: Any,
        *,
        now: str,
        agent_id: str = "",
        agent_groups: Sequence[str] = (),
        tool: str = "",
        mcp_server: str = "",
        credential: str = "",
    ) -> ContainmentDecision:
        containments, facts = self._load(tenant, now)
        # Group membership and risk come from Sentinel's own records, NEVER from
        # the caller -- the caller is the agent being contained. See
        # `SqlContainmentRepository.agent_facts`.
        #
        # Any groups the caller passed are UNIONED with, not substituted for, the
        # recorded ones: a caller may legitimately know about a grouping Sentinel
        # does not, but it can never remove itself from one Sentinel recorded.
        groups = tuple(facts.groups_of(agent_id)) + tuple(g for g in agent_groups if g)
        return evaluate_containment(
            containments,
            now=now,
            agent_id=agent_id,
            agent_groups=groups,
            tool=tool,
            mcp_server=mcp_server,
            credential=credential,
            agent_is_high_risk=facts.is_high_risk(agent_id),
        )
