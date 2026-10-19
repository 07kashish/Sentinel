"""The query side of CQRS. Projections only; never loads an aggregate.

WHY THIS IS A SEPARATE CLASS AND NOT A REPOSITORY METHOD
---------------------------------------------------------
In the predecessor every read went through the same code as every write.
`GET /incidents` loaded aggregates through `repository.list_incidents`, paying
for JSON parsing, enum construction and invariant machinery it had no use for,
and carrying a hard-coded `LIMIT 200` with no cursor because there was nowhere
else to put paging.

Reads here take no row locks, construct no aggregates, and page with a keyset
cursor rather than an offset -- `OFFSET n` re-scans and discards n rows, so the
last page of a large tenant is the most expensive query in the system.

Every method takes an explicit tenant and opens its own short transaction, so a
slow dashboard query cannot hold a connection that a write path needs.
"""

from __future__ import annotations

import json
from typing import Any, Literal, Mapping, Sequence

from sentinel.domain.primitives import IncidentId, TenantId
from sentinel.infrastructure.sql.engine import ConnectionPool

__all__ = ["SqlReadModel"]

MAX_PAGE = 500


class SqlReadModel:
    __slots__ = ("_pool",)

    def __init__(self, *, pool: ConnectionPool) -> None:
        self._pool = pool

    def _scoped(self, tenant: TenantId):
        """Every read establishes tenant context, exactly like a write does."""
        return _ScopedRead(self._pool, tenant)

    def incident_summary(
        self, tenant: TenantId, incident_id: IncidentId
    ) -> Mapping[str, Any] | None:
        with self._scoped(tenant) as conn:
            row = conn.one(
                f"SELECT incident_id, state, facts_json, version, updated_at "
                f"FROM incidents WHERE tenant_id={conn.p} AND incident_id={conn.p}",
                (tenant.value, incident_id.value),
            )
        if row is None:
            return None
        return _project(row)

    def list_incidents(
        self, tenant: TenantId, *, limit: int, after: str | None
    ) -> Sequence[Mapping[str, Any]]:
        """Keyset pagination. `after` is the last `updated_at` seen.

        A cursor rather than an offset: with `OFFSET n` the database still reads
        and discards n rows, so paging through a large tenant gets slower with
        every page and the final page is the most expensive query in the system.
        """
        bounded = max(1, min(int(limit), MAX_PAGE))
        with self._scoped(tenant) as conn:
            if after:
                rows = conn.execute(
                    f"SELECT incident_id, state, facts_json, version, updated_at "
                    f"FROM incidents WHERE tenant_id={conn.p} AND updated_at<{conn.p} "
                    f"ORDER BY updated_at DESC LIMIT {conn.p}",
                    (tenant.value, after, bounded),
                )
            else:
                rows = conn.execute(
                    f"SELECT incident_id, state, facts_json, version, updated_at "
                    f"FROM incidents WHERE tenant_id={conn.p} "
                    f"ORDER BY updated_at DESC LIMIT {conn.p}",
                    (tenant.value, bounded),
                )
        return [_project(r) for r in rows]

    def incident_history(
        self, tenant: TenantId, incident_id: IncidentId
    ) -> Sequence[Mapping[str, Any]]:
        with self._scoped(tenant) as conn:
            rows = conn.execute(
                f"SELECT seq, from_state, to_state, actor, occurred_at "
                f"FROM incident_transitions WHERE tenant_id={conn.p} AND incident_id={conn.p} "
                f"ORDER BY seq ASC",
                (tenant.value, incident_id.value),
            )
        return [
            {
                "seq": int(r["seq"]),
                "from": r["from_state"],
                "to": r["to_state"],
                "actor": r["actor"],
                "at": r["occurred_at"],
            }
            for r in rows
        ]

    def counts_by_state(self, tenant: TenantId) -> Mapping[str, int]:
        with self._scoped(tenant) as conn:
            rows = conn.execute(
                f"SELECT state, COUNT(*) AS n FROM incidents WHERE tenant_id={conn.p} "
                f"GROUP BY state",
                (tenant.value,),
            )
        return {r["state"]: int(r["n"]) for r in rows}

    def report(self, tenant: TenantId, incident_id: IncidentId) -> str | None:
        with self._scoped(tenant) as conn:
            row = conn.one(
                f"SELECT content FROM reports WHERE tenant_id={conn.p} AND incident_id={conn.p}",
                (tenant.value, incident_id.value),
            )
        return row["content"] if row else None

    def dead_letter_count(self, tenant: TenantId) -> int:
        with self._scoped(tenant) as conn:
            row = conn.one(
                f"SELECT COUNT(*) AS n FROM outbox WHERE tenant_id={conn.p} AND state='dead'",
                (tenant.value,),
            )
        return int(row["n"]) if row else 0

    def attestation_summary(self, tenant: TenantId) -> Mapping[str, int]:
        """Anchored versus unattested, counted separately and never summed.

        The predecessor reported an `attestations_success` counter that was
        pinned to zero and an `attestation_capability` string that a dashboard
        could read as a success. These are two different facts about the world
        and the API says which is which.
        """
        with self._scoped(tenant) as conn:
            rows = conn.execute(
                f"SELECT state, COUNT(*) AS n FROM incidents WHERE tenant_id={conn.p} "
                f"AND state IN ('attested','completed_attested','completed_unattested',"
                f"'attestation_unavailable') GROUP BY state",
                (tenant.value,),
            )
        counts = {r["state"]: int(r["n"]) for r in rows}
        return {
            "anchored": counts.get("attested", 0) + counts.get("completed_attested", 0),
            "completed_unattested": counts.get("completed_unattested", 0),
            "awaiting_attestation_retry": counts.get("attestation_unavailable", 0),
        }


class _ScopedRead:
    """A short, tenant-scoped, read-only transaction."""

    __slots__ = ("_pool_ctx", "_conn", "_tenant")

    def __init__(self, pool: ConnectionPool, tenant: TenantId) -> None:
        self._pool_ctx = pool.acquire()
        self._tenant = tenant
        self._conn = None

    def __enter__(self):
        self._conn = self._pool_ctx.__enter__()
        self._conn.begin()
        self._conn.set_tenant(self._tenant.value)
        return self._conn

    def __exit__(self, exc_type, exc, tb) -> Literal[False]:
        try:
            # A read commits rather than rolls back so PostgreSQL releases its
            # snapshot promptly; an idle-in-transaction reader holds back vacuum.
            #
            # Guarded because `_conn` is None until `__enter__` runs, and
            # `__exit__` can be reached without it if acquiring the connection
            # raised. Committing nothing is right there; an AttributeError
            # would replace the real failure with a confusing one.
            if self._conn is not None:
                self._conn.commit()
        finally:
            self._pool_ctx.__exit__(exc_type, exc, tb)
        return False


def _project(row: Any) -> Mapping[str, Any]:
    facts = json.loads(row["facts_json"])
    state = row["state"]
    return {
        "incident_id": row["incident_id"],
        "state": state,
        # Explicit, separate booleans. The predecessor exposed a single
        # `is_complete` that was true for an incident whose attestation had been
        # skipped, which is what let a dashboard present an unattested incident
        # as an attested one.
        "is_terminal": state
        in {"completed_attested", "completed_unattested", "failed", "closed_no_action"},
        "is_attested": state in {"attested", "completed_attested"},
        "version": int(row["version"]),
        "updated_at": row["updated_at"],
        "severity": facts.get("severity"),
        "priority": facts.get("priority"),
        "trust_level": facts.get("trust_level"),
        "attestation_outcome": facts.get("attestation_outcome"),
        "attestation_detail": facts.get("attestation_detail"),
        "detector_version": facts.get("detector_version"),
    }
