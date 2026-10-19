"""Sharded, fenced work distribution.

THE TWO DEFECTS THIS IS SHAPED AGAINST
--------------------------------------

**1. Dispatch was O(tenants) connections per dequeue.**

The predecessor's `claim()` iterated `db._tenant_ids()`, opening a connection and
running a query per tenant, then picked a global winner and claimed it with one
more connection. At 1,000 tenants a single dequeue cost 1,002 connect/query/close
cycles; at the 50 ms idle poll floor an idle three-replica deployment generated
tens of thousands of connections per second while doing no work at all. Tenant
count, not event volume, was the first thing that broke.

Work is sharded on insert by a stable hash of the tenant. A worker owns a shard
range and claims with ONE indexed query. Adding tenants does not add queries.

**2. Reclamation charged the retry budget of healthy work.**

`reclaim_abandoned()` reset `state='pending'` for claims older than the timeout
but did not reset `attempts`, while every claim incremented it. The pipeline
makes a synchronous model call, provider lookups and an anchoring write, so a
slow-but-alive worker exceeding the 300-second timeout had its item reclaimed and
its budget charged. Three of those and work that was succeeding was dead-lettered.

Here reclamation and failure are different operations. `reap_expired_leases`
returns the item to `pending` and leaves `attempts` alone; only `fail()` -- an
actual reported failure -- spends budget.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import uuid
from datetime import timedelta
from types import MappingProxyType
from typing import Any, Mapping

from sentinel.application.records import QueuedWork
from sentinel.domain.errors import ExecutionFenceLost
from sentinel.domain.incident import IncidentState
from sentinel.domain.primitives import IncidentId, MessageId, TenantId, Timestamp
from sentinel.infrastructure.sql.engine import ConnectionPool

__all__ = ["SqlWorkQueue", "shard_for"]

_PRIORITY_RANK: Mapping[str, int] = MappingProxyType(
    {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
)


def shard_for(tenant: TenantId, shard_count: int) -> int:
    """Stable shard assignment.

    `hashlib`, not the builtin `hash()`: Python's string hash is randomised per
    process by PYTHONHASHSEED, so a builtin-hash shard would place the same
    tenant in different shards on different replicas and after every restart --
    which means some rows would never be claimed by anyone.
    """
    digest = hashlib.blake2b(tenant.value.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "big") % max(1, shard_count)


class SqlWorkQueue:
    """Database-backed queue: atomic submission, sharded claim, fenced completion."""

    __slots__ = ("_pool", "_shard_count", "_worker_id", "_max_attempts", "_lease_seconds")

    def __init__(
        self,
        *,
        pool: ConnectionPool,
        shard_count: int,
        max_attempts: int = 5,
        lease_seconds: int = 300,
        worker_id: str | None = None,
    ) -> None:
        self._pool = pool
        self._shard_count = max(1, shard_count)
        self._max_attempts = max_attempts
        self._lease_seconds = lease_seconds
        # Identity includes a per-instance UUID, so two worker threads in one
        # process are distinguishable. The predecessor's WORKER_ID was a module
        # global shared by every thread, which was safe only while worker
        # concurrency happened to be exactly one.
        self._worker_id = worker_id or (
            f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
        )

    @property
    def worker_id(self) -> str:
        return self._worker_id

    def submit(
        self,
        *,
        tenant: TenantId,
        incident_id: IncidentId,
        payload: Mapping[str, Any],
        priority: str,
        uow: Any,
    ) -> None:
        """Enqueue inside the CALLER's transaction.

        The queue row and the incident row commit together, so the API can only
        answer "queued" once a worker can actually see the work. The predecessor
        wrote them in two transactions with the enqueue deferred until after the
        response, so a crash in between acknowledged work that was then lost.
        """
        conn = uow._conn  # noqa: SLF001 - the queue is part of the same transaction
        p = conn.p
        now = _now_iso(uow)
        conn.execute_rowcount(
            f"INSERT INTO work_queue (tenant_id, work_id, incident_id, shard, priority, "
            f"payload_json, state, attempts, lease_epoch, available_at, enqueued_at) "
            f"VALUES ({p},{p},{p},{p},{p},{p},'pending',0,0,{p},{p})",
            (
                tenant.value,
                uuid.uuid4().hex,
                incident_id.value,
                shard_for(tenant, self._shard_count),
                _PRIORITY_RANK.get(str(priority).upper(), 2),
                json.dumps(dict(payload), sort_keys=True, default=str),
                now,
                now,
            ),
        )

    def claim(self, *, shard: int, shard_count: int, now: Timestamp) -> QueuedWork | None:
        """Take the highest-priority due item in this shard. ONE query.

        The claim allocates a strictly increasing `lease_epoch` -- a fencing
        token. A holder of an older epoch is provably stale, so a paused worker
        that wakes up cannot overwrite the state of whoever legitimately
        reclaimed the item.
        """
        deadline = Timestamp(now.value + timedelta(seconds=self._lease_seconds))
        with self._pool.acquire() as conn:
            conn.begin()
            # The claim is the ONE deliberately cross-tenant read in the
            # system: a shard holds every tenant that hashes into it, and there
            # is no tenant to bind before the row is chosen. Under the tenant
            # policy alone this SELECT matched nothing on PostgreSQL -- the
            # queue was protected, the scan was unscoped, and no work was ever
            # claimed while every SQLite test passed. The scope is declared
            # explicitly here rather than granted to the connection.
            conn.set_worker_scope()
            p = conn.p
            row = conn.one(
                f"SELECT tenant_id, work_id, incident_id, payload_json, attempts, lease_epoch "
                f"FROM work_queue WHERE shard={p} AND state='pending' AND available_at<={p} "
                f"ORDER BY priority ASC, enqueued_at ASC LIMIT 1"
                + conn.lock_clause(skip_locked=True),
                (shard, now.isoformat()),
            )
            if row is None:
                conn.commit()
                return None
            epoch = int(row["lease_epoch"]) + 1
            claimed = conn.execute_rowcount(
                f"UPDATE work_queue SET state='claimed', claimed_by={p}, lease_epoch={p}, "
                f"attempts=attempts+1, lease_until={p} "
                f"WHERE tenant_id={p} AND work_id={p} AND state='pending'",
                (
                    self._worker_id,
                    epoch,
                    deadline.isoformat(),
                    row["tenant_id"],
                    row["work_id"],
                ),
            )
            conn.commit()
            if claimed != 1:
                return None
        return QueuedWork(
            work_id=MessageId(row["work_id"]),
            tenant_id=TenantId(row["tenant_id"]),
            incident_id=IncidentId(row["incident_id"]),
            payload=json.loads(row["payload_json"]),
            attempts=int(row["attempts"]) + 1,
            lease_epoch=epoch,
            claimed_by=self._worker_id,
        )

    def complete(self, work: QueuedWork) -> None:
        """Mark done, ONLY if this worker still owns the lease."""
        self._finish(work, state="done", error=None, available_at=None)

    def fail(
        self, work: QueuedWork, *, error: str, now: Timestamp, retry_in_seconds: int
    ) -> bool:
        """Record a real failure and schedule a retry with a real delay.

        The predecessor's `fail()` returned the item straight to `pending` with
        no backoff, so with the queue otherwise empty it was re-claimed on the
        next 50 ms poll: three attempts burned in about 150 milliseconds, before
        any transient dependency could plausibly have recovered. The retry budget
        existed; the retry *window* did not.
        """
        retry = work.attempts < self._max_attempts
        available = Timestamp(now.value + timedelta(seconds=max(1, retry_in_seconds)))
        self._finish(
            work,
            state="pending" if retry else "dead",
            error=error,
            available_at=available.isoformat(),
        )
        return retry

    def _finish(
        self, work: QueuedWork, *, state: str, error: str | None, available_at: str | None
    ) -> None:
        with self._pool.acquire() as conn:
            conn.begin()
            # Tenant-scoped, not worker-scoped: the item names its tenant, so
            # the narrower context is available and is the one used. A finish
            # that could reach another tenant's row would be a way to complete
            # somebody else's work.
            conn.set_tenant(work.tenant_id.value)
            p = conn.p
            affected = conn.execute_rowcount(
                f"UPDATE work_queue SET state={p}, last_error={p}, claimed_by=NULL, "
                f"lease_until=NULL, available_at=COALESCE({p}, available_at) "
                f"WHERE tenant_id={p} AND work_id={p} AND claimed_by={p} AND lease_epoch={p}",
                (
                    state,
                    (error or "")[:1000],
                    available_at,
                    work.tenant_id.value,
                    work.work_id.value,
                    work.claimed_by,
                    work.lease_epoch,
                ),
            )
            conn.commit()
        if affected == 0:
            raise ExecutionFenceLost(
                f"worker {work.claimed_by} holds lease epoch {work.lease_epoch} for "
                f"item {work.work_id}, but the row no longer matches. Another worker "
                "reclaimed this incident; abandoning rather than overwriting its work."
            )

    def reap_expired_leases(self, *, now: Timestamp, shard: int, shard_count: int) -> int:
        """Return work whose owner died. Does NOT touch `attempts`.

        Reclaiming a merely-slow worker's item is safe because completion is
        fenced -- that worker's `complete()` will simply be refused. What is not
        safe is charging it as a failure, which is what the predecessor did.
        """
        with self._pool.acquire() as conn:
            conn.begin()
            # Cross-tenant by design: a dead worker's shard holds every tenant.
            conn.set_worker_scope()
            p = conn.p
            affected = conn.execute_rowcount(
                f"UPDATE work_queue SET state='pending', claimed_by=NULL, lease_until=NULL "
                f"WHERE shard={p} AND state='claimed' AND lease_until IS NOT NULL "
                f"AND lease_until<{p}",
                (shard, now.isoformat()),
            )
            conn.commit()
        return affected

    def depth(self, *, state: str) -> int:
        with self._pool.acquire() as conn:
            conn.begin()
            # An operational gauge over the whole queue, so cross-tenant.
            conn.set_worker_scope()
            row = conn.one(
                f"SELECT COUNT(*) AS n FROM work_queue WHERE state={conn.p}", (state,)
            )
            conn.commit()
        return int(row["n"]) if row else 0

    def reenqueue_parked_attestations(
        self,
        *,
        tenants: tuple[TenantId, ...],
        now: Timestamp,
        older_than_seconds: int,
    ) -> int:
        """Re-enqueue incidents parked in ATTESTATION_UNAVAILABLE after backoff."""
        cutoff = Timestamp(now.value - timedelta(seconds=max(1, older_than_seconds)))
        total = 0
        for tenant in tenants:
            with self._pool.acquire() as conn:
                conn.begin()
                conn.set_tenant(tenant.value)
                p = conn.p
                rows = conn.execute(
                    f"SELECT incident_id, facts_json FROM incidents "
                    f"WHERE tenant_id={p} AND state={p} AND updated_at<={p} "
                    f"ORDER BY updated_at ASC",
                    (
                        tenant.value,
                        IncidentState.ATTESTATION_UNAVAILABLE.value,
                        cutoff.isoformat(),
                    ),
                )
                for row in rows:
                    incident_id = str(row["incident_id"])
                    existing = conn.one(
                        f"SELECT 1 FROM work_queue WHERE tenant_id={p} AND incident_id={p} "
                        f"AND state IN ('pending','claimed')",
                        (tenant.value, incident_id),
                    )
                    if existing is not None:
                        continue
                    total += conn.execute_rowcount(
                        f"INSERT INTO work_queue (tenant_id, work_id, incident_id, shard, "
                        f"priority, payload_json, state, attempts, lease_epoch, "
                        f"available_at, enqueued_at) "
                        f"VALUES ({p},{p},{p},{p},1,{p},'pending',0,0,{p},{p})",
                        (
                            tenant.value,
                            uuid.uuid4().hex,
                            incident_id,
                            shard_for(tenant, self._shard_count),
                            json.dumps(
                                {
                                    "requeued_from": IncidentState.ATTESTATION_UNAVAILABLE.value
                                },
                                sort_keys=True,
                            ),
                            now.isoformat(),
                            now.isoformat(),
                        ),
                    )
                conn.commit()
        return total


def _now_iso(uow: Any) -> str:
    return uow._clock.now().isoformat()  # noqa: SLF001 - same transaction, same clock
