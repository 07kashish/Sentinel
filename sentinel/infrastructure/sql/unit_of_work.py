"""The SQL unit of work and the repositories that share its transaction.

WHY REPOSITORIES ARE CONSTRUCTED BY THE UNIT OF WORK
----------------------------------------------------
They must share one connection and one transaction. Injecting them
independently is how two writes that a docstring calls "atomic" end up in two
transactions -- which is precisely the class the predecessor spent four
remediation passes closing (`create` + enqueue, evidence + ledger + transition,
seal + claim). Here there is no way to obtain a repository except from a unit of
work, so there is no way to use two of them outside one transaction.

WHY `begin()` REQUIRES A TENANT
-------------------------------
`UnitOfWorkFactory.begin(tenant)` is the only entry point to the database, and
its tenant argument is mandatory. Row-level-security context is established
immediately, before any statement the caller can issue.

This is the structural fix for the most subtle defect in the predecessor: with
`delivery_queue` under FORCE RLS and `dlq.succeed()`/`dlq.fail()` calling
`db._connect()` with no tenant, `current_setting('sentinel.tenant_id', true)`
returned NULL, the policy matched no rows, `fail()` raised KeyError on every call
and `succeed()` silently updated nothing. It was invisible on SQLite, which has
no RLS, and broke every terminal delivery operation on the production engine.

DOMAIN EVENTS COMMIT WITH THE STATE THEY DESCRIBE
--------------------------------------------------
`collect()` stages events; `commit()` writes them to `domain_events` inside the
same transaction and only then publishes. An event describing a change that
rolled back cannot exist, and a change that committed cannot fail to produce its
event.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Iterable, Literal

from sentinel.application.ports import Clock, EventPublisher
from sentinel.domain.errors import ArtifactMissing, ConcurrencyConflict, ExecutionFenceLost
from sentinel.domain.events import DomainEvent
from sentinel.domain.incident import Incident, IncidentState
from sentinel.domain.primitives import (
    IncidentId,
    TenantId,
)
from sentinel.infrastructure.containment import SqlContainmentRepository
from sentinel.infrastructure.enterprise import (
    SqlPolicyStore,
    SqlTenantKeys,
    SqlTenantSettings,
)
from sentinel.infrastructure.sql.engine import Connection, ConnectionPool
from sentinel.infrastructure.sql.journal import SqlExecutionJournal, SqlInbox
from sentinel.infrastructure.sql.repositories import (
    ApprovalRepository,
    LedgerRepository,
    OutboxRepository,
)

__all__ = ["SqlUnitOfWork", "SqlUnitOfWorkFactory"]


def _dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


class _IncidentRepository:
    __slots__ = ("_conn", "_tenant", "_clock")

    def __init__(self, conn: Connection, tenant: TenantId, clock: Clock) -> None:
        self._conn = conn
        self._tenant = tenant
        self._clock = clock

    def _hydrate(self, row: Any) -> Incident:
        return Incident.rehydrate(
            tenant_id=self._tenant,
            incident_id=IncidentId(row["incident_id"]),
            state=IncidentState(row["state"]),
            facts=json.loads(row["facts_json"]),
            version=int(row["version"]),
            execution_epoch=int(row["execution_epoch"]),
        )

    def get(self, incident_id: IncidentId) -> Incident | None:
        p = self._conn.p
        row = self._conn.one(
            f"SELECT * FROM incidents WHERE tenant_id={p} AND incident_id={p}",
            (self._tenant.value, incident_id.value),
        )
        return self._hydrate(row) if row else None

    def get_for_update(self, incident_id: IncidentId) -> Incident | None:
        p = self._conn.p
        row = self._conn.one(
            f"SELECT * FROM incidents WHERE tenant_id={p} AND incident_id={p}"
            + self._conn.lock_clause(),
            (self._tenant.value, incident_id.value),
        )
        return self._hydrate(row) if row else None

    def exists(self, incident_id: IncidentId) -> bool:
        p = self._conn.p
        return (
            self._conn.one(
                f"SELECT 1 FROM incidents WHERE tenant_id={p} AND incident_id={p}",
                (self._tenant.value, incident_id.value),
            )
            is not None
        )

    def add(self, incident: Incident) -> None:
        """Insert a new aggregate. Idempotent on (tenant, incident).

        `DO NOTHING` rather than an error: admission is at-least-once by nature
        (a client retry, a redelivered message), and the caller has already been
        told the work is accepted. Re-admitting the same identifier must be a
        no-op, not a 500.
        """
        p = self._conn.p
        now = self._clock.now().isoformat()
        self._conn.execute_rowcount(
            f"INSERT INTO incidents (tenant_id, incident_id, state, facts_json, version, "
            f"execution_epoch, created_at, updated_at) VALUES ({p},{p},{p},{p},{p},{p},{p},{p}) "
            f"ON CONFLICT (tenant_id, incident_id) DO NOTHING",
            (
                self._tenant.value,
                incident.incident_id.value,
                incident.state.value,
                _dumps(incident.facts),
                incident.version,
                incident.execution_epoch,
                now,
                now,
            ),
        )
        # No transition row is written here. The `IncidentAdmitted` event the
        # aggregate raised produces it at commit, so there is exactly one writer
        # of the audit trail.

    def save(self, incident: Incident) -> None:
        """Persist with an optimistic version check.

        The predicate is `version = loaded_version`: the stored row must still be
        at the version this aggregate was READ at. That is the textbook form and
        it is correct for a save that applied zero transitions -- claiming the
        execution fence changes `execution_epoch` and nothing else, and a
        predicate of `version < new_version` refused it as a phantom conflict.

        A mismatch means another writer moved the aggregate between the read and
        the write: `ConcurrencyConflict`, which is retryable, and distinct from
        `ExecutionFenceLost`, which is not.
        """
        p = self._conn.p
        now = self._clock.now().isoformat()
        affected = self._conn.execute_rowcount(
            f"UPDATE incidents SET state={p}, facts_json={p}, version={p}, "
            f"execution_epoch={p}, updated_at={p} "
            f"WHERE tenant_id={p} AND incident_id={p} AND version={p}",
            (
                incident.state.value,
                _dumps(incident.facts),
                incident.version,
                incident.execution_epoch,
                now,
                self._tenant.value,
                incident.incident_id.value,
                incident.loaded_version,
            ),
        )
        if affected == 0:
            current = self._conn.one(
                f"SELECT version FROM incidents WHERE tenant_id={p} AND incident_id={p}",
                (self._tenant.value, incident.incident_id.value),
            )
            if current is None:
                raise ArtifactMissing(
                    f"incident {incident.incident_id} does not exist for this tenant"
                )
            raise ConcurrencyConflict(
                f"incident {incident.incident_id} was read at version "
                f"{incident.loaded_version} and is now at {current['version']}; "
                "another writer moved it. Re-read and retry."
            )

    def claim_execution(self, incident_id: IncidentId, *, epoch: int) -> None:
        p = self._conn.p
        row = self._conn.one(
            f"SELECT execution_epoch FROM incidents WHERE tenant_id={p} AND incident_id={p}"
            + self._conn.lock_clause(),
            (self._tenant.value, incident_id.value),
        )
        if row is None:
            raise ArtifactMissing(f"incident {incident_id} does not exist")
        if int(row["execution_epoch"]) >= epoch:
            raise ExecutionFenceLost(
                f"incident {incident_id} is owned at epoch {row['execution_epoch']}; "
                f"refusing to hand it to epoch {epoch}"
            )
        self._conn.execute_rowcount(
            f"UPDATE incidents SET execution_epoch={p} WHERE tenant_id={p} AND incident_id={p}",
            (epoch, self._tenant.value, incident_id.value),
        )


class SqlUnitOfWork:
    """One transaction on one pooled connection, scoped to one tenant."""

    __slots__ = (
        "_pool_ctx",
        "_conn",
        "_tenant",
        "_publisher",
        "_clock",
        "_pending",
        "incidents",
        "ledger",
        "approvals",
        "containments",
        "policies",
        "tenant_settings",
        "tenant_keys",
        "outbox",
        "journal",
        "inbox",
        "_committed",
    )

    def __init__(
        self,
        pool: ConnectionPool,
        tenant: TenantId,
        publisher: EventPublisher,
        clock: Clock,
        evidence_cipher: Any = None,
    ) -> None:
        self._clock = clock
        self._pool_ctx = pool.acquire()
        self._conn = self._pool_ctx.__enter__()
        self._tenant = tenant
        self._publisher = publisher
        self._pending: list[DomainEvent] = []
        self._committed = False
        # The connection is already checked out. If opening the transaction or
        # binding the tenant fails, `__exit__` will never run -- the caller never
        # received the object -- so the release has to happen HERE. Without it
        # every failed `begin()` (a PostgreSQL restart, a `SET` refused mid
        # failover) permanently removed one connection from a bounded pool, and
        # the symptom was pool exhaustion some minutes later in an unrelated
        # request.
        try:
            self._conn.begin()
            # RLS context first. Nothing the caller can issue runs before it.
            self._conn.set_tenant(tenant.value)
        except BaseException:
            self._pool_ctx.__exit__(None, None, None)
            raise
        self.incidents = _IncidentRepository(self._conn, tenant, clock)
        self.ledger = LedgerRepository(self._conn, tenant, clock, cipher=evidence_cipher)
        self.approvals = ApprovalRepository(self._conn, tenant)
        self.containments = SqlContainmentRepository(self._conn, tenant)
        # Enterprise controls share this transaction so a policy activation and
        # the mode change that makes it enforce commit together. Two
        # transactions would allow a window in which a BLOCK policy is active
        # under a mode that does not enforce, or the reverse.
        self.policies = SqlPolicyStore(self._conn, tenant)
        self.tenant_settings = SqlTenantSettings(self._conn, tenant)
        self.tenant_keys = SqlTenantKeys(self._conn, tenant)
        self.outbox = OutboxRepository(self._conn, tenant)
        # The journal and the inbox share this transaction, so a step's outcome
        # and the lifecycle transition it produced cannot commit separately.
        self.journal = SqlExecutionJournal(self._conn, tenant)
        self.inbox = SqlInbox(self._conn, tenant)

    def __enter__(self) -> "SqlUnitOfWork":
        return self

    def __exit__(
        self, exc_type: Any, exc: Any, tb: Any
    ) -> Literal[False]:
        try:
            if exc_type is not None or not self._committed:
                self.rollback()
        finally:
            self._pool_ctx.__exit__(None, None, None)
        return False

    def collect(self, events: Iterable[DomainEvent]) -> None:
        self._pending.extend(events)

    def commit(self) -> None:
        """Write the audit trail and the event log, commit, THEN publish.

        Ordering matters. Both logs are written inside the transaction so they
        share the fate of the change they describe; publication happens only
        after the commit succeeds, so a subscriber can never observe an event for
        a transaction that was rolled back.

        The audit trail is DERIVED from the same events rather than written
        separately by each mutator. A second, hand-maintained source for "how did
        this incident get here" is how an audit trail drifts from the thing it
        audits.
        """
        p = self._conn.p
        self._append_audit_trail()
        for event in self._pending:
            self._conn.execute_rowcount(
                f"INSERT INTO domain_events (tenant_id, event_id, incident_id, event_type, "
                f"event_version, payload_json, occurred_at, recorded_at) "
                f"VALUES ({p},{p},{p},{p},{p},{p},{p},{p})",
                (
                    self._tenant.value,
                    uuid.uuid4().hex,
                    event.incident_id.value,
                    event.event_type,
                    event.event_version,
                    _dumps(dict(event.payload())),
                    event.occurred_at.isoformat(),
                    event.occurred_at.isoformat(),
                ),
            )
        self._conn.commit()
        self._committed = True
        published, self._pending = list(self._pending), []
        if published:
            self._publisher.publish(self._tenant, published)

    def _append_audit_trail(self) -> None:
        """Append one ordered transition row per state change, per incident."""
        p = self._conn.p
        next_seq: dict[str, int] = {}
        for event in self._pending:
            if event.event_type not in {"IncidentAdmitted", "IncidentStateChanged"}:
                continue
            incident_id = event.incident_id.value
            if incident_id not in next_seq:
                row = self._conn.one(
                    f"SELECT COALESCE(MAX(seq), 0) AS n FROM incident_transitions "
                    f"WHERE tenant_id={p} AND incident_id={p}",
                    (self._tenant.value, incident_id),
                )
                next_seq[incident_id] = int(row["n"]) if row else 0
            next_seq[incident_id] += 1
            body = dict(event.payload())
            self._conn.execute_rowcount(
                f"INSERT INTO incident_transitions (tenant_id, incident_id, seq, "
                f"from_state, to_state, facts_added, actor, occurred_at) "
                f"VALUES ({p},{p},{p},{p},{p},{p},{p},{p})",
                (
                    self._tenant.value,
                    incident_id,
                    next_seq[incident_id],
                    body.get("from"),
                    body.get("to", "received"),
                    _dumps(body),
                    body.get("actor", "ingest"),
                    event.occurred_at.isoformat(),
                ),
            )

    def rollback(self) -> None:
        self._pending.clear()
        self._conn.rollback()


class SqlUnitOfWorkFactory:
    """The only door to the database. Requires a tenant, always."""

    __slots__ = ("_pool", "_publisher", "_clock", "_evidence_cipher")

    def __init__(
        self, *, pool: ConnectionPool, publisher: EventPublisher, clock: Clock, evidence_cipher: Any = None
    ) -> None:
        self._pool = pool
        self._publisher = publisher
        self._clock = clock
        self._evidence_cipher = evidence_cipher

    def begin(self, tenant: TenantId) -> SqlUnitOfWork:
        return SqlUnitOfWork(self._pool, tenant, self._publisher, self._clock, self._evidence_cipher)
