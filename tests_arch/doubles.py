"""In-memory implementations of every driven port, for testing.

These are TEST DOUBLES, not production adapters. They live under `tests_arch/`
and are never imported by `sentinel.*`; the production adapters are in
`sentinel/infrastructure/`. Their purpose is to demonstrate the property the
architecture was built for: every use case can be exercised with no database, no
network, no clock and no framework.

Note what is absent. There is no `monkeypatch`, no module-global reset, no
`importlib.reload`, and no environment variable. Each double is a class,
constructed and passed in. That is only possible because nothing in the
application layer reaches for a module-level singleton — which is exactly the
property the predecessor lacked, where `db._db_path`, `rules._POLICY`,
`config._cached`, `INCIDENT_QUEUE` and `MONITOR` were all process globals and
test isolation depended on remembering to clear them.
"""

from __future__ import annotations

import itertools
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Sequence

from sentinel.application.records import (
    ApprovalRecord,
    DetectionVerdict,
    EvidenceRecord,
    ModelAdvice,
    OutboxRecord,
    QueuedWork,
    VerifiedIdentity,
)
from sentinel.domain.errors import (
    ArtifactMissing,
    ConcurrencyConflict,
    ExecutionFenceLost,
    TransientFailure,
)
from sentinel.domain.execution import (
    StepName,
    StepRecord,
    StepStatus,
    check_step_transition,
)
from sentinel.domain.events import DomainEvent
from sentinel.domain.incident import (
    AttestationDisposition,
    AttestationOutcome,
    Incident,
)
from sentinel.domain.primitives import (
    Address,
    ApprovalId,
    BatchId,
    Digest,
    IdempotencyKey,
    IncidentId,
    MessageId,
    Severity,
    TenantId,
    Timestamp,
    TrustLevel,
)

__all__ = [
    "FakeAgentRegistry",
    "FakeAttestationGateway",
    "FakeClock",
    "FakeDetectionPolicy",
    "FakeEvidenceBuilder",
    "FakeIdentityVerifier",
    "FakeIds",
    "FakeModelAdvisor",
    "FakePlanner",
    "FakeReplayGuard",
    "FakeReportRenderer",
    "InMemoryStore",
    "InMemoryUnitOfWorkFactory",
    "InMemoryWorkQueue",
    "RecordingLogger",
]


# ── Infrastructure primitives ────────────────────────────────────────────────


class FakeClock:
    def __init__(self, start: datetime | None = None) -> None:
        self._now = start or datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)

    def now(self) -> Timestamp:
        return Timestamp(self._now)

    def advance(self, seconds: float) -> None:
        self._now = self._now + timedelta(seconds=seconds)


class FakeIds:
    def __init__(self, prefix: str = "gen") -> None:
        self._counter = itertools.count(1)
        self._prefix = prefix

    def _next(self, kind: str) -> str:
        return f"{self._prefix}-{kind}-{next(self._counter)}"

    def incident_id(self) -> IncidentId:
        return IncidentId(self._next("inc"))

    def approval_id(self) -> ApprovalId:
        return ApprovalId(self._next("apr"))

    def batch_id(self, *, at: Timestamp) -> BatchId:
        return BatchId(self._next("batch"))

    def message_id(self) -> MessageId:
        return MessageId(self._next("msg"))

    def idempotency_key(self, *, tenant: TenantId, incident: IncidentId) -> IdempotencyKey:
        return IdempotencyKey(f"idem-{tenant}-{incident}")


class RecordingLogger:
    def __init__(self) -> None:
        self.records: list[tuple[str, str, dict[str, Any]]] = []

    def _log(self, level: str, event: str, fields: dict[str, Any]) -> None:
        self.records.append((level, event, fields))

    def info(self, event: str, /, **fields: Any) -> None:
        self._log("info", event, fields)

    def warning(self, event: str, /, **fields: Any) -> None:
        self._log("warning", event, fields)

    def error(self, event: str, /, **fields: Any) -> None:
        self._log("error", event, fields)

    def critical(self, event: str, /, **fields: Any) -> None:
        self._log("critical", event, fields)

    def bind(self, **fields: Any) -> "RecordingLogger":
        return self

    def events(self, level: str | None = None) -> list[str]:
        return [e for lvl, e, _ in self.records if level is None or lvl == level]


# ── Shared store ─────────────────────────────────────────────────────────────


class InMemoryStore:
    """Per-tenant data. Explicitly keyed by tenant so isolation is visible."""

    def __init__(self) -> None:
        self.incidents: dict[tuple[str, str], Incident] = {}
        self.evidence: dict[tuple[str, str], EvidenceRecord] = {}
        self.reports: dict[tuple[str, str], str] = {}
        self.approvals: dict[tuple[str, str], ApprovalRecord] = {}
        self.outbox: list[OutboxRecord] = []
        self.ledger: list[dict[str, Any]] = []
        self.published: list[tuple[str, DomainEvent]] = []
        self.queue: list[QueuedWork] = []
        #: (tenant, incident, step) -> StepRecord
        self.journal: dict[tuple[str, str, str], Any] = {}
        #: (tenant, message_id) -> kind
        self.inbox: dict[tuple[str, str], str] = {}
        self.withdrawn_reports: dict[tuple[str, str], str] = {}
        #: Every external effect, in order, with its idempotency key. The
        #: exactly-once assertions read this: a duplicated effect is a
        #: duplicated entry here, which no internal bookkeeping can hide.
        self.effects: list[tuple[str, str]] = []


# ── Repositories ─────────────────────────────────────────────────────────────


class _IncidentRepo:
    def __init__(self, store: InMemoryStore, tenant: TenantId) -> None:
        self._store = store
        self._tenant = tenant

    def _key(self, incident_id: IncidentId) -> tuple[str, str]:
        return (self._tenant.value, incident_id.value)

    def _clone(self, incident: Incident) -> Incident:
        """Round-trip through `rehydrate`, exactly as the SQL repository does.

        A double that skips the reconstruction the real one performs is a double
        that tests a different object.
        """
        return Incident.rehydrate(
            tenant_id=incident.tenant_id,
            incident_id=incident.incident_id,
            state=incident.state,
            facts=dict(incident.facts),
            version=incident.version,
            execution_epoch=incident.execution_epoch,
        )

    def get(self, incident_id: IncidentId) -> Incident | None:
        found = self._store.incidents.get(self._key(incident_id))
        return self._clone(found) if found else None

    def get_for_update(self, incident_id: IncidentId) -> Incident | None:
        return self.get(incident_id)

    def exists(self, incident_id: IncidentId) -> bool:
        return self._key(incident_id) in self._store.incidents

    def add(self, incident: Incident) -> None:
        self._store.incidents.setdefault(self._key(incident.incident_id), self._clone(incident))

    def save(self, incident: Incident) -> None:
        key = self._key(incident.incident_id)
        stored = self._store.incidents.get(key)
        if stored is not None and stored.version != incident.loaded_version:
            raise ConcurrencyConflict(
                f"incident {incident.incident_id} was read at version "
                f"{incident.loaded_version} and is now at {stored.version}"
            )
        self._store.incidents[key] = self._clone(incident)

    def claim_execution(self, incident_id: IncidentId, *, epoch: int) -> None:
        stored = self._store.incidents.get(self._key(incident_id))
        if stored is None:
            raise KeyError(str(incident_id))
        if epoch <= stored.execution_epoch:
            raise ExecutionFenceLost(f"owned at epoch {stored.execution_epoch}")
        stored.execution_epoch = epoch


class _LedgerRepo:
    def __init__(self, store: InMemoryStore, tenant: TenantId) -> None:
        self._store = store
        self._tenant = tenant

    def _key(self, incident_id: IncidentId) -> tuple[str, str]:
        return (self._tenant.value, incident_id.value)

    def _mine(self) -> list[dict[str, Any]]:
        return [e for e in self._store.ledger if e["tenant"] == self._tenant.value]

    def append(
        self, *, incident_id: IncidentId, entry_hash: Digest, manifest: Mapping[str, Any]
    ) -> tuple[int, Digest]:
        mine = self._mine()
        previous = mine[-1]["chain_hash"] if mine else Digest("0" * 64)
        chained = Digest(
            __import__("hashlib")
            .sha256(f"{previous.value}{entry_hash.value}".encode())
            .hexdigest()
        )
        sequence = len(mine) + 1
        self._store.ledger.append(
            {
                "tenant": self._tenant.value,
                "incident_id": incident_id.value,
                "seq": sequence,
                "entry_hash": entry_hash,
                "chain_hash": chained,
                "prev_chain_hash": previous,
                "manifest": dict(manifest),
                "batch_id": None,
            }
        )
        return sequence, chained

    def head(self) -> Digest | None:
        mine = self._mine()
        return mine[-1]["chain_hash"] if mine else None

    def store_evidence(self, record: EvidenceRecord) -> None:
        self._store.evidence[self._key(record.incident_id)] = record

    def get_evidence(self, incident_id: IncidentId) -> EvidenceRecord | None:
        return self._store.evidence.get(self._key(incident_id))

    def unsealed_entries(self, *, limit: int) -> Sequence[Mapping[str, Any]]:
        return [e for e in self._mine() if e["batch_id"] is None][:limit]

    def seal(
        self,
        *,
        batch_id: BatchId,
        merkle_root: Digest,
        sequences: Sequence[int],
        signature: str | None,
        signer: Address | None,
        manifest: Mapping[str, Any],
        at: Timestamp,
    ) -> None:
        wanted = set(sequences)
        for entry in self._mine():
            if entry["seq"] in wanted:
                if entry["batch_id"] is not None:
                    raise ConcurrencyConflict(f"entry {entry['seq']} is already sealed")
                entry["batch_id"] = batch_id.value

    def store_report(self, *, incident_id: IncidentId, content: str, at: Timestamp) -> None:
        self._store.reports[self._key(incident_id)] = content

    def get_report(self, incident_id: IncidentId) -> str | None:
        key = self._key(incident_id)
        if key in self._store.withdrawn_reports:
            return None
        return self._store.reports.get(key)

    def redact_evidence(self, *, incident_id: IncidentId, reason: str, actor: str, at) -> bool:
        """Destroy the body, keep the commitment. Idempotent."""
        key = self._key(incident_id)
        record = self._store.evidence.get(key)
        if record is None or record.is_redacted:
            return False
        self._store.evidence[key] = replace(
            record, redacted_at=at, redaction_reason=reason, content={}
        )
        return True

    def withdraw_report(self, *, incident_id: IncidentId, reason: str, at) -> bool:
        key = self._key(incident_id)
        if key not in self._store.reports or key in self._store.withdrawn_reports:
            return False
        self._store.withdrawn_reports[key] = reason
        return True


class _ApprovalRepo:
    def __init__(self, store: InMemoryStore, tenant: TenantId) -> None:
        self._store = store
        self._tenant = tenant

    def _key(self, approval_id: ApprovalId) -> tuple[str, str]:
        return (self._tenant.value, approval_id.value)

    def propose(self, records: Sequence[ApprovalRecord]) -> None:
        for record in records:
            self._store.approvals.setdefault(self._key(record.approval_id), record)

    def get(self, approval_id: ApprovalId) -> ApprovalRecord | None:
        return self._store.approvals.get(self._key(approval_id))

    def claim_for_execution(self, approval_id: ApprovalId) -> ApprovalRecord | None:
        key = self._key(approval_id)
        record = self._store.approvals.get(key)
        if record is None or record.state != "pending":
            return None
        claimed = replace(record, state="executing")
        self._store.approvals[key] = claimed
        return claimed

    def record_outcome(
        self,
        *,
        approval_id: ApprovalId,
        state: str,
        decided_by: str,
        receipt: Mapping[str, Any],
        at: Timestamp,
    ) -> None:
        key = self._key(approval_id)
        record = self._store.approvals[key]
        self._store.approvals[key] = replace(
            record, state=state, decided_by=decided_by, decided_at=at, receipt=dict(receipt)
        )

    def release(self, approval_id: ApprovalId, *, error: str, at: Timestamp) -> None:
        key = self._key(approval_id)
        record = self._store.approvals[key]
        self._store.approvals[key] = replace(record, state="pending")

    def withdraw(self, approval_id: ApprovalId, *, reason: str, at) -> bool:
        """Withdraw a proposal a human has not acted on. Never one already decided."""
        key = self._key(approval_id)
        record = self._store.approvals.get(key)
        if record is None or record.state != "pending":
            return False
        self._store.approvals[key] = replace(record, state="withdrawn", decided_at=at)
        return True

    def pending_for_incident(self, incident_id: IncidentId) -> Sequence[ApprovalRecord]:
        return [
            r
            for (tenant, _), r in self._store.approvals.items()
            if tenant == self._tenant.value
            and r.incident_id == incident_id
            and r.state == "pending"
        ]


class _OutboxRepo:
    def __init__(self, store: InMemoryStore, tenant: TenantId, ids: FakeIds) -> None:
        self._store = store
        self._tenant = tenant
        self._ids = ids

    def enqueue(
        self,
        *,
        incident_id: IncidentId,
        kind: str,
        payload: Mapping[str, Any],
        idempotency_key: IdempotencyKey,
        at: Timestamp,
    ) -> IdempotencyKey:
        for existing in self._store.outbox:
            if existing.idempotency_key == idempotency_key:
                return existing.idempotency_key
        self._store.outbox.append(
            OutboxRecord(
                record_id=self._ids.message_id(),
                tenant_id=self._tenant,
                incident_id=incident_id,
                kind=kind,
                payload=dict(payload),
                idempotency_key=idempotency_key,
                attempts=0,
                max_attempts=5,
                state="pending",
            )
        )
        return idempotency_key

    def claim_batch(
        self, *, limit: int, now: Timestamp, lease_seconds: int
    ) -> Sequence[OutboxRecord]:
        claimed: list[OutboxRecord] = []
        for index, record in enumerate(self._store.outbox):
            if len(claimed) >= limit:
                break
            if record.tenant_id == self._tenant and record.state == "pending":
                leased = replace(record, state="delivering")
                self._store.outbox[index] = leased
                claimed.append(leased)
        return claimed

    def mark_delivered(
        self, *, record_id: MessageId, result: Mapping[str, Any], at: Timestamp
    ) -> None:
        for index, record in enumerate(self._store.outbox):
            if record.record_id == record_id:
                self._store.outbox[index] = replace(record, state="delivered")

    def mark_failed(self, *, record_id: MessageId, error: str, at: Timestamp) -> str:
        for index, record in enumerate(self._store.outbox):
            if record.record_id == record_id:
                attempts = record.attempts + 1
                state = "dead" if attempts >= record.max_attempts else "pending"
                self._store.outbox[index] = replace(
                    record, attempts=attempts, state=state, last_error=error
                )
                return state
        raise KeyError(str(record_id))

    def reap_expired_leases(self, *, now: Timestamp) -> int:
        return 0

    def dead_letters(self, *, limit: int) -> Sequence[OutboxRecord]:
        return [
            r
            for r in self._store.outbox
            if r.tenant_id == self._tenant and r.state == "dead"
        ][:limit]

    def replay(self, record_id: MessageId, *, at: Timestamp) -> bool:
        for index, record in enumerate(self._store.outbox):
            if record.record_id == record_id and record.state == "dead":
                self._store.outbox[index] = replace(record, state="pending", attempts=0)
                return True
        return False


class _Journal:
    """In-memory execution journal, enforcing the same pure transition rules.

    It calls `check_step_transition` — the SAME pure function the SQL journal
    calls — so a double that accepted an illegal step transition would be
    testing a different machine from the one that ships.
    """

    def __init__(self, store: InMemoryStore, tenant: TenantId) -> None:
        self._store = store
        self._tenant = tenant

    def _key(self, incident_id: IncidentId, step) -> tuple[str, str, str]:
        return (self._tenant.value, incident_id.value, step.value)

    def load(self, incident_id: IncidentId):
        prefix = (self._tenant.value, incident_id.value)
        return {
            StepName(step): record
            for (tenant, incident, step), record in self._store.journal.items()
            if (tenant, incident) == prefix
        }

    def settled_steps(self, incident_id: IncidentId):
        return frozenset(
            name for name, record in self.load(incident_id).items() if record.is_settled
        )

    def enter(self, incident_id: IncidentId, *, step, epoch: int, now):
        key = self._key(incident_id, step)
        prior = self._store.journal.get(key)
        check_step_transition(prior.status if prior else None, StepStatus.RUNNING)
        if prior is not None and prior.epoch > epoch:
            raise ExecutionFenceLost(f"step {step} held at epoch {prior.epoch}")
        attempts = (prior.attempts if prior else 0) + 1
        record = StepRecord(
            step=step, status=StepStatus.RUNNING, epoch=epoch, attempts=attempts
        )
        self._store.journal[key] = record
        return record

    def settle(
        self, incident_id: IncidentId, *, step, status, result, epoch: int, now, error=None
    ):
        key = self._key(incident_id, step)
        prior = self._store.journal.get(key)
        if prior is None:
            raise ArtifactMissing(f"step {step} was never entered")
        check_step_transition(prior.status, status)
        if prior.epoch != epoch:
            raise ExecutionFenceLost(
                f"step {step} is held at epoch {prior.epoch}, not {epoch}"
            )
        self._store.journal[key] = StepRecord(
            step=step,
            status=status,
            epoch=epoch,
            attempts=prior.attempts,
            result=dict(result),
            error=error,
        )


class _Inbox:
    """At-most-once acceptance. The insert IS the claim, as in SQL."""

    def __init__(self, store: InMemoryStore, tenant: TenantId) -> None:
        self._store = store
        self._tenant = tenant

    def accept(self, *, message_id, kind: str, now) -> bool:
        key = (self._tenant.value, message_id.value)
        if key in self._store.inbox:
            return False
        self._store.inbox[key] = kind
        return True

    def seen(self, message_id) -> bool:
        return (self._tenant.value, message_id.value) in self._store.inbox

    def purge_before(self, *, cutoff) -> int:
        return 0


class _UnitOfWork:
    def __init__(self, store: InMemoryStore, tenant: TenantId, ids: FakeIds) -> None:
        self._store = store
        self._tenant = tenant
        self.incidents = _IncidentRepo(store, tenant)
        self.ledger = _LedgerRepo(store, tenant)
        self.approvals = _ApprovalRepo(store, tenant)
        self.outbox = _OutboxRepo(store, tenant, ids)
        self.journal = _Journal(store, tenant)
        self.inbox = _Inbox(store, tenant)
        self._pending: list[DomainEvent] = []
        self.committed = False

    def __enter__(self) -> "_UnitOfWork":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        if exc_type is not None:
            self.rollback()
        return False

    def collect(self, events: Iterable[DomainEvent]) -> None:
        self._pending.extend(events)

    def commit(self) -> None:
        self.committed = True
        for event in self._pending:
            self._store.published.append((self._tenant.value, event))
        self._pending.clear()

    def rollback(self) -> None:
        self._pending.clear()


class InMemoryUnitOfWorkFactory:
    def __init__(self, store: InMemoryStore, ids: FakeIds | None = None) -> None:
        self._store = store
        self._ids = ids or FakeIds("uow")

    def begin(self, tenant: TenantId) -> _UnitOfWork:
        return _UnitOfWork(self._store, tenant, self._ids)


# ── Work queue ───────────────────────────────────────────────────────────────


class InMemoryWorkQueue:
    def __init__(self, store: InMemoryStore, ids: FakeIds) -> None:
        self._store = store
        self._ids = ids
        self._epochs: dict[str, int] = {}

    def submit(
        self,
        *,
        tenant: TenantId,
        incident_id: IncidentId,
        payload: Mapping[str, Any],
        priority: str,
        uow: Any,
    ) -> None:
        self._store.queue.append(
            QueuedWork(
                work_id=self._ids.message_id(),
                tenant_id=tenant,
                incident_id=incident_id,
                payload=dict(payload),
                attempts=0,
                lease_epoch=0,
                claimed_by="",
            )
        )

    def claim(self, *, shard: int, shard_count: int, now: Timestamp) -> QueuedWork | None:
        for index, work in enumerate(self._store.queue):
            if hash(work.tenant_id.value) % shard_count != shard:
                continue
            epoch = self._epochs.get(work.work_id.value, 0) + 1
            self._epochs[work.work_id.value] = epoch
            claimed = replace(
                work, lease_epoch=epoch, attempts=work.attempts + 1, claimed_by="test-worker"
            )
            self._store.queue.pop(index)
            return claimed
        return None

    def complete(self, work: QueuedWork) -> None:
        return None

    def fail(
        self, work: QueuedWork, *, error: str, now: Timestamp, retry_in_seconds: int
    ) -> bool:
        if work.attempts >= 3:
            return False
        self._store.queue.append(work)
        return True

    def reap_expired_leases(self, *, now: Timestamp, shard: int, shard_count: int) -> int:
        return 0

    def depth(self, *, state: str) -> int:
        return len(self._store.queue)


# ── Outbound doubles ─────────────────────────────────────────────────────────


class FakeAgentRegistry:
    def __init__(self, enrolled: Mapping[str, Iterable[str]] | None = None) -> None:
        self._enrolled = {k: set(v) for k, v in (enrolled or {}).items()}
        self._enrolled_at: dict[tuple[str, str], Timestamp] = {}
        self._last_event: dict[tuple[str, str], Timestamp] = {}

    def enrolled_addresses(self, tenant: TenantId) -> frozenset[str]:
        return frozenset(self._enrolled.get(tenant.value, set()))

    def enrol(self, tenant: TenantId, *, address: Address, label: str, at: Timestamp) -> None:
        self._enrolled.setdefault(tenant.value, set()).add(address.value)
        self._enrolled_at[(tenant.value, address.value)] = at

    def revoke(self, tenant: TenantId, *, address: Address) -> None:
        self._enrolled.get(tenant.value, set()).discard(address.value)
        self._enrolled_at.pop((tenant.value, address.value), None)
        self._last_event.pop((tenant.value, address.value), None)

    def record_event(self, tenant: TenantId, *, address: Address, at: Timestamp) -> None:
        if address.value in self._enrolled.get(tenant.value, set()):
            self._last_event[(tenant.value, address.value)] = at

    def list_activity(self, tenant: TenantId):
        from sentinel.application.bypass_detection import AgentActivity

        out = []
        for address in self._enrolled.get(tenant.value, set()):
            enrolled_at = self._enrolled_at.get((tenant.value, address))
            if enrolled_at is None:
                continue
            out.append(
                AgentActivity(
                    address=address,
                    enrolled_at=enrolled_at,
                    last_event_at=self._last_event.get((tenant.value, address)),
                )
            )
        return out


class FakeIdentityVerifier:
    """Verifies against a fixed map of signature -> address."""

    def __init__(self, signatures: Mapping[str, str] | None = None) -> None:
        self._signatures = dict(signatures or {})

    def verify(
        self, *, payload: Mapping[str, Any], signature: str | None, enrolled: frozenset[str]
    ) -> VerifiedIdentity:
        if not signature:
            return VerifiedIdentity(TrustLevel.UNSIGNED, "no signature presented")
        recovered = self._signatures.get(signature)
        if recovered is None:
            return VerifiedIdentity(TrustLevel.INVALID, "signature did not recover")
        if recovered not in enrolled:
            return VerifiedIdentity(TrustLevel.INVALID, "recovered address is not enrolled")
        return VerifiedIdentity(TrustLevel.VERIFIED, "signature verified", Address(recovered))

    def digest(self, payload: Mapping[str, Any]) -> Digest:
        import hashlib
        import json

        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return Digest(hashlib.sha256(canonical.encode()).hexdigest())


class FakeReplayGuard:
    def __init__(self, *, accept: bool = True) -> None:
        self.accept = accept
        self.seen: set[str] = set()

    def check_and_consume(
        self,
        *,
        tenant: TenantId,
        agent: Address,
        event_digest: Digest,
        claimed_at: Timestamp | None,
        now: Timestamp,
    ) -> tuple[bool, str]:
        if not self.accept:
            return False, "replay guard configured to reject"
        key = f"{tenant}:{agent}:{event_digest}"
        if key in self.seen:
            return False, "digest already consumed for this agent"
        self.seen.add(key)
        return True, "fresh"

    def purge_expired(self, *, tenant: TenantId, now: Timestamp) -> int:
        return 0


class FakeDetectionPolicy:
    def __init__(self, *, severity: int = 90, fired: bool = True, version: str = "policy-test-1"):
        self._severity = severity
        self._fired = fired
        self._version = version

    def evaluate(self, *, payload: Mapping[str, Any], trust: TrustLevel) -> DetectionVerdict:
        return DetectionVerdict(
            fired=self._fired,
            severity=Severity(self._severity),
            incident_type="prompt_injection_suspected",
            description="test rule matched",
            matched_rules=("rule-1",),
            detector_version=self._version,
            signals={"policy": {"fired": self._fired}},
        )

    def version(self) -> str:
        return self._version


class FakeModelAdvisor:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls = 0

    def advise(self, *, incident: Mapping[str, Any]) -> ModelAdvice:
        self.calls += 1
        if self.fail:
            raise TransientFailure("advisor endpoint unreachable")
        return ModelAdvice(
            available=True,
            detail="advisory second opinion recorded; not authoritative",
            model_receipt="fake-advisor-1",
            suggested_priority="HIGH",
            recommendations=("isolate the agent",),
            reasoning="matched a known injection shape",
        )

    def model_receipt(self) -> str:
        return "fake-advisor-1"


class FakeEvidenceBuilder:
    def build(
        self,
        *,
        tenant: TenantId,
        incident_id: IncidentId,
        incident_facts: Mapping[str, Any],
        approvals: Sequence[ApprovalRecord],
        advice: ModelAdvice | None,
        detector_version: str,
        at: Timestamp,
    ) -> tuple[EvidenceRecord, Digest, Mapping[str, Any]]:
        import hashlib
        import json

        content = {
            "tenant_id": tenant.value,
            "incident_id": incident_id.value,
            "facts": dict(incident_facts),
            "approvals": [a.approval_id.value for a in approvals],
            "advisory_available": bool(advice and advice.available),
            "detector_version": detector_version,
        }
        canonical = json.dumps(content, sort_keys=True, separators=(",", ":"), default=str)
        digest = Digest(hashlib.sha256(canonical.encode()).hexdigest())
        manifest = {"v": 2, "tenant_id": tenant.value, "incident_id": incident_id.value,
                    "body_digest": digest.value}
        leaf = Digest(
            hashlib.sha256(
                json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        )
        record = EvidenceRecord(
            incident_id=incident_id,
            uri=f"sentinel://evidence/{tenant}/{incident_id}",
            digest=digest,
            content=content,
            created_at=at,
        )
        return record, leaf, manifest


class FakeReportRenderer:
    def render(
        self,
        *,
        incident_facts: Mapping[str, Any],
        evidence: EvidenceRecord,
        approvals: Sequence[ApprovalRecord],
        advice: ModelAdvice | None,
        at: Timestamp,
    ) -> str:
        return (
            f"# Incident {evidence.incident_id}\n"
            f"evidence_digest: {evidence.digest}\n"
            f"severity: {incident_facts.get('severity')}\n"
            f"approvals: {len(approvals)}\n"
            f"advisory: {'yes' if advice and advice.available else 'no'}\n"
        )


class FakePlanner:
    def __init__(self, *, actions: Sequence[tuple[str, str]] = ()) -> None:
        self._actions = tuple(actions)

    def propose(
        self,
        *,
        incident_facts: Mapping[str, Any],
        advice: ModelAdvice | None,
        incident_id: IncidentId,
        ids: Any,
        at: Timestamp,
    ) -> Sequence[ApprovalRecord]:
        return [
            ApprovalRecord(
                approval_id=ids.approval_id(),
                incident_id=incident_id,
                action=action,
                target=target,
                state="pending",
                proposed_at=at,
            )
            for action, target in self._actions
        ]


class FakeAttestationGateway:
    """Configurable outcome, so the transient-versus-permanent split is testable."""

    def __init__(
        self,
        *,
        disposition: AttestationDisposition = AttestationDisposition.ANCHORED,
        effects: list[tuple[str, str]] | None = None,
    ):
        self.disposition = disposition
        self.calls: list[IdempotencyKey] = []
        #: Shared with the store when supplied, so a test asserts on the
        #: TOTAL set of external effects rather than a per-adapter counter.
        self.effects = effects if effects is not None else []

    def anchor(
        self,
        *,
        tenant: TenantId,
        incident_id: IncidentId,
        evidence_digest: Digest,
        subject: Address | None,
        idempotency_key: IdempotencyKey,
    ) -> AttestationOutcome:
        self.calls.append(idempotency_key)
        self.effects.append(("anchor", idempotency_key.value))
        if self.disposition is AttestationDisposition.ANCHORED:
            if subject is None:
                return AttestationOutcome(
                    AttestationDisposition.NOT_ANCHORABLE,
                    "no signature-recovered identity for this incident",
                )
            return AttestationOutcome(
                AttestationDisposition.ANCHORED,
                "anchored",
                transaction_hash=f"0x{evidence_digest.value[:40]}",
                subject=subject,
            )
        if self.disposition is AttestationDisposition.UNAVAILABLE:
            return AttestationOutcome(
                AttestationDisposition.UNAVAILABLE, "gateway unreachable"
            )
        return AttestationOutcome(
            AttestationDisposition.NOT_ANCHORABLE, "no attestation capability configured"
        )

    def reconcile(self, *, idempotency_key: IdempotencyKey):
        """This double does not remember; the caller re-sends under one key."""
        return None

    def capability(self) -> tuple[bool, str]:
        return self.disposition is AttestationDisposition.ANCHORED, "test gateway"
