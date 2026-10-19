"""Driven ports. Every capability the application needs from the outside world.

WHY THIS EXISTS
---------------
The predecessor had exactly one abstraction boundary in ~27k lines
(`app/detection/registry.py`, a BYO-detector hook) and it worked well. Everything
else depended on concrete modules: `repository` on `app.storage.db`, `pipeline` on
`agents.supervisor_agent`, `durable_queue` on `repository` via a function-local
import that existed solely to break an import cycle. A cycle broken by a local
import is the type system reporting inverted layers, and the report being
silenced.

Every port here is a `Protocol`, so:

  * **Adapters do not import the application.** They satisfy the protocol
    structurally; nothing inherits from anything. Dependencies point inward
    because the outward-facing code has no inward-facing import to make.
  * **Every service is replaceable.** A test double is a class with the right
    methods, not a subclass and not a patch of a module global.
  * **Nothing is a singleton.** Every port instance is constructed by the
    composition root and passed as an argument.

THE TENANT-SCOPING RULE
-----------------------
`UnitOfWorkFactory.begin()` requires a `TenantId`. There is no way to obtain a
unit of work, and therefore no way to obtain a connection, without naming the
tenant it is scoped to.

This is a direct structural fix. In the predecessor, `db._connect()` took an
optional tenant and only established PostgreSQL row-level-security context when
one was supplied. `dlq.succeed()` and `dlq.fail()` called it without one. With
FORCE RLS enabled by default and `delivery_queue` a protected table, the policy
`tenant_id = current_setting(...)` evaluated against NULL and matched no rows:
`fail()` raised KeyError on every call and `succeed()` silently updated nothing.
It was invisible on SQLite, which has no RLS, and fatal on the production engine.

Making the tenant a required argument of the only entry point means that defect
is not expressible.
"""

from __future__ import annotations

from typing import Any, Mapping, Protocol, Sequence, runtime_checkable

from sentinel.domain.events import DomainEvent
from sentinel.domain.incident import AttestationOutcome
from sentinel.domain.primitives import (
    Address,
    ApprovalId,
    BatchId,
    Digest,
    IdempotencyKey,
    IncidentId,
    MessageId,
    TenantId,
    Timestamp,
    TrustLevel,
)

__all__ = [
    "AgentObserver",
    "ExecutionRecorder",
    "AgentRegistry",
    "ApprovalRecord",
    "ApprovalRepository",
    "AttestationGateway",
    "Clock",
    "DetectionPolicy",
    "DetectionVerdict",
    "EventPublisher",
    "EvidenceBuilder",
    "EvidenceRecord",
    "IdentityVerifier",
    "IdGenerator",
    "IncidentRepository",
    "LedgerRepository",
    "Logger",
    "ModelAdvisor",
    "ModelAdvice",
    "OutboxRecord",
    "OutboxRepository",
    "QueuedWork",
    "ReadModel",
    "RemediationExecutor",
    "RemediationPlanner",
    "ReplayGuard",
    "ReportRenderer",
    "SecurityAudit",
    "UnitOfWork",
    "UnitOfWorkFactory",
    "VerifiedIdentity",
    "WorkQueue",
]


# ── Supporting record types ──────────────────────────────────────────────────
#
# Deliberately dataclass-free `Protocol`-adjacent plain structures live in
# `sentinel.application.records` so ports stay import-light. These are the
# structural shapes ports exchange.

from sentinel.application.records import (  # noqa: E402  (grouped for readability)
    ApprovalRecord,
    DetectionVerdict,
    EvidenceRecord,
    ModelAdvice,
    OutboxRecord,
    QueuedWork,
    VerifiedIdentity,
)


# ── Infrastructure primitives ────────────────────────────────────────────────


@runtime_checkable
class Clock(Protocol):
    """Time, injected.

    The predecessor called `datetime.now(timezone.utc)` in 14 modules and
    `time.time()` in the rate limiter, which meant the shared token bucket's
    refill arithmetic was only as correct as NTP across the fleet, and no test
    could assert a time-dependent rule without freezing time globally.
    """

    def now(self) -> Timestamp: ...


@runtime_checkable
class IdGenerator(Protocol):
    """Identifier minting, injected, so tests are deterministic."""

    def incident_id(self) -> IncidentId: ...
    def approval_id(self) -> ApprovalId: ...
    def batch_id(self, *, at: Timestamp) -> BatchId: ...
    def message_id(self) -> MessageId: ...
    def idempotency_key(self, *, tenant: TenantId, incident: IncidentId) -> IdempotencyKey: ...


@runtime_checkable
class Logger(Protocol):
    """Structured logging. A port because the domain must not know structlog."""

    def info(self, event: str, /, **fields: Any) -> None: ...
    def warning(self, event: str, /, **fields: Any) -> None: ...
    def error(self, event: str, /, **fields: Any) -> None: ...
    #: Reserved for conditions where the process keeps serving but a stated
    #: guarantee no longer holds -- detection silently falling back to rules-only
    #: being the case this was added for. An operator must be paged on these; an
    #: `error` is one request going wrong, a `critical` is the product not doing
    #: what its documentation says it does.
    def critical(self, event: str, /, **fields: Any) -> None: ...
    def bind(self, **fields: Any) -> "Logger": ...


# ── Persistence ports ────────────────────────────────────────────────────────


# ── Persistence contract ─────────────────────────────────────────────────────
#
# MOVED to `repository_ports.py`, and re-exported here so no import changes.
#
# `ports.py` describes the ambient collaborators a handler needs; the
# repositories describe how state is read and written. Two jobs, two reasons to
# change, and together they took this module past the 800-line fitness limit.
from sentinel.application.repository_ports import (  # noqa: E402,F401
    ApprovalRepository,
    ContainmentRepository,
    IncidentRepository,
    LedgerRepository,
    OutboxRepository,
    UnitOfWork,
    UnitOfWorkFactory,
)


@runtime_checkable
class ReadModel(Protocol):
    """The query side of CQRS. Reads never load an aggregate.

    Separate from the repositories because a query has no business taking the
    row locks, running the invariant checks, or paying the object-construction
    cost that a command needs. In the predecessor every read went through the
    same code as every write.
    """

    def attestation_summary(self, tenant: TenantId) -> Mapping[str, int]:
        """Counts by attestation outcome. Called by `incident_queries.py`."""
        ...

    def incident_summary(
        self, tenant: TenantId, incident_id: IncidentId
    ) -> Mapping[str, Any] | None: ...

    def list_incidents(
        self, tenant: TenantId, *, limit: int, after: str | None
    ) -> Sequence[Mapping[str, Any]]: ...

    def incident_history(
        self, tenant: TenantId, incident_id: IncidentId
    ) -> Sequence[Mapping[str, Any]]: ...

    def counts_by_state(self, tenant: TenantId) -> Mapping[str, int]: ...

    def report(self, tenant: TenantId, incident_id: IncidentId) -> str | None: ...

    def dead_letter_count(self, tenant: TenantId) -> int: ...


# ── Work distribution ────────────────────────────────────────────────────────


@runtime_checkable
class WorkQueue(Protocol):
    """Durable work distribution with fenced leases.

    `claim` takes a shard so dispatch is O(1) queries. The predecessor's
    `claim()` iterated every tenant, opening a connection per tenant, on every
    poll -- so a single dequeue at 1,000 tenants cost 1,002 connect/query/close
    cycles, and an idle three-replica deployment generated tens of thousands of
    connections per second while doing no work. Tenant count, not event volume,
    was the first thing that broke.
    """

    def submit(
        self,
        *,
        tenant: TenantId,
        incident_id: IncidentId,
        payload: Mapping[str, Any],
        priority: str,
        uow: UnitOfWork,
    ) -> None:
        """Enqueue inside the CALLER's transaction, so acceptance is atomic."""
        ...

    def claim(self, *, shard: int, shard_count: int, now: Timestamp) -> QueuedWork | None: ...

    def complete(self, work: QueuedWork) -> None:
        """Fenced. Raises `ExecutionFenceLost` if the lease was reclaimed."""
        ...

    def fail(self, work: QueuedWork, *, error: str, now: Timestamp, retry_in_seconds: int) -> bool:
        """Fenced. Returns whether it will be retried."""
        ...

    def reap_expired_leases(self, *, now: Timestamp, shard: int, shard_count: int) -> int:
        """Reclaim work whose owner died. Does NOT charge the retry budget.

        The predecessor's reclamation incremented `attempts`, so a
        slow-but-healthy worker exceeding the 300s claim timeout had its item
        reclaimed and its budget charged; three such events dead-lettered work
        that was succeeding.
        """
        ...

    def depth(self, *, state: str) -> int: ...



# ── Outbound integration ports ───────────────────────────────────────────────


@runtime_checkable
class AttestationGateway(Protocol):
    """The external anchoring system.

    `idempotency_key` is a REQUIRED argument. In the predecessor
    `publish_attestation` accepted one and its single call site omitted it, so
    the key was generated, persisted, returned and never sent -- the outbox could
    not deduplicate at the only place deduplication mattered.
    """

    def anchor(
        self,
        *,
        tenant: TenantId,
        incident_id: IncidentId,
        evidence_digest: Digest,
        subject: Address | None,
        idempotency_key: IdempotencyKey,
    ) -> AttestationOutcome:
        """Attempt the anchor. MUST NOT raise for a transient failure.

        A transient failure is returned as `AttestationDisposition.UNAVAILABLE`,
        because the distinction between "cannot" and "could not" is a domain
        fact this adapter is the only thing positioned to know.
        """
        ...

    def reconcile(
        self, *, idempotency_key: IdempotencyKey
    ) -> "AttestationOutcome | None":
        """Ask what was already done under this key. None if nothing was.

        This closes the last gap in the exactly-once story. The inbox
        deduplicates acceptance and the journal deduplicates execution, but
        neither can see a crash BETWEEN an external effect and the record of
        it: from inside the process, "the anchor landed and we died" is
        indistinguishable from "we died before anchoring".

        Reconciliation resolves it by asking the only party that knows. A
        gateway that cannot answer returns None, and the engine falls back to
        re-sending with the same deterministic key -- still correct, and
        merely relying on the gateway to deduplicate rather than to report.

        MUST be side-effect free. A `reconcile` that creates the thing it was
        asked about turns the recovery path into the defect.
        """
        ...

    def capability(self) -> tuple[bool, str]:
        """(can_anchor, human-readable reason). Never cached: a stale yes lies."""
        ...


@runtime_checkable
class ModelAdvisor(Protocol):
    """The LLM. Advisory only, by architecture.

    Its opinion reaches `advisory_*` fields and cannot move triage. This is the
    single best decision in the predecessor's design and is preserved verbatim:
    the model reads attacker-influenced text, and a system whose priority can be
    argued down by its input has no priority at all.
    """

    def advise(self, *, incident: Mapping[str, Any]) -> ModelAdvice: ...
    def model_receipt(self) -> str: ...


@runtime_checkable
class IdentityVerifier(Protocol):
    """Signature recovery. The ONLY sanctioned source of an `Address`."""

    def verify(
        self, *, payload: Mapping[str, Any], signature: str | None, enrolled: frozenset[str]
    ) -> VerifiedIdentity: ...

    def digest(self, payload: Mapping[str, Any]) -> Digest: ...


@runtime_checkable
class ReplayGuard(Protocol):
    """Freshness. A valid signature proves authorship, never recency."""

    def check_and_consume(
        self,
        *,
        tenant: TenantId,
        agent: Address,
        event_digest: Digest,
        claimed_at: Timestamp | None,
        now: Timestamp,
    ) -> tuple[bool, str]: ...

    def purge_expired(self, *, tenant: TenantId, now: Timestamp) -> int: ...


@runtime_checkable
class DetectionPolicy(Protocol):
    """Deterministic rule evaluation. Reproducible from its version alone."""

    def evaluate(
        self, *, payload: Mapping[str, Any], trust: TrustLevel
    ) -> DetectionVerdict: ...

    def version(self) -> str: ...


@runtime_checkable
class EvidenceBuilder(Protocol):
    """Builds the canonical evidence body and its identity-bound leaf hash."""

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
        """Returns (record, leaf_hash, manifest)."""
        ...


@runtime_checkable
class ReportRenderer(Protocol):
    """Renders the analyst-facing report from durable facts only.

    Takes explicit arguments rather than a mutable context object. The
    predecessor rendered from a `Context` whose artifact fields were `None` on
    any resumed run, producing a durable report that said 'Not available'
    throughout — and committed it as the auditable record.
    """

    def render(
        self,
        *,
        incident_facts: Mapping[str, Any],
        evidence: EvidenceRecord,
        approvals: Sequence[ApprovalRecord],
        advice: ModelAdvice | None,
        at: Timestamp,
    ) -> str: ...


@runtime_checkable
class EventPublisher(Protocol):
    """Where domain events go after the transaction that produced them commits."""

    def publish(self, tenant: TenantId, events: Sequence[DomainEvent]) -> None: ...


@runtime_checkable
class SecurityAudit(Protocol):
    """Appends a tamper-evident record of a security decision.

    A port, so the interface layer depends on the CAPABILITY of auditing and not on
    a table. That is what lets a test inject a recorder and a deployment inject the
    hash-chained SQL implementation, and it is what keeps a dependency pointing
    inward from an adapter that knows about `security_audit`.

    `record` returns None and MUST NOT raise. An authentication denial that cannot
    be audited is still a denial, and turning a logging outage into a total outage
    of a security service is the worse failure. The trade is stated plainly in
    `sentinel/infrastructure/security_audit.py`, and the dense `seq` is what makes
    the resulting gap detectable after the fact.
    """

    def record(
        self,
        *,
        tenant: TenantId,
        actor: str,
        action: str,
        resource_type: str,
        resource_id: str,
        outcome: Any,
        detail: Mapping[str, Any] | None = None,
    ) -> None: ...


@runtime_checkable
class RemediationExecutor(Protocol):
    """Performs an approved real-world action. Idempotent by contract."""

    def execute(
        self,
        *,
        action: str,
        target: str,
        idempotency_key: IdempotencyKey,
        tenant: str = "",
    ) -> Mapping[str, Any]: ...

    def supports(self, action: str) -> bool: ...


@runtime_checkable
class RemediationPlanner(Protocol):
    """Proposes actions for a human to approve. Executes nothing.

    Separated from the executor because proposing and performing have different
    authorisation, different failure modes and different audit requirements, and
    because the LLM's recommendations feed this and must never reach the
    executor.
    """

    def propose(
        self,
        *,
        incident_facts: Mapping[str, Any],
        advice: ModelAdvice | None,
        incident_id: IncidentId,
        ids: IdGenerator,
        at: Timestamp,
    ) -> Sequence[ApprovalRecord]: ...


@runtime_checkable
class ExecutionRecorder(Protocol):
    """Records one step of an agent's execution chain.

    Separate from `AgentObserver` because they answer different questions and
    have different failure consequences. The observer answers "does this agent
    exist and what does it reach" -- an inventory. This answers "what followed
    what" -- a causal trace.

    Both are visibility rather than enforcement, and neither may reject an
    event: losing a node degrades a story, while losing the event is a blind
    spot in the thing the product is for.
    """

    def record(self, node: Any) -> None: ...

    def session(self, tenant_id: str, session_id: str) -> Any:
        """The session's steps in order, for sequence detection.

        On the protocol because escalation needs to READ the chain the moment a
        step that could complete a rule arrives -- so recording and reading are
        one collaborator rather than two that could be wired to different
        stores and silently disagree about what happened.
        """
        ...


@runtime_checkable
class AgentObserver(Protocol):
    """Records that an agent was SEEN, and what it reached.

    Separate from `AgentRegistry` because the two answer different questions and
    must not be allowed to blur. `AgentRegistry` is a trust anchor: enrolment,
    revocation, which addresses an operator decided about. This is observation:
    what actually turned up, whether or not anybody decided anything about it.

    Keeping them apart is what makes "unmanaged" expressible. `record_event` on
    the registry issues an UPDATE against the enrolment table, so an agent
    nobody enrolled updates zero rows and vanishes -- and an inventory built on
    that can only ever list agents somebody already knew about, which is the
    opposite of discovery.

    Observation must never be read as permission. Nothing here returns a
    decision, and the classification an operator sees is derived by comparing
    observation against enrolment rather than stored as a fact either side could
    edit.
    """

    def observe(
        self,
        tenant_id: str,
        agent_id: str,
        *,
        at: str = "",
        edges: Sequence[tuple[Any, str]] = (),
        #: True when this event TRIPPED POLICY. Deliberately distinct from an
        #: incident: a violation the gate refused never became one, so counting
        #: only incidents undercounts exactly the cases where enforcement
        #: worked. The concrete observer has always accepted this and the call
        #: site has always passed it; the protocol had drifted, which meant the
        #: next implementer would have omitted it and silently stopped
        #: recording policy trips.
        violation: bool = False,
    ) -> None:
        """Note one observation. Must not raise on a malformed agent id.

        Called on the ingest hot path for every admitted event, so it is
        expected to be cheap and to bound whatever it stores -- an agent that
        touches a million distinct paths must not become a million rows.
        """
        ...


@runtime_checkable
class AgentRegistry(Protocol):
    """Which agent addresses a tenant has enrolled.

    A port of its own rather than a method on the incident repository: enrolment
    is a governance concern with a different lifecycle, different access control
    and a different rate of change from incident processing.
    """

    def enrolled_addresses(self, tenant: TenantId) -> frozenset[str]: ...

    def enrol(self, tenant: TenantId, *, address: Address, label: str, at: Timestamp) -> None: ...

    def revoke(self, tenant: TenantId, *, address: Address) -> None: ...

    def record_event(self, tenant: TenantId, *, address: Address, at: Timestamp) -> None:
        """Mark that Sentinel observed an event from this enrolled agent."""
        ...

    def list_activity(self, tenant: TenantId) -> Sequence[Any]:
        """Enrolled (non-revoked) agents with enrolment and last-event times.

        Returns application `AgentActivity` snapshots (or structural equivalents).
        """
        ...
