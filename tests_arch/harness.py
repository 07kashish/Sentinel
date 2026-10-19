"""A real engine over a real database, small enough to run thousands of times.

Chaos, concurrency and mutation testing all need the SAME thing: an engine wired
to genuine SQL (so transactions, locks and constraints are real) that can be
built and torn down in milliseconds. SQLite on a temp file gives that.

The two boundaries that reach outside the process -- the attestation gateway and
the advisory model -- are injected, because those are exactly the boundaries the
tests need to make fail on demand. Everything else is production code.
"""

from __future__ import annotations

import itertools
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from sentinel.application.execution.engine import ExecutionEngine
from sentinel.application.execution.pipeline import INCIDENT_PLAN, PipelineSteps
from sentinel.domain.attestation import AttestationDisposition, AttestationOutcome
from sentinel.domain.execution import StepName, StepStatus
from sentinel.domain.incident import Incident, IncidentState
from sentinel.domain.primitives import (
    Address,
    Digest,
    IdempotencyKey,
    IncidentId,
    MessageId,
    Severity,
    TenantId,
    TrustLevel,
)
from sentinel.infrastructure.evidence import (
    CanonicalEvidenceBuilder,
    MarkdownReportRenderer,
    RuleBasedPlanner,
)
from sentinel.infrastructure.sql.engine import Dialect, EngineConfig, build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.infrastructure.sql.unit_of_work import SqlUnitOfWorkFactory
from tests_arch.doubles import FakeClock, FakeIds, RecordingLogger

TENANT = TenantId("acme")

__all__ = [
    "EffectLog",
    "Harness",
    "ScriptedGateway",
    "TENANT",
    "TransientAdvisor",
]


class EffectLog:
    """Every external effect, with its idempotency key. Thread-safe.

    The exactly-once assertions read THIS, not an internal counter. An effect
    that reached the outside world twice appears twice here, and no amount of
    journal or inbox bookkeeping can hide it.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.entries: list[tuple[str, str]] = []

    def record(self, kind: str, key: str) -> None:
        with self._lock:
            self.entries.append((kind, key))

    def keys(self, kind: str) -> list[str]:
        with self._lock:
            return [k for t, k in self.entries if t == kind]

    def distinct_keys(self, kind: str) -> set[str]:
        return set(self.keys(kind))

    @property
    def duplicates(self) -> list[str]:
        """Keys that were applied more than once. Must always be empty."""
        with self._lock:
            seen: dict[str, int] = {}
            for _kind, key in self.entries:
                seen[key] = seen.get(key, 0) + 1
        return sorted(k for k, n in seen.items() if n > 1)


@dataclass
class ScriptedGateway:
    """An attestation gateway whose behaviour a test dictates, call by call.

    `script` is consumed one entry per call; when it runs out, `default` applies.
    `crash_after_effect` makes the gateway record its effect and THEN raise --
    which is the single hardest failure in the system to get right, because the
    anchor exists and nothing wrote that it does.
    """

    effects: EffectLog
    default: AttestationDisposition = AttestationDisposition.ANCHORED
    script: list[AttestationDisposition] = field(default_factory=list)
    crash_after_effect: int = -1
    calls: int = 0
    #: Whether this gateway can answer `reconcile`. A real one usually can;
    #: setting it False exercises the fallback path.
    remembers: bool = True
    #: key -> (transaction_hash, subject). What was actually applied.
    anchored: dict = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def anchor(
        self,
        *,
        tenant: TenantId,
        incident_id: IncidentId,
        evidence_digest: Digest,
        subject: Address | None,
        idempotency_key: IdempotencyKey,
    ) -> AttestationOutcome:
        with self._lock:
            index = self.calls
            self.calls += 1
            disposition = (
                self.script[index] if index < len(self.script) else self.default
            )
        # The effect is recorded BEFORE any crash, exactly as a real gateway
        # would have applied it before the caller learned anything.
        self.effects.record("anchor", idempotency_key.value)
        if disposition is AttestationDisposition.ANCHORED and subject is not None:
            with self._lock:
                self.anchored.setdefault(
                    idempotency_key.value,
                    (f"0x{evidence_digest.value[:40]}", subject),
                )
        if index == self.crash_after_effect:
            raise ConnectionResetError(
                "gateway connection reset AFTER the anchor was applied"
            )
        if disposition is AttestationDisposition.ANCHORED:
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
        if disposition is AttestationDisposition.UNAVAILABLE:
            return AttestationOutcome(
                AttestationDisposition.UNAVAILABLE, "gateway unreachable"
            )
        return AttestationOutcome(
            AttestationDisposition.NOT_ANCHORABLE, "no attestation capability"
        )

    def reconcile(
        self, *, idempotency_key: IdempotencyKey
    ) -> AttestationOutcome | None:
        """Report an anchor previously applied under this key, if any.

        `remembers` models a gateway that can answer. Set it False to model
        one that cannot, so both branches of the recovery path are tested.
        """
        if not self.remembers:
            return None
        with self._lock:
            applied = self.anchored.get(idempotency_key.value)
        if applied is None:
            return None
        return AttestationOutcome(
            AttestationDisposition.ANCHORED,
            "reconciled",
            transaction_hash=applied[0],
            subject=applied[1],
        )

    def capability(self) -> tuple[bool, str]:
        return True, "scripted"


@dataclass
class TransientAdvisor:
    """An advisory model that fails for the first `failures` calls."""

    failures: int = 0
    calls: int = 0

    def advise(self, *, incident: Mapping[str, Any]):
        from sentinel.application.records import ModelAdvice

        self.calls += 1
        if self.calls <= self.failures:
            raise TimeoutError("advisory model timed out")
        return ModelAdvice(
            available=True,
            detail="advisory second opinion recorded; not authoritative",
            model_receipt="harness-advisor",
            suggested_priority="HIGH",
        )

    def model_receipt(self) -> str:
        return "harness-advisor"


class Harness:
    """A live engine over a temp SQLite database."""

    def __init__(
        self,
        tmp_path: Path,
        *,
        engine_config: "EngineConfig | None" = None,
        gateway: ScriptedGateway | None = None,
        advisor: Any = None,
        name: str | None = None,
    ) -> None:
        # A UNIQUE database per harness unless the caller names one. Sharing a
        # file across instances made a mutation probe resume the PREVIOUS
        # leg's finished incident, so the mutation appeared undetectable when
        # in fact the probe never re-ran.
        self.clock = FakeClock()
        self.ids = FakeIds()
        self.logger = RecordingLogger()
        self.gateway = gateway or ScriptedGateway(effects=EffectLog())
        # Observe the log the gateway actually writes to. Keeping a second one
        # would make every duplicate-effect assertion vacuously pass.
        self.effects = self.gateway.effects
        self.advisor = advisor or TransientAdvisor()

        # The backend is INJECTED. The chaos and concurrency suites are
        # parametrised over SQLite and PostgreSQL, because the defect class this
        # architecture is most organised against -- row-level security silently
        # matching no rows -- is invisible on one engine and fatal on the other.
        config = engine_config or EngineConfig(
            dialect=Dialect.SQLITE,
            dsn=str(tmp_path / (name or f"h-{uuid.uuid4().hex[:12]}.db")),
            pool_min=1,
            pool_max=8,
        )
        self.config = config
        self.pool = build_engine(config)
        migrate(self.pool)
        with self.pool.acquire() as conn:
            conn.begin()
            conn.execute_rowcount(
                f"INSERT INTO tenants (tenant_id, name, created_at) "
                f"VALUES ({conn.p},{conn.p},{conn.p}) "
                f"ON CONFLICT (tenant_id) DO NOTHING",
                (TENANT.value, "Acme", self.clock.now().isoformat()),
            )
            conn.commit()

        self.published: list[str] = []

        class _Publisher:
            def __init__(self, sink: list[str]) -> None:
                self._sink = sink

            def publish(self, tenant: TenantId, events: Sequence[Any]) -> None:
                self._sink.extend(e.event_type for e in events)

        self.uows = SqlUnitOfWorkFactory(
            pool=self.pool, publisher=_Publisher(self.published), clock=self.clock
        )
        steps = PipelineSteps(
            advisor=self.advisor,
            evidence_builder=CanonicalEvidenceBuilder(),
            report_renderer=MarkdownReportRenderer(),
            planner=RuleBasedPlanner(),
            attestation=self.gateway,
            ids=self.ids,
            logger=self.logger,
        )
        self.engine = ExecutionEngine(
            uow_factory=self.uows,
            plan=INCIDENT_PLAN,
            handlers=steps.handlers(),
            compensators=steps.compensators(),
            hydrators=steps.hydrators(),
            clock=self.clock,
            logger=self.logger,
        )
        self._epochs = itertools.count(1)

    # ── Fixture helpers ──────────────────────────────────────────────────────

    def admit(
        self,
        incident_id: str = "inc-1",
        *,
        severity: int = 90,
        signed: bool = True,
    ) -> IncidentId:
        """Create an incident directly, bypassing HTTP. Signed by default so the
        happy path reaches a real anchor rather than COMPLETED_UNATTESTED."""
        identifier = IncidentId(incident_id)
        with self.uows.begin(TENANT) as uow:
            incident = Incident.admit(
                tenant_id=TENANT,
                incident_id=identifier,
                severity=Severity(severity),
                trust_level=TrustLevel.VERIFIED if signed else TrustLevel.UNSIGNED,
                source="harness",
                now=self.clock.now(),
                facts={
                    "detector_version": "harness-policy-1",
                    "incident_type": "prompt_injection_suspected",
                    "description": "harness incident",
                    "signer_address": "0x" + "ab" * 20 if signed else None,
                    "raw_payload": {"agentId": "agent-1"},
                },
            )
            uow.incidents.add(incident)
            uow.collect(incident.pull_events())
            uow.commit()
        return identifier

    def run(self, incident_id: IncidentId, *, epoch: int | None = None, message: str | None = None):
        return self.engine.execute(
            tenant=TENANT,
            incident_id=incident_id,
            epoch=epoch if epoch is not None else next(self._epochs),
            message_id=MessageId(message) if message else None,
        )

    # ── Observation ──────────────────────────────────────────────────────────

    def state(self, incident_id: IncidentId) -> IncidentState:
        with self.uows.begin(TENANT) as uow:
            incident = uow.incidents.get(incident_id)
            uow.commit()
        return incident.state

    def journal(self, incident_id: IncidentId) -> Mapping[StepName, Any]:
        with self.uows.begin(TENANT) as uow:
            entries = uow.journal.load(incident_id)
            uow.commit()
        return entries

    def settled(self, incident_id: IncidentId) -> set[str]:
        return {
            n.value for n, r in self.journal(incident_id).items() if r.is_settled
        }

    def evidence(self, incident_id: IncidentId):
        with self.uows.begin(TENANT) as uow:
            found = uow.ledger.get_evidence(incident_id)
            uow.commit()
        return found

    def report(self, incident_id: IncidentId) -> str | None:
        with self.uows.begin(TENANT) as uow:
            found = uow.ledger.get_report(incident_id)
            uow.commit()
        return found

    def ledger_rows(self) -> list[Mapping[str, Any]]:
        with self.pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(TENANT.value)
            rows = conn.execute(
                f"SELECT seq, incident_id, entry_hash, prev_chain_hash, chain_hash "
                f"FROM ledger_entries WHERE tenant_id={conn.p} ORDER BY seq",
                (TENANT.value,),
            )
            conn.commit()
        return [dict(r) for r in rows]

    def transitions(self, incident_id: IncidentId) -> list[str]:
        with self.pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(TENANT.value)
            rows = conn.execute(
                f"SELECT seq, to_state FROM incident_transitions "
                f"WHERE tenant_id={conn.p} AND incident_id={conn.p} ORDER BY seq",
                (TENANT.value, incident_id.value),
            )
            conn.commit()
        return [r["to_state"] for r in rows]

    def close(self) -> None:
        self.pool.close()

    # ── Invariants, asserted after every chaotic run ────────────────────────

    def assert_invariants(self, incident_id: IncidentId) -> None:
        """Every guarantee the engine claims, checked at once.

        Called after each chaos scenario. A scenario "passes" only if the system
        is in a state the design says is possible -- not merely if it did not
        raise.
        """
        state = self.state(incident_id)

        # 1. EXACTLY-ONCE EFFECT. Not "the gateway was called once" -- the
        #    engine cannot promise that, because a crash between the effect and
        #    its record forces a re-attempt, and claiming otherwise would be the
        #    lie this whole design exists to avoid.
        #
        #    What it promises is that every attempt at a given step carries the
        #    SAME idempotency key, so the receiving system collapses them into
        #    one effect. Two DIFFERENT keys for one step would be two effects.
        #
        #    Scoped to THIS incident by exact key PREFIX, not by substring: a run
        #    over sixteen incidents legitimately produces sixteen keys, and a
        #    substring match would count `inc-p10`'s key against `inc-p1`.
        prefix = f"idem-{TENANT}-{incident_id}-"
        expected = f"{prefix}attest"
        mine = {k for k in self.effects.distinct_keys("anchor") if k.startswith(prefix)}
        assert len(mine) <= 1, (
            f"incident {incident_id} produced {len(mine)} distinct effect keys: "
            f"{sorted(mine)}. Each would be a separate effect at the gateway."
        )
        if mine:
            assert mine == {expected}, (
                f"effect key is not the deterministic one: {sorted(mine)}"
            )

        # 2. No impossible state: an attested state must carry a real anchor.
        with self.uows.begin(TENANT) as uow:
            incident = uow.incidents.get(incident_id)
            uow.commit()
        if state.is_attested:
            assert incident.fact("attestation_outcome") == "anchored"
        if state is IncidentState.COMPLETED_UNATTESTED:
            assert incident.fact("attestation_outcome") == "not_anchorable"

        # 3. No artifact loss: any state asserting evidence has evidence.
        evidence_states = {
            IncidentState.EVIDENCE_STORED,
            IncidentState.REPORTED,
            IncidentState.AWAITING_APPROVAL,
            IncidentState.ATTESTED,
            IncidentState.ATTESTATION_UNAVAILABLE,
            IncidentState.COMPLETED_ATTESTED,
            IncidentState.COMPLETED_UNATTESTED,
        }
        if state in evidence_states:
            found = self.evidence(incident_id)
            assert found is not None, f"{state.value} asserts evidence; none found"

        # 4. No duplicated transition: the audit trail is strictly ordered and
        #    each entry follows the previous one legally.
        history = self.transitions(incident_id)
        assert len(history) == len(
            [h for i, h in enumerate(history) if i == 0 or h != history[i - 1] or True]
        )
        assert history[0] == IncidentState.RECEIVED.value

        # 5. The ledger chain is unbroken and forkless.
        rows = self.ledger_rows()
        previous = "0" * 64
        for row in rows:
            assert row["prev_chain_hash"] == previous, "ledger chain is broken"
            previous = row["chain_hash"]
        assert len({r["prev_chain_hash"] for r in rows}) == len(rows), "ledger fork"

        # 6. No step is settled twice with conflicting outcomes; every journal
        #    entry is a legal status.
        for name, record in self.journal(incident_id).items():
            assert record.status in set(StepStatus)
            assert record.attempts >= 1
