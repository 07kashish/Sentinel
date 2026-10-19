"""Application-layer tests with NO database, network, framework or patching.

Every collaborator is constructed and passed in. If any test here ever needs
`monkeypatch`, a global reset, or an environment variable, the architecture has
regressed.

The engine is exercised over in-memory doubles here and over real SQL in
`test_execution_chaos.py`. Both matter: this suite is fast enough to run on every
keystroke, and the SQL suite is the one that would catch a defect that only
appears with real transactions.
"""

from __future__ import annotations

import pytest

from sentinel.application.commands.admit_event import AdmitEvent, AdmitEventHandler
from sentinel.application.execution.engine import ExecutionEngine
from sentinel.application.execution.handler import ProcessIncident, ProcessIncidentHandler
from sentinel.application.execution.pipeline import INCIDENT_PLAN, PipelineSteps
from sentinel.domain.errors import ArtifactMissing, ExecutionFenceLost
from sentinel.domain.execution import StepStatus
from sentinel.domain.incident import AttestationDisposition, IncidentState
from sentinel.domain.primitives import IncidentId, MessageId, TenantId
from sentinel.infrastructure.evidence import (
    CanonicalEvidenceBuilder,
    MarkdownReportRenderer,
    RuleBasedPlanner,
)
from tests_arch.doubles import (
    FakeAgentRegistry,
    FakeAttestationGateway,
    FakeClock,
    FakeDetectionPolicy,
    FakeIdentityVerifier,
    FakeIds,
    FakeModelAdvisor,
    FakeReplayGuard,
    InMemoryStore,
    InMemoryUnitOfWorkFactory,
    InMemoryWorkQueue,
    RecordingLogger,
)

TENANT = TenantId("acme")
SIGNER = "0x" + "ab" * 20


class World:
    """A fully wired application, assembled by hand in a dozen lines."""

    def __init__(
        self,
        *,
        disposition: AttestationDisposition = AttestationDisposition.ANCHORED,
        severity: int = 90,
        advisor_fails: bool = False,
    ) -> None:
        self.store = InMemoryStore()
        self.clock = FakeClock()
        self.ids = FakeIds()
        self.logger = RecordingLogger()
        self.uows = InMemoryUnitOfWorkFactory(self.store, self.ids)
        self.queue = InMemoryWorkQueue(self.store, self.ids)
        self.gateway = FakeAttestationGateway(
            disposition=disposition, effects=self.store.effects
        )
        self.advisor = FakeModelAdvisor(fail=advisor_fails)
        self.replay = FakeReplayGuard()

        self.admit = AdmitEventHandler(
            uow_factory=self.uows,
            agents=FakeAgentRegistry({TENANT.value: [SIGNER]}),
            identity=FakeIdentityVerifier({"sig-good": SIGNER}),
            replay=self.replay,
            policy=FakeDetectionPolicy(severity=severity),
            queue=self.queue,
            clock=self.clock,
            ids=self.ids,
            logger=self.logger,
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
        self.process = ProcessIncidentHandler(engine=self.engine, logger=self.logger)

    def admit_signed(self) -> IncidentId:
        result = self.admit.handle(
            AdmitEvent(
                tenant=TENANT,
                payload={
                    "agentId": "a1",
                    "action": "read /etc/passwd",
                    "timestamp": "2026-07-25T12:00:00+00:00",
                },
                signature="sig-good",
                source="agent-runtime",
            )
        )
        assert result.ok, result.detail
        return IncidentId(result.detail["incident_id"])

    def run(self, incident_id: IncidentId, *, epoch: int = 1, message: str | None = None):
        return self.process.handle(
            ProcessIncident(
                tenant=TENANT,
                incident_id=incident_id,
                lease_epoch=epoch,
                message_id=MessageId(message) if message else None,
            )
        )

    def incident(self, incident_id: IncidentId):
        return self.store.incidents[(TENANT.value, incident_id.value)]

    def journal(self, incident_id: IncidentId):
        return {
            step: record
            for (tenant, inc, step), record in self.store.journal.items()
            if tenant == TENANT.value and inc == incident_id.value
        }


# ── Admission: the single path ───────────────────────────────────────────────


def test_a_signed_event_is_admitted_and_enqueued_in_one_transaction():
    world = World()
    incident_id = world.admit_signed()
    assert (TENANT.value, incident_id.value) in world.store.incidents
    assert len(world.store.queue) == 1


def test_an_unsigned_event_cannot_manufacture_a_critical_incident():
    world = World(severity=100)
    result = world.admit.handle(
        AdmitEvent(tenant=TENANT, payload={"agentId": "a1"}, signature=None, source="http")
    )
    assert result.detail["severity"] == 79
    assert result.detail["priority"] == "HIGH"
    assert result.detail["severity_capped"] is True


def test_a_verified_event_may_reach_critical():
    world = World(severity=100)
    result = world.admit.handle(
        AdmitEvent(tenant=TENANT, payload={"agentId": "a1"}, signature="sig-good", source="h")
    )
    assert result.detail["severity"] == 100
    assert result.detail["priority"] == "CRITICAL"


def test_a_replayed_signed_event_is_refused_and_writes_no_incident():
    world = World()
    payload = {"agentId": "a1", "action": "x"}
    first = world.admit.handle(
        AdmitEvent(tenant=TENANT, payload=payload, signature="sig-good", source="s")
    )
    second = world.admit.handle(
        AdmitEvent(tenant=TENANT, payload=payload, signature="sig-good", source="s")
    )
    assert first.ok and not second.ok
    assert second.outcome == "replay_rejected"
    assert len(world.store.incidents) == 1


def test_a_non_firing_policy_creates_no_incident():
    world = World()
    world.admit._policy = FakeDetectionPolicy(fired=False)  # noqa: SLF001
    result = world.admit.handle(
        AdmitEvent(tenant=TENANT, payload={"agentId": "a"}, signature=None, source="s")
    )
    assert result.ok and result.outcome == "no_incident"
    assert not world.store.incidents


# ── The engine ───────────────────────────────────────────────────────────────


def test_a_full_run_settles_every_step_and_completes():
    world = World()
    incident_id = world.admit_signed()
    result = world.run(incident_id)

    assert result.ok
    assert world.incident(incident_id).state is IncidentState.COMPLETED_ATTESTED
    settled = {
        step for step, record in world.journal(incident_id).items() if record.is_settled
    }
    assert settled == {n.value for n in INCIDENT_PLAN.names}


def test_a_transient_outage_parks_the_step_unsettled():
    """The attest step stays RUNNING so the next delivery re-enters it."""
    world = World(disposition=AttestationDisposition.UNAVAILABLE)
    incident_id = world.admit_signed()
    world.run(incident_id)

    incident = world.incident(incident_id)
    assert incident.state is IncidentState.ATTESTATION_UNAVAILABLE
    assert not incident.state.is_terminal
    assert world.journal(incident_id)["attest"].status is StepStatus.RUNNING


def test_the_resumed_run_hydrates_and_anchors():
    world = World(disposition=AttestationDisposition.UNAVAILABLE)
    incident_id = world.admit_signed()
    world.run(incident_id, epoch=1)

    world.gateway.disposition = AttestationDisposition.ANCHORED
    world.run(incident_id, epoch=2)

    assert world.incident(incident_id).state is IncidentState.COMPLETED_ATTESTED
    assert len(set(world.store.effects)) == 1, "one logical effect across both runs"


def test_a_replay_executes_nothing():
    world = World()
    incident_id = world.admit_signed()
    world.run(incident_id, epoch=1)
    before = len(world.store.effects)

    result = world.run(incident_id, epoch=2)

    assert result.detail["executed"] == []
    assert len(world.store.effects) == before


def test_a_missing_artifact_halts_rather_than_producing_a_false_success():
    world = World(disposition=AttestationDisposition.UNAVAILABLE)
    incident_id = world.admit_signed()
    world.run(incident_id, epoch=1)

    del world.store.evidence[(TENANT.value, incident_id.value)]

    with pytest.raises(ArtifactMissing):
        world.run(incident_id, epoch=2)
    assert not world.incident(incident_id).state.is_attested


def test_a_stale_worker_is_refused_on_a_live_incident():
    world = World(disposition=AttestationDisposition.UNAVAILABLE)
    incident_id = world.admit_signed()
    world.run(incident_id, epoch=5)
    assert not world.incident(incident_id).is_terminal

    with pytest.raises(ExecutionFenceLost):
        world.run(incident_id, epoch=2)


def test_an_unsigned_incident_completes_unattested_and_says_so():
    world = World()
    result = world.admit.handle(
        AdmitEvent(tenant=TENANT, payload={"agentId": "a"}, signature=None, source="s")
    )
    incident_id = IncidentId(result.detail["incident_id"])
    world.run(incident_id)
    incident = world.incident(incident_id)
    assert incident.state is IncidentState.COMPLETED_UNATTESTED
    assert not incident.is_attested


# ── Inbox ────────────────────────────────────────────────────────────────────


def test_a_redelivered_message_does_no_work_twice():
    world = World()
    incident_id = world.admit_signed()
    first = world.run(incident_id, epoch=1, message="m-1")
    second = world.run(incident_id, epoch=2, message="m-1")

    assert first.outcome == "processed"
    assert second.outcome == "duplicate_delivery"
    assert len(world.store.effects) == 1


def test_a_transiently_failed_work_id_is_not_accepted_before_it_parks():
    world = World(disposition=AttestationDisposition.UNAVAILABLE)
    incident_id = world.admit_signed()

    first = world.run(incident_id, epoch=1, message="m-transient")
    duplicate = world.run(incident_id, epoch=2, message="m-transient")

    assert first.outcome == "processed"
    assert duplicate.outcome == "duplicate_delivery"
    assert world.incident(incident_id).state is IncidentState.ATTESTATION_UNAVAILABLE

    world.gateway.disposition = AttestationDisposition.ANCHORED
    resumed = world.run(incident_id, epoch=3, message="m-requeued")

    assert resumed.outcome == "processed"
    assert world.incident(incident_id).state is IncidentState.COMPLETED_ATTESTED


# ── The advisory boundary ────────────────────────────────────────────────────


def test_the_advisor_cannot_move_priority():
    world = World(severity=50)
    incident_id = world.admit_signed()
    world.run(incident_id)
    incident = world.incident(incident_id)
    assert incident.priority.value == "MEDIUM"
    assert incident.fact("advisory_priority") == "HIGH"
    assert incident.fact("priority_basis") == "deterministic_policy"


def test_an_advisor_outage_is_never_fatal():
    world = World(advisor_fails=True)
    incident_id = world.admit_signed()
    result = world.run(incident_id)
    assert result.ok
    assert world.incident(incident_id).state is IncidentState.COMPLETED_ATTESTED
    assert world.incident(incident_id).fact("advisory_available") is False


# ── Events ───────────────────────────────────────────────────────────────────


def test_events_are_published_only_on_commit():
    world = World()
    incident_id = world.admit_signed()
    world.run(incident_id)
    published = [e.event_type for _, e in world.store.published]
    assert "IncidentAdmitted" in published
    assert "EvidenceStored" in published
    assert "AttestationRecorded" in published
    assert "IncidentCompleted" in published


def test_every_published_event_is_scoped_to_its_tenant():
    world = World()
    incident_id = world.admit_signed()
    world.run(incident_id)
    assert {tenant for tenant, _ in world.store.published} == {TENANT.value}
