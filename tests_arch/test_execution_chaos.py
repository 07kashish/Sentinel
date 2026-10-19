"""Chaos tests: fail at every point, then assert the invariants still hold.

The question a chaos test answers is not "does the happy path work" but "is every
state the system can be left in by an arbitrary failure a state the design says
is possible". Each scenario kills the engine at a specific, adversarially chosen
moment and then runs `Harness.assert_invariants`, which checks all six
guarantees at once.

The moments are chosen to be the ones that are actually hard:

  * between an external effect and the record of it (the only gap the journal
    cannot close on its own)
  * between a step's durable intent and its outcome
  * during the saga unwind itself
  * repeatedly, so recovery is exercised from a recovering state
"""

from __future__ import annotations

import pytest

from sentinel.domain.attestation import AttestationDisposition
from sentinel.domain.errors import ArtifactMissing
from sentinel.domain.execution import StepName, StepStatus
from sentinel.domain.incident import IncidentState
from sentinel.infrastructure.sql.work_queue import SqlWorkQueue
from tests_arch.harness import EffectLog, Harness, ScriptedGateway, TransientAdvisor, TENANT


@pytest.fixture
def harness(tmp_path, engine_config):
    """Runs on EVERY backend. See `conftest.engine_config`."""
    h = Harness(tmp_path, engine_config=engine_config)
    yield h
    h.close()


# ── Baseline: the happy path, so a chaos failure is attributable ────────────


def test_a_clean_run_reaches_completed_attested(harness):
    incident = harness.admit()
    outcome = harness.run(incident)
    assert outcome.accepted
    assert harness.state(incident) is IncidentState.COMPLETED_ATTESTED
    assert harness.settled(incident) == set(n.value for n in harness.engine.plan.names)
    assert len(harness.effects.keys("anchor")) == 1
    harness.assert_invariants(incident)


# ── Crash between the effect and its record ─────────────────────────────────


def test_a_crash_after_the_anchor_never_anchors_twice(tmp_path, engine_config):
    """THE hardest case in the whole system.

    The gateway applies the anchor and the connection dies before the caller
    learns anything. The journal row stays RUNNING, so the next attempt knows the
    effect MAY have happened; it re-runs the step with the SAME deterministic
    idempotency key, and the receiving system collapses the duplicate.

    With a gateway that can report what it already applied, the retry does not
    re-send at all: it reconciles, adopts the recorded outcome, and completes.
    That is strictly stronger than re-sending under a stable key, and it is why
    `reconcile` exists.

    The weaker guarantee -- re-send under ONE key -- is asserted by
    `test_a_gateway_that_cannot_reconcile_still_converges`, which models a
    gateway that cannot answer.
    """
    effects = EffectLog()
    gateway = ScriptedGateway(effects=effects, crash_after_effect=0, remembers=True)
    harness = Harness(tmp_path, engine_config=engine_config, gateway=gateway)
    try:
        incident = harness.admit()

        with pytest.raises(Exception):
            harness.run(incident, epoch=1)

        # The effect was applied; nothing recorded it.
        assert len(effects.keys("anchor")) == 1
        journal = harness.journal(incident)
        assert journal[StepName("attest")].status is StepStatus.RUNNING
        assert not harness.state(incident).is_terminal

        # Recovery at a new epoch.
        harness.run(incident, epoch=2)

        assert harness.state(incident) is IncidentState.COMPLETED_ATTESTED
        applied = effects.keys("anchor")
        assert len(applied) == 1, (
            "the retry re-sent the anchor instead of reconciling it"
        )
        assert len(set(applied)) == 1
        harness.assert_invariants(incident)
    finally:
        harness.close()


def test_repeated_crashes_still_converge_on_one_effect(tmp_path, engine_config):
    """Five interrupted attempts, then success. Still ONE logical effect.

    Modelled against a gateway that CANNOT reconcile (`remembers=False`), so
    every attempt genuinely re-sends. That is the harder case: convergence rests
    entirely on the idempotency key being deterministic across epochs.
    """
    effects = EffectLog()
    gateway = ScriptedGateway(effects=effects, crash_after_effect=-1, remembers=False)
    harness = Harness(tmp_path, engine_config=engine_config, gateway=gateway)
    try:
        incident = harness.admit()
        for attempt in range(5):
            gateway.crash_after_effect = gateway.calls
            with pytest.raises(Exception):
                harness.run(incident, epoch=attempt + 1)
            harness.assert_invariants(incident)

        gateway.crash_after_effect = -1
        harness.run(incident, epoch=99)

        assert harness.state(incident) is IncidentState.COMPLETED_ATTESTED
        assert len(effects.distinct_keys("anchor")) == 1
        harness.assert_invariants(incident)
    finally:
        harness.close()


# ── Transient outages ────────────────────────────────────────────────────────


def test_a_transient_outage_parks_and_never_completes(tmp_path, engine_config):
    harness = Harness(
        tmp_path,
        engine_config=engine_config,
        gateway=ScriptedGateway(
            effects=EffectLog(), default=AttestationDisposition.UNAVAILABLE
        ),
    )
    try:
        incident = harness.admit()
        for epoch in range(1, 6):
            harness.run(incident, epoch=epoch)
            state = harness.state(incident)
            assert state is IncidentState.ATTESTATION_UNAVAILABLE
            assert not state.is_terminal
            assert not state.is_attested
            harness.assert_invariants(incident)
    finally:
        harness.close()


def test_an_outage_that_clears_completes_normally(tmp_path, engine_config):
    effects = EffectLog()
    gateway = ScriptedGateway(
        effects=effects,
        script=[AttestationDisposition.UNAVAILABLE] * 3,
        default=AttestationDisposition.ANCHORED,
    )
    harness = Harness(tmp_path, engine_config=engine_config, gateway=gateway)
    try:
        incident = harness.admit()
        for epoch in range(1, 4):
            harness.run(incident, epoch=epoch)
            assert harness.state(incident) is IncidentState.ATTESTATION_UNAVAILABLE

        harness.run(incident, epoch=4)
        assert harness.state(incident) is IncidentState.COMPLETED_ATTESTED
        assert len(effects.distinct_keys("anchor")) == 1
        harness.assert_invariants(incident)
    finally:
        harness.close()


def test_a_parked_duplicate_message_does_not_prevent_requeued_recovery(
    tmp_path, engine_config
):
    effects = EffectLog()
    gateway = ScriptedGateway(
        effects=effects,
        default=AttestationDisposition.UNAVAILABLE,
    )
    harness = Harness(tmp_path, engine_config=engine_config, gateway=gateway)
    try:
        incident = harness.admit()
        harness.run(incident, epoch=1, message="work-1")

        gateway.default = AttestationDisposition.ANCHORED
        duplicate = harness.run(incident, epoch=2, message="work-1")
        assert not duplicate.accepted
        assert harness.state(incident) is IncidentState.ATTESTATION_UNAVAILABLE

        recovered = harness.run(incident, epoch=3, message="work-2")
        assert recovered.accepted
        assert harness.state(incident) is IncidentState.COMPLETED_ATTESTED
        harness.assert_invariants(incident)
    finally:
        harness.close()


def test_parked_attestations_are_reenqueued_after_backoff(tmp_path, engine_config):
    harness = Harness(
        tmp_path,
        engine_config=engine_config,
        gateway=ScriptedGateway(
            effects=EffectLog(), default=AttestationDisposition.UNAVAILABLE
        ),
    )
    try:
        incident = harness.admit()
        harness.run(incident, epoch=1, message="work-1")
        harness.clock.advance(60)

        queue = SqlWorkQueue(pool=harness.pool, shard_count=1, worker_id="reaper-test")
        assert (
            queue.reenqueue_parked_attestations(
                tenants=(TENANT,),
                now=harness.clock.now(),
                older_than_seconds=10,
            )
            == 1
        )

        claimed = queue.claim(shard=0, shard_count=1, now=harness.clock.now())
        assert claimed is not None
        assert claimed.incident_id == incident
    finally:
        harness.close()


def test_an_advisory_outage_is_never_fatal(tmp_path, engine_config):
    harness = Harness(tmp_path, engine_config=engine_config, advisor=TransientAdvisor(failures=99))
    try:
        incident = harness.admit()
        harness.run(incident)
        assert harness.state(incident) is IncidentState.COMPLETED_ATTESTED
        harness.assert_invariants(incident)
    finally:
        harness.close()


# ── Artifact destruction ─────────────────────────────────────────────────────


def test_destroying_evidence_mid_run_halts_rather_than_producing_a_false_success(
    tmp_path, engine_config
):
    """The predecessor's exact defect, reproduced adversarially.

    Delete the evidence row after it is written and resume. A system that
    proceeded would attest nothing and report success. This one refuses to
    continue on a lie about its own state.
    """
    harness = Harness(
        tmp_path,
        engine_config=engine_config,
        gateway=ScriptedGateway(
            effects=EffectLog(), default=AttestationDisposition.UNAVAILABLE
        ),
    )
    try:
        incident = harness.admit()
        harness.run(incident, epoch=1)
        assert harness.evidence(incident) is not None

        with harness.pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(TENANT.value)
            conn.execute_rowcount(
                f"DELETE FROM evidence WHERE tenant_id={conn.p} AND incident_id={conn.p}",
                (TENANT.value, incident.value),
            )
            conn.commit()

        with pytest.raises(ArtifactMissing):
            harness.run(incident, epoch=2)

        # No false success, and no anchor published without evidence.
        assert not harness.state(incident).is_attested
        assert not harness.effects.duplicates
    finally:
        harness.close()


def test_a_withdrawn_report_is_detected_on_resume(tmp_path, engine_config):
    harness = Harness(
        tmp_path,
        engine_config=engine_config,
        gateway=ScriptedGateway(
            effects=EffectLog(), default=AttestationDisposition.UNAVAILABLE
        ),
    )
    try:
        incident = harness.admit()
        harness.run(incident, epoch=1)
        assert harness.report(incident) is not None

        with harness.uows.begin(TENANT) as uow:
            uow.ledger.withdraw_report(
                incident_id=incident, reason="chaos", at=harness.clock.now()
            )
            uow.commit()

        with pytest.raises(ArtifactMissing):
            harness.run(incident, epoch=2)
    finally:
        harness.close()


# ── Redelivery ───────────────────────────────────────────────────────────────


def test_redelivery_of_the_same_message_does_no_work_twice(harness):
    incident = harness.admit()
    first = harness.run(incident, epoch=1, message="msg-1")
    second = harness.run(incident, epoch=2, message="msg-1")

    assert first.accepted
    assert not second.accepted, "the inbox must recognise a redelivery"
    assert len(harness.effects.keys("anchor")) == 1
    harness.assert_invariants(incident)


def test_a_new_message_for_a_finished_incident_is_a_no_op(harness):
    incident = harness.admit()
    harness.run(incident, epoch=1, message="msg-1")
    before = len(harness.effects.keys("anchor"))

    result = harness.run(incident, epoch=2, message="msg-2")

    assert result.accepted, "a NEW message is accepted by the inbox"
    assert result.executed == (), "but a terminal incident has no work left"
    assert len(harness.effects.keys("anchor")) == before
    harness.assert_invariants(incident)


def test_replaying_a_completed_run_executes_nothing(harness):
    incident = harness.admit()
    harness.run(incident, epoch=1)
    settled_before = harness.settled(incident)
    transitions_before = harness.transitions(incident)

    for epoch in range(2, 6):
        outcome = harness.run(incident, epoch=epoch)
        assert outcome.executed == ()

    assert harness.settled(incident) == settled_before
    assert harness.transitions(incident) == transitions_before, (
        "a replay must not append duplicate transitions"
    )
    harness.assert_invariants(incident)


# ── Saga unwind ──────────────────────────────────────────────────────────────


def test_a_deterministic_failure_before_the_pivot_unwinds(tmp_path, engine_config):
    """Break a compensatable step and confirm the saga unwinds in reverse."""
    harness = Harness(tmp_path, engine_config=engine_config)
    try:
        incident = harness.admit()

        # Force a deterministic failure at `approvals`, which is the last
        # compensatable step before the pivot.
        def explode(ctx):
            raise ArtifactMissing("chaos: approvals cannot be proposed")

        harness.engine._handlers[StepName("approvals")] = explode  # noqa: SLF001

        harness.run(incident, epoch=1)

        assert harness.state(incident) is IncidentState.FAILED
        journal = harness.journal(incident)
        assert journal[StepName("approvals")].status is StepStatus.FAILED
        # Everything completed before it was compensated.
        for name in ("evidence", "report", "detect"):
            assert journal[StepName(name)].status is StepStatus.COMPENSATED

        # The evidence body is gone; the ledger commitment is not.
        evidence = harness.evidence(incident)
        assert evidence is not None and evidence.is_redacted
        rows = harness.ledger_rows()
        assert rows, "the ledger entry survives compensation"
        assert not harness.effects.keys("anchor"), "the pivot was never reached"
        harness.assert_invariants(incident)
    finally:
        harness.close()


def test_a_failure_after_the_pivot_never_unwinds(tmp_path, engine_config):
    """Past the point of no return the saga may only go forward.

    Compensating here would promise to withdraw an anchor that cannot be
    withdrawn, so the engine records the failure and leaves the completed steps
    completed.
    """
    harness = Harness(tmp_path, engine_config=engine_config)
    try:
        incident = harness.admit()

        def explode(ctx):
            raise ArtifactMissing("chaos: completion is broken")

        harness.engine._handlers[StepName("complete")] = explode  # noqa: SLF001

        harness.run(incident, epoch=1)

        journal = harness.journal(incident)
        assert journal[StepName("attest")].status is StepStatus.COMPLETED
        assert journal[StepName("complete")].status is StepStatus.FAILED
        # NOTHING was compensated: the pivot forbids it.
        assert not any(
            r.status is StepStatus.COMPENSATED for r in journal.values()
        ), "a step was unwound after the pivot"
        assert len(harness.effects.keys("anchor")) == 1
        harness.assert_invariants(incident)
    finally:
        harness.close()


def test_a_compensation_that_itself_fails_does_not_abort_the_unwind(tmp_path, engine_config):
    """One failed compensation must not strand the others.

    Abandoning the unwind half-way leaves a worse state than either finishing it
    or never starting, so the failure is recorded per step and the remaining
    compensations still run.
    """
    harness = Harness(tmp_path, engine_config=engine_config)
    try:
        incident = harness.admit()

        def explode(ctx):
            raise ArtifactMissing("chaos: approvals broken")

        def bad_compensation(ctx, result):
            raise RuntimeError("chaos: this compensation is broken")

        harness.engine._handlers[StepName("approvals")] = explode  # noqa: SLF001
        harness.engine._compensators[StepName("report")] = bad_compensation  # noqa: SLF001

        harness.run(incident, epoch=1)

        journal = harness.journal(incident)
        # The broken one is left COMPENSATING -- durable intent recorded, effect
        # unconfirmed. That is strictly more informative than reverting it to
        # COMPLETED, which would claim the unwind was never attempted, and it is
        # the state an operator needs to see.
        assert journal[StepName("report")].status is StepStatus.COMPENSATING
        # The ones around it still unwound: one failure does not abort the rest.
        assert journal[StepName("evidence")].status is StepStatus.COMPENSATED
        assert "compensation_failed" in harness.logger.events("error")
        harness.assert_invariants(incident)
    finally:
        harness.close()


# ── Interleaved chaos ────────────────────────────────────────────────────────


@pytest.mark.parametrize("crash_at", [0, 1, 2])
def test_the_system_is_recoverable_from_any_crash_point(tmp_path, engine_config, crash_at):
    """Crash at the Nth gateway call, then recover. Always converges."""
    effects = EffectLog()
    gateway = ScriptedGateway(
        effects=effects,
        script=[AttestationDisposition.UNAVAILABLE] * crash_at,
        default=AttestationDisposition.ANCHORED,
        crash_after_effect=crash_at,
    )
    harness = Harness(tmp_path, engine_config=engine_config, gateway=gateway)
    try:
        incident = harness.admit()
        for epoch in range(1, crash_at + 2):
            try:
                harness.run(incident, epoch=epoch)
            except Exception:  # noqa: BLE001 - the crash is the point
                pass
            harness.assert_invariants(incident)

        gateway.crash_after_effect = -1
        harness.run(incident, epoch=50)

        assert harness.state(incident) is IncidentState.COMPLETED_ATTESTED
        assert len(effects.distinct_keys("anchor")) == 1
        harness.assert_invariants(incident)
    finally:
        harness.close()


# ── Reconciliation: closing the crash-between-effect-and-record gap ─────────


def test_a_reconciling_gateway_is_asked_before_the_anchor_is_re_sent(tmp_path, engine_config):
    """The last gap in exactly-once, closed by asking instead of assuming.

    A crash after the anchor leaves the journal RUNNING. The retry knows the
    effect MAY have landed, so it RECONCILES: it asks the gateway what was
    already applied under this key and adopts that outcome, rather than sending
    a second request and relying on the gateway to collapse it.
    """
    effects = EffectLog()
    gateway = ScriptedGateway(effects=effects, crash_after_effect=0, remembers=True)
    harness = Harness(tmp_path, engine_config=engine_config, gateway=gateway)
    try:
        incident = harness.admit()
        with pytest.raises(Exception):
            harness.run(incident, epoch=1)
        assert len(effects.keys("anchor")) == 1

        harness.run(incident, epoch=2)

        assert harness.state(incident) is IncidentState.COMPLETED_ATTESTED
        # The gateway was NOT called a second time: the retry reconciled.
        assert len(effects.keys("anchor")) == 1, (
            "the anchor was re-sent even though the gateway could report it"
        )
        assert "attestation_reconciled" in harness.logger.events("info")
        harness.assert_invariants(incident)
    finally:
        harness.close()


def test_a_gateway_that_cannot_reconcile_still_converges(tmp_path, engine_config):
    """The fallback path: re-send under the same key.

    Not every gateway can answer "what did you already do under this key". When
    it cannot, the engine re-sends -- which is still correct, because the key is
    deterministic and the receiving system deduplicates. This asserts the
    fallback is exercised and still yields ONE logical effect.
    """
    effects = EffectLog()
    gateway = ScriptedGateway(effects=effects, crash_after_effect=0, remembers=False)
    harness = Harness(tmp_path, engine_config=engine_config, gateway=gateway)
    try:
        incident = harness.admit()
        with pytest.raises(Exception):
            harness.run(incident, epoch=1)
        harness.run(incident, epoch=2)

        assert harness.state(incident) is IncidentState.COMPLETED_ATTESTED
        assert len(effects.keys("anchor")) == 2, "the fallback re-sends"
        assert len(effects.distinct_keys("anchor")) == 1, "under ONE key"
        harness.assert_invariants(incident)
    finally:
        harness.close()


def test_reconciliation_is_not_consulted_on_a_first_attempt(tmp_path, engine_config):
    """A step running for the first time has nothing to reconcile.

    Asking on every attempt would double the request count on the happy path for
    no benefit, so `reentry` gates it.
    """
    effects = EffectLog()
    gateway = ScriptedGateway(effects=effects, remembers=True)
    harness = Harness(tmp_path, engine_config=engine_config, gateway=gateway)
    try:
        incident = harness.admit()
        harness.run(incident, epoch=1)
        assert harness.state(incident) is IncidentState.COMPLETED_ATTESTED
        assert "attestation_reconciled" not in harness.logger.events("info")
        assert len(effects.keys("anchor")) == 1
    finally:
        harness.close()
