"""Domain tests. No fixtures, no database, no clock — the domain is pure.

Every test here constructs its subject in one line and asserts a rule. If any of
them ever needs a fixture, the domain has grown a dependency it should not have.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from sentinel.domain import (
    AttestationDisposition,
    AttestationOutcome,
    Digest,
    ExecutionFenceLost,
    Fence,
    IllegalTransition,
    Incident,
    IncidentId,
    IncidentState,
    InvalidValue,
    MissingRequiredFact,
    Priority,
    Severity,
    TenantId,
    Timestamp,
    TrustLevel,
)

NOW = Timestamp(datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc))
TENANT = TenantId("acme")
INCIDENT = IncidentId("inc-1")
DIGEST = Digest("a" * 64)
WORKER = Fence.worker(1)


def _admitted(severity: int = 90, trust: TrustLevel = TrustLevel.VERIFIED) -> Incident:
    incident = Incident.admit(
        tenant_id=TENANT,
        incident_id=INCIDENT,
        severity=Severity(severity),
        trust_level=trust,
        source="agent-runtime",
        now=NOW,
    )
    incident.claim_execution(1)
    return incident


def _to_reported(incident: Incident) -> Incident:
    incident.advance(IncidentState.VALIDATED, fence=WORKER, now=NOW)
    incident.advance(IncidentState.IDENTITY_CHECKED, fence=WORKER, now=NOW, trust_level="verified")
    incident.advance(IncidentState.REPLAY_CHECKED, fence=WORKER, now=NOW)
    incident.advance(IncidentState.POLICY_EVALUATED, fence=WORKER, now=NOW, detector_version="p-1")
    incident.advance(IncidentState.DETECTED, fence=WORKER, now=NOW)
    incident.record_evidence(
        digest=DIGEST, uri="sentinel://e/1", ledger_sequence=1, chain_hash=DIGEST,
        fence=WORKER, now=NOW,
    )
    incident.record_report(report_bytes=100, fence=WORKER, now=NOW)
    return incident


# ── Value objects ────────────────────────────────────────────────────────────


def test_severity_is_capped_for_an_unverified_source_in_the_domain():
    """The cap the predecessor enforced on one of six HTTP routes."""
    assert Severity(100).capped_for(TrustLevel.UNSIGNED).value == 79
    assert Severity(100).capped_for(TrustLevel.VERIFIED).value == 100


def test_priority_has_exactly_one_derivation():
    assert Severity(90).priority is Priority.CRITICAL
    assert Severity(75).priority is Priority.HIGH
    assert Severity(50).priority is Priority.MEDIUM
    assert Severity(10).priority is Priority.LOW


def test_an_unverified_caller_cannot_manufacture_a_critical_incident():
    incident = _admitted(severity=100, trust=TrustLevel.UNSIGNED)
    assert incident.severity.value == 79
    assert incident.priority is Priority.HIGH
    assert incident.fact("severity_capped") is True


@pytest.mark.parametrize("bad", ["", "not hex", "A" * 63, 123])
def test_digest_rejects_anything_that_is_not_a_sha256(bad):
    with pytest.raises(InvalidValue):
        Digest(bad)


def test_distinct_id_types_do_not_compare_equal():
    """The transposition class the predecessor hit three times."""
    assert TenantId("x") != IncidentId("x")


# ── The Critical fix: COMPLETED requires a real anchor ───────────────────────


def test_a_transient_attestation_outage_cannot_reach_any_completed_state():
    """THE regression. A gateway outage must park, not complete.

    In the predecessor this produced `COMPLETED` with `is_anchored=false`,
    indistinguishable from success.
    """
    incident = _to_reported(_admitted())
    incident.record_attestation(
        AttestationOutcome(
            disposition=AttestationDisposition.UNAVAILABLE,
            detail="gateway timeout after 20s",
        ),
        fence=WORKER,
        now=NOW,
    )
    assert incident.state is IncidentState.ATTESTATION_UNAVAILABLE
    assert not incident.state.is_terminal
    assert not incident.is_attested


def test_an_unavailable_incident_resumes_and_can_still_be_attested():
    incident = _to_reported(_admitted())
    incident.record_attestation(
        AttestationOutcome(AttestationDisposition.UNAVAILABLE, "gateway timeout"),
        fence=WORKER, now=NOW,
    )
    incident.record_attestation(
        AttestationOutcome(
            AttestationDisposition.ANCHORED, "anchored", transaction_hash="0xabc"
        ),
        fence=WORKER, now=NOW,
    )
    assert incident.state is IncidentState.ATTESTED
    incident.complete(fence=WORKER, now=NOW)
    assert incident.state is IncidentState.COMPLETED_ATTESTED
    assert incident.is_attested


def test_completed_attested_is_unreachable_without_an_anchored_outcome():
    incident = _to_reported(_admitted())
    incident.record_attestation(
        AttestationOutcome(AttestationDisposition.NOT_ANCHORABLE, "no verified identity"),
        fence=WORKER, now=NOW,
    )
    assert incident.state is IncidentState.COMPLETED_UNATTESTED
    assert not incident.is_attested


def test_an_anchored_outcome_must_carry_the_hash_that_proves_it():
    with pytest.raises(MissingRequiredFact):
        AttestationOutcome(AttestationDisposition.ANCHORED, "anchored")


def test_the_caller_cannot_choose_the_destination_of_an_attestation():
    """The destination is a property of the outcome, not an argument.

    The mapping is total and lives on the outcome, so there is no argument a
    caller could pass to send an UNAVAILABLE outcome to a completed state.
    """
    assert (
        AttestationOutcome(AttestationDisposition.UNAVAILABLE, "down").next_state_name
        == IncidentState.ATTESTATION_UNAVAILABLE.value
    )
    assert (
        AttestationOutcome(
            AttestationDisposition.NOT_ANCHORABLE, "no identity"
        ).next_state_name
        == IncidentState.COMPLETED_UNATTESTED.value
    )
    assert (
        AttestationOutcome(
            AttestationDisposition.ANCHORED, "ok", transaction_hash="0x1"
        ).next_state_name
        == IncidentState.ATTESTED.value
    )


# ── Fencing ──────────────────────────────────────────────────────────────────


def test_every_mutator_requires_a_fence_including_fail():
    """`fail()` was the predecessor's unfenced back door. It has no default now."""
    incident = _admitted()
    with pytest.raises(TypeError):
        incident.fail(reason="x", now=NOW)  # type: ignore[call-arg]


def test_a_stale_worker_cannot_write():
    incident = _admitted()
    incident.claim_execution(5)
    with pytest.raises(ExecutionFenceLost):
        incident.advance(IncidentState.VALIDATED, fence=Fence.worker(1), now=NOW)


def test_an_older_epoch_can_never_reclaim_the_fence():
    incident = _admitted()
    incident.claim_execution(9)
    with pytest.raises(ExecutionFenceLost):
        incident.claim_execution(9)
    with pytest.raises(ExecutionFenceLost):
        incident.claim_execution(2)


def test_unfenced_writes_must_state_their_justification():
    with pytest.raises(IllegalTransition):
        Fence.unfenced(reason="")
    assert Fence.unfenced(reason="retention sweep").is_fenced is False


# ── Lifecycle integrity ──────────────────────────────────────────────────────


def test_illegal_edges_are_refused():
    incident = _admitted()
    with pytest.raises(IllegalTransition):
        incident.advance(IncidentState.REPORTED, fence=WORKER, now=NOW)


def test_a_terminal_incident_cannot_be_moved():
    incident = _admitted()
    incident.fail(reason="boom", fence=WORKER, now=NOW)
    with pytest.raises(IllegalTransition):
        incident.advance(IncidentState.VALIDATED, fence=WORKER, now=NOW)


def test_evidence_may_only_be_committed_from_detected_or_investigated():
    incident = _admitted()
    with pytest.raises(IllegalTransition):
        incident.record_evidence(
            digest=DIGEST, uri="u", ledger_sequence=1, chain_hash=DIGEST,
            fence=WORKER, now=NOW,
        )


def test_awaiting_approval_never_means_waiting_for_nobody():
    incident = _to_reported(_admitted())
    with pytest.raises(MissingRequiredFact):
        incident.request_approvals(approval_ids=[], fence=WORKER, now=NOW)


def test_failure_always_carries_a_reason():
    incident = _admitted()
    with pytest.raises(MissingRequiredFact):
        incident.fail(reason="", fence=WORKER, now=NOW)


# ── Events ───────────────────────────────────────────────────────────────────


def test_the_aggregate_collects_events_rather_than_publishing_them():
    incident = _admitted()
    incident.advance(IncidentState.VALIDATED, fence=WORKER, now=NOW)
    events = incident.pull_events()
    assert [e.event_type for e in events] == ["IncidentAdmitted", "IncidentStateChanged"]
    assert incident.pull_events() == ()


def test_events_carry_a_version_from_the_first_release():
    incident = _admitted()
    assert all(e.event_version == 1 for e in incident.pull_events())


def test_completion_raises_a_completion_event_stating_whether_it_was_attested():
    incident = _to_reported(_admitted())
    incident.record_attestation(
        AttestationOutcome(AttestationDisposition.NOT_ANCHORABLE, "no identity"),
        fence=WORKER, now=NOW,
    )
    completed = [e for e in incident.pull_events() if e.event_type == "IncidentCompleted"]
    assert len(completed) == 1
    assert completed[0].payload()["attested"] is False
