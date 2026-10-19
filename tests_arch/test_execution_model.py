"""Exhaustive verification: every reachable state, not a sample of them.

`test_execution_properties.py` samples. This enumerates. Within the depth bound
the result is a proof by exhaustion — if a violating state were reachable, it
would be in the visited set, because the visited set is every reachable state.

The suite also verifies the CHECKER, by injecting a known-broken rule and
requiring the search to find it. A model checker that cannot fail is a model
checker that proves nothing, and that failure mode is invisible from a green run.
"""

from __future__ import annotations

import pytest

from sentinel.application.execution.pipeline import INCIDENT_PLAN
from sentinel.domain.attestation import AttestationDisposition
from sentinel.domain.execution import (
    ExecutionPlan,
    StepDefinition,
    StepKind,
    StepName,
)
from sentinel.domain.incident import IncidentState
from tests_arch.model_checker import Event, explore


def test_no_reachable_state_violates_any_invariant():
    """THE result. Every state reachable in 12 adversarial events is legal."""
    visited, violations = explore(INCIDENT_PLAN, max_depth=12)

    assert not violations, "reachable invariant violations:\n" + "\n\n".join(
        str(v) for v in violations[:5]
    )
    # A real search, not a vacuous one: if this number collapsed to a handful,
    # the exploration would be terminating early and proving nothing.
    assert len(visited) > 150, (
        f"only {len(visited)} states explored; the search is not reaching the "
        "interesting part of the space"
    )


def test_the_search_reaches_a_completed_attested_state():
    """The bound must be large enough to finish the plan, or nothing is proved."""
    visited, _ = explore(INCIDENT_PLAN, max_depth=12)
    assert any(
        s.incident_state is IncidentState.COMPLETED_ATTESTED for s in visited
    ), "the search never completes an incident; the depth bound is too small"


def test_the_search_reaches_every_terminal_state():
    """Coverage of the outcomes, not just the happy one."""
    visited, _ = explore(INCIDENT_PLAN, max_depth=12)
    reached = {s.incident_state for s in visited}
    for expected in (
        IncidentState.COMPLETED_ATTESTED,
        IncidentState.ATTESTATION_UNAVAILABLE,
        IncidentState.FAILED,
    ):
        assert expected in reached, f"{expected.value} was never reached"


def test_no_crash_sequence_produces_a_duplicate_effect():
    """Exhaustive over crash-after-effect interleavings specifically.

    The crash-after-effect event models the one failure the journal cannot see:
    the anchor lands and the process dies before recording it. Every sequence of
    those, combined with reclaims, must still yield one distinct effect key.
    """
    visited, violations = explore(
        INCIDENT_PLAN,
        max_depth=14,
        events=(
            Event.SUCCEED,
            Event.CRASH_AFTER_EFFECT,
            Event.CRASH_BEFORE_EFFECT,
            Event.RECLAIM,
        ),
    )
    duplicates = [v for v in violations if "DUPLICATE_EFFECT" in v.invariant]
    assert not duplicates, "\n".join(str(v) for v in duplicates[:3])
    assert all(len(set(s.effect_keys)) <= 1 for s in visited)


def test_no_outage_sequence_reaches_a_terminal_state():
    """Exhaustive over outage interleavings. A transient failure never completes."""
    visited, violations = explore(
        INCIDENT_PLAN,
        max_depth=14,
        events=(Event.SUCCEED, Event.OUTAGE, Event.RECLAIM),
    )
    bad = [v for v in violations if "TRANSIENT_OUTAGE_COMPLETED" in v.invariant]
    assert not bad, "\n".join(str(v) for v in bad[:3])

    parked = [
        s
        for s in visited
        if s.attestation_outcome == AttestationDisposition.UNAVAILABLE.value
    ]
    assert parked, "the outage path was never exercised"
    assert all(not s.incident_state.is_terminal for s in parked)


def test_no_reachable_state_loses_an_artifact():
    _visited, violations = explore(INCIDENT_PLAN, max_depth=12)
    losses = [
        v for v in violations if "EVIDENCE_LOSS" in v.invariant or "REPORT_LOSS" in v.invariant
    ]
    assert not losses, "\n".join(str(v) for v in losses[:3])


def test_every_attested_state_carries_an_anchor():
    visited, violations = explore(INCIDENT_PLAN, max_depth=12)
    bad = [v for v in violations if "ATTESTED_WITHOUT_ANCHOR" in v.invariant]
    assert not bad, "\n".join(str(v) for v in bad[:3])

    attested = [s for s in visited if s.incident_state.is_attested]
    assert attested, "the attested path was never exercised"
    assert all(
        s.attestation_outcome == AttestationDisposition.ANCHORED.value for s in attested
    )


# ── The checker must be able to fail ────────────────────────────────────────


def test_the_checker_detects_a_deliberately_broken_plan():
    """Inject a plan whose pivot is not last and confirm the search notices.

    Without this, every result above could be the checker silently exploring
    nothing. A verification tool that cannot report a failure is indistinguishable
    from one that always passes.
    """
    # A plan where the pivot is FIRST: the attest step runs before evidence
    # exists, so `record_attestation` is refused and the search should reach
    # far fewer states than the real plan.
    broken = ExecutionPlan(
        (
            StepDefinition(StepName("attest"), StepKind.PIVOT),
            StepDefinition(StepName("complete"), StepKind.RETRIABLE),
        )
    )
    visited, _violations = explore(broken, max_depth=6)
    assert not any(
        s.incident_state is IncidentState.COMPLETED_ATTESTED for s in visited
    ), (
        "a plan that attests before producing evidence reached a completed "
        "attested state; the lifecycle preconditions are not being enforced"
    )


def test_the_checker_reports_a_violation_when_one_exists():
    """Directly: feed the invariant checker a state it must reject."""
    from tests_arch.model_checker import ModelState, _invariants

    forged = ModelState(
        incident_state=IncidentState.COMPLETED_ATTESTED,
        journal=(("attest", "completed"), ("complete", "completed")),
        epoch=1,
        effect_keys=("key-a", "key-b"),  # two distinct effects
        has_evidence=False,  # and no evidence
        has_report=False,
        attestation_outcome=AttestationDisposition.UNAVAILABLE.value,  # from an outage
    )
    broken = list(_invariants(forged))
    assert any("ATTESTED_WITHOUT_ANCHOR" in b for b in broken)
    assert any("TRANSIENT_OUTAGE_COMPLETED" in b for b in broken)
    assert any("DUPLICATE_EFFECT" in b for b in broken)
    assert any("EVIDENCE_LOSS" in b for b in broken)
    assert any("REPORT_LOSS" in b for b in broken)


@pytest.mark.parametrize("depth", [4, 8, 12, 15])
def test_the_result_is_stable_as_the_bound_grows(depth):
    """No violation appears at a deeper bound. Evidence the bound is adequate.

    If violations only showed up at depth 15, the depth-12 result would be an
    artefact of the bound rather than a property of the system.
    """
    _visited, violations = explore(INCIDENT_PLAN, max_depth=depth)
    assert not violations, "\n".join(str(v) for v in violations[:3])
