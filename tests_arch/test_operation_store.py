"""Durable operations and shared controls, at the store and runner level.

Fault injection is the point of this file. The end-to-end contract shows the
happy paths over HTTP; here the storage FAILS at the worst moment -- after the
side effect has run -- and the requirement is that the outcome becomes a
reconcilable UNKNOWN, never a silent success and never a retry-inviting
refusal. On both engines.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sentinel.application.protect_controls import CircuitOpen, ToolBudgetExceeded
from sentinel.application.protect_gate import ProtectGate
from sentinel.application.tool_runner import ProtectedToolRunner
from sentinel.domain.execution_binding import issue_authorization
from sentinel.domain.operations import OperationState, OutcomeUnknown
from sentinel.domain.primitives import TrustLevel
from sentinel.infrastructure.detection import DeterministicPolicy
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.nonce_ledger import SqlNonceLedger
from sentinel.infrastructure.sql.operation_store import OperationConflict, SqlOperationStore
from sentinel.infrastructure.sql.protect_controls_store import SqlProtectControls
from tests_arch.doubles import FakeClock

TENANT = "acme"
NOW = datetime(2026, 9, 14, 12, 0, tzinfo=timezone.utc)


class _FailingReceipts:
    """A receipt store that is down. Raised AFTER the effect, by design."""

    def record(self, *args, **kwargs):
        raise RuntimeError("receipt store unavailable")


def _authorization(parameters=None, *, now=NOW):
    return issue_authorization(
        authorization_id="auth-1",
        nonce="nonce-1",
        tenant_id=TENANT,
        actor_identity="key:test",
        agent_identity="agent-1",
        tool_identity="echo",
        action="echo",
        target_resource="res",
        parameters=parameters or {"value": "approved"},
        now=now,
        policy_decision="allow",
    )


def _runner(pool, *, receipts=None, clock=None):
    clock = clock or FakeClock(NOW)
    return ProtectedToolRunner(
        gate=ProtectGate(policy=DeterministicPolicy.default(), enforce=True),
        controls=SqlProtectControls(pool=pool, clock=clock),
        clock=clock,
        operations=SqlOperationStore(pool=pool),
        receipts=receipts,
    )


# ── Post-effect storage failure ──────────────────────────────────────────────


def test_a_storage_failure_after_the_effect_is_an_unknown_outcome(migrated_pool):
    ran: list[dict] = []
    runner = _runner(migrated_pool, receipts=_FailingReceipts())
    with pytest.raises(OutcomeUnknown) as caught:
        runner.execute_bound(
            authorization=_authorization(),
            agent_id="agent-1",
            tool="echo",
            action="echo",
            resource="res",
            parameters={"value": "approved"},
            trust=TrustLevel.VERIFIED,
            side_effect=lambda params: ran.append(dict(params)) or {"ok": True},
            nonces=SqlNonceLedger(pool=migrated_pool),
            now=NOW,
            tenant=TENANT,
        )
    assert ran == [{"value": "approved"}], "the effect did run; the outcome is what is unknown"
    operation_id = caught.value.operation_id
    store = SqlOperationStore(pool=migrated_pool)
    op = store.get(TENANT, operation_id)
    assert op is not None and op.state is OperationState.UNKNOWN_AFTER_EFFECT
    assert op.started_at, "the intent must carry the clock time at which the effect started"

    # Known uncertainty is recorded immediately; the reaper must not rewrite it.
    assert store.mark_stale_pending_unknown(TENANT, now=NOW + timedelta(seconds=10), pending_deadline_seconds=900) == 0
    assert store.mark_stale_pending_unknown(TENANT, now=NOW + timedelta(seconds=1000), pending_deadline_seconds=900) == 0
    op = store.get(TENANT, operation_id)
    assert op.state is OperationState.UNKNOWN_AFTER_EFFECT and op.needs_reconciliation

    # A human settles it, with a note, and it cannot be settled twice.
    assert store.reconcile(
        TENANT, operation_id, resolved_state=OperationState.SUCCEEDED, by="key:ops",
        at=(NOW + timedelta(seconds=1100)).isoformat(), note="confirmed in the target system's audit log",
    )
    assert store.get(TENANT, operation_id).state is OperationState.SUCCEEDED
    assert not store.reconcile(
        TENANT, operation_id, resolved_state=OperationState.FAILED, by="key:ops",
        at=NOW.isoformat(), note="second opinion",
    )


def test_a_failing_effect_requires_reconciliation_without_retaining_error_text(migrated_pool):
    runner = _runner(migrated_pool)

    def explode(params):
        raise RuntimeError("upstream returned 502")

    with pytest.raises(OutcomeUnknown):
        runner.execute_bound(
            authorization=_authorization(),
            agent_id="agent-1", tool="echo", action="echo", resource="res",
            parameters={"value": "approved"}, trust=TrustLevel.VERIFIED,
            side_effect=explode, nonces=SqlNonceLedger(pool=migrated_pool), now=NOW, tenant=TENANT,
        )
    ops = SqlOperationStore(pool=migrated_pool).list(TENANT, states=(OperationState.UNKNOWN_AFTER_EFFECT,))
    assert len(ops) == 1 and "RuntimeError" in ops[0].error
    assert "502" not in ops[0].error


def test_timestamps_come_from_the_clock_at_each_event(migrated_pool):
    clock = FakeClock(NOW)
    runner = _runner(migrated_pool, clock=clock)

    def slow(params):
        clock.advance(7)
        return {"ok": True}

    _outcome, _result, receipt = runner.execute_bound(
        authorization=_authorization(),
        agent_id="agent-1", tool="echo", action="echo", resource="res",
        parameters={"value": "approved"}, trust=TrustLevel.VERIFIED,
        side_effect=slow, nonces=SqlNonceLedger(pool=migrated_pool), now=NOW, tenant=TENANT,
    )
    started = datetime.fromisoformat(receipt.started_at)
    completed = datetime.fromisoformat(receipt.completed_at)
    assert (completed - started).total_seconds() == 7
    op = SqlOperationStore(pool=migrated_pool).get(TENANT, "op-auth-1")
    assert op.state is OperationState.SUCCEEDED
    assert datetime.fromisoformat(op.completed_at) - datetime.fromisoformat(op.started_at) == timedelta(seconds=7)


def test_an_operation_id_cannot_be_reused_for_a_different_intent(migrated_pool):
    from sentinel.domain.operations import ExecutionOperation

    store = SqlOperationStore(pool=migrated_pool)
    base = dict(
        operation_id="op-x", tenant_id=TENANT, agent_identity="a", tool_identity="t",
        action="t", target_resource="r", state=OperationState.PENDING, started_at=NOW.isoformat(),
    )
    store.begin(TENANT, ExecutionOperation(parameter_digest="a" * 64, **base))
    store.begin(TENANT, ExecutionOperation(parameter_digest="a" * 64, **base))  # same intent: no-op
    with pytest.raises(OperationConflict):
        store.begin(TENANT, ExecutionOperation(parameter_digest="b" * 64, **base))


# ── Shared controls across processes and tenants ─────────────────────────────


def test_budget_and_breaker_are_shared_across_two_pools(engine_config, migrated_pool):
    """Two pools on one database stand in for two replicas."""
    other = build_engine(engine_config)
    try:
        clock = FakeClock(NOW)
        a = SqlProtectControls(pool=migrated_pool, budget_per_minute=2, circuit_threshold=2, clock=clock)
        b = SqlProtectControls(pool=other, budget_per_minute=2, circuit_threshold=2, clock=clock)
        a.assert_may_execute(agent_id="agent-1", tenant_id=TENANT)
        b.assert_may_execute(agent_id="agent-1", tenant_id=TENANT)
        with pytest.raises(ToolBudgetExceeded):
            a.assert_may_execute(agent_id="agent-1", tenant_id=TENANT)
        with pytest.raises(ToolBudgetExceeded):
            b.assert_may_execute(agent_id="agent-1", tenant_id=TENANT)

        # Failures recorded on one replica open the breaker on the other.
        a.record_failure(agent_id="agent-2", tenant_id=TENANT)
        b.record_failure(agent_id="agent-2", tenant_id=TENANT)
        with pytest.raises(CircuitOpen):
            a.assert_may_execute(agent_id="agent-2", tenant_id=TENANT)
        # After the cooldown the breaker is half-open and a call may try.
        clock.advance(31)
        a.assert_may_execute(agent_id="agent-2", tenant_id=TENANT)
    finally:
        other.close()


def test_controls_are_keyed_by_tenant_and_refuse_an_empty_tenant(migrated_pool):
    controls = SqlProtectControls(pool=migrated_pool, budget_per_minute=1, clock=FakeClock(NOW))
    controls.assert_may_execute(agent_id="agent-1", tenant_id="acme")
    with pytest.raises(ToolBudgetExceeded):
        controls.assert_may_execute(agent_id="agent-1", tenant_id="acme")
    controls.assert_may_execute(agent_id="agent-1", tenant_id="globex")
    with pytest.raises(ValueError):
        controls.assert_may_execute(agent_id="agent-1", tenant_id="")


def test_an_unavailable_control_store_refuses_rather_than_allows(migrated_pool):
    from sentinel.infrastructure.sql.protect_controls_store import ControlStateUnavailable

    class _DeadPool:
        def acquire(self):
            raise ControlStateUnavailable("database gone")

    controls = SqlProtectControls(pool=_DeadPool(), budget_per_minute=1, clock=FakeClock(NOW))
    with pytest.raises(ControlStateUnavailable):
        controls.assert_may_execute(agent_id="agent-1", tenant_id="acme")
