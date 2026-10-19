"""F-11: approved remediation goes through ProtectedToolRunner."""

from __future__ import annotations

from datetime import datetime, timezone

from sentinel.application.commands.decide_approval import DecideApproval, DecideApprovalHandler
from sentinel.application.protect_gate import ProtectGate
from sentinel.application.records import ApprovalRecord
from sentinel.application.tool_runner import ProtectedToolRunner
from sentinel.domain.primitives import (
    ApprovalId,
    IdempotencyKey,
    IncidentId,
    TenantId,
    Timestamp,
)
from sentinel.infrastructure.detection import DeterministicPolicy
from tests_arch.doubles import FakeClock, FakeIds, InMemoryStore, InMemoryUnitOfWorkFactory, RecordingLogger

NOW = Timestamp(datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc))
TENANT = TenantId("acme")


class _RecordingExecutor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def supports(self, action: str) -> bool:
        return True

    def execute(
        self,
        *,
        action: str,
        target: str,
        idempotency_key: IdempotencyKey,
        tenant: str = "",
    ):
        self.calls.append((action, target))
        return {"executed": True, "action": action, "target": target}


class _MemoryNonceLedger:
    """A single-process `NonceLedger` for the handler under test.

    The handler's DEFAULT is `RejectingNonceLedger`, which claims nothing --
    so a construction site that forgets the shared ledger refuses every
    approval with `replayed` rather than silently protecting nothing across
    replicas. That default is right for production and wrong for a test that
    wants to see the integration run, so the test supplies a ledger that
    actually claims.
    """

    def __init__(self) -> None:
        self.used: set[tuple[str, str]] = set()

    def claim(self, *, tenant_id: str, nonce: str) -> bool:
        key = (tenant_id, nonce)
        if key in self.used:
            return False
        self.used.add(key)
        return True


def _handler(executor, *, enforce: bool) -> tuple[DecideApprovalHandler, InMemoryUnitOfWorkFactory]:
    uows = InMemoryUnitOfWorkFactory(InMemoryStore())
    gate = ProtectGate(policy=DeterministicPolicy.default(), enforce=enforce)
    handler = DecideApprovalHandler(
        uow_factory=uows,
        executor=executor,
        tool_runner=ProtectedToolRunner(gate=gate),
        clock=FakeClock(),
        ids=FakeIds(),
        logger=RecordingLogger(),
        nonces=_MemoryNonceLedger(),
    )
    return handler, uows


def _seed(uows: InMemoryUnitOfWorkFactory, *, action: str, target: str) -> ApprovalId:
    approval_id = ApprovalId("apr-test-0001")
    with uows.begin(TENANT) as uow:
        uow.approvals.propose(
            [
                ApprovalRecord(
                    approval_id=approval_id,
                    incident_id=IncidentId("inc-test-0001"),
                    action=action,
                    target=target,
                    state="pending",
                    proposed_at=NOW,
                )
            ]
        )
        uow.commit()
    return approval_id


def test_benign_approved_remediation_executes_via_tool_runner():
    executor = _RecordingExecutor()
    handler, uows = _handler(executor, enforce=True)
    approval_id = _seed(uows, action="notify_analyst", target="pager:oncall")

    result = handler.handle(
        DecideApproval(
            tenant=TENANT,
            approval_id=approval_id,
            decision="approve",
            decided_by="analyst:1",
        )
    )
    assert result.ok
    assert executor.calls == [("notify_analyst", "pager:oncall")]


def test_enforced_protect_blocks_sensitive_remediation_side_effect():
    """A high-risk target must not reach the integration when enforce is on."""
    executor = _RecordingExecutor()
    handler, uows = _handler(executor, enforce=True)
    approval_id = _seed(uows, action="read_file", target=".env")

    result = handler.handle(
        DecideApproval(
            tenant=TENANT,
            approval_id=approval_id,
            decision="approve",
            decided_by="analyst:1",
        )
    )
    assert not result.ok
    assert result.outcome == "protect_denied"
    assert executor.calls == []


def test_advisory_allows_sensitive_target_but_still_runs_executor():
    executor = _RecordingExecutor()
    handler, uows = _handler(executor, enforce=False)
    approval_id = _seed(uows, action="read_file", target=".env")

    result = handler.handle(
        DecideApproval(
            tenant=TENANT,
            approval_id=approval_id,
            decision="approve",
            decided_by="analyst:1",
        )
    )
    assert result.ok
    assert executor.calls == [("read_file", ".env")]
