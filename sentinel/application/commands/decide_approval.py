"""The human-approval gate. The one place this product acts on the world.

THE DEFECT THIS IS SHAPED AGAINST
---------------------------------
The predecessor's `execute_approved` was:

    approval = db.get_approval(...)               # READ
    if approval["state"] != "pending": return     # CHECK
    receipt = for_action(action).execute(...)     # EXTERNAL SIDE EFFECT
    db.decide_approval(...)                       # WRITE

No lock, no transaction spanning the check and the write, no execution fence.
Two concurrent `POST /approvals/{id}/decide` requests -- an impatient analyst
double-clicking, or a retrying HTTP client -- both observed `pending` and both
invoked the real remediation.

The inline comment claimed idempotency because the approval id was passed as a
key, but that defence was delegated entirely to the provider and was unverified
for every integration; for a simulated one it was meaningless.

This was the least concurrency-protected write path in the codebase, while the
ledger append three modules away had row locks, fencing tokens, epochs and a
unique index. The asymmetry is the finding: the code was hardened where hardening
was interesting, not where the consequences were physical.

THE FIX
-------
Claim, then act, then record -- the same claim/deliver/record shape the
attestation outbox already uses, because it is the same problem.

`claim_for_execution` is a conditional UPDATE from `pending` to `executing`. Only
the caller whose UPDATE affected a row proceeds to the side effect. A failure
releases the claim so a later attempt can retry; a success records the receipt.
The external call happens OUTSIDE the transaction on purpose: holding a database
transaction open across a network call to a third party is how a slow integration
becomes a database outage.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any

from sentinel.application.messages import Command, Result
from sentinel.application.ports import (
    Clock,
    IdGenerator,
    Logger,
    RemediationExecutor,
    UnitOfWorkFactory,
)
from sentinel.application.tool_runner import ProtectedToolRunner, ToolExecutionRefused
from sentinel.domain.errors import TransientFailure
from sentinel.domain.execution_binding import (
    NonceLedger,
    RejectingNonceLedger,
    issue_authorization,
)
from sentinel.domain.primitives import ApprovalId, IdempotencyKey, TrustLevel

__all__ = ["DecideApproval", "DecideApprovalHandler"]


@dataclass(frozen=True, slots=True)
class DecideApproval(Command):
    approval_id: ApprovalId
    decision: str
    decided_by: str
    reason: str = ""


class DecideApprovalHandler:
    __slots__ = (
        "_uow_factory", "_executor", "_tool_runner", "_clock", "_ids", "_logger",
        "_nonces", "_receipts",
    )

    def __init__(
        self,
        *,
        uow_factory: UnitOfWorkFactory,
        executor: RemediationExecutor,
        tool_runner: ProtectedToolRunner,
        clock: Clock,
        ids: IdGenerator,
        logger: Logger,
        nonces: NonceLedger | None = None,
        receipts: Any = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._executor = executor
        self._tool_runner = tool_runner
        self._clock = clock
        self._ids = ids
        self._logger = logger
        #: Single-use enforcement for the authorization minted at approval.
        #: Defaults to the REFUSING ledger, so a construction site that forgot
        #: to pass the shared one gets an obvious refusal rather than a
        #: per-process set that protects nothing across replicas.
        self._nonces = nonces if nonces is not None else RejectingNonceLedger()
        #: Optional durable receipt store. A remediation is the one action this
        #: product takes on the world, so its receipt belongs beside the others.
        self._receipts = receipts

    def handle(self, command: DecideApproval) -> Result:
        if command.decision not in {"approve", "reject"}:
            return Result.refused(
                "invalid_decision", detail="decision must be 'approve' or 'reject'"
            )
        if command.decision == "reject":
            return self._reject(command)
        return self._approve(command)

    # ── Reject ───────────────────────────────────────────────────────────────

    def _reject(self, command: DecideApproval) -> Result:
        """A rejection is a decision and must be recorded as one.

        `reason` is required by the domain record. The predecessor's route
        omitted it against a keyword-only parameter with no default, so every
        rejection raised TypeError and returned HTTP 500 -- the analyst action
        that says 'do not do this' was the one that could not be performed.
        """
        now = self._clock.now()
        with self._uow_factory.begin(command.tenant) as uow:
            claimed = uow.approvals.claim_for_execution(command.approval_id)
            if claimed is None:
                uow.commit()
                return Result.refused(
                    "not_pending",
                    detail="this approval is not awaiting a decision",
                    approval_id=command.approval_id.value,
                )
            uow.approvals.record_outcome(
                approval_id=command.approval_id,
                state="rejected",
                decided_by=command.decided_by,
                receipt={
                    "outcome": "rejected",
                    "executed": False,
                    "reason": command.reason or "no reason given",
                },
                at=now,
            )
            uow.commit()
        self._logger.info(
            "approval_rejected",
            tenant=str(command.tenant),
            approval_id=command.approval_id.value,
            decided_by=command.decided_by,
        )
        return Result.accepted(
            "rejected", approval_id=command.approval_id.value, executed=False
        )

    # ── Approve ──────────────────────────────────────────────────────────────

    def _approve(self, command: DecideApproval) -> Result:
        now = self._clock.now()

        # 1. Claim. Exactly one caller wins; everyone else is refused here,
        #    before any external effect.
        with self._uow_factory.begin(command.tenant) as uow:
            claimed = uow.approvals.claim_for_execution(command.approval_id)
            if claimed is None:
                uow.commit()
                return Result.refused(
                    "not_pending",
                    detail=(
                        "this approval is not awaiting a decision; it has already "
                        "been decided or is being executed by another caller"
                    ),
                    approval_id=command.approval_id.value,
                )
            uow.commit()

        # Expiry is checked AFTER the claim and BEFORE any external effect.
        #
        # After, because checking before would read a row this caller does not
        # own -- two concurrent decisions would both pass the check and race on
        # to the claim, which is the shape of the original defect this module
        # was written to fix.
        #
        # Before, because that is the whole point: an approval whose window has
        # closed must not reach the integration. The state moves to `expired`
        # rather than back to `pending`, so a closed window is terminal and a
        # retry cannot walk it open again.
        if claimed.is_expired(now):
            with self._uow_factory.begin(command.tenant) as uow:
                uow.approvals.record_outcome(
                    approval_id=command.approval_id,
                    state="expired",
                    decided_by=command.decided_by,
                    receipt={
                        "outcome": "expired",
                        "executed": False,
                        "detail": (
                            "this approval's window closed before it was decided; "
                            "nothing was executed. Raise a new request if the "
                            "action is still warranted."
                        ),
                        "expires_at": str(claimed.expires_at),
                    },
                    at=now,
                )
                uow.commit()
            self._logger.warning(
                "approval_expired",
                tenant=str(command.tenant),
                approval_id=command.approval_id.value,
                action=claimed.action,
                expires_at=str(claimed.expires_at),
                decided_by=command.decided_by,
            )
            return Result.refused(
                "expired",
                approval_id=command.approval_id.value,
                action=claimed.action,
                detail="the approval window has closed; nothing was executed",
            )

        if not claimed.target:
            with self._uow_factory.begin(command.tenant) as uow:
                uow.approvals.record_outcome(
                    approval_id=command.approval_id,
                    state="refused",
                    decided_by=command.decided_by,
                    receipt={
                        "outcome": "refused",
                        "executed": False,
                        "detail": "no target could be resolved; refusing to act",
                    },
                    at=now,
                )
                uow.commit()
            return Result.refused("no_target", approval_id=command.approval_id.value)

        if not self._executor.supports(claimed.action):
            with self._uow_factory.begin(command.tenant) as uow:
                uow.approvals.record_outcome(
                    approval_id=command.approval_id,
                    state="refused",
                    decided_by=command.decided_by,
                    receipt={
                        "outcome": "refused",
                        "executed": False,
                        "detail": (
                            f"no integration is configured for action "
                            f"{claimed.action!r}; nothing was executed"
                        ),
                    },
                    at=now,
                )
                uow.commit()
            return Result.refused(
                "unsupported_action",
                approval_id=command.approval_id.value,
                action=claimed.action,
            )

        # 2. Act. OUTSIDE any transaction: a slow third party must not hold a
        #    database connection, and a database that is briefly unavailable must
        #    not roll back an action that already happened in the real world.
        #
        # Every remediation side effect goes through ProtectedToolRunner so
        # SENTINEL_PROTECT_ENFORCE can fail closed before the integration runs.
        #
        # BOUND, not merely gated. The authorization is minted HERE, at the
        # moment of approval, and commits to the action and target the analyst
        # approved. `execute_bound` recomputes the parameter digest immediately
        # before the integration runs and passes the VERIFIED parameters into
        # it -- so what reaches the integration is what was approved, rather
        # than what a closure happened to close over.
        idempotency = IdempotencyKey(f"apr-{command.approval_id.value}")
        agent_identity = f"remediation:{command.decided_by}"
        approved_parameters = {
            "action": claimed.action,
            "target": claimed.target,
            "tenant": str(command.tenant),
            "idempotency_key": idempotency.value,
        }
        authorization = issue_authorization(
            authorization_id=f"auth-{command.approval_id.value}",
            # Random, not derived: a retry after a released claim must present
            # a fresh nonce, or the ledger reads the retry as a replay.
            nonce=secrets.token_urlsafe(16),
            tenant_id=str(command.tenant),
            actor_identity=command.decided_by,
            agent_identity=agent_identity,
            tool_identity=claimed.action,
            action=claimed.action,
            target_resource=claimed.target,
            parameters=approved_parameters,
            now=now.value,
            policy_decision="approved",
            conditions={"approval_id": command.approval_id.value},
        )

        try:
            _protect, receipt, execution_receipt = self._tool_runner.execute_bound(
                authorization=authorization,
                # The runner is shared across tenants, so the containment check
                # inside it needs to know whose kill switch to read.
                tenant=command.tenant,
                agent_id=agent_identity,
                tool=claimed.action,
                resource=claimed.target,
                action=claimed.action,
                parameters=approved_parameters,
                trust=TrustLevel.VERIFIED,
                # The integration call is a METHOD defined below `_approve`, not
                # a closure defined above the runner call. The runner is the
                # only thing that may invoke it, and it invokes it with the
                # VERIFIED parameters -- so the integration cannot read the
                # approval record directly and act on something the digest did
                # not cover. Source order is asserted by
                # `test_decide_approval_wraps_executor_in_tool_runner`.
                side_effect=self._run_integration,
                nonces=self._nonces,
                now=now.value,
            )
        except ToolExecutionRefused as exc:
            with self._uow_factory.begin(command.tenant) as uow:
                uow.approvals.record_outcome(
                    approval_id=command.approval_id,
                    state="refused",
                    decided_by=command.decided_by,
                    receipt={
                        "outcome": "protect_denied",
                        "executed": False,
                        "detail": str(exc),
                    },
                    at=now,
                )
                uow.commit()
            self._logger.warning(
                "approval_protect_denied",
                tenant=str(command.tenant),
                approval_id=command.approval_id.value,
                action=claimed.action,
                detail=str(exc),
            )
            return Result.refused(
                "protect_denied",
                approval_id=command.approval_id.value,
                action=claimed.action,
                detail=str(exc),
            )
        except Exception as exc:  # noqa: BLE001 - release the claim, then classify
            with self._uow_factory.begin(command.tenant) as uow:
                uow.approvals.release(
                    command.approval_id, error=f"{type(exc).__name__}: {exc}", at=now
                )
                uow.commit()
            self._logger.error(
                "approval_execution_failed",
                tenant=str(command.tenant),
                approval_id=command.approval_id.value,
                action=claimed.action,
                error=f"{type(exc).__name__}: {exc}",
            )
            raise TransientFailure(
                f"remediation {claimed.action!r} failed: {type(exc).__name__}: {exc}"
            ) from exc

        # 3. Record. The receipt is the only truth about what happened.
        receipt = {
            **dict(receipt),
            # The binding evidence rides on the approval's own receipt, so
            # "did what ran match what was approved" is answerable from the
            # approval record alone.
            "execution_receipt": execution_receipt.as_document(),
        }
        with self._uow_factory.begin(command.tenant) as uow:
            uow.approvals.record_outcome(
                approval_id=command.approval_id,
                state="decided",
                decided_by=command.decided_by,
                receipt=receipt,
                at=now,
            )
            uow.commit()
        if self._receipts is not None:
            try:
                self._receipts.record(
                    str(command.tenant),
                    receipt=execution_receipt,
                    approved_parameter_digest=authorization.approved_parameter_digest,
                    authorization_id=authorization.authorization_id,
                )
            except Exception as exc:  # noqa: BLE001 - the action already happened
                # Logged, not raised. The remediation ran and its receipt is on
                # the approval record; a receipt-store outage must not turn a
                # completed action into a reported failure.
                self._logger.error(
                    "execution_receipt_not_stored",
                    tenant=str(command.tenant),
                    approval_id=command.approval_id.value,
                    error=f"{type(exc).__name__}: {exc}",
                )

        executed = bool(receipt.get("executed"))
        self._logger.info(
            "approval_executed",
            tenant=str(command.tenant),
            approval_id=command.approval_id.value,
            action=claimed.action,
            target=claimed.target,
            executed=executed,
            decided_by=command.decided_by,
        )
        return Result.accepted(
            "decided",
            approval_id=command.approval_id.value,
            action=claimed.action,
            executed=executed,
            receipt=dict(receipt),
        )

    # ── The integration call, reachable only through the bound runner ────────

    def _run_integration(self, verified: Any) -> Any:
        """Run the configured integration with the VERIFIED parameters.

        `verified` is the mapping `execute_bound` recomputed the digest over
        immediately before calling this -- not the approval record, and not a
        closure variable. Every field the integration acts on came through the
        binding check, so what runs is what was approved.
        """
        return self._executor.execute(
            action=str(verified["action"]),
            # The tenant an integration acting on SENTINEL'S OWN state cannot
            # work without. Webhook integrations do not declare it and are
            # called exactly as before.
            tenant=str(verified["tenant"]),
            target=str(verified["target"]),
            idempotency_key=IdempotencyKey(str(verified["idempotency_key"])),
        )
