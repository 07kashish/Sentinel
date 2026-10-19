"""An execution OPERATION: the durable record of an attempt to change the world.

WHY A RECEIPT IS NOT ENOUGH
---------------------------
`ExecutionReceipt` is written AFTER the side effect returns. Between the moment
the tool is invoked and the moment the receipt is stored there is a window in
which the effect may have happened and nothing durable says so: a process
killed there, or a database that refuses the write, leaves a change in the
world with no record of the intent that caused it. The receipt is then absent,
and absence reads as "nothing happened" -- which is the one thing it must not
be allowed to mean for a consequential action.

So the intent is written FIRST, as a `pending` operation with a stable id, and
the outcome is written second. If the second write never lands, the row stays
`pending` past its deadline and reconciliation moves it to
`unknown_after_effect`, which is the honest state: the effect may have run and
somebody has to look. Nothing here promises exactly-once execution across
arbitrary remote APIs -- no in-process wrapper can -- and the state model says
so by having an "unknown" state at all.

STATES
------
    pending               intent recorded; the effect has been or is about to be invoked
    succeeded             the effect returned and its outcome was recorded
    failed                downstream evidence established failure during reconciliation
    refused               binding, policy, containment or controls refused it BEFORE the effect
    unknown_after_effect  invocation occurred; result or durable confirmation is uncertain

`refused` is recorded with digests only. A refused attempt is evidence of what
somebody tried, and the parameter VALUES they tried with are the last thing
that belongs in an evidence table; the digest identifies them without keeping
them.

TIMESTAMPS
----------
`started_at` and `completed_at` are read from the clock AT those events, not
copied from a single `now` a caller passed in. An operation that reports the
same instant for start and completion is reporting the caller's argument, not
what happened.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

__all__ = [
    "ExecutionOperation",
    "OperationState",
    "OutcomeUnknown",
    "TERMINAL_STATES",
]


class OperationState(str, Enum):
    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    REFUSED = "refused"
    UNKNOWN_AFTER_EFFECT = "unknown_after_effect"


TERMINAL_STATES: frozenset[OperationState] = frozenset(
    {
        OperationState.SUCCEEDED,
        OperationState.FAILED,
        OperationState.REFUSED,
        OperationState.UNKNOWN_AFTER_EFFECT,
    }
)


class OutcomeUnknown(RuntimeError):
    """The side effect was invoked and its outcome could not be durably recorded.

    Raised INSTEAD of returning the result, because a result returned to the
    caller with no record behind it is a success the evidence cannot see.
    Carries the operation id so the caller can report exactly which operation
    needs reconciliation. This is never a `DomainRuleViolated`: nothing was
    refused, and retrying it is exactly the wrong response.
    """

    def __init__(self, operation_id: str, detail: str) -> None:
        super().__init__(
            f"operation {operation_id!r}: the effect was invoked but its outcome "
            f"could not be recorded ({detail}); it is UNKNOWN until reconciled"
        )
        self.operation_id = operation_id
        self.detail = detail


@dataclass(frozen=True, slots=True)
class ExecutionOperation:
    """One attempt, from intent to outcome."""

    operation_id: str
    tenant_id: str
    agent_identity: str
    tool_identity: str
    action: str
    target_resource: str
    #: Digest of the parameters about to run. Never the parameters.
    parameter_digest: str
    state: OperationState
    started_at: str
    completed_at: str = ""
    authorization_id: str = ""
    receipt_id: str = ""
    #: Set when the downstream target accepted an idempotency key; empty means
    #: the target offered no such protection and the caller was told so.
    downstream_idempotency_key: str = ""
    downstream_supports_idempotency: bool = False
    error: str = ""
    result_digest: str = ""
    reconciled_by: str = ""
    reconciled_at: str = ""
    reconciliation_note: str = ""
    #: Free-form, digests and identifiers only by convention; the store does
    #: not inspect it.
    attributes: Mapping[str, Any] = field(default_factory=dict)

    @property
    def is_terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    @property
    def needs_reconciliation(self) -> bool:
        return self.state is OperationState.UNKNOWN_AFTER_EFFECT

    def as_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "tenant_id": self.tenant_id,
            "agent_identity": self.agent_identity,
            "tool_identity": self.tool_identity,
            "action": self.action,
            "target_resource": self.target_resource,
            "parameter_digest": self.parameter_digest,
            "state": self.state.value,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "authorization_id": self.authorization_id,
            "receipt_id": self.receipt_id,
            "downstream_idempotency_key": self.downstream_idempotency_key,
            "downstream_supports_idempotency": self.downstream_supports_idempotency,
            "error": self.error,
            "result_digest": self.result_digest,
            "reconciled_by": self.reconciled_by,
            "reconciled_at": self.reconciled_at,
            "reconciliation_note": self.reconciliation_note,
            "attributes": dict(self.attributes),
            "is_terminal": self.is_terminal,
            "needs_reconciliation": self.needs_reconciliation,
        }
