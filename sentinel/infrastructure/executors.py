"""Remediation executors: the components that act on the real world.

`NullRemediationExecutor` is the executor for a deployment with no integrations
configured. It is not a stand-in for a real one -- it is the correct behaviour
for that deployment, and it is explicit about it: `supports()` returns False, so
`DecideApprovalHandler` refuses the approval with `unsupported_action` and
records a receipt saying nothing was executed.

That distinction matters. The predecessor returned `status="simulated",
executed=false` from what looked like a successful execution path, which reads as
success to any caller that only checks for an exception.
"""

from __future__ import annotations

from typing import Any, Mapping, Protocol, runtime_checkable

from sentinel.domain.primitives import IdempotencyKey

__all__ = ["Integration", "NullRemediationExecutor"]


@runtime_checkable
class Integration(Protocol):
    """One outbound system that can perform an action."""

    def execute(self, *, target: str, idempotency_key: IdempotencyKey) -> Mapping[str, Any]: ...


class NullRemediationExecutor:
    """No integrations configured. Supports nothing, and says so."""

    __slots__ = ("_reason",)

    def __init__(self, *, reason: str = "no remediation integrations are configured") -> None:
        self._reason = reason

    def supports(self, action: str) -> bool:
        return False

    def execute(
        self,
        *,
        action: str,
        target: str,
        idempotency_key: IdempotencyKey,
        tenant: str = "",
    ) -> Mapping[str, Any]:
        # Unreachable through DecideApprovalHandler, which checks `supports`
        # first. Raising rather than returning a success-shaped dict means a
        # caller that skips the check gets an error, not a false receipt.
        raise NotImplementedError(
            f"{self._reason}; action {action!r} cannot be executed by this deployment"
        )
