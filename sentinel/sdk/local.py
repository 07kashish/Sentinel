"""The IN-PROCESS client: agent and gate share one Python process.

Split out of `sentinel/sdk/__init__.py` so that importing the package -- which
Python does before importing any submodule -- no longer pulls the application
layer in. `from sentinel.sdk.remote import SentinelClient` must work in a
customer's runtime with nothing installed beyond the standard library, and it
could not while this class lived in the package initialiser.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping, TypeVar

from sentinel.application.protect_controls import ProtectControls
from sentinel.application.protect_gate import ProtectGate
from sentinel.application.tool_runner import ProtectedToolRunner
from sentinel.domain.primitives import TrustLevel
from sentinel.domain.protect import ProtectOutcome

__all__ = ["ProtectClient"]

T = TypeVar("T")


class ProtectClient:
    """Convenience wrapper: evaluate or execute through ProtectedToolRunner."""

    __slots__ = ("_runner",)

    def __init__(self, runner: ProtectedToolRunner) -> None:
        self._runner = runner

    @classmethod
    def from_gate(
        cls,
        gate: ProtectGate,
        *,
        controls: ProtectControls | None = None,
    ) -> "ProtectClient":
        return cls(ProtectedToolRunner(gate=gate, controls=controls))

    def evaluate(
        self, *, payload: Mapping[str, Any], trust: TrustLevel
    ) -> ProtectOutcome:
        return self._runner.gate.evaluate(payload=payload, trust=trust)

    def execute(
        self,
        *,
        agent_id: str,
        tool: str,
        trust: TrustLevel,
        side_effect: Callable[[], T],
        resource: str = "",
        action: str = "",
        metadata: Mapping[str, Any] | None = None,
    ) -> tuple[ProtectOutcome, T]:
        return self._runner.execute(
            agent_id=agent_id,
            tool=tool,
            trust=trust,
            side_effect=side_effect,
            resource=resource,
            action=action,
            metadata=metadata,
        )
