"""Protect-mode runtime controls: kill switch, tool budget, circuit breaker.

These sit beside ProtectGate so enforcement can fail closed for reasons other
than a policy match (operator halt, spend limits, cascading refusal).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from sentinel.domain.errors import DomainRuleViolated

__all__ = [
    "CircuitOpen",
    "KillSwitchActive",
    "ProtectControls",
    "ToolBudgetExceeded",
]


class KillSwitchActive(DomainRuleViolated):
    """Global protect kill switch is on — every tool side effect is refused."""

    is_retryable = False


class ToolBudgetExceeded(DomainRuleViolated):
    """Agent exceeded its configured tool-execution budget."""

    is_retryable = False


class CircuitOpen(DomainRuleViolated):
    """Circuit breaker open after consecutive protect refusals/failures."""

    is_retryable = True


@dataclass
class ProtectControls:
    """Process-local controls applied before a ProtectedToolRunner side effect."""

    kill_switch: bool = False
    budget_per_minute: int = 0
    circuit_threshold: int = 20
    circuit_cooldown_seconds: float = 30.0

    def __post_init__(self) -> None:
        self._lock = threading.Lock()
        self._budget_window_start = time.monotonic()
        self._budget_counts: dict[tuple[str, str], int] = {}
        self._consecutive_failures: dict[tuple[str, str], int] = {}
        self._circuit_opened_at: dict[tuple[str, str], float] = {}

    def assert_may_execute(self, *, agent_id: str, tenant_id: str = "") -> None:
        if self.kill_switch:
            raise KillSwitchActive(
                "protect kill switch is active; refusing all tool side effects"
            )
        key = self._key(tenant_id=tenant_id, agent_id=agent_id)
        self._assert_circuit(key)
        self._consume_budget(key, agent_id=agent_id)

    def record_success(self, *, agent_id: str = "", tenant_id: str = "") -> None:
        key = self._key(tenant_id=tenant_id, agent_id=agent_id)
        with self._lock:
            self._consecutive_failures.pop(key, None)
            self._circuit_opened_at.pop(key, None)

    def record_failure(self, *, agent_id: str = "", tenant_id: str = "") -> None:
        key = self._key(tenant_id=tenant_id, agent_id=agent_id)
        with self._lock:
            failures = self._consecutive_failures.get(key, 0) + 1
            self._consecutive_failures[key] = failures
            if (
                self.circuit_threshold > 0
                and failures >= self.circuit_threshold
            ):
                self._circuit_opened_at[key] = time.monotonic()

    def _assert_circuit(self, key: tuple[str, str]) -> None:
        with self._lock:
            opened_at = self._circuit_opened_at.get(key)
            if opened_at is None:
                return
            elapsed = time.monotonic() - opened_at
            if elapsed < self.circuit_cooldown_seconds:
                raise CircuitOpen(
                    f"protect circuit open for "
                    f"{self.circuit_cooldown_seconds - elapsed:.1f}s more"
                )
            self._circuit_opened_at.pop(key, None)
            self._consecutive_failures.pop(key, None)

    def _consume_budget(self, key: tuple[str, str], *, agent_id: str) -> None:
        if self.budget_per_minute <= 0:
            return
        with self._lock:
            now = time.monotonic()
            if now - self._budget_window_start >= 60.0:
                self._budget_window_start = now
                self._budget_counts.clear()
            used = self._budget_counts.get(key, 0)
            if used >= self.budget_per_minute:
                raise ToolBudgetExceeded(
                    f"agent {agent_id!r} exceeded tool budget "
                    f"{self.budget_per_minute}/min"
                )
            self._budget_counts[key] = used + 1

    @staticmethod
    def _key(*, tenant_id: str, agent_id: str) -> tuple[str, str]:
        return (str(tenant_id or ""), str(agent_id or ""))
