"""Deployment-wide tool budget and circuit breaker, in the shared database.

WHY NOT THE IN-PROCESS VERSION
------------------------------
`ProtectControls` keeps its counters in a dict. Across N replicas that is N
independent budgets and N independent breakers: an agent allowed 10 tool
calls a minute gets 10 per replica, and a breaker that opened on one pod is
closed on the next. Every check reports healthy while the deployment-wide
control does not exist -- the same defect class as a per-process rate
limiter, which this codebase already refuses to start with.

This store keeps ONE row per (tenant, agent) and applies every change as a
single conditional UPDATE, so two replicas racing on the same agent cannot
both consume the last unit of budget or both miss the failure that should
open the breaker. It is tenant-scoped: a same-named agent in two tenants has
two rows, and neither can consume, reset, open or inspect the other's.

OUTAGE BEHAVIOUR (documented, not accidental)
---------------------------------------------
If the database is unreachable when a control must be consulted, the tool
call is REFUSED with a retryable error. A control that cannot be read is a
control whose answer is unknown, and the budget and breaker exist to stop
runaway agents -- the case in which the database is most likely to be
struggling. Failing open there would remove the control at the moment it is
needed. The kill switch is configuration, not state, and needs no store.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sentinel.application.protect_controls import (
    CircuitOpen,
    KillSwitchActive,
    ToolBudgetExceeded,
)
from sentinel.domain.errors import TransientFailure
from sentinel.infrastructure.sql.engine import ConnectionPool

__all__ = ["ControlStateUnavailable", "SqlProtectControls"]


class ControlStateUnavailable(TransientFailure):
    """The shared control state could not be read or written. Refuse."""

    is_retryable = True


def _key(tenant_id: Any, agent_id: Any) -> tuple[str, str]:
    tenant = str(getattr(tenant_id, "value", tenant_id) or "")
    agent = str(agent_id or "")
    if not tenant:
        # A budget shared by every tenant that forgot to name one is a
        # cross-tenant control: refuse to key on the empty string.
        raise ValueError("a tenant is required to consult shared control state")
    if not agent:
        raise ValueError("an agent is required to consult shared control state")
    return tenant, agent


@dataclass(frozen=True, slots=True)
class SqlProtectControls:
    """Same surface as `ProtectControls`, backed by `protect_control_state`."""

    pool: ConnectionPool
    kill_switch: bool = False
    budget_per_minute: int = 0
    circuit_threshold: int = 20
    circuit_cooldown_seconds: float = 30.0
    clock: Any = None

    def _now(self) -> datetime:
        if self.clock is not None:
            value = self.clock.now()
            return getattr(value, "value", value)
        return datetime.now(timezone.utc)

    def assert_may_execute(self, *, agent_id: str, tenant_id: str = "") -> None:
        if self.kill_switch:
            raise KillSwitchActive(
                "protect kill switch is active; refusing all tool side effects"
            )
        tenant, agent = _key(tenant_id, agent_id)
        now = self._now()
        window_start = now.replace(second=0, microsecond=0)
        try:
            with self.pool.acquire() as conn:
                p = conn.p
                conn.begin()
                conn.set_tenant(tenant)
                row = conn.one(
                    f"SELECT window_start, budget_used, consecutive_failures, "
                    f"circuit_opened_at FROM protect_control_state "
                    f"WHERE tenant_id={p} AND agent_id={p}" + conn.lock_clause(),
                    (tenant, agent),
                )
                if row is None:
                    conn.execute_rowcount(
                        f"INSERT INTO protect_control_state (tenant_id, agent_id, "
                        f"window_start, budget_used, consecutive_failures, "
                        f"circuit_opened_at) VALUES ({p}, {p}, {p}, 0, 0, '')",
                        (tenant, agent, window_start.isoformat()),
                    )
                    row = {
                        "window_start": window_start.isoformat(),
                        "budget_used": 0,
                        "consecutive_failures": 0,
                        "circuit_opened_at": "",
                    }
                opened = str(row["circuit_opened_at"] or "")
                if opened:
                    elapsed = (now - datetime.fromisoformat(opened)).total_seconds()
                    if elapsed < self.circuit_cooldown_seconds:
                        conn.commit()
                        raise CircuitOpen(
                            f"protect circuit open for agent {agent!r} in tenant "
                            f"{tenant!r} for {self.circuit_cooldown_seconds - elapsed:.1f}s more"
                        )
                    # Cooldown elapsed: half-open. Clear and let this call try.
                    conn.execute_rowcount(
                        f"UPDATE protect_control_state SET circuit_opened_at='', "
                        f"consecutive_failures=0 WHERE tenant_id={p} AND agent_id={p}",
                        (tenant, agent),
                    )
                if self.budget_per_minute > 0:
                    used = int(row["budget_used"])
                    if str(row["window_start"]) != window_start.isoformat():
                        used = 0
                    if used >= self.budget_per_minute:
                        conn.commit()
                        raise ToolBudgetExceeded(
                            f"agent {agent!r} exceeded tool budget "
                            f"{self.budget_per_minute}/min in tenant {tenant!r}"
                        )
                    conn.execute_rowcount(
                        f"UPDATE protect_control_state SET window_start={p}, "
                        f"budget_used={p} WHERE tenant_id={p} AND agent_id={p}",
                        (window_start.isoformat(), used + 1, tenant, agent),
                    )
                conn.commit()
        except (CircuitOpen, ToolBudgetExceeded, KillSwitchActive):
            raise
        except TransientFailure as exc:
            raise ControlStateUnavailable(
                f"shared control state unavailable; refusing tool execution for "
                f"agent {agent!r}: {exc}"
            ) from exc

    def record_success(self, *, agent_id: str = "", tenant_id: str = "") -> None:
        try:
            tenant, agent = _key(tenant_id, agent_id)
        except ValueError:
            return
        try:
            with self.pool.acquire() as conn:
                p = conn.p
                conn.begin()
                conn.set_tenant(tenant)
                conn.execute_rowcount(
                    f"UPDATE protect_control_state SET consecutive_failures=0, "
                    f"circuit_opened_at='' WHERE tenant_id={p} AND agent_id={p}",
                    (tenant, agent),
                )
                conn.commit()
        except TransientFailure:
            # A success that could not be recorded leaves the failure count
            # where it was: the breaker stays at least as strict as before.
            return

    def record_failure(self, *, agent_id: str = "", tenant_id: str = "") -> None:
        try:
            tenant, agent = _key(tenant_id, agent_id)
        except ValueError:
            return
        now = self._now()
        try:
            with self.pool.acquire() as conn:
                p = conn.p
                conn.begin()
                conn.set_tenant(tenant)
                row = conn.one(
                    f"SELECT consecutive_failures FROM protect_control_state "
                    f"WHERE tenant_id={p} AND agent_id={p}" + conn.lock_clause(),
                    (tenant, agent),
                )
                if row is None:
                    conn.execute_rowcount(
                        f"INSERT INTO protect_control_state (tenant_id, agent_id, "
                        f"window_start, budget_used, consecutive_failures, "
                        f"circuit_opened_at) VALUES ({p}, {p}, {p}, 0, 0, '')",
                        (tenant, agent, now.replace(second=0, microsecond=0).isoformat()),
                    )
                    failures = 0
                else:
                    failures = int(row["consecutive_failures"])
                failures += 1
                opened = (
                    now.isoformat()
                    if self.circuit_threshold > 0 and failures >= self.circuit_threshold
                    else ""
                )
                conn.execute_rowcount(
                    f"UPDATE protect_control_state SET consecutive_failures={p}, "
                    f"circuit_opened_at=CASE WHEN {p}='' THEN circuit_opened_at ELSE {p} END "
                    f"WHERE tenant_id={p} AND agent_id={p}",
                    (failures, opened, opened, tenant, agent),
                )
                conn.commit()
        except TransientFailure:
            # Cannot record the failure: the next assert will read stale state.
            # Preferable to raising here, because this runs in an except path.
            return

    def purge_stale(self, tenant: str, *, older_than: datetime) -> int:
        """Rows whose window and breaker are both long past. Housekeeping."""
        cutoff = (older_than - timedelta(minutes=2)).isoformat()
        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)
            removed = conn.execute_rowcount(
                f"DELETE FROM protect_control_state WHERE tenant_id={p} "
                f"AND window_start<{p} AND circuit_opened_at=''",
                (tenant, cutoff),
            )
            conn.commit()
        return removed
