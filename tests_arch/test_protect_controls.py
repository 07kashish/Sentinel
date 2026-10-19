from __future__ import annotations

import pytest

from sentinel.application.protect_controls import (
    CircuitOpen,
    ProtectControls,
    ToolBudgetExceeded,
)


def test_tool_budget_is_keyed_by_tenant_and_agent():
    controls = ProtectControls(budget_per_minute=1)

    controls.assert_may_execute(tenant_id="acme", agent_id="agent-1")

    with pytest.raises(ToolBudgetExceeded):
        controls.assert_may_execute(tenant_id="acme", agent_id="agent-1")

    controls.assert_may_execute(tenant_id="globex", agent_id="agent-1")
    controls.assert_may_execute(tenant_id="acme", agent_id="agent-2")


def test_circuit_breaker_is_keyed_by_tenant_and_agent():
    controls = ProtectControls(circuit_threshold=2, circuit_cooldown_seconds=60)

    controls.record_failure(tenant_id="acme", agent_id="agent-1")
    controls.record_failure(tenant_id="acme", agent_id="agent-1")

    with pytest.raises(CircuitOpen):
        controls.assert_may_execute(tenant_id="acme", agent_id="agent-1")

    controls.assert_may_execute(tenant_id="globex", agent_id="agent-1")
    controls.assert_may_execute(tenant_id="acme", agent_id="agent-2")


def test_circuit_success_resets_only_the_matching_scope():
    controls = ProtectControls(circuit_threshold=1, circuit_cooldown_seconds=60)
    controls.record_failure(tenant_id="acme", agent_id="agent-1")
    controls.record_failure(tenant_id="globex", agent_id="agent-1")

    controls.record_success(tenant_id="acme", agent_id="agent-1")

    controls.assert_may_execute(tenant_id="acme", agent_id="agent-1")
    with pytest.raises(CircuitOpen):
        controls.assert_may_execute(tenant_id="globex", agent_id="agent-1")
