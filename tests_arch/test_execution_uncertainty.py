"""HTTP faults after invocation must never claim that nothing happened."""
import pytest

from sentinel.application.tool_proxy import RegisteredSideEffect
from sentinel.domain.operations import OperationState
from tests_arch.test_execution_contract import _evaluate, _execute, harness  # noqa: F401


@pytest.mark.parametrize("failure", ["target_timeout", "control_store", "receipt_store"])
def test_post_invocation_failure_is_unknown_and_never_reexecutes(harness, monkeypatch, failure):  # noqa: F811
    secret_value = "synthetic-private-result-do-not-retain"
    def effect(arguments):
        harness.effects.append(dict(arguments))
        if failure == "target_timeout":
            raise TimeoutError(secret_value)
        return {"changed": True}
    harness.container.tool_proxy.register(RegisteredSideEffect(name="echo", runner=effect))
    def unavailable(*args, **kwargs):
        raise RuntimeError(secret_value)
    if failure == "control_store":
        monkeypatch.setattr(type(harness.container.protect_controls), "record_success", unavailable)
    if failure == "receipt_store":
        monkeypatch.setattr(type(harness.container.receipts), "record", unavailable)
    token = _evaluate(harness).json()["authorization"]["token"]
    response = _execute(harness, token)
    assert response.status_code == 500
    detail = response.json()["detail"]
    assert detail["outcome"] == "unknown_after_effect"
    assert secret_value not in response.text
    operation = harness.container.operations.get("acme", detail["operation_id"])
    assert operation.state is OperationState.UNKNOWN_AFTER_EFFECT
    assert secret_value not in operation.error
    assert harness.container.operations.get("globex", detail["operation_id"]) is None
    assert len(harness.effects) == 1
    assert _execute(harness, token).status_code == 403
    assert len(harness.effects) == 1
