"""MCP reply enforcement survives removal of the A2A runtime."""
import importlib.util

import pytest

from sentinel.application.protect_gate import ProtectGate
from sentinel.domain.primitives import TrustLevel
from sentinel.infrastructure.detection import DeterministicPolicy, PolicyRule
from tests_arch.test_mcp_wire_proxy import (
    POISONED,
    _call,
    _enrol,
    app as app,
)


@pytest.mark.usefixtures("app")
def test_injected_mcp_reply_is_refused_without_a2a(request):
    client, container, upstream = request.getfixturevalue("app")
    _enrol(container)
    # Exercise the real route, gate and ruleset with the parked collaborator
    # absent. This also runs unchanged once the Container no longer has it.
    if hasattr(container, "a2a_gateway"):
        object.__delattr__(container, "a2a_gateway")
    upstream.call_result = {"content": [{"type": "text", "text": POISONED}]}
    response = _call(client)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["error"]["code"] == -32050
    assert body["error"]["data"]["sentinel"]["reason"] == "poisoned_result"
    assert "result" not in body
    assert POISONED not in response.text
    assert any(call.get("method") == "tools/call" for call in upstream.forwarded)


def test_reply_policy_payload_preserves_fields_except_retired_a2a_metadata():
    assert importlib.util.find_spec("sentinel.interface.reply_inspection") is not None
    from sentinel.interface.reply_inspection import inspect_reply

    class RecordingPolicy(DeterministicPolicy):
        def evaluate(self, *, payload, trust):
            self.observed = (payload, trust)
            return super().evaluate(payload=payload, trust=trust)

    policy = RecordingPolicy(version="reply-contract", rules=(PolicyRule(
        rule_id="reply-text", description="Inspect the actual returned prose",
        field="metadata.prompt", mode="contains", values=("hostile Ω",),
        severity=80, incident_type="prompt_injection",
    ),))
    reply = {"result": {
        "parts": [{"kind": "text", "text": "  first"}],
        "status": {"message": {"parts": [{"type": "text", "text": "hostile Ω"}]}},
        "artifacts": [{"parts": [{"kind": "text", "text": "last  "}]}],
    }}
    reason = inspect_reply(ProtectGate(policy=policy, enforce=True), reply,
                           agent_id="agent-Ω")
    assert reason == "the reply from agent-Ω matched reply-text"
    assert policy.observed == ({
        "eventType": "agent_delegation", "action": "delegate",
        "resource": "agent-Ω", "agentId": "agent-Ω",
        "metadata": {"prompt": "first hostile Ω last"},
    }, TrustLevel.UNSIGNED)
