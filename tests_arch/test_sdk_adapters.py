"""Framework adapters fail closed and do not import their frameworks."""

from __future__ import annotations

import asyncio
import json

import pytest

from sentinel.infrastructure.outbound import OutboundRefused
from sentinel.sdk.adapters._gate import GateRefused
from sentinel.sdk.adapters.anthropic import gate_tool_use
from sentinel.sdk.adapters.langchain import guard_tool
from sentinel.sdk.adapters.openai_agents import guard_function, guard_function_tool
from sentinel.sdk.remote import Decision, SentinelClient, SentinelUnavailable

from tests_arch.test_sdk_remote import KEY, _FakeTransport, _Response


def _remote(body):
    return SentinelClient(
        base_url="https://sentinel.example",
        api_key=KEY,
        _transport=_FakeTransport(
            response=_Response(200, json.dumps(body).encode("utf-8"))
        ),
    )


def _broken():
    return SentinelClient(
        base_url="https://sentinel.example",
        api_key=KEY,
        _transport=_FakeTransport(error=OutboundRefused("unknown decision")),
    )


def test_openai_function_wrapper_checks_before_invocation():
    called: list[dict] = []

    def tool(name: str) -> str:
        called.append({"name": name})
        return f"hello {name}"

    guarded = guard_function(
        _remote({"decision": "block", "reason": "policy"}),
        tool,
        agent_id="agent-1",
    )

    with pytest.raises(GateRefused):
        guarded("Ada")
    assert called == []


def test_openai_function_wrapper_fail_closes_on_transport_error():
    called = False

    def tool() -> str:
        nonlocal called
        called = True
        return "ran"

    with pytest.raises(SentinelUnavailable):
        guard_function(_broken(), tool, agent_id="agent-1")()
    assert called is False


def test_openai_function_wrapper_uses_remote_execute_when_authorized():
    seen: dict[str, object] = {}

    class SwapTransport:
        def __init__(self):
            self.calls = 0

        def request(self, *, method, url, headers=None, body=None, idempotent=False):
            self.calls += 1
            seen["url"] = url
            seen["body"] = body
            if self.calls == 1:
                return _Response(
                    200,
                    json.dumps(
                        {
                            "decision": "allow",
                            "authorization": {"token": "tok-1", "digest": "d" * 64},
                        }
                    ).encode("utf-8"),
                )
            return _Response(
                200,
                json.dumps(
                    {
                        "tool": "email",
                        "result": "sent",
                        "protect": {"decision": "allow"},
                    }
                ).encode("utf-8"),
            )

    client = SentinelClient(
        base_url="https://sentinel.example",
        api_key=KEY,
        _transport=SwapTransport(),
    )

    def local_tool(to: str) -> str:
        raise AssertionError(f"local tool should not run for {to}")

    guarded = guard_function(
        client,
        local_tool,
        agent_id="agent-1",
        tool_name="email",
        execute_remotely=True,
    )

    assert guarded("ops@example.com") == "sent"
    assert json.loads(seen["body"].decode("utf-8"))["authorization"] == "tok-1"  # type: ignore[union-attr]


def test_openai_function_tool_wrapper_gates_json_arguments():
    class Tool:
        name = "lookup"

        async def on_invoke_tool(self, ctx, input_json):
            return json.loads(input_json)["query"]

    guarded = guard_function_tool(
        _remote({"decision": "allow"}), Tool(), agent_id="agent-1"
    )

    assert asyncio.run(guarded.on_invoke_tool(None, '{"query":"status"}')) == "status"


def test_langchain_wrapper_gates_invoke_and_preserves_attributes():
    class Tool:
        name = "search"
        description = "Search things"

        def invoke(self, tool_input, config=None, **kwargs):
            return tool_input["q"]

    guarded = guard_tool(_remote({"decision": "warn"}), Tool(), agent_id="agent-1")

    assert guarded.description == "Search things"
    assert guarded.invoke({"q": "policy"}) == "policy"


def test_langchain_wrapper_fail_closes_on_unknown_decision():
    class Tool:
        name = "search"

        def invoke(self, tool_input, config=None, **kwargs):
            raise AssertionError("tool should not run")

    guarded = guard_tool(
        _remote({"decision": "new_decision"}), Tool(), agent_id="agent-1"
    )

    with pytest.raises(SentinelUnavailable):
        guarded.invoke({"q": "policy"})


def test_anthropic_tool_use_returns_error_block_on_stop_decision():
    result = gate_tool_use(
        _remote({"decision": "require_jit_credential", "reason": "credential"}),
        {"type": "tool_use", "id": "tu-1", "name": "deploy", "input": {"env": "prod"}},
        agent_id="agent-1",
    )

    assert result.approved is False
    assert result.tool_result == {
        "type": "tool_result",
        "tool_use_id": "tu-1",
        "is_error": True,
        "content": "Sentinel stopped this tool call: require_jit_credential -- credential",
    }


def test_anthropic_tool_use_can_return_error_block_on_transport_error():
    result = gate_tool_use(
        _broken(),
        {"type": "tool_use", "id": "tu-1", "name": "deploy", "input": {}},
        agent_id="agent-1",
        on_unavailable="tool_result",
    )

    assert result.approved is False
    assert result.tool_result is not None
    assert "authorization gate could not be reached" in result.tool_result["content"]


def test_adapter_modules_do_not_import_frameworks():
    import sys

    assert "agents" not in sys.modules
    assert "langchain_core" not in sys.modules
    assert "anthropic" not in sys.modules
    assert Decision.CONTAIN.stops_action is True


# ── Gemini / Antigravity: a functionCall part is gated before the host runs it ──


def test_gemini_function_call_returns_a_function_response_on_stop_decision():
    from sentinel.sdk.adapters.gemini import gate_function_call

    result = gate_function_call(
        _remote({"decision": "require_approval", "reason": "protected change"}),
        {"functionCall": {"id": "fc-1", "name": "deploy", "args": {"env": "prod"}}},
        agent_id="agent:antigravity",
    )
    assert result.approved is False
    assert result.function_response == {"functionResponse": {
        "id": "fc-1", "name": "deploy",
        "response": {"error": "Sentinel stopped this function call: require_approval -- protected change", "sentinel_refused": True},
    }}


def test_gemini_function_call_is_approved_with_the_arguments_the_gate_saw():
    from sentinel.sdk.adapters.gemini import gate_function_call

    class _Call:
        name, id, args = "search", None, {"q": "hello"}

    class _Part:
        function_call = _Call()

    result = gate_function_call(_remote({"decision": "allow", "reason": ""}), _Part(), agent_id="agent:antigravity")
    assert result.approved is True and result.args == {"q": "hello"} and result.function_response is None


def test_gemini_function_call_fails_closed_on_transport_error():
    from sentinel.sdk.adapters.gemini import gate_function_call

    with pytest.raises(SentinelUnavailable):
        gate_function_call(_broken(), {"functionCall": {"name": "deploy", "args": {}}}, agent_id="a")
    result = gate_function_call(_broken(), {"functionCall": {"name": "deploy", "args": {}}}, agent_id="a",
                                on_unavailable="function_response")
    assert result.approved is False and "could not be reached" in result.function_response["functionResponse"]["response"]["error"]


def test_gemini_adapter_imports_no_google_sdk():
    import sys

    import sentinel.sdk.adapters.gemini  # noqa: F401

    assert not any(m.startswith(("google.genai", "google.generativeai", "vertexai")) for m in sys.modules)
