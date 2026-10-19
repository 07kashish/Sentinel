"""Gate a Gemini `functionCall` part before the host runs the function.

WHERE THIS SITS
---------------
With the Gemini API (google-genai, Vertex AI, or an agent host built on them
such as Antigravity) the HOST executes tools: the model answers with a part
carrying `functionCall: {name, args}`, the host runs the function and replies
with a `functionResponse` part. This helper goes between the two. It does not
call Gemini and does not run anything; it returns either the arguments the
gate approved or the `functionResponse` part the host sends back INSTEAD of
running the function, so the model learns the call was refused and why.

Both wire shapes are accepted: the REST/JSON part (`{"functionCall": {...}}`)
and the SDK object (`part.function_call.name`, `.args`). Nothing from the
Gemini SDK is imported, so this file has no dependency on it -- the same rule
every adapter here keeps.

THE DEFAULT ON AN OUTAGE IS TO RAISE
------------------------------------
`on_unavailable="raise"` propagates `SentinelUnavailable`, the fail-closed
shape of the rest of the SDK. `on_unavailable="function_response"` tells the
model the function could not be run -- also fail-closed, since the function
does not run either way; only who hears about it differs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Mapping

from sentinel.sdk.adapters._gate import GateRefused, NotCanonical, gate
from sentinel.sdk.remote import GateResponse, SentinelClient, SentinelUnavailable

__all__ = ["GatedFunctionCall", "gate_function_call"]


@dataclass(frozen=True, slots=True)
class GatedFunctionCall:
    """The gate's answer for one `functionCall` part.

    `approved` is the field to branch on. When False, `function_response` is
    the part to send back in the function's place; when True it is None and
    `args` is what the function may be run with.
    """

    name: str
    args: Mapping[str, Any]
    approved: bool
    reason: str
    call_id: str = ""
    response: GateResponse | None = None

    @property
    def requires_redaction(self) -> bool:
        return self.response is not None and self.response.requires_redaction

    @property
    def function_response(self) -> dict[str, Any] | None:
        if self.approved:
            return None
        body: dict[str, Any] = {"name": self.name, "response": {"error": self.reason, "sentinel_refused": True}}
        if self.call_id:
            body["id"] = self.call_id
        return {"functionResponse": body}


def _unpack(part: Any) -> tuple[str, str, Mapping[str, Any]]:
    """(name, id, args) from a JSON part or an SDK part object."""
    call: Any = None
    if isinstance(part, Mapping):
        call = part.get("functionCall", part.get("function_call"))
    else:
        call = getattr(part, "function_call", None)
    if call is None:
        raise ValueError("expected a part carrying a functionCall")
    if isinstance(call, Mapping):
        name, call_id, args = call.get("name", ""), call.get("id", ""), call.get("args", {})
    else:
        name, call_id, args = getattr(call, "name", ""), getattr(call, "id", "") or "", getattr(call, "args", {})
    name = str(name or "").strip()
    if not name:
        raise ValueError("functionCall has no name")
    if args is None:
        args = {}
    if not isinstance(args, Mapping):
        raise ValueError("functionCall args must be an object")
    return name, str(call_id or ""), args


def gate_function_call(
    client: SentinelClient,
    part: Any,
    *,
    agent_id: str,
    action: str = "",
    resource: str = "",
    metadata: Mapping[str, Any] | None = None,
    trust_level: str = "",
    on_unavailable: Literal["raise", "function_response"] = "raise",
) -> GatedFunctionCall:
    """Gate one `functionCall` part. A malformed part is a caller error, not a decision."""
    name, call_id, args = _unpack(part)
    try:
        call = gate(client, agent_id=agent_id, tool=name, arguments=args, action=action,
                    resource=resource, metadata=metadata, trust_level=trust_level)
    except GateRefused as refused:
        return GatedFunctionCall(
            name=name, args=dict(args), approved=False, call_id=call_id, response=refused.response,
            reason=(f"Sentinel stopped this function call: {refused.response.decision.value}"
                    + (f" -- {refused.response.reason}" if refused.response.reason else "")),
        )
    except NotCanonical as error:
        return GatedFunctionCall(name=name, args=dict(args), approved=False, call_id=call_id,
                                 reason=f"this function call could not be evaluated: {error}")
    except SentinelUnavailable as outage:
        if on_unavailable == "raise":
            raise
        return GatedFunctionCall(name=name, args=dict(args), approved=False, call_id=call_id,
                                 reason=f"this function call was NOT run: the authorization gate could not be reached ({outage})")
    return GatedFunctionCall(name=name, args=call.arguments, approved=True, call_id=call_id,
                             reason=call.response.reason, response=call.response)
