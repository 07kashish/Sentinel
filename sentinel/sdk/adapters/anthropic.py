"""Gate an Anthropic `tool_use` content block before the host runs the tool.

WHERE THIS SITS
---------------
With the Messages API the HOST executes tools: the model returns a
`{"type": "tool_use", "id", "name", "input"}` block, the host runs the tool
and answers with a `tool_result` block. This helper goes between the two. It
does not call the API and does not run anything; it returns either the input
the gate approved or a `tool_result` error block the host sends back instead
of running the tool.

THE DEFAULT ON AN OUTAGE IS TO RAISE
------------------------------------
`on_unavailable="raise"` propagates `SentinelUnavailable`, which is the
fail-closed shape the rest of the SDK has. `on_unavailable="tool_result"` is
for a host loop that would rather tell the model the tool could not be run
than abort the conversation -- ALSO fail-closed, since the tool does not run
either way; the difference is only who hears about it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Mapping

from sentinel.sdk.adapters._gate import GateRefused, NotCanonical, gate
from sentinel.sdk.remote import GateResponse, SentinelClient, SentinelUnavailable

__all__ = ["GatedToolUse", "gate_tool_use"]


@dataclass(frozen=True, slots=True)
class GatedToolUse:
    """The gate's answer for one `tool_use` block.

    `approved` is the field to branch on. When False, `tool_result` is the
    error block to send back in the tool's place; when True it is None and
    `input` is what the tool may be run with.
    """

    tool_use_id: str
    name: str
    input: Mapping[str, Any]
    approved: bool
    reason: str
    response: GateResponse | None = None

    @property
    def requires_redaction(self) -> bool:
        return self.response is not None and self.response.requires_redaction

    @property
    def tool_result(self) -> dict[str, Any] | None:
        if self.approved:
            return None
        return {
            "type": "tool_result",
            "tool_use_id": self.tool_use_id,
            "is_error": True,
            "content": self.reason,
        }


def gate_tool_use(
    client: SentinelClient,
    block: Mapping[str, Any],
    *,
    agent_id: str,
    action: str = "",
    resource: str = "",
    metadata: Mapping[str, Any] | None = None,
    trust_level: str = "",
    on_unavailable: Literal["raise", "tool_result"] = "raise",
) -> GatedToolUse:
    """Gate one `tool_use` block. A malformed block is a caller error, not a decision."""
    if not isinstance(block, Mapping) or block.get("type") != "tool_use":
        raise ValueError("expected a content block with type 'tool_use'")
    name = str(block.get("name", "")).strip()
    tool_use_id = str(block.get("id", ""))
    tool_input = block.get("input", {})
    if not name:
        raise ValueError("tool_use block has no tool name")
    if tool_input is None:
        tool_input = {}
    if not isinstance(tool_input, Mapping):
        raise ValueError("tool_use block input must be an object")

    try:
        call = gate(
            client,
            agent_id=agent_id,
            tool=name,
            arguments=tool_input,
            action=action,
            resource=resource,
            metadata=metadata,
            trust_level=trust_level,
        )
    except GateRefused as refused:
        return GatedToolUse(
            tool_use_id=tool_use_id,
            name=name,
            input=dict(tool_input),
            approved=False,
            reason=(
                f"Sentinel stopped this tool call: {refused.response.decision.value}"
                + (f" -- {refused.response.reason}" if refused.response.reason else "")
            ),
            response=refused.response,
        )
    except NotCanonical as error:
        return GatedToolUse(
            tool_use_id=tool_use_id,
            name=name,
            input=dict(tool_input),
            approved=False,
            reason=f"this tool call could not be evaluated: {error}",
        )
    except SentinelUnavailable as outage:
        if on_unavailable == "raise":
            raise
        return GatedToolUse(
            tool_use_id=tool_use_id,
            name=name,
            input=dict(tool_input),
            approved=False,
            reason=(
                "this tool call was NOT run: the authorization gate could not "
                f"be reached ({outage})"
            ),
        )

    return GatedToolUse(
        tool_use_id=tool_use_id,
        name=name,
        input=call.arguments,
        approved=True,
        reason=call.response.reason,
        response=call.response,
    )
