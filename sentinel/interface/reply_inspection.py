"""Inspect MCP reply text with the existing deterministic protect gate."""
from __future__ import annotations

from typing import Any, Mapping

from sentinel.application.protect_gate import ProtectGate
from sentinel.domain.primitives import TrustLevel
from sentinel.domain.reply_text import text_parts


def inspect_reply(
    gate: ProtectGate, reply: Mapping[str, Any] | None, *, agent_id: str
) -> str | None:
    """Return the refusal reason, preserving the legacy MCP policy projection.

    Only synthetic A2A registry metadata is retired. Event type, action,
    resource, agent, prompt normalization and unsigned trust are unchanged.
    """
    if not reply:
        return None
    result = reply.get("result")
    if not isinstance(result, Mapping):
        return None
    candidates = [result]
    status_block = result.get("status")
    if isinstance(status_block, Mapping) and isinstance(
        status_block.get("message"), Mapping
    ):
        candidates.append(status_block["message"])
    for entry in result.get("artifacts", ()) or ():
        if isinstance(entry, Mapping):
            candidates.append(entry)
    text = " ".join(part for c in candidates for part in text_parts(c)).strip()
    if not text:
        return None
    outcome = gate.evaluate(payload={
        "eventType": "agent_delegation",
        "action": "delegate",
        "resource": agent_id,
        "agentId": agent_id,
        "metadata": {"prompt": text},
    }, trust=TrustLevel.UNSIGNED)
    if outcome.decision.stops_action:
        return (
            f"the reply from {agent_id} matched "
            f"{', '.join(outcome.matched_rules) or 'a detection rule'}"
        )
    return None
