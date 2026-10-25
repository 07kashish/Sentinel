"""Bounded text-part extraction shared by reply inspectors."""
from __future__ import annotations

from typing import Any, Mapping

MAX_PART_DEPTH = 12
MAX_TEXT_BYTES = 65_536


def text_parts(message: Mapping[str, Any]) -> tuple[str, ...]:
    """Extract text parts in order with the existing depth and length limits.

    Binary and structured-data parts are not stringified as prompt text.
    The historical MAX_TEXT_BYTES bound counts Python string characters;
    extraction preserves that behavior for policy compatibility.
    """
    collected: list[str] = []
    budget = MAX_TEXT_BYTES

    def _walk(node: Any, depth: int) -> None:
        nonlocal budget
        if depth > MAX_PART_DEPTH or budget <= 0:
            return
        if isinstance(node, Mapping):
            if str(node.get("kind") or node.get("type") or "") == "text":
                text = node.get("text")
                if isinstance(text, str) and text:
                    clipped = text[:budget]
                    budget -= len(clipped)
                    collected.append(clipped)
                return
            for value in node.values():
                _walk(value, depth + 1)
        elif isinstance(node, (list, tuple)):
            for item in node:
                _walk(item, depth + 1)

    _walk(message.get("parts", ()), 0)
    return tuple(collected)
