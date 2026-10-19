"""Bounds on attacker-supplied structure. Refuse, never truncate.

WHY A TYPE AND NOT A VALIDATOR CALL
-----------------------------------
`EventPayload.metadata` was `Mapping[str, Any]` with a length limit on its
siblings and none on itself. `action` was capped at 8192 characters and `resource`
at 2048, which reads as careful -- and then the one field with unbounded structure
had no cap at all. Everything below is reachable through it:

  * A dict nested ten thousand deep. `json.dumps` on it raises
    `RecursionError`, which is not a `ValueError`, so a handler that catches
    JSON errors does not catch this. The canonicalisation that a signature
    covers runs `json.dumps`.
  * One key holding fifty megabytes. It is persisted, re-read by every
    subsequent pipeline step, canonicalised for the event digest, and copied
    into the audit trail.
  * Fifty thousand keys, each tiny. Passes any per-value length check, and
    sorting them for canonicalisation is the cost.

This is the "memory poisoning" class in concrete terms: the incident record is
the context every later step reads, so whatever lands in it is read repeatedly, by
code that assumes it is small.

REFUSE RATHER THAN TRUNCATE
--------------------------
Truncating attacker-supplied structure silently changes evidence. A `metadata`
that is trimmed to fit is a record that says something the agent did not say, in a
system whose output is meant to be relied on. A 400 naming the limit is honest and
the client can retry with less.

BOUNDS ARE CHECKED WHILE WALKING, NOT AFTER SERIALISING
-------------------------------------------------------
`len(json.dumps(value))` has already built the fifty-megabyte string. The walk
below carries a running byte budget and stops the moment it is exceeded, so the
cost of rejecting a hostile payload is proportional to the limit and not to the
payload.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from sentinel.domain.errors import DomainRuleViolated

__all__ = ["BoundsExceeded", "StructureBounds", "check_bounds"]


class BoundsExceeded(DomainRuleViolated):
    """Attacker-supplied structure exceeded a declared bound. Refused."""


@dataclass(frozen=True, slots=True)
class StructureBounds:
    """The limits applied to one untrusted structure.

    Defaults are sized for telemetry metadata: a handful of small keys describing
    a tool call. They are deliberately tight, because the cost of raising a limit
    for a legitimate client is a config change and the cost of an absent limit is
    an outage.
    """

    #: Nesting depth. 6 is generous for a flat property bag and far below the
    #: point at which recursive serialisation threatens the stack.
    max_depth: int = 6
    #: Keys in any single mapping.
    max_keys: int = 64
    #: Items in any single sequence.
    max_items: int = 256
    #: Characters in any single string, key or value.
    max_string: int = 4096
    #: Total approximate serialised size of the whole structure.
    max_total_bytes: int = 65_536
    #: Total number of nodes, so breadth-across-many-small-containers is bounded
    #: even when no single container exceeds its own limit.
    max_nodes: int = 2048


def check_bounds(
    value: Any, bounds: StructureBounds, *, field: str = "value"
) -> None:
    """Walk `value` and raise `BoundsExceeded` at the first violation.

    Iterative rather than recursive. A recursive checker is itself vulnerable to
    the deeply-nested input it exists to reject: it would raise `RecursionError`
    -- not a `DomainRuleViolated`, so it escapes as a 500 rather than a 400, and
    the attacker learns they found something.
    """
    budget = _Budget(bounds, field)
    # (node, depth). Explicit stack, so depth is data rather than call frames.
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        node, depth = stack.pop()
        budget.count_node()
        if depth > bounds.max_depth:
            budget.fail(
                f"nesting is deeper than {bounds.max_depth}. Deeply nested "
                "structure makes serialisation recursive, and the canonical form "
                "a signature covers is produced by serialising this."
            )
        if isinstance(node, Mapping):
            if len(node) > bounds.max_keys:
                budget.fail(
                    f"a mapping has {len(node)} keys, over the {bounds.max_keys} "
                    "limit"
                )
            for key, child in node.items():
                if not isinstance(key, str):
                    budget.fail(
                        f"a mapping key is {type(key).__name__}, not a string. "
                        "Non-string keys do not survive JSON canonicalisation, so "
                        "the signed form would differ from the submitted form."
                    )
                budget.count_string(key, what="a key")
                stack.append((child, depth + 1))
        elif isinstance(node, (list, tuple)):
            if len(node) > bounds.max_items:
                budget.fail(
                    f"a sequence has {len(node)} items, over the "
                    f"{bounds.max_items} limit"
                )
            for child in node:
                stack.append((child, depth + 1))
        elif isinstance(node, str):
            budget.count_string(node, what="a string value")
        elif isinstance(node, bool) or node is None:
            # `bool` before `int` deliberately: bool is a subclass of int.
            budget.spend(5)
        elif isinstance(node, int):
            budget.spend(len(str(node)))
        elif isinstance(node, float):
            # Rejected rather than bounded. A float does not round-trip through
            # JSON identically on every platform, so a signature computed over a
            # canonical form containing one is not reliably verifiable. Send a
            # string or an integer.
            budget.fail(
                "floating-point values are refused: they do not round-trip "
                "through JSON identically across platforms, so a signature over "
                "the canonical form would not reliably verify. Use a string."
            )
        else:
            budget.fail(
                f"values of type {type(node).__name__} are not permitted; "
                "metadata must be JSON-shaped"
            )


class _Budget:
    """Running totals for one walk. Fails fast, so hostile input costs the limit."""

    __slots__ = ("_bounds", "_field", "_bytes", "_nodes")

    def __init__(self, bounds: StructureBounds, field: str) -> None:
        self._bounds = bounds
        self._field = field
        self._bytes = 0
        self._nodes = 0

    def fail(self, why: str) -> None:
        raise BoundsExceeded(f"{self._field}: {why}")

    def count_node(self) -> None:
        self._nodes += 1
        if self._nodes > self._bounds.max_nodes:
            self.fail(
                f"more than {self._bounds.max_nodes} values. Many small "
                "containers stay under every individual limit while the total is "
                "still unbounded, which is the shape this bound exists to catch."
            )

    def count_string(self, text: str, *, what: str) -> None:
        if len(text) > self._bounds.max_string:
            self.fail(
                f"{what} is {len(text)} characters, over the "
                f"{self._bounds.max_string} limit"
            )
        # +2 for the quotes a serialiser will add. Approximate on purpose: this is
        # a budget, not an accounting record, and an exact byte count would mean
        # encoding every value to measure it.
        self.spend(len(text) + 2)

    def spend(self, amount: int) -> None:
        self._bytes += amount
        if self._bytes > self._bounds.max_total_bytes:
            self.fail(
                f"total size exceeds {self._bounds.max_total_bytes} bytes. "
                "Refused rather than truncated: trimming attacker-supplied "
                "structure would record something the agent did not send."
            )
