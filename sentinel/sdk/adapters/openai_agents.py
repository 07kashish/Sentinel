"""Gate tools written for the OpenAI Agents SDK pattern.

TWO ENTRY POINTS, FOR THE TWO PLACES A TOOL EXISTS
--------------------------------------------------
`guard_function` wraps a plain Python function BEFORE it is decorated with
`@function_tool`, so the schema the SDK derives is the original signature and
the gate runs inside every invocation. `guard_function_tool` wraps an
already-built `FunctionTool` -- any object with `.name` and an async
`.on_invoke_tool(ctx, input_json)` -- by replacing that one callable.

Neither imports `agents`. The SDK is duck-typed at exactly the attributes the
pattern needs, so this module imports with nothing installed and an upgrade of
the framework cannot remove the gate.

WHAT A STOP LOOKS LIKE
----------------------
`GateRefused`, raised out of the tool. The Agents SDK surfaces a tool
exception to the run loop, which is the right place: a refusal is not a tool
result the model should reason about as if the tool had run.
"""

from __future__ import annotations

import copy
import dataclasses
import functools
import inspect
import json
from typing import Any, Callable, Mapping

from sentinel.sdk.adapters._gate import NotCanonical, gate
from sentinel.sdk.remote import SentinelClient

__all__ = ["guard_function", "guard_function_tool"]


def guard_function(
    client: SentinelClient,
    fn: Callable[..., Any],
    *,
    agent_id: str,
    tool_name: str = "",
    action: str = "",
    resource: str = "",
    metadata: Mapping[str, Any] | None = None,
    trust_level: str = "",
    execute_remotely: bool = False,
) -> Callable[..., Any]:
    """Return `fn` with the gate in front of it. Signature preserved.

    Arguments are bound against `fn`'s signature so the gate sees them by
    NAME, in the shape the server's parameter digest covers, regardless of
    whether the SDK calls positionally or by keyword.
    """
    name = tool_name or getattr(fn, "__name__", "") or "tool"
    signature = inspect.signature(fn)

    def _gate_call(args: tuple[Any, ...], kwargs: Mapping[str, Any]):
        bound = signature.bind(*args, **kwargs)
        bound.apply_defaults()
        return gate(
            client,
            agent_id=agent_id,
            tool=name,
            arguments=dict(bound.arguments),
            action=action,
            resource=resource,
            metadata=metadata,
            trust_level=trust_level,
        )

    def _remote(call) -> Any:
        return client.execute(
            agent_id=agent_id,
            tool=name,
            action=call.action,
            arguments=call.arguments,
            resource=resource,
            metadata=metadata,
            trust_level=trust_level or "unsigned",
            authorization=call.authorization,
        ).result

    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def guarded_async(*args: Any, **kwargs: Any) -> Any:
            call = _gate_call(args, kwargs)
            if execute_remotely:
                return _remote(call)
            return await fn(*args, **kwargs)

        return guarded_async

    @functools.wraps(fn)
    def guarded(*args: Any, **kwargs: Any) -> Any:
        call = _gate_call(args, kwargs)
        if execute_remotely:
            return _remote(call)
        return fn(*args, **kwargs)

    return guarded


def guard_function_tool(
    client: SentinelClient,
    tool: Any,
    *,
    agent_id: str,
    action: str = "",
    resource: str = "",
    metadata: Mapping[str, Any] | None = None,
    trust_level: str = "",
    execute_remotely: bool = False,
) -> Any:
    """Return a copy of a `FunctionTool` whose `on_invoke_tool` is gated.

    A copy, not a mutation: the caller's original stays ungated and usable
    for comparison, and a dataclass-based tool is copied with
    `dataclasses.replace` so nothing else about it changes.

    The SDK hands the tool its arguments as a JSON string. That string is
    parsed HERE, gated, and the ORIGINAL string handed on -- re-serialising
    it could not promise the tool sees exactly what the model produced.
    """
    name = str(getattr(tool, "name", "") or "").strip()
    original = getattr(tool, "on_invoke_tool", None)
    if not name or not callable(original):
        raise TypeError(
            "guard_function_tool needs an object with a non-empty `name` and a "
            "callable `on_invoke_tool`, which is what a FunctionTool has"
        )

    async def on_invoke_tool(ctx: Any, input_json: str) -> Any:
        try:
            arguments = json.loads(input_json) if input_json else {}
        except ValueError as error:
            raise NotCanonical(
                f"tool {name!r} received arguments that are not JSON: {error}"
            ) from error
        if not isinstance(arguments, Mapping):
            raise NotCanonical(
                f"tool {name!r} received a JSON {type(arguments).__name__}; "
                "tool arguments must be an object"
            )
        call = gate(
            client,
            agent_id=agent_id,
            tool=name,
            arguments=arguments,
            action=action,
            resource=resource,
            metadata=metadata,
            trust_level=trust_level,
        )
        if execute_remotely:
            return client.execute(
                agent_id=agent_id,
                tool=name,
                action=call.action,
                arguments=call.arguments,
                resource=resource,
                metadata=metadata,
                trust_level=trust_level or "unsigned",
                authorization=call.authorization,
            ).result
        outcome = original(ctx, input_json)
        if inspect.isawaitable(outcome):
            return await outcome
        return outcome

    if dataclasses.is_dataclass(tool) and not isinstance(tool, type):
        return dataclasses.replace(tool, on_invoke_tool=on_invoke_tool)
    guarded = copy.copy(tool)
    setattr(guarded, "on_invoke_tool", on_invoke_tool)
    return guarded
