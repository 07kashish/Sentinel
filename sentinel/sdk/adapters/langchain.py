"""Gate a LangChain-style tool: anything with `.name` and `.invoke` or `.run`.

DUCK-TYPED, DELIBERATELY
------------------------
`langchain_core.tools.BaseTool` is not imported. The wrapper needs a name, an
`invoke`, and optionally `ainvoke` and `run`; every other attribute
(`description`, `args_schema`, `metadata`, ...) is passed through by
`__getattr__` so a tool-calling agent that inspects the tool still sees what
it expects. This is also why the wrapper is a plain object and not a
`BaseTool` subclass: subclassing would make the SDK's import depend on the
framework version, and the gate must not be the thing an upgrade breaks.

WHAT THE GATE SEES
------------------
LangChain calls a tool with a dict of arguments, a `ToolCall` dict
(`{"name", "args", "id", "type": "tool_call"}`), or a bare string for a
single-input tool. All three are reduced to the argument object the server
digests -- the string becomes `{"input": <string>}`, named so the gate's
record says what it was.
"""

from __future__ import annotations

from typing import Any, Mapping

from sentinel.sdk.adapters._gate import gate
from sentinel.sdk.remote import SentinelClient

__all__ = ["GuardedTool", "guard_tool"]


def _arguments_of(tool_input: Any) -> dict[str, Any]:
    if isinstance(tool_input, Mapping):
        if tool_input.get("type") == "tool_call" and isinstance(
            tool_input.get("args"), Mapping
        ):
            return dict(tool_input["args"])
        return dict(tool_input)
    if isinstance(tool_input, str):
        return {"input": tool_input}
    return {"input": tool_input}


class GuardedTool:
    """A tool with Sentinel in front of every `invoke`, `ainvoke` and `run`."""

    __slots__ = (
        "_client",
        "_tool",
        "_agent_id",
        "_action",
        "_resource",
        "_metadata",
        "_trust_level",
        "_execute_remotely",
    )

    def __init__(
        self,
        client: SentinelClient,
        tool: Any,
        *,
        agent_id: str,
        action: str = "",
        resource: str = "",
        metadata: Mapping[str, Any] | None = None,
        trust_level: str = "",
        execute_remotely: bool = False,
    ) -> None:
        name = str(getattr(tool, "name", "") or "").strip()
        if not name:
            raise TypeError("guard_tool needs an object with a non-empty `name`")
        if not callable(getattr(tool, "invoke", None)) and not callable(
            getattr(tool, "run", None)
        ):
            raise TypeError(
                f"tool {name!r} has neither `invoke` nor `run`; nothing to gate"
            )
        self._client = client
        self._tool = tool
        self._agent_id = agent_id
        self._action = action
        self._resource = resource
        self._metadata = metadata
        self._trust_level = trust_level
        self._execute_remotely = execute_remotely

    @property
    def name(self) -> str:
        return str(self._tool.name)

    @property
    def wrapped(self) -> Any:
        return self._tool

    def __getattr__(self, attribute: str) -> Any:
        # Only reached for attributes this class does not define; delegated so
        # `description`, `args_schema` and friends read through unchanged.
        return getattr(self._tool, attribute)

    def _gate(self, tool_input: Any):
        return gate(
            self._client,
            agent_id=self._agent_id,
            tool=self.name,
            arguments=_arguments_of(tool_input),
            action=self._action,
            resource=self._resource,
            metadata=self._metadata,
            trust_level=self._trust_level,
        )

    def _remote(self, call) -> Any:
        return self._client.execute(
            agent_id=self._agent_id,
            tool=self.name,
            action=call.action,
            arguments=call.arguments,
            resource=self._resource,
            metadata=self._metadata,
            trust_level=self._trust_level or "unsigned",
            authorization=call.authorization,
        ).result

    def invoke(self, tool_input: Any, config: Any = None, **kwargs: Any) -> Any:
        call = self._gate(tool_input)
        if self._execute_remotely:
            return self._remote(call)
        return self._tool.invoke(tool_input, config, **kwargs)

    async def ainvoke(self, tool_input: Any, config: Any = None, **kwargs: Any) -> Any:
        call = self._gate(tool_input)
        if self._execute_remotely:
            return self._remote(call)
        ainvoke = getattr(self._tool, "ainvoke", None)
        if callable(ainvoke):
            return await ainvoke(tool_input, config, **kwargs)
        return self._tool.invoke(tool_input, config, **kwargs)

    def run(self, tool_input: Any, **kwargs: Any) -> Any:
        call = self._gate(tool_input)
        if self._execute_remotely:
            return self._remote(call)
        runner = getattr(self._tool, "run", None)
        if callable(runner):
            return runner(tool_input, **kwargs)
        return self._tool.invoke(tool_input, **kwargs)


def guard_tool(client: SentinelClient, tool: Any, **options: Any) -> GuardedTool:
    """`GuardedTool(client, tool, agent_id=..., ...)`, as a function."""
    return GuardedTool(client, tool, **options)
