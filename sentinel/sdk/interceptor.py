"""Fail-closed network-style tool interceptor for agent SDKs.

If an agent imports this module but calls tools without going through
`InterceptedToolClient.execute`, that is an integration bug the architecture
tests cannot catch at runtime. This client refuses to expose a raw side-effect
hook — the only public execute path hits Sentinel's inline proxy contract.

When `require_enrolled` is True (default), `agent_id` must be non-empty and an
optional `is_enrolled` predicate must accept it — refusing silent bypass by
anonymous or unknown agents that still import the SDK.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping, Protocol

from sentinel.application.tool_proxy import InlineToolProxy, ToolProxyRefused
from sentinel.domain.errors import DomainRuleViolated
from sentinel.domain.primitives import TrustLevel

__all__ = ["InterceptedToolClient", "InterceptorMisuse", "RemoteToolTransport"]


class InterceptorMisuse(DomainRuleViolated):
    """Caller attempted to bypass the interceptor contract."""

    is_retryable = False


class RemoteToolTransport(Protocol):
    """HTTP (or equivalent) transport to POST /v1/tools/execute."""

    def post_execute(self, body: Mapping[str, Any]) -> Mapping[str, Any]: ...


class InterceptedToolClient:
    """SDK entry: either local InlineToolProxy or remote /v1/tools/execute."""

    __slots__ = ("_local", "_remote", "_require_enrolled", "_is_enrolled")

    def __init__(
        self,
        *,
        local: InlineToolProxy | None = None,
        remote: RemoteToolTransport | None = None,
        require_enrolled: bool = True,
        is_enrolled: Callable[[str], bool] | None = None,
    ) -> None:
        if local is None and remote is None:
            raise InterceptorMisuse(
                "InterceptedToolClient requires local proxy or remote transport; "
                "refusing to construct a bypassable client"
            )
        self._local = local
        self._remote = remote
        self._require_enrolled = require_enrolled
        self._is_enrolled = is_enrolled

    def execute(
        self,
        *,
        agent_id: str,
        tool: str,
        trust: TrustLevel | str = TrustLevel.UNSIGNED,
        arguments: Mapping[str, Any] | None = None,
        resource: str = "",
        action: str = "",
        metadata: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        if self._require_enrolled:
            if not str(agent_id or "").strip():
                raise InterceptorMisuse(
                    "agent_id required for enrolled SDK execution; refusing anonymous bypass"
                )
            if self._is_enrolled is not None and not self._is_enrolled(agent_id):
                raise InterceptorMisuse(
                    f"agent {agent_id!r} is not enrolled; refusing tool execute outside "
                    "Sentinel enrollment contract"
                )
        trust_level = trust if isinstance(trust, TrustLevel) else TrustLevel(trust)
        if self._local is not None:
            try:
                return self._local.execute(
                    agent_id=agent_id,
                    tool=tool,
                    trust=trust_level,
                    arguments=arguments,
                    resource=resource,
                    action=action,
                    metadata=metadata,
                )
            except ToolProxyRefused as exc:
                raise InterceptorMisuse(str(exc)) from exc
        if self._remote is None:
            raise InterceptorMisuse("no remote transport configured")
        return self._remote.post_execute(
            {
                "agentId": agent_id,
                "tool": tool,
                "trustLevel": trust_level.value,
                "arguments": dict(arguments or {}),
                "resource": resource,
                "action": action or tool,
                "metadata": dict(metadata or {}),
            }
        )

    def bind_local_effect(
        self, name: str, runner: Callable[[Mapping[str, Any]], Any]
    ) -> None:
        """Register a local effect. Refused when only remote transport is set."""
        if self._local is None:
            raise InterceptorMisuse(
                "cannot bind local effects on a remote-only interceptor"
            )
        from sentinel.application.tool_proxy import RegisteredSideEffect

        self._local.register(RegisteredSideEffect(name=name, runner=runner))
