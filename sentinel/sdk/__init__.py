"""Thin SDK surface agents can import for protect-gated tool execution.

TWO SHAPES, FOR TWO DEPLOYMENTS
-------------------------------
`ProtectClient` (in `sentinel.sdk.local`) wraps an IN-PROCESS gate: the agent
and the authorization logic share a Python process. `SentinelClient` (in
`sentinel.sdk.remote`) talks to a DEPLOYED Sentinel over HTTP, which is the
shape most customers need, since their agent runs in their own runtime.

The remote client raises `SentinelUnavailable` on every failure to obtain a
decision. There is no return value meaning "could not tell", because a network
error that looks like an allow is what turns this from a control into
decoration.

THIS INITIALISER IS LAZY, ON PURPOSE
------------------------------------
Python imports a package before any of its submodules, so an eager
`from sentinel.application... import ...` here would run for
`from sentinel.sdk.remote import SentinelClient` too -- and that line is the
one a customer types into an agent runtime where only the standard library is
installed. The remote client, the framework adapters and the MCP stdio wrapper
import nothing outside the standard library and this package's pure modules;
the in-process pieces are resolved on first attribute access instead.

Prefer InterceptedToolClient / POST /v1/tools/execute for remote side effects.
Importing this package does not auto-instrument anything.
"""

from __future__ import annotations

import importlib
from types import MappingProxyType
from typing import Any, Mapping

from sentinel.sdk.remote import (
    Authorization,
    Decision,
    ExecutionResult,
    FailureMode,
    GateResponse,
    SentinelClient,
    SentinelRefused,
    SentinelUnavailable,
    UnsafeFailOpenWarning,
)

__all__ = [
    "Authorization",
    "Decision",
    "ExecutionResult",
    "FailureMode",
    "GateResponse",
    "InterceptedToolClient",
    "InterceptorMisuse",
    "ProtectClient",
    "ProtectControls",
    "ProtectGate",
    "ProtectedToolRunner",
    "SentinelClient",
    "SentinelRefused",
    "SentinelUnavailable",
    "ToolExecutionRefused",
    "UnsafeFailOpenWarning",
    "TrustLevel",
]

#: Names resolved on first access, and the module each lives in. A read-only
#: mapping rather than a dict: this is configuration, not state.
_LAZY: Mapping[str, str] = MappingProxyType(
    {
        "InterceptedToolClient": "sentinel.sdk.interceptor",
        "InterceptorMisuse": "sentinel.sdk.interceptor",
        "ProtectClient": "sentinel.sdk.local",
        "ProtectControls": "sentinel.application.protect_controls",
        "ProtectGate": "sentinel.application.protect_gate",
        "ProtectedToolRunner": "sentinel.application.tool_runner",
        "ToolExecutionRefused": "sentinel.application.tool_runner",
        "TrustLevel": "sentinel.domain.primitives",
    }
)


def __getattr__(name: str) -> Any:
    module_name = _LAZY.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return getattr(importlib.import_module(module_name), name)


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_LAZY))
