"""Framework adapters for the remote SDK.

Each adapter is a small module that imports NOTHING from the framework it
targets. They are duck-typed against the one or two attributes the pattern
needs -- a callable, an object with `.name` and `.invoke`, a `tool_use` content
block -- so installing this package never installs a framework, and a
framework upgrade cannot break the gate.

    openai_agents  -- wrap a Python function or a FunctionTool
    langchain      -- wrap anything with `.name` and `.invoke` / `.run`
    anthropic      -- gate a `tool_use` block before the host runs the tool

All three share `_gate`, which owns the one rule that matters: a stop
decision or a transport failure raises, and the tool does not run.
"""

from sentinel.sdk.adapters._gate import (
    GatedCall,
    GateRefused,
    NotCanonical,
    canonical_bytes,
    digest_of,
    parameter_digest,
)

__all__ = [
    "GateRefused",
    "GatedCall",
    "NotCanonical",
    "canonical_bytes",
    "digest_of",
    "parameter_digest",
]
