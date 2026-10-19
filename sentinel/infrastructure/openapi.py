"""OpenAPI specs as pinnable tool definitions.

WHY THIS IS INGESTION AND NOT A SECOND GATEWAY
------------------------------------------------
An agent handed an OpenAPI document gets the same thing an MCP server gives it:
a list of named operations, each with prose the model reads as instructions and
a schema describing what it may send. The three questions are identical --

  1. is this API one we enrolled,
  2. is this operation what it was when it was approved,
  3. is the operation's DESCRIPTION itself an injection

-- and `McpGateway` already answers all three. So this module converts a spec
into the tool definitions that gateway already pins, rather than growing a
second trust engine beside it. Two engines would be two places for the answers
to disagree, which is the defect this codebase keeps finding under different
names.

The naming is inherited rather than ideal: the shared types are still called
`McpToolDefinition` because MCP is where they were written. They describe "a
named operation with server-supplied prose and a schema", which is exactly what
an OpenAPI operation is.

WHAT AN OPENAPI SPEC IS, FROM A SECURITY POINT OF VIEW
--------------------------------------------------------
It is a document, usually fetched from the API vendor, whose `summary` and
`description` fields are copied verbatim into the tool descriptions a model
reads. That makes every one of those fields attacker-controlled text on the
instruction path the moment the vendor is compromised or hostile -- the same
position an MCP tool description is in, and not a position most teams think of a
"schema file" as occupying.

The parameter schema matters too, and differently. An operation that quietly
gains a `role` parameter, or whose `path` changes from `/v1/reports/{id}` to
`/v1/admin/{id}`, is a different capability wearing the same `operationId`. The
fingerprint covers all of it.

BOUNDS, BECAUSE A SPEC IS UNTRUSTED INPUT
-------------------------------------------
A spec is parsed before anyone has decided to trust it, so parsing is where a
hostile document gets its one shot. This repository has already paid for that
lesson once: a pre-auth SAML document with three XML entities expanded to a
thousand characters and was on track to exhaust the process. So the document is
bounded on every axis a hostile author controls -- operation count, nesting
depth, and the length of the prose fields -- and `$ref` is NOT resolved.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from sentinel.domain.errors import DomainRuleViolated
from sentinel.domain.mcp import McpToolDefinition

__all__ = [
    "OpenApiRefused",
    "MAX_OPERATIONS",
    "MAX_SCHEMA_DEPTH",
    "MAX_DESCRIPTION_CHARS",
    "operations_from_spec",
    "load_spec",
]

#: A spec offering more operations than this is refused rather than enrolled.
#: An operator cannot meaningfully review a thousand operations, and enrolment
#: is supposed to mean somebody looked.
MAX_OPERATIONS = 500

#: Refuse a parameter schema nested deeper than this. Depth is the cheap axis
#: for a hostile document: nesting costs the author one character per level and
#: costs the parser a stack frame.
MAX_SCHEMA_DEPTH = 20

#: Prose fields are truncated, not refused. A long description is far more often
#: a verbose vendor than an attack, and refusing the whole spec over one wordy
#: field would push operators to skip enrolment entirely.
MAX_DESCRIPTION_CHARS = 8192

#: The methods that name an operation in an OpenAPI path item. Everything else
#: in a path item (`parameters`, `servers`, `summary`) is not an operation, and
#: treating it as one would invent tools the API does not offer.
_HTTP_METHODS = frozenset(
    {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
)


class OpenApiRefused(DomainRuleViolated):
    """A spec was refused. Never retryable -- the document does not change."""

    is_retryable = False


def load_spec(path: str | Path) -> Mapping[str, Any]:
    """Read a spec from a file.

    JSON only. YAML would need a parser, and the safe loader question ("did you
    use `safe_load`?") is one this codebase would rather not have. `openapi.json`
    is what every generator emits alongside the YAML anyway.
    """
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise OpenApiRefused(f"cannot read OpenAPI spec: {exc}") from exc
    if not isinstance(raw, dict):
        raise OpenApiRefused("an OpenAPI spec must be a JSON object")
    return raw


def _depth(value: Any, current: int = 0) -> int:
    if current > MAX_SCHEMA_DEPTH:
        return current
    if isinstance(value, dict):
        return max((_depth(v, current + 1) for v in value.values()), default=current)
    if isinstance(value, list):
        return max((_depth(v, current + 1) for v in value), default=current)
    return current


def _text(value: Any) -> str:
    return str(value or "").strip()[:MAX_DESCRIPTION_CHARS]


def _operation_name(method: str, path: str, operation: Mapping[str, Any]) -> str:
    """What the operation is pinned UNDER.

    `operationId` when the spec provides one, because that is the handle
    generators use and therefore the name an agent will call. Otherwise
    `METHOD /path`, which is stable and unambiguous.

    Note what this means for drift: if a spec keeps its `operationId` and changes
    its PATH, the name is unchanged and only the fingerprint moves. That is the
    rug pull, and catching it is the entire reason the path is part of the
    fingerprint below.
    """
    operation_id = _text(operation.get("operationId"))
    return operation_id or f"{method.upper()} {path}"


def _description(operation: Mapping[str, Any]) -> str:
    """The prose a model reads before deciding to call this operation.

    `summary` and `description` are concatenated because generators put the
    instruction-shaped text in either one, and a scanner that reads only one of
    them can be evaded by moving the payload to the other.
    """
    parts = [_text(operation.get("summary")), _text(operation.get("description"))]
    return "\n".join(p for p in parts if p)[:MAX_DESCRIPTION_CHARS]


def _schema(
    method: str, path: str, operation: Mapping[str, Any], shared: Any
) -> dict[str, Any]:
    """Everything that determines what this operation can be made to do.

    The METHOD and PATH are in here deliberately, not just the parameters. An
    operation that keeps its `operationId` and moves from `/v1/reports/{id}` to
    `/v1/admin/{id}` is a different capability with the same name, and the only
    thing that catches it is the fingerprint covering the path.

    Path-item level `parameters` are merged in because they apply to every
    operation under that path -- reading only the operation's own list would miss
    a parameter added one level up.
    """
    parameters: list[Any] = []
    if isinstance(shared, list):
        parameters.extend(shared)
    own = operation.get("parameters")
    if isinstance(own, list):
        parameters.extend(own)

    return {
        "method": method.upper(),
        "path": path,
        "parameters": parameters,
        "requestBody": operation.get("requestBody", {}),
        # `security` is included because an operation that drops its security
        # requirement has changed what it is, even if nothing else moved.
        "security": operation.get("security", []),
    }


def operations_from_spec(spec: Mapping[str, Any]) -> tuple[McpToolDefinition, ...]:
    """Convert a spec into pinnable tool definitions, one per operation.

    `$ref` is deliberately NOT resolved. Resolution means following pointers
    inside a document nobody has decided to trust yet -- into other files, or in
    a cycle -- and an unresolved `$ref` still fingerprints perfectly well: if the
    reference target changes, the referring schema is unchanged, but so is the
    capability as far as the pin is concerned. That is a real limit and it is
    recorded in docs/ rather than papered over.
    """
    paths = spec.get("paths")
    if not isinstance(paths, dict) or not paths:
        raise OpenApiRefused(
            "the spec declares no paths; there is nothing to enrol. An empty "
            "pin set would read as 'this API has no operations' rather than as "
            "'this spec could not be understood'."
        )

    definitions: list[McpToolDefinition] = []
    seen: set[str] = set()

    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        shared = item.get("parameters")
        for method, operation in item.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(operation, dict):
                continue

            if len(definitions) >= MAX_OPERATIONS:
                raise OpenApiRefused(
                    f"the spec declares more than {MAX_OPERATIONS} operations. "
                    "Enrolment is meant to record that an operator reviewed "
                    "these; nobody reviews a thousand."
                )

            schema = _schema(method, str(path), operation, shared)
            if _depth(schema) > MAX_SCHEMA_DEPTH:
                raise OpenApiRefused(
                    f"operation {method.upper()} {path} has a schema nested "
                    f"deeper than {MAX_SCHEMA_DEPTH}; refusing to walk it"
                )

            name = _operation_name(method, str(path), operation)
            if name in seen:
                # Two operations pinned under one name means one of them is
                # unpinnable, and which one wins would depend on iteration
                # order. Refused rather than resolved -- the same decision the
                # API-key parser makes about duplicate key material.
                raise OpenApiRefused(
                    f"duplicate operation name {name!r}. Two operations sharing "
                    "an operationId cannot both be pinned, and silently keeping "
                    "one would leave the other unreviewed but callable."
                )
            seen.add(name)

            definitions.append(
                McpToolDefinition(
                    name=name,
                    description=_description(operation),
                    input_schema=schema,
                )
            )

    if not definitions:
        raise OpenApiRefused(
            "the spec declares paths but no operations under any HTTP method"
        )
    return tuple(definitions)
