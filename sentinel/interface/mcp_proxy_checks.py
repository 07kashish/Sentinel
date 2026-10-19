"""The proxy's decisions, as pure functions over what an upstream said.

WHY THESE ARE NOT IN `mcp_proxy_routes.py`
------------------------------------------
The route module wires: it reads headers, resolves the enrolment record,
orders the checks and shapes the reply. This module decides -- and every
function here takes a parsed upstream reply plus the record it is judged
against, and returns a refusal or None. Nothing in it touches FastAPI, a
request, or a socket.

That split is what makes the adversarial suite possible to write honestly.
`tests_arch/test_mcp_attacks.py` drives these through the real route, but the
functions themselves can be reasoned about one at a time, which is how the
duplicate-tool-name collision was found: two callers resolving the same
ambiguity differently is visible when both resolutions sit in one file, and
was not when they were three hundred lines apart.

REFUSALS ARE JSON-RPC ERROR OBJECTS, NOT EXCEPTIONS
---------------------------------------------------
The caller is an MCP client mid-session, and an in-band error is the shape it
can handle and show its agent. Every function here returns `None` for "carry
on" and a dict for "stop", so a caller that forgets to check gets a `None` it
cannot accidentally forward -- the same reason `InlineToolProxy` raises rather
than returning a falsy value, arrived at from the opposite direction because
this layer's output IS the protocol reply.
"""

from __future__ import annotations

from typing import Any, Mapping
from urllib.parse import urlsplit

from sentinel.domain.mcp import McpToolDefinition
from sentinel.domain.primitives import TrustLevel
from sentinel.infrastructure.mcp_wire import McpUpstreamReply
from sentinel.infrastructure.persistence.audit import Outcome

__all__ = [
    "JSONRPC_SENTINEL_REFUSED",
    "audience_matches",
    "check_listing_drift",
    "check_server_identity",
    "duplicate_tool_name",
    "evaluate_tools_call",
    "origin",
    "param_name",
    "parse_trust",
    "rpc_error",
    "server_identity",
    "tools_from_listing",
]

#: JSON-RPC error code for a Sentinel policy refusal. In the implementation-
#: defined server-error range (-32000..-32099); one code for every refusal so a
#: client can branch on it, with the specifics in `data.sentinel`.
JSONRPC_SENTINEL_REFUSED = -32050


def rpc_error(
    request_id: Any,
    code: int,
    message: str,
    *,
    sentinel: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if sentinel is not None:
        error["data"] = {"sentinel": dict(sentinel)}
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def parse_trust(raw: str) -> TrustLevel:
    """The AGENT's trust level, defaulting to the least-trusted tier.

    Unrecognised values fall to UNSIGNED rather than raising: this header
    modulates severity in the caller's favour, so a caller who garbles it gets
    the strictest treatment, not an error message to iterate against.
    """
    name = (raw or "unsigned").strip().lower()
    try:
        return TrustLevel(name)
    except ValueError:
        return TrustLevel.UNSIGNED


def param_name(message: Mapping[str, Any]) -> str:
    params = message.get("params")
    if isinstance(params, Mapping):
        name = params.get("name")
        if isinstance(name, str):
            return name
    return ""


def origin(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    if not parts.scheme or not parts.netloc:
        return ""
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}"


def audience_matches(audiences: tuple[str, ...], endpoint: str) -> bool:
    """Does any audience name this server?

    Matched at ORIGIN granularity: RFC 8707 resource indicators are URIs, and
    an authorization server may issue the token for the server's canonical URI
    rather than the exact path the proxy dials. An audience that is not a URI
    at all (a bare client-id, an API name) cannot be judged and counts as a
    match -- the check exists to catch a token PLAINLY bound elsewhere, not to
    reject every issuer whose audience format we have not met.
    """
    target = origin(endpoint)
    if not target:
        return True
    judgeable = [a for a in audiences if origin(a)]
    if not judgeable:
        return True
    return any(origin(a) == target for a in judgeable)


def tools_from_listing(
    listing: McpUpstreamReply,
) -> tuple[McpToolDefinition, ...] | None:
    """Every well-formed tool in an upstream tools/list reply, or None.

    None for a reply that is not a listing at all (an error object, a
    notification); malformed ENTRIES inside an otherwise valid listing are
    skipped rather than invented. The permissive direction — guessing a
    definition the server did not properly serve — is the one that must not
    exist.
    """
    body = listing.message
    if not isinstance(body, Mapping):
        return None
    result = body.get("result")
    if not isinstance(result, Mapping):
        return None
    tools = result.get("tools")
    if not isinstance(tools, list):
        return None
    parsed: list[McpToolDefinition] = []
    for entry in tools:
        if not isinstance(entry, Mapping):
            continue
        try:
            parsed.append(
                McpToolDefinition(
                    name=str(entry.get("name") or ""),
                    description=str(entry.get("description") or ""),
                    input_schema=dict(entry.get("inputSchema") or {}),
                )
            )
        except (ValueError, TypeError):
            continue
    return tuple(parsed)


def duplicate_tool_name(tools: tuple[McpToolDefinition, ...]) -> str:
    """The first tool name served more than once, or "".

    A listing carrying one name twice is not a cosmetic defect, it is an
    ambiguity the gateway must not resolve on the server's behalf. Whichever
    copy Sentinel evaluates, the SERVER decides which copy actually runs, so
    picking one silently means a benign definition can be evaluated while a
    hostile one executes under the same name.

    Found by `tests_arch/test_mcp_attacks.py::test_tool_name_collision_is_
    refused_rather_than_resolved`, and the two resolutions really did differ:
    `_evaluate_tools_call` took the FIRST match while `diff_tools` built a
    dict in which the LAST won. An attacker choosing the order chose which
    copy got inspected.
    """
    seen: set[str] = set()
    for tool in tools:
        if tool.name in seen:
            return tool.name
        seen.add(tool.name)
    return ""


def evaluate_tools_call(
    *,
    gateway,
    registry,
    server,
    tools: tuple[McpToolDefinition, ...] | None,
    agent: str,
    session_id: str,
    trust: TrustLevel,
    message: Mapping[str, Any],
    audit,
) -> dict[str, Any] | None:
    """Evaluate the called tool against the server's CURRENT listing.

    `tools` is what the server serves now (live, or within the operator-set
    cache TTL): evaluating the definition the CLIENT supplies would let a
    hostile client describe a benign tool and call a hostile one. Every drift
    the evaluation finds is written to the durable change log before the
    refusal is returned — the forensic record must exist even if the caller
    discards the error.
    """
    request_id = message.get("id")
    name = param_name(message)
    if not name:
        audit(Outcome.DENIED, {"reason": "missing_tool_name"})
        return rpc_error(
            request_id,
            -32602,
            "tools/call requires params.name",
            sentinel={"decision": "refused"},
        )
    params = message.get("params")
    arguments = (
        dict(params.get("arguments") or {})
        if isinstance(params, Mapping) and isinstance(params.get("arguments"), Mapping)
        else {}
    )

    collision = duplicate_tool_name(tools or ())
    if collision:
        audit(Outcome.DENIED, {"reason": "duplicate_tool_name", "tool": collision})
        return rpc_error(
            request_id,
            JSONRPC_SENTINEL_REFUSED,
            f"server {server.server_id!r} lists tool {collision!r} more than "
            "once. A duplicate name is ambiguous -- the server chooses which "
            "copy runs, so evaluating either one proves nothing about the "
            "other. Refusing rather than picking.",
            sentinel={"decision": "refused", "reason": "duplicate_tool_name",
                      "tool": collision},
        )

    live = next((tool for tool in tools or () if tool.name == name), None)
    if live is None:
        audit(Outcome.DENIED, {"reason": "tool_not_offered", "tool": name})
        return rpc_error(
            request_id,
            JSONRPC_SENTINEL_REFUSED,
            f"tool {name!r} is not offered by server {server.server_id!r}; "
            "refusing to forward a call to a tool the server does not list",
            sentinel={"decision": "refused", "tool": name},
        )

    evaluation = gateway.evaluate_request(
        tenant_id=server.tenant_id,
        server_id=server.server_id,
        agent_id=agent,
        tool=live,
        endpoint=server.endpoint,
        arguments=arguments,
        session_id=session_id,
        trust=trust,
    )
    if evaluation.changes:
        registry.record_changes(server, evaluation.changes)
    if evaluation.allowed:
        return None
    audit(
        Outcome.DENIED,
        {
            "reason": "policy_refused",
            "tool": name,
            "changes": [c.kind.value for c in evaluation.changes],
            "decision": (
                evaluation.protect.decision.value if evaluation.protect else None
            ),
        },
    )
    return rpc_error(
        request_id,
        JSONRPC_SENTINEL_REFUSED,
        f"tool call {name!r} refused by policy",
        sentinel={
            "decision": "refused",
            **evaluation.as_dict(),
        },
    )


def check_listing_drift(
    *,
    gateway,
    registry,
    server,
    observed: tuple[McpToolDefinition, ...] | None,
    request_id: Any,
    audit,
) -> dict[str, Any] | None:
    """Refuse a listing that has drifted from the pinned set.

    The listing is where tool DESCRIPTIONS reach the model, so this is where a
    poisoned description would land. Blocking drift kinds (a new tool, a
    changed definition) refuse the whole listing rather than filtering it:
    a filtered listing would be a server response Sentinel partly authored,
    and fabricated upstream state is banned in this codebase by standing rule.
    Removal-only drift passes with an audit record — a server that dropped a
    tool has narrowed, not widened, and refusing that would make every
    legitimate deprecation an outage. Every observed drift, blocking or not,
    lands in the durable change log.
    """
    if observed is None:
        # An error reply or a notification: nothing listed, nothing to check.
        return None

    collision = duplicate_tool_name(observed)
    if collision:
        audit(Outcome.DENIED, {"reason": "duplicate_tool_name", "tool": collision})
        return rpc_error(
            request_id,
            JSONRPC_SENTINEL_REFUSED,
            f"the listing serves tool {collision!r} more than once; a duplicate "
            "name is ambiguous and is refused rather than resolved",
            sentinel={"decision": "refused", "reason": "duplicate_tool_name",
                      "tool": collision},
        )

    changes = gateway.diff_tools(server, observed)
    if changes:
        registry.record_changes(server, changes)
    blocking = [c for c in changes if c.kind.value != "tool_removed"]
    if not blocking:
        if changes:
            audit(
                Outcome.SUCCESS,
                {"drift": [c.as_dict() for c in changes], "note": "removals only"},
            )
        return None
    audit(
        Outcome.DENIED,
        {"reason": "listing_drift", "drift": [c.as_dict() for c in changes]},
    )
    return rpc_error(
        request_id,
        JSONRPC_SENTINEL_REFUSED,
        "the server's tool listing no longer matches what was pinned at "
        "enrolment; re-approve the server or treat it as compromised",
        sentinel={
            "decision": "refused",
            "changes": [c.as_dict() for c in changes],
        },
    )


def server_identity(reply: McpUpstreamReply) -> str:
    """`name/version` from an initialize result, or "" when absent.

    A flat string rather than a dict because it is compared, logged and shown
    to an operator, and every one of those is easier to get right on a scalar.
    """
    body = reply.message
    if not isinstance(body, Mapping):
        return ""
    result = body.get("result")
    if not isinstance(result, Mapping):
        return ""
    info = result.get("serverInfo")
    if not isinstance(info, Mapping):
        return ""
    name = str(info.get("name") or "").strip()
    version = str(info.get("version") or "").strip()
    if not name:
        return ""
    return f"{name}/{version}" if version else name


def check_server_identity(
    *,
    registry,
    server,
    reply: McpUpstreamReply,
    request_id: Any,
    audit,
) -> dict[str, Any] | None:
    """Is the thing answering at this endpoint still the thing we enrolled?

    The tool pins catch a changed TOOL and catch nothing about a changed
    SERVER. An endpoint can be rehosted, a DNS record can be moved, and a
    service can take over an address an operator approved months ago -- in each
    case the tools may be byte-identical while the party serving them is not.

    A changed NAME is refused: a different server is answering, which is the
    impersonation case and not something to resolve by guessing. A changed
    VERSION is recorded and allowed -- servers are upgraded, and refusing every
    version bump would make routine maintenance an outage while training
    operators to ignore the signal. First observation is recorded rather than
    refused: enrolment approves an ENDPOINT and its tools, the identity is
    learned on first contact, and that is stated rather than dressed up as
    verification.
    """
    observed = server_identity(reply)
    if not observed:
        return None
    known = registry.server_info(server.tenant_id, server.server_id)
    if not known:
        registry.record_server_info(server.tenant_id, server.server_id, observed)
        audit(Outcome.SUCCESS, {"server_identity": observed, "note": "first observed"})
        return None
    if known == observed:
        return None

    if known.split("/")[0] != observed.split("/")[0]:
        audit(
            Outcome.DENIED,
            {
                "reason": "server_identity_changed",
                "known_identity": known,
                "observed_identity": observed,
            },
        )
        return rpc_error(
            request_id,
            JSONRPC_SENTINEL_REFUSED,
            f"the server answering {server.server_id!r} now identifies as "
            f"{observed!r}, not {known!r}. A different server is answering an "
            "enrolled endpoint; re-enrol it deliberately or treat the endpoint "
            "as taken over.",
            sentinel={
                "decision": "refused",
                "reason": "server_identity_changed",
                "known_identity": known,
                "observed_identity": observed,
            },
        )

    registry.record_server_info(server.tenant_id, server.server_id, observed)
    audit(
        Outcome.SUCCESS,
        {
            "server_identity": observed,
            "previous_identity": known,
            "note": "version changed",
        },
    )
    return None
