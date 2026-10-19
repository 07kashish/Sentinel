"""The MCP wire proxy: JSON-RPC in, policy in the middle, JSON-RPC out.

WHAT THIS ROUTE IS
------------------
`/v1/mcp/proxy/{server_id}` is an MCP Streamable HTTP endpoint an MCP client
points at INSTEAD of the real server. Sentinel forwards each JSON-RPC message to
the enrolled upstream and returns the upstream's reply — with three security
properties a description-based API (`/v1/mcp/evaluate`) cannot provide:

  1. THE ENDPOINT COMES FROM THE ENROLMENT RECORD, NEVER THE REQUEST. There is
     no URL parameter. A caller cannot point this process at a server nobody
     enrolled — an unknown or blocked `server_id` is refused before any network
     activity, which is the default-deny egress posture stated in
     `sentinel/infrastructure/mcp_wire.py`.

  2. `tools/call` IS EVALUATED AGAINST THE SERVER'S LIVE DEFINITION. The proxy
     fetches the tool's definition from the upstream at call time, so the
     pin-drift check compares what the operator approved against what the server
     claims NOW — the rug pull is caught even if the client's cached listing is
     stale. The cost is one extra upstream round trip per call, stated in
     `docs/MCP_GATEWAY.md` rather than hidden.

  3. `tools/list` IS DRIFT-CHECKED BEFORE THE CLIENT SEES IT. Descriptions in a
     listing are prose the model will read as instructions. A listing that
     no longer matches the pinned set is refused, not sanitised: editing a
     hostile listing into a safe-looking one would hand the client a fabricated
     server response, and this codebase does not fabricate upstream state.

METHODS ARE ALLOWLISTED, HONESTLY
---------------------------------
Only the methods this gateway has been taught are forwarded: `initialize`,
`ping`, `tools/list`, `tools/call`, and the client lifecycle notifications.
Everything else — resources, prompts, sampling, roots — answers JSON-RPC
-32601 with an explicit NOT_SUPPORTED marker, per the standing rule that
unimplemented functionality returns a refusal rather than a quiet pass-through.
A pass-through of a method nobody evaluated would be an unevaluated side
channel wearing a security product's badge.

REFUSALS TRAVEL IN-BAND
-----------------------
Policy refusals are JSON-RPC error objects (code -32050, data.sentinel carries
the reasons), not bare HTTP errors: the caller is an MCP client mid-session, and
an in-band error is the shape it can actually handle and show to its agent.
Transport-level problems (unknown tenant key, proxy disabled) remain HTTP.

DELEGATED IDENTITY
------------------
`X-Sentinel-Agent-Id` (required), `X-Sentinel-Principal` and
`X-Sentinel-Session-Id` (optional) carry the delegation chain — which human
authorised which agent in which session — into the audit record and the
policy evaluation. They are Sentinel headers, not MCP protocol fields, so the
forwarded message is untouched. `X-Sentinel-Upstream-Authorization` carries the
client's own OAuth credential for the upstream server; it is forwarded verbatim
and never logged, stored, or minted here.
"""

from __future__ import annotations

import secrets
import time
from typing import Any, Mapping

from fastapi import Depends, FastAPI, Header, HTTPException, Response, status

from sentinel.application.agent_capabilities import AgentCapabilityRefused
from sentinel.application.tool_runner import ToolExecutionRefused
from sentinel.composition.container import Container
from sentinel.domain.authorization import Capability
from sentinel.domain.execution_binding import issue_authorization
from sentinel.domain.mcp import (
    McpServerTrust,
    McpToolDefinition,
    classify_destination,
)
from sentinel.infrastructure.mcp_wire import (
    McpUpstreamReply,
    McpWireError,
    challenge_resource_metadata,
    token_audiences,
)
from sentinel.infrastructure.outbound import OutboundRefused, OutboundUnavailable
from sentinel.infrastructure.persistence.audit import Outcome
from sentinel.interface.mcp_proxy_checks import (
    JSONRPC_SENTINEL_REFUSED,
    audience_matches,
    check_listing_drift,
    check_server_identity,
    evaluate_tools_call,
    origin,
    param_name,
    rpc_error,
    tools_from_listing,
)
from sentinel.interface.a2a_proxy_routes import _inspect_reply
from sentinel.interface.mcp_streaming import RelayPolicy, stream_through

__all__ = ["register_mcp_proxy_routes"]

#: Methods this gateway forwards. Deliberately small: each entry is a claim
#: that the gateway understands the method's security consequences. Grow this
#: list by adding evaluation, never by adding pass-through.
FORWARDED_METHODS = frozenset(
    {
        "initialize",
        "ping",
        "tools/list",
        "tools/call",
        "notifications/initialized",
        "notifications/cancelled",
    }
)


def register_mcp_proxy_routes(
    app: FastAPI,
    container: Container,
    *,
    require,
) -> None:
    """Attach the MCP wire proxy. No-op when the proxy is not configured.

    Not registering the route at all — rather than registering it and answering
    503 — means a deployment that has not enabled the proxy does not advertise
    it, and a scanner sees 404 exactly as if the feature did not exist.
    """
    upstream = container.mcp_upstream
    if upstream is None:
        return

    audit = container.security_audit
    gateway = container.mcp_gateway
    registry = container.mcp_registry
    settings = container.settings
    # Per-process tools/list reuse for tools/call evaluation. Empty and inert
    # at the default TTL of 0 -- every call then evaluates the LIVE listing.
    # Keyed by (tenant, server) so one tenant's cache cannot answer another's.
    listing_cache: dict[tuple[str, str], tuple[float, tuple[McpToolDefinition, ...]]] = {}

    @app.post("/v1/mcp/proxy/{server_id}")
    def mcp_proxy(
        server_id: str,
        message: dict[str, Any],
        response: Response,
        principal=Depends(require(Capability.EXECUTE_TOOL)),
        agent_id: str = Header(default="", alias="X-Sentinel-Agent-Id"),
        human_principal: str = Header(default="", alias="X-Sentinel-Principal"),
        session_id: str = Header(default="", alias="X-Sentinel-Session-Id"),
        mcp_session: str = Header(default="", alias="Mcp-Session-Id"),
        upstream_authorization: str = Header(
            default="", alias="X-Sentinel-Upstream-Authorization"
        ),
        accept: str = Header(default="", alias="Accept"),
    ):
        """Buffered by default; streamed when enabled, asked for, and a tool call."""
        def call(sink: Any) -> Any:
            return _proxy(server_id, message, response, principal, agent_id, human_principal,
                          session_id, mcp_session, upstream_authorization, sink)

        streaming = (settings.workflow.mcp_proxy_streaming and "text/event-stream" in accept.lower()
                     and message.get("method") == "tools/call")
        return stream_through(call, request_id=message.get("id")) if streaming else call(None)

    def _proxy(
        server_id: str,
        message: dict[str, Any],
        response: Response,
        principal: Any,
        agent_id: str,
        human_principal: str,
        session_id: str,
        mcp_session: str,
        upstream_authorization: str,
        sink: Any,
    ):
        # ── Attribution before anything else ─────────────────────────────
        # A proxy call with no agent identity would produce an audit record
        # that answers "what happened" but not "who did it", which is half an
        # evidence trail. Refused up front, as a transport error: this is a
        # caller integration mistake, not an MCP protocol event.
        agent = agent_id.strip()
        if not agent:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail=(
                    "X-Sentinel-Agent-Id is required: a proxied MCP call must "
                    "be attributable to an agent"
                ),
            )
        trust = principal.trust

        request_id = message.get("id")
        method = message.get("method")
        if message.get("jsonrpc") != "2.0" or not isinstance(method, str):
            # Includes batches: FastAPI already refused non-object bodies via
            # the `dict` annotation, and a single-message body without a method
            # is not something this gateway can evaluate.
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail=(
                    "body must be a single JSON-RPC 2.0 request object; "
                    "batching is not part of the supported protocol revision"
                ),
            )

        tenant_id = principal.tenant.value
        actor = f"key:{principal.key_hash[:12]}"
        # Filled in once the enrolment record is read; every audit record from
        # then on carries the one-word answer to "where was this headed".
        egress: dict[str, str] = {}

        def _audit(outcome: Outcome, detail: dict[str, Any]) -> None:
            # The delegation chain rides on every record so an investigation
            # reads WHO (human) delegated to WHOM (agent) in WHICH session
            # without a join against anything else.
            detail.setdefault("agent_id", agent)
            if human_principal:
                detail.setdefault("principal", human_principal)
            if session_id:
                detail.setdefault("session_id", session_id)
            if egress:
                detail.setdefault("destination_class", egress["class"])
            detail.setdefault("method", method)
            audit.record(
                tenant=principal.tenant,
                actor=actor,
                action="mcp.proxy",
                resource_type="mcp_server",
                resource_id=server_id,
                outcome=outcome,
                detail=detail,
            )

        # ── 1. Server trust, before any network activity ──────────────────
        server = gateway.resolve(tenant_id, server_id)
        if server.trust is not McpServerTrust.ENROLLED:
            # OBSERVED is refused here even though `evaluate` accepts it: the
            # evaluation API judges a call somebody else already made, while
            # THIS route is the thing making the call. Dialling a server an
            # operator has seen but not approved would turn observation into
            # authorisation.
            _audit(
                Outcome.DENIED,
                {"reason": "server_not_enrolled", "server_trust": server.trust.value},
            )
            return rpc_error(
                request_id,
                JSONRPC_SENTINEL_REFUSED,
                f"MCP server {server_id!r} is {server.trust.value}; the proxy "
                "forwards to ENROLLED servers only",
                sentinel={
                    "decision": "refused",
                    "server_id": server_id,
                    "server_trust": server.trust.value,
                },
            )
        if not server.endpoint:
            _audit(Outcome.DENIED, {"reason": "no_endpoint_recorded"})
            return rpc_error(
                request_id,
                JSONRPC_SENTINEL_REFUSED,
                f"MCP server {server_id!r} was enrolled without an endpoint; "
                "the proxy has nowhere sanctioned to send this",
                sentinel={"decision": "refused", "server_id": server_id},
            )
        egress["class"] = classify_destination(
            server.endpoint, allowed_hosts=settings.mcp_proxy_allowed_hosts
        ).value

        # ── 1b. Credential audience restriction ───────────────────────────
        # A JWT bound to a DIFFERENT resource must not be replayed through the
        # proxy against this one -- that is the confused-deputy shape the MCP
        # authorization spec's resource binding exists to stop. Only a
        # structurally-inspectable token can be judged (Sentinel holds no
        # upstream keys and verifies nothing); an opaque token passes, and
        # that limit is stated rather than papered over.
        if upstream_authorization and settings.mcp_proxy_require_token_audience:
            audiences = token_audiences(upstream_authorization)
            if audiences is not None and not audience_matches(
                audiences, server.endpoint
            ):
                _audit(
                    Outcome.DENIED,
                    {
                        "reason": "token_audience_mismatch",
                        # The audiences are identifiers, not secrets; the token
                        # itself is never recorded.
                        "token_audiences": list(audiences),
                    },
                )
                return rpc_error(
                    request_id,
                    JSONRPC_SENTINEL_REFUSED,
                    "the upstream credential is audience-bound to a different "
                    "resource; refusing to replay it against this server",
                    sentinel={
                        "decision": "refused",
                        "reason": "token_audience_mismatch",
                        "endpoint_origin": origin(server.endpoint),
                    },
                )

        # ── 2. Method allowlist ───────────────────────────────────────────
        if method not in FORWARDED_METHODS:
            _audit(Outcome.DENIED, {"reason": "method_not_supported"})
            return rpc_error(
                request_id,
                -32601,
                f"method {method!r} is not supported by this gateway",
                sentinel={
                    "decision": "NOT_SUPPORTED",
                    "supported": sorted(FORWARDED_METHODS),
                },
            )

        relay = (
            RelayPolicy(
                sink=sink,
                inspect=lambda text: str(_inspect_reply(
                    container.a2a_gateway, {"result": {"parts": [{"kind": "text", "text": text}]}},
                    agent_id=agent, tenant=tenant_id) or ""),
            )
            if sink is not None else None
        )

        def _forward(payload: Mapping[str, Any]) -> McpUpstreamReply:
            return upstream.forward(
                endpoint=server.endpoint,
                message=payload,
                session_id=mcp_session,
                upstream_authorization=upstream_authorization,
                # Only the tool call itself is streamed; the listing that pins
                # the definition first is a lookup, and has nothing to relay.
                **({"on_event": relay} if relay is not None and payload.get("method") == "tools/call" else {}),
            )

        def _auth_challenge(reply: McpUpstreamReply) -> Response:
            """Relay the upstream's 401/403, but not an issuer it chose for us.

            The WWW-Authenticate header carries the RFC 9728 resource-metadata
            pointer the client's authorization-server discovery starts from, so
            relaying it is what makes OAuth work THROUGH the proxy rather than
            only around it.

            It is NOT relayed unread. That pointer is supplied by the resource
            whose trustworthiness is the open question: a compromised server
            answering `resource_metadata="https://attacker.example/..."` aims
            the client's entire OAuth flow at an authorization server the
            attacker runs. Sentinel is the one party in this exchange that
            knows which endpoint an operator actually enrolled, so it is the
            only party positioned to notice. A pointer that is not same-origin
            with the enrolled endpoint is STRIPPED and the refusal is recorded
            as issuer confusion -- the client still learns it is unauthorized,
            and learns it from a challenge naming nobody, which fails closed
            rather than sending it somewhere hostile.
            """
            metadata = challenge_resource_metadata(reply.www_authenticate)
            confused = bool(metadata) and origin(metadata) != origin(
                server.endpoint
            )
            _audit(
                Outcome.DENIED,
                {
                    "reason": (
                        "oauth_issuer_confusion"
                        if confused
                        else "upstream_auth_required"
                    ),
                    "status": reply.status,
                    **(
                        {
                            "declared_resource_metadata": metadata,
                            "enrolled_origin": origin(server.endpoint),
                        }
                        if confused
                        else {}
                    ),
                },
            )
            headers = (
                {"WWW-Authenticate": reply.www_authenticate}
                if reply.www_authenticate and not confused
                else None
            )
            return Response(status_code=reply.status, headers=headers)

        def _current_tools(
            marker: Any,
        ) -> tuple[McpToolDefinition, ...] | McpUpstreamReply | None:
            """The server's live tool listing for evaluation, observed as served.

            Live by default; the cache exists only when an operator set a TTL,
            trading a bounded rug-pull detection window for one fewer upstream
            round trip. Every LIVE listing is recorded to provenance before any
            decision is made about it -- an investigation needs "what was
            served" even when (especially when) the answer got the call
            refused. Returns the upstream reply itself for an auth challenge
            (relayed, not judged) and None for an unparseable listing.
            """
            ttl = settings.mcp_proxy_definition_cache_seconds
            key = (tenant_id, server_id)
            if ttl > 0:
                cached = listing_cache.get(key)
                if cached is not None and time.monotonic() - cached[0] < ttl:
                    return cached[1]
            listing = _forward(
                {
                    "jsonrpc": "2.0",
                    "id": f"sentinel-listing-{marker}",
                    "method": "tools/list",
                }
            )
            if listing.status in (401, 403):
                return listing
            tools = tools_from_listing(listing)
            if tools is None:
                return None
            registry.observe_tools(server, tools)
            if ttl > 0:
                listing_cache[key] = (time.monotonic(), tools)
            return tools

        # ── 3. Method-specific evaluation ─────────────────────────────────
        try:
            if method == "tools/call":
                current = _current_tools(request_id)
                if isinstance(current, McpUpstreamReply):
                    return _auth_challenge(current)
                refusal = evaluate_tools_call(
                    gateway=gateway,
                    registry=registry,
                    server=server,
                    tools=current,
                    agent=agent,
                    session_id=session_id,
                    trust=trust,
                    message=message,
                    audit=_audit,
                )
                if refusal is not None:
                    return refusal

                name = param_name(message)
                params = message.get("params")
                arguments = (
                    dict(params.get("arguments") or {})
                    if isinstance(params, Mapping)
                    and isinstance(params.get("arguments"), Mapping)
                    else {}
                )
                live = next((tool for tool in current or () if tool.name == name), None)
                if live is None:
                    # Defensive: evaluate_tools_call returned no refusal only
                    # after finding this tool in the same listing.
                    _audit(Outcome.DENIED, {"reason": "tool_not_offered", "tool": name})
                    return rpc_error(
                        request_id,
                        JSONRPC_SENTINEL_REFUSED,
                        f"tool {name!r} is not offered by server {server.server_id!r}",
                        sentinel={"decision": "refused", "tool": name},
                    )

                evaluation = gateway.evaluate_request(
                    tenant_id=tenant_id,
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
                if not evaluation.allowed:
                    _audit(
                        Outcome.DENIED,
                        {
                            "reason": "policy_refused",
                            "tool": name,
                            "decision": (
                                evaluation.protect.decision.value
                                if evaluation.protect
                                else None
                            ),
                        },
                    )
                    return rpc_error(
                        request_id,
                        JSONRPC_SENTINEL_REFUSED,
                        f"tool call {name!r} refused by policy",
                        sentinel={"decision": "refused", **evaluation.as_dict()},
                    )

                try:
                    capability = container.capability_gate.require(
                        tenant_id=tenant_id, agent_id=agent, tool=name
                    )
                except AgentCapabilityRefused as exc:
                    _audit(
                        Outcome.DENIED,
                        {"reason": "capability_refused", "tool": name},
                    )
                    return rpc_error(
                        request_id,
                        JSONRPC_SENTINEL_REFUSED,
                        str(exc),
                        sentinel={"decision": "refused", "reason": "capability_refused"},
                    )

                now = container.clock.now().value
                authorization = issue_authorization(
                    authorization_id=f"mcp-{secrets.token_urlsafe(12)}",
                    nonce=secrets.token_urlsafe(24),
                    tenant_id=tenant_id,
                    actor_identity=actor,
                    agent_identity=agent,
                    tool_identity=name,
                    action=name,
                    target_resource=f"mcp://{server.server_id}/{name}",
                    parameters=arguments,
                    now=now,
                    policy_decision=(
                        evaluation.protect.decision.value
                        if evaluation.protect
                        else "allow"
                    ),
                    mcp_server_identity=server.server_id,
                    conditions={
                        "server_id": server.server_id,
                        "tool_fingerprint": live.fingerprint,
                        "session_id": session_id,
                    },
                )

                def _bound_forward(verified: Mapping[str, Any]) -> McpUpstreamReply:
                    outbound = dict(message)
                    outbound_params = (
                        dict(outbound.get("params") or {})
                        if isinstance(outbound.get("params"), Mapping)
                        else {}
                    )
                    outbound_params["arguments"] = dict(verified)
                    outbound["params"] = outbound_params
                    return _forward(outbound)

                try:
                    _protect, reply, receipt = container.tool_runner.execute_bound(
                        authorization=authorization,
                        tenant=tenant_id,
                        agent_id=agent,
                        tool=name,
                        action=name,
                        resource=f"mcp://{server.server_id}/{name}",
                        parameters=arguments,
                        trust=trust,
                        side_effect=_bound_forward,
                        nonces=container.nonces,
                        now=now,
                        mcp_server=server.server_id,
                    )
                except (ToolExecutionRefused, ValueError) as exc:
                    _audit(
                        Outcome.DENIED,
                        {"reason": "bound_execution_refused", "tool": name},
                    )
                    return rpc_error(
                        request_id,
                        JSONRPC_SENTINEL_REFUSED,
                        str(exc),
                        sentinel={
                            "decision": "refused",
                            "reason": "bound_execution_refused",
                        },
                    )

                if reply.status in (401, 403):
                    return _auth_challenge(reply)
                container.receipts.record(
                    tenant_id,
                    receipt=receipt,
                    approved_parameter_digest=authorization.approved_parameter_digest,
                    authorization_id=authorization.authorization_id,
                )
                verdict = _inspect_reply(
                    container.a2a_gateway,
                    _mcp_reply_for_detector(reply.message),
                    agent_id=agent,
                    tenant=tenant_id,
                )
                if verdict is not None:
                    _audit(
                        Outcome.DENIED,
                        {
                            "reason": "poisoned_result",
                            "tool": name,
                            "receipt_id": receipt.receipt_id,
                            "reply": verdict,
                        },
                    )
                    return rpc_error(
                        request_id,
                        JSONRPC_SENTINEL_REFUSED,
                        "the MCP server's tool result was refused",
                        sentinel={
                            "decision": "refused",
                            "reason": "poisoned_result",
                            "note": (
                                "the result is NOT returned. Handing back a "
                                "sanitised version would fabricate upstream "
                                "state."
                            ),
                        },
                    )
                _audit(
                    Outcome.SUCCESS,
                    {
                        "tool": name,
                        "receipt_id": receipt.receipt_id,
                        "capability": capability.as_dict(),
                        **(relay.as_detail() if relay is not None else {}),
                    },
                )
            elif method == "tools/list":
                reply = _forward(message)
                if reply.status in (401, 403):
                    return _auth_challenge(reply)
                observed = tools_from_listing(reply)
                if observed is not None:
                    registry.observe_tools(server, observed)
                refusal = check_listing_drift(
                    gateway=gateway,
                    registry=registry,
                    server=server,
                    observed=observed,
                    request_id=request_id,
                    audit=_audit,
                )
                if refusal is not None:
                    return refusal
                _audit(Outcome.SUCCESS, {})
            else:
                # initialize / ping / lifecycle notifications: no arguments to
                # inspect and no tool content; forwarded, and still audited so
                # the session's existence is on the record.
                reply = _forward(message)
                if reply.status in (401, 403):
                    return _auth_challenge(reply)
                if method == "initialize":
                    refusal = check_server_identity(
                        registry=registry,
                        server=server,
                        reply=reply,
                        request_id=request_id,
                        audit=_audit,
                    )
                    if refusal is not None:
                        return refusal
                _audit(Outcome.SUCCESS, {})
        except OutboundRefused as exc:
            # The hardened client refused the destination or the response.
            # This is Sentinel speaking, so it is reported as Sentinel.
            _audit(Outcome.DENIED, {"reason": "outbound_refused", "detail": str(exc)})
            return rpc_error(
                request_id,
                JSONRPC_SENTINEL_REFUSED,
                "outbound request refused by egress policy",
                sentinel={"decision": "refused", "detail": str(exc)},
            )
        except (OutboundUnavailable, McpWireError) as exc:
            _audit(
                Outcome.DENIED,
                {"reason": "upstream_unavailable", "detail": str(exc)},
            )
            return rpc_error(
                request_id,
                JSONRPC_SENTINEL_REFUSED,
                "upstream MCP server unreachable or not speaking MCP",
                sentinel={"decision": "upstream_error", "detail": str(exc)},
            )

        # Hand the upstream's session identity back to the client. Session
        # identity belongs to the two protocol endpoints; the proxy carries it,
        # it does not own it.
        if reply.message is None:
            # A fresh Response, not the injected one: returning a Response
            # object replaces it, so the session header must ride the object
            # actually sent.
            return Response(
                status_code=status.HTTP_202_ACCEPTED,
                headers=(
                    {"Mcp-Session-Id": reply.session_id} if reply.session_id else None
                ),
            )
        if reply.session_id:
            response.headers["Mcp-Session-Id"] = reply.session_id
        return reply.message


def _mcp_reply_for_detector(
    reply: Mapping[str, Any] | None,
) -> Mapping[str, Any] | None:
    """Project an MCP tool result onto the reply shape the A2A detector reads.

    MCP text results arrive under `result.content[]`; the A2A detector scans
    `result.parts[]`. This adapter changes only that wrapper so both proxies use
    the same reply-inspection policy and refusal path.
    """
    if not reply:
        return None
    result = reply.get("result")
    if not isinstance(result, Mapping):
        return reply
    content = result.get("content")
    if not isinstance(content, list):
        return reply
    parts: list[dict[str, str]] = []
    for item in content:
        if not isinstance(item, Mapping):
            continue
        if str(item.get("kind") or item.get("type") or "") != "text":
            continue
        text = item.get("text")
        if isinstance(text, str) and text:
            parts.append({"kind": "text", "text": text})
    if not parts:
        return reply
    projected = dict(reply)
    projected["result"] = {**dict(result), "parts": parts}
    return projected
