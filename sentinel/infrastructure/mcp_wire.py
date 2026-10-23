"""The MCP wire client: one JSON-RPC message to one ENROLLED server, hardened.

WHY THIS MODULE EXISTS
----------------------
`sentinel/application/mcp_gateway.py` decides about MCP calls that are
*described* to it. That is the evaluation path, and it is honest about its
limit: no transport, no JSON-RPC, no live server. This module is the missing
transport — the piece that lets Sentinel sit BETWEEN an MCP client and an MCP
server instead of beside them, so a tool call passes through the policy gate on
its way to the server rather than being reported after the fact.

It deliberately speaks to ONE server per call, named by its enrolment record.
There is no "connect to a URL" entry point. The endpoint comes from what an
operator enrolled, never from the request — that is the default-deny egress
posture: this process dials MCP servers an operator decided about, and nothing
else. A caller who wants Sentinel to reach a new server has exactly one path:
enrol it.

WHAT IS FORWARDED AND WHAT IS REFUSED
-------------------------------------
One JSON-RPC 2.0 message per HTTP POST, per the MCP Streamable HTTP transport.
Batches are refused: the 2025-06-18 protocol revision removed JSON-RPC batching,
and accepting a batch here would mean evaluating message one and smuggling
message two. The upstream may answer either `application/json` or a
`text/event-stream` body; both are parsed, bounded by the same
`HardenedHttpClient` limits that protect every other outbound call this process
makes (post-resolution address validation, no redirects, bounded response,
TLS floor).

PROTOCOL SUPPORT IS VERSIONED, NOT IMPROVISED
---------------------------------------------
`MCP_PROTOCOL_VERSION` names the one revision this gateway understands. Nothing
here invents wire behaviour: requests carry the version header the spec defines,
session identity uses the `Mcp-Session-Id` header the spec defines, and methods
this gateway has not been taught are refused upstream of the network — see
`sentinel/interface/mcp_proxy_routes.py` for the allowlist and the reasoning.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from sentinel.domain.errors import SentinelError
from sentinel.infrastructure.outbound import HardenedHttpClient

__all__ = [
    "MCP_PROTOCOL_VERSION",
    "McpUpstreamClient",
    "McpUpstreamReply",
    "McpWireError",
    "challenge_resource_metadata",
    "token_audiences",
]

#: The MCP revision this gateway implements. Sent on every upstream request as
#: `MCP-Protocol-Version` per the Streamable HTTP transport. Bump deliberately,
#: with the behaviour changes the new revision requires — never silently.
MCP_PROTOCOL_VERSION = "2025-06-18"


class McpWireError(SentinelError):
    """The upstream server's reply could not be treated as MCP.

    Not retryable by this layer: a server that answers with an unparseable body
    or an unexpected content type is not a transient network condition, it is a
    server that is not speaking the protocol we verified at enrolment time.
    """

    is_retryable = False


@dataclass(frozen=True, slots=True)
class McpUpstreamReply:
    """What the upstream said, already parsed and bounded.

    `message` is None for a notification the server accepted without a body
    (HTTP 202 per the transport spec). `session_id` is whatever `Mcp-Session-Id`
    the server assigned or echoed, carried back so the proxy can hand it to the
    client — session identity belongs to the two endpoints, not to us.
    """

    status: int
    message: dict[str, Any] | None
    session_id: str = ""
    #: The upstream's `WWW-Authenticate` challenge, carried verbatim on a 401 or
    #: 403 so the proxy can relay it. Per the MCP authorization spec the
    #: challenge names the protected-resource metadata (RFC 9728) the client
    #: needs to discover the authorization server -- swallowing it would break
    #: the client's whole OAuth flow while looking like a generic error.
    www_authenticate: str = ""


class McpUpstreamClient:
    """Forwards one JSON-RPC message over HTTPS and parses the reply.

    Built on `HardenedHttpClient` rather than any richer HTTP library because
    the threat model is identical to the attestation gateway's: a configured
    URL, a credential in a header, and a peer who controls every byte of the
    response. Redirect-following, unbounded bodies and DNS rebinding are all
    already refused there, and this module inherits every one of those refusals
    by construction.
    """

    __slots__ = ("_client",)

    def __init__(self, *, client: HardenedHttpClient) -> None:
        self._client = client

    def _forward_streaming(
        self, endpoint: str, headers: Mapping[str, str], body: bytes,
        on_event: Callable[[Mapping[str, Any]], None],
    ) -> McpUpstreamReply:
        with self._client.stream(method="POST", url=endpoint, headers=dict(headers), body=body) as response:
            session = str(response.headers.get("mcp-session-id", "") or "")
            if response.status in (401, 403):
                return McpUpstreamReply(status=response.status, message=None, session_id=session,
                                        www_authenticate=str(response.headers.get("www-authenticate", "") or ""))
            content_type = str(response.headers.get("content-type", "")).lower()
            if "text/event-stream" not in content_type:
                if response.status == 202 or not response.body:
                    return McpUpstreamReply(status=response.status, message=None, session_id=session)
                if "application/json" not in content_type:
                    raise McpWireError(f"upstream answered content-type {content_type!r}")
                return McpUpstreamReply(status=response.status, message=_parse_json_object(response.body), session_id=session)
            final: dict[str, Any] | None = None
            for event in response.events:
                candidate = _event_message(event)
                if candidate is None:
                    continue
                if "method" in candidate:
                    on_event(candidate)      # a notification or a server-initiated request
                else:
                    final = candidate        # the response closes the interaction
                    break
        if final is None:
            raise McpWireError("upstream event stream ended without a JSON-RPC response")
        return McpUpstreamReply(status=response.status, message=final, session_id=session)

    def forward(
        self,
        *,
        endpoint: str,
        message: Mapping[str, Any],
        session_id: str = "",
        upstream_authorization: str = "",
        on_event: Callable[[Mapping[str, Any]], None] | None = None,
    ) -> McpUpstreamReply:
        """POST one JSON-RPC message to the enrolled endpoint. Parse the reply.

        With `on_event`, an event-stream reply is read INCREMENTALLY: every
        message before the response is handed to `on_event` as it arrives, and
        the response itself is returned exactly as in the buffered case, so
        everything downstream of this call (receipt, result inspection, audit)
        is unchanged. `on_event` decides what, if anything, reaches the client.

        `upstream_authorization`, when present, is the OAuth credential the
        CLIENT holds for the upstream server, passed through verbatim. It is
        never logged, never stored, and never synthesised here — Sentinel
        carries the client's delegated credential, it does not mint one.
        """
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            # Both reply shapes the transport permits. A server that answers a
            # POST with an SSE stream is in-spec, so refusing the content type
            # would be refusing compliant servers.
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
        }
        if session_id:
            headers["Mcp-Session-Id"] = session_id
        if upstream_authorization:
            headers["Authorization"] = upstream_authorization

        body = json.dumps(dict(message)).encode("utf-8")
        if on_event is not None:
            return self._forward_streaming(endpoint, headers, body, on_event)
        response = self._client.request(
            method="POST", url=endpoint, headers=headers, body=body
        )

        reply_session = str(response.headers.get("mcp-session-id", "") or "")
        if response.status in (401, 403):
            # An authorization challenge, not a protocol reply. The body (often
            # HTML or empty) is deliberately not parsed: what the client needs
            # is the status and the WWW-Authenticate header, which carries the
            # RFC 9728 resource-metadata pointer its OAuth flow starts from.
            return McpUpstreamReply(
                status=response.status,
                message=None,
                session_id=reply_session,
                www_authenticate=str(
                    response.headers.get("www-authenticate", "") or ""
                ),
            )
        if response.status == 202 or not response.body:
            # A notification accepted without a reply body. In-spec, and the
            # absence of a message is information, not an error.
            return McpUpstreamReply(
                status=response.status, message=None, session_id=reply_session
            )

        content_type = str(response.headers.get("content-type", "")).lower()
        if "text/event-stream" in content_type:
            parsed = _last_json_rpc_from_sse(response.body)
        elif "application/json" in content_type:
            parsed = _parse_json_object(response.body)
        else:
            raise McpWireError(
                f"upstream answered content-type {content_type!r}; the MCP "
                "Streamable HTTP transport defines application/json and "
                "text/event-stream, and guessing at anything else would mean "
                "acting on bytes we cannot classify"
            )
        return McpUpstreamReply(
            status=response.status, message=parsed, session_id=reply_session
        )


def _event_message(event: bytes) -> dict[str, Any] | None:
    """The JSON-RPC object in one server-sent event, or None."""
    try:
        lines = [line[len("data:"):].strip() for line in event.decode("utf-8").splitlines() if line.startswith("data:")]
        candidate = json.loads("\n".join(lines)) if lines else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return candidate if isinstance(candidate, dict) else None


def _parse_json_object(raw: bytes) -> dict[str, Any]:
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise McpWireError(f"upstream body is not JSON: {exc}") from exc
    if isinstance(parsed, list):
        # A batch reply from a server this gateway told (via the protocol
        # version header) that it speaks 2025-06-18, where batching is removed.
        raise McpWireError(
            "upstream answered with a JSON-RPC batch; batching is not part of "
            f"protocol revision {MCP_PROTOCOL_VERSION} and a batch reply to a "
            "single message cannot be attributed to it safely"
        )
    if not isinstance(parsed, dict):
        raise McpWireError(
            f"upstream body is JSON but not an object ({type(parsed).__name__})"
        )
    return parsed


def _last_json_rpc_from_sse(raw: bytes) -> dict[str, Any]:
    """Extract the response message from an SSE body.

    The transport allows a server to stream related messages (progress
    notifications, server-initiated requests) before the actual response on the
    same stream. This v1 gateway does not relay intermediate stream traffic —
    stated in `docs/INTEGRATIONS.md`, not hidden — so the LAST well-formed data
    event is taken, which per the spec's ordering is the response that closes
    the interaction. The body is already size-bounded by `HardenedHttpClient`,
    so a stream that never ends was refused before this function ran.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise McpWireError(f"upstream SSE body is not UTF-8: {exc}") from exc

    last: dict[str, Any] | None = None
    for event in text.split("\n\n"):
        data_lines = [
            line[len("data:"):].strip()
            for line in event.splitlines()
            if line.startswith("data:")
        ]
        if not data_lines:
            continue
        try:
            candidate = json.loads("\n".join(data_lines))
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict):
            last = candidate
    if last is None:
        raise McpWireError(
            "upstream SSE stream contained no parseable JSON-RPC message"
        )
    return last


def token_audiences(authorization: str) -> tuple[str, ...] | None:
    """The `aud` claim of a Bearer JWT, WITHOUT verifying the token.

    Returns None when the credential is not inspectable -- not a Bearer scheme,
    not JWT-shaped, or carrying no `aud` claim. None means "no opinion", never
    "valid": Sentinel is not the resource server, holds none of its keys, and
    therefore cannot verify a signature. What it CAN do without pretending
    otherwise is read the audience out of a structurally-JWT credential and
    refuse to forward one that is plainly bound to a DIFFERENT resource --
    the credential-audience restriction of the MCP authorization spec (RFC 8707
    resource indicators), enforced at the one point where a token aimed at
    server A could otherwise be replayed against server B through this proxy.
    """
    import base64
    import binascii

    scheme, _, credential = authorization.strip().partition(" ")
    if scheme.lower() != "bearer":
        return None
    parts = credential.strip().split(".")
    if len(parts) != 3:
        return None
    payload = parts[1]
    try:
        decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        claims = json.loads(decoded)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None
    if not isinstance(claims, dict) or "aud" not in claims:
        return None
    aud = claims["aud"]
    if isinstance(aud, str):
        return (aud,)
    if isinstance(aud, list):
        return tuple(str(a) for a in aud)
    return None


def challenge_resource_metadata(www_authenticate: str) -> str:
    """The `resource_metadata` URL named by a Bearer challenge, or "".

    RFC 9728 lets a 401 point the client at the protected-resource metadata
    document that names which authorization server to trust. That pointer is
    supplied by the RESOURCE -- which, for an MCP server, is the party whose
    trustworthiness is in question. A compromised server that answers 401 with
    `resource_metadata="https://attacker.example/..."` sends the client's whole
    OAuth flow to an authorization server the attacker controls; the client
    then either discloses credentials to it or obtains a token the attacker
    minted. That is OAuth issuer confusion, and it is the reason this value is
    extracted rather than relayed unread -- see `mcp_proxy_routes.py`, which
    refuses a challenge whose pointer is not same-origin with the endpoint an
    operator actually enrolled.

    Deliberately a small, permissive parser: challenges are comma-separated
    `key=value` auth-params where the value may be quoted. Anything it cannot
    find returns "" -- and "" means "nothing to check", so the caller must not
    read it as "checked and safe".
    """
    for scheme_params in www_authenticate.split(","):
        key, _, raw = scheme_params.partition("=")
        # `Bearer resource_metadata="..."` puts the scheme on the first param,
        # so the key is matched on its tail rather than on equality.
        if key.strip().lower().split()[-1:] != ["resource_metadata"]:
            continue
        return raw.strip().strip('"').strip()
    return ""
