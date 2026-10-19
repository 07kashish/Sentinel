"""The MCP wire client's parsing and header discipline, without a network.

`HardenedHttpClient`'s transport behaviour (SSRF, redirects, bounds) is proven
in `test_security_outbound.py`. What is proven HERE is the layer above it: that
the wire client speaks the MCP Streamable HTTP shapes correctly and refuses
the shapes it cannot classify — because a proxy that guesses at an upstream
reply is a proxy that can be made to relay something nobody parsed.
"""

from __future__ import annotations

import json

import pytest

from sentinel.infrastructure.mcp_wire import (
    MCP_PROTOCOL_VERSION,
    McpUpstreamClient,
    McpWireError,
)
from sentinel.infrastructure.outbound import OutboundResponse


class FakeHttp:
    """Stands in for HardenedHttpClient; records the request, returns a script."""

    def __init__(self, *, status=200, headers=None, body=b"{}"):
        self.status = status
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.body = body
        self.requests: list[dict] = []

    def request(self, *, method, url, headers=None, body=None, idempotent=False):
        self.requests.append(
            {"method": method, "url": url, "headers": dict(headers or {}), "body": body}
        )
        return OutboundResponse(
            status=self.status, headers=self.headers, body=self.body, peer="fake:443"
        )


def _reply(**over):
    message = {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
    message.update(over)
    return json.dumps(message).encode()


def test_the_protocol_version_and_session_ride_every_request():
    http = FakeHttp(
        headers={"Content-Type": "application/json"}, body=_reply()
    )
    client = McpUpstreamClient(client=http)
    client.forward(
        endpoint="https://mcp.example/rpc",
        message={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        session_id="sess-9",
    )
    sent = http.requests[0]["headers"]
    assert sent["MCP-Protocol-Version"] == MCP_PROTOCOL_VERSION
    assert sent["Mcp-Session-Id"] == "sess-9"
    assert "Authorization" not in sent, (
        "an Authorization header appeared from nowhere; credentials are "
        "forwarded only when the caller supplies one"
    )


def test_an_upstream_credential_is_forwarded_verbatim_when_supplied():
    http = FakeHttp(headers={"Content-Type": "application/json"}, body=_reply())
    client = McpUpstreamClient(client=http)
    client.forward(
        endpoint="https://mcp.example/rpc",
        message={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        upstream_authorization="Bearer upstream-token",
    )
    assert http.requests[0]["headers"]["Authorization"] == "Bearer upstream-token"


def test_a_json_reply_is_parsed_and_the_session_header_carried_back():
    http = FakeHttp(
        headers={"Content-Type": "application/json", "Mcp-Session-Id": "s-2"},
        body=_reply(),
    )
    reply = McpUpstreamClient(client=http).forward(
        endpoint="https://mcp.example/rpc",
        message={"jsonrpc": "2.0", "id": 1, "method": "ping"},
    )
    assert reply.message == {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
    assert reply.session_id == "s-2"


def test_an_sse_reply_yields_the_response_that_closes_the_interaction():
    """Progress notifications may precede the response on the same stream."""
    progress = json.dumps(
        {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"n": 1}}
    )
    final = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"done": True}})
    body = f"event: message\ndata: {progress}\n\nevent: message\ndata: {final}\n\n"
    http = FakeHttp(
        headers={"Content-Type": "text/event-stream"}, body=body.encode()
    )
    reply = McpUpstreamClient(client=http).forward(
        endpoint="https://mcp.example/rpc",
        message={"jsonrpc": "2.0", "id": 1, "method": "tools/call"},
    )
    assert reply.message == {"jsonrpc": "2.0", "id": 1, "result": {"done": True}}


def test_a_202_with_no_body_is_a_notification_acknowledgement():
    http = FakeHttp(status=202, headers={}, body=b"")
    reply = McpUpstreamClient(client=http).forward(
        endpoint="https://mcp.example/rpc",
        message={"jsonrpc": "2.0", "method": "notifications/initialized"},
    )
    assert reply.status == 202
    assert reply.message is None


def test_a_batch_reply_is_refused_not_guessed_at():
    http = FakeHttp(
        headers={"Content-Type": "application/json"},
        body=json.dumps([{"jsonrpc": "2.0", "id": 1, "result": {}}]).encode(),
    )
    with pytest.raises(McpWireError) as caught:
        McpUpstreamClient(client=http).forward(
            endpoint="https://mcp.example/rpc",
            message={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
    assert "batch" in str(caught.value).lower()


def test_an_unclassifiable_content_type_is_refused():
    http = FakeHttp(headers={"Content-Type": "text/html"}, body=b"<html>hi</html>")
    with pytest.raises(McpWireError) as caught:
        McpUpstreamClient(client=http).forward(
            endpoint="https://mcp.example/rpc",
            message={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
    assert "content-type" in str(caught.value).lower()


def test_an_sse_stream_with_no_parseable_message_is_refused():
    http = FakeHttp(
        headers={"Content-Type": "text/event-stream"},
        body=b"event: message\ndata: not-json\n\n",
    )
    with pytest.raises(McpWireError):
        McpUpstreamClient(client=http).forward(
            endpoint="https://mcp.example/rpc",
            message={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )


def test_a_401_challenge_is_returned_not_parsed():
    """The body of a 401 is often HTML; what matters is the header."""
    http = FakeHttp(
        status=401,
        headers={
            "Content-Type": "text/html",
            "WWW-Authenticate": (
                'Bearer resource_metadata='
                '"https://mcp.example/.well-known/oauth-protected-resource"'
            ),
        },
        body=b"<html>unauthorized</html>",
    )
    reply = McpUpstreamClient(client=http).forward(
        endpoint="https://mcp.example/rpc",
        message={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    assert reply.status == 401
    assert reply.message is None
    assert "resource_metadata" in reply.www_authenticate


def test_token_audiences_reads_a_jwt_without_verifying_it():
    import base64 as _b64
    import json as _json

    def _jwt(payload):
        seg = lambda b: (  # noqa: E731 - three uses, one line each
            _b64.urlsafe_b64encode(_json.dumps(b).encode()).decode().rstrip("=")
        )
        return f"Bearer {seg({'alg': 'RS256'})}.{seg(payload)}.not-a-real-signature"

    from sentinel.infrastructure.mcp_wire import token_audiences

    assert token_audiences(_jwt({"aud": "https://mcp.example/rpc"})) == (
        "https://mcp.example/rpc",
    )
    assert token_audiences(_jwt({"aud": ["a", "b"]})) == ("a", "b")
    # None means "no opinion", never "valid": not-a-JWT, no aud, wrong scheme.
    assert token_audiences("Bearer opaque-token") is None
    assert token_audiences(_jwt({"sub": "x"})) is None
    assert token_audiences("Basic dXNlcjpwdw==") is None
