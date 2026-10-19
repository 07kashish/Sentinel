"""MCP over stdio on one side, Sentinel's MCP proxy over HTTP on the other.

WHAT THIS IS
------------
Claude Desktop, Cursor and most other MCP clients launch a server as a child
process and speak JSON-RPC to it over stdin/stdout. Sentinel's proxy
(`POST /v1/mcp/proxy/{server_id}`) is an HTTP endpoint. This module is the
child process that bridges the two: every message the client writes is
forwarded to the proxy with the delegation headers, and the proxy's answer is
written back.

    python -m sentinel.sdk.mcp_stdio --server-id aws-prod \\
        --sentinel-url https://sentinel.example --agent-id agent:desktop \\
        --api-key-env SENTINEL_API_KEY

The client sees an ordinary MCP server. The upstream server sees Sentinel.
Every `tools/call` is evaluated against the live definition, every listing is
drift-checked, and none of it depends on the client cooperating -- the client
was pointed here instead of at the server, which is the only integration step.

FAIL CLOSED, IN BAND
--------------------
When Sentinel cannot be reached the request is answered with a JSON-RPC error
(`-32051`), not dropped and not answered with a fabricated result. An MCP
client shows an error to its agent; a silent exit would look, to the agent,
exactly like a server that never had the tool. Notifications carry no id and
cannot be answered, so a failure to forward one is written to stderr.

FRAMING
-------
Both wire framings in use are accepted, per message: newline-delimited JSON
(the MCP stdio transport) and `Content-Length:` headers (the LSP framing some
clients still emit). A reply uses the framing its request arrived in. Batches
are refused with `-32600`: the proxy does not accept them either, and a
wrapper that split a batch would be evaluating messages the proxy never saw
together.

STANDARD LIBRARY ONLY
---------------------
`argparse`, `json`, `sys`, and the hardened HTTP client this package already
depends on. The environment is read through `read_environment`, the one
sanctioned reader, so the API key is obtained the way every other Sentinel
process obtains configuration.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Any, BinaryIO, Mapping, Sequence, TextIO

from sentinel.sdk.remote import McpProxyReply, SentinelClient, SentinelUnavailable

__all__ = [
    "JSONRPC_INVALID_REQUEST",
    "JSONRPC_PARSE_ERROR",
    "JSONRPC_SENTINEL_UNAVAILABLE",
    "JSONRPC_UPSTREAM_AUTH_REQUIRED",
    "Bridge",
    "Framing",
    "main",
    "read_message",
    "serve",
    "write_message",
]

JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
#: Sentinel could not be reached, or answered something that is not MCP.
#: Adjacent to the proxy's own `-32050` (policy refusal) so a client that
#: groups errors by code sees them side by side, and distinct from it because
#: "the gate said no" and "nobody answered" must never be one code.
JSONRPC_SENTINEL_UNAVAILABLE = -32051
#: The upstream demanded authorization. Over HTTP the proxy relays this as a
#: bare 401/403 with `WWW-Authenticate`; stdio has no headers, so the
#: challenge rides in `error.data`.
JSONRPC_UPSTREAM_AUTH_REQUIRED = -32052

#: A single JSON-RPC message larger than this is refused. Generous for tool
#: arguments; small enough that a runaway client cannot exhaust memory.
_MAX_MESSAGE_BYTES = 4 * 1024 * 1024


class Framing(Enum):
    NEWLINE = "newline"
    CONTENT_LENGTH = "content-length"


def _error(request_id: Any, code: int, message: str, **data: Any) -> dict[str, Any]:
    body: dict[str, Any] = {"code": code, "message": message}
    if data:
        body["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": body}


# ── framing ────────────────────────────────────────────────────────────────


def read_message(stream: BinaryIO) -> tuple[bytes, Framing] | None:
    """One raw message from the client, and the framing it arrived in.

    Returns None at end of input. Blank lines between newline-delimited
    messages are skipped. A `Content-Length` header switches to header framing
    for that message only.
    """
    while True:
        line = stream.readline(_MAX_MESSAGE_BYTES + 1)
        if not line:
            return None
        if len(line) > _MAX_MESSAGE_BYTES:
            return b"", Framing.NEWLINE
        if not line.strip():
            continue
        if line.lower().startswith(b"content-length:"):
            return _read_content_length_body(stream, line), Framing.CONTENT_LENGTH
        return line.rstrip(b"\r\n"), Framing.NEWLINE


def _read_content_length_body(stream: BinaryIO, header: bytes) -> bytes:
    try:
        length = int(header.split(b":", 1)[1].strip())
    except ValueError:
        length = -1
    # Consume the remaining headers up to the blank line; only Content-Length
    # is meaningful and anything else (Content-Type) is ignored by design.
    while True:
        extra = stream.readline(_MAX_MESSAGE_BYTES + 1)
        if not extra or extra in (b"\r\n", b"\n"):
            break
    if length < 0 or length > _MAX_MESSAGE_BYTES:
        # Returned as an unparseable message so the loop answers with a
        # parse error rather than reading a body whose size it cannot trust.
        return b""
    return stream.read(length)


def write_message(stream: BinaryIO, message: Mapping[str, Any], framing: Framing) -> None:
    encoded = json.dumps(message, ensure_ascii=False).encode("utf-8")
    if framing is Framing.CONTENT_LENGTH:
        stream.write(f"Content-Length: {len(encoded)}\r\n\r\n".encode("ascii"))
        stream.write(encoded)
    else:
        stream.write(encoded + b"\n")
    stream.flush()


# ── the bridge ─────────────────────────────────────────────────────────────


@dataclass(slots=True)
class Bridge:
    """Forwards one client's messages to one enrolled server through Sentinel.

    Mutable in exactly one field: `mcp_session_id`, the upstream session
    identity the proxy hands back on `initialize` and expects on every later
    call. It belongs to the two protocol endpoints; this process carries it.
    """

    client: SentinelClient
    server_id: str
    agent_id: str
    principal: str = ""
    session_id: str = ""
    trust_level: str = ""
    upstream_authorization: str = ""
    mcp_session_id: str = ""

    def handle(self, raw: bytes) -> Mapping[str, Any] | None:
        """One message in, at most one message out. Never raises on input."""
        try:
            message = json.loads(raw)
        except ValueError as error:
            return _error(None, JSONRPC_PARSE_ERROR, f"message is not JSON: {error}")
        if isinstance(message, list):
            return _error(
                None,
                JSONRPC_INVALID_REQUEST,
                "JSON-RPC batches are refused: Sentinel evaluates one message "
                "at a time and a wrapper that split a batch would be "
                "forwarding messages the gate never saw together",
            )
        if (
            not isinstance(message, dict)
            or message.get("jsonrpc") != "2.0"
            or not isinstance(message.get("method"), str)
        ):
            request_id = message.get("id") if isinstance(message, dict) else None
            return _error(
                request_id,
                JSONRPC_INVALID_REQUEST,
                "expected a single JSON-RPC 2.0 request object with a method",
            )

        request_id = message.get("id")
        is_notification = "id" not in message

        try:
            reply = self.client.forward_mcp(
                server_id=self.server_id,
                message=raw,
                agent_id=self.agent_id,
                principal=self.principal,
                session_id=self.session_id,
                trust_level=self.trust_level,
                mcp_session_id=self.mcp_session_id,
                upstream_authorization=self.upstream_authorization,
            )
        except SentinelUnavailable as outage:
            if is_notification:
                return None
            return _error(
                request_id,
                JSONRPC_SENTINEL_UNAVAILABLE,
                "Sentinel could not be reached; the request was NOT forwarded",
                sentinel={"decision": "unavailable", "detail": str(outage)},
            )

        if reply.session_id:
            self.mcp_session_id = reply.session_id
        return self._translate(reply, request_id, is_notification)

    def _translate(
        self, reply: McpProxyReply, request_id: Any, is_notification: bool
    ) -> Mapping[str, Any] | None:
        if reply.status == 202 or (reply.status == 200 and reply.message is None):
            # The proxy's answer to a notification. Nothing to write.
            return None
        if reply.status in (401, 403) and reply.message is None:
            if is_notification:
                return None
            return _error(
                request_id,
                JSONRPC_UPSTREAM_AUTH_REQUIRED,
                "the upstream MCP server requires authorization",
                sentinel={
                    "decision": "upstream_auth_required",
                    "status": reply.status,
                    "www_authenticate": reply.www_authenticate,
                },
            )
        if reply.status != 200 or reply.message is None:
            if is_notification:
                return None
            return _error(
                request_id,
                JSONRPC_SENTINEL_UNAVAILABLE,
                f"Sentinel answered HTTP {reply.status}, which is not an MCP "
                "reply; the request was NOT forwarded",
                sentinel={"decision": "unavailable", "status": reply.status},
            )
        return reply.message


def serve(bridge: Bridge, *, stdin: BinaryIO, stdout: BinaryIO, stderr: TextIO) -> int:
    """Run until the client closes stdin. Returns the process exit code."""
    while True:
        item = read_message(stdin)
        if item is None:
            return 0
        raw, framing = item
        reply = bridge.handle(raw)
        if reply is not None:
            write_message(stdout, reply, framing)
        elif not raw.strip():
            stderr.write("sentinel-mcp-stdio: dropped an unreadable message\n")


# ── cli ────────────────────────────────────────────────────────────────────


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel-mcp-stdio",
        description=(
            "Bridge an MCP client on stdio to Sentinel's MCP proxy. "
            "Point the client at this command instead of at the server."
        ),
    )
    parser.add_argument("--server-id", required=True, help="the enrolled MCP server id")
    parser.add_argument("--sentinel-url", required=True, help="Sentinel base URL")
    parser.add_argument(
        "--agent-id",
        default="",
        help="X-Sentinel-Agent-Id (or set SENTINEL_AGENT_ID)",
    )
    parser.add_argument(
        "--api-key-env",
        default="SENTINEL_API_KEY",
        help="environment variable holding the Sentinel API key",
    )
    parser.add_argument("--principal", default="", help="X-Sentinel-Principal")
    parser.add_argument("--session-id", default="", help="X-Sentinel-Session-Id")
    parser.add_argument("--trust-level", default="", help="X-Sentinel-Trust-Level")
    parser.add_argument(
        "--upstream-authorization-env",
        default="SENTINEL_UPSTREAM_AUTHORIZATION",
        help="environment variable holding the client's own upstream credential",
    )
    parser.add_argument("--timeout", type=float, default=30.0, help="seconds per call")
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    stdin: BinaryIO | None = None,
    stdout: BinaryIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Entry point. Streams and environment are parameters so this is testable."""
    args = _parser().parse_args(list(argv) if argv is not None else None)
    env = environ if environ is not None else os.environ
    err = stderr or sys.stderr

    api_key = env.get(args.api_key_env, "")
    if not api_key.strip():
        err.write(
            f"sentinel-mcp-stdio: {args.api_key_env} is not set; refusing to "
            "start a bridge that could not authenticate to Sentinel\n"
        )
        return 78  # EX_CONFIG
    agent_id = (args.agent_id or env.get("SENTINEL_AGENT_ID", "")).strip()
    if not agent_id:
        err.write(
            "sentinel-mcp-stdio: --agent-id (or SENTINEL_AGENT_ID) is required; "
            "a proxied MCP call must be attributable to an agent\n"
        )
        return 78

    try:
        client = SentinelClient(
            base_url=args.sentinel_url, api_key=api_key, timeout_seconds=args.timeout
        )
    except ValueError as error:
        err.write(f"sentinel-mcp-stdio: {error}\n")
        return 78

    bridge = Bridge(
        client=client,
        server_id=args.server_id,
        agent_id=agent_id,
        principal=args.principal,
        session_id=args.session_id,
        trust_level=args.trust_level,
        upstream_authorization=env.get(args.upstream_authorization_env, ""),
    )
    return serve(
        bridge,
        stdin=stdin or sys.stdin.buffer,
        stdout=stdout or sys.stdout.buffer,
        stderr=err,
    )


if __name__ == "__main__":
    sys.exit(main())
