"""The stdio MCP bridge forwards through Sentinel and fails closed in band."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from sentinel.sdk.mcp_stdio import (
    Bridge,
    Framing,
    JSONRPC_INVALID_REQUEST,
    JSONRPC_SENTINEL_UNAVAILABLE,
    read_message,
    write_message,
)
from sentinel.sdk.remote import SentinelClient, SentinelUnavailable

ROOT = Path(__file__).resolve().parent.parent


class _LoopbackHandler(BaseHTTPRequestHandler):
    seen: dict[str, object] = {}

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        type(self).seen = {
            "path": self.path,
            "agent_id": self.headers.get("X-Sentinel-Agent-Id"),
            "authorization": self.headers.get("Authorization"),
            "body": body,
        }
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Mcp-Session-Id", "mcp-session-1")
        self.end_headers()
        self.wfile.write(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": json.loads(body.decode("utf-8"))["id"],
                    "result": {"ok": True},
                }
            ).encode("utf-8")
        )

    def log_message(self, format, *args):  # noqa: A002
        return


def test_mcp_stdio_subprocess_forwards_one_request_to_sentinel():
    try:
        server = HTTPServer(("127.0.0.1", 0), _LoopbackHandler)
    except PermissionError as exc:
        pytest.skip(f"loopback listener refused by this sandbox: {exc}")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"

    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "sentinel.sdk.mcp_stdio",
                "--server-id",
                "aws-prod",
                "--sentinel-url",
                base_url,
                "--api-key-env",
                "SENTINEL_API_KEY",
                "--agent-id",
                "agent-1",
            ],
            input='{"jsonrpc":"2.0","id":1,"method":"ping"}\n',
            text=True,
            capture_output=True,
            cwd=str(ROOT),
            env={"PYTHONPATH": str(ROOT), "SENTINEL_API_KEY": "sk-test"},
            timeout=10,
        )
    finally:
        server.shutdown()
        server.server_close()

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"ok": True},
    }
    assert _LoopbackHandler.seen["path"] == "/v1/mcp/proxy/aws-prod"
    assert _LoopbackHandler.seen["agent_id"] == "agent-1"
    assert _LoopbackHandler.seen["authorization"] == "Bearer sk-test"
    assert json.loads(_LoopbackHandler.seen["body"].decode("utf-8"))["method"] == "ping"  # type: ignore[union-attr]


def test_mcp_bridge_refuses_batches():
    bridge = Bridge(
        client=SentinelClient(base_url="https://sentinel.example", api_key="sk-test"),
        server_id="server-1",
        agent_id="agent-1",
    )

    reply = bridge.handle(b'[{"jsonrpc":"2.0","id":1,"method":"ping"}]')

    assert reply is not None
    assert reply["error"]["code"] == JSONRPC_INVALID_REQUEST


def test_mcp_bridge_returns_jsonrpc_error_when_sentinel_is_unreachable():
    class BrokenClient:
        def forward_mcp(self, **kwargs):
            raise SentinelUnavailable("down")

    bridge = Bridge(client=BrokenClient(), server_id="server-1", agent_id="agent-1")  # type: ignore[arg-type]

    reply = bridge.handle(b'{"jsonrpc":"2.0","id":"r1","method":"tools/list"}')

    assert reply is not None
    assert reply["id"] == "r1"
    assert reply["error"]["code"] == JSONRPC_SENTINEL_UNAVAILABLE


def test_content_length_framing_round_trips():
    import io

    inbound = io.BytesIO(b'Content-Length: 44\r\n\r\n{"jsonrpc":"2.0","id":1,"method":"ping"}')

    raw, framing = read_message(inbound)  # type: ignore[misc]
    assert framing is Framing.CONTENT_LENGTH
    assert json.loads(raw) == {"jsonrpc": "2.0", "id": 1, "method": "ping"}

    outbound = io.BytesIO()
    write_message(outbound, {"jsonrpc": "2.0", "id": 1, "result": {}}, framing)

    assert outbound.getvalue().startswith(b"Content-Length: ")
