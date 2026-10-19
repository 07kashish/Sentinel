"""`mcp-discover`: contact a candidate server, record it, enrol NOTHING.

WHY THE "ENROLS NOTHING" HALF IS THE POINT
------------------------------------------
Discovery exists to remove the hand-authoring of a tools file, not to remove
the review. `mcp-enrol` takes a file because enrolment is the moment an
operator says "these are the tools I reviewed"; a discover command that
enrolled what it found would collapse that into "approve whatever the server
served, unread" and quietly delete the reason pinning exists.

So the assertions here are as much about what did NOT happen -- the server is
OBSERVED and not ENROLLED, and the proxy still refuses it -- as about the file
being written.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from sentinel.domain.mcp import McpServerTrust
from sentinel.infrastructure.mcp_registry import SqlMcpRegistry
from sentinel.infrastructure.mcp_wire import McpUpstreamReply
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.interface.mcp_cli import discover_mcp_server

ENDPOINT = "https://candidate.example/rpc"
TOOLS = [
    {
        "name": "search_docs",
        "description": "Search the internal documentation index.",
        "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}},
    }
]


class FakeWire:
    """Answers initialize and tools/list; records what it was asked."""

    def __init__(self, *, tools=None, init_status=200, list_status=200):
        self.tools = TOOLS if tools is None else tools
        self.init_status = init_status
        self.list_status = list_status
        self.calls: list[str] = []

    def forward(self, *, endpoint, message, session_id="", upstream_authorization=""):
        method = message.get("method", "")
        self.calls.append(method)
        if method == "initialize":
            if self.init_status != 200:
                return McpUpstreamReply(status=self.init_status, message=None)
            return McpUpstreamReply(
                status=200,
                message={
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "candidate", "version": "3.1"},
                    },
                },
                session_id="disc-1",
            )
        return McpUpstreamReply(
            status=self.list_status,
            message={
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "result": {"tools": list(self.tools)},
            },
        )


@pytest.fixture
def registry(engine_config):
    pool = build_engine(engine_config)
    migrate(pool)
    with pool.acquire() as conn:
        conn.begin()
        conn.execute_rowcount(
            f"INSERT INTO tenants (tenant_id, name, created_at) "
            f"VALUES ({conn.p},{conn.p},{conn.p})",
            ("acme", "Acme", "2026-07-25T12:00:00+00:00"),
        )
        conn.commit()
    try:
        yield SqlMcpRegistry(pool=pool)
    finally:
        pool.close()


def _run(registry, wire, out_path="", server_id="candidate-mcp"):
    stream = io.StringIO()
    code = discover_mcp_server(
        tenant="acme",
        server_id=server_id,
        endpoint=ENDPOINT,
        out_path=str(out_path),
        registry=registry,
        settings=None,
        stream=stream,
        client=wire,
    )
    return code, stream.getvalue()


def test_discovery_records_the_server_as_observed_never_enrolled(registry):
    """OBSERVED is refused by the proxy; that is the safe resting state."""
    code, output = _run(registry, FakeWire())
    assert code == 0, output

    found = registry.lookup("acme", "candidate-mcp")
    assert found is not None
    assert found.trust is McpServerTrust.OBSERVED, (
        "discovery enrolled a server; the operator review step has been deleted"
    )
    assert found.endpoint == ENDPOINT
    assert "OBSERVED" in output
    assert "will NOT dial" in output


def test_discovery_records_what_the_server_served(registry):
    """The provenance record starts at discovery, not at first proxied call."""
    _run(registry, FakeWire())
    rows = registry.tool_provenance("acme", "candidate-mcp")
    assert [r["tool_name"] for r in rows] == ["search_docs"]
    assert registry.server_info("acme", "candidate-mcp") == "candidate/3.1"


def test_discovery_writes_the_file_mcp_enrol_accepts(registry, tmp_path):
    out = tmp_path / "tools.json"
    _run(registry, FakeWire(), out_path=out)
    document = json.loads(Path(out).read_text(encoding="utf-8"))
    assert [t["name"] for t in document["tools"]] == ["search_docs"]
    # The shape `mcp-enrol` reads: either a bare list or {"tools": [...]}.
    assert isinstance(document["tools"], list)


def test_an_authorization_challenge_is_reported_not_worked_around(registry):
    """Discovery holds no upstream credential and will not invent one."""
    wire = FakeWire(init_status=401)
    code, output = _run(registry, wire)
    assert code != 0
    assert "requires authorization" in output
    assert registry.lookup("acme", "candidate-mcp") is None, (
        "a server that never listed its tools was recorded anyway"
    )
    assert wire.calls == ["initialize"], "the listing was attempted after a 401"


def test_a_server_listing_nothing_records_nothing(registry):
    code, output = _run(registry, FakeWire(tools=[]))
    assert code != 0
    assert "listed no tools" in output
    assert registry.lookup("acme", "candidate-mcp") is None
