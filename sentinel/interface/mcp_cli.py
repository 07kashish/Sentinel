"""Every MCP operator command: enrol, block, list, provenance, discover.

WHY THESE ARE NOT IN `cli.py`
-----------------------------
Two reasons, and the second matters more than the size one.

They are trust-anchor operations. Enrolling a server decides which servers an
agent may reach and what their tools are allowed to be, which
`sentinel/domain/authorization.py` records as guarded by shell access to the
host rather than by a bearer token. Keeping them together makes that boundary
one file to read rather than a set of branches inside a command dispatcher.

`discover_mcp_server` is also the one CLI operation that opens a network
connection. Beside the pure database commands it invited the reading that
discovery is just another registry write; it is not, and its egress policy is
now visible at the top of the file it lives in.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Sequence, TextIO

from sentinel.domain.mcp import McpServerIdentity, McpServerTrust, McpToolDefinition
from sentinel.application.mcp_gateway import McpCallRefused, McpGateway
from sentinel.application.protect_gate import ProtectGate
from sentinel.infrastructure.detection import DeterministicPolicy
from sentinel.infrastructure.mcp_registry import SqlMcpRegistry
from sentinel.infrastructure.openapi import (
    OpenApiRefused,
    load_spec,
    operations_from_spec,
)

__all__ = ["discover_mcp_server", "mcp_command"]


def _load_tool_definitions(path: str) -> tuple[McpToolDefinition, ...]:
    """Read reviewed tool definitions from a server's `tools/list` output.

    Accepts either the raw JSON-RPC result (`{"tools": [...]}`) or a bare list,
    because an operator captures whichever their client prints and should not
    have to reshape it to enrol a server.

    A FILE and not a live fetch, deliberately. Enrolment is the moment an
    operator says "these are the tools I reviewed", and fetching the definitions
    at enrolment time would mean the thing being approved is whatever the server
    happened to serve, unread. The point of a pin is that a human looked.
    """
    raw: Any = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        raw = raw.get("tools", [])
    if not isinstance(raw, list) or not raw:
        raise ValueError(
            f"{path} contains no tool definitions; expected a list or "
            '{"tools": [...]}'
        )
    tools: list[McpToolDefinition] = []
    for entry in raw:
        if not isinstance(entry, dict) or not str(entry.get("name", "")).strip():
            raise ValueError(f"{path} has an entry with no name: {entry!r}")
        tools.append(
            McpToolDefinition(
                name=str(entry["name"]),
                description=str(entry.get("description", "")),
                # Both spellings: `inputSchema` is what MCP puts on the wire,
                # `input_schema` is what this codebase calls it.
                input_schema=dict(
                    entry.get("inputSchema") or entry.get("input_schema") or {}
                ),
            )
        )
    return tuple(tools)


def mcp_command(
    command: str,
    rest: Sequence[str],
    *,
    pool: Any,
    stream: TextIO,
    settings: Any = None,
) -> int:
    """MCP trust-anchor operations. CLI-only, for the reason agent enrol is.

    Enrolling an MCP server decides which servers an agent may reach and what
    their tools are allowed to be. That is a trust-anchor change, and
    `sentinel/domain/authorization.py` records the decision that trust-anchor
    changes are guarded by shell access to the host rather than by a bearer
    token -- a credential that could enrol its own MCP server could enrol a
    hostile one.
    """
    registry = SqlMcpRegistry(pool=pool)

    if command == "mcp-list":
        if len(rest) < 1:
            stream.write("usage: mcp-list <tenant>\n")
            return 64
        servers = registry.list_servers(rest[0])
        if not servers:
            stream.write(f"no MCP servers enrolled for {rest[0]}\n")
            return 0
        for row in servers:
            stream.write(
                f"{row['server_id']}\t{row['trust']}\t"
                f"{row['pinned_tools']} pinned\t{row['endpoint']}\n"
            )
        return 0

    if command == "mcp-discover":
        if len(rest) < 3:
            stream.write("usage: mcp-discover <tenant> <server> <endpoint> [out.json]\n")
            return 64
        return discover_mcp_server(
            tenant=rest[0],
            server_id=rest[1],
            endpoint=rest[2],
            out_path=rest[3] if len(rest) > 3 else "",
            registry=registry,
            settings=settings,
            stream=stream,
        )

    if command == "mcp-provenance":
        if len(rest) < 2:
            stream.write("usage: mcp-provenance <tenant> <server>\n")
            return 64
        rows = registry.tool_provenance(rest[0], rest[1])
        changes = registry.tool_changes(rest[0], rest[1])
        if not rows and not changes:
            stream.write(f"no provenance recorded for {rest[1]} ({rest[0]})\n")
            return 0
        # str() around the fingerprint: the registry returns
        # dict[str, object], and slicing an object is not valid.
        for row in rows:
            stream.write(
                f"{row['tool_name']}\t{str(row['fingerprint'])[:16]}\t"
                f"first {row['first_seen']}\tlast {row['last_seen']}\t"
                f"seen {row['times_seen']}x\n"
            )
        for row in changes:
            stream.write(
                f"DRIFT {row['observed_at']}\t{row['tool_name']}\t"
                f"{row['kind']}\t{row['detail']}\n"
            )
        return 0

    if command == "mcp-block":
        if len(rest) < 2:
            stream.write("usage: mcp-block <tenant> <server>\n")
            return 64
        registry.record(
            McpServerIdentity(
                tenant_id=rest[0],
                server_id=rest[1],
                trust=McpServerTrust.BLOCKED,
            )
        )
        stream.write(f"blocked MCP server {rest[1]} for {rest[0]}\n")
        return 0

    if len(rest) < 3:
        stream.write(f"usage: {command} <tenant> <server> <file.json> [endpoint]\n")
        return 64
    tenant, server_id, path = rest[0], rest[1], rest[2]
    endpoint = rest[3] if len(rest) > 3 else ""
    try:
        # Same enrolment, two ingestion formats. An OpenAPI operation and
        # an MCP tool are the same thing from the gateway's point of view --
        # a named operation with server-supplied prose and a schema -- so
        # they share one pinning engine rather than getting a second one
        # that could disagree with the first.
        if command == "openapi-enrol":
            tools = operations_from_spec(load_spec(path))
        else:
            tools = _load_tool_definitions(path)
    except OpenApiRefused as exc:
        stream.write(f"cannot read OpenAPI spec: {exc}\n")
        return 66  # EX_NOINPUT
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        stream.write(f"cannot read tool definitions: {exc}\n")
        return 66  # EX_NOINPUT

    # The gateway rather than the registry directly, so `enrol` refuses to
    # launder a BLOCKED server back into ENROLLED without someone deciding to
    # unblock it first. `ProtectGate` is constructed only to satisfy the
    # gateway's constructor; enrolment never evaluates content.
    gateway = McpGateway(
        protect=ProtectGate(policy=DeterministicPolicy.default(), enforce=False),
        pins=registry,
        servers=registry,
    )
    existing = registry.lookup(tenant, server_id)
    try:
        gateway.enrol(
            McpServerIdentity(
                tenant_id=tenant,
                server_id=server_id,
                endpoint=endpoint or (existing.endpoint if existing else ""),
                trust=existing.trust if existing else McpServerTrust.UNKNOWN,
            ),
            tools,
        )
    except McpCallRefused as exc:
        stream.write(f"{exc}\n")
        return 1
    stream.write(
        f"enrolled MCP server {server_id} for {tenant} "
        f"with {len(tools)} pinned tool definition(s)\n"
    )
    for tool in tools:
        stream.write(f"  {tool.name}\t{tool.fingerprint[:16]}\n")
    return 0


def discover_mcp_server(
    *,
    tenant: str,
    server_id: str,
    endpoint: str,
    out_path: str,
    registry: Any,
    settings: Any,
    stream: TextIO,
    client: Any = None,
) -> int:
    """Contact a candidate MCP server, record what it serves, enrol NOTHING.

    WHY DISCOVERY IS SEPARATE FROM ENROLMENT
    ----------------------------------------
    `mcp-enrol` takes a tools file because enrolment is the moment an operator
    says "these are the tools I reviewed". Fetching the listing at enrolment
    time would collapse that into "approve whatever the server happens to
    serve, unread", which is the whole point of pinning thrown away for a
    saved keystroke.

    So discovery does the fetching and stops. It writes the file `mcp-enrol`
    accepts, leaves the server at OBSERVED — evaluated, never dialled by the
    proxy — and makes the operator run the second command. The review step
    stays; only the hand-authoring of JSON goes away.

    THIS COMMAND DIALS A URL FROM ARGV, AND THAT IS NOT THE PROXY'S RULE
    -------------------------------------------------------------------
    The proxy refuses to take an endpoint from a request precisely because a
    request is untrusted. An argv here is an operator at a shell on the host,
    which `sentinel/domain/authorization.py` already records as the trust
    anchor for enrolment. The egress policy still applies: the same
    `HardenedHttpClient` settings the proxy runs under, so discovery cannot
    reach anywhere the proxy could not.
    """
    from sentinel.domain.mcp import McpServerIdentity, McpServerTrust

    from sentinel.infrastructure.mcp_wire import (
        MCP_PROTOCOL_VERSION,
        McpUpstreamClient,
    )
    from sentinel.infrastructure.outbound import (
        HardenedHttpClient,
        OutboundPolicy,
        OutboundRefused,
        OutboundUnavailable,
    )

    # Injectable like every other collaborator in this codebase, so the tests
    # drive the logic without opening a socket. The default is the same
    # hardened client the proxy runs under -- discovery cannot reach anywhere
    # the proxy could not.
    if client is None:
        client = McpUpstreamClient(
            client=HardenedHttpClient(
                policy=OutboundPolicy(
                    allowed_hosts=getattr(
                        settings, "mcp_proxy_allowed_hosts", frozenset()
                    ),
                    allow_private_destinations=getattr(
                        settings, "mcp_proxy_allow_private", False
                    ),
                )
            )
        )

    try:
        hello = client.forward(
            endpoint=endpoint,
            message={
                "jsonrpc": "2.0",
                "id": "sentinel-discover-init",
                "method": "initialize",
                "params": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "sentinel-discover", "version": "1"},
                },
            },
        )
        if hello.status in (401, 403):
            # Reported, not worked around. A server that requires authorization
            # needs a credential the operator supplies to their client; this
            # command does not hold one and will not invent one.
            stream.write(
                f"{endpoint} requires authorization (HTTP {hello.status}). "
                "Discovery holds no upstream credential; enrol it by hand once "
                "you can list its tools with an authorized client.\n"
            )
            return 75
        listing = client.forward(
            endpoint=endpoint,
            message={
                "jsonrpc": "2.0",
                "id": "sentinel-discover-list",
                "method": "tools/list",
            },
            session_id=hello.session_id,
        )
    except OutboundRefused as exc:
        stream.write(f"refused by egress policy: {exc}\n")
        return 77
    except (OutboundUnavailable, Exception) as exc:  # noqa: BLE001 - reported, not swallowed
        stream.write(f"{endpoint} could not be reached or did not speak MCP: {exc}\n")
        return 75

    identity = ""
    if isinstance(hello.message, dict):
        info = (hello.message.get("result") or {}).get("serverInfo") or {}
        name = str(info.get("name") or "").strip()
        version = str(info.get("version") or "").strip()
        identity = f"{name}/{version}" if name and version else name

    raw_tools = []
    if isinstance(listing.message, dict):
        result = listing.message.get("result") or {}
        if isinstance(result, dict) and isinstance(result.get("tools"), list):
            raw_tools = [
            entry for entry in result["tools"] if isinstance(entry, dict)
        ]
    if not raw_tools:
        stream.write(f"{endpoint} listed no tools; nothing to review.\n")
        return 75

    definitions = []
    for entry in raw_tools:
        try:
            definitions.append(
                McpToolDefinition(
                    name=str(entry.get("name") or ""),
                    description=str(entry.get("description") or ""),
                    input_schema=dict(entry.get("inputSchema") or {}),
                )
            )
        except (ValueError, TypeError):
            continue

    # OBSERVED, never ENROLLED. The proxy refuses OBSERVED, so discovering a
    # server grants it nothing -- it only means Sentinel now has a record of
    # having seen it, which is what makes a later enrolment a decision about
    # something known rather than about a string somebody typed.
    observed_server = McpServerIdentity(
        tenant_id=tenant,
        server_id=server_id,
        endpoint=endpoint,
        trust=McpServerTrust.OBSERVED,
    )
    registry.record(observed_server)
    if identity:
        registry.record_server_info(tenant, server_id, identity)
    registry.observe_tools(observed_server, tuple(definitions))

    document = json.dumps({"tools": raw_tools}, indent=2, sort_keys=True)
    if out_path:
        Path(out_path).write_text(document + "\n", encoding="utf-8")

    stream.write(f"server:  {identity or '(no serverInfo reported)'}\n")
    stream.write(f"endpoint: {endpoint}\n")
    stream.write(f"tools:   {len(definitions)}\n")
    for definition in definitions:
        stream.write(f"  {definition.name}\t{definition.fingerprint[:16]}\n")
    stream.write(
        f"\nrecorded as OBSERVED for {tenant}. The proxy will NOT dial an "
        f"OBSERVED server.\n"
    )
    if out_path:
        stream.write(
            f"wrote {out_path}. Review the descriptions -- they are instructions "
            f"the model reads -- then:\n"
            f"  python -m sentinel.interface.cli mcp-enrol {tenant} {server_id} "
            f"{out_path} {endpoint}\n"
        )
    else:
        stream.write(
            "re-run with an output path to write the file mcp-enrol takes.\n"
        )
    return 0
