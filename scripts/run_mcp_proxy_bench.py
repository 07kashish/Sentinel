"""Measure the MCP proxy's OWN overhead. Never the upstream's.

WHAT IS MEASURED, AND WHAT THE NUMBER IS NOT
--------------------------------------------
The upstream is a stub that returns instantly, so what this records is the
work Sentinel performs per proxied call: policy evaluation, the pin and
duplicate checks, the provenance write, the audit write, and the HTTP layer
around them. It is NOT end-to-end MCP latency -- a real server's response time
is added on top and dominates in any deployment. Quoting these figures as
"MCP call latency" would be the fake-benchmark failure the specification bans
in section 127; they are the gateway's tax, which is the part Sentinel
controls and the only part it should claim.

Specification section 79 targets p95 < 50 ms and p99 < 100 ms for a decision
that does not depend on an external network service. That is the bar this
measures against.

Two workloads are reported because they cost different amounts:
  * `tools_call` -- the full path with a listing fetch, evaluation, provenance
    and audit. The expensive one.
  * `refused_unknown` -- a call to a server nobody enrolled, which must be
    refused before any network activity. The cheap path, measured to show the
    refusal is cheap: a gate that costs more than the thing it guards is a
    denial-of-service primitive.

Run:  python scripts/run_mcp_proxy_bench.py [--requests 300] [--out reports/mcp_proxy_bench.json]
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from sentinel.composition.container import build_container  # noqa: E402
from sentinel.composition.settings import Settings  # noqa: E402
from sentinel.domain.mcp import McpServerIdentity, McpToolDefinition  # noqa: E402
from sentinel.infrastructure.mcp_wire import McpUpstreamReply  # noqa: E402
from sentinel.infrastructure.sql.engine import build_engine  # noqa: E402
from sentinel.infrastructure.sql.migrate import migrate  # noqa: E402
from sentinel.interface.http import create_app  # noqa: E402

KEY = "bench-ingest-key-that-is-long-enough-for-production"
ENDPOINT = "https://mcp.bench.example/rpc"
TOOL = McpToolDefinition(
    name="search_docs",
    description="Search the internal documentation index.",
    input_schema={"type": "object", "properties": {"q": {"type": "string"}}},
)


class StubUpstream:
    """Returns instantly, so the measured time is Sentinel's, not the network's."""

    def forward(self, *, endpoint, message, session_id="", upstream_authorization=""):
        method = message.get("method", "")
        if method == "tools/list":
            body = {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "result": {
                    "tools": [
                        {
                            "name": TOOL.name,
                            "description": TOOL.description,
                            "inputSchema": dict(TOOL.input_schema),
                        }
                    ]
                },
            }
        else:
            body = {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "result": {"content": [{"type": "text", "text": "ok"}]},
            }
        return McpUpstreamReply(status=200, message=body)


def _percentile(values: list[float], pct: float) -> float:
    """Nearest-rank percentile. No interpolation: a real observed sample."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, int(round(pct / 100.0 * len(ordered))))
    return ordered[min(rank, len(ordered)) - 1]


def _measure(client, *, server: str, requests: int, workers: int) -> dict:
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": TOOL.name, "arguments": {"q": "quarterly report"}},
    }
    headers = {
        "Authorization": f"Bearer {KEY}",
        "X-Sentinel-Agent-Id": "bench-agent",
        "X-Sentinel-Principal": "user:bench@example.com",
        "X-Sentinel-Session-Id": "bench-session",
    }

    def one() -> tuple[float, int]:
        start = time.perf_counter()
        response = client.post(f"/v1/mcp/proxy/{server}", json=body, headers=headers)
        return (time.perf_counter() - start) * 1000.0, response.status_code

    # Warm the process: first-call import and connection costs are real but are
    # not what a steady-state percentile is meant to describe.
    for _ in range(min(20, requests)):
        one()

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda _i: one(), range(requests)))
    wall = time.perf_counter() - started

    latencies = [ms for ms, _status in results]
    errors = sum(1 for _ms, status in results if status >= 500)
    return {
        "requests": requests,
        "concurrency": workers,
        "achieved_rps": round(requests / wall, 1) if wall else 0.0,
        "p50_ms": round(statistics.median(latencies), 2),
        "p95_ms": round(_percentile(latencies, 95), 2),
        "p99_ms": round(_percentile(latencies, 99), 2),
        "max_ms": round(max(latencies), 2),
        "server_errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--requests", type=int, default=300)
    parser.add_argument("--out", default="reports/mcp_proxy_bench.json")
    args = parser.parse_args()

    db = os.path.join(tempfile.mkdtemp(), "bench.db")
    settings = Settings.from_environment(
        {
            "SENTINEL_ENV": "development",
            "SENTINEL_API_KEYS": f"acme:{KEY}:ingest",
            "SENTINEL_DB_PATH": db,
            "SENTINEL_PROTECT_ENFORCE": "true",
            "SENTINEL_RATE_LIMIT_FAIL_OPEN": "true",
            # The limiter would otherwise shape the measurement into a study of
            # the limiter. It is measured elsewhere; this run is about the gate.
            "SENTINEL_ADDRESS_LIMIT_PER_MINUTE": "10000000",
            "SENTINEL_CREDENTIAL_LIMIT_PER_MINUTE": "10000000",
        }
    )
    pool = build_engine(settings.engine)
    migrate(pool)
    with pool.acquire() as conn:
        conn.begin()
        conn.execute_rowcount(
            f"INSERT INTO tenants (tenant_id, name, created_at) "
            f"VALUES ({conn.p},{conn.p},{conn.p})",
            ("acme", "Acme", "2026-08-28T00:00:00+00:00"),
        )
        conn.commit()
    pool.close()

    container = build_container(settings, mcp_upstream=StubUpstream())
    try:
        container.mcp_gateway.enrol(
            McpServerIdentity(
                tenant_id="acme", server_id="bench-mcp", endpoint=ENDPOINT
            ),
            (TOOL,),
        )
        client = TestClient(create_app(container), raise_server_exceptions=False)

        report = {
            "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "what_this_measures": (
                "Sentinel's own per-call overhead with a stub upstream that "
                "returns instantly. NOT end-to-end MCP latency: a real "
                "server's response time is added on top and dominates."
            ),
            "engine": "sqlite",
            "definition_cache_seconds": settings.mcp_proxy_definition_cache_seconds,
            "target": "section 79: p95 < 50 ms, p99 < 100 ms",
            "tools_call": [],
            "refused_unknown_server": [],
        }
        for workers in (1, 4, 8, 16):
            report["tools_call"].append(
                _measure(
                    client, server="bench-mcp", requests=args.requests, workers=workers
                )
            )
        for workers in (1, 8):
            report["refused_unknown_server"].append(
                _measure(
                    client,
                    server="never-enrolled",
                    requests=args.requests,
                    workers=workers,
                )
            )

        worst_p95 = max(row["p95_ms"] for row in report["tools_call"])
        worst_p99 = max(row["p99_ms"] for row in report["tools_call"])
        report["meets_p95_target"] = worst_p95 < 50.0
        report["meets_p99_target"] = worst_p99 < 100.0

        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))
        print(f"\nwrote {args.out}")
    finally:
        container.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
