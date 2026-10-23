#!/usr/bin/env python3
"""One load-generator WORKER. Runs in its own OS process, drives HTTP over TCP.

WHY THIS IS A SEPARATE PROCESS AND NOT A THREAD
------------------------------------------------
`scripts/profile_ingest.py` drives the app through an in-process
`fastapi.testclient.TestClient` with N Python threads. Its own PostgreSQL run
showed what that costs:

    p95                          995.2 ms
    mean SQL per request         110.8 ms   (22%)
    mean NON-SQL per request     383.5 ms   (78%)
    slowest single statement     SELECT set_config(...)  20.3 ms mean

`set_config` touches no table and returns no rows. A 20 ms mean on it is not
database work; it is six threads queueing for one GIL, and the request handler
was competing with the load generator for the same interpreter. The 995 ms
number is therefore an upper bound on that harness, not a measurement of the
service -- and the 624 ms SQLite figure before it had the identical flaw,
unnoticed because nobody broke it down.

This worker fixes the method rather than the number:

  * the application is a REAL uvicorn server in its own process;
  * each load generator is its own OS process, so N of them have N GILs;
  * requests cross a real TCP socket, so kernel, sockets and HTTP framing are
    in the measurement where production has them too;
  * only the client's own send->receive time is recorded, and it is recorded
    per request rather than aggregated here, so the parent computes percentiles
    over the true global distribution instead of averaging pre-computed ones.

WHAT IT STILL IS NOT
--------------------
One host, loopback TCP, no load balancer, no ingress, no TLS termination, no
second replica. Those remain absent, and the report says so. What changes is
that the generator no longer competes with the server for the same interpreter,
which was the specific confound that made the previous two numbers unusable.

Invoked by `scripts/run_ingest_loadtest.py`; not intended to be run by hand.
Emits one JSON object on stdout so the parent can merge results without a
shared file.
"""

from __future__ import annotations

import argparse
import http.client
import json
import sys
import time


def _payload(n: int, action: str = "read_file") -> dict:
    """Shape-identical to scripts/profile_ingest.py::_payload.

    `action` IS THE VARIABLE THAT DECIDES WHAT IS BEING MEASURED, and that only
    became clear after a run that measured the wrong thing.

    The action and resource determine whether deterministic rules create an
    incident. Compare equivalent verdicts and database row counts when measuring
    policy cost; an incident-write workload measures additional work.
    """
    return {
        "eventId": f"loadgen-{n}",
        "timestamp": "2026-08-13T12:00:00Z",
        "agentId": "0x" + "cd" * 20,
        "eventType": "tool_call",
        "action": action,
        "resource": "README.md",
        "metadata": {},
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--worker", type=int, required=True)
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--start", type=int, required=True)
    parser.add_argument("--action", default="read_file")
    args = parser.parse_args(argv[1:])

    # One keep-alive connection per worker. Opening a socket per request would
    # measure TCP handshake cost, which production clients amortise too.
    conn = http.client.HTTPConnection(args.host, args.port, timeout=120)
    headers = {
        "Authorization": f"Bearer {args.key}",
        "Content-Type": "application/json",
    }

    latencies: list[float] = []
    statuses: dict[str, int] = {}
    errors: list[str] = []

    for i in range(args.count):
        body = json.dumps(_payload(args.start + i, args.action))
        started = time.perf_counter()
        try:
            conn.request("POST", "/v1/events", body=body, headers=headers)
            response = conn.getresponse()
            status = str(response.status)
            response.read()
        except Exception as exc:  # noqa: BLE001 - reported, never silently dropped
            # Reconnect and keep going: a dropped connection is a real event
            # worth counting, not a reason to abandon the measurement.
            errors.append(f"{type(exc).__name__}: {exc}")
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
            conn = http.client.HTTPConnection(args.host, args.port, timeout=120)
            continue
        latencies.append((time.perf_counter() - started) * 1000.0)
        statuses[status] = statuses.get(status, 0) + 1

    conn.close()
    json.dump(
        {
            "worker": args.worker,
            "latencies_ms": latencies,
            "status_counts": statuses,
            "errors": errors[:20],
            "error_count": len(errors),
        },
        sys.stdout,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
