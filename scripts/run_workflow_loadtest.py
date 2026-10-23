#!/usr/bin/env python3
"""Measure the bound-execution path under concurrency, on PostgreSQL, over HTTP.

WHAT IS MEASURED
----------------
One "change" is the pair every protected action costs: POST
/v1/protect/evaluate (policy decision, authorization issued and stored) and
POST /v1/tools/execute (token resolved, binding verified, nonce consumed,
budget and breaker checked under a row lock, intent written, a no-op tool run,
receipt and outcome written). The tool does nothing, so the number is
Sentinel's own overhead and excludes any target system.

The service runs as a real uvicorn process against a real PostgreSQL, driven
by threads over loopback HTTP. Each worker uses its own agent id so the
per-agent budget does not serialise the run; the tool budget is raised for the
same reason and that is recorded.

WHAT THIS IS NOT
----------------
A capacity claim. One machine runs the client, the service and the database,
so they compete for the same cores; there is no network, no TLS, one service
process and no replica contention beyond a single pool. It is a regression
instrument and a first-order estimate, and the report says so. Never quote a
figure from it without its environment block.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import secrets
import socket
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _post(base: str, path: str, key: str, body: dict) -> tuple[int, dict]:
    request = urllib.request.Request(base + path, data=json.dumps(body).encode(), method="POST",
                                     headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - loopback
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        return exc.code, {}


def _pct(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return round(ordered[max(0, int(len(ordered) * fraction) - 1)] * 1000, 2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dsn", required=True, help="PostgreSQL DSN of an EMPTY database the run may migrate")
    parser.add_argument("--changes", type=int, default=2000)
    parser.add_argument("--concurrency", type=int, default=16)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)

    key = "loadtest-" + secrets.token_hex(20)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    env = {**os.environ, "PYTHONPATH": str(ROOT), "SENTINEL_ENV": "development", "SENTINEL_DATABASE_URL": args.dsn,
           "SENTINEL_API_KEYS": f"acme:{key}:ingest", "SENTINEL_CORS_ORIGINS": "https://console.local.invalid",
           "SENTINEL_PROTECT_ENFORCE": "true",
           "SENTINEL_TOOL_BUDGET_PER_MINUTE": "1000000", "SENTINEL_CREDENTIAL_LIMIT": "10000000",
           "SENTINEL_ADDRESS_LIMIT": "10000000"}
    subprocess.run([sys.executable, "-m", "sentinel.interface.cli", "migrate"], env=env, check=True, capture_output=True)
    server = subprocess.Popen([sys.executable, "-c", (
        "import uvicorn\n"
        "from sentinel.application.tool_proxy import RegisteredSideEffect\n"
        "from sentinel.composition.container import build_container\n"
        "from sentinel.composition.settings import Settings, read_environment\n"
        "from sentinel.interface.http import create_app\n"
        "container = build_container(Settings.from_environment(read_environment()))\n"
        "container.tool_proxy.register(RegisteredSideEffect(name='noop', runner=lambda a: {'ok': True}))\n"
        f"uvicorn.run(create_app(container), host='127.0.0.1', port={port}, log_level='error')\n")],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    base = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 60
        while True:
            try:
                urllib.request.urlopen(base + "/health/ready", timeout=2).close()  # noqa: S310
                break
            except (urllib.error.URLError, OSError):
                if server.poll() is not None or time.monotonic() > deadline:
                    print("the service did not start: " + (server.stderr.read().decode()[-600:] if server.stderr else ""), file=sys.stderr)
                    return 2
                time.sleep(0.3)

        per_worker = args.changes // args.concurrency
        evaluate, execute, failures = [], [], []
        lock = threading.Lock()

        def worker(index: int) -> None:
            ev, ex, bad = [], [], 0
            for n in range(per_worker):
                body = {"agentId": f"load-agent-{index}", "tool": "noop", "action": "noop",
                        "resource": f"load/{index}/{n}", "arguments": {"n": n}}
                t0 = time.perf_counter()
                code, reply = _post(base, "/v1/protect/evaluate", key, body)
                t1 = time.perf_counter()
                token = (reply.get("authorization") or {}).get("token")
                if code != 200 or not token:
                    bad += 1
                    continue
                code, _ = _post(base, "/v1/tools/execute", key, dict(body, authorization=token))
                t2 = time.perf_counter()
                if code != 200:
                    bad += 1
                    continue
                ev.append(t1 - t0)
                ex.append(t2 - t1)
            with lock:
                evaluate.extend(ev)
                execute.extend(ex)
                failures.append(bad)

        started = time.perf_counter()
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(args.concurrency)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        elapsed = time.perf_counter() - started
    finally:
        server.terminate()
        server.wait(timeout=15)

    completed = len(execute)
    report = {
        "schema": "sentinel.workflow-loadtest/v1",
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "commit": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip(),  # noqa: S603,S607
        "workload": {"changes_requested": per_worker * args.concurrency, "concurrency": args.concurrency,
                     "tool": "no-op (Sentinel overhead only)", "per_change": "evaluate + bound execute"},
        "result": {"completed": completed, "failed": sum(failures), "seconds": round(elapsed, 2),
                   "changes_per_second": round(completed / elapsed, 1) if elapsed else None,
                   "evaluate_ms": {"p50": _pct(evaluate, 0.5), "p95": _pct(evaluate, 0.95), "p99": _pct(evaluate, 0.99)} if evaluate else None,
                   "execute_ms": {"p50": _pct(execute, 0.5), "p95": _pct(execute, 0.95), "p99": _pct(execute, 0.99)} if execute else None,
                   "mean_change_ms": round((statistics.mean(evaluate) + statistics.mean(execute)) * 1000, 2) if execute else None},
        "environment": {"platform": platform.platform(), "machine": platform.machine(), "python": platform.python_version(),
                        "cpu_count": os.cpu_count(), "database": "PostgreSQL on the same host",
                        "service": "one uvicorn process, one event loop", "transport": "loopback HTTP, no TLS"},
        "limitations": ["client, service and database share one machine and its cores", "no network latency and no TLS",
                        "one service process; replica contention is not exercised", "a no-op tool; target latency excluded",
                        "rate limits and the per-agent tool budget were raised so they do not shape the result",
                        "not a capacity or sizing claim"],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report["result"], indent=2))
    return 0 if completed and not sum(failures) else 1


if __name__ == "__main__":
    raise SystemExit(main())
