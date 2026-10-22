#!/usr/bin/env python3
"""Ingest p95 measured WITHOUT the in-process harness confound.

THE PROBLEM WITH THE TWO NUMBERS THIS REPLACES
------------------------------------------------
`docs/PRODUCTION_READINESS_REPORT.md` has carried an ingest p95 gate row twice,
and both figures came from `scripts/profile_ingest.py`, which drives the app
through an in-process `TestClient` with N Python THREADS:

    624 ms   SQLite,     6 writers, 55k rows
    995 ms   PostgreSQL, 6 writers, 55,200 rows

The PostgreSQL run's own breakdown is what disqualifies both:

    mean SQL per request       110.8 ms   (22%)
    mean NON-SQL per request   383.5 ms   (78%)
    slowest statement          SELECT set_config(...)  20.3 ms mean, 78.6 ms p95

`set_config` touches no table and returns no rows. Twenty milliseconds of mean
latency on it is not database cost; it is six threads contending for one GIL,
with the load generator competing against the request handler inside the same
interpreter. Neither number measures the service. The SQLite figure had the
identical flaw and nobody noticed, because it was never broken down.

WHAT THIS DOES INSTEAD
----------------------
  1. Starts a REAL uvicorn server in its own OS process, against a real
     PostgreSQL 16 database, migrated first.
  2. Seeds the database to the target row count.
  3. Runs N load generators as N SEPARATE OS PROCESSES
     (`scripts/loadgen_client.py`), each with its own GIL and its own
     keep-alive TCP connection.
  4. Merges the per-request latencies from every worker and computes
     percentiles over the TRUE global distribution -- not an average of
     per-worker percentiles, which is a different and wrong number.

WHAT IT STILL IS NOT, STATED SO THE ROW CANNOT BE OVER-READ
-------------------------------------------------------------
One host. Loopback TCP. No load balancer, no ingress, no TLS termination, no
second replica, no competing tenants. All are real sources of production latency
this cannot see. What it removes is one specific, MEASURED confound: the
generator no longer shares an interpreter with the server.

Usage:
  PYTHONPATH=. python scripts/run_ingest_loadtest.py --workers 6 --events 55000
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))

OUT = ROOT / "reports" / "ingest_loadtest_postgres.json"
TARGET_P95_MS = 500.0
KEY = "k" * 40
TENANT = "acme"


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round(pct * (len(ordered) - 1)))))
    return ordered[idx]


def _free_port() -> int:
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_for_health(port: int, deadline_s: float = 180.0) -> bool:
    import http.client

    deadline = time.time() + deadline_s
    while time.time() < deadline:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            conn.request("GET", "/health/live")
            ok = conn.getresponse().status == 200
            conn.close()
            if ok:
                return True
        except Exception:  # noqa: BLE001 - server not up yet
            pass
        time.sleep(0.5)
    return False


def _unverified(reason: str) -> int:
    payload = {
        "ok": False,
        "status": "UNVERIFIED",
        "precondition": reason,
        "note": (
            "No number recorded. An ingest gate row must not be filled with a "
            "measurement the harness could not actually take."
        ),
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 2


def main() -> int:  # noqa: PLR0915 - a measurement is a linear script
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--events", type=int, default=55000)
    parser.add_argument(
        "--measure",
        type=int,
        default=1200,
        help="requests to MEASURE at the final row count, split across workers",
    )
    parser.add_argument(
        "--action",
        default="read_file",
        help=(
            "the tool-call action sent in every event. DECIDES WHAT IS MEASURED: "
            "the default 'read_file' scores 0.5409 and FIRES the detector, so "
            "every request creates an incident. Use a benign action such as "
            "'list_dir' (0.3502) to measure classifier cost without the "
            "incident-write path underneath it."
        ),
    )
    parser.add_argument(
        "--server-workers",
        type=int,
        default=1,
        help=(
            "application server processes. DEFAULT 1, which is what a single "
            "uvicorn gives -- but the shipped Dockerfile runs `gunicorn "
            "--workers 4`, so 1 UNDER-REPRESENTS production for any workload "
            "whose cost is GIL-held. Use 4 to measure the shipped process model."
        ),
    )
    parser.add_argument(
        "--no-soft-detect",
        action="store_true",
        help=(
            "disable the soft-prompt classifier. OFF BY DEFAULT: the shipped "
            "configuration has it on, and profile_ingest.py (which produced the "
            "995 ms figure this is compared against) leaves it on too. Use this "
            "only to isolate the detector's own cost."
        ),
    )
    args = parser.parse_args()

    from _embedded_postgres import PostgresUnavailableHere, start_embedded_postgres

    try:
        server = start_embedded_postgres()
    except PostgresUnavailableHere as exc:
        return _unverified(f"no PostgreSQL: {exc}")

    dsn = server.fresh_database("loadtest")
    port = _free_port()
    started_all = time.perf_counter()
    proc = None

    try:
        env = {
            "SENTINEL_ENV": "development",
            "SENTINEL_API_KEYS": f"{TENANT}:{KEY}:ingest",
            "SENTINEL_DATABASE_URL": dsn,
            "SENTINEL_DB_POOL_MIN": "4",
            "SENTINEL_DB_POOL_MAX": "20",
            # The edge limiter is PER SOURCE ADDRESS and every request here comes
            # from one, so the shipped default would throttle the generator
            # rather than measure the service.
            "SENTINEL_ADDRESS_LIMIT": "5000000",
            "SENTINEL_CREDENTIAL_LIMIT": "5000000",
        }
        # THE SOFT-PROMPT DETECTOR IS ON BY DEFAULT HERE, DELIBERATELY.
        #
        # The first run of this script disabled it, and that was a confound of
        # exactly the kind this script exists to remove. `profile_ingest.py`,
        # which produced the 995 ms figure being compared against, does NOT
        # disable it -- so a run with it off would have attributed the
        # detector's cost to the harness change and overstated the improvement.
        # Caught by reading profile_ingest.py's environment rather than assuming
        # it matched.
        #
        # On is also the SHIPPED default (`SENTINEL_SOFT_PROMPT_DETECT` defaults
        # to true), so this measures the configuration a deployment actually
        # runs. `--no-soft-detect` exists to isolate the detector's own cost.
        if args.no_soft_detect:
            env["SENTINEL_SOFT_PROMPT_DETECT"] = "false"
        child_env = {**os.environ, **env, "PYTHONPATH": str(ROOT)}

        print("migrating ...", flush=True)
        migrate = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [sys.executable, "-m", "sentinel.interface.cli", "migrate"],
            env=child_env, capture_output=True, text=True, cwd=str(ROOT), check=False,
        )
        if migrate.returncode != 0:
            return _unverified(f"migrate failed: {migrate.stderr[-500:]}")

        print(f"starting uvicorn on :{port} (separate process) ...", flush=True)
        if args.server_workers > 1:
            # `uvicorn --workers N` forks N independent processes behind one
            # socket, which is the same process model `gunicorn --workers 4`
            # gives the shipped image. It matters here because the cost under
            # test holds the GIL: one process serialises it, four do not.
            command = [
                sys.executable, "-m", "uvicorn",
                "sentinel.interface.asgi:create_application",
                "--factory", "--host", "127.0.0.1", "--port", str(port),
                "--workers", str(args.server_workers), "--log-level", "warning",
            ]
        else:
            command = [
                sys.executable, "-m", "uvicorn",
                "sentinel.interface.asgi:create_application",
                "--factory", "--host", "127.0.0.1", "--port", str(port),
                "--log-level", "warning",
            ]
        proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            command,
            env=child_env, cwd=str(ROOT),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if not _wait_for_health(port):
            return _unverified(f"server never became healthy on port {port}")
        print("server healthy", flush=True)

        def _run_workers(total: int, start_at: int, label: str) -> dict:
            """Fan `total` requests across `--workers` separate PROCESSES."""
            per = total // args.workers
            procs = []
            for w in range(args.workers):
                offset = start_at + w * per
                procs.append(
                    subprocess.Popen(  # noqa: S603 - fixed argv, no shell
                        [
                            sys.executable,
                            str(ROOT / "scripts" / "loadgen_client.py"),
                            "--port", str(port), "--key", KEY,
                            "--worker", str(w), "--count", str(per),
                            "--start", str(offset), "--action", args.action,
                        ],
                        env=child_env, cwd=str(ROOT),
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    )
                )
            began = time.perf_counter()
            merged: list[float] = []
            statuses: dict[str, int] = {}
            errors = 0
            for p in procs:
                out, err = p.communicate()
                if p.returncode != 0 or not out.strip():
                    raise RuntimeError(
                        f"load worker failed rc={p.returncode}: {err[-300:]}"
                    )
                data = json.loads(out)
                merged.extend(data["latencies_ms"])
                for code, n in data["status_counts"].items():
                    statuses[code] = statuses.get(code, 0) + n
                errors += data["error_count"]
            elapsed = time.perf_counter() - began
            rate = len(merged) / elapsed if elapsed else 0.0
            print(
                f"  {label}: {len(merged)} requests in {elapsed:.1f}s ({rate:.1f}/s)",
                flush=True,
            )
            return {
                "requests": len(merged),
                "elapsed_seconds": round(elapsed, 3),
                "throughput_rps": round(rate, 2),
                "status_counts": statuses,
                "transport_errors": errors,
                "latencies": merged,
            }

        print(f"seeding to {args.events} rows ...", flush=True)
        seed = _run_workers(args.events, 0, "seed")

        print(f"measuring {args.measure} requests at {args.events} rows ...", flush=True)
        measured = _run_workers(args.measure, args.events, "measure")

        lat = measured["latencies"]
        p95 = _percentile(lat, 0.95)
        try:
            import psycopg

            with psycopg.connect(dsn, autocommit=True) as conn:
                # SET THE TENANT FIRST. `incidents` is under FORCE ROW LEVEL
                # SECURITY and this DSN uses the non-superuser app role, so an
                # unscoped count returns 0 -- not an error, just a confident
                # zero.
                #
                # The first version of this line omitted it and duly reported
                # `rows_in_incidents_after: 0` for a run that had just written
                # 54,996 rows. That is the identical defect as the retention
                # sweep, written by the same hand in the same session that
                # documented it four times. It is left recorded here rather than
                # quietly fixed, because "I know about this class" is evidently
                # not the same as "I will not write it again".
                conn.execute(
                    "SELECT set_config('sentinel.tenant_id', %s, false)", (TENANT,)
                )
                # A CENSUS, NOT ONE TABLE.
                #
                # "p95 at 55k rows" is meaningless without saying WHICH rows. A
                # firing action writes an incident per event -- incidents,
                # transitions, domain_events, work_queue, outbox all grow
                # together. A benign action writes NONE of them, so a run seeded
                # with 55,000 benign events leaves `incidents` empty and the
                # latency is being measured against a nearly-empty database.
                #
                # Comparing those two as though both were "55k rows" would be a
                # category error, and the first version of this script invited
                # it by reporting a single count.
                census = {}
                for table in (
                    "incidents", "incident_transitions", "domain_events",
                    "work_queue", "outbox", "evidence", "ledger_entries",
                ):
                    try:
                        census[table] = conn.execute(
                            f"SELECT count(*) FROM {table}"  # noqa: S608 - fixed names
                        ).fetchone()[0]
                    except Exception as exc:  # noqa: BLE001
                        census[table] = f"unavailable: {exc}"
                row_count = census
        except Exception as exc:  # noqa: BLE001
            row_count = f"unavailable: {exc}"

        payload = {
            "ok": bool(p95 <= TARGET_P95_MS),
            "status": "measured_out_of_process_load",
            "target_p95_ms": TARGET_P95_MS,
            "methodology": {
                "load_generator": (
                    f"{args.workers} SEPARATE OS PROCESSES "
                    "(scripts/loadgen_client.py), one keep-alive TCP connection each"
                ),
                "application": (
                    f"real uvicorn server, {args.server_workers} worker "
                    "process(es), in its own OS process tree"
                ),
                "soft_prompt_detector": (
                    "disabled" if args.no_soft_detect else "ENABLED (shipped default, matching profile_ingest.py)"
                ),
                "transport": "HTTP over loopback TCP",
                "action_sent": args.action,
                "detector_fires_on_this_action": args.action in {
                    "read_file", "get_status", "fetch_metrics",
                    "http_get", "db_query", "retrieve record",
                },
                "database": (
                    f"PostgreSQL {server.version.split(',')[0]}, non-superuser role "
                    "so FORCE row-level security is enforced"
                ),
                "percentiles": (
                    "computed over the merged per-request latencies from every "
                    "worker, not averaged from per-worker percentiles"
                ),
                "why_this_differs": (
                    "The 624 ms SQLite and 995 ms PostgreSQL figures came from an "
                    "in-process TestClient driven by N THREADS. That run's own "
                    "breakdown showed only 22% of latency inside the database and a "
                    "20.3 ms mean on SELECT set_config(), a statement that touches "
                    "no table and returns no rows -- i.e. it was measuring GIL "
                    "contention between the generator and the handler. Separate "
                    "processes remove that specific confound."
                ),
                "still_not_measured": [
                    "one host, loopback TCP: no network latency, no load balancer, "
                    "no ingress, no TLS termination",
                    "a single application replica",
                    "no competing tenants and no background workload",
                ],
            },
            "workload": {
                "workers": args.workers,
                "rows_seeded": args.events,
                "table_census_after": row_count,
                "census_note": (
                    "What actually grew. A benign action creates no incident, so "
                    "a benign-seeded run leaves incidents/transitions/domain_events "
                    "empty and measures latency against a near-empty database. A "
                    "firing action writes all of them per event. These are not the "
                    "same workload and must not be compared as though they were."
                ),
                "measured_requests": measured["requests"],
                "seed_phase": {k: v for k, v in seed.items() if k != "latencies"},
            },
            "measured": {
                "p50_ms": round(_percentile(lat, 0.50), 3),
                "p95_ms": round(p95, 3),
                "p99_ms": round(_percentile(lat, 0.99), 3),
                "max_ms": round(max(lat), 3) if lat else 0.0,
                "mean_ms": round(statistics.mean(lat), 3) if lat else 0.0,
                "throughput_rps": measured["throughput_rps"],
                "status_counts": measured["status_counts"],
                "transport_errors": measured["transport_errors"],
            },
            "meets_target": bool(p95 <= TARGET_P95_MS),
            "total_seconds": round(time.perf_counter() - started_all, 2),
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(json.dumps(payload["measured"], indent=2))
        print(f"meets <{TARGET_P95_MS}ms target: {payload['meets_target']}")
        return 0
    except Exception as exc:  # noqa: BLE001 - a failed run reports, never invents
        return _unverified(f"{type(exc).__name__}: {exc}")
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proc.kill()
        server.close()


if __name__ == "__main__":
    raise SystemExit(main())
