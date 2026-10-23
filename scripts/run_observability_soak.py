#!/usr/bin/env python3
"""Sustained soak that measures the SLIs `docs/OPERATIONS.md` names.

WHAT THIS IS, AND MORE IMPORTANTLY WHAT IT IS NOT
--------------------------------------------------
`docs/OPERATIONS.md` states an API availability SLO of 99.9% over 30 days and
an ingest p95 under 500 ms. Neither had a measurement behind it; the only
evidence was `tests_arch/test_multi_tenant_soak.py`, which issues 80 requests and
takes under a second. Eighty requests cannot distinguish 99.9% from 97%.

This script runs the same surfaces continuously for a configured duration and
reports what it actually observes. It is honest about its own limits:

  * It drives the app through an in-process `TestClient`. There is no network,
    no load balancer, no ingress, no kube-proxy, no second replica and no
    rolling deploy. Every one of those is a real source of production
    unavailability that this cannot see, so the number here is an **upper
    bound** on production availability, not an estimate of it.
  * An hour is not thirty days. A one-hour run cannot observe a 30-day SLO; at
    99.9% the expected budget over an hour is ~3.6 seconds of downtime, so a
    clean hour is consistent with 99.9% but does not demonstrate it. It rules
    out gross unavailability, which is all a short run can do.
  * The engine is whichever one you ask for. `--postgres` runs against a real
    PostgreSQL 16 server as a non-superuser (so row-level security is enforced
    and its predicate is part of the cost); without it the run is SQLite, which
    is not what production uses. Every report records which, in `backend`.

Results are rewritten every `--report-interval` seconds, so a run stopped early
still leaves a truthful record of the window it actually covered.

Usage:
  PYTHONPATH=. python scripts/run_observability_soak.py --seconds 3600
  PYTHONPATH=. python scripts/run_observability_soak.py --postgres --seconds 600
"""

from __future__ import annotations

import argparse
import json
import logging
import statistics
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
OUT = ROOT / "docs" / "observability_soak.json"
#: `--postgres` writes here. Kept apart so a PostgreSQL run cannot overwrite the
#: SQLite record that the existing gate rows cite, and so the two engines'
#: numbers are never confused for each other.
POSTGRES_OUT = ROOT / "docs" / "observability_soak_postgres.json"

AVAILABILITY_SLO = 0.999
INGEST_P95_TARGET_MS = 500.0


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round(pct * (len(ordered) - 1)))))
    return ordered[idx]


class Tally:
    """Latencies and outcomes per surface, under one lock."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.latencies: dict[str, list[float]] = {"ingest": [], "ready": []}
        self.attempts: dict[str, int] = {"ingest": 0, "ready": 0}
        self.failures: dict[str, int] = {"ingest": 0, "ready": 0}
        #: 429 is counted apart from both success and failure. A rejected request
        #: is the limiter doing its job, not the service being unavailable, and
        #: folding the two together would let a correctly-throttling deployment
        #: look like an outage -- or hide a real one behind "it was just throttling".
        self.throttled: dict[str, int] = {"ingest": 0, "ready": 0}
        self.status_counts: dict[str, dict[str, int]] = {"ingest": {}, "ready": {}}

    def record(self, surface: str, status: object, elapsed_ms: float, ok: bool) -> None:
        with self._lock:
            self.attempts[surface] += 1
            self.latencies[surface].append(elapsed_ms)
            key = str(status)
            self.status_counts[surface][key] = self.status_counts[surface].get(key, 0) + 1
            if key == "429":
                self.throttled[surface] += 1
            elif not ok:
                self.failures[surface] += 1

    def snapshot(self) -> dict:
        with self._lock:
            out = {}
            for surface in self.attempts:
                attempts = self.attempts[surface]
                failures = self.failures[surface]
                throttled = self.throttled[surface]
                served = attempts - throttled
                lat = list(self.latencies[surface])
                out[surface] = {
                    "attempts": attempts,
                    "failures": failures,
                    "throttled_429": throttled,
                    # Availability of the service to requests it agreed to serve.
                    "success_ratio": (served - failures) / served if served else 0.0,
                    "success_ratio_including_throttled": (
                        (attempts - failures - throttled) / attempts if attempts else 0.0
                    ),
                    "p50_ms": round(_percentile(lat, 0.50), 3),
                    "p95_ms": round(_percentile(lat, 0.95), 3),
                    "p99_ms": round(_percentile(lat, 0.99), 3),
                    "max_ms": round(max(lat), 3) if lat else 0.0,
                    "mean_ms": round(statistics.mean(lat), 3) if lat else 0.0,
                    "status_counts": dict(self.status_counts[surface]),
                }
            return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=int, default=3600)
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--report-interval", type=int, default=60)
    parser.add_argument(
        "--rps",
        type=float,
        default=40.0,
        help="target ingest requests/sec across all workers",
    )
    parser.add_argument(
        "--production-shaped",
        action="store_true",
        help=(
            "also run WorkerPool and MaintenanceLoop, as a real deployment does. "
            "Without this the queue never drains and no retention sweep runs, "
            "which is how the original 624ms measurement was taken."
        ),
    )
    parser.add_argument("--retention-days", type=int, default=90)
    parser.add_argument("--retention-interval", type=int, default=60)
    parser.add_argument(
        "--address-limit",
        type=int,
        default=600_000,
        help=(
            "SENTINEL_ADDRESS_LIMIT for the run. Raised on purpose: the edge "
            "limiter is PER SOURCE ADDRESS, and every request here comes from one "
            "address, so the shipped default of 120/min throttles the load "
            "generator rather than measuring the service. See the throttling note."
        ),
    )
    parser.add_argument(
        "--postgres",
        action="store_true",
        help=(
            "run against a real PostgreSQL 16 server instead of SQLite. The "
            "'Ingest p95, 6 concurrent writers' gate row is about production, "
            "and production is PostgreSQL."
        ),
    )
    parser.add_argument(
        "--incident-retention-days",
        type=int,
        default=None,
        help=(
            "SENTINEL_INCIDENT_RETENTION_DAYS. Unset by default, matching the "
            "shipped configuration: incident history is never deleted unless an "
            "operator has chosen a window."
        ),
    )
    args = parser.parse_args()
    out = POSTGRES_OUT if args.postgres else OUT

    from fastapi.testclient import TestClient

    from sentinel.composition.container import build_container
    from sentinel.composition.settings import Settings
    from sentinel.infrastructure.sql.engine import build_engine
    from sentinel.infrastructure.sql.migrate import migrate
    from sentinel.interface.http import create_app

    tmp = Path(tempfile.mkdtemp(prefix="sentinel_soak_"))
    key_a, key_b = "a" * 40, "b" * 40
    env = {
        "SENTINEL_ENV": "development",
        "SENTINEL_API_KEYS": f"tenant-a:{key_a}:ingest,tenant-b:{key_b}:ingest",
        "SENTINEL_ADDRESS_LIMIT": str(args.address_limit),
        "SENTINEL_CREDENTIAL_LIMIT": str(args.address_limit),
        "SENTINEL_RETENTION_DAYS": str(args.retention_days),
        "SENTINEL_RETENTION_INTERVAL": str(args.retention_interval),
    }
    if args.incident_retention_days is not None:
        env["SENTINEL_INCIDENT_RETENTION_DAYS"] = str(args.incident_retention_days)

    server = None
    if args.postgres:
        from _embedded_postgres import PostgresUnavailableHere, start_embedded_postgres

        try:
            server = start_embedded_postgres()
        except PostgresUnavailableHere as exc:
            payload = {
                "ok": False,
                "status": "UNVERIFIED",
                "backend": {"engine": "postgres"},
                "precondition": str(exc),
                "note": (
                    "No number recorded. A PostgreSQL gate row must not be filled "
                    "with a SQLite measurement."
                ),
                "recorded_at": datetime.now(timezone.utc).isoformat(),
            }
            out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            print(json.dumps(payload, indent=2))
            return 2
        env["SENTINEL_DATABASE_URL"] = server.fresh_database("soak")
        env["SENTINEL_DB_POOL_MIN"] = "2"
        env["SENTINEL_DB_POOL_MAX"] = "20"
        backend = {
            "engine": "postgres",
            "server_version": server.version,
            "connected_as": "sentinel_app (NOSUPERUSER, so FORCE RLS applies)",
            "provenance": (
                "pgserver-embedded PostgreSQL 16 binaries over a real TCP socket. "
                "Docker is absent here, so the postgres:16 CONTAINER IMAGE was "
                "not used."
            ),
            "pool_max": 20,
        }
    else:
        env["SENTINEL_DB_PATH"] = str(tmp / "soak.db")
        backend = {"engine": "sqlite", "path": str(tmp / "soak.db"), "pool_max": 4}

    settings = Settings.from_environment(env)
    pool = build_engine(settings.engine)
    migrate(pool)
    pool.close()
    container = build_container(settings)
    # After build_container: `StructuredLogger.__init__` resets the level, so
    # raising it earlier is silently undone. At soak rates the per-incident log
    # line is the dominant cost of the harness rather than of the service.
    logging.getLogger("sentinel").setLevel(logging.CRITICAL)
    client = TestClient(create_app(container), raise_server_exceptions=False)

    workers = maintenance = None
    if args.production_shaped:
        from sentinel.domain.primitives import TenantId
        from sentinel.interface.worker import MaintenanceLoop, WorkerPool

        workers = WorkerPool(container, size=2)
        workers.start()
        maintenance = MaintenanceLoop(
            container,
            tenants=lambda: [TenantId("tenant-a"), TenantId("tenant-b")],
            interval_seconds=30,
        )
        maintenance.start()

    tally = Tally()
    stop = threading.Event()
    started_wall = datetime.now(timezone.utc)
    started = time.perf_counter()
    detection_modes: set[str] = set()

    interval = args.workers / args.rps if args.rps > 0 else 0.0

    def _ingest(worker: int) -> None:
        n = 0
        while not stop.is_set():
            n += 1
            cycle_started = time.perf_counter()
            payload = {
                "eventId": f"soak-{worker}-{n}",
                "timestamp": "2026-08-12T12:00:00Z",
                "agentId": "0x" + "cd" * 20,
                "eventType": "tool_call",
                "action": "read_file",
                "resource": "README.md",
                "metadata": {},
            }
            key = key_a if worker % 2 == 0 else key_b
            t0 = time.perf_counter()
            try:
                res = client.post(
                    "/v1/events", json=payload, headers={"Authorization": f"Bearer {key}"}
                )
                ms = (time.perf_counter() - t0) * 1000.0
                tally.record("ingest", res.status_code, ms, res.status_code in (200, 201, 202))
            except Exception as exc:  # noqa: BLE001 - an exception IS the failure
                ms = (time.perf_counter() - t0) * 1000.0
                tally.record("ingest", type(exc).__name__, ms, False)
            # Paced, not flat-out. An unpaced generator measures how fast one
            # laptop can saturate SQLite, which is not an availability SLI.
            slack = interval - (time.perf_counter() - cycle_started)
            if slack > 0:
                stop.wait(slack)

    def _ready() -> None:
        while not stop.is_set():
            t0 = time.perf_counter()
            try:
                res = client.get("/health/ready")
                ms = (time.perf_counter() - t0) * 1000.0
                ok = res.status_code == 200
                tally.record("ready", res.status_code, ms, ok)
                if ok:
                    mode = res.json().get("detection_mode")
                    if mode:
                        detection_modes.add(str(mode))
            except Exception as exc:  # noqa: BLE001
                ms = (time.perf_counter() - t0) * 1000.0
                tally.record("ready", type(exc).__name__, ms, False)
            time.sleep(0.2)  # a probe cadence, not a flood

    def _write(elapsed: float, final: bool) -> dict:
        snap = tally.snapshot()
        ready = snap["ready"]
        ingest = snap["ingest"]
        payload = {
            "ok": True,
            "status": "measured_short_soak",
            "final": final,
            "backend": backend,
            "window": {
                "started_at": started_wall.isoformat(),
                "elapsed_seconds": round(elapsed, 2),
                "elapsed_minutes": round(elapsed / 60.0, 2),
                "workers": args.workers,
            },
            "slo_targets": {
                "api_availability_30d": AVAILABILITY_SLO,
                "ingest_p95_ms": INGEST_P95_TARGET_MS,
            },
            "measured": snap,
            "observed_detection_modes": sorted(detection_modes),
            "readiness_throttling_note": (
                "`/health/ready` is NOT in the throttle exemption list "
                "(sentinel/interface/throttle.py: exempt_paths = ('/health/live',)), "
                "so it consumes the per-address budget. An earlier run of this "
                "script at ~180 rps from a single address had 27 of 270 readiness "
                "probes answered 429. In a cluster the kubelet probes from the node "
                "address and client traffic arrives from elsewhere, so the buckets "
                "usually differ -- but where they do not, throttled readiness marks "
                "pods NotReady under load and sheds them from the Service, which "
                "adds load to the rest. Worth an explicit decision; liveness is "
                "exempt, readiness is not."
            ),
            "throughput_rps": round(ingest["attempts"] / elapsed, 2) if elapsed else 0.0,
            "meets_ingest_p95_target": ingest["p95_ms"] < INGEST_P95_TARGET_MS,
            "availability_observed": ready["success_ratio"],
            # Deliberately NOT "meets 30d SLO". A short window cannot observe one.
            "thirty_day_slo_status": "UNVERIFIED",
            "interpretation": (
                f"In-process TestClient soak over {elapsed / 60.0:.1f} minutes. This is an "
                "UPPER BOUND on production availability: no network, ingress, load "
                "balancer, second replica or rolling deploy is exercised. A clean short "
                "window is consistent with the 99.9%/30d SLO but does not demonstrate it "
                "-- 99.9% permits ~43 minutes of downtime per 30 days, which a run this "
                "long cannot sample. The 30-day row stays UNVERIFIED."
            ),
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return payload

    threads = [threading.Thread(target=_ingest, args=(w,), daemon=True) for w in range(args.workers)]
    threads.append(threading.Thread(target=_ready, daemon=True))
    for t in threads:
        t.start()

    try:
        while True:
            elapsed = time.perf_counter() - started
            if elapsed >= args.seconds:
                break
            time.sleep(min(args.report_interval, max(1.0, args.seconds - elapsed)))
            snap = _write(time.perf_counter() - started, final=False)
            print(
                f"[{snap['window']['elapsed_minutes']:.1f}m] "
                f"ingest n={snap['measured']['ingest']['attempts']} "
                f"p95={snap['measured']['ingest']['p95_ms']}ms "
                f"avail={snap['availability_observed']:.6f}",
                flush=True,
            )
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=30)
        if maintenance is not None:
            maintenance.stop(timeout=10)
        if workers is not None:
            workers.stop(timeout=10)
        final = _write(time.perf_counter() - started, final=True)
        container.close()
        if server is not None:
            server.close()
        print(json.dumps(final, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
