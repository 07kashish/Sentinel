#!/usr/bin/env python3
"""Controlled before/after for the retention sweep. One variable.

WHY NOT JUST RE-RUN THE SOAK
-----------------------------
A 40-minute soak cannot demonstrate retention at all: the shortest configurable
window is one day, and no row created during the run is ever old enough to be
swept. Re-running it would show a number that moved for other reasons and invite
the reader to credit the fix for it.

So this constructs the state a long-running deployment actually reaches -- tables
grown to N rows, with finished operational work aged past the retention window,
which is what a worker draining the queue for a month leaves behind -- measures
ingest p95 against it, runs one sweep, and measures again. Nothing else changes
between the two measurements: same process, same connection pool, same client.

The seeding is bulk SQL rather than N real requests because building 55k rows
through the API takes ~70 minutes (measured). The rows are shaped like the ones
the API writes, and the measurement itself always goes through the real HTTP
ingest path.

Usage:
  PYTHONPATH=. python scripts/measure_retention_effect.py --rows 55000
"""

from __future__ import annotations

import argparse
import json
import logging
import statistics
import tempfile
import time
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "reports" / "retention_effect.json"
KEY = "t" * 40
TENANT = "acme"


def _payload(n: int) -> dict:
    return {
        "eventId": f"retention-probe-{n}",
        "timestamp": "2026-08-13T12:00:00Z",
        "agentId": "0x" + "cd" * 20,
        "eventType": "tool_call",
        "action": "read_file",
        "resource": "README.md",
        "metadata": {},
    }


def _percentile(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(pct * (len(ordered) - 1))))]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=55_000)
    parser.add_argument("--sample-size", type=int, default=300)
    parser.add_argument("--retention-days", type=int, default=90)
    args = parser.parse_args()
    logging.getLogger("sentinel").setLevel(logging.CRITICAL)

    from fastapi.testclient import TestClient

    from sentinel.composition.container import build_container
    from sentinel.composition.settings import Settings
    from sentinel.domain.primitives import TenantId, Timestamp
    from sentinel.infrastructure.sql.engine import build_engine
    from sentinel.infrastructure.sql.migrate import migrate
    from sentinel.interface.http import create_app

    tmp = Path(tempfile.mkdtemp(prefix="sentinel_retention_"))
    db = tmp / "retention.db"
    settings = Settings.from_environment(
        {
            "SENTINEL_ENV": "development",
            "SENTINEL_DB_PATH": str(db),
            "SENTINEL_API_KEYS": f"{TENANT}:{KEY}:ingest",
            "SENTINEL_ADDRESS_LIMIT": "100000000",
            "SENTINEL_CREDENTIAL_LIMIT": "100000000",
            "SENTINEL_RETENTION_DAYS": str(args.retention_days),
        }
    )
    pool = build_engine(settings.engine)
    migrate(pool)
    pool.close()
    container = build_container(settings)
    client = TestClient(create_app(container), raise_server_exceptions=False)
    headers = {"Authorization": f"Bearer {KEY}"}

    now = container.clock.now()
    # Old enough to be swept: a deployment that has been up longer than its
    # retention window, which is the steady state this is about.
    aged = Timestamp(now.value - timedelta(days=args.retention_days + 30)).isoformat()
    payload_json = json.dumps({"action": "read_file", "resource": "README.md"})

    print(f"seeding {args.rows} aged rows ...", flush=True)
    with container.pool.acquire() as conn:
        p = conn.p
        conn.begin()
        for i in range(args.rows):
            inc = f"inc-seed-{i}"
            conn.execute(
                f"INSERT INTO incidents (tenant_id, incident_id, state, facts_json, "
                f"version, execution_epoch, created_at, updated_at) "
                f"VALUES ({p},{p},'completed_unattested',{p},1,0,{p},{p})",
                (TENANT, inc, payload_json, aged, aged),
            )
            conn.execute(
                f"INSERT INTO incident_transitions (tenant_id, incident_id, seq, "
                f"from_state, to_state, facts_added, actor, occurred_at) "
                f"VALUES ({p},{p},1,'received','validated',{p},'seed',{p})",
                (TENANT, inc, "{}", aged),
            )
            conn.execute(
                f"INSERT INTO domain_events (tenant_id, event_id, incident_id, "
                f"event_type, event_version, payload_json, occurred_at, recorded_at) "
                f"VALUES ({p},{p},{p},'IncidentAdmitted',1,{p},{p},{p})",
                (TENANT, f"ev-seed-{i}", inc, payload_json, aged, aged),
            )
            # Finished work: what a worker leaves behind and nothing ever removed.
            conn.execute(
                f"INSERT INTO work_queue (tenant_id, work_id, incident_id, shard, "
                f"priority, payload_json, state, attempts, enqueued_at, available_at) "
                f"VALUES ({p},{p},{p},0,'HIGH',{p},'done',1,{p},{p})",
                (TENANT, f"w-seed-{i}", inc, payload_json, aged, aged),
            )
            conn.execute(
                f"INSERT INTO outbox (tenant_id, record_id, incident_id, kind, "
                f"payload_json, idempotency_key, state, attempts, max_attempts, "
                f"available_at, created_at, updated_at) "
                f"VALUES ({p},{p},{p},'webhook',{p},{p},'delivered',1,5,{p},{p},{p})",
                (TENANT, f"o-seed-{i}", inc, payload_json, f"idem-seed-{i}", aged, aged, aged),
            )
        conn.commit()

    def _counts() -> dict[str, int]:
        out = {}
        with container.pool.acquire() as conn:
            conn.begin()
            for table in ("incidents", "domain_events", "incident_transitions",
                          "work_queue", "outbox", "inbox", "replay_nonces"):
                out[table] = int(conn.one(f"SELECT COUNT(*) AS n FROM {table}")["n"])  # noqa: S608
            conn.commit()
        return out

    def _measure(label: str, offset: int) -> dict:
        latencies: list[float] = []
        for i in range(args.sample_size):
            t0 = time.perf_counter()
            res = client.post("/v1/events", json=_payload(offset + i), headers=headers)
            latencies.append((time.perf_counter() - t0) * 1000.0)
            assert res.status_code in (200, 201, 202), res.text
        result = {
            "p50_ms": round(_percentile(latencies, 0.50), 3),
            "p95_ms": round(_percentile(latencies, 0.95), 3),
            "p99_ms": round(_percentile(latencies, 0.99), 3),
            "mean_ms": round(statistics.mean(latencies), 3),
            "n": len(latencies),
        }
        print(f"  {label}: p50={result['p50_ms']}ms p95={result['p95_ms']}ms", flush=True)
        return result

    before_counts = _counts()
    before_bytes = db.stat().st_size
    print("measuring BEFORE sweep ...", flush=True)
    before = _measure("before", 0)

    print("sweeping ...", flush=True)
    t0 = time.perf_counter()
    swept = container.retention.sweep(
        now=container.clock.now(),
        retention_days=args.retention_days,
        # Required since the sweep was found to delete nothing on PostgreSQL
        # without a tenant context. This script measures SQLite, where there is
        # no RLS, so passing it changes no result here -- but a call site that
        # could omit it is a call site that will silently no-op the day it is
        # pointed at the production engine.
        tenants=[TenantId(TENANT)],
    )
    sweep_seconds = time.perf_counter() - t0

    # VACUUM is what actually returns freed pages to the filesystem on SQLite.
    # Reported separately: the sweep frees logical space, reclaiming it on disk
    # is a second decision with its own cost.
    with container.pool.acquire() as conn:
        conn._raw.execute("VACUUM")  # noqa: SLF001 - maintenance, outside a transaction
    after_bytes = db.stat().st_size

    print("measuring AFTER sweep ...", flush=True)
    after = _measure("after", args.sample_size)
    after_counts = _counts()
    container.close()

    report = {
        "rows_seeded": args.rows,
        "retention_days": args.retention_days,
        "sweep": dict(swept.as_dict()),
        "sweep_seconds": round(sweep_seconds, 4),
        "before": before,
        "after": after,
        "p95_change_ms": round(after["p95_ms"] - before["p95_ms"], 3),
        "p95_change_pct": (
            round(100.0 * (after["p95_ms"] - before["p95_ms"]) / before["p95_ms"], 1)
            if before["p95_ms"]
            else None
        ),
        "table_counts_before": before_counts,
        "table_counts_after": after_counts,
        "db_bytes_before": before_bytes,
        "db_bytes_after_vacuum": after_bytes,
        "caveats": (
            "SQLite, single-threaded, in-process TestClient. The sweep removes "
            "finished operational rows only; incidents, domain_events and "
            "incident_transitions are retained by design and still grow, so this "
            "measures a partial reduction in table volume, not its elimination."
        ),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({k: report[k] for k in
                      ("sweep", "before", "after", "p95_change_ms", "p95_change_pct",
                       "db_bytes_before", "db_bytes_after_vacuum")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
