#!/usr/bin/env python3
"""Profile POST /v1/events as the database grows. Diagnosis, not a benchmark.

WHY
---
A 40-minute soak measured ingest p95 rising from 83 ms to 624 ms as the tables
grew to ~55k events, against a stated <500 ms target. `docs/PERFORMANCE_REPORT.md`
and `tests_arch/test_persistence_benchmarks.py` did not catch it, and the reason
matters: that microbench profiles READ queries (`events.stream_tail`,
`events.for_incident`) against a seeded table. The soak issues no reads at all.
Whatever is slow is on the WRITE path, so measuring the read path more carefully
would never have found it.

This script attributes the cost per SQL statement rather than guessing. It drives
real requests through the real app at increasing table sizes and reports which
statements grow with N -- plus their query plans at the largest size, so a
sequential scan shows up by name.

WHY IT NOW RUNS ON POSTGRESQL TOO
---------------------------------
The first pass measured SQLite only, because the script hard-wired
`SENTINEL_DB_PATH`. Production runs PostgreSQL, and the two engines do not share
a write path: SQLite serialises every writer at `BEGIN IMMEDIATE`, so six
concurrent writers there are six writers queued behind one lock, which is a
measurement of SQLite's lock and not of the application. `--postgres` starts a
real PostgreSQL 16 server (see `scripts/_embedded_postgres.py` for what that is
and is not) and connects as a NON-superuser, so row-level security is actually
enforced and its predicate is part of what gets measured.

ATTRIBUTION METHOD
------------------
Statement timing wraps `Connection.execute`/`execute_rowcount` in Python. The
earlier SQLite-only revision used `sqlite3.set_trace_callback`, which times the
GAP between one statement starting and the next one starting -- so it charged
application work to whichever statement preceded it, and it could not run at all
with more than one writer. The wrapper measures the call itself, is thread-safe,
and works on both drivers, which is what makes a six-writer statement breakdown
possible. Statement-level numbers here are therefore NOT directly comparable with
the trace-callback numbers in the previous `docs/ingest_profile.json`; the
end-to-end p50/p95 request latencies are.

Usage:
  PYTHONPATH=. python scripts/profile_ingest.py --events 55000 --sample-every 5000
  PYTHONPATH=. python scripts/profile_ingest.py --postgres --workers 6
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import threading
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

DEFAULT_OUT = ROOT / "docs" / "ingest_profile.json"

KEY = "p" * 40


def _payload(n: int) -> dict:
    return {
        "eventId": f"profile-{n}",
        "timestamp": "2026-08-13T12:00:00Z",
        "agentId": "0x" + "cd" * 20,
        "eventType": "tool_call",
        "action": "read_file",
        "resource": "README.md",
        "metadata": {},
    }


def _normalise(sql: str) -> str:
    """Collapse a statement to a stable key: first words plus target table."""
    flat = " ".join(sql.split())
    return flat[:120]


class StatementProfiler:
    """Times every statement the app issues, on either driver.

    Installed by patching the two methods on `Connection` that every repository
    goes through. There is no third way to reach the database -- `test_architecture_rules`
    enforces that -- so this sees the whole write path rather than a sample of it.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._timings: dict[str, list[float]] = defaultdict(list)
        self.enabled = False
        self._patched = False
        self._originals: dict[str, object] = {}

    def install(self) -> None:
        if self._patched:
            return
        from sentinel.infrastructure.sql.engine import Connection

        for name in ("execute", "execute_rowcount"):
            original = getattr(Connection, name)
            self._originals[name] = original

            def _wrapped(conn, sql, params=(), *, _original=original):
                if not self.enabled:
                    return _original(conn, sql, params)
                started = time.perf_counter()
                try:
                    return _original(conn, sql, params)
                finally:
                    elapsed = (time.perf_counter() - started) * 1000.0
                    with self._lock:
                        self._timings[_normalise(sql)].append(elapsed)

            setattr(Connection, name, _wrapped)
        self._patched = True

    def remove(self) -> None:
        if not self._patched:
            return
        from sentinel.infrastructure.sql.engine import Connection

        for name, original in self._originals.items():
            setattr(Connection, name, original)
        self._patched = False

    def reset(self) -> None:
        with self._lock:
            self._timings.clear()

    def report(self) -> list[dict]:
        with self._lock:
            snapshot = {sql: list(v) for sql, v in self._timings.items()}
        return sorted(
            (
                {
                    "sql": sql,
                    "calls": len(v),
                    "total_ms": round(sum(v), 2),
                    "mean_ms": round(statistics.mean(v), 4),
                    "p95_ms": round(sorted(v)[int(0.95 * (len(v) - 1))], 4),
                }
                for sql, v in snapshot.items()
                if v
            ),
            key=lambda d: d["total_ms"],
            reverse=True,
        )

    def statements(self) -> list[str]:
        with self._lock:
            return sorted(self._timings)

    def total_ms(self) -> float:
        """Every millisecond spent inside a database call during the window.

        Compared against the wall-clock request latencies, this is the question
        "is the database the problem?" answered with a number instead of an
        assumption. Under N concurrent threads the sum can exceed the wall clock,
        because the calls overlap; what matters is the per-request share.
        """
        with self._lock:
            return sum(sum(v) for v in self._timings.values())


def _sqlite_inventory(dsn: str, statements: list[str]) -> tuple[dict, dict, int | None]:
    import sqlite3

    probe = sqlite3.connect(dsn)
    tables: dict[str, int | None] = {}
    for (name,) in probe.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall():
        try:
            tables[name] = probe.execute(f"SELECT count(*) FROM {name}").fetchone()[0]  # noqa: S608
        except sqlite3.Error:
            tables[name] = None
    plans: dict[str, list[str]] = {}
    for sql in statements:
        if not sql.lower().startswith("select"):
            continue
        try:
            plans[sql] = [str(r[-1]) for r in probe.execute(f"EXPLAIN QUERY PLAN {sql}")]
        except sqlite3.Error as exc:
            plans[sql] = [f"<could not plan: {exc}>"]
    probe.close()
    size = Path(dsn).stat().st_size if Path(dsn).exists() else None
    return tables, plans, size


def _postgres_inventory(
    dsn: str, admin_dsn: str, statements: list[str]
) -> tuple[dict, dict, int | None]:
    """Counts from the ADMIN role, plans from the APP role. Both on purpose.

    Counting as the app role returns ZERO for every table, and that is RLS
    working: `FORCE ROW LEVEL SECURITY` with no `sentinel.tenant_id` set means
    `current_setting(..., true)` is NULL and no row matches. A census must
    therefore run as a superuser, which bypasses the policy.

    Planning, by contrast, must run as the app role, because the plan the
    application actually gets includes the RLS predicate and a superuser's does
    not. Getting these two the wrong way round produces a report where the tables
    are empty and the plans are the wrong ones.
    """
    import psycopg

    # Same server, same database, superuser role: swap only the DSN's db name.
    admin_here = admin_dsn.rsplit("/", 1)[0] + "/" + dsn.rsplit("/", 1)[1]

    tables: dict[str, int | None] = {}
    plans: dict[str, list[str]] = {}
    with psycopg.connect(admin_here, autocommit=True) as conn:
        names = [
            r[0]
            for r in conn.execute(
                "SELECT tablename FROM pg_tables WHERE schemaname='public' "
                "ORDER BY tablename"
            ).fetchall()
        ]
        for name in names:
            try:
                tables[name] = int(
                    conn.execute(f'SELECT count(*) FROM "{name}"').fetchone()[0]  # noqa: S608
                )
            except psycopg.Error:
                tables[name] = None
        size = int(
            conn.execute("SELECT pg_database_size(current_database())").fetchone()[0]
        )

    with psycopg.connect(dsn, autocommit=True) as conn:
        for sql in statements:
            if not sql.lower().startswith("select"):
                continue
            # The statements are captured with %s placeholders still in them, so
            # they cannot be prepared as-is. EXPLAIN with GENERIC_PLAN gives the
            # planner's shape without binding values, which is exactly the
            # question being asked: index or scan?
            try:
                plans[sql] = [
                    str(r[0])
                    for r in conn.execute(f"EXPLAIN (GENERIC_PLAN) {sql}").fetchall()
                ]
            except psycopg.Error as exc:
                plans[sql] = [f"<could not plan: {exc}>"]
    return tables, plans, size


def main() -> int:  # noqa: PLR0915 - a profiler is a linear script
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, default=55_000)
    parser.add_argument("--sample-every", type=int, default=5_000)
    parser.add_argument("--sample-size", type=int, default=200)
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="concurrent ingest threads during sampling (1 isolates growth from contention)",
    )
    parser.add_argument(
        "--postgres",
        action="store_true",
        help=(
            "measure against a real PostgreSQL 16 server as a non-superuser, "
            "instead of SQLite. Production runs PostgreSQL; a SQLite number is "
            "not evidence for it."
        ),
    )
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()

    out = args.out or (
        DEFAULT_OUT
        if not args.postgres
        else ROOT / "docs" / f"ingest_profile_postgres_{args.workers}w.json"
    )

    import logging
    import tempfile

    from fastapi.testclient import TestClient

    from sentinel.composition.container import build_container
    from sentinel.composition.settings import Settings
    from sentinel.infrastructure.sql.engine import build_engine
    from sentinel.infrastructure.sql.migrate import migrate
    from sentinel.interface.http import create_app

    env = {
        "SENTINEL_ENV": "development",
        "SENTINEL_API_KEYS": f"acme:{KEY}:ingest",
        "SENTINEL_ADDRESS_LIMIT": "100000000",
        "SENTINEL_CREDENTIAL_LIMIT": "100000000",
    }
    server = None
    backend: dict[str, object] = {}
    tmp = Path(tempfile.mkdtemp(prefix="sentinel_profile_"))
    if args.postgres:
        from _embedded_postgres import PostgresUnavailableHere, start_embedded_postgres

        try:
            server = start_embedded_postgres()
        except PostgresUnavailableHere as exc:
            report = {
                "status": "UNVERIFIED",
                "engine": "postgres",
                "reason": str(exc),
                "note": (
                    "No number is recorded. A PostgreSQL row must not be filled "
                    "with a SQLite measurement."
                ),
            }
            out.write_text(json.dumps(report, indent=2), encoding="utf-8")
            print(json.dumps(report, indent=2))
            return 2
        dsn = server.fresh_database("profile")
        env["SENTINEL_DATABASE_URL"] = dsn
        # Match the pool the soak and the chart use, so contention is the app's
        # and not an artificially narrow pool's.
        env["SENTINEL_DB_POOL_MIN"] = "2"
        env["SENTINEL_DB_POOL_MAX"] = "20"
        backend = {
            "engine": "postgres",
            "server_version": server.version,
            "data_directory": server.data_directory,
            "connected_as": "sentinel_app (NOSUPERUSER, so FORCE RLS applies)",
            "provenance": (
                "pgserver-embedded PostgreSQL 16 binaries over a real TCP socket. "
                "Docker is absent here (`docker --version` -> command not found), "
                "so the postgres:16 CONTAINER IMAGE was not used."
            ),
            "pool_max": 20,
        }
    else:
        db = tmp / "profile.db"
        env["SENTINEL_DB_PATH"] = str(db)
        backend = {"engine": "sqlite", "path": str(db), "pool_max": 4}

    settings = Settings.from_environment(env)
    pool = build_engine(settings.engine)
    migrate(pool)
    pool.close()

    profiler = StatementProfiler()
    profiler.install()

    container = build_container(settings)
    # AFTER build_container: `StructuredLogger.__init__` calls `setLevel(INFO)`
    # on the shared `sentinel` logger, so raising the level before this point is
    # silently undone. At 55k events the per-incident log line is the dominant
    # cost of running the script and it drowns the report.
    logging.getLogger("sentinel").setLevel(logging.CRITICAL)

    client = TestClient(create_app(container), raise_server_exceptions=False)
    headers = {"Authorization": f"Bearer {KEY}"}

    samples: list[dict] = []
    sent = 0
    t_start = time.perf_counter()
    # Seeding is not measured, so it may use more threads than the sample does.
    # It is most of the wall clock at 55k rows and almost all of that is waiting
    # on the database, so widening it shortens the run without touching the
    # number the run exists to produce.
    seed_workers = max(args.workers, 8)
    from concurrent.futures import ThreadPoolExecutor

    def _post(n: int) -> float:
        started = time.perf_counter()
        client.post("/v1/events", json=_payload(n), headers=headers)
        return (time.perf_counter() - started) * 1000.0

    while sent < args.events:
        target = min(sent + args.sample_every, args.events)
        if target > sent:
            # Seeding is not measured, so it may use as many threads as it likes.
            with ThreadPoolExecutor(max_workers=seed_workers) as ex:
                list(ex.map(_post, range(sent + 1, target + 1)))
            sent = target

        # ── sample at this table size ────────────────────────────────────────
        profiler.reset()
        profiler.enabled = True
        base = sent
        sent += args.sample_size
        if args.workers == 1:
            latencies = [_post(n) for n in range(base + 1, sent + 1)]
        else:
            with ThreadPoolExecutor(max_workers=args.workers) as ex:
                latencies = list(ex.map(_post, range(base + 1, sent + 1)))
        profiler.enabled = False

        ordered = sorted(latencies)
        per_stmt = profiler.report()
        sql_total = profiler.total_ms()
        mean_request = statistics.mean(latencies)
        sql_per_request = sql_total / len(latencies)
        samples.append(
            {
                "rows_ingested": sent,
                "p50_ms": round(ordered[len(ordered) // 2], 3),
                "p95_ms": round(ordered[int(0.95 * (len(ordered) - 1))], 3),
                "mean_ms": round(mean_request, 3),
                # Where the time goes, per request: inside a database call, or
                # everywhere else. The prior SQLite pass could only rank
                # statements against each other; it could not say whether the
                # statements were the cost at all.
                "mean_sql_ms_per_request": round(sql_per_request, 3),
                "mean_non_sql_ms_per_request": round(mean_request - sql_per_request, 3),
                "sql_share_of_mean_latency": round(sql_per_request / mean_request, 4)
                if mean_request
                else None,
                "top_statements": per_stmt[:8],
            }
        )
        print(
            f"[{sent:>7} rows] p50={samples[-1]['p50_ms']:>8.2f}ms "
            f"p95={samples[-1]['p95_ms']:>8.2f}ms  "
            f"sql={samples[-1]['mean_sql_ms_per_request']:>7.2f}ms/req "
            f"({(samples[-1]['sql_share_of_mean_latency'] or 0) * 100:.0f}%)  "
            f"slowest={per_stmt[0]['sql'][:55] if per_stmt else 'n/a'}",
            flush=True,
        )

    statements = profiler.statements()
    profiler.remove()
    container.close()

    if args.postgres:
        assert server is not None
        tables, plans, size = _postgres_inventory(
            str(env["SENTINEL_DATABASE_URL"]), server.admin_dsn, statements
        )
    else:
        tables, plans, size = _sqlite_inventory(str(env["SENTINEL_DB_PATH"]), statements)

    report = {
        "status": "measured",
        "backend": backend,
        "workers": args.workers,
        "attribution": (
            "python-level wrapper around Connection.execute/execute_rowcount; "
            "thread-safe, so it also reports under concurrency. NOT the "
            "sqlite3 trace callback the first pass used"
        ),
        "events_ingested": sent,
        "elapsed_seconds": round(time.perf_counter() - t_start, 2),
        "samples": samples,
        "final_table_counts": dict(sorted(tables.items(), key=lambda kv: -(kv[1] or 0))),
        "query_plans_at_final_size": plans,
        "db_bytes": size,
        "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("\n=== table counts ===")
    for name, count in list(report["final_table_counts"].items())[:12]:
        print(f"  {name:<28} {count}")
    print(f"\nwrote {out}")

    if server is not None:
        server.close()
    return 0


if __name__ == "__main__":
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    raise SystemExit(main())
