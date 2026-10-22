"""Microbenchmarks for PERFORMANCE_REPORT.md — real numbers only."""

from __future__ import annotations

import json
import statistics
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sentinel.composition.settings import Settings
from sentinel.domain.primitives import TenantId, Timestamp
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.infrastructure.sql.work_queue import SqlWorkQueue, shard_for


def _settings(db: Path) -> Settings:
    return Settings.from_environment(
        {
            "SENTINEL_ENV": "development",
            "SENTINEL_DB_PATH": str(db),
            "SENTINEL_API_KEYS": "bench:" + ("k" * 40) + ":ingest",
        }
    )


def run(scale: int = 1000) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "bench.db"
        settings = _settings(db)
        pool = build_engine(settings.engine)
        migrate(pool)
        queue = SqlWorkQueue(
            pool=pool,
            shard_count=1,
            max_attempts=5,
            lease_seconds=300,
        )
        now = Timestamp(datetime.now(timezone.utc))
        tenant = TenantId("bench")
        now_iso = now.isoformat()

        t1 = time.perf_counter()
        with pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant.value)
            p = conn.p
            for i in range(scale):
                conn.execute_rowcount(
                    f"INSERT INTO work_queue (tenant_id, work_id, incident_id, shard, priority, "
                    f"payload_json, state, attempts, lease_epoch, available_at, enqueued_at) "
                    f"VALUES ({p},{p},{p},{p},{p},{p},'pending',0,0,{p},{p})",
                    (
                        tenant.value,
                        uuid.uuid4().hex,
                        f"inc-{i:06d}",
                        shard_for(tenant, 1),
                        2,
                        "{}",
                        now_iso,
                        now_iso,
                    ),
                )
            conn.commit()
        enqueue_s = time.perf_counter() - t1

        claim_times: list[float] = []
        claimed = 0
        # At large scales, measure a sample of claims rather than draining all
        # rows (full drain of 100k SQLite claim/complete loops is hours-scale).
        claim_target = scale if scale <= 1000 else min(1000, scale)
        for _ in range(claim_target):
            started = time.perf_counter()
            work = queue.claim(shard=0, shard_count=1, now=now)
            claim_times.append((time.perf_counter() - started) * 1000)
            if work is None:
                break
            claimed += 1
            queue.complete(work)

        pool.close()
        return {
            "scale_requested": scale,
            "enqueued": scale,
            "claimed_sample": claimed,
            "claim_sample_size_target": claim_target,
            "enqueue_seconds": round(enqueue_s, 4),
            "claim_latency_ms": {
                "n": len(claim_times),
                "mean": round(statistics.mean(claim_times), 3) if claim_times else None,
                "p95": round(sorted(claim_times)[max(0, int(len(claim_times) * 0.95) - 1)], 3)
                if claim_times
                else None,
                "max": round(max(claim_times), 3) if claim_times else None,
            },
            "notes": (
                "SQLite single-process microbench on work_queue. "
                "Scales >1000 report claim latency on a 1000-claim sample after full enqueue. "
                "Production multi-tenant cardinality remains separate."
            ),
        }


def main() -> None:
    out = {}
    for scale in (10, 100, 1000, 10000):
        out[str(scale)] = run(scale)
    # Attempt 100k only if prior tier stayed under a soft wall-time budget.
    if out["10000"]["enqueue_seconds"] < 5.0:
        try:
            out["100000"] = run(100000)
        except Exception as exc:  # noqa: BLE001
            out["100000"] = {
                "scale_requested": 100000,
                "status": "UNVERIFIED",
                "error": type(exc).__name__,
                "detail": str(exc)[:200],
            }
    else:
        out["100000"] = {
            "scale_requested": 100000,
            "status": "UNVERIFIED",
            "reason": "skipped: 10k enqueue exceeded soft budget",
        }
    path = Path("reports/performance_microbench.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
