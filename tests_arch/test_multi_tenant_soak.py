"""Multi-tenant soak + local SLO measurement (P2).

Reports measured numbers honestly. Does not claim production 99.9% availability.
"""

from __future__ import annotations

import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from fastapi.testclient import TestClient

from sentinel.composition.container import build_container
from sentinel.composition.settings import Settings
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.interface.http import create_app


def test_multi_tenant_concurrent_ingest_soak(tmp_path):
    """Sustained concurrent ingest across tenants; measure success + p95 latency."""
    db = tmp_path / "soak.db"
    key_a = "a" * 40
    key_b = "b" * 40
    env = {
        "SENTINEL_ENV": "development",
        "SENTINEL_DB_PATH": str(db),
        "SENTINEL_API_KEYS": f"tenant-a:{key_a}:ingest,tenant-b:{key_b}:ingest",
    }
    settings = Settings.from_environment(env)
    pool = build_engine(settings.engine)
    migrate(pool)
    pool.close()
    container = build_container(settings)
    client = TestClient(create_app(container), raise_server_exceptions=False)

    tenants = [key_a, key_b]
    per_tenant = 40
    latencies_ms: list[float] = []
    failures = 0

    def _one(key: str, n: int) -> tuple[int, float]:
        payload = {
            "eventId": f"soak-{key[0]}-{n}",
            "timestamp": "2026-08-10T12:00:00Z",
            "agentId": "0x" + "cd" * 20,
            "eventType": "tool_call",
            "action": "read_file",
            "resource": "README.md",
            "metadata": {},
        }
        started = time.perf_counter()
        res = client.post(
            "/v1/events",
            json=payload,
            headers={"Authorization": f"Bearer {key}"},
        )
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return res.status_code, elapsed_ms

    try:
        with ThreadPoolExecutor(max_workers=8) as pool_ex:
            futures = [
                pool_ex.submit(_one, key, n)
                for key in tenants
                for n in range(per_tenant)
            ]
            for fut in as_completed(futures):
                code, ms = fut.result()
                latencies_ms.append(ms)
                if code not in (200, 201, 202):
                    failures += 1

        total = len(latencies_ms)
        success_rate = (total - failures) / total if total else 0.0
        sorted_ms = sorted(latencies_ms)
        p95 = sorted_ms[int(0.95 * (total - 1))] if total else 0.0
        # Local TestClient soak — not a 30d production SLO. Targets from OPERATIONS.md.
        assert success_rate >= 0.99, f"soak success_rate={success_rate} failures={failures}"
        # Soft ceiling for in-process client; production ingest SLO is <500ms at stated load.
        assert p95 < 2000.0, f"soak ingest p95_ms={p95}"
        print(
            f"SOAK_METRICS success_rate={success_rate:.4f} "
            f"ingest_p95_ms={p95:.3f} mean_ms={statistics.mean(latencies_ms):.3f} "
            f"n={total} failures={failures}"
        )
    finally:
        container.close()


def test_compute_low_confidence_region_is_not_constant():
    from sentinel.application.calibration import compute_low_confidence_region

    assert compute_low_confidence_region(0.0) is True
    assert compute_low_confidence_region(1.0) is True
    assert compute_low_confidence_region(0.42) is False
    assert compute_low_confidence_region(0.99) is False
