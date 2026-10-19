"""Last consented inventory per device. Self-reports are not trusted enrollment."""
from __future__ import annotations

import json

from sentinel.infrastructure.sql.engine import ConnectionPool

DEVICE_STATEMENTS = ("""
CREATE TABLE IF NOT EXISTS device_discovery (
    tenant_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    received_at TEXT NOT NULL,
    submitted_by TEXT NOT NULL,
    report_json TEXT NOT NULL,
    PRIMARY KEY (tenant_id, device_id)
)
""",)


class SqlDeviceDiscovery:
    def __init__(self, pool: ConnectionPool):
        self.pool = pool

    def save(self, tenant: str, report: dict, *, received_at: str, actor: str) -> None:
        with self.pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant)
            conn.serialise_tenant(tenant, purpose="device_discovery")
            p = conn.p
            found = conn.one(f"SELECT device_id FROM device_discovery WHERE tenant_id={p} AND device_id={p}",
                             (tenant, report["device_id"]))
            count = conn.one(f"SELECT COUNT(*) AS n FROM device_discovery WHERE tenant_id={p}", (tenant,))
            if found is None and count and int(count["n"]) >= 1000:
                raise ValueError("Device inventory limit reached; remove an old report first.")
            conn.execute_rowcount(
                f"INSERT INTO device_discovery (tenant_id, device_id, received_at, submitted_by, report_json) "
                f"VALUES ({p},{p},{p},{p},{p}) ON CONFLICT (tenant_id, device_id) DO UPDATE SET "
                "received_at=excluded.received_at, submitted_by=excluded.submitted_by, report_json=excluded.report_json",
                (tenant, report["device_id"], received_at, actor, json.dumps(report)),
            )
            conn.commit()

    def list(self, tenant: str) -> dict:
        with self.pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant)
            rows = conn.execute(f"SELECT received_at, report_json FROM device_discovery WHERE tenant_id={conn.p} "
                                "ORDER BY received_at DESC, device_id LIMIT 101", (tenant,))
            conn.commit()
        return {"devices": [{"received_at": r["received_at"], "report": json.loads(r["report_json"]),
                             "trust": "self_reported", "enforced": False} for r in rows[:100]],
                "truncated": len(rows) > 100}

    def delete(self, tenant: str, device_id: str) -> bool:
        with self.pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant)
            n = conn.execute_rowcount(f"DELETE FROM device_discovery WHERE tenant_id={conn.p} AND device_id={conn.p}",
                                     (tenant, device_id))
            conn.commit()
            return n > 0
