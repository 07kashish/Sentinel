"""Local SQLite backup/restore drill — records experimental RPO/RTO."""

from __future__ import annotations

import json
import shutil
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from sentinel.composition.settings import Settings
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.migrate import migrate, verify


def drill() -> dict:
    started = time.perf_counter()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        live = root / "live.db"
        backup = root / "backup.db"
        restored = root / "restored.db"

        settings = Settings.from_environment(
            {
                "SENTINEL_ENV": "development",
                "SENTINEL_DB_PATH": str(live),
                "SENTINEL_API_KEYS": "drill:" + ("k" * 40) + ":ingest",
            }
        )
        pool = build_engine(settings.engine)
        t0 = time.perf_counter()
        migrate(pool)
        migrate_s = time.perf_counter() - t0
        with pool.acquire() as conn:
            conn.begin()
            conn.set_tenant("drill")
            conn.execute_rowcount(
                "INSERT INTO agents (tenant_id, address, label, enrolled_at) "
                "VALUES (?, ?, ?, ?)",
                ("drill", "0x" + "ab" * 20, "drill-agent", datetime.now(timezone.utc).isoformat()),
            )
            conn.commit()
        pool.close()

        t1 = time.perf_counter()
        shutil.copy2(live, backup)
        backup_s = time.perf_counter() - t1

        # Simulate loss
        live.unlink()

        t2 = time.perf_counter()
        shutil.copy2(backup, restored)
        restore_s = time.perf_counter() - t2

        settings2 = Settings.from_environment(
            {
                "SENTINEL_ENV": "development",
                "SENTINEL_DB_PATH": str(restored),
                "SENTINEL_API_KEYS": "drill:" + ("k" * 40) + ":ingest",
            }
        )
        pool2 = build_engine(settings2.engine)
        t3 = time.perf_counter()
        version = verify(pool2)
        verify_s = time.perf_counter() - t3
        with pool2.acquire() as conn:
            conn.begin()
            conn.set_tenant("drill")
            row = conn.one(
                "SELECT address FROM agents WHERE tenant_id=?", ("drill",)
            )
            conn.commit()
        pool2.close()
        ok = row is not None
        total = time.perf_counter() - started
        return {
            "engine": "sqlite",
            "ok": ok,
            "schema_version": version,
            "migrate_seconds": round(migrate_s, 4),
            "backup_seconds": round(backup_s, 4),
            "restore_seconds": round(restore_s, 4),
            "verify_seconds": round(verify_s, 4),
            "experimental_rto_seconds": round(restore_s + verify_s, 4),
            "experimental_rpo_seconds": 0.0,
            "notes": (
                "File-copy drill only. Postgres PITR live drill remains UNVERIFIED. "
                "RPO≈0 for this offline copy taken after writes stopped."
            ),
            "wall_seconds": round(total, 4),
        }


if __name__ == "__main__":
    result = drill()
    out = Path("docs/dr_sqlite_drill.json")
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["ok"] else 1)
