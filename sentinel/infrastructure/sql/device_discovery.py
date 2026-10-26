"""Historical device DDL required by migration 38; no runtime device store."""
from __future__ import annotations



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
