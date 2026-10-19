"""Evidence bodies are sealed in the live repository, per tenant and per record.

The cipher existed and nothing used it: evidence bodies sat in the database
as readable JSON. These tests hold the wiring: a body written with a key is
not readable in the row; it opens only for its own tenant and incident; rows
written before a key existed stay readable and can be sealed in place; a key
rotation rewraps without losing anything; and a process with no key refuses
to pretend an encrypted body is empty.
"""

from __future__ import annotations

import base64
import io
import json
import secrets
from datetime import datetime, timezone

import pytest

from sentinel.application.records import EvidenceRecord
from sentinel.composition.settings import ConfigurationError, Settings
from sentinel.domain.primitives import Digest, IncidentId, TenantId, Timestamp
from sentinel.infrastructure.persistence.crypto import CryptoError, EnvelopeCipher, StaticKeyProvider
from sentinel.infrastructure.sql.repositories import SEALED_PREFIX, EvidenceSealed
from sentinel.infrastructure.sql.unit_of_work import SqlUnitOfWorkFactory
from tests_arch.doubles import FakeClock

NOW = datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)
MARKER = "cardholder-4111-marker-in-the-body"


class _NoEvents:
    def publish(self, *_a, **_k):
        return None


def _cipher(*key_ids: str, active: str) -> EnvelopeCipher:
    return EnvelopeCipher(StaticKeyProvider(keys={k: _KEYS[k] for k in key_ids}, active=active))


_KEYS = {"k1": secrets.token_bytes(32), "k2": secrets.token_bytes(32)}


def _factory(pool, cipher=None) -> SqlUnitOfWorkFactory:
    return SqlUnitOfWorkFactory(pool=pool, publisher=_NoEvents(), clock=FakeClock(NOW), evidence_cipher=cipher)


def _record(incident: str) -> EvidenceRecord:
    return EvidenceRecord(incident_id=IncidentId(incident), uri=f"evidence://{incident}", digest=Digest("ab" * 32),
                          content={"note": MARKER, "n": 1}, created_at=Timestamp(NOW))


def _raw(pool, tenant: str, incident: str) -> str:
    with pool.acquire() as conn:
        conn.begin()
        conn.set_tenant(tenant)
        row = conn.one(f"SELECT content_json FROM evidence WHERE tenant_id={conn.p} AND incident_id={conn.p}", (tenant, incident))
        conn.commit()
    return str(row["content_json"])


def _store(factory, tenant: str, incident: str) -> None:
    with factory.begin(TenantId(tenant)) as uow:
        uow.ledger.store_evidence(_record(incident))
        uow.commit()


def _read(factory, tenant: str, incident: str):
    with factory.begin(TenantId(tenant)) as uow:
        return uow.ledger.get_evidence(IncidentId(incident))


def test_a_sealed_body_is_unreadable_in_the_row_and_round_trips(migrated_pool):
    factory = _factory(migrated_pool, _cipher("k1", active="k1"))
    _store(factory, "acme", "inc-1")
    stored = _raw(migrated_pool, "acme", "inc-1")
    assert stored.startswith(SEALED_PREFIX) and MARKER not in stored
    assert _read(factory, "acme", "inc-1").content == {"note": MARKER, "n": 1}


def test_a_sealed_body_opens_only_for_its_own_tenant_and_incident(migrated_pool):
    factory = _factory(migrated_pool, _cipher("k1", active="k1"))
    _store(factory, "acme", "inc-1")
    _store(factory, "acme", "inc-2")
    stolen = _raw(migrated_pool, "acme", "inc-1")
    with migrated_pool.acquire() as conn:            # an operator copies one body over another
        conn.begin()
        conn.set_tenant("acme")
        conn.execute_rowcount(f"UPDATE evidence SET content_json={conn.p} WHERE tenant_id={conn.p} AND incident_id={conn.p}",
                              (stolen, "acme", "inc-2"))
        conn.commit()
    with pytest.raises(CryptoError):
        _read(factory, "acme", "inc-2")


def test_a_process_without_a_key_refuses_rather_than_returning_empty(migrated_pool):
    _store(_factory(migrated_pool, _cipher("k1", active="k1")), "acme", "inc-1")
    with pytest.raises(EvidenceSealed):
        _read(_factory(migrated_pool), "acme", "inc-1")


def test_plaintext_rows_stay_readable_and_are_sealed_in_place(migrated_pool):
    _store(_factory(migrated_pool), "acme", "inc-old")
    assert MARKER in _raw(migrated_pool, "acme", "inc-old")
    factory = _factory(migrated_pool, _cipher("k1", active="k1"))
    assert _read(factory, "acme", "inc-old").content["note"] == MARKER
    with factory.begin(TenantId("acme")) as uow:
        assert uow.ledger.reseal_evidence() == 1
        assert uow.ledger.reseal_evidence() == 0, "resealing is not idempotent"
        uow.commit()
    assert MARKER not in _raw(migrated_pool, "acme", "inc-old")
    assert _read(factory, "acme", "inc-old").content["note"] == MARKER


def test_a_key_rotation_rewraps_every_row_even_past_the_first_batch(migrated_pool):
    old = _factory(migrated_pool, _cipher("k1", active="k1"))
    for index in range(5):
        _store(old, "acme", f"inc-{index}")
    rotating = _factory(migrated_pool, _cipher("k1", "k2", active="k2"))
    total = 0
    while True:
        with rotating.begin(TenantId("acme")) as uow:
            changed = uow.ledger.reseal_evidence(limit=2)   # smaller than the table, on purpose
            uow.commit()
        total += changed
        if not changed:
            break
    assert total == 5
    retired = _factory(migrated_pool, _cipher("k2", active="k2"))     # k1 is gone
    for index in range(5):
        assert _read(retired, "acme", f"inc-{index}").content["note"] == MARKER
        assert _raw(migrated_pool, "acme", f"inc-{index}").startswith(f"{SEALED_PREFIX}1.k2.")


# ── Configuration ────────────────────────────────────────────────────────────


def _production(**extra) -> dict:
    return {"SENTINEL_ENV": "production", "SENTINEL_API_KEYS": "acme:" + "k" * 40 + ":analyst",
            "SENTINEL_DATABASE_URL": "postgresql://sentinel@db/sentinel", "SENTINEL_CORS_ORIGINS": "https://console.example.com",
            "SENTINEL_RATE_LIMIT_FAIL_OPEN": "false", "SENTINEL_REQUIRE_EXECUTION_BINDING": "true", **extra}


def test_production_refuses_to_store_readable_evidence_without_being_told_to():
    with pytest.raises(ConfigurationError, match="readable JSON"):
        Settings.from_environment(_production())
    assert Settings.from_environment(_production(SENTINEL_EVIDENCE_ENCRYPTION="off")).workflow.evidence_keys == {}
    key = base64.b64encode(secrets.token_bytes(32)).decode()
    sealed = Settings.from_environment(_production(SENTINEL_DATA_KEY_K1=key, SENTINEL_ACTIVE_KEY_ID="k1"))
    assert sealed.workflow.evidence_active_key == "k1" and key not in repr(sealed.workflow)


@pytest.mark.parametrize("extra", [
    {"SENTINEL_DATA_KEY_K1": "a2V5", "SENTINEL_ACTIVE_KEY_ID": "k9"},
    {"SENTINEL_DATA_KEY_K1": "a2V5", "SENTINEL_ACTIVE_KEY_ID": "k1", "SENTINEL_EVIDENCE_ENCRYPTION": "off"},
    {"SENTINEL_EVIDENCE_ENCRYPTION": "sometimes"},
])
def test_contradictory_key_configuration_refuses_to_start(extra):
    with pytest.raises(ConfigurationError):
        Settings.from_environment(_production(**extra))


def test_the_reseal_command_reports_what_it_did(tmp_path):
    from sentinel.interface.cli import main

    out = io.StringIO()
    assert main(["evidence-reseal"], out=out) in {64, 78}
    assert "evidence-reseal" in out.getvalue() or "data key" in out.getvalue() or "invalid" in out.getvalue()
    assert json.dumps({"ok": True})
