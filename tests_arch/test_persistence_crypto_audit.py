"""Encryption and the audit chain, proved rather than described.

The encryption tests are pure and fast. The audit tests run against both database
engines, because the chain's correctness depends on the per-tenant serialisation
the engine provides and that differs between them.
"""

from __future__ import annotations

import base64
import secrets
from datetime import datetime, timedelta, timezone

import pytest

from sentinel.domain.primitives import TenantId, Timestamp
from sentinel.infrastructure.persistence.audit import (
    GENESIS,
    AuditLog,
    Outcome,
)
from sentinel.infrastructure.persistence.crypto import (
    KEY_BYTES,
    CipherText,
    CryptoError,
    EnvelopeCipher,
    EnvironmentKeyProvider,
    StaticKeyProvider,
)
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.migrate import migrate

TENANT = TenantId("acme")
OTHER = TenantId("globex")
NOW = Timestamp(datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc))


def _provider(active: str = "k1", *ids: str) -> StaticKeyProvider:
    keys = {name: secrets.token_bytes(KEY_BYTES) for name in (active, *ids)}
    return StaticKeyProvider(keys=keys, active=active)


# ── Encryption ───────────────────────────────────────────────────────────────


def test_a_sealed_payload_round_trips():
    cipher = EnvelopeCipher(_provider())
    sealed = cipher.seal(
        b"attacker payload", tenant_id="acme", record_type="evidence", record_id="inc-1"
    )
    opened = cipher.open(
        sealed, tenant_id="acme", record_type="evidence", record_id="inc-1"
    )
    assert opened == b"attacker payload"


def test_the_ciphertext_does_not_contain_the_plaintext():
    cipher = EnvelopeCipher(_provider())
    wire = cipher.seal(
        b"SUPER-SECRET-MARKER",
        tenant_id="acme",
        record_type="evidence",
        record_id="inc-1",
    ).to_wire()
    assert b"SUPER-SECRET-MARKER" not in wire.encode()
    assert "SUPER" not in wire


def test_a_ciphertext_cannot_be_moved_to_another_tenant():
    """THE property associated data exists for.

    AES-GCM authenticates the ciphertext but not its context. Without AAD, a blob
    lifted from one tenant's row into another's decrypts perfectly under the same
    key -- the record simply now claims to belong to someone else.
    """
    cipher = EnvelopeCipher(_provider())
    sealed = cipher.seal(
        b"acme evidence", tenant_id="acme", record_type="evidence", record_id="inc-1"
    )
    with pytest.raises(CryptoError) as caught:
        cipher.open(
            sealed, tenant_id="globex", record_type="evidence", record_id="inc-1"
        )
    assert "different tenant" in str(caught.value)


def test_a_ciphertext_cannot_be_moved_to_another_row_or_table():
    cipher = EnvelopeCipher(_provider())
    sealed = cipher.seal(
        b"body", tenant_id="acme", record_type="evidence", record_id="inc-1"
    )
    with pytest.raises(CryptoError):
        cipher.open(sealed, tenant_id="acme", record_type="evidence", record_id="inc-2")
    with pytest.raises(CryptoError):
        cipher.open(sealed, tenant_id="acme", record_type="reports", record_id="inc-1")


def test_the_associated_data_is_length_prefixed_not_delimited():
    """A delimiter-joined AAD lets two different records collide.

    `("a|b", "c")` and `("a", "b|c")` produce the same joined string, so a tenant
    id containing the delimiter would make two distinct records share associated
    data -- and a ciphertext would move freely between them.
    """
    cipher = EnvelopeCipher(_provider())
    sealed = cipher.seal(
        b"x", tenant_id="a|b", record_type="c", record_id="inc-1"
    )
    with pytest.raises(CryptoError):
        cipher.open(sealed, tenant_id="a", record_type="b|c", record_id="inc-1")


def test_tampering_with_the_payload_is_detected():
    cipher = EnvelopeCipher(_provider())
    sealed = cipher.seal(
        b"original", tenant_id="acme", record_type="evidence", record_id="inc-1"
    )
    flipped = CipherText(
        key_id=sealed.key_id,
        wrapped_dek=sealed.wrapped_dek,
        dek_nonce=sealed.dek_nonce,
        nonce=sealed.nonce,
        payload=bytes([sealed.payload[0] ^ 0x01]) + sealed.payload[1:],
    )
    with pytest.raises(CryptoError) as caught:
        cipher.open(flipped, tenant_id="acme", record_type="evidence", record_id="inc-1")
    assert "altered" in str(caught.value)


def test_every_record_gets_a_distinct_data_key_and_nonce():
    """Nonce reuse under one key is catastrophic for GCM, so both are per-record."""
    cipher = EnvelopeCipher(_provider())
    sealed = [
        cipher.seal(b"same plaintext", tenant_id="acme", record_type="e", record_id="i")
        for _ in range(20)
    ]
    assert len({s.nonce for s in sealed}) == 20
    assert len({s.wrapped_dek for s in sealed}) == 20
    # Identical plaintext under identical context must still produce distinct
    # ciphertext, or equality of ciphertexts leaks equality of plaintexts.
    assert len({s.payload for s in sealed}) == 20


def test_rotation_rewraps_the_key_without_touching_the_payload():
    """The entire reason for an envelope.

    Rotating a key-encrypting key rewrites ~60 bytes per record. Without the
    envelope it would rewrite every payload -- and the plaintext is never
    materialised here, so a rotation needs no access to the data it re-keys.
    """
    keys = {"k1": secrets.token_bytes(KEY_BYTES), "k2": secrets.token_bytes(KEY_BYTES)}
    old = EnvelopeCipher(StaticKeyProvider(keys=keys, active="k1"))
    sealed = old.seal(
        b"long lived evidence", tenant_id="acme", record_type="evidence", record_id="i"
    )
    assert sealed.key_id == "k1"

    rotated = EnvelopeCipher(StaticKeyProvider(keys=keys, active="k2"))
    rewrapped = rotated.rewrap(
        sealed, tenant_id="acme", record_type="evidence", record_id="i"
    )

    assert rewrapped.key_id == "k2"
    assert rewrapped.payload == sealed.payload, "the payload was re-encrypted"
    assert rewrapped.nonce == sealed.nonce
    assert rewrapped.wrapped_dek != sealed.wrapped_dek
    assert (
        rotated.open(rewrapped, tenant_id="acme", record_type="evidence", record_id="i")
        == b"long lived evidence"
    )


def test_records_sealed_before_a_rotation_stay_readable():
    """The most common way a key rotation destroys data.

    Retiring the old key id makes every record sealed with it unreadable. The
    provider must keep resolving old ids; only `current_key_id` moves.
    """
    keys = {"k1": secrets.token_bytes(KEY_BYTES), "k2": secrets.token_bytes(KEY_BYTES)}
    old = EnvelopeCipher(StaticKeyProvider(keys=keys, active="k1"))
    sealed = old.seal(b"older", tenant_id="acme", record_type="e", record_id="i")

    rotated = EnvelopeCipher(StaticKeyProvider(keys=keys, active="k2"))
    assert (
        rotated.open(sealed, tenant_id="acme", record_type="e", record_id="i") == b"older"
    )

    # And dropping k1 is what breaks it -- named explicitly so the failure is
    # recognisable if it ever happens in production.
    without = EnvelopeCipher(StaticKeyProvider(keys={"k2": keys["k2"]}, active="k2"))
    with pytest.raises(CryptoError) as caught:
        without.open(sealed, tenant_id="acme", record_type="e", record_id="i")
    assert "must remain resolvable" in str(caught.value)


def test_the_wire_format_survives_a_round_trip_through_a_text_column():
    cipher = EnvelopeCipher(_provider())
    wire = cipher.seal_json(
        {"prompt": "ignore previous instructions", "n": 7},
        tenant_id="acme",
        record_type="evidence",
        record_id="inc-9",
    )
    assert wire.isprintable() and " " not in wire
    restored = cipher.open_json(
        wire, tenant_id="acme", record_type="evidence", record_id="inc-9"
    )
    assert restored == {"prompt": "ignore previous instructions", "n": 7}


def test_a_short_key_is_refused_at_construction():
    with pytest.raises(CryptoError) as caught:
        StaticKeyProvider(keys={"k1": b"tooshort"}, active="k1")
    assert "AES-256" in str(caught.value)


def test_an_unknown_ciphertext_version_is_refused_rather_than_guessed():
    with pytest.raises(CryptoError) as caught:
        CipherText.from_wire("99.k1.AA.AA.AA.AA")
    assert "not supported" in str(caught.value)


def test_a_malformed_ciphertext_is_refused():
    for bad in ("", "1.k1", "not-a-ciphertext", "1.k1.!!!.AA.AA.AA"):
        with pytest.raises(CryptoError):
            CipherText.from_wire(bad)


def test_the_environment_provider_refuses_an_incomplete_configuration():
    key = base64.b64encode(secrets.token_bytes(KEY_BYTES)).decode()
    with pytest.raises(CryptoError) as caught:
        EnvironmentKeyProvider({})
    assert "no data keys configured" in str(caught.value)

    with pytest.raises(CryptoError) as caught:
        EnvironmentKeyProvider({"SENTINEL_DATA_KEY_K1": key})
    assert "SENTINEL_ACTIVE_KEY_ID" in str(caught.value)

    with pytest.raises(CryptoError) as caught:
        EnvironmentKeyProvider(
            {"SENTINEL_DATA_KEY_K1": "not base64!!", "SENTINEL_ACTIVE_KEY_ID": "k1"}
        )
    assert "base64" in str(caught.value)

    provider = EnvironmentKeyProvider(
        {"SENTINEL_DATA_KEY_K1": key, "SENTINEL_ACTIVE_KEY_ID": "k1"}
    )
    assert provider.current_key_id() == "k1"
    assert len(provider.key("k1")) == KEY_BYTES


# ── Audit chain ──────────────────────────────────────────────────────────────


@pytest.fixture
def audited(engine_config):
    database = build_engine(engine_config)
    migrate(database)
    with database.acquire() as conn:
        conn.begin()
        for tenant in (TENANT, OTHER):
            conn.execute_rowcount(
                f"INSERT INTO tenants (tenant_id, name, created_at) "
                f"VALUES ({conn.p},{conn.p},{conn.p})",
                (tenant.value, tenant.value, NOW.isoformat()),
            )
        conn.commit()
    yield database
    database.close()


def _write(database, tenant: TenantId, count: int, *, action: str = "incident.admit"):
    written = []
    with database.acquire() as conn:
        conn.begin()
        conn.set_tenant(tenant.value)
        log = AuditLog(conn, tenant)
        for i in range(count):
            written.append(
                log.record(
                    actor=f"user-{i % 3}",
                    action=action,
                    resource_type="incident",
                    resource_id=f"inc-{i:04d}",
                    outcome=Outcome.SUCCESS,
                    at=Timestamp(NOW.value + timedelta(seconds=i)),
                    detail={"index": i},
                )
            )
        conn.commit()
    return written


def test_entries_chain_to_their_predecessor(audited):
    written = _write(audited, TENANT, 5)
    assert written[0].prev_chain_hash == GENESIS
    for previous, entry in zip(written, written[1:]):
        assert entry.prev_chain_hash == previous.chain_hash
        assert entry.seq == previous.seq + 1


def test_a_freshly_written_chain_verifies(audited):
    _write(audited, TENANT, 12)
    with audited.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT.value)
        result = AuditLog(conn, TENANT).verify()
        conn.commit()
    assert result.intact, str(result)
    assert result.entries == 12


def test_editing_an_entry_breaks_the_chain(audited):
    """The property that makes this an audit log rather than a table.

    An administrator with UPDATE rights can change a row. What they cannot do is
    change it without the chain noticing.
    """
    _write(audited, TENANT, 6)
    with audited.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT.value)
        conn.execute_rowcount(
            f"UPDATE security_audit SET outcome='denied' WHERE tenant_id={conn.p} AND seq=3",
            (TENANT.value,),
        )
        conn.commit()

    with audited.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT.value)
        result = AuditLog(conn, TENANT).verify()
        conn.commit()

    assert not result.intact
    assert result.broken_at == 3
    assert "content altered" in result.reason


def test_deleting_an_entry_breaks_the_chain(audited):
    _write(audited, TENANT, 6)
    with audited.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT.value)
        conn.execute_rowcount(
            f"DELETE FROM security_audit WHERE tenant_id={conn.p} AND seq=4",
            (TENANT.value,),
        )
        conn.commit()

    with audited.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT.value)
        result = AuditLog(conn, TENANT).verify()
        conn.commit()

    assert not result.intact
    assert result.broken_at == 5
    assert "removed" in result.reason


def test_the_verifier_names_where_the_chain_broke(audited):
    """An actionable report, not an alarm.

    "The log is intact to 17 and diverges at 18" is something an operator can act
    on. "The log is broken" is not.
    """
    _write(audited, TENANT, 20)
    with audited.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT.value)
        conn.execute_rowcount(
            f"UPDATE security_audit SET actor='forged' WHERE tenant_id={conn.p} AND seq=18",
            (TENANT.value,),
        )
        conn.commit()
    with audited.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT.value)
        result = AuditLog(conn, TENANT).verify()
        conn.commit()
    assert result.broken_at == 18
    assert result.entries == 17, "entries counts what verified, not what exists"


def test_each_tenant_has_an_independent_chain(audited):
    _write(audited, TENANT, 4)
    _write(audited, OTHER, 7)
    for tenant, expected in ((TENANT, 4), (OTHER, 7)):
        with audited.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant.value)
            result = AuditLog(conn, tenant).verify()
            conn.commit()
        assert result.intact and result.entries == expected


def test_a_denied_action_is_recorded_as_carefully_as_a_success(audited):
    """"We were asked and said no" is what gets disputed later."""
    with audited.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT.value)
        entry = AuditLog(conn, TENANT).record(
            actor="analyst-7",
            action="approval.execute",
            resource_type="approval",
            resource_id="apr-1",
            outcome=Outcome.DENIED,
            at=NOW,
            detail={"reason": "insufficient role"},
        )
        conn.commit()
    assert entry.outcome is Outcome.DENIED
    assert entry.detail["reason"] == "insufficient role"


def test_entries_are_queryable_by_resource_and_by_actor(audited):
    _write(audited, TENANT, 9)
    with audited.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT.value)
        log = AuditLog(conn, TENANT)
        by_resource = log.for_resource(resource_type="incident", resource_id="inc-0003")
        by_actor = log.by_actor(actor="user-1")
        conn.commit()
    assert [e.resource_id for e in by_resource] == ["inc-0003"]
    assert by_actor and all(e.actor == "user-1" for e in by_actor)


def test_pagination_is_keyset_not_offset(audited):
    """OFFSET makes page N cost N pages, and an auditor reads every page."""
    _write(audited, TENANT, 25)
    seen: list[int] = []
    after = 0
    with audited.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT.value)
        log = AuditLog(conn, TENANT)
        while True:
            page = log.entries(limit=10, after_seq=after)
            if not page:
                break
            seen.extend(e.seq for e in page)
            after = page[-1].seq
        conn.commit()
    assert seen == list(range(1, 26))


def test_the_head_is_publishable_and_changes_with_every_entry(audited):
    """The head is what closes the gap a self-consistent chain leaves open.

    A chain proves internal consistency; someone with write access can truncate
    it and rebuild a valid chain over the remainder. Publishing the head
    externally is what makes that detectable, so the head must be stable to read
    and must move on every append.
    """
    with audited.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT.value)
        assert AuditLog(conn, TENANT).head() == GENESIS
        conn.commit()

    heads = []
    for _ in range(3):
        _write(audited, TENANT, 1)
        with audited.acquire() as conn:
            conn.begin()
            conn.set_tenant(TENANT.value)
            heads.append(AuditLog(conn, TENANT).head())
            conn.commit()
    assert len(set(heads)) == 3
    assert GENESIS not in heads


def test_canonicalisation_does_not_depend_on_dict_ordering(audited):
    """A chain that verifies only on the machine that wrote it is not a chain."""
    from sentinel.infrastructure.persistence.audit import AuditEntry

    first = AuditEntry(
        tenant_id=TENANT, seq=1, actor="a", action="x", resource_type="t",
        resource_id="r", outcome=Outcome.SUCCESS, occurred_at=NOW,
        detail={"alpha": 1, "beta": 2},
    )
    second = AuditEntry(
        tenant_id=TENANT, seq=1, actor="a", action="x", resource_type="t",
        resource_id="r", outcome=Outcome.SUCCESS, occurred_at=NOW,
        detail={"beta": 2, "alpha": 1},
    )
    assert first.canonical() == second.canonical()
    assert first.compute_chain_hash() == second.compute_chain_hash()


def test_the_audit_write_shares_the_transaction_it_describes(audited):
    """An audit entry for a rolled-back action must not exist.

    The whole reason `AuditLog` is constructed from the unit of work rather than
    injected independently: a log written in its own transaction records actions
    that never happened and misses ones that did.
    """
    with pytest.raises(RuntimeError):
        with audited.acquire() as conn:
            conn.begin()
            conn.set_tenant(TENANT.value)
            AuditLog(conn, TENANT).record(
                actor="a", action="doomed", resource_type="incident",
                resource_id="inc-x", outcome=Outcome.SUCCESS, at=NOW,
            )
            raise RuntimeError("the surrounding action failed")

    with audited.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT.value)
        result = AuditLog(conn, TENANT).verify()
        conn.commit()
    assert result.entries == 0, "an audit entry survived a rolled-back transaction"


def test_audit_log_and_live_service_writer_share_one_verifiable_chain(audited):
    """Both writers use the live table, canonicalization and advisory-lock key."""
    from types import SimpleNamespace

    from sentinel.infrastructure.security_audit import SqlSecurityAudit

    failures = []
    service = SqlSecurityAudit(
        pool=audited, clock=SimpleNamespace(now=lambda: NOW),
        logger=SimpleNamespace(error=lambda *args, **kwargs: failures.append(kwargs)),
    )
    for action in ("before", "after"):
        service.record(tenant=TENANT, actor="service", action=action,
                       resource_type="incident", resource_id="shared",
                       outcome=Outcome.SUCCESS, detail={"source": "live"})
        if action == "before":
            _write(audited, TENANT, 1)
    assert not failures
    with audited.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT.value)
        log = AuditLog(conn, TENANT)
        entries = log.entries()
        result = log.verify()
        conn.commit()
    assert [entry.action for entry in entries] == ["before", "incident.admit", "after"]
    assert result.intact and result.entries == 3
    assert entries[0].detail == {"source": "live"}
