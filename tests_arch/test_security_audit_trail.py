"""The audit trail, driven through real requests against a real database.

WHAT THIS IS CLOSING
--------------------
Before this, every authentication failure and authorisation denial was a structured
log line and nothing else. An attacker who obtained one valid credential left no
tamper-evident trace of what it was used for, because log lines are mutable,
unordered across replicas, and usually outside retention by the time anyone asks.

So these tests assert three things, in order of importance:

  1. the entries exist, written by an actual HTTP request rather than a unit call
  2. the chain detects tampering -- editing or deleting a row breaks verification
     and the break names the sequence number
  3. the entry does not contain the credential

The third is easy to get wrong in a way nobody notices: an audit trail that stores
the presented token is a credential store with worse access control.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from sentinel.composition.container import build_container
from sentinel.composition.settings import Settings
from sentinel.domain.primitives import TenantId
from sentinel.infrastructure.persistence.audit import GENESIS, Outcome
from sentinel.infrastructure.security_audit import NullSecurityAudit, SqlSecurityAudit
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.migrate import CURRENT_VERSION, migrate
from sentinel.interface.http import _UNKNOWN_TENANT as UNAUTHENTICATED
from sentinel.interface.http import create_app

INGEST_KEY = "i" * 40
ANALYST_KEY = "a" * 40
ADMIN_KEY = "d" * 40
TENANT = TenantId("acme")


@pytest.fixture
def app(tmp_path):
    settings = Settings.from_environment(
        {
            "SENTINEL_API_KEYS": (
                f"acme:{INGEST_KEY}:ingest,"
                f"acme:{ANALYST_KEY}:analyst,"
                f"acme:{ADMIN_KEY}:admin"
            ),
            "SENTINEL_DB_PATH": str(tmp_path / "audit.db"),
        }
    )
    pool = build_engine(settings.engine)
    migrate(pool)
    pool.close()
    container = build_container(settings)
    try:
        yield TestClient(create_app(container), raise_server_exceptions=False), container
    finally:
        container.close()


def _entries(container, tenant: str = "acme") -> list[dict]:
    with container.pool.acquire() as conn:
        conn.begin()
        conn.set_tenant(tenant)
        rows = conn.execute(
            f"SELECT * FROM security_audit WHERE tenant_id={conn.p} ORDER BY seq",
            (tenant,),
        )
        conn.commit()
    return [dict(row) for row in rows]


# ── The migration ────────────────────────────────────────────────────────────


def test_the_audit_table_is_part_of_the_live_schema(app):
    """It previously existed only in the parallel persistence package, where
    nothing the application runs could write to it."""
    _client, container = app
    with container.pool.acquire() as conn:
        conn.begin()
        conn.execute("SELECT COUNT(*) AS n FROM security_audit")
        conn.commit()
    assert CURRENT_VERSION >= 6, "the audit migration is not in the ordered list"


def test_the_audit_table_is_tenant_protected():
    """A tenant reading another's security history is the worst instance of a
    cross-tenant read, so the table must be in the RLS set rather than merely
    filtered in application SQL."""
    from sentinel.infrastructure.sql.schema import PROTECTED_TABLES

    assert "security_audit" in PROTECTED_TABLES


# ── Entries are written by real requests ─────────────────────────────────────


def test_an_authorization_denial_is_recorded_durably(app):
    """The proven privilege attempt from F-2, now leaving a trace."""
    client, container = app
    response = client.post(
        "/v1/events",
        headers={"Authorization": f"Bearer {ANALYST_KEY}"},
        json={"agentId": "forged", "action": "x"},
    )
    assert response.status_code == 403

    entries = _entries(container)
    assert len(entries) == 1, entries
    entry = entries[0]
    assert entry["outcome"] == Outcome.DENIED.value
    assert entry["resource_type"] == "capability"
    assert entry["resource_id"] == "ingest_event"
    assert entry["actor"].startswith("key:")
    detail = json.loads(entry["detail"])
    assert detail["role"] == "analyst"
    assert detail["reason"] == "capability_not_held"


def test_an_unrecognised_credential_is_recorded(app):
    """Credential brute force is only visible if each attempt is durable."""
    client, container = app
    assert client.get(
        "/v1/incidents", headers={"Authorization": "Bearer " + "z" * 40}
    ).status_code == 401

    entries = _entries(container, tenant=UNAUTHENTICATED)
    assert len(entries) == 1
    assert entries[0]["outcome"] == Outcome.DENIED.value
    assert entries[0]["actor"].startswith("unknown:")
    assert json.loads(entries[0]["detail"])["reason"] == "unrecognised_credential"


def test_a_missing_credential_is_recorded(app):
    client, container = app
    assert client.get("/v1/incidents").status_code == 401
    entries = _entries(container, tenant=UNAUTHENTICATED)
    assert json.loads(entries[0]["detail"])["reason"] == "missing_bearer_token"


def test_unauthenticated_attempts_do_not_pollute_a_real_tenants_chain(app):
    """Otherwise anyone with network access can write into the audit trail of a
    tenant they cannot otherwise touch, and a tenant's own chain becomes
    attacker-influenced."""
    client, container = app
    for _ in range(3):
        client.get("/v1/incidents", headers={"Authorization": "Bearer " + "q" * 40})
    assert _entries(container, tenant="acme") == []
    assert len(_entries(container, tenant=UNAUTHENTICATED)) == 3


def test_an_approval_decision_is_recorded_whether_it_succeeds_or_not(app):
    """"Who approved this remediation" is the question asked months later."""
    client, container = app
    client.post(
        "/v1/approvals/apr-does-not-exist",
        headers={"Authorization": f"Bearer {ANALYST_KEY}"},
        json={"decision": "approve"},
    )
    entries = [e for e in _entries(container) if e["resource_type"] == "approval"]
    assert len(entries) == 1
    assert entries[0]["action"] == "approval.approve"
    assert entries[0]["resource_id"] == "apr-does-not-exist"


def test_a_successful_request_is_not_audited_as_a_denial(app):
    """Auditing every read would bury the denials in noise; the trail exists to
    make refusals and effects findable, not to mirror the access log."""
    client, container = app
    assert client.get(
        "/v1/incidents", headers={"Authorization": f"Bearer {ANALYST_KEY}"}
    ).status_code == 200
    assert _entries(container) == []


# ── The credential must not be in the trail ──────────────────────────────────


def test_no_entry_contains_the_presented_credential(app):
    """An audit trail that stores the credential is a credential store."""
    client, container = app
    client.get("/v1/incidents", headers={"Authorization": f"Bearer {INGEST_KEY}"})
    client.get("/v1/incidents", headers={"Authorization": "Bearer " + "z" * 40})

    everything = json.dumps(
        _entries(container) + _entries(container, tenant=UNAUTHENTICATED)
    )
    for secret in (INGEST_KEY, ANALYST_KEY, ADMIN_KEY, "z" * 40):
        assert secret not in everything, "a credential reached the audit trail"


def test_the_actor_prefix_is_short_enough_to_be_unusable(app):
    """Long enough to correlate every action by one credential across thousands of
    requests; too short to authenticate with."""
    client, container = app
    client.get("/v1/incidents", headers={"Authorization": "Bearer " + "z" * 40})
    actor = _entries(container, tenant=UNAUTHENTICATED)[0]["actor"]
    digest_part = actor.split(":", 1)[1]
    assert len(digest_part) == 12


# ── The chain ────────────────────────────────────────────────────────────────


def test_the_first_entry_chains_from_genesis(app):
    client, container = app
    client.get("/v1/incidents", headers={"Authorization": "Bearer " + "z" * 40})
    assert _entries(container, tenant=UNAUTHENTICATED)[0]["prev_chain_hash"] == GENESIS


def test_each_entry_chains_to_the_previous_one(app):
    client, container = app
    for _ in range(4):
        client.post(
            "/v1/events",
            headers={"Authorization": f"Bearer {ANALYST_KEY}"},
            json={"agentId": "forged", "action": "x"},
        )
    entries = _entries(container)
    assert len(entries) == 4
    assert [e["seq"] for e in entries] == [1, 2, 3, 4], "seq must be dense"
    for previous, current in zip(entries, entries[1:]):
        assert current["prev_chain_hash"] == previous["chain_hash"]


def test_editing_an_entry_breaks_the_chain(app):
    """The property that makes this an audit trail rather than a table.

    Verified by recomputing, because a stored hash that is never checked is
    decoration.
    """
    client, container = app
    for _ in range(3):
        client.post(
            "/v1/events",
            headers={"Authorization": f"Bearer {ANALYST_KEY}"},
            json={"agentId": "forged", "action": "x"},
        )

    with container.pool.acquire() as conn:
        conn.begin()
        conn.set_tenant("acme")
        conn.execute_rowcount(
            f"UPDATE security_audit SET outcome={conn.p} WHERE seq={conn.p}",
            (Outcome.SUCCESS.value, 2),
        )
        conn.commit()

    assert _recompute(_entries(container)) == 2, (
        "editing entry 2 did not break verification at entry 2"
    )


def test_deleting_an_entry_is_detectable_as_a_gap(app):
    """Dense `seq` is what makes removal visible. A sparse or shared sequence
    would make a deleted row indistinguishable from one that never existed."""
    client, container = app
    for _ in range(3):
        client.post(
            "/v1/events",
            headers={"Authorization": f"Bearer {ANALYST_KEY}"},
            json={"agentId": "forged", "action": "x"},
        )
    with container.pool.acquire() as conn:
        conn.begin()
        conn.set_tenant("acme")
        conn.execute_rowcount(f"DELETE FROM security_audit WHERE seq={conn.p}", (2,))
        conn.commit()

    sequences = [e["seq"] for e in _entries(container)]
    assert sequences == [1, 3]
    assert sequences != list(range(1, len(sequences) + 1)), "the gap is invisible"


def _recompute(entries: list[dict]) -> int | None:
    """Return the seq of the first entry whose stored hash does not match, or None."""
    from sentinel.domain.primitives import Timestamp
    from sentinel.infrastructure.persistence.audit import AuditEntry

    previous = GENESIS
    for row in entries:
        rebuilt = AuditEntry(
            tenant_id=TenantId(row["tenant_id"]),
            seq=int(row["seq"]),
            actor=row["actor"],
            action=row["action"],
            resource_type=row["resource_type"],
            resource_id=row["resource_id"],
            outcome=Outcome(row["outcome"]),
            occurred_at=Timestamp.parse(row["occurred_at"]),
            detail=json.loads(row["detail"]),
            prev_chain_hash=previous,
        )
        if rebuilt.compute_chain_hash() != row["chain_hash"]:
            return int(row["seq"])
        previous = row["chain_hash"]
    return None


def test_an_untampered_chain_verifies_clean(app):
    """The negative control. Without it, a verifier that always reports tampering
    would pass every test above."""
    client, container = app
    for _ in range(3):
        client.post(
            "/v1/events",
            headers={"Authorization": f"Bearer {ANALYST_KEY}"},
            json={"agentId": "forged", "action": "x"},
        )
    assert _recompute(_entries(container)) is None


# ── Failure policy ───────────────────────────────────────────────────────────


class _BrokenPool:
    """A pool whose every checkout fails, standing in for a database outage."""

    def acquire(self):
        raise RuntimeError("audit table is on fire")


class _Recorder:
    def __init__(self) -> None:
        self.errors: list[tuple[str, dict]] = []

    def error(self, event: str, /, **fields) -> None:
        self.errors.append((event, fields))


def test_an_audit_write_failure_does_not_break_the_request(tmp_path):
    """Deliberate, and the weaker half of the design.

    An authentication denial that cannot be audited is still a denial, and refusing
    the request twice helps nobody. Failing the request instead would turn a
    logging outage into a total outage of a security service -- the more likely
    event and the worse one. The dense `seq` is what makes the resulting gap
    detectable afterwards.

    Injected through `build_container` rather than patched: `SqlSecurityAudit` uses
    `__slots__`, so its internals are not reassignable -- which is the design
    working, not an obstacle to route around.
    """
    settings = Settings.from_environment(
        {
            "SENTINEL_API_KEYS": f"acme:{ANALYST_KEY}:analyst",
            "SENTINEL_DB_PATH": str(tmp_path / "broken.db"),
        }
    )
    pool = build_engine(settings.engine)
    migrate(pool)
    pool.close()
    recorder = _Recorder()
    container = build_container(
        settings,
        security_audit=SqlSecurityAudit(
            pool=_BrokenPool(), clock=None, logger=recorder
        ),
    )
    try:
        client = TestClient(create_app(container), raise_server_exceptions=False)
        response = client.post(
            "/v1/events",
            headers={"Authorization": f"Bearer {ANALYST_KEY}"},
            json={"agentId": "forged", "action": "x"},
        )
        assert response.status_code == 403, "the original outcome must stand"
        # And the failure must be loud: this is the condition under which an
        # attacker can act unaudited.
        assert recorder.errors, "an audit write failed silently"
        assert recorder.errors[0][0] == "security_audit_write_failed"
        assert recorder.errors[0][1]["audited_outcome"] == "denied"
    finally:
        container.close()


def test_record_never_raises_whatever_the_backend_does():
    """The port's contract. A caller must never need a try/except around auditing,
    because the one place it would be forgotten is an error path."""
    audit = SqlSecurityAudit(pool=_BrokenPool(), clock=None, logger=_Recorder())
    audit.record(
        tenant=TENANT,
        actor="key:abc",
        action="test",
        resource_type="x",
        resource_id="y",
        outcome=Outcome.DENIED,
    )


def test_the_null_audit_is_explicit_rather_than_none():
    """A conditional around a security control is how the control gets skipped."""
    audit = NullSecurityAudit()
    audit.record(tenant=TENANT, actor="a", action="b", resource_type="c",
                 resource_id="d", outcome=Outcome.DENIED)


def test_the_adapter_satisfies_the_port():
    from sentinel.application.ports import SecurityAudit

    assert isinstance(NullSecurityAudit(), SecurityAudit)
    assert isinstance(
        SqlSecurityAudit(pool=None, clock=None, logger=None), SecurityAudit
    )
