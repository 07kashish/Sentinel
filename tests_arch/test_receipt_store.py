"""Receipts that survive, so the diff is a query rather than a return value.

WHY THIS EXISTS
---------------
`execute_bound` returned a receipt and nothing kept it. That is enough to hand
to a caller and not enough to answer "show me every execution this week whose
parameters differed from what was approved" -- which is the question the
binding was built for.

TWO PROPERTIES CARRY THE FILE
-----------------------------
Append-only, asserted structurally: there is no `update` and no `delete` on the
class, and `record` REFUSES a different receipt at an existing id rather than
overwriting. Two receipts for one execution is either a bug or somebody
rewriting what ran, and picking one resolves neither.

And the mismatch query must not count UNBOUND executions. An unbound execution
has no approved digest, so a naive `approved <> actual` reports every one of
them as a substitution -- and the mismatch count would then be dominated by
executions nobody ever claimed to have bound.

Parametrised over BOTH engines, per the fitness rule. That rule exists because
the retention sweep once passed on SQLite while deleting nothing on PostgreSQL.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from sentinel.domain.execution_binding import ExecutionReceipt, parameter_digest
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.infrastructure.sql.receipt_store import (
    ReceiptConflict,
    SqlReceiptStore,
)

TENANT = "acme"
OTHER = "globex"

APPROVED = {"bucket": "acme-reports", "key": "q3/summary.pdf"}
SUBSTITUTED = {"bucket": "attacker-exfil", "key": "q3/summary.pdf"}


@pytest.fixture
def store(engine_config):
    pool = build_engine(engine_config)
    migrate(pool)
    try:
        yield SqlReceiptStore(pool=pool)
    finally:
        pool.close()


def _receipt(**overrides) -> ExecutionReceipt:
    defaults = dict(
        receipt_id="receipt-1",
        tenant_id=TENANT,
        authorization_digest="a" * 64,
        executed_request_digest="b" * 64,
        actual_parameter_digest=parameter_digest(APPROVED),
        execution_identity="worker:1",
        started_at="2026-09-04T12:00:00+00:00",
        completed_at="2026-09-04T12:00:01+00:00",
        outcome="succeeded",
    )
    defaults.update(overrides)
    return ExecutionReceipt(**defaults)  # type: ignore[arg-type]


# ── it stores and returns what it was given ───────────────────────────────


def test_a_recorded_receipt_comes_back(store):
    """The anchor. Every assertion below is meaningless if nothing persists."""
    store.record(
        TENANT,
        receipt=_receipt(),
        approved_parameter_digest=parameter_digest(APPROVED),
        authorization_id="auth-1",
    )

    row = store.get(TENANT, "receipt-1")

    assert row is not None
    assert row["authorization_id"] == "auth-1"
    assert row["approved_parameter_digest"] == parameter_digest(APPROVED)
    assert row["actual_parameter_digest"] == parameter_digest(APPROVED)
    assert row["outcome"] == "succeeded"


def test_an_absent_receipt_is_none_rather_than_an_error(store):
    assert store.get(TENANT, "never-recorded") is None


def test_the_json_columns_round_trip(store):
    store.record(
        TENANT,
        receipt=_receipt(bounded_mutations=("request_id",)),
        differing_keys=["bucket"],
        defects=["parameters_differ"],
    )

    row = store.get(TENANT, "receipt-1")

    assert row["differing_keys"] == ["bucket"]
    assert row["bounded_mutations"] == ["request_id"]
    assert row["defects"] == ["parameters_differ"]


def test_a_corrupted_json_column_does_not_lose_the_receipt(store):
    """The digests are the evidence. Losing a whole record to protect a hint
    would be the wrong trade.
    """
    store.record(TENANT, receipt=_receipt(), differing_keys=["bucket"])
    with store.pool.acquire() as conn:
        p = conn.p
        conn.begin()
        conn.set_tenant(TENANT)
        conn.execute_rowcount(
            f"UPDATE execution_receipts SET differing_keys='not json' "
            f"WHERE tenant_id={p} AND receipt_id={p}",
            (TENANT, "receipt-1"),
        )
        conn.commit()

    row = store.get(TENANT, "receipt-1")

    assert row is not None
    assert row["differing_keys"] == []
    assert row["actual_parameter_digest"] == parameter_digest(APPROVED)


# ── append-only ───────────────────────────────────────────────────────────


def test_the_store_has_no_update_or_delete():
    """Structural. A receipt is a record of something that happened; a store
    that could edit one is a store whose contents are an opinion.
    """
    for forbidden in ("update", "delete", "remove", "purge", "overwrite"):
        assert not hasattr(SqlReceiptStore, forbidden), forbidden


def test_recording_an_identical_receipt_twice_is_a_no_op(store):
    """A retry is not an error. Without this, an at-least-once delivery would
    turn every redelivery into a conflict.
    """
    for _ in range(2):
        store.record(
            TENANT,
            receipt=_receipt(),
            approved_parameter_digest=parameter_digest(APPROVED),
            authorization_id="auth-1",
        )

    assert len(store.recent(TENANT)) == 1


def test_a_different_receipt_at_the_same_id_is_refused(store):
    """Two receipts for one execution is either a bug or a rewrite of what
    ran, and picking one resolves neither.
    """
    store.record(TENANT, receipt=_receipt(), approved_parameter_digest="a" * 64)

    with pytest.raises(ReceiptConflict) as raised:
        store.record(
            TENANT,
            receipt=_receipt(outcome="failed"),
            approved_parameter_digest="a" * 64,
        )

    assert "differs in" in str(raised.value)
    assert "outcome" in str(raised.value)
    # And the original survives.
    assert store.get(TENANT, "receipt-1")["outcome"] == "succeeded"


def test_a_conflict_is_not_retryable():
    assert ReceiptConflict.is_retryable is False


# ── the mismatch query is the point ───────────────────────────────────────


def test_a_substituted_execution_is_reported_as_mismatched(store):
    store.record(
        TENANT,
        receipt=_receipt(
            receipt_id="bad",
            actual_parameter_digest=parameter_digest(SUBSTITUTED),
        ),
        approved_parameter_digest=parameter_digest(APPROVED),
        differing_keys=["bucket"],
        defects=["parameters_differ"],
    )

    mismatched = store.mismatched(TENANT)

    assert [row["receipt_id"] for row in mismatched] == ["bad"]
    assert mismatched[0]["differing_keys"] == ["bucket"]


def test_a_matching_execution_is_not_reported_as_mismatched(store):
    """The negative control. Without it, a query returning everything would
    satisfy the test above.
    """
    store.record(
        TENANT,
        receipt=_receipt(receipt_id="good"),
        approved_parameter_digest=parameter_digest(APPROVED),
    )

    assert store.mismatched(TENANT) == []
    assert len(store.recent(TENANT)) == 1


def test_a_receipt_with_no_approved_digest_is_not_counted_as_a_mismatch(store):
    """THE query bug this guards. A receipt recorded WITHOUT an approved digest
    has nothing to compare against, so a naive `approved <> actual` reports it
    as a substitution -- and the mismatch count would then be dominated by
    receipts nobody supplied a left-hand side for.
    """
    store.record(
        TENANT,
        receipt=_receipt(receipt_id="incomparable"),
        approved_parameter_digest="",
    )
    # And one that IS bound and mismatched, so the query is not simply empty.
    store.record(
        TENANT,
        receipt=_receipt(
            receipt_id="bound-bad",
            actual_parameter_digest=parameter_digest(SUBSTITUTED),
        ),
        approved_parameter_digest=parameter_digest(APPROVED),
    )

    mismatched = store.mismatched(TENANT)

    assert [row["receipt_id"] for row in mismatched] == ["bound-bad"]


def test_coverage_reports_its_own_blindness(store):
    """The design error a test caught, kept as a test.

    The first version of `coverage` returned a bound-versus-unbound ratio over
    these rows. But `ExecutionReceipt` REQUIRES a valid authorization digest,
    and the unbound `execute` path returns no receipt at all -- so every row
    here is bound by construction and the ratio was always 1.0. A metric that
    can only report perfect coverage is worse than no metric.

    What it reports now is the count, how many are COMPARABLE, and the fact
    that an unbound execution leaves no trace in this table at all.
    """
    empty = store.coverage(TENANT)
    assert empty["receipts"] == 0
    assert "produces NO receipt" in empty["blindness"]

    store.record(
        TENANT, receipt=_receipt(receipt_id="a"), approved_parameter_digest="a" * 64
    )
    store.record(
        TENANT, receipt=_receipt(receipt_id="b"), approved_parameter_digest=""
    )

    coverage = store.coverage(TENANT)

    assert coverage["receipts"] == 2
    assert coverage["comparable"] == 1
    assert coverage["not_comparable"] == 1


def test_coverage_never_claims_to_see_unbound_executions(store):
    """Asserted directly, because the tempting fix for the above would be to
    keep a `bound_fraction` that is structurally always 1.0.
    """
    coverage = store.coverage(TENANT)

    assert "bound_fraction" not in coverage
    assert "unbound" not in coverage


# ── ordering ──────────────────────────────────────────────────────────────


def test_recent_returns_newest_first(store):
    for index, moment in enumerate(
        ("12:00:01", "12:00:03", "12:00:02"), start=1
    ):
        store.record(
            TENANT,
            receipt=_receipt(
                receipt_id=f"r{index}",
                completed_at=f"2026-09-04T{moment}+00:00",
            ),
            approved_parameter_digest="a" * 64,
        )

    assert [row["receipt_id"] for row in store.recent(TENANT)] == ["r2", "r3", "r1"]


def test_a_tie_on_the_timestamp_is_broken_deterministically(store):
    """Two receipts completing in the same second would otherwise come back in
    whatever order the engine chose, and a paginating console would show one
    twice and skip another.
    """
    for name in ("r1", "r2", "r3"):
        store.record(
            TENANT,
            receipt=_receipt(receipt_id=name),
            approved_parameter_digest="a" * 64,
        )

    first = [row["receipt_id"] for row in store.recent(TENANT)]
    second = [row["receipt_id"] for row in store.recent(TENANT)]

    assert first == second == ["r3", "r2", "r1"]


def test_the_limit_is_honoured(store):
    for index in range(5):
        store.record(
            TENANT,
            receipt=_receipt(receipt_id=f"r{index}"),
            approved_parameter_digest="a" * 64,
        )

    assert len(store.recent(TENANT, limit=2)) == 2


# ── tenancy ───────────────────────────────────────────────────────────────


def test_one_tenants_receipts_are_not_visible_to_another(store):
    store.record(
        TENANT, receipt=_receipt(receipt_id="mine"), approved_parameter_digest="a" * 64
    )
    store.record(
        OTHER,
        receipt=replace(_receipt(receipt_id="theirs"), tenant_id=OTHER),
        approved_parameter_digest="a" * 64,
    )

    assert [row["receipt_id"] for row in store.recent(TENANT)] == ["mine"]
    assert [row["receipt_id"] for row in store.recent(OTHER)] == ["theirs"]
    assert store.get(TENANT, "theirs") is None


def test_the_same_receipt_id_can_exist_under_two_tenants(store):
    """The primary key is (tenant_id, receipt_id). A global id space would
    make one tenant's receipt id collide with another's, and the conflict
    check would then report a rewrite that never happened.
    """
    store.record(
        TENANT, receipt=_receipt(), approved_parameter_digest="a" * 64
    )
    store.record(
        OTHER,
        receipt=replace(_receipt(), tenant_id=OTHER, outcome="failed"),
        approved_parameter_digest="a" * 64,
    )

    assert store.get(TENANT, "receipt-1")["outcome"] == "succeeded"
    assert store.get(OTHER, "receipt-1")["outcome"] == "failed"


def test_the_table_is_protected_by_row_level_security():
    """Registered in PROTECTED_TABLES, so the audited RLS loop covers it. A
    cross-tenant write here would let one tenant fabricate another's record of
    a substituted execution -- the record the whole binding exists to produce.
    """
    from sentinel.infrastructure.sql.schema import PROTECTED_TABLES

    assert "execution_receipts" in PROTECTED_TABLES
