"""Durable execution receipts, so the approved-versus-executed diff is a query.

WHY A RECEIPT NEEDS STORAGE
---------------------------
`execute_bound` returns a receipt, which is enough to hand to its caller and
not enough to answer "show me every execution this week whose parameters
differed from what was approved". That question is the reason the binding
exists, and answering it needs the receipts to still be there.

WHY THIS TABLE IS APPEND-ONLY, LIKE THE TRANSPARENCY LOG
---------------------------------------------------------
`(tenant_id, receipt_id)` is the primary key and there is no `update` and no
`delete` method on this class. A receipt is a record of something that
happened; a store that could edit one is a store whose contents are an opinion.
`record` is idempotent for an IDENTICAL receipt and REFUSES a different one at
the same id, because two receipts for one execution is either a bug or somebody
rewriting what ran.

WHY THE APPROVED DIGEST IS STORED SEPARATELY FROM THE ACTUAL ONE
-----------------------------------------------------------------
`ExecutionReceipt` carries only the actual parameter digest -- it is a record
of what ran. The diff needs both, so the approved digest is stored alongside
from the authorization. Deriving it later by looking up the authorization would
work until an authorization was expired out, at which point the historical diff
would silently lose its left-hand side.

WHAT IS NOT STORED
------------------
Parameter VALUES. `differing_keys` names which keys differed and nothing else,
for the reason `binding_routes.py` gives: this row is read by a console, cached
by a browser and pasted into tickets, and a table holding both sets of
parameters would be the most sensitive one in the product.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from sentinel.domain.errors import DomainRuleViolated
from sentinel.infrastructure.sql.engine import ConnectionPool

__all__ = ["ReceiptConflict", "SqlReceiptStore"]


class ReceiptConflict(DomainRuleViolated):
    """A different receipt already exists at this id.

    Not retryable. Two receipts for one execution is either a bug in the
    caller or an attempt to rewrite what ran, and the correct response to both
    is to stop rather than to pick one.
    """

    is_retryable = False


#: The columns, in one place, so `record` and `_row` cannot drift apart. A
#: mismatch between an INSERT's column list and a SELECT's field order is the
#: classic way a store starts returning one field's value under another's name.
_COLUMNS: tuple[str, ...] = (
    "receipt_id",
    "authorization_id",
    "authorization_digest",
    "executed_request_digest",
    "approved_parameter_digest",
    "actual_parameter_digest",
    "delegation_passport_digest",
    "differing_keys",
    "bounded_mutations",
    "defects",
    "execution_identity",
    "side_effect",
    "outcome",
    "started_at",
    "completed_at",
)

#: The joined forms, computed ONCE at import. Interpolating
#: `", ".join(_COLUMNS)` inside each query would put a call inside a SQL
#: string, and `test_sql_is_never_built_from_data.py` is right to object: an
#: allowlist entry for a call is weaker than one for a constant, because a call
#: can be given a different argument. These cannot.
_COLUMN_LIST: str = ", ".join(_COLUMNS)
_INSERT_COLUMNS: tuple[str, ...] = ("tenant_id",) + _COLUMNS
_INSERT_COLUMN_LIST: str = ", ".join(_INSERT_COLUMNS)

#: Stored as JSON text rather than in a side table. A receipt's lists are
#: short, read together with the row, and never queried by element -- so a
#: join would buy nothing and cost a second table's RLS policy.
_JSON_COLUMNS: frozenset[str] = frozenset({
    "differing_keys",
    "bounded_mutations",
    "defects",
})


@dataclass(frozen=True, slots=True)
class SqlReceiptStore:
    """Append-only receipt storage, scoped to a tenant by RLS.

    Frozen and holding only a pool: nothing here is per-request state, so one
    store is safe to share.
    """

    pool: ConnectionPool

    def record(
        self,
        tenant: str,
        *,
        receipt: Any,
        approved_parameter_digest: str = "",
        authorization_id: str = "",
        delegation_passport_digest: str = "",
        differing_keys: Sequence[str] = (),
        defects: Sequence[str] = (),
    ) -> None:
        """Store one receipt. Idempotent for an identical one.

        `approved_parameter_digest` is passed in rather than read off the
        receipt, because a receipt records what RAN. Storing it here means a
        historical diff keeps its left-hand side after the authorization it
        came from has been expired out.
        """
        values = {
            "receipt_id": receipt.receipt_id,
            "authorization_id": authorization_id,
            "authorization_digest": receipt.authorization_digest,
            "executed_request_digest": receipt.executed_request_digest,
            "approved_parameter_digest": approved_parameter_digest,
            "actual_parameter_digest": receipt.actual_parameter_digest,
            "delegation_passport_digest": delegation_passport_digest,
            "differing_keys": json.dumps(list(differing_keys)),
            "bounded_mutations": json.dumps(list(receipt.bounded_mutations)),
            "defects": json.dumps(list(defects)),
            "execution_identity": receipt.execution_identity,
            "side_effect": receipt.side_effect,
            "outcome": receipt.outcome,
            "started_at": receipt.started_at,
            "completed_at": receipt.completed_at,
        }

        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)

            existing = conn.execute(
                f"SELECT {_COLUMN_LIST} FROM execution_receipts "
                f"WHERE tenant_id={p} AND receipt_id={p}",
                (tenant, receipt.receipt_id),
            )
            if existing:
                current = dict(existing[0])
                differing = [
                    column
                    for column in _COLUMNS
                    if str(current.get(column, "")) != str(values[column])
                ]
                conn.commit()
                if differing:
                    raise ReceiptConflict(
                        f"receipt {receipt.receipt_id!r} already exists for "
                        f"tenant {tenant!r} and differs in "
                        f"{', '.join(differing)}. Two receipts for one "
                        "execution is either a bug or a rewrite of what ran, "
                        "and neither is resolved by picking one."
                    )
                # Identical: a retry, which is not an error.
                return

            placeholders = ", ".join([p] * len(_INSERT_COLUMNS))
            conn.execute_rowcount(
                f"INSERT INTO execution_receipts ({_INSERT_COLUMN_LIST}) "
                f"VALUES ({placeholders})",
                (tenant,) + tuple(values[column] for column in _COLUMNS),
            )
            conn.commit()

    def get(self, tenant: str, receipt_id: str) -> dict[str, Any] | None:
        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)
            rows = conn.execute(
                f"SELECT {_COLUMN_LIST} FROM execution_receipts "
                f"WHERE tenant_id={p} AND receipt_id={p}",
                (tenant, receipt_id),
            )
            conn.commit()
        return self._row(rows[0]) if rows else None

    def recent(self, tenant: str, *, limit: int = 100) -> list[dict[str, Any]]:
        """The most recent receipts, newest first.

        Ordered by `completed_at` and then by `receipt_id`. The tiebreak is not
        decoration: two receipts completing in the same second would otherwise
        come back in whatever order the engine chose, and a paginating console
        would show one twice and skip another.
        """
        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)
            rows = conn.execute(
                f"SELECT {_COLUMN_LIST} FROM execution_receipts "
                f"WHERE tenant_id={p} "
                f"ORDER BY completed_at DESC, receipt_id DESC LIMIT {p}",
                (tenant, int(limit)),
            )
            conn.commit()
        return [self._row(row) for row in rows]

    def mismatched(self, tenant: str, *, limit: int = 100) -> list[dict[str, Any]]:
        """Only the executions whose parameters differed from what was approved.

        A BOUND receipt whose two digests disagree. The `authorization_digest
        <> ''` clause matters: an unbound execution has no approved digest, so
        without it every unbound row would look like a mismatch and the count
        would be dominated by executions nobody claimed to have bound.
        """
        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)
            rows = conn.execute(
                f"SELECT {_COLUMN_LIST} FROM execution_receipts "
                f"WHERE tenant_id={p} "
                "AND authorization_digest <> '' "
                "AND approved_parameter_digest <> '' "
                "AND approved_parameter_digest <> actual_parameter_digest "
                f"ORDER BY completed_at DESC, receipt_id DESC LIMIT {p}",
                (tenant, int(limit)),
            )
            conn.commit()
        return [self._row(row) for row in rows]

    def coverage(self, tenant: str, *, limit: int = 500) -> dict[str, Any]:
        """How many receipts exist, and the blindness that comes with that.

        THIS STORE CANNOT SEE AN UNBOUND EXECUTION, and that is the important
        part. `ProtectedToolRunner.execute` -- the unbound path -- returns no
        receipt, so an unbound execution leaves no row here at all. There is no
        bound-versus-unbound ratio to compute from this table.

        The first version of this method returned exactly that ratio, counting
        rows with a non-empty `authorization_digest` against the rest. A test
        caught it: `ExecutionReceipt` REQUIRES a valid digest, so every row is
        bound by construction and the ratio was always 1.0 -- a metric that
        could only ever report perfect coverage.
        """
        rows = self.recent(tenant, limit=limit)
        with_approval = sum(1 for row in rows if row["approved_parameter_digest"])
        return {
            "receipts": len(rows),
            # A receipt recorded without an approved digest cannot be compared,
            # so it is counted separately rather than folded into either side.
            "comparable": with_approval,
            "not_comparable": len(rows) - with_approval,
            "blindness": (
                "An unbound execution produces NO receipt, so it does not "
                "appear here. A low receipt count may mean low binding "
                "adoption rather than low activity, and this store cannot "
                "tell the two apart -- set "
                "SENTINEL_REQUIRE_EXECUTION_BINDING to remove the ambiguity."
            ),
        }

    @staticmethod
    def _row(row: Mapping[str, Any]) -> dict[str, Any]:
        """One row, with its JSON columns decoded.

        A malformed JSON column decodes to an empty list rather than raising.
        The row's digests are the evidence; a corrupted `differing_keys` should
        not make the receipt unreadable, and losing the whole record to protect
        a hint would be the wrong trade.
        """
        decoded: dict[str, Any] = {}
        for column in _COLUMNS:
            value = row.get(column)
            if column in _JSON_COLUMNS:
                try:
                    parsed = json.loads(value) if value else []
                except (json.JSONDecodeError, TypeError):
                    parsed = []
                decoded[column] = parsed if isinstance(parsed, list) else []
            else:
                decoded[column] = "" if value is None else value
        return decoded
