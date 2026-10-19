"""Commit execution receipts to the transparency log, exactly once each.

WHY THIS EXISTS
---------------
The log, its proofs and its published roots were all served -- and nothing in
the running service ever appended to it. A receipt that is not a leaf is a row
in a database its operator controls, and the word "evidence" does not apply.

A receipt's LEAF is the SHA-256 of its canonical JSON (sorted keys, no
whitespace, UTF-8) over exactly the stored fields, so a holder of the receipt
can recompute it with nothing from Sentinel. The leaf and the commitment row
are written in ONE transaction: either both exist or neither, so a crash
between them cannot produce a second leaf for the same receipt on retry. Two
replicas racing for a sequence collide on the primary key; the loser rolls
back and the receipt is committed on the next pass.

Commitment is asynchronous on purpose. The receipt write is already on the
path that decides whether an outcome is known; adding a second store to that
path would turn a log hiccup into an unknown outcome. The cost is a window in
which a receipt exists and is not yet committed, and `pending` reports its size.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

from sentinel.infrastructure.sql.engine import ConnectionPool

__all__ = ["RECEIPT_FIELDS", "SqlEvidenceCommitments", "receipt_leaf"]

#: The fields a leaf commits to, in the receipt's stored spelling. Adding a
#: field here changes every future leaf and no past one; never reorder or
#: remove, because a verifier recomputes leaves from this list.
RECEIPT_FIELDS: tuple[str, ...] = (
    "receipt_id", "authorization_id", "authorization_digest", "executed_request_digest",
    "approved_parameter_digest", "actual_parameter_digest", "delegation_passport_digest",
    "execution_identity", "side_effect", "outcome", "started_at", "completed_at",
)
_COLUMN_LIST = ", ".join(RECEIPT_FIELDS)


def receipt_leaf(tenant_id: str, receipt: Mapping[str, Any]) -> bytes:
    """The 32-byte leaf for one receipt. Pure, and reproducible offline."""
    material = {"tenant_id": tenant_id, **{f: str(receipt.get(f, "") or "") for f in RECEIPT_FIELDS}}
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).digest()


@dataclass(frozen=True, slots=True)
class SqlEvidenceCommitments:
    pool: ConnectionPool

    def pending(self, tenant: str) -> int:
        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)
            row = conn.one(
                "SELECT COUNT(*) AS n FROM execution_receipts r WHERE r.tenant_id=" + p + " AND NOT EXISTS "
                "(SELECT 1 FROM evidence_commitments c WHERE c.tenant_id=r.tenant_id AND c.receipt_id=r.receipt_id)",
                (tenant,),
            )
            conn.commit()
        return int(row["n"]) if row else 0

    def commit_pending(self, tenant: str, *, at: str, limit: int = 200) -> int:
        """Commit up to `limit` uncommitted receipts, oldest first. Returns the count.

        One transaction per receipt. A sequence collision with another replica
        ends the pass; whatever is left is picked up on the next one.
        """
        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)
            waiting = conn.execute(
                f"SELECT {_COLUMN_LIST} FROM execution_receipts r WHERE r.tenant_id={p} AND NOT EXISTS "
                "(SELECT 1 FROM evidence_commitments c WHERE c.tenant_id=r.tenant_id AND c.receipt_id=r.receipt_id) "
                f"ORDER BY r.completed_at, r.receipt_id LIMIT {p}",
                (tenant, int(limit)),
            )
            conn.commit()
        committed = 0
        for row in waiting:
            if not self._commit_one(tenant, dict(row), at=at):
                break
            committed += 1
        return committed

    def _commit_one(self, tenant: str, receipt: Mapping[str, Any], *, at: str) -> bool:
        leaf = receipt_leaf(tenant, receipt).hex()
        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)
            last = conn.one(
                f"SELECT COALESCE(MAX(sequence), -1) AS last FROM transparency_leaves WHERE tenant_id={p}",
                (tenant,),
            )
            sequence = (int(last["last"]) if last else -1) + 1
            try:
                conn.execute_rowcount(
                    "INSERT INTO transparency_leaves (tenant_id, sequence, digest, appended_at) "
                    f"VALUES ({p},{p},{p},{p})",
                    (tenant, sequence, leaf, at),
                )
                conn.execute_rowcount(
                    "INSERT INTO evidence_commitments (tenant_id, receipt_id, leaf_digest, sequence, committed_at) "
                    f"VALUES ({p},{p},{p},{p},{p})",
                    (tenant, str(receipt["receipt_id"]), leaf, sequence, at),
                )
            except Exception:  # noqa: BLE001 - a lost race for the sequence; retried next pass
                conn.rollback()
                return False
            conn.commit()
        return True

    def export(self, tenant: str, *, after_sequence: int = -1, limit: int = 500) -> list[dict[str, Any]]:
        """Committed receipts with their leaf and position, in log order."""
        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)
            rows = conn.execute(
                "SELECT c.sequence AS sequence, c.leaf_digest AS leaf_digest, c.committed_at AS committed_at, "
                + ", ".join(f"r.{f} AS {f}" for f in RECEIPT_FIELDS)
                + " FROM evidence_commitments c JOIN execution_receipts r "
                "ON r.tenant_id=c.tenant_id AND r.receipt_id=c.receipt_id "
                f"WHERE c.tenant_id={p} AND c.sequence>{p} ORDER BY c.sequence LIMIT {p}",
                (tenant, int(after_sequence), int(limit)),
            )
            conn.commit()
        return [
            {"sequence": int(row["sequence"]), "leaf_digest": str(row["leaf_digest"]),
             "committed_at": str(row["committed_at"]),
             "receipt": {f: str(row[f] or "") for f in RECEIPT_FIELDS}}
            for row in rows
        ]
