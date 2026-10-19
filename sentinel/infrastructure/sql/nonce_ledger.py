"""The shared nonce ledger: single-use enforcement that survives a replica.

WHY THIS IS A TABLE AND NOT A SET
---------------------------------
`verify_binding` claims an authorization's nonce as the LAST step before the
side effect, through the `NonceLedger` port. The port's contract is that
`claim` is atomic across every process that can enforce, because two replicas
each holding an in-memory set would both observe an unused nonce and both
execute -- the same defect class as a per-process rate limiter, and one that
passes every single-process test.

So the claim is an INSERT against a primary key. Two concurrent claims for one
nonce race in the database, exactly one row lands, and the loser's
`ON CONFLICT DO NOTHING` reports zero affected rows. The atomicity belongs to
the engine, not to code remembering to lock.

TENANT-SCOPED, EXPLICITLY
-------------------------
`(tenant_id, nonce)` is the key. A nonce is minted per authorization and is
already unguessable, but scoping it by tenant means a nonce one tenant issued
can never be claimed against another -- and the predicate is written into the
statement rather than left to row-level security alone, so the SQLite engine
the test suite runs on enforces the same boundary PostgreSQL does.

WHERE THE DDL LIVES, AND WHY THAT IS PROVISIONAL
-------------------------------------------------
`schema.py` and `migrate.py` are the audited application site for DDL and are
owned elsewhere. Until this table is added there, `ensure_schema` creates it
lazily -- idempotent, run once by the composition root at build time, and
applying the same FORCE row-level security policy the audited tables get. It
should move into the migration list; this module says so rather than hiding
the gap.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sentinel.domain.errors import TransientFailure
from sentinel.infrastructure.sql.engine import ConnectionPool
from sentinel.infrastructure.sql.schema import rls_statements

__all__ = ["NONCE_TABLE_DDL", "SqlNonceLedger"]

#: The table. Stated once, here, so the lazy creation and any future migration
#: agree on the shape. `claimed_at` is evidence, not a key: a ledger that could
#: not say WHEN a nonce was burned could not answer a replay investigation.
NONCE_TABLE_DDL = """
    CREATE TABLE IF NOT EXISTS execution_nonces (
        tenant_id  TEXT NOT NULL,
        nonce      TEXT NOT NULL,
        claimed_at TEXT NOT NULL,
        PRIMARY KEY (tenant_id, nonce)
    )
"""


@dataclass(frozen=True, slots=True)
class SqlNonceLedger:
    """`NonceLedger` over the shared database.

    Frozen and holding only a pool: nothing here is per-request state, so one
    ledger is shared by every enforcement point in the process, and every
    process shares the table.
    """

    pool: ConnectionPool

    def ensure_schema(self) -> None:
        """Create the table if the migration list has not yet. Idempotent."""
        with self.pool.acquire() as conn:
            conn.begin()
            conn.execute_rowcount(NONCE_TABLE_DDL)
            if conn.dialect.supports_rls:
                for statement in rls_statements("execution_nonces"):
                    conn.execute_rowcount(statement)
            conn.commit()

    def claim(self, *, tenant_id: str, nonce: str) -> bool:
        """True exactly once per (tenant, nonce). Atomic in the database.

        A malformed claim -- empty tenant or nonce -- is refused rather than
        inserted: an empty nonce would be claimable once per deployment and
        would then read as "replayed" for every honest caller after it.
        """
        if not tenant_id.strip() or not nonce.strip():
            return False
        claimed_at = datetime.now(timezone.utc).isoformat()
        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant_id)
            try:
                affected = conn.execute_rowcount(
                    f"INSERT INTO execution_nonces (tenant_id, nonce, claimed_at) "
                    f"VALUES ({p},{p},{p}) "
                    f"ON CONFLICT (tenant_id, nonce) DO NOTHING",
                    (tenant_id, nonce, claimed_at),
                )
            except TransientFailure:
                # The engine refused the insert for a reason other than the
                # conflict clause -- a lost connection, a missing table. The
                # ledger cannot say the nonce is unused, so it says nothing was
                # claimed. Failing closed here turns an outage into a refusal,
                # which is the documented posture of `RejectingNonceLedger`.
                conn.rollback()
                return False
            conn.commit()
        return affected == 1
