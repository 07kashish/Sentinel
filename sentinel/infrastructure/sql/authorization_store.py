"""Issued execution authorizations, durably, so a token can be redeemed anywhere.

WHAT THIS STORE IS FOR
----------------------
`POST /v1/protect/evaluate` issues an `ExecutionAuthorization` when the policy
says an action may proceed. The agent then presents it to
`POST /v1/tools/execute`, which may be answered by a different replica. The
authorization therefore has to live somewhere every replica can read, keyed by
the tenant that issued it -- and that is this table.

THE TOKEN IS BOUND TO THE ROW, NOT TO A SHARED SECRET
------------------------------------------------------
The caller holds `sxa1.<authorization_id>.<secret>`. The secret is 32 random
bytes minted at issuance and stored here only as its SHA-256; redeeming a token
looks the row up by id under the caller's tenant and compares the digest of
the presented secret in constant time. The token is therefore opaque,
unforgeable and bound to exactly one stored authorization -- and it needs no
HMAC key shared across replicas, because the shared state IS the row. An HMAC
design would have added a production-required secret to `settings.py`, and a
setting whose absence refuses startup is not something to introduce from the
side.

STATE, AND WHY `require_approval` IS A STATE RATHER THAN A REFUSAL
------------------------------------------------------------------
An authorization issued for a `require_approval` decision is stored as
`pending_approval`. It has every field an active one has and it redeems for
nothing: `resolve` reports the state and the execute route refuses it by name.
A holder of `DECIDE_APPROVAL` activates it, which is the approval decision the
protect verdict asked for. The alternative -- issuing nothing and asking the
agent to re-evaluate after approval -- would mean the approved parameters and
the executed parameters were never the same committed object, which is the
gap the whole binding exists to close.

WHAT IS NOT STORED
------------------
Parameter VALUES. The row holds the authorization document, which commits to
the parameters by digest. A caller that needs the values has them; this table
is read by whoever can read the database, and it should not be the most
sensitive one in it.

WHERE THE DDL LIVES
-------------------
Lazily, from `ensure_schema`, for the reason `nonce_ledger.py` gives: the
audited migration list is owned elsewhere. The table should move there.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from typing import Any, Mapping

from sentinel.domain.execution_binding import ExecutionAuthorization
from sentinel.infrastructure.sql.engine import ConnectionPool
from sentinel.infrastructure.sql.schema import rls_statements

__all__ = [
    "AUTHORIZATION_TABLE_DDL",
    "STATE_ACTIVE",
    "STATE_PENDING_APPROVAL",
    "STATE_REVOKED",
    "TOKEN_PREFIX",
    "SqlAuthorizationStore",
    "StoredAuthorization",
]

TOKEN_PREFIX = "sxa1"
STATE_ACTIVE = "active"
STATE_PENDING_APPROVAL = "pending_approval"
STATE_REVOKED = "revoked"

AUTHORIZATION_TABLE_DDL = """
    CREATE TABLE IF NOT EXISTS execution_authorizations (
        tenant_id        TEXT NOT NULL,
        authorization_id TEXT NOT NULL,
        nonce            TEXT NOT NULL,
        token_digest     TEXT NOT NULL,
        state            TEXT NOT NULL,
        document         TEXT NOT NULL,
        issued_at        TEXT NOT NULL,
        expires_at       TEXT NOT NULL,
        approved_by      TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (tenant_id, authorization_id)
    )
"""

_COLUMNS: tuple[str, ...] = (
    "authorization_id",
    "nonce",
    "token_digest",
    "state",
    "document",
    "issued_at",
    "expires_at",
    "approved_by",
)
_COLUMN_LIST: str = ", ".join(_COLUMNS)


def _token_digest(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def new_token(authorization_id: str) -> tuple[str, str]:
    """A fresh bearer token for `authorization_id`, and the digest to store.

    Returns `(token, token_digest)`. The secret half is never stored; only its
    digest is, so a read of this table yields nothing redeemable.
    """
    secret = secrets.token_urlsafe(32)
    return f"{TOKEN_PREFIX}.{authorization_id}.{secret}", _token_digest(secret)


def parse_token(token: str) -> tuple[str, str] | None:
    """`(authorization_id, secret)` from a token, or None when malformed."""
    parts = str(token or "").strip().split(".")
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX:
        return None
    authorization_id, secret = parts[1], parts[2]
    if not authorization_id or not secret:
        return None
    return authorization_id, secret


@dataclass(frozen=True, slots=True)
class StoredAuthorization:
    """An authorization as the store holds it, with its lifecycle state."""

    authorization: ExecutionAuthorization
    state: str
    approved_by: str = ""

    @property
    def redeemable(self) -> bool:
        return self.state == STATE_ACTIVE


@dataclass(frozen=True, slots=True)
class SqlAuthorizationStore:
    """Tenant-scoped storage for issued authorizations."""

    pool: ConnectionPool

    def ensure_schema(self) -> None:
        """Create the table if the migration list has not yet. Idempotent."""
        with self.pool.acquire() as conn:
            conn.begin()
            conn.execute_rowcount(AUTHORIZATION_TABLE_DDL)
            if conn.dialect.supports_rls:
                for statement in rls_statements("execution_authorizations"):
                    conn.execute_rowcount(statement)
            conn.commit()

    def issue(
        self,
        authorization: ExecutionAuthorization,
        *,
        state: str = STATE_ACTIVE,
    ) -> str:
        """Store an authorization and return the bearer token that redeems it.

        The token is returned exactly once, from here. There is no method that
        returns it again: a store that could re-issue a token for a stored row
        would make every reader of the table a holder of every authorization.
        """
        if state not in {STATE_ACTIVE, STATE_PENDING_APPROVAL}:
            raise ValueError(f"an authorization cannot be issued as {state!r}")
        token, token_digest = new_token(authorization.authorization_id)
        document = json.dumps(authorization.as_document(), sort_keys=True)
        tenant = authorization.tenant_id
        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)
            conn.execute_rowcount(
                "INSERT INTO execution_authorizations "
                "(tenant_id, authorization_id, nonce, token_digest, state, "
                "document, issued_at, expires_at, approved_by) "
                f"VALUES ({p},{p},{p},{p},{p},{p},{p},{p},{p})",
                (
                    tenant,
                    authorization.authorization_id,
                    authorization.nonce,
                    token_digest,
                    state,
                    document,
                    authorization.issued_at,
                    authorization.expires_at,
                    "",
                ),
            )
            conn.commit()
        return token

    def get(self, tenant: str, authorization_id: str) -> StoredAuthorization | None:
        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)
            rows = conn.execute(
                f"SELECT {_COLUMN_LIST} FROM execution_authorizations "
                f"WHERE tenant_id={p} AND authorization_id={p}",
                (tenant, authorization_id),
            )
            conn.commit()
        return self._stored(rows[0]) if rows else None

    def get_by_nonce(self, tenant: str, nonce: str) -> StoredAuthorization | None:
        """Look an authorization up by the nonce its receipt will name."""
        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)
            rows = conn.execute(
                f"SELECT {_COLUMN_LIST} FROM execution_authorizations "
                f"WHERE tenant_id={p} AND nonce={p}",
                (tenant, nonce),
            )
            conn.commit()
        return self._stored(rows[0]) if rows else None

    def list(
        self, tenant: str, *, state: str = "", limit: int = 100
    ) -> list[StoredAuthorization]:
        """Authorizations for this tenant, newest first, optionally by state.

        The inbox. Tokens are never returned: a listing that carried secrets
        would let anyone who can read the inbox redeem every entry in it.
        """
        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)
            if state:
                rows = conn.execute(
                    f"SELECT {_COLUMN_LIST} FROM execution_authorizations "
                    f"WHERE tenant_id={p} AND state={p} "
                    f"ORDER BY issued_at DESC LIMIT {p}",
                    (tenant, state, int(limit)),
                )
            else:
                rows = conn.execute(
                    f"SELECT {_COLUMN_LIST} FROM execution_authorizations "
                    f"WHERE tenant_id={p} ORDER BY issued_at DESC LIMIT {p}",
                    (tenant, int(limit)),
                )
            conn.commit()
        out: list[StoredAuthorization] = []
        for row in rows:
            stored = self._stored(row)
            if stored is not None:
                out.append(stored)
        return out

    def resolve(self, tenant: str, token: str) -> StoredAuthorization | None:
        """The stored authorization a token redeems, or None.

        None for a malformed token, an unknown id, a row under another tenant
        (the predicate is explicit, so the lookup never sees it) and a secret
        that does not match. All four are the same answer on purpose: a caller
        that could distinguish "no such id" from "wrong secret" could enumerate
        ids.
        """
        parsed = parse_token(token)
        if parsed is None:
            return None
        authorization_id, secret = parsed
        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)
            rows = conn.execute(
                f"SELECT {_COLUMN_LIST} FROM execution_authorizations "
                f"WHERE tenant_id={p} AND authorization_id={p}",
                (tenant, authorization_id),
            )
            conn.commit()
        if not rows:
            return None
        row = rows[0]
        if not hmac.compare_digest(
            str(row["token_digest"]), _token_digest(secret)
        ):
            return None
        return self._stored(row)

    def activate(
        self, tenant: str, authorization_id: str, *, approved_by: str
    ) -> StoredAuthorization | None:
        """The approval decision: `pending_approval` -> `active`, once.

        A conditional UPDATE, so two concurrent approvals cannot both report
        that they were the one that activated it. Returns the stored row after
        the transition, or None when there was nothing pending to activate --
        including an authorization that is already active, which a second
        approver must not be told they approved.
        """
        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)
            affected = conn.execute_rowcount(
                f"UPDATE execution_authorizations SET state={p}, approved_by={p} "
                f"WHERE tenant_id={p} AND authorization_id={p} AND state={p}",
                (
                    STATE_ACTIVE,
                    approved_by,
                    tenant,
                    authorization_id,
                    STATE_PENDING_APPROVAL,
                ),
            )
            conn.commit()
        if affected != 1:
            return None
        return self.get(tenant, authorization_id)

    def record_approval(
        self, tenant: str, authorization_id: str, *, approver: str, quorum: int
    ) -> tuple[str, tuple[str, ...]] | None:
        """One approver's yes. Activates only when `quorum` DISTINCT approvers agree.

        Approvers accumulate in `approved_by` while the row is still pending,
        so a partially approved authorization is not redeemable: redemption
        checks the state, not the column. The write is a compare-and-swap on
        the previous approver list, so two concurrent approvals cannot both
        believe they were the deciding one, and a lost race is retried against
        the new list rather than overwriting it.

        Returns `(state, approvers)`, or None when the authorization is not
        pending. Raises `ValueError` when this approver has already approved.
        """
        for _ in range(8):
            current = self.get(tenant, authorization_id)
            if current is None or current.state != STATE_PENDING_APPROVAL:
                return None
            approvers = tuple(a for a in current.approved_by.split(",") if a)
            if approver in approvers:
                raise ValueError("this approver has already approved this authorization")
            updated = (*approvers, approver)
            state = STATE_ACTIVE if len(updated) >= max(1, int(quorum)) else STATE_PENDING_APPROVAL
            with self.pool.acquire() as conn:
                p = conn.p
                conn.begin()
                conn.set_tenant(tenant)
                affected = conn.execute_rowcount(
                    f"UPDATE execution_authorizations SET state={p}, approved_by={p} "
                    f"WHERE tenant_id={p} AND authorization_id={p} AND state={p} AND approved_by={p}",
                    (state, ",".join(updated), tenant, authorization_id,
                     STATE_PENDING_APPROVAL, current.approved_by),
                )
                conn.commit()
            if affected == 1:
                return state, updated
        return None

    def revoke(self, tenant: str, authorization_id: str) -> bool:
        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)
            affected = conn.execute_rowcount(
                f"UPDATE execution_authorizations SET state={p} "
                f"WHERE tenant_id={p} AND authorization_id={p}",
                (STATE_REVOKED, tenant, authorization_id),
            )
            conn.commit()
        return affected == 1

    @staticmethod
    def _stored(row: Mapping[str, Any]) -> StoredAuthorization | None:
        try:
            document = json.loads(str(row["document"]))
            authorization = ExecutionAuthorization.from_document(document)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            # A row that no longer rebuilds into a valid authorization is a
            # row nothing can be bound to. None, not a partial object.
            return None
        return StoredAuthorization(
            authorization=authorization,
            state=str(row["state"]),
            approved_by=str(row.get("approved_by") or ""),
        )
