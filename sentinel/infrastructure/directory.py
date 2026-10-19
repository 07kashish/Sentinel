"""SCIM 2.0 user directory persistence (tenant-scoped).

Stores users in the existing `users` table. Fail closed: every mutation requires
an explicit tenant; deactivated users cannot authenticate via SCIM reactivation
without MANAGE_USERS.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Mapping

from sentinel.domain.authorization import VALID_ROLES
from sentinel.domain.errors import DomainRuleViolated
from sentinel.domain.primitives import TenantId, Timestamp
from sentinel.infrastructure.sql.engine import ConnectionPool

__all__ = ["DirectoryError", "MAX_PAGE_START", "ScimUser", "SqlDirectory"]

#: Largest `startIndex` a SCIM page request may ask for.
#:
#: Exists because the value becomes a SQL `OFFSET`, and an unbounded integer
#: from a query string is one a 64-bit column cannot hold -- which surfaced as
#: an OverflowError and an HTTP 500 rather than as a rejected request. A billion
#: is far beyond any tenant's user count and comfortably inside int64.
MAX_PAGE_START = 1_000_000_000


class DirectoryError(DomainRuleViolated):
    is_retryable = False


@dataclass(frozen=True, slots=True)
class ScimUser:
    user_id: str
    external_id: str
    email: str
    display_name: str
    role: str
    active: bool
    tenant_id: str

    def as_scim(self) -> dict[str, Any]:
        return {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": self.user_id,
            "externalId": self.external_id,
            "userName": self.email,
            "displayName": self.display_name,
            "active": self.active,
            "roles": [{"value": self.role, "primary": True}],
            "meta": {"resourceType": "User"},
        }


class SqlDirectory:
    """Tenant-bound SCIM user store."""

    __slots__ = ("_pool",)

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    def create(
        self,
        tenant: TenantId,
        *,
        email: str,
        display_name: str,
        role: str,
        external_id: str,
        at: Timestamp,
        active: bool = True,
    ) -> ScimUser:
        email_n = email.strip().lower()
        role_n = role.strip().lower()
        if not email_n or "@" not in email_n:
            raise DirectoryError("email is required")
        if role_n not in VALID_ROLES:
            raise DirectoryError(f"role {role!r} is not grantable")
        if role_n == "ingest":
            raise DirectoryError("SCIM cannot mint ingest machine credentials")
        user_id = f"usr-{uuid.uuid4().hex}"
        ext = external_id.strip() or user_id
        state = "active" if active else "suspended"
        now = at.isoformat()
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant.value)
            p = conn.p
            try:
                conn.execute_rowcount(
                    f"INSERT INTO users (tenant_id, user_id, email, display_name, role, "
                    f"state, created_at, updated_at, external_id) "
                    f"VALUES ({p},{p},{p},{p},{p},{p},{p},{p},{p})",
                    (
                        tenant.value,
                        user_id,
                        email_n,
                        display_name.strip(),
                        role_n,
                        state,
                        now,
                        now,
                        ext,
                    ),
                )
            except Exception as exc:  # noqa: BLE001 - unique violations etc.
                conn.rollback()
                raise DirectoryError(f"user create failed: {exc}") from exc
            conn.commit()
        return ScimUser(
            user_id=user_id,
            external_id=ext,
            email=email_n,
            display_name=display_name.strip(),
            role=role_n,
            active=active,
            tenant_id=tenant.value,
        )

    def get(self, tenant: TenantId, user_id: str) -> ScimUser | None:
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant.value)
            p = conn.p
            row = conn.one(
                f"SELECT user_id, external_id, email, display_name, role, state "
                f"FROM users WHERE tenant_id={p} AND user_id={p}",
                (tenant.value, user_id),
            )
            conn.commit()
        if row is None:
            return None
        return self._row(tenant.value, row)

    def list_users(self, tenant: TenantId, *, start: int = 1, count: int = 100) -> list[ScimUser]:
        # BOTH ENDS, not just the bottom. `max(1, start)` bounded this below and
        # nothing bounded it above, so a caller could send
        #   GET /scim/v2/Users?startIndex=1141909118505301951119360
        # and the offset reached the driver as an integer no 64-bit column can
        # hold: OverflowError -> TransientFailure -> HTTP 500 with a traceback.
        # Found by the schema fuzzer in CI, not by a hand-written test, which is
        # the point of running one -- nobody writes that number by hand.
        #
        # Clamped rather than rejected. RFC 7644 3.4.2.4 says a startIndex past
        # the end is a valid request that returns no resources, so a 4xx here
        # would be wrong for real SCIM clients (Okta, Entra) that page until
        # they see an empty page. A billion is far past any tenant's user count
        # and comfortably inside int64, so the query runs and returns nothing --
        # which is the honest answer to "give me the billionth user".
        start = min(MAX_PAGE_START, max(1, start))
        count = min(200, max(1, count))
        offset = start - 1
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant.value)
            p = conn.p
            rows = conn.execute(
                f"SELECT user_id, external_id, email, display_name, role, state "
                f"FROM users WHERE tenant_id={p} ORDER BY email LIMIT {p} OFFSET {p}",
                (tenant.value, count, offset),
            )
            conn.commit()
        return [self._row(tenant.value, r) for r in rows]

    def replace(
        self,
        tenant: TenantId,
        user_id: str,
        *,
        email: str | None = None,
        display_name: str | None = None,
        role: str | None = None,
        active: bool | None = None,
        at: Timestamp,
    ) -> ScimUser:
        existing = self.get(tenant, user_id)
        if existing is None:
            raise DirectoryError("user not found")
        email_n = (email or existing.email).strip().lower()
        display = display_name if display_name is not None else existing.display_name
        role_n = (role or existing.role).strip().lower()
        if role_n not in VALID_ROLES or role_n == "ingest":
            raise DirectoryError("role is not grantable via SCIM")
        is_active = existing.active if active is None else bool(active)
        state = "active" if is_active else "suspended"
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant.value)
            p = conn.p
            updated = conn.execute_rowcount(
                f"UPDATE users SET email={p}, display_name={p}, role={p}, state={p}, "
                f"updated_at={p} WHERE tenant_id={p} AND user_id={p}",
                (
                    email_n,
                    display,
                    role_n,
                    state,
                    at.isoformat(),
                    tenant.value,
                    user_id,
                ),
            )
            if updated != 1:
                conn.rollback()
                raise DirectoryError("user update failed")
            conn.commit()
        return ScimUser(
            user_id=user_id,
            external_id=existing.external_id,
            email=email_n,
            display_name=display,
            role=role_n,
            active=is_active,
            tenant_id=tenant.value,
        )

    def deactivate(self, tenant: TenantId, user_id: str, *, at: Timestamp) -> ScimUser:
        return self.replace(tenant, user_id, active=False, at=at)

    @staticmethod
    def _row(tenant_id: str, row: Mapping[str, Any]) -> ScimUser:
        state = str(row["state"])
        return ScimUser(
            user_id=str(row["user_id"]),
            external_id=str(row["external_id"] or ""),
            email=str(row["email"]),
            display_name=str(row["display_name"] or ""),
            role=str(row["role"]),
            active=state == "active",
            tenant_id=tenant_id,
        )
