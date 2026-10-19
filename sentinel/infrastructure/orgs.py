"""Organization / tenant membership registry (in-DB).

Organizations map 1:1 with tenant_id for this tree. Memberships bind users to
roles within the tenant. Fail closed on cross-tenant membership writes.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from sentinel.domain.authorization import VALID_ROLES
from sentinel.domain.errors import DomainRuleViolated
from sentinel.domain.primitives import TenantId, Timestamp
from sentinel.infrastructure.sql.engine import ConnectionPool

__all__ = ["OrgError", "Organization", "OrgMember", "SqlOrgRegistry"]


class OrgError(DomainRuleViolated):
    is_retryable = False


@dataclass(frozen=True, slots=True)
class Organization:
    org_id: str
    tenant_id: str
    name: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "org_id": self.org_id,
            "tenant_id": self.tenant_id,
            "name": self.name,
        }


@dataclass(frozen=True, slots=True)
class OrgMember:
    user_id: str
    role: str
    email: str

    def as_dict(self) -> dict[str, Any]:
        return {"user_id": self.user_id, "role": self.role, "email": self.email}


#: DDL applied once via migrate helper if table missing — also listed for docs.
ORG_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS organizations (
    tenant_id TEXT NOT NULL PRIMARY KEY,
    org_id    TEXT NOT NULL UNIQUE,
    name      TEXT NOT NULL,
    created_at TEXT NOT NULL
)
"""


class SqlOrgRegistry:
    __slots__ = ("_pool",)

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    def create_org(
        self, tenant: TenantId, *, name: str, at: Timestamp
    ) -> Organization:
        name_n = name.strip()
        if not name_n:
            raise OrgError("organization name is required")
        org_id = f"org-{uuid.uuid4().hex[:16]}"
        with self._pool.acquire() as conn:
            conn.begin()
            # Org row is keyed by tenant; set tenant context for RLS-friendly DBs.
            conn.set_tenant(tenant.value)
            p = conn.p
            existing = conn.one(
                f"SELECT org_id, name FROM organizations WHERE tenant_id={p}",
                (tenant.value,),
            )
            if existing is not None:
                conn.commit()
                return Organization(
                    org_id=str(existing["org_id"]),
                    tenant_id=tenant.value,
                    name=str(existing["name"]),
                )
            conn.execute_rowcount(
                f"INSERT INTO organizations (tenant_id, org_id, name, created_at) "
                f"VALUES ({p},{p},{p},{p})",
                (tenant.value, org_id, name_n, at.isoformat()),
            )
            conn.commit()
        return Organization(org_id=org_id, tenant_id=tenant.value, name=name_n)

    def get_org(self, tenant: TenantId) -> Organization | None:
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant.value)
            p = conn.p
            row = conn.one(
                f"SELECT org_id, name FROM organizations WHERE tenant_id={p}",
                (tenant.value,),
            )
            conn.commit()
        if row is None:
            return None
        return Organization(
            org_id=str(row["org_id"]), tenant_id=tenant.value, name=str(row["name"])
        )

    def list_members_from_directory(
        self, tenant: TenantId, directory_rows: list[Any]
    ) -> list[OrgMember]:
        """Map directory users to org members (same tenant only)."""
        out: list[OrgMember] = []
        for user in directory_rows:
            if getattr(user, "tenant_id", None) != tenant.value:
                raise OrgError("cross-tenant membership refused")
            role = str(user.role)
            if role not in VALID_ROLES:
                raise OrgError(f"invalid role {role!r}")
            out.append(
                OrgMember(user_id=user.user_id, role=role, email=user.email)
            )
        return out
