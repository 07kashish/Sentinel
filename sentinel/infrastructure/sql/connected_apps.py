"""Connected applications: the business systems Sentinel may call on an agent's behalf.

The missing piece of the product definition ("the connected tool executes the
approved request") for anything that is not Kubernetes, GitHub or AWS. An
application is registered ONCE by an administrator, with the credential
Sentinel will present; from then on an agent asks to call it and never holds
the credential. The credential is sealed under the evidence data key before
it reaches the database and is never returned by any route.

Configuration, not a log: rows are removed by an administrator, never by age.
"""
from __future__ import annotations

import json
import re
from typing import Any, Mapping
from urllib.parse import urlsplit

from sentinel.infrastructure.sql.engine import ConnectionPool

CONNECTED_APP_STATEMENTS = ("""
CREATE TABLE IF NOT EXISTS connected_apps (
    tenant_id             TEXT NOT NULL,
    app_id                TEXT NOT NULL,
    display_name          TEXT NOT NULL,
    base_url              TEXT NOT NULL,
    allowed_methods       TEXT NOT NULL,
    allowed_path_prefixes TEXT NOT NULL,
    auth_kind             TEXT NOT NULL,
    auth_header           TEXT NOT NULL DEFAULT '',
    credential_sealed     TEXT NOT NULL DEFAULT '',
    created_by            TEXT NOT NULL,
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL,
    PRIMARY KEY (tenant_id, app_id)
)
""",)

APP_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"})
AUTH_KINDS = frozenset({"none", "bearer", "header", "basic"})
MAX_APPS_PER_TENANT = 200
RECORD_TYPE = "connected_app"


class ConnectedAppInvalid(ValueError):
    """A registration that would not do what its author believes. Never echoes the secret."""


def validate_registration(spec: Mapping[str, Any]) -> dict[str, Any]:
    """Check everything but the secret's value; returns the normalised fields."""
    app_id = str(spec.get("app_id", "")).strip()
    if not APP_ID.match(app_id):
        raise ConnectedAppInvalid("app_id: lowercase letters, digits and hyphens, up to 63 characters")
    name = str(spec.get("display_name", "")).strip()[:120] or app_id
    base = str(spec.get("base_url", "")).strip().rstrip("/")
    parts = urlsplit(base)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
        raise ConnectedAppInvalid("base_url must be https://host[:port][/prefix] with no credentials, query or fragment")
    methods = sorted({str(m).upper() for m in (spec.get("allowed_methods") or ["GET"])})
    if not methods or any(m not in METHODS for m in methods):
        raise ConnectedAppInvalid(f"allowed_methods: choose from {', '.join(sorted(METHODS))}")
    prefixes = [str(p) for p in (spec.get("allowed_path_prefixes") or ["/"])]
    if not prefixes or any(not p.startswith("/") or ".." in p or "?" in p or "#" in p or len(p) > 512 for p in prefixes):
        raise ConnectedAppInvalid("allowed_path_prefixes: each must start with / and contain no '..', '?' or '#'")
    auth = spec.get("auth") or {"kind": "none"}
    kind = str(auth.get("kind", "none")).lower()
    if kind not in AUTH_KINDS:
        raise ConnectedAppInvalid(f"auth.kind: choose from {', '.join(sorted(AUTH_KINDS))}")
    header = str(auth.get("header", "")).strip()
    if kind == "header" and not re.match(r"^[A-Za-z0-9-]{1,64}$", header):
        raise ConnectedAppInvalid("auth.header: a header name is required for kind=header")
    if header.lower() in {"host", "content-length", "transfer-encoding", "cookie"}:
        raise ConnectedAppInvalid("auth.header: that header cannot carry a credential")
    secret = auth.get("secret")
    if kind != "none" and (not isinstance(secret, str) or not secret.strip() or len(secret) > 4096):
        raise ConnectedAppInvalid("auth.secret is required for this auth.kind (1-4096 characters)")
    if kind == "none" and secret:
        raise ConnectedAppInvalid("auth.secret given with auth.kind=none")
    return {"app_id": app_id, "display_name": name, "base_url": base, "allowed_methods": methods,
            "allowed_path_prefixes": prefixes, "auth_kind": kind, "auth_header": header if kind == "header" else "",
            "secret": secret if kind != "none" else ""}


class SqlConnectedApps:
    """Tenant-scoped registry. `cipher` is the evidence EnvelopeCipher or None."""

    def __init__(self, pool: ConnectionPool, cipher: Any = None) -> None:
        self.pool = pool
        self.cipher = cipher

    def save(self, tenant: str, spec: Mapping[str, Any], *, actor: str, now: str) -> dict[str, Any]:
        fields = validate_registration(spec)
        if fields["secret"] and self.cipher is None:
            raise ConnectedAppInvalid(
                "this deployment has no data key, so a credential cannot be stored sealed; "
                "configure SENTINEL_DATA_KEY_<id> or register the application with auth.kind=none"
            )
        sealed = ""
        if fields["secret"]:
            sealed = self.cipher.seal_json({"secret": fields["secret"]}, tenant_id=tenant,
                                           record_type=RECORD_TYPE, record_id=fields["app_id"])
        with self.pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant)
            conn.serialise_tenant(tenant, purpose="connected_apps")
            p = conn.p
            found = conn.one(f"SELECT created_at, credential_sealed FROM connected_apps WHERE tenant_id={p} AND app_id={p}",
                             (tenant, fields["app_id"]))
            count = conn.one(f"SELECT COUNT(*) AS n FROM connected_apps WHERE tenant_id={p}", (tenant,))
            if found is None and count and int(count["n"]) >= MAX_APPS_PER_TENANT:
                raise ConnectedAppInvalid("application limit reached for this tenant; remove one first")
            # Re-registering without a secret keeps the sealed one it already has.
            if not sealed and found is not None and fields["auth_kind"] != "none":
                sealed = str(found["credential_sealed"] or "")
                if not sealed:
                    raise ConnectedAppInvalid("auth.secret is required: no credential is stored for this application yet")
            created_at = str(found["created_at"]) if found is not None else now
            conn.execute_rowcount(
                "INSERT INTO connected_apps (tenant_id, app_id, display_name, base_url, allowed_methods, allowed_path_prefixes, "
                f"auth_kind, auth_header, credential_sealed, created_by, created_at, updated_at) VALUES ({p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p}) "
                "ON CONFLICT (tenant_id, app_id) DO UPDATE SET display_name=excluded.display_name, base_url=excluded.base_url, "
                "allowed_methods=excluded.allowed_methods, allowed_path_prefixes=excluded.allowed_path_prefixes, auth_kind=excluded.auth_kind, "
                "auth_header=excluded.auth_header, credential_sealed=excluded.credential_sealed, updated_at=excluded.updated_at",
                (tenant, fields["app_id"], fields["display_name"], fields["base_url"], ",".join(fields["allowed_methods"]),
                 json.dumps(fields["allowed_path_prefixes"]), fields["auth_kind"], fields["auth_header"], sealed, actor, created_at, now),
            )
            conn.commit()
        return self._public(fields, created_at, now, bool(sealed))

    def list(self, tenant: str) -> list[dict[str, Any]]:
        with self.pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant)
            rows = conn.execute(f"SELECT * FROM connected_apps WHERE tenant_id={conn.p} ORDER BY app_id", (tenant,))
            conn.commit()
        return [self._row_public(r) for r in rows]

    def get(self, tenant: str, app_id: str) -> dict[str, Any] | None:
        """The full registration INCLUDING the opened credential, for the adapter only."""
        with self.pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant)
            row = conn.one(f"SELECT * FROM connected_apps WHERE tenant_id={conn.p} AND app_id={conn.p}", (tenant, app_id))
            conn.commit()
        if row is None:
            return None
        secret = ""
        if row["credential_sealed"]:
            if self.cipher is None:
                raise ConnectedAppInvalid("a sealed credential exists but this process has no data key")
            opened = self.cipher.open_json(str(row["credential_sealed"]), tenant_id=tenant, record_type=RECORD_TYPE, record_id=app_id)
            secret = str(opened.get("secret", "")) if isinstance(opened, dict) else ""
        return {**self._row_public(row), "secret": secret}

    def delete(self, tenant: str, app_id: str) -> bool:
        with self.pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant)
            n = conn.execute_rowcount(f"DELETE FROM connected_apps WHERE tenant_id={conn.p} AND app_id={conn.p}", (tenant, app_id))
            conn.commit()
        return n > 0

    @staticmethod
    def _row_public(row: Mapping[str, Any]) -> dict[str, Any]:
        return {"app_id": row["app_id"], "display_name": row["display_name"], "base_url": row["base_url"],
                "allowed_methods": str(row["allowed_methods"]).split(","), "allowed_path_prefixes": json.loads(row["allowed_path_prefixes"]),
                "auth": {"kind": row["auth_kind"], "header": row["auth_header"] or None,
                         "credential": "sealed" if row["credential_sealed"] else "none"},
                "created_by": row["created_by"], "created_at": row["created_at"], "updated_at": row["updated_at"]}

    @staticmethod
    def _public(fields: Mapping[str, Any], created_at: str, updated_at: str, sealed: bool) -> dict[str, Any]:
        return {"app_id": fields["app_id"], "display_name": fields["display_name"], "base_url": fields["base_url"],
                "allowed_methods": list(fields["allowed_methods"]), "allowed_path_prefixes": list(fields["allowed_path_prefixes"]),
                "auth": {"kind": fields["auth_kind"], "header": fields["auth_header"] or None, "credential": "sealed" if sealed else "none"},
                "created_by": "", "created_at": created_at, "updated_at": updated_at}
