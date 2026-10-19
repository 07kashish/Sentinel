"""Storage for the enterprise controls: policy versions, settings, tenant keys.

WHY ONE MODULE FOR FOUR TABLES
--------------------------------
They are read together and they answer one question: what has this tenant
configured about how their estate is governed. A policy version without the
protection mode is half an answer -- a BLOCK rule under MONITOR blocks nothing --
and splitting them across modules makes the half-answer the easy one to fetch.

ACTIVATION IS A CONDITIONAL UPDATE, WHICH IS WHAT MAKES ROLLBACK SAFE
----------------------------------------------------------------------
`activate` deactivates every version and activates one, inside the caller's
transaction. Two concurrent activations therefore serialise rather than both
succeeding, and the invariant "exactly one active version" is enforced by the
write path rather than by a partial index -- which the two engines spell
differently, and a constraint that exists on PostgreSQL only is worse than one
that exists on neither because it passes tests on SQLite.

Rollback is the same operation pointed at an older version. There is no separate
code path, so there is nothing that can be correct for deployment and wrong for
rollback -- which is the usual way a rollback fails on the night it is needed.
"""

from __future__ import annotations

import json
from typing import Any, Sequence

from sentinel.domain.keys import KeyState, KeyVersion, TenantKey
from sentinel.domain.modes import ModeTransition, ProtectionMode
from sentinel.domain.policy_as_code import (
    PolicyEffect,
    PolicyRule,
    PolicyVersion,
)
from sentinel.domain.residency import (
    Region,
    RetentionPolicy,
    assert_no_cross_region_read,
)

__all__ = [
    "SqlPolicyStore",
    "SqlTenantKeys",
    "SqlTenantSettings",
]


def _rules_to_json(rules: Sequence[PolicyRule]) -> str:
    return json.dumps([rule.as_dict() for rule in rules], sort_keys=True)


def _rules_from_json(raw: str) -> tuple[PolicyRule, ...]:
    return tuple(
        PolicyRule(
            name=str(item["name"]),
            effect=PolicyEffect(str(item["effect"])),
            actions=tuple(item.get("actions") or ()),
            resources=tuple(item.get("resources") or ()),
            destinations=tuple(item.get("destinations") or ()),
            min_severity=int(item.get("min_severity") or 0),
            description=str(item.get("description") or ""),
        )
        for item in json.loads(raw or "[]")
    )


class SqlPolicyStore:
    """Versioned policy documents for one tenant."""

    __slots__ = ("_conn", "_tenant")

    def __init__(self, conn: Any, tenant: Any) -> None:
        self._conn = conn
        self._tenant = tenant

    def _hydrate(self, row: Any) -> PolicyVersion:
        return PolicyVersion(
            version=int(row["version"]),
            rules=_rules_from_json(str(row["rules_json"])),
            created_by=str(row["created_by"]),
            created_at=str(row["created_at"]),
            note=str(row["note"] or ""),
        )

    def next_version(self) -> int:
        p = self._conn.p
        row = self._conn.one(
            f"SELECT MAX(version) AS top FROM policy_versions WHERE tenant_id={p}",
            (self._tenant.value,),
        )
        top = (row or {}).get("top") if row else None
        return int(top or 0) + 1

    def save(self, version: PolicyVersion) -> None:
        """Store a version. Idempotent on (tenant, version).

        `DO NOTHING` rather than an upsert: a stored version is what an operator
        reviewed and what a rollback returns to. Rewriting one in place would
        make "roll back to version 3" mean something different tomorrow.
        """
        p = self._conn.p
        self._conn.execute_rowcount(
            f"INSERT INTO policy_versions (tenant_id, version, digest, rules_json, "
            f"created_by, created_at, note, active) "
            f"VALUES ({p},{p},{p},{p},{p},{p},{p},0) "
            f"ON CONFLICT (tenant_id, version) DO NOTHING",
            (
                self._tenant.value,
                version.version,
                version.digest,
                _rules_to_json(version.rules),
                version.created_by,
                version.created_at,
                version.note,
            ),
        )

    def activate(self, version: int, *, by: str, at: str) -> bool:
        """Make one version active and every other inactive.

        Returns whether the version existed. Both statements run in the caller's
        transaction, so there is no window in which a tenant has zero active
        versions -- a window a reader could land in and conclude the tenant has
        no policy, which for an enforcement path means allowing everything.
        """
        p = self._conn.p
        exists = self._conn.one(
            f"SELECT 1 AS ok FROM policy_versions WHERE tenant_id={p} AND version={p}",
            (self._tenant.value, version),
        )
        if exists is None:
            return False
        self._conn.execute_rowcount(
            f"UPDATE policy_versions SET active=0 WHERE tenant_id={p}",
            (self._tenant.value,),
        )
        self._conn.execute_rowcount(
            f"UPDATE policy_versions SET active=1, activated_at={p}, activated_by={p} "
            f"WHERE tenant_id={p} AND version={p}",
            (at, by, self._tenant.value, version),
        )
        return True

    def active(self) -> PolicyVersion | None:
        p = self._conn.p
        row = self._conn.one(
            f"SELECT * FROM policy_versions WHERE tenant_id={p} AND active=1",
            (self._tenant.value,),
        )
        return self._hydrate(row) if row else None

    def get(self, version: int) -> PolicyVersion | None:
        p = self._conn.p
        row = self._conn.one(
            f"SELECT * FROM policy_versions WHERE tenant_id={p} AND version={p}",
            (self._tenant.value, version),
        )
        return self._hydrate(row) if row else None

    def history(self) -> tuple[PolicyVersion, ...]:
        p = self._conn.p
        rows = self._conn.execute(
            f"SELECT * FROM policy_versions WHERE tenant_id={p} ORDER BY version DESC",
            (self._tenant.value,),
        )
        return tuple(self._hydrate(row) for row in rows)


class SqlTenantSettings:
    """Residency, retention and protection mode for one tenant."""

    __slots__ = ("_conn", "_tenant")

    def __init__(self, conn: Any, tenant: Any) -> None:
        self._conn = conn
        self._tenant = tenant

    def retention(self) -> RetentionPolicy:
        """This tenant's retention policy, or the conservative default.

        A missing row returns defaults rather than raising. A tenant that has
        never configured retention still has data being swept, and a sweep that
        raised on them would stop sweeping every tenant after the first
        unconfigured one -- turning a missing row into unbounded growth estate
        -wide.
        """
        p = self._conn.p
        row = self._conn.one(
            f"SELECT * FROM tenant_settings WHERE tenant_id={p}", (self._tenant.value,)
        )
        if row is None:
            return RetentionPolicy(tenant_id=self._tenant.value)
        return RetentionPolicy(
            tenant_id=self._tenant.value,
            region=Region(str(row["region"])),
            events_days=int(row["events_days"]),
            incidents_days=int(row["incidents_days"]),
            raw_payloads_days=int(row["raw_payloads_days"]),
            evidence_days=int(row["evidence_days"]),
            execution_nodes_days=int(row["execution_nodes_days"]),
        )

    def save_retention(self, policy: RetentionPolicy, *, by: str, at: str) -> None:
        """Persist a validated policy.

        `RetentionPolicy.__post_init__` has already refused anything out of
        bounds, so this writes rather than re-checking. Validating in two places
        is how the two checks come to disagree.
        """
        p = self._conn.p
        updated = self._conn.execute_rowcount(
            f"UPDATE tenant_settings SET region={p}, events_days={p}, incidents_days={p}, "
            f"raw_payloads_days={p}, evidence_days={p}, execution_nodes_days={p}, "
            f"updated_at={p}, updated_by={p} WHERE tenant_id={p}",
            (
                policy.region.value,
                policy.events_days,
                policy.incidents_days,
                policy.raw_payloads_days,
                policy.evidence_days,
                policy.execution_nodes_days,
                at,
                by,
                self._tenant.value,
            ),
        )
        if updated:
            return
        self._conn.execute_rowcount(
            f"INSERT INTO tenant_settings (tenant_id, region, events_days, incidents_days, "
            f"raw_payloads_days, evidence_days, execution_nodes_days, updated_at, updated_by) "
            f"VALUES ({p},{p},{p},{p},{p},{p},{p},{p},{p}) "
            f"ON CONFLICT (tenant_id) DO NOTHING",
            (
                self._tenant.value,
                policy.region.value,
                policy.events_days,
                policy.incidents_days,
                policy.raw_payloads_days,
                policy.evidence_days,
                policy.execution_nodes_days,
                at,
                by,
            ),
        )

    def assert_resident_in(self, region: Region) -> None:
        """Refuse to operate on a tenant that lives in another region.

        SECTION 79, made enforceable. Storing a region on a tenant proves
        nothing; refusing to touch their data from the wrong deployment is the
        property a regulator is actually asking about.

        Called from the retention sweep, which is the path that DELETES -- a US
        deployment reaching into EU rows is bad enough when reading and
        unrecoverable when deleting.
        """
        assert_no_cross_region_read(home=self.retention().region, requested=region)

    def mode(self) -> ProtectionMode:
        p = self._conn.p
        row = self._conn.one(
            f"SELECT protection_mode FROM tenant_settings WHERE tenant_id={p}",
            (self._tenant.value,),
        )
        if row is None:
            return ProtectionMode.MONITOR
        return ProtectionMode(str(row["protection_mode"]))

    def record_transition(self, transition: ModeTransition) -> None:
        """Append a mode change to the tenant's audit trail.

        `ModeTransition.__post_init__` has already refused an unattributed change
        and an unexplained reduction, so a row here is always a decision somebody
        owns.
        """
        p = self._conn.p
        row = self._conn.one(
            f"SELECT MAX(seq) AS top FROM mode_transitions WHERE tenant_id={p}",
            (self._tenant.value,),
        )
        seq = int(((row or {}).get("top") if row else None) or 0) + 1
        self._conn.execute_rowcount(
            f"INSERT INTO mode_transitions (tenant_id, seq, from_mode, to_mode, "
            f"changed_by, changed_at, reason) VALUES ({p},{p},{p},{p},{p},{p},{p})",
            (
                self._tenant.value,
                seq,
                transition.from_mode.value,
                transition.to_mode.value,
                transition.changed_by,
                transition.changed_at,
                transition.reason,
            ),
        )
        updated = self._conn.execute_rowcount(
            f"UPDATE tenant_settings SET protection_mode={p} WHERE tenant_id={p}",
            (transition.to_mode.value, self._tenant.value),
        )
        if not updated:
            self._conn.execute_rowcount(
                f"INSERT INTO tenant_settings (tenant_id, protection_mode) "
                f"VALUES ({p},{p}) ON CONFLICT (tenant_id) DO NOTHING",
                (self._tenant.value, transition.to_mode.value),
            )

    def transitions(self) -> tuple[dict[str, Any], ...]:
        p = self._conn.p
        rows = self._conn.execute(
            f"SELECT * FROM mode_transitions WHERE tenant_id={p} ORDER BY seq DESC",
            (self._tenant.value,),
        )
        return tuple(
            {
                "seq": int(row["seq"]),
                "from_mode": str(row["from_mode"]),
                "to_mode": str(row["to_mode"]),
                "changed_by": str(row["changed_by"]),
                "changed_at": str(row["changed_at"]),
                "reason": str(row["reason"] or ""),
            }
            for row in rows
        )


class SqlTenantKeys:
    """Key versions for one tenant. References only, never material."""

    __slots__ = ("_conn", "_tenant")

    def __init__(self, conn: Any, tenant: Any) -> None:
        self._conn = conn
        self._tenant = tenant

    def load(self) -> TenantKey:
        p = self._conn.p
        rows = self._conn.execute(
            f"SELECT * FROM tenant_key_versions WHERE tenant_id={p} ORDER BY version",
            (self._tenant.value,),
        )
        return TenantKey(
            tenant_id=self._tenant.value,
            versions=tuple(
                KeyVersion(
                    version=int(row["version"]),
                    key_ref=str(row["key_ref"]),
                    state=KeyState(str(row["state"])),
                    created_at=str(row["created_at"]),
                    provider=str(row["provider"] or "vendor"),
                    revoked_at=str(row["revoked_at"] or ""),
                    revoked_by=str(row["revoked_by"] or ""),
                )
                for row in rows
            ),
        )

    def save(self, key: TenantKey) -> None:
        """Persist every version, upserting state.

        The whole set rather than a delta. `TenantKey` operations return a new
        aggregate in which several versions may have changed state at once --
        `revoke` touches all of them -- and writing a delta would mean deriving
        which ones changed, which is the derivation that gets it wrong and leaves
        one version readable after a revocation.
        """
        p = self._conn.p
        for version in key.versions:
            updated = self._conn.execute_rowcount(
                f"UPDATE tenant_key_versions SET key_ref={p}, state={p}, provider={p}, "
                f"revoked_at={p}, revoked_by={p} WHERE tenant_id={p} AND version={p}",
                (
                    version.key_ref,
                    version.state.value,
                    version.provider,
                    version.revoked_at,
                    version.revoked_by,
                    self._tenant.value,
                    version.version,
                ),
            )
            if updated:
                continue
            self._conn.execute_rowcount(
                f"INSERT INTO tenant_key_versions (tenant_id, version, key_ref, state, "
                f"provider, created_at, revoked_at, revoked_by) "
                f"VALUES ({p},{p},{p},{p},{p},{p},{p},{p}) "
                f"ON CONFLICT (tenant_id, version) DO NOTHING",
                (
                    self._tenant.value,
                    version.version,
                    version.key_ref,
                    version.state.value,
                    version.provider,
                    version.created_at,
                    version.revoked_at,
                    version.revoked_by,
                ),
            )
