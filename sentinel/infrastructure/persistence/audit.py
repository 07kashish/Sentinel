"""The audit log: append-only, hash-chained, and verifiable.

WHY A CHAIN AND NOT JUST A TABLE
---------------------------------
A table of rows an administrator can `UPDATE` is not an audit log. It is a record
of whatever the last person with write access wanted it to say, and its value in
a dispute is zero -- which is the moment it is read.

Each entry commits to its predecessor:

    chain_hash(n) = H( chain_hash(n-1) || canonical(entry n) )

So a deletion, an edit, or a reordering breaks every link after it. `verify`
walks the chain and reports the first sequence number where it stops matching,
which is what turns "the log looks fine" into "the log is intact up to entry
4,182 and diverges at 4,183".

This is deliberately the same construction as the evidence ledger. Reusing a
shape the team already reasons about correctly is worth more than a marginally
better one nobody checks.

WHAT IT DOES NOT CLAIM
----------------------
A chain proves INTERNAL consistency. Someone with write access can still truncate
the log and rebuild a valid chain over what remains, because they hold the same
hash function. Detecting that needs an external anchor -- periodically publishing
the head hash somewhere the database cannot reach. `head()` exists to be
published; doing so is an operational decision, and pretending the chain alone
makes the log tamper-PROOF rather than tamper-EVIDENT would be the kind of
overclaim this codebase has been burned by before.

SOFT DELETE DOES NOT APPLY HERE
--------------------------------
Live tables are not partitioned; retention uses DELETE sweeps for explicitly
eligible operational and incident history rows. `security_audit` is append-only
and is never swept. Removing entries would break its chain.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from sentinel.domain.errors import SentinelError
from sentinel.domain.primitives import TenantId, Timestamp
from sentinel.infrastructure.sql.engine import Connection

__all__ = [
    "AuditEntry",
    "AuditLog",
    "AuditTampering",
    "ChainVerification",
    "Outcome",
]

GENESIS = "0" * 64


class AuditTampering(SentinelError):
    """The audit chain does not verify. Deterministic; never retried."""

    is_retryable = False


class Outcome(str, Enum):
    """Whether the audited action succeeded. Recorded, never inferred."""

    SUCCESS = "success"
    #: The action was refused by policy. As important as a success: "we were
    #: asked and said no" is precisely what gets disputed later.
    DENIED = "denied"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """One audited action. Immutable, and hashed exactly as written."""

    tenant_id: TenantId
    seq: int
    actor: str
    action: str
    resource_type: str
    resource_id: str
    outcome: Outcome
    occurred_at: Timestamp
    detail: Mapping[str, Any] = field(default_factory=dict)
    prev_chain_hash: str = GENESIS
    chain_hash: str = ""

    def canonical(self) -> bytes:
        """The exact bytes the chain commits to.

        Sorted keys and no whitespace, so two processes hashing the same entry
        agree. A canonicalisation that depends on dict ordering produces a chain
        that verifies on the machine that wrote it and nowhere else.
        """
        return json.dumps(
            {
                "tenant_id": self.tenant_id.value,
                "seq": self.seq,
                "actor": self.actor,
                "action": self.action,
                "resource_type": self.resource_type,
                "resource_id": self.resource_id,
                "outcome": self.outcome.value,
                "occurred_at": self.occurred_at.isoformat(),
                "detail": dict(self.detail),
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")

    def compute_chain_hash(self) -> str:
        digest = hashlib.sha256()
        digest.update(self.prev_chain_hash.encode("ascii"))
        digest.update(self.canonical())
        return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class ChainVerification:
    """The result of walking a tenant's chain."""

    tenant_id: TenantId
    entries: int
    intact: bool
    head: str
    #: The first sequence number that failed, if any. Naming WHERE it broke is
    #: the difference between an actionable report and an alarm.
    broken_at: int | None = None
    reason: str = ""

    def __str__(self) -> str:
        if self.intact:
            return f"{self.tenant_id}: {self.entries} entries intact, head={self.head[:16]}"
        return f"{self.tenant_id}: BROKEN at seq {self.broken_at} -- {self.reason}"


class AuditLog:
    """Append-only audit writer and verifier, scoped to one tenant.

    Uses the caller's live SQL connection, so an entry commits in the SAME
    transaction as the caller's action. That coupling is the point: an audit
    log written in a separate transaction records actions that were rolled back
    and misses actions that were not.
    """

    __slots__ = ("_conn", "_tenant")

    def __init__(self, conn: Connection, tenant: TenantId) -> None:
        self._conn = conn
        self._tenant = tenant

    # ── Writing ──────────────────────────────────────────────────────────────

    def record(
        self,
        *,
        actor: str,
        action: str,
        resource_type: str,
        resource_id: str,
        outcome: Outcome,
        at: Timestamp,
        detail: Mapping[str, Any] | None = None,
    ) -> AuditEntry:
        """Append one entry, linked to the current head.

        The head is read INSIDE this transaction, under a per-tenant advisory
        lock. Reading it on one connection and inserting on another is how the
        evidence ledger was once forked by eight concurrent writers, and an audit
        chain has exactly the same shape.
        """
        p = self._conn.p
        self._conn.serialise_tenant(self._tenant.value, purpose="security_audit")

        head = self._conn.one(
            f"SELECT seq, chain_hash FROM security_audit WHERE tenant_id={p} "
            f"ORDER BY seq DESC LIMIT 1" + self._conn.lock_clause(),
            (self._tenant.value,),
        )
        previous = head["chain_hash"] if head else GENESIS
        seq = (int(head["seq"]) + 1) if head else 1

        entry = AuditEntry(
            tenant_id=self._tenant,
            seq=seq,
            actor=actor,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            occurred_at=at,
            detail=dict(detail or {}),
            prev_chain_hash=previous,
        )
        sealed = AuditEntry(
            **{
                **{f: getattr(entry, f) for f in entry.__slots__ if f != "chain_hash"},
                "chain_hash": entry.compute_chain_hash(),
            }
        )

        self._conn.execute_rowcount(
            f"INSERT INTO security_audit (tenant_id, seq, actor, action, resource_type, "
            f"resource_id, outcome, detail, prev_chain_hash, chain_hash, "
            f"occurred_at) VALUES ({p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p})",
            (
                self._tenant.value,
                sealed.seq,
                sealed.actor,
                sealed.action,
                sealed.resource_type,
                sealed.resource_id,
                sealed.outcome.value,
                json.dumps(dict(sealed.detail), sort_keys=True, default=str),
                sealed.prev_chain_hash,
                sealed.chain_hash,
                sealed.occurred_at.isoformat(),
            ),
        )
        return sealed

    # ── Reading ──────────────────────────────────────────────────────────────

    def head(self) -> str:
        """The current chain head. Publish this externally to close the gap
        a self-consistent chain leaves open."""
        p = self._conn.p
        row = self._conn.one(
            f"SELECT chain_hash FROM security_audit WHERE tenant_id={p} "
            f"ORDER BY seq DESC LIMIT 1",
            (self._tenant.value,),
        )
        return row["chain_hash"] if row else GENESIS

    def entries(self, *, limit: int = 100, after_seq: int = 0) -> Sequence[AuditEntry]:
        """A page of entries, oldest first within the page.

        Keyset pagination on `seq`, not OFFSET. OFFSET makes page N cost N pages
        of work, so the last page of a long log is the slowest -- and an auditor
        reads the whole log.
        """
        p = self._conn.p
        rows = self._conn.execute(
            f"SELECT * FROM security_audit WHERE tenant_id={p} AND seq>{p} "
            f"ORDER BY seq ASC LIMIT {p}",
            (self._tenant.value, after_seq, limit),
        )
        return [self._hydrate(row) for row in rows]

    def for_resource(
        self, *, resource_type: str, resource_id: str, limit: int = 100
    ) -> Sequence[AuditEntry]:
        p = self._conn.p
        rows = self._conn.execute(
            f"SELECT * FROM security_audit WHERE tenant_id={p} AND resource_type={p} "
            f"AND resource_id={p} ORDER BY occurred_at DESC LIMIT {p}",
            (self._tenant.value, resource_type, resource_id, limit),
        )
        return [self._hydrate(row) for row in rows]

    def by_actor(self, *, actor: str, limit: int = 100) -> Sequence[AuditEntry]:
        p = self._conn.p
        rows = self._conn.execute(
            f"SELECT * FROM security_audit WHERE tenant_id={p} AND actor={p} "
            f"ORDER BY occurred_at DESC LIMIT {p}",
            (self._tenant.value, actor, limit),
        )
        return [self._hydrate(row) for row in rows]

    # ── Verification ─────────────────────────────────────────────────────────

    def verify(self, *, batch: int = 1000) -> ChainVerification:
        """Walk the chain and report the first divergence.

        Streamed in pages rather than loaded whole: an audit log is the largest
        table in the system, and a verifier that needs it all in memory is one
        that stops being run.
        """
        p = self._conn.p
        previous = GENESIS
        expected_seq = 1
        count = 0
        after = 0

        while True:
            rows = self._conn.execute(
                f"SELECT * FROM security_audit WHERE tenant_id={p} AND seq>{p} "
                f"ORDER BY seq ASC LIMIT {p}",
                (self._tenant.value, after, batch),
            )
            if not rows:
                break
            for row in rows:
                entry = self._hydrate(row)
                if entry.seq != expected_seq:
                    return ChainVerification(
                        tenant_id=self._tenant,
                        entries=count,
                        intact=False,
                        head=previous,
                        broken_at=entry.seq,
                        reason=(
                            f"sequence jumped from {expected_seq - 1} to {entry.seq}; "
                            f"{entry.seq - expected_seq} entr(y/ies) removed"
                        ),
                    )
                if entry.prev_chain_hash != previous:
                    return ChainVerification(
                        tenant_id=self._tenant,
                        entries=count,
                        intact=False,
                        head=previous,
                        broken_at=entry.seq,
                        reason=(
                            "predecessor mismatch: entry claims "
                            f"{entry.prev_chain_hash[:16]}, chain is at "
                            f"{previous[:16]}"
                        ),
                    )
                recomputed = entry.compute_chain_hash()
                if recomputed != entry.chain_hash:
                    return ChainVerification(
                        tenant_id=self._tenant,
                        entries=count,
                        intact=False,
                        head=previous,
                        broken_at=entry.seq,
                        reason=(
                            "content altered: stored hash "
                            f"{entry.chain_hash[:16]} does not match recomputed "
                            f"{recomputed[:16]}"
                        ),
                    )
                previous = entry.chain_hash
                expected_seq += 1
                count += 1
                after = entry.seq

        return ChainVerification(
            tenant_id=self._tenant, entries=count, intact=True, head=previous
        )

    # ── Internals ────────────────────────────────────────────────────────────

    def _hydrate(self, row: Any) -> AuditEntry:
        return AuditEntry(
            tenant_id=self._tenant,
            seq=int(row["seq"]),
            actor=row["actor"],
            action=row["action"],
            resource_type=row["resource_type"],
            resource_id=row["resource_id"],
            outcome=Outcome(row["outcome"]),
            occurred_at=Timestamp.parse(row["occurred_at"]),
            detail=json.loads(row["detail"]) if row["detail"] else {},
            prev_chain_hash=row["prev_chain_hash"],
            chain_hash=row["chain_hash"],
        )
