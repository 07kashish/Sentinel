"""The security audit trail, wired to every decision that grants or denies.

WHY A LOG LINE IS NOT AN AUDIT TRAIL
------------------------------------
Before this module, every authentication failure and authorisation denial was a
structured log line and nothing more. Log lines are:

  * **mutable** -- whoever reaches the log pipeline can edit or drop them
  * **unordered** -- interleaved across replicas, with no way to prove none is
    missing
  * **outside retention** -- shipped to a system with a 14-day window, when the
    question "who approved this remediation" is asked months later

So an attacker who obtained one valid credential left no tamper-evident trace of
what it was used for. That is the gap this closes, and it is the reason the trail
is hash-chained rather than merely written down: each entry commits to the previous
entry's digest, so removing or editing one breaks verification from that point
forward and the break names the sequence number.

WHAT IS RECORDED, AND WHAT IS DELIBERATELY NOT
----------------------------------------------
Recorded: the actor, the action, the resource, the outcome, and a small detail map.

NOT recorded: the presented credential, in any form that could be replayed. The
actor is `key:<first 12 hex of the SHA-256 digest>` -- enough to correlate every
action by one credential and to match it against the configured bindings, and not
enough to authenticate with. An audit trail that stores the credential is a
credential store with worse access control.

Also not recorded: request bodies. They contain the attacker-controlled content
this system exists to examine, and copying it into a second append-only table
doubles the surface for no investigative gain -- the incident record already holds
it, bounded.

FAILURE POLICY: THE AUDIT WRITE MUST NOT BREAK THE REQUEST
----------------------------------------------------------
An authentication DENIAL that cannot be audited is still a denial, and refusing
the request twice does not help. So a write failure is logged loudly and the
original outcome stands.

That is a deliberate trade and it is the weaker half of this design: an attacker
who can break the audit write can act unaudited. The alternative -- fail the
request when auditing fails -- converts a logging outage into a total outage of a
security service, which is the more likely event and the worse one. `verify()`
detects the resulting gap after the fact, because `seq` is dense.
"""

from __future__ import annotations

import json
from typing import Any, Mapping

from sentinel.domain.primitives import TenantId
from sentinel.infrastructure.persistence.audit import GENESIS, AuditEntry, Outcome

__all__ = ["NullSecurityAudit", "SqlSecurityAudit"]


class NullSecurityAudit:
    """Records nothing. For tests that are not about auditing.

    Explicit rather than `None`, so a caller never has to write `if self._audit`.
    A conditional around a security control is how the control comes to be skipped.
    """

    __slots__ = ()

    def record(self, **_kwargs: Any) -> None:
        return None


class SqlSecurityAudit:
    """Appends hash-chained entries to `security_audit` on the live engine.

    Reuses `AuditEntry` from the persistence package rather than reimplementing the
    canonicalisation and chaining. Two implementations of a hash chain is two
    chains that can disagree about what they committed to, and the difference would
    only surface during the investigation that needed it.
    """

    __slots__ = ("_pool", "_clock", "_logger")

    def __init__(self, *, pool: Any, clock: Any, logger: Any) -> None:
        self._pool = pool
        self._clock = clock
        self._logger = logger

    def record(
        self,
        *,
        tenant: TenantId,
        actor: str,
        action: str,
        resource_type: str,
        resource_id: str,
        outcome: Outcome,
        detail: Mapping[str, Any] | None = None,
    ) -> None:
        """Append one entry. Never raises.

        The whole call is wrapped: a broken audit write must not turn a 403 into a
        500, because the 403 was correct and the caller learning about our database
        is a disclosure.
        """
        try:
            self._append(
                tenant=tenant,
                actor=actor,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                outcome=outcome,
                detail=detail or {},
            )
        except Exception as exc:  # noqa: BLE001 - auditing must not break a request
            # Loud, because this is the condition under which an attacker can act
            # unaudited. `seq` is dense, so `verify()` finds the gap afterwards.
            self._logger.error(
                "security_audit_write_failed",
                error_type=type(exc).__name__,
                error=str(exc),
                audited_action=action,
                audited_outcome=outcome.value,
            )

    def _append(
        self,
        *,
        tenant: TenantId,
        actor: str,
        action: str,
        resource_type: str,
        resource_id: str,
        outcome: Outcome,
        detail: Mapping[str, Any],
    ) -> None:
        with self._pool.acquire() as conn:
            conn.begin()
            try:
                conn.set_tenant(tenant.value)
                # Serialise appends for this tenant. `SELECT ... FOR UPDATE` cannot
                # lock the head row when there is no head row yet, so two
                # concurrent first-writes would both read prev=GENESIS and fork the
                # chain -- the exact defect found and fixed in the persistence
                # audit log. An advisory lock has something to hold when the table
                # is empty.
                conn.serialise_tenant(tenant.value, purpose="security_audit")
                head = conn.one(
                    "SELECT seq, chain_hash FROM security_audit "
                    f"WHERE tenant_id={conn.p} ORDER BY seq DESC LIMIT 1",
                    (tenant.value,),
                )
                previous_seq = int(head["seq"]) if head else 0
                previous_hash = str(head["chain_hash"]) if head else GENESIS

                entry = AuditEntry(
                    tenant_id=tenant,
                    seq=previous_seq + 1,
                    actor=actor,
                    action=action,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    outcome=outcome,
                    # `Clock.now()` already returns a `Timestamp`; wrapping it again
                    # raises InvalidValue, and because `record` swallows everything
                    # that presented as "auditing silently does nothing".
                    occurred_at=self._clock.now(),
                    detail=dict(detail),
                    prev_chain_hash=previous_hash,
                )
                sealed = AuditEntry(
                    **{
                        **{
                            field: getattr(entry, field)
                            for field in AuditEntry.__slots__
                            if field != "chain_hash"
                        },
                        "chain_hash": entry.compute_chain_hash(),
                    }
                )
                p = conn.p
                conn.execute_rowcount(
                    "INSERT INTO security_audit (tenant_id, seq, actor, action, "
                    "resource_type, resource_id, outcome, occurred_at, detail, "
                    f"prev_chain_hash, chain_hash) VALUES "
                    f"({p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p})",
                    (
                        tenant.value,
                        sealed.seq,
                        sealed.actor,
                        sealed.action,
                        sealed.resource_type,
                        sealed.resource_id,
                        sealed.outcome.value,
                        sealed.occurred_at.isoformat(),
                        json.dumps(dict(sealed.detail), sort_keys=True, default=str),
                        sealed.prev_chain_hash,
                        sealed.chain_hash,
                    ),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
