"""Ledger, approval and outbox repositories.

Split out of `unit_of_work.py` when that module crossed the size at which it
stops having one reason to change -- a limit this codebase enforces on itself in
`tests_arch/test_architecture_rules.py` rather than leaving to judgement.

Every class here is constructed BY the unit of work and shares its connection and
transaction. They are private to that module by convention and by leading
underscore: obtaining one outside a unit of work would be obtaining a repository
outside a transaction, which is the class of defect the unit-of-work pattern
exists to prevent.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Mapping, Sequence

from sentinel.application.ports import Clock
from sentinel.application.records import ApprovalRecord, EvidenceRecord, OutboxRecord
from sentinel.domain.errors import ArtifactMissing, ConcurrencyConflict
from sentinel.domain.primitives import (
    Address,
    ApprovalId,
    BatchId,
    Digest,
    IdempotencyKey,
    IncidentId,
    MessageId,
    TenantId,
    Timestamp,
)
from sentinel.infrastructure.sql.engine import Connection

__all__ = ["GENESIS", "LedgerRepository", "ApprovalRepository", "OutboxRepository"]

#: The zero hash every tenant's chain starts from.
GENESIS = Digest("0" * 64)


def _dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


#: Marks a sealed evidence body. A body without it is plaintext JSON written
#: before a data key was configured, and stays readable.
SEALED_PREFIX = "enc:"


class EvidenceSealed(RuntimeError):
    """An encrypted evidence body was read by a process holding no key."""


class LedgerRepository:
    __slots__ = ("_conn", "_tenant", "_clock", "_cipher")

    def __init__(self, conn: Connection, tenant: TenantId, clock: Clock, *, cipher: Any = None) -> None:
        self._conn = conn
        self._tenant = tenant
        self._clock = clock
        #: `EnvelopeCipher`, or None. With one, evidence BODIES are sealed per
        #: record under a data key wrapped by the deployment's key, bound to
        #: this tenant and incident, so a row copied to another tenant or
        #: another incident does not open. The digest column is over the
        #: plaintext and is unaffected, so verification does not need the key.
        self._cipher = cipher

    def _seal_body(self, incident_id: str, content: Mapping[str, Any]) -> str:
        if self._cipher is None:
            return _dumps(content)
        return SEALED_PREFIX + self._cipher.seal_json(
            content, tenant_id=self._tenant.value, record_type="evidence", record_id=incident_id
        )

    def _open_body(self, incident_id: str, stored: str | None) -> Mapping[str, Any]:
        if not stored:
            return {}
        if not stored.startswith(SEALED_PREFIX):
            return json.loads(stored)  # written before encryption was configured
        if self._cipher is None:
            raise EvidenceSealed(
                f"evidence for incident {incident_id!r} is encrypted and this process has no "
                "data key configured; refusing to return an empty body in its place"
            )
        return self._cipher.open_json(
            stored[len(SEALED_PREFIX):], tenant_id=self._tenant.value,
            record_type="evidence", record_id=incident_id,
        )

    def reseal_evidence(self, *, limit: int = 500) -> int:
        """Seal plaintext bodies and rewrap sealed ones under the active key. Returns rows changed.

        This is both the migration (rows written before keys were configured)
        and the rotation (rows sealed under a retired key id). Idempotent: a row
        already sealed under the active key is left alone.
        """
        if self._cipher is None:
            return 0
        p = self._conn.p
        active = f"{SEALED_PREFIX}1.{self._cipher.active_key_id}."
        # Rows already under the active key are excluded IN the query. Skipping
        # them in the loop instead would let a first page of finished rows end a
        # batched run before it ever reached the rows that still need work.
        rows = self._conn.execute(
            f"SELECT incident_id, content_json FROM evidence WHERE tenant_id={p} "
            f"AND content_json IS NOT NULL AND content_json NOT LIKE {p} ORDER BY incident_id LIMIT {p}",
            (self._tenant.value, active + "%", int(limit)),
        )
        changed = 0
        for row in rows:
            stored, incident = str(row["content_json"]), str(row["incident_id"])
            if stored.startswith(active):
                continue
            if stored.startswith(SEALED_PREFIX):
                # Rotation rewraps the ~60-byte data key; the payload is never decrypted.
                from sentinel.infrastructure.persistence.crypto import CipherText

                resealed = SEALED_PREFIX + self._cipher.rewrap(
                    CipherText.from_wire(stored[len(SEALED_PREFIX):]), tenant_id=self._tenant.value,
                    record_type="evidence", record_id=incident,
                ).to_wire()
            else:
                resealed = self._seal_body(incident, json.loads(stored))
            changed += self._conn.execute_rowcount(
                f"UPDATE evidence SET content_json={p} WHERE tenant_id={p} AND incident_id={p} AND content_json={p}",
                (resealed, self._tenant.value, incident, stored),
            )
        return changed

    def head(self) -> Digest | None:
        p = self._conn.p
        row = self._conn.one(
            f"SELECT chain_hash FROM ledger_entries WHERE tenant_id={p} "
            f"ORDER BY seq DESC LIMIT 1",
            (self._tenant.value,),
        )
        return Digest(row["chain_hash"]) if row else None

    def append(
        self, *, incident_id: IncidentId, entry_hash: Digest, manifest: Mapping[str, Any]
    ) -> tuple[int, Digest]:
        """Append a leaf, reading the head INSIDE this transaction.

        The predecessor read the head on one connection and inserted on another,
        so eight concurrent writers could fork the chain. Reading it here, under
        the same transaction that inserts, plus `UNIQUE(tenant_id,
        prev_chain_hash)`, makes a fork unstorable rather than merely unlikely.
        """
        import hashlib

        p = self._conn.p
        # Serialise the whole append for this tenant. The FOR UPDATE below is
        # kept as well -- it is correct once a head exists -- but it cannot be
        # the only guard, because an empty chain has no row to lock.
        self._conn.serialise_tenant(self._tenant.value, purpose="ledger-append")
        head_row = self._conn.one(
            f"SELECT seq, chain_hash FROM ledger_entries WHERE tenant_id={p} "
            f"ORDER BY seq DESC LIMIT 1" + self._conn.lock_clause(),
            (self._tenant.value,),
        )
        previous = Digest(head_row["chain_hash"]) if head_row else GENESIS
        sequence = (int(head_row["seq"]) + 1) if head_row else 1
        chained = Digest(
            hashlib.sha256(f"{previous.value}{entry_hash.value}".encode()).hexdigest()
        )
        now = self._now()
        self._conn.execute_rowcount(
            f"INSERT INTO ledger_entries (tenant_id, seq, incident_id, entry_hash, "
            f"prev_chain_hash, chain_hash, manifest_json, batch_id, created_at) "
            f"VALUES ({p},{p},{p},{p},{p},{p},{p},NULL,{p})",
            (
                self._tenant.value,
                sequence,
                incident_id.value,
                entry_hash.value,
                previous.value,
                chained.value,
                _dumps(manifest),
                now,
            ),
        )
        return sequence, chained

    def store_evidence(self, record: EvidenceRecord) -> None:
        p = self._conn.p
        self._conn.execute_rowcount(
            f"INSERT INTO evidence (tenant_id, incident_id, uri, digest, content_json, "
            f"created_at) VALUES ({p},{p},{p},{p},{p},{p}) "
            f"ON CONFLICT (tenant_id, incident_id) DO NOTHING",
            (
                self._tenant.value,
                record.incident_id.value,
                record.uri,
                record.digest.value,
                self._seal_body(record.incident_id.value, record.content),
                record.created_at.isoformat(),
            ),
        )

    def get_evidence(self, incident_id: IncidentId) -> EvidenceRecord | None:
        p = self._conn.p
        row = self._conn.one(
            f"SELECT * FROM evidence WHERE tenant_id={p} AND incident_id={p}",
            (self._tenant.value, incident_id.value),
        )
        if row is None:
            return None
        return EvidenceRecord(
            incident_id=IncidentId(row["incident_id"]),
            uri=row["uri"],
            digest=Digest(row["digest"]),
            content=self._open_body(row["incident_id"], row["content_json"]),
            created_at=Timestamp.parse(row["created_at"]),
            redacted_at=Timestamp.parse(row["redacted_at"]) if row["redacted_at"] else None,
            redaction_reason=row["redaction_reason"],
        )

    def unsealed_entries(self, *, limit: int) -> Sequence[Mapping[str, Any]]:
        p = self._conn.p
        rows = self._conn.execute(
            f"SELECT seq, incident_id, entry_hash FROM ledger_entries "
            f"WHERE tenant_id={p} AND batch_id IS NULL ORDER BY seq ASC LIMIT {p}",
            (self._tenant.value, limit),
        )
        return [dict(r) for r in rows]

    def seal(
        self,
        *,
        batch_id: BatchId,
        merkle_root: Digest,
        sequences: Sequence[int],
        signature: str | None,
        signer: Address | None,
        manifest: Mapping[str, Any],
        at: Timestamp,
    ) -> None:
        p = self._conn.p
        self._conn.execute_rowcount(
            f"INSERT INTO ledger_batches (tenant_id, batch_id, merkle_root, leaf_count, "
            f"root_signature, signer_address, manifest_json, sealed_at) "
            f"VALUES ({p},{p},{p},{p},{p},{p},{p},{p})",
            (
                self._tenant.value,
                batch_id.value,
                merkle_root.value,
                len(sequences),
                signature,
                signer.value if signer else None,
                _dumps(manifest),
                at.isoformat(),
            ),
        )
        for sequence in sequences:
            claimed = self._conn.execute_rowcount(
                f"UPDATE ledger_entries SET batch_id={p} "
                f"WHERE tenant_id={p} AND seq={p} AND batch_id IS NULL",
                (batch_id.value, self._tenant.value, sequence),
            )
            if claimed == 0:
                raise ConcurrencyConflict(
                    f"ledger entry {sequence} was sealed into another batch "
                    "concurrently; this seal is abandoned"
                )

    def store_report(self, *, incident_id: IncidentId, content: str, at: Timestamp) -> None:
        p = self._conn.p
        self._conn.execute_rowcount(
            f"INSERT INTO reports (tenant_id, incident_id, content, created_at) "
            f"VALUES ({p},{p},{p},{p}) ON CONFLICT (tenant_id, incident_id) DO NOTHING",
            (self._tenant.value, incident_id.value, content, at.isoformat()),
        )

    def get_report(self, incident_id: IncidentId) -> str | None:
        p = self._conn.p
        row = self._conn.one(
            f"SELECT content FROM reports WHERE tenant_id={p} AND incident_id={p} "
            f"AND withdrawn_at IS NULL",
            (self._tenant.value, incident_id.value),
        )
        return row["content"] if row else None

    def redact_evidence(
        self, *, incident_id: IncidentId, reason: str, actor: str, at: Timestamp
    ) -> bool:
        """Destroy the evidence BODY and leave an auditable tombstone.

        The ledger commitment and the hash chain are untouched, so every
        inclusion proof over this entry still verifies and `verify_package`
        reports REDACTED distinctly from tampering. That separation -- commitment
        in the append-only chain, body in a mutable row -- is what makes lawful
        erasure possible at all without breaking the proofs.

        Idempotent: redacting an already-redacted body is a no-op, so a retried
        compensation cannot overwrite the original reason with a later one.
        """
        p = self._conn.p
        return bool(
            self._conn.execute_rowcount(
                f"UPDATE evidence SET content_json=NULL, redacted_at={p}, "
                f"redaction_reason={p}, redacted_by={p} "
                f"WHERE tenant_id={p} AND incident_id={p} AND redacted_at IS NULL",
                (
                    at.isoformat(),
                    reason[:1000],
                    actor,
                    self._tenant.value,
                    incident_id.value,
                ),
            )
        )

    def withdraw_report(
        self, *, incident_id: IncidentId, reason: str, at: Timestamp
    ) -> bool:
        """Mark a report withdrawn. The text is retained deliberately.

        A withdrawn report is still evidence of what this system said at the
        time, and an audit trail that deletes its own mistakes is not one.
        Idempotent on `withdrawn_at IS NULL`.
        """
        p = self._conn.p
        return bool(
            self._conn.execute_rowcount(
                f"UPDATE reports SET withdrawn_at={p}, withdrawn_why={p} "
                f"WHERE tenant_id={p} AND incident_id={p} AND withdrawn_at IS NULL",
                (at.isoformat(), reason[:1000], self._tenant.value, incident_id.value),
            )
        )

    def _now(self) -> str:
        return self._clock.now().isoformat()


class ApprovalRepository:
    __slots__ = ("_conn", "_tenant")

    def __init__(self, conn: Connection, tenant: TenantId) -> None:
        self._conn = conn
        self._tenant = tenant

    def _hydrate(self, row: Any) -> ApprovalRecord:
        return ApprovalRecord(
            approval_id=ApprovalId(row["approval_id"]),
            incident_id=IncidentId(row["incident_id"]),
            action=row["action"],
            target=row["target"],
            state=row["state"],
            proposed_at=Timestamp.parse(row["proposed_at"]),
            decided_by=row["decided_by"],
            decided_at=Timestamp.parse(row["decided_at"]) if row["decided_at"] else None,
            receipt=json.loads(row["receipt_json"]) if row["receipt_json"] else {},
            # `_hydrate` is the ONLY place these reach the domain record. A column
            # added to the table and to the INSERT but not read back here would
            # leave `expires_at` permanently None, and the expiry check in
            # `DecideApprovalHandler` would be a branch that can never be taken --
            # a gate that executes nothing, which is this repository's most-found
            # defect. `test_an_approval_past_its_window_is_refused` fails if this
            # line is removed.
            expires_at=Timestamp.parse(row["expires_at"]) if row["expires_at"] else None,
            context=json.loads(row["context_json"]) if row["context_json"] else {},
        )

    def propose(self, records: Sequence[ApprovalRecord]) -> None:
        p = self._conn.p
        for record in records:
            self._conn.execute_rowcount(
                f"INSERT INTO approvals (tenant_id, approval_id, incident_id, action, target, "
                f"state, proposed_at, expires_at, context_json) "
                f"VALUES ({p},{p},{p},{p},{p},{p},{p},{p},{p}) "
                f"ON CONFLICT (tenant_id, approval_id) DO NOTHING",
                (
                    self._tenant.value,
                    record.approval_id.value,
                    record.incident_id.value,
                    record.action,
                    record.target,
                    "pending",
                    record.proposed_at.isoformat(),
                    record.expires_at.isoformat() if record.expires_at else "",
                    json.dumps(dict(record.context)) if record.context else None,
                ),
            )

    def get(self, approval_id: ApprovalId) -> ApprovalRecord | None:
        p = self._conn.p
        row = self._conn.one(
            f"SELECT * FROM approvals WHERE tenant_id={p} AND approval_id={p}",
            (self._tenant.value, approval_id.value),
        )
        return self._hydrate(row) if row else None

    def claim_for_execution(
        self, approval_id: ApprovalId, *, at: Timestamp | None = None
    ) -> ApprovalRecord | None:
        """Atomically move pending -> executing.

        A conditional UPDATE, not a read-then-check. The predecessor read the
        state, compared it to `"pending"`, performed the EXTERNAL remediation,
        and only then wrote -- with no lock and no transaction spanning the
        three. Two concurrent decisions both saw `pending` and both invoked the
        real-world action. This is the human-approval gate: the one place the
        product touches the world, and it was the least protected write path in
        the codebase.
        """
        p = self._conn.p
        affected = self._conn.execute_rowcount(
            f"UPDATE approvals SET state='executing', executing_since={p} "
            f"WHERE tenant_id={p} AND approval_id={p} AND state='pending'",
            (at.isoformat() if at is not None else "", self._tenant.value, approval_id.value),
        )
        if affected == 0:
            return None
        return self.get(approval_id)

    def record_outcome(
        self,
        *,
        approval_id: ApprovalId,
        state: str,
        decided_by: str,
        receipt: Mapping[str, Any],
        at: Timestamp,
    ) -> None:
        p = self._conn.p
        self._conn.execute_rowcount(
            f"UPDATE approvals SET state={p}, decided_by={p}, decided_at={p}, "
            f"receipt_json={p}, executing_since='' "
            f"WHERE tenant_id={p} AND approval_id={p}",
            (
                state,
                decided_by,
                at.isoformat(),
                _dumps(receipt),
                self._tenant.value,
                approval_id.value,
            ),
        )

    def release(self, approval_id: ApprovalId, *, error: str, at: Timestamp) -> None:
        p = self._conn.p
        self._conn.execute_rowcount(
            f"UPDATE approvals SET state='pending', receipt_json={p}, executing_since='' "
            f"WHERE tenant_id={p} AND approval_id={p} AND state='executing'",
            (_dumps({"last_error": error[:1000]}), self._tenant.value, approval_id.value),
        )

    def reap_stale_execution_claims(self, *, older_than: Timestamp, at: Timestamp) -> int:
        """Release approval claims whose executor lease has expired."""
        p = self._conn.p
        return self._conn.execute_rowcount(
            f"UPDATE approvals SET state='pending', receipt_json={p}, executing_since='' "
            f"WHERE tenant_id={p} AND state='executing' AND executing_since<>'' "
            f"AND executing_since<{p}",
            (
                _dumps(
                    {
                        "last_error": "execution claim lease expired; released by maintenance",
                        "released_at": at.isoformat(),
                    }
                ),
                self._tenant.value,
                older_than.isoformat(),
            ),
        )

    def withdraw(self, approval_id: ApprovalId, *, reason: str, at: Timestamp) -> bool:
        """Withdraw a proposal a human has not yet acted on.

        Scoped to `state='pending'`. An approval a human already decided is a
        record of a human decision and the action may already have reached the
        world; a compensation must not erase either.
        """
        p = self._conn.p
        return bool(
            self._conn.execute_rowcount(
                f"UPDATE approvals SET state='withdrawn', decided_at={p}, receipt_json={p} "
                f"WHERE tenant_id={p} AND approval_id={p} AND state='pending'",
                (
                    at.isoformat(),
                    _dumps({"outcome": "withdrawn", "executed": False, "reason": reason}),
                    self._tenant.value,
                    approval_id.value,
                ),
            )
        )

    def pending_for_incident(self, incident_id: IncidentId) -> Sequence[ApprovalRecord]:
        p = self._conn.p
        rows = self._conn.execute(
            f"SELECT * FROM approvals WHERE tenant_id={p} AND incident_id={p} "
            f"AND state='pending' ORDER BY proposed_at ASC",
            (self._tenant.value, incident_id.value),
        )
        return [self._hydrate(r) for r in rows]


class OutboxRepository:
    __slots__ = ("_conn", "_tenant")

    def __init__(self, conn: Connection, tenant: TenantId) -> None:
        self._conn = conn
        self._tenant = tenant

    def _hydrate(self, row: Any) -> OutboxRecord:
        return OutboxRecord(
            record_id=MessageId(row["record_id"]),
            tenant_id=self._tenant,
            incident_id=IncidentId(row["incident_id"]),
            kind=row["kind"],
            payload=json.loads(row["payload_json"]),
            idempotency_key=IdempotencyKey(row["idempotency_key"]),
            attempts=int(row["attempts"]),
            max_attempts=int(row["max_attempts"]),
            state=row["state"],
            last_error=row["last_error"],
        )

    def enqueue(
        self,
        *,
        incident_id: IncidentId,
        kind: str,
        payload: Mapping[str, Any],
        idempotency_key: IdempotencyKey,
        at: Timestamp,
    ) -> IdempotencyKey:
        p = self._conn.p
        existing = self._conn.one(
            f"SELECT idempotency_key FROM outbox WHERE tenant_id={p} AND idempotency_key={p}",
            (self._tenant.value, idempotency_key.value),
        )
        if existing is not None:
            return idempotency_key
        self._conn.execute_rowcount(
            f"INSERT INTO outbox (tenant_id, record_id, incident_id, kind, payload_json, "
            f"idempotency_key, state, attempts, max_attempts, available_at, created_at, "
            f"updated_at) VALUES ({p},{p},{p},{p},{p},{p},'pending',0,5,{p},{p},{p}) "
            f"ON CONFLICT (tenant_id, idempotency_key) DO NOTHING",
            (
                self._tenant.value,
                uuid.uuid4().hex,
                incident_id.value,
                kind,
                _dumps(payload),
                idempotency_key.value,
                at.isoformat(),
                at.isoformat(),
                at.isoformat(),
            ),
        )
        return idempotency_key

    def claim_batch(
        self, *, limit: int, now: Timestamp, lease_seconds: int
    ) -> Sequence[OutboxRecord]:
        """Claim due records by taking an ABSOLUTE lease, not a jittered delay.

        The predecessor claimed by pushing `next_at` forward by
        `random.uniform(0, ceiling)` and documented the result as exclusive. Full
        jitter has a lower bound of zero, so a small draw left the row
        immediately due again and a concurrent drain re-claimed it. A duplicated
        delivery is indistinguishable at the receiver from a real second event.

        Here the row moves to `delivering` with an explicit `lease_until`. State
        and deadline are both set in the transaction that reads the row, so a
        second claimer sees `delivering` regardless of any random draw.
        """
        from datetime import timedelta

        p = self._conn.p
        deadline = Timestamp(now.value + timedelta(seconds=lease_seconds))
        rows = self._conn.execute(
            f"SELECT * FROM outbox WHERE tenant_id={p} AND state='pending' "
            f"AND available_at<={p} ORDER BY available_at ASC LIMIT {p}"
            + self._conn.lock_clause(skip_locked=True),
            (self._tenant.value, now.isoformat(), limit),
        )
        claimed: list[OutboxRecord] = []
        for row in rows:
            affected = self._conn.execute_rowcount(
                f"UPDATE outbox SET state='delivering', lease_until={p}, updated_at={p} "
                f"WHERE tenant_id={p} AND record_id={p} AND state='pending'",
                (deadline.isoformat(), now.isoformat(), self._tenant.value, row["record_id"]),
            )
            if affected:
                claimed.append(self._hydrate(row))
        return claimed

    def mark_delivered(
        self, *, record_id: MessageId, result: Mapping[str, Any], at: Timestamp
    ) -> None:
        p = self._conn.p
        self._conn.execute_rowcount(
            f"UPDATE outbox SET state='delivered', result_json={p}, lease_until=NULL, "
            f"updated_at={p} WHERE tenant_id={p} AND record_id={p}",
            (_dumps(result), at.isoformat(), self._tenant.value, record_id.value),
        )

    def mark_failed(self, *, record_id: MessageId, error: str, at: Timestamp) -> str:
        """Increment and decide terminality under ONE lock.

        Deciding the next state from a separately-read `attempts` lets two
        concurrent failures both observe the same count and each grant one extra
        attempt.
        """
        from datetime import timedelta

        p = self._conn.p
        row = self._conn.one(
            f"SELECT attempts, max_attempts FROM outbox WHERE tenant_id={p} AND record_id={p}"
            + self._conn.lock_clause(),
            (self._tenant.value, record_id.value),
        )
        if row is None:
            raise ArtifactMissing(f"no outbox record {record_id} for this tenant")
        attempts = int(row["attempts"]) + 1
        state = "dead" if attempts >= int(row["max_attempts"]) else "pending"
        backoff = min(300, 2 ** min(attempts, 8))
        self._conn.execute_rowcount(
            f"UPDATE outbox SET attempts={p}, state={p}, last_error={p}, available_at={p}, "
            f"lease_until=NULL, updated_at={p} WHERE tenant_id={p} AND record_id={p}",
            (
                attempts,
                state,
                error[:1000],
                Timestamp(at.value + timedelta(seconds=backoff)).isoformat(),
                at.isoformat(),
                self._tenant.value,
                record_id.value,
            ),
        )
        return state

    def reap_expired_leases(self, *, now: Timestamp) -> int:
        """Return records whose deliverer died to `pending`.

        Without this the predecessor's `delivering` was a terminal hang state: a
        worker killed mid-delivery stranded the row forever, because nothing
        swept it and only the exception path released the claim.
        """
        p = self._conn.p
        return self._conn.execute_rowcount(
            f"UPDATE outbox SET state='pending', lease_until=NULL, updated_at={p} "
            f"WHERE tenant_id={p} AND state='delivering' AND lease_until IS NOT NULL "
            f"AND lease_until<{p}",
            (now.isoformat(), self._tenant.value, now.isoformat()),
        )

    def dead_letters(self, *, limit: int) -> Sequence[OutboxRecord]:
        p = self._conn.p
        rows = self._conn.execute(
            f"SELECT * FROM outbox WHERE tenant_id={p} AND state='dead' "
            f"ORDER BY updated_at DESC LIMIT {p}",
            (self._tenant.value, limit),
        )
        return [self._hydrate(r) for r in rows]

    def replay(self, record_id: MessageId, *, at: Timestamp) -> bool:
        p = self._conn.p
        return bool(
            self._conn.execute_rowcount(
                f"UPDATE outbox SET state='pending', attempts=0, available_at={p}, "
                f"updated_at={p} WHERE tenant_id={p} AND record_id={p} AND state='dead'",
                (at.isoformat(), at.isoformat(), self._tenant.value, record_id.value),
            )
        )
