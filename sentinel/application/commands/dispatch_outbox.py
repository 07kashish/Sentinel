"""The outbox dispatcher. The half the predecessor never built.

WHY THIS EXISTS AS A SEPARATE COMMAND
--------------------------------------
The predecessor had an `attestation_outbox` table with `pending`, `delivering`
and `delivered` states -- the outbox *table* pattern with none of the outbox
*dispatch* pattern. The intent was written and then, in the same call stack, by
the same worker, immediately claimed and delivered. There was no independent
dispatcher, which had three consequences:

  * A worker killed between `claim` and `complete` stranded the row in
    `delivering` **forever**. Nothing swept it; only the exception path released
    the claim, so a SIGKILL was permanent.
  * The delivery inherited the pipeline's retry budget rather than having its
    own, so an attestation gateway outage consumed the incident's attempts.
  * `dlq.drain()`, the function that would have retried failed deliveries, had
    **zero callers**. The dead-letter queue was write-only, and `/dlq/{id}/replay`
    moved a record from `dead` to `pending` where nothing would ever pick it up
    -- so the operator's "retry" button silently removed the failure from view
    without delivering it.

This handler is the missing consumer. It is invoked on an interval by a
leader-elected job (see `sentinel.interface.worker`), claims a bounded batch
under an absolute lease, delivers, and records the outcome. It reaps expired
leases first, so a dead deliverer's work returns to the queue rather than
stranding.
"""

from __future__ import annotations

import inspect

from dataclasses import dataclass
from typing import Any

from sentinel.application.messages import Command, Result
from sentinel.application.ports import (
    AttestationGateway,
    Clock,
    Logger,
    UnitOfWorkFactory,
)
from sentinel.domain.incident import AttestationDisposition
from sentinel.domain.primitives import Address, Digest

__all__ = ["DispatchOutbox", "DispatchOutboxHandler"]


def _accepted_parameters(callable_: Any) -> frozenset[str]:
    """Parameter names a callable accepts, or an empty set if unreadable.

    Empty on failure rather than raising: an exotic callable that cannot be
    introspected is delivered to WITHOUT the tenant, which is the pre-existing
    behaviour and therefore the safe direction for an unknown.
    """
    try:
        return frozenset(inspect.signature(callable_).parameters)
    except (TypeError, ValueError):  # pragma: no cover - exotic callables
        return frozenset()

@dataclass(frozen=True, slots=True)
class DispatchOutbox(Command):
    """Deliver one batch of durable intents for this tenant."""


class DispatchOutboxHandler:
    __slots__ = (
        "_uow_factory",
        "_attestation",
        "_siem",
        "_clock",
        "_logger",
        "_batch_size",
        "_lease_seconds",
    )

    def __init__(
        self,
        *,
        uow_factory: UnitOfWorkFactory,
        attestation: AttestationGateway,
        clock: Clock,
        logger: Logger,
        siem_deliverer: Any = None,
        batch_size: int = 50,
        lease_seconds: int = 120,
    ) -> None:
        self._uow_factory = uow_factory
        self._attestation = attestation
        # Optional, like every other integration in this codebase: None means
        # SIEM export is not configured, and an outbox row of kind "siem" is
        # then a misconfiguration rather than a silent no-op -- `_deliver`
        # refuses it by name rather than dropping it.
        self._siem = siem_deliverer
        self._clock = clock
        self._logger = logger
        self._batch_size = batch_size
        self._lease_seconds = lease_seconds

    def handle(self, command: DispatchOutbox) -> Result:
        now = self._clock.now()
        tenant = command.tenant

        # 1. Reap first. A deliverer that died holds a lease that has expired;
        #    returning its record to `pending` here is the only thing that stops
        #    `delivering` being a terminal hang state.
        with self._uow_factory.begin(tenant) as uow:
            reaped = uow.outbox.reap_expired_leases(now=now)
            uow.commit()
        if reaped:
            self._logger.warning(
                "outbox_leases_reaped", tenant=str(tenant), count=reaped
            )

        # 2. Claim a bounded batch. Bounded because the predecessor's claim
        #    loaded every due row for every tenant into memory with no LIMIT.
        with self._uow_factory.begin(tenant) as uow:
            batch = list(
                uow.outbox.claim_batch(
                    limit=self._batch_size, now=now, lease_seconds=self._lease_seconds
                )
            )
            uow.commit()

        delivered = failed = dead = 0
        for record in batch:
            # 3. Deliver OUTSIDE the transaction. A third party's latency must
            #    not be a database connection's hold time.
            # `str | None`: the success path genuinely has no error, and the
            # first binding below is a string, so mypy inferred `str` and then
            # rejected the None that the anchored case assigns.
            error: str | None
            try:
                outcome = self._deliver(record)
            except Exception as exc:  # noqa: BLE001 - one bad record must not stop the batch
                outcome = None
                error = f"{type(exc).__name__}: {exc}"
            else:
                error = None if outcome.is_anchored else outcome.detail

            with self._uow_factory.begin(tenant) as uow:
                if outcome is not None and outcome.is_anchored:
                    uow.outbox.mark_delivered(
                        record_id=record.record_id,
                        result={
                            "disposition": outcome.disposition.value,
                            "transaction_hash": outcome.transaction_hash,
                            "detail": outcome.detail,
                        },
                        at=now,
                    )
                    delivered += 1
                elif (
                    outcome is not None
                    and outcome.disposition is AttestationDisposition.NOT_ANCHORABLE
                ):
                    # Permanent for this record. Marking it delivered with an
                    # explicit non-anchored disposition is honest and stops it
                    # consuming a retry budget it can never satisfy.
                    uow.outbox.mark_delivered(
                        record_id=record.record_id,
                        result={
                            "disposition": outcome.disposition.value,
                            "detail": outcome.detail,
                            "anchored": False,
                        },
                        at=now,
                    )
                    delivered += 1
                else:
                    state = uow.outbox.mark_failed(
                        record_id=record.record_id,
                        error=error or "delivery did not produce an outcome",
                        at=now,
                    )
                    failed += 1
                    if state == "dead":
                        dead += 1
                uow.commit()

        if dead:
            # A dead letter is a hole in the customer's audit trail. It is
            # counted and logged at error so it is discoverable without anyone
            # remembering to look at a table.
            self._logger.error(
                "outbox_records_dead",
                tenant=str(tenant),
                count=dead,
                detail="these deliveries exhausted their budget and need an operator",
            )

        return Result.accepted(
            "dispatched",
            claimed=len(batch),
            delivered=delivered,
            failed=failed,
            dead=dead,
            reaped=reaped,
        )

    def _deliver(self, record):
        if record.kind == "siem":
            # Refused BY NAME when unconfigured, never dropped. A row of this
            # kind exists because something committed the intent to export it;
            # treating it as delivered because no deliverer happens to be wired
            # would discard a security event, which is the one outcome this
            # pipeline exists to prevent. Failing keeps it on the retry budget
            # and, on exhaustion, in the dead-letter state where it is visible.
            if self._siem is None:
                raise ValueError(
                    "an outbox row of kind 'siem' was claimed but no SIEM "
                    "deliverer is configured. Set SENTINEL_SIEM_WEBHOOK_URL, or "
                    "stop enqueuing exports -- the event is NOT discarded."
                )
            # THE TENANT COMES FROM THE RECORD, never from the payload.
            #
            # A tenant-routed deliverer sends each tenant's events to that
            # tenant's own sink; one built from process-wide settings sends
            # everything to one endpoint and takes no tenant at all. Both are
            # valid -- the second is correct for a single-tenant deployment --
            # so the tenant is passed only to a deliverer that declares it.
            #
            # Inspected rather than try/except TypeError, for the reason
            # `remediation._invoke` records: catching it would also swallow a
            # TypeError raised INSIDE a correct deliverer and silently retry
            # without the tenant, which for a routed deliverer means retrying
            # against no destination at all.
            if "tenant" in _accepted_parameters(self._siem.deliver):
                return self._siem.deliver(
                    payload=record.payload,
                    idempotency_key=record.idempotency_key.value,
                    tenant=str(record.tenant_id),
                )
            return self._siem.deliver(
                payload=record.payload, idempotency_key=record.idempotency_key.value
            )
        if record.kind != "attestation":
            raise ValueError(f"no deliverer is registered for outbox kind {record.kind!r}")
        payload = record.payload
        raw_subject = payload.get("subject")
        subject = Address(raw_subject) if isinstance(raw_subject, str) and raw_subject else None
        return self._attestation.anchor(
            tenant=record.tenant_id,
            incident_id=record.incident_id,
            evidence_digest=Digest(str(payload["evidence_digest"])),
            subject=subject,
            idempotency_key=record.idempotency_key,
        )
