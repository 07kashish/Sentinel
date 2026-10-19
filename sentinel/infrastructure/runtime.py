"""Process-runtime adapters: time, identifiers, and structured logging.

Each is a port implementation the composition root constructs once and injects.
The predecessor called `datetime.now()` in fourteen modules and `time.time()` in
its rate limiter, so no time-dependent rule could be tested without freezing time
globally, and a "shared" token bucket was only as accurate as NTP across the
fleet.
"""

from __future__ import annotations

import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping

from sentinel.domain.primitives import (
    ApprovalId,
    BatchId,
    IdempotencyKey,
    IncidentId,
    MessageId,
    TenantId,
    Timestamp,
)

__all__ = ["StructuredLogger", "SystemClock", "UuidIdGenerator"]


class SystemClock:
    """Wall-clock time, UTC, injected everywhere rather than called everywhere."""

    __slots__ = ()

    def now(self) -> Timestamp:
        return Timestamp(datetime.now(timezone.utc))


class UuidIdGenerator:
    """Identifier minting.

    The attestation idempotency key is a UUID5 over (tenant, incident): stable
    for a given incident across every retry, so the gateway deduplicates a
    replayed anchor rather than writing it twice. A random key per attempt would
    make the outbox's whole reason for existing inoperative.
    """

    __slots__ = ("_namespace",)

    _NAMESPACE = uuid.UUID("6f9619ff-8b86-d011-b42d-00c04fc964ff")

    def __init__(self, namespace: uuid.UUID | None = None) -> None:
        self._namespace = namespace or self._NAMESPACE

    def incident_id(self) -> IncidentId:
        return IncidentId(f"inc-{uuid.uuid4().hex}")

    def approval_id(self) -> ApprovalId:
        return ApprovalId(f"apr-{uuid.uuid4().hex}")

    def batch_id(self, *, at: Timestamp) -> BatchId:
        stamp = at.value.strftime("%Y%m%dT%H%M%SZ")
        return BatchId(f"batch-{stamp}-{uuid.uuid4().hex[:8]}")

    def message_id(self) -> MessageId:
        return MessageId(f"msg-{uuid.uuid4().hex}")

    def idempotency_key(self, *, tenant: TenantId, incident: IncidentId) -> IdempotencyKey:
        derived = uuid.uuid5(self._namespace, f"sentinel:{tenant}:{incident}")
        return IdempotencyKey(f"idem-{derived.hex}")


class StructuredLogger:
    """JSON-line logging over the stdlib. No global configuration mutated.

    The handler is attached to a named logger owned by this instance rather than
    to the root logger, so constructing one never changes logging behaviour for
    the rest of the process -- which is what makes it safe to build one per test.
    """

    __slots__ = ("_logger", "_bound")

    def __init__(
        self,
        name: str = "sentinel",
        *,
        stream: Any = None,
        level: int = logging.INFO,
        bound: Mapping[str, Any] | None = None,
    ) -> None:
        self._bound = dict(bound or {})
        self._logger = logging.getLogger(name)
        self._logger.setLevel(level)
        self._logger.propagate = False
        if not self._logger.handlers:
            handler = logging.StreamHandler(stream or sys.stdout)
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(handler)

    def _emit(self, level: int, event: str, fields: Mapping[str, Any]) -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": logging.getLevelName(level).lower(),
            "event": event,
            **self._bound,
            **fields,
        }
        self._logger.log(level, json.dumps(record, default=str, sort_keys=True))

    def info(self, event: str, /, **fields: Any) -> None:
        self._emit(logging.INFO, event, fields)

    def warning(self, event: str, /, **fields: Any) -> None:
        self._emit(logging.WARNING, event, fields)

    def error(self, event: str, /, **fields: Any) -> None:
        self._emit(logging.ERROR, event, fields)

    def critical(self, event: str, /, **fields: Any) -> None:
        self._emit(logging.CRITICAL, event, fields)

    def bind(self, **fields: Any) -> "StructuredLogger":
        return StructuredLogger(
            self._logger.name, bound={**self._bound, **fields}, level=self._logger.level
        )
