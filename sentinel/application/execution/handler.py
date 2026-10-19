"""The command handler that drives the execution engine.

A deliberately thin adapter: the command bus speaks commands and results, the
engine speaks incidents, epochs and steps. Keeping the translation here means the
engine has no opinion about how it was invoked, so it can be driven from a queue
worker, an operator CLI, or a test, with no branch anywhere for which one it is.
"""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.application.execution.engine import ExecutionEngine
from sentinel.application.messages import Command, Result
from sentinel.application.ports import Logger
from sentinel.domain.primitives import IncidentId, MessageId

__all__ = ["ProcessIncident", "ProcessIncidentHandler"]


@dataclass(frozen=True, slots=True)
class ProcessIncident(Command):
    """Advance one incident as far as its lease and its plan allow.

    `message_id` opts into inbox deduplication. A queue worker supplies the work
    item's id so a redelivery is recognised at the boundary; a caller with no
    message identity omits it and relies on the journal alone, which is still
    correct and merely does more work to discover the same thing.
    """

    incident_id: IncidentId
    lease_epoch: int
    message_id: MessageId | None = None


class ProcessIncidentHandler:
    __slots__ = ("_engine", "_logger")

    def __init__(self, *, engine: ExecutionEngine, logger: Logger) -> None:
        self._engine = engine
        self._logger = logger

    def handle(self, command: ProcessIncident) -> Result:
        outcome = self._engine.execute(
            tenant=command.tenant,
            incident_id=command.incident_id,
            epoch=command.lease_epoch,
            message_id=command.message_id,
        )
        if not outcome.accepted:
            return Result.accepted(
                "duplicate_delivery",
                incident_id=command.incident_id.value,
                detail=outcome.detail,
            )
        self._logger.info(
            "incident_advanced",
            tenant=str(command.tenant),
            incident_id=command.incident_id.value,
            executed=list(outcome.executed),
            replayed=list(outcome.replayed),
            final_state=outcome.final_state,
        )
        return Result.accepted(
            "processed",
            incident_id=command.incident_id.value,
            state=outcome.final_state,
            executed=list(outcome.executed),
            replayed=list(outcome.replayed),
            compensated=list(outcome.compensated),
        )
