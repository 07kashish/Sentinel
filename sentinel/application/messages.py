"""CQRS message contracts: commands, queries, and their handlers.

WHY COMMANDS AND QUERIES ARE SEPARATED
--------------------------------------
In the predecessor every read went through the same code as every write.
`GET /incidents` loaded aggregates through the repository, which meant a read
paid for invariant checking and object construction it had no use for, and — more
importantly — the read path and the write path could not be optimised, scaled or
reasoned about independently. `repository.list_incidents` carried a hard-coded
`LIMIT 200` with no cursor because there was nowhere else to put paging.

Here:

  * A **command** mutates. It goes through a unit of work, loads an aggregate,
    invokes domain behaviour, and commits. It returns an acknowledgement, never
    a projection — returning read data from a write forces the write path to
    serve read shapes.
  * A **query** never mutates and never loads an aggregate. It reads a
    projection through `ReadModel`.

Both are plain frozen dataclasses. They carry no behaviour, so a handler can be
swapped without touching its message, and a message can be logged, queued or
replayed without dragging a handler along.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Generic, Mapping, Protocol, TypeVar

from sentinel.domain.primitives import TenantId

__all__ = [
    "Command",
    "CommandHandler",
    "Query",
    "QueryHandler",
    "Result",
    "TCommand",
    "TQuery",
    "TResult",
]


@dataclass(frozen=True, slots=True)
class Command:
    """A request to change state. May be refused.

    Every command carries its tenant, because there is no ambient tenant context
    anywhere in this architecture. The predecessor threaded `tenant_id` through
    as a positional string and relied on each call site to remember; here it is a
    typed field on the message the bus dispatches, so a handler cannot run
    without one.
    """

    tenant: TenantId


@dataclass(frozen=True, slots=True)
class Query:
    """A request for a projection. Never mutates."""

    tenant: TenantId


@dataclass(frozen=True, slots=True)
class Result:
    """A command acknowledgement.

    Deliberately thin: `ok`, an outcome word, and a small detail map. A command
    that wants to return a projection is a query wearing a disguise.
    """

    ok: bool
    outcome: str
    detail: Mapping[str, Any]

    @classmethod
    def accepted(cls, outcome: str, **detail: Any) -> "Result":
        return cls(ok=True, outcome=outcome, detail=detail)

    @classmethod
    def refused(cls, outcome: str, **detail: Any) -> "Result":
        return cls(ok=False, outcome=outcome, detail=detail)


TCommand = TypeVar("TCommand", bound=Command, contravariant=True)
TQuery = TypeVar("TQuery", bound=Query, contravariant=True)
TResult = TypeVar("TResult", covariant=True)


class CommandHandler(Protocol, Generic[TCommand]):
    """Handles exactly one command type. One class, one reason to change."""

    def handle(self, command: TCommand) -> Result: ...


class QueryHandler(Protocol, Generic[TQuery, TResult]):
    """Handles exactly one query type."""

    def handle(self, query: TQuery) -> TResult: ...
