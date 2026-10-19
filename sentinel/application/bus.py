"""Command, query and event buses.

WHY THESE ARE INSTANCES AND NOT MODULES
---------------------------------------
Every bus here is an object constructed with its handler map and passed to
whoever needs it. There is no module-level registry, no decorator that mutates
global state at import, and no `@handler` side effect.

That is deliberate and it is the difference between this and the predecessor,
where importing `api.main` executed configuration parsing, deployment validation,
schema DDL, additive migrations, a full ledger backfill and tenant
synchronisation as import side effects. Importing the module to read its routes
applied a schema. Tests could not import the application without starting a
background consumer that then raced them for their own queue items — which
presented as flakiness rather than as the design problem it was.

Here, importing this module does nothing. Constructing a bus does nothing but
store a mapping. Wiring happens once, explicitly, in the composition root.

RETRY CLASSIFICATION
--------------------
`CommandBus.dispatch` does not classify failures, and that is the point. The
predecessor inferred retryability from a tuple of exception TYPES, which put
`ValueError`, `TypeError` and `KeyError` — the three most common incidental
exceptions in Python — in the permanent-failure bucket. Here the error object
states its own retryability (`SentinelError.is_retryable`), declared by the code
that knows why it failed, and the worker reads the declaration.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping, Sequence

from sentinel.application.messages import Command, CommandHandler, Query, QueryHandler, Result
from sentinel.application.ports import EventPublisher, Logger
from sentinel.domain.errors import SentinelError
from sentinel.domain.events import DomainEvent
from sentinel.domain.primitives import TenantId

__all__ = ["CommandBus", "EventBus", "QueryBus", "UnregisteredMessage"]


class UnregisteredMessage(LookupError):
    """No handler is wired for this message type.

    A hard error, never a silent no-op. A dispatched command that quietly does
    nothing is indistinguishable from one that succeeded, which is the class of
    defect this whole architecture is organised against.
    """


class CommandBus:
    """Dispatches a command to the one handler registered for its type."""

    __slots__ = ("_handlers", "_logger")

    def __init__(
        self,
        handlers: Mapping[type[Command], CommandHandler[Any]],
        *,
        logger: Logger,
    ) -> None:
        self._handlers = dict(handlers)
        self._logger = logger

    def dispatch(self, command: Command) -> Result:
        handler = self._handlers.get(type(command))
        if handler is None:
            raise UnregisteredMessage(
                f"no handler registered for {type(command).__name__}. Commands are "
                "wired explicitly in the composition root; a missing registration "
                "is a wiring bug, not a runtime condition to absorb."
            )
        try:
            return handler.handle(command)
        except SentinelError as exc:
            # Logged with the declared classification, then re-raised. The bus
            # never decides whether to retry -- the caller that owns the retry
            # budget does, by reading `is_retryable` off the error itself.
            self._logger.warning(
                "command_failed",
                command=type(command).__name__,
                tenant=str(command.tenant),
                error=type(exc).__name__,
                detail=str(exc),
                retryable=exc.is_retryable,
                abandon=exc.is_abandon,
            )
            raise

    def handles(self, command_type: type[Command]) -> bool:
        return command_type in self._handlers


class QueryBus:
    """Dispatches a query to the one handler registered for its type."""

    __slots__ = ("_handlers",)

    def __init__(self, handlers: Mapping[type[Query], QueryHandler[Any, Any]]) -> None:
        self._handlers = dict(handlers)

    def ask(self, query: Query) -> Any:
        handler = self._handlers.get(type(query))
        if handler is None:
            raise UnregisteredMessage(
                f"no handler registered for {type(query).__name__}"
            )
        return handler.handle(query)

    def handles(self, query_type: type[Query]) -> bool:
        return query_type in self._handlers


Subscriber = Callable[[TenantId, DomainEvent], None]


class EventBus:
    """Fans domain events out to subscribers, and satisfies `EventPublisher`.

    A failing subscriber must not fail the publication: events describe things
    that have ALREADY happened and committed, so refusing to deliver to the
    remaining subscribers because one webhook is down would lose facts that are
    already true. Each failure is logged individually and the fan-out continues.

    This is the opposite of the predecessor's `drain()`, where a `KeyError` from
    one message's terminal handler propagated out and aborted the drain for every
    remaining tenant -- because the failing call sat outside the try block that
    was there to contain exactly that.
    """

    __slots__ = ("_subscribers", "_logger")

    def __init__(
        self,
        subscribers: Mapping[type[DomainEvent], Sequence[Subscriber]],
        *,
        logger: Logger,
    ) -> None:
        self._subscribers = {k: tuple(v) for k, v in subscribers.items()}
        self._logger = logger

    def publish(self, tenant: TenantId, events: Sequence[DomainEvent]) -> None:
        for event in events:
            for subscriber in self._subscribers.get(type(event), ()):
                try:
                    subscriber(tenant, event)
                except Exception as exc:  # noqa: BLE001
                    self._logger.error(
                        "event_subscriber_failed",
                        event=event.event_type,
                        tenant=str(tenant),
                        subscriber=getattr(subscriber, "__qualname__", repr(subscriber)),
                        error=f"{type(exc).__name__}: {exc}",
                    )

    def subscriber_count(self, event_type: type[DomainEvent]) -> int:
        return len(self._subscribers.get(event_type, ()))


def _assert_publisher_shape(bus: EventBus) -> EventPublisher:
    """Compile-time check that EventBus satisfies EventPublisher structurally."""
    return bus
