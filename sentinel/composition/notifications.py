"""Wiring incidents into the tools a SOC already uses.

Split out of `container.py` so the composition root stays readable. This is
still composition -- it constructs adapters from settings and subscribes them to
domain events -- but SOAR fan-out is a self-contained decision with six
connectors and a threshold, and keeping it inline pushed the container past the
size at which a module stops having one reason to change.
"""

from __future__ import annotations

from typing import Callable, Mapping, Sequence

from sentinel.application.ports import Logger
from sentinel.composition.settings import Settings
from sentinel.domain.events import DomainEvent, IncidentAdmitted
from sentinel.domain.primitives import TenantId
from sentinel.infrastructure.outbound import HardenedHttpClient
from sentinel.infrastructure.soar import (
    Connector,
    JiraConnector,
    PagerDutyConnector,
    ServiceNowConnector,
    SlackConnector,
    SoarDispatcher,
    TeamsConnector,
    WebhookConnector,
)

__all__ = ["build_soar_dispatcher", "soar_subscriber", "subscribers_with_soar"]


def build_soar_dispatcher(settings: Settings, *, logger: Logger) -> SoarDispatcher | None:
    """Build the SOAR fan-out, or None when nothing is configured.

    None rather than an empty dispatcher: a dispatcher with no connectors
    reports `fully_delivered=False` for every incident, which reads as a
    delivery failure when the truth is that nobody asked for delivery.
    """
    endpoints = settings.soar_endpoints
    if not endpoints:
        return None

    client = HardenedHttpClient()
    # Typed so each lambda's result is upcast to the protocol. Without it the
    # comprehension infers the common BASE class, `_HttpConnector`, which does
    # not implement `deliver` -- that lives on each subclass -- so the list
    # type satisfied nothing.
    builders: Mapping[str, Callable[[str], Connector]] = {
        "servicenow": lambda url: ServiceNowConnector(client=client, url=url),
        "jira": lambda url: JiraConnector(client=client, url=url),
        "slack": lambda url: SlackConnector(client=client, url=url),
        "teams": lambda url: TeamsConnector(client=client, url=url),
        "webhook": lambda url: WebhookConnector(client=client, url=url),
        "pagerduty": lambda url: PagerDutyConnector(
            client=client, url=url, routing_key=settings.soar_pagerduty_routing_key
        ),
    }
    # Annotated: the builders return six DIFFERENT connector classes, so
    # the comprehension infers the first one's type and then rejects the
    # rest. The dispatcher wants the protocol, which all six satisfy.
    connectors: list[Connector] = [
        builders[name](url) for name, url in endpoints.items()
    ]
    logger.info(
        "soar_connectors_configured",
        connectors=sorted(endpoints),
        minimum_priority=settings.soar_min_priority,
    )
    return SoarDispatcher(
        connectors=connectors,
        logger=logger,
        minimum_priority=settings.soar_min_priority,
    )


def soar_subscriber(
    dispatcher: SoarDispatcher, *, logger: Logger
) -> Callable[[TenantId, DomainEvent], None]:
    """Fan an admitted incident out to the SOC's own tools.

    SUBSCRIBED, NOT CALLED INLINE
    -------------------------------
    Publication happens after the transaction commits, so a slow ServiceNow does
    not hold a database transaction open and a failed notification cannot roll
    back an incident that was correctly recorded. The incident is the durable
    artifact; the notification is a best-effort copy of it.

    NOTHING HERE RAISES
    ---------------------
    An exception in a subscriber must not fail the admission that produced it.
    An incident that was detected and stored but whose Slack message failed is a
    working system with a broken integration; an incident that was rejected
    because Slack was down is a broken system.
    """

    def dispatch(tenant: TenantId, event: DomainEvent) -> None:
        payload = dict(event.payload())
        incident = {
            "incident_id": str(event.incident_id),
            "priority": str(payload.get("priority", "LOW")),
            "severity": payload.get("severity", 0),
            "agent_id": str(payload.get("source", "")),
            "title": f"Agent security incident {event.incident_id}",
            "summary": (
                f"Severity {payload.get('severity', 0)} "
                f"({payload.get('priority', 'LOW')}) raised from "
                f"{payload.get('source', 'unknown source')}."
            ),
        }
        if not dispatcher.should_dispatch(incident):
            return
        try:
            dispatcher.dispatch(incident)
        except Exception as exc:  # noqa: BLE001 - see the docstring
            logger.error(
                "soar_dispatch_failed",
                tenant=str(tenant),
                incident_id=str(event.incident_id),
                error=f"{type(exc).__name__}: {exc}",
            )

    return dispatch


def subscribers_with_soar(
    settings: Settings,
    *,
    logger: Logger,
    defaults: Mapping[type[DomainEvent], Sequence[Callable[[TenantId, DomainEvent], None]]],
) -> Mapping[type[DomainEvent], Sequence[Callable[[TenantId, DomainEvent], None]]]:
    """The default subscribers, plus SOAR fan-out when it is configured.

    SECTION 37, WIRED. `SoarDispatcher` previously existed with six connectors,
    escaping and tests, and was constructed by nothing -- so no incident ever
    reached ServiceNow, Slack or PagerDuty.
    """
    subscribers = dict(defaults)
    dispatcher = build_soar_dispatcher(settings, logger=logger)
    if dispatcher is not None:
        subscribers[IncidentAdmitted] = tuple(subscribers.get(IncidentAdmitted, ())) + (
            soar_subscriber(dispatcher, logger=logger),
        )
    return subscribers
