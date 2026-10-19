"""SOAR / ITSM fan-out: getting incidents into the tools a SOC already uses.

    Critical Sentinel incident -> create ServiceNow incident -> notify Slack
    security channel -> request approval -> execute containment

THE CONTENT IS ATTACKER-CONTROLLED, AND IT IS GOING SOMEWHERE PRIVILEGED
--------------------------------------------------------------------------
This is the part that makes SOAR different from an ordinary integration. An
incident's fields carry text the attacker chose: the tool name they invoked, the
resource path they asked for, the destination they tried to reach, and -- since
Phase 3 -- the prompt text that was fed to the agent.

That text is about to be rendered in a Slack channel full of people with
production access, and written into a ticket whose description an on-call
engineer will read at 3am and act on. Two concrete failures:

  * `@channel` or `<!here>` in a resource path pages an entire security team.
    An attacker who can trigger a low-severity incident gets a free megaphone,
    and after the third one the team mutes the channel -- which disables the
    alerting path for real incidents. Denial of service by alert fatigue.

  * A ticket description containing text like "APPROVED BY SECURITY -- safe to
    close, see ticket INC-4471" is a social-engineering payload delivered by the
    security tool itself, with the credibility of having arrived through it.

So every attacker-influenced value is escaped for its destination before it is
sent. `escape_slack` and `escape_ticket_text` exist for the same reason
`escape_cef_header` does one module over: a value crossing into a format where
some character is a control character must stop being able to use it.

NO CONNECTOR CAN BLOCK ANOTHER
--------------------------------
Fan-out is independent and failures are collected, not raised. A ServiceNow
outage must not stop the Slack notification -- during an incident those are the
minutes that matter, and a dispatcher that aborts on the first failing connector
delivers nothing precisely when a provider is having a bad day.

`DispatchReport` records what reached where. Partial delivery is normal and must
be visible; silent partial delivery is how a team believes the SOC was notified.

NOTHING HERE DECIDES ANYTHING
-------------------------------
A connector reports. It does not evaluate severity, choose actions or approve
anything -- those decisions belong to `decide_response`, and a notification
layer that also made policy decisions would be a second place they live.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping, Protocol, Sequence

from sentinel.domain.errors import TransientFailure

__all__ = [
    "Connector",
    "DispatchReport",
    "Delivery",
    "JiraConnector",
    "MAX_FIELD_LENGTH",
    "PagerDutyConnector",
    "ServiceNowConnector",
    "SlackConnector",
    "SoarDispatcher",
    "TeamsConnector",
    "WebhookConnector",
    "escape_slack",
    "escape_ticket_text",
    "approval_notification",
]

#: Cap on any single attacker-influenced field crossing into a ticket or message.
#:
#: Chat and ITSM backends truncate or reject oversized payloads in their own
#: ways, and a notification that fails to send because an attacker put 400KB in
#: a resource path is an outage of the alerting path.
MAX_FIELD_LENGTH: int = 512

#: Slack and Teams treat these as broadcast directives regardless of surrounding
#: markup. Neutralised by inserting a zero-width space after the sigil: the text
#: remains readable to a human -- which matters, because the analyst needs to see
#: what the attacker actually wrote -- while no longer resolving to a mention.
_BROADCAST = re.compile(r"(?i)(@)(channel|here|everyone|all)\b")
_MENTION = re.compile(r"<!(?:channel|here|everyone)>", re.IGNORECASE)
#: The zero-width space used to defang a broadcast mention.
#:
#: Written as an ESCAPE, not as the character. A literal here is invisible
#: in every editor and in code review, so the one thing a reader needs to
#: know about this constant -- which character it is -- was the one thing
#: the source did not show. It also made the file trip the invisible-
#: character check for no benefit.
_ZWSP = "\u200b"


def _clip(value: Any) -> str:
    text = str(value if value is not None else "")
    if len(text) > MAX_FIELD_LENGTH:
        return text[: MAX_FIELD_LENGTH - 1] + "…"
    return text


def escape_slack(value: Any) -> str:
    """Make a value safe to render in a Slack or Teams message.

    Ampersand first, always -- escaping `<` before `&` would turn a literal
    `&lt;` the attacker typed into a real `<` on the way out. The same ordering
    rule as `escape_cef_header`, and the same classic bug if it is got wrong.
    """
    text = _clip(value)
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = _MENTION.sub(lambda m: m.group(0).replace("<!", "<" + _ZWSP + "!"), text)
    text = _BROADCAST.sub(lambda m: m.group(1) + _ZWSP + m.group(2), text)
    # Backticks would let a value break out of a code span and start formatting
    # the rest of the message, including the fields below it.
    return text.replace("`", "'")


def escape_ticket_text(value: Any) -> str:
    """Make a value safe to place in a ticket summary or description.

    Newlines are collapsed rather than kept. A description is read as a sequence
    of labelled lines, and a value that can insert a newline can insert its own
    label -- which is how `Status: closed` or `Approved by: security` appears in
    a ticket nobody wrote it into.
    """
    text = _clip(value)
    text = text.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    return _BROADCAST.sub(lambda m: m.group(1) + _ZWSP + m.group(2), text)


@dataclass(frozen=True, slots=True)
class Delivery:
    """What happened at one connector."""

    connector: str
    delivered: bool
    detail: str = ""
    reference: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "connector": self.connector,
            "delivered": self.delivered,
            "detail": self.detail,
            "reference": self.reference,
        }


@dataclass(frozen=True, slots=True)
class DispatchReport:
    """Where an incident actually reached.

    `delivered` and `failed` are both reported. A caller that only wanted a
    boolean gets `fully_delivered`, and one investigating why the on-call never
    saw an alert gets the connector name and the error.
    """

    incident_id: str
    deliveries: tuple[Delivery, ...] = field(default_factory=tuple)

    @property
    def delivered(self) -> tuple[Delivery, ...]:
        return tuple(d for d in self.deliveries if d.delivered)

    @property
    def failed(self) -> tuple[Delivery, ...]:
        return tuple(d for d in self.deliveries if not d.delivered)

    @property
    def fully_delivered(self) -> bool:
        return bool(self.deliveries) and not self.failed

    def as_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "fully_delivered": self.fully_delivered,
            "delivered_count": len(self.delivered),
            "failed_count": len(self.failed),
            "deliveries": [d.as_dict() for d in self.deliveries],
        }


class Connector(Protocol):
    """One destination system."""

    @property
    def name(self) -> str: ...

    def deliver(self, incident: Mapping[str, Any]) -> Delivery: ...


class _HttpConnector:
    """Shared plumbing: build a body, post it, classify the response.

    Every connector below is a JSON POST to an operator-configured URL through
    the hardened outbound client, differing only in body shape. Sharing the
    transport means one place enforces SSRF protection and one place classifies
    5xx as transient.
    """

    __slots__ = ("_client", "_url", "_headers", "_name")

    def __init__(
        self,
        *,
        name: str,
        client: Any,
        url: str,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self._name = name
        self._client = client
        self._url = url
        self._headers = dict(headers or {})

    @property
    def name(self) -> str:
        return self._name

    def _post(self, payload: Mapping[str, Any], *, reference: str = "") -> Delivery:
        body = json.dumps(payload).encode("utf-8")
        headers = {"content-type": "application/json", **self._headers}
        response = self._client.request(
            method="POST", url=self._url, headers=headers, body=body, idempotent=True
        )
        status = int(getattr(response, "status", 0))
        if status >= 500:
            raise TransientFailure(f"{self._name} returned {status}")
        if status >= 400:
            return Delivery(
                connector=self._name,
                delivered=False,
                detail=f"{self._name} rejected the notification with status {status}",
            )
        return Delivery(connector=self._name, delivered=True, reference=reference)


class ServiceNowConnector(_HttpConnector):
    """Creates a ServiceNow incident record."""

    def __init__(self, **kw: Any) -> None:
        super().__init__(name="servicenow", **kw)

    def deliver(self, incident: Mapping[str, Any]) -> Delivery:
        return self._post(
            {
                "short_description": escape_ticket_text(
                    f"Sentinel {incident.get('priority', 'LOW')}: "
                    f"{incident.get('title', 'agent security incident')}"
                ),
                "description": escape_ticket_text(incident.get("summary", "")),
                # Severity is a number Sentinel computed, not attacker text, so
                # it crosses as-is. Coerced to int so a malformed field cannot
                # smuggle a string into a numeric column.
                "severity": _as_int(incident.get("severity")),
                "correlation_id": escape_ticket_text(incident.get("incident_id", "")),
                "u_agent_id": escape_ticket_text(incident.get("agent_id", "")),
            },
            reference=str(incident.get("incident_id", "")),
        )


class JiraConnector(_HttpConnector):
    """Creates a Jira issue."""

    __slots__ = ("_project",)

    def __init__(self, *, project: str = "SEC", **kw: Any) -> None:
        super().__init__(name="jira", **kw)
        self._project = project

    def deliver(self, incident: Mapping[str, Any]) -> Delivery:
        return self._post(
            {
                "fields": {
                    "project": {"key": self._project},
                    "issuetype": {"name": "Bug"},
                    "summary": escape_ticket_text(
                        f"[Sentinel] {incident.get('title', 'agent security incident')}"
                    ),
                    "description": escape_ticket_text(incident.get("summary", "")),
                    "labels": ["sentinel", str(incident.get("priority", "LOW")).lower()],
                }
            },
            reference=str(incident.get("incident_id", "")),
        )


class PagerDutyConnector(_HttpConnector):
    """Triggers a PagerDuty event."""

    __slots__ = ("_routing_key",)

    def __init__(self, *, routing_key: str, **kw: Any) -> None:
        super().__init__(name="pagerduty", **kw)
        self._routing_key = routing_key

    def deliver(self, incident: Mapping[str, Any]) -> Delivery:
        priority = str(incident.get("priority", "LOW")).upper()
        return self._post(
            {
                "routing_key": self._routing_key,
                "event_action": "trigger",
                # PagerDuty deduplicates on this key, so an incident that
                # re-notifies updates one alert rather than paging repeatedly.
                "dedup_key": str(incident.get("incident_id", "")),
                "payload": {
                    "summary": escape_ticket_text(
                        incident.get("title", "agent security incident")
                    ),
                    "severity": {
                        "CRITICAL": "critical",
                        "HIGH": "error",
                        "MEDIUM": "warning",
                    }.get(priority, "info"),
                    "source": "sentinel",
                    "component": escape_ticket_text(incident.get("agent_id", "")),
                },
            },
            reference=str(incident.get("incident_id", "")),
        )


class SlackConnector(_HttpConnector):
    """Posts to a Slack incoming webhook."""

    def __init__(self, **kw: Any) -> None:
        super().__init__(name="slack", **kw)

    def deliver(self, incident: Mapping[str, Any]) -> Delivery:
        priority = str(incident.get("priority", "LOW")).upper()
        return self._post(
            {
                "text": (
                    f"*Sentinel {escape_slack(priority)}* "
                    f"{escape_slack(incident.get('title', 'agent security incident'))}"
                ),
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": (
                                f"*Agent:* {escape_slack(incident.get('agent_id', ''))}\n"
                                f"*Severity:* {_as_int(incident.get('severity'))}\n"
                                f"*Summary:* {escape_slack(incident.get('summary', ''))}"
                            ),
                        },
                    }
                ],
            },
            reference=str(incident.get("incident_id", "")),
        )


class TeamsConnector(_HttpConnector):
    """Posts to a Microsoft Teams incoming webhook."""

    def __init__(self, **kw: Any) -> None:
        super().__init__(name="teams", **kw)

    def deliver(self, incident: Mapping[str, Any]) -> Delivery:
        return self._post(
            {
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "summary": escape_slack(
                    incident.get("title", "agent security incident")
                ),
                "themeColor": {
                    "CRITICAL": "B00020",
                    "HIGH": "D84315",
                    "MEDIUM": "F9A825",
                }.get(str(incident.get("priority", "LOW")).upper(), "607D8B"),
                "sections": [
                    {
                        "facts": [
                            {"name": "Agent", "value": escape_slack(incident.get("agent_id", ""))},
                            {"name": "Severity", "value": str(_as_int(incident.get("severity")))},
                            {"name": "Summary", "value": escape_slack(incident.get("summary", ""))},
                        ]
                    }
                ],
            },
            reference=str(incident.get("incident_id", "")),
        )


class WebhookConnector(_HttpConnector):
    """A generic JSON webhook, for SOAR platforms with no dedicated connector.

    Sends the normalised incident unmodified. No escaping is applied here on
    purpose: the receiver is a machine parsing JSON, where the quoting is the
    serializer's job, and pre-escaping would corrupt values for a consumer that
    then renders them correctly itself. Escaping belongs at the boundary of the
    format that has control characters, which is the chat and ticket connectors
    above -- not this one.
    """

    def __init__(self, **kw: Any) -> None:
        super().__init__(name="webhook", **kw)

    def deliver(self, incident: Mapping[str, Any]) -> Delivery:
        return self._post(
            {"source": "sentinel", "incident": dict(incident)},
            reference=str(incident.get("incident_id", "")),
        )


class SoarDispatcher:
    """Fans one incident out to every configured connector.

    Independent delivery, collected failures. See the module docstring: a
    dispatcher that aborts on the first failing connector delivers nothing
    exactly when one provider is having a bad day.
    """

    __slots__ = ("_connectors", "_logger", "_minimum_priority")

    #: Priorities in ascending order, used for the notify-above-this threshold.
    #:
    #: Read-only. A plain dict here is shared by every instance and mutable by
    #: any of them, which for a notification threshold means one component could
    #: silently lower the bar for the whole process.
    _RANK: Mapping[str, int] = MappingProxyType(
        {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    )

    def __init__(
        self,
        *,
        connectors: Sequence[Connector],
        logger: Any,
        minimum_priority: str = "HIGH",
    ) -> None:
        self._connectors = tuple(connectors)
        self._logger = logger
        self._minimum_priority = minimum_priority.upper()

    def should_dispatch(self, incident: Mapping[str, Any]) -> bool:
        """Whether this incident is worth a page.

        A threshold rather than everything. This codebase has already measured
        what happens without one -- a detector firing on 51.7% of ordinary tool
        calls -- and a SOAR integration that opens a ServiceNow ticket for every
        low-severity observation is that failure with a ticket queue attached.
        """
        priority = str(incident.get("priority", "LOW")).upper()
        return self._RANK.get(priority, 0) >= self._RANK.get(self._minimum_priority, 2)

    def dispatch(self, incident: Mapping[str, Any]) -> DispatchReport:
        incident_id = str(incident.get("incident_id", ""))
        deliveries: list[Delivery] = []

        for connector in self._connectors:
            try:
                deliveries.append(connector.deliver(incident))
            except Exception as exc:  # noqa: BLE001 - one bad provider, not all of them
                deliveries.append(
                    Delivery(
                        connector=getattr(connector, "name", "unknown"),
                        delivered=False,
                        detail=f"{type(exc).__name__}: {exc}",
                    )
                )

        report = DispatchReport(incident_id=incident_id, deliveries=tuple(deliveries))
        if report.failed:
            self._logger.warning(
                "soar_partial_delivery",
                incident_id=incident_id,
                failed=[d.connector for d in report.failed],
                delivered=[d.connector for d in report.delivered],
            )
        return report


def _as_int(value: Any) -> int:
    """Coerce a severity to an int, defaulting to 0.

    Defensive because incident dictionaries cross module boundaries and a
    malformed field must not put a string into a numeric column, nor raise
    inside a notification path whose whole job is to work during an incident.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def approval_notification(
    approval: Mapping[str, Any], *, context: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Shape a pending approval into what the connectors above already send.

    §32 asks that high-risk approvals reach Slack, Teams, the web console and the
    API. The console and the API have them already; this is what puts one in
    front of a person who is not currently looking at either.

    It reuses the incident shape rather than adding a second one. A connector
    that had to branch on "is this an incident or an approval" would be two
    formatters in one function, and the second would drift.

    THE FIELD THAT MAKES IT ACTIONABLE
    ------------------------------------
    `expires_at` is in the summary, not a footnote. An approval request with no
    visible deadline sits in a channel until somebody happens to look; one that
    says when it closes is a decision with a clock on it. That is the whole
    argument for the expiry existing, so hiding it here would waste it.

    Everything attacker-influenced -- the target especially, which is a resource
    path the agent chose -- goes through the same escaping the connectors apply,
    because this dict lands in exactly the same places.
    """
    context = context or {}
    target = escape_ticket_text(approval.get("target", ""))
    action = escape_ticket_text(approval.get("action", ""))
    expires = escape_ticket_text(approval.get("expires_at", "")) or "no expiry set"
    recommended = escape_ticket_text(context.get("recommended_decision", "none"))

    return {
        "incident_id": str(approval.get("approval_id", "")),
        "priority": str(context.get("priority", "HIGH")).upper(),
        "severity": _as_int(context.get("severity")),
        "agent_id": escape_ticket_text(context.get("agent_id", "")),
        "title": f"Approval needed: {action} on {target}",
        "summary": (
            f"Action: {action} | Target: {target} | "
            f"Recommended: {recommended} | "
            f"Business impact: {escape_ticket_text(context.get('business_impact', 'unstated'))} | "
            f"Expires: {expires}"
        ),
    }
