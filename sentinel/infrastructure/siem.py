"""SIEM export, and the escaping that stops an attacker forging events in it.

WHY EXPORT AT ALL
-----------------
Sentinel's audit trail is hash-chained and tenant-scoped, which makes it good
evidence and a poor place to correlate. A SOC already watches one console, and a
finding that lives only in this product's database is a finding nobody sees at
3am. Export puts Sentinel's events beside the firewall's and the identity
provider's, where the analyst already is.

THE SECURITY PROPERTY THIS MODULE IS ACTUALLY ABOUT
-----------------------------------------------------
Not delivery. **Escaping.**

Every SIEM format is a flat text encoding with delimiters, and several of the
fields Sentinel exports are attacker-controlled: an MCP tool description, a
prompt, a resource path an agent chose. CEF separates fields with `|`, separates
extension keys with spaces and `=`, and separates EVENTS with newlines. So an
unescaped field containing

    something\\nCEF:0|Sentinel|Sentinel|1.0|login|Successful login|0|

is not a weird log line. It is a SECOND EVENT, forged, in the analyst's console,
attributed to Sentinel. An attacker who can influence one exported string can
manufacture a clean-looking history around the thing they actually did -- which
is more valuable to them than evading detection, because it actively misleads
the investigation that follows.

That is the reason this module exists as its own thing with its own tests rather
than as an f-string at a call site. `json.dumps` gets this right for free, which
is exactly why the JSON formats are cheap and CEF needs care.

DELIVERY, AND WHY IT ARRIVED LATE
---------------------------------
The first version of this module refused to deliver at all, for a stated
reason: an HTTP pusher without retry policy and a delivery guarantee silently
drops security events. That reason has now been answered rather than waved
away — `SiemWebhookDeliverer` below performs exactly ONE attempt and owns
neither retry nor durability, because both belong to the transactional outbox
that invokes it (`application/commands/dispatch_outbox.py`): the intent to
export is committed in the same transaction as the incident, delivery is
retried on the outbox's budget with its lease/reap machinery, and exhaustion
lands in the dead-letter state where the worker logs it at error. A failed
POST here is therefore never a silently dropped event; it is a pending row.
The CLI's file/stdout export remains for deployments that already run a
collector.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Iterable, Iterator, Mapping

from sentinel.domain.errors import TransientFailure

__all__ = [
    "SiemEvent",
    "SiemDeliveryFailed",
    "SiemWebhookDeliverer",
    "escape_cef_header",
    "escape_cef_extension",
    "format_cef",
    "format_ecs",
    "render",
    "SUPPORTED_FORMATS",
]

SUPPORTED_FORMATS = ("cef", "ecs")

#: CEF's own version and the vendor triple. Fixed, so they are never a place a
#: caller-supplied string can land.
_CEF_VERSION = "CEF:0"
_VENDOR = "Sentinel"
_PRODUCT = "SentinelSOC"
_DEV_VERSION = "1.0"

#: Map Sentinel outcomes onto CEF severity 0-10. `denied` is deliberately not
#: low: a refusal is the record of something being attempted.
_SEVERITY = MappingProxyType({
    "success": 2,
    "failed": 6,
    "denied": 7,
})


@dataclass(frozen=True, slots=True)
class SiemEvent:
    """One exportable security event, independent of any output format.

    Deliberately flat and small. A format-specific structure here would mean the
    escaping rules of one SIEM leaked into what the others receive.
    """

    tenant_id: str
    occurred_at: str
    actor: str
    action: str
    resource_type: str
    resource_id: str
    outcome: str
    #: Sequence number in the hash-chained audit trail. Exported so an analyst
    #: can ask this system for the chain around an event they are looking at.
    sequence: int = 0
    detail: Mapping[str, Any] | None = None

    @classmethod
    def from_audit_row(cls, row: Mapping[str, Any]) -> "SiemEvent":
        raw = row.get("detail") or "{}"
        try:
            detail = json.loads(raw) if isinstance(raw, str) else dict(raw)
        except (json.JSONDecodeError, TypeError, ValueError):
            # A detail column that will not parse is REPORTED, not dropped and
            # not allowed to abort the export. Losing one field is recoverable;
            # losing the run means the rest of the day's events never ship.
            detail = {"unparsed_detail": str(raw)[:512]}
        return cls(
            tenant_id=str(row.get("tenant_id", "")),
            occurred_at=str(row.get("occurred_at", "")),
            actor=str(row.get("actor", "")),
            action=str(row.get("action", "")),
            resource_type=str(row.get("resource_type", "")),
            resource_id=str(row.get("resource_id", "")),
            outcome=str(row.get("outcome", "")),
            sequence=int(row.get("seq", 0) or 0),
            detail=detail if isinstance(detail, dict) else {"detail": detail},
        )

    @property
    def severity(self) -> int:
        return _SEVERITY.get(self.outcome.strip().lower(), 4)


# ── CEF escaping ─────────────────────────────────────────────────────────────


def escape_cef_header(value: str) -> str:
    """Escape a value for a CEF HEADER field (the pipe-separated prefix).

    Backslash first, always. Escaping `|` before `\\` would turn a literal
    backslash-pipe into an escaped pipe and lose the distinction -- the classic
    ordering bug in every escaping routine ever written.

    Newlines are removed rather than escaped: a newline in a header field ends
    the event, and everything after it is parsed as a new one.
    """
    text = str(value)
    text = text.replace("\\", "\\\\")
    text = text.replace("|", "\\|")
    return _strip_newlines(text)


def escape_cef_extension(value: Any) -> str:
    """Escape a value for a CEF EXTENSION field (the `key=value` tail).

    `=` is escaped here and not in the header, because the extension is where it
    is a delimiter. An unescaped `=` lets one field's value declare the next
    field's name, which is how a forged `outcome=success` gets in.
    """
    text = str(value)
    text = text.replace("\\", "\\\\")
    text = text.replace("=", "\\=")
    return _strip_newlines(text)


def _strip_newlines(text: str) -> str:
    """Remove every character a SIEM might treat as an event boundary.

    Replaced with a space rather than deleted so words do not silently join, and
    covering more than \\n and \\r: U+2028 and U+2029 are line terminators to a
    surprising number of parsers, and a NUL can truncate a C-based one.
    """
    for char in ("\r\n", "\n", "\r", " ", " ", "\x00", "\x0b", "\x0c"):
        text = text.replace(char, " ")
    return text


def format_cef(event: SiemEvent) -> str:
    """Render one event as a single CEF line.

    The return value contains no newline, and that is a guarantee the tests
    assert directly: one event in, one line out, no matter what the fields hold.
    """
    header = "|".join(
        [
            _CEF_VERSION,
            _VENDOR,
            _PRODUCT,
            _DEV_VERSION,
            escape_cef_header(event.action or "event"),
            escape_cef_header(f"{event.action} {event.outcome}".strip()),
            str(event.severity),
        ]
    )

    extension: dict[str, Any] = {
        "rt": event.occurred_at,
        "suser": event.actor,
        "act": event.action,
        "outcome": event.outcome,
        "cs1Label": "tenant",
        "cs1": event.tenant_id,
        "cs2Label": "resourceType",
        "cs2": event.resource_type,
        "cs3Label": "resourceId",
        "cs3": event.resource_id,
        "cn1Label": "auditSequence",
        "cn1": event.sequence,
    }
    for key, value in (event.detail or {}).items():
        # Detail keys are attacker-influenced too -- an MCP server id, a tool
        # name. A key containing `=` or a space would otherwise open a new
        # field, so keys are normalised to an alphanumeric CEF-safe form rather
        # than escaped: a key is an identifier, not free text.
        safe_key = "".join(c for c in str(key) if c.isalnum())[:32]
        if safe_key:
            extension[f"detail_{safe_key}"] = value

    tail = " ".join(f"{k}={escape_cef_extension(v)}" for k, v in extension.items())
    return f"{header}|{tail}"


def format_ecs(event: SiemEvent) -> str:
    """Render one event as a single Elastic Common Schema JSON line.

    `json.dumps` handles every escaping concern CEF needs care for, which is the
    argument for preferring this format wherever the destination accepts it.
    """
    document = {
        "@timestamp": event.occurred_at,
        "event": {
            "kind": "event",
            "category": ["configuration"],
            "action": event.action,
            "outcome": "success" if event.outcome.lower() == "success" else "failure",
            "sequence": event.sequence,
            "severity": event.severity,
            "provider": _PRODUCT,
        },
        "observer": {"vendor": _VENDOR, "product": _PRODUCT, "version": _DEV_VERSION},
        "organization": {"id": event.tenant_id},
        "user": {"name": event.actor},
        "sentinel": {
            "resource_type": event.resource_type,
            "resource_id": event.resource_id,
            "detail": dict(event.detail or {}),
        },
    }
    # `ensure_ascii` keeps the line byte-safe for transports that are not
    # UTF-8 clean, and it renders U+2028/U+2029 as escapes rather than as
    # characters a JavaScript-based log viewer would treat as line breaks.
    return json.dumps(document, ensure_ascii=True, sort_keys=True, default=str)


def render(events: Iterable[SiemEvent], *, fmt: str = "cef") -> Iterator[str]:
    """Render events, one line each, in the requested format."""
    normalised = fmt.strip().lower()
    if normalised not in SUPPORTED_FORMATS:
        raise ValueError(
            f"unknown SIEM format {fmt!r}; supported: {', '.join(SUPPORTED_FORMATS)}"
        )
    formatter = format_cef if normalised == "cef" else format_ecs
    for event in events:
        yield formatter(event)


class SiemDeliveryFailed(TransientFailure):
    """One delivery attempt failed. Retryable BY THE OUTBOX, never by this class.

    Deliberately transient even for a 4xx: a misconfigured collector URL or an
    expired token is permanent from the webhook's point of view, but marking it
    delivered-with-a-shrug would silently discard a security event, which is
    the one outcome this pipeline exists to prevent. Failing keeps the record
    on the outbox's retry budget, and exhaustion lands it in the dead-letter
    state where the worker logs it at error -- visible, attributable, and
    replayable once the operator fixes the endpoint.
    """


class SiemWebhookDeliverer:
    """POST one rendered event to an HTTPS collector. One attempt, no retry.

    Retry, backoff and dead-lettering belong to the outbox dispatcher that
    calls this; durability belongs to the admission transaction that enqueued
    the record. This class owns exactly the wire: render as ECS (the JSON shape
    Splunk HEC, Elastic, Datadog and generic collectors all accept), attach the
    bearer token and the idempotency key, refuse to treat a non-2xx as success.
    """

    __slots__ = ("_client", "_url", "_token")

    def __init__(self, *, client: Any, url: str, token: str = "") -> None:
        self._client = client
        self._url = url
        self._token = token

    def deliver(
        self, *, payload: Mapping[str, Any], idempotency_key: str
    ) -> dict[str, Any]:
        """Deliver one outbox record's event. Returns the delivery receipt.

        The idempotency key rides an `X-Sentinel-Idempotency-Key` header so a
        collector that deduplicates can, and a redelivery after a crashed
        deliverer (the at-least-once case the outbox lease permits) is
        identifiable as the same event rather than a second one.
        """
        event = SiemEvent(
            tenant_id=str(payload.get("tenant_id", "")),
            occurred_at=str(payload.get("occurred_at", "")),
            actor=str(payload.get("actor", "")),
            action=str(payload.get("action", "")),
            resource_type=str(payload.get("resource_type", "")),
            resource_id=str(payload.get("resource_id", "")),
            outcome=str(payload.get("outcome", "")),
            detail=dict(payload.get("detail") or {}),
        )
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        headers["X-Sentinel-Idempotency-Key"] = idempotency_key

        response = self._client.request(
            method="POST",
            url=self._url,
            headers=headers,
            body=format_ecs(event).encode("utf-8"),
            idempotent=True,
        )
        if not 200 <= response.status < 300:
            raise SiemDeliveryFailed(
                f"collector answered HTTP {response.status}; the event stays "
                "on the outbox retry budget rather than being discarded"
            )
        return {"delivered": True, "status": response.status, "peer": response.peer}
