"""SIEM transports beyond the single webhook: OTLP/HTTP and syslog over TLS.

WHY MORE THAN ONE WIRE
----------------------
`SiemWebhookDeliverer` posts ECS JSON to one HTTPS collector, which Splunk HEC,
Elastic and Datadog all accept. Two large classes of deployment cannot use it:

  * an OpenTelemetry collector is the standard aggregation point in most
    enterprises that have one, and it speaks OTLP, not an arbitrary JSON POST;
  * QRadar, and most on-premises SIEMs, ingest syslog. Over TLS, framed, from a
    host that is not on the public internet.

Both are implemented here over the same primitives the rest of the process
uses. Neither adds a dependency.

WHAT IS DELIBERATELY NOT HERE
-----------------------------
KAFKA. A Kafka producer is a broker-protocol client with its own connection
pooling, partitioner and retry semantics; there is no honest way to add it
without a dependency, and a "Kafka transport" that quietly posted to a REST
proxy would be a capability claim this module could not honour. A deployment
that asks for it gets `NOT_SUPPORTED` at configuration time rather than a
delivery path that silently is not Kafka.

THE FAN-OUT AND ITS ONE HONEST COMPROMISE
-------------------------------------------
`FanOutSiemDeliverer` sends one outbox record to every configured sink. If any
sink fails, it RAISES, so the record stays on the outbox's retry budget rather
than being marked delivered -- which means the sinks that already succeeded will
receive the event again on the retry.

That is a deliberate choice of duplicate-over-loss, and it is why every sink
carries the idempotency key: a redelivery is identifiable as the same event
rather than as a second one. The alternative -- per-sink delivery state -- would
mean an outbox row per sink, and the reason not to build that yet is that
nothing in this codebase needs it. The compromise is recorded in the receipt:
`sinks` names what succeeded and what did not, so an operator reading a
dead-lettered record can see which collector is the problem.
"""

from __future__ import annotations

import json
import socket
import ssl
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from sentinel.infrastructure.siem import SiemDeliveryFailed, SiemEvent, format_ecs

__all__ = [
    "FanOutSiemDeliverer",
    "OtlpLogDeliverer",
    "SyslogTarget",
    "SyslogTlsDeliverer",
    "UnsupportedSiemTransport",
    "event_from_payload",
    "rfc5424_line",
]


class UnsupportedSiemTransport(ValueError):
    """A transport this build cannot perform. Raised at CONFIGURATION time.

    Never at delivery time, and never swallowed into a success receipt. An
    operator who configures Kafka learns at start-up that this build does not
    speak it, rather than discovering during an audit that a year of events
    went somewhere else.
    """


def event_from_payload(payload: Mapping[str, Any]) -> SiemEvent:
    """Rebuild a `SiemEvent` from an outbox record's payload.

    Shared by every transport so the three of them cannot drift into disagreeing
    about which field is the actor.
    """
    return SiemEvent(
        tenant_id=str(payload.get("tenant_id", "")),
        occurred_at=str(payload.get("occurred_at", "")),
        actor=str(payload.get("actor", "")),
        action=str(payload.get("action", "")),
        resource_type=str(payload.get("resource_type", "")),
        resource_id=str(payload.get("resource_id", "")),
        outcome=str(payload.get("outcome", "")),
        sequence=int(payload.get("sequence", 0) or 0),
        detail=dict(payload.get("detail") or {}),
    )


# ── OTLP / HTTP ──────────────────────────────────────────────────────────────

#: OTLP severity numbers (`logs.proto` SeverityNumber) for Sentinel outcomes.
#: `denied` is WARN rather than INFO for the same reason CEF rates it 7: a
#: refusal is the record of something having been attempted.
_OTLP_SEVERITY: Mapping[str, tuple[int, str]] = MappingProxyType({
    "success": (9, "INFO"),
    "failed": (17, "ERROR"),
    "denied": (13, "WARN"),
})


def _otlp_attribute(key: str, value: Any) -> dict[str, Any]:
    """One OTLP KeyValue. Non-scalars are serialised, never dropped."""
    if isinstance(value, bool):
        return {"key": key, "value": {"boolValue": value}}
    if isinstance(value, int):
        return {"key": key, "value": {"intValue": str(value)}}
    if isinstance(value, float):
        return {"key": key, "value": {"doubleValue": value}}
    if isinstance(value, str):
        return {"key": key, "value": {"stringValue": value}}
    return {"key": key, "value": {"stringValue": json.dumps(value, default=str)}}


class OtlpLogDeliverer:
    """Deliver one event as an OTLP/HTTP log record. One attempt, no retry.

    JSON encoding (`application/json`) rather than protobuf, which OTLP defines
    and every collector accepts, and which needs no code generation and no
    dependency.

    Retry, backoff and dead-lettering belong to the outbox dispatcher that calls
    this -- the same division `SiemWebhookDeliverer` follows.
    """

    __slots__ = ("_client", "_url", "_token", "_service")

    def __init__(
        self,
        *,
        client: Any,
        url: str,
        token: str = "",
        service_name: str = "sentinel",
    ) -> None:
        self._client = client
        self._url = url
        self._token = token
        self._service = service_name

    def deliver(
        self, *, payload: Mapping[str, Any], idempotency_key: str
    ) -> dict[str, Any]:
        event = event_from_payload(payload)
        number, text = _OTLP_SEVERITY.get(
            event.outcome.strip().lower(), (9, "INFO")
        )

        attributes = [
            _otlp_attribute("sentinel.tenant_id", event.tenant_id),
            _otlp_attribute("sentinel.actor", event.actor),
            _otlp_attribute("sentinel.action", event.action),
            _otlp_attribute("sentinel.resource_type", event.resource_type),
            _otlp_attribute("sentinel.resource_id", event.resource_id),
            _otlp_attribute("sentinel.outcome", event.outcome),
            _otlp_attribute("sentinel.audit_sequence", event.sequence),
            # Carried as an attribute so a collector that deduplicates can, and
            # so an at-least-once redelivery is identifiable as the same event.
            _otlp_attribute("sentinel.idempotency_key", idempotency_key),
        ]
        attributes.extend(
            _otlp_attribute(f"sentinel.detail.{k}", v)
            for k, v in sorted((event.detail or {}).items())
        )

        document = {
            "resourceLogs": [
                {
                    "resource": {
                        "attributes": [
                            _otlp_attribute("service.name", self._service),
                            _otlp_attribute("service.namespace", "sentinel"),
                        ]
                    },
                    "scopeLogs": [
                        {
                            "scope": {"name": "sentinel.audit"},
                            "logRecords": [
                                {
                                    # OTLP wants nanoseconds since epoch as a
                                    # string. `occurred_at` is an ISO timestamp
                                    # and is carried in `observedTimeUnixNano`'s
                                    # place as an attribute rather than being
                                    # reparsed here -- a transport is the wrong
                                    # place to reinterpret a recorded time.
                                    "timeUnixNano": "0",
                                    "severityNumber": number,
                                    "severityText": text,
                                    "body": {"stringValue": format_ecs(event)},
                                    "attributes": [
                                        *attributes,
                                        _otlp_attribute(
                                            "sentinel.occurred_at", event.occurred_at
                                        ),
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ]
        }

        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        headers["X-Sentinel-Idempotency-Key"] = idempotency_key

        response = self._client.request(
            method="POST",
            url=self._url,
            headers=headers,
            body=json.dumps(document, ensure_ascii=True, default=str).encode("utf-8"),
            idempotent=True,
        )
        if not 200 <= response.status < 300:
            raise SiemDeliveryFailed(
                f"OTLP collector answered HTTP {response.status}; the event "
                "stays on the outbox retry budget rather than being discarded"
            )
        return {
            "delivered": True,
            "transport": "otlp",
            "status": response.status,
            "peer": response.peer,
        }


# ── syslog / RFC 5424 over TLS ───────────────────────────────────────────────

#: Facility 13 is `log audit` in RFC 5424's table, which is what these are.
_SYSLOG_FACILITY = 13

#: RFC 5424 severity for each Sentinel outcome. 5 notice / 4 warning / 3 error.
_SYSLOG_SEVERITY: Mapping[str, int] = MappingProxyType({
    "success": 5,
    "denied": 4,
    "failed": 3,
})

#: RFC 5424 caps these fields; over-long values are truncated rather than sent,
#: because a receiver that rejects the frame drops the whole event.
_MAX_HOSTNAME = 255
_MAX_APPNAME = 48
_MAX_MSGID = 32


def _printable(value: str, limit: int) -> str:
    """RFC 5424 header fields are PRINTUSASCII with no spaces.

    A space in an APP-NAME would shift every following field by one, so a
    receiver would read the message id as the process id and the structured data
    as the message. Sanitised rather than escaped: these are identifiers, and an
    identifier that needs escaping is one to normalise.
    """
    cleaned = "".join(
        c if 33 <= ord(c) <= 126 else "_" for c in (value or "").strip()
    )
    return (cleaned[:limit] or "-")


def rfc5424_line(
    event: SiemEvent,
    *,
    hostname: str,
    app_name: str,
    idempotency_key: str,
) -> bytes:
    """Render one event as an RFC 5424 message.

    The MSG is the ECS JSON line, so a receiver that parses JSON out of syslog
    gets the same document the webhook transport sends, and one that does not
    still gets a readable, correctly-framed record.

    STRUCTURED-DATA carries the idempotency key. Its value is escaped per
    RFC 5424 section 6.3.3 -- `"`, `\\` and `]` -- because an unescaped `]`
    would terminate the SD-ELEMENT early and split one record into two.
    """
    severity = _SYSLOG_SEVERITY.get(event.outcome.strip().lower(), 5)
    priority = _SYSLOG_FACILITY * 8 + severity

    escaped = (
        str(idempotency_key)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("]", "\\]")
    )
    structured = f'[sentinel@0 idempotencyKey="{escaped}"]'

    # TIMESTAMP is `occurred_at` when it is present and NILVALUE otherwise. A
    # transport that substituted "now" for a missing recorded time would be
    # inventing the one field an investigator most needs to trust.
    timestamp = _printable(event.occurred_at, 64) if event.occurred_at else "-"

    header = (
        f"<{priority}>1 {timestamp} "
        f"{_printable(hostname, _MAX_HOSTNAME)} "
        f"{_printable(app_name, _MAX_APPNAME)} "
        f"- {_printable(event.action, _MAX_MSGID)} "
        f"{structured} "
    )
    # BOM before the MSG marks it as UTF-8, per RFC 5424 section 6.4.
    return header.encode("utf-8") + b"\xef\xbb\xbf" + format_ecs(event).encode("utf-8")


@dataclass(frozen=True, slots=True)
class SyslogTarget:
    """Where syslog goes, and how long it may take to get there."""

    host: str
    port: int = 6514
    timeout_seconds: float = 10.0
    app_name: str = "sentinel"


class SyslogTlsDeliverer:
    """Deliver one event as RFC 5424 syslog over TLS. One attempt, no retry.

    RFC 5425 transport: octet-counted framing (`MSG-LEN SP SYSLOG-MSG`) rather
    than the non-transparent newline framing, because the message body is JSON
    and JSON contains no newlines only by convention. A receiver using newline
    framing would split one record wherever a detail value happened to contain
    one; octet counting cannot be confused by content.

    TLS is not optional and the certificate is verified. A syslog stream is the
    audit trail in transit: in the clear it is readable by anyone on the path,
    and unverified it is writable by them.
    """

    __slots__ = ("_target", "_context", "_connect", "_hostname")

    def __init__(
        self,
        *,
        target: SyslogTarget,
        hostname: str = "sentinel",
        ssl_context: ssl.SSLContext | None = None,
        connect: Any = None,
    ) -> None:
        self._target = target
        self._hostname = hostname
        self._connect = connect
        if ssl_context is not None:
            self._context = ssl_context
        else:
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            # These are the defaults, and they are the two settings whose
            # accidental removal turns TLS into obfuscation.
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            self._context = context

    def deliver(
        self, *, payload: Mapping[str, Any], idempotency_key: str
    ) -> dict[str, Any]:
        event = event_from_payload(payload)
        message = rfc5424_line(
            event,
            hostname=self._hostname,
            app_name=self._target.app_name,
            idempotency_key=idempotency_key,
        )
        frame = f"{len(message)} ".encode("ascii") + message

        try:
            with self._open() as stream:
                stream.sendall(frame)
        except (OSError, ssl.SSLError) as exc:
            raise SiemDeliveryFailed(
                f"syslog delivery to {self._target.host}:{self._target.port} "
                f"failed: {type(exc).__name__}: {exc}; the event stays on the "
                "outbox retry budget rather than being discarded"
            ) from exc

        return {
            "delivered": True,
            "transport": "syslog",
            "bytes": len(frame),
            "peer": f"{self._target.host}:{self._target.port}",
        }

    def _open(self):
        if self._connect is not None:
            return self._connect(self._target)
        raw = socket.create_connection(
            (self._target.host, self._target.port),
            timeout=self._target.timeout_seconds,
        )
        return self._context.wrap_socket(raw, server_hostname=self._target.host)


# ── Fan-out ──────────────────────────────────────────────────────────────────


class FanOutSiemDeliverer:
    """Deliver one record to every configured sink.

    Raises if ANY sink failed, so the outbox retries. See the module docstring
    for why that is duplicate-over-loss rather than a bug, and why the receipt
    names each sink.
    """

    __slots__ = ("_sinks",)

    def __init__(self, *, sinks: Mapping[str, Any]) -> None:
        if not sinks:
            raise UnsupportedSiemTransport(
                "a fan-out deliverer with no sinks would report every event as "
                "delivered to nowhere; configure at least one transport or "
                "leave SIEM export unconfigured"
            )
        self._sinks = dict(sinks)

    @property
    def sink_names(self) -> Iterable[str]:
        return tuple(sorted(self._sinks))

    def deliver(
        self, *, payload: Mapping[str, Any], idempotency_key: str
    ) -> dict[str, Any]:
        receipts: dict[str, Any] = {}
        failures: list[str] = []

        for name in sorted(self._sinks):
            try:
                receipts[name] = self._sinks[name].deliver(
                    payload=payload, idempotency_key=idempotency_key
                )
            except Exception as exc:  # noqa: BLE001 - every sink failure is one
                # Recorded, not raised yet. One collector being down must not
                # stop the others from receiving the event on this attempt --
                # otherwise a single broken sink means nothing ships anywhere
                # until an operator notices.
                receipts[name] = {"delivered": False, "error": str(exc)}
                failures.append(f"{name}: {exc}")

        if failures:
            raise SiemDeliveryFailed(
                "SIEM fan-out incomplete (" + "; ".join(failures) + "). The "
                "record stays on the outbox retry budget; sinks that already "
                "succeeded will see this event again, identifiable by its "
                "idempotency key."
            )
        return {"delivered": True, "transport": "fanout", "sinks": receipts}
