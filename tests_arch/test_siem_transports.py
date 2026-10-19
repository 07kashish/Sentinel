"""OTLP and syslog transports: framing, escaping, and never a false receipt.

WHY EACH GROUP EXISTS
---------------------
FRAMING. A syslog receiver reads a length prefix and then exactly that many
bytes. Get the count wrong by one and every subsequent record on the connection
is misaligned -- the failure is silent, downstream, and looks like corruption
rather than like a bug here. The framing tests count bytes, not characters,
because the message body is UTF-8 and `len(str)` is the wrong number.

ESCAPING. RFC 5424 structured data ends at the first unescaped `]`. A value
carrying one would split a record in two, and the second half would parse as a
different event -- the syslog equivalent of the CEF injection `siem.py` already
guards.

NEVER A FALSE RECEIPT. Every transport must raise on a non-success rather than
return a delivered-shaped dict. A silently discarded security event is the one
outcome the outbox exists to prevent, and a receipt saying `delivered: True`
would take the record off the retry budget forever.
"""

from __future__ import annotations

import json

import pytest

from sentinel.infrastructure.siem import SiemDeliveryFailed
from sentinel.infrastructure.siem_transports import (
    FanOutSiemDeliverer,
    OtlpLogDeliverer,
    SyslogTarget,
    SyslogTlsDeliverer,
    UnsupportedSiemTransport,
    event_from_payload,
    rfc5424_line,
)

PAYLOAD = {
    "tenant_id": "acme",
    "occurred_at": "2026-08-30T12:00:00Z",
    "actor": "finance-agent",
    "action": "export_rows",
    "resource_type": "database",
    "resource_id": "customers",
    "outcome": "denied",
    "sequence": 41,
    "detail": {"rows": 48291, "destination": "unknown.example"},
}


class _Response:
    def __init__(self, status: int) -> None:
        self.status = status
        self.peer = "203.0.113.9:4318"
        self.body = b"{}"
        self.headers: dict[str, str] = {}


class _Client:
    def __init__(self, status: int = 200) -> None:
        self.status = status
        self.sent: list[dict] = []

    def request(self, *, method, url, headers=None, body=None, idempotent=False):
        self.sent.append(
            {"method": method, "url": url, "headers": dict(headers or {}), "body": body}
        )
        return _Response(self.status)


# ── OTLP ─────────────────────────────────────────────────────────────────────


def test_otlp_sends_a_well_formed_logs_envelope():
    client = _Client()
    OtlpLogDeliverer(client=client, url="https://collector.example/v1/logs").deliver(
        payload=PAYLOAD, idempotency_key="idem-1"
    )

    document = json.loads(client.sent[0]["body"])
    record = document["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
    assert record["severityText"] == "WARN"  # `denied` is not INFO
    attributes = {a["key"]: a["value"] for a in record["attributes"]}
    assert attributes["sentinel.actor"] == {"stringValue": "finance-agent"}
    assert attributes["sentinel.idempotency_key"] == {"stringValue": "idem-1"}
    # Detail values keep their types rather than being stringified wholesale.
    assert attributes["sentinel.detail.rows"] == {"intValue": "48291"}


def test_otlp_carries_the_idempotency_key_in_a_header_too():
    """A collector that deduplicates on headers can, without parsing the body."""
    client = _Client()
    OtlpLogDeliverer(client=client, url="https://collector.example/v1/logs").deliver(
        payload=PAYLOAD, idempotency_key="idem-2"
    )
    assert client.sent[0]["headers"]["X-Sentinel-Idempotency-Key"] == "idem-2"


def test_otlp_refuses_to_call_a_non_2xx_a_delivery():
    deliverer = OtlpLogDeliverer(
        client=_Client(status=503), url="https://collector.example/v1/logs"
    )
    with pytest.raises(SiemDeliveryFailed, match="503"):
        deliverer.deliver(payload=PAYLOAD, idempotency_key="idem-3")


def test_otlp_treats_a_4xx_as_retryable_too():
    """A misconfigured token is permanent from the collector's point of view.
    Marking it delivered would discard the event; the outbox's dead-letter state
    is where a permanent failure belongs, and it gets there by failing.
    """
    deliverer = OtlpLogDeliverer(
        client=_Client(status=401), url="https://collector.example/v1/logs"
    )
    with pytest.raises(SiemDeliveryFailed):
        deliverer.deliver(payload=PAYLOAD, idempotency_key="idem-4")


# ── syslog ───────────────────────────────────────────────────────────────────


class _Stream:
    def __init__(self, frames: list[bytes], fail: Exception | None = None) -> None:
        self._frames = frames
        self._fail = fail

    def sendall(self, data: bytes) -> None:
        if self._fail is not None:
            raise self._fail
        self._frames.append(data)

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


def _syslog(frames: list[bytes], fail: Exception | None = None) -> SyslogTlsDeliverer:
    return SyslogTlsDeliverer(
        target=SyslogTarget(host="siem.internal"),
        hostname="sentinel-1",
        connect=lambda _target: _Stream(frames, fail),
    )


def test_syslog_octet_count_is_bytes_not_characters():
    """THE framing test. The MSG is UTF-8 and carries a BOM; counting
    characters would understate the length and misalign every record after it
    on the same connection.
    """
    frames: list[bytes] = []
    _syslog(frames).deliver(payload=PAYLOAD, idempotency_key="idem-5")

    prefix, _, message = frames[0].partition(b" ")
    assert int(prefix) == len(message), "octet count does not match the frame"


def test_syslog_priority_encodes_facility_and_severity():
    frames: list[bytes] = []
    _syslog(frames).deliver(payload=PAYLOAD, idempotency_key="idem-6")
    # facility 13 (log audit) * 8 + severity 4 (warning, for `denied`) = 108
    assert frames[0].split(b" ", 1)[1].startswith(b"<108>1 ")


def test_syslog_structured_data_escapes_a_closing_bracket():
    """An unescaped `]` terminates the SD-ELEMENT, and the rest of the record
    parses as a different message.
    """
    line = rfc5424_line(
        event_from_payload(PAYLOAD),
        hostname="h",
        app_name="sentinel",
        idempotency_key='ev]il" \\key',
    )
    assert b'idempotencyKey="ev\\]il\\" \\\\key"' in line


def test_syslog_header_fields_cannot_contain_a_space():
    """A space in APP-NAME shifts every following field by one, so the receiver
    reads the message id as the process id.
    """
    line = rfc5424_line(
        event_from_payload({**PAYLOAD, "action": "export rows now"}),
        hostname="my host",
        app_name="sentinel agent",
        idempotency_key="k",
    )
    header = line.split(b"[sentinel@0")[0]
    # <PRI>VERSION, TIMESTAMP, HOSTNAME, APP-NAME, PROCID, MSGID, then SD.
    assert len(header.split(b" ")) == 7, header


def test_syslog_does_not_invent_a_timestamp_it_was_not_given():
    """Substituting "now" for a missing recorded time would fabricate the one
    field an investigator most needs to trust. NILVALUE says "not recorded".
    """
    line = rfc5424_line(
        event_from_payload({**PAYLOAD, "occurred_at": ""}),
        hostname="h",
        app_name="a",
        idempotency_key="k",
    )
    assert line.split(b" ")[1] == b"-"


def test_syslog_turns_a_socket_error_into_a_retryable_failure():
    deliverer = _syslog([], fail=OSError("connection reset"))
    with pytest.raises(SiemDeliveryFailed, match="connection reset"):
        deliverer.deliver(payload=PAYLOAD, idempotency_key="idem-7")


def test_syslog_verifies_tls_by_default():
    """A syslog stream is the audit trail in transit: in the clear it is
    readable by anyone on the path, unverified it is writable by them.
    """
    import ssl

    deliverer = SyslogTlsDeliverer(target=SyslogTarget(host="siem.internal"))
    context = deliverer._context  # noqa: SLF001 - asserting a security default
    assert context.check_hostname is True
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2


# ── fan-out ──────────────────────────────────────────────────────────────────


class _Sink:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.calls = 0

    def deliver(self, *, payload, idempotency_key):
        self.calls += 1
        if self.fail:
            raise SiemDeliveryFailed("collector unreachable")
        return {"delivered": True}


def test_fanout_delivers_to_every_sink():
    a, b = _Sink(), _Sink()
    receipt = FanOutSiemDeliverer(sinks={"a": a, "b": b}).deliver(
        payload=PAYLOAD, idempotency_key="idem-8"
    )
    assert a.calls == 1 and b.calls == 1
    assert receipt["sinks"]["a"]["delivered"] is True


def test_one_failing_sink_does_not_stop_the_others_on_this_attempt():
    """A single broken collector must not mean nothing ships anywhere."""
    good, bad = _Sink(), _Sink(fail=True)
    with pytest.raises(SiemDeliveryFailed):
        FanOutSiemDeliverer(sinks={"good": good, "bad": bad}).deliver(
            payload=PAYLOAD, idempotency_key="idem-9"
        )
    assert good.calls == 1, "a healthy sink was skipped because another failed"


def test_a_partial_fanout_raises_so_the_outbox_retries():
    with pytest.raises(SiemDeliveryFailed, match="fan-out incomplete"):
        FanOutSiemDeliverer(sinks={"bad": _Sink(fail=True)}).deliver(
            payload=PAYLOAD, idempotency_key="idem-10"
        )


def test_a_fanout_with_no_sinks_is_refused_rather_than_reporting_success():
    """It would report every event as delivered to nowhere."""
    with pytest.raises(UnsupportedSiemTransport, match="delivered to nowhere"):
        FanOutSiemDeliverer(sinks={})


# ── wiring: settings -> deliverer ────────────────────────────────────────────


def _settings(**overrides):
    from sentinel.composition.settings import Settings

    return Settings.from_environment(
        {
            "SENTINEL_ENV": "development",
            "SENTINEL_API_KEYS": "acme:supersecretkeyvalue012345:admin",
            "SENTINEL_DATABASE_URL": "postgresql://s:p@db.internal:5432/sentinel",
            **overrides,
        }
    )


def test_no_sink_configured_returns_none_not_an_empty_fanout():
    """`PipelineSteps.siem_export` is derived from this being None. An empty
    fan-out would satisfy the type and quietly enqueue export intents for a sink
    that does not exist -- outbox rows piling up forever.
    """
    from sentinel.composition.siem_wiring import build_siem_deliverer

    assert build_siem_deliverer(_settings()) is None


def test_one_sink_is_used_directly_rather_than_wrapped():
    from sentinel.composition.siem_wiring import build_siem_deliverer

    deliverer = build_siem_deliverer(
        _settings(SENTINEL_SIEM_OTLP_URL="https://collector.example/v1/logs")
    )
    assert isinstance(deliverer, OtlpLogDeliverer)


def test_two_sinks_fan_out():
    from sentinel.composition.siem_wiring import build_siem_deliverer

    deliverer = build_siem_deliverer(
        _settings(
            SENTINEL_SIEM_WEBHOOK_URL="https://splunk.example/services/collector",
            SENTINEL_SIEM_SYSLOG_HOST="siem.internal",
        )
    )
    assert isinstance(deliverer, FanOutSiemDeliverer)
    assert sorted(deliverer.sink_names) == ["syslog", "webhook"]


def test_kafka_is_refused_by_name_at_start_up():
    """Not a typo and not a silent no-op. An operator who configures Kafka on a
    build that cannot speak it must learn at start-up, not discover during an
    audit that a year of events went somewhere else.
    """
    from sentinel.composition.settings import ConfigurationError

    with pytest.raises(ConfigurationError, match="NOT_SUPPORTED"):
        _settings(SENTINEL_SIEM_KAFKA_BROKERS="kafka-1:9092")


def test_a_half_configured_transport_is_a_start_up_error():
    from sentinel.composition.settings import ConfigurationError

    with pytest.raises(ConfigurationError, match="SENTINEL_SIEM_OTLP_URL is required"):
        _settings(SENTINEL_SIEM_OTLP_TOKEN="tok")


def test_a_malformed_syslog_port_fails_at_start_up():
    from sentinel.composition.settings import ConfigurationError
    from sentinel.composition.siem_wiring import build_siem_deliverer

    with pytest.raises(ConfigurationError, match="must be an integer"):
        build_siem_deliverer(
            _settings(
                SENTINEL_SIEM_SYSLOG_HOST="siem.internal",
                SENTINEL_SIEM_SYSLOG_PORT="six-five-one-four",
            )
        )
