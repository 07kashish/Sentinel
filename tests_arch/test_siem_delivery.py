"""Real SIEM delivery: the outbox owns durability, the webhook owns the wire.

WHY THIS SUITE EXISTS SEPARATELY FROM `test_siem_export.py`
------------------------------------------------------------
That module tests RENDERING -- CEF escaping, ECS field names -- which is a pure
function over an event. This one tests the claim the rendering module could not
make until delivery existed: **a security event is never silently discarded.**

The claim decomposes into three properties, and each has a test here rather
than a paragraph:

  1. A non-2xx from the collector does NOT mark the record delivered. It fails,
     which keeps the row on the outbox's retry budget.
  2. An unconfigured deliverer REFUSES a claimed `siem` row by name rather than
     treating it as a no-op. A row exists because something committed the
     intent to export it; silently succeeding would be the discard.
  3. The idempotency key travels to the collector, so an at-least-once
     redelivery after a crashed deliverer is identifiable as the SAME event
     rather than a second one.

Delivery is one attempt with no retry inside it, deliberately: retry, backoff
and dead-lettering already exist in the outbox dispatcher, and a second retry
loop nested inside the first would multiply the budget nobody configured.
"""

from __future__ import annotations

import json

import pytest

from sentinel.infrastructure.outbound import OutboundResponse
from sentinel.infrastructure.siem import SiemDeliveryFailed, SiemWebhookDeliverer

PAYLOAD = {
    "tenant_id": "acme",
    "occurred_at": "2026-08-28T00:00:00+00:00",
    "actor": "agent-7",
    "action": "iam:AttachUserPolicy",
    "resource_type": "incident",
    "resource_id": "inc-1",
    "outcome": "detected",
    "detail": {"severity": 92},
}


class FakeHttp:
    def __init__(self, *, status=200):
        self.status = status
        self.requests: list[dict] = []

    def request(self, *, method, url, headers=None, body=None, idempotent=False):
        self.requests.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers or {}),
                "body": body,
                "idempotent": idempotent,
            }
        )
        return OutboundResponse(
            status=self.status, headers={}, body=b"{}", peer="collector:443"
        )


def _deliverer(http, *, token="collector-token"):
    return SiemWebhookDeliverer(
        client=http, url="https://collector.example/services/collector", token=token
    )


def test_a_delivered_event_reaches_the_collector_as_ecs_json():
    http = FakeHttp()
    receipt = _deliverer(http).deliver(payload=PAYLOAD, idempotency_key="key-1")

    assert receipt["delivered"] is True
    sent = http.requests[0]
    assert sent["method"] == "POST"
    document = json.loads(sent["body"].decode("utf-8"))
    # ECS field names, because that is the shape Splunk HEC, Elastic and
    # Datadog all ingest without a custom parser.
    assert document["event"]["action"] == "iam:AttachUserPolicy"
    assert document["organization"]["id"] == "acme"


def test_the_idempotency_key_travels_so_a_redelivery_is_identifiable():
    """The outbox lease permits at-least-once. The collector needs to know."""
    http = FakeHttp()
    _deliverer(http).deliver(payload=PAYLOAD, idempotency_key="key-42")
    assert http.requests[0]["headers"]["X-Sentinel-Idempotency-Key"] == "key-42"
    assert http.requests[0]["headers"]["Authorization"] == "Bearer collector-token"


def test_a_rejected_delivery_fails_rather_than_reporting_success():
    """THE property. A 4xx must not be laundered into 'delivered'.

    A misconfigured URL or an expired token is permanent from the webhook's
    point of view, and marking it delivered-with-a-shrug would discard a
    security event. Failing keeps the row on the outbox's retry budget and,
    on exhaustion, in the dead-letter state where an operator can see it.
    """
    http = FakeHttp(status=403)
    with pytest.raises(SiemDeliveryFailed) as refused:
        _deliverer(http).deliver(payload=PAYLOAD, idempotency_key="key-2")
    assert "403" in str(refused.value)


def test_a_server_error_also_fails():
    http = FakeHttp(status=503)
    with pytest.raises(SiemDeliveryFailed):
        _deliverer(http).deliver(payload=PAYLOAD, idempotency_key="key-3")


def test_no_authorization_header_appears_when_no_token_is_configured():
    """A collector on a private network may need none; inventing one is worse."""
    http = FakeHttp()
    _deliverer(http, token="").deliver(payload=PAYLOAD, idempotency_key="key-4")
    assert "Authorization" not in http.requests[0]["headers"]


# ── The dispatcher's half of the contract ────────────────────────────────────


def test_an_unconfigured_deliverer_refuses_a_siem_row_by_name():
    """Not a no-op. A row exists because the intent to export was committed.

    Treating it as delivered because nothing happens to be wired would be
    exactly the silent discard the whole outbox path exists to prevent.
    """
    from sentinel.application.commands.dispatch_outbox import DispatchOutboxHandler

    handler = DispatchOutboxHandler(
        uow_factory=None,
        attestation=None,
        clock=None,
        logger=None,
        siem_deliverer=None,
    )

    class _Record:
        kind = "siem"
        payload = PAYLOAD

        class idempotency_key:  # noqa: N801 - a stand-in value object
            value = "key-5"

    with pytest.raises(ValueError) as refused:
        handler._deliver(_Record())
    assert "siem" in str(refused.value)
    assert "NOT discarded" in str(refused.value)


def test_a_configured_deliverer_is_used_for_a_siem_row():
    from sentinel.application.commands.dispatch_outbox import DispatchOutboxHandler

    http = FakeHttp()
    handler = DispatchOutboxHandler(
        uow_factory=None,
        attestation=None,
        clock=None,
        logger=None,
        siem_deliverer=_deliverer(http),
    )

    class _Record:
        kind = "siem"
        payload = PAYLOAD

        class idempotency_key:  # noqa: N801 - a stand-in value object
            value = "key-6"

    receipt = handler._deliver(_Record())
    assert receipt["delivered"] is True
    assert http.requests, "the configured deliverer was not called"
