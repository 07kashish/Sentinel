"""Bounded operational traces through the standard OTLP exporter.

This is lossy operational telemetry, never the durable execution evidence store.
No request paths, IDs, parameters, exception text or tenant data are exported.
"""
from __future__ import annotations

from collections import deque
from threading import Condition, Thread
from time import monotonic
from urllib.parse import urlsplit

from opentelemetry.exporter.otlp.proto.http import Compression
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceResponse
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import SpanLimits, SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.export import SpanExportResult
from requests import Response

from sentinel.infrastructure.outbound import HardenedHttpClient, OutboundPolicy


class HardenedOtlpSession:
    """Adapt OTLP serialization to Sentinel's bounded, no-redirect transport."""

    def __init__(self, endpoint: str, allow_http: bool):
        parts = urlsplit(endpoint)
        if (not parts.hostname or parts.username or parts.password or parts.query or parts.fragment
                or parts.scheme not in ({"https", "http"} if allow_http else {"https"})):
            raise ValueError("OTLP endpoint requires an explicit host and permitted scheme without userinfo, query or fragment")
        self.endpoint = endpoint
        self.headers = {}
        self.client = HardenedHttpClient(policy=OutboundPolicy(
            allowed_schemes=frozenset({parts.scheme}), allowed_hosts=frozenset({parts.hostname}),
            allow_private_destinations=True, max_response_bytes=65536,
            connect_timeout_seconds=1.0, read_timeout_seconds=1.0,
        ))

    def post(self, *, url, data, verify, timeout, cert):
        if url != self.endpoint or verify is not True or cert is not None:
            raise ValueError("unsupported OTLP transport override")
        result = self.client.request(method="POST", url=url, headers=self.headers, body=data)
        response = Response()
        response.status_code = result.status
        response.reason = "collector response"  # never log an untrusted reason/body
        response._content = b""
        if result.status == 200 and result.body:
            ack = ExportTraceServiceResponse()
            try:
                ack.ParseFromString(result.body)
                if ack.partial_success.rejected_spans:
                    response.status_code = 400
            except Exception:
                response.status_code = 400
        elif result.status != 200:
            # Only a complete OTLP success acknowledges the whole batch.
            response.status_code = 400
        return response

    def close(self):
        pass  # HardenedHttpClient closes each response/connection itself.


class BoundedSpanProcessor(SpanProcessor):
    def __init__(self, exporter, metrics, *, capacity=256, batch_size=32):
        if not 1 <= batch_size <= capacity <= 4096:
            raise ValueError("invalid trace queue bounds")
        self.exporter, self.metrics = exporter, metrics
        self.capacity, self.batch_size = capacity, batch_size
        self.queue = deque()
        self.condition = Condition()
        self.in_flight = False
        self.closing = False
        self.closed = False
        self.thread = Thread(target=self._run, name="sentinel-traces", daemon=True)
        self.thread.start()

    def on_start(self, span, parent_context=None):
        pass

    def _drop(self, count, reason):
        self.metrics.inc("sentinel_trace_spans_dropped_total", amount=count, labels={"reason": reason})

    def on_end(self, span):
        with self.condition:
            if self.closing or len(self.queue) >= self.capacity:
                self._drop(1, "closed" if self.closing else "queue_full")
                return
            self.queue.append(span)
            self.condition.notify_all()

    def _run(self):
        try:
            while True:
                with self.condition:
                    self.condition.wait_for(lambda: self.queue or self.closing)
                    if not self.queue and self.closing:
                        return
                    if not self.closing and len(self.queue) < self.batch_size:
                        self.condition.wait(timeout=0.05)
                    batch = [self.queue.popleft() for _ in range(min(len(self.queue), self.batch_size))]
                    self.in_flight = True
                try:
                    success = self.exporter.export(batch) is SpanExportResult.SUCCESS
                except Exception:
                    success = False  # no exception text or remote response retained
                if success:
                    self.metrics.inc("sentinel_trace_spans_exported_total", amount=len(batch))
                else:
                    self._drop(len(batch), "export_failed")
                with self.condition:
                    self.in_flight = False
                    self.condition.notify_all()
        finally:
            self.exporter.shutdown()
            with self.condition:
                self.closed = True
                self.condition.notify_all()

    def force_flush(self, timeout_millis=3000):
        with self.condition:
            return self.condition.wait_for(lambda: not self.queue and not self.in_flight,
                                           timeout=max(0, timeout_millis) / 1000)

    def shutdown(self):
        with self.condition:
            self.closing = True
            self.condition.notify_all()
        deadline = monotonic() + 3.0
        self.force_flush(2000)
        with self.condition:
            remaining = len(self.queue)
            self.queue.clear()
            if remaining:
                self._drop(remaining, "shutdown_timeout")
            self.condition.notify_all()
        self.thread.join(timeout=max(0, deadline - monotonic()))


def build_tracer(endpoint, metrics, *, allow_http=False, capacity=256, batch_size=32):
    session = HardenedOtlpSession(endpoint, allow_http)
    exporter = OTLPSpanExporter(endpoint=endpoint, session=session, timeout=1.0,
                                certificate_file=True, headers={"User-Agent": "sentinel-traces"},
                                compression=Compression.NoCompression)
    processor = BoundedSpanProcessor(exporter, metrics, capacity=capacity, batch_size=batch_size)
    # Explicit Resource avoids environment resource detectors adding host or
    # customer-controlled values. No global provider or propagator is installed.
    provider = TracerProvider(resource=Resource({"service.name": "sentinel"}),
                              span_limits=SpanLimits(max_attributes=2, max_events=0, max_links=0,
                                                     max_attribute_length=32),
                              shutdown_on_exit=False)
    provider.add_span_processor(processor)
    return provider, provider.get_tracer("sentinel.operational"), processor
