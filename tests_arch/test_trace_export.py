"""Real local HTTP/protobuf transport plus bounded-queue fault injection."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Event, Thread

import pytest
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest, ExportTraceServiceResponse
from opentelemetry.sdk.trace.export import SpanExportResult

from sentinel.infrastructure.observability import MetricsRegistry, OtelHooks, correlation_var, new_correlation
from sentinel.infrastructure.trace_export import BoundedSpanProcessor


@contextmanager
def receiver(*, partial=False, status=200):
    received = []
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            data = self.rfile.read(int(self.headers["Content-Length"]))
            request = ExportTraceServiceRequest()
            request.ParseFromString(data)
            received.append((self.path, data, request))
            reply = ExportTraceServiceResponse()
            if partial:
                reply.partial_success.rejected_spans = 1
            body = reply.SerializeToString()
            self.send_response(status)
            self.send_header("Content-Type", "application/x-protobuf")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *_):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/v1/traces", received
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_real_otlp_http_exports_without_sensitive_attributes_and_flushes():
    metrics = MetricsRegistry()
    with receiver() as (endpoint, received):
        hooks = OtelHooks(endpoint=endpoint, metrics=metrics, allow_http=True)
        token = correlation_var.set(new_correlation(request_id="secret-request", tenant_id="private-tenant"))
        try:
            with pytest.raises(ValueError):
                with hooks.span("secret-operation", method="POST", path="/secret-path", parameters="secret-body"):
                    raise ValueError("secret-exception")
            hooks.close()
            assert hooks._processor.closed
        finally:
            correlation_var.reset(token)
            hooks.close()
    assert len(received) == 1
    path, body, request = received[0]
    assert path == "/v1/traces"
    assert b"secret" not in body and b"private-tenant" not in body
    span = request.resource_spans[0].scope_spans[0].spans[0]
    assert span.name == "sentinel.operation"
    assert span.end_time_unix_nano >= span.start_time_unix_nano > 0
    assert len(span.trace_id) == 16 and len(span.span_id) == 8
    assert span.status.code == 2 and not span.events
    assert hooks.exported_events == ()
    assert 'sentinel_trace_spans_exported_total 1.0' in metrics.render_prometheus()


@pytest.mark.parametrize("partial,status", [(True, 200), (False, 500), (False, 302)])
def test_rejection_partial_delivery_and_redirect_are_not_reported_as_success(partial, status):
    metrics = MetricsRegistry()
    with receiver(partial=partial, status=status) as (endpoint, received):
        hooks = OtelHooks(endpoint=endpoint, allow_http=True, metrics=metrics)
        with hooks.span("http.request", method="GET"):
            pass
        hooks.close()
    assert len(received) == 1
    text = metrics.render_prometheus()
    assert 'reason="export_failed"' in text
    assert 'sentinel_trace_spans_exported_total' not in text


def test_slow_collector_bounds_queue_and_counts_drops():
    entered, release = Event(), Event()
    class SlowExporter:
        def export(self, spans):
            entered.set()
            assert release.wait(5)
            return SpanExportResult.SUCCESS
        def shutdown(self):
            pass
    metrics = MetricsRegistry()
    processor = BoundedSpanProcessor(SlowExporter(), metrics, capacity=4, batch_size=2)
    try:
        processor.on_end(object())
        assert entered.wait(2)
        for _ in range(1000):
            processor.on_end(object())
        assert len(processor.queue) == 4
        assert not processor.force_flush(10)
        assert 'reason="queue_full"} 996.0' in metrics.render_prometheus()
    finally:
        release.set()
        processor.shutdown()
    assert processor.closed and not processor.queue


def test_unavailable_collector_is_counted_without_failing_the_business_action():
    class Unavailable:
        def export(self, spans):
            raise RuntimeError("sensitive-remote-error")
        def shutdown(self):
            pass
    metrics = MetricsRegistry()
    processor = BoundedSpanProcessor(Unavailable(), metrics)
    processor.on_end(object())
    processor.shutdown()
    assert 'reason="export_failed"} 1.0' in metrics.render_prometheus()
    assert 'sensitive' not in metrics.render_prometheus()


@pytest.mark.parametrize("endpoint", ["http://localhost:4318/v1/traces", "https://user:password@collector/v1/traces", "https://collector/v1/traces?token=x"])
def test_unsafe_production_endpoint_refuses_startup(endpoint):
    with pytest.raises(ValueError):
        OtelHooks(endpoint=endpoint)


def test_startup_failure_closes_the_trace_worker(tmp_path, engine_config):
    from threading import enumerate as threads
    from dataclasses import replace
    from sentinel.composition.settings import Settings
    from sentinel.infrastructure.oidc import OidcError
    from sentinel.composition.container import build_container
    from sentinel.infrastructure.sql.engine import build_engine
    from sentinel.infrastructure.sql.migrate import migrate

    with receiver() as (endpoint, _):
        settings = Settings.from_environment({
            "SENTINEL_DB_PATH": str(tmp_path / "startup.db"),
            "SENTINEL_API_KEYS": "tenant:" + "x" * 40 + ":admin",
            "SENTINEL_SOFT_PROMPT_DETECT": "false",
            "SENTINEL_OTLP_ENDPOINT": endpoint,
            "SENTINEL_OIDC_ISSUER": "https://issuer.example.invalid",
            "SENTINEL_OIDC_AUDIENCE": "sentinel",
            "SENTINEL_OIDC_JWKS_JSON": "{",  # malformed after exporter construction
        })
        settings = replace(settings, engine=engine_config)
        pool = build_engine(settings.engine)
        try:
            migrate(pool)
        finally:
            pool.close()
        before = {t.ident for t in threads() if t.name == "sentinel-traces"}
        with pytest.raises(OidcError, match="JWKS JSON is invalid"):
            build_container(settings)
        assert {t.ident for t in threads() if t.name == "sentinel-traces"} == before
