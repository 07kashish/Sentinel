"""In-process observability: Prometheus text, correlation IDs, optional OTLP hooks.

OpenTelemetry is loaded only when SENTINEL_OTLP_ENDPOINT is configured.
Unset hooks are no-ops. Metrics are process-local counters/histograms.
"""

from __future__ import annotations

import contextvars
import math
import re
from threading import RLock
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Iterator, Mapping
from uuid import uuid4

__all__ = [
    "Correlation",
    "MetricsRegistry",
    "OtelHooks",
    "correlation_var",
    "new_correlation",
]

correlation_var: contextvars.ContextVar["Correlation | None"] = contextvars.ContextVar(
    "sentinel_correlation", default=None
)


@dataclass(frozen=True, slots=True)
class Correlation:
    request_id: str
    tenant_id: str = ""
    incident_id: str = ""
    epoch: str = ""
    worker_shard: str = ""

    def as_dict(self) -> dict[str, str]:
        out = {"request_id": self.request_id}
        if self.tenant_id:
            out["tenant_id"] = self.tenant_id
        if self.incident_id:
            out["incident_id"] = self.incident_id
        if self.epoch:
            out["epoch"] = self.epoch
        if self.worker_shard:
            out["worker_shard"] = self.worker_shard
        return out


def new_correlation(
    *,
    request_id: str | None = None,
    tenant_id: str = "",
    incident_id: str = "",
    epoch: str = "",
    worker_shard: str = "",
) -> Correlation:
    return Correlation(
        request_id=request_id or uuid4().hex,
        tenant_id=tenant_id,
        incident_id=incident_id,
        epoch=epoch,
        worker_shard=worker_shard,
    )


@dataclass
class MetricsRegistry:
    """Bounded, thread-safe process-local metrics; scrape one process per pod.

    This registry does not aggregate gunicorn workers. Deployment-wide values
    require per-process scrape targets and aggregation in Prometheus.
    """

    max_series: int = 2048
    _values: dict = field(default_factory=dict)
    _types: dict = field(default_factory=dict)
    _dropped: int = 0
    _lock: Any = field(default_factory=RLock)

    def _slot(self, name, labels, kind):
        if not re.fullmatch(r"[a-zA-Z_:][a-zA-Z0-9_:]{0,127}", name):
            self._dropped += 1
            return None
        pairs = tuple(sorted((str(k), str(v)) for k, v in (labels or {}).items()))
        allowed = {"method", "path", "route", "status", "mode", "backend", "reason"}
        if len(pairs) > 8 or any(k not in allowed or len(v) > 256 for k, v in pairs):
            self._dropped += 1
            return None
        key = (name, pairs)
        if self._types.get(name, kind) != kind or (key not in self._values and len(self._values) >= self.max_series):
            self._dropped += 1
            return None
        self._types[name] = kind
        if key not in self._values:
            self._values[key] = [0.0, 0, [0] * len(_BUCKETS)] if kind == "histogram" else 0.0
        return key

    def inc(self, name: str, *, amount: float = 1.0, labels: Mapping[str, str] | None = None) -> None:
        with self._lock:
            if not math.isfinite(amount) or amount < 0:
                self._dropped += 1
                return
            key = self._slot(name, labels, "counter")
            if key is not None:
                self._values[key] += amount

    def set_gauge(self, name: str, value: float, *, labels: Mapping[str, str] | None = None) -> None:
        with self._lock:
            if not math.isfinite(value):
                self._dropped += 1
                return
            key = self._slot(name, labels, "gauge")
            if key is not None:
                self._values[key] = value

    def observe(self, name: str, value: float, *, labels: Mapping[str, str] | None = None) -> None:
        with self._lock:
            if not math.isfinite(value) or value < 0:
                self._dropped += 1
                return
            key = self._slot(name, labels, "histogram")
            if key is not None:
                sample = self._values[key]
                sample[0] += value
                sample[1] += 1
                for i, upper in enumerate(_BUCKETS):
                    sample[2][i] += int(value <= upper)

    def render_prometheus(self) -> str:
        with self._lock:
            lines = []
            declared = set()
            for (name, pairs), sample in sorted(self._values.items()):
                kind = self._types[name]
                if name not in declared:
                    lines.append(f"# TYPE {name} {kind}")
                    declared.add(name)
                labels = dict(pairs)
                if kind != "histogram":
                    lines.append(f"{_key(name, labels)} {sample}")
                    continue
                for upper, count in zip(_BUCKETS, sample[2]):
                    bound = "+Inf" if math.isinf(upper) else str(upper)
                    lines.append(f"{_key(name + '_bucket', {**labels, 'le': bound})} {count}")
                lines.append(f"{_key(name + '_sum', labels)} {sample[0]}")
                lines.append(f"{_key(name + '_count', labels)} {sample[1]}")
            lines.append("# TYPE sentinel_metric_samples_dropped_total counter")
            lines.append(f"sentinel_metric_samples_dropped_total {self._dropped}")
            return "\n".join(lines) + "\n"


_BUCKETS = (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, float("inf"))


def _key(name: str, labels: Mapping[str, str] | None) -> str:
    if not labels:
        return name
    def escaped(value):
        return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')
    parts = ",".join(f'{k}="{escaped(v)}"' for k, v in sorted(labels.items()))
    return f"{name}{{{parts}}}"


class OtelHooks:
    """Optional bounded operational tracing. Durable evidence is separate."""

    def __init__(self, *, endpoint: str = "", metrics=None, allow_http=False,
                 capacity=256, batch_size=32) -> None:
        self._provider = self._tracer = self._processor = None
        metrics = metrics if metrics is not None else MetricsRegistry()
        for reason in ("queue_full", "closed", "export_failed", "shutdown_timeout"):
            metrics.inc("sentinel_trace_spans_dropped_total", amount=0, labels={"reason": reason})
        metrics.set_gauge("sentinel_trace_export_enabled", float(bool(endpoint.strip())))
        if endpoint.strip():
            from sentinel.infrastructure.trace_export import build_tracer
            self._provider, self._tracer, self._processor = build_tracer(
                endpoint.strip(), metrics,
                allow_http=allow_http, capacity=capacity, batch_size=batch_size)

    @property
    def enabled(self) -> bool:
        return self._tracer is not None

    @contextmanager
    def span(self, name: str, **attrs: Any) -> Iterator[None]:
        if not self.enabled:
            yield
            return
        from opentelemetry.trace import Status, StatusCode
        method = attrs.get("method", "OTHER")
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            method = "OTHER"
        safe_name = name if name in {"http.request", "worker.run"} else "sentinel.operation"
        with self._tracer.start_as_current_span(safe_name, attributes={"http.request.method": method},
                record_exception=False, set_status_on_exception=False) as span:
            try:
                yield
            except BaseException:
                span.set_status(Status(StatusCode.ERROR))
                raise
            else:
                span.set_status(Status(StatusCode.OK))

    def force_flush(self, timeout_millis=3000):
        return self._processor.force_flush(timeout_millis) if self.enabled else True

    def close(self):
        if self._provider is not None:
            self._provider.shutdown()

    @property
    def exported_events(self) -> tuple:
        # Compatibility accessor: no process-local span history is retained.
        return ()
