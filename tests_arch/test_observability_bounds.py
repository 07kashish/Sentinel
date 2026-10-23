"""Bound attacker-controlled cardinality and verify usable histogram samples."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

from fastapi.testclient import TestClient

from sentinel.composition.container import build_container
from sentinel.composition.settings import Settings
from sentinel.infrastructure.observability import MetricsRegistry
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.interface.http import create_app


def test_registry_bounds_arbitrary_names_and_label_sets():
    metrics = MetricsRegistry(max_series=32)
    for i in range(10_000):
        metrics.inc("requests", labels={"path": str(i)})
        metrics.inc(f"arbitrary_{i}")
        metrics.inc("private", labels={"tenant": str(i), "agent": str(i)})
    assert len(metrics._values) == 32
    assert len(metrics._types) <= 32
    assert metrics._dropped > 20_000
    assert "tenant=" not in metrics.render_prometheus()


def test_prometheus_escaping_and_cumulative_histograms():
    metrics = MetricsRegistry()
    metrics.inc("hits", labels={"route": 'a"b\\c\nd'})
    for value in (0.001, 0.08, 0.5):
        metrics.observe("latency", value)
    text = metrics.render_prometheus()
    assert 'route="a\\"b\\\\c\\nd"' in text
    assert '# TYPE latency histogram' in text
    assert 'latency_bucket{le="0.1"} 2' in text
    assert 'latency_bucket{le="+Inf"} 3' in text
    assert 'latency_count 3' in text


def test_concurrent_record_and_scrape_preserves_counts():
    metrics = MetricsRegistry()
    def record(_):
        for _ in range(1000):
            metrics.inc("hits")
            metrics.observe("duration", 0.01)
            metrics.render_prometheus()
    with ThreadPoolExecutor(max_workers=4) as workers:
        list(workers.map(record, range(4)))
    text = metrics.render_prometheus()
    assert 'hits 4000.0' in text
    assert 'duration_count 4000' in text


def test_ten_thousand_unknown_http_paths_use_one_bucket(tmp_path, engine_config):
    settings = Settings.from_environment({"SENTINEL_ENV": "development",
        "SENTINEL_DB_PATH": str(tmp_path / "metrics.db"),
        "SENTINEL_API_KEYS": "acme:" + "a" * 40 + ":viewer",
        })
    settings = replace(settings, engine=engine_config)
    pool = build_engine(settings.engine)
    migrate(pool)
    pool.close()
    container = build_container(settings)
    try:
        app = create_app(container)
        with TestClient(app) as client:
            for i in range(10_000):
                client.get(f"/unmatched-sensitive-id-{i}")
        text = container.metrics.render_prometheus()
        assert 'unmatched-sensitive-id' not in text
        assert 'path="__unmatched__"' in text
        assert len(container.metrics._values) < 10
    finally:
        container.close()
