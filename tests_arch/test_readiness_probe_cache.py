"""Readiness is exempt from throttling, and that is only safe with the cache.

THE FINDING THIS CLOSES
-----------------------
`/health/live` was exempt from rate limiting and `/health/ready` was not. The
reason liveness is exempt is written in `throttle.py`: a kubelet polling every
second must not exhaust a bucket and get the pod killed.

The same argument applies to readiness, and the consequence is worse. A
throttled readiness probe marks the pod NotReady, which sheds it from the
Service, which moves its traffic onto the remaining pods -- under exactly the
load that caused the throttling. That is a cascade.

It was not hypothetical. The observability soak measured it: at ~180 rps from a
single address, 27 of 270 readiness probes were answered 429. In a cluster the
kubelet usually probes from the node address while clients arrive from
elsewhere, so the buckets usually differ. "Usually" is not a control.

WHY THE CACHE IS A PRECONDITION AND NOT AN OPTIMISATION
---------------------------------------------------------
`/health/ready` runs a database query. Exempting an unauthenticated route from
rate limiting while it queries the database per request turns it into a load
amplifier anyone can aim at the database -- trading a cascading-failure risk for
a denial-of-service one.

The cache is what makes the exemption defensible, so the two must move together.
`test_the_exemption_and_the_cache_are_documented_as_one_decision` fails if the
cache is removed while the exemption stands.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sentinel.composition.container import build_container
from sentinel.composition.settings import Settings
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.interface.http import create_app
from sentinel.interface.throttle import ThrottlePolicy

KEY = "k" * 40


def _settings_for(engine_config) -> Settings:
    env = {
        "SENTINEL_ENV": "development",
        "SENTINEL_API_KEYS": f"acme:{KEY}:admin",
    }
    if engine_config.dialect.name == "POSTGRES":
        env["SENTINEL_DATABASE_URL"] = engine_config.dsn
        env["SENTINEL_DB_POOL_MIN"] = "1"
        env["SENTINEL_DB_POOL_MAX"] = "4"
    else:
        env["SENTINEL_DB_PATH"] = engine_config.dsn
    return Settings.from_environment(env)


@pytest.fixture
def app(engine_config):
    """Both engines, because the thing being cached is a DATABASE probe.

    The pool, the connection lifecycle and the cost of a round trip all differ
    between SQLite and PostgreSQL, and the probe is the only place readiness
    touches any of them. A cache proven to work against an in-process file
    would say nothing about the engine production runs.
    """
    settings = _settings_for(engine_config)
    pool = build_engine(settings.engine)
    migrate(pool)
    pool.close()

    container = build_container(settings)
    try:
        yield TestClient(create_app(container)), container
    finally:
        container.close()


# ── the probe is memoised ────────────────────────────────────────────────────


def test_repeated_readiness_probes_do_not_requery_the_database(app, monkeypatch):
    """THE property the throttle exemption depends on.

    Without it, an unauthenticated unmetered route runs a query per request.
    """
    http, container = app

    calls = {"n": 0}
    pool_type = type(container.pool)
    real_acquire = pool_type.acquire

    def counting_acquire(self, *args, **kwargs):
        calls["n"] += 1
        return real_acquire(self, *args, **kwargs)

    # The CLASS, not the instance: `ConnectionPool` uses __slots__, so the
    # instance attribute is read-only and setattr raises.
    monkeypatch.setattr(pool_type, "acquire", counting_acquire)

    for _ in range(25):
        assert http.get("/health/ready").status_code == 200

    assert calls["n"] <= 2, (
        f"25 readiness probes issued {calls['n']} database acquisitions. The "
        "cache is not in effect, and the throttle exemption on this route is "
        "therefore an unauthenticated load amplifier."
    )


def test_readiness_still_answers_correctly_while_cached(app):
    """A cache that returned the wrong answer would be worse than no cache."""
    http, _container = app
    for _ in range(5):
        response = http.get("/health/ready")
        assert response.status_code == 200
        assert response.json()["ready"] is True


def test_the_cache_expires(app, monkeypatch):
    """A pod whose database has gone must stop advertising itself.

    The window is `readiness_cache_seconds`; this proves it is a window and not
    a permanent memo.
    """
    import sentinel.interface.health_routes as health

    http, container = app

    # The clock is controlled BEFORE the first probe. An earlier version primed
    # the cache with the real monotonic clock -- some hundreds of thousands of
    # seconds since boot -- and then set the fake clock to 0. The stored
    # deadline was still far in the "future", so nothing ever expired and the
    # test passed a stale answer off as a fresh one.
    clock = {"now": 1000.0}
    monkeypatch.setattr(health.time, "monotonic", lambda: clock["now"])

    assert http.get("/health/ready").status_code == 200

    def broken(_self, *_args, **_kwargs):
        raise RuntimeError("database is gone")

    monkeypatch.setattr(type(container.pool), "acquire", broken)

    # Still inside the window: the cached answer stands, which is the whole
    # point of the cache and is checked here so expiry is not confused with
    # "the cache never worked".
    assert http.get("/health/ready").status_code == 200

    clock["now"] = 1000.0 + 60.0
    assert http.get("/health/ready").status_code == 503


def test_a_failed_probe_never_leaks_the_exception_text(app, monkeypatch):
    """The DSN, the internal hostname and the driver version all live in that
    string, and this endpoint is unauthenticated.
    """
    http, container = app

    def broken(_self, *_args, **_kwargs):
        raise RuntimeError("could not connect to host=db.internal user=sentinel")

    monkeypatch.setattr(type(container.pool), "acquire", broken)
    response = http.get("/health/ready")

    assert response.status_code == 503
    body = response.text
    assert "db.internal" not in body
    assert "could not connect" not in body


# ── the exemption ────────────────────────────────────────────────────────────


def test_both_health_probes_are_exempt_from_rate_limiting():
    exempt = ThrottlePolicy().exempt_paths
    assert "/health/live" in exempt
    assert "/health/ready" in exempt


def test_no_other_route_is_exempt():
    """The exemption list is the one place an endpoint can escape the limiter.

    Anything beyond the two probes needs a reason somebody wrote down, so a
    silent third entry fails here.
    """
    assert set(ThrottlePolicy().exempt_paths) == {"/health/live", "/health/ready"}


def test_the_exemption_and_the_cache_are_documented_as_one_decision():
    """Removing the cache must not leave the exemption standing.

    They are separated by two modules, so nothing but a written link stops
    someone deleting the cache as a needless optimisation and leaving an
    unauthenticated unmetered database probe behind.
    """
    import inspect

    from sentinel.interface import health_routes, throttle

    throttle_source = inspect.getsource(throttle)
    assert "readiness_cache_seconds" in throttle_source, (
        "throttle.py exempts /health/ready without naming the cache that makes "
        "it safe"
    )

    health_source = inspect.getsource(health_routes)
    assert "readiness_cache_seconds" in health_source
    assert "throttle" in health_source, (
        "health_routes.py memoises the probe without saying that a throttle "
        "exemption depends on it"
    )
