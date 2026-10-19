"""Edge rate limiting, driven through real requests.

WHY THE FAILED-AUTHENTICATION BUCKET IS THE POINT
-------------------------------------------------
The most valuable request to limit is the one that fails authentication, and a
FastAPI dependency cannot limit it -- by the time a dependency runs, `authenticate`
has already rejected the request. So this is middleware, and the first test below
is that a brute-force attempt is actually stopped rather than merely logged.

The second thing these tests pin is the header-trust rule. `X-Forwarded-For` is
client-supplied, so a limiter that reads it by default is bypassed by adding a
header. The default is to ignore it entirely, and when hops ARE configured the
value is taken from the RIGHT -- because a proxy appends, and everything left of
what our own proxies added is attacker-controlled.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sentinel.composition.container import build_container
from sentinel.composition.settings import ConfigurationError, Settings
from sentinel.infrastructure.persistence.cache import (
    InProcessCache,
    RateLimitDecision,
    TokenBucketLimiter,
)
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.interface.http import create_app
from sentinel.interface.throttle import ThrottlePolicy, _client_address

VIEWER_KEY = "v" * 40


def _build(tmp_path, **env_overrides):
    env = {
        "SENTINEL_API_KEYS": f"acme:{VIEWER_KEY}:viewer",
        "SENTINEL_DB_PATH": str(tmp_path / "throttle.db"),
    }
    env.update(env_overrides)
    settings = Settings.from_environment(env)
    pool = build_engine(settings.engine)
    migrate(pool)
    pool.close()
    return settings


@pytest.fixture
def client(tmp_path):
    settings = _build(
        tmp_path,
        SENTINEL_AUTH_FAILURE_LIMIT="3",
        SENTINEL_CREDENTIAL_LIMIT="5",
        SENTINEL_ADDRESS_LIMIT="4",
    )
    container = build_container(settings)
    try:
        yield TestClient(create_app(container), raise_server_exceptions=False), container
    finally:
        container.close()


# ── The brute-force bucket ───────────────────────────────────────────────────


def test_repeated_authentication_failures_are_eventually_refused(client):
    """Without this, guessing is unlimited as well as invisible."""
    http, _container = client
    bad = {"Authorization": "Bearer " + "z" * 40}
    statuses = [http.get("/v1/incidents", headers=bad).status_code for _ in range(8)]

    assert statuses[0] == 401, "the first attempt should be a normal rejection"
    assert 429 in statuses, f"brute force was never throttled: {statuses}"
    # Once throttled it stays throttled for the window.
    assert statuses[-1] == 429


def test_the_bucket_is_keyed_on_the_guess_not_the_caller(client):
    """An attacker rotating source addresses must not get a fresh allowance.

    Keying on the presented credential means the bucket follows the guess. A
    different guess gets its own bucket -- which is why the per-address backstop
    exists and is tested separately.
    """
    http, _container = client
    same = {"Authorization": "Bearer " + "z" * 40}
    for _ in range(6):
        http.get("/v1/incidents", headers=same)
    # Same credential, "different" caller: still refused.
    refused = http.get(
        "/v1/incidents", headers={**same, "X-Forwarded-For": "203.0.113.9"}
    )
    assert refused.status_code == 429


def test_a_throttled_response_tells_the_caller_when_to_retry(client):
    http, _container = client
    bad = {"Authorization": "Bearer " + "q" * 40}
    for _ in range(8):
        response = http.get("/v1/incidents", headers=bad)
        if response.status_code == 429:
            break
    assert response.status_code == 429
    assert int(response.headers["Retry-After"]) >= 1
    assert response.json()["reason"] == "auth_failure_rate_limited"


def test_a_throttled_response_still_carries_the_security_headers(client):
    """A 429 is a response like any other. Middleware ordering decides this, and
    ordering is easy to get backwards, so it is asserted rather than assumed."""
    http, _container = client
    bad = {"Authorization": "Bearer " + "w" * 40}
    for _ in range(8):
        response = http.get("/v1/incidents", headers=bad)
        if response.status_code == 429:
            break
    assert response.status_code == 429
    for header in ("content-security-policy", "x-content-type-options", "cache-control"):
        assert response.headers.get(header), f"{header} missing on a 429"


def test_throttling_is_recorded_in_the_audit_trail(client):
    """"Were we being brute-forced on the 14th" is asked after the fact."""
    http, container = client
    bad = {"Authorization": "Bearer " + "e" * 40}
    for _ in range(8):
        http.get("/v1/incidents", headers=bad)

    with container.pool.acquire() as conn:
        conn.begin()
        conn.set_tenant("unauthenticated:none")
        rows = conn.execute(
            "SELECT resource_id FROM security_audit "
            f"WHERE tenant_id={conn.p} AND resource_type='rate_limit'",
            ("unauthenticated:none",),
        )
        conn.commit()
    assert any(r["resource_id"] == "auth_failure_rate_limited" for r in rows)


# ── The valid-credential bucket ──────────────────────────────────────────────


def test_a_valid_credential_is_bounded_too(client):
    """Bounds the damage one compromised credential can do."""
    http, _container = client
    auth = {"Authorization": f"Bearer {VIEWER_KEY}"}
    statuses = [http.get("/v1/incidents", headers=auth).status_code for _ in range(9)]
    assert statuses[0] == 200
    assert 429 in statuses, f"a valid credential was never bounded: {statuses}"


def test_the_credential_bucket_is_separate_from_the_failure_bucket(client):
    """Exhausting one must not lock out the other, or a single attacker with a
    bad key denies service to every legitimate caller."""
    http, _container = client
    for _ in range(8):
        http.get("/v1/incidents", headers={"Authorization": "Bearer " + "z" * 40})
    good = http.get("/v1/incidents", headers={"Authorization": f"Bearer {VIEWER_KEY}"})
    assert good.status_code == 200, (
        "a brute-force attempt on a bad key denied service to a valid one"
    )


# ── The address backstop ─────────────────────────────────────────────────────


def test_unauthenticated_traffic_with_no_credential_is_limited_by_address(client):
    http, _container = client
    statuses = [http.get("/v1/incidents").status_code for _ in range(8)]
    assert 429 in statuses, f"credential-less traffic was never limited: {statuses}"


def test_liveness_is_never_throttled(client):
    """A kubelet polling every second must not exhaust a bucket and get the pod
    killed. It is the one exempt path, and it discloses nothing."""
    http, _container = client
    for _ in range(40):
        assert http.get("/health/live").status_code == 200


# ── X-Forwarded-For trust ────────────────────────────────────────────────────


class _Request:
    def __init__(self, headers: dict[str, str], host: str = "10.1.1.1") -> None:
        self.headers = headers
        self.client = type("C", (), {"host": host})()


def test_the_forwarded_header_is_ignored_by_default():
    """Trusting a client-supplied header for a security decision means the
    limiter is bypassed by adding a header."""
    request = _Request({"x-forwarded-for": "1.2.3.4"})
    assert _client_address(request, 0) == "10.1.1.1"


def test_a_configured_hop_is_taken_from_the_right():
    """A proxy APPENDS, so the rightmost entries are the ones our own
    infrastructure added. Counting from the left takes the attacker's value --
    the classic bypass."""
    request = _Request({"x-forwarded-for": "1.2.3.4, 203.0.113.7, 10.0.0.9"})
    # One trusted hop: the entry our proxy recorded is the last-but-one.
    assert _client_address(request, 1) == "10.0.0.9"
    assert _client_address(request, 2) == "203.0.113.7"


def test_a_forged_chain_shorter_than_configured_falls_back_to_the_socket():
    """An attacker sending a single spoofed entry must not have it selected."""
    request = _Request({"x-forwarded-for": "1.2.3.4"})
    assert _client_address(request, 3) == "10.1.1.1"


def test_an_absent_header_with_hops_configured_uses_the_socket():
    assert _client_address(_Request({}), 2) == "10.1.1.1"


# ── Failure policy ───────────────────────────────────────────────────────────


class _BrokenCache:
    def get(self, _key):
        from sentinel.domain.errors import TransientFailure

        raise TransientFailure("cache is gone")

    def set(self, *_a, **_kw):
        from sentinel.domain.errors import TransientFailure

        raise TransientFailure("cache is gone")


def test_a_degraded_decision_is_distinguishable_from_a_budgeted_one():
    """Collapsing "allowed because there was budget" and "allowed because the
    limiter was down" hides a bypass."""
    limiter = TokenBucketLimiter(
        cache=_BrokenCache(), limits={"credential": 10}, fail_open=True
    )
    decision = limiter.check(tenant_id="acme", klass="credential")
    assert decision.allowed is True
    assert decision.degraded is True


def test_fail_closed_denies_when_the_limiter_is_unreachable():
    limiter = TokenBucketLimiter(
        cache=_BrokenCache(), limits={"credential": 10}, fail_open=False
    )
    decision = limiter.check(tenant_id="acme", klass="credential")
    assert decision.allowed is False
    assert decision.degraded is True


def test_an_unconfigured_route_class_raises_rather_than_allowing():
    """An unlimited class is a decision and must be stated as one."""
    from sentinel.domain.errors import TransientFailure

    limiter = TokenBucketLimiter(cache=InProcessCache(), limits={}, fail_open=True)
    with pytest.raises(TransientFailure):
        limiter.check(tenant_id="acme", klass="credential")


def test_production_refuses_to_start_without_an_explicit_failure_policy():
    """Both answers are defensible and the wrong one is a silent bypass or a
    silent outage, so this refuses to guess."""
    with pytest.raises(ConfigurationError) as refused:
        Settings.from_environment(
            {
                "SENTINEL_ENV": "production",
                "SENTINEL_API_KEYS": f"acme:{'k' * 40}:admin",
                "SENTINEL_DATABASE_URL": "postgresql://u:p@db/sentinel",
                "SENTINEL_CORS_ORIGINS": "https://console.example",
            }
        )
    assert "SENTINEL_RATE_LIMIT_FAIL_OPEN" in str(refused.value)


def test_production_refuses_multi_shard_without_a_shared_limiter():
    """A per-process limiter across N replicas permits N times the configured
    rate, which looks correct and is not."""
    with pytest.raises(ConfigurationError) as refused:
        Settings.from_environment(
            {
                "SENTINEL_ENV": "production",
                "SENTINEL_API_KEYS": f"acme:{'k' * 40}:admin",
                "SENTINEL_DATABASE_URL": "postgresql://u:p@db/sentinel",
                "SENTINEL_CORS_ORIGINS": "https://console.example",
                "SENTINEL_RATE_LIMIT_FAIL_OPEN": "false",
                "SENTINEL_REQUIRE_EXECUTION_BINDING": "false",
                # Production refuses readable evidence unless told; this test is about Redis.
                "SENTINEL_EVIDENCE_ENCRYPTION": "off",
                "SENTINEL_WORKER_SHARD_COUNT": "3",
            }
        )
    assert "per-process" in str(refused.value)


def test_a_single_shard_production_deployment_is_allowed_without_redis():
    """One replica genuinely does not need a shared bucket. Refusing it would
    push small deployments to disable limiting entirely."""
    settings = Settings.from_environment(
        {
            "SENTINEL_ENV": "production",
            "SENTINEL_API_KEYS": f"acme:{'k' * 40}:admin",
            "SENTINEL_DATABASE_URL": "postgresql://u:p@db/sentinel",
            "SENTINEL_CORS_ORIGINS": "https://console.example",
            "SENTINEL_RATE_LIMIT_FAIL_OPEN": "false",
                "SENTINEL_REQUIRE_EXECUTION_BINDING": "false",
                "SENTINEL_EVIDENCE_ENCRYPTION": "off",  # this test is about the limiter, not evidence
        }
    )
    assert settings.rate_limit_fail_open is False
    assert settings.redis_url == ""


def test_a_malformed_redis_url_is_refused():
    with pytest.raises(ConfigurationError):
        Settings.from_environment(
            {
                "SENTINEL_API_KEYS": f"acme:{'k' * 40}:admin",
                "SENTINEL_REDIS_URL": "http://redis:6379",
            }
        )


def test_the_policy_states_every_class_it_limits():
    """A class the limiter does not know about raises, so the policy and the
    limiter must agree by construction."""
    policy = ThrottlePolicy()
    assert set(policy.classes()) == {"auth_failure", "credential", "address"}
    assert all(v > 0 for v in policy.classes().values())


def test_the_decision_type_reports_remaining_budget():
    decision = RateLimitDecision(allowed=True, remaining=4.0, retry_after_seconds=0.0)
    assert decision.degraded is False
