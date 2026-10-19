"""The console may publish ONE key, and only a read-only one.

A link to the console is shared with people who hold no credential. The
published key is served unauthenticated, so the load-bearing tests are the
refusals: an analyst or admin key -- which could approve agent actions or
change policy -- must stop the service from starting, and one visitor must not
be able to exhaust the shared key for everyone else.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sentinel.composition.container import build_container
from sentinel.composition.settings import ConfigurationError, Settings
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.interface.http import create_app

VIEWER = "demo-viewer-key-that-is-long-enough-000000"
ANALYST = "acme-analyst-key-that-is-long-enough-00000"


def _client(engine_config, **env):
    source = {"SENTINEL_API_KEYS": f"demo:{VIEWER}:viewer,acme:{ANALYST}:analyst", **env}
    if engine_config.dialect.name == "POSTGRES":
        source.update(SENTINEL_DATABASE_URL=engine_config.dsn, SENTINEL_DB_POOL_MIN="1", SENTINEL_DB_POOL_MAX="4")
    else:
        source["SENTINEL_DB_PATH"] = engine_config.dsn
    settings = Settings.from_environment(source)
    pool = build_engine(settings.engine)
    migrate(pool)
    pool.close()
    container = build_container(settings)
    return TestClient(create_app(container), raise_server_exceptions=False), container


def test_without_a_demo_token_nothing_is_published(engine_config):
    client, container = _client(engine_config)
    try:
        response = client.get("/console/demo.json")
        assert response.status_code == 200 and response.json() == {"enabled": False}
    finally:
        container.close()


def test_a_viewer_token_is_published_read_only_and_uncached(engine_config):
    client, container = _client(engine_config, SENTINEL_CONSOLE_DEMO_TOKEN=VIEWER)
    try:
        response = client.get("/console/demo.json")
        body = response.json()
        assert body["enabled"] is True and body["token"] == VIEWER
        assert body["tenant"] == "demo" and body["role"] == "viewer" and body["poll_seconds"] >= 15
        assert response.headers["cache-control"] == "no-store"
        # the published key can read and cannot decide
        headers = {"Authorization": f"Bearer {VIEWER}"}
        assert client.get("/v1/dashboard", headers=headers).status_code == 200
        assert client.post("/v1/authorizations/az-x/decide", headers=headers,
                           json={"decision": "approve", "reason": "should never work"}).status_code == 403
    finally:
        container.close()


@pytest.mark.parametrize("token, reason", [(ANALYST, "role 'analyst'"), ("not-a-configured-key-000000000000000", "authenticates nothing")])
def test_a_publishable_token_that_is_not_a_viewer_key_refuses_to_start(engine_config, token, reason):
    with pytest.raises(ConfigurationError, match=reason):
        _client(engine_config, SENTINEL_CONSOLE_DEMO_TOKEN=token)


def test_each_visitor_address_gets_its_own_bucket_for_the_shared_key(engine_config):
    client, container = _client(engine_config, SENTINEL_CONSOLE_DEMO_TOKEN=VIEWER, SENTINEL_CREDENTIAL_LIMIT="3",
                                SENTINEL_TRUSTED_PROXY_HOPS="1")
    try:
        def call(address):
            return client.get("/v1/dashboard", headers={"Authorization": f"Bearer {VIEWER}", "X-Forwarded-For": address}).status_code

        first = [call("198.51.100.7") for _ in range(5)]
        assert 429 in first, "the per-credential limit never applied"
        assert call("203.0.113.9") == 200, "one visitor exhausted the shared demo key for everyone"
    finally:
        container.close()


def test_an_ordinary_key_still_has_one_bucket_across_addresses(engine_config):
    client, container = _client(engine_config, SENTINEL_CONSOLE_DEMO_TOKEN=VIEWER, SENTINEL_CREDENTIAL_LIMIT="3",
                                SENTINEL_TRUSTED_PROXY_HOPS="1")
    try:
        def call(address):
            return client.get("/v1/dashboard", headers={"Authorization": f"Bearer {ANALYST}", "X-Forwarded-For": address}).status_code

        codes = [call(f"198.51.100.{i}") for i in range(6)]
        assert 429 in codes, "rotating addresses escaped the limit on a private key"
    finally:
        container.close()
