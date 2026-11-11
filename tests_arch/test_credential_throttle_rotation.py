"""A private credential keeps one throttle bucket across trusted client addresses."""
from fastapi.testclient import TestClient

from sentinel.composition.container import build_container
from sentinel.composition.settings import Settings
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.interface.http import create_app

ANALYST = "acme-analyst-key-that-is-long-enough-00000"


def _client(engine_config, **env):
    source = {"SENTINEL_API_KEYS": f"acme:{ANALYST}:analyst", **env}
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


def test_an_ordinary_key_still_has_one_bucket_across_addresses(engine_config):
    client, container = _client(engine_config, SENTINEL_CREDENTIAL_LIMIT="3",
                                SENTINEL_TRUSTED_PROXY_HOPS="1")
    try:
        def call(address):
            return client.get("/v1/dashboard", headers={"Authorization": f"Bearer {ANALYST}", "X-Forwarded-For": address}).status_code

        codes = [call(f"198.51.100.{i}") for i in range(6)]
        assert 429 in codes, "rotating addresses escaped the limit on a private key"
    finally:
        container.close()
