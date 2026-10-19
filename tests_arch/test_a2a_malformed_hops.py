"""A malformed signed hop is the caller's error, and the route must say so.

Found by the schema fuzzer in CI: `POST /v1/a2a/evaluate` with
`signedHops: [{"document": {}, ...}]` answered 500. The domain reads hop
documents lazily inside `verify_chain`, so the `KeyError` for a missing
`issuer` surfaced past the route's parse-time validation and became a server
error. A 500 for a malformed request is worse than wrong: it tells a fuzzer the
request reached code that did not expect it.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from sentinel.composition.container import build_container
from sentinel.composition.settings import Settings
from sentinel.infrastructure.sql.engine import Dialect, build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.interface.http import create_app

ADMIN = "a" * 40


def _client(engine_config):
    env = {
        "SENTINEL_ENV": "development",
        "SENTINEL_API_KEYS": f"acme:{ADMIN}:admin",
        "SENTINEL_SOFT_PROMPT_DETECT": "false",
    }
    if engine_config.dialect is Dialect.SQLITE:
        env["SENTINEL_DB_PATH"] = engine_config.dsn
    else:
        env["SENTINEL_DATABASE_URL"] = engine_config.dsn
    settings = Settings.from_environment(env)
    pool = build_engine(settings.engine)
    migrate(pool)
    pool.close()
    container = build_container(settings)
    return TestClient(create_app(container), raise_server_exceptions=False), container


def test_a_signed_hop_with_an_empty_document_is_a_400_not_a_500(engine_config):
    client, container = _client(engine_config)
    try:
        response = client.post(
            "/v1/a2a/evaluate",
            headers={"Authorization": f"Bearer {ADMIN}"},
            json={
                "principal": "0",
                "signedHops": [
                    {"document": {}, "key_id": "0", "signature": "0", "signed_at": "0" * 25}
                ],
            },
        )
        assert response.status_code == 400, response.text
        assert "issuer" in response.json()["detail"]
    finally:
        container.close()


def test_a_signed_hop_with_a_wrongly_typed_field_is_a_400(engine_config):
    client, container = _client(engine_config)
    try:
        response = client.post(
            "/v1/a2a/evaluate",
            headers={"Authorization": f"Bearer {ADMIN}"},
            json={
                "principal": "0",
                "signedHops": [
                    {
                        "document": {
                            "issuer": "a",
                            "subject": "b",
                            "tenant_id": "acme",
                            "depth": "not-a-number",
                        },
                        "key_id": "a#1",
                        "signature": "0",
                        "signed_at": "2026-09-11T00:00:00+00:00",
                    }
                ],
            },
        )
        assert response.status_code == 400, response.text
        assert "malformed" in response.json()["detail"]
    finally:
        container.close()
