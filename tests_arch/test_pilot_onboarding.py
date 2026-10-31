"""Retained advisor security and historical schema-upgrade coverage."""
import pytest

from sentinel.composition.container import build_container
from sentinel.composition.settings import ConfigurationError, Settings
from sentinel.infrastructure.model_advisor import HttpModelAdvisor
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.migrate import CURRENT_VERSION, migrate

ADMIN = "pilot-admin-synthetic-key-00000000000000"


def test_upgrade_from_previous_schema(engine_config, monkeypatch):
    import importlib
    migration_module = importlib.import_module("sentinel.infrastructure.sql.migrate")
    pool = build_engine(engine_config)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(migration_module, "MIGRATIONS", tuple(
                row for row in migration_module.MIGRATIONS if row[0] <= 37
            ))
            assert migrate(pool) == 37
        assert migrate(pool) == CURRENT_VERSION
        assert migrate(pool) == CURRENT_VERSION
    finally:
        pool.close()


def test_advisor_configuration_is_complete_secret_safe_and_https():
    env = {"SENTINEL_API_KEYS": f"acme:{ADMIN}:admin", "SENTINEL_ADVISOR_ENDPOINT": "https://model.example/v1"}
    with pytest.raises(ConfigurationError):
        Settings.from_environment(env)
    env.update(SENTINEL_ADVISOR_MODEL="pilot-model", SENTINEL_ADVISOR_TOKEN="synthetic-provider-key")
    settings = Settings.from_environment(env)
    assert "synthetic-provider-key" not in repr(settings)
    for endpoint in ["http://model.example/v1", "https://user:secret@model.example", "https://model.example?key=secret"]:
        with pytest.raises(ConfigurationError):
            Settings.from_environment({**env, "SENTINEL_ADVISOR_ENDPOINT": endpoint})
    container = build_container(settings, verify_schema=False)
    try:
        assert isinstance(container.advisor, HttpModelAdvisor)
        assert container.advisor.model_receipt() == "pilot-model"
    finally:
        container.close()
