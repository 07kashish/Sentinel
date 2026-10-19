"""A configured tenant is a swept tenant.

The maintenance loop iterates the `tenants` table, and nothing in the service
ever wrote to it: every test inserted its own row, so a real deployment ran
retention, reaping, reconciliation and evidence commitment for nobody. Found
by deploying to a cluster and watching a receipt never reach the log.
"""

from __future__ import annotations

import json
from dataclasses import replace

from sentinel.composition.container import build_container
from sentinel.composition.settings import Settings
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.interface.asgi import _tenants, ensure_configured_tenants
from tests_arch.test_agent_identity_providers import AUDIENCE, _Issuer


def _container(tmp_path, engine_config, **extra):
    issuer = _Issuer()
    env = {
        "SENTINEL_ENV": "development", "SENTINEL_DB_PATH": str(tmp_path / "t.db"),
        "SENTINEL_API_KEYS": "acme:" + "a" * 40 + ":ingest,globex:" + "g" * 40 + ":admin,acme:" + "b" * 40 + ":analyst",
        "SENTINEL_SOFT_PROMPT_DETECT": "false",
        "SENTINEL_AGENT_IDP_JSON": json.dumps([{"name": "idp", "kind": "generic", "issuer": issuer.issuer,
                                                "audience": AUDIENCE, "tenant": "initech", "jwks": issuer.jwks}]),
        **extra,
    }
    settings = replace(Settings.from_environment(env), engine=engine_config)
    pool = build_engine(settings.engine)
    migrate(pool)
    pool.close()
    return build_container(settings)


def test_tenants_named_by_keys_and_identity_providers_are_enrolled_once(tmp_path, engine_config):
    container = _container(tmp_path, engine_config)
    try:
        assert _tenants(container) == [], "the premise: a migrated database has no tenants"
        assert ensure_configured_tenants(container) == ["acme", "globex", "initech"]
        assert ensure_configured_tenants(container) == [], "a second replica starting must not fail or duplicate"
        assert [t.value for t in _tenants(container)] == ["acme", "globex", "initech"]
    finally:
        container.close()


def test_the_maintenance_loop_then_sweeps_them(tmp_path, engine_config):
    from sentinel.interface.worker import MaintenanceLoop

    container = _container(tmp_path, engine_config)
    try:
        ensure_configured_tenants(container)
        loop = MaintenanceLoop(container, tenants=lambda: _tenants(container), interval_seconds=30.0)
        totals = loop.run_once()
        assert "receipts_committed" in totals and "operations_reconciled" in totals
    finally:
        container.close()


def test_a_tenant_first_seen_in_a_verified_sign_in_is_enrolled_once(tmp_path, engine_config):
    from sentinel.interface.principals import _enrol_tenant_once

    container = _container(tmp_path, engine_config)
    try:
        _enrol_tenant_once(container, "umbrella")
        _enrol_tenant_once(container, "umbrella")
        assert [t.value for t in _tenants(container)] == ["umbrella"]
        assert container.enrolled_tenants == {"umbrella"}
    finally:
        container.close()


def test_enrolment_happens_only_after_the_token_verified():
    import inspect

    from sentinel.interface import principals

    source = inspect.getsource(principals.principal_from_jwt)
    assert source.index("container.oidc.verify(raw_token)") < source.index("_enrol_tenant_once("), (
        "a tenant row must never be created from an unverified token"
    )
