"""Wire connected applications: the registry (sealed credentials) and the `app_call` effect."""

from __future__ import annotations

from sentinel.application.tool_proxy import RegisteredSideEffect
from sentinel.composition.evidence_wiring import evidence_cipher
from sentinel.composition.settings import Settings
from sentinel.infrastructure.app_call import app_call_adapter
from sentinel.infrastructure.sql.connected_apps import SqlConnectedApps
from sentinel.infrastructure.sql.engine import ConnectionPool

__all__ = ["build_connected_apps", "connected_app_effect"]


def build_connected_apps(settings: Settings, pool: ConnectionPool) -> SqlConnectedApps:
    """The registry seals credentials under the same data key as evidence bodies;
    with no key configured it still lists and deletes, and refuses to store a secret."""
    return SqlConnectedApps(pool, evidence_cipher(settings))


def connected_app_effect(registry: SqlConnectedApps) -> RegisteredSideEffect:
    return app_call_adapter(registry)
