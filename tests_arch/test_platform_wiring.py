"""Configuration -> built adapter. The wiring, not the adapters.

`test_platform_adapters.py` proves the adapters refuse what they should.
`test_components_are_reachable.py` proves they are referenced. Neither proves
the reference does the right thing with the operator's configuration, and that
gap is where `test_phase4_wiring.py`'s `expires_at` bug lived: a column, a
hydration line, an enforced branch and passing tests, with the one site that
CREATES the value never setting it.

So these tests follow the value from an environment mapping to a registered
side effect, and assert the three properties an operator's mistake would break:

  * a platform nobody configured is ABSENT, not present-and-inert;
  * a platform configured HALFWAY is a start-up error, not a silent absence;
  * the SQL adapter can never be pointed at Sentinel's own store.
"""

from __future__ import annotations

import pytest

from sentinel.composition.platform_wiring import build_platform_effects
from sentinel.composition.settings import ConfigurationError, Settings
from sentinel.composition.settings_parsers import platform_adapters

STORE = "postgresql://sentinel:pw@db.internal:5432/sentinel"

_BASE = {
    "SENTINEL_ENV": "development",
    "SENTINEL_API_KEYS": "acme:supersecretkeyvalue012345:admin",
    "SENTINEL_DATABASE_URL": STORE,
}


def _settings(**overrides) -> Settings:
    return Settings.from_environment({**_BASE, **overrides})


# ── The parser ───────────────────────────────────────────────────────────────


def test_no_platform_settings_means_no_platforms():
    assert platform_adapters({}) == {}


def test_a_fully_configured_platform_is_collected():
    parsed = platform_adapters(
        {
            "SENTINEL_GITHUB_TOKEN": "ghp_x",
            "SENTINEL_GITHUB_CEILING": "moderate",
        }
    )
    assert parsed["github"]["token"] == "ghp_x"
    assert parsed["github"]["ceiling"] == "moderate"


def test_a_half_configured_platform_is_a_start_up_error():
    """Silently building nothing would leave an operator believing the adapter
    is live until the first refusal during an incident.
    """
    with pytest.raises(ConfigurationError, match="SENTINEL_AWS_REGION is required"):
        platform_adapters(
            {
                "SENTINEL_AWS_ACCESS_KEY_ID": "AKIA",
                "SENTINEL_AWS_SECRET_ACCESS_KEY": "secret",
            }
        )


def test_a_secret_can_come_from_a_file_mount(tmp_path):
    """A credential in the process environment is inherited by every child
    process. The `_FILE` variant is what a Kubernetes secret mount uses.
    """
    mount = tmp_path / "token"
    mount.write_text("ghp_from_mount\n", encoding="utf-8")
    parsed = platform_adapters({"SENTINEL_GITHUB_TOKEN_FILE": str(mount)})
    assert parsed["github"]["token"] == "ghp_from_mount"


def test_the_direct_variable_wins_over_the_file():
    parsed = platform_adapters(
        {
            "SENTINEL_GITHUB_TOKEN": "explicit",
            "SENTINEL_GITHUB_TOKEN_FILE": "/does/not/exist",
        }
    )
    # The unreadable file is never opened, so this also proves the direct value
    # short-circuits rather than being merged.
    assert parsed["github"]["token"] == "explicit"


def test_an_unreadable_secret_mount_is_an_error_not_an_empty_credential():
    with pytest.raises(ConfigurationError, match="could not be read"):
        platform_adapters({"SENTINEL_KUBERNETES_TOKEN_FILE": "/does/not/exist"})


# ── The wiring ───────────────────────────────────────────────────────────────


def test_an_unconfigured_deployment_registers_no_platform_effects():
    assert build_platform_effects(_settings()) == {}


def test_configured_platforms_become_registered_effects():
    effects = build_platform_effects(
        _settings(
            SENTINEL_GITHUB_TOKEN="ghp_x",
            SENTINEL_KUBERNETES_API_SERVER="https://cluster.internal:6443",
            SENTINEL_KUBERNETES_TOKEN="tok",
        )
    )
    assert sorted(effects) == ["github_api", "kubernetes_api"]


def test_the_sql_tool_may_not_be_pointed_at_sentinels_own_store():
    """THE wiring rule that no adapter can enforce for itself.

    `platforms/postgres.py` has never heard of `Settings.engine`, so only the
    composition root can notice that an operator reused the obvious DSN and
    handed agents a cursor over the incidents that describe them.
    """
    with pytest.raises(ConfigurationError, match="Sentinel's own store"):
        build_platform_effects(_settings(SENTINEL_POSTGRES_DSN=STORE))


def test_the_store_check_survives_a_driver_suffix_and_a_different_user():
    """A string comparison would be defeated by any of these, and each reaches
    exactly the same rows.
    """
    for disguise in (
        "postgresql+psycopg://sentinel:pw@db.internal:5432/sentinel",
        "postgresql://someone_else:other@db.internal:5432/sentinel",
        "postgresql://sentinel:pw@db.internal:5432/sentinel?sslmode=require",
        "postgresql://sentinel:pw@DB.INTERNAL/sentinel",
    ):
        with pytest.raises(ConfigurationError, match="Sentinel's own store"):
            build_platform_effects(_settings(SENTINEL_POSTGRES_DSN=disguise))


def test_a_different_database_on_the_same_server_is_allowed():
    """The check must not be so broad that a legitimate warehouse alongside the
    store is unreachable -- an over-broad refusal gets worked around.
    """
    effects = build_platform_effects(
        _settings(
            SENTINEL_POSTGRES_DSN="postgresql://reader@db.internal:5432/warehouse"
        )
    )
    assert "sql_query" in effects


def test_a_malformed_credential_fails_at_start_up_not_at_tool_call():
    """An operator is looking at start-up. Surfacing a bad region later as a
    tool refusal means discovering it during an incident.
    """
    with pytest.raises(ConfigurationError, match="not a valid region name"):
        build_platform_effects(
            _settings(
                SENTINEL_AWS_ACCESS_KEY_ID="AKIA",
                SENTINEL_AWS_SECRET_ACCESS_KEY="s",
                SENTINEL_AWS_REGION="attacker.example.com",
            )
        )


def test_an_unreadable_ceiling_fails_at_start_up():
    with pytest.raises(ConfigurationError, match="not one of"):
        build_platform_effects(
            _settings(SENTINEL_GITHUB_TOKEN="ghp_x", SENTINEL_GITHUB_CEILING="yolo")
        )


def test_the_ceiling_by_omission_is_read_only():
    """A deployment that supplies credentials and forgets the ceiling gets
    read-only, not everything the credential can do.
    """
    from sentinel.infrastructure.tool_adapters import ToolAdapterRefused

    effects = build_platform_effects(_settings(SENTINEL_GITHUB_TOKEN="ghp_x"))
    with pytest.raises(ToolAdapterRefused, match="above this adapter's 'low'"):
        effects["github_api"].runner(
            {"method": "DELETE", "path": "/repos/acme/widgets"}
        )


def test_the_kubernetes_adapter_gets_a_client_scoped_to_the_api_server():
    """Found by deploying: the default hardened client refuses a private API
    server and does not trust the cluster CA, so the tool could never work in
    a real cluster. The fix must stay as narrow as one host and one CA."""
    from sentinel.composition.platform_wiring import _kubernetes_client

    client = _kubernetes_client({"api_server": "https://kubernetes.default.svc", "token": "t"})
    policy = client._policy
    assert policy.allow_private_destinations is True
    assert policy.allowed_hosts == frozenset({"kubernetes.default.svc"})
    assert policy.allowed_schemes == frozenset({"https"})


def test_an_unreadable_kubernetes_ca_bundle_refuses_to_start(tmp_path):
    from sentinel.composition.platform_wiring import _kubernetes_client
    from sentinel.composition.settings import ConfigurationError

    with pytest.raises(ConfigurationError, match="CA_FILE"):
        _kubernetes_client({"api_server": "https://k8s.internal", "token": "t", "ca_file": str(tmp_path / "missing.crt")})

