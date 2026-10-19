"""A declared SIEM credential must be used, or the process must not start.

THE DEFECT
----------
`credential_ref` was parsed from `SENTINEL_TENANT_SIEM_SINKS`, validated against
a shape, stored on `TenantIntegration`, carried through
`TenantRoutedSiemDeliverer`, handed to the deliverer factory -- and dropped on
the floor. The factory built every per-tenant webhook with `token=""`.

So an operator who configured

    SENTINEL_TENANT_SIEM_SINKS=acme=https://acme.example/ingest|secrets/acme-siem

got an unauthenticated export of that tenant's security events, while every
piece of configuration in front of them said otherwise. Nothing failed. Nothing
logged. The events arrived.

A configuration field that is accepted and ignored is worse than one that is
rejected. Rejection produces a deploy failure; silent acceptance produces
confident, wrong belief about who can read a tenant's incidents.

WHY REFUSAL AND NOT A WARNING
-----------------------------
A warning is a line in a log nobody reads during a deploy that otherwise
succeeded. The failure mode here is silent disclosure over an unauthenticated
channel, which is the class of thing that stays wrong until somebody
independently notices -- and there is no monitoring for "the token we are not
sending".

Refusing at WIRING time and not at delivery time is the second half. A missing
secret discovered on the first export is discovered by a dead-lettered record
in the middle of the night; discovered at startup it is a failed deploy, which
is the cheapest moment for a configuration to be wrong.
"""

from __future__ import annotations

import pytest

from sentinel.composition import settings_parsers as parsers
from sentinel.composition.settings import ConfigurationError, Settings
from sentinel.composition.siem_wiring import build_siem_deliverer

BASE = {
    "SENTINEL_ENV": "development",
    "SENTINEL_API_KEYS": "acme:" + "k" * 40 + ":admin",
}


def _settings(**extra) -> Settings:
    return Settings.from_environment({**BASE, **extra})


# ── the reference resolves ───────────────────────────────────────────────────


def test_a_credential_reference_maps_to_a_documented_variable_name():
    """`credential_ref` allows `.`, `/` and `-`; environment names do not.

    The mapping has to exist somewhere, and an operator guessing at it gets an
    unauthenticated sink. One function applies it on both sides.
    """
    assert (
        parsers.credential_env_name("secrets/acme-siem")
        == "SENTINEL_TENANT_SIEM_SECRET_SECRETS_ACME_SIEM"
    )


def test_the_resolved_token_reaches_the_deliverer():
    """The whole point. Not "a token exists" -- this token, on this sink."""
    settings = _settings(
        SENTINEL_TENANT_SIEM_SINKS="acme=https://acme.example/ingest|secrets/acme",
        SENTINEL_TENANT_SIEM_SECRET_SECRETS_ACME="tok-acme-123",
    )
    deliverer = build_siem_deliverer(settings)

    built = deliverer._factory("https://acme.example/ingest", "secrets/acme")
    assert built._token == "tok-acme-123"


def test_two_tenants_get_two_different_tokens():
    """A shared token would make the routing pointless: any tenant's sink
    operator could then present it to another tenant's endpoint.
    """
    settings = _settings(
        SENTINEL_TENANT_SIEM_SINKS=(
            "acme=https://acme.example/i|secrets/acme;"
            "globex=https://globex.example/i|secrets/globex"
        ),
        SENTINEL_TENANT_SIEM_SECRET_SECRETS_ACME="tok-acme",
        SENTINEL_TENANT_SIEM_SECRET_SECRETS_GLOBEX="tok-globex",
    )
    deliverer = build_siem_deliverer(settings)

    acme = deliverer._factory("https://acme.example/i", "secrets/acme")
    globex = deliverer._factory("https://globex.example/i", "secrets/globex")
    assert acme._token == "tok-acme"
    assert globex._token == "tok-globex"


# ── an unresolvable reference is a refusal ───────────────────────────────────


def test_a_reference_with_no_secret_refuses_to_start():
    """THE regression. This configuration used to produce a working,
    unauthenticated exporter.
    """
    settings = _settings(
        SENTINEL_TENANT_SIEM_SINKS="acme=https://acme.example/ingest|secrets/acme",
    )
    with pytest.raises(ConfigurationError) as raised:
        build_siem_deliverer(settings)

    message = str(raised.value)
    assert "secrets/acme" in message
    # The message must name the variable to set. "Missing credential" sends an
    # operator to read the parser.
    assert "SENTINEL_TENANT_SIEM_SECRET_SECRETS_ACME" in message


def test_an_empty_secret_is_treated_as_absent():
    """A variable set to whitespace is a mistake, not a token.

    Accepting it would authenticate with an empty bearer, which most receivers
    treat as anonymous -- the original defect with an extra step.
    """
    settings = _settings(
        SENTINEL_TENANT_SIEM_SINKS="acme=https://acme.example/ingest|secrets/acme",
        SENTINEL_TENANT_SIEM_SECRET_SECRETS_ACME="   ",
    )
    with pytest.raises(ConfigurationError):
        build_siem_deliverer(settings)


def test_one_unresolved_reference_among_several_still_refuses():
    """Partial configuration must not start.

    Starting with the resolvable ones would export the unconfigured tenant's
    events unauthenticated, which is the exact failure being closed -- now
    harder to see because most of the deployment is correct.
    """
    settings = _settings(
        SENTINEL_TENANT_SIEM_SINKS=(
            "acme=https://acme.example/i|secrets/acme;"
            "globex=https://globex.example/i|secrets/globex"
        ),
        SENTINEL_TENANT_SIEM_SECRET_SECRETS_ACME="tok-acme",
    )
    with pytest.raises(ConfigurationError) as raised:
        build_siem_deliverer(settings)
    assert "secrets/globex" in str(raised.value)
    assert "secrets/acme" not in str(raised.value)


# ── an unauthenticated sink stays possible, but only deliberately ────────────


def test_a_sink_with_no_reference_is_allowed_and_unauthenticated():
    """Somebody chose this. It is a decision, not a gap.

    The distinction is the reason refusal is safe to add: a deployment that
    genuinely wants an unauthenticated sink has a way to say so that reads as
    intent in the configuration file.
    """
    settings = _settings(
        SENTINEL_TENANT_SIEM_SINKS="acme=https://acme.example/ingest",
    )
    deliverer = build_siem_deliverer(settings)
    built = deliverer._factory("https://acme.example/ingest", "")
    assert built._token == ""


def test_no_tenant_sinks_at_all_is_unaffected():
    """The process-wide path must keep working; this change is additive."""
    assert build_siem_deliverer(_settings()) is None


# ── the secret does not leak into the sink table ─────────────────────────────


def test_the_credential_map_holds_only_references_that_were_declared():
    """An environment full of `SENTINEL_TENANT_SIEM_SECRET_*` variables must not
    become a map of every secret on the host.

    Resolution is driven by the sinks, so a stray variable is inert rather than
    loaded and carried around.
    """
    resolved = parsers.tenant_siem_credentials(
        {
            "SENTINEL_TENANT_SIEM_SINKS": "acme=https://a.example/i|secrets/acme",
            "SENTINEL_TENANT_SIEM_SECRET_SECRETS_ACME": "tok-acme",
            "SENTINEL_TENANT_SIEM_SECRET_SOMETHING_ELSE": "tok-unrelated",
        }
    )
    assert dict(resolved) == {"secrets/acme": "tok-acme"}


def test_the_token_is_not_in_the_integration_row_an_operator_can_read():
    """`TenantIntegration.as_dict` carries the REFERENCE, never the secret.

    The row is meant to be readable -- an operator has to be able to see where
    a tenant's events go. That is only safe while the thing it carries is a
    pointer.
    """
    from sentinel.domain.tenant_integrations import IntegrationKind, TenantIntegration

    row = TenantIntegration(
        tenant_id="acme",
        kind=IntegrationKind.SIEM,
        endpoint="https://acme.example/ingest",
        credential_ref="secrets/acme",
    ).as_dict()
    assert row["credential_ref"] == "secrets/acme"
    assert "tok-" not in repr(row)
