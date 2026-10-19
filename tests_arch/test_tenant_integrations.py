"""Where a tenant's data may be sent — and the fallback that must not exist.

THE DEFECT THIS ADDRESSES
---------------------------
`SENTINEL_SIEM_WEBHOOK_URL` and `SENTINEL_REMEDIATION_ENDPOINTS` are process-wide
`Settings`. One deployment, one webhook, every tenant.

Correct for a single-tenant install. In multi-tenant SaaS it means tenant A's
incidents — agent names, resource paths, prompt fragments, the shape of their
estate — go to whatever endpoint the operator configured, which belongs to
somebody else. **No RLS policy catches this**, because the data leaves through a
correctly-authorised code path.

THE TEST THAT MATTERS MOST
----------------------------
`test_a_tenant_with_nothing_configured_gets_nothing`. The convenient design is
to fall back to a global default so things "just work", and the convenience is
exactly the bug: the tenant most likely to have no configuration is a NEW one,
and a new tenant silently shipping its first incidents to an existing customer's
SIEM is the worst possible first day.

An export that does not happen is a gap somebody notices. An export to the wrong
tenant is one nobody does.
"""

from __future__ import annotations

import pytest

from sentinel.domain.tenant_integrations import (
    IntegrationKind,
    TenantIntegration,
    TenantIntegrationRegistry,
)


def _integration(tenant="acme", kind=IntegrationKind.SIEM, **overrides):
    base = {
        "tenant_id": tenant,
        "kind": kind,
        "endpoint": f"https://{tenant}.siem.example/ingest",
        "credential_ref": "secrets/acme-siem",
    }
    base.update(overrides)
    return TenantIntegration(**base)


# ── the rule: no fallback, ever ──────────────────────────────────────────────


def test_a_tenant_with_nothing_configured_gets_nothing():
    """THE test. No deployment default, no other tenant's endpoint, nothing."""
    registry = TenantIntegrationRegistry(
        [_integration(tenant="acme")],
        deployment_defaults={IntegrationKind.SIEM: "https://shared.example/ingest"},
    )
    resolution = registry.resolve("newcomer", IntegrationKind.SIEM)

    assert resolution.deliverable is False
    assert resolution.integration is None
    assert "NOT_CONFIGURED" in resolution.reason


def test_one_tenants_endpoint_is_never_reachable_by_another():
    """The cross-tenant disclosure no RLS policy can catch."""
    registry = TenantIntegrationRegistry([_integration(tenant="acme")])
    resolution = registry.resolve("globex", IntegrationKind.SIEM)
    assert resolution.integration is None


def test_a_deployment_default_is_not_reached_by_accident():
    """A default exists for single-tenant installs and is reachable only by a
    tenant that opted IN — an explicit, recorded act.
    """
    registry = TenantIntegrationRegistry(
        deployment_defaults={IntegrationKind.SIEM: "https://shared.example/ingest"}
    )
    assert registry.resolve("acme", IntegrationKind.SIEM).deliverable is False

    registry.opt_in_to_default("acme", IntegrationKind.SIEM)
    resolved = registry.resolve("acme", IntegrationKind.SIEM)
    assert resolved.deliverable is True
    assert resolved.integration.uses_deployment_default is True
    assert "opted in to" in resolved.reason


def test_opting_in_to_a_default_that_does_not_exist_is_refused():
    registry = TenantIntegrationRegistry()
    with pytest.raises(ValueError, match="does not exist"):
        registry.opt_in_to_default("acme", IntegrationKind.SIEM)


def test_a_shared_destination_is_a_row_an_audit_can_see():
    """Rather than an absence an audit has to infer. "Which tenants share the
    deployment webhook" should be a query, not an archaeology exercise.
    """
    registry = TenantIntegrationRegistry(
        deployment_defaults={IntegrationKind.SIEM: "https://shared.example/x"}
    )
    registry.opt_in_to_default("acme", IntegrationKind.SIEM)
    assert registry.for_tenant("acme")[0].uses_deployment_default is True


def test_a_disabled_integration_delivers_nothing_and_says_why():
    """Disabled is a decision, and it reads differently from unconfigured. An
    operator debugging a missing export needs to know which one they have.
    """
    registry = TenantIntegrationRegistry([_integration(enabled=False)])
    resolution = registry.resolve("acme", IntegrationKind.SIEM)
    assert resolution.deliverable is False
    assert "disabled" in resolution.reason
    assert "NOT_CONFIGURED" not in resolution.reason


def test_kinds_are_resolved_independently():
    """A tenant with a SIEM and no SOAR must not get its SIEM endpoint for SOAR
    traffic.
    """
    registry = TenantIntegrationRegistry([_integration(kind=IntegrationKind.SIEM)])
    assert registry.resolve("acme", IntegrationKind.SIEM).deliverable is True
    assert registry.resolve("acme", IntegrationKind.SOAR).deliverable is False


# ── credentials are pointers, never secrets ──────────────────────────────────


def test_a_credential_reference_that_looks_like_a_secret_is_refused():
    """The failure mode is somebody pasting the token into the field named
    `credential_ref`, and nothing noticing until it appears in a log.
    """
    for pasted in (
        "sk-abc123def456ghi789",
        "ghp_aaaaaaaaaaaaaaaaaaaa",
        "xoxb-1234-5678-abcdefg",
        "AKIAIOSFODNN7EXAMPLE",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    ):
        with pytest.raises(ValueError, match="looks like a SECRET"):
            _integration(credential_ref=pasted)


def test_an_ordinary_secret_store_key_is_accepted():
    assert _integration(credential_ref="secrets/prod/siem-token").credential_ref


def test_a_malformed_reference_is_refused():
    with pytest.raises(ValueError, match="not a valid secret-store key"):
        _integration(credential_ref="has spaces and $ymbols")


def test_the_model_holds_no_secret_to_leak():
    """`as_dict` cannot carry a secret because none is stored. A model that held
    one would put it one `repr()` away from every log line and evidence record.
    """
    import dataclasses

    fields = {f.name for f in dataclasses.fields(TenantIntegration)}
    for secret_shaped in ("token", "secret", "password", "key", "credential"):
        assert secret_shaped not in fields, (
            f"TenantIntegration has a field called {secret_shaped!r}; "
            "credentials are referenced, never held"
        )
    assert "credential_ref" in fields


# ── construction refuses the shapes that configure nothing ───────────────────


def test_an_integration_with_no_tenant_belongs_to_everybody():
    with pytest.raises(ValueError, match="belongs to everybody"):
        _integration(tenant="  ")


def test_an_integration_with_no_endpoint_is_refused():
    """A destination that configures nothing should be absent, not present and
    empty — the same distinction `build_connectors` draws.
    """
    with pytest.raises(ValueError, match="configures nothing"):
        _integration(endpoint="")


# ── resolution is a named rule, not a lookup ─────────────────────────────────


def test_every_resolution_explains_itself():
    """An operator whose export did not happen needs to know whether the tenant
    is unconfigured, disabled, or delivering somewhere they did not expect.
    """
    registry = TenantIntegrationRegistry([_integration()])
    for tenant in ("acme", "unknown"):
        resolution = registry.resolve(tenant, IntegrationKind.SIEM)
        assert len(resolution.reason) > 30
        assert resolution.as_dict()["reason"]


def test_a_delivered_resolution_names_whose_destination_it_is():
    registry = TenantIntegrationRegistry([_integration()])
    reason = registry.resolve("acme", IntegrationKind.SIEM).reason
    assert "this tenant's own" in reason
    # The ENDPOINT too: an operator checking where an export went should not
    # need a second query to find out.
    assert "acme.siem.example" in reason


def test_the_registry_decides_nothing_beyond_where():
    """It resolves a destination. It does not deliver, retry, or hold a client —
    those belong to the outbox, which is what makes a third-party outage a queue
    depth rather than a blocked request.
    """
    import inspect

    from sentinel.domain import tenant_integrations

    source = inspect.getsource(tenant_integrations)
    for forbidden in ("requests", "urllib", "http.client", "psycopg", "socket"):
        assert forbidden not in source, (
            f"tenant_integrations reaches for {forbidden!r}; it decides WHERE, "
            "not whether the destination answered"
        )


# ── the wiring, end to end ───────────────────────────────────────────────────


def _settings(**overrides):
    from sentinel.composition.settings import Settings

    env = {
        "SENTINEL_ENV": "development",
        "SENTINEL_API_KEYS": f"acme:{'k' * 40}:admin",
        "SENTINEL_DB_PATH": "unused.db",
    }
    env.update(overrides)
    return Settings.from_environment(env)


class _RecordingSink:
    """A sink that remembers where it was built and what it was given."""

    def __init__(self, endpoint: str, log: list) -> None:
        self.endpoint = endpoint
        self._log = log

    def deliver(self, *, payload, idempotency_key):
        self._log.append((self.endpoint, payload.get("event")))
        return {"status": 200}


def _router(rows, log=None):
    from sentinel.domain.tenant_integrations import (
        IntegrationKind,
        TenantIntegration,
        TenantIntegrationRegistry,
    )
    from sentinel.infrastructure.siem_routing import TenantRoutedSiemDeliverer

    log = [] if log is None else log
    registry = TenantIntegrationRegistry(
        TenantIntegration(
            tenant_id=tenant, kind=IntegrationKind.SIEM, endpoint=endpoint
        )
        for tenant, endpoint in rows
    )
    return (
        TenantRoutedSiemDeliverer(
            registry=registry,
            factory=lambda endpoint, _ref: _RecordingSink(endpoint, log),
        ),
        registry,
        log,
    )


def test_per_tenant_sinks_produce_a_routed_deliverer():
    from sentinel.composition.siem_wiring import build_siem_deliverer
    from sentinel.infrastructure.siem_routing import TenantRoutedSiemDeliverer

    # The secret is supplied because the reference is. A sink that names a
    # `credential_ref` with no secret behind it now REFUSES to build rather
    # than exporting the tenant's events unauthenticated -- see
    # `test_tenant_siem_credentials.py`, which owns that behaviour. This test
    # is about the routing shape, so it configures a complete sink.
    deliverer = build_siem_deliverer(
        _settings(
            SENTINEL_TENANT_SIEM_SINKS="acme=https://acme.example/x|secrets/acme",
            SENTINEL_TENANT_SIEM_SECRET_SECRETS_ACME="tok-acme",
        )
    )
    assert isinstance(deliverer, TenantRoutedSiemDeliverer)


def test_routing_excludes_the_process_wide_sink_entirely():
    """Both together would send every tenant's events to the shared endpoint AS
    WELL AS their own — the disclosure this closes, still happening, now
    alongside the correct behaviour where it is harder to notice.
    """
    from sentinel.composition.siem_wiring import build_siem_deliverer
    from sentinel.infrastructure.siem_routing import TenantRoutedSiemDeliverer

    deliverer = build_siem_deliverer(
        _settings(
            SENTINEL_SIEM_WEBHOOK_URL="https://shared.example/everything",
            SENTINEL_TENANT_SIEM_SINKS="acme=https://acme.example/x",
        )
    )
    assert isinstance(deliverer, TenantRoutedSiemDeliverer)


def test_a_single_tenant_deployment_is_unchanged():
    """`siem_webhook_url` remains the single-tenant answer. This work must not
    make an existing deployment reconfigure to keep working.
    """
    from sentinel.composition.siem_wiring import build_siem_deliverer
    from sentinel.infrastructure.siem_routing import TenantRoutedSiemDeliverer

    deliverer = build_siem_deliverer(
        _settings(SENTINEL_SIEM_WEBHOOK_URL="https://one.example/ingest")
    )
    assert deliverer is not None
    assert not isinstance(deliverer, TenantRoutedSiemDeliverer)


def test_each_tenant_reaches_only_its_own_endpoint():
    router, _registry, log = _router(
        [("acme", "https://acme.example/x"), ("globex", "https://globex.example/x")]
    )
    router.deliver(payload={"event": "a"}, idempotency_key="1", tenant="acme")
    router.deliver(payload={"event": "b"}, idempotency_key="2", tenant="globex")

    assert log == [
        ("https://acme.example/x", "a"),
        ("https://globex.example/x", "b"),
    ]


def test_an_unconfigured_tenant_raises_rather_than_reporting_success():
    """A row of kind siem exists because something committed the intent to
    export it. Reporting success for an export that did not happen discards a
    security event — the one outcome the outbox exists to prevent.
    """
    from sentinel.infrastructure.siem_routing import SiemNotConfigured

    router, _registry, _log = _router([])
    with pytest.raises(SiemNotConfigured, match="NOT discarded"):
        router.deliver(payload={}, idempotency_key="1", tenant="newcomer")


def test_the_unconfigured_failure_is_retryable():
    """The fix is an operator configuring the tenant. A non-retryable failure
    would dead-letter it immediately, past the window in which somebody might
    notice and fix it while the event is still live.
    """
    from sentinel.infrastructure.siem_routing import SiemNotConfigured

    assert SiemNotConfigured.is_retryable is True


def test_a_record_with_no_tenant_is_refused():
    from sentinel.infrastructure.siem_routing import SiemNotConfigured

    router, _registry, _log = _router([("acme", "https://acme.example/x")])
    with pytest.raises(SiemNotConfigured, match="refusing to guess"):
        router.deliver(payload={}, idempotency_key="1", tenant="  ")


def test_the_tenant_comes_from_the_record_not_the_payload():
    """A payload field would be caller-influenced, and a caller that could name
    the tenant could name somebody else's sink — the defect reintroduced one
    layer down.
    """
    import inspect

    from sentinel.infrastructure.siem_routing import TenantRoutedSiemDeliverer

    parameters = inspect.signature(TenantRoutedSiemDeliverer.deliver).parameters
    assert "tenant" in parameters
    body = inspect.getsource(TenantRoutedSiemDeliverer.deliver)
    assert "payload.get" not in body
    assert "payload[" not in body


def test_a_receipt_records_where_the_event_actually_went():
    """"The export succeeded" is not auditable in a multi-tenant deployment;
    "it went to acme's endpoint" is, and it makes a mis-routing visible after
    the fact rather than only in the code.
    """
    router, _registry, _log = _router([("acme", "https://acme.example/x")])
    receipt = router.deliver(payload={}, idempotency_key="1", tenant="acme")
    assert receipt["destination"] == "https://acme.example/x"
    assert receipt["tenant_id"] == "acme"


def test_a_repointed_endpoint_is_not_served_from_the_cache():
    """The cache key includes the endpoint, so a re-pointed webhook does not
    keep delivering to the previous address.
    """
    from sentinel.domain.tenant_integrations import (
        IntegrationKind,
        TenantIntegration,
    )

    built: list[str] = []

    class _Sink:
        def deliver(self, *, payload, idempotency_key):
            return {}

    from sentinel.domain.tenant_integrations import TenantIntegrationRegistry
    from sentinel.infrastructure.siem_routing import TenantRoutedSiemDeliverer

    registry = TenantIntegrationRegistry(
        [
            TenantIntegration(
                tenant_id="acme",
                kind=IntegrationKind.SIEM,
                endpoint="https://old.example/x",
            )
        ]
    )

    def _factory(endpoint, _ref):
        built.append(endpoint)
        return _Sink()

    router = TenantRoutedSiemDeliverer(registry=registry, factory=_factory)
    router.deliver(payload={}, idempotency_key="1", tenant="acme")
    router.deliver(payload={}, idempotency_key="2", tenant="acme")
    assert built == ["https://old.example/x"], "the client was rebuilt per record"

    registry._by_tenant[("acme", IntegrationKind.SIEM)] = TenantIntegration(
        tenant_id="acme",
        kind=IntegrationKind.SIEM,
        endpoint="https://new.example/x",
    )
    router.deliver(payload={}, idempotency_key="3", tenant="acme")
    assert built == ["https://old.example/x", "https://new.example/x"]


def test_the_outbox_passes_the_tenant_to_a_routed_deliverer():
    """The dispatcher inspects the signature: a process-wide deliverer takes no
    tenant and must keep working, a routed one needs it and must receive it.
    """
    import inspect

    from sentinel.application.commands import dispatch_outbox

    source = inspect.getsource(dispatch_outbox)
    assert "tenant=str(record.tenant_id)" in source
    assert "_accepted_parameters" in source
