"""Turn SIEM settings into the one deliverer the outbox dispatcher calls.

WHY A SEPARATE MODULE
---------------------
`container.py` previously built `SiemWebhookDeliverer` inline, which was right
while there was one wire. There are now three shapes -- webhook, OTLP, syslog --
plus the fan-out that composes them, and the rule for which to build has its own
reason to change. The container calls one function.

THE ONE INVARIANT THIS FUNCTION CARRIES
-----------------------------------------
`PipelineSteps.siem_export` is derived from whether this returns None. That
coupling is why the function returns None rather than an empty fan-out for an
unconfigured deployment: `None` means no export intent is ever ENQUEUED, which
is a different thing from intents being enqueued and dropped. An empty deliverer
would satisfy the type and quietly produce the second behaviour -- outbox rows
piling up for a sink that does not exist.
"""

from __future__ import annotations

from typing import Any

from sentinel.composition import settings_parsers as _parsers
from sentinel.composition.settings import ConfigurationError, Settings
from sentinel.infrastructure.outbound import HardenedHttpClient
from sentinel.domain.tenant_integrations import (
    IntegrationKind,
    TenantIntegration,
    TenantIntegrationRegistry,
)
from sentinel.infrastructure.siem import SiemWebhookDeliverer
from sentinel.infrastructure.siem_routing import TenantRoutedSiemDeliverer
from sentinel.infrastructure.siem_transports import (
    FanOutSiemDeliverer,
    OtlpLogDeliverer,
    SyslogTarget,
    SyslogTlsDeliverer,
    UnsupportedSiemTransport,
)

__all__ = ["build_siem_deliverer"]


def build_siem_deliverer(
    settings: Settings, *, http_client: HardenedHttpClient | None = None
) -> Any | None:
    """Build the SIEM deliverer, or None when no sink is configured.

    One sink is used directly rather than being wrapped in a fan-out of one.
    The wrapper would add a receipt shape and a failure message that mention
    sinks nobody configured, and an operator reading a dead-lettered record
    should see the transport that failed, not a container around it.
    """
    client = http_client or HardenedHttpClient()

    # PER-TENANT ROUTING TAKES PRECEDENCE, and excludes the process-wide sink
    # entirely rather than layering on top of it.
    #
    # Both together would mean every tenant's events going to the shared
    # endpoint AS WELL AS their own -- which is the cross-tenant disclosure this
    # routing exists to close, still happening, now alongside the correct
    # behaviour where it is harder to notice.
    #
    # A tenant absent from `tenant_siem_sinks` therefore exports NOWHERE. That
    # is the rule `TenantIntegrationRegistry.resolve` documents, and this is the
    # wiring that makes it true.
    if settings.tenant_siem_sinks:
        registry = TenantIntegrationRegistry(
            TenantIntegration(
                tenant_id=tenant,
                kind=IntegrationKind.SIEM,
                endpoint=endpoint,
                credential_ref=credential,
            )
            for tenant, endpoint, credential in settings.tenant_siem_sinks
        )
        # EVERY DECLARED CREDENTIAL MUST RESOLVE, OR THE PROCESS DOES NOT START.
        #
        # `credential_ref` used to be parsed, carried through the registry,
        # handed to this factory -- and dropped. Every per-tenant sink went out
        # unauthenticated while an operator who had written
        # `acme=https://...|secrets/acme-siem` had every reason to believe
        # otherwise. A configuration field accepted and ignored is worse than
        # one rejected: it produces a confident, wrong belief about who can
        # read a tenant's security events.
        #
        # Refused at wiring time rather than at delivery time. A missing secret
        # discovered on the first export is discovered by a dead-lettered
        # record at 3am; discovered here it is a failed deploy, which is the
        # cheapest moment for it to be wrong.
        unresolved = sorted(
            {
                credential
                for _tenant, _endpoint, credential in settings.tenant_siem_sinks
                if credential and credential not in settings.tenant_siem_credentials
            }
        )
        if unresolved:
            raise ConfigurationError(
                "these SIEM credential references resolve to no secret: "
                f"{unresolved}. Set "
                + ", ".join(
                    _parsers.credential_env_name(ref) for ref in unresolved
                )
                + ". Refusing to start rather than exporting a tenant's "
                "security events over an unauthenticated connection the "
                "configuration says is authenticated. A sink that is genuinely "
                "meant to be unauthenticated carries no credential_ref at all, "
                "which is a decision somebody made rather than a gap nobody "
                "noticed."
            )

        credentials = settings.tenant_siem_credentials
        return TenantRoutedSiemDeliverer(
            registry=registry,
            factory=lambda endpoint, credential_ref: SiemWebhookDeliverer(
                client=client,
                url=endpoint,
                # Empty ONLY when the sink declared no reference. An unresolved
                # reference cannot reach here -- it was refused above.
                token=credentials.get(credential_ref, "") if credential_ref else "",
            ),
        )

    sinks: dict[str, Any] = {}

    if settings.siem_webhook_url:
        sinks["webhook"] = SiemWebhookDeliverer(
            client=client,
            url=settings.siem_webhook_url,
            token=settings.siem_webhook_token,
        )

    transports = settings.siem_transports

    if (otlp := transports.get("otlp")) is not None:
        sinks["otlp"] = OtlpLogDeliverer(
            client=client,
            url=otlp["url"],
            token=otlp.get("token", ""),
            service_name=otlp.get("service_name") or "sentinel",
        )

    if (syslog := transports.get("syslog")) is not None:
        try:
            port = int(syslog.get("port") or 6514)
        except ValueError as exc:
            raise ConfigurationError(
                "SENTINEL_SIEM_SYSLOG_PORT must be an integer, not "
                f"{syslog.get('port')!r}"
            ) from exc
        if not 1 <= port <= 65535:
            raise ConfigurationError(
                f"SENTINEL_SIEM_SYSLOG_PORT {port} is not a valid port"
            )
        sinks["syslog"] = SyslogTlsDeliverer(
            target=SyslogTarget(
                host=syslog["host"],
                port=port,
                app_name=syslog.get("app_name") or "sentinel",
            )
        )

    if not sinks:
        return None
    if len(sinks) == 1:
        return next(iter(sinks.values()))
    try:
        return FanOutSiemDeliverer(sinks=sinks)
    except UnsupportedSiemTransport as exc:  # pragma: no cover - guarded above
        raise ConfigurationError(str(exc)) from exc
