"""Deliver each tenant's events to that tenant's sink, or to nothing.

WHAT THIS CLOSES
----------------
`build_siem_deliverer` builds ONE deliverer from process-wide settings, and the
outbox dispatcher calls it for every record regardless of whose it is. So in a
multi-tenant deployment every tenant's incidents go to one operator-configured
endpoint -- a cross-tenant disclosure that no RLS policy catches, because the
data leaves through a correctly-authorised path after being read by the tenant
that owns it.

This router sits in front of that. It resolves the record's tenant through
`TenantIntegrationRegistry` and delivers only where that tenant said to.

A TENANT WITH NO SINK RAISES, IT DOES NOT SILENTLY SUCCEED
-------------------------------------------------------------
`SiemNotConfigured` is raised rather than returning a receipt. That is the same
decision `dispatch_outbox` already makes for a missing deliverer, and for the
same reason: a row of kind `siem` exists because something committed the intent
to export it. Reporting success for an export that did not happen discards a
security event, which is the one outcome the outbox exists to prevent.

Raising keeps the record on its retry budget and, on exhaustion, in the
dead-letter state where an operator can see it. A tenant that genuinely should
export nowhere is configured with `enabled=False`, which is a decision somebody
made rather than a gap nobody noticed -- and the two produce different messages.

PER-TENANT DELIVERERS ARE BUILT ONCE AND CACHED
------------------------------------------------
Building an HTTP client per record would open a connection per event. The cache
is keyed by tenant AND endpoint, so a tenant whose endpoint changes gets a new
client rather than continuing to use the old one -- the failure that would make
a re-pointed webhook keep delivering to the previous address.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

from sentinel.domain.errors import SentinelError
from sentinel.domain.tenant_integrations import (
    IntegrationKind,
    TenantIntegrationRegistry,
)

__all__ = ["SiemNotConfigured", "TenantRoutedSiemDeliverer"]


class SiemNotConfigured(SentinelError):
    """This tenant has no SIEM sink, so nothing was delivered.

    RETRYABLE. The record stays on its budget because the correct fix is an
    operator configuring the tenant, and a non-retryable failure would move it
    to the dead-letter queue immediately -- past the window in which somebody
    might notice the alert and fix the configuration while the event is still
    live.
    """

    is_retryable = True


class TenantRoutedSiemDeliverer:
    """Routes each record to its own tenant's sink.

    Takes a FACTORY rather than pre-built deliverers, because the set of tenants
    is not known at construction and a registry that had to be reloaded to add
    one would make onboarding a restart.
    """

    __slots__ = ("_registry", "_factory", "_cache")

    def __init__(
        self,
        *,
        registry: TenantIntegrationRegistry,
        factory: Callable[[str, str], Any],
    ) -> None:
        self._registry = registry
        self._factory = factory
        #: (tenant, endpoint) -> deliverer. The endpoint is in the key so a
        #: re-pointed webhook does not keep delivering to the previous address.
        self._cache: dict[tuple[str, str], Any] = {}

    def deliver(
        self, *, payload: Mapping[str, Any], idempotency_key: str, tenant: str
    ) -> dict[str, Any]:
        """Deliver one record to the sink its tenant configured.

        `tenant` is REQUIRED and comes from the outbox record, never from the
        payload. A payload field would be caller-influenced, and a caller that
        could name the tenant could name somebody else's sink -- which is the
        defect this class exists to close, reintroduced one layer down.
        """
        if not tenant.strip():
            raise SiemNotConfigured(
                "no tenant on this record; refusing to guess a destination"
            )

        resolution = self._registry.resolve(tenant, IntegrationKind.SIEM)
        integration = resolution.integration
        # Tested against `integration` rather than `resolution.deliverable`,
        # which says the same thing. `deliverable` plus an assert to narrow the
        # type would be an assert carrying a runtime invariant, and asserts are
        # stripped under `-O` -- so the narrowing would vanish in exactly the
        # build where a None slipping through matters most.
        if integration is None:
            raise SiemNotConfigured(
                f"{resolution.reason} The event is NOT discarded: this record "
                "stays on its retry budget and becomes visible in the "
                "dead-letter queue if it is never configured."
            )

        key = (tenant, integration.endpoint)
        deliverer = self._cache.get(key)
        if deliverer is None:
            deliverer = self._factory(integration.endpoint, integration.credential_ref)
            self._cache[key] = deliverer

        receipt = deliverer.deliver(
            payload=payload, idempotency_key=idempotency_key
        )
        # The destination is recorded in the receipt. "The export succeeded" is
        # not an auditable statement in a multi-tenant deployment; "it went to
        # acme's endpoint" is, and it is what makes a mis-routing visible after
        # the fact rather than only in the code.
        return {
            **dict(receipt),
            "tenant_id": tenant,
            "destination": integration.endpoint,
            "destination_is_shared": integration.uses_deployment_default,
        }
