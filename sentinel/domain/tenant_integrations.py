"""Phase 13: where a tenant's data may be sent, decided per tenant.

THE DEFECT
----------
`SENTINEL_SIEM_WEBHOOK_URL` and `SENTINEL_REMEDIATION_ENDPOINTS` are process-wide
`Settings`. One deployment, one webhook, every tenant.

In a single-tenant deployment that is correct and simple. In the multi-tenant
SaaS this product is built to be, it means tenant A's incidents -- agent names,
resource paths, prompt fragments, the shape of their estate -- are delivered to
whatever endpoint the operator configured, which belongs to somebody else or to
nobody in particular. It is a cross-tenant disclosure that no RLS policy can
catch, because the data leaves through a correctly-authorised code path.

THE RULE THAT MATTERS MORE THAN THE MODEL
-------------------------------------------
A tenant with no configured destination gets NOTHING. It does not inherit the
deployment default, and it does not inherit another tenant's.

That is the opposite of the usual convenience -- fall back to a global default
so things "just work" -- and the usual convenience is precisely the bug: the
tenant most likely to have no configuration is a new one, and a new tenant
silently shipping its first incidents to an existing customer's SIEM is the
worst possible first day.

`resolve` returns `None` and the caller reports NOT_CONFIGURED. An export that
does not happen is a gap somebody notices; an export to the wrong tenant is one
nobody does.

A DEPLOYMENT DEFAULT STILL EXISTS, AND IT IS OPT-IN PER TENANT
----------------------------------------------------------------
Single-tenant deployments should not have to configure the same webhook twice.
So a default may be declared, and a tenant may opt IN to it by name -- an
explicit act, recorded per tenant, rather than a fallback that happens when
nobody was paying attention.

CREDENTIALS ARE NOT IN THIS MODULE
-----------------------------------
`credential_ref` is a POINTER: a key in whatever secret store the deployment
runs. The secret itself never enters this dataclass, is never serialised by
`as_dict`, and therefore cannot end up in a log line, an evidence record or an
API response by accident. A model that held the secret would put it one
`repr()` away from every one of those.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping

__all__ = [
    "IntegrationKind",
    "IntegrationResolution",
    "TenantIntegration",
    "TenantIntegrationRegistry",
]


class IntegrationKind(str, Enum):
    """Destinations a tenant may configure independently."""

    SIEM = "siem"
    SOAR = "soar"
    SLACK = "slack"
    TEAMS = "teams"
    PAGERDUTY = "pagerduty"
    SERVICENOW = "servicenow"
    JIRA = "jira"
    WEBHOOK = "webhook"
    KMS = "kms"


#: A credential reference. A key in a secret store, not a secret: opaque,
#: bounded, and with no shape that could accidentally BE a token.
_CREDENTIAL_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")

#: Values that look like the secret rather than a pointer to one. Checked
#: because the failure mode is somebody pasting the token into the field named
#: `credential_ref` and nothing noticing until it appears in a log.
_SECRET_SHAPED = re.compile(
    r"^(?:sk-|ghp_|xox[baprs]-|AKIA|Bearer\s|eyJ[A-Za-z0-9_-]{10,})", re.I
)


@dataclass(frozen=True, slots=True)
class TenantIntegration:
    """One destination one tenant has configured.

    `endpoint` is where data goes. `credential_ref` is how to find the secret,
    never the secret. Neither is optional: a destination with no endpoint
    configures nothing, and an endpoint reachable with no credential is either
    unauthenticated -- which is a decision, not a default -- or broken.
    """

    tenant_id: str
    kind: IntegrationKind
    endpoint: str
    credential_ref: str = ""
    enabled: bool = True
    #: Set when this tenant opted in to the deployment-wide default rather than
    #: naming its own endpoint. Recorded so an audit can tell a deliberate
    #: shared destination from a per-tenant one.
    uses_deployment_default: bool = False

    def __post_init__(self) -> None:
        if not self.tenant_id.strip():
            raise ValueError("an integration with no tenant belongs to everybody")
        if not self.endpoint.strip():
            raise ValueError(
                f"{self.kind.value} integration for {self.tenant_id!r} has no "
                "endpoint; a destination that configures nothing should be "
                "absent, not present and empty"
            )
        if self.credential_ref:
            if _SECRET_SHAPED.match(self.credential_ref):
                raise ValueError(
                    "credential_ref looks like a SECRET rather than a reference "
                    "to one. This field is a key in a secret store and is "
                    "carried in configuration that gets logged and exported; a "
                    "token here is a disclosed token."
                )
            if not _CREDENTIAL_REF.fullmatch(self.credential_ref):
                raise ValueError(
                    f"credential_ref {self.credential_ref!r} is not a valid "
                    "secret-store key"
                )

    def as_dict(self) -> dict[str, Any]:
        """Serialisation that CANNOT carry a secret, because none is held.

        `credential_ref` is included: it is a pointer, and an operator reading
        an integration needs to know which secret it uses. The secret itself is
        not in this object to leak.
        """
        return {
            "tenant_id": self.tenant_id,
            "kind": self.kind.value,
            "endpoint": self.endpoint,
            "credential_ref": self.credential_ref,
            "enabled": self.enabled,
            "uses_deployment_default": self.uses_deployment_default,
        }


@dataclass(frozen=True, slots=True)
class IntegrationResolution:
    """What a delivery attempt resolved to, and why.

    A resolution carrying `integration=None` is NOT an error -- it is a tenant
    that configured nothing, which is a normal state with a specific correct
    behaviour: report NOT_CONFIGURED and deliver nowhere.
    """

    kind: IntegrationKind
    tenant_id: str
    integration: TenantIntegration | None
    reason: str

    @property
    def deliverable(self) -> bool:
        return self.integration is not None

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "tenant_id": self.tenant_id,
            "deliverable": self.deliverable,
            "reason": self.reason,
            "integration": (
                self.integration.as_dict() if self.integration else None
            ),
        }


class TenantIntegrationRegistry:
    """Resolves a tenant and a kind to a destination, or to nothing.

    Deliberately a small class rather than a dict lookup: the resolution RULE is
    the security property, and putting it behind a named method means there is
    one place to read it and one place a test can hold it.
    """

    __slots__ = ("_by_tenant", "_defaults")

    def __init__(
        self,
        integrations: Iterable[TenantIntegration] = (),
        *,
        deployment_defaults: Mapping[IntegrationKind, str] | None = None,
    ) -> None:
        self._by_tenant: dict[tuple[str, IntegrationKind], TenantIntegration] = {}
        for integration in integrations:
            self._by_tenant[(integration.tenant_id, integration.kind)] = integration
        self._defaults = dict(deployment_defaults or {})

    def resolve(
        self, tenant_id: str, kind: IntegrationKind
    ) -> IntegrationResolution:
        """Where this tenant's data of this kind may go.

        THE RULE, and the reason this method exists rather than a dict access:

        A tenant with nothing configured resolves to NOTHING. It does not fall
        back to the deployment default and it certainly does not fall back to
        another tenant's endpoint. The tenant most likely to have no
        configuration is a NEW one, and a new tenant silently shipping its first
        incidents to an existing customer's SIEM is the worst possible first
        day.

        A deployment default is reachable only by a tenant that opted IN to it,
        which is a row in this registry like any other -- an explicit act,
        recorded, auditable -- rather than something that happens when nobody
        was paying attention.
        """
        configured = self._by_tenant.get((tenant_id, kind))
        if configured is None:
            return IntegrationResolution(
                kind=kind,
                tenant_id=tenant_id,
                integration=None,
                reason=(
                    f"tenant {tenant_id!r} has no {kind.value} integration. "
                    "NOT_CONFIGURED: nothing is delivered. There is no fallback "
                    "to a deployment default or to another tenant, because an "
                    "export that does not happen is a gap somebody notices and "
                    "an export to the wrong tenant is one nobody does."
                ),
            )
        if not configured.enabled:
            return IntegrationResolution(
                kind=kind,
                tenant_id=tenant_id,
                integration=None,
                reason=(
                    f"tenant {tenant_id!r} has a {kind.value} integration and it "
                    "is disabled. Disabled is a decision; nothing is delivered."
                ),
            )
        return IntegrationResolution(
            kind=kind,
            tenant_id=tenant_id,
            integration=configured,
            # The endpoint is named, not just its provenance. An operator
            # checking where an export went should not have to make a second
            # query to find out, and "the tenant's own destination" answers a
            # question nobody asked.
            reason=(
                f"delivering to this tenant's own {kind.value} destination "
                f"({configured.endpoint})"
                if not configured.uses_deployment_default
                else (
                    f"delivering to the deployment-wide {kind.value} destination "
                    f"({configured.endpoint}), which this tenant opted in to"
                )
            ),
        )

    def for_tenant(self, tenant_id: str) -> tuple[TenantIntegration, ...]:
        return tuple(
            sorted(
                (i for (t, _k), i in self._by_tenant.items() if t == tenant_id),
                key=lambda i: i.kind.value,
            )
        )

    def opt_in_to_default(
        self, tenant_id: str, kind: IntegrationKind, *, credential_ref: str = ""
    ) -> TenantIntegration:
        """Record that a tenant chose the deployment-wide destination.

        Returns a normal `TenantIntegration` flagged as such, so the shared
        destination is a row an audit can see rather than an absence an audit
        has to infer.
        """
        endpoint = self._defaults.get(kind, "")
        if not endpoint:
            raise ValueError(
                f"there is no deployment default for {kind.value}; a tenant "
                "cannot opt in to a destination that does not exist"
            )
        integration = TenantIntegration(
            tenant_id=tenant_id,
            kind=kind,
            endpoint=endpoint,
            credential_ref=credential_ref,
            uses_deployment_default=True,
        )
        self._by_tenant[(tenant_id, kind)] = integration
        return integration
