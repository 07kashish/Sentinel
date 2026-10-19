"""Turning a bearer JWT into a `Principal`, for both kinds of JWT the service accepts.

Two issuers, two meanings:

  * The HUMAN OIDC issuer (`SENTINEL_OIDC_*`): a person at the tenant's IdP.
    Tenant and role are claims Sentinel configured; trust is `verified`.
  * An AGENT identity provider (`SENTINEL_AGENT_IDP_JSON`): Okta Agent SSO or
    Entra Agent ID vouching for an agent. Tenant and role come from the
    registration; trust is `verified`; and the agent id is BOUND to the
    principal, so the routes that take an `agentId` refuse any other value.

Kept out of `http.py` so the authentication dependency there stays a short
dispatch, and so the two paths are testable without the app.
"""

from __future__ import annotations

from typing import Any, Callable

from fastapi import HTTPException, status

from sentinel.domain.authorization import UnknownRole, capabilities_for
from sentinel.domain.primitives import TenantId, TrustLevel
from sentinel.infrastructure.agent_identity_providers import AGENT_ROLE
from sentinel.infrastructure.observability import correlation_var, new_correlation
from sentinel.infrastructure.oidc import OidcError
from sentinel.infrastructure.persistence.audit import Outcome
from sentinel.interface.http_models import Principal

__all__ = ["principal_from_jwt", "require_agent_identity", "tenant_for_jwt"]


def _is_jwt(token: str) -> bool:
    # Compact JWTs have two dots; API keys do not.
    return token.count(".") == 2


def tenant_for_jwt(container: Any, token: str) -> str | None:
    """The tenant a JWT belongs to, for throttle routing. None when unknown."""
    if not _is_jwt(token):
        return None
    agent_idps = getattr(container, "agent_idps", None)
    if agent_idps is not None and agent_idps.provider_for(token) is not None:
        try:
            return agent_idps.verify(token).tenant_id
        except OidcError:
            return None
    if container.oidc is not None:
        try:
            return container.oidc.verify(token).tenant_id
        except OidcError:
            return None
    return None


def _bind_correlation(tenant_id: str) -> None:
    corr = correlation_var.get()
    if corr is not None:
        correlation_var.set(
            new_correlation(
                request_id=corr.request_id,
                tenant_id=tenant_id,
                worker_shard=corr.worker_shard,
            )
        )


def _enrol_tenant_once(container: Any, tenant_id: str) -> None:
    """Give a tenant its directory row the first time a VERIFIED sign-in names it.

    Maintenance sweeps the `tenants` table. Tenants named in configuration are
    enrolled at startup; a tenant that exists only as a claim in the human
    identity provider is unknown until somebody signs in, and would otherwise
    never be swept. Only reached after the token verified, so an unauthenticated
    caller cannot create rows. One insert per tenant per process; a failure is
    logged and never fails the sign-in.
    """
    seen = getattr(container, "enrolled_tenants", None)
    if seen is None or tenant_id in seen:
        return
    try:
        with container.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.execute_rowcount(
                f"INSERT INTO tenants (tenant_id, name, created_at) VALUES ({p},{p},{p}) "
                "ON CONFLICT (tenant_id) DO NOTHING",
                (tenant_id, tenant_id, container.clock.now().value.isoformat()),
            )
            conn.commit()
        seen.add(tenant_id)
    except Exception as exc:  # noqa: BLE001 - enrolment must never fail authentication
        container.logger.error("tenant_enrolment_failed", tenant=tenant_id, error=type(exc).__name__)


def principal_from_jwt(
    container: Any,
    raw_token: str,
    *,
    action: str,
    audit_denial: Callable[..., None],
    unknown_tenant: Any,
) -> Principal | None:
    """A principal for a JWT, or None when the token is not a JWT at all.

    Raises `HTTPException` for a JWT that fails verification or names an
    issuer nobody registered -- a JWT never falls through to the API-key path,
    because a token shaped like a credential from an IdP and refused by every
    IdP is an attack or a misconfiguration, and either deserves a 401 that
    says so rather than "invalid API key".
    """
    if not _is_jwt(raw_token):
        return None
    agent_idps = getattr(container, "agent_idps", None)
    if agent_idps is None and container.oidc is None:
        return None

    if agent_idps is not None and agent_idps.provider_for(raw_token) is not None:
        try:
            identity = agent_idps.verify(raw_token)
        except OidcError as exc:
            audit_denial(
                tenant=unknown_tenant,
                actor="agent-idp:invalid",
                action=action,
                outcome=Outcome.DENIED,
                reason=str(exc),
            )
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                detail="invalid agent identity token",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc
        _bind_correlation(identity.tenant_id)
        return Principal(
            tenant=TenantId(identity.tenant_id),
            role=AGENT_ROLE,
            key_hash=f"agent-idp:{identity.provider}:{identity.subject}",
            capabilities=capabilities_for(AGENT_ROLE),
            # The customer's IdP vouched for this agent. Verified, and BOUND:
            # the routes check `agent_id` against the body.
            trust=TrustLevel.VERIFIED,
            agent_id=identity.agent_id,
            workload=identity.workload,
        )

    if container.oidc is None:
        audit_denial(
            tenant=unknown_tenant,
            actor="jwt:unknown-issuer",
            action=action,
            outcome=Outcome.DENIED,
            reason="JWT from an issuer that is not registered",
        )
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="token issuer is not registered",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        claims = container.oidc.verify(raw_token)
    except OidcError as exc:
        audit_denial(
            tenant=unknown_tenant,
            actor="oidc:invalid",
            action=action,
            outcome=Outcome.DENIED,
            reason=str(exc),
        )
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="invalid OIDC token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    try:
        caps = capabilities_for(claims.role)
    except UnknownRole as exc:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail=f"OIDC role {claims.role!r} is not granted",
        ) from exc
    _bind_correlation(claims.tenant_id)
    _enrol_tenant_once(container, claims.tenant_id)
    return Principal(
        tenant=TenantId(claims.tenant_id),
        role=claims.role,
        key_hash=f"oidc:{claims.subject}",
        capabilities=caps,
        # A verified identity from the tenant's IdP. This is one of the two
        # ways an HTTP caller reaches `verified`; nothing in a request body can.
        trust=TrustLevel.VERIFIED,
    )


def require_agent_identity(principal: Principal, agent_id: str, *, container: Any = None) -> None:
    """Refuse a body `agentId` that differs from the credential's bound agent.

    With `SENTINEL_REQUIRE_WORKLOAD_IDENTITY` on, also refuse any credential
    that binds NO agent. An API key proves possession of a shared secret;
    anything holding it could type any agent's name, so on the agent path it
    is not an identity at all.

    A no-op for API keys and human OIDC principals, which bind no agent. For
    an IdP-issued agent token it is the property that makes the identity
    first-class: the credential IS the agent, and cannot speak as another.
    """
    bound = getattr(principal, "agent_id", "")
    workflow = getattr(getattr(container, "settings", None), "workflow", None)
    if not bound and workflow is not None and workflow.require_workload_identity:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail=(
                "this deployment requires an agent identity issued by a registered "
                "identity provider or workload attestor; an API key cannot act as an agent"
            ),
        )
    if bound and agent_id.strip() != bound:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail=(
                f"this credential is the identity of agent {bound!r} and cannot "
                f"act as {agent_id!r}; an agent token speaks only for itself"
            ),
        )
