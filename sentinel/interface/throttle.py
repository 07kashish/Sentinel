"""Edge rate limiting. The control that makes brute force cost something.

WHY THIS IS MIDDLEWARE AND NOT A DEPENDENCY
-------------------------------------------
The most valuable request to limit is the one that fails authentication, and by
the time a FastAPI dependency runs, `authenticate` has already rejected it. A
dependency can only limit callers who are already authenticated -- which is the
opposite of what a limiter is for.

So this runs before routing, keys on what is knowable before authentication, and
limits authentication FAILURES harder than anything else.

WHAT IS KEYED, AND WHY NOT THE IP
---------------------------------
Three buckets, in the order they are consulted:

  1. **Failed authentication**, keyed by the SHA-256 prefix of the presented
     credential. This is the brute-force bucket. Keying on the credential rather
     than the caller means an attacker rotating source addresses through a botnet
     still exhausts one bucket per guessed key -- and since each guess is a
     different key, the bucket that actually bites is the third one.
  2. **Per credential**, keyed by the digest prefix of a valid key. Bounds the
     damage one compromised credential can do.
  3. **Per source address**, the backstop for unauthenticated traffic where there
     is no credential to key on.

The source address is used LAST and never alone, because behind a load balancer
every request shares one address unless `X-Forwarded-For` is trusted -- and
trusting a client-supplied header for a security decision is how a limiter is
bypassed by adding a header. `trusted_proxy_hops` must be set deliberately by a
deployment that actually terminates at a proxy it controls; the default is zero,
meaning the header is ignored entirely.

FAILURE POLICY IS THE DEPLOYMENT'S DECISION
-------------------------------------------
`TokenBucketLimiter.fail_open` has no default and neither does this. A limiter that
fails open loses the limit during an outage; one that fails closed loses
availability. For an ingest path the first is usually right and for an admin path
the second is, so the choice is configuration, and a `degraded` decision is
reported distinctly so an operator can tell "allowed because there was budget"
from "allowed because the limiter was down".
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping

from starlette.responses import JSONResponse

__all__ = ["ThrottlePolicy", "install_throttle"]


@dataclass(frozen=True, slots=True)
class ThrottlePolicy:
    """Per-minute allowances. Every class must be stated, including the generous ones."""

    #: Failed authentications per minute for one presented credential. Very low:
    #: a legitimate client does not fail authentication repeatedly, and the only
    #: caller that does is guessing.
    auth_failures_per_minute: int = 10
    #: Requests per minute for one valid credential.
    per_credential_per_minute: int = 600
    #: Requests per minute from one source address, for traffic with no usable
    #: credential. The backstop, not the primary control.
    per_address_per_minute: int = 120
    #: How many `X-Forwarded-For` hops to trust. ZERO by default: trusting a
    #: client-supplied header for a security decision means the limiter is
    #: bypassed by adding a header.
    trusted_proxy_hops: int = 0
    #: Paths exempt from limiting. Both health probes.
    #:
    #: Liveness: a kubelet polling every second must not be able to exhaust a
    #: bucket and get the pod killed, and the route discloses nothing.
    #:
    #: Readiness, for a stronger version of the same reason. A throttled
    #: readiness probe marks the pod NotReady, which sheds it from the Service,
    #: which moves its traffic onto the remaining pods -- under exactly the load
    #: that caused the throttling. That is a cascade, and an observability soak
    #: measured it: at ~180 rps from one address, 27 of 270 readiness probes
    #: were answered 429. In a cluster the kubelet usually probes from the node
    #: address while clients arrive from elsewhere, so the buckets usually
    #: differ -- and "usually" is not a control.
    #:
    #: This is only safe because `/health/ready` MEMOISES its database probe
    #: (see `readiness_cache_seconds` in `http.py`). Without that cache an
    #: unmetered unauthenticated route would run a query per request, and
    #: exempting it would trade a cascading-failure risk for a denial-of-service
    #: one. Remove the cache and this exemption must go with it.
    exempt_paths: tuple[str, ...] = ("/health/live", "/health/ready")

    def classes(self) -> Mapping[str, int]:
        return {
            "auth_failure": self.auth_failures_per_minute,
            "credential": self.per_credential_per_minute,
            "address": self.per_address_per_minute,
        }


def _client_address(request: Any, hops: int) -> str:
    """The caller's address, taking a forwarded header only as far as configured.

    With `hops=0` the socket address is used and `X-Forwarded-For` is ignored. With
    `hops=n` the (n+1)-th entry FROM THE RIGHT is taken, because a proxy appends
    and everything to the left of what our own proxies added is attacker-supplied.
    Counting from the left is the classic mistake: the attacker controls that end.
    """
    socket_address = request.client.host if request.client else "unknown"
    if hops <= 0:
        return socket_address
    forwarded = request.headers.get("x-forwarded-for", "")
    if not forwarded:
        return socket_address
    chain = [part.strip() for part in forwarded.split(",") if part.strip()]
    if not chain:
        return socket_address
    index = len(chain) - hops
    if index < 0:
        # Fewer hops present than configured: the chain is shorter than the
        # deployment claims, so nothing in it is trustworthy. Fall back to the
        # socket rather than picking the leftmost value an attacker supplied.
        return socket_address
    return chain[index]


def install_throttle(
    app: Any,
    *,
    limiter: Any,
    policy: ThrottlePolicy,
    audit: Any,
    tenant_of: Any,
    logger: Any,
    shared_digests: frozenset[str] = frozenset(),
) -> None:
    """Attach the throttle to `app`. Registered before the security headers.

    `tenant_of(digest, token)` maps a presented credential to a tenant id, or
    None when the credential is unrecognised. It receives the digest for API-key
    lookup and the raw token so a JWT can be verified to its tenant claim. It is
    injected rather than read from settings so this module needs no knowledge of
    how credentials are configured.
    """

    @app.middleware("http")
    async def _throttle(request, call_next):
        if request.url.path in policy.exempt_paths:
            return await call_next(request)

        presented, token = _presented_credential(request)
        # The lookup sees the DIGEST for an API key and the TOKEN for a JWT,
        # because a JWT's tenant is a verified claim rather than a table entry.
        # Without the second argument every SSO caller landed in the
        # auth-failure bucket -- ten requests a minute, keyed on a guess that
        # was not one.
        tenant = tenant_of(presented, token) if presented else None

        if presented is not None and tenant is None:
            # An unrecognised credential. This is the brute-force signal and it
            # gets the tightest bucket, keyed on the guess so that an attacker
            # rotating addresses gains nothing.
            decision = limiter.check(tenant_id=f"guess:{presented[:12]}", klass="auth_failure")
            if not decision.allowed:
                return _refused(
                    decision,
                    audit=audit,
                    tenant="unauthenticated:none",
                    actor=f"unknown:{presented[:12]}",
                    action=f"{request.method} {request.url.path}",
                    reason="auth_failure_rate_limited",
                    logger=logger,
                )

        if tenant is not None:
            # A credential PUBLISHED on purpose (the console's read-only demo
            # key) is held by everyone at once. One bucket for all of them
            # would let a single visitor exhaust it for the rest, so its
            # bucket is per address as well.
            bucket = f"{tenant}:{presented[:12]}"
            if presented in shared_digests:
                bucket += ":" + _client_address(request, policy.trusted_proxy_hops)
            decision = limiter.check(tenant_id=bucket, klass="credential")
            if not decision.allowed:
                return _refused(
                    decision,
                    audit=audit,
                    tenant=tenant,
                    actor=f"key:{presented[:12]}",
                    action=f"{request.method} {request.url.path}",
                    reason="credential_rate_limited",
                    logger=logger,
                )
        else:
            address = _client_address(request, policy.trusted_proxy_hops)
            decision = limiter.check(tenant_id=f"addr:{address}", klass="address")
            if not decision.allowed:
                return _refused(
                    decision,
                    audit=audit,
                    tenant="unauthenticated:none",
                    actor=f"addr:{address}",
                    action=f"{request.method} {request.url.path}",
                    reason="address_rate_limited",
                    logger=logger,
                )

        return await call_next(request)


def _presented_credential(request: Any) -> tuple[str | None, str]:
    """The SHA-256 of the presented bearer token and the token itself.

    The digest is what becomes a bucket key -- a limiter's key space ends up in
    cache dumps, metrics labels and slow-query logs, so the raw credential never
    does. The token is handed ONLY to `tenant_of`, which needs it to verify a
    JWT's tenant claim, and goes nowhere else.
    """
    header = request.headers.get("authorization", "")
    if not header.startswith("Bearer "):
        return None, ""
    token = header.removeprefix("Bearer ").strip()
    if not token:
        return None, ""
    return hashlib.sha256(token.encode("utf-8")).hexdigest(), token


def _presented_digest(request: Any) -> str | None:
    """The digest alone. Kept for callers that only key on it."""
    return _presented_credential(request)[0]


def _refused(
    decision: Any,
    *,
    audit: Any,
    tenant: str,
    actor: str,
    action: str,
    reason: str,
    logger: Any,
) -> JSONResponse:
    """429 with `Retry-After`, audited durably.

    A refusal that is only a log line is a refusal nobody can reconstruct later,
    and "were we being brute-forced on the 14th" is exactly the question asked
    after the fact.
    """
    from sentinel.domain.primitives import TenantId
    from sentinel.infrastructure.persistence.audit import Outcome

    retry_after = max(1, int(decision.retry_after_seconds) or 1)
    audit.record(
        tenant=TenantId(tenant),
        actor=actor,
        action=action,
        resource_type="rate_limit",
        resource_id=reason,
        outcome=Outcome.DENIED,
        detail={"reason": reason, "degraded": bool(decision.degraded)},
    )
    if decision.degraded:
        logger.error(
            "rate_limiter_degraded",
            reason=reason,
            note="the limiter was unreachable; this decision came from fail_open",
        )
    return JSONResponse(
        status_code=429,
        content={
            "detail": (
                "rate limit exceeded. This limit exists per credential and per "
                "source; retry after the interval below."
            ),
            "reason": reason,
        },
        headers={"Retry-After": str(retry_after)},
    )
