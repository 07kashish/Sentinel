"""Choosing which adapter to build, and saying why in each case.

SPLIT OUT OF `container.py`, WHICH HAD TWO JOBS
------------------------------------------------
`build_container` assembles the object graph. These four functions DECIDE which
implementation goes into it -- a shared limiter or a per-process one, which
detection policy, which attestation gateway, which subscribers -- and each
carries a substantial argument about the trade-off.

Two jobs, read by different people, changing for different reasons. Keeping
them together took one module to exactly the 800 lines at which the fitness
rule says it has stopped having a single reason to change, and the next
addition broke it.

Every function here is imported back into `container.py`, so no call site
changed.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Callable, Mapping, Sequence

from sentinel.application.ports import (
    AttestationGateway,
    Logger,
)
from sentinel.composition.settings import Settings
from sentinel.domain.events import (
    AttestationRecorded,
    DomainEvent,
    IncidentAdmitted,
    IncidentCompleted,
    IncidentFailed,
)
from sentinel.domain.primitives import TenantId
from sentinel.infrastructure.attestation import (
    HttpAttestationGateway,
    UnconfiguredAttestationGateway,
)
from sentinel.application.ports import DetectionPolicy
from sentinel.infrastructure.detection import DeterministicPolicy
from sentinel.infrastructure.persistence.cache import (
    InProcessCache,
    RateLimiter,
    RedisCache,
    TokenBucketLimiter,
)

# The four helpers this module owns. `Container` and `build_container`
# stay in container.py; this __all__ came across with the copied import
# region and named things that are not here.
__all__ = [
    "_attestation_for",
    "_default_subscribers",
    "_detection_policy_for",
    "_limiter_for",
]


def _limiter_for(settings: Settings, *, logger: Any) -> RateLimiter:
    """Build the edge limiter, shared through Redis when one is configured.

    The in-process fallback is honest about what it is: single-process buckets. It
    is correct for a one-replica deployment and wrong for several, which is why
    production refuses to start multi-shard without Redis rather than quietly
    permitting N times the configured rate.
    """
    limits = {
        "auth_failure": settings.auth_failure_limit_per_minute,
        "credential": settings.credential_limit_per_minute,
        "address": settings.address_limit_per_minute,
    }
    if settings.redis_url:
        cache: Any = RedisCache.from_url(settings.redis_url)
        logger.info("rate_limiter_shared", backend="redis")
    else:
        cache = InProcessCache()
        logger.info(
            "rate_limiter_per_process",
            backend="in_process",
            note=(
                "buckets are not shared between replicas; the effective limit is "
                "this rate times the replica count"
            ),
        )
    return TokenBucketLimiter(
        cache=cache, limits=limits, fail_open=settings.rate_limit_fail_open
    )


class DetectionMode(str, Enum):
    """The detector selected by composition and exposed by diagnostics."""

    RULES_ONLY_CONFIGURED = "rules-only-configured"


def _detection_policy_for(
    settings: Settings, *, logger: Logger
) -> tuple[DetectionPolicy, DetectionMode]:
    """Construct the deterministic rules policy used by the service."""
    policy = DeterministicPolicy.default()
    mode = DetectionMode.RULES_ONLY_CONFIGURED
    logger.info("detection_rules_configured", detection_mode=mode.value,
                detector_version=policy.version())
    return policy, mode


def _attestation_for(settings: Settings) -> AttestationGateway:
    """Choose the gateway from configuration, and say which was chosen.

    An unconfigured deployment gets `UnconfiguredAttestationGateway`, which is
    the honest description of it: incidents complete as COMPLETED_UNATTESTED with
    a stated reason, never as attested.
    """
    if settings.attestation_endpoint:
        return HttpAttestationGateway(
            endpoint=settings.attestation_endpoint, token=settings.attestation_token
        )
    return UnconfiguredAttestationGateway(
        reason=(
            "SENTINEL_ATTESTATION_ENDPOINT is not configured, so this deployment "
            "has no anchoring capability. Incidents will complete as "
            "completed_unattested, which is accurate."
        )
    )




def _default_subscribers(
    logger: Logger,
) -> Mapping[type[DomainEvent], Sequence[Callable[[TenantId, DomainEvent], None]]]:
    """Audit logging for the events an operator must never miss.

    Deliberately minimal. Webhook fan-out, SIEM export and notification are
    supplied by the caller, because the container's job is wiring, not policy.
    """

    def log(tenant: TenantId, event: DomainEvent) -> None:
        logger.info(
            "domain_event",
            tenant=str(tenant),
            event=event.event_type,
            incident_id=str(event.incident_id),
            **dict(event.payload()),
        )

    return {
        IncidentAdmitted: (log,),
        AttestationRecorded: (log,),
        IncidentCompleted: (log,),
        IncidentFailed: (log,),
    }




