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

from pathlib import Path
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
from sentinel.infrastructure.soft_detection import (
    DetectionMode,
    SoftAugmentedPolicy,
    SoftPromptScorer,
)
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


#: Measured on the independent English held-out split. Quoted in the CRITICAL
#: log so the operator reading it at 3am does not have to find the benchmark to
#: learn what the fallback costs.
_RULES_ONLY_RECALL = 0.067
_SOFT_AND_RULES_RECALL = 0.855

#: Mirrors `evaluation.soft_prompt.DEFAULT_ARTIFACT`. Duplicated rather than
#: imported because this value is needed to *report* a failure whose cause may be
#: that `evaluation` is not importable at all. The duplication is held to the
#: original by `test_detection_mode.py::test_default_artifact_path_matches_loader`.
DEFAULT_SOFT_PROMPT_ARTIFACT = Path("evaluation/artifacts/soft_prompt_model.pkl")


def _detection_policy_for(
    settings: Settings, *, logger: Logger
) -> tuple[DetectionPolicy, DetectionMode]:
    """Deterministic rules, optionally OR'd with the soft prompt classifier.

    Returns the mode alongside the policy because the caller cannot otherwise
    tell them apart: `SoftAugmentedPolicy(base, soft=None)` and the bare
    `DeterministicPolicy` behave identically, which is exactly how the silent
    fallback stayed invisible. Every path out of here either logs CRITICAL or
    returns `SOFT_AND_RULES`.
    """
    base = DeterministicPolicy.default()
    if not settings.soft_prompt_detect:
        logger.warning(
            "detection_soft_prompt_disabled",
            detection_mode=DetectionMode.RULES_ONLY_CONFIGURED.value,
            reason="SENTINEL_SOFT_PROMPT_DETECT is false",
            independent_english_recall=_RULES_ONLY_RECALL,
        )
        return base, DetectionMode.RULES_ONLY_CONFIGURED

    path = (
        Path(settings.soft_prompt_model_path)
        if settings.soft_prompt_model_path
        else DEFAULT_SOFT_PROMPT_ARTIFACT
    )
    try:
        # Load outside sentinel/infrastructure so pickle stays out of that tree.
        from evaluation.soft_prompt import SoftPromptClassifier

        clf = SoftPromptClassifier.load(path)
    except Exception as exc:  # noqa: BLE001 - any load failure degrades detection
        # Reached when the runtime lacks scikit-learn, when the pickle was
        # written by an incompatible version, or when the file is corrupt. The
        # process still starts -- refusing to serve would turn a detection
        # regression into a full outage -- but it starts loudly.
        logger.critical(
            "detection_degraded_soft_prompt_unloadable",
            detection_mode=DetectionMode.RULES_ONLY_DEGRADED.value,
            artifact_path=str(path),
            error_type=type(exc).__name__,
            error=str(exc),
            independent_english_recall=_RULES_ONLY_RECALL,
            expected_recall_when_loaded=_SOFT_AND_RULES_RECALL,
            remedy=(
                "install the pinned scikit-learn, restore the artifact, or set "
                "SENTINEL_SOFT_PROMPT_DETECT=false to make rules-only explicit"
            ),
        )
        return base, DetectionMode.RULES_ONLY_DEGRADED
    if clf is None:
        logger.critical(
            "detection_degraded_soft_prompt_missing",
            detection_mode=DetectionMode.RULES_ONLY_DEGRADED.value,
            artifact_path=str(path),
            independent_english_recall=_RULES_ONLY_RECALL,
            expected_recall_when_loaded=_SOFT_AND_RULES_RECALL,
            remedy=(
                "restore the artifact or point SENTINEL_SOFT_PROMPT_MODEL at it"
            ),
        )
        return base, DetectionMode.RULES_ONLY_DEGRADED
    soft = SoftPromptScorer(
        score_fn=clf.predict_proba,
        version=str(clf.meta.get("version") or clf.path.name),
        threshold=settings.soft_prompt_threshold,
    )
    logger.info(
        "detection_soft_prompt_loaded",
        detection_mode=DetectionMode.SOFT_AND_RULES.value,
        artifact_path=str(clf.path),
        model_version=soft.version,
        threshold=soft.threshold,
    )
    return SoftAugmentedPolicy(base=base, soft=soft), DetectionMode.SOFT_AND_RULES


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




