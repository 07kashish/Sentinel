"""Liveness, readiness and diagnostics.

WHY THESE MOVED OUT OF `http.py`
---------------------------------
`http.py` crossed the 800-line cap when readiness gained a probe cache. These
four things are one subject -- can this instance serve traffic, and how much may
we say about why not -- and they share a probe and a cache that nothing else
touches.

THE THREE ENDPOINTS SAY DIFFERENT AMOUNTS ON PURPOSE
------------------------------------------------------
`/health/live` is a fixed string. `/health/ready` is booleans and nothing else:
it is unauthenticated, and the exception text from a failed probe carries the
DSN, the internal hostname and the driver version. `/health/diagnostics` is the
detail, behind `READ_DIAGNOSTICS` -- the answer to reconnaissance is not to
withhold what an operator needs, it is to require a credential for it.

WHY READINESS MEMOISES ITS PROBE
---------------------------------
`/health/ready` is exempt from rate limiting (see `throttle.py`), because a
throttled readiness probe marks the pod NotReady, sheds it from the Service and
moves its traffic onto the remaining pods -- under exactly the load that caused
the throttling.

An unmetered unauthenticated route that ran a database query per request would
be a load amplifier anyone could aim at the database. The cache is what makes
the exemption safe, and the two must be changed together.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import Depends, FastAPI, Response, status

from sentinel.domain.authorization import Capability

__all__ = ["register_health_routes"]


def register_health_routes(
    app: FastAPI, container: Any, settings: Any, *, require: Any, Principal: Any
) -> None:
    """Attach the probes."""

    @app.get("/health/live")
    def liveness():
        """Is the process running. Unauthenticated, and says nothing else.

        A kubelet cannot present a credential, so this one route must be open.
        Everything it could disclose has been removed: no version, no backend, no
        tenant count, no component list. "ok" is the entire vocabulary.
        """
        return {"status": "ok"}

    #: How long a readiness probe result may be reused, in seconds.
    #:
    #: This is what makes exempting `/health/ready` from throttling SAFE. The
    #: endpoint hits the database, so an unmetered unauthenticated route that
    #: probed on every request would be a load amplifier anyone could point at
    #: the database. With a short cache the cost is bounded no matter how often
    #: it is called, and the answer stays fresh enough for an orchestrator that
    #: polls every 1-10 seconds and requires consecutive failures anyway.
    #:
    #: One second, not ten: a pod whose database has gone must stop advertising
    #: itself quickly, and this is the window in which it still claims to be
    #: ready.
    readiness_cache_seconds = 1.0

    #: (monotonic_deadline, result). A CLOSURE over this factory call, not
    #: module state -- each application instance gets its own, so a test and a
    #: server in one process cannot see each other's cached answer.
    readiness_cache: dict[str, tuple[float, tuple[bool, str]]] = {}

    def _probe_database_uncached() -> tuple[bool, str]:
        try:
            with container.pool.acquire() as conn:
                conn.begin()
                conn.execute("SELECT 1")
                conn.commit()
            return True, "reachable"
        except Exception as exc:  # noqa: BLE001 - any failure means not ready
            # The exception text is logged, never returned. It carries the DSN,
            # the internal hostname and the driver version, and this endpoint was
            # previously unauthenticated -- so an unauthenticated caller could
            # read the database host out of a 503 body.
            container.logger.error(
                "readiness_database_probe_failed",
                error_type=type(exc).__name__,
                error=str(exc),
            )
            return False, "unreachable"

    def _probe_database() -> tuple[bool, str]:
        """The probe, memoised for `readiness_cache_seconds`.

        `time.monotonic` rather than the injected clock: this is a cache expiry,
        not a recorded moment, and it must not move when the wall clock is
        adjusted. A backwards NTP step against a wall-clock deadline would pin a
        stale answer for as long as the correction.
        """
        now = time.monotonic()
        cached = readiness_cache.get("database")
        if cached is not None and cached[0] > now:
            return cached[1]
        result = _probe_database_uncached()
        readiness_cache["database"] = (now + readiness_cache_seconds, result)
        return result

    @app.get("/health/ready")
    def readiness(response: Response):
        """Can this instance serve traffic. Unauthenticated, but opaque.

        An orchestrator needs this without a credential, so the body carries only
        booleans and fixed strings -- never an exception message. The detailed
        version is `/health/diagnostics`, which requires a capability.
        """
        database_ok, _detail = _probe_database()
        ready = database_ok and bool(settings.api_keys)
        if not ready:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        if not settings.ready_exposes_detection_mode:
            return {"ready": ready}
        # Opt-in only. Naming the running detector here tells an unauthenticated
        # caller when the ML path is down, which is exactly the window an
        # attacker would pick -- so the default body stays boolean-only and the
        # always-on alerting surfaces are the CRITICAL log, `/health/diagnostics`
        # and the authenticated metrics scrape. An operator whose readiness port
        # is cluster-internal can enable this knowingly. Either way the value
        # never gates readiness: degraded detection is worse than full detection
        # and better than no service at all.
        return {"ready": ready, "detection_mode": container.detection_mode.value}

    @app.get("/health/diagnostics")
    def diagnostics(
        principal: Principal = Depends(require(Capability.READ_DIAGNOSTICS)),
    ):
        """The detail readiness used to leak, behind a capability.

        Which database, which gateway, which components are degraded: all of it is
        reconnaissance, and all of it is genuinely useful to an operator. The
        answer is not to withhold it but to require a credential for it.
        """
        database_ok, database_detail = _probe_database()
        can_anchor, reason = container.attestation.capability()
        return {
            "ready": database_ok and bool(settings.api_keys),
            "checks": {
                "configuration": bool(settings.api_keys),
                "database": database_ok,
                "database_detail": database_detail,
                "backend": settings.engine.safe_description(),
                # Attestation capability is REPORTED, never a readiness gate: a
                # deployment with no gateway is degraded, not unhealthy, and it
                # completes incidents as `completed_unattested` rather than
                # pretending otherwise.
                "attestation_capable": can_anchor,
                "attestation_detail": reason,
                "oidc_enabled": container.oidc is not None,
                "protect_kill_switch": settings.protect_kill_switch,
                # Section 31. Reported so an operator can confirm which
                # mode a replica is actually in, rather than inferring it
                # from a boolean whose name predates the vocabulary.
                "protection_mode": settings.protection_mode.value,
                "enforces": settings.protection_mode.enforces,
                "denies_by_default": settings.protection_mode.denies_by_default,
                "protect_enforcement": settings.protect_enforcement,
                "detection_mode": container.detection_mode.value,
                "detector_version": container.policy.version(),
            },
        }
