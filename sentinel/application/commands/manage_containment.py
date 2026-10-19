"""Activating and lifting the granular kill switch.

WHY THESE ARE COMMANDS AND NOT A REPOSITORY CALL FROM THE ROUTE
------------------------------------------------------------------
Everything else that changes state in this system goes through the command bus,
and containment is the last thing that should be the exception. Activating one
stops production work: it needs the same tenant scoping, the same transaction
boundary, the same structured logging and the same Result shape as approving a
remediation, and a route reaching past the bus into a repository would get some
of those and quietly miss the rest.

THE CACHE INVALIDATION IS PART OF THE COMMAND, NOT AN AFTERTHOUGHT
--------------------------------------------------------------------
`ContainmentGuard` caches for `CACHE_TTL_SECONDS`. If activation did not
invalidate, an operator would hit the switch, watch the agent keep working for
several seconds, and reasonably conclude the control is broken -- then hit it
again, and again. The invalidation makes it immediate in the process that
handled the request; other replicas still wait out the TTL, which is what that
constant is documented to bound.

Invalidation happens AFTER the commit. Invalidating first would open a window
where the cache is empty, a concurrent request re-reads the store, and the
pre-commit state gets cached as fresh -- leaving the containment un-enforced in
this process for a full TTL, which is precisely the failure the invalidation was
added to prevent.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Protocol

from dataclasses import dataclass

from sentinel.application.messages import Command, Result
from sentinel.application.ports import Clock, IdGenerator, Logger, UnitOfWorkFactory
from sentinel.domain.containment import (
    Containment,
    ContainmentScope,
    InvalidContainment,
)

__all__ = [
    "ActivateContainment",
    "ActivateContainmentHandler",
    "LiftContainment",
    "LiftContainmentHandler",
]


class ContainmentGuard(Protocol):
    """The cache that decides whether an agent is currently contained.

    Declared because both handlers previously took `guard: object`. A parameter
    typed `object` has NO contract -- any argument satisfies it, including one
    with no `invalidate` method -- and the failure then surfaces at runtime
    inside a broad `except` that logs and carries on. `object` is also the type
    that hid a renamed attribute elsewhere in this codebase.
    """

    def invalidate(self, tenant: str) -> None:
        """Drop the cached decision for one tenant after a change.

        Called after a containment is committed. A failure here is logged and
        swallowed on purpose: the containment IS committed, and failing the
        command would tell an operator their kill switch did not work when it
        did.
        """
        ...


@dataclass(frozen=True, slots=True)
class ActivateContainment(Command):
    scope: str
    selector: str
    created_by: str
    reason: str = ""
    expires_at: str = ""


@dataclass(frozen=True, slots=True)
class LiftContainment(Command):
    containment_id: str
    revoked_by: str


#: A containment is a deliberate outage. Whoever finds it next month has the
#: scope, the owner, this sentence and this date to decide whether lifting it
#: is safe, so both are required -- at ACTIVATION. Rows stored before this rule
#: still load; the rule governs what may be created, not what may be read.
MIN_REASON_LENGTH = 8
MAX_CONTAINMENT_DAYS = 30


def _governance_refusal(command: "ActivateContainment", *, now: datetime) -> tuple[str, str] | None:
    if len(command.reason.strip()) < MIN_REASON_LENGTH:
        return ("reason_required",
                f"a containment needs a reason of at least {MIN_REASON_LENGTH} characters; "
                "the person who has to decide whether to lift it was not in the room")
    if not command.expires_at.strip():
        return ("expiry_required",
                "a containment needs an expiry. An indefinite pause nobody owns becomes a permanent state; "
                f"set one up to {MAX_CONTAINMENT_DAYS} days ahead and activate again to extend it")
    try:
        expires = datetime.fromisoformat(command.expires_at.strip().replace("Z", "+00:00"))
    except ValueError:
        return ("expiry_invalid", "expiresAt must be an ISO-8601 timestamp")
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires <= now:
        return ("expiry_invalid", "expiresAt is not in the future")
    if expires - now > timedelta(days=MAX_CONTAINMENT_DAYS):
        return ("expiry_too_far",
                f"a containment may run at most {MAX_CONTAINMENT_DAYS} days before someone has to look at it again; "
                "activate a new one, with a reason, to extend it")
    return None


class ActivateContainmentHandler:
    __slots__ = ("_uow_factory", "_guard", "_clock", "_ids", "_logger")

    def __init__(
        self,
        *,
        uow_factory: UnitOfWorkFactory,
        guard: ContainmentGuard | None,
        clock: Clock,
        ids: IdGenerator,
        logger: Logger,
    ) -> None:
        self._uow_factory = uow_factory
        self._guard = guard
        self._clock = clock
        self._ids = ids
        self._logger = logger

    def handle(self, command: ActivateContainment) -> Result:
        try:
            scope = ContainmentScope(command.scope)
        except ValueError:
            return Result.refused(
                "unknown_scope",
                detail=(
                    "scope must be one of: "
                    + ", ".join(s.value for s in ContainmentScope)
                ),
            )

        refusal = _governance_refusal(command, now=self._clock.now().value)
        if refusal is not None:
            return Result.refused(refusal[0], detail=refusal[1])

        # `message_id` rather than a new minting method: it is the generator's
        # existing opaque identifier, and widening the IdGenerator protocol for
        # one caller would make every test double implement it.
        containment_id = f"con-{self._ids.message_id().value}"
        try:
            containment = Containment(
                containment_id=containment_id,
                tenant_id=str(command.tenant),
                scope=scope,
                selector=command.selector,
                created_by=command.created_by,
                created_at=str(self._clock.now()),
                reason=command.reason,
                expires_at=command.expires_at,
            )
        except InvalidContainment as exc:
            # A domain refusal, not a server fault. This exact class of escape
            # produced a 500 on `/v1/mcp/evaluate` earlier in this codebase's
            # history, from a whitespace-only tool name.
            return Result.refused("invalid_containment", detail=str(exc))

        with self._uow_factory.begin(command.tenant) as uow:
            uow.containments.create(containment)
            uow.commit()

        # After the commit. See the module docstring.
        self._invalidate(str(command.tenant))

        self._logger.warning(
            # WARNING, not INFO. Somebody just stopped production work on
            # purpose, and it should be visible in a log an operator is already
            # watching rather than only in the audit trail.
            "containment_activated",
            tenant=str(command.tenant),
            containment_id=containment_id,
            scope=scope.value,
            selector=command.selector,
            created_by=command.created_by,
            expires_at=command.expires_at or "never",
        )
        return Result.accepted(
            "contained",
            containment_id=containment_id,
            scope=scope.value,
            selector=command.selector,
            expires_at=command.expires_at,
        )

    def _invalidate(self, tenant: str) -> None:
        if self._guard is None:
            return
        try:
            self._guard.invalidate(tenant)
        except Exception as exc:  # noqa: BLE001
            # The containment IS committed. Failing the command here would tell
            # the operator their kill switch did not work when it did -- they
            # would hit it again, and the second attempt would succeed at
            # nothing. Logged loudly instead: the worst case is one TTL of delay.
            self._logger.error(
                "containment_cache_invalidation_failed",
                tenant=tenant,
                detail="the containment is stored and WILL take effect within the cache TTL",
                error=f"{type(exc).__name__}: {exc}",
            )


class LiftContainmentHandler:
    __slots__ = ("_uow_factory", "_guard", "_clock", "_logger")

    def __init__(
        self,
        *,
        uow_factory: UnitOfWorkFactory,
        guard: ContainmentGuard | None,
        clock: Clock,
        logger: Logger,
    ) -> None:
        self._uow_factory = uow_factory
        self._guard = guard
        self._clock = clock
        self._logger = logger

    def handle(self, command: LiftContainment) -> Result:
        now = str(self._clock.now())
        with self._uow_factory.begin(command.tenant) as uow:
            lifted = uow.containments.revoke(
                command.containment_id, revoked_by=command.revoked_by, at=now
            )
            uow.commit()

        if not lifted:
            # Either it does not exist or it was already lifted. Reported as one
            # refusal rather than two: distinguishing them would tell a caller
            # whether a containment id exists in a tenant they may be probing.
            return Result.refused(
                "not_active",
                detail="no active containment with that id",
                containment_id=command.containment_id,
            )

        if self._guard is not None:
            try:
                self._guard.invalidate(str(command.tenant))
            except Exception as exc:  # noqa: BLE001
                self._logger.error(
                    "containment_cache_invalidation_failed",
                    tenant=str(command.tenant),
                    error=f"{type(exc).__name__}: {exc}",
                )

        self._logger.warning(
            "containment_lifted",
            tenant=str(command.tenant),
            containment_id=command.containment_id,
            revoked_by=command.revoked_by,
        )
        return Result.accepted("lifted", containment_id=command.containment_id)
