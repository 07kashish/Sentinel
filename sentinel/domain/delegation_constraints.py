"""Phase 4: the constraints a delegation carries, and what violates them.

WHY THIS IS A SEPARATE MODULE AND NOT MORE FIELDS ON `DelegationHop`
----------------------------------------------------------------------
`a2a.py` answers "was this hop entitled to what it granted" -- a question about
SCOPES, and it answers it well. Phase 4 adds a different question: "is this
delegation still valid, here, now, for this object". Those are different
failure modes with different evidence and different remedies, and folding them
into one 620-line module would make the amplification logic harder to read
without making either check better.

`a2a.DelegationHop` stays exactly as it is, so every existing caller, the wire
proxy and the SQL card store keep working unchanged. A `Constraint` is attached
alongside a hop when the issuer recorded one, and `evaluate` is called with the
context an action is being attempted in.

THE FOUR THINGS THAT WERE UNDETECTABLE
----------------------------------------
1. EXPIRY. Nothing in the delegation model carried one, so every delegation
   ever issued was permanent. An agent handed `read:customers` for a
   twenty-minute task held it until somebody noticed -- and nobody notices a
   grant that never appears in a review because it was never written down as
   expiring.

2. ENVIRONMENT. A delegation issued against `dev` and presented against
   `production` is the cheapest privilege escalation there is, and scope
   checking cannot see it: `read:customers` in dev and `read:customers` in
   production are the same string.

3. RESOURCE. A scope names a VERB, not an OBJECT. `read:customers` says nothing
   about WHICH customers, so a delegation intended for one record authorised
   the table.

4. TENANT. A chain assembled in one tenant and presented in another is a
   cross-tenant authority claim. The stores are RLS-protected, but the CHAIN is
   caller-supplied and nothing compared its tenant to the caller's.

TIME IS PASSED IN, NEVER READ
-----------------------------
`evaluate` takes `now`. It does not call `datetime.now`, because a domain rule
that reads the clock cannot be tested at a boundary and cannot be replayed
against historical evidence -- and policy simulation (Phase 7) replays exactly
that. The same reason `Fence` takes its timestamp.

ABSENT IS NOT PERMISSIVE, BUT IT IS NOT FATAL EITHER
------------------------------------------------------
A delegation with no expiry is reported as UNBOUNDED, at moderate severity, not
refused. Refusing would break every delegation issued before this module
existed; ignoring would leave the gap that motivated it. Reporting makes the
unbounded grants show up in a review, which is the thing that was impossible
before.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from sentinel.domain.a2a import Severity

__all__ = [
    "ENVIRONMENT_RANK",
    "ConstraintFinding",
    "ConstraintKind",
    "DelegationConstraint",
    "DelegationContext",
    "evaluate",
]


class ConstraintKind(str, Enum):
    """One member per way a delegation can be invalid where it is presented."""

    EXPIRED = "delegation_expired"
    NOT_YET_VALID = "delegation_not_yet_valid"
    UNBOUNDED = "delegation_unbounded"
    ENVIRONMENT_ESCALATION = "environment_escalation"
    RESOURCE_NOT_PERMITTED = "resource_not_permitted"
    TENANT_MISMATCH = "tenant_mismatch"
    PURPOSE_MISSING = "purpose_missing"
    EXCESSIVE_LIFETIME = "excessive_lifetime"


#: Severity per kind, in ONE place, so an author constructing a finding cannot
#: understate it. Same discipline as `a2a.FINDING_SEVERITY`.
#:
#: TENANT_MISMATCH is critical and EXPIRED is high, deliberately: an expired
#: delegation is authority that has run out, while a cross-tenant one is
#: authority that never existed. The second is an attack; the first is often a
#: long-running job nobody re-issued.
CONSTRAINT_SEVERITY: Mapping[ConstraintKind, Severity] = MappingProxyType({
    ConstraintKind.TENANT_MISMATCH: Severity.CRITICAL,
    ConstraintKind.ENVIRONMENT_ESCALATION: Severity.CRITICAL,
    ConstraintKind.EXPIRED: Severity.HIGH,
    ConstraintKind.RESOURCE_NOT_PERMITTED: Severity.HIGH,
    ConstraintKind.NOT_YET_VALID: Severity.HIGH,
    ConstraintKind.EXCESSIVE_LIFETIME: Severity.MODERATE,
    ConstraintKind.UNBOUNDED: Severity.MODERATE,
    ConstraintKind.PURPOSE_MISSING: Severity.LOW,
})

#: Environments ordered by blast radius, least first. A delegation issued at one
#: rank and presented at a HIGHER one is escalation; the reverse is not.
#:
#: An unrecognised environment name ranks ABOVE production rather than below.
#: A deployment with an environment this table has not been taught should have
#: its delegations refused for review, not waved through as harmless -- the safe
#: reading of an unknown blast radius is the worst one.
ENVIRONMENT_RANK: Mapping[str, int] = MappingProxyType({
    "test": 0,
    "dev": 1,
    "development": 1,
    "sandbox": 1,
    "qa": 2,
    "staging": 3,
    "stage": 3,
    "preprod": 3,
    "production": 4,
    "prod": 4,
})

#: Rank given to an environment nobody declared. Above production, for the
#: reason above.
UNKNOWN_ENVIRONMENT_RANK = 5

#: A delegation valid for longer than this is reported. Not refused -- some
#: legitimate automation runs for days -- but a month-long grant to an
#: autonomous agent is a standing credential wearing a delegation's name, and it
#: should appear in a review.
MAX_REASONABLE_LIFETIME = timedelta(days=7)


def environment_rank(name: str) -> int:
    return ENVIRONMENT_RANK.get(name.strip().lower(), UNKNOWN_ENVIRONMENT_RANK)


@dataclass(frozen=True, slots=True)
class DelegationConstraint:
    """What the ISSUER of a delegation restricted it to.

    Every field is optional because a constraint that could not be expressed
    partially would not be adopted at all -- an issuer who knows the expiry but
    not the resource pattern must be able to record the expiry.
    """

    tenant_id: str = ""
    environment: str = ""
    purpose: str = ""
    #: fnmatch patterns. `db://customers/*` permits one table, not the estate.
    resources: tuple[str, ...] = ()
    issued_at: datetime | None = None
    expires_at: datetime | None = None
    #: The policy version in force when this was issued, so a chain can be
    #: replayed against the rules that actually applied to it.
    policy_version: str = ""

    def __post_init__(self) -> None:
        if (
            self.issued_at is not None
            and self.expires_at is not None
            and self.expires_at <= self.issued_at
        ):
            raise ValueError(
                "a delegation that expires at or before it is issued grants "
                "nothing; refusing to construct one rather than let it read as "
                "a valid grant that happens to fail every check"
            )

    @property
    def lifetime(self) -> timedelta | None:
        if self.issued_at is None or self.expires_at is None:
            return None
        return self.expires_at - self.issued_at


@dataclass(frozen=True, slots=True)
class DelegationContext:
    """Where and when a delegation is being PRESENTED. The other half.

    A constraint alone proves nothing: `expires_at` is only meaningful against a
    clock, and `environment` only against the environment the action targets.
    """

    tenant_id: str = ""
    environment: str = ""
    resource: str = ""


@dataclass(frozen=True, slots=True)
class ConstraintFinding:
    kind: ConstraintKind
    detail: str
    #: 1-indexed hop, matching `A2AFinding`. 0 is the chain as a whole.
    hop: int = 0

    @property
    def severity(self) -> Severity:
        return CONSTRAINT_SEVERITY[self.kind]

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "severity": self.severity.value,
            "detail": self.detail,
            "hop": self.hop,
        }


def _resource_permitted(resource: str, patterns: Sequence[str]) -> bool:
    """Does the targeted resource match any permitted pattern?

    `fnmatch`, not a prefix test. A prefix test accepts `db://customers-evil`
    for a permitted `db://customers`, which is the same defect as comparing
    paths by string prefix instead of by component -- and this codebase has
    fixed that once already in `FileSandbox`.
    """
    return any(fnmatch.fnmatchcase(resource, pattern) for pattern in patterns)


def evaluate(
    constraint: DelegationConstraint,
    *,
    context: DelegationContext,
    now: datetime,
    hop: int = 0,
) -> tuple[ConstraintFinding, ...]:
    """Every way this delegation is invalid where it is being presented.

    Returns ALL findings rather than the first. An expired delegation presented
    in the wrong environment is two separate problems with two separate
    remedies, and reporting one hides the other from whoever fixes it.
    """
    findings: list[ConstraintFinding] = []

    def add(kind: ConstraintKind, detail: str) -> None:
        findings.append(ConstraintFinding(kind=kind, detail=detail, hop=hop))

    # ── tenant ───────────────────────────────────────────────────────────────
    if constraint.tenant_id and context.tenant_id:
        if constraint.tenant_id != context.tenant_id:
            add(
                ConstraintKind.TENANT_MISMATCH,
                f"issued for tenant {constraint.tenant_id!r}, presented in "
                f"{context.tenant_id!r}: authority that never existed here",
            )

    # ── time ─────────────────────────────────────────────────────────────────
    if constraint.expires_at is None:
        add(
            ConstraintKind.UNBOUNDED,
            "no expiry recorded: this delegation does not end. Reported rather "
            "than refused, so grants issued before expiry existed still work — "
            "but an unbounded grant to an autonomous agent belongs in a review",
        )
    else:
        if constraint.expires_at <= now:
            overdue = now - constraint.expires_at
            add(
                ConstraintKind.EXPIRED,
                f"expired {overdue} ago, at {constraint.expires_at.isoformat()}",
            )
        lifetime = constraint.lifetime
        if lifetime is not None and lifetime > MAX_REASONABLE_LIFETIME:
            add(
                ConstraintKind.EXCESSIVE_LIFETIME,
                f"valid for {lifetime}, over the {MAX_REASONABLE_LIFETIME} at "
                "which a delegation stops being a task grant and becomes a "
                "standing credential",
            )

    if constraint.issued_at is not None and constraint.issued_at > now:
        add(
            ConstraintKind.NOT_YET_VALID,
            f"issued at {constraint.issued_at.isoformat()}, which is in the "
            "future: either a forged timestamp or a clock this deployment "
            "cannot reconcile. Neither is a delegation to honour",
        )

    # ── environment ──────────────────────────────────────────────────────────
    if constraint.environment and context.environment:
        issued = environment_rank(constraint.environment)
        presented = environment_rank(context.environment)
        if presented > issued:
            add(
                ConstraintKind.ENVIRONMENT_ESCALATION,
                f"issued against {constraint.environment!r} and presented "
                f"against {context.environment!r}. Scope checking cannot see "
                "this: the same capability string means a different blast "
                "radius in each",
            )

    # ── resource ─────────────────────────────────────────────────────────────
    if constraint.resources and context.resource:
        if not _resource_permitted(context.resource, constraint.resources):
            add(
                ConstraintKind.RESOURCE_NOT_PERMITTED,
                f"{context.resource!r} matches none of "
                f"{list(constraint.resources)}. A scope names a verb, not an "
                "object; this is the check that says which object",
            )

    # ── purpose ──────────────────────────────────────────────────────────────
    if not constraint.purpose.strip():
        add(
            ConstraintKind.PURPOSE_MISSING,
            "no declared purpose: nothing to compare later behaviour against, "
            "so intent divergence cannot be assessed for this delegation",
        )

    return tuple(findings)
