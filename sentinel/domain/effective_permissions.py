"""What an agent can ACTUALLY reach, versus what somebody configured.

THE GAP THIS CLOSES
-------------------
`agent_tool_grants` answers "what was this agent granted". Every access review
that reads it concludes the agent can do those things and nothing else, and that
conclusion is wrong in three specific ways:

  1. DELEGATION. An agent handed scopes through an A2A chain holds them without
     any grant row existing. The grant table shows nothing; the agent can act.
  2. A SHARED CREDENTIAL. Two agents presenting the same credential are, to
     every system downstream, the same principal. Whatever one can reach, the
     other can -- and no row anywhere says so, because the fact lives in the
     pairing of two rows that were each written innocently.
  3. OBSERVED REACH. An agent that has demonstrably touched a resource can
     touch it, whatever the configuration says. A grant table disagreeing with
     observed behaviour is not evidence the behaviour did not happen.

So the configured set is a floor, not a ceiling, and the number an access review
needs is the transitive closure. This module computes it.

EVERY REACHABLE ITEM CARRIES ITS PROVENANCE
---------------------------------------------
`ReachPath` says WHY something is reachable and through how many hops. A closure
that returned a flat set would tell a reviewer that an agent can reach a
production database and give them no way to find out how -- and "how" is the
only part they can act on. Revoking a grant does nothing when the reach came
from a shared credential.

WHAT THIS IS NOT
----------------
It is not a proof of unreachability. Absence from the closure means "no path was
found in the facts supplied", never "no path exists" -- the inputs are one
tenant's recorded grants, delegations, credentials and observations, and a path
through a system Sentinel has no record of is invisible here. `EffectiveReach`
carries that sentence in its own output rather than leaving it to a document.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Iterable, Mapping

__all__ = [
    "EffectiveReach",
    "ReachPath",
    "ReachSource",
    "Recommendation",
    "compute_effective_reach",
    "RecommendationAction",
    "recommend_least_privilege",
]

#: How deep the closure may walk. A chain longer than this is a topology nobody
#: designed, and following it forever on caller-supplied edges is a way to hang
#: a review. The bound is REPORTED when it truncates rather than applied
#: silently -- a closure that quietly stopped early would understate reach,
#: which is the one direction an access review must not be wrong in.
MAX_HOPS = 6


class ReachSource(str, Enum):
    """Why something is reachable. Ordered by how directly a reviewer can act.

    `GRANT` is revocable in one operation. `SHARED_CREDENTIAL` needs the
    credential rotated or split, which is a bigger change and is why it is worth
    naming separately rather than folding into a generic "indirect".
    """

    GRANT = "grant"
    DELEGATION = "delegation"
    SHARED_CREDENTIAL = "shared_credential"
    OBSERVED = "observed"


#: How much each source contributes to concern. A grant is a decision somebody
#: made; reach that arrives through a shared credential is reach nobody chose,
#: which is why it scores higher despite conferring the same access.
#: `MappingProxyType`, not a bare dict: this decides how much an access-review
#: finding weighs, and `test_there_is_no_mutable_module_level_state` rejects a
#: module-level dict literal for exactly that reason -- "any import could edit
#: it" is not a property a scoring table should have.
SOURCE_CONCERN: Mapping[ReachSource, int] = MappingProxyType({
    ReachSource.GRANT: 0,
    ReachSource.OBSERVED: 10,
    ReachSource.DELEGATION: 20,
    ReachSource.SHARED_CREDENTIAL: 35,
})


@dataclass(frozen=True, slots=True)
class ReachPath:
    """One reachable capability and the route to it."""

    capability: str
    source: ReachSource
    #: The agents between this one and the capability, in order. Empty for a
    #: direct grant.
    via: tuple[str, ...] = ()
    detail: str = ""

    @property
    def hops(self) -> int:
        return len(self.via)

    @property
    def is_direct(self) -> bool:
        return self.source is ReachSource.GRANT and not self.via

    def as_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability,
            "source": self.source.value,
            "via": list(self.via),
            "hops": self.hops,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class EffectiveReach:
    """The closure for one agent, with its provenance and its own limits."""

    agent_id: str
    paths: tuple[ReachPath, ...]
    #: Reach found beyond `MAX_HOPS`, abandoned. Non-empty means this result
    #: UNDERSTATES reach, and that is said rather than implied.
    truncated_at: tuple[str, ...] = ()

    limits: str = field(
        default=(
            "Absence from this list means no path was found in the facts "
            "supplied -- recorded grants, delegations, credentials and "
            "observations for one tenant. It is NOT proof that no path exists: "
            "a route through a system Sentinel has no record of is invisible "
            "here."
        ),
        compare=False,
    )

    @property
    def capabilities(self) -> tuple[str, ...]:
        return tuple(sorted({p.capability for p in self.paths}))

    @property
    def direct(self) -> tuple[str, ...]:
        return tuple(sorted({p.capability for p in self.paths if p.is_direct}))

    @property
    def indirect(self) -> tuple[str, ...]:
        """Reachable WITHOUT a grant saying so. The number a review is missing."""
        granted = set(self.direct)
        return tuple(
            sorted({p.capability for p in self.paths if p.capability not in granted})
        )

    @property
    def concern(self) -> int:
        """A bounded, explainable score. Every point traces to a named path."""
        by_capability: dict[str, int] = {}
        for path in self.paths:
            points = SOURCE_CONCERN[path.source]
            # The WORST route to a capability decides its contribution. A
            # capability reachable both by grant and by a shared credential is a
            # shared-credential problem; scoring it as a grant would hide that.
            by_capability[path.capability] = max(
                by_capability.get(path.capability, 0), points
            )
        return min(100, sum(by_capability.values()))

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "capabilities": list(self.capabilities),
            "direct": list(self.direct),
            "indirect": list(self.indirect),
            "concern": self.concern,
            "paths": [p.as_dict() for p in self.paths],
            "truncated_at": list(self.truncated_at),
            "limits": self.limits,
        }


def compute_effective_reach(
    agent_id: str,
    *,
    grants: Mapping[str, Iterable[str]],
    delegations: Mapping[str, Iterable[str]] | None = None,
    credentials: Mapping[str, Iterable[str]] | None = None,
    observed: Mapping[str, Iterable[str]] | None = None,
    max_hops: int = MAX_HOPS,
) -> EffectiveReach:
    """Walk every route from `agent_id` to a capability.

    `grants`      agent -> capabilities explicitly granted
    `delegations` agent -> agents it may delegate to
    `credentials` credential -> agents that present it
    `observed`    agent -> capabilities it has actually exercised

    Breadth-first, so the route recorded for a capability is the SHORTEST one
    found. A reviewer shown a six-hop path to something also reachable in one
    would spend their time on the wrong link.
    """
    delegation_map = {k: tuple(v) for k, v in (delegations or {}).items()}
    grant_map = {k: tuple(v) for k, v in grants.items()}
    observed_map = {k: tuple(v) for k, v in (observed or {}).items()}

    # Invert the credential map into agent -> peers sharing a credential with it.
    peers: dict[str, set[str]] = {}
    for credential, holders in (credentials or {}).items():
        members = tuple(holders)
        for member in members:
            peers.setdefault(member, set()).update(
                other for other in members if other != member
            )

    paths: list[ReachPath] = []
    #: Keyed by (capability, SOURCE), not by capability alone.
    #:
    #: Deduping on the capability would keep only the shortest route and drop
    #: every other way in -- so a capability that is BOTH granted directly and
    #: reachable through a shared credential would be recorded as a plain grant.
    #: That is the reviewer's worst case: they revoke the grant, believe the
    #: reach is gone, and it is not. One route per source, shortest of each.
    seen_route: set[tuple[str, ReachSource]] = set()
    truncated: list[str] = []

    def _add(capability: str, source: ReachSource, via: tuple[str, ...], detail: str):
        # First route for this (capability, source) wins, and BFS means the
        # first is the shortest.
        key = (capability, source)
        if key in seen_route:
            return
        seen_route.add(key)
        paths.append(
            ReachPath(capability=capability, source=source, via=via, detail=detail)
        )

    for capability in grant_map.get(agent_id, ()):
        _add(capability, ReachSource.GRANT, (), "granted directly")
    for capability in observed_map.get(agent_id, ()):
        _add(
            capability,
            ReachSource.OBSERVED,
            (),
            "exercised in recorded activity, whatever the grant table says",
        )

    # (agent, route-so-far, how it was reached)
    queue: deque[tuple[str, tuple[str, ...], ReachSource]] = deque()
    visited: set[str] = {agent_id}

    for peer in sorted(peers.get(agent_id, ())):
        queue.append((peer, (peer,), ReachSource.SHARED_CREDENTIAL))
    for target in delegation_map.get(agent_id, ()):
        queue.append((target, (target,), ReachSource.DELEGATION))

    while queue:
        current, via, source = queue.popleft()
        if len(via) > max_hops:
            truncated.append(" -> ".join(via))
            continue
        if current in visited:
            continue
        visited.add(current)

        reason = (
            "shares a credential with " + via[0]
            if source is ReachSource.SHARED_CREDENTIAL
            else "delegated through " + " -> ".join(via)
        )
        for capability in grant_map.get(current, ()):
            _add(capability, source, via, f"{reason}, which holds this grant")
        for capability in observed_map.get(current, ()):
            _add(capability, source, via, f"{reason}, which has exercised this")

        for peer in sorted(peers.get(current, ())):
            queue.append((peer, via + (peer,), ReachSource.SHARED_CREDENTIAL))
        for target in delegation_map.get(current, ()):
            queue.append((target, via + (target,), source))

    return EffectiveReach(
        agent_id=agent_id,
        paths=tuple(
            sorted(paths, key=lambda p: (-SOURCE_CONCERN[p.source], p.capability))
        ),
        truncated_at=tuple(sorted(set(truncated))),
    )


class RecommendationAction(str, Enum):
    """What the reviewer is being told.

    A `str` Enum so existing comparisons against the literal strings keep
    working, but a closed set so a typo in an action name is a failure at
    import rather than a recommendation nothing downstream matches.
    """

    #: Held and not exercised. An inference from ABSENCE -- only as sound as
    #: the completeness of the activity record.
    REVOKE_GRANT = "revoke_grant"
    #: Exercised while holding no grant. An inference from PRESENCE, and either
    #: a stale grant table or an authorization bypass.
    USED_WITHOUT_GRANT = "used_without_grant"
    #: The window is too short to infer anything from absence.
    INSUFFICIENT_HISTORY = "insufficient_history"
    #: The window was long enough but the activity record has holes.
    INCOMPLETE_ACTIVITY_RECORD = "incomplete_activity_record"


@dataclass(frozen=True, slots=True)
class Recommendation:
    """One suggested permission change. A PROPOSAL, never an applied action."""

    agent_id: str
    capability: str
    action: RecommendationAction
    reason: str

    @property
    def is_security_finding(self) -> bool:
        """True when this is something that already happened.

        An unused grant is latent risk to be reviewed at leisure. An ungranted
        use is an event, and the two must not arrive in one undifferentiated
        list where the urgent item sorts alphabetically among the routine ones.
        """
        return self.action is RecommendationAction.USED_WITHOUT_GRANT

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "capability": self.capability,
            "action": self.action.value,
            "reason": self.reason,
            "is_security_finding": self.is_security_finding,
        }


def recommend_least_privilege(
    agent_id: str,
    *,
    granted: Iterable[str],
    used: Iterable[str],
    observation_window_days: int,
    activity_complete: bool = True,
    minimum_window_days: int = 30,
) -> tuple[Recommendation, ...]:
    """Grants an agent holds and has not exercised, and uses it never held.

    NOTHING IS APPLIED. These are proposals for a human, and that is not
    timidity: an agent that runs quarterly has used nothing this month, and
    revoking on that basis breaks it on the one day of the year it matters.

    TWO DIRECTIONS, WITH DIFFERENT EVIDENCE REQUIREMENTS
    ----------------------------------------------------
    A revocation is an inference from ABSENCE -- "we never saw it used" -- so
    it is only as sound as the record it is drawn from. Both a window shorter
    than `minimum_window_days` and an incomplete activity record suppress every
    revocation, because a removal list that looks actionable invites somebody
    to act on it.

    An ungranted use is an inference from PRESENCE. Seeing the call is positive
    evidence and a gap in the record cannot un-see it, so those findings
    survive weak coverage and are returned in every case. They are also the
    more urgent half: an unused grant is latent risk, an ungranted use already
    happened and means either a stale grant table or an authorization bypass.

    `activity_complete` is a keyword with a default of True only because every
    existing caller passes a complete record; a caller drawing from telemetry
    that dropped MUST pass False, and the docstring says so here rather than
    leaving the optimistic default to be discovered.
    """
    held = set(granted)
    exercised = set(used)

    # Computed first and returned in every branch below. Dropping these was the
    # original defect: the set difference in the other direction is the only
    # signal in this function that describes something that already occurred.
    ungranted = tuple(
        Recommendation(
            agent_id=agent_id,
            capability=capability,
            action=RecommendationAction.USED_WITHOUT_GRANT,
            reason=(
                f"{capability} was exercised with no grant recorded for it. "
                "Either the grant table is stale or authorization was bypassed; "
                "this describes something that already happened, so it is not "
                "suppressed by a short window or an incomplete record."
            ),
        )
        for capability in sorted(exercised - held)
    )

    if observation_window_days < minimum_window_days:
        return ungranted + (
            Recommendation(
                agent_id=agent_id,
                capability="",
                action=RecommendationAction.INSUFFICIENT_HISTORY,
                reason=(
                    f"observed for {observation_window_days} days, under the "
                    f"{minimum_window_days}-day minimum. An agent that runs "
                    "quarterly has used nothing this month; a removal list built "
                    "on this window would break it on the day it matters."
                ),
            ),
        )

    if not activity_complete:
        return ungranted + (
            Recommendation(
                agent_id=agent_id,
                capability="",
                action=RecommendationAction.INCOMPLETE_ACTIVITY_RECORD,
                reason=(
                    f"the window of {observation_window_days} days is long "
                    "enough, but the activity record has holes. Every "
                    "revocation here would be an inference from an absence that "
                    "may only be missing telemetry, so none is offered. The "
                    "uses observed are still reported."
                ),
            ),
        )

    return ungranted + tuple(
        Recommendation(
            agent_id=agent_id,
            capability=capability,
            action=RecommendationAction.REVOKE_GRANT,
            reason=(
                f"granted but not exercised in {observation_window_days} days "
                "of recorded activity"
            ),
        )
        for capability in sorted(held - exercised)
    )
