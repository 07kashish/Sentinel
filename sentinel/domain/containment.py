"""The emergency kill switch: six scopes, tenant-authorized, revocable.

WHAT WAS ALREADY HERE, AND WHY IT IS NOT THIS
-----------------------------------------------
`ProtectControls.kill_switch` is a process-local boolean read from
`SENTINEL_PROTECT_KILL_SWITCH` at startup. It works, and it is the right tool
for exactly one job: an operator with shell access halting a runaway
deployment.

It cannot do any of the six things §35 asks for. It is not tenant-scoped -- one
tenant's emergency stops every tenant sharing the process. It is not granular
-- there is no way to say "this one agent" or "this one MCP server". It is not
revocable at runtime, because changing it means an environment change and a
restart, which is the wrong shape for a control whose whole purpose is speed.
And its activation is invisible: a boolean in an environment variable records
nobody's name and no reason.

So this module is the operator-facing kill switch and that one stays as the
process-level halt. Both exist because they answer different questions.

FAIL-OPEN ON THE LOOKUP, DELIBERATELY
---------------------------------------
If the containment store cannot be read, this module reports "no containment
found" rather than "contain everything". That looks like the wrong default for
a security control, so it is worth being explicit about the reasoning.

Containment is a *deny* list. Failing closed on an unreadable deny list means a
database blip halts every agent in every tenant -- the store being briefly
unavailable becomes a total outage, and the blast radius of a transient fault is
larger than the attack the control defends against. The enforcement path already
fails closed on its own errors; that is where fail-closed belongs, because there
the failure is scoped to one request instead of to the estate.

The caller is expected to log the lookup failure loudly. A kill switch that is
silently not working is worse than one that is loudly not working.

EXPIRY EXISTS BECAUSE EMERGENCIES END
---------------------------------------
Every containment carries an optional expiry. An incident at 3am produces a
`pause_high_risk` that nobody remembers to lift, and three weeks later a team is
debugging why their agents are slow. An expiring containment turns that from a
silent permanent state into a decision somebody has to re-make.

A containment with no expiry is allowed -- some are genuinely indefinite -- but
it is a choice made at creation rather than the only available shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Sequence

from sentinel.domain.errors import DomainRuleViolated

__all__ = [
    "ContainmentScope",
    "Containment",
    "ContainmentDecision",
    "InvalidContainment",
    "MAX_SELECTOR_LENGTH",
    "MAX_REASON_LENGTH",
    "evaluate_containment",
]

#: Selectors are agent ids, tool names, MCP server ids and credential
#: fingerprints. All are short. The cap stops a caller storing a document in a
#: field that is compared on every enforcement decision.
MAX_SELECTOR_LENGTH: int = 256

#: The reason is written by an operator under time pressure and read by whoever
#: picks the incident up next. Long enough for a sentence and an incident link.
MAX_REASON_LENGTH: int = 1024


class InvalidContainment(DomainRuleViolated):
    """A containment that could not do what it claims."""

    is_retryable = False


class ContainmentScope(str, Enum):
    """The six controls §35 enumerates, and nothing else.

    A closed set rather than a free-text scope. Every member here has a matching
    branch in `_matches`, so adding a scope without teaching the matcher about it
    is a change that fails rather than a containment that silently never fires --
    the defect class this repository has found more often than any other.
    """

    #: Disable one agent.
    AGENT = "agent"
    #: Disable a named group of agents.
    AGENT_GROUP = "agent_group"
    #: Disable one tool, for every agent.
    TOOL = "tool"
    #: Disable one MCP server, for every agent.
    MCP_SERVER = "mcp_server"
    #: Block a credential by its fingerprint.
    CREDENTIAL = "credential"
    #: Pause every agent currently classed high-risk. The only scope with no
    #: selector: it names a condition, not a thing.
    HIGH_RISK_AGENTS = "high_risk_agents"

    @property
    def needs_selector(self) -> bool:
        return self is not ContainmentScope.HIGH_RISK_AGENTS


@dataclass(frozen=True, slots=True)
class Containment:
    """One active block, and the record of who put it there.

    Frozen: lifting a containment is a new record with `revoked_at` set, not a
    mutation of this one. An audit that can be edited in place answers "what is
    blocked now" and loses "what was blocked at 03:14, and by whom".
    """

    containment_id: str
    tenant_id: str
    scope: ContainmentScope
    #: What is blocked. Empty exactly when the scope is HIGH_RISK_AGENTS.
    selector: str
    #: Who authorized it. Never blank -- a kill switch with no name attached is
    #: an outage with no owner.
    created_by: str
    created_at: str
    reason: str = ""
    #: ISO-8601. Empty means indefinite; see the module docstring.
    expires_at: str = ""
    revoked_at: str = ""
    revoked_by: str = ""

    def __post_init__(self) -> None:
        if not self.tenant_id:
            raise InvalidContainment("a containment must belong to a tenant")
        if not self.created_by.strip():
            raise InvalidContainment(
                "a containment must record who authorized it; "
                "an unattributed kill switch is an outage with no owner"
            )
        selector = self.selector.strip()
        if self.scope.needs_selector and not selector:
            raise InvalidContainment(
                f"scope {self.scope.value!r} blocks a specific thing and needs a selector"
            )
        if not self.scope.needs_selector and selector:
            # A selector here would read as though it narrowed the scope. It does
            # not, and a control that appears narrower than it is is how an
            # operator pauses the estate believing they paused one team.
            raise InvalidContainment(
                f"scope {self.scope.value!r} takes no selector; it applies to every "
                f"agent currently classed high-risk"
            )
        if len(selector) > MAX_SELECTOR_LENGTH:
            raise InvalidContainment(
                f"selector exceeds {MAX_SELECTOR_LENGTH} characters"
            )
        if len(self.reason) > MAX_REASON_LENGTH:
            raise InvalidContainment(f"reason exceeds {MAX_REASON_LENGTH} characters")

    @property
    def is_revoked(self) -> bool:
        return bool(self.revoked_at)

    def is_expired(self, now: str) -> bool:
        """Expiry compared as ISO-8601 strings.

        Sound only because every timestamp in this system is UTC with a `Z`
        suffix and fixed-width fields, which makes lexicographic order the same
        as chronological order. Stated rather than assumed, because the day
        someone stores a `+05:30` offset this comparison silently starts
        answering a different question.
        """
        return bool(self.expires_at) and self.expires_at <= now

    def is_active(self, now: str) -> bool:
        return not self.is_revoked and not self.is_expired(now)

    def as_dict(self) -> dict[str, Any]:
        return {
            "containment_id": self.containment_id,
            "tenant_id": self.tenant_id,
            "scope": self.scope.value,
            "selector": self.selector,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "reason": self.reason,
            "expires_at": self.expires_at,
            "revoked_at": self.revoked_at,
            "revoked_by": self.revoked_by,
        }


@dataclass(frozen=True, slots=True)
class ContainmentDecision:
    """Whether this call is blocked, and by which record.

    The matching containment travels with the answer. "Blocked" alone sends an
    operator hunting through a list to find out why their agent stopped; the id,
    the scope and the reason turn that into one line in an error message.
    """

    blocked: bool = False
    containment: Containment | None = None
    matched: tuple[Containment, ...] = field(default_factory=tuple)

    @property
    def reason(self) -> str:
        if self.containment is None:
            return ""
        scope = self.containment.scope.value
        detail = self.containment.reason or "no reason recorded"
        return (
            f"contained by {self.containment.containment_id} "
            f"(scope={scope}, by={self.containment.created_by}): {detail}"
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "blocked": self.blocked,
            "reason": self.reason,
            "containment": self.containment.as_dict() if self.containment else None,
            "match_count": len(self.matched),
        }


def _matches(
    containment: Containment,
    *,
    agent_id: str,
    agent_groups: frozenset[str],
    tool: str,
    mcp_server: str,
    credential: str,
    agent_is_high_risk: bool,
) -> bool:
    """Exact matching, never prefix or substring.

    A substring match would make a containment on agent `bot` block `chatbot-7`
    and `robot-billing`. Over-blocking is the failure mode operators forgive
    least, because it looks exactly like the product being broken.
    """
    scope = containment.scope
    selector = containment.selector

    if scope is ContainmentScope.AGENT:
        return bool(agent_id) and agent_id == selector
    if scope is ContainmentScope.AGENT_GROUP:
        return selector in agent_groups
    if scope is ContainmentScope.TOOL:
        return bool(tool) and tool == selector
    if scope is ContainmentScope.MCP_SERVER:
        return bool(mcp_server) and mcp_server == selector
    if scope is ContainmentScope.CREDENTIAL:
        return bool(credential) and credential == selector
    if scope is ContainmentScope.HIGH_RISK_AGENTS:
        return agent_is_high_risk
    # Unreachable while ContainmentScope stays closed. Returning False rather
    # than raising: a new scope should fail to block, not fail the request --
    # but the test suite asserts every scope has a branch, so it should not
    # reach here at all.
    return False


def evaluate_containment(
    containments: Iterable[Containment],
    *,
    now: str,
    agent_id: str = "",
    agent_groups: Sequence[str] = (),
    tool: str = "",
    mcp_server: str = "",
    credential: str = "",
    agent_is_high_risk: bool = False,
) -> ContainmentDecision:
    """Decide whether an action is blocked by any active containment.

    Pure. Takes the containments rather than fetching them, so the decision can
    be tested without a database and so the enforcement path controls when the
    read happens.

    `agent_is_high_risk` is passed in rather than derived here. Risk
    classification belongs to the risk engine, and a containment module that
    computed its own would be a second, quietly diverging definition of
    "high-risk" -- the exact duplication `Severity.priority` exists to prevent.
    """
    groups = frozenset(g for g in agent_groups if g)
    matched = tuple(
        c
        for c in containments
        if c.is_active(now)
        and _matches(
            c,
            agent_id=agent_id,
            agent_groups=groups,
            tool=tool,
            mcp_server=mcp_server,
            credential=credential,
            agent_is_high_risk=agent_is_high_risk,
        )
    )
    if not matched:
        return ContainmentDecision()

    # Report the narrowest match first. When an agent is blocked both by its own
    # id and by an estate-wide pause, the useful answer is the specific one --
    # it is the one an operator can lift without re-opening the whole estate.
    order = {
        ContainmentScope.AGENT: 0,
        ContainmentScope.CREDENTIAL: 1,
        ContainmentScope.TOOL: 2,
        ContainmentScope.MCP_SERVER: 3,
        ContainmentScope.AGENT_GROUP: 4,
        ContainmentScope.HIGH_RISK_AGENTS: 5,
    }
    narrowest = min(matched, key=lambda c: (order[c.scope], c.containment_id))
    return ContainmentDecision(blocked=True, containment=narrowest, matched=matched)
