"""Agent-to-agent delegation: who authorised the action at the end of the chain.

THE QUESTION THIS MODULE EXISTS TO ANSWER
-------------------------------------------
When a Finance Agent asks a Research Agent to fetch a document, and the Research
Agent calls an MCP tool that reads customer records, the record of that read says
`research-agent`. That is true and it is useless. The authority came from an
employee who asked for a quarterly report, through two agents, and the only
question an incident review has is whether that employee's authority actually
extended this far.

`execution_graph.py` records that the calls happened. This module records what
each hop was ENTITLED to, and refuses the ones that were not.

WHY DELEGATION IS NOT JUST ANOTHER EDGE
-----------------------------------------
An edge in the execution graph is an observation: this happened. A delegation
hop is a CLAIM: I am permitted to ask you to do this, on behalf of someone who
permitted me. Claims can be false, and the failure modes are specific:

  * PRIVILEGE AMPLIFICATION -- an agent grants a scope it does not itself hold.
    This is the one that matters most, because it is how a chain of individually
    reasonable delegations ends somewhere nobody authorised. It is also the one
    a graph cannot see: every hop looks locally fine.
  * DELEGATION LOOP -- A asks B asks A. Unbounded work, and an authority
    laundering primitive: each pass can widen scope if nothing checks.
  * ROGUE SPAWN -- delegation to an agent nobody enrolled.
  * CARD DRIFT -- the target agent's advertised capabilities changed after it
    was approved. Same failure as MCP tool-definition drift, same fix: pin the
    fingerprint and compare.
  * DEPTH -- a chain long enough that no human reviewing the first hop could
    have anticipated the last.
  * TASK REPLAY -- the same task id presented twice, so one approval performs
    two actions.

MONOTONIC NARROWING IS THE RULE
---------------------------------
Authority may narrow along a chain and may never widen. `effective_scopes` is
therefore an intersection, not a union, and `find_amplification` compares each
hop's grant against what the delegator actually held at that point -- not
against what the original principal held, which would let an agent regain scope
a previous hop had already dropped.

THIS MODULE DECIDES NOTHING
---------------------------
It returns findings. `A2AGateway` projects them onto the event payload the
deterministic policy already understands, exactly as `McpGateway` does, so there
is one rule set and no second place for the two paths to disagree.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Final, Iterable, Mapping, Sequence

from sentinel.domain.errors import DomainRuleViolated

__all__ = [
    "A2AFinding",
    "A2AFindingKind",
    "A2ARuleViolated",
    "AgentCard",
    "DelegationChain",
    "DelegationHop",
    "MAX_DELEGATION_DEPTH",
    "Severity",
    "card_fingerprint",
    "scope_covers",
]

#: How many hops a chain may have before the last one is beyond anything the
#: human at the start could have anticipated. Four is the shipped default: an
#: employee, an orchestrator, a specialist and a tool-runner is a real topology;
#: a fifth hop is a chain nobody drew on a whiteboard.
MAX_DELEGATION_DEPTH: Final[int] = 4

#: A scope name. Deliberately narrow: scopes are identifiers that get compared,
#: and an identifier containing whitespace or a separator is one that can be
#: made to compare equal to something it is not.
_SCOPE_RE = re.compile(r"^[a-z0-9_]+(:[a-z0-9_*-]+)*$")

#: An agent id. Same reasoning, and it is a graph key.
_AGENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class A2ARuleViolated(DomainRuleViolated):
    """A delegation broke a structural rule. Not retryable without an operator.

    Every violation here means a chain was malformed or an agent claimed
    authority it did not hold. Neither becomes true on a second attempt, and a
    retryable classification would turn a refused amplification into a refused
    amplification repeated until something gives.
    """

    is_retryable = False


class Severity(str, Enum):
    """How much a finding matters. Ordered, and the order is used."""

    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


_SEVERITY_ORDER: Final[tuple[Severity, ...]] = (
    Severity.LOW,
    Severity.MODERATE,
    Severity.HIGH,
    Severity.CRITICAL,
)


def worst(severities: Iterable[Severity]) -> Severity:
    """The highest severity present, or LOW for an empty set."""
    found = list(severities)
    if not found:
        return Severity.LOW
    return max(found, key=_SEVERITY_ORDER.index)


class A2AFindingKind(str, Enum):
    """The named failure modes. One enum member per thing that can go wrong.

    Named rather than free text because these reach policy as
    `metadata.a2a.findings`, and a rule matching on a string an author typed
    twice is a rule that silently stops matching when someone fixes a typo.
    """

    PRIVILEGE_AMPLIFICATION = "privilege_amplification"
    DELEGATION_LOOP = "delegation_loop"
    DEPTH_EXCEEDED = "depth_exceeded"
    UNENROLLED_AGENT = "unenrolled_agent"
    CARD_DRIFT = "card_drift"
    CAPABILITY_NOT_ADVERTISED = "capability_not_advertised"
    TASK_REPLAY = "task_replay"
    SELF_DELEGATION = "self_delegation"
    UNKNOWN_PRINCIPAL = "unknown_principal"


#: Severity per finding kind. A table rather than a field on each finding, so
#: the severity of privilege amplification is decided in ONE place and an author
#: constructing a finding cannot understate it.
#:
#: `MappingProxyType`, not a bare dict: this decides how serious an authority
#: violation is, and `test_architecture_rules.py` rejects module-level mutable
#: state for exactly this reason.
FINDING_SEVERITY: Mapping[A2AFindingKind, Severity] = MappingProxyType({
    A2AFindingKind.PRIVILEGE_AMPLIFICATION: Severity.CRITICAL,
    A2AFindingKind.DELEGATION_LOOP: Severity.HIGH,
    A2AFindingKind.DEPTH_EXCEEDED: Severity.MODERATE,
    A2AFindingKind.UNENROLLED_AGENT: Severity.CRITICAL,
    A2AFindingKind.CARD_DRIFT: Severity.HIGH,
    A2AFindingKind.CAPABILITY_NOT_ADVERTISED: Severity.HIGH,
    A2AFindingKind.TASK_REPLAY: Severity.HIGH,
    A2AFindingKind.SELF_DELEGATION: Severity.MODERATE,
    A2AFindingKind.UNKNOWN_PRINCIPAL: Severity.CRITICAL,
})


@dataclass(frozen=True, slots=True)
class A2AFinding:
    """One thing wrong with a delegation, and enough detail to act on it."""

    kind: A2AFindingKind
    detail: str
    #: Which hop, 1-indexed. 0 means the finding is about the chain as a whole.
    hop: int = 0

    @property
    def severity(self) -> Severity:
        return FINDING_SEVERITY[self.kind]

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "severity": self.severity.value,
            "detail": self.detail,
            "hop": self.hop,
        }


# ── Scopes ───────────────────────────────────────────────────────────────────


def _validate(value: str, *, pattern: re.Pattern[str], label: str) -> str:
    text = str(value or "").strip()
    if not pattern.fullmatch(text):
        raise A2ARuleViolated(f"{label} {value!r} is not a valid {label}")
    return text


def scope_covers(held: str, requested: str) -> bool:
    """Does `held` authorise `requested`?

    Exact match, or a trailing `*` segment covering the rest. `read:*` covers
    `read:customers`; `read:customers` does NOT cover `read:customers:pii`,
    because a scope that covered everything beneath it would make narrowing
    impossible to express -- and narrowing is the only direction authority is
    allowed to move.

    The wildcard matches whole SEGMENTS, not a string prefix. `read:cust*` is
    not a pattern; it is a scope name that happens to end in a star, and
    treating it as a prefix would let `read:cust*` cover `read:customers:pii`
    through a grant nobody wrote.
    """
    if held == requested:
        return True
    if not held.endswith(":*"):
        return False
    prefix = held[:-1]  # keep the trailing ':'
    remainder = requested[len(prefix):] if requested.startswith(prefix) else ""
    return bool(remainder) and ":" not in remainder


def narrow(held: Iterable[str], granted: Iterable[str]) -> tuple[str, ...]:
    """The scopes a delegate actually ends up with: an INTERSECTION.

    Not a union, and not the grant taken at face value. A hop may hand on less
    than it holds and may never hand on more, so what survives is exactly the
    granted scopes that the delegator was covered for.
    """
    holder = tuple(held)
    return tuple(
        sorted(
            {
                scope
                for scope in granted
                if any(scope_covers(h, scope) for h in holder)
            }
        )
    )


# ── Agent cards ──────────────────────────────────────────────────────────────


def card_fingerprint(payload: Mapping[str, Any]) -> str:
    """A stable hash over an agent card's SECURITY-RELEVANT fields.

    Deliberately not a hash of the whole document. A card carries a description
    and a display name that a publisher may reword without changing what the
    agent can do, and fingerprinting those would produce drift alerts nobody can
    action -- which is how a drift alert comes to be ignored.

    What IS fingerprinted is what changes the agent's reach: its id, its
    version, its endpoint, and the capabilities it advertises. Sorted, so key
    order in the source document cannot change the answer.
    """
    material = {
        "agent_id": str(payload.get("agent_id") or payload.get("agentId") or ""),
        "version": str(payload.get("version") or ""),
        "endpoint": str(payload.get("endpoint") or "").lower(),
        "capabilities": sorted(
            str(c) for c in (payload.get("capabilities") or ())
        ),
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class AgentCard:
    """What an agent advertises it can do, and the fingerprint that pins it.

    The A2A analogue of `McpToolDefinition`, and it exists for the same reason:
    a name is not an identity. An agent enrolled as `research-agent` advertising
    `read:docs` on Monday and `read:customers` on Friday presents the same name
    to the same allowlist, and only a fingerprint over the capabilities catches
    it.
    """

    agent_id: str
    version: str
    endpoint: str
    capabilities: frozenset[str]
    #: Prose the publisher supplies. NOT fingerprinted -- see `card_fingerprint`
    #: -- and never trusted: it is attacker-influenced text that a model reads,
    #: so it goes to the injection detector like an MCP tool description does.
    description: str = ""

    def __post_init__(self) -> None:
        _validate(self.agent_id, pattern=_AGENT_RE, label="agent id")
        for capability in self.capabilities:
            _validate(capability, pattern=_SCOPE_RE, label="capability")

    @property
    def fingerprint(self) -> str:
        return card_fingerprint(
            {
                "agent_id": self.agent_id,
                "version": self.version,
                "endpoint": self.endpoint,
                "capabilities": sorted(self.capabilities),
            }
        )

    def advertises(self, scope: str) -> bool:
        return any(scope_covers(c, scope) for c in self.capabilities)

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "version": self.version,
            "endpoint": self.endpoint,
            "capabilities": sorted(self.capabilities),
            "fingerprint": self.fingerprint,
        }


# ── Delegation ───────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class DelegationHop:
    """One agent handing authority to another, with the scopes it granted."""

    from_agent: str
    to_agent: str
    granted: frozenset[str]
    #: The task this hop authorises. Carried so a replay of the same task id can
    #: be recognised, and so an investigator can tie a hop to what was asked.
    task_id: str = ""
    #: The instruction text passed across the hop. Attacker-influenced prose on
    #: the instruction path -- the cross-agent injection surface -- and it is
    #: never inspected here. `A2AGateway` sends it to the same detector the MCP
    #: tool description goes to.
    instruction: str = ""

    def __post_init__(self) -> None:
        _validate(self.from_agent, pattern=_AGENT_RE, label="agent id")
        _validate(self.to_agent, pattern=_AGENT_RE, label="agent id")
        for scope in self.granted:
            _validate(scope, pattern=_SCOPE_RE, label="scope")

    def as_dict(self) -> dict[str, Any]:
        return {
            "from": self.from_agent,
            "to": self.to_agent,
            "granted": sorted(self.granted),
            "task_id": self.task_id,
        }


@dataclass(frozen=True, slots=True)
class DelegationChain:
    """A human principal and the ordered hops that carry their authority.

    `principal_scopes` is what the human was entitled to. Everything downstream
    is bounded by it, and the bound is enforced hop by hop rather than only at
    the end -- a chain that widens at hop 2 and narrows again at hop 3 has still
    laundered authority, and only a per-hop check sees it.
    """

    principal: str
    principal_scopes: frozenset[str]
    hops: tuple[DelegationHop, ...] = field(default_factory=tuple)

    @property
    def depth(self) -> int:
        return len(self.hops)

    @property
    def agents(self) -> tuple[str, ...]:
        """Every agent in the chain, in order, starting with the first delegate."""
        return tuple(hop.to_agent for hop in self.hops)

    @property
    def terminal_agent(self) -> str:
        return self.hops[-1].to_agent if self.hops else ""

    def scopes_at(self, index: int) -> tuple[str, ...]:
        """What the agent holds after `index` hops. Index 0 is the principal."""
        held: tuple[str, ...] = tuple(sorted(self.principal_scopes))
        for hop in self.hops[:index]:
            held = narrow(held, hop.granted)
        return held

    @property
    def effective_scopes(self) -> tuple[str, ...]:
        return self.scopes_at(self.depth)

    def as_dict(self) -> dict[str, Any]:
        return {
            "principal": self.principal,
            "principal_scopes": sorted(self.principal_scopes),
            "depth": self.depth,
            "agents": list(self.agents),
            "effective_scopes": list(self.effective_scopes),
            "hops": [hop.as_dict() for hop in self.hops],
        }


# ── The checks ───────────────────────────────────────────────────────────────


def find_amplification(chain: DelegationChain) -> tuple[A2AFinding, ...]:
    """Every hop that granted a scope its delegator did not hold.

    THE check. Each hop is compared against what the delegator actually held AT
    THAT POINT, not against the principal's original scopes -- comparing to the
    original would let hop 3 regain something hop 2 had already dropped, which
    is precisely the laundering this is for.
    """
    findings: list[A2AFinding] = []
    for index, hop in enumerate(chain.hops):
        held = chain.scopes_at(index)
        over = sorted(
            scope
            for scope in hop.granted
            if not any(scope_covers(h, scope) for h in held)
        )
        if over:
            holder = hop.from_agent or chain.principal
            findings.append(
                A2AFinding(
                    kind=A2AFindingKind.PRIVILEGE_AMPLIFICATION,
                    hop=index + 1,
                    detail=(
                        f"{holder} granted {', '.join(over)} to {hop.to_agent} "
                        f"while holding only {', '.join(held) or 'nothing'}. "
                        "Authority may narrow along a chain and may never widen."
                    ),
                )
            )
    return tuple(findings)


def find_loops(chain: DelegationChain) -> tuple[A2AFinding, ...]:
    """An agent appearing twice, and any hop delegating to itself.

    Self-delegation is reported separately and rated lower: it is usually a
    caller bug rather than an attack, and collapsing the two would make the
    critical case harder to see in a list of findings.
    """
    findings: list[A2AFinding] = []
    seen: set[str] = set()

    for index, hop in enumerate(chain.hops):
        if hop.from_agent == hop.to_agent:
            findings.append(
                A2AFinding(
                    kind=A2AFindingKind.SELF_DELEGATION,
                    hop=index + 1,
                    detail=f"{hop.from_agent} delegated to itself",
                )
            )
            continue
        if hop.to_agent in seen:
            findings.append(
                A2AFinding(
                    kind=A2AFindingKind.DELEGATION_LOOP,
                    hop=index + 1,
                    detail=(
                        f"{hop.to_agent} already appears earlier in this chain. "
                        "A cycle is unbounded work and an authority-laundering "
                        "path: each pass can widen scope if nothing checks."
                    ),
                )
            )
        seen.add(hop.to_agent)
    return tuple(findings)


def find_depth(
    chain: DelegationChain, *, max_depth: int = MAX_DELEGATION_DEPTH
) -> tuple[A2AFinding, ...]:
    if chain.depth <= max_depth:
        return ()
    return (
        A2AFinding(
            kind=A2AFindingKind.DEPTH_EXCEEDED,
            detail=(
                f"chain is {chain.depth} hops deep, over the {max_depth}-hop "
                "limit. No human reviewing the first hop could have anticipated "
                "the last."
            ),
        ),
    )


def find_unadvertised(
    chain: DelegationChain, cards: Mapping[str, AgentCard]
) -> tuple[A2AFinding, ...]:
    """Hops granting a scope the target agent never advertised it could use.

    Separate from amplification, and both can fire on one hop. Amplification is
    "the delegator did not have this to give"; this is "the delegate never said
    it did this". The second is how a compromised orchestrator turns a
    document-summarising agent into a database client.
    """
    findings: list[A2AFinding] = []
    for index, hop in enumerate(chain.hops):
        card = cards.get(hop.to_agent)
        if card is None:
            findings.append(
                A2AFinding(
                    kind=A2AFindingKind.UNENROLLED_AGENT,
                    hop=index + 1,
                    detail=(
                        f"{hop.to_agent} is not enrolled. A delegation target "
                        "nobody registered is an agent nobody reviewed."
                    ),
                )
            )
            continue
        unadvertised = sorted(s for s in hop.granted if not card.advertises(s))
        if unadvertised:
            findings.append(
                A2AFinding(
                    kind=A2AFindingKind.CAPABILITY_NOT_ADVERTISED,
                    hop=index + 1,
                    detail=(
                        f"{hop.to_agent} was granted {', '.join(unadvertised)}, "
                        f"which its enrolled card does not advertise "
                        f"(it advertises {', '.join(sorted(card.capabilities)) or 'nothing'})."
                    ),
                )
            )
    return tuple(findings)


def find_card_drift(
    live: Mapping[str, AgentCard], pinned: Mapping[str, str]
) -> tuple[A2AFinding, ...]:
    """Agents whose advertised capabilities changed since they were approved.

    An agent with no pin is NOT reported here. Whether an unpinned agent may be
    used at all is a policy question the gateway asks separately; reporting it as
    drift would conflate "changed since approval" with "never approved", and the
    two need different operator responses.
    """
    findings: list[A2AFinding] = []
    for agent_id, card in sorted(live.items()):
        expected = pinned.get(agent_id)
        if expected and expected != card.fingerprint:
            findings.append(
                A2AFinding(
                    kind=A2AFindingKind.CARD_DRIFT,
                    detail=(
                        f"{agent_id}'s card fingerprint is {card.fingerprint[:16]}..., "
                        f"pinned as {expected[:16]}.... Its id, version, endpoint "
                        "or capabilities changed after it was approved."
                    ),
                )
            )
    return tuple(findings)


def find_replay(
    chain: DelegationChain, seen_task_ids: Iterable[str]
) -> tuple[A2AFinding, ...]:
    """Task ids already used. One approval must not perform two actions."""
    already = set(seen_task_ids)
    findings: list[A2AFinding] = []
    for index, hop in enumerate(chain.hops):
        if hop.task_id and hop.task_id in already:
            findings.append(
                A2AFinding(
                    kind=A2AFindingKind.TASK_REPLAY,
                    hop=index + 1,
                    detail=(
                        f"task {hop.task_id!r} has been presented before. One "
                        "authorisation must not perform two actions."
                    ),
                )
            )
    return tuple(findings)


def inspect_chain(
    chain: DelegationChain,
    *,
    cards: Mapping[str, AgentCard] | None = None,
    pinned: Mapping[str, str] | None = None,
    seen_task_ids: Sequence[str] = (),
    max_depth: int = MAX_DELEGATION_DEPTH,
    known_principals: Iterable[str] | None = None,
) -> tuple[A2AFinding, ...]:
    """Every structural finding for one chain, in a stable order.

    Ordered worst-first so a caller that truncates for display truncates the
    least important, and so a log line showing one finding shows the one that
    matters.
    """
    registry = dict(cards or {})
    findings: list[A2AFinding] = []

    if known_principals is not None and chain.principal not in set(known_principals):
        findings.append(
            A2AFinding(
                kind=A2AFindingKind.UNKNOWN_PRINCIPAL,
                detail=(
                    f"principal {chain.principal!r} is not a known human "
                    "identity. A chain rooted in nobody has no authority to "
                    "narrow from, and every scope below it is unattributable."
                ),
            )
        )

    findings.extend(find_amplification(chain))
    findings.extend(find_unadvertised(chain, registry))
    findings.extend(find_card_drift(registry, dict(pinned or {})))
    findings.extend(find_replay(chain, seen_task_ids))
    findings.extend(find_loops(chain))
    findings.extend(find_depth(chain, max_depth=max_depth))

    return tuple(
        sorted(
            findings,
            key=lambda f: (-_SEVERITY_ORDER.index(f.severity), f.hop, f.kind.value),
        )
    )
