"""Agent inventory: what Sentinel has SEEN, versus what an operator enrolled.

THE DEFECT THIS EXISTS TO FIX
------------------------------
`AdmitEvent` recorded contact only for agents that were already enrolled AND
signed:

    if identity.trust is TrustLevel.VERIFIED and identity.address is not None:
        self._agents.record_event(...)

Everything else left no trace of the agent's existence. Demonstrated against a
live build: an agent nobody enrolled sent one event, Sentinel raised a HIGH
severity incident (79) about it -- and the `agents` table stayed empty. The
product knew something bad had happened and could not say who did it.

That is the exact shape "Agent Discovery" is for. A shadow agent -- one somebody
spun up without telling security -- is not a hypothetical: it is the normal
outcome of a platform team moving fast, and it is invisible precisely because
nobody enrolled it.

OBSERVATION IS NOT TRUST
------------------------
`AgentClassification` deliberately mirrors `McpServerTrust`. Having seen an
agent says nothing about whether it is permitted, and the two must never be
conflated: an inventory that promoted "we have seen this" into "this is known
and therefore fine" would turn discovery into an authorisation bypass. So
observation is recorded separately from enrolment, and classification is
DERIVED by comparing the two rather than stored as a fact somebody could edit.

WHAT IS NOT INFERRED
--------------------
The specification's agent profile lists Owner, Team, Purpose, Framework, Model,
Environment and Risk Tier. None of those are observable from a stream of tool
calls, and guessing them would be fabrication -- this product's entire claim is
that it does not invent findings. They are DECLARED by an operator or they are
absent, and `AgentProfile.declared` keeps them visibly separate from everything
Sentinel worked out for itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Final, Mapping, Sequence

#: Declared values are bounded: they are operator text that ends up in an API
#: response and a CLI table.
MAX_DECLARED_CHARS: Final[int] = 256

__all__ = [
    "AgentClassification",
    "DECLARABLE_FIELDS",
    "DeclarationRejected",
    "MAX_DECLARED_CHARS",
    "RISK_TIERS",
    "validate_declaration",
    "ObservedEdgeKind",
    "ObservedEdge",
    "AgentProfile",
    "classify_agent",
    "TrustFactor",
    "TrustScore",
    "TRUST_DEDUCTIONS",
    "TRUST_FACTOR_CAP",
    "score_agent_trust",
]


#: Risk tiers an operator may assert. A free-text tier is not a tier: two teams
#: writing "high" and "High" produce an inventory that cannot be filtered, and
#: the whole point of recording a tier is to sort by it during an incident.
RISK_TIERS: Final[tuple[str, ...]] = ("low", "medium", "high", "critical")

#: Profile fields a human declares, because Sentinel cannot observe them.
#:
#: The specification lists these as part of an agent profile alongside things
#: like Last Seen and Violations. The difference is that those are MEASURED and
#: these are ASSERTED -- nothing in a stream of tool calls reveals which team
#: owns an agent or which framework it was built with, and inferring them would
#: be fabrication in a product whose claim is that it does not invent findings.
#:
#: A CLOSED set, not free-form keys. An inventory where every team invents its
#: own field names cannot be queried, and "which agents does the payments team
#: own" is the question this exists to answer. An unknown key is refused with
#: the valid ones listed rather than silently accepted.
DECLARABLE_FIELDS: Final[Mapping[str, str]] = MappingProxyType({
    "owner": "Person or rota accountable for this agent",
    "team": "Team that operates it",
    "purpose": "What it is for, in one line",
    "framework": "Agent framework it is built on",
    "model": "Model it runs",
    "environment": "production, staging, development",
    "instance": "Which deployment or instance this id refers to",
    "risk_tier": f"One of: {', '.join(RISK_TIERS)}",
    "business_application": "Business system it serves",
    "cloud_environment": "Cloud account or project it runs in",
})


class DeclarationRejected(ValueError):
    """A declared field or value was not acceptable."""


def validate_declaration(field: str, value: str) -> tuple[str, str]:
    """Normalise and check one declared field. Pure, so it is testable.

    Returns the normalised pair. Raises `DeclarationRejected` with the valid
    options named, because an error that says only "invalid" sends an operator
    to the source code.
    """
    key = (field or "").strip().lower()
    if key not in DECLARABLE_FIELDS:
        raise DeclarationRejected(
            f"unknown field {field!r}. Declarable fields are: "
            f"{', '.join(sorted(DECLARABLE_FIELDS))}. Everything else about an "
            "agent is observed rather than declared."
        )

    text = (value or "").strip()
    if not text:
        raise DeclarationRejected(
            f"{key} was given an empty value. To remove a declaration use "
            "`agent-undeclare`; recording a blank is not the same as recording "
            "nothing, and it reads as though somebody answered."
        )
    if len(text) > MAX_DECLARED_CHARS:
        raise DeclarationRejected(
            f"{key} is longer than {MAX_DECLARED_CHARS} characters"
        )

    if key == "risk_tier" and text.lower() not in RISK_TIERS:
        raise DeclarationRejected(
            f"risk_tier must be one of {', '.join(RISK_TIERS)}; got {text!r}"
        )
    if key == "risk_tier":
        text = text.lower()

    return key, text


class AgentClassification(str, Enum):
    """How an observed agent stands relative to what an operator decided.

    Ordered by how much attention it deserves, not alphabetically.
    """

    #: Enrolled and active. The intended state.
    MANAGED = "managed"

    #: Observed sending events, never enrolled. The spec's required category,
    #: and the reason this module exists: a shadow agent nobody registered.
    UNMANAGED = "unmanaged"

    #: Enrolled, then REVOKED -- and still sending events. The most serious of
    #: the three by a wide margin: somebody deliberately withdrew this agent's
    #: standing and it is still running. Neither "managed" nor "unmanaged"
    #: describes that, and folding it into either would hide it.
    REVOKED_BUT_ACTIVE = "revoked_but_active"

    @property
    def needs_attention(self) -> bool:
        """Whether a human should look at this agent.

        MANAGED is the only state that does not, which is why this is a property
        rather than a caller-side comparison someone can get backwards.
        """
        return self is not AgentClassification.MANAGED


def classify_agent(*, enrolled: bool, revoked: bool) -> AgentClassification:
    """Derive classification from enrolment facts. Pure, so it is testable.

    Derived rather than stored. A stored classification is a fact that can drift
    from the two facts it summarises -- and the drift would show up as an agent
    marked `managed` after its enrolment was revoked, which is the one case that
    most needs to be visible.
    """
    if not enrolled:
        return AgentClassification.UNMANAGED
    if revoked:
        return AgentClassification.REVOKED_BUT_ACTIVE
    return AgentClassification.MANAGED


@dataclass(frozen=True, slots=True)
class TrustFactor:
    """One thing that moved an agent's trust score, and by how much.

    Carried because `docs/` has a standing objection to opaque scores, and a
    security product that outputs "trust: 42" without saying why is asking an
    operator to act on a number they cannot check. Every factor names the
    observation behind it.
    """

    name: str
    delta: int
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "delta": self.delta, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class TrustScore:
    """A 0-100 score, and the complete list of what produced it.

    NOT a model output and not a heuristic anyone has to take on faith: it is a
    sum of named deductions from a documented starting point, so a reader can
    recompute it by hand and disagree with a specific line rather than with the
    number.

    Deliberately NOT used to make decisions. Nothing in the enforcement path
    reads this -- `ProtectGate` decides on content, `AgentCapabilityGate` on
    grants. A score that silently gated traffic would be an unreviewable policy,
    and the reason to publish one is triage: which of two hundred agents should
    a human look at first.
    """

    score: int
    factors: tuple[TrustFactor, ...] = ()

    @property
    def band(self) -> str:
        """A coarse label, because 71 and 74 do not mean different things.

        Bands exist so an operator sorts by category rather than by a precision
        the inputs do not support.
        """
        if self.score >= 80:
            return "trusted"
        if self.score >= 50:
            return "watch"
        return "untrusted"

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "band": self.band,
            "factors": [f.as_dict() for f in self.factors],
        }


#: Every deduction, in one place, so the scoring rules are reviewable as a table
#: rather than scattered through a function. Positive numbers are deductions.
TRUST_DEDUCTIONS: Final[Mapping[str, int]] = MappingProxyType({
    "unmanaged": 40,
    "revoked_but_active": 60,
    "incident": 10,
    "ungranted_tool": 15,
    "external_destination": 10,
    "no_owner_declared": 10,
})

#: The maximum any single repeated factor may remove, so one noisy agent with
#: forty incidents does not produce a score indistinguishable from an agent with
#: four. Beyond a handful, more of the same tells an operator nothing new.
TRUST_FACTOR_CAP: Final[int] = 30


def score_agent_trust(
    *,
    classification: "AgentClassification",
    incident_count: int = 0,
    ungranted_tools: Sequence[str] = (),
    external_destinations: Sequence[str] = (),
    has_owner: bool = False,
) -> TrustScore:
    """Compute a trust score from observed facts. Pure, so it is testable.

    Starts at 100 and deducts. Starting high and deducting -- rather than
    accumulating credit -- means an agent Sentinel knows NOTHING about scores
    well, and that is the correct default: absence of evidence is not evidence
    of misbehaviour, and an inventory that flagged every quiet agent as
    untrusted would train operators to ignore the column.

    What lowers it is always something OBSERVED: an enrolment state, a counted
    incident, a tool used without a grant, data sent somewhere external.
    """
    factors: list[TrustFactor] = []

    if classification is AgentClassification.UNMANAGED:
        factors.append(
            TrustFactor(
                "unmanaged",
                TRUST_DEDUCTIONS["unmanaged"],
                "no operator ever enrolled this agent",
            )
        )
    elif classification is AgentClassification.REVOKED_BUT_ACTIVE:
        factors.append(
            TrustFactor(
                "revoked_but_active",
                TRUST_DEDUCTIONS["revoked_but_active"],
                "enrolment was revoked and the agent is still sending events",
            )
        )

    if incident_count:
        capped = min(incident_count * TRUST_DEDUCTIONS["incident"], TRUST_FACTOR_CAP)
        factors.append(
            TrustFactor("incidents", capped, f"{incident_count} incident(s) name this agent")
        )

    if ungranted_tools:
        capped = min(
            len(ungranted_tools) * TRUST_DEDUCTIONS["ungranted_tool"], TRUST_FACTOR_CAP
        )
        factors.append(
            TrustFactor(
                "ungranted_tools",
                capped,
                f"used without a grant: {', '.join(sorted(ungranted_tools)[:5])}",
            )
        )

    if external_destinations:
        capped = min(
            len(external_destinations) * TRUST_DEDUCTIONS["external_destination"],
            TRUST_FACTOR_CAP,
        )
        factors.append(
            TrustFactor(
                "external_destinations",
                capped,
                f"sent data to {len(external_destinations)} external destination(s)",
            )
        )

    if not has_owner:
        # Not a security property, and it is here anyway: an agent nobody owns
        # is an agent nobody will investigate, which is what turns a small
        # incident into a long one.
        factors.append(
            TrustFactor(
                "no_owner",
                TRUST_DEDUCTIONS["no_owner_declared"],
                "no owner declared, so nobody is accountable for it",
            )
        )

    total = sum(f.delta for f in factors)
    return TrustScore(score=max(0, 100 - total), factors=tuple(factors))


class ObservedEdgeKind(str, Enum):
    """What kind of thing an agent was observed reaching.

    These are the edges of the attack surface graph. Each is something the
    product genuinely sees in an event, which is why there is no `HUMAN` or
    `CLOUD_ENVIRONMENT` member: Sentinel does not observe those, and a graph
    with invented nodes answers reachability questions wrongly in the direction
    that gets somebody hurt.
    """

    #: The action an agent performed: `read_file`, `http_get`.
    ACTION = "action"
    #: What it acted on: a path, a table, a bucket.
    RESOURCE = "resource"
    #: Where data was sent. The edge that answers "can this agent exfiltrate".
    DESTINATION = "destination"
    #: An MCP server it called through.
    MCP_SERVER = "mcp_server"
    #: A tool invoked through the inline proxy.
    TOOL = "tool"
    #: The CREDENTIAL an agent's traffic arrived under, recorded as a
    #: short hash prefix and never the secret itself. This is the link the
    #: specification's chain needs -- Human -> Agent -> Credential -> Tool
    #: -- and the one that answers "if this key leaked, which agents are
    #: affected", which is how a compromise gets scoped.
    CREDENTIAL = "credential"


@dataclass(frozen=True, slots=True)
class ObservedEdge:
    """One agent -> thing relationship, with how often and how recently.

    `occurrences` and `last_seen` are carried because an edge seen once six
    months ago and an edge seen four thousand times today are different facts,
    and a graph that flattens them makes every agent look equally connected.
    """

    kind: ObservedEdgeKind
    target: str
    occurrences: int = 0
    first_seen: str = ""
    last_seen: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "target": self.target,
            "occurrences": self.occurrences,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass(frozen=True, slots=True)
class AgentProfile:
    """Everything known about one agent, with observed and declared kept apart.

    The separation is the point. `edges`, `last_seen` and `classification` are
    things Sentinel worked out; `declared` is what a human asserted. Merging
    them into one flat record would make an operator's guess at "Framework:
    LangChain" indistinguishable from a measurement, and this product's whole
    claim is that it does not invent findings.
    """

    tenant_id: str
    agent_id: str
    classification: AgentClassification
    first_seen: str = ""
    last_seen: str = ""
    event_count: int = 0
    #: Tools the agent is AUTHORISED to invoke (`agent_tool_grants`).
    granted_tools: tuple[str, ...] = ()
    #: What it was actually observed doing.
    edges: tuple[ObservedEdge, ...] = ()
    #: Operator-declared metadata. Absent unless somebody wrote it down.
    declared: Mapping[str, str] = field(default_factory=dict)
    incident_count: int = 0
    #: Human label from enrolment. Empty for an agent nobody enrolled.
    label: str = ""
    #: Times this agent's activity TRIPPED POLICY. Deliberately not the same as
    #: `incident_count`: a violation the gate refused never became an incident,
    #: so counting only incidents undercounts exactly the cases where
    #: enforcement worked. An agent with many violations and no incidents is
    #: being stopped; one with many incidents and no violations is not.
    violation_count: int = 0
    #: Which detector and enforcement posture governed this agent's traffic.
    policy: str = ""

    @property
    def observed_tools(self) -> tuple[str, ...]:
        return tuple(
            e.target for e in self.edges if e.kind is ObservedEdgeKind.TOOL
        )

    @property
    def ungranted_tools_used(self) -> tuple[str, ...]:
        """Tools it USED that it was never granted.

        The most actionable line in a profile. Under observe mode these calls
        were allowed, so this is the list an operator works through before
        turning enforcement on -- and after enforcement it should be empty,
        which makes it a check on the rollout rather than only a report.
        """
        granted = set(self.granted_tools)
        return tuple(sorted(t for t in set(self.observed_tools) if t not in granted))

    @property
    def external_destinations(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                e.target
                for e in self.edges
                if e.kind is ObservedEdgeKind.DESTINATION and e.target
            )
        )

    @property
    def credentials(self) -> tuple[str, ...]:
        """Credential fingerprints this agent's traffic arrived under.

        Hash prefixes, never secrets. The question it answers is the one asked
        during a compromise: if this key leaked, which agents are affected --
        and the inverse, which is just as useful: an agent presenting several
        credentials is either shared infrastructure or somebody's key sprawl.
        """
        return tuple(
            sorted(e.target for e in self.edges if e.kind is ObservedEdgeKind.CREDENTIAL)
        )

    @property
    def mcp_servers(self) -> tuple[str, ...]:
        return tuple(
            sorted(e.target for e in self.edges if e.kind is ObservedEdgeKind.MCP_SERVER)
        )

    @property
    def accessible_data(self) -> tuple[str, ...]:
        """Resources this agent actually touched.

        Named "accessible data" after the specification, with one honest
        correction built into the name of the underlying edge: this is what the
        agent DID reach, not what it COULD reach. Sentinel observes traffic, not
        grants on somebody else's database, and reporting the second while
        measuring the first would overstate coverage in the direction that gets
        somebody hurt.
        """
        return tuple(
            sorted(e.target for e in self.edges if e.kind is ObservedEdgeKind.RESOURCE)
        )

    @property
    def name(self) -> str:
        """A human label, falling back to the id.

        `agents.label` is set at enrolment. An unmanaged agent has no label by
        definition -- nobody enrolled it -- so its id is the only name it has.
        """
        return self.label or self.agent_id

    @property
    def trust(self) -> TrustScore:
        """Computed on read, never stored.

        A stored score drifts from the facts it summarises the moment a new
        incident lands, and a stale trust score is worse than none: it is a
        number an operator trusts that quietly stopped being true.
        """
        return score_agent_trust(
            classification=self.classification,
            incident_count=self.incident_count,
            ungranted_tools=self.ungranted_tools_used,
            external_destinations=self.external_destinations,
            has_owner=bool(self.declared.get("owner")),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "name": self.name,
            "classification": self.classification.value,
            "needs_attention": self.classification.needs_attention,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_count": self.event_count,
            "granted_tools": list(self.granted_tools),
            "observed_tools": list(self.observed_tools),
            "ungranted_tools_used": list(self.ungranted_tools_used),
            "external_destinations": list(self.external_destinations),
            "edges": [e.as_dict() for e in self.edges],
            "declared": dict(self.declared),
            "incident_count": self.incident_count,
            "violation_count": self.violation_count,
            "credentials": list(self.credentials),
            "mcp_servers": list(self.mcp_servers),
            "accessible_data": list(self.accessible_data),
            "trust": self.trust.as_dict(),
            "policy": self.policy,
        }
