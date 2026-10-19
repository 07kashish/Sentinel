"""Per-agent behavioural baselines, and divergence from declared intent.

TWO QUESTIONS, ONE MODULE
-------------------------
Both compare what an agent DID against a reference, and differ only in where
the reference comes from:

  * A BASELINE is what this agent has usually done. "Normally reads 2-10
    support tickets; suddenly reads 50,000 customer records."
  * DECLARED INTENT is what it said it would do this time. "Generate the
    quarterly finance report", followed by reading the payroll database and
    emailing a CSV outside the company.

Neither is visible to a per-event detector. Reading a customer record is
allowed; reading fifty thousand is the same action at a volume nobody asked
for, and the difference is arithmetic against history rather than anything in
the event itself.

DETERMINISTIC FEATURES, NOT A MODEL
-------------------------------------
The specification is explicit: *do not rely only on an LLM for blocking
decisions; use deterministic features plus statistical evidence*. Everything
here is counting and set arithmetic. Given the same history and the same
observation it returns the same answer, and every finding names the numbers it
came from -- so an operator can disagree with a specific line rather than with
a score.

NEITHER OF THESE BLOCKS ANYTHING
----------------------------------
A baseline is built from an agent's own past behaviour, so an attacker patient
enough to drift the baseline can move it -- and a control that can be trained is
not a control. Divergence rests on a self-declared intent string, which a
hostile agent simply writes to match whatever it intends to do.

Both are strong EVIDENCE and poor AUTHORITY, so they raise severity and produce
findings for a human. `ProtectGate` keeps deciding on content, and
`AgentCapabilityGate` on grants.

A COLD BASELINE IS NOT A CLEAN ONE
------------------------------------
An agent with three observations has no usual behaviour, and scoring it as
normal would mean every genuinely new agent -- including one an attacker just
introduced -- looks reassuring. `BehaviourBaseline.is_established` says whether
there is enough history to judge, and findings from an unestablished baseline
say so rather than borrowing confidence they have not earned.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final, Mapping, Sequence

__all__ = [
    "BehaviourBaseline",
    "BaselineDeviation",
    "IntentDivergence",
    "MIN_OBSERVATIONS_FOR_BASELINE",
    "VOLUME_SPIKE_MULTIPLE",
    "SENSITIVE_INTENT_TERMS",
    "compare_to_baseline",
    "assess_intent_divergence",
]

#: Below this many observed sessions an agent has no usual behaviour worth
#: comparing against. Five is not a statistical threshold -- it is the point at
#: which "this agent has never done that" stops meaning "we have barely seen
#: this agent". Under it, every first action looks anomalous and the finding
#: says nothing an operator can act on.
MIN_OBSERVATIONS_FOR_BASELINE: Final[int] = 5

#: How many times the usual per-session volume counts as a spike. The example
#: in the specification is 2-10 tickets against 50,000 records, which is four
#: orders of magnitude; a multiple of ten catches that with room to spare while
#: leaving ordinary busy days alone.
VOLUME_SPIKE_MULTIPLE: Final[int] = 10

#: Words in an OBSERVED action or resource that make a step sensitive
#: regardless of what the agent said it was doing.
#:
#: Deliberately about the observation, not the intent: an agent that declares
#: "generate the quarterly finance report" and reads the payroll database has
#: diverged whether or not the word "payroll" appears in its stated purpose.
SENSITIVE_INTENT_TERMS: Final[Mapping[str, str]] = MappingProxyType({
    "payroll": "payroll data",
    "salary": "compensation data",
    "pii": "personally identifiable information",
    "customer": "customer records",
    "ssn": "national identifiers",
    "passport": "identity documents",
    "credential": "credentials",
    "secret": "secrets",
    "password": "passwords",
    "token": "tokens",
    "private_key": "private keys",
    ".env": "environment secrets",
    "medical": "health data",
    "patient": "health data",
})


@dataclass(frozen=True, slots=True)
class BehaviourBaseline:
    """What one agent has usually done, as counted facts.

    Sets rather than a model, so "unusual" means "not in the set we have seen",
    which is a statement an operator can verify by looking.
    """

    agent_id: str
    sessions_observed: int = 0
    tools: frozenset[str] = frozenset()
    resources: frozenset[str] = frozenset()
    destinations: frozenset[str] = frozenset()
    mcp_servers: frozenset[str] = frozenset()
    credentials: frozenset[str] = frozenset()
    #: Hours of the day (UTC) in which this agent has been seen working.
    active_hours: frozenset[int] = frozenset()
    #: Humans or principals this agent has worked on behalf of. An agent that
    #: has only ever served one team and suddenly serves another is either a
    #: reassignment nobody recorded or a credential in the wrong hands.
    users: frozenset[str] = frozenset()
    #: Other agents seen in the same sessions -- delegation, observed rather
    #: than declared. An agent that has never spawned anything and suddenly
    #: does is the delegation-abuse case the specification's chain calls out.
    spawned_agents: frozenset[str] = frozenset()
    #: Canonical actions that touch credentials or privilege. Tracked apart
    #: from `tools` because a first-ever privileged action is a different fact
    #: from a first-ever ordinary one, and averaging them together hides it.
    privileged_actions: frozenset[str] = frozenset()
    #: Distinct (action, resource-prefix) shapes. Not the resources themselves:
    #: an agent that reads `tickets/1` through `tickets/900` has one query
    #: pattern and nine hundred resources, and tracking only the latter makes
    #: every ordinary day look like a thousand new things.
    query_patterns: frozenset[str] = frozenset()
    #: Signatures of the action sequences this agent runs. A workflow it has
    #: never run before is a change in what the agent is FOR, which no single
    #: unusual step reveals.
    workflows: frozenset[str] = frozenset()
    #: Typical steps per session, and the largest ever seen.
    mean_steps_per_session: float = 0.0
    max_steps_per_session: int = 0

    @property
    def is_established(self) -> bool:
        return self.sessions_observed >= MIN_OBSERVATIONS_FOR_BASELINE

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "sessions_observed": self.sessions_observed,
            "established": self.is_established,
            "tools": sorted(self.tools),
            "resources": sorted(self.resources),
            "destinations": sorted(self.destinations),
            "mcp_servers": sorted(self.mcp_servers),
            "active_hours": sorted(self.active_hours),
            "users": sorted(self.users),
            "spawned_agents": sorted(self.spawned_agents),
            "privileged_actions": sorted(self.privileged_actions),
            "query_patterns": sorted(self.query_patterns),
            "workflows": sorted(self.workflows),
            "mean_steps_per_session": round(self.mean_steps_per_session, 2),
            "max_steps_per_session": self.max_steps_per_session,
        }


@dataclass(frozen=True, slots=True)
class BaselineDeviation:
    """One way an observation departed from the agent's usual behaviour."""

    kind: str
    detail: str
    severity: int
    #: The specific values that were new or excessive. An alert that says
    #: "unusual destination" without naming it cannot be triaged.
    observed: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "detail": self.detail,
            "severity": self.severity,
            "observed": list(self.observed),
        }


def compare_to_baseline(
    baseline: BehaviourBaseline,
    *,
    tools: Sequence[str] = (),
    resources: Sequence[str] = (),
    destinations: Sequence[str] = (),
    mcp_servers: Sequence[str] = (),
    credentials: Sequence[str] = (),
    users: Sequence[str] = (),
    spawned_agents: Sequence[str] = (),
    privileged_actions: Sequence[str] = (),
    query_patterns: Sequence[str] = (),
    workflows: Sequence[str] = (),
    step_count: int = 0,
    hour: int | None = None,
) -> tuple[BaselineDeviation, ...]:
    """Compare one session against what this agent usually does.

    Returns every deviation found, each naming the values responsible. An empty
    result means "nothing departed from the usual", which is only meaningful
    when `baseline.is_established` -- and callers are expected to report that
    alongside, because an unestablished baseline produces an empty result for
    the uninteresting reason.
    """
    deviations: list[BaselineDeviation] = []

    def _new(observed: Sequence[str], known: frozenset[str]) -> tuple[str, ...]:
        return tuple(sorted({v for v in observed if v and v not in known}))

    for label, observed, known, severity, why in (
        ("unusual_tool", tools, baseline.tools, 40,
         "invoked a tool it has never used"),
        ("unusual_user", users, baseline.users, 45,
         "acted on behalf of a principal it has never served"),
        ("unusual_spawned_agent", spawned_agents, baseline.spawned_agents, 55,
         "delegated to an agent it has never delegated to"),
        ("unusual_privilege_use", privileged_actions, baseline.privileged_actions, 70,
         "performed a privileged action it has never performed"),
        ("unusual_query_pattern", query_patterns, baseline.query_patterns, 30,
         "issued a shape of query it has never issued"),
        ("unusual_workflow", workflows, baseline.workflows, 35,
         "ran a workflow it has never run"),
        ("unusual_resource", resources, baseline.resources, 35,
         "touched a resource it has never touched"),
        ("unusual_destination", destinations, baseline.destinations, 60,
         "sent data somewhere it has never sent data"),
        ("unusual_mcp_server", mcp_servers, baseline.mcp_servers, 50,
         "called an MCP server it has never called"),
        ("unusual_credential", credentials, baseline.credentials, 55,
         "presented a credential it has never presented"),
    ):
        fresh = _new(observed, known)
        if fresh:
            deviations.append(
                BaselineDeviation(
                    kind=label,
                    detail=f"{baseline.agent_id} {why}: {', '.join(fresh[:5])}",
                    severity=severity,
                    observed=fresh,
                )
            )

    # VOLUME. The specification's own example, and the one deviation that is
    # about the SAME action repeated rather than a new one.
    if baseline.mean_steps_per_session > 0 and step_count > 0:
        threshold = baseline.mean_steps_per_session * VOLUME_SPIKE_MULTIPLE
        if step_count > threshold:
            deviations.append(
                BaselineDeviation(
                    kind="volume_spike",
                    detail=(
                        f"{baseline.agent_id} took {step_count} steps in one "
                        f"session against a usual {baseline.mean_steps_per_session:.1f} "
                        f"(more than {VOLUME_SPIKE_MULTIPLE}x). Reading one record "
                        "is permitted; reading fifty thousand is the same action "
                        "at a volume nobody asked for."
                    ),
                    severity=65,
                    observed=(str(step_count),),
                )
            )

    # HOURS. Weakest signal here and deliberately lowest severity: plenty of
    # legitimate work happens out of hours, and an agent is not a person with a
    # working day. It is worth recording and not worth waking anybody for.
    if hour is not None and baseline.active_hours and hour not in baseline.active_hours:
        deviations.append(
            BaselineDeviation(
                kind="unusual_hour",
                detail=(
                    f"{baseline.agent_id} was active at {hour:02d}:00 UTC, outside "
                    f"its usual hours ({', '.join(f'{h:02d}' for h in sorted(baseline.active_hours))})"
                ),
                severity=20,
                observed=(f"{hour:02d}:00",),
            )
        )

    return tuple(deviations)


@dataclass(frozen=True, slots=True)
class IntentDivergence:
    """How far an agent's actions departed from what it said it would do."""

    declared_intent: str
    #: Observed steps that no reading of the declared intent covers.
    unexplained: tuple[str, ...] = ()
    #: Sensitive categories touched, named in plain words.
    sensitive_touched: tuple[str, ...] = ()
    external_destinations: tuple[str, ...] = ()
    risk: int = 0

    @property
    def diverged(self) -> bool:
        return self.risk > 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "declared_intent": self.declared_intent,
            "unexplained": list(self.unexplained),
            "sensitive_touched": list(self.sensitive_touched),
            "external_destinations": list(self.external_destinations),
            "risk": self.risk,
            "diverged": self.diverged,
        }


def assess_intent_divergence(
    declared_intent: str,
    *,
    actions: Sequence[str] = (),
    resources: Sequence[str] = (),
    destinations: Sequence[str] = (),
) -> IntentDivergence:
    """Compare a declared intent against what was actually done.

    WORD OVERLAP, NOT UNDERSTANDING, and that limit is the point. The
    specification asks for deterministic features plus statistical evidence
    rather than an LLM's judgement, and a lexical check has a property a model
    does not: an operator can reproduce it by hand and see exactly why a step
    was called unexplained.

    It is deliberately WEAK evidence on its own. "Generate quarterly finance
    report" does not lexically cover `read_payroll_db`, and a legitimate agent
    might well read payroll to produce a finance report -- so an unexplained
    step is a question, not a verdict. What raises real risk is the
    combination the specification names: sensitive data touched AND sent
    outside, neither of which the declared intent mentioned.
    """
    intent = (declared_intent or "").strip()
    if not intent:
        return IntentDivergence(declared_intent="")

    intent_words = {
        word.strip(".,;:!?\"'()[]").lower()
        for word in intent.split()
        if len(word.strip(".,;:!?\"'()[]")) > 3
    }

    def _explained(item: str) -> bool:
        """Whether any meaningful word of the item appears in the intent."""
        parts = {
            piece
            for piece in item.lower().replace("/", " ").replace("_", " ").replace(".", " ").split()
            if len(piece) > 3
        }
        return bool(parts & intent_words)

    unexplained = tuple(
        sorted({item for item in (*actions, *resources) if item and not _explained(item)})
    )

    sensitive: set[str] = set()
    for item in (*actions, *resources):
        lowered = (item or "").lower()
        for term, description in SENSITIVE_INTENT_TERMS.items():
            if term in lowered and term not in intent.lower():
                sensitive.add(description)

    external = tuple(sorted({d for d in destinations if d}))

    # Scoring, stated as a table rather than buried in arithmetic.
    risk = 0
    if unexplained:
        risk += min(len(unexplained) * 5, 20)
    if sensitive:
        risk += min(len(sensitive) * 20, 50)
    if external:
        risk += 20
    # The combination the specification calls out: sensitive data AND an
    # external destination, neither mentioned in the declared intent. Either
    # alone is a question; together they are the shape of an exfiltration.
    if sensitive and external:
        risk += 20

    return IntentDivergence(
        declared_intent=intent,
        unexplained=unexplained,
        sensitive_touched=tuple(sorted(sensitive)),
        external_destinations=external,
        risk=min(risk, 100),
    )
