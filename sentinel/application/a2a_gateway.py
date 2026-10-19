"""A2A security gateway: the delegation checks a generic tool gate cannot make.

WHAT THIS ADDS, AND WHAT IT DELIBERATELY DOES NOT
---------------------------------------------------
It does NOT decide ALLOW / WARN / REQUIRE_APPROVAL / BLOCK. `ProtectGate` does
that, from the deterministic policy, and this gateway projects every delegation
onto the event payload that gate already understands. One rule set governs the
protect path, the MCP path and this one, so there is no third place for them to
disagree -- and the existing prompt-injection detector is reused rather than
reimplemented. Exactly the pattern `McpGateway` set, for exactly the same
reasons.

What it adds is the three questions agent-to-agent delegation raises that a bare
tool call does not:

  1. WHOSE AUTHORITY IS THIS?  A tool call has one actor. A delegated call has a
     chain, and the record at the end of it names the last agent -- which is
     true and useless. `DelegationChain` carries the human principal and what
     each hop was entitled to, and `inspect_chain` refuses the hops that were
     not.

  2. IS THIS AGENT WHAT IT WAS WHEN IT WAS APPROVED?  Agent cards change after
     enrolment. An agent advertising `read:docs` on Monday and `read:customers`
     on Friday presents the same NAME to the same allowlist. Same failure as MCP
     tool-definition drift, same fix: pin the fingerprint and compare.

  3. IS THE TASK TEXT ITSELF AN ATTACK?  The instruction one agent sends another
     is prose a model reads and acts on, and it may have originated in a
     document nobody vetted. It is attacker-influenced text on the instruction
     path -- cross-agent prompt injection -- and inspecting the SCOPES will
     never find it. The instruction is what gets sent to the detector, in the
     same `metadata.prompt` field an MCP tool description goes to.

FAIL CLOSED, AND SAY SO
-----------------------
`require_allowed` raises `A2ADelegationRefused` rather than returning a falsy
value, matching `McpGateway.require_allowed`. A security decision a caller can
ignore by forgetting to check a return value is not a security decision.

WHAT THIS IS NOT
----------------
It is not an A2A wire proxy. `McpGateway` evaluates and
`interface/mcp_proxy_routes.py` speaks the protocol; the equivalent split
applies here, and the wire half is not built. This evaluates delegations
presented to it over Sentinel's own API, which means an agent framework that
never calls Sentinel is outside enforcement -- the same residual risk F-11
records for the inline tool proxy, and it is stated here rather than implied.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Protocol

from sentinel.application.protect_gate import ProtectGate
from sentinel.domain.delegation_constraints import (
    ConstraintFinding,
    ConstraintKind,
    DelegationConstraint,
    DelegationContext,
)
from sentinel.domain.delegation_constraints import evaluate as evaluate_constraint
from sentinel.domain.a2a import (
    MAX_DELEGATION_DEPTH,
    A2AFinding,
    A2AFindingKind,
    AgentCard,
    DelegationChain,
    Severity,
    inspect_chain,
    worst,
)
from sentinel.domain.errors import DomainRuleViolated
from sentinel.domain.primitives import TrustLevel
from sentinel.domain.protect import ProtectOutcome

__all__ = [
    "A2ADelegationRefused",
    "A2AEvaluation",
    "A2AGateway",
    "AgentCardStore",
    "InMemoryAgentCards",
    "TaskLedger",
    "InMemoryTaskLedger",
]


class A2ADelegationRefused(DomainRuleViolated):
    """The gateway refused a delegation. Not retryable without operator action.

    Every refusal here means either a chain claimed authority nobody granted or
    an agent's card changed after approval. Neither becomes true on a retry, and
    a retryable classification would turn a refused amplification into the same
    refusal repeated until something gives.
    """

    is_retryable = False


@dataclass(frozen=True, slots=True)
class A2AEvaluation:
    """What the gateway concluded, and everything an analyst needs to see why."""

    outcome: ProtectOutcome
    chain: DelegationChain
    findings: tuple[A2AFinding, ...]
    #: Phase 4. Reported ALONGSIDE the structural findings rather than merged
    #: into them: "this hop granted more than it held" and "this delegation
    #: expired an hour ago" are different failures with different remedies, and
    #: one list would make a policy rule matching either match both.
    constraint_findings: tuple[ConstraintFinding, ...] = ()

    @property
    def severity(self) -> Severity:
        return worst(
            [f.severity for f in self.findings]
            + [f.severity for f in self.constraint_findings]
        )

    @property
    def blocked_structurally(self) -> bool:
        """A CRITICAL structural finding, independent of what policy decided.

        Kept separate from `outcome` on purpose. Policy can be misconfigured;
        privilege amplification is not a matter of opinion, and a deployment
        whose policy happens not to match must still not execute a delegation
        that laundered authority.
        """
        # Constraint findings count here too. A cross-tenant chain and an
        # environment escalation are both CRITICAL and both are authority
        # claims, not opinions -- the same reason amplification does not defer
        # to policy.
        # Iterated separately rather than unpacked into one tuple. Merging
            # two tuples of different types produces `object`, and `.severity`
            # then resolves on neither -- the same widening that hid a renamed
            # attribute elsewhere in this codebase, where a `getattr` default
            # masked it.
        return any(
            finding.severity is Severity.CRITICAL for finding in self.findings
        ) or any(
            finding.severity is Severity.CRITICAL
            for finding in self.constraint_findings
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": self.outcome.decision.value,
            "enforced": self.outcome.enforced,
            "severity": self.severity.value,
            "structurally_blocked": self.blocked_structurally,
            "chain": self.chain.as_dict(),
            "findings": [f.as_dict() for f in self.findings],
        }


class AgentCardStore(Protocol):
    """Where enrolled agent cards and their pinned fingerprints live."""

    def cards(self, tenant_id: str) -> Mapping[str, AgentCard]: ...

    def pins(self, tenant_id: str) -> Mapping[str, str]: ...

    def enrol(self, tenant_id: str, card: AgentCard) -> None: ...


class InMemoryAgentCards:
    """Process-local card store. Honest about its limits.

    Dedupes and pins within one process. A multi-replica deployment needs the
    SQL-backed store for the same reason `InMemoryToolPins` does -- a pin one
    replica holds is not a pin the next request sees.
    """

    __slots__ = ("_cards", "_pins")

    def __init__(self) -> None:
        self._cards: dict[str, dict[str, AgentCard]] = {}
        self._pins: dict[str, dict[str, str]] = {}

    def cards(self, tenant_id: str) -> Mapping[str, AgentCard]:
        return dict(self._cards.get(tenant_id, {}))

    def pins(self, tenant_id: str) -> Mapping[str, str]:
        return dict(self._pins.get(tenant_id, {}))

    def enrol(self, tenant_id: str, card: AgentCard) -> None:
        self._cards.setdefault(tenant_id, {})[card.agent_id] = card
        # Enrolment pins. An enrolled agent whose fingerprint is not recorded is
        # an agent that can change freely and never trip drift detection, which
        # would make the whole card mechanism decorative.
        self._pins.setdefault(tenant_id, {})[card.agent_id] = card.fingerprint


class TaskLedger(Protocol):
    """Remembers task ids already presented, so a replay is recognisable."""

    def seen(self, tenant_id: str) -> Iterable[str]: ...

    def record(self, tenant_id: str, task_ids: Iterable[str]) -> None: ...


class InMemoryTaskLedger:
    """Process-local replay detection. Same limits as `InMemoryAgentCards`."""

    __slots__ = ("_seen",)

    def __init__(self) -> None:
        self._seen: dict[str, set[str]] = {}

    def seen(self, tenant_id: str) -> Iterable[str]:
        return tuple(self._seen.get(tenant_id, ()))

    def record(self, tenant_id: str, task_ids: Iterable[str]) -> None:
        bucket = self._seen.setdefault(tenant_id, set())
        bucket.update(t for t in task_ids if t)


class A2AGateway:
    """Evaluates one delegation chain. Performs no I/O and speaks no protocol."""

    __slots__ = ("_gate", "_cards", "_tasks", "_max_depth", "_require_enrolment")

    def __init__(
        self,
        *,
        gate: ProtectGate,
        cards: AgentCardStore | None = None,
        tasks: TaskLedger | None = None,
        max_depth: int = MAX_DELEGATION_DEPTH,
        require_enrolment: bool = True,
    ) -> None:
        self._gate = gate
        self._cards = cards or InMemoryAgentCards()
        self._tasks = tasks or InMemoryTaskLedger()
        self._max_depth = max_depth
        # Defaults to TRUE, unlike `agent_require_grant`, and the difference is
        # deliberate: A2A delegation is new here, so requiring enrolment breaks
        # nothing that already works, whereas agents existed in every deployment
        # before capability grants did.
        self._require_enrolment = require_enrolment

    def enrol(self, tenant_id: str, card: AgentCard) -> AgentCard:
        """Register an agent card and pin its fingerprint."""
        self._cards.enrol(tenant_id, card)
        return card

    def cards_for(self, tenant_id: str) -> Mapping[str, AgentCard]:
        """The enrolled cards, for callers that need the ENDPOINT.

        Exposed rather than left to callers reaching into `_cards`, because the
        wire proxy needs exactly one thing from the store -- where an enrolled
        agent lives -- and reading it through the gateway keeps the store an
        implementation detail the proxy does not have to know the shape of.
        """
        return self._cards.cards(tenant_id)

    def evaluate(
        self,
        *,
        tenant_id: str,
        chain: DelegationChain,
        trust: TrustLevel = TrustLevel.UNSIGNED,
        known_principals: Iterable[str] | None = None,
        resource: str = "",
        constraint: DelegationConstraint | None = None,
        context: DelegationContext | None = None,
        now: Any = None,
    ) -> A2AEvaluation:
        """Inspect the chain, then run the SAME policy every other path runs."""
        cards = self._cards.cards(tenant_id)
        findings = inspect_chain(
            chain,
            cards=cards if self._require_enrolment else None,
            pinned=self._cards.pins(tenant_id),
            seen_task_ids=tuple(self._tasks.seen(tenant_id)),
            max_depth=self._max_depth,
            known_principals=known_principals,
        )
        # Phase 4: is this delegation still valid HERE and NOW, for THIS object?
        # `inspect_chain` answers a different question -- was the hop entitled
        # to what it granted -- and neither subsumes the other. A hop can be
        # perfectly entitled to a scope that expired an hour ago.
        constraint_findings: tuple[ConstraintFinding, ...] = ()
        if constraint is not None:
            if now is None:
                raise ValueError(
                    "a delegation constraint was supplied without `now`. Expiry "
                    "cannot be judged against an unspecified instant, and this "
                    "gateway holds no clock so that a chain can be replayed "
                    "against the time it actually happened."
                )
            constraint_findings = evaluate_constraint(
                constraint,
                context=context
                or DelegationContext(tenant_id=tenant_id, resource=resource),
                # REQUIRED, not defaulted to "now". This class holds no clock
                # on purpose: a gateway that reads the wall clock cannot be
                # replayed against historical evidence, which is exactly what
                # policy simulation does. A caller that supplies a constraint
                # and no clock is asking for an expiry check against an
                # unspecified instant, and the honest answer is to refuse.
                now=now,
            )

        outcome = self._gate.evaluate(
            payload=self._as_event_payload(
                chain, findings, resource=resource, constraints=constraint_findings
            ),
            trust=trust,
        )
        return A2AEvaluation(
            outcome=outcome,
            chain=chain,
            findings=findings,
            constraint_findings=constraint_findings,
        )

    def require_allowed(
        self,
        *,
        tenant_id: str,
        chain: DelegationChain,
        trust: TrustLevel = TrustLevel.UNSIGNED,
        known_principals: Iterable[str] | None = None,
        resource: str = "",
        constraint: DelegationConstraint | None = None,
        context: DelegationContext | None = None,
        now: Any = None,
    ) -> A2AEvaluation:
        """Evaluate and RAISE unless the delegation may proceed.

        Two independent reasons to refuse, and both are checked:

          * a CRITICAL structural finding -- privilege amplification, an
            unenrolled target, an unattributable principal. Policy does not get
            a vote on these. A deployment whose rules happen not to match must
            still not execute a delegation that laundered authority.
          * the policy decision itself.

        Task ids are recorded ONLY on the allowed path. Recording a refused
        delegation's task would make the operator's corrected retry look like a
        replay.
        """
        # EVERY argument forwarded. The first version of this added `constraint`,
        # `context` and `now` to the signature and did not pass them on, so the
        # enforcement path accepted a constraint and silently ignored it -- a
        # caller would believe expiry and environment were being checked while
        # only `evaluate` ever saw them. Accepted-and-ignored is worse than
        # unsupported, because unsupported fails visibly.
        evaluation = self.evaluate(
            tenant_id=tenant_id,
            chain=chain,
            trust=trust,
            known_principals=known_principals,
            resource=resource,
            constraint=constraint,
            context=context,
            now=now,
        )
        if evaluation.blocked_structurally:
            reasons = "; ".join(
                f.detail
                for f in evaluation.findings
                if f.severity is Severity.CRITICAL
            )
            raise A2ADelegationRefused(
                f"delegation refused on structural grounds: {reasons}"
            )
        if evaluation.outcome.decision.stops_action:
            raise A2ADelegationRefused(
                f"delegation refused by policy: {evaluation.outcome.decision.value}"
            )
        self._tasks.record(tenant_id, (hop.task_id for hop in chain.hops))
        return evaluation

    @staticmethod
    def _as_event_payload(
        chain: DelegationChain,
        findings: tuple[A2AFinding, ...],
        *,
        resource: str = "",
        constraints: tuple[ConstraintFinding, ...] = (),
    ) -> dict[str, Any]:
        """Project a delegation onto the payload the deterministic policy reads.

        `metadata.prompt` carries the LAST hop's instruction deliberately: that
        is the text the receiving agent treats as instructions, and it is the
        field the prompt-injection detector reads. Scopes will never reveal a
        cross-agent injection; the prose is where it lives.

        `agentId` is the TERMINAL agent -- the one about to act -- while
        `metadata.a2a.principal` carries the human whose authority it is. Both,
        because policy rules are written against `agentId` and an investigator
        needs the principal.
        """
        terminal = chain.hops[-1] if chain.hops else None
        return {
            "eventType": "agent_delegation",
            "action": "delegate",
            "resource": resource or (terminal.to_agent if terminal else ""),
            "agentId": chain.terminal_agent,
            "metadata": {
                "prompt": terminal.instruction if terminal else "",
                "a2a": {
                    "principal": chain.principal,
                    "depth": chain.depth,
                    "agents": list(chain.agents),
                    "effective_scopes": list(chain.effective_scopes),
                    "findings": [f.kind.value for f in findings],
                    "severity": worst(f.severity for f in findings).value,
                    # Named individually as well as in the list so a policy rule
                    # can match the one case without substring-matching a list.
                    "privilege_amplification": any(
                        f.kind is A2AFindingKind.PRIVILEGE_AMPLIFICATION
                        for f in findings
                    ),
                    # Phase 4 constraints, projected under their OWN key rather
                    # than appended to `findings`. A rule written to match
                    # privilege amplification must not start matching an expired
                    # delegation because both ended up in one list.
                    "constraints": [f.kind.value for f in constraints],
                    "constraint_severity": (
                        worst(f.severity for f in constraints).value
                        if constraints
                        else "low"
                    ),
                    # The two that are authority claims rather than hygiene, so
                    # a rule can match them without parsing a list.
                    "tenant_mismatch": any(
                        f.kind is ConstraintKind.TENANT_MISMATCH for f in constraints
                    ),
                    "environment_escalation": any(
                        f.kind is ConstraintKind.ENVIRONMENT_ESCALATION
                        for f in constraints
                    ),
                    "delegation_expired": any(
                        f.kind is ConstraintKind.EXPIRED for f in constraints
                    ),
                },
            },
        }
