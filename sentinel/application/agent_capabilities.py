"""What an enrolled agent may INVOKE, as opposed to who it is.

THE GAP THIS CLOSES
-------------------
Enrolment answered "is this agent one we know". It never answered "what is this
agent allowed to do". The `agents` table holds an address, a label, an enrolment
time and a revocation time -- and nothing about capability -- so any enrolled
agent could invoke any registered tool. A summarisation agent and a deployment
agent had exactly the same reach.

That is an asymmetry with the rest of this system rather than an oversight in
isolation. `McpGateway` pins what a SERVER may offer. `FileSandbox` bounds what
an EFFECT may touch. Nothing pinned what an AGENT may invoke, which left the
weakest link at the point an attacker actually reaches: a compromised or
prompt-injected agent has whatever credential the real agent had, and until now
that credential was good for every tool on the proxy.

WHY GRANTS AND NOT ROLES
------------------------
A role would need a taxonomy that fits every customer's agents, and the ones
that fit everybody ("reader", "writer") stop meaning anything the moment tools
have different blast radii -- `read_file` and `http_request` are both "read" and
only one of them can exfiltrate. A grant names the tool, so the reviewable
question is the concrete one: may THIS agent call THIS tool.

OBSERVE MODE IS THE DEFAULT, AND THAT IS DELIBERATE
-----------------------------------------------------
`require_grant` defaults to FALSE, unlike `McpGateway`'s pin requirement, which
defaults to true. The difference is not inconsistency:

  * MCP enrolment was new. No deployment had MCP servers, so requiring pins on
    day one broke nothing.
  * Agents already exist in every pilot. Defaulting to deny would mean an
    upgrade silently stops every working agent, and the response to that is an
    operator switching the feature off permanently at 3am -- which is worse than
    an honest observe mode, because it is off AND nobody is looking at it.

So an ungranted agent is ALLOWED while `require_grant` is false, and the
decision records that the check was skipped. `AgentCapabilityDecision.enforced`
exists precisely so "allowed" cannot be mistaken for "allowed because it was
permitted". An operator grants capabilities, watches the observed set, then
turns enforcement on with evidence rather than hope.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from sentinel.domain.errors import DomainRuleViolated

__all__ = [
    "AgentCapabilityRefused",
    "AgentCapabilityDecision",
    "AgentCapabilityStore",
    "InMemoryAgentCapabilities",
    "AgentCapabilityGate",
]


class AgentCapabilityRefused(DomainRuleViolated):
    """An agent invoked a tool it was not granted.

    Not retryable: a missing grant is an operator decision, and retrying without
    one changes nothing.
    """

    is_retryable = False


@dataclass(frozen=True, slots=True)
class AgentCapabilityDecision:
    """Whether the call may proceed, and whether the check actually decided it.

    `allowed` and `enforced` are separate on purpose. In observe mode `allowed`
    is True for an agent with no grants at all, and reporting only `allowed`
    would make a skipped check indistinguishable from a passed one -- the
    gate-that-executes-nothing shape this codebase keeps finding.
    """

    allowed: bool
    enforced: bool
    agent_id: str
    tool: str
    granted: tuple[str, ...] = ()
    reason: str = ""

    #: The grant store could not be read, so `granted` is empty because nothing
    #: was LEARNED -- not because the agent holds no grants. Separate from
    #: `allowed` and `enforced` for the same reason those are separate from each
    #: other: without it, a degraded observe-mode allow is byte-identical to a
    #: healthy one, and an operator reading the audit record cannot tell that
    #: the check never ran. `RateLimitDecision.degraded` exists for this exact
    #: reason and this mirrors it deliberately.
    degraded: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "enforced": self.enforced,
            "agent_id": self.agent_id,
            "tool": self.tool,
            "granted": list(self.granted),
            "reason": self.reason,
            "degraded": self.degraded,
        }


class AgentCapabilityStore(Protocol):
    """Where an agent's granted tools live."""

    def granted(self, tenant_id: str, agent_id: str) -> frozenset[str]: ...

    def grant(self, tenant_id: str, agent_id: str, tools: frozenset[str]) -> None: ...

    def revoke(self, tenant_id: str, agent_id: str, tools: frozenset[str]) -> None: ...


@dataclass
class InMemoryAgentCapabilities:
    """Process-local grants. Tests and single-process use only.

    Keyed by `(tenant_id, agent_id)`. An agent id is a tenant-local handle, so a
    store keyed on agent id alone would let one tenant's grant answer another
    tenant's call -- the defect this repository has already shipped once in a
    different table.
    """

    #: `default_factory`, not `None` with a `__post_init__` guard. The guard
    #: version needed an `assert` in every method to satisfy a type checker, and
    #: `assert` is stripped under `python -O` -- so the "invariant" would not
    #: exist in a deployment that enabled optimisations.
    #: `test_nothing_uses_assert_for_a_runtime_invariant` caught exactly that.
    _grants: dict[tuple[str, str], set[str]] = field(default_factory=dict)

    def granted(self, tenant_id: str, agent_id: str) -> frozenset[str]:
        return frozenset(self._grants.get((tenant_id, agent_id), set()))

    def grant(self, tenant_id: str, agent_id: str, tools: frozenset[str]) -> None:
        self._grants.setdefault((tenant_id, agent_id), set()).update(tools)

    def revoke(self, tenant_id: str, agent_id: str, tools: frozenset[str]) -> None:
        current = self._grants.get((tenant_id, agent_id))
        if current is not None:
            current.difference_update(tools)


class AgentCapabilityGate:
    """Decide whether an agent may invoke a tool.

    Sits in FRONT of `ProtectGate` rather than beside it, and the two answer
    different questions. Protect asks "is this action dangerous"; this asks "is
    this agent supposed to be doing it at all". A perfectly benign `read_file`
    from an agent whose only job is to summarise text is not dangerous by
    content and is still wrong.
    """

    __slots__ = ("_store", "_require_grant")

    def __init__(
        self,
        *,
        store: AgentCapabilityStore | None = None,
        require_grant: bool = False,
    ) -> None:
        self._store = store if store is not None else InMemoryAgentCapabilities()
        self._require_grant = bool(require_grant)

    @property
    def enforced(self) -> bool:
        return self._require_grant

    def decide(
        self, *, tenant_id: str, agent_id: str, tool: str
    ) -> AgentCapabilityDecision:
        """Evaluate one invocation. Returns; never raises.

        THE OUTAGE CASE, WHICH USED TO CONTRADICT THAT SENTENCE
        ------------------------------------------------------
        `self._store` is Redis or Postgres in a deployment, so losing the
        availability zone holding it makes `granted` raise. That read was the
        first statement in this method, ahead of the `_require_grant` branch,
        so the exception escaped BOTH modes -- and observe mode exists
        precisely to not block: it is how Phase 30 onboards a design partner
        while an operator is still discovering which grants are needed, and it
        labels its own allow "This is not an authorisation."

        A store blip therefore took an outage in the one mode that had been
        sold as decisive of nothing, and `decide` raised from a method
        documenting that it never does -- so any caller that trusted the
        docstring and omitted a handler propagated it.

        The two modes want OPPOSITE things from the same fault, which is why
        this is not one blanket try/except at the call site:

          - observe mode must ALLOW, because it never decided anything anyway;
          - enforcing mode must REFUSE, because an unreadable grant store is
            indistinguishable from an agent holding no grant.

        Both are marked `degraded`, and both name the outage in `reason`. An
        allow that silently means "we could not check" is the failure this
        codebase keeps finding, and `degraded` is what stops it being silent.
        """
        try:
            granted = self._store.granted(tenant_id, agent_id)
        except Exception as exc:  # noqa: BLE001 - every backend failure, one meaning
            detail = f"{type(exc).__name__}: {exc}"[:200]
            if not self._require_grant:
                return AgentCapabilityDecision(
                    allowed=True,
                    enforced=False,
                    agent_id=agent_id,
                    tool=tool,
                    granted=(),
                    degraded=True,
                    reason=(
                        f"the capability store could not be read ({detail}), so "
                        f"no grant for {tool!r} could be checked. Permitted "
                        "because capability enforcement is OFF (observe mode). "
                        "This is not an authorisation, and unlike a healthy "
                        "observe-mode allow it is not evidence the agent has no "
                        "grants -- nothing was read."
                    ),
                )
            return AgentCapabilityDecision(
                allowed=False,
                enforced=True,
                agent_id=agent_id,
                tool=tool,
                granted=(),
                degraded=True,
                reason=(
                    f"the capability store could not be read ({detail}), so "
                    f"whether {agent_id!r} is granted {tool!r} is UNKNOWN. "
                    "Refused because capability enforcement is ON: an "
                    "unreadable grant store cannot be distinguished from an "
                    "agent that holds no grant, and the safe reading of the two "
                    "is the same one."
                ),
            )

        if tool in granted:
            return AgentCapabilityDecision(
                allowed=True,
                enforced=self._require_grant,
                agent_id=agent_id,
                tool=tool,
                granted=tuple(sorted(granted)),
            )

        if not self._require_grant:
            # OBSERVE MODE. Allowed, and the record says the check did not
            # decide it -- so a reader cannot mistake this for a grant.
            return AgentCapabilityDecision(
                allowed=True,
                enforced=False,
                agent_id=agent_id,
                tool=tool,
                granted=tuple(sorted(granted)),
                reason=(
                    f"agent {agent_id!r} has no grant for {tool!r}; permitted "
                    "because capability enforcement is OFF (observe mode). This "
                    "is not an authorisation."
                ),
            )

        return AgentCapabilityDecision(
            allowed=False,
            enforced=True,
            agent_id=agent_id,
            tool=tool,
            granted=tuple(sorted(granted)),
            reason=(
                f"agent {agent_id!r} is not granted {tool!r}. Granted: "
                f"{', '.join(sorted(granted)) or '(none)'}. Grant it deliberately "
                f"with `cli agent-grant <tenant> {agent_id} {tool}`."
            ),
        )

    def require(self, *, tenant_id: str, agent_id: str, tool: str) -> AgentCapabilityDecision:
        """Evaluate and RAISE on refusal.

        The form callers should reach for. `decide` returns a value a caller can
        forget to check; this one cannot be ignored by omission -- the same
        reason `McpGateway.require_allowed` exists.
        """
        decision = self.decide(tenant_id=tenant_id, agent_id=agent_id, tool=tool)
        if not decision.allowed:
            raise AgentCapabilityRefused(decision.reason)
        return decision
