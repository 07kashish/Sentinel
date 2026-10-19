"""What Sentinel may do to the world, and who gets to decide.

TWO QUESTIONS, DELIBERATELY SEPARATED
---------------------------------------
"What is this action?" and "may it run without a human?" are different
questions, and the specification answers them in different sections. §34 asks
for a catalogue of concrete actions; §33 asks for a strategy that maps how bad
a thing is onto how much autonomy the response gets. Keeping them apart means
a new action inherits the strategy instead of re-arguing it, and a change to
the strategy applies to every action at once.

THE RULE THE SPECIFICATION IS EMPHATIC ABOUT
----------------------------------------------
    Do NOT give an LLM unrestricted power to perform remediation.
    AI -> investigation/recommendation
    deterministic engine -> enforcement

So `decide_response` is a pure function of the severity and the action's own
declared properties. No model output reaches it. A model may *recommend* -- and
`Disposition` carries that recommendation to a human -- but a recommendation is
an argument, and this function is the decision.

WHY SELF-REPORTED EVIDENCE CANNOT TRIGGER AUTOMATION
------------------------------------------------------
This is the subtle one, and it is the reason `decide_response` takes a second
argument that looks redundant.

Phase 3 raises incident severity when a sequence rule matches on the execution
graph. That graph is built from `parentEventId`, `sessionId` and `eventId` --
all THREE self-reported by the agent. `execution_graph.py` says so directly:
evidence, never authority, and nothing in the enforcement path consults it.

If severity alone drove automatic containment, that guarantee would be quietly
undone here. A hostile agent that can shape a graph can manufacture a
`credential_to_privilege` match, which scores 90, which is CRITICAL -- and
would then trigger deterministic containment. Point that at a *different*
agent's session id and the attack stops being a self-inflicted denial of
service and becomes a way to disable someone else's production agent by
writing three JSON bodies.

So evidence provenance travels with the severity, and self-reported evidence
caps the disposition at `REQUIRE_APPROVAL` no matter how high the score. The
finding still surfaces, at full severity, to a human. It simply does not get to
pull the trigger by itself.

WHY "REVERSIBLE" IS A PROPERTY OF THE ACTION AND NOT A JUDGEMENT CALL
----------------------------------------------------------------------
§33 permits automatic *reversible* actions at MEDIUM. That is only safe if
"reversible" means something specific. Here it means: this module can name the
operation that undoes it, and `rollback_for` returns that operation. An action
with no named inverse is not reversible, whatever it feels like -- rotating a
token is not undoable by rotating it again, and killing a container does not
un-kill by starting a new one, because the new one is not the old one.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Final, Mapping

from sentinel.domain.errors import DomainRuleViolated
from sentinel.domain.primitives import Priority, Severity

__all__ = [
    "BlastRadius",
    "Disposition",
    "EvidenceOrigin",
    "RemediationAction",
    "ResponseDecision",
    "UnknownRemediationAction",
    "REMEDIATION_ACTIONS",
    "action_named",
    "decide_response",
    "rollback_for",
]


class UnknownRemediationAction(DomainRuleViolated):
    """An action name that is not in the catalogue.

    Refused rather than passed through. An executor that accepted an arbitrary
    string would let a typo become an un-auditable action name, and would let a
    caller invent one that no policy has ever reasoned about.
    """

    is_retryable = False


class BlastRadius(str, Enum):
    """How much stops working if this action is wrong.

    The ordering is the point: an action that can only affect its own target is
    a different risk from one that halts a fleet, and the strategy below refuses
    to take the wide ones automatically at any severity.
    """

    #: One agent, one key, one container. A mistake affects one thing.
    SINGLE = "single"
    #: A group, a tool, an MCP server. A mistake affects everything using it.
    GROUP = "group"
    #: The tenant's estate. A mistake is an outage.
    ESTATE = "estate"


class EvidenceOrigin(str, Enum):
    """Where the severity came from, and therefore how far it may be trusted.

    Not a confidence score. A confidence number invites arithmetic -- averaging
    it, weighting it, letting a high-confidence self-report out-vote an observed
    fact. This is a categorical statement about who produced the evidence, and
    the strategy treats it as a ceiling rather than a term.
    """

    #: Sentinel observed it in the enforcement path: a policy match on a request
    #: that actually passed through the gateway.
    OBSERVED = "observed"
    #: The agent told us. Execution-graph correlation, declared intent, baselines
    #: built from an agent's own history. Real evidence, and shapeable by the
    #: thing it is evidence about.
    SELF_REPORTED = "self_reported"


class Disposition(str, Enum):
    """What happens next. The output of the strategy."""

    #: Record it. Nothing acts.
    OBSERVE = "observe"
    #: Run it now: non-disruptive and reversible.
    AUTOMATIC_SAFE = "automatic_safe"
    #: Run it now: disruptive but reversible, and the severity justifies it.
    AUTOMATIC_REVERSIBLE = "automatic_reversible"
    #: Raise an approval and wait for a person.
    REQUIRE_APPROVAL = "require_approval"
    #: Deterministic emergency containment, pre-declared, no model involved.
    EMERGENCY_CONTAINMENT = "emergency_containment"


@dataclass(frozen=True, slots=True)
class RemediationAction:
    """One concrete thing that can be done to a real system.

    The flags are not documentation. `decide_response` reads them, so declaring
    an action `reversible` when nothing can undo it is the way to get it run
    automatically when it should not have been.
    """

    name: str
    #: One line an operator reads in an approval or an audit row.
    summary: str
    #: Which external system performs it. Wiring, not behaviour -- but it is what
    #: an operator checks first when an action is unsupported.
    provider: str
    blast_radius: BlastRadius
    #: True when `rollback_for` names an operation that genuinely restores the
    #: prior state. See the module docstring: this is a claim about an inverse
    #: existing, not a feeling about how serious the action is.
    reversible: bool
    #: True when the action stops work that was otherwise succeeding. A
    #: non-disruptive action is one whose worst case is a notification nobody
    #: needed.
    disruptive: bool
    #: The action that undoes this one, if there is one.
    rollback: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "summary": self.summary,
            "provider": self.provider,
            "blast_radius": self.blast_radius.value,
            "reversible": self.reversible,
            "disruptive": self.disruptive,
            "rollback": self.rollback,
        }


#: The catalogue the specification enumerates, in its order.
#:
#: Each entry declares what undoing it means. Where the rollback string is empty
#: the action is genuinely one-way, and saying so here is what keeps it out of
#: the automatic dispositions below.
REMEDIATION_ACTIONS: Final[tuple[RemediationAction, ...]] = (
    RemediationAction(
        name="disable_agent",
        summary="Stop one agent from acting",
        provider="sentinel",
        blast_radius=BlastRadius.SINGLE,
        reversible=True,
        disruptive=True,
        rollback="enable_agent",
    ),
    RemediationAction(
        name="revoke_agent_credential",
        summary="Revoke the credential an agent presents",
        provider="sentinel",
        blast_radius=BlastRadius.SINGLE,
        reversible=False,
        disruptive=True,
        # No rollback: a revoked credential is not un-revoked. Issuing a new one
        # is a different credential, and calling that a rollback would let this
        # action be taken automatically on the strength of a lie.
    ),
    RemediationAction(
        name="rotate_token",
        summary="Rotate a token, invalidating the old value",
        provider="sentinel",
        blast_radius=BlastRadius.SINGLE,
        reversible=False,
        disruptive=True,
    ),
    RemediationAction(
        name="disable_api_key",
        summary="Disable an API key",
        provider="sentinel",
        blast_radius=BlastRadius.SINGLE,
        reversible=True,
        disruptive=True,
        rollback="enable_api_key",
    ),
    RemediationAction(
        name="block_mcp_server",
        summary="Block an MCP server for this tenant",
        provider="sentinel",
        blast_radius=BlastRadius.GROUP,
        reversible=True,
        disruptive=True,
        rollback="unblock_mcp_server",
    ),
    RemediationAction(
        name="remove_tool_access",
        summary="Remove an agent's grant for one tool",
        provider="sentinel",
        blast_radius=BlastRadius.SINGLE,
        reversible=True,
        disruptive=True,
        rollback="restore_tool_access",
    ),
    RemediationAction(
        name="kill_container",
        summary="Terminate a running container",
        provider="kubernetes",
        blast_radius=BlastRadius.SINGLE,
        reversible=False,
        disruptive=True,
        # Restarting produces a new container, not the old one. Its in-memory
        # state is gone either way.
    ),
    RemediationAction(
        name="quarantine_workload",
        summary="Apply a deny-all network policy to a workload",
        provider="kubernetes",
        blast_radius=BlastRadius.SINGLE,
        reversible=True,
        disruptive=True,
        rollback="release_workload",
    ),
    RemediationAction(
        name="revoke_cloud_session",
        summary="Revoke active cloud sessions for a principal",
        provider="aws",
        blast_radius=BlastRadius.SINGLE,
        reversible=False,
        disruptive=True,
    ),
    RemediationAction(
        name="disable_service_account",
        summary="Disable a service account",
        provider="gcp",
        blast_radius=BlastRadius.SINGLE,
        reversible=True,
        disruptive=True,
        rollback="enable_service_account",
    ),
    RemediationAction(
        name="block_external_domain",
        summary="Add a destination to the tenant's egress denylist",
        provider="sentinel",
        blast_radius=BlastRadius.GROUP,
        reversible=True,
        disruptive=True,
        rollback="unblock_external_domain",
    ),
    RemediationAction(
        name="pause_workflow",
        summary="Pause a running workflow",
        provider="sentinel",
        blast_radius=BlastRadius.GROUP,
        reversible=True,
        disruptive=True,
        rollback="resume_workflow",
    ),
    RemediationAction(
        name="pause_high_risk_agents",
        summary="Pause every agent currently classed high-risk",
        provider="sentinel",
        # The only ESTATE-radius action, and the reason that radius exists. §35
        # lists it as an operator control, which is precisely what it must stay:
        # `decide_response` refuses it automatically at every severity, so it can
        # only ever be reached through a human decision.
        blast_radius=BlastRadius.ESTATE,
        reversible=True,
        disruptive=True,
        rollback="resume_high_risk_agents",
    ),
    RemediationAction(
        name="resume_high_risk_agents",
        summary="Lift an estate-wide high-risk pause",
        provider="sentinel",
        blast_radius=BlastRadius.ESTATE,
        reversible=True,
        disruptive=False,
        rollback="pause_high_risk_agents",
    ),
    RemediationAction(
        name="notify_owner",
        summary="Notify the registered owner of the affected agent",
        provider="notification",
        blast_radius=BlastRadius.SINGLE,
        reversible=False,
        # The only non-disruptive action in the catalogue, and the reason
        # AUTOMATIC_SAFE exists: at LOW severity there should be something worth
        # doing, and telling the owner is it.
        disruptive=False,
    ),
    RemediationAction(
        name="create_incident_ticket",
        summary="Open a ticket in the tenant's ITSM system",
        provider="itsm",
        blast_radius=BlastRadius.SINGLE,
        reversible=False,
        disruptive=False,
    ),
    # ── Inverses ─────────────────────────────────────────────────────────────
    # Present in the catalogue because a rollback is itself an executed action:
    # it needs a target, an idempotency key, an audit row and a receipt, exactly
    # like the action it undoes. Naming them here also means `rollback_for`
    # cannot point at something that does not exist.
    RemediationAction(
        name="enable_agent",
        summary="Allow a disabled agent to act again",
        provider="sentinel",
        blast_radius=BlastRadius.SINGLE,
        reversible=True,
        disruptive=False,
        rollback="disable_agent",
    ),
    RemediationAction(
        name="enable_api_key",
        summary="Re-enable a disabled API key",
        provider="sentinel",
        blast_radius=BlastRadius.SINGLE,
        reversible=True,
        disruptive=False,
        rollback="disable_api_key",
    ),
    RemediationAction(
        name="unblock_mcp_server",
        summary="Remove an MCP server from the tenant blocklist",
        provider="sentinel",
        blast_radius=BlastRadius.GROUP,
        reversible=True,
        disruptive=False,
        rollback="block_mcp_server",
    ),
    RemediationAction(
        name="restore_tool_access",
        summary="Restore a removed tool grant",
        provider="sentinel",
        blast_radius=BlastRadius.SINGLE,
        reversible=True,
        disruptive=False,
        rollback="remove_tool_access",
    ),
    RemediationAction(
        name="release_workload",
        summary="Remove a quarantine network policy",
        provider="kubernetes",
        blast_radius=BlastRadius.SINGLE,
        reversible=True,
        disruptive=False,
        rollback="quarantine_workload",
    ),
    RemediationAction(
        name="enable_service_account",
        summary="Re-enable a disabled service account",
        provider="gcp",
        blast_radius=BlastRadius.SINGLE,
        reversible=True,
        disruptive=False,
        rollback="disable_service_account",
    ),
    RemediationAction(
        name="unblock_external_domain",
        summary="Remove a destination from the egress denylist",
        provider="sentinel",
        blast_radius=BlastRadius.GROUP,
        reversible=True,
        disruptive=False,
        rollback="block_external_domain",
    ),
    RemediationAction(
        name="resume_workflow",
        summary="Resume a paused workflow",
        provider="sentinel",
        blast_radius=BlastRadius.GROUP,
        reversible=True,
        disruptive=False,
        rollback="pause_workflow",
    ),
)


_BY_NAME: Final[Mapping[str, RemediationAction]] = MappingProxyType(
    {action.name: action for action in REMEDIATION_ACTIONS}
)


def action_named(name: str) -> RemediationAction:
    """Look an action up, refusing anything not in the catalogue."""
    action = _BY_NAME.get((name or "").strip())
    if action is None:
        raise UnknownRemediationAction(f"{name!r} is not a known remediation action")
    return action


def rollback_for(name: str) -> RemediationAction | None:
    """The action that undoes `name`, or None when nothing does."""
    action = action_named(name)
    if not action.rollback:
        return None
    return action_named(action.rollback)


#: Actions permitted as deterministic emergency containment at CRITICAL.
#:
#: Pre-declared, and short on purpose. This is the one path where the system
#: acts against a live production workload with no human in the loop, so the set
#: is a fixed list that an operator can read in one glance rather than a
#: predicate that happens to select a few actions today and more tomorrow.
#:
#: Every member is reversible and SINGLE-radius: the worst case of a false
#: positive here is one agent stopped and a release call to undo it.
EMERGENCY_CONTAINMENT_ACTIONS: Final[frozenset[str]] = frozenset(
    {"disable_agent", "quarantine_workload", "remove_tool_access"}
)


@dataclass(frozen=True, slots=True)
class ResponseDecision:
    """The strategy's answer, with the reason attached.

    The reason travels because "why did this run without asking me" is the first
    question an operator has after an automatic action, and reconstructing it
    from a severity number and a catalogue lookup takes longer than it should.
    """

    action: RemediationAction
    disposition: Disposition
    priority: Priority
    reason: str
    #: True when a higher disposition was available on severity alone and
    #: something -- provenance, blast radius, irreversibility -- held it back.
    #: Surfaced so an operator can see the system chose restraint deliberately
    #: rather than failing to notice.
    restrained: bool = False

    @property
    def is_automatic(self) -> bool:
        return self.disposition in {
            Disposition.AUTOMATIC_SAFE,
            Disposition.AUTOMATIC_REVERSIBLE,
            Disposition.EMERGENCY_CONTAINMENT,
        }

    @property
    def needs_human(self) -> bool:
        return self.disposition is Disposition.REQUIRE_APPROVAL

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.name,
            "disposition": self.disposition.value,
            "priority": self.priority.value,
            "reason": self.reason,
            "restrained": self.restrained,
            "automatic": self.is_automatic,
        }


def decide_response(
    action: RemediationAction | str,
    severity: Severity,
    *,
    origin: EvidenceOrigin = EvidenceOrigin.SELF_REPORTED,
) -> ResponseDecision:
    """Map severity and an action's properties onto how much autonomy it gets.

    Deterministic, total, and reads nothing but its arguments -- the "no LLM in
    enforcement" requirement is satisfied by there being nowhere for a model to
    plug in, rather than by a comment asking callers not to.

    `origin` defaults to SELF_REPORTED, which is the restrictive value. A caller
    that forgets to pass it gets a human in the loop rather than an automatic
    action against production; the safe default is the one you get by accident.
    """
    action = action if isinstance(action, RemediationAction) else action_named(action)
    priority = severity.priority

    # ── The ceiling, applied first ───────────────────────────────────────────
    # A wide blast radius is never automatic, at any severity. An action that can
    # halt a fleet is one where a false positive IS the incident, and the whole
    # point of `pause all high-risk agents` living behind an operator's hand is
    # that nobody wants a detector to reach for it unattended.
    if action.blast_radius is BlastRadius.ESTATE:
        return ResponseDecision(
            action=action,
            disposition=Disposition.REQUIRE_APPROVAL,
            priority=priority,
            reason=(
                f"{action.name} affects the whole estate; estate-wide actions "
                f"always require a human decision"
            ),
            restrained=priority in {Priority.CRITICAL, Priority.HIGH},
        )

    # ── CRITICAL: deterministic emergency containment ────────────────────────
    if priority is Priority.CRITICAL:
        if origin is EvidenceOrigin.SELF_REPORTED:
            # See the module docstring. The whole self-reported-correlation
            # attack lands here, and this is where it stops.
            return ResponseDecision(
                action=action,
                disposition=Disposition.REQUIRE_APPROVAL,
                priority=priority,
                reason=(
                    "severity is critical but rests on self-reported evidence, "
                    "which the reported-on agent can shape; a human decides"
                ),
                restrained=True,
            )
        if action.name in EMERGENCY_CONTAINMENT_ACTIONS:
            return ResponseDecision(
                action=action,
                disposition=Disposition.EMERGENCY_CONTAINMENT,
                priority=priority,
                reason=(
                    f"observed critical activity; {action.name} is pre-declared "
                    f"emergency containment and is reversible"
                ),
            )
        return ResponseDecision(
            action=action,
            disposition=Disposition.REQUIRE_APPROVAL,
            priority=priority,
            reason=(
                f"{action.name} is not in the pre-declared emergency containment "
                f"set; containment is a fixed list, not a severity threshold"
            ),
            restrained=True,
        )

    # ── HIGH: a person decides ───────────────────────────────────────────────
    if priority is Priority.HIGH:
        return ResponseDecision(
            action=action,
            disposition=Disposition.REQUIRE_APPROVAL,
            priority=priority,
            reason="high severity requires human approval before acting",
        )

    # ── MEDIUM: automatic, but only what can be undone ───────────────────────
    if priority is Priority.MEDIUM:
        if not action.disruptive:
            return ResponseDecision(
                action=action,
                disposition=Disposition.AUTOMATIC_SAFE,
                priority=priority,
                reason=f"{action.name} is non-disruptive and safe to run unattended",
            )
        if action.reversible and origin is EvidenceOrigin.OBSERVED:
            return ResponseDecision(
                action=action,
                disposition=Disposition.AUTOMATIC_REVERSIBLE,
                priority=priority,
                reason=(
                    f"observed medium-severity activity; {action.name} is "
                    f"reversible via {action.rollback}"
                ),
            )
        if action.reversible:
            return ResponseDecision(
                action=action,
                disposition=Disposition.REQUIRE_APPROVAL,
                priority=priority,
                reason=(
                    f"{action.name} is reversible but the evidence is "
                    f"self-reported; a human decides"
                ),
                restrained=True,
            )
        return ResponseDecision(
            action=action,
            disposition=Disposition.REQUIRE_APPROVAL,
            priority=priority,
            reason=(
                f"{action.name} cannot be undone; irreversible actions are never "
                f"automatic"
            ),
            restrained=True,
        )

    # ── LOW: notify, or do nothing ───────────────────────────────────────────
    if not action.disruptive:
        return ResponseDecision(
            action=action,
            disposition=Disposition.AUTOMATIC_SAFE,
            priority=priority,
            reason=f"{action.name} is non-disruptive; safe at low severity",
        )
    return ResponseDecision(
        action=action,
        disposition=Disposition.OBSERVE,
        priority=priority,
        reason=(
            f"low severity does not justify {action.name}, which interrupts work; "
            f"recorded without acting"
        ),
        restrained=True,
    )
