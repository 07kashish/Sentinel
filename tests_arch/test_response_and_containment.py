"""Safe autonomous response and the granular kill switch.

THE CLAIM THESE TESTS EXIST TO SUPPORT
----------------------------------------
Automated response is the point in this product where a detector stops writing
rows and starts breaking things. Every other subsystem's worst failure is a
missed alert or a noisy one; this one's worst failure is stopping production
work that was fine.

So the tests below are built around one question: what does the system decline
to do on its own? A response engine that acts on everything is easy to write and
impossible to deploy, and the interesting assertions here are all negative --
the estate-wide action that stays behind a human, the critical severity that
does NOT trigger containment because of where the evidence came from, the
irreversible action that never runs unattended.

THE ATTACK THAT SHAPED `decide_response`
------------------------------------------
Phase 3 raises severity from sequence rules that read the execution graph, and
that graph is built entirely from self-reported correlation -- `eventId`,
`sessionId`, `parentEventId`. `execution_graph.py` promises that nothing in the
enforcement path consults it, precisely because an agent can draw whatever
arrows it likes.

Automatic containment driven by severity alone would have broken that promise
from a different direction. A hostile agent forges a `credential_to_privilege`
chain -- severity 90, CRITICAL -- against ANOTHER agent's session id, and the
system disables a healthy production agent on the strength of three JSON bodies.
`test_a_forged_sequence_chain_cannot_trigger_automatic_containment` is that
attack, written down.
"""

from __future__ import annotations

import pytest

from sentinel.domain.containment import (
    Containment,
    ContainmentScope,
    InvalidContainment,
    evaluate_containment,
)
from sentinel.domain.primitives import Priority, Severity
from sentinel.domain.remediation import (
    EMERGENCY_CONTAINMENT_ACTIONS,
    REMEDIATION_ACTIONS,
    BlastRadius,
    Disposition,
    EvidenceOrigin,
    UnknownRemediationAction,
    action_named,
    decide_response,
    rollback_for,
)

NOW = "2026-08-24T12:00:00Z"


def _containment(scope: ContainmentScope, selector: str = "", **kw) -> Containment:
    return Containment(
        containment_id=kw.pop("containment_id", f"c-{scope.value}"),
        tenant_id="acme",
        scope=scope,
        selector=selector,
        created_by=kw.pop("created_by", "analyst@acme.test"),
        created_at="2026-08-24T00:00:00Z",
        **kw,
    )


# ── The catalogue ────────────────────────────────────────────────────────────


def test_every_action_the_specification_names_is_in_the_catalogue():
    """The list is copied from section 34. A catalogue missing an entry is a
    remediation that cannot be requested, which is invisible until an incident
    needs it."""
    required = {
        "disable_agent",
        "revoke_agent_credential",
        "rotate_token",
        "disable_api_key",
        "block_mcp_server",
        "remove_tool_access",
        "kill_container",
        "quarantine_workload",
        "revoke_cloud_session",
        "disable_service_account",
        "block_external_domain",
        "pause_workflow",
        "notify_owner",
        "create_incident_ticket",
    }
    assert required <= {a.name for a in REMEDIATION_ACTIONS}


def test_an_action_outside_the_catalogue_is_refused_rather_than_passed_through():
    """An executor accepting arbitrary strings lets a typo become an
    un-auditable action name."""
    with pytest.raises(UnknownRemediationAction):
        action_named("disable_agnet")


def test_every_reversible_action_names_a_rollback_that_actually_exists():
    """`reversible` is read by the response strategy, so an action claiming it
    without a real inverse is the way to get run automatically when you should
    not have been."""
    for action in REMEDIATION_ACTIONS:
        if not action.reversible:
            continue
        assert action.rollback, f"{action.name} claims reversible with no rollback"
        # Raises UnknownRemediationAction if the inverse is not in the catalogue.
        assert rollback_for(action.name) is not None


def test_an_irreversible_action_declares_no_rollback():
    """Revoking a credential is not undone by issuing a new one -- that is a
    different credential. Naming it a rollback would be a lie the strategy
    believes."""
    assert action_named("revoke_agent_credential").reversible is False
    assert rollback_for("revoke_agent_credential") is None


def test_every_emergency_containment_action_is_reversible_and_narrow():
    """This is the one path that touches production with no human. The worst
    case of a false positive must be one agent stopped and one call to undo
    it."""
    for name in EMERGENCY_CONTAINMENT_ACTIONS:
        action = action_named(name)
        assert action.reversible, f"{name} runs unattended and cannot be undone"
        assert action.blast_radius is BlastRadius.SINGLE


# ── The response strategy (section 33) ───────────────────────────────────────


def test_low_severity_notifies_but_does_not_interrupt():
    low = Severity(10)
    assert decide_response("notify_owner", low).disposition is Disposition.AUTOMATIC_SAFE
    assert decide_response("disable_agent", low).disposition is Disposition.OBSERVE


def test_medium_severity_runs_reversible_actions_automatically():
    decision = decide_response(
        "quarantine_workload", Severity(50), origin=EvidenceOrigin.OBSERVED
    )
    assert decision.priority is Priority.MEDIUM
    assert decision.disposition is Disposition.AUTOMATIC_REVERSIBLE
    assert decision.is_automatic


def test_medium_severity_will_not_run_an_irreversible_action():
    """Section 33 permits automatic *reversible* action at medium. Rotating a
    token cannot be undone, so it is not that."""
    decision = decide_response(
        "rotate_token", Severity(50), origin=EvidenceOrigin.OBSERVED
    )
    assert decision.disposition is Disposition.REQUIRE_APPROVAL
    assert decision.restrained


def test_high_severity_requires_a_human():
    decision = decide_response(
        "disable_agent", Severity(75), origin=EvidenceOrigin.OBSERVED
    )
    assert decision.priority is Priority.HIGH
    assert decision.needs_human


def test_critical_observed_activity_triggers_deterministic_containment():
    """The one case where the system acts alone."""
    decision = decide_response(
        "disable_agent", Severity(95), origin=EvidenceOrigin.OBSERVED
    )
    assert decision.disposition is Disposition.EMERGENCY_CONTAINMENT
    assert decision.is_automatic


def test_a_forged_sequence_chain_cannot_trigger_automatic_containment():
    """THE headline case for this module.

    `credential_to_privilege` scores 90 -- CRITICAL. It is detected on the
    execution graph, which is built from self-reported correlation an agent
    controls. If severity alone drove containment, forging that chain against
    another agent's session id would disable a healthy production agent."""
    decision = decide_response(
        "disable_agent", Severity(90), origin=EvidenceOrigin.SELF_REPORTED
    )
    assert decision.disposition is Disposition.REQUIRE_APPROVAL
    assert not decision.is_automatic
    assert decision.restrained
    # The severity is NOT reduced. The finding reaches a human at full weight;
    # it simply does not pull the trigger by itself.
    assert decision.priority is Priority.CRITICAL


def test_the_restrictive_provenance_is_the_default():
    """A caller that forgets the argument must get a human in the loop, not an
    automatic action against production."""
    assert decide_response("disable_agent", Severity(95)).needs_human


def test_an_estate_wide_action_is_never_automatic_at_any_severity():
    """A false positive on an estate-wide action IS the incident."""
    estate = [a for a in REMEDIATION_ACTIONS if a.blast_radius is BlastRadius.ESTATE]
    # Without this the loop below iterates zero times and the test passes while
    # asserting nothing -- the defect class this repository has found more often
    # than any other, and one an earlier draft of this very test shipped with.
    assert estate, "no estate-radius action exists; this test would prove nothing"
    for action in estate:
        for severity in (Severity(10), Severity(50), Severity(75), Severity(100)):
            decision = decide_response(
                action, severity, origin=EvidenceOrigin.OBSERVED
            )
            assert not decision.is_automatic, f"{action.name} ran automatically"


def test_critical_severity_does_not_promote_an_action_outside_the_declared_set():
    """Containment is a fixed list, not a severity threshold. `kill_container`
    is drastic and irreversible; a high enough number must not reach it."""
    decision = decide_response(
        "kill_container", Severity(100), origin=EvidenceOrigin.OBSERVED
    )
    assert decision.disposition is Disposition.REQUIRE_APPROVAL


def test_the_strategy_reads_nothing_but_its_arguments():
    """The section-33 requirement is that no model output reaches enforcement.
    Called twice with identical arguments, the answer must be identical."""
    first = decide_response("disable_agent", Severity(95), origin=EvidenceOrigin.OBSERVED)
    second = decide_response("disable_agent", Severity(95), origin=EvidenceOrigin.OBSERVED)
    assert first == second


# ── The kill switch (section 35) ─────────────────────────────────────────────


def test_all_six_controls_the_specification_names_can_actually_block():
    """A scope with no matcher branch is a kill switch that silently never
    fires -- this repository's most-found defect class."""
    cases = {
        ContainmentScope.AGENT: ({"agent_id": "agent-1"}, "agent-1"),
        ContainmentScope.AGENT_GROUP: ({"agent_groups": ["payments"]}, "payments"),
        ContainmentScope.TOOL: ({"tool": "shell"}, "shell"),
        ContainmentScope.MCP_SERVER: ({"mcp_server": "srv-9"}, "srv-9"),
        ContainmentScope.CREDENTIAL: ({"credential": "fp-abc"}, "fp-abc"),
        ContainmentScope.HIGH_RISK_AGENTS: ({"agent_is_high_risk": True}, ""),
    }
    assert set(cases) == set(ContainmentScope), "a scope has no coverage here"

    for scope, (call_kwargs, selector) in cases.items():
        decision = evaluate_containment(
            [_containment(scope, selector)], now=NOW, **call_kwargs
        )
        assert decision.blocked, f"scope {scope.value} did not block"


def test_a_containment_matches_exactly_and_not_by_substring():
    """A block on `bot` matching `chatbot-7` is over-blocking, which operators
    forgive least because it looks like the product being broken."""
    decision = evaluate_containment(
        [_containment(ContainmentScope.AGENT, "bot")], now=NOW, agent_id="chatbot-7"
    )
    assert not decision.blocked


def test_an_expired_containment_stops_blocking():
    """A 3am pause nobody lifts becomes a silent permanent state."""
    expired = _containment(
        ContainmentScope.AGENT, "agent-1", expires_at="2026-08-24T01:00:00Z"
    )
    assert not evaluate_containment([expired], now=NOW, agent_id="agent-1").blocked


def test_a_revoked_containment_stops_blocking():
    revoked = _containment(
        ContainmentScope.AGENT,
        "agent-1",
        revoked_at="2026-08-24T09:00:00Z",
        revoked_by="analyst@acme.test",
    )
    assert not evaluate_containment([revoked], now=NOW, agent_id="agent-1").blocked


def test_a_containment_without_an_expiry_keeps_blocking():
    """Indefinite is allowed. It must be a choice, not an accident."""
    forever = _containment(ContainmentScope.AGENT, "agent-1")
    assert evaluate_containment([forever], now=NOW, agent_id="agent-1").blocked


def test_the_narrowest_match_is_reported_first():
    """An agent blocked both by id and by an estate-wide pause should show the
    specific block: it is the one an operator can lift without re-opening
    everything."""
    decision = evaluate_containment(
        [
            _containment(ContainmentScope.HIGH_RISK_AGENTS, containment_id="c-wide"),
            _containment(ContainmentScope.AGENT, "agent-1", containment_id="c-narrow"),
        ],
        now=NOW,
        agent_id="agent-1",
        agent_is_high_risk=True,
    )
    assert decision.blocked
    assert decision.containment is not None
    assert decision.containment.containment_id == "c-narrow"
    assert len(decision.matched) == 2


def test_a_block_explains_itself():
    """"Blocked" alone sends an operator hunting through a list to find out why
    their agent stopped."""
    decision = evaluate_containment(
        [_containment(ContainmentScope.AGENT, "agent-1", reason="suspected exfil")],
        now=NOW,
        agent_id="agent-1",
    )
    assert "c-agent" in decision.reason
    assert "suspected exfil" in decision.reason
    assert "analyst@acme.test" in decision.reason


def test_a_containment_must_record_who_authorized_it():
    """A kill switch with no name attached is an outage with no owner."""
    with pytest.raises(InvalidContainment):
        Containment(
            containment_id="c-1",
            tenant_id="acme",
            scope=ContainmentScope.AGENT,
            selector="agent-1",
            created_by="   ",
            created_at=NOW,
        )


def test_a_scoped_containment_requires_something_to_scope_to():
    with pytest.raises(InvalidContainment):
        _containment(ContainmentScope.AGENT, "")


def test_the_estate_wide_scope_refuses_a_selector():
    """A selector here would read as though it narrowed the scope. It does not,
    and that is how an operator pauses the estate believing they paused one
    team."""
    with pytest.raises(InvalidContainment):
        _containment(ContainmentScope.HIGH_RISK_AGENTS, "payments")


def test_nothing_is_blocked_when_no_containment_matches():
    decision = evaluate_containment(
        [_containment(ContainmentScope.AGENT, "agent-other")], now=NOW, agent_id="agent-1"
    )
    assert not decision.blocked
    assert decision.reason == ""
