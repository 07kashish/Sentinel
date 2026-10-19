"""The wiring, not the components. Everything here failed silently once.

WHY THIS MODULE IS SEPARATE
-----------------------------
`test_remediation_execution.py` proves the Phase 4 components work.
`test_components_are_reachable.py` proves they are referenced somewhere. Neither
proves the reference does the right thing.

Between those two lies the failure this module exists for: `expires_at` had a
column, a hydration line, an enforced branch in `DecideApprovalHandler` and
passing tests -- and the one site that CREATES approvals never set it, so every
real approval had no expiry and the branch could not be taken.

A reference is not a wire. These tests follow the value.
"""

from __future__ import annotations

import pytest

from sentinel.domain.primitives import ApprovalId, IncidentId, Timestamp
from sentinel.domain.remediation import REMEDIATION_ACTIONS, Disposition
from sentinel.infrastructure.evidence import APPROVAL_WINDOW, RuleBasedPlanner

AT = Timestamp.parse("2026-08-24T12:00:00+00:00")


class _Ids:
    def approval_id(self) -> ApprovalId:
        return ApprovalId("apr-1")


class _Logger:
    def _noop(self, *args, **kwargs) -> None:
        return None

    info = warning = error = debug = _noop


def _propose(**facts):
    base = {
        "incident_type": "sensitive_resource_access",
        "signer_address": "agent-1",
        "severity": 75,
    }
    base.update(facts)
    return RuleBasedPlanner().propose(
        incident_facts=base,
        advice=None,
        incident_id=IncidentId("inc-1"),
        ids=_Ids(),
        at=AT,
    )


# ── Section 32: the expiry is actually set ───────────────────────────────────


def test_a_proposed_approval_carries_an_expiry():
    """THE gap. Without this the expiry branch in `DecideApprovalHandler` is
    unreachable and every approval is a standing authorization to act on
    production."""
    (approval,) = _propose()
    assert approval.expires_at is not None
    assert approval.expires_at == Timestamp(AT.value + APPROVAL_WINDOW)


def test_the_expiry_actually_expires():
    (approval,) = _propose()
    assert not approval.is_expired(AT)
    assert approval.is_expired(Timestamp(AT.value + APPROVAL_WINDOW * 2))


def test_a_proposed_approval_carries_the_section_32_context():
    (approval,) = _propose()
    for field in (
        "risk_factors",
        "business_impact",
        "recommended_decision",
        "recommendation_reason",
        "session_id",
        "blast_radius",
        "reversible",
    ):
        assert field in approval.context, f"context is missing {field}"


# ── Section 33: decide_response is consulted ─────────────────────────────────


def test_the_recommended_decision_comes_from_the_response_strategy():
    """Not a constant and not a guess -- the deterministic strategy's answer."""
    (approval,) = _propose(severity=75)
    assert approval.context["recommended_decision"] == Disposition.REQUIRE_APPROVAL.value


def test_self_reported_critical_severity_is_recommended_for_approval():
    """The forged-chain defence, visible where an analyst reads it."""
    (approval,) = _propose(severity=95)
    assert approval.context["recommended_decision"] == Disposition.REQUIRE_APPROVAL.value
    assert approval.context["restrained"] is True
    assert approval.context["evidence_origin"] == "self_reported"


def test_observed_critical_severity_is_recommended_for_containment():
    (approval,) = _propose(
        incident_type="prompt_injection_suspected",
        severity=95,
        evidence_origin="observed",
    )
    assert (
        approval.context["recommended_decision"]
        == Disposition.EMERGENCY_CONTAINMENT.value
    )


# ── The vocabulary mismatch that would have refused every remediation ────────


def test_every_proposed_action_is_in_the_catalogue():
    """The planner used to propose `quarantine_agent_session`,
    `revoke_tool_grant`, `isolate_agent` and `require_human_review` -- none of
    which exist in the catalogue.

    Invisible while the deployment ran `NullRemediationExecutor`, which refuses
    everything identically. With a real executor wired, every one of those is an
    approval an analyst can click and which can never do anything.
    """
    catalogue = {action.name for action in REMEDIATION_ACTIONS}
    planner = RuleBasedPlanner()
    proposed = set(planner._actions.values())
    assert proposed, "the planner proposes nothing; this test would prove nothing"
    missing = proposed - catalogue
    assert not missing, f"planner proposes actions absent from the catalogue: {missing}"


def test_an_action_outside_the_catalogue_produces_no_proposal():
    """Refuse to propose rather than raise an approval nothing can execute."""
    planner = RuleBasedPlanner(actions={"sensitive_resource_access": "not_an_action"})
    proposals = planner.propose(
        incident_facts={
            "incident_type": "sensitive_resource_access",
            "signer_address": "agent-1",
            "severity": 75,
        },
        advice=None,
        incident_id=IncidentId("inc-1"),
        ids=_Ids(),
        at=AT,
    )
    assert proposals == ()


# ── Section 34: the container wires the real executor when configured ────────


def _container(engine_config, env_extra):
    """Build a real container on whichever engine the fixture selected.

    Parametrised over both engines via `engine_config`, per
    `test_no_new_test_module_drives_the_database_on_one_engine_only`. The
    executor choice is engine-independent, but the container also runs
    `verify()` against the schema -- and a migration that applies on SQLite and
    not on PostgreSQL is exactly the class of bug this repository has shipped.
    """
    from sentinel.composition.container import build_container
    from sentinel.composition.settings import Settings
    from sentinel.infrastructure.sql.engine import Dialect, build_engine
    from sentinel.infrastructure.sql.migrate import migrate

    env = {
        "SENTINEL_ENV": "development",
        "SENTINEL_API_KEYS": "acme:analyst-key-0000000000000000000:analyst",
        "SENTINEL_SOFT_PROMPT_DETECT": "false",
    }
    if engine_config.dialect is Dialect.POSTGRES:
        env["SENTINEL_DATABASE_URL"] = engine_config.dsn
        env["SENTINEL_DB_POOL_MIN"] = "1"
        env["SENTINEL_DB_POOL_MAX"] = "4"
    else:
        env["SENTINEL_DB_PATH"] = engine_config.dsn
    env.update(env_extra)
    settings = Settings.from_environment(env)
    pool = build_engine(settings.engine)
    migrate(pool)
    pool.close()
    return build_container(settings)


def test_without_endpoints_containment_on_sentinels_own_state_still_works(
    engine_config,
):
    """UPDATED, because the behaviour it described was a limitation, not a rule.

    This test used to assert that a deployment without
    `SENTINEL_REMEDIATION_ENDPOINTS` got `NullRemediationExecutor` and could not
    `disable_agent`. That was correct while every action needed an outbound
    integration -- and it is exactly why containment almost never worked:
    `disable_agent` is a write to a table this process already owns, and
    requiring an operator to run a webhook that called back into Sentinel to
    perform it meant almost nobody could contain anything.

    `build_sentinel_integrations` removes that requirement, so the assertion had
    to change. What has NOT changed is the property the old test was protecting:
    an action with no integration behind it is still refused with a reason
    rather than given a false receipt, and `supports()` is still the check that
    says which is which.
    """
    container = _container(engine_config, {})
    try:
        # Sentinel's own state: available with nothing configured but a database.
        assert container.executor.supports("disable_agent")
        assert container.executor.supports("block_mcp_server")
        assert container.executor.supports("remove_tool_access")

        # Needs a cluster credential this deployment does not have.
        assert not container.executor.supports("kill_container")
        # Sentinel does not issue tokens, so this is unsupported at any
        # configuration -- the honest answer, not a degraded one.
        assert not container.executor.supports("rotate_token")
    finally:
        container.close()


def test_the_null_executor_is_still_what_nothing_at_all_produces():
    """The distinction the old test protected, kept where it is now true.

    `NullRemediationExecutor` is no longer what a deployment without webhooks
    gets -- it is what a deployment with NOTHING gets: no endpoints, no cloud
    credentials, no store. It still refuses every action with a reason instead
    of returning a success-shaped receipt.
    """
    from sentinel.infrastructure.remediation import build_remediation_executor

    executor = build_remediation_executor(
        endpoints={}, client=None, audit=None, clock=lambda: AT, native={}
    )
    assert type(executor).__name__ == "NullRemediationExecutor"
    assert not executor.supports("disable_agent")


def test_with_endpoints_the_deployment_gets_the_guarded_executor(engine_config):
    container = _container(
        engine_config,
        {"SENTINEL_REMEDIATION_ENDPOINTS": "disable_agent=https://remediate.test/a"},
    )
    try:
        assert type(container.executor).__name__ == "GuardedRemediationExecutor"
        assert container.executor.supports("disable_agent")
        # Configured actions only. The registry is the boundary.
        assert not container.executor.supports("kill_container")
    finally:
        container.close()


def test_a_plaintext_remediation_endpoint_is_refused_at_startup(engine_config):
    """A URL that can disable production agents, sent in the clear, can be
    forged by anyone on the path."""
    from sentinel.composition.settings import ConfigurationError

    with pytest.raises(ConfigurationError):
        _container(
            engine_config,
            {"SENTINEL_REMEDIATION_ENDPOINTS": "disable_agent=http://x.test/a"},
        )


# ── Section 37: SOAR is subscribed to incident admission ─────────────────────


def _settings(**extra):
    from sentinel.composition.settings import Settings

    env = {
        "SENTINEL_ENV": "development",
        "SENTINEL_API_KEYS": "acme:k1:analyst",
        "SENTINEL_DB_PATH": ":memory:",
    }
    env.update(extra)
    return Settings.from_environment(env)


def test_without_endpoints_no_soar_dispatcher_is_built():
    """None rather than an empty dispatcher: an empty one reports
    `fully_delivered=False` for every incident, which reads as a delivery
    failure when nobody asked for delivery."""
    from sentinel.composition.notifications import build_soar_dispatcher

    assert build_soar_dispatcher(_settings(), logger=_Logger()) is None


def test_configured_connectors_are_subscribed_to_incident_admission():
    """`SoarDispatcher` had six connectors, escaping and tests, and was
    constructed by nothing -- so no incident ever reached ServiceNow or
    Slack."""
    from sentinel.composition.container import _default_subscribers
    from sentinel.composition.notifications import subscribers_with_soar
    from sentinel.domain.events import IncidentAdmitted

    logger = _Logger()
    subscribers = subscribers_with_soar(
        _settings(SENTINEL_SOAR_ENDPOINTS="slack=https://hooks.test/s"),
        logger=logger,
        defaults=_default_subscribers(logger),
    )
    # The default log subscriber, plus the SOAR one.
    assert len(subscribers[IncidentAdmitted]) == 2


def test_a_soar_connector_failure_cannot_fail_the_admission_that_produced_it():
    """An incident detected and stored but whose Slack message failed is a
    working system with a broken integration. An incident REJECTED because Slack
    was down is a broken system."""
    from sentinel.composition.notifications import soar_subscriber
    from sentinel.domain.events import IncidentAdmitted
    from sentinel.domain.primitives import Priority, Severity, TenantId

    class _ExplodingDispatcher:
        def should_dispatch(self, incident):
            return True

        def dispatch(self, incident):
            raise RuntimeError("every provider is down")

    subscriber = soar_subscriber(_ExplodingDispatcher(), logger=_Logger())
    event = IncidentAdmitted(
        tenant_id=TenantId("acme"),
        incident_id=IncidentId("inc-1"),
        occurred_at=AT,
        severity=Severity(90),
        priority=Priority.CRITICAL,
        source="agent-1",
    )
    # Must not raise.
    subscriber(TenantId("acme"), event)


def test_low_priority_incidents_are_not_dispatched():
    from sentinel.composition.notifications import soar_subscriber
    from sentinel.domain.events import IncidentAdmitted
    from sentinel.domain.primitives import Priority, Severity, TenantId

    dispatched = []

    class _Recording:
        def should_dispatch(self, incident):
            return str(incident.get("priority")) in {"HIGH", "CRITICAL"}

        def dispatch(self, incident):
            dispatched.append(incident)

    subscriber = soar_subscriber(_Recording(), logger=_Logger())
    for priority, severity in ((Priority.LOW, 10), (Priority.CRITICAL, 95)):
        subscriber(
            TenantId("acme"),
            IncidentAdmitted(
                tenant_id=TenantId("acme"),
                incident_id=IncidentId("inc-1"),
                occurred_at=AT,
                severity=Severity(severity),
                priority=priority,
                source="agent-1",
            ),
        )
    assert [d["priority"] for d in dispatched] == ["CRITICAL"]
