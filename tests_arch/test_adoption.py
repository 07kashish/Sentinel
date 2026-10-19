""""Zero events" and "not deployed" are the same number and opposite facts.

A control nobody routes through is not a control, and the most common failure
of a tool like this is not a bug -- it is a deployment ingesting from two
agents out of forty, producing no incidents because it sees nothing, and
showing a quiet dashboard everybody reads as good news.

So these tests are mostly about the funnel refusing to flatter: UNKNOWN is not
a zero, a triage rate is refused over a short window, and every stage names
the fact that produced it.
"""

from __future__ import annotations

import pytest

from sentinel.domain.adoption import (
    MIN_WINDOW_DAYS_FOR_ENGAGEMENT,
    ActivationStage,
    TenantCounts,
    assess_adoption,
)


def _assess(**counts):
    return assess_adoption(tenant="acme", counts=TenantCounts(**counts))


# ── the distinction the module exists for ────────────────────────────────────


def test_no_signal_at_all_is_unknown_and_not_a_zero():
    """A tenant with nothing connected and one connected-and-idle produce the
    same counts. Reporting either as "0% adopted" points a decision the wrong
    way.
    """
    snapshot = _assess()

    assert snapshot.stage is ActivationStage.UNKNOWN
    assert "absence of a signal" in snapshot.evidence
    assert "NOT a measurement of zero usage" in snapshot.evidence


def test_unknown_ranks_below_connected_rather_than_equal_to_it():
    """`is_at_least` must not treat "we cannot see" as "the first stage"."""
    unknown = _assess()
    connected = _assess(credentials_configured=1)

    assert not unknown.is_at_least(ActivationStage.CONNECTED)
    assert connected.is_at_least(ActivationStage.CONNECTED)


def test_a_configured_credential_with_no_events_is_connected():
    """The credential exists and nothing is using it -- usually the agent side
    was never wired up, which is a different problem from a broken detector.
    """
    snapshot = _assess(credentials_configured=2)

    assert snapshot.stage is ActivationStage.CONNECTED
    assert "never wired up" in snapshot.blocking_next_stage


# ── the funnel, checked from the far end backwards ───────────────────────────


def test_events_alone_are_ingesting():
    snapshot = _assess(credentials_configured=1, events_ingested=500)

    assert snapshot.stage is ActivationStage.INGESTING
    assert "500 event(s)" in snapshot.evidence


def test_ingesting_without_incidents_states_both_possible_causes():
    """Benign traffic and an uncovered policy produce the same silence and
    need opposite responses.
    """
    snapshot = _assess(events_ingested=500)

    assert "genuinely benign" in snapshot.blocking_next_stage
    assert "does not cover" in snapshot.blocking_next_stage


def test_an_incident_raised_is_detecting():
    snapshot = _assess(events_ingested=500, incidents_raised=3)

    assert snapshot.stage is ActivationStage.DETECTING
    assert "exercised rather than merely configured" in snapshot.evidence


def test_detecting_names_triage_as_the_stage_most_deployments_never_leave():
    """An incident nobody opened is a log line with extra steps."""
    snapshot = _assess(events_ingested=500, incidents_raised=3)

    assert "NO incident has been triaged" in snapshot.blocking_next_stage
    assert "log line with extra steps" in snapshot.blocking_next_stage


def test_a_triaged_incident_is_investigating():
    """The first stage that requires a PERSON."""
    snapshot = _assess(
        events_ingested=500, incidents_raised=3, incidents_triaged=1
    )

    assert snapshot.stage is ActivationStage.INVESTIGATING


def test_investigating_does_not_call_missing_enforcement_a_gap():
    """Detection without enforcement is the deliberate default for
    correlation-driven findings. A funnel that scored it as incomplete would
    push somebody to turn on blocking the product deliberately does not do.
    """
    snapshot = _assess(incidents_raised=3, incidents_triaged=3)

    assert "deliberate default" in snapshot.blocking_next_stage
    assert "may be correct rather than incomplete" in snapshot.blocking_next_stage


def test_a_refused_action_is_enforcing():
    snapshot = _assess(events_ingested=500, actions_refused=2)

    assert snapshot.stage is ActivationStage.ENFORCING
    assert "in the path, not beside it" in snapshot.evidence


def test_a_containment_alone_is_enforcing():
    snapshot = _assess(containments_activated=1)

    assert snapshot.stage is ActivationStage.ENFORCING


def test_the_stages_are_checked_from_the_far_end_backwards():
    """Enforcement implies detection implies ingestion.

    Checking forwards would report a tenant as INGESTING because the first
    matching branch won, understating a deployment that is actually in the
    path -- and understating adoption is how a working deployment gets
    reported as a failing one.
    """
    snapshot = _assess(
        credentials_configured=4,
        agents_observed=12,
        events_ingested=9000,
        incidents_raised=40,
        incidents_triaged=31,
        actions_refused=5,
        containments_activated=2,
    )

    assert snapshot.stage is ActivationStage.ENFORCING


def test_the_top_stage_redirects_to_coverage_rather_than_declaring_victory():
    """Reaching the end of the funnel says nothing about the agents that were
    never connected, which is the question that actually matters next.
    """
    snapshot = _assess(agents_observed=12, actions_refused=5)

    assert "coverage" in snapshot.blocking_next_stage
    assert "never connected" in snapshot.blocking_next_stage


# ── the rate that refuses ────────────────────────────────────────────────────


def test_no_engagement_rate_is_quoted_over_a_short_window():
    """An incident raised yesterday has not been ignored; it has not been
    reached yet. A triage rate over three days measures the window.
    """
    snapshot = _assess(
        incidents_raised=10, incidents_triaged=2, observation_window_days=3
    )

    assert snapshot.engagement_rate() is None
    assert "measures the window" in snapshot.rate_refusal_reason()


def test_a_rate_is_quoted_once_the_window_is_long_enough():
    """The refusal must not be so eager the metric never exists."""
    snapshot = _assess(
        incidents_raised=10,
        incidents_triaged=4,
        observation_window_days=MIN_WINDOW_DAYS_FOR_ENGAGEMENT,
    )

    assert snapshot.engagement_rate() == 0.4
    assert snapshot.rate_refusal_reason() == ""


def test_no_incidents_is_neither_full_nor_zero_triage():
    """Both readings are wrong, and a dashboard will pick whichever suits."""
    snapshot = _assess(events_ingested=10, observation_window_days=90)

    assert snapshot.engagement_rate() is None
    reason = snapshot.rate_refusal_reason()
    assert "NOT a 100% triage rate" in reason
    assert "not a 0% one" in reason


def test_the_minimum_window_matches_the_privilege_recommender():
    """Two different thresholds for "long enough to infer from" would drift
    into disagreeing about what counts as evidence.
    """
    from sentinel.domain.effective_permissions import recommend_least_privilege

    recommendation = recommend_least_privilege(
        "a",
        granted=["x"],
        used=[],
        observation_window_days=MIN_WINDOW_DAYS_FOR_ENGAGEMENT,
    )

    # At exactly the shared minimum, the recommender stops refusing.
    assert recommendation[0].action == "revoke_grant"


# ── refusals on impossible inputs ────────────────────────────────────────────


def test_a_negative_count_is_refused_rather_than_clamped():
    """A negative means a query returned something unexpected. Computing a
    funnel from it produces a confident wrong answer instead of an error.
    """
    with pytest.raises(ValueError) as raised:
        _assess(events_ingested=-1)

    assert "not observations" in str(raised.value)


def test_more_triaged_than_raised_is_refused():
    """The two counts came from different windows or different tenants.
    Refusing beats reporting a triage rate above 100%.
    """
    with pytest.raises(ValueError) as raised:
        _assess(incidents_raised=2, incidents_triaged=5)

    assert "above 100%" in str(raised.value)


def test_a_snapshot_with_no_tenant_is_refused():
    with pytest.raises(ValueError) as raised:
        assess_adoption(tenant="  ", counts=TenantCounts())

    assert "tenant" in str(raised.value)


# ── no egress, and the limits travel ─────────────────────────────────────────


def test_the_module_opens_no_socket_and_holds_no_client():
    """A "business instrumentation" module that shipped usage data off a
    customer's estate would be an exfiltration channel wearing a
    product-analytics label -- and in a security product it is the most
    sensitive telemetry in the building: which agents exist, how many, how
    often they act.
    """
    import inspect

    from sentinel.domain import adoption

    source = inspect.getsource(adoption)
    for forbidden in ("import socket", "urllib", "requests", "httpx", "http.client"):
        assert forbidden not in source, f"{forbidden} appears in an egress-free module"


def test_the_module_states_that_nothing_is_sent_anywhere():
    import inspect

    from sentinel.domain import adoption

    doc = " ".join((inspect.getdoc(adoption) or "").split())

    assert "NO EGRESS" in doc
    assert "exfiltration channel" in doc


def test_the_limits_say_a_low_stage_may_mean_narrow_deployment():
    """Otherwise a low stage reads as a broken product rather than an
    unfinished rollout.
    """
    limits = _assess(events_ingested=1).as_dict()["limits"]

    assert "not deployed widely rather than not working" in limits
    assert "UNKNOWN means NO signal" in limits


def test_the_serialised_form_leads_with_the_stage_and_its_evidence():
    """A stage is never an opinion: a reader has to see which number produced
    it before they see the number itself.
    """
    document = _assess(events_ingested=1).as_dict()
    keys = list(document)

    assert keys[0] == "stage"
    assert keys[1] == "evidence"


def test_the_document_contains_no_floats():
    """The canonical JSON form refuses floats, so a snapshot carrying one
    could not be signed.
    """

    def walk(value, path="root"):
        if isinstance(value, float):
            raise AssertionError(f"float at {path}")
        if isinstance(value, dict):
            for key, item in value.items():
                walk(item, f"{path}.{key}")
        elif isinstance(value, (list, tuple)):
            for index, item in enumerate(value):
                walk(item, f"{path}[{index}]")

    walk(
        _assess(
            incidents_raised=10,
            incidents_triaged=4,
            observation_window_days=90,
        ).as_dict()
    )


def test_the_rate_is_serialised_as_a_string_and_null_when_refused():
    quoted = _assess(
        incidents_raised=10, incidents_triaged=4, observation_window_days=90
    ).as_dict()
    refused = _assess(incidents_raised=10, observation_window_days=1).as_dict()

    assert quoted["engagement_rate"] == "0.4000"
    assert refused["engagement_rate"] is None


def test_the_module_holds_no_mutable_state():
    import types

    from sentinel.domain import adoption

    mutable = [
        name
        for name, value in vars(adoption).items()
        if not name.startswith("__")
        and isinstance(value, (dict, list, set))
        and not isinstance(value, (frozenset, types.MappingProxyType))
    ]
    assert not mutable, f"module-level mutable state: {mutable}"
