"""What an agent can ACTUALLY reach, versus what somebody granted it.

WHY THE INDIRECT PATHS ARE THE WHOLE POINT
--------------------------------------------
`agent_tool_grants` answers "what was this agent granted", and every access
review that reads it concludes the agent can do those things and nothing else.
That conclusion is wrong in three ways this module computes, and the shared
credential is the one nobody sees coming: two agents presenting the same
credential are the same principal to every system downstream, so whatever one
can reach the other can — and no row anywhere says so, because the fact lives in
the pairing of two rows that were each written innocently.

`test_a_shared_credential_confers_reach_nobody_granted` is that case.

WHY EVERY PATH CARRIES ITS PROVENANCE
---------------------------------------
Telling a reviewer an agent can reach a production database, without telling them
how, gives them nothing to act on. Revoking a grant does nothing when the reach
came from a shared credential — so the route is the actionable part, not the
capability.
"""

from __future__ import annotations

from sentinel.domain.effective_permissions import (
    ReachSource,
    compute_effective_reach,
    RecommendationAction,
    recommend_least_privilege,
)


def _reach(agent="a", **kwargs):
    kwargs.setdefault("grants", {})
    return compute_effective_reach(agent, **kwargs)


# ── direct ───────────────────────────────────────────────────────────────────


def test_a_direct_grant_is_reported_as_direct():
    result = _reach(grants={"a": ["read_file"]})
    assert result.direct == ("read_file",)
    assert result.indirect == ()
    assert result.paths[0].source is ReachSource.GRANT


def test_an_agent_with_nothing_reaches_nothing():
    assert _reach(grants={"b": ["read_file"]}).capabilities == ()


# ── the three indirect routes ────────────────────────────────────────────────


def test_a_shared_credential_confers_reach_nobody_granted():
    """THE case an access review misses. `a` was granted nothing; `b` was
    granted a database. They present the same credential, so to every system
    downstream they are the same principal.
    """
    result = _reach(
        grants={"b": ["sql_query"]},
        credentials={"cred-1": ["a", "b"]},
    )
    assert result.capabilities == ("sql_query",)
    assert result.direct == ()
    assert result.indirect == ("sql_query",)
    assert result.paths[0].source is ReachSource.SHARED_CREDENTIAL
    assert result.paths[0].via == ("b",)


def test_delegation_confers_reach_with_no_grant_row():
    result = _reach(
        grants={"b": ["github_api"]},
        delegations={"a": ["b"]},
    )
    assert result.indirect == ("github_api",)
    assert result.paths[0].source is ReachSource.DELEGATION


def test_observed_activity_counts_even_against_the_grant_table():
    """A grant table disagreeing with observed behaviour is not evidence the
    behaviour did not happen.
    """
    result = _reach(grants={}, observed={"a": ["aws_api"]})
    assert result.capabilities == ("aws_api",)
    assert result.paths[0].source is ReachSource.OBSERVED


def test_reach_is_transitive_across_several_hops():
    result = _reach(
        grants={"c": ["kubernetes_api"]},
        delegations={"a": ["b"], "b": ["c"]},
    )
    assert result.capabilities == ("kubernetes_api",)
    assert result.paths[0].via == ("b", "c")
    assert result.paths[0].hops == 2


# ── provenance and ordering ──────────────────────────────────────────────────


def test_the_shortest_route_is_the_one_reported():
    """A reviewer shown a six-hop path to something also reachable in one would
    spend their time on the wrong link.
    """
    result = _reach(
        grants={"b": ["sql_query"], "d": ["sql_query"]},
        delegations={"a": ["b", "c"], "c": ["d"]},
    )
    assert len(result.paths) == 1
    assert result.paths[0].via == ("b",)


def test_every_path_says_why():
    result = _reach(
        grants={"b": ["sql_query"]}, credentials={"cred-1": ["a", "b"]}
    )
    assert "shares a credential with b" in result.paths[0].detail


def test_a_cycle_does_not_hang_the_closure():
    """Caller-supplied edges can form a cycle. That is malformed data, not a
    reason to hang an access review.
    """
    result = _reach(
        grants={"b": ["read_file"]},
        delegations={"a": ["b"], "b": ["a"]},
    )
    assert result.capabilities == ("read_file",)


def test_reach_beyond_the_hop_limit_is_reported_not_silently_dropped():
    """A closure that quietly stopped early would UNDERSTATE reach, which is the
    one direction an access review must not be wrong in.
    """
    chain = {f"a{i}": [f"a{i + 1}"] for i in range(10)}
    chain["a"] = ["a0"]
    result = compute_effective_reach(
        "a", grants={"a9": ["sql_query"]}, delegations=chain, max_hops=3
    )
    assert result.truncated_at, "the closure was truncated without saying so"


# ── scoring ──────────────────────────────────────────────────────────────────


def test_a_shared_credential_scores_above_an_explicit_grant():
    """Both confer the same access. One was a decision somebody made; the other
    is reach nobody chose.
    """
    granted = _reach(grants={"a": ["sql_query"]})
    shared = _reach(grants={"b": ["sql_query"]}, credentials={"c-1": ["a", "b"]})
    assert shared.concern > granted.concern
    assert granted.concern == 0


def test_the_worst_route_to_a_capability_decides_its_weight():
    """Reachable both by grant and by a shared credential is a shared-credential
    problem; scoring it as a grant would hide that.
    """
    result = _reach(
        grants={"a": ["sql_query"], "b": ["sql_query"]},
        credentials={"c-1": ["a", "b"]},
    )
    assert result.concern > 0


def test_the_result_states_that_absence_is_not_proof():
    document = _reach(grants={"a": ["read_file"]}).as_dict()
    assert "NOT proof that no path exists" in document["limits"]


# ── least privilege ──────────────────────────────────────────────────────────


def test_unused_grants_are_proposed_for_removal():
    recommendations = recommend_least_privilege(
        "a",
        granted=["read_file", "write_file", "http_request"],
        used=["read_file"],
        observation_window_days=90,
    )
    assert {r.capability for r in recommendations} == {"write_file", "http_request"}
    assert all(r.action == "revoke_grant" for r in recommendations)


def test_a_short_window_produces_an_advisory_not_a_removal_list():
    """An agent that runs quarterly has used nothing this month. A list that
    looks actionable invites somebody to act on it.
    """
    recommendations = recommend_least_privilege(
        "a", granted=["a", "b", "c"], used=[], observation_window_days=2
    )
    assert len(recommendations) == 1
    assert recommendations[0].action == "insufficient_history"
    assert "quarterly" in recommendations[0].reason


def test_nothing_is_recommended_when_everything_is_used():
    assert (
        recommend_least_privilege(
            "a", granted=["x"], used=["x"], observation_window_days=90
        )
        == ()
    )


def test_a_recommendation_is_a_proposal_and_never_an_action():
    """Nothing here mutates anything. The type has no execute, no apply, and no
    handle to a store -- an access-review suggestion that could revoke on its
    own would break an agent on the one day of the year it matters.
    """
    recommendation = recommend_least_privilege(
        "a", granted=["x"], used=[], observation_window_days=90
    )[0]
    for forbidden in ("execute", "apply", "revoke", "commit"):
        assert not hasattr(recommendation, forbidden)


# ── the direction the recommender used to discard ────────────────────────────


def test_a_capability_used_without_a_grant_is_reported():
    """The set difference in the OTHER direction.

    `granted - used` was computed and `used - granted` was thrown on the floor.
    But a capability an agent exercised while holding no grant for it is either
    a stale grant table or an authorization bypass -- the only signal in this
    function describing something that ALREADY HAPPENED, and it was discarded.
    """
    recommendations = recommend_least_privilege(
        "a",
        granted=["read_file"],
        used=["read_file", "delete_bucket"],
        observation_window_days=90,
    )

    finding = next(
        r
        for r in recommendations
        if r.action is RecommendationAction.USED_WITHOUT_GRANT
    )
    assert finding.capability == "delete_bucket"
    assert "bypassed" in finding.reason


def test_an_ungranted_use_is_marked_a_security_finding_and_a_revocation_is_not():
    """An unused grant is latent risk. An ungranted use is an event.

    Both arriving in one undifferentiated list would sort the urgent item
    alphabetically among the routine ones.
    """
    recommendations = recommend_least_privilege(
        "a",
        granted=["read_file", "write_file"],
        used=["read_file", "delete_bucket"],
        observation_window_days=90,
    )
    by_action = {r.action: r for r in recommendations}

    assert by_action[RecommendationAction.USED_WITHOUT_GRANT].is_security_finding
    assert not by_action[RecommendationAction.REVOKE_GRANT].is_security_finding


def test_an_ungranted_use_survives_a_window_too_short_to_revoke_on():
    """Presence and absence need different amounts of evidence.

    A revocation infers from ABSENCE and needs a complete record. Seeing a call
    is positive evidence, and a short window cannot un-see it -- so the finding
    stands while every revocation is suppressed.
    """
    recommendations = recommend_least_privilege(
        "a",
        granted=["read_file"],
        used=["delete_bucket"],
        observation_window_days=2,
    )
    actions = {r.action for r in recommendations}

    assert RecommendationAction.USED_WITHOUT_GRANT in actions
    assert RecommendationAction.INSUFFICIENT_HISTORY in actions
    assert RecommendationAction.REVOKE_GRANT not in actions, (
        "a two-day window produced a removal list"
    )


def test_an_incomplete_activity_record_suppresses_every_revocation():
    """A long window over dropped telemetry is not a long window.

    The window length says how far back the record reaches; it says nothing
    about whether the record has holes. An agent whose activity went unrecorded
    for a fortnight looks identical to one that did nothing.
    """
    recommendations = recommend_least_privilege(
        "a",
        granted=["read_file", "write_file"],
        used=["read_file"],
        observation_window_days=365,
        activity_complete=False,
    )
    actions = {r.action for r in recommendations}

    assert actions == {RecommendationAction.INCOMPLETE_ACTIVITY_RECORD}
    advisory = recommendations[0]
    assert "holes" in advisory.reason
    assert "long" in advisory.reason, (
        "the advisory must distinguish itself from the short-window case, or an "
        "operator lengthens the window and waits for a list that never comes"
    )


def test_an_ungranted_use_survives_an_incomplete_record_too():
    recommendations = recommend_least_privilege(
        "a",
        granted=[],
        used=["delete_bucket"],
        observation_window_days=365,
        activity_complete=False,
    )
    actions = {r.action for r in recommendations}

    assert RecommendationAction.USED_WITHOUT_GRANT in actions
    assert RecommendationAction.REVOKE_GRANT not in actions


def test_a_complete_record_over_a_long_window_still_revokes():
    """The suppression must not be so eager that the feature never fires."""
    recommendations = recommend_least_privilege(
        "a",
        granted=["read_file", "write_file"],
        used=["read_file"],
        observation_window_days=90,
        activity_complete=True,
    )

    assert [r.capability for r in recommendations] == ["write_file"]
    assert recommendations[0].action is RecommendationAction.REVOKE_GRANT


def test_recommendations_are_ordered_deterministically():
    """Two runs over the same agent must produce the same list, or every diff
    between access reviews is noise and nobody reads them.
    """
    first = recommend_least_privilege(
        "a",
        granted=["z", "a", "m"],
        used=["q", "b"],
        observation_window_days=90,
    )
    second = recommend_least_privilege(
        "a",
        granted=["m", "z", "a"],
        used=["b", "q"],
        observation_window_days=90,
    )

    assert [r.as_dict() for r in first] == [r.as_dict() for r in second]
    assert [r.capability for r in first] == ["b", "q", "a", "m", "z"], (
        "security findings must come before routine revocations"
    )


def test_the_action_is_a_closed_set():
    """A str Enum, so existing comparisons against literals keep working while
    a typo in an action name fails at import rather than producing a
    recommendation nothing downstream matches.
    """
    recommendation = recommend_least_privilege(
        "a", granted=["x"], used=[], observation_window_days=90
    )[0]

    assert recommendation.action == "revoke_grant"
    assert recommendation.action is RecommendationAction.REVOKE_GRANT
    assert recommendation.as_dict()["action"] == "revoke_grant"


def test_the_serialised_form_distinguishes_the_two_kinds():
    """A consumer reading only `as_dict()` must still be able to tell an event
    from a suggestion.
    """
    recommendations = recommend_least_privilege(
        "a",
        granted=["read_file"],
        used=["delete_bucket"],
        observation_window_days=90,
    )
    documents = [r.as_dict() for r in recommendations]

    assert any(d["is_security_finding"] for d in documents)
    assert any(not d["is_security_finding"] for d in documents)
