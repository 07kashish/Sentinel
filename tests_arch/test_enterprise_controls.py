"""Protection modes, policy-as-code, customer keys, residency and retention.

THE CLAIM THESE TESTS EXIST TO SUPPORT
----------------------------------------
Phase 5 is the phase where a customer's own obligations start being enforced by
this product: their regulator's residency rule, their auditor's retention
schedule, their security team's key custody. Each of those is a promise that is
easy to make in a data model and hard to keep in a code path.

So the assertions below are mostly about what the system REFUSES:

  * a mode name that could mean two things, refused rather than guessed
  * a policy that parses perfectly and could never match anything, refused
    rather than deployed
  * a rotation after revocation, refused rather than quietly restoring access
    the customer removed on purpose
  * a read that crosses a residency boundary, raised rather than filtered
  * a retention setting that would trim the hash-chained audit trail, refused
    rather than honoured

Each of those is a case where the permissive behaviour is the one a reasonable
implementation drifts into, and where drifting is a breach of something the
customer was told.
"""

from __future__ import annotations

import pytest

from sentinel.domain.errors import DomainRuleViolated
from sentinel.domain.keys import (
    KeyState,
    KeyVersion,
    TenantKey,
    UnusableKey,
)
from sentinel.domain.modes import (
    AmbiguousMode,
    ModeTransition,
    ProtectionMode,
    parse_mode,
)
from sentinel.domain.policy_as_code import (
    MAX_RULES,
    MalformedPolicy,
    PolicyEffect,
    PolicyRule,
    PolicyVersion,
    diff_versions,
    simulate,
    validate,
)
from sentinel.domain.residency import (
    CrossRegionAccess,
    IMMUTABLE_CLASSES,
    InvalidRetention,
    Region,
    RetentionPolicy,
    assert_no_cross_region_read,
)

AT = "2026-08-24T12:00:00Z"


# ── Section 31: protection modes ─────────────────────────────────────────────


def test_the_five_modes_the_specification_names_all_parse():
    for name in ("observe", "monitor", "warn", "protect", "lockdown"):
        assert parse_mode(name).value == name


@pytest.mark.parametrize(
    "ambiguous", ["on", "off", "enabled", "true", "enforce", "block", "audit", "strict"]
)
def test_an_ambiguous_mode_name_is_refused_rather_than_guessed(ambiguous):
    """Every one of these has been used to mean both "watch" and "block". A
    deployment that guesses will eventually guess in the direction that leaves
    an estate unprotected, or takes it down."""
    with pytest.raises(AmbiguousMode):
        parse_mode(ambiguous)


def test_an_unset_mode_is_refused_rather_than_defaulted():
    """Refusal happens at startup where a human is present to fix it."""
    with pytest.raises(AmbiguousMode):
        parse_mode("")


def test_only_protect_and_lockdown_enforce():
    """A policy may decide BLOCK while the deployment is in MONITOR; the correct
    outcome is a recorded decision and an unblocked call."""
    assert not ProtectionMode.OBSERVE.enforces
    assert not ProtectionMode.MONITOR.enforces
    assert not ProtectionMode.WARN.enforces
    assert ProtectionMode.PROTECT.enforces
    assert ProtectionMode.LOCKDOWN.enforces


def test_only_lockdown_denies_by_default():
    """"Stop what we judged bad" and "stop everything we have not judged" are
    different, and the second must never be reachable by nudging a threshold."""
    assert ProtectionMode.LOCKDOWN.denies_by_default
    for mode in ProtectionMode:
        if mode is not ProtectionMode.LOCKDOWN:
            assert not mode.denies_by_default


def test_capabilities_are_monotonic_in_the_ranking():
    """Derived from the rank rather than written per mode, so two people editing
    two rows months apart cannot make MONITOR block while PROTECT does not."""
    ordered = sorted(ProtectionMode, key=lambda m: m.rank)
    for earlier, later in zip(ordered, ordered[1:]):
        assert later.rank > earlier.rank
        assert not (earlier.enforces and not later.enforces)
        assert not (earlier.notifies and not later.notifies)


def test_a_mode_transition_must_name_who_made_it():
    with pytest.raises(DomainRuleViolated):
        ModeTransition(
            tenant_id="acme",
            from_mode=ProtectionMode.PROTECT,
            to_mode=ProtectionMode.MONITOR,
            changed_by="  ",
            changed_at=AT,
            reason="rollout",
        )


def test_lowering_protection_requires_a_reason():
    """An unexplained tightening causes an outage somebody notices immediately.
    An unexplained loosening is silent."""
    with pytest.raises(DomainRuleViolated):
        ModeTransition(
            tenant_id="acme",
            from_mode=ProtectionMode.PROTECT,
            to_mode=ProtectionMode.OBSERVE,
            changed_by="admin@acme.test",
            changed_at=AT,
        )


def test_raising_protection_needs_no_reason():
    transition = ModeTransition(
        tenant_id="acme",
        from_mode=ProtectionMode.MONITOR,
        to_mode=ProtectionMode.PROTECT,
        changed_by="admin@acme.test",
        changed_at=AT,
    )
    assert not transition.is_reduction


def test_a_transition_that_changes_nothing_is_refused():
    """It would be an audit row implying something happened."""
    with pytest.raises(DomainRuleViolated):
        ModeTransition(
            tenant_id="acme",
            from_mode=ProtectionMode.PROTECT,
            to_mode=ProtectionMode.PROTECT,
            changed_by="admin@acme.test",
            changed_at=AT,
        )


# ── Section 29: policy-as-code ───────────────────────────────────────────────


def _rule(name="r1", effect=PolicyEffect.BLOCK, **kw):
    kw.setdefault("actions", ("read_file",))
    return PolicyRule(name=name, effect=effect, **kw)


def test_a_valid_policy_passes():
    assert validate([_rule()]) == (_rule(),)


def test_a_policy_naming_an_action_no_agent_emits_is_refused():
    """THE headline case. Syntactically perfect, permanently inert -- and
    deploying it tells an operator they are protected when they are not. The
    same failure Phase 3 hit with sequence rules written for names no agent
    emits."""
    with pytest.raises(MalformedPolicy) as caught:
        validate([_rule(actions=("read_sensitive_file",))], known_actions=["read_file"])
    assert "never match" in str(caught.value)


def test_a_prefix_selector_is_not_checked_against_known_actions():
    """A deployment may legitimately write a rule ahead of the action
    existing."""
    validate([_rule(actions=("read_*",))], known_actions=["write_file"])


def test_an_empty_policy_is_refused():
    """It would replace the active policy with nothing."""
    with pytest.raises(MalformedPolicy):
        validate([])


def test_a_catch_all_block_is_refused():
    """A rule with no selectors matches every event. As a BLOCK that is an
    estate-wide outage in a file that reviews cleanly."""
    with pytest.raises(MalformedPolicy):
        validate([PolicyRule(name="everything", effect=PolicyEffect.BLOCK)])


def test_a_catch_all_allow_is_permitted():
    """The same shape is legitimate as a default-allow backstop."""
    validate([PolicyRule(name="default", effect=PolicyEffect.ALLOW)])


def test_duplicate_rule_names_are_refused():
    """Two rules with one name make a finding ambiguous and a diff
    meaningless."""
    with pytest.raises(MalformedPolicy):
        validate([_rule(name="dup"), _rule(name="dup", actions=("write_file",))])


def test_a_rule_requiring_the_maximum_severity_is_refused():
    """`>= 100` fires only on the single highest possible score -- almost always
    a misunderstanding of the scale, and inert in practice."""
    with pytest.raises(MalformedPolicy):
        validate([_rule(min_severity=100)])


def test_an_unbounded_policy_is_refused():
    """Every rule is evaluated against every event."""
    with pytest.raises(MalformedPolicy):
        validate([_rule(name=f"r{i}") for i in range(MAX_RULES + 1)])


def test_a_version_digest_ignores_formatting_but_not_content():
    """A reformat in an editor must not produce a "new policy" whose diff is
    noise."""
    a = PolicyVersion(version=1, rules=(_rule(),), created_by="x", created_at=AT)
    b = PolicyVersion(version=2, rules=(_rule(),), created_by="y", created_at="later")
    c = PolicyVersion(
        version=3, rules=(_rule(effect=PolicyEffect.WARN),), created_by="x", created_at=AT
    )
    assert a.digest == b.digest
    assert a.digest != c.digest


def test_a_diff_is_by_name_so_reordering_is_not_a_change():
    """An operator who cannot trust a diff stops reading it."""
    one, two = _rule(name="a"), _rule(name="b", actions=("write_file",))
    before = PolicyVersion(version=1, rules=(one, two), created_by="x", created_at=AT)
    after = PolicyVersion(version=2, rules=(two, one), created_by="x", created_at=AT)
    assert diff_versions(before, after).is_empty


def test_a_diff_reports_additions_removals_and_changes():
    before = PolicyVersion(
        version=1,
        rules=(_rule(name="keep"), _rule(name="drop", actions=("x",))),
        created_by="x",
        created_at=AT,
    )
    after = PolicyVersion(
        version=2,
        rules=(
            _rule(name="keep", effect=PolicyEffect.WARN),
            _rule(name="new", actions=("y",)),
        ),
        created_by="x",
        created_at=AT,
    )
    diff = diff_versions(before, after)
    assert diff.added == ("new",)
    assert diff.removed == ("drop",)
    assert diff.changed == ("keep",)


# ── Section 30: policy simulation ────────────────────────────────────────────


def _events():
    return [
        {"action": "read_file", "agent_id": "a1", "severity": 10},
        {"action": "read_file", "agent_id": "a2", "severity": 10, "incident_id": "i-1"},
        {"action": "write_file", "agent_id": "a3", "severity": 10},
    ]


def test_simulation_answers_what_a_policy_would_have_done():
    candidate = PolicyVersion(
        version=2, rules=(_rule(effect=PolicyEffect.BLOCK),), created_by="x", created_at=AT
    )
    result = simulate(candidate, _events())
    assert result.events_evaluated == 3
    assert result.would_block == 2
    assert result.would_allow == 1
    assert result.matches_by_rule == {"r1": 2}


def test_simulation_reports_which_agents_a_policy_would_affect():
    candidate = PolicyVersion(
        version=2, rules=(_rule(effect=PolicyEffect.BLOCK),), created_by="x", created_at=AT
    )
    assert simulate(candidate, _events()).affected_agents == ("a1", "a2")


def test_a_newly_blocked_event_that_raised_no_incident_counts_as_a_possible_false_positive():
    """The closest available proxy, and a proxy is what it is."""
    candidate = PolicyVersion(
        version=2, rules=(_rule(effect=PolicyEffect.BLOCK),), created_by="x", created_at=AT
    )
    # a1 had no incident; a2 did.
    assert simulate(candidate, _events()).potential_false_positives == 1


def test_a_simulation_result_declares_itself_an_estimate():
    """A number presented without that gets quoted in a change review as though
    it were a measurement."""
    candidate = PolicyVersion(
        version=1, rules=(_rule(),), created_by="x", created_at=AT
    )
    payload = simulate(candidate, _events()).as_dict()
    assert payload["is_estimate"] is True
    assert payload["estimate_caveat"]


def test_simulating_changes_nothing():
    """The candidate is never activated -- that is the entire point of asking."""
    candidate = PolicyVersion(
        version=2, rules=(_rule(effect=PolicyEffect.BLOCK),), created_by="x", created_at=AT
    )
    events = _events()
    before = [dict(e) for e in events]
    simulate(candidate, events)
    assert events == before


def test_a_selector_is_matched_by_prefix_never_by_regular_expression():
    """A regex over operator-supplied text evaluated on every event is a
    catastrophic-backtracking denial of service an operator can introduce by
    accident."""
    rule = PolicyRule(name="p", effect=PolicyEffect.BLOCK, actions=("read_*",))
    assert rule.matches(action="read_file")
    assert not rule.matches(action="write_file")
    # A regex metacharacter is a literal here, so it simply does not match.
    literal = PolicyRule(name="p", effect=PolicyEffect.BLOCK, actions=("read.*",))
    assert not literal.matches(action="read_file")


# ── Section 55: customer-managed keys ────────────────────────────────────────


def _key():
    return TenantKey("acme").rotate(key_ref="arn:k1", at=AT, provider="aws_kms")


def test_rotation_keeps_prior_versions_readable():
    """A system that treats rotation as "revoke then create" destroys the
    tenant's history on a routine operation."""
    rotated = _key().rotate(key_ref="arn:k2", at=AT)
    assert rotated.active is not None
    assert rotated.active.version == 2
    assert rotated.version_numbered(1).state is KeyState.DECRYPT_ONLY
    assert rotated.assert_can_decrypt(1)


def test_revocation_makes_every_version_unreadable():
    """Revoking only the active version would leave the tenant's history
    readable, which is not what a customer means."""
    revoked = _key().rotate(key_ref="arn:k2", at=AT).revoke(at=AT, by="customer")
    assert revoked.is_revoked
    for version in revoked.versions:
        assert version.state is KeyState.REVOKED
    with pytest.raises(UnusableKey):
        revoked.assert_can_decrypt(1)


def test_revocation_is_terminal():
    """THE property BYOK is bought for: the customer can make their data
    unreadable unilaterally. A revocation support can undo is a suspension with
    a misleading name."""
    revoked = _key().revoke(at=AT, by="customer")
    with pytest.raises(UnusableKey):
        revoked.rotate(key_ref="arn:new", at=AT)
    with pytest.raises(UnusableKey):
        revoked.assert_can_encrypt()


def test_revocation_must_record_who_performed_it():
    """The operation a customer will later need to prove they performed."""
    with pytest.raises(UnusableKey):
        _key().revoke(at=AT, by="   ")


def test_two_active_versions_are_impossible():
    """Two answers to "which key encrypts this write" makes the loser's data
    undecryptable."""
    with pytest.raises(UnusableKey):
        TenantKey(
            tenant_id="acme",
            versions=(
                KeyVersion(version=1, key_ref="a", state=KeyState.ACTIVE, created_at=AT),
                KeyVersion(version=2, key_ref="b", state=KeyState.ACTIVE, created_at=AT),
            ),
        )


def test_a_key_version_never_holds_material():
    """A vendor that holds the bytes can decrypt after revocation regardless of
    what its state machine says."""
    import dataclasses

    fields = {f.name for f in dataclasses.fields(KeyVersion)}
    for forbidden in ("key", "material", "secret", "plaintext", "private_key"):
        assert forbidden not in fields


def test_an_empty_key_reference_is_refused():
    """It would silently mean 'no encryption'."""
    with pytest.raises(UnusableKey):
        KeyVersion(version=1, key_ref="  ", state=KeyState.ACTIVE, created_at=AT)


# ── Sections 78 and 79: retention and residency ──────────────────────────────


def test_a_cross_region_read_raises_rather_than_returning_a_subset():
    """"The report showed 4 of 7 regions and said nothing" is worse than an
    error."""
    with pytest.raises(CrossRegionAccess):
        assert_no_cross_region_read(home=Region.EU, requested=Region.US)


def test_a_same_region_read_is_permitted():
    assert_no_cross_region_read(home=Region.EU, requested=Region.EU)


def test_the_four_deployment_regions_the_specification_names_all_exist():
    assert {r.value for r in Region} == {"us", "eu", "in", "customer"}


def test_retention_defaults_are_conservative():
    """A default that costs money without being chosen is one nobody would have
    picked."""
    policy = RetentionPolicy("acme")
    assert policy.raw_payloads_days <= 30
    assert policy.events_days <= 90


def test_retention_outside_the_permitted_range_is_refused():
    with pytest.raises(InvalidRetention):
        RetentionPolicy("acme", incidents_days=30)


def test_raw_payloads_cannot_outlive_the_events_that_reference_them():
    """An orphan nothing can interpret, and the most sensitive thing stored."""
    with pytest.raises(InvalidRetention):
        RetentionPolicy("acme", events_days=30, raw_payloads_days=90)


@pytest.mark.parametrize("data_class", sorted(IMMUTABLE_CLASSES))
def test_the_evidence_chain_is_not_subject_to_tenant_retention(data_class):
    """A compliance feature that destroys the evidence chain is not the feature
    anybody wanted."""
    with pytest.raises(InvalidRetention):
        RetentionPolicy("acme").days_for(data_class)


def test_every_immutable_class_explains_itself():
    """"n/a" is how a declaration requirement gets satisfied without a decision
    being made."""
    for data_class, reason in IMMUTABLE_CLASSES.items():
        assert len(reason) > 40, f"{data_class} has a placeholder reason"


def test_a_configurable_class_reports_its_window():
    assert RetentionPolicy("acme", events_days=30).days_for("events") == 30
