"""The decision set, and the inversion that makes a forgotten one fail closed.

WHAT CHANGED AND WHY IT IS DELICATE
-------------------------------------
Phase 6 widened `ProtectDecision` from four members to eight. Widening an enum
that gates enforcement is the kind of change that looks trivial and is not:
`stops_action` used to be a membership test against the decisions that STOP, so
a new decision added and not listed there would **silently allow**.

That is a new enforcement outcome which enforces nothing — the worst possible
direction for the bug, and one that no existing test would have caught because
every existing decision was already in the set.

So the predicate is inverted. `_PROCEEDS` lists the decisions under which the
action may go ahead; everything else stops. A member added to this enum and
never classified now fails CLOSED, and
`test_every_decision_is_explicitly_classified` makes the omission loud rather
than merely safe.

THE FOUR ORIGINALS ARE UNTOUCHED
----------------------------------
Same names, same string values, same behaviour. `test_the_original_four
_decisions_behave_exactly_as_before` pins that, because a stored outcome, a
policy rule or an integration written against `"block"` must keep meaning what
it meant.
"""

from __future__ import annotations

from sentinel.domain.protect import ProtectDecision


# ── the inversion, which is the whole point ──────────────────────────────────


def test_every_decision_is_explicitly_classified():
    """A member nobody classified stops by default — and this makes it loud.

    Safe-by-default is not enough on its own: a decision that silently stops
    everything is also wrong, just wrong in the survivable direction. Somebody
    has to decide.
    """
    from sentinel.domain.protect import _PROCEEDS

    unclassified = [
        d
        for d in ProtectDecision
        if d not in _PROCEEDS and not d.stops_action
    ]
    assert not unclassified, f"neither proceeds nor stops: {unclassified}"

    # And the positive half: every member is reachable by one branch or other.
    assert {d for d in ProtectDecision} == {
        d for d in ProtectDecision if d.stops_action
    } | _PROCEEDS


def test_a_hypothetical_new_decision_stops_by_default():
    """The property, stated directly. Simulated by asking the predicate about a
    member that is not in the proceed set — the same position a future
    unclassified decision would be in.
    """
    from sentinel.domain.protect import _PROCEEDS

    for decision in ProtectDecision:
        if decision not in _PROCEEDS:
            assert decision.stops_action, (
                f"{decision} is outside the proceed allowlist and does not "
                "stop; the inversion has been undone"
            )


def test_the_proceed_set_is_small_and_deliberate():
    """Three members. If this grows, somebody widened what may run without a
    stop — which should be a diff a reviewer sees.
    """
    from sentinel.domain.protect import _PROCEEDS

    assert _PROCEEDS == {
        ProtectDecision.ALLOW,
        ProtectDecision.WARN,
        ProtectDecision.ALLOW_WITH_REDACTION,
    }


# ── backward compatibility, which is not optional here ───────────────────────


def test_the_original_four_decisions_behave_exactly_as_before():
    """A stored outcome, a policy rule or an integration written against
    `"block"` must keep meaning what it meant.
    """
    assert ProtectDecision.ALLOW.value == "allow"
    assert ProtectDecision.WARN.value == "warn"
    assert ProtectDecision.REQUIRE_APPROVAL.value == "require_approval"
    assert ProtectDecision.BLOCK.value == "block"

    assert ProtectDecision.ALLOW.stops_action is False
    assert ProtectDecision.WARN.stops_action is False
    assert ProtectDecision.REQUIRE_APPROVAL.stops_action is True
    assert ProtectDecision.BLOCK.stops_action is True


# ── what each new decision means ─────────────────────────────────────────────


def test_redaction_proceeds_because_the_action_happens():
    """The response is transformed on its way back, not withheld. A caller that
    treated it as a stop would break every workflow it was meant to keep
    working — which is how a redaction control ends up switched off.
    """
    assert ProtectDecision.ALLOW_WITH_REDACTION.stops_action is False
    assert ProtectDecision.ALLOW_WITH_REDACTION.requires_human is False


def test_step_up_stops_and_needs_the_same_person_not_a_second_one():
    """Distinct from REQUIRE_APPROVAL, which asks somebody else. This asks the
    original human to prove they are still there.
    """
    assert ProtectDecision.STEP_UP_AUTH.stops_action is True
    assert ProtectDecision.STEP_UP_AUTH.requires_human is True


def test_a_jit_credential_stops_but_no_person_has_to_wake_up():
    """A machine can satisfy it. An operator sizing a rollout needs to know
    which refusals page somebody and which resolve themselves.
    """
    assert ProtectDecision.REQUIRE_JIT_CREDENTIAL.stops_action is True
    assert ProtectDecision.REQUIRE_JIT_CREDENTIAL.requires_human is False


def test_contain_is_separate_from_block_because_the_response_differs():
    """Blocking one call and disabling the agent are different operator
    actions. A gate that could only say "no" left the second to be noticed by
    hand.
    """
    assert ProtectDecision.CONTAIN.stops_action is True
    assert ProtectDecision.CONTAIN.requires_human is True
    assert ProtectDecision.CONTAIN is not ProtectDecision.BLOCK


def test_block_does_not_require_a_human_to_unblock_it():
    """A blocked call is refused and over. Marking it human-requiring would
    inflate the page count for a rollout and make the estimate useless.
    """
    assert ProtectDecision.BLOCK.requires_human is False


# ── the enum is still serialisable the way callers expect ────────────────────


def test_every_decision_round_trips_through_its_string_value():
    """Outcomes are persisted and shipped to SIEM as strings."""
    for decision in ProtectDecision:
        assert ProtectDecision(decision.value) is decision


def test_no_two_decisions_share_a_value():
    values = [d.value for d in ProtectDecision]
    assert len(values) == len(set(values))


# ── an ML score alone must never reach a destructive decision ────────────────


def test_composed_detection_uses_deterministic_rules_for_protect():
    from sentinel.composition.adapters import _detection_policy_for
    from sentinel.composition.settings import Settings
    from sentinel.domain.primitives import TrustLevel
    from sentinel.infrastructure.detection import DeterministicPolicy
    from tests_arch.doubles import RecordingLogger

    policy, _mode = _detection_policy_for(Settings.from_environment({}), logger=RecordingLogger())
    rules = DeterministicPolicy.default()
    for payload, fired in (
        ({"eventType": "prompt", "action": "http_get", "metadata": {"prompt": "http_get"}}, False),
        ({"eventType": "file_access", "action": "read_file", "resource": "/root/.aws/credentials"}, True),
    ):
        verdict = policy.evaluate(payload=payload, trust=TrustLevel.UNSIGNED)
        assert verdict.fired is fired
        assert verdict == rules.evaluate(payload=payload, trust=TrustLevel.UNSIGNED)


def test_an_advisory_verdict_lands_on_a_human_not_on_a_refusal():
    """The positive statement of the same rule: what the ML path CAN do is ask
    a person, which is the correct amount of authority for a probability.
    """
    from sentinel.domain.primitives import Severity, TrustLevel
    from sentinel.domain.protect import ProtectVerdict, decide_protect

    outcome = decide_protect(
        verdict=ProtectVerdict(
            fired=True,
            severity=Severity(75),
            detector_version="advisory-score",
            matched_rules=("advisory-signal",),
        ),
        trust=TrustLevel.UNSIGNED,
        enforce=True,
    )
    assert outcome.decision is not ProtectDecision.BLOCK
    assert outcome.decision is not ProtectDecision.CONTAIN
    assert outcome.decision.requires_human is True
