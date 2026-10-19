"""The detonation subsystem, now that something calls it.

WHAT THIS GUARDS
----------------
Before this seam existed, `Detonator`, `assess`, `ContainerDetonator` and
`TracingContainerDetonator` all had passing tests and ZERO production callers.
The whole subsystem was decorative: a sandbox nothing calls is not a sandbox.
That is the same defect `test_components_are_reachable` was written for, and
detonation was never in its registry -- which is why nothing noticed.

So these tests cover two things a unit test of the sandbox cannot:

  * the SERVICE composes detonation, behaviour assessment and the scope
    comparison, and returns all three;
  * a boundary that cannot trace syscalls yields UNOBSERVED rather than a
    pass, and `safe_to_admit` is false for it.

THE SECOND ONE IS THE LOAD-BEARING CASE
----------------------------------------
`ContainerDetonator` reports an exit code and two output streams. Nothing in
that can contradict a declaration. The tempting shape was to omit the scope
verdict when it cannot be produced -- and an absent verdict reads as a clean
one, so every caller would have treated a non-tracing sandbox as agreement.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from sentinel.application.skill_detonation import SkillDetonationService
from sentinel.domain.detonation import (
    DetonationObservation,
    DetonationUnavailable,
    RefusingDetonator,
    ScopedDetonation,
)
from sentinel.domain.observed_binding import (
    AuthorizedScope,
    ObservationState,
    ObservedVerdict,
)

SCOPE = AuthorizedScope(
    permitted_paths=("/srv/reports/*",),
    permitted_hosts=("s3.eu-west-2.amazonaws.com",),
)
CANARIES = {"AWS_SECRET_ACCESS_KEY": "canary-value-8f21"}


@dataclass
class _Attempt:
    host: str
    port: int = 443
    succeeded: bool = False


@dataclass
class _Facts:
    files_read: tuple[str, ...] = ()
    files_written: tuple[str, ...] = ()
    network_attempts: tuple[_Attempt, ...] = ()
    processes_spawned: tuple[str, ...] = ()
    unparsed: int = 0
    observed_file_access: bool = True


class _PlainDetonator:
    """A boundary that contains but does not trace. Has no scope method."""

    def __init__(self, observation: DetonationObservation) -> None:
        self.observation = observation
        self.calls = 0

    def detonate(self, *, skill_id, package, canaries):
        self.calls += 1
        return self.observation


class _TracingDouble(_PlainDetonator):
    """A boundary that DOES trace, and so can answer the scope question."""

    def __init__(self, observation, facts) -> None:
        super().__init__(observation)
        self.facts = facts

    def detonate_observing_scope(self, *, skill_id, package, canaries, scope):
        self.calls += 1
        return self.observation, scope.compare(self.facts)


def _observation(**kw) -> DetonationObservation:
    return DetonationObservation(skill_id="skill-1", **kw)


def _review(detonator, **kw) -> ScopedDetonation:
    options = dict(
        skill_id="skill-1", package=b"payload", canaries=CANARIES, scope=SCOPE
    )
    options.update(kw)
    return SkillDetonationService(detonator=detonator).review(**options)


# ── the untraced boundary is UNOBSERVED, not clean ─────────────────────────


def test_a_boundary_that_cannot_trace_yields_unobserved_not_a_pass():
    """THE load-bearing test. An exit code cannot contradict a declaration,
    and an absent scope verdict would read as a clean one.
    """
    detonator = _PlainDetonator(_observation())

    review = _review(detonator)

    assert detonator.calls == 1
    assert review.scope.state is ObservationState.UNOBSERVED
    assert review.scope.consistent is False
    assert "never asked" in review.scope.unobserved_reason


def test_an_untraced_clean_run_is_not_safe_to_admit():
    """The consequence of the test above, stated where it bites. No findings
    and no scope evidence must not add up to admission.
    """
    review = _review(_PlainDetonator(_observation()))

    assert review.verdict.findings == ()
    assert review.safe_to_admit is False


# ── the traced boundary answers the question ───────────────────────────────


def test_a_traced_run_inside_scope_is_consistent_and_admissible():
    """THE control. Every negative below would pass against a service that
    reported everything as unsafe.
    """
    review = _review(
        _TracingDouble(
            _observation(
                files_read=("/srv/reports/q3.pdf",), observation_incomplete=False
            ),
            _Facts(files_read=("/srv/reports/q3.pdf",)),
        )
    )

    assert review.scope.state is ObservationState.CONSISTENT
    assert review.verdict.findings == ()
    assert review.safe_to_admit is True


def test_a_traced_run_outside_scope_is_violated():
    review = _review(
        _TracingDouble(
            _observation(observation_incomplete=False),
            _Facts(files_read=("/etc/shadow",)),
        )
    )

    assert review.scope.state is ObservationState.VIOLATED
    assert review.safe_to_admit is False


def test_the_scope_method_is_preferred_over_plain_detonate():
    """Otherwise the tracing boundary would be asked the weaker question and
    the capability it costs would buy nothing.
    """
    detonator = _TracingDouble(
        _observation(observation_incomplete=False),
        _Facts(files_read=("/etc/shadow",)),
    )

    review = _review(detonator)

    # A plain `detonate` would have produced UNOBSERVED, not VIOLATED.
    assert review.scope.state is ObservationState.VIOLATED


def test_a_none_valued_scope_method_falls_back_instead_of_crashing():
    """`ScopeObservingDetonator` is runtime-checkable, and a runtime-checkable
    Protocol matches on the ATTRIBUTE NAME alone -- so `isinstance` would agree
    with this object and the call would then fail. `callable` is the property
    actually relied on.
    """
    detonator = _PlainDetonator(_observation())
    detonator.detonate_observing_scope = None

    review = _review(detonator)

    assert review.scope.state is ObservationState.UNOBSERVED


# ── the canary path, which was unreachable ────────────────────────────────


def test_the_real_detonators_canary_output_reaches_assess():
    """THE regression test for a live defect this seam exposed.

    Both real detonators do the value matching themselves and record the
    canary's NAME in `outbound_payloads`, so the credential-shaped string
    never enters an evidence record. `assess` searched those names for the
    VALUE, which can never match -- so CANARY_EXFILTRATION, the one behaviour
    the module calls proof rather than signal, could not fire from either
    sandbox.

    It passed every test because the unit tests of `assess` hand-built
    observations containing values, while the unit tests of the detonators
    asserted names. Nothing crossed the seam. This does.
    """
    from sentinel.domain.detonation import Behaviour, assess
    from sentinel.infrastructure.detonation_tracing import _canaries_in

    value = CANARIES["AWS_SECRET_ACCESS_KEY"]
    # The real matcher, against output that really contains the seeded value.
    payloads = _canaries_in(CANARIES, f"exfiltrating {value} now")
    assert payloads == ("AWS_SECRET_ACCESS_KEY",), (
        "control: the detonator must report the NAME, not the value"
    )

    verdict = assess(_observation(outbound_payloads=payloads), canaries=CANARIES)

    behaviours = {f.behaviour for f in verdict.findings}
    assert Behaviour.CANARY_EXFILTRATION in behaviours


def test_a_skill_that_printed_only_the_variable_name_is_not_a_finding():
    """The positive control's opposite, and the reason the detonators match on
    the value in the first place: printing the NAME demonstrates nothing.

    This asserts the detonator reports nothing for such output -- so the
    name-matching in `assess` cannot be reached by a skill that merely
    mentioned the variable.
    """
    from sentinel.infrastructure.detonation_tracing import _canaries_in

    assert _canaries_in(CANARIES, "I will read AWS_SECRET_ACCESS_KEY") == ()


def test_the_canary_value_never_appears_in_the_serialised_evidence():
    """The reason the detonators report names. A canary is credential-shaped,
    and an evidence record is exactly the kind of artifact that gets copied
    into a ticket.
    """
    from sentinel.infrastructure.detonation_tracing import _canaries_in

    value = CANARIES["AWS_SECRET_ACCESS_KEY"]
    payloads = _canaries_in(CANARIES, f"leaking {value}")

    review = _review(
        _TracingDouble(
            _observation(outbound_payloads=payloads, observation_incomplete=False),
            _Facts(files_read=("/srv/reports/q3.pdf",)),
        )
    )

    serialised = repr(review.as_dict())
    assert "AWS_SECRET_ACCESS_KEY" in serialised, "control: the name is present"
    assert value not in serialised


# ── the two judgements are independent ─────────────────────────────────────


def test_a_behaviour_finding_and_a_clean_scope_can_coexist():
    """Authorized to do something, and the something is dangerous. A service
    that collapsed the two questions into one verdict would lose this case.
    """
    review = _review(
        _TracingDouble(
            _observation(
                files_read=("/srv/reports/q3.pdf",),
                # The NAME, which is what a real detonator records.
                outbound_payloads=("AWS_SECRET_ACCESS_KEY",),
                observation_incomplete=False,
            ),
            _Facts(files_read=("/srv/reports/q3.pdf",)),
        )
    )

    assert review.scope.state is ObservationState.CONSISTENT
    assert review.verdict.findings, "canary exfiltration should be a finding"
    assert review.safe_to_admit is False


def test_an_incomplete_observation_is_not_safe_to_admit_even_when_in_scope():
    """`observation_incomplete` is True for every traced run by design, so
    admission cannot key off findings alone.
    """
    review = _review(
        _TracingDouble(
            _observation(
                files_read=("/srv/reports/q3.pdf",), observation_incomplete=True
            ),
            _Facts(files_read=("/srv/reports/q3.pdf",)),
        )
    )

    assert review.scope.state is ObservationState.CONSISTENT
    assert review.safe_to_admit is False


# ── refusal propagates rather than becoming an empty recording ────────────


def test_no_configured_boundary_refuses_rather_than_returning_a_clean_review():
    """A caller that got a clean-looking result because NOTHING RAN is the
    exact failure `RefusingDetonator` exists to prevent, so this layer must
    not catch it and substitute an empty recording.
    """
    with pytest.raises(DetonationUnavailable):
        _review(RefusingDetonator())


# ── the REAL tracing detonator, without needing a container runtime ───────


def test_the_real_tracing_detonator_delegates_to_the_scope_comparison(monkeypatch):
    """The service finds this method by `getattr`, so no static check protects
    its NAME. A rename would leave every test above passing -- they use
    doubles -- while production silently fell back to UNOBSERVED for a sandbox
    that was tracing perfectly well.

    `_run` is patched rather than Docker being required, so this exercises the
    real class's wiring: that it calls `_run`, keeps the observation, and
    compares the FACTS rather than the observation.
    """
    from sentinel.infrastructure.detonation_tracing import (
        TracingContainerDetonator,
    )

    observation = _observation(observation_incomplete=True)
    facts = _Facts(files_read=("/etc/shadow",))
    detonator = TracingContainerDetonator(image="img:1")

    monkeypatch.setattr(
        TracingContainerDetonator,
        "_run",
        lambda self, *, skill_id, package, canaries: (observation, facts),
    )

    got, verdict = detonator.detonate_observing_scope(
        skill_id="skill-1", package=b"p", canaries=CANARIES, scope=SCOPE
    )

    assert got is observation
    # VIOLATED proves the FACTS were compared. The observation carries no
    # `observed_file_access`, so comparing it instead would have produced
    # UNOBSERVED -- which is exactly the mistake this method exists to avoid.
    assert verdict.state is ObservationState.VIOLATED


def test_the_service_uses_the_real_tracing_detonators_scope_method(monkeypatch):
    """The end-to-end chain with the REAL detonator class in it, so the
    `getattr` name and the method's signature are both exercised together.
    """
    from sentinel.infrastructure.detonation_tracing import (
        TracingContainerDetonator,
    )

    monkeypatch.setattr(
        TracingContainerDetonator,
        "_run",
        lambda self, *, skill_id, package, canaries: (
            _observation(observation_incomplete=False),
            _Facts(files_read=("/srv/reports/q3.pdf",)),
        ),
    )

    review = _review(TracingContainerDetonator(image="img:1"))

    assert review.scope.state is ObservationState.CONSISTENT
    assert review.safe_to_admit is True


# ── the port is part of the destination ───────────────────────────────────


def test_a_permitted_host_on_an_unexpected_port_is_a_violation():
    """A permitted host reached on 22 is not the same finding as one reached
    on 443. Matching only the bare host would let it through.
    """
    review = _review(
        _TracingDouble(
            _observation(observation_incomplete=False),
            _Facts(
                files_read=("/srv/reports/q3.pdf",),
                network_attempts=(
                    _Attempt(host="s3.eu-west-2.amazonaws.com", port=22),
                ),
            ),
        ),
        scope=AuthorizedScope(
            permitted_paths=("/srv/reports/*",),
            permitted_hosts=("s3.eu-west-2.amazonaws.com:443",),
        ),
    )

    assert review.scope.state is ObservationState.VIOLATED
    assert "22" in review.scope.violations[0].observed


def test_a_port_agnostic_pattern_still_permits_any_port():
    """The complement: a scope that names only the host is not silently
    tightened into requiring a port.
    """
    review = _review(
        _TracingDouble(
            _observation(observation_incomplete=False),
            _Facts(
                files_read=("/srv/reports/q3.pdf",),
                network_attempts=(
                    _Attempt(host="s3.eu-west-2.amazonaws.com", port=22),
                ),
            ),
        ),
    )

    assert review.scope.state is ObservationState.CONSISTENT


# ── safe_to_admit cannot be handed a pre-decided answer ───────────────────


def test_safe_to_admit_is_derived_and_not_settable():
    """A settable field would let an admission path be given the answer it
    wanted, which is how a control becomes a formality.
    """
    with pytest.raises(TypeError):
        ScopedDetonation(  # type: ignore[call-arg]
            observation=_observation(),
            verdict=_review(_PlainDetonator(_observation())).verdict,
            scope=ObservedVerdict(
                state=ObservationState.CONSISTENT
            ),
            safe_to_admit=True,
        )


def test_the_serialised_form_carries_the_scope_state_not_just_a_boolean():
    """A reader of the evidence has to be able to tell VIOLATED from
    UNOBSERVED. A single boolean collapses them.
    """
    payload = _review(_PlainDetonator(_observation())).as_dict()

    assert payload["scope"]["state"] == "unobserved"
    assert payload["safe_to_admit"] is False
    assert payload["scope"]["unobserved_reason"]
