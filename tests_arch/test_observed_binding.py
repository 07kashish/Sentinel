"""Evidence about conduct, not about a request.

WHAT THIS CLOSES
----------------
`verify_binding` compares an authorization against what the caller DECLARES.
That catches substitution when an agent is manipulated and not when the caller
lies about the declaration and executes something else -- an in-process wrapper
cannot see the syscalls of a closure it was handed.

A trace can. This compares what strace OBSERVED against the authorized scope,
which is the only kind of evidence here that does not depend on the caller
having been honest.

THE TEST THAT MATTERS MOST IS THE UNOBSERVED ONE
-------------------------------------------------
`test_an_empty_file_list_with_no_syscall_coverage_is_unobserved` is the
load-bearing case. An empty `files_read` means nothing unless a file-opening
syscall appeared: the emptiness may describe the FILTER rather than the
process. A two-valued verdict would report every unfiltered trace as clean,
and it would do so for exactly the traces where the filter was misconfigured.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from sentinel.domain.observed_binding import (
    ObservationState,
    ObservedVerdict,
    ScopeViolation,
    ViolationKind,
    compare_trace_to_scope,
)

PERMITTED = ("/srv/reports/*", "/tmp/*")
HOSTS = ("s3.eu-west-2.amazonaws.com",)


@dataclass
class _Attempt:
    address: str


@dataclass
class _Facts:
    """A hand-built stand-in for TraceFacts.

    Duck-typed on purpose: it lets a test set exactly the combination of
    emptiness and syscall coverage that matters, which a real trace makes
    awkward to arrange.
    """

    files_read: tuple[str, ...] = ()
    files_written: tuple[str, ...] = ()
    network_attempts: tuple[_Attempt, ...] = ()
    processes_spawned: tuple[str, ...] = ()
    syscalls_seen: tuple[str, ...] = ("openat",)
    unparsed: int = 0
    observed_file_access: bool = True


def _compare(facts, **overrides):
    options = dict(permitted_paths=PERMITTED, permitted_hosts=HOSTS)
    options.update(overrides)
    return compare_trace_to_scope(facts, **options)


# ── the anchor ─────────────────────────────────────────────────────────────


def test_a_trace_inside_scope_is_consistent():
    """THE control. Every violation test below would pass against a comparator
    that reported everything as violated.
    """
    verdict = _compare(
        _Facts(files_read=("/srv/reports/q3.pdf",), files_written=("/tmp/x",))
    )

    assert verdict.state is ObservationState.CONSISTENT
    assert verdict.consistent
    assert verdict.violations == ()


# ── the unobserved case, which is the point ────────────────────────────────


def test_an_empty_file_list_with_no_syscall_coverage_is_unobserved():
    """THE load-bearing test. An empty `files_read` with no file-opening
    syscall describes the FILTER, not the process -- and a two-valued verdict
    would report exactly the misconfigured traces as clean.
    """
    verdict = _compare(_Facts(syscalls_seen=(), observed_file_access=False))

    assert verdict.state is ObservationState.UNOBSERVED
    assert verdict.consistent is False
    assert "describes the FILTER" in verdict.unobserved_reason


def test_an_empty_file_list_with_syscall_coverage_is_consistent():
    """The other side. A trace that DID capture file syscalls and saw no file
    opened is a genuine clean result, and it must be distinguishable from the
    case above.
    """
    verdict = _compare(_Facts(observed_file_access=True))

    assert verdict.state is ObservationState.CONSISTENT


def test_an_unparsed_line_makes_the_whole_trace_unobserved():
    """A conclusion drawn from the readable part is a conclusion about a
    subset nobody chose -- and the unreadable lines are the ones a hostile
    process would want unreadable.
    """
    verdict = _compare(
        _Facts(files_read=("/srv/reports/q3.pdf",), unparsed=3)
    )

    assert verdict.state is ObservationState.UNOBSERVED
    assert "only partly read" in verdict.unobserved_reason


def test_unparsed_takes_precedence_over_a_violation():
    """Deliberate ordering. A partly-read trace cannot support "violated"
    either: the finding might be an artefact of what was missed, and reporting
    a specific violation from an incomplete trace invites acting on it.
    """
    verdict = _compare(
        _Facts(files_read=("/etc/shadow",), unparsed=1)
    )

    assert verdict.state is ObservationState.UNOBSERVED


def test_consistent_is_derived_and_false_for_unobserved():
    """A caller that treated "could not tell" as "fine" is the failure this
    module is arranged around.
    """
    unobserved = ObservedVerdict(
        state=ObservationState.UNOBSERVED, unobserved_reason="filter inactive"
    )

    assert unobserved.consistent is False


# ── violations ─────────────────────────────────────────────────────────────


def test_a_file_read_outside_scope_is_a_violation():
    verdict = _compare(_Facts(files_read=("/etc/shadow",)))

    assert verdict.state is ObservationState.VIOLATED
    assert verdict.violations[0].kind is ViolationKind.FILE_OUTSIDE_SCOPE
    assert verdict.violations[0].observed == "/etc/shadow"


def test_a_write_outside_scope_is_a_distinct_kind():
    """The response differs: a read outside scope is disclosure and a write
    outside scope is tampering or exfiltration.
    """
    verdict = _compare(_Facts(files_written=("/etc/crontab",)))

    assert verdict.violations[0].kind is ViolationKind.WRITE_OUTSIDE_SCOPE
    assert "exfiltration" in verdict.violations[0].explanation


def test_a_lookalike_path_is_not_treated_as_in_scope():
    """`/srv/reports-evil/x` shares a prefix with `/srv/reports/`. A prefix
    test accepts it; this codebase has already fixed that defect in a file
    sandbox and a delegation resource check, and reintroducing it here would
    be worse than never having known.
    """
    verdict = _compare(_Facts(files_read=("/srv/reports-evil/x",)))

    assert verdict.state is ObservationState.VIOLATED


def test_a_network_attempt_outside_scope_is_a_violation_even_when_refused():
    """Under an isolated network the ATTEMPT is the finding. A comparator that
    only reported established connections would see nothing in exactly the
    configuration designed to refuse them.
    """
    verdict = _compare(
        _Facts(network_attempts=(_Attempt(address="attacker.example"),))
    )

    assert verdict.violations[0].kind is ViolationKind.NETWORK_OUTSIDE_SCOPE
    assert "refused" in verdict.violations[0].detail


def test_a_permitted_host_is_not_a_violation():
    verdict = _compare(
        _Facts(network_attempts=(_Attempt(address=HOSTS[0]),))
    )

    assert verdict.state is ObservationState.CONSISTENT


def test_an_unexpected_process_is_a_violation_when_processes_are_constrained():
    """A tool that shells out is a tool whose real behaviour is not its own."""
    verdict = _compare(
        _Facts(processes_spawned=("/bin/sh",)),
        permitted_processes=("/usr/bin/python3",),
    )

    assert verdict.violations[0].kind is ViolationKind.UNEXPECTED_PROCESS


def test_processes_are_unconstrained_when_no_list_is_given():
    """An empty permitted list means "not checked", not "nothing permitted".
    The inverse would report every trace as violated the moment a process
    appeared.
    """
    verdict = _compare(_Facts(processes_spawned=("/bin/sh",)))

    assert verdict.state is ObservationState.CONSISTENT


def test_every_violation_is_reported_not_just_the_first():
    verdict = _compare(
        _Facts(
            files_read=("/etc/shadow",),
            files_written=("/etc/crontab",),
            network_attempts=(_Attempt(address="attacker.example"),),
        )
    )

    kinds = {v.kind for v in verdict.violations}
    assert {
        ViolationKind.FILE_OUTSIDE_SCOPE,
        ViolationKind.WRITE_OUTSIDE_SCOPE,
        ViolationKind.NETWORK_OUTSIDE_SCOPE,
    } == kinds


# ── the verdict cannot contradict itself ──────────────────────────────────


def test_violated_with_no_violations_is_refused():
    """It would name nothing to act on, so a reader could not tell what was
    touched.
    """
    with pytest.raises(ValueError) as raised:
        ObservedVerdict(state=ObservationState.VIOLATED)

    assert "nothing to act on" in str(raised.value)


def test_consistent_carrying_violations_is_refused():
    """A reader would act on the violations and ignore the state, which is the
    wrong way round.
    """
    with pytest.raises(ValueError) as raised:
        ObservedVerdict(
            state=ObservationState.CONSISTENT,
            violations=(
                ScopeViolation(
                    kind=ViolationKind.FILE_OUTSIDE_SCOPE, observed="/etc/shadow"
                ),
            ),
        )

    assert "wrong way round" in str(raised.value)


def test_unobserved_without_a_reason_is_refused():
    """It reads as a broken tracer rather than an unanswerable question, and
    an operator will disable it.
    """
    with pytest.raises(ValueError) as raised:
        ObservedVerdict(state=ObservationState.UNOBSERVED)

    assert "operator will disable it" in str(raised.value)


def test_every_state_and_kind_explains_itself():
    for value in list(ObservationState) + list(ViolationKind):
        assert len(value.explanation) > 40, value.name


def test_the_explanation_distinguishes_conduct_from_a_request():
    """The claim that makes this worth having: a trace violation is evidence
    about what a process DID, not about what it asked for.
    """
    assert "conduct" in ObservationState.VIOLATED.explanation


# ── it works against the REAL parser output ───────────────────────────────


def test_it_reads_real_trace_facts_from_the_captured_fixture():
    """The duck typing has to work against the actual `TraceFacts`, not only
    against the stand-in above -- otherwise this module is tested only against
    a shape I invented.
    """
    from pathlib import Path

    from sentinel.infrastructure.strace_parse import parse_strace

    fixture = (
        Path(__file__).resolve().parent / "fixtures" / "strace_real.log"
    )
    facts = parse_strace(fixture.read_text(encoding="utf-8"))

    verdict = compare_trace_to_scope(
        facts, permitted_paths=("/nothing/*",), permitted_hosts=()
    )

    # Whatever it concludes, it must be one of the three states and must not
    # raise on a real trace. A CONSISTENT result here would be suspicious --
    # the permitted list is deliberately empty of anything real.
    assert verdict.state in set(ObservationState)
    assert verdict.state is not ObservationState.CONSISTENT, verdict.explain()


def test_a_real_trace_inside_a_generous_scope_is_consistent_or_unobserved():
    """The complement. With everything permitted the only honest outcomes are
    CONSISTENT or UNOBSERVED -- never VIOLATED.
    """
    from pathlib import Path

    from sentinel.infrastructure.strace_parse import parse_strace

    fixture = (
        Path(__file__).resolve().parent / "fixtures" / "strace_real.log"
    )
    facts = parse_strace(fixture.read_text(encoding="utf-8"))

    verdict = compare_trace_to_scope(
        facts, permitted_paths=("*",), permitted_hosts=("*",)
    )

    assert verdict.state is not ObservationState.VIOLATED, verdict.explain()
