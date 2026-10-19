"""Compare what an authorization permitted against what a trace OBSERVED.

WHY THIS IS THE LAST PIECE OF THE BINDING
------------------------------------------
`verify_binding` compares an authorization against what the caller DECLARES it
is about to do. That catches every case where the declared action and the
approved action disagree -- which is what parameter, tool and resource
substitution look like when an agent is manipulated. It does not catch a caller
that lies about the declaration AND executes something else, because an
in-process wrapper cannot see the syscalls of a closure it was handed.

A trace can. `TraceFacts` records the files a process actually opened and the
network addresses it actually reached, from strace rather than from anybody's
assertion. This module compares those against the authorization's scope.

THE THREE-VALUED RESULT IS THE WHOLE POINT
-------------------------------------------
strace observes syscalls and nothing else. It cannot see a decoded payload
never written to a file, a package resolved from a cache, or code evaluated
from a string. And an empty `files_read` means nothing at all unless a
file-opening syscall appears in `syscalls_seen` -- the emptiness might describe
the filter rather than the process.

So the verdict is CONSISTENT, VIOLATED or UNOBSERVED, and UNOBSERVED is not a
pass. A two-valued answer would report every unfiltered trace as clean, which
is precisely the failure `TraceFacts.observed_file_access` was built to expose.

WHAT A VIOLATION HERE MEANS THAT A DECLARATION MISMATCH DOES NOT
----------------------------------------------------------------
A declaration mismatch says the caller asked for something other than what was
approved. A trace violation says the process TOUCHED something outside its
authorized scope, whatever it claimed. The second is evidence about conduct
rather than about a request, and it is the only kind this system can produce
without trusting the caller at all.

WHAT THIS DOES NOT DO
---------------------
It does not run anything and it does not block. The detonation container runs
the process; this reads the facts afterwards. Enforcement from a trace would
mean stopping a syscall mid-flight, which is a seccomp or LSM problem and a
different piece of software -- so a violation here is a finding, and the thing
that acts on it is the containment path.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping, Sequence

__all__ = [
    "UNTRACED_REASON",
    "AuthorizedScope",
    "ObservedVerdict",
    "ObservationState",
    "ScopeViolation",
    "ViolationKind",
    "compare_trace_to_scope",
]

#: Why an isolation boundary that does not trace syscalls yields UNOBSERVED
#: rather than CONSISTENT. Named as a constant so the application layer states
#: the same thing the comparator would, instead of inventing a cheerier phrase.
UNTRACED_REASON = (
    "this isolation boundary does not trace syscalls, so it produced no "
    "evidence about which files or hosts the skill actually touched. An "
    "exit code and two output streams cannot contradict a declaration. NOT a "
    "pass: it means the question was never asked."
)


class ObservationState(str, Enum):
    """Whether the trace can answer the question at all."""

    CONSISTENT = "consistent"
    VIOLATED = "violated"
    #: The trace could not be read to show one way or the other. NOT a pass,
    #: and the entire reason this enum has three members.
    UNOBSERVED = "unobserved"

    @property
    def explanation(self) -> str:
        return _STATE_EXPLANATIONS[self]


_STATE_EXPLANATIONS: Mapping[ObservationState, str] = MappingProxyType({
    ObservationState.CONSISTENT: (
        "every observed file and network destination falls inside the "
        "authorized scope, AND the trace was complete enough for that to mean "
        "something"
    ),
    ObservationState.VIOLATED: (
        "the process touched something outside its authorized scope. Evidence "
        "about conduct rather than about a request -- it does not depend on "
        "the caller having been honest"
    ),
    ObservationState.UNOBSERVED: (
        "the trace cannot answer this. Either no file-opening syscall was "
        "captured, so an empty file list describes the FILTER rather than the "
        "process, or part of the trace could not be parsed. Not a pass: "
        "'nothing was seen' and 'nothing happened' are different facts"
    ),
})


class ViolationKind(str, Enum):
    FILE_OUTSIDE_SCOPE = "file_outside_scope"
    WRITE_OUTSIDE_SCOPE = "write_outside_scope"
    NETWORK_OUTSIDE_SCOPE = "network_outside_scope"
    UNEXPECTED_PROCESS = "unexpected_process"

    @property
    def explanation(self) -> str:
        return _KIND_EXPLANATIONS[self]


_KIND_EXPLANATIONS: Mapping[ViolationKind, str] = MappingProxyType({
    ViolationKind.FILE_OUTSIDE_SCOPE: (
        "a file was read that the authorization did not cover"
    ),
    ViolationKind.WRITE_OUTSIDE_SCOPE: (
        "a file was WRITTEN outside the authorized scope, which is the "
        "shape exfiltration and tampering both take"
    ),
    ViolationKind.NETWORK_OUTSIDE_SCOPE: (
        "a network destination was attempted that the authorization did not "
        "cover. Reported even when the connection was REFUSED, because under "
        "an isolated network the attempt is the finding"
    ),
    ViolationKind.UNEXPECTED_PROCESS: (
        "a process was spawned that the authorization did not name. A tool "
        "that shells out is a tool whose real behaviour is not its own"
    ),
})


@dataclass(frozen=True, slots=True)
class ScopeViolation:
    kind: ViolationKind
    #: What was touched. A path or an address, never file CONTENT.
    observed: str
    detail: str = ""

    @property
    def explanation(self) -> str:
        """The kind's explanation, reachable from the finding.

        Every other finding type in this codebase exposes `.explanation`, and
        a reader who has a violation in hand should not have to know it lives
        on the enum -- nor serialise the whole thing to read it.
        """
        return self.kind.explanation

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "observed": self.observed,
            "detail": self.detail,
            "explanation": self.kind.explanation,
        }


@dataclass(frozen=True, slots=True)
class ObservedVerdict:
    """What the trace showed against what was authorized."""

    state: ObservationState
    violations: tuple[ScopeViolation, ...] = ()
    #: Why the trace could not answer, when it could not.
    unobserved_reason: str = ""

    def __post_init__(self) -> None:
        if self.state is ObservationState.VIOLATED and not self.violations:
            raise ValueError(
                "VIOLATED with no violations names nothing to act on, so a "
                "reader cannot tell what was touched"
            )
        if self.state is not ObservationState.VIOLATED and self.violations:
            raise ValueError(
                f"state is {self.state.value} while carrying "
                f"{len(self.violations)} violation(s). A reader would act on "
                "the violations and ignore the state, which is the wrong way "
                "round"
            )
        if (
            self.state is ObservationState.UNOBSERVED
            and not self.unobserved_reason.strip()
        ):
            raise ValueError(
                "UNOBSERVED without a reason reads as a broken tracer rather "
                "than an unanswerable question, and an operator will disable it"
            )

    @property
    def consistent(self) -> bool:
        """True ONLY for a complete trace with nothing outside scope.

        Derived, and deliberately false for UNOBSERVED. A caller that treated
        "could not tell" as "fine" is the failure this module is arranged
        around.
        """
        return self.state is ObservationState.CONSISTENT

    def as_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "state_explanation": self.state.explanation,
            "consistent": self.consistent,
            "violations": [v.as_dict() for v in self.violations],
            "unobserved_reason": self.unobserved_reason,
        }

    def explain(self) -> str:
        if self.state is ObservationState.CONSISTENT:
            return "the trace is consistent with the authorized scope"
        if self.state is ObservationState.UNOBSERVED:
            return f"UNOBSERVED: {self.unobserved_reason}"
        return "\n".join(
            [f"trace VIOLATED the authorized scope, {len(self.violations)} finding(s):"]
            + [
                f"  {v.kind.value}: {v.observed}"
                + (f" -- {v.detail}" if v.detail else "")
                for v in self.violations
            ]
        )


@dataclass(frozen=True, slots=True)
class AuthorizedScope:
    """What an authorization permits a detonated skill to touch.

    A named type rather than three loose sequences, because the three are
    passed together everywhere and a caller that swapped `permitted_hosts` for
    `permitted_processes` positionally would get a comparison that ran happily
    and meant nothing.

    `permitted_processes` empty means NOT CHECKED, not "nothing permitted" --
    the inverse would report every trace as violated the moment a process
    appeared. `permitted_paths` empty is the opposite: it means nothing is
    permitted, because a scope that authorized no path and then saw a file
    opened has been contradicted.
    """

    permitted_paths: tuple[str, ...] = ()
    permitted_hosts: tuple[str, ...] = ()
    permitted_processes: tuple[str, ...] = ()

    def compare(self, facts: Any, *, require_file_observation: bool = True):
        """Compare a trace against this scope."""
        return compare_trace_to_scope(
            facts,
            permitted_paths=self.permitted_paths,
            permitted_hosts=self.permitted_hosts,
            permitted_processes=self.permitted_processes,
            require_file_observation=require_file_observation,
        )

    def unobserved(self, reason: str = UNTRACED_REASON) -> ObservedVerdict:
        """The verdict when nothing was traced at all.

        On the scope rather than free-floating, so a caller that could not
        observe still returns the same TYPE as one that could -- and cannot
        express "no evidence" as an absent verdict, which reads as fine.
        """
        return ObservedVerdict(
            state=ObservationState.UNOBSERVED, unobserved_reason=reason
        )


def _within(path: str, patterns: Sequence[str]) -> bool:
    """Is this path covered by any pattern?

    `fnmatch`, not a prefix test. A prefix test accepts `/srv/data-evil` for a
    permitted `/srv/data`, which is the same defect this codebase has already
    fixed in a file sandbox and a delegation resource check -- and fixing it
    twice and then reintroducing it here would be worse than not knowing.
    """
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def compare_trace_to_scope(
    facts: Any,
    *,
    permitted_paths: Sequence[str],
    permitted_hosts: Sequence[str] = (),
    permitted_processes: Sequence[str] = (),
    require_file_observation: bool = True,
) -> ObservedVerdict:
    """Compare `TraceFacts` against an authorization's scope.

    `facts` is duck-typed rather than imported, so this domain module does not
    depend on the infrastructure that produces a trace -- and so a test can
    pass a hand-built object with exactly the combination of emptiness and
    syscall coverage that matters.

    `require_file_observation` defaults TRUE and should stay true. It is what
    turns an empty `files_read` into UNOBSERVED rather than CONSISTENT when no
    file-opening syscall was captured. Setting it false says "trust the
    emptiness", which is only defensible when something else established that
    the filter was active.
    """
    unparsed = int(getattr(facts, "unparsed", 0) or 0)
    if unparsed:
        return ObservedVerdict(
            state=ObservationState.UNOBSERVED,
            unobserved_reason=(
                f"{unparsed} trace line(s) could not be parsed, so this trace "
                "was only partly read. A conclusion drawn from the readable "
                "part would be a conclusion about a subset nobody chose."
            ),
        )

    files_read = tuple(getattr(facts, "files_read", ()) or ())
    files_written = tuple(getattr(facts, "files_written", ()) or ())
    attempts = tuple(getattr(facts, "network_attempts", ()) or ())
    processes = tuple(getattr(facts, "processes_spawned", ()) or ())

    # THE CHECK THAT MAKES AN EMPTY LIST MEAN SOMETHING.
    #
    # `observed_file_access` is false when no file-opening syscall appeared at
    # all, which means an empty `files_read` describes the filter rather than
    # the process. Reporting that as consistent is exactly the failure
    # `TraceFacts` exposes the flag for.
    if require_file_observation and not files_read and not files_written:
        if not getattr(facts, "observed_file_access", False):
            return ObservedVerdict(
                state=ObservationState.UNOBSERVED,
                unobserved_reason=(
                    "no file-opening syscall appears in this trace, so the "
                    "empty file list describes the FILTER rather than the "
                    "process. 'Nothing was seen' and 'nothing happened' are "
                    "different facts."
                ),
            )

    violations: list[ScopeViolation] = []

    for path in files_read:
        if not _within(path, permitted_paths):
            violations.append(
                ScopeViolation(
                    kind=ViolationKind.FILE_OUTSIDE_SCOPE,
                    observed=path,
                    detail=f"not covered by {list(permitted_paths)}",
                )
            )

    for path in files_written:
        if not _within(path, permitted_paths):
            # A separate kind from a read, because the response differs: a read
            # outside scope is disclosure and a write outside scope is
            # tampering or exfiltration.
            violations.append(
                ScopeViolation(
                    kind=ViolationKind.WRITE_OUTSIDE_SCOPE,
                    observed=path,
                    detail=f"not covered by {list(permitted_paths)}",
                )
            )

    for attempt in attempts:
        # `NetworkAttempt` carries `host` and `port`; a plain string
        # destination carries both joined. Both forms are accepted because the
        # real parser produces the first and `DetonationObservation` the second.
        host = str(getattr(attempt, "address", "") or getattr(attempt, "host", ""))
        if not host:
            continue
        port = getattr(attempt, "port", None)
        # Both spellings are offered to the patterns, so a scope may pin a port
        # (`registry.internal:443`) or ignore it (`registry.internal`). Matching
        # ONLY the bare host would let a permitted host on an unexpected port
        # through -- and a permitted host reached on 22 is not the same finding
        # as one reached on 443.
        candidates = [host] if port is None else [f"{host}:{port}", host]
        if not any(_within(c, permitted_hosts) for c in candidates):
            violations.append(
                ScopeViolation(
                    kind=ViolationKind.NETWORK_OUTSIDE_SCOPE,
                    observed=candidates[0],
                    detail=(
                        "reported even if the connection was refused: under an "
                        "isolated network the ATTEMPT is the finding"
                    ),
                )
            )

    for process in processes:
        if permitted_processes and not _within(process, permitted_processes):
            violations.append(
                ScopeViolation(
                    kind=ViolationKind.UNEXPECTED_PROCESS,
                    observed=process,
                    detail=f"not among {list(permitted_processes)}",
                )
            )

    if violations:
        return ObservedVerdict(
            state=ObservationState.VIOLATED, violations=tuple(violations)
        )
    return ObservedVerdict(state=ObservationState.CONSISTENT)
