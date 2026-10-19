"""Turn strace output into observations. Written against real traces, not guesses.

WHY THIS EXISTS
---------------
`detonation_container.py` contains an untrusted skill well and observes it
badly: an OCI run reports an exit code and two output streams, so every
recording it makes sets `observation_incomplete=True` and names the behaviours
nobody watched. This module is the watching.

DESIGNED FROM CAPTURED OUTPUT, NOT FROM THE MAN PAGE
-----------------------------------------------------
Every shape handled here was taken from a real trace captured from a container
(`tests_arch/fixtures/strace_real.log`). Three of them would have been got
wrong by writing the parser from memory:

1. **busybox uses `open`, not `openat`.** A parser matching only `openat`
   reports zero file access for an Alpine-based image -- and zero file access
   is indistinguishable from a clean skill.

2. **A `connect` result has three shapes:** `= 0`, `= -1 ECONNREFUSED (...)`
   and `= ? ERESTARTSYS (...)`. All three appear in the captured trace.

3. **Under `--network=none` every connect FAILS.** So an attempt is the
   finding, and a parser that recorded only successful connections would
   report nothing for a skill trying continuously to phone home. `succeeded`
   is carried per attempt rather than used as a filter.

WHAT AN UNPARSED LINE MEANS
---------------------------
It is counted and returned. A parser that silently skips what it does not
understand reports a clean trace from a trace it could not read -- the same
failure as an empty inventory reading as a clean estate, one layer down. The
caller decides what to do with a non-zero `unparsed` count; this module
refuses to hide it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "NetworkAttempt",
    "TraceFacts",
    "parse_strace",
]

#: `PID<whitespace>syscall(args) = result`, which is the `-f` layout. The PID
#: column is optional so a single-process trace (`strace` without `-f`) parses
#: too -- and a parser that required it would silently return nothing for one.
_LINE = re.compile(
    r"^\s*(?P<pid>\d+)?\s*(?P<call>[a-z_0-9]+)\((?P<args>.*)\)\s*=\s*(?P<result>.+)$"
)

#: `= 0`, `= 3`, `= -1 ECONNREFUSED (Connection refused)`, `= ? ERESTARTSYS (...)`.
#: All three are in the captured fixture.
_RESULT = re.compile(r"^(?P<value>-?\d+|\?)\s*(?P<errno>[A-Z][A-Z0-9_]*)?")

_INET = re.compile(
    r'sa_family=AF_INET,\s*sin_port=htons\((?P<port>\d+)\),\s*'
    r'sin_addr=inet_addr\("(?P<host>[^"]+)"\)'
)
_INET6 = re.compile(
    r'sa_family=AF_INET6,\s*sin6_port=htons\((?P<port>\d+)\).*?'
    r'inet_pton\(AF_INET6,\s*"(?P<host>[^"]+)"'
)
_UNIX = re.compile(r'sa_family=AF_UNIX,\s*sun_path="(?P<path>[^"]*)"')

_FIRST_STRING = re.compile(r'^"(?P<value>(?:[^"\\]|\\.)*)"')

#: Open flags that mean the file was opened for WRITING. Checked as whole
#: tokens: `O_RDONLY` contains neither, and a substring test for "WR" would
#: match it inside nothing but would match `O_RDWR` correctly by accident
#: rather than by intent.
_WRITE_FLAGS = frozenset({"O_WRONLY", "O_RDWR", "O_APPEND", "O_CREAT", "O_TRUNC"})

#: Calls that name a file in their first string argument.
_FILE_CALLS = frozenset({"open", "openat", "creat", "unlink", "unlinkat", "stat"})

#: Calls that start a process.
_EXEC_CALLS = frozenset({"execve", "execveat"})

#: Calls that attempt a network connection.
_CONNECT_CALLS = frozenset({"connect", "sendto", "sendmsg"})


@dataclass(frozen=True, slots=True)
class NetworkAttempt:
    """One attempted connection, and whether it got anywhere.

    `succeeded` is recorded rather than used as a filter. Under
    `--network=none` every connect fails, so filtering on success would report
    nothing at all for a skill trying continuously to phone home -- and the
    attempt is the finding.
    """

    host: str
    port: int
    succeeded: bool
    #: The errno when it failed: ECONNREFUSED, ENETUNREACH, EPERM. Useful
    #: because EPERM means the sandbox refused it and ECONNREFUSED means
    #: something answered the namespace, which are different facts.
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "succeeded": self.succeeded,
            "error": self.error,
        }


@dataclass(frozen=True, slots=True)
class TraceFacts:
    """What the trace showed, and what it could not be read to show."""

    files_read: tuple[str, ...] = ()
    files_written: tuple[str, ...] = ()
    network_attempts: tuple[NetworkAttempt, ...] = ()
    unix_sockets: tuple[str, ...] = ()
    processes_spawned: tuple[str, ...] = ()
    #: Syscall names that actually appeared. Lets a caller tell "no files were
    #: opened" from "the filter never captured an open" -- the two look
    #: identical in an empty `files_read`.
    syscalls_seen: tuple[str, ...] = ()
    #: Lines the parser could not read. NOT silently dropped: a parser that
    #: skips what it does not understand reports a clean trace from a trace it
    #: could not read.
    unparsed: int = 0
    #: Exit statuses seen, so a caller can tell a completed run from a killed
    #: one without re-reading the raw text.
    exit_statuses: tuple[int, ...] = ()

    limits: str = field(
        default=(
            "strace observes SYSCALLS. It cannot see what a process did inside "
            "itself: a decoded payload never written to a file, a package "
            "resolved from a cache, code evaluated from a string. An empty "
            "`files_read` means nothing unless `open` or `openat` appears in "
            "`syscalls_seen`, and a non-zero `unparsed` means this trace was "
            "only partly read."
        ),
        compare=False,
    )

    @property
    def attempted_network(self) -> bool:
        """Did the skill try to reach the network at all?

        True for a refused connection. That is the point: under
        `--network=none` the attempt is what there is to see.
        """
        return bool(self.network_attempts)

    @property
    def observed_file_access(self) -> bool:
        """Can an empty file list be trusted?

        False when no file-opening syscall appeared at all, because then the
        emptiness describes the filter rather than the skill.
        """
        return any(call in _FILE_CALLS for call in self.syscalls_seen)

    def as_dict(self) -> dict[str, Any]:
        return {
            "files_read": list(self.files_read),
            "files_written": list(self.files_written),
            "network_attempts": [a.as_dict() for a in self.network_attempts],
            "unix_sockets": list(self.unix_sockets),
            "processes_spawned": list(self.processes_spawned),
            "syscalls_seen": list(self.syscalls_seen),
            "unparsed": self.unparsed,
            "exit_statuses": list(self.exit_statuses),
            "attempted_network": self.attempted_network,
            "observed_file_access": self.observed_file_access,
            "limits": self.limits,
        }


def _result(raw: str) -> tuple[bool, str]:
    """(succeeded, errno). `?` is a failure with a named errno, not a success."""
    match = _RESULT.match(raw.strip())
    if match is None:
        return False, ""
    value = match.group("value")
    errno = match.group("errno") or ""
    if value == "?":
        # `= ? ERESTARTSYS` -- the call did not complete. Treated as a failure
        # with its errno, because reporting it as success would turn an
        # interrupted connect into a completed one.
        return False, errno
    return int(value) >= 0 and not errno, errno


def _first_string(args: str) -> str:
    match = _FIRST_STRING.match(args.strip())
    if match is None:
        return ""
    return match.group("value")


def _is_write(args: str) -> bool:
    """Whole-token flag check.

    A substring test would be wrong in both directions: `O_RDONLY` contains no
    write flag but `O_NOFOLLOW` contains `O_NO`, and matching loosely turns
    every read into a write.
    """
    tokens = set(re.findall(r"O_[A-Z]+", args))
    return bool(tokens & _WRITE_FLAGS)


def parse_strace(text: str) -> TraceFacts:
    """Read a trace into facts. Never raises on malformed input.

    Unreadable lines are COUNTED rather than skipped, because a parser that
    quietly drops what it cannot read produces a clean-looking result from a
    trace it did not understand -- and this result is used to decide whether a
    skill is safe.
    """
    files_read: list[str] = []
    files_written: list[str] = []
    attempts: list[NetworkAttempt] = []
    sockets: list[str] = []
    processes: list[str] = []
    seen: set[str] = set()
    statuses: list[int] = []
    unparsed = 0

    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if not line:
            continue

        exited = re.search(r"\+\+\+ exited with (\d+) \+\+\+", line)
        if exited:
            statuses.append(int(exited.group(1)))
            continue
        if "--- SIG" in line or line.endswith("<unfinished ...>"):
            # A signal notification and an unfinished call carry no completed
            # syscall. Skipped deliberately, and NOT counted as unparsed --
            # counting them would make `unparsed` fire on every normal trace
            # and stop being read.
            continue

        match = _LINE.match(line)
        if match is None:
            unparsed += 1
            continue

        call = match.group("call")
        args = match.group("args")
        succeeded, errno = _result(match.group("result"))
        seen.add(call)

        if call in _FILE_CALLS:
            path = _first_string(args)
            if not path and call == "openat":
                # `openat(AT_FDCWD, "/path", ...)` -- the path is the SECOND
                # argument. Missing this reported every openat as pathless,
                # which on a glibc image is every file access there is.
                second = re.search(r',\s*"((?:[^"\\]|\\.)*)"', args)
                path = second.group(1) if second else ""
            if path:
                (files_written if _is_write(args) else files_read).append(path)
        elif call in _EXEC_CALLS:
            path = _first_string(args)
            if path:
                processes.append(path)
        elif call in _CONNECT_CALLS:
            inet = _INET.search(args) or _INET6.search(args)
            if inet:
                attempts.append(
                    NetworkAttempt(
                        host=inet.group("host"),
                        port=int(inet.group("port")),
                        succeeded=succeeded,
                        error=errno,
                    )
                )
            else:
                unix = _UNIX.search(args)
                if unix:
                    sockets.append(unix.group("path"))

    def _unique(values: list[str]) -> tuple[str, ...]:
        return tuple(sorted(set(values)))

    return TraceFacts(
        files_read=_unique(files_read),
        files_written=_unique(files_written),
        # Attempts are NOT deduplicated: forty refused connections to one host
        # is a different fact from one, and collapsing them would hide a retry
        # loop trying to get out.
        network_attempts=tuple(attempts),
        unix_sockets=_unique(sockets),
        processes_spawned=_unique(processes),
        syscalls_seen=tuple(sorted(seen)),
        unparsed=unparsed,
        exit_statuses=tuple(statuses),
    )
