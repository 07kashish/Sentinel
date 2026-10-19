"""Parsed against a REAL trace, because the guesses would have been wrong.

`tests_arch/fixtures/strace_real.log` was captured from an actual container
run. Three things in it contradict what a parser written from the man page
would assume, and each is asserted below:

  * busybox uses `open`, not `openat`, so an openat-only parser reports zero
    file access for an Alpine image -- and zero file access is
    indistinguishable from a clean skill;
  * a `connect` result has three shapes, including `= ? ERESTARTSYS`;
  * every connect FAILS under `--network=none`, so an attempt is the finding
    and a parser filtering on success would report nothing at all.
"""

from __future__ import annotations

from pathlib import Path

from sentinel.infrastructure.strace_parse import parse_strace

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "strace_real.log"


def _real():
    return parse_strace(FIXTURE.read_text(encoding="utf-8"))


# ── against the captured trace ───────────────────────────────────────────────


def test_the_fixture_is_a_real_captured_trace_not_a_handwritten_one():
    """If this is ever replaced by something hand-written, the parser stops
    being tested against reality and starts being tested against its author's
    assumptions.
    """
    text = FIXTURE.read_text(encoding="utf-8")

    assert "+++ exited with" in text, "no real strace exit markers"
    assert "--- SIGCHLD" in text, "no real signal notifications"
    assert "O_LARGEFILE" in text, "no real kernel flag detail"


def test_busybox_open_is_parsed_not_only_openat():
    """THE assumption that would have broken this silently.

    `cat /etc/hostname` on Alpine emits `open`, and an `openat`-only parser
    returns an empty file list -- which reads exactly like a skill that
    touched nothing.
    """
    facts = _real()

    assert "/etc/hostname" in facts.files_read
    assert "open" in facts.syscalls_seen


def test_reads_and_writes_are_distinguished_by_their_flags():
    facts = _real()

    assert "/etc/passwd" in facts.files_read
    assert "/tmp/out.txt" in facts.files_written
    assert "/tmp/out.txt" not in facts.files_read


def test_a_path_opened_both_ways_appears_in_both_lists():
    """`/dev/null` is opened O_WRONLY several times and O_RDONLY once in this
    trace. Both are true, and collapsing them would lose one.
    """
    facts = _real()

    assert "/dev/null" in facts.files_read
    assert "/dev/null" in facts.files_written


def test_processes_spawned_are_captured_from_execve():
    facts = _real()

    assert "/usr/bin/nc" in facts.processes_spawned
    assert "/bin/cat" in facts.processes_spawned


def test_a_refused_connection_is_still_recorded_as_an_attempt():
    """Under --network=none every connect fails, so filtering on success would
    report nothing for a skill trying continuously to phone home.
    """
    facts = _real()
    refused = [a for a in facts.network_attempts if a.host == "127.0.0.1"]

    assert refused, "the refused connection was dropped"
    assert refused[0].port == 9
    assert refused[0].succeeded is False
    assert refused[0].error == "ECONNREFUSED"


def test_the_interrupted_result_shape_is_parsed_as_a_failure():
    """`= ? ERESTARTSYS` -- the call did not complete. Reporting it as a
    success would turn an interrupted connect into a completed one.
    """
    facts = _real()
    interrupted = [a for a in facts.network_attempts if a.host == "10.0.0.1"]

    assert interrupted
    assert interrupted[0].port == 443
    assert interrupted[0].succeeded is False
    assert interrupted[0].error == "ERESTARTSYS"


def test_the_real_trace_parses_with_nothing_left_over():
    """A non-zero count here means the parser read only part of a real trace,
    and the facts it returned describe only that part.
    """
    assert _real().unparsed == 0


def test_exit_statuses_are_collected():
    facts = _real()

    assert facts.exit_statuses
    assert 1 in facts.exit_statuses, "the failing nc exit was lost"


def test_signal_lines_are_not_counted_as_unparsed():
    """They carry no completed syscall. Counting them would make `unparsed`
    fire on every normal trace and stop being read.
    """
    facts = parse_strace(
        "13    --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED} ---\n"
    )

    assert facts.unparsed == 0


# ── the honesty properties ───────────────────────────────────────────────────


def test_an_unreadable_line_is_counted_and_not_skipped():
    """A parser that silently drops what it cannot read produces a clean
    result from a trace it did not understand -- and this result decides
    whether a skill is safe.
    """
    facts = parse_strace("this is not a syscall line at all\nnor is this\n")

    assert facts.unparsed == 2


def test_an_empty_file_list_is_untrustworthy_when_no_open_was_traced():
    """The distinction that matters: "no files were opened" versus "the filter
    never captured an open". They produce the same empty list.
    """
    no_file_syscalls = parse_strace('13 execve("/bin/sh", ["sh"], 0x0) = 0\n')

    assert no_file_syscalls.files_read == ()
    assert no_file_syscalls.observed_file_access is False


def test_an_empty_file_list_is_trustworthy_when_opens_were_traced():
    """The positive case, or the flag is always False and stops being read."""
    facts = parse_strace('13 open("/tmp/x", O_WRONLY|O_CREAT, 0666) = 3\n')

    assert facts.observed_file_access is True


def test_repeated_connection_attempts_are_not_deduplicated():
    """Forty refused connections to one host is a different fact from one, and
    collapsing them would hide a retry loop trying to get out.
    """
    line = (
        '18 connect(3, {sa_family=AF_INET, sin_port=htons(443), '
        'sin_addr=inet_addr("10.0.0.1")}, 16) = -1 ECONNREFUSED (refused)\n'
    )
    facts = parse_strace(line * 5)

    assert len(facts.network_attempts) == 5


def test_files_are_deduplicated_because_a_path_is_a_path():
    """Unlike attempts: reading one file twice is one fact about which file
    was read, and a list of duplicates buries the other paths.
    """
    line = '13 open("/etc/passwd", O_RDONLY) = 3\n'
    facts = parse_strace(line * 4)

    assert facts.files_read == ("/etc/passwd",)


def test_the_limits_state_what_syscalls_cannot_show():
    """A decoded payload never written to a file, code evaluated from a
    string. Unsaid, a clean trace reads as a clean skill.
    """
    limits = _real().limits

    assert "cannot see what a process did inside itself" in limits
    assert "evaluated from a string" in limits


def test_the_module_records_why_it_was_written_from_captured_output():
    import inspect

    from sentinel.infrastructure import strace_parse

    doc = " ".join((inspect.getdoc(strace_parse) or "").split())

    assert "not from the man page" in doc.lower()
    assert "busybox uses `open`, not `openat`" in doc


# ── shapes the fixture does not contain, handled anyway ─────────────────────


def test_a_successful_connection_is_recorded_as_successful():
    """The fixture has no successful connect, because --network=none means
    there cannot be one. The positive branch still needs a test, or a skill
    that DID get out would be reported as having failed.
    """
    facts = parse_strace(
        '18 connect(3, {sa_family=AF_INET, sin_port=htons(443), '
        'sin_addr=inet_addr("93.184.216.34")}, 16) = 0\n'
    )

    assert facts.network_attempts[0].succeeded is True
    assert facts.network_attempts[0].error == ""


def test_an_openat_with_a_directory_fd_finds_the_path_in_the_second_argument():
    """`openat(AT_FDCWD, "/path", ...)`. Missing this reported every openat as
    pathless, which on a glibc image is every file access there is.
    """
    facts = parse_strace(
        '13 openat(AT_FDCWD, "/etc/shadow", O_RDONLY|O_CLOEXEC) = 3\n'
    )

    assert facts.files_read == ("/etc/shadow",)


def test_a_unix_socket_is_recorded_separately_from_an_inet_attempt():
    """Reaching the docker socket is a different finding from reaching the
    internet, and lumping them together loses which one happened.
    """
    facts = parse_strace(
        '13 connect(3, {sa_family=AF_UNIX, sun_path="/var/run/docker.sock"}, '
        "110) = 0\n"
    )

    assert facts.unix_sockets == ("/var/run/docker.sock",)
    assert facts.network_attempts == ()


def test_a_trace_without_pid_columns_still_parses():
    """`strace` without `-f` omits the PID column, and a parser requiring it
    would return nothing at all for such a trace.
    """
    facts = parse_strace('open("/etc/hostname", O_RDONLY) = 3\n')

    assert facts.files_read == ("/etc/hostname",)


def test_an_empty_trace_returns_empty_facts_rather_than_raising():
    facts = parse_strace("")

    assert facts.files_read == ()
    assert facts.unparsed == 0
    assert facts.observed_file_access is False


def test_o_rdonly_is_never_mistaken_for_a_write():
    """A substring flag test would be wrong in both directions. Whole tokens
    only.
    """
    facts = parse_strace('13 open("/etc/passwd", O_RDONLY|O_NOFOLLOW) = 3\n')

    assert facts.files_read == ("/etc/passwd",)
    assert facts.files_written == ()
