"""Detonation that OBSERVES, and the capability it costs to do so.

WHAT THIS ADDS TO `ContainerDetonator`
--------------------------------------
That class contains a skill well and observes it badly: an OCI run reports an
exit code and two output streams, so every recording it makes sets
`observation_incomplete=True` and names the behaviours nobody watched. This one
runs the payload under `strace` and turns the syscalls into real observations --
files read and written, connections attempted, processes spawned.

THE COST, STATED RATHER THAN BURIED
------------------------------------
`ptrace` needs `CAP_SYS_PTRACE`, so this adds `--cap-add=SYS_PTRACE` to an
otherwise `--cap-drop=ALL` container. That is a genuine widening and it is the
reason this is a SEPARATE class rather than a flag on the other one: a
deployment should choose observation over minimal capability deliberately, not
inherit it from a default.

What the capability actually permits: tracing processes in the container's own
PID namespace. The container runs one untrusted process as uid 65534 in an
isolated namespace, so there is nothing else in there to trace -- but
`SYS_PTRACE` has been part of container-escape chains, and pretending otherwise
would be the kind of quiet reassurance this codebase exists not to give.

Every other flag is unchanged. `--network=none`, `--read-only`,
`no-new-privileges`, the non-root user and the pid and memory ceilings are all
still asserted against the executed argv.

WHY THE TRACE COMES BACK ON STDERR
-----------------------------------
`strace -o /dev/stderr` keeps the trace and the payload's own output on
separate streams, so neither has to be disentangled from the other by pattern
matching. The alternative -- writing the trace to a file inside the container
-- would need a writable mount that survives `--rm`, and a writable host mount
is exactly what an untrusted skill would like.

OBSERVATION IS STILL INCOMPLETE, AND STILL SAYS SO
---------------------------------------------------
strace sees syscalls. It cannot see what a process did inside itself: a payload
decoded in memory, code evaluated from a string, a package resolved from a
cache. So `observation_incomplete` remains True -- with a reason naming only
what is STILL unwatched, which is a much shorter list than before.

Flipping it to False would be the tempting move and would be wrong: it would
turn "we watched the syscalls" into "we watched everything", and the whole
point of the field is that a reader can tell the difference.
"""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from sentinel.domain.detonation import (
    DetonationObservation,
    DetonationUnavailable,
)
from sentinel.domain.observed_binding import AuthorizedScope, ObservedVerdict
from sentinel.infrastructure.detonation_container import (
    DEFAULT_TIMEOUT_SECONDS,
    ISOLATION_KIND,
    REQUIRED_ISOLATION_FLAGS,
    required_flags_missing_from,
    runtime_available,
)
from sentinel.infrastructure.strace_parse import TraceFacts, parse_strace

__all__ = [
    "PTRACE_CAPABILITY",
    "STILL_UNOBSERVED",
    "TRACED_SYSCALLS",
    "TracingContainerDetonator",
    "build_traced_argv",
]

#: The one capability added, named as a constant so a test can assert that it
#: is the ONLY addition rather than trusting the argv builder.
PTRACE_CAPABILITY = "--cap-add=SYS_PTRACE"

#: What strace is asked to record. `%file` rather than `openat`: busybox uses
#: `open`, and an `openat`-only filter reports zero file access for an
#: Alpine-based image -- which is indistinguishable from a clean skill. Learned
#: from a captured trace, not from the man page.
TRACED_SYSCALLS = "%file,%network,%process"

#: Behaviours strace still cannot show. Named individually because "partial
#: coverage" is a shrug, and a reader needs to know exactly which absences in
#: the recording mean nothing.
STILL_UNOBSERVED: tuple[str, ...] = (
    "packages_installed — a package resolved from an image cache performs no "
    "distinguishable syscall; an install that reached the network appears as "
    "a refused connection instead",
    "remote_code_loaded — code fetched and then evaluated in memory never "
    "touches the filesystem, so nothing separates it from arithmetic",
    "outbound_payloads — the CONTENT of a blocked connection is never sent, "
    "so there is no payload to capture; only the attempt is visible",
)

#: Reported as the boundary. Still `container`, never `sandbox`: tracing the
#: syscalls does not change what the isolation is worth, and it now costs one
#: extra capability.
TRACED_ISOLATION_KIND = f"{ISOLATION_KIND}+ptrace"


def build_traced_argv(
    *,
    image: str,
    package_path: str,
    skill_id: str,
    canaries: Mapping[str, str],
    binary: str = "docker",
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    entrypoint: Sequence[str] = ("/usr/bin/python3", "-I", "-S", "/skill/package"),
    workspace_bytes: int = 16 * 1024 * 1024,
) -> tuple[str, ...]:
    """The argument vector, as a pure function. Every isolation flag retained.

    Pure for the same reason `build_run_argv` is: the isolation is decided in
    one list a test can read with no daemon installed, rather than in a comment
    or a config default.

    `SYS_PTRACE` is added and nothing is removed. A test asserts that the
    difference between this vector and the untraced one is exactly that one
    flag plus the strace wrapper -- because the tempting shortcut when ptrace
    misbehaves is to drop `--read-only` or relax `--cap-drop`, and that would
    trade the isolation for the observation without saying so.
    """
    if not image.strip():
        raise ValueError(
            "no detonation image configured; refusing to build a run command, "
            "because the alternative is falling back to a default image "
            "nobody reviewed"
        )
    if timeout_seconds <= 0:
        raise ValueError(
            f"timeout_seconds={timeout_seconds} would let an untrusted skill "
            "run with no wall-clock ceiling"
        )
    if not entrypoint:
        raise ValueError("no entrypoint to trace")

    argv: list[str] = [binary, "run"]
    argv.extend(sorted(REQUIRED_ISOLATION_FLAGS))
    argv.append(PTRACE_CAPABILITY)
    argv.extend(
        [
            # mode=1777 because the container runs as uid 65534 and a tmpfs
            # defaults to root-owned: without it the skill cannot write to
            # its OWN workspace and dies with EACCES. Found by a live traced
            # run -- the argv assertions all passed while the payload could
            # not create a file. Sticky and world-writable like /tmp, on a
            # private noexec/nosuid mount destroyed with the container.
            f"--tmpfs=/workspace:rw,noexec,nosuid,mode=1777,size={workspace_bytes}",
            f"--volume={package_path}:/skill/package:ro",
            "--workdir=/workspace",
            f"--env=SENTINEL_SKILL_ID={skill_id}",
            f"--stop-timeout={timeout_seconds}",
            # The entrypoint is REPLACED so strace becomes pid 1 and the
            # payload its child. Wrapping it any other way -- a shell that
            # execs strace, say -- would put a process between them that the
            # trace then has to be filtered for.
            "--entrypoint=/usr/bin/strace",
        ]
    )
    for name, value in sorted(canaries.items()):
        argv.append(f"--env=SENTINEL_CANARY_{name}={value}")

    argv.append(image)
    argv.extend(
        [
            "-f",
            "-e",
            f"trace={TRACED_SYSCALLS}",
            # To STDERR, so the trace and the payload's own output stay on
            # separate streams. The alternative is a writable mount that
            # survives --rm, and a writable host mount is exactly what an
            # untrusted skill would like.
            "-o",
            "/dev/stderr",
            *entrypoint,
        ]
    )
    return tuple(argv)


def _incomplete_reason(facts: TraceFacts, extra: str = "") -> str:
    unwatched = " | ".join(STILL_UNOBSERVED)
    parsed = (
        f"{facts.unparsed} trace line(s) could not be read, so the facts below "
        "describe only the part that was. "
        if facts.unparsed
        else ""
    )
    files = (
        ""
        if facts.observed_file_access
        else (
            "NO file-opening syscall appeared in this trace, so an empty "
            "files_read describes the filter rather than the skill. "
        )
    )
    return (
        f"{TRACED_ISOLATION_KIND} isolation WITH syscall tracing. Files, "
        f"connections and processes were observed. {parsed}{files}"
        f"Still unwatched: {unwatched}. "
        "observation_incomplete stays True on purpose: flipping it would turn "
        '"we watched the syscalls" into "we watched everything". '
        f"{extra}"
    ).strip()


@dataclass(frozen=True, slots=True)
class TracingContainerDetonator:
    """Runs a skill under strace inside a container. Refuses when it cannot.

    Frozen and holding no client, for the same reason as the untraced
    detonator: it runs one command and returns one recording.
    """

    image: str
    binary: str = "docker"
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    entrypoint: tuple[str, ...] = (
        "/usr/bin/python3",
        "-I",
        "-S",
        "/skill/package",
    )

    def detonate(
        self, *, skill_id: str, package: bytes, canaries: Mapping[str, str]
    ) -> DetonationObservation:
        """Run the skill, trace it, and report what the syscalls showed."""
        observation, _facts = self._run(
            skill_id=skill_id, package=package, canaries=canaries
        )
        return observation

    def _run(
        self, *, skill_id: str, package: bytes, canaries: Mapping[str, str]
    ) -> tuple[DetonationObservation, TraceFacts]:
        """Run once, returning the observation AND the trace it came from.

        Two returns rather than one because the scope comparison needs facts
        that `DetonationObservation` deliberately does not carry, and stashing
        them on `self` would mean mutable state on a frozen dataclass -- which
        would also make one detonator's second run able to answer with the
        first run's trace.
        """
        if not runtime_available(self.binary):
            raise DetonationUnavailable(
                f"{self.binary!r} is not on PATH; refusing to execute skill "
                f"{skill_id!r}. There is no subprocess fallback on purpose: "
                "running untrusted code on the control-plane host shares this "
                "process's filesystem, network position and credentials, "
                "which is the attack this feature exists to prevent."
            )

        with tempfile.TemporaryDirectory(prefix="sentinel-trace-") as staging:
            package_path = Path(staging) / "package.bin"
            package_path.write_bytes(package)

            argv = build_traced_argv(
                image=self.image,
                package_path=str(package_path),
                skill_id=skill_id,
                canaries=canaries,
                binary=self.binary,
                timeout_seconds=self.timeout_seconds,
                entrypoint=self.entrypoint,
            )

            missing = required_flags_missing_from(argv)
            if missing:
                raise DetonationUnavailable(
                    f"refusing to detonate {skill_id!r}: the traced run "
                    f"command is missing required isolation flags {missing}. "
                    "Adding tracing must not cost any of them -- executing "
                    "with partial isolation is worse than not executing, "
                    "because the result would be trusted."
                )

            try:
                completed = subprocess.run(
                    argv,
                    capture_output=True,
                    timeout=self.timeout_seconds,
                    check=False,
                    # Bytes, decoded explicitly. `text=True` decodes with the
                    # locale codec, which in this codebase has already produced
                    # a silently EMPTY output string on a cp1252 host -- and an
                    # empty trace parses to "nothing happened".
                    text=False,
                )
            except subprocess.TimeoutExpired as expired:
                # A partial trace is still evidence: a skill killed at the
                # ceiling was doing something up to that point, and discarding
                # what it did would report the timeout as the only finding.
                partial = parse_strace(_decode(expired.stderr))
                return (
                    self._observation(
                        skill_id,
                        partial,
                        extra=(
                            f"The skill did not finish within "
                            f"{self.timeout_seconds}s and was killed; this "
                            "trace is partial."
                        ),
                    ),
                    partial,
                )
            except OSError as error:
                raise DetonationUnavailable(
                    f"could not start {self.binary!r} to detonate "
                    f"{skill_id!r}: {error}. Refusing rather than returning a "
                    "recording, because a tooling failure that reads as a "
                    "clean run is worse than no run at all."
                ) from error

            facts = parse_strace(_decode(completed.stderr))
            return (
                self._observation(
                    skill_id,
                    facts,
                    extra=f"Process exited with code {completed.returncode}.",
                    stdout=_decode(completed.stdout),
                    canaries=canaries,
                ),
                facts,
            )

    def detonate_observing_scope(
        self,
        *,
        skill_id: str,
        package: bytes,
        canaries: Mapping[str, str],
        scope: AuthorizedScope,
    ) -> tuple[DetonationObservation, ObservedVerdict]:
        """Detonate, and also compare the trace against the authorized scope.

        WHY THIS IS A SEPARATE METHOD AND NOT A POST-HOC HELPER
        -------------------------------------------------------
        The comparison has to happen HERE, while `facts` is still in hand.
        `DetonationObservation` deliberately drops `unparsed` and
        `observed_file_access` -- it is a facts-with-no-judgement type and
        those are facts about the RECORDING rather than about the skill. But
        they are exactly the two signals that make the verdict three-valued: a
        comparison run against the observation alone could not tell an empty
        `files_read` that means "nothing was opened" from one that means "the
        filter was not active", and would report the second as consistent.

        So a caller cannot reconstruct this from a returned observation, and
        offering it a helper that looked as though it could would be worse
        than not offering one.
        """
        observation, facts = self._run(
            skill_id=skill_id, package=package, canaries=canaries
        )
        return observation, scope.compare(facts)

    def _observation(
        self,
        skill_id: str,
        facts: TraceFacts,
        *,
        extra: str = "",
        stdout: str = "",
        canaries: Mapping[str, str] | None = None,
    ) -> DetonationObservation:
        return DetonationObservation(
            skill_id=skill_id,
            # Hosts are recorded whether or not the connection succeeded.
            # Under --network=none every one fails, so filtering on success
            # would report nothing for a skill trying continuously to get out.
            network_destinations=tuple(
                sorted({f"{a.host}:{a.port}" for a in facts.network_attempts})
            ),
            files_read=facts.files_read,
            files_written=facts.files_written,
            processes_spawned=facts.processes_spawned,
            environment_read=(),
            outbound_payloads=_canaries_in(canaries or {}, stdout),
            observation_incomplete=True,
            incomplete_reason=_incomplete_reason(facts, extra),
        )


def _canaries_in(canaries: Mapping[str, str], stdout: str) -> tuple[str, ...]:
    """Canary values the skill printed.

    Matched on the VALUE, not the name: a skill that printed only the variable
    name has demonstrated nothing, while one that printed the value has
    demonstrated everything.
    """
    return tuple(
        sorted(name for name, value in canaries.items() if value and value in stdout)
    )


def _decode(raw: bytes | None) -> str:
    if not raw:
        return ""
    return raw.decode("utf-8", errors="replace")
