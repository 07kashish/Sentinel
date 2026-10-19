"""Run an untrusted skill in a container, and say plainly what that is worth.

WHAT THIS IS
------------
An implementation of the `Detonator` protocol backed by an OCI runtime. The
skill runs with no network, no capabilities, a read-only root filesystem, a
non-root user, no new privileges, and hard ceilings on memory, processes and
wall clock.

TWO THINGS THAT GET CONFUSED, AND MUST NOT BE
----------------------------------------------
**Containment** is stopping the skill from doing harm. This is good at that:
`--network=none` means an exfiltration attempt fails rather than succeeds.

**Observation** is recording what the skill tried to do. This is BAD at that.
`docker run` reports an exit code and two output streams. It does not report
which files were read, which hosts were contacted, which processes were
spawned, or which environment variables were touched -- that needs syscall
tracing (seccomp-notify, eBPF, or ptrace inside the guest), and none of it is
here.

So every observation this class produces sets `observation_incomplete=True`
with a reason naming what was not watched. That is the whole reason the field
exists: an empty `network_destinations` tuple from an uninstrumented run reads
identically to "this skill made no network calls", and one is a measurement
while the other is a shrug. `assess` would then return a clean verdict about a
skill nobody watched.

A CONTAINER IS NOT A VIRTUAL MACHINE
------------------------------------
It shares the host kernel. A kernel exploit escapes it, and so does a
container-runtime vulnerability. The `Detonator` protocol names a microVM or
gVisor as the intended boundary and this is weaker than both. Calling it
"sandboxed" without that qualification is the specific dishonesty available
here, because an operator who reads "sandboxed" allows a different set of
skills than one who reads "shares the host kernel".

It is a real improvement over running the skill on the control-plane host,
which is what the alternative actually is. It is not a substitute for hardware
isolation against a genuinely hostile skill.

THE DESIGN THAT MAKES THE ISOLATION TESTABLE
---------------------------------------------
`build_run_argv` is a PURE function returning the exact argument vector. The
isolation lives in a list a test can read with no daemon installed -- not in a
comment, a config default, or a runbook sentence. Every previous version of
this kind of check in this codebase passed while reading something other than
what it appeared to read, so `REQUIRED_ISOLATION_FLAGS` is asserted against the
argv that is actually executed.

WHEN THE RUNTIME IS MISSING
---------------------------
It REFUSES. No subprocess fallback, no degraded mode: a subprocess on this host
shares the filesystem, network position, environment and credentials of the
control plane -- the exact attack the feature prevents, reached by precisely
the deployments that never configured isolation.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from sentinel.domain.detonation import (
    DetonationObservation,
    DetonationUnavailable,
)

__all__ = [
    "ISOLATION_KIND",
    "REQUIRED_ISOLATION_FLAGS",
    "UNOBSERVED_BEHAVIOURS",
    "ContainerDetonator",
    "build_run_argv",
    "required_flags_missing_from",
    "runtime_available",
]

#: Reported wherever the boundary is named. Never the bare word "sandbox": a
#: container shares the host kernel, and the distinction changes which skills
#: an operator is willing to run.
ISOLATION_KIND = "container"

#: What a plain OCI run does not watch. Named explicitly and quoted in the
#: incomplete-observation reason, because "coverage was partial" is a shrug
#: wearing a data structure while this list tells an analyst exactly which
#: absences in the recording mean nothing.
UNOBSERVED_BEHAVIOURS: tuple[str, ...] = (
    "network_destinations",
    "files_read",
    "files_written",
    "processes_spawned",
    "packages_installed",
    "environment_read",
    "remote_code_loaded",
)

#: Flags whose absence changes what an escaping skill can do. Asserted against
#: the real argv by the test module, so dropping one fails a test rather than
#: surviving a code review somebody skims.
#:
#: A frozenset, not a list: module-level mutable state is how one caller's edit
#: silently weakens every other caller's isolation.
REQUIRED_ISOLATION_FLAGS: frozenset[str] = frozenset(
    {
        # No route off the box. The most valuable flag here: it turns
        # exfiltration and callback into failures instead of successes.
        "--network=none",
        # Drop every Linux capability, so the skill cannot mount, load modules,
        # change ownership or open raw sockets.
        "--cap-drop=ALL",
        # Immutable root filesystem; the workspace is a separate tmpfs.
        "--read-only",
        # setuid binaries in the image cannot elevate.
        "--security-opt=no-new-privileges",
        # Not root even inside the container, so a runtime escape lands as an
        # unprivileged user rather than as root on the host.
        "--user=65534:65534",
        # A fork bomb terminates instead of taking the host with it.
        "--pids-limit=64",
        # Memory ceiling, so an allocation loop stays contained.
        "--memory=256m",
        # No IPC with anything outside.
        "--ipc=none",
        # Removed on exit, so nothing survives to be re-entered.
        "--rm",
    }
)

#: Wall-clock ceiling. A skill that hangs must produce a recording that says so,
#: never an absent one -- an absent finding reads as clean.
DEFAULT_TIMEOUT_SECONDS = 30


def runtime_available(binary: str = "docker") -> bool:
    """Is an OCI runtime actually on PATH?

    Resolved with `shutil.which` so what is tested is what `subprocess` will
    resolve. A check in this codebase previously looked for a tool that was
    installed but not on PATH and concluded it was absent, so the resolution
    method matters more than it looks.

    The result is used to REFUSE, never to pick a fallback.
    """
    return shutil.which(binary) is not None


def build_run_argv(
    *,
    image: str,
    package_path: str,
    skill_id: str,
    canaries: Mapping[str, str],
    binary: str = "docker",
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    workspace_bytes: int = 16 * 1024 * 1024,
) -> tuple[str, ...]:
    """The exact argument vector, as a pure function.

    Pure on purpose. This is the only place isolation is decided, and a test
    reads the result with no daemon installed. Nothing here touches the
    environment, the clock or a config file, so what a test asserts on is what
    the subprocess receives.

    Canaries are seeded throwaway values passed as environment variables --
    never real secrets. A skill that reads one and tries to send it is caught,
    and with `--network=none` the send fails: the attempt is recorded and the
    exfiltration does not happen.
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

    argv: list[str] = [binary, "run"]
    # Sorted so the vector is deterministic and a diff between two runs is
    # meaningful rather than set-ordering noise.
    argv.extend(sorted(REQUIRED_ISOLATION_FLAGS))
    argv.extend(
        [
            # mode=1777 because the container runs as uid 65534 and a tmpfs
            # defaults to root-owned: without it the skill cannot write to
            # its OWN workspace and dies with EACCES. Found by a live traced
            # run -- the argv assertions all passed while the payload could
            # not create a file. Sticky and world-writable like /tmp, on a
            # private noexec/nosuid mount destroyed with the container.
            f"--tmpfs=/workspace:rw,noexec,nosuid,mode=1777,size={workspace_bytes}",
            # The package is mounted READ-ONLY. A skill that could rewrite its
            # own package would defeat the digest that was reviewed.
            f"--volume={package_path}:/skill/package:ro",
            "--workdir=/workspace",
            f"--env=SENTINEL_SKILL_ID={skill_id}",
            f"--stop-timeout={timeout_seconds}",
        ]
    )
    for name, value in sorted(canaries.items()):
        argv.append(f"--env=SENTINEL_CANARY_{name}={value}")
    argv.append(image)
    return tuple(argv)


def required_flags_missing_from(argv: Sequence[str]) -> tuple[str, ...]:
    """Which isolation flags are absent from a command vector.

    Returns the missing flags rather than a boolean: "isolation is wrong" and
    "the network flag specifically is missing" call for different responses,
    and a boolean would collapse them.
    """
    return tuple(sorted(REQUIRED_ISOLATION_FLAGS - set(argv)))


def _incomplete_reason(extra: str = "") -> str:
    unwatched = ", ".join(UNOBSERVED_BEHAVIOURS)
    reason = (
        f"{ISOLATION_KIND} isolation without syscall tracing. An OCI run "
        f"reports an exit code and output streams only, so these were NOT "
        f"watched and their emptiness in this recording means nothing: "
        f"{unwatched}. Reaching a clean verdict from these absences would be "
        "judging a skill nobody observed. Containment held -- --network=none "
        "means an exfiltration attempt failed -- but the attempt was not seen."
    )
    return f"{reason} {extra}".strip()


@dataclass(frozen=True, slots=True)
class ContainerDetonator:
    """Detonates a skill in a container. Refuses when it cannot isolate.

    Frozen, and holds no handle to a store or a network client: it runs one
    command and returns one recording. Anything else would be another thing to
    get wrong on the wrong side of the boundary.
    """

    image: str
    binary: str = "docker"
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS

    def detonate(
        self, *, skill_id: str, package: bytes, canaries: Mapping[str, str]
    ) -> DetonationObservation:
        """Run the skill and report what was actually seen.

        A missing runtime raises. A timeout and a crash produce recordings that
        say so. None of the three yields something that reads as a clean run:
        a tooling error must never become an execution success.
        """
        if not runtime_available(self.binary):
            raise DetonationUnavailable(
                f"{self.binary!r} is not on PATH; refusing to execute skill "
                f"{skill_id!r}. There is no subprocess fallback on purpose: "
                "running untrusted code on the control-plane host shares this "
                "process's filesystem, network position and credentials, "
                "which is the attack this feature exists to prevent."
            )

        with tempfile.TemporaryDirectory(prefix="sentinel-detonate-") as staging:
            package_path = Path(staging) / "package.bin"
            package_path.write_bytes(package)

            argv = build_run_argv(
                image=self.image,
                package_path=str(package_path),
                skill_id=skill_id,
                canaries=canaries,
                binary=self.binary,
                timeout_seconds=self.timeout_seconds,
            )

            missing = required_flags_missing_from(argv)
            if missing:
                # Belt and braces against a future edit to `build_run_argv`.
                # Refusing beats running an untrusted skill with isolation
                # somebody weakened by accident.
                raise DetonationUnavailable(
                    f"refusing to detonate {skill_id!r}: the run command is "
                    f"missing required isolation flags {missing}. Executing "
                    "with partial isolation is worse than not executing, "
                    "because the result would be trusted."
                )

            try:
                completed = subprocess.run(
                    argv,
                    capture_output=True,
                    timeout=self.timeout_seconds,
                    check=False,
                    # Bytes, decoded explicitly below. `text=True` decodes with
                    # the locale codec, which in this codebase has already
                    # produced a silently EMPTY output string on a cp1252 host
                    # -- turning a real finding into an apparent clean run.
                    text=False,
                )
            except subprocess.TimeoutExpired:
                return DetonationObservation(
                    skill_id=skill_id,
                    observation_incomplete=True,
                    incomplete_reason=_incomplete_reason(
                        f"The skill did not finish within {self.timeout_seconds}s "
                        "and was killed, so even the output streams are partial."
                    ),
                )
            except OSError as error:
                # On PATH and still could not start: an infrastructure fault,
                # not a verdict about the skill.
                raise DetonationUnavailable(
                    f"could not start {self.binary!r} to detonate "
                    f"{skill_id!r}: {error}. Refusing rather than returning a "
                    "recording, because a tooling failure that reads as a "
                    "clean run is worse than no run at all."
                ) from error

            stdout = _decode(completed.stdout)
            stderr = _decode(completed.stderr)

            return DetonationObservation(
                skill_id=skill_id,
                # The ONE behaviour genuinely observable without tracing: a
                # canary value appearing in the skill's own output. That is an
                # exfiltration attempt through the only channel it has left.
                outbound_payloads=_canaries_in_output(
                    canaries, stdout=stdout, stderr=stderr
                ),
                observation_incomplete=True,
                incomplete_reason=_incomplete_reason(
                    f"Process exited with code {completed.returncode}."
                ),
            )


def _canaries_in_output(
    canaries: Mapping[str, str], *, stdout: str, stderr: str
) -> tuple[str, ...]:
    """Canary values the skill emitted on its own output streams.

    Reported as `outbound_payloads` because that is what it is: with the
    network cut, stdout is the remaining exfiltration channel, and a skill that
    prints a seeded credential was trying to get it out.

    Matched on the VALUE, not the name. A skill that read the variable and
    printed only its name has demonstrated nothing; one that printed the value
    has demonstrated everything.
    """
    combined = stdout + stderr
    return tuple(
        sorted(
            name
            for name, value in canaries.items()
            if value and value in combined
        )
    )


def _decode(raw: bytes | None) -> str:
    """Decode subprocess output without letting the locale eat it.

    `errors="replace"` rather than strict: a skill can emit arbitrary bytes,
    and a decode error here would surface as a crash in the analysis layer --
    filed as a scanner fault instead of as the skill's output, which has
    already happened once in this codebase.
    """
    if not raw:
        return ""
    return raw.decode("utf-8", errors="replace")
