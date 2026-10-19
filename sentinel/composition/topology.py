"""Observe how many processes are actually serving this deployment.

WHY A DECLARATION IS NOT ENOUGH
--------------------------------
`SENTINEL_WORKER_SHARD_COUNT` is what the operator SAYS the topology is, and
`settings.py` refuses production when that number exceeds one without a shared
limiter. That refusal is correct and stays. It is also evadable by accident:

    uvicorn sentinel.interface.asgi:app --workers 4

with `SENTINEL_WORKER_SHARD_COUNT` unset leaves the declared count at 1, so the
refusal never fires, and four processes each enforce the configured rate
independently. The deployment permits four times the limit and every check
reports healthy -- a limiter that looks correct and is not.

So this module reads the topology from somewhere the operator cannot mistype:
the process table.

THE THREE-VALUED RESULT, AND WHY IT IS NOT TWO
-----------------------------------------------
`Observation` is SINGLE, MULTIPLE or **UNOBSERVABLE**. The third member is the
point. Process observation here reads `/proc`, so it works on the Linux
containers this ships to and returns nothing on Windows, and a boolean result
would have to render "I could not look" as one of "fine" or "broken". Rendering
it as "fine" is how the original defect got in; rendering it as "broken" would
refuse every developer machine.

UNOBSERVABLE means the caller has to decide what an unverified assumption is
worth, and `require_shared_limiter_or_refuse` decides it explicitly rather than
by omission.

WHY NOT REGISTER PEERS IN REDIS
--------------------------------
The obvious design -- each process writes a heartbeat to the shared cache and
counts its peers -- observes the real quantity and works on every platform. It
also cannot detect the case that matters. The limiter is only process-local
when Redis is absent, so the dangerous topology is exactly *no Redis plus
several processes*, and a Redis-based observer is blind in precisely that
configuration. It would report cleanly on every deployment that was already
safe. Local observation is uglier and looks where the problem is.

PURE JUDGEMENT, SEPARATE I/O
-----------------------------
`judge_topology` takes what was read and returns the verdict; `observe_topology`
does the reading. Every interesting case -- a parent launched with `--workers 4`,
siblings present but no flag, nothing readable -- is therefore testable without
a real process tree, which is the same split that made container isolation
testable without a Docker daemon.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Sequence

__all__ = [
    "ATTESTED_SINGLE_PROCESS",
    "Observation",
    "ObservedTopology",
    "TopologyRefused",
    "judge_topology",
    "observe_topology",
    "require_shared_limiter_or_refuse",
    "worker_count_in_argv",
]

#: Set this to true to state, on the record, that this deployment runs one
#: process. It is only consulted when observation FAILED -- an attestation
#: cannot override a contradicting observation, or it would be a way to switch
#: the check off.
ATTESTED_SINGLE_PROCESS = "SENTINEL_SINGLE_PROCESS_ATTESTED"

#: How uvicorn, gunicorn and hypercorn all spell it.
_WORKER_FLAGS = frozenset({"--workers", "-w"})
_WORKER_PREFIX = "--workers="


class Observation(str, Enum):
    """What the process table actually said."""

    #: One process serves this deployment. A per-process limiter is the whole
    #: limiter, so it is correct.
    SINGLE = "single"
    #: More than one. A per-process limiter multiplies the configured rate by
    #: the number of processes.
    MULTIPLE = "multiple"
    #: Could not be determined. NOT a synonym for SINGLE, which is the entire
    #: reason this member exists.
    UNOBSERVABLE = "unobservable"


class TopologyRefused(RuntimeError):
    """Startup refused because the observed topology needs a shared limiter."""


@dataclass(frozen=True, slots=True)
class ObservedTopology:
    """What was observed, how many, and by reading what.

    `how` carries the evidence rather than a summary, so a refusal message can
    say "the parent process was launched with --workers 4" instead of "topology
    check failed". An operator who cannot see what was read cannot tell a real
    finding from a broken detector, and will switch the detector off.
    """

    observation: Observation
    #: Processes observed. Zero when UNOBSERVABLE -- never 1, because 1 is a
    #: claim and this is the absence of one.
    process_count: int
    how: str

    def __post_init__(self) -> None:
        if self.observation is Observation.UNOBSERVABLE:
            if self.process_count != 0:
                raise ValueError(
                    f"process_count={self.process_count} with an UNOBSERVABLE "
                    "observation. Nothing was counted, so any count here is a "
                    "number the caller might believe."
                )
        elif self.process_count < 1:
            raise ValueError(
                f"process_count={self.process_count} contradicts a "
                f"{self.observation.value} observation"
            )
        if self.observation is Observation.MULTIPLE and self.process_count < 2:
            raise ValueError(
                "MULTIPLE with fewer than two processes is not a multiple"
            )

    @property
    def needs_shared_state(self) -> bool:
        """True only when several processes were actually SEEN.

        UNOBSERVABLE deliberately answers False: this property reports what was
        observed, and the decision about an unverified assumption belongs to
        `require_shared_limiter_or_refuse`, where it is written out.
        """
        return self.observation is Observation.MULTIPLE


def worker_count_in_argv(argv: Sequence[str]) -> int:
    """The worker count named on a command line, or 0 if none is.

    Reads the launch command rather than the environment, which is the point:
    `--workers 4` is not something the operator can forget to mirror into a
    variable, because it IS the thing that creates the processes.
    """
    for index, token in enumerate(argv):
        if token in _WORKER_FLAGS and index + 1 < len(argv):
            try:
                count = int(argv[index + 1])
            except ValueError:
                continue
            if count > 0:
                return count
        elif token.startswith(_WORKER_PREFIX):
            try:
                count = int(token[len(_WORKER_PREFIX) :])
            except ValueError:
                continue
            if count > 0:
                return count
    return 0


def judge_topology(
    *,
    proc_readable: bool,
    self_argv: Sequence[str] = (),
    parent_argv: Sequence[str] = (),
    sibling_count: int = 1,
) -> ObservedTopology:
    """Turn what was read into a verdict. Pure.

    `sibling_count` is how many processes share our parent AND our executable,
    counting ourselves, so 1 means we are alone. It is the fallback signal for a
    server that spawns workers without recording a flag anywhere -- the flag is
    the better evidence when it exists, because it states intent, so the larger
    of the two wins.
    """
    if not proc_readable:
        return ObservedTopology(
            observation=Observation.UNOBSERVABLE,
            process_count=0,
            how=(
                "the process table could not be read (no /proc), so the number "
                "of processes serving this deployment is unknown"
            ),
        )

    declared = max(worker_count_in_argv(self_argv), worker_count_in_argv(parent_argv))
    counted = max(sibling_count, 1)

    if declared > 1 and declared >= counted:
        return ObservedTopology(
            observation=Observation.MULTIPLE,
            process_count=declared,
            how=(
                f"the launch command names {declared} workers "
                f"(--workers {declared})"
            ),
        )
    if counted > 1:
        return ObservedTopology(
            observation=Observation.MULTIPLE,
            process_count=counted,
            how=(
                f"{counted} processes share this parent and executable, so this "
                "is one worker among several"
            ),
        )
    return ObservedTopology(
        observation=Observation.SINGLE,
        process_count=1,
        how=(
            "no worker flag on the launch command and no sibling worker "
            "processes: this deployment is one process"
        ),
    )


def _read_cmdline(path: Path) -> list[str]:
    """A process's argv, or empty. NUL-separated, with a trailing NUL."""
    try:
        raw = path.read_bytes()
    except OSError:
        return []
    return [part for part in raw.decode("utf-8", "replace").split("\0") if part]


def _read_ppid(path: Path) -> int:
    """The parent pid from /proc/<pid>/status.

    Reads `status` and not `stat` deliberately: in `stat` the second field is
    the executable name in parentheses and may itself contain spaces and
    parentheses, so positional parsing of that file is a well-known way to read
    the wrong number.
    """
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("PPid:"):
                return int(line.split(":", 1)[1].strip())
    except (OSError, ValueError):
        return 0
    return 0


def observe_topology(*, proc_root: Path | None = None) -> ObservedTopology:
    """Read the process table and judge it.

    `proc_root` is injectable so the reading itself can be tested against a
    fabricated tree; the judgement is already testable through
    `judge_topology`.
    """
    root = proc_root if proc_root is not None else Path("/proc")
    self_dir = root / "self"
    if not self_dir.exists():
        return judge_topology(proc_readable=False)

    self_argv = _read_cmdline(self_dir / "cmdline")
    our_ppid = _read_ppid(self_dir / "status")
    parent_argv = (
        _read_cmdline(root / str(our_ppid) / "cmdline") if our_ppid else []
    )

    # Siblings: same parent, same executable. Matching argv[0] as well as the
    # parent matters because a supervisor may also have spawned something that
    # is not a worker, and counting those would inflate the number and produce
    # a refusal the operator cannot reproduce.
    siblings = 0
    executable = self_argv[0] if self_argv else ""
    if our_ppid and executable:
        try:
            entries = list(root.iterdir())
        except OSError:
            entries = []
        for entry in entries:
            if not entry.name.isdigit():
                continue
            if _read_ppid(entry / "status") != our_ppid:
                continue
            argv = _read_cmdline(entry / "cmdline")
            if argv and argv[0] == executable:
                siblings += 1

    return judge_topology(
        proc_readable=True,
        self_argv=self_argv,
        parent_argv=parent_argv,
        sibling_count=siblings,
    )


def require_shared_limiter_or_refuse(
    *,
    topology: ObservedTopology,
    redis_url: str,
    production: bool,
    attested_single_process: bool = False,
) -> None:
    """Refuse to start when the limiter would be per-process across replicas.

    Three outcomes, and the middle one is the one this function exists for:

      * A shared limiter is configured. Nothing to refuse, whatever the
        topology -- the limit is enforced in one place.
      * Several processes were OBSERVED with no shared limiter. Refuse, naming
        the count and how it was seen. This fires whether or not the operator
        declared it, which is the whole improvement.
      * Topology could not be observed, in production, with no shared limiter.
        Refuse unless the operator has attested single-process operation. The
        assumption that makes a per-process limiter safe is unverified here,
        and defaulting to "probably fine" is the original defect.

    Outside production the unobservable case passes: a developer machine cannot
    read /proc on Windows and is not serving traffic.
    """
    if redis_url.strip():
        return

    if topology.needs_shared_state:
        raise TopologyRefused(
            f"{topology.process_count} processes are serving this deployment -- "
            f"{topology.how} -- and SENTINEL_REDIS_URL is unset, so the rate "
            f"limiter is per-process and this deployment permits "
            f"{topology.process_count}x the configured rate. Set "
            f"SENTINEL_REDIS_URL so the limit is enforced in one place, or run "
            f"a single process. This was OBSERVED from the process table, not "
            f"read from SENTINEL_WORKER_SHARD_COUNT, so correcting that "
            f"variable will not clear it."
        )

    if (
        production
        and topology.observation is Observation.UNOBSERVABLE
        and not attested_single_process
    ):
        raise TopologyRefused(
            f"the number of processes serving this deployment could not be "
            f"determined ({topology.how}) and SENTINEL_REDIS_URL is unset. A "
            f"per-process rate limiter is only correct if this is the only "
            f"process, and that cannot be verified here, so it is an "
            f"unverified assumption underneath a security control. Set "
            f"SENTINEL_REDIS_URL, or set {ATTESTED_SINGLE_PROCESS}=true to "
            f"state on the record that this deployment runs one process."
        )
