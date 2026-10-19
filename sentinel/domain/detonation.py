"""Phase 11: what a skill DID when it ran, and the verdict over that.

WHAT THIS MODULE IS AND IS NOT
------------------------------
It is the observation record a sandbox produces and the verdict logic over it.
It is NOT a sandbox, and it deliberately cannot become one: nothing here spawns
a process, opens a socket or touches a filesystem. A domain module that could
execute a skill would be a domain module that executes untrusted code on the
control plane, which is the single thing the specification forbids outright.

`Detonator` is the port a real isolation boundary implements -- gVisor, a
Firecracker microVM, a disposable container on a node that runs nothing else.
`RefusingDetonator` is what a deployment without one gets, and it REFUSES.

WHY THERE IS NO SUBPROCESS FALLBACK
-------------------------------------
The tempting shape is: use the real sandbox when configured, otherwise run it in
a subprocess with a timeout and reduced privileges. That would be worse than
having nothing. A subprocess on the control-plane host shares its filesystem,
its network position, its environment and its credentials -- so the "degraded"
mode is precisely the attack the whole feature exists to prevent, and it would
be reached by exactly the deployments that did not configure isolation.

So the fallback is a refusal with a reason. `test_nothing_here_can_execute_
anything` greps this module for every primitive that could start one.

THE CANARY IS WHAT MAKES EXFILTRATION PROVABLE
------------------------------------------------
"Did this skill steal credentials" is not answerable by watching syscalls: a
skill legitimately reads configuration, and a skill legitimately makes requests.
What IS answerable is whether a value that exists nowhere in the world except
the sandbox appeared in an outbound payload.

So the sandbox seeds fake credentials, and `assess` looks for those exact
strings in what left. A match is not a heuristic -- the only way that value
reaches a network is if the skill read it and sent it. Absence is not proof of
innocence, and `DetonationVerdict.limits` says so.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Protocol, Sequence, runtime_checkable

from sentinel.domain.errors import DomainRuleViolated
from sentinel.domain.observed_binding import AuthorizedScope, ObservedVerdict

__all__ = [
    "BEHAVIOUR_SEVERITY",
    "Behaviour",
    "BehaviourFinding",
    "DetonationObservation",
    "DetonationVerdict",
    "Detonator",
    "DetonationUnavailable",
    "RefusingDetonator",
    "ScopeObservingDetonator",
    "ScopedDetonation",
    "assess",
]


class DetonationUnavailable(DomainRuleViolated):
    """No isolation boundary is configured, so nothing was executed.

    NOT retryable. A deployment without a sandbox will not acquire one between
    two attempts, and retrying would turn a configuration gap into a loop.
    """

    is_retryable = False


class Behaviour(str, Enum):
    """One member per thing a skill can be observed doing that matters."""

    CANARY_EXFILTRATION = "canary_exfiltration"
    CREDENTIAL_FILE_READ = "credential_file_read"
    REMOTE_CODE_LOADED = "remote_code_loaded"
    PERSISTENCE_ATTEMPT = "persistence_attempt"
    UNDECLARED_NETWORK = "undeclared_network"
    PACKAGE_INSTALLED_AT_RUNTIME = "package_installed_at_runtime"
    PROCESS_SPAWNED = "process_spawned"
    ENVIRONMENT_HARVESTED = "environment_harvested"
    SYSTEM_PROMPT_MODIFIED = "system_prompt_modified"


#: Severity per behaviour, in one place so an author constructing a finding
#: cannot understate it. Same discipline as every other severity table here.
#:
#: CANARY_EXFILTRATION is the only one that is PROOF rather than signal, and it
#: is weighted accordingly: the seeded value exists nowhere but the sandbox, so
#: its appearance in an outbound payload has exactly one explanation.
BEHAVIOUR_SEVERITY: Mapping[Behaviour, int] = MappingProxyType({
    Behaviour.CANARY_EXFILTRATION: 100,
    Behaviour.REMOTE_CODE_LOADED: 80,
    Behaviour.CREDENTIAL_FILE_READ: 70,
    Behaviour.PERSISTENCE_ATTEMPT: 70,
    Behaviour.SYSTEM_PROMPT_MODIFIED: 60,
    Behaviour.PACKAGE_INSTALLED_AT_RUNTIME: 50,
    Behaviour.ENVIRONMENT_HARVESTED: 40,
    Behaviour.UNDECLARED_NETWORK: 40,
    Behaviour.PROCESS_SPAWNED: 30,
})

#: Paths whose reading is credential access whatever the skill says it is for.
#: Substring-matched against observed reads, lowercased.
CREDENTIAL_PATHS: tuple[str, ...] = (
    ".aws/credentials",
    ".ssh/id_",
    ".kube/config",
    ".docker/config.json",
    ".netrc",
    ".git-credentials",
    "service-account.json",
    "/var/run/secrets/",
)

#: Files whose modification outlives the run. A skill that writes here is asking
#: to run again after nobody invoked it.
PERSISTENCE_PATHS: tuple[str, ...] = (
    ".bashrc",
    ".bash_profile",
    ".zshrc",
    ".profile",
    "crontab",
    "/etc/cron",
    "systemd/system",
    "launchagents",
    ".config/autostart",
)

#: Environment variables whose reading is harvesting rather than configuration.
SECRET_ENVIRONMENT: tuple[str, ...] = (
    "aws_secret",
    "aws_session",
    "api_key",
    "apikey",
    "token",
    "password",
    "secret",
    "private_key",
)


@dataclass(frozen=True, slots=True)
class DetonationObservation:
    """What an isolation boundary saw. Facts, with no judgement attached.

    Separated from the verdict so the same recording can be re-judged when the
    rules improve, and so a sandbox implementation cannot quietly decide what is
    dangerous -- that decision belongs in one reviewable place.
    """

    skill_id: str
    #: Hosts contacted, however contacted. A sandbox that cannot distinguish DNS
    #: from a connection records both here rather than guessing.
    network_destinations: tuple[str, ...] = ()
    files_read: tuple[str, ...] = ()
    files_written: tuple[str, ...] = ()
    processes_spawned: tuple[str, ...] = ()
    packages_installed: tuple[str, ...] = ()
    environment_read: tuple[str, ...] = ()
    #: Payload fragments observed leaving. The sandbox captures what it can; a
    #: partial capture is stated by the sandbox, not assumed here.
    outbound_payloads: tuple[str, ...] = ()
    #: Code fetched and then executed, as opposed to fetched and stored.
    remote_code_loaded: tuple[str, ...] = ()
    #: True when the boundary could not observe everything it was asked to. A
    #: verdict over a partial recording is a partial verdict, and this is what
    #: makes that visible instead of inferred from a short list.
    observation_incomplete: bool = False
    incomplete_reason: str = ""


@dataclass(frozen=True, slots=True)
class BehaviourFinding:
    behaviour: Behaviour
    detail: str
    #: The observed value that produced this. Present so an analyst can act
    #: without re-reading the recording.
    evidence: str = ""

    @property
    def severity(self) -> int:
        return BEHAVIOUR_SEVERITY[self.behaviour]

    def as_dict(self) -> dict[str, Any]:
        return {
            "behaviour": self.behaviour.value,
            "severity": self.severity,
            "detail": self.detail,
            "evidence": self.evidence,
        }


@dataclass(frozen=True, slots=True)
class DetonationVerdict:
    """What the observation means, and what it cannot mean."""

    skill_id: str
    findings: tuple[BehaviourFinding, ...]
    observation_incomplete: bool = False

    limits: str = field(
        default=(
            "A clean run is NOT a safety certificate. A skill that checks the "
            "date, waits for a real credential, or recognises a sandbox will do "
            "nothing here and everything in production. This says what was "
            "observed in one execution, not what the code is capable of."
        ),
        compare=False,
    )

    @property
    def score(self) -> int:
        """Highest severity observed, not a sum.

        A sum would let three moderate behaviours outrank one exfiltration, and
        the question an operator is asking is "what is the worst thing this
        did", not "how many things did it do".
        """
        return max((f.severity for f in self.findings), default=0)

    @property
    def proven_malicious(self) -> bool:
        """Reserved for the canary. Everything else is signal, not proof."""
        return any(
            f.behaviour is Behaviour.CANARY_EXFILTRATION for f in self.findings
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "skill_id": self.skill_id,
            "score": self.score,
            "proven_malicious": self.proven_malicious,
            "observation_incomplete": self.observation_incomplete,
            "findings": [f.as_dict() for f in self.findings],
            "limits": self.limits,
        }


@runtime_checkable
class Detonator(Protocol):
    """An isolation boundary that will run a skill and report what it did.

    Implementations run the skill somewhere that is NOT the control plane:
    a microVM, a gVisor sandbox, a disposable node. The protocol is deliberately
    one method wide, because every additional capability is another thing an
    implementation could get wrong on the wrong side of the boundary.
    """

    def detonate(
        self, *, skill_id: str, package: bytes, canaries: Mapping[str, str]
    ) -> DetonationObservation: ...


@dataclass(frozen=True, slots=True)
class ScopedDetonation:
    """One recording, its behaviour verdict, and its scope verdict.

    THREE values rather than two, and the third is the one that does not
    depend on the caller having been honest. `verdict` says what the recording
    MEANS against a catalogue of dangerous behaviours. `scope` says whether
    what the process touched stayed inside what its authorization permitted --
    which is a different question, and the only one here answered from
    syscalls rather than from a declaration.

    `scope` is never absent. A boundary that cannot trace returns UNOBSERVED
    with a reason, because an absent verdict reads as a clean one.
    """

    observation: DetonationObservation
    verdict: DetonationVerdict
    scope: ObservedVerdict

    @property
    def safe_to_admit(self) -> bool:
        """True only when BOTH questions were answered and both came back clean.

        Derived, and deliberately false when the scope verdict is UNOBSERVED.
        An admission decision that treated "we could not tell" as "fine" is the
        failure the three-valued state exists to prevent -- and this property
        is where that would otherwise be quietly reintroduced.
        """
        return (
            not self.verdict.findings
            and not self.observation.observation_incomplete
            and self.scope.consistent
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "skill_id": self.observation.skill_id,
            "safe_to_admit": self.safe_to_admit,
            "observation_incomplete": self.observation.observation_incomplete,
            "incomplete_reason": self.observation.incomplete_reason,
            "findings": [f.as_dict() for f in self.verdict.findings],
            "scope": self.scope.as_dict(),
        }


@runtime_checkable
class ScopeObservingDetonator(Protocol):
    """A boundary that can also say whether the trace stayed inside scope.

    Separate from `Detonator` on purpose. Most boundaries cannot do this --
    observing it needs syscall tracing, which costs a capability -- so making
    it a second protocol lets the application layer ASK, get UNOBSERVED from
    the ones that cannot, and never silently treat a plain detonator's silence
    as agreement.
    """

    def detonate_observing_scope(
        self,
        *,
        skill_id: str,
        package: bytes,
        canaries: Mapping[str, str],
        scope: AuthorizedScope,
    ) -> tuple[DetonationObservation, ObservedVerdict]: ...


class RefusingDetonator:
    """What a deployment with no isolation boundary gets. Refuses, loudly.

    The alternative shape -- fall back to a subprocess with a timeout -- would
    be worse than having nothing at all. A subprocess on this host shares its
    filesystem, its network position, its environment and its credentials, so
    the "degraded" mode is exactly the attack the feature exists to prevent, and
    it would be reached by precisely the deployments that never configured
    isolation.
    """

    __slots__ = ("_reason",)

    def __init__(self, *, reason: str = "no detonation sandbox is configured") -> None:
        self._reason = reason

    def detonate(
        self, *, skill_id: str, package: bytes, canaries: Mapping[str, str]
    ) -> DetonationObservation:
        raise DetonationUnavailable(
            f"{self._reason}; refusing to execute skill {skill_id!r}. There is "
            "no subprocess fallback on purpose: running untrusted code on the "
            "control-plane host shares this process's filesystem, network "
            "position and credentials, which is the attack this feature exists "
            "to prevent."
        )


def assess(
    observation: DetonationObservation,
    *,
    canaries: Mapping[str, str],
    declared_destinations: Iterable[str] = (),
) -> DetonationVerdict:
    """Judge one recording. Pure: no I/O, no clock, no configuration.

    `canaries` maps a name to the exact seeded value. `declared_destinations` is
    what the skill's manifest said it would contact -- traffic beyond it is
    undeclared, which is a finding even when the destination looks benign.
    """
    findings: list[BehaviourFinding] = []

    def add(behaviour: Behaviour, detail: str, evidence: str = "") -> None:
        findings.append(
            BehaviourFinding(behaviour=behaviour, detail=detail, evidence=evidence)
        )

    # ── the canary: the only PROOF available ─────────────────────────────────
    #
    # MATCHED ON THE NAME AS WELL AS THE VALUE, and the name is the case that
    # actually fires in production.
    #
    # Both real detonators do the value matching THEMSELVES -- they search the
    # skill's output for the seeded value and then record the canary's NAME in
    # `outbound_payloads`, deliberately, so the credential-shaped string never
    # enters an evidence record. This function used to search those names for
    # the value, which can never match. The result was that
    # CANARY_EXFILTRATION -- the one behaviour this module calls proof rather
    # than signal -- was unreachable from either sandbox, and it passed every
    # test because the unit tests of `assess` hand-built observations
    # containing values while the unit tests of the detonators asserted names.
    #
    # The value check is KEPT alongside it, for a sandbox that reports raw
    # payload content rather than pre-matched names. A name present in
    # `outbound_payloads` already means the producer saw the value, so both
    # spellings are proof and neither is a weaker inference.
    payloads = tuple(observation.outbound_payloads)
    haystack = " ".join(payloads)
    for name, value in canaries.items():
        if name in payloads or (value and value in haystack):
            add(
                Behaviour.CANARY_EXFILTRATION,
                f"the seeded credential {name!r} appeared in an outbound "
                "payload. That value exists nowhere but this sandbox, so the "
                "skill read it and sent it. This is proof, not signal.",
                evidence=name,
            )

    lowered_reads = [p.lower() for p in observation.files_read]
    for path in lowered_reads:
        for marker in CREDENTIAL_PATHS:
            if marker in path:
                add(
                    Behaviour.CREDENTIAL_FILE_READ,
                    f"read {path}, which holds credentials whatever the skill "
                    "says it wanted from there",
                    evidence=path,
                )
                break

    for path in observation.files_written:
        lowered = path.lower()
        for marker in PERSISTENCE_PATHS:
            if marker in lowered:
                add(
                    Behaviour.PERSISTENCE_ATTEMPT,
                    f"wrote {path}, which survives the run: the skill is asking "
                    "to execute again when nobody invoked it",
                    evidence=path,
                )
                break

    for source in observation.remote_code_loaded:
        add(
            Behaviour.REMOTE_CODE_LOADED,
            f"fetched and executed code from {source}. Whatever was reviewed, "
            "this is not what ran",
            evidence=source,
        )

    declared = {d.lower() for d in declared_destinations}
    for destination in observation.network_destinations:
        if destination.lower() not in declared:
            add(
                Behaviour.UNDECLARED_NETWORK,
                f"contacted {destination}, which its manifest does not declare",
                evidence=destination,
            )

    for package in observation.packages_installed:
        add(
            Behaviour.PACKAGE_INSTALLED_AT_RUNTIME,
            f"installed {package} while running: what executes is no longer what "
            "was scanned",
            evidence=package,
        )

    for process in observation.processes_spawned:
        add(
            Behaviour.PROCESS_SPAWNED,
            f"spawned {process}",
            evidence=process,
        )

    harvested = [
        name
        for name in observation.environment_read
        if any(marker in name.lower() for marker in SECRET_ENVIRONMENT)
    ]
    if harvested:
        add(
            Behaviour.ENVIRONMENT_HARVESTED,
            f"read {len(harvested)} secret-shaped environment variable(s): "
            f"{', '.join(sorted(harvested)[:5])}",
            evidence=",".join(sorted(harvested)[:5]),
        )

    return DetonationVerdict(
        skill_id=observation.skill_id,
        findings=tuple(
            sorted(findings, key=lambda f: (-f.severity, f.behaviour.value))
        ),
        observation_incomplete=observation.observation_incomplete,
    )


def typosquat_candidates(
    name: str, *, popular: Sequence[str], max_distance: int = 1
) -> tuple[str, ...]:
    """Popular package names this one is one edit away from.

    DAMERAU edit distance ONE by default -- a transposition is one keystroke
    error, so `reqeusts` for `requests` is caught. That bound is the point. At distance two
    every short name resembles every other, the list fills with noise, and an
    operator stops reading it -- which is how the real `reqeusts` gets installed.

    An exact match returns nothing: a package that IS the popular one is not
    impersonating it.
    """
    target = name.strip().lower()
    if not target:
        return ()

    hits: list[str] = []
    for candidate in popular:
        other = candidate.strip().lower()
        if other == target or not other:
            continue
        if abs(len(other) - len(target)) > max_distance:
            continue
        if _edit_distance(target, other, limit=max_distance) <= max_distance:
            hits.append(candidate)
    return tuple(sorted(hits))


def _edit_distance(left: str, right: str, *, limit: int) -> int:
    """DAMERAU-Levenshtein, abandoned once it exceeds `limit`.

    Transposition counts as ONE edit, and that is the whole reason this is not
    plain Levenshtein. `reqeusts` for `requests` is a swap of two adjacent
    characters -- the single most common typosquat there is, and the one a
    tired reader is likeliest to miss. Ordinary Levenshtein scores it 2, so a
    distance-1 bound found nothing and the check was decorative against the
    exact attack it was written for. Caught by
    `test_a_one_edit_impersonation_is_caught`.

    Raising the bound to 2 instead would have "fixed" it by matching everything
    else as well: at distance 2 every short name resembles every other, the
    list fills with noise, and an operator stops reading it. Counting a swap as
    one keystroke error is both more accurate and tighter.

    Bounded because this runs over every dependency against every popular name,
    and "further than one" is all the caller needs -- the exact distance between
    two unrelated strings is work nobody reads.
    """
    if left == right:
        return 0

    # Full matrix rather than two rolling rows: transposition needs the row
    # before last, and a two-row optimisation cannot see it.
    rows, columns = len(left), len(right)
    matrix = [[0] * (columns + 1) for _ in range(rows + 1)]
    for i in range(rows + 1):
        matrix[i][0] = i
    for j in range(columns + 1):
        matrix[0][j] = j

    for i in range(1, rows + 1):
        for j in range(1, columns + 1):
            cost = int(left[i - 1] != right[j - 1])
            matrix[i][j] = min(
                matrix[i - 1][j] + 1,
                matrix[i][j - 1] + 1,
                matrix[i - 1][j - 1] + cost,
            )
            if (
                i > 1
                and j > 1
                and left[i - 1] == right[j - 2]
                and left[i - 2] == right[j - 1]
            ):
                matrix[i][j] = min(matrix[i][j], matrix[i - 2][j - 2] + 1)
        if min(matrix[i]) > limit:
            return limit + 1
    return matrix[rows][columns]
