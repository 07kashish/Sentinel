"""What an endpoint sensor found, and what it deliberately did not look at.

WHY THIS IS A DOMAIN MODULE WITH NO FILESYSTEM IN IT
-----------------------------------------------------
The judgement -- is this an agent, is it shadow, what does it reach -- is pure
and belongs here. The reading of files belongs in
`sentinel/infrastructure/endpoint_scan.py`, so every interesting case can be
tested without fabricating a home directory: a scan that found nothing, a scan
that could not read a directory, and a scan that found a credential are three
different verdicts and only one of them is good news.

PRIVACY IS A DESIGN CONSTRAINT, NOT A SETTING
----------------------------------------------
This runs on developer machines. The thing that kills an endpoint sensor is not
a bug -- it is one engineer discovering it read something personal, after which
it is uninstalled everywhere and never reinstalled. So:

  * Only ALLOWLISTED paths are read, and the allowlist is agent configuration:
    `.mcp.json`, `.cursor/mcp.json`, `claude_desktop_config.json`, and the
    framework manifests. Never a home directory walk, never documents, never
    browser data, never shell history.
  * CREDENTIAL VALUES ARE NEVER RETAINED. An MCP server config routinely
    contains an API key in an `env` block. The sensor records THAT a secret is
    present and its digest, never the secret -- because a sensor that collects
    credentials centralises every developer's keys into one database, which is
    a worse problem than the one it was deployed to solve.
  * Findings are digests and counts where they can be, names where they must
    be. A server's name is needed to act on it; the token it holds is not.

READ-ONLY, AND THAT IS STRUCTURAL
----------------------------------
Nothing in this module or its infrastructure half writes to a scanned path.
There is no quarantine, no rewrite, no "fix it for you". An endpoint tool that
can modify a developer's configuration is an endpoint tool with a blast radius,
and the containment path already exists on the server side where it is
authorised and audited.

WHAT "SHADOW" MEANS HERE, AND WHY IT IS THREE-VALUED
-----------------------------------------------------
An agent is SHADOW when the estate has no record of it. That requires knowing
what the estate DOES have -- so `classify` takes the enrolled set, and when it
is not supplied every finding is `UNKNOWN` rather than `SHADOW`. An empty
enrolled set with a two-valued answer would report every agent on every machine
as shadow on the first run, which is the report that gets the sensor ignored.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping, Sequence

__all__ = [
    "AgentKind",
    "Enrolment",
    "EndpointFinding",
    "EndpointReport",
    "ScanOutcome",
    "SensorScan",
    "SecretPresence",
    "classify",
    "secret_digest",
]


class AgentKind(str, Enum):
    """What kind of agent software a finding describes."""

    MCP_SERVER = "mcp_server"
    CODING_AGENT = "coding_agent"
    FRAMEWORK = "framework"
    AGENT_PROCESS = "agent_process"
    CI_RUNNER = "ci_runner"

    @property
    def explanation(self) -> str:
        return _KIND_EXPLANATIONS[self]


_KIND_EXPLANATIONS: Mapping[AgentKind, str] = MappingProxyType({
    AgentKind.MCP_SERVER: (
        "an MCP server this machine is configured to call. The highest-value "
        "finding: it is the surface through which an agent reaches tools"
    ),
    AgentKind.CODING_AGENT: (
        "an editor or CLI agent configured on this machine, which is the "
        "principal at the top of most delegation chains"
    ),
    AgentKind.FRAMEWORK: (
        "an agent framework declared as a dependency. Presence is not use, so "
        "this is inventory rather than exposure"
    ),
    AgentKind.AGENT_PROCESS: (
        "an agent process observed running. Stronger evidence than a config "
        "file, which may be stale"
    ),
    AgentKind.CI_RUNNER: (
        "a CI runner configuration, which executes with credentials nobody is "
        "watching interactively"
    ),
})


class Enrolment(str, Enum):
    """Whether the estate knows about this.

    THREE-VALUED, and UNKNOWN is why. Deciding "shadow" needs the enrolled set;
    without it, a two-valued answer reports every agent on every machine as
    shadow on the first run -- which is the report that gets a sensor ignored.
    """

    ENROLLED = "enrolled"
    SHADOW = "shadow"
    UNKNOWN = "unknown"

    @property
    def explanation(self) -> str:
        return _ENROLMENT_EXPLANATIONS[self]


_ENROLMENT_EXPLANATIONS: Mapping[Enrolment, str] = MappingProxyType({
    Enrolment.ENROLLED: "the estate has a record of this agent",
    Enrolment.SHADOW: (
        "the estate has NO record of this agent, and the enrolled set was "
        "supplied -- so this is a genuine gap rather than an unanswered "
        "question"
    ),
    Enrolment.UNKNOWN: (
        "no enrolled set was supplied, so whether the estate knows about this "
        "was NOT determined. Not the same as shadow"
    ),
})


class ScanOutcome(str, Enum):
    """What the scan itself managed to do.

    `UNREADABLE` exists because a sensor that could not read anything and a
    machine with no agents on it produce the same empty finding list, and
    reporting the first as the second is how an endpoint fleet appears clean.
    """

    COMPLETE = "complete"
    PARTIAL = "partial"
    UNREADABLE = "unreadable"

    @property
    def explanation(self) -> str:
        return _OUTCOME_EXPLANATIONS[self]


_OUTCOME_EXPLANATIONS: Mapping[ScanOutcome, str] = MappingProxyType({
    ScanOutcome.COMPLETE: "every allowlisted path was readable",
    ScanOutcome.PARTIAL: (
        "some allowlisted paths could not be read, so this machine's inventory "
        "is incomplete and an absent finding is not evidence of absence"
    ),
    ScanOutcome.UNREADABLE: (
        "NOTHING was readable. An empty finding list here means the sensor "
        "failed, not that the machine is clean -- and treating the two alike "
        "is how a fleet reports healthy while blind"
    ),
})


class SecretPresence(str, Enum):
    """Whether a finding's configuration carries a credential.

    `PRESENT` never travels with the value. A sensor that collected
    credentials would centralise every developer's keys into one database,
    which is a worse problem than the one it was deployed to solve.
    """

    ABSENT = "absent"
    PRESENT = "present"
    NOT_INSPECTED = "not_inspected"


def secret_digest(value: str) -> str:
    """A stable identifier for a credential, without the credential.

    Truncated to 16 hex characters on purpose. Enough to correlate the same key
    appearing on twelve machines -- which is the question worth answering --
    and short enough that it is useless for offline recovery of a short or
    low-entropy secret. A full SHA-256 of a weak token is a token somebody can
    grind.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True, slots=True)
class EndpointFinding:
    """One piece of agent software on one machine."""

    kind: AgentKind
    #: The server or tool name. Needed to act on it.
    name: str
    #: Where it was found. An allowlisted path, relative to the scan root, so
    #: a home directory name never leaves the machine.
    source: str
    #: Digests of any credential values, never the values.
    secret_digests: tuple[str, ...] = ()
    secrets: SecretPresence = SecretPresence.NOT_INSPECTED
    #: Hosts this configuration reaches. Names, not contents.
    reaches: tuple[str, ...] = ()
    command: str = ""
    version: str = ""

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError(
                "an unnamed finding cannot be acted on or correlated; refusing "
                "to record one rather than emit a row nobody can use"
            )
        if self.secrets is SecretPresence.ABSENT and self.secret_digests:
            raise ValueError(
                "secrets are reported ABSENT while digests were recorded. One "
                "of the two is wrong, and the combination would let a reader "
                "conclude a config is clean while holding evidence it is not"
            )
        for digest in self.secret_digests:
            if len(digest) != 16:
                raise ValueError(
                    f"{digest!r} is not a 16-character digest. A full-length "
                    "hash of a weak token is a token somebody can grind, and a "
                    "raw value here would be the leak this sensor exists to "
                    "avoid causing"
                )

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "name": self.name,
            "source": self.source,
            "secrets": self.secrets.value,
            "secret_digests": list(self.secret_digests),
            "reaches": list(self.reaches),
            "command": self.command,
            "version": self.version,
        }


@dataclass(frozen=True, slots=True)
class SensorScan:
    """The raw result of one machine's scan, before classification."""

    host_id: str
    findings: tuple[EndpointFinding, ...] = ()
    #: Allowlisted paths that existed and could not be read.
    unreadable: tuple[str, ...] = ()
    #: Allowlisted paths that were read. Needed to tell "nothing there" from
    #: "nothing looked at".
    inspected: tuple[str, ...] = ()
    scanned_at: str = ""

    @property
    def outcome(self) -> ScanOutcome:
        if not self.inspected:
            return ScanOutcome.UNREADABLE
        return ScanOutcome.PARTIAL if self.unreadable else ScanOutcome.COMPLETE


@dataclass(frozen=True, slots=True)
class ClassifiedFinding:
    finding: EndpointFinding
    enrolment: Enrolment

    def as_dict(self) -> dict[str, Any]:
        return {
            **self.finding.as_dict(),
            "enrolment": self.enrolment.value,
            "enrolment_explanation": self.enrolment.explanation,
        }


@dataclass(frozen=True, slots=True)
class EndpointReport:
    """One machine, classified.

    `trustworthy` is derived and deliberately strict: a PARTIAL or UNREADABLE
    scan produces a report whose absences mean nothing, and a caller that
    aggregated it into a fleet total would be counting a blind machine as a
    clean one.
    """

    host_id: str
    outcome: ScanOutcome
    findings: tuple[ClassifiedFinding, ...] = ()
    unreadable: tuple[str, ...] = ()
    inspected: tuple[str, ...] = ()
    scanned_at: str = ""

    @property
    def trustworthy(self) -> bool:
        """Whether an ABSENCE in this report is evidence of absence."""
        return self.outcome is ScanOutcome.COMPLETE

    @property
    def shadow(self) -> tuple[ClassifiedFinding, ...]:
        return tuple(
            item for item in self.findings if item.enrolment is Enrolment.SHADOW
        )

    @property
    def with_secrets(self) -> tuple[ClassifiedFinding, ...]:
        return tuple(
            item
            for item in self.findings
            if item.finding.secrets is SecretPresence.PRESENT
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "host_id": self.host_id,
            "outcome": self.outcome.value,
            "outcome_explanation": self.outcome.explanation,
            "trustworthy": self.trustworthy,
            "scanned_at": self.scanned_at,
            "inspected": list(self.inspected),
            "unreadable": list(self.unreadable),
            "findings": [item.as_dict() for item in self.findings],
            "shadow_count": len(self.shadow),
            "with_secrets_count": len(self.with_secrets),
            "note": (
                "Credential VALUES are never collected. `secret_digests` are "
                "16-character digests, enough to correlate the same key across "
                "machines and useless for recovering it."
            ),
        }

    def render(self) -> str:
        lines = [
            f"{self.host_id}: {self.outcome.value} "
            f"({len(self.findings)} finding(s))",
        ]
        if not self.trustworthy:
            lines.append(f"  WARNING: {self.outcome.explanation}")
        for item in self.findings:
            lines.append(
                f"  [{item.enrolment.value}] {item.finding.kind.value} "
                f"{item.finding.name} <- {item.finding.source}"
            )
        return "\n".join(lines)


def classify(
    scan: SensorScan,
    *,
    enrolled: Sequence[str] | None = None,
) -> EndpointReport:
    """Decide, per finding, whether the estate knows about it.

    `enrolled` is OPTIONAL and its absence is not an empty set. Passing None
    yields UNKNOWN for every finding; passing an empty sequence means the
    estate genuinely has no agents, and every finding is then SHADOW. Those are
    different claims and conflating them would report a whole fleet as shadow
    on the first run, before anybody had enrolled anything.
    """
    known = None if enrolled is None else {name.strip() for name in enrolled}

    classified = tuple(
        ClassifiedFinding(
            finding=finding,
            enrolment=(
                Enrolment.UNKNOWN
                if known is None
                else Enrolment.ENROLLED
                if finding.name in known
                else Enrolment.SHADOW
            ),
        )
        for finding in scan.findings
    )

    return EndpointReport(
        host_id=scan.host_id,
        outcome=scan.outcome,
        findings=classified,
        unreadable=scan.unreadable,
        inspected=scan.inspected,
        scanned_at=scan.scanned_at,
    )


@dataclass(frozen=True, slots=True)
class FleetSummary:
    """Many machines, with the blind ones counted separately.

    The separation is the point. A fleet total that mixed complete and
    unreadable scans would report "3 shadow agents across 40 machines" when 30
    of those machines were never read -- and the number would go DOWN as the
    sensor broke on more of them.
    """

    reports: tuple[EndpointReport, ...] = field(default=())

    @property
    def trustworthy_hosts(self) -> int:
        return sum(1 for report in self.reports if report.trustworthy)

    @property
    def blind_hosts(self) -> int:
        return sum(1 for report in self.reports if not report.trustworthy)

    @property
    def shadow_findings(self) -> int:
        """Counted ONLY over machines whose absences mean something."""
        return sum(
            len(report.shadow) for report in self.reports if report.trustworthy
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "hosts": len(self.reports),
            "trustworthy_hosts": self.trustworthy_hosts,
            "blind_hosts": self.blind_hosts,
            "shadow_findings": self.shadow_findings,
            "coverage_note": (
                "shadow_findings counts only hosts with a COMPLETE scan. A "
                "total mixing in unreadable hosts would fall as the sensor "
                "broke on more of them."
            ),
        }
