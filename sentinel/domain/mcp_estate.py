"""Phase 9: the questions no single MCP call can answer.

WHY THIS IS NOT MORE CHECKS IN THE PROXY
------------------------------------------
`mcp_proxy_checks.py` judges one call against one server, and judges it well:
drifted listings, duplicate names WITHIN a server, changed server identity,
foreign OAuth issuers. Every one of those is answerable from the request in
hand.

Three failure modes are not, because they are properties of the ESTATE:

  1. CROSS-SERVER NAME COLLISION. Server A offers `read_file`; a newly enrolled
     server B also offers `read_file`. Neither listing is drifted, neither
     contains a duplicate, and both pass every per-call check -- but an agent
     configured with both now resolves `read_file` to whichever its client
     happens to pick, and a hostile server that guesses a common tool name has
     shadowed a trusted one without ever failing a check.

  2. SHADOW MCP. An agent calling a server nobody enrolled. The proxy refuses
     it, correctly, but the proxy only sees traffic that came through the
     proxy. A server reached directly leaves its trace in telemetry, and the
     only place that can be noticed is where enrolled servers and observed
     servers are compared.

  3. CREDENTIAL SPRAWL. One credential presented to eight servers. Each call is
     individually fine; the estate has one secret whose compromise reaches
     eight blast radii, and no per-call view can see the eighth.

WHAT THIS DELIBERATELY DOES NOT DO
------------------------------------
It does not decide. These are findings for an operator and inputs to policy,
not refusals -- a collision between two legitimately-enrolled servers is a
configuration problem to resolve deliberately, and blocking both would take out
the trusted one as well as the impostor.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence

__all__ = [
    "ESTATE_SEVERITY",
    "EstateFinding",
    "EstateFindingKind",
    "EstateReport",
    "ObservedServerUse",
    "ServerRecord",
    "assess_estate",
]


class EstateFindingKind(str, Enum):
    CROSS_SERVER_COLLISION = "cross_server_tool_collision"
    SHADOW_SERVER = "shadow_mcp_server"
    CREDENTIAL_SPRAWL = "credential_sprawl"
    BLOCKED_SERVER_STILL_USED = "blocked_server_still_used"
    UNUSED_ENROLMENT = "unused_enrolment"


#: Severity per kind, decided in one place so an author constructing a finding
#: cannot understate it.
#:
#: BLOCKED_SERVER_STILL_USED outranks SHADOW_SERVER deliberately. A shadow
#: server is one nobody assessed; a blocked one is a server somebody assessed
#: and REFUSED, still being reached. The second is a control that is not
#: holding, which is worse than a control nobody applied.
ESTATE_SEVERITY: Mapping[EstateFindingKind, str] = MappingProxyType({
    EstateFindingKind.BLOCKED_SERVER_STILL_USED: "critical",
    EstateFindingKind.SHADOW_SERVER: "high",
    EstateFindingKind.CROSS_SERVER_COLLISION: "high",
    EstateFindingKind.CREDENTIAL_SPRAWL: "moderate",
    EstateFindingKind.UNUSED_ENROLMENT: "low",
})

#: A credential presented to more servers than this is sprawl. Three is not a
#: magic number and is not pretending to be: it is the point at which "this
#: credential is for that integration" stops being a defensible description,
#: and it is a parameter because a deployment may reasonably disagree.
DEFAULT_SPRAWL_THRESHOLD = 3


@dataclass(frozen=True, slots=True)
class ServerRecord:
    """One enrolled server and what it offers. The registry's view."""

    server_id: str
    trust: str
    tool_names: tuple[str, ...] = ()
    endpoint: str = ""
    credential_id: str = ""

    @property
    def is_blocked(self) -> bool:
        return self.trust.lower() == "blocked"

    @property
    def is_enrolled(self) -> bool:
        return self.trust.lower() == "enrolled"


@dataclass(frozen=True, slots=True)
class ObservedServerUse:
    """One server an agent was seen using. Telemetry's view.

    Separate from `ServerRecord` because they answer different questions and
    come from different places: the registry says what an operator approved,
    telemetry says what actually happened, and the interesting findings are all
    in the difference.
    """

    server_id: str
    agent_ids: tuple[str, ...] = ()
    call_count: int = 0
    credential_id: str = ""


@dataclass(frozen=True, slots=True)
class EstateFinding:
    kind: EstateFindingKind
    detail: str
    #: Everything the finding is about: server ids, tool names, agent ids. Named
    #: `subjects` rather than `server_id` because a collision is about two
    #: servers and sprawl is about one credential and many.
    subjects: tuple[str, ...] = ()

    @property
    def severity(self) -> str:
        return ESTATE_SEVERITY[self.kind]

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "severity": self.severity,
            "detail": self.detail,
            "subjects": list(self.subjects),
        }


@dataclass(frozen=True, slots=True)
class EstateReport:
    findings: tuple[EstateFinding, ...]
    enrolled_count: int = 0
    observed_count: int = 0

    limits: str = field(
        default=(
            "Shadow servers are found by comparing enrolled servers to OBSERVED "
            "ones, so this sees only servers that appear in telemetry Sentinel "
            "received. A server reached by an agent that reports nothing is "
            "invisible here, and absence of a shadow finding is not evidence "
            "that none exists."
        ),
        compare=False,
    )

    def of_kind(self, kind: EstateFindingKind) -> tuple[EstateFinding, ...]:
        return tuple(f for f in self.findings if f.kind is kind)

    def as_dict(self) -> dict[str, Any]:
        return {
            "enrolled_count": self.enrolled_count,
            "observed_count": self.observed_count,
            "findings": [f.as_dict() for f in self.findings],
            "limits": self.limits,
        }


def assess_estate(
    *,
    enrolled: Sequence[ServerRecord],
    observed: Iterable[ObservedServerUse] = (),
    sprawl_threshold: int = DEFAULT_SPRAWL_THRESHOLD,
) -> EstateReport:
    """Everything wrong with the ESTATE, as opposed to with one call.

    Pure. Takes both views rather than fetching either, so the answer can be
    checked against a fixed corpus and so this cannot become a component that
    queries production on a path nobody expected.
    """
    findings: list[EstateFinding] = []
    observed_list = list(observed)
    by_id = {s.server_id: s for s in enrolled}

    def add(kind: EstateFindingKind, detail: str, subjects: Sequence[str]) -> None:
        findings.append(
            EstateFinding(kind=kind, detail=detail, subjects=tuple(subjects))
        )

    # ── 1. cross-server tool-name collision ──────────────────────────────────
    #
    # Only among servers that could actually be reached. A blocked server's
    # tools are unreachable, so reporting a collision with one would send an
    # operator to resolve an ambiguity that cannot occur.
    reachable = [s for s in enrolled if not s.is_blocked]
    offering: dict[str, list[str]] = {}
    for server in reachable:
        for tool in server.tool_names:
            offering.setdefault(tool, []).append(server.server_id)

    for tool, servers in sorted(offering.items()):
        if len(servers) > 1:
            add(
                EstateFindingKind.CROSS_SERVER_COLLISION,
                f"{len(servers)} reachable servers offer a tool called {tool!r} "
                f"({', '.join(sorted(servers))}). Every per-call check passes: "
                "neither listing is drifted and neither contains a duplicate. "
                "An agent configured with both resolves the name to whichever "
                "its client picks, so a server that guessed a common tool name "
                "has shadowed a trusted one without failing a check.",
                [tool, *sorted(servers)],
            )

    # ── 2. shadow and blocked-but-used ───────────────────────────────────────
    for use in observed_list:
        record = by_id.get(use.server_id)
        if record is None:
            add(
                EstateFindingKind.SHADOW_SERVER,
                f"{use.server_id!r} was used by "
                f"{', '.join(sorted(use.agent_ids)) or 'an agent'} and is "
                "enrolled by nobody. The proxy refuses unenrolled servers, so "
                "this traffic did not go through it.",
                [use.server_id, *sorted(use.agent_ids)],
            )
        elif record.is_blocked:
            add(
                EstateFindingKind.BLOCKED_SERVER_STILL_USED,
                f"{use.server_id!r} is BLOCKED and was still reached "
                f"{use.call_count} time(s). A server somebody assessed and "
                "refused, still being called, is a control that is not holding "
                "-- worse than one nobody applied.",
                [use.server_id, *sorted(use.agent_ids)],
            )

    # ── 3. credential sprawl ─────────────────────────────────────────────────
    #
    # Counted across BOTH views. A credential shared between one enrolled server
    # and four shadow ones is exactly the case worth catching, and counting only
    # enrolments would miss it.
    credential_servers: dict[str, set[str]] = {}
    # Swept as two typed passes rather than one `(*enrolled, *observed_list)`
    # chain. The chain joins to `object`, so `entry.server_id` type-checks as an
    # attribute nothing is known to have -- and the `getattr` default silently
    # covers a record whose credential field was renamed, turning a sprawl sweep
    # that sees nothing into a sweep that reports nothing wrong.
    for record in enrolled:
        if record.credential_id:
            credential_servers.setdefault(record.credential_id, set()).add(
                record.server_id
            )
    for use in observed_list:
        if use.credential_id:
            credential_servers.setdefault(use.credential_id, set()).add(
                use.server_id
            )

    for credential, sharing in sorted(credential_servers.items()):
        if len(sharing) >= sprawl_threshold:
            add(
                EstateFindingKind.CREDENTIAL_SPRAWL,
                f"credential {credential!r} is presented to {len(sharing)} "
                f"servers ({', '.join(sorted(sharing))}). Each call is "
                "individually fine; the estate has one secret whose compromise "
                "reaches every one of those blast radii.",
                [credential, *sorted(sharing)],
            )

    # ── 4. enrolments nothing uses ───────────────────────────────────────────
    #
    # Low severity and worth saying: an enrolled server nobody calls is standing
    # trust with no benefit, and it is the cheapest thing to remove from an
    # estate before it becomes the thing an attacker impersonates.
    used = {u.server_id for u in observed_list}
    for server in enrolled:
        if server.is_enrolled and server.server_id not in used and observed_list:
            add(
                EstateFindingKind.UNUSED_ENROLMENT,
                f"{server.server_id!r} is enrolled and appears in no observed "
                "traffic: standing trust with no benefit",
                [server.server_id],
            )

    order = ("critical", "high", "moderate", "low")
    return EstateReport(
        findings=tuple(
            sorted(findings, key=lambda f: (order.index(f.severity), f.kind.value))
        ),
        enrolled_count=len(enrolled),
        observed_count=len(observed_list),
    )
