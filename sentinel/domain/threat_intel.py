"""Shared threat indicators that cannot be traced back to a tenant.

THE PROBLEM
-----------
Sentinel sees things one deployment could never see alone: an MCP server whose
tool definitions changed after enrolment, a skill that reached for credentials
it never declared, a package name one edit away from a real one. That knowledge
is worth far more pooled than isolated.

Pooling it is also the fastest way to leak a customer's estate. "Server
`billing-mcp.acme.internal` is malicious" tells every reader that somebody runs
`billing-mcp.acme.internal`, and an indicator observed by exactly one reporter
IS that reporter's inventory with a security label attached.

So the boundary here is not storage, it is PUBLICATION. A deployment may record
anything about its own estate. What crosses to other tenants is what this
module decides, and it refuses far more than it emits.

FOUR RULES, EACH CLOSING A SPECIFIC LEAK
-----------------------------------------
1. AN INDICATOR IS ABOUT AN ARTIFACT, NEVER ABOUT A TENANT.
   A tool-definition digest, a package name, a published domain: these describe
   a thing that exists in the world independently of who found it. An internal
   hostname, a resource ARN, an agent id and a credential reference describe
   the reporter, and `IndicatorKind` has no member for any of them -- so a new
   category cannot be added without someone deciding to add it.

2. K-ANONYMITY BEFORE PUBLICATION.
   An indicator is publishable only once `MIN_DISTINCT_REPORTERS` separate
   tenants have independently observed it. Below that, republishing is
   republishing one tenant's inventory.

3. COUNTS ARE BUCKETED AND DENOMINATORS ARE WITHHELD.
   "Seen by 3 of 4 tenants" is close to naming them. Exact counts also let a
   reader watch a number change and infer who joined. Only a coarse band is
   emitted, and the population size never is.

4. TIME IS COARSE.
   A timestamp to the second correlates an indicator with one deployment's
   activity. Only the observation DATE is published.

WHAT THIS MODULE IS NOT
-----------------------
It is not a feed, a client or a server. It is the decision about what may
leave, kept pure and separately testable, because "did we leak a customer"
should be answerable by reading one file and running its tests -- not by
auditing whatever the transport happened to serialise.

Nothing here assigns blame or authority either. A reputation signal is advisory
input to a human or a policy author. It is not an authorization decision, and
`ThreatSignal` deliberately carries no verdict that an enforcement path could
read as one.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import date, datetime
from enum import Enum
from types import MappingProxyType
from typing import Iterable, Mapping, Sequence


__all__ = [
    "IndicatorKind",
    "Confidence",
    "LocalObservation",
    "PublishRefusal",
    "PublishableIndicator",
    "ReporterBand",
    "aggregate",
    "fingerprint",
]


#: How many DISTINCT tenants must independently observe an indicator before it
#: may be published.
#:
#: Three, not two. With two, either reporter knows the other one saw it -- an
#: indicator they reported and can now see published tells them exactly one
#: other deployment has it, and in a small population that is often an
#: identification. Three is the smallest number where no single participant can
#: resolve the set by subtracting themselves.
#:
#: It is not five, because a threat feed that requires five independent
#: discoveries publishes nothing during the window when a novel attack is worth
#: warning about. Three trades the smallest amount of anonymity for usefulness
#: at the moment usefulness matters.
MIN_DISTINCT_REPORTERS = 3

#: Minimum tenant population before ANY indicator may be published.
#:
#: k-anonymity over a tiny population is arithmetic, not privacy: 3 of 4 names
#: three quarters of the estate. Below this, the module publishes nothing at
#: all, which is the correct behaviour for a deployment with too few
#: participants to anonymise anyone.
MIN_POPULATION = 10


class IndicatorKind(str, Enum):
    """What an indicator can be ABOUT.

    Deliberately short, and deliberately containing no member that names a
    tenant's infrastructure. Adding one is a decision someone has to make in a
    diff, which is the point -- `test_no_indicator_kind_describes_a_tenant`
    pins the current set.
    """

    #: sha256 of an MCP tool's declared definition. Identifies the DEFINITION,
    #: which is the thing that gets poisoned, not the server that served it.
    MCP_TOOL_DEFINITION = "mcp_tool_definition"
    #: A tool definition that changed after enrolment -- the rug pull.
    MCP_DEFINITION_DRIFT = "mcp_definition_drift"
    #: sha256 of a skill artefact. The package, not the deployment using it.
    SKILL_ARTEFACT = "skill_artefact"
    #: A package name published to a public registry. Already public.
    MALICIOUS_PACKAGE = "malicious_package"
    #: A package name within one edit of a popular one.
    TYPOSQUAT_PACKAGE = "typosquat_package"
    #: A PUBLIC domain a skill or tool reached for. Internal hostnames are
    #: refused; see `_PRIVATE_HOST`.
    EXFILTRATION_DOMAIN = "exfiltration_domain"
    #: A behavioural pattern: a named class of abuse, carrying no identifiers.
    ABUSE_PATTERN = "abuse_pattern"
    #: A prompt-injection string found in a tool description or a returned
    #: payload. Attacker-authored, and the same everywhere it appears.
    INJECTION_STRING = "injection_string"


class Confidence(str, Enum):
    """How much the aggregate is worth acting on. Advisory, never authority."""

    #: Multiple independent reporters, and a mechanism that cannot be
    #: coincidence -- a definition digest that changed, a canary exfiltrated.
    CORROBORATED = "corroborated"
    #: Multiple reporters, heuristic mechanism.
    SUSPECTED = "suspected"
    #: Reported, and this module will not publish it. Present so a refusal has
    #: a name rather than being an absence.
    UNPUBLISHABLE = "unpublishable"


class ReporterBand(str, Enum):
    """A coarse band instead of a count.

    An exact count moves by one when a deployment joins, and a reader watching
    it learns something about a specific participant. Bands change rarely and
    say what an operator actually needs: is this one-off, spreading, or
    everywhere.
    """

    FEW = "3-5"
    SEVERAL = "6-20"
    MANY = "21-100"
    WIDESPREAD = "100+"


#: Hosts that are somebody's INFRASTRUCTURE rather than a public destination.
#: RFC1918, loopback, link-local, and the TLDs enterprises use internally.
#:
#: `.test`, `.invalid` and `.example` are deliberately NOT here. They are RFC
#: 2606 documentation names, not private infrastructure, so refusing them as
#: "private hostname" would attach an inaccurate reason to the refusal -- and a
#: refusal reason that is wrong is worse than no reason, because somebody will
#: act on it. They are also harmless to publish: nothing routes there.
_PRIVATE_HOST = re.compile(
    r"""^(
        localhost |
        .*\.(local|internal|intranet|lan|home|corp) |
        10\.\d+\.\d+\.\d+ |
        127\.\d+\.\d+\.\d+ |
        192\.168\.\d+\.\d+ |
        172\.(1[6-9]|2\d|3[01])\.\d+\.\d+ |
        169\.254\.\d+\.\d+ |
        .*\.(svc|cluster)\.local
    )$""",
    re.IGNORECASE | re.VERBOSE,
)

#: Shapes that are a tenant's own naming rather than a public artefact. Checked
#: on the indicator VALUE, because the kind alone cannot stop somebody putting
#: an ARN in a package-name field.
_TENANT_SHAPED = (
    re.compile(r"^arn:aws"),
    re.compile(r"^projects/[^/]+/"),          # GCP resource path
    re.compile(r"^/subscriptions/[0-9a-f-]{36}", re.IGNORECASE),  # Azure
    re.compile(r"\.s3[.-][a-z0-9-]*\.amazonaws\.com$", re.IGNORECASE),
    re.compile(r"^[a-z0-9-]+\.(rds|redshift)\.[a-z0-9-]+\.amazonaws\.com$", re.I),
)


def fingerprint(value: str, *, kind: IndicatorKind) -> str:
    """A stable, kind-scoped digest of an indicator value.

    Kind-scoped so the same string under two kinds does not produce one
    identifier: a package name and a domain can coincide, and merging their
    reporter sets would inflate one indicator's count with the other's
    observers.

    NOT salted. A salt would make the digest unlinkable across deployments,
    which is exactly the linking this module exists to perform -- an indicator
    is only publishable because several tenants reported THE SAME artefact, and
    per-tenant salts make that unknowable. The values hashed here are artefact
    identifiers, already public or already attacker-authored, so the digest is
    a convenience for comparison rather than a confidentiality control. Nothing
    should treat it as one.
    """
    normalised = value.strip().lower()
    return hashlib.sha256(f"{kind.value}\x00{normalised}".encode()).hexdigest()


class PublishRefusal(str, Enum):
    """Why an indicator may not leave. Reported, never silent."""

    TOO_FEW_REPORTERS = "too_few_reporters"
    POPULATION_TOO_SMALL = "population_too_small"
    PRIVATE_HOSTNAME = "private_hostname"
    TENANT_SHAPED_VALUE = "tenant_shaped_value"
    EMPTY_VALUE = "empty_value"


@dataclass(frozen=True, slots=True)
class LocalObservation:
    """One tenant's sighting of one artefact.

    `tenant_id` is present because counting DISTINCT reporters requires knowing
    who reported. It is used for that and discarded: no `PublishableIndicator`
    carries it, and `test_no_tenant_id_survives_aggregation` proves it.
    """

    kind: IndicatorKind
    value: str
    tenant_id: str
    observed_at: datetime
    #: Whether the mechanism is deterministic (a digest changed, a canary left
    #: the sandbox) rather than heuristic. Drives `Confidence`.
    corroborating_mechanism: bool = False
    detail: str = ""

    def __post_init__(self) -> None:
        if not self.tenant_id.strip():
            raise ValueError(
                "an observation with no tenant cannot be counted toward "
                "k-anonymity, and an uncounted reporter is how a single-source "
                "indicator reaches the threshold"
            )


@dataclass(frozen=True, slots=True)
class PublishableIndicator:
    """What may cross a tenant boundary.

    Every field is about the artefact or the aggregate. There is no tenant, no
    exact count, no denominator and no sub-day timestamp, and the tests assert
    each of those absences rather than trusting the shape.
    """

    kind: IndicatorKind
    fingerprint: str
    confidence: Confidence
    reporters: ReporterBand
    first_seen: date
    last_seen: date
    #: The artefact value, ONLY where it is already public: a package name, a
    #: public domain, an attacker-authored string. Empty for everything else,
    #: so a consumer matches on the fingerprint.
    public_value: str = ""
    #: Named abuse classes. Vocabulary, not free text from a payload.
    patterns: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "fingerprint": self.fingerprint,
            "confidence": self.confidence.value,
            "reporters": self.reporters.value,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "public_value": self.public_value,
            "patterns": list(self.patterns),
        }


@dataclass(frozen=True, slots=True)
class Aggregation:
    """What may be published, and what was withheld and why."""

    publishable: tuple[PublishableIndicator, ...]
    withheld: tuple[tuple[str, PublishRefusal], ...] = field(default=())

    def as_dict(self) -> dict[str, object]:
        return {
            "publishable": [i.as_dict() for i in self.publishable],
            "withheld": [
                {"fingerprint": f, "reason": r.value} for f, r in self.withheld
            ],
            "note": (
                "`withheld` names fingerprints, never values or tenants. An "
                "indicator below the reporter threshold is one tenant's "
                "inventory, and the reason it was refused must not itself "
                "disclose it."
            ),
        }


def _band(count: int) -> ReporterBand:
    if count <= 5:
        return ReporterBand.FEW
    if count <= 20:
        return ReporterBand.SEVERAL
    if count <= 100:
        return ReporterBand.MANY
    return ReporterBand.WIDESPREAD


#: Which kinds carry a value that is already public, and may therefore be
#: emitted in the clear. Everything else publishes a fingerprint only.
_PUBLIC_VALUE_KINDS: Mapping[IndicatorKind, bool] = MappingProxyType({
    IndicatorKind.MALICIOUS_PACKAGE: True,
    IndicatorKind.TYPOSQUAT_PACKAGE: True,
    IndicatorKind.EXFILTRATION_DOMAIN: True,
    IndicatorKind.INJECTION_STRING: True,
    IndicatorKind.ABUSE_PATTERN: True,
    IndicatorKind.MCP_TOOL_DEFINITION: False,
    IndicatorKind.MCP_DEFINITION_DRIFT: False,
    IndicatorKind.SKILL_ARTEFACT: False,
})


def _refuse(observation: LocalObservation) -> PublishRefusal | None:
    """Value-level refusals, applied before any counting."""
    value = observation.value.strip()
    if not value:
        return PublishRefusal.EMPTY_VALUE
    if observation.kind is IndicatorKind.EXFILTRATION_DOMAIN:
        host = value.lower().split("/")[0].split(":")[0]
        if _PRIVATE_HOST.match(host):
            # A private hostname is the reporter's own network. Publishing it
            # would describe their infrastructure, and it is useless to anyone
            # else -- the same name means something different in every estate.
            return PublishRefusal.PRIVATE_HOSTNAME
    for pattern in _TENANT_SHAPED:
        if pattern.search(value):
            return PublishRefusal.TENANT_SHAPED_VALUE
    return None


def aggregate(
    observations: Iterable[LocalObservation],
    *,
    population: int,
    min_reporters: int = MIN_DISTINCT_REPORTERS,
    min_population: int = MIN_POPULATION,
) -> Aggregation:
    """Decide what may cross a tenant boundary.

    `population` is the number of tenants that COULD have reported. Passed in
    rather than inferred from the observations: inferring it from who happened
    to report makes the denominator equal the numerator, and every indicator
    would then look unanimous.
    """
    grouped: dict[str, list[LocalObservation]] = {}
    withheld: list[tuple[str, PublishRefusal]] = []

    for observation in observations:
        digest = fingerprint(observation.value, kind=observation.kind)
        refusal = _refuse(observation)
        if refusal is not None:
            withheld.append((digest, refusal))
            continue
        grouped.setdefault(digest, []).append(observation)

    # Population is checked ONCE, for everything. A deployment too small to
    # anonymise anybody publishes nothing, rather than publishing the subset
    # that happens to clear the reporter threshold.
    if population < min_population:
        return Aggregation(
            publishable=(),
            withheld=tuple(
                sorted(
                    {
                        (digest, PublishRefusal.POPULATION_TOO_SMALL)
                        for digest in grouped
                    }
                    | set(withheld)
                )
            ),
        )

    publishable: list[PublishableIndicator] = []
    for digest, sightings in sorted(grouped.items()):
        reporters = {s.tenant_id for s in sightings}
        if len(reporters) < min_reporters:
            withheld.append((digest, PublishRefusal.TOO_FEW_REPORTERS))
            continue

        kind = sightings[0].kind
        corroborated = any(s.corroborating_mechanism for s in sightings)
        dates = sorted(s.observed_at.date() for s in sightings)
        patterns = tuple(
            sorted({s.detail.strip() for s in sightings if s.detail.strip()})
        )

        publishable.append(
            PublishableIndicator(
                kind=kind,
                fingerprint=digest,
                confidence=(
                    Confidence.CORROBORATED if corroborated else Confidence.SUSPECTED
                ),
                reporters=_band(len(reporters)),
                first_seen=dates[0],
                last_seen=dates[-1],
                public_value=(
                    sightings[0].value.strip().lower()
                    if _PUBLIC_VALUE_KINDS.get(kind, False)
                    else ""
                ),
                patterns=patterns if kind is IndicatorKind.ABUSE_PATTERN else (),
            )
        )

    return Aggregation(
        publishable=tuple(publishable),
        withheld=tuple(sorted(set(withheld))),
    )


def local_only(observations: Sequence[LocalObservation]) -> tuple[str, ...]:
    """Fingerprints a deployment holds that it may NOT share.

    Useful to an operator: these are findings worth acting on in their own
    estate and worth nobody else's attention yet. Returned as fingerprints so
    the answer to "what are we sitting on" does not itself become a list of
    internal hostnames.
    """
    result = aggregate(observations, population=MIN_POPULATION)
    return tuple(digest for digest, _reason in result.withheld)
