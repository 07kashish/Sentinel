"""Discovery that does not depend on an agent volunteering its existence.

THE GAP THIS CLOSES
-------------------
`SqlAgentInventory` classifies agents as MANAGED or UNMANAGED, and both come
from the same place: telemetry that arrived at `/v1/events`. An agent that never
calls Sentinel is not classified UNMANAGED, it is ABSENT -- and the agent an
attacker introduced yesterday is exactly the one that will not be sending
telemetry. So the inventory answered "which of the agents talking to us are
enrolled", while the question an operator asked was "what is running".

This module asks the infrastructure instead, using the credentials the Tier-1
adapters already hold. A pod running an agent framework appears whether or not
it has ever emitted an event.

WHAT IT WILL NOT CLAIM
----------------------
It sees exactly what the credential can list, in the namespaces and accounts it
was pointed at, and it recognises only the markers below. That is a real and
partial view, and `DiscoveryReport.scope` carries it in the result so a reader
cannot mistake "we found three" for "there are three". A discovery feature that
reports a count without its denominator is how "we have full coverage" gets
said out loud.

Specifically, it does NOT find: an agent on a laptop, an agent in a cloud
account nobody gave a credential for, a namespace the token cannot list, a
framework whose image and labels look like nothing on the marker list, or a
serverless function. Every report this module produces states that.

RECOGNITION IS BY DECLARED MARKER, NOT BY GUESSING
----------------------------------------------------
A workload is a candidate agent because it carries a label, an annotation or an
image name that says so. Heuristics over process names and open ports would
produce a longer list and a worse one -- an operator who has to dismiss forty
false candidates stops reading the list, and then the real one goes unnoticed
too. Precision over recall here is deliberate, and the recall cost is stated
rather than hidden.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence

from sentinel.domain.inventory import AgentClassification
from sentinel.infrastructure.outbound import (
    HardenedHttpClient,
    OutboundRefused,
    OutboundUnavailable,
)
from sentinel.infrastructure.platforms.aws import AwsCredentials, sign_request
from sentinel.infrastructure.platforms.kubernetes import KubernetesCredentials

__all__ = [
    "AGENT_MARKERS",
    "DiscoveredWorkload",
    "DiscoveryReport",
    "DiscoverySource",
    "discover_aws_principals",
    "discover_kubernetes_workloads",
    "reconcile",
]


class DiscoverySource(str, Enum):
    KUBERNETES = "kubernetes"
    AWS_IAM = "aws_iam"


#: Labels, annotations and image substrings that DECLARE a workload is an agent.
#:
#: Deliberately a short, explicit list. Every entry is something a team wrote on
#: purpose -- a label they set, an image they chose -- so a match is a statement
#: rather than an inference. Adding a heuristic here is cheap and the cost lands
#: on whoever reads the results.
#:
#: `MappingProxyType`, not a bare dict: this decides what gets reported as an
#: unmanaged agent, and `test_architecture_rules.py` rejects module-level
#: mutable state for exactly that reason.
AGENT_MARKERS: Mapping[str, tuple[str, ...]] = MappingProxyType({
    "labels": (
        "sentinel.io/agent",
        "app.kubernetes.io/component",
        "agent.ai/framework",
    ),
    "annotations": ("sentinel.io/agent-id",),
    "images": (
        "langchain",
        "langgraph",
        "crewai",
        "autogen",
        "llama-index",
        "openai-agents",
        "anthropic",
        "mcp-server",
    ),
})

#: Label VALUES that count as a component declaration. `app.kubernetes.io/
#: component` is a generic label -- most workloads carry it -- so matching on the
#: key alone would report the whole cluster.
_COMPONENT_VALUES = frozenset({"agent", "ai-agent", "llm-agent", "mcp-server"})

_RFC1123 = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


@dataclass(frozen=True, slots=True)
class DiscoveredWorkload:
    """One thing that is running and looks like an agent."""

    source: DiscoverySource
    #: The identifier this workload would use if it ever emitted telemetry, so a
    #: discovered workload and an enrolled agent can be compared at all. Taken
    #: from an explicit annotation where present, and from the workload name
    #: otherwise -- and `identity_is_declared` says which, because a name-based
    #: match is a guess and a reader should know when they are reading one.
    agent_id: str
    name: str
    location: str
    identity_is_declared: bool = False
    image: str = ""
    markers: tuple[str, ...] = ()
    #: What the workload can reach, as far as this credential can tell. Empty is
    #: "not determined", never "nothing".
    principals: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source.value,
            "agent_id": self.agent_id,
            "name": self.name,
            "location": self.location,
            "identity_is_declared": self.identity_is_declared,
            "image": self.image,
            "markers": list(self.markers),
            "principals": list(self.principals),
        }


@dataclass(frozen=True, slots=True)
class DiscoveryReport:
    """What was found, AND what was looked at. The second is not optional.

    A count without its denominator is how "we have full coverage" gets said out
    loud. `scope` says which namespaces or accounts were listed, `unreachable`
    says which could not be, and `limits` states the recall cost of matching on
    declared markers.
    """

    workloads: tuple[DiscoveredWorkload, ...]
    scope: tuple[str, ...]
    unreachable: tuple[tuple[str, str], ...] = ()
    examined: int = 0

    #: Restated in every report rather than left to the documentation, because a
    #: report is what gets pasted into a review and a document is not.
    limits: str = field(
        default=(
            "Sees only what this credential can list, in the scope named above, "
            "and recognises only workloads carrying a declared agent marker. "
            "Absence from this list is NOT evidence that nothing is running: an "
            "agent on a laptop, in an account with no credential here, in a "
            "namespace this token cannot read, or built on a framework not on "
            "the marker list will not appear."
        ),
        compare=False,
    )

    def as_dict(self) -> dict[str, Any]:
        return {
            "workloads": [w.as_dict() for w in self.workloads],
            "scope": list(self.scope),
            "unreachable": [{"target": t, "reason": r} for t, r in self.unreachable],
            "examined": self.examined,
            "found": len(self.workloads),
            "limits": self.limits,
        }


def _markers_for(
    labels: Mapping[str, Any], annotations: Mapping[str, Any], image: str
) -> tuple[str, ...]:
    """Why this workload was treated as an agent. Empty means it was not."""
    found: list[str] = []
    for key in AGENT_MARKERS["labels"]:
        value = labels.get(key)
        if value is None:
            continue
        if key == "app.kubernetes.io/component":
            # The generic one. Matching the KEY alone would report every
            # workload in the cluster that follows the recommended labels.
            if str(value).lower() in _COMPONENT_VALUES:
                found.append(f"label:{key}={value}")
        else:
            found.append(f"label:{key}")
    for key in AGENT_MARKERS["annotations"]:
        if key in annotations:
            found.append(f"annotation:{key}")
    lowered = image.lower()
    for fragment in AGENT_MARKERS["images"]:
        if fragment in lowered:
            found.append(f"image:{fragment}")
    return tuple(found)


def discover_kubernetes_workloads(
    *,
    client: HardenedHttpClient,
    credentials: KubernetesCredentials,
    namespaces: Sequence[str],
) -> DiscoveryReport:
    """List pods in the given namespaces and report the ones declaring an agent.

    Namespaces are REQUIRED rather than discovered. Listing every namespace needs
    a cluster-wide read this deployment may not have been granted, and silently
    falling back to `default` would produce a confident report about one
    namespace out of forty.
    """
    server = str(credentials.api_server).rstrip("/")
    headers = {
        "authorization": f"Bearer {credentials.token}",
        "accept": "application/json",
    }

    workloads: list[DiscoveredWorkload] = []
    unreachable: list[tuple[str, str]] = []
    scope: list[str] = []
    examined = 0

    for namespace in namespaces:
        name = str(namespace).strip()
        if not _RFC1123.fullmatch(name):
            unreachable.append((name, "not a valid RFC 1123 namespace name"))
            continue
        scope.append(name)
        try:
            response = client.request(
                method="GET",
                url=f"{server}/api/v1/namespaces/{name}/pods",
                headers=headers,
                body=None,
                idempotent=True,
            )
        except (OutboundRefused, OutboundUnavailable) as exc:
            # Recorded, never swallowed. A namespace that could not be listed is
            # a hole in the report, and a report that hides its holes is worse
            # than one that admits them.
            unreachable.append((name, f"{type(exc).__name__}: {exc}"))
            continue
        if response.status != 200:
            unreachable.append((name, f"HTTP {response.status}"))
            continue

        try:
            body = response.json()
        except OutboundRefused as exc:
            unreachable.append((name, f"unparseable response: {exc}"))
            continue

        for item in body.get("items", []) if isinstance(body, Mapping) else []:
            examined += 1
            metadata = item.get("metadata") or {}
            spec = item.get("spec") or {}
            containers = spec.get("containers") or []
            image = str((containers[0] or {}).get("image", "")) if containers else ""
            labels = metadata.get("labels") or {}
            annotations = metadata.get("annotations") or {}

            markers = _markers_for(labels, annotations, image)
            if not markers:
                continue

            declared = str(annotations.get("sentinel.io/agent-id", "")).strip()
            workloads.append(
                DiscoveredWorkload(
                    source=DiscoverySource.KUBERNETES,
                    agent_id=declared or str(metadata.get("name", "")),
                    name=str(metadata.get("name", "")),
                    location=f"{name}/{metadata.get('name', '')}",
                    identity_is_declared=bool(declared),
                    image=image,
                    markers=markers,
                    principals=(
                        (str(spec.get("serviceAccountName")),)
                        if spec.get("serviceAccountName")
                        else ()
                    ),
                )
            )

    return DiscoveryReport(
        workloads=tuple(workloads),
        scope=tuple(scope),
        unreachable=tuple(unreachable),
        examined=examined,
    )


def discover_aws_principals(
    *,
    client: HardenedHttpClient,
    credentials: AwsCredentials,
    clock: Any = None,
    path_prefix: str = "/",
) -> DiscoveryReport:
    """List IAM users whose path or name declares them an agent identity.

    IAM does not know what an agent is, so this reports PRINCIPALS rather than
    agents: the credentials an agent would act as. Matching is on the IAM path
    prefix, which is the mechanism AWS provides for exactly this kind of
    grouping and which somebody had to set deliberately.

    Only one page is fetched. A truncated listing is reported in `unreachable`
    rather than paged through silently -- a partial list presented as complete is
    the failure this module's whole design is arranged against.
    """
    import datetime as _dt

    now = (
        clock() if clock is not None else _dt.datetime.now(_dt.timezone.utc)
    )
    payload = urllib.parse.urlencode(
        {
            "Action": "ListUsers",
            "Version": "2010-05-08",
            "PathPrefix": path_prefix,
            "MaxItems": "100",
        }
    ).encode("utf-8")

    headers = sign_request(
        credentials=credentials,
        service="iam",
        host="iam.amazonaws.com",
        amz_target="",
        payload=payload,
        now=now,
    )
    headers["accept"] = "application/json"

    try:
        response = client.request(
            method="POST",
            url="https://iam.amazonaws.com/",
            headers=headers,
            body=payload,
            idempotent=True,
        )
    except (OutboundRefused, OutboundUnavailable) as exc:
        return DiscoveryReport(
            workloads=(),
            scope=(f"iam:{path_prefix}",),
            unreachable=((f"iam:{path_prefix}", f"{type(exc).__name__}: {exc}"),),
        )

    if response.status != 200:
        return DiscoveryReport(
            workloads=(),
            scope=(f"iam:{path_prefix}",),
            unreachable=((f"iam:{path_prefix}", f"HTTP {response.status}"),),
        )

    body = response.body.decode("utf-8", errors="replace")
    # IAM's query protocol answers XML unless asked otherwise, and this module
    # will not add an XML parser to read one field. The user names are extracted
    # with an anchored pattern over a response from a host whose certificate was
    # verified -- and if the shape ever changes, the result is an EMPTY list
    # with the reason recorded, not a wrong one.
    names = re.findall(r"<UserName>([\w+=,.@-]{1,64})</UserName>", body)
    truncated = "<IsTruncated>true</IsTruncated>" in body

    unreachable: list[tuple[str, str]] = []
    if truncated:
        unreachable.append(
            (
                f"iam:{path_prefix}",
                "the listing was truncated; this report covers the first page "
                "only and is not the complete set of principals",
            )
        )
    if not names and "<ListUsersResult" not in body:
        unreachable.append(
            (f"iam:{path_prefix}", "response was not a recognised ListUsers result")
        )

    return DiscoveryReport(
        workloads=tuple(
            DiscoveredWorkload(
                source=DiscoverySource.AWS_IAM,
                agent_id=name,
                name=name,
                location=f"iam:user{path_prefix}{name}",
                identity_is_declared=path_prefix != "/",
                markers=(f"iam_path:{path_prefix}",),
            )
            for name in names
        ),
        scope=(f"iam:{path_prefix}",),
        unreachable=tuple(unreachable),
        examined=len(names),
    )


def reconcile(
    report: DiscoveryReport,
    *,
    enrolled: Iterable[str],
    revoked: Iterable[str] = (),
) -> dict[str, AgentClassification]:
    """Classify each discovered workload against what Sentinel knows.

    Reuses `AgentClassification` rather than inventing a parallel vocabulary:
    two enums for one concept is two enums that drift, and an operator reading
    "unmanaged" in one screen and something else in another has to learn which
    is which.

    REVOKED_BUT_ACTIVE is the finding that justifies this module. An agent whose
    enrolment was withdrawn and whose pod is still running is invisible to
    telemetry-based inventory -- it stopped reporting, so it stopped appearing --
    and it is the single most interesting thing infrastructure discovery can
    say.
    """
    enrolled_set = {str(a).strip() for a in enrolled if str(a).strip()}
    revoked_set = {str(a).strip() for a in revoked if str(a).strip()}

    classified: dict[str, AgentClassification] = {}
    for workload in report.workloads:
        agent_id = workload.agent_id
        if agent_id in revoked_set:
            classified[agent_id] = AgentClassification.REVOKED_BUT_ACTIVE
        elif agent_id in enrolled_set:
            classified[agent_id] = AgentClassification.MANAGED
        else:
            classified[agent_id] = AgentClassification.UNMANAGED
    return classified
