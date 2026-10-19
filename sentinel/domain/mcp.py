"""Model Context Protocol types, and the trust questions MCP raises.

WHY MCP NEEDS ITS OWN DOMAIN TYPES
------------------------------------
Sentinel already evaluates tool calls: `ProtectGate` decides ALLOW / WARN /
REQUIRE_APPROVAL / BLOCK from an event payload, and `InlineToolProxy` refuses to
run any side effect the gate has not cleared. That machinery is sound and this
module does not duplicate it.

What it cannot see is everything MCP puts *around* the call. Treating an MCP
interaction as generic HTTP loses exactly the parts an attacker uses:

  * A tool's DESCRIPTION is instructions the model reads. A description is an
    injection vector that arrives from the server, not from the user, and no
    amount of scrutiny applied to the ARGUMENTS will find it.
  * Tool definitions can change after enrolment. A server that ships a benign
    `search_docs` on Monday and a data-exfiltrating `search_docs` on Friday
    presents the same NAME to the same allowlist. Only a fingerprint over the
    definition catches that.
  * Servers appear. An agent can be pointed at a server nobody enrolled, and
    every call to it looks like an ordinary tool call.

So this module models the three things MCP has that a bare tool call does not:
the SERVER as an identity, the TOOL DEFINITION as a fingerprintable artifact,
and the CALL as something that happened against a specific pinned definition.

WHAT IS DELIBERATELY NOT HERE
------------------------------
No transport, no JSON-RPC, no HTTP, no persistence, no detection policy. This is
`sentinel/domain/` -- it imports nothing but the standard library and other
domain modules, exactly like `domain/protect.py` beside it. The gateway that
uses these types lives in `sentinel/application/mcp_gateway.py`, and the code
that speaks the wire protocol belongs in `infrastructure/` when it is written.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

__all__ = [
    "DestinationClass",
    "McpServerIdentity",
    "McpServerTrust",
    "McpToolDefinition",
    "McpToolCall",
    "McpChange",
    "McpChangeKind",
    "classify_destination",
    "fingerprint_definition",
]


class McpServerTrust(str, Enum):
    """How much of what a server says is taken at face value.

    Ordered by how much an operator has committed to. `UNKNOWN` is the default
    for a reason: a server nobody enrolled must not become trusted by the fact
    that an agent happened to call it.
    """

    #: Never seen before, or seen and not yet decided about. Fail closed.
    UNKNOWN = "unknown"
    #: Seen and recorded, but not approved. Calls are evaluated, not assumed.
    OBSERVED = "observed"
    #: An operator enrolled it, and its tool definitions are pinned.
    ENROLLED = "enrolled"
    #: Explicitly distrusted. Calls are refused regardless of content.
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class McpServerIdentity:
    """Which MCP server this is, independent of what it currently claims.

    `server_id` is the operator's stable handle. `endpoint` is where it was
    reached. They are separate because an endpoint can move (a rehosted server
    is still the same server) and because an endpoint can be REUSED by something
    else entirely -- which is a change worth noticing rather than papering over.
    """

    tenant_id: str
    server_id: str
    endpoint: str = ""
    trust: McpServerTrust = McpServerTrust.UNKNOWN

    def __post_init__(self) -> None:
        if not self.tenant_id.strip():
            raise ValueError("MCP server identity requires a tenant")
        if not self.server_id.strip():
            raise ValueError("MCP server identity requires a server_id")

    @property
    def is_actionable(self) -> bool:
        """Whether a call to this server may be considered at all.

        BLOCKED and UNKNOWN both return False. That is the fail-closed posture
        the rest of this codebase uses: an unrecognised server is refused rather
        than given the benefit of the doubt, because "we have never seen this
        server" is precisely the state an attacker-introduced server is in.
        """
        return self.trust in {McpServerTrust.OBSERVED, McpServerTrust.ENROLLED}


@dataclass(frozen=True, slots=True)
class McpToolDefinition:
    """What a server says a tool IS -- name, description and input schema.

    All three matter, and the description matters most. It is prose the model
    reads and acts on, supplied by the server, so it is attacker-controlled text
    on the instruction path. `sentinel/infrastructure/soft_detection.py` already
    knows how to judge such text; this type exists so it can be pointed at it.
    """

    name: str
    description: str = ""
    input_schema: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("an MCP tool definition requires a name")

    @property
    def fingerprint(self) -> str:
        """A stable hash over everything that changes the tool's MEANING.

        Name, description and schema together -- because a rug pull can alter
        any one of them while leaving the others intact, and each is enough to
        change what the agent will do.
        """
        return fingerprint_definition(self)

    @property
    def description_sha256(self) -> str:
        """Hash of the description ALONE, for provenance records.

        The combined fingerprint says "something changed"; this says whether
        the something was the instruction text the model reads. An investigator
        looking at a definition change asks that question first, because a
        description change is the injection vector and a schema change is
        usually a version bump.
        """
        return hashlib.sha256(self.description.encode("utf-8")).hexdigest()

    @property
    def schema_sha256(self) -> str:
        """Hash of the input schema alone, canonicalised like the fingerprint."""
        canonical = json.dumps(
            dict(self.input_schema), sort_keys=True, separators=(",", ":"), default=str
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def fingerprint_definition(definition: McpToolDefinition) -> str:
    """SHA-256 over the canonical form of a tool definition.

    `sort_keys=True` so a server reordering its schema keys does not read as a
    change -- a fingerprint that alarms on formatting is a fingerprint people
    learn to ignore, which is the alert-fatigue failure this codebase already
    documents for the detector's false positives.
    """
    canonical = json.dumps(
        {
            "name": definition.name,
            "description": definition.description,
            "input_schema": definition.input_schema,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class McpChangeKind(str, Enum):
    """What kind of drift was observed between a pinned tool and a live one."""

    #: A tool that was not in the pinned set. New capability, unreviewed.
    TOOL_ADDED = "tool_added"
    #: A pinned tool the server no longer offers.
    TOOL_REMOVED = "tool_removed"
    #: Same name, different definition. THE RUG PULL.
    DEFINITION_CHANGED = "definition_changed"
    #: The description alone changed -- the instruction text the model reads.
    DESCRIPTION_CHANGED = "description_changed"
    #: The input schema alone changed: new or widened parameters.
    SCHEMA_CHANGED = "schema_changed"


@dataclass(frozen=True, slots=True)
class McpChange:
    """One observed difference between the pinned definition and the live one."""

    kind: McpChangeKind
    tool_name: str
    pinned_fingerprint: str = ""
    observed_fingerprint: str = ""
    detail: str = ""

    def as_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind.value,
            "tool": self.tool_name,
            "pinned_fingerprint": self.pinned_fingerprint,
            "observed_fingerprint": self.observed_fingerprint,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class McpToolCall:
    """An agent invoking a tool on a server, with the definition in force.

    `definition` is carried alongside the call rather than looked up later,
    because the question "what did the tool claim to be AT THE MOMENT IT WAS
    CALLED" is the one an investigation needs, and a later lookup answers a
    different question.
    """

    tenant_id: str
    server: McpServerIdentity
    tool: McpToolDefinition
    agent_id: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    session_id: str = ""

    def __post_init__(self) -> None:
        if not self.agent_id.strip():
            raise ValueError("an MCP tool call requires an agent_id")
        if self.tenant_id != self.server.tenant_id:
            raise ValueError(
                f"tenant mismatch: call is for {self.tenant_id!r} but the server "
                f"identity belongs to {self.server.tenant_id!r}. A call must not "
                "cross a tenant boundary through its server reference."
            )

    def as_event_payload(self) -> dict[str, Any]:
        """Render as the event shape `ProtectGate` already understands.

        This is the whole integration. Rather than build a second decision
        engine for MCP, an MCP call is projected onto the payload the existing
        deterministic policy evaluates, so one set of rules governs both and
        there is no second place for them to disagree.

        `metadata.prompt` carries the tool DESCRIPTION deliberately: that is the
        server-supplied text the model treats as instructions, and it is the
        field the prompt-injection detector reads.
        """
        return {
            "eventType": "tool_call",
            "action": self.tool.name,
            "resource": self.server.endpoint or self.server.server_id,
            "agentId": self.agent_id,
            "metadata": {
                "prompt": self.tool.description,
                "mcp_server_id": self.server.server_id,
                "mcp_server_trust": self.server.trust.value,
                "mcp_tool_fingerprint": self.tool.fingerprint,
                "arguments": dict(self.arguments),
            },
        }


class DestinationClass(str, Enum):
    """Where an egress destination sits, in the vocabulary policy speaks.

    This is the EXPLAINABLE label carried in evidence and audit records, not
    the enforcement itself: enforcement is the enrolment check (only enrolled
    servers are dialled at all) plus the outbound client's post-resolution
    address validation. The label exists so an incident answers "where was the
    data headed" in one word an analyst can filter on.
    """

    #: Private, loopback or link-local address space, by IP literal.
    INTERNAL = "internal"
    #: The host appears on the deployment's explicit egress allowlist.
    ALLOWLISTED = "allowlisted"
    #: Public internet, reached only because an operator enrolled it.
    EXTERNAL = "external"
    #: The endpoint could not be parsed. Never dialled; recorded as itself.
    INVALID = "invalid"


def classify_destination(
    endpoint: str, *, allowed_hosts: frozenset[str] | None = None
) -> DestinationClass:
    """Classify an endpoint WITHOUT resolving it. Pure, and honest about it.

    A hostname is judged by its literal form and the allowlist only: this is
    `sentinel/domain/`, so there is no DNS here, and pretending to know that
    `internal.corp.example` is internal without resolving it would be a
    classification an attacker chooses with a hostname. The resolution-aware
    judgement -- the one that actually refuses private addresses -- lives in
    `sentinel/infrastructure/outbound.py` at connection time. `localhost` is
    the one name classified INTERNAL without resolution, because its meaning
    is fixed by standard rather than by a resolver's answer.
    """
    import ipaddress
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(endpoint)
        host = parts.hostname or ""
    except ValueError:
        return DestinationClass.INVALID
    if not host:
        return DestinationClass.INVALID
    if host == "localhost":
        return DestinationClass.INTERNAL
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        return DestinationClass.INTERNAL
    if allowed_hosts and host in allowed_hosts:
        return DestinationClass.ALLOWLISTED
    return DestinationClass.EXTERNAL
