"""HTTP request/response models and principal type for the ASGI edge."""

from __future__ import annotations

from types import MappingProxyType
from typing import Any, Literal, Mapping

from pydantic import BaseModel, Field, field_validator, model_validator

from sentinel.domain.authorization import Capability
from sentinel.domain.bounded import BoundsExceeded, StructureBounds, check_bounds
from sentinel.domain.primitives import TenantId, TrustLevel

__all__ = [
    "ApprovalDecision",
    "EventPayload",
    "Principal",
    "McpCallPayload",
    "ProtectPayload",
    "SECURITY_HEADERS",
    "TRUST_LEVEL_REFUSAL",
    "UNKNOWN_TENANT",
    "refuse_trust_level",
]

UNKNOWN_TENANT = "unauthenticated:none"

_METADATA_BOUNDS = StructureBounds()

#: Why a request carrying `trustLevel` is refused, verbatim, so a caller with
#: an old SDK reads the reason rather than a bare 422.
#:
#: The field let a caller ASSERT its own trust. Proven against the running
#: app: an API-key caller posting `trustLevel: "verified"` against
#: `/home/user/.aws/credentials` produced a severity above the unsigned cap,
#: because the cap keys on trust and trust was whatever the body said. Trust
#: is now derived from the credential that authenticated the request and from
#: nothing else.
TRUST_LEVEL_REFUSAL = (
    "trustLevel is no longer accepted. Trust is derived from the credential: "
    "an API key is 'unsigned', a verified OIDC identity is 'verified', and a "
    "signed event is verified by its signature. A caller cannot assert its "
    "own trust, because the severity cap keys on it."
)


def refuse_trust_level(data: Any) -> Any:
    """`model_validator(mode="before")` body: refuse a caller-asserted trust."""
    if isinstance(data, Mapping) and "trustLevel" in data:
        raise ValueError(TRUST_LEVEL_REFUSAL)
    return data


class Principal:
    """An authenticated caller. Constructed per request, never cached.

    `trust` is DERIVED from how the caller authenticated and is the only trust
    a route may use. An API key proves possession of a shared secret and
    nothing about the agent it speaks for, so it is `unsigned`; a verified
    OIDC identity is `verified`. It is a keyword with a default so existing
    construction sites keep working, and the default is the least trusted
    tier for the obvious reason.
    """

    __slots__ = ("tenant", "role", "key_hash", "capabilities", "trust", "agent_id", "workload")

    def __init__(
        self,
        *,
        tenant: TenantId,
        role: str,
        key_hash: str,
        capabilities: frozenset[Capability],
        trust: TrustLevel = TrustLevel.UNSIGNED,
        agent_id: str = "",
        workload: str = "",
    ) -> None:
        self.tenant = tenant
        self.role = role
        self.key_hash = key_hash
        self.capabilities = capabilities
        self.trust = trust
        #: Set only for a token an agent identity provider issued. When set, the
        #: credential IS this agent, and routes refuse a body naming another.
        self.agent_id = agent_id
        #: The attested workload (pod or SPIFFE ID) behind an agent token, when
        #: the issuer is a workload identity kind. Empty otherwise.
        self.workload = workload

    def can(self, required: Capability) -> bool:
        return required in self.capabilities


class EventPayload(BaseModel):
    """The one ingest shape. Note what is absent: `severity`."""

    agentId: str = Field(min_length=1, max_length=128)
    eventType: str = Field(default="tool_call", max_length=64)
    action: str = Field(default="", max_length=8192)
    resource: str = Field(default="", max_length=2048)
    #: Where data went. DOCUMENTED SINCE THE FIRST PILOT AND SILENTLY DROPPED:
    #: `docs/history/PILOT_README.md` shows `destination` in both its PowerShell and curl
    #: examples, and this model did not declare it -- so pydantic discarded it
    #: before anything could read it. Every pilot that followed the instructions
    #: was sending a field that went nowhere.
    #:
    #: It matters more than its size suggests: `destination` is the edge that
    #: answers "can this agent send data OUT", which is the question the attack
    #: surface graph exists for. Everything else records what was touched; this
    #: records where it went.
    destination: str | None = Field(default=None, max_length=2048)
    #: WHAT MAKES A CAUSAL CHAIN POSSIBLE, and dropped until now for the same
    #: reason `destination` was: not declared, so pydantic discarded it.
    #: `docs/history/PILOT_README.md` shows `eventId` in both its PowerShell and curl
    #: examples, so pilots have been sending an identifier that went nowhere.
    #:
    #: Without these three there is no execution graph to build. An event with
    #: no identity cannot be referred to, a stream with no session cannot be
    #: partitioned into stories, and a step with no parent cannot say what
    #: caused it -- which is precisely the "understand this as ONE security
    #: story" the graph exists to provide.
    #:
    #: All three are SELF-REPORTED and used only for correlation, never for
    #: trust. An agent that forges a parent id draws a wrong arrow in its own
    #: story; it does not gain any permission by doing so.
    eventId: str = Field(default="", max_length=128)
    sessionId: str = Field(default="", max_length=128)
    parentEventId: str = Field(default="", max_length=128)
    timestamp: str | None = None
    metadata: Mapping[str, Any] = Field(default_factory=dict)
    signature: str | None = Field(default=None, max_length=256)
    riskAssertion: str | None = Field(default=None, max_length=32)

    @field_validator("metadata")
    @classmethod
    def _bound_metadata(cls, value: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            check_bounds(value, _METADATA_BOUNDS, field="metadata")
        except BoundsExceeded as exc:
            raise ValueError(str(exc)) from exc
        return value


class ApprovalDecision(BaseModel):
    #: `Literal`, not `Field(pattern="^(approve|reject)$")`.
    #:
    #: The pattern and the Literal accept exactly the same two strings, so this
    #: is not a behaviour change -- it is a change to what the OpenAPI schema
    #: SAYS. A pattern describes an infinite string space with a filter; a
    #: Literal renders as `enum: [approve, reject]`, which is what this field
    #: actually is.
    #:
    #: It matters because the schema is not only documentation here: CI fuzzes
    #: the API from it. Generating random strings and discarding all but two
    #: exact matches meant almost every example was filtered out, and
    #: schemathesis failed the run with "Too many generated examples are
    #: filtered out for this operation" -- so the approvals endpoint, which
    #: authorises remediation, was the one operation the fuzzer could not
    #: meaningfully reach.
    #:
    #: An enum also gives API consumers the two valid values in generated
    #: clients rather than a regex to reverse-engineer.
    decision: Literal["approve", "reject"]
    reason: str = Field(default="", max_length=2048)


class ProtectPayload(BaseModel):
    """A proposed action. NOTE WHAT IS ABSENT: `trustLevel`.

    `tool`, `arguments` and `mcpServer` are what an authorization is issued
    against. A payload without a tool is still evaluated -- it is a question
    about an action -- but nothing can be bound to it, so no authorization is
    issued and the response says so.
    """

    agentId: str = Field(min_length=1, max_length=128)
    eventType: str = Field(default="tool_call", max_length=64)
    action: str = Field(default="", max_length=8192)
    resource: str = Field(default="", max_length=2048)
    #: Where an outbound call is going. The ingest event carries this field and
    #: the sequence detector reads it; the protect payload silently DROPPED it
    #: (pydantic ignores unknown fields), so a caller asking "may I POST to
    #: attacker.example" with the destination here rather than inside
    #: `arguments.url` was answered `allow` by a gate that never saw the host.
    destination: str = Field(default="", max_length=2048)
    tool: str = Field(default="", max_length=128)
    arguments: Mapping[str, Any] = Field(default_factory=dict)
    mcpServer: str = Field(default="", max_length=128)
    metadata: Mapping[str, Any] = Field(default_factory=dict)
    signature: str | None = Field(default=None, max_length=256)

    @model_validator(mode="before")
    @classmethod
    def _no_asserted_trust(cls, data: Any) -> Any:
        return refuse_trust_level(data)

    @field_validator("metadata", "arguments")
    @classmethod
    def _bound_metadata(cls, value: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            check_bounds(value, _METADATA_BOUNDS, field="metadata")
        except BoundsExceeded as exc:
            raise ValueError(str(exc)) from exc
        return value


class McpCallPayload(BaseModel):
    """A proposed MCP tool call, described entirely by an untrusted caller.

    NOTE WHAT IS ABSENT: there is no field for the MCP server's trust level, and
    that is the security decision this model makes. The gateway refuses a server
    whose trust is UNKNOWN, so a `trust` field here would let a caller mark its
    own server `enrolled` and step over the only check standing between an
    attacker-introduced server and the rest of the pipeline. Trust is read from
    the enrolment record, which is written by an operator through the CLI.

    The calling AGENT's trust is not accepted either. It is derived from the
    credential that authenticated the request, exactly as on `ProtectPayload`,
    and a request still carrying `trustLevel` is refused with the reason.

    `description` is bounded rather than unbounded because it is attacker-supplied
    text that reaches the detector. `action` on `ProtectPayload` is capped at 8192
    for the same reason and this matches it.
    """

    serverId: str = Field(min_length=1, max_length=128)
    agentId: str = Field(min_length=1, max_length=128)
    toolName: str = Field(min_length=1, max_length=256)
    description: str = Field(default="", max_length=8192)
    endpoint: str = Field(default="", max_length=2048)
    inputSchema: Mapping[str, Any] = Field(default_factory=dict)
    arguments: Mapping[str, Any] = Field(default_factory=dict)
    sessionId: str = Field(default="", max_length=128)

    @model_validator(mode="before")
    @classmethod
    def _no_asserted_trust(cls, data: Any) -> Any:
        return refuse_trust_level(data)

    @field_validator("inputSchema", "arguments")
    @classmethod
    def _bound_structures(cls, value: Mapping[str, Any]) -> Mapping[str, Any]:
        """Same depth/breadth bounds as `metadata`.

        A tool's input schema is server-supplied and nested by nature, so it is
        the most plausible place in this payload for a parser-exhaustion attempt.
        """
        try:
            check_bounds(value, _METADATA_BOUNDS, field="inputSchema")
        except BoundsExceeded as exc:
            raise ValueError(str(exc)) from exc
        return value


SECURITY_HEADERS: Mapping[str, str] = MappingProxyType({
    "Content-Security-Policy": (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; "
        "form-action 'none'; require-trusted-types-for 'script'; trusted-types 'none'"
    ),
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": (
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
        "magnetometer=(), microphone=(), payment=(), usb=()"
    ),
    "Cache-Control": "no-store, no-transform",
    "Pragma": "no-cache",
})


class ContainmentRequest(BaseModel):
    """An operator activating the granular kill switch (section 35)."""

    #: `Literal`, not a free string or a pattern -- the same reasoning as
    #: `ApprovalDecision.decision` above. It renders as an enum in the schema,
    #: which is what CI's fuzzer needs to generate valid examples instead of
    #: filtering almost all of them out.
    scope: Literal[
        "agent",
        "agent_group",
        "tool",
        "mcp_server",
        "credential",
        "high_risk_agents",
    ]
    #: What to block. Empty exactly when scope is `high_risk_agents`; the domain
    #: refuses the mismatch either way, and refuses a selector on that scope
    #: because it would read as narrowing something that is not narrowed.
    selector: str = Field(default="", max_length=256)
    reason: str = Field(default="", max_length=1024)
    #: ISO-8601. Empty means indefinite -- allowed, but a choice made here rather
    #: than the only available shape. A 3am pause nobody lifts otherwise becomes
    #: a silent permanent state.
    expiresAt: str = Field(default="", max_length=64)
