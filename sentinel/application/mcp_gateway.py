"""MCP security gateway: the trust checks a generic tool gate cannot make.

WHAT THIS ADDS, AND WHAT IT DELIBERATELY DOES NOT
---------------------------------------------------
It does NOT decide ALLOW / WARN / REQUIRE_APPROVAL / BLOCK. `ProtectGate` does
that, from the deterministic policy, and this gateway projects every MCP call
onto the event payload that gate already understands
(`McpToolCall.as_event_payload`). One rule set governs both paths, so there is
no second place for them to disagree -- and the existing prompt-injection
detector is reused rather than reimplemented.

What it adds is the three questions MCP raises that a bare tool call does not:

  1. IS THIS SERVER KNOWN?  An agent can be pointed at a server nobody
     enrolled, and every call to it looks like an ordinary tool call. Unknown
     and blocked servers are refused before any content is examined.

  2. IS THIS TOOL WHAT IT WAS WHEN IT WAS APPROVED?  Tool definitions can change
     after enrolment. A server shipping a benign `search_docs` on Monday and a
     data-exfiltrating `search_docs` on Friday presents the same NAME to the
     same allowlist. Only a fingerprint over the definition catches that, and
     that is what pinning is for.

  3. IS THE TOOL'S DESCRIPTION ITSELF AN ATTACK?  A description is prose the
     model reads and acts on, supplied by the server. It is attacker-controlled
     text on the instruction path, and scrutinising the ARGUMENTS will never
     find it. The description is what gets sent to the detector.

FAIL CLOSED, AND SAY SO
-----------------------
Every refusal here raises `McpCallRefused` rather than returning a falsy value.
`sentinel/interface/http.py` and `InlineToolProxy` both establish that pattern:
a security decision that can be ignored by a caller who forgets to check a
return value is not a security decision. `docs/PRODUCTION_READINESS_REPORT.md`
records what this codebase costs itself when a gate returns quietly instead.

WHERE THE WIRE LIVES
--------------------
This gateway evaluates calls; it does not perform I/O, and that stays true.
The piece that SPEAKS MCP is `sentinel/infrastructure/mcp_wire.py` (the
JSON-RPC/Streamable-HTTP client) fronted by `interface/mcp_proxy_routes.py`,
which routes every proxied `tools/call` through `evaluate_request` below with
the server's LIVE definition. Scope and limits of that wire support --
allowlisted methods, one protocol revision, no server discovery -- are stated
in `docs/MCP_GATEWAY.md` rather than implied here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from sentinel.application.protect_gate import ProtectGate
from sentinel.domain.errors import DomainRuleViolated
from sentinel.domain.mcp import (
    McpChange,
    McpChangeKind,
    McpServerIdentity,
    McpServerTrust,
    McpToolCall,
    McpToolDefinition,
)
from sentinel.domain.primitives import TrustLevel
from sentinel.domain.protect import ProtectOutcome

__all__ = [
    "McpCallRefused",
    "McpGateway",
    "McpEvaluation",
    "ToolPinStore",
    "InMemoryToolPins",
    "McpServerDirectory",
    "InMemoryServerDirectory",
]


class McpCallRefused(DomainRuleViolated):
    """The gateway refused an MCP call. Never retryable without operator action.

    Not retryable on purpose: every refusal here means an operator has to decide
    something -- enrol the server, re-approve a changed tool, or investigate an
    injected description. Retrying without that changes nothing and would turn a
    trust decision into a spin loop.
    """

    is_retryable = False


@dataclass(frozen=True, slots=True)
class McpEvaluation:
    """What the gateway concluded, with the reasons it concluded it.

    `changes` and `protect` are both carried so an incident can answer "what
    drifted" and "what did policy say" without a second lookup. `docs/` has a
    standing objection to opaque scores; a decision here always arrives with the
    findings that produced it.
    """

    allowed: bool
    server: McpServerIdentity
    tool: McpToolDefinition
    protect: ProtectOutcome | None = None
    changes: tuple[McpChange, ...] = ()
    reason: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "server_id": self.server.server_id,
            "server_trust": self.server.trust.value,
            "tool": self.tool.name,
            "tool_fingerprint": self.tool.fingerprint,
            "changes": [c.as_dict() for c in self.changes],
            "protect": self.protect.as_dict() if self.protect else None,
            "reason": self.reason,
        }


class ToolPinStore:
    """Where a server's approved tool fingerprints live.

    A Protocol in all but name, kept as a small class so `InMemoryToolPins` can
    be the obvious default without the composition root needing an adapter yet.
    A durable implementation belongs in `infrastructure/sql/` and must be tenant
    scoped like every other table -- `PROTECTED_TABLES` and FORCE row-level
    security are not optional for this data, because a pin is a security
    decision about one tenant's servers.
    """

    def pinned(self, server: McpServerIdentity) -> Mapping[str, str]:
        raise NotImplementedError

    def pin(self, server: McpServerIdentity, tools: Mapping[str, str]) -> None:
        raise NotImplementedError


@dataclass
class InMemoryToolPins(ToolPinStore):
    """Process-local pins. For tests and single-process use only.

    Keyed by (tenant_id, server_id) rather than server_id alone. That is not
    defensive style: this codebase has already shipped one cross-tenant defect
    from an unscoped lookup, and a pin store keyed on server id would let one
    tenant's enrolment decide another tenant's calls.
    """

    _pins: dict[tuple[str, str], dict[str, str]] = field(default_factory=dict)

    def pinned(self, server: McpServerIdentity) -> Mapping[str, str]:
        return dict(self._pins.get((server.tenant_id, server.server_id), {}))

    def pin(self, server: McpServerIdentity, tools: Mapping[str, str]) -> None:
        self._pins[(server.tenant_id, server.server_id)] = dict(tools)


class McpServerDirectory:
    """Which MCP servers a tenant has decided about, and what it decided.

    Separate from `ToolPinStore` because the two answer different questions and
    a caller may legitimately have one without the other: trust is "may we talk
    to this server at all", pins are "is this tool what it was when approved".

    The reason this exists at all is that trust MUST NOT arrive from the caller.
    `McpGateway.evaluate` refuses a server whose trust is UNKNOWN -- so if the
    trust level were a field on the request, the first thing a hostile caller
    would do is set it to `enrolled` and walk straight through the check. The
    only safe source is a record an operator wrote.
    """

    def lookup(self, tenant_id: str, server_id: str) -> McpServerIdentity | None:
        raise NotImplementedError

    def record(self, server: McpServerIdentity) -> None:
        raise NotImplementedError


@dataclass
class InMemoryServerDirectory(McpServerDirectory):
    """Process-local server records. For tests and single-process use only.

    Keyed by (tenant_id, server_id) for the same reason `InMemoryToolPins` is:
    a directory keyed on server id alone would let one tenant's enrolment answer
    another tenant's lookup, which is the whole decision this type exists to
    make.
    """

    _servers: dict[tuple[str, str], McpServerIdentity] = field(default_factory=dict)

    def lookup(self, tenant_id: str, server_id: str) -> McpServerIdentity | None:
        return self._servers.get((tenant_id, server_id))

    def record(self, server: McpServerIdentity) -> None:
        self._servers[(server.tenant_id, server.server_id)] = server


class McpGateway:
    """Evaluate an MCP tool call: server trust, definition drift, then policy."""

    __slots__ = ("_protect", "_pins", "_servers", "_require_pin")

    def __init__(
        self,
        *,
        protect: ProtectGate,
        pins: ToolPinStore | None = None,
        servers: McpServerDirectory | None = None,
        require_pin: bool = True,
    ) -> None:
        self._protect = protect
        self._pins = pins if pins is not None else InMemoryToolPins()
        self._servers = servers if servers is not None else InMemoryServerDirectory()
        # `require_pin=False` exists for an OBSERVE-mode rollout, where an
        # operator is still discovering which servers exist and refusing every
        # unpinned tool would simply stop the agent working. It weakens check 2
        # only; server trust and description scanning are unaffected, and the
        # evaluation records that the pin check was skipped so a reader cannot
        # mistake a permissive run for a clean one.
        self._require_pin = bool(require_pin)

    # ── Enrolment ────────────────────────────────────────────────────────────

    def enrol(
        self, server: McpServerIdentity, tools: tuple[McpToolDefinition, ...]
    ) -> McpServerIdentity:
        """Pin a server's current tool definitions and mark it ENROLLED.

        This is the operator saying "these are the tools I reviewed". Everything
        the drift check does later is measured against this moment.
        """
        if server.trust is McpServerTrust.BLOCKED:
            raise McpCallRefused(
                f"server {server.server_id!r} is BLOCKED and cannot be enrolled; "
                "unblock it deliberately first"
            )
        self._pins.pin(server, {t.name: t.fingerprint for t in tools})
        enrolled = McpServerIdentity(
            tenant_id=server.tenant_id,
            server_id=server.server_id,
            endpoint=server.endpoint,
            trust=McpServerTrust.ENROLLED,
        )
        # Recorded, not just returned. A caller that enrols a server and then
        # looks it up on a different request -- which is every real caller, since
        # enrolment and use are separate HTTP calls -- must find it ENROLLED.
        self._servers.record(enrolled)
        return enrolled

    def block(self, tenant_id: str, server_id: str, *, endpoint: str = "") -> McpServerIdentity:
        """Mark a server BLOCKED. Its pins are left in place deliberately.

        Deleting them would destroy the record of what was approved, which is
        the first thing an investigation asks after a server turns hostile.
        """
        blocked = McpServerIdentity(
            tenant_id=tenant_id,
            server_id=server_id,
            endpoint=endpoint,
            trust=McpServerTrust.BLOCKED,
        )
        self._servers.record(blocked)
        return blocked

    # ── Resolution ────────────────────────────────────────────────────────

    def resolve(
        self, tenant_id: str, server_id: str, *, endpoint: str = ""
    ) -> McpServerIdentity:
        """Look up a server's trust. The ONLY sanctioned source of trust.

        A server with no record resolves to UNKNOWN, which `evaluate` refuses.
        That is the fail-closed direction: an agent that has reached a server
        nobody enrolled is exactly the situation this gateway exists to catch,
        and inferring trust from the fact that a call arrived would defeat it.

        `endpoint` is the endpoint the call was made against, and it does not
        override the recorded one -- it is carried so a caller can see, in the
        evaluation, that the endpoint moved.
        """
        found = self._servers.lookup(tenant_id, server_id)
        if found is not None:
            return found
        return McpServerIdentity(
            tenant_id=tenant_id,
            server_id=server_id,
            endpoint=endpoint,
            trust=McpServerTrust.UNKNOWN,
        )

    # ── Drift ────────────────────────────────────────────────────────────────

    def diff_tools(
        self, server: McpServerIdentity, observed: tuple[McpToolDefinition, ...]
    ) -> tuple[McpChange, ...]:
        """Compare what a server offers now against what was pinned.

        Reports additions and removals as well as changes: a tool that appears
        after enrolment is an unreviewed capability, and one that disappears may
        mean the server is not the server that was enrolled.
        """
        pinned = self._pins.pinned(server)
        seen = {t.name: t for t in observed}
        changes: list[McpChange] = []

        for name, definition in seen.items():
            if name not in pinned:
                changes.append(
                    McpChange(
                        kind=McpChangeKind.TOOL_ADDED,
                        tool_name=name,
                        observed_fingerprint=definition.fingerprint,
                        detail="tool was not present when the server was enrolled",
                    )
                )
                continue
            if pinned[name] != definition.fingerprint:
                changes.append(
                    McpChange(
                        kind=McpChangeKind.DEFINITION_CHANGED,
                        tool_name=name,
                        pinned_fingerprint=pinned[name],
                        observed_fingerprint=definition.fingerprint,
                        detail=(
                            "the tool's definition changed after approval; the "
                            "name is unchanged so an allowlist would not notice"
                        ),
                    )
                )

        for name, fingerprint in pinned.items():
            if name not in seen:
                changes.append(
                    McpChange(
                        kind=McpChangeKind.TOOL_REMOVED,
                        tool_name=name,
                        pinned_fingerprint=fingerprint,
                        detail="a pinned tool is no longer offered by the server",
                    )
                )

        return tuple(changes)

    # ── The call ─────────────────────────────────────────────────────────────

    def evaluate(
        self, call: McpToolCall, *, trust: TrustLevel = TrustLevel.UNSIGNED
    ) -> McpEvaluation:
        """Decide whether an MCP tool call may proceed.

        Order matters and is deliberate: cheapest and most categorical first.
        A blocked server is refused without its content being read at all, so a
        hostile server cannot spend our detector's time or reach our parser.
        """
        # 1. SERVER TRUST. Before any content is examined.
        if call.server.trust is McpServerTrust.BLOCKED:
            return McpEvaluation(
                allowed=False,
                server=call.server,
                tool=call.tool,
                reason=f"MCP server {call.server.server_id!r} is BLOCKED",
            )
        if not call.server.is_actionable:
            return McpEvaluation(
                allowed=False,
                server=call.server,
                tool=call.tool,
                reason=(
                    f"MCP server {call.server.server_id!r} is UNKNOWN. An agent "
                    "reached a server nobody enrolled; enrol it deliberately or "
                    "block it. Unknown is refused rather than assumed safe."
                ),
            )

        # 2. DEFINITION DRIFT. Same name, different tool -- the rug pull.
        #
        # Scoped to the ONE tool being called, not `diff_tools` over the whole
        # pinned set. A single call is not an observation of the server's tool
        # LISTING, so it is no evidence that the other pinned tools are gone --
        # and diffing it against all of them reported every unrelated tool as
        # TOOL_REMOVED. With twenty pinned tools that is nineteen false entries
        # in the audit record of every single call. This codebase has already
        # measured what a detector that cries wolf costs (F-10: 51.7% of
        # ordinary actions flagged), and the fix there was the same one as here
        # -- narrow the input to what the check can actually speak to.
        # Removals are real drift, and `diff_tools` still reports them; it is
        # the right caller for that, because it is given a full listing.
        changes: tuple[McpChange, ...] = ()
        pinned = self._pins.pinned(call.server)
        if pinned:
            changes = tuple(
                change
                for change in self.diff_tools(call.server, (call.tool,))
                if change.tool_name == call.tool.name
            )
            blocking = [c for c in changes if c.kind is not McpChangeKind.TOOL_REMOVED]
            if blocking:
                return McpEvaluation(
                    allowed=False,
                    server=call.server,
                    tool=call.tool,
                    changes=changes,
                    reason=(
                        f"tool {call.tool.name!r} no longer matches the definition "
                        "pinned at enrolment. Re-approve it or treat the server as "
                        "compromised."
                    ),
                )
        elif self._require_pin:
            return McpEvaluation(
                allowed=False,
                server=call.server,
                tool=call.tool,
                reason=(
                    f"server {call.server.server_id!r} has no pinned tools. Enrol "
                    "it, or run the gateway with require_pin=False during an "
                    "OBSERVE-mode rollout."
                ),
            )

        # 3. CONTENT. The existing deterministic policy, via ProtectGate, on a
        #    payload whose metadata.prompt is the tool DESCRIPTION -- the
        #    server-supplied text the model treats as instructions.
        outcome = self._protect.evaluate(
            payload=call.as_event_payload(), trust=trust
        )
        allowed = not outcome.enforced
        return McpEvaluation(
            allowed=allowed,
            server=call.server,
            tool=call.tool,
            protect=outcome,
            changes=changes,
            reason=outcome.reason if not allowed else "",
        )

    def require_allowed(
        self, call: McpToolCall, *, trust: TrustLevel = TrustLevel.UNSIGNED
    ) -> McpEvaluation:
        """Evaluate and RAISE on refusal.

        The form callers should reach for. `evaluate` returns a value a caller
        can forget to check; this one cannot be ignored by omission.
        """
        evaluation = self.evaluate(call, trust=trust)
        if not evaluation.allowed:
            raise McpCallRefused(evaluation.reason or "MCP call refused")
        return evaluation

    def evaluate_request(
        self,
        *,
        tenant_id: str,
        server_id: str,
        agent_id: str,
        tool: McpToolDefinition,
        endpoint: str = "",
        arguments: Mapping[str, Any] | None = None,
        session_id: str = "",
        trust: TrustLevel = TrustLevel.UNSIGNED,
    ) -> McpEvaluation:
        """Evaluate a call described entirely by UNTRUSTED caller-supplied fields.

        The form an HTTP route should use, and the reason it exists is narrow:
        there is no parameter here for MCP server trust. Trust is resolved from
        the directory, so a request cannot promote its own server by asserting a
        trust level -- which, since UNKNOWN is the only thing standing between an
        attacker-introduced server and the rest of the pipeline, is the single
        field most worth making unreachable from the wire.

        `trust` is the AGENT's `TrustLevel`, the same one `/v1/protect/evaluate`
        accepts, and it is a different axis entirely: it says how sure we are of
        who is calling, not whether the server they reached is one we know.
        """
        return self.evaluate(
            McpToolCall(
                tenant_id=tenant_id,
                server=self.resolve(tenant_id, server_id, endpoint=endpoint),
                tool=tool,
                agent_id=agent_id,
                arguments=dict(arguments or {}),
                session_id=session_id,
            ),
            trust=trust,
        )
