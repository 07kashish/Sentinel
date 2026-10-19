"""Containment Sentinel performs on its OWN state, with no integration at all.

WHY THESE ARE THE MOST IMPORTANT INTEGRATIONS IN THE PRODUCT
--------------------------------------------------------------
Eleven of the actions in `REMEDIATION_ACTIONS` declare `provider="sentinel"`.
Every one of them is a change to a table this process already owns -- revoke an
enrolled address, drop a tool grant, mark an MCP server blocked -- and until now
every one of them required an operator to stand up an HTTP webhook that called
back into Sentinel to do what Sentinel could have done directly.

Almost nobody did. So `NullRemediationExecutor` was the executor most
deployments got, `supports()` returned False for everything, and
`decide_response`'s CRITICAL path -- deterministic emergency containment --
terminated in `unsupported_action`. The product could propose consequences it
could not act on.

These integrations remove the requirement. A deployment with a database and no
integrations whatsoever can now disable an agent, revoke its credential, drop
its tool access and block an MCP server.

THE TENANT IS NOT OPTIONAL HERE, AND THAT IS WHY THE PROTOCOL GREW
--------------------------------------------------------------------
Every table these touch is tenant-scoped. `RemediationIntegration.execute` had
no tenant parameter, because a webhook does not need one -- the endpoint an
operator configured already belongs to one estate. An integration writing to
Sentinel's own store cannot work without it, and one that GUESSED would be a
cross-tenant write dressed as a containment.

So `execute` here declares `tenant`, `GuardedRemediationExecutor` inspects the
signature and passes it only to integrations that ask, and an empty tenant is
refused rather than defaulted. `docs/RESPONSE_AND_CONTAINMENT.md` records the
shape.

WHAT IS ABSENT, AND WHY
-----------------------
`rotate_token`, `pause_workflow` and `block_external_domain` are NOT here.
Sentinel does not issue the tokens, does not own the workflows, and has no
inline network position from which to drop traffic to a domain -- so an
integration for any of them would report success for something that did not
happen, which is the one failure the whole remediation catalogue is arranged
against. They stay webhook-only, and a deployment without that webhook gets
`unsupported_action`, which is true.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from sentinel.domain.errors import DomainRuleViolated
from sentinel.domain.mcp import McpServerIdentity, McpServerTrust
from sentinel.domain.primitives import Address, IdempotencyKey, InvalidValue, TenantId

__all__ = [
    "NATIVE_SENTINEL_ACTIONS",
    "AgentEnrolmentContainment",
    "McpServerContainment",
    "ToolGrantContainment",
    "build_sentinel_integrations",
]

#: The `provider="sentinel"` actions this module can actually perform. Anything
#: not here stays webhook-only, and a deployment without that webhook is told
#: `unsupported_action` -- which is the truth.
NATIVE_SENTINEL_ACTIONS: tuple[str, ...] = (
    "disable_agent",
    "enable_agent",
    "revoke_agent_credential",
    "remove_tool_access",
    "restore_tool_access",
    "block_mcp_server",
    "unblock_mcp_server",
)

#: `agent/tool` for the grant actions. A grant is a pair, and an action that
#: took only the agent would be "remove every tool", which is a different and
#: much larger action than the catalogue's SINGLE blast radius declares.
_PAIR = re.compile(r"^(?P<left>[^/\s]{1,128})/(?P<right>[^/\s]{1,128})$")


class ContainmentTargetInvalid(DomainRuleViolated):
    """The target did not parse into the fields this action needs.

    Not retryable: a malformed target is malformed on the second attempt too,
    and retrying would burn the approval's budget against a typo.
    """

    is_retryable = False


def _tenant(value: str) -> TenantId:
    try:
        return TenantId(value)
    except InvalidValue as exc:
        raise ContainmentTargetInvalid(f"invalid tenant {value!r}: {exc}") from exc


def _pair(target: str, *, action: str, left: str, right: str) -> tuple[str, str]:
    matched = _PAIR.match(str(target).strip())
    if not matched:
        raise ContainmentTargetInvalid(
            f"{action}: target {target!r} must be '{left}/{right}'"
        )
    return matched.group("left"), matched.group("right")


class AgentEnrolmentContainment:
    """`disable_agent` / `enable_agent` / `revoke_agent_credential`.

    All three act on the enrolment record, and the difference between them is
    what the catalogue says about REVERSIBILITY rather than what the code does:

      * `disable_agent` is reversible -- `enable_agent` re-enrols the address.
      * `revoke_agent_credential` is NOT, and the catalogue declares no
        rollback for it. The mechanism is the same revocation; the promise
        attached to it is different, and `decide_response` reads that promise
        to decide what may run automatically. Implementing them with one class
        does not merge those promises, because the catalogue holds them.
    """

    __slots__ = ("_registry", "_clock")

    def __init__(self, *, registry: Any, clock: Any) -> None:
        self._registry = registry
        self._clock = clock

    @property
    def provider(self) -> str:
        return "sentinel"

    def execute(
        self, *, target: str, idempotency_key: IdempotencyKey, tenant: str
    ) -> Mapping[str, Any]:
        tenant_id = _tenant(tenant)
        try:
            address = Address(str(target).strip())
        except InvalidValue as exc:
            raise ContainmentTargetInvalid(
                f"target {target!r} is not a valid agent address: {exc}"
            ) from exc

        # Which direction is decided by the CALLER's action name, and this class
        # is registered under three of them. `enable_agent` is the only one that
        # re-enrols; the container passes a flag rather than this class sniffing
        # an action string it was never given.
        self._registry.revoke(tenant_id, address=address)
        return {
            "provider": "sentinel",
            "action": "revoke_enrolment",
            "tenant": tenant_id.value,
            "address": address.value,
            # Reported so a receipt says what changed in Sentinel rather than
            # only that something did. An empty diff and a real one must not
            # read the same in an audit.
            "effect": "the address may no longer sign events for this tenant",
        }


class AgentReinstatement(AgentEnrolmentContainment):
    """`enable_agent`: the inverse, re-enrolling the address.

    A separate class rather than a flag because it is registered under a
    different action name, and a single class that branched on a string it was
    handed would be one refactor away from doing the opposite of what an
    approval said.
    """

    __slots__ = ()

    def execute(
        self, *, target: str, idempotency_key: IdempotencyKey, tenant: str
    ) -> Mapping[str, Any]:
        tenant_id = _tenant(tenant)
        try:
            address = Address(str(target).strip())
        except InvalidValue as exc:
            raise ContainmentTargetInvalid(
                f"target {target!r} is not a valid agent address: {exc}"
            ) from exc

        self._registry.enrol(
            tenant_id,
            address=address,
            label="reinstated by remediation",
            at=self._clock.now(),
        )
        return {
            "provider": "sentinel",
            "action": "reinstate_enrolment",
            "tenant": tenant_id.value,
            "address": address.value,
            "effect": "the address may sign events for this tenant again",
        }


class ToolGrantContainment:
    """`remove_tool_access` / `restore_tool_access`. Target is `agent/tool`.

    ONE tool, never all of them. The catalogue rates this blast radius SINGLE,
    and an implementation that dropped every grant when handed a bare agent id
    would make that declaration false -- which matters because `decide_response`
    reads blast radius to decide what may run without a human.
    """

    __slots__ = ("_capabilities", "_restore")

    def __init__(self, *, capabilities: Any, restore: bool = False) -> None:
        self._capabilities = capabilities
        self._restore = restore

    @property
    def provider(self) -> str:
        return "sentinel"

    def execute(
        self, *, target: str, idempotency_key: IdempotencyKey, tenant: str
    ) -> Mapping[str, Any]:
        tenant_id = _tenant(tenant)
        agent_id, tool = _pair(
            target, action="remove_tool_access", left="agent", right="tool"
        )
        if self._restore:
            self._capabilities.grant(tenant_id.value, agent_id, frozenset({tool}))
        else:
            self._capabilities.revoke(tenant_id.value, agent_id, frozenset({tool}))
        return {
            "provider": "sentinel",
            "action": "restore_tool_access" if self._restore else "remove_tool_access",
            "tenant": tenant_id.value,
            "agent_id": agent_id,
            "tool": tool,
        }


class McpServerContainment:
    """`block_mcp_server` / `unblock_mcp_server`.

    Blocking writes a BLOCKED trust record, which `McpGateway.resolve` refuses
    before any content is examined -- so the block takes effect on the next call
    without anything else being told about it.

    Unblocking restores UNKNOWN, NOT ENROLLED. An operator who blocked a server
    during an incident and later lifts the block should get back the state where
    the server must be re-enrolled deliberately; silently restoring the previous
    trust would turn "we are done investigating" into "this server is approved
    again", which nobody said.
    """

    __slots__ = ("_registry", "_unblock")

    def __init__(self, *, registry: Any, unblock: bool = False) -> None:
        self._registry = registry
        self._unblock = unblock

    @property
    def provider(self) -> str:
        return "sentinel"

    def execute(
        self, *, target: str, idempotency_key: IdempotencyKey, tenant: str
    ) -> Mapping[str, Any]:
        tenant_id = _tenant(tenant)
        server_id = str(target).strip()
        if not server_id or "/" in server_id:
            raise ContainmentTargetInvalid(
                f"block_mcp_server: target {target!r} must be a server id"
            )

        existing = self._registry.lookup(tenant_id.value, server_id)
        endpoint = getattr(existing, "endpoint", "") if existing else ""
        trust = McpServerTrust.UNKNOWN if self._unblock else McpServerTrust.BLOCKED

        self._registry.record(
            McpServerIdentity(
                tenant_id=tenant_id.value,
                server_id=server_id,
                endpoint=endpoint,
                trust=trust,
            )
        )
        return {
            "provider": "sentinel",
            "action": "unblock_mcp_server" if self._unblock else "block_mcp_server",
            "tenant": tenant_id.value,
            "server_id": server_id,
            "trust": trust.value,
            "effect": (
                "the server must be re-enrolled deliberately"
                if self._unblock
                else "every call to this server is refused before content is examined"
            ),
        }


def build_sentinel_integrations(
    *, registry: Any, capabilities: Any, mcp_registry: Any, clock: Any
) -> dict[str, Any]:
    """Every `provider="sentinel"` action this process can perform itself.

    Returned in the action -> integration shape `GuardedRemediationExecutor`
    takes, so the composition root merges it with the native platform
    integrations and the operator's webhooks rather than choosing between them.
    """
    enrolment = AgentEnrolmentContainment(registry=registry, clock=clock)
    return {
        "disable_agent": enrolment,
        "revoke_agent_credential": enrolment,
        "enable_agent": AgentReinstatement(registry=registry, clock=clock),
        "remove_tool_access": ToolGrantContainment(capabilities=capabilities),
        "restore_tool_access": ToolGrantContainment(
            capabilities=capabilities, restore=True
        ),
        "block_mcp_server": McpServerContainment(registry=mcp_registry),
        "unblock_mcp_server": McpServerContainment(
            registry=mcp_registry, unblock=True
        ),
    }
