"""Inline tool execution proxy — the only sanctioned remote side-effect path.

Agents that want Sentinel to run a tool MUST call POST /v1/tools/execute (or
the SDK interceptor that wraps it). There is no alternate in-product execute
route. External processes that never call Sentinel remain outside enforcement;
that residual risk is documented on F-11.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from sentinel.application.tool_runner import ProtectedToolRunner, ToolExecutionRefused
from sentinel.domain.errors import DomainRuleViolated
from sentinel.domain.execution_binding import (
    ExecutionAuthorization,
    NonceLedger,
)
from sentinel.application.agent_capabilities import (
    AgentCapabilityGate,
    AgentCapabilityRefused,
)
from sentinel.domain.primitives import TrustLevel
from sentinel.domain.protect import ProtectOutcome

__all__ = ["InlineToolProxy", "ToolProxyRefused", "RegisteredSideEffect"]


class ToolProxyRefused(DomainRuleViolated):
    """Proxy refused the tool call (kill switch, protect, budget, unknown tool)."""

    is_retryable = False


@dataclass(frozen=True, slots=True)
class RegisteredSideEffect:
    """A named side effect the proxy is allowed to invoke after protect clears."""

    name: str
    runner: Callable[[Mapping[str, Any]], Any]
    #: Identifiers (never values) worth recording with the intent so the target
    #: can later be asked whether this operation landed.
    hint: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None
    #: `(operation_id, hint) -> ReconcileVerdict`. Reads the target; never writes.
    reconciler: Callable[[str, Mapping[str, Any]], Any] | None = None
    #: `(context, args)`: an effect that must know WHICH tenant is calling and
    #: what resource was authorized -- a connected application is the tenant's,
    #: and its credential must only ever be aimed where the gate decided.
    #: When set, the proxy uses it instead of `runner` on both paths.
    tenant_runner: Callable[[Any, Mapping[str, Any]], Any] | None = None


@dataclass(frozen=True, slots=True)
class EffectContext:
    """What a tenant-aware effect is told, beyond its arguments. Never the credential."""

    tenant_id: str
    resource: str
    action: str
    agent_id: str


def _safe_hint(effect: RegisteredSideEffect, args: Mapping[str, Any]) -> Mapping[str, Any]:
    """The effect's reconcile hint, or nothing. A hint that cannot be computed
    must not stop the execution; the operation simply has no automatic path."""
    if effect.hint is None:
        return {}
    try:
        hint = effect.hint(args)
    except Exception:  # noqa: BLE001
        return {}
    return {"reconcile_hint": dict(hint)} if isinstance(hint, Mapping) and hint else {}


class InlineToolProxy:
    """Always evaluates ProtectGate (via ProtectedToolRunner) before any effect."""

    __slots__ = ("_tool_runner", "_effects", "_capabilities", "_receipts")

    def __init__(
        self,
        *,
        tool_runner: ProtectedToolRunner,
        effects: Mapping[str, RegisteredSideEffect] | None = None,
        capabilities: AgentCapabilityGate | None = None,
        receipts: Any = None,
    ) -> None:
        self._tool_runner = tool_runner
        self._effects = dict(effects or {})
        #: Where a bound execution's receipt is written, when a store is
        #: configured. Optional for the same reason `capabilities` is; a
        #: receipt that only exists in the HTTP response is one nobody can
        #: query a week later, which is the question the diff exists for.
        self._receipts = receipts
        # Optional so every existing caller keeps working unchanged. `None`
        # means the capability question is not asked at all, which is a
        # different state from asking it in observe mode -- and the difference
        # is visible, because an observe-mode gate records that it was
        # consulted and a None one leaves no trace.
        self._capabilities = capabilities

    def register(self, effect: RegisteredSideEffect) -> None:
        self._effects[effect.name] = effect

    def reconciler_for(self, tool: str) -> Callable[[str, Mapping[str, Any]], Any] | None:
        effect = self._effects.get(tool)
        return effect.reconciler if effect is not None else None

    def execute(
        self,
        *,
        agent_id: str,
        tool: str,
        trust: TrustLevel,
        tenant_id: str = "",
        arguments: Mapping[str, Any] | None = None,
        resource: str = "",
        action: str = "",
        metadata: Mapping[str, Any] | None = None,
        authorization: ExecutionAuthorization | None = None,
        nonces: NonceLedger | None = None,
        now: datetime | None = None,
        delegation_passport_digest: str = "",
        approved: bool = False,
    ) -> dict[str, Any]:
        """Run a registered tool only after protect allows it.

        Unknown tools are refused (fail closed) -- the proxy never invents an
        effect. Kill switch / budget / circuit are enforced inside tool_runner.

        WITH AND WITHOUT AN AUTHORIZATION
        ---------------------------------
        Supplying `authorization` routes the call through
        `ProtectedToolRunner.execute_bound`, which recomputes the parameter
        digest immediately before the side effect and passes the VERIFIED
        parameters into it. Omitting it uses the unbound path, which binds
        nothing and which the runner refuses outright when
        `SENTINEL_REQUIRE_EXECUTION_BINDING` is set.

        This proxy is the chokepoint the MCP gateway routes through, so until it
        could take an authorization, setting that flag refused every tool call
        in the product -- a switch that turned the service off rather than one
        that enforced binding. `arguments` is already the real parameter
        mapping here, which is why this is the right place for the binding to
        live rather than the honest-caller convention it replaces.
        """
        if tool not in self._effects:
            raise ToolProxyRefused(
                f"tool {tool!r} is not registered on the inline proxy; "
                "refusing (fail closed)"
            )

        # CAPABILITY, BEFORE CONTENT.
        #
        # "Is this agent supposed to be doing this at all" is a cheaper and more
        # categorical question than "is this action dangerous", and the answers
        # are independent: a perfectly benign read_file from an agent whose only
        # job is summarising text is harmless by content and still wrong.
        #
        # Checked before ProtectGate so an ungranted agent cannot spend the
        # detector's time, and before the effect for the obvious reason.
        capability = None
        if self._capabilities is not None:
            try:
                capability = self._capabilities.require(
                    tenant_id=tenant_id, agent_id=agent_id, tool=tool
                )
            except AgentCapabilityRefused as exc:
                raise ToolProxyRefused(str(exc)) from exc

        effect = self._effects[tool]
        args = dict(arguments or {})
        runner = effect.runner
        if effect.tenant_runner is not None:
            context = EffectContext(tenant_id=str(tenant_id or ""), resource=str(resource or ""),
                                    action=str(action or tool), agent_id=str(agent_id))
            tenant_runner = effect.tenant_runner

            def runner(parameters: Mapping[str, Any]) -> Any:  # noqa: F811 - the tenant-aware form
                return tenant_runner(context, parameters)
        receipt = None
        # The runner is a singleton and the tenant varies per request. Passed
        # through on BOTH paths so containment reads the caller's kill switch
        # rather than none at all -- an omission here made the granular kill
        # switch decorative for every HTTP execution.
        contained_tenant = tenant_id or None

        try:
            if authorization is not None:
                if nonces is None:
                    # Refused rather than defaulted. A default in-process ledger
                    # would make single-use per-process, which across replicas
                    # is no replay protection at all -- the same defect class as
                    # a per-process rate limiter, and it would pass every test.
                    raise ToolProxyRefused(
                        f"tool {tool!r} refused: an authorization was supplied "
                        "with no nonce ledger, so single-use cannot be "
                        "enforced. Pass the deployment's shared ledger."
                    )
                outcome, result, receipt = self._tool_runner.execute_bound(
                    authorization=authorization,
                    agent_id=agent_id,
                    tool=tool,
                    action=action or tool,
                    resource=resource,
                    # The SAME mapping the effect will receive. execute_bound
                    # passes the verified parameters into the side effect, so
                    # what runs is what the digest was checked against.
                    parameters=args,
                    trust=trust,
                    side_effect=runner,
                    nonces=nonces,
                    now=now or datetime.now(timezone.utc),
                    mcp_server=str((metadata or {}).get("mcp_server", "")),
                    delegation_passport_digest=delegation_passport_digest,
                    tenant=contained_tenant,
                    # The human decision, when the authorization was activated
                    # by one. Satisfies require_approval at execution time;
                    # never a block.
                    approved=approved,
                    intent_attributes=_safe_hint(effect, args),
                )
            else:
                def side_effect() -> Any:
                    return runner(args)

                outcome, result = self._tool_runner.execute(
                    agent_id=agent_id,
                    tool=tool,
                    trust=trust,
                    side_effect=side_effect,
                    resource=resource,
                    action=action or tool,
                    metadata={**(metadata or {}), "arguments": args},
                    tenant=contained_tenant,
                )
        except ToolExecutionRefused as exc:
            raise ToolProxyRefused(str(exc)) from exc
        except ValueError as exc:
            # The canonicaliser refused the arguments -- a float, an integer
            # past 2^53, a non-string key. Nothing ran; the parameters cannot
            # be committed to, so they cannot be bound.
            raise ToolProxyRefused(
                f"tool {tool!r} refused: the arguments cannot be canonicalised "
                f"for binding ({exc})"
            ) from exc

        if (
            receipt is not None
            and self._receipts is not None
            and tenant_id
            and not getattr(self._tool_runner, "records_receipts", False)
        ):
            # Durable, so the approved-versus-executed diff can see this
            # execution after the response is gone. Written after the effect
            # and never able to undo it: a store outage is logged by the
            # store, not turned into a refusal of something that already ran.
            self._receipts.record(
                tenant_id,
                receipt=receipt,
                approved_parameter_digest=authorization.approved_parameter_digest,
                authorization_id=authorization.authorization_id,
                delegation_passport_digest=delegation_passport_digest,
            )

        response: dict[str, Any] = {
            "tool": tool,
            "result": result,
            "protect": outcome.as_dict(),
        }
        if receipt is not None:
            # The receipt, not just the result. A caller that cannot obtain the
            # binding evidence cannot pass it on, and evidence nobody can
            # forward is evidence nobody uses.
            response["receipt"] = receipt.as_document()
        if capability is not None:
            # Reported so a caller can tell an authorised call from one that was
            # merely not refused. In observe mode `allowed` is True for an agent
            # with no grants at all, and `enforced` is what distinguishes them.
            response["capability"] = capability.as_dict()
        return response

    def evaluate_only(
        self,
        *,
        agent_id: str,
        tool: str,
        trust: TrustLevel,
        resource: str = "",
        action: str = "",
        metadata: Mapping[str, Any] | None = None,
    ) -> ProtectOutcome:
        """Protect decision without executing — used by advisory clients."""
        payload = {
            "agentId": agent_id,
            "eventType": "tool_call",
            "action": action or tool,
            "resource": resource,
            "tool": tool,
            "metadata": dict(metadata or {}),
        }
        return self._tool_runner.gate.evaluate(payload=payload, trust=trust)
