"""Fail-closed tool execution wrapper for in-process agents.

WHY THIS EXISTS
---------------
ProtectGate is the decision + callback seam. Agents still need a single
entry point that *constructs* the tool payload and makes skipping the gate a
deliberate fork of this module rather than an easy omission at a call site.

ProtectedToolRunner.execute is that entry point:

  1. Honour kill switch / budget / circuit (ProtectControls) fail-closed.
  2. Build a canonical tool-call payload from the intended action.
  3. Always ask ProtectGate.run_if_allowed before the side effect.
  4. Never invoke the side effect when enforcement stops the action.
  5. When enforcement is on and the gate/policy cannot be evaluated, refuse
     (fail closed) -- never silently allow.

LIMITATIONS
-----------
External agents that do not call this wrapper are not intercepted. F-11 stays
PARTIAL until every production tool path is proven to go through it.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, TypeVar

from sentinel.application.protect_controls import (
    CircuitOpen,
    KillSwitchActive,
    ProtectControls,
    ToolBudgetExceeded,
)
from sentinel.application.protect_gate import ProtectDenied, ProtectGate
from sentinel.domain.errors import DomainRuleViolated, TransientFailure
from sentinel.application.operation_context import operation_scope
from sentinel.domain.operations import (
    ExecutionOperation,
    OperationState,
    OutcomeUnknown,
)
from sentinel.domain.execution_binding import (
    BindingVerdict,
    ExecutionAuthorization,
    ExecutionReceipt,
    ExecutionRequest,
    NonceLedger,
    verify_binding,
)
from sentinel.domain.passport import digest_of
from sentinel.domain.primitives import TenantId, TrustLevel
from sentinel.domain.protect import ProtectOutcome

__all__ = ["ProtectedToolRunner", "ToolExecutionRefused"]

T = TypeVar("T")


def _request_document(request: ExecutionRequest) -> dict[str, Any]:
    """The executed request, in the form a receipt commits to.

    Domain-separated like every other document this codebase hashes, so an
    executed-request digest can never be presented as an authorization digest
    or a parameter digest.
    """
    return {
        "context": "sentinel.execution.request.v1",
        "tenant_id": request.tenant_id,
        "agent_identity": request.agent_identity,
        "tool_identity": request.tool_identity,
        "action": request.action,
        "target_resource": request.target_resource,
        "mcp_server_identity": request.mcp_server_identity,
        "parameter_digest": request.parameter_digest,
    }


def _result_digest(result: Any) -> str:
    """A digest of the result, or empty when one cannot honestly be produced.

    Empty rather than a digest of `repr(result)`. A repr digest looks exactly
    like a real commitment and is stable only by accident -- it changes with a
    memory address for any object without a defined repr, so the same result
    would hash differently on two runs and an auditor comparing receipts would
    see tampering that never happened.

    A tool returning something unhashable is common and is not an error, so this
    records the absence instead of inventing the value. `ExecutionReceipt`
    permits an empty `result_digest` for exactly this reason.
    """
    if result is None:
        return ""
    try:
        if isinstance(result, Mapping):
            return digest_of({"context": "sentinel.execution.result.v1",
                              "result": dict(result)})
        if isinstance(result, (str, int, bool)):
            return digest_of({"context": "sentinel.execution.result.v1",
                              "result": result})
    except (ValueError, TypeError):
        return ""
    return ""


def _tenant_for_containment(tenant: Any) -> Any:
    """Containment's repository path expects a TenantId, while routes hold str."""
    if tenant is None or hasattr(tenant, "value"):
        return tenant
    text = str(tenant)
    return TenantId(text) if text else None


class ControlStateRefused(TransientFailure):
    """The shared budget/breaker state could not be consulted. Refused, retryable.

    Distinct from `ToolExecutionRefused` (a decision) because the right
    response differs: a caller may retry this after the store recovers, and
    must not retry a refusal.
    """

    is_retryable = True


class ToolExecutionRefused(DomainRuleViolated):
    """Tool side effect refused: enforced deny, or evaluation failure under enforce."""


class ProtectedToolRunner:
    """The only sanctioned way for an in-process agent to run a tool side effect."""

    __slots__ = (
        "_gate", "_controls", "_containment", "_tenant", "_clock",
        "_require_binding", "_operations", "_receipts",
    )

    def __init__(
        self,
        *,
        gate: ProtectGate,
        controls: ProtectControls | None = None,
        containment: Any = None,
        tenant: Any = None,
        clock: Any = None,
        require_binding: bool = False,
        operations: Any = None,
        receipts: Any = None,
    ) -> None:
        self._gate = gate
        self._controls = controls or ProtectControls()
        #: Durable intent-before-effect record and append-only receipt store.
        #: Optional so in-process construction sites keep working; the
        #: composition root wires both, and `records_receipts` tells the proxy
        #: not to write a second receipt.
        self._operations = operations
        self._receipts = receipts
        #: The granular kill switch. Optional so existing construction sites keep
        #: working; when absent, containment is simply not enforced here, which
        #: `test_the_runner_consults_containment_when_one_is_configured` and the
        #: composition root's wiring together make a deployment-time choice
        #: rather than an accident.
        self._containment = containment
        self._tenant = tenant
        self._clock = clock
        #: When True the unbound `execute` refuses. Defaults False so existing
        #: construction sites keep working; the composition root passes the
        #: deployment's setting, and production must state it. See
        #: `Settings.require_execution_binding`.
        self._require_binding = require_binding

    @property
    def gate(self) -> ProtectGate:
        return self._gate

    @property
    def controls(self) -> ProtectControls:
        return self._controls

    def execute(
        self,
        *,
        agent_id: str,
        tool: str,
        trust: TrustLevel,
        side_effect: Callable[[], T],
        resource: str = "",
        action: str = "",
        metadata: Mapping[str, Any] | None = None,
        event_type: str = "tool_call",
        tenant: Any = None,
    ) -> tuple[ProtectOutcome, T]:
        """Evaluate protect, then run side_effect only if not enforced-stopped.

        side_effect is intentionally a zero-arg callable so callers cannot
        obtain a "pre-approved" handle: the only way through is this method.
        """
        if self._require_binding:
            # THE UNBOUND PATH, REFUSED.
            #
            # This method decides over a payload the caller built and then runs
            # a closure the caller also built, so the two are connected by
            # nothing but the caller having been honest. With binding required,
            # allowing it would make "authorization is bound to execution" a
            # claim about the code and not about this deployment.
            #
            # Refused here rather than filtered upstream: a bypass that needs a
            # deliberate fork of this module is the property the class docstring
            # claims, and an upstream check would leave the method itself usable.
            raise ToolExecutionRefused(
                f"tool {tool!r} refused: SENTINEL_REQUIRE_EXECUTION_BINDING is "
                "set, and `execute` binds nothing -- it takes an opaque "
                "zero-argument closure, so an agent authorized against one "
                "resource could act on another with every passport and proof "
                "still verifying. Use `execute_bound` with an "
                "ExecutionAuthorization, which passes the verified parameters "
                "into the side effect."
            )

        if not tool or not str(tool).strip():
            raise ToolExecutionRefused("tool name is required")
        if not agent_id or not str(agent_id).strip():
            raise ToolExecutionRefused("agent_id is required")

        # The granular kill switch, checked BEFORE the gate.
        #
        # Before, because a containment is an operator's explicit "stop this",
        # and it should not depend on a policy evaluation succeeding. If the gate
        # were consulted first, a contained agent would still be stopped -- but
        # an operator watching a detector misbehave would be relying on that same
        # detector to honour their override.
        #
        # The refusal names the containment, so the agent's owner sees why their
        # tool stopped working instead of a generic denial.
        # The runner is a singleton and the tenant varies per request, so the
        # caller's tenant wins over the constructed one. A containment check
        # against the wrong tenant would be worse than no check: it would read
        # somebody else's kill switch and either block work nobody stopped or
        # miss the one that was.
        contained_tenant = _tenant_for_containment(
            tenant if tenant is not None else self._tenant
        )
        # The TENANT reaches the controls: budget and breaker are keyed on
        # (tenant, agent). See execute_bound for the defect this closes.
        control_tenant = str(getattr(contained_tenant, "value", contained_tenant) or "")
        try:
            self._controls.assert_may_execute(
                agent_id=str(agent_id), tenant_id=control_tenant
            )
        except (KillSwitchActive, ToolBudgetExceeded, CircuitOpen) as exc:
            raise ToolExecutionRefused(str(exc)) from exc
        except TransientFailure as exc:
            raise ControlStateRefused(f"tool {tool!r} refused: {exc}") from exc
        if self._containment is not None and contained_tenant is not None:
            decision = self._containment.check(
                contained_tenant,
                now=str(self._clock.now()) if self._clock is not None else "",
                agent_id=str(agent_id),
                tool=str(tool),
                credential=str((metadata or {}).get("credential", "")),
                mcp_server=str((metadata or {}).get("mcp_server", "")),
            )
            if decision.blocked:
                self._controls.record_failure(agent_id=str(agent_id), tenant_id=control_tenant)
                raise ToolExecutionRefused(
                    f"tool {tool!r} refused: {decision.reason}"
                )

        payload: dict[str, Any] = {
            "agentId": agent_id,
            "eventType": event_type,
            "action": action or tool,
            "resource": resource,
            "tool": tool,
            "metadata": dict(metadata or {}),
        }

        try:
            # THE load-bearing call. Mutation tests remove this and must fail.
            result = self._gate.run_if_allowed(
                payload=payload,
                trust=trust,
                action=side_effect,
            )
        except ProtectDenied as denied:
            self._controls.record_failure(agent_id=str(agent_id), tenant_id=control_tenant)
            raise ToolExecutionRefused(
                f"tool {tool!r} refused by protect: {denied.outcome.decision.value}"
            ) from denied
        except ToolExecutionRefused:
            self._controls.record_failure(agent_id=str(agent_id), tenant_id=control_tenant)
            raise
        except DomainRuleViolated as violated:
            # The SIDE EFFECT refused, not the gate. `run_if_allowed` invokes the
            # side effect, so anything it raises arrives here too -- and until
            # real adapters existed, the only registered effects were `echo` and
            # `noop`, which cannot raise. The catch-all below was therefore
            # always reporting a genuine evaluation failure, and its message said
            # so accurately.
            #
            # That stopped being true the moment an adapter could refuse. A
            # sandbox escape blocked by `read_file` is containment WORKING, and
            # reporting it as "protect evaluation failed" sends whoever is
            # on-call to investigate the detector instead of the agent that just
            # tried to read outside its sandbox. The refusal is still a refusal
            # and still counts as a failure; only the attribution changes.
            self._controls.record_failure(agent_id=str(agent_id), tenant_id=control_tenant)
            raise ToolExecutionRefused(
                f"tool {tool!r} refused the effect: {violated}"
            ) from violated
        except Exception as exc:  # noqa: BLE001 - evaluation must not fail open
            self._controls.record_failure(agent_id=str(agent_id), tenant_id=control_tenant)
            if self._gate.enforce:
                raise ToolExecutionRefused(
                    f"protect evaluation failed under enforcement; "
                    f"refusing tool {tool!r} (fail closed)"
                ) from exc
            raise
        else:
            self._controls.record_success(agent_id=str(agent_id), tenant_id=control_tenant)
            return result

    @property
    def records_receipts(self) -> bool:
        """True when this runner writes receipts itself, so callers must not."""
        return self._receipts is not None

    def execute_bound(
        self,
        *,
        authorization: ExecutionAuthorization,
        agent_id: str,
        tool: str,
        action: str,
        resource: str,
        parameters: Mapping[str, Any],
        trust: TrustLevel,
        side_effect: Callable[[Mapping[str, Any]], T],
        nonces: NonceLedger,
        now: datetime,
        mcp_server: str = "",
        delegation_passport_digest: str = "",
        approved_parameters: Mapping[str, Any] | None = None,
        event_type: str = "tool_call",
        tenant: Any = None,
        approved: bool = False,
        intent_attributes: Mapping[str, Any] | None = None,
    ) -> tuple[ProtectOutcome, T, ExecutionReceipt]:
        """Run a tool only if this execution is the one that was authorized.

        WHAT THIS ADDS OVER `execute`
        ------------------------------
        `execute` takes a zero-argument closure and a payload DESCRIBING it. The
        gate decides over the description and then calls the closure, which can
        do anything; the two are connected only by the caller having been
        honest. So an agent approved to write one bucket could write another and
        every passport, signature and inclusion proof would still verify,
        because each is a true statement about the decision.

        Here `side_effect` takes the parameters as an argument and this method
        passes in the ones that were verified. The values that reach the tool
        are therefore the values the digest was checked against -- the binding
        is structural rather than a promise.

        WHERE THE CHECK SITS
        --------------------
        Inside the closure handed to the gate, immediately before the effect.
        Not before `run_if_allowed`: anything that can change between the check
        and the call is unchecked, which is the failure being closed.

        THE RESIDUAL, STATED PLAINLY
        ----------------------------
        `agent_id`, `tool`, `action`, `resource` and `mcp_server` are what the
        CALLER says it is about to do, and they are compared against what was
        authorized. A caller that both lies about them and executes something
        else is not caught here, because an in-process wrapper cannot observe
        the syscalls of a closure it was handed. What is caught is every case
        where the declared action and the approved action disagree, which is
        what parameter substitution, tool substitution and resource
        substitution actually look like in practice.

        Closing the residual needs enforcement outside the calling process.
        The MCP proxy binds the wire request; this method does not claim
        syscall-level observation of arbitrary user-supplied effects.
        """
        if not tool or not str(tool).strip():
            raise ToolExecutionRefused("tool name is required")
        if not agent_id or not str(agent_id).strip():
            raise ToolExecutionRefused("agent_id is required")

        contained_tenant = _tenant_for_containment(
            tenant if tenant is not None else self._tenant
        )
        # The TENANT reaches the controls. Budget and breaker are keyed on
        # (tenant, agent); without the tenant every replica's counters keyed on
        # ("", agent) and a same-named agent in two tenants shared one budget
        # and one breaker -- twenty refusals in one tenant closed the other.
        control_tenant = str(getattr(contained_tenant, "value", contained_tenant) or "")
        try:
            self._controls.assert_may_execute(
                agent_id=str(agent_id), tenant_id=control_tenant
            )
        except (KillSwitchActive, ToolBudgetExceeded, CircuitOpen) as exc:
            raise ToolExecutionRefused(str(exc)) from exc
        except TransientFailure as exc:
            # The shared control state could not be read. Refuse: a control
            # whose answer is unknown is not a control, and this is exactly the
            # moment -- a struggling database -- a runaway agent is likeliest.
            raise ControlStateRefused(
                f"tool {tool!r} refused: {exc}"
            ) from exc
        if self._containment is not None and contained_tenant is not None:
            decision = self._containment.check(
                contained_tenant,
                now=str(self._clock.now()) if self._clock is not None else "",
                agent_id=str(agent_id),
                tool=str(tool),
                credential="",
                mcp_server=str(mcp_server),
            )
            if decision.blocked:
                self._controls.record_failure(agent_id=str(agent_id), tenant_id=control_tenant)
                raise ToolExecutionRefused(
                    f"tool {tool!r} refused: {decision.reason}"
                )

        request = ExecutionRequest(
            # Built from what the CALLER is about to do, never from the
            # authorization. Copying these across from the authorization would
            # make every identity comparison below compare a field to itself,
            # which is a check that cannot fail.
            tenant_id=str(getattr(contained_tenant, "value", contained_tenant) or ""),
            agent_identity=str(agent_id),
            tool_identity=str(tool),
            action=str(action),
            target_resource=str(resource),
            parameters=dict(parameters),
            mcp_server_identity=str(mcp_server),
            # The chain the caller is ACTUALLY presenting. Compared against
            # the one the authorization was issued against, so a valid chain
            # from a different principal is refused rather than accepted for
            # granting the same capability.
            delegation_passport_digest=str(delegation_passport_digest),
        )

        payload: dict[str, Any] = {
            "agentId": agent_id,
            "eventType": event_type,
            "action": action or tool,
            "resource": resource,
            "tool": tool,
            "metadata": {
                "mcp_server": mcp_server,
                "authorization_id": authorization.authorization_id,
                # The digest, not the parameters. Parameters can carry
                # sensitive values and this payload reaches detection, logs and
                # evidence; a digest identifies them without disclosing them.
                "parameter_digest": request.parameter_digest,
                "delegation_passport_digest": request.delegation_passport_digest,
            },
        }

        verdict_box: dict[str, BindingVerdict] = {}
        started = now.astimezone(timezone.utc).isoformat()
        operation_id = f"op-{authorization.authorization_id}"
        marks: dict[str, Any] = {"started_at": "", "intent_recorded": False}

        def _clock_now() -> datetime:
            """The clock AT the event, never the `now` the caller passed in."""
            if self._clock is not None:
                value = self._clock.now()
                value = getattr(value, "value", value)
                if isinstance(value, datetime):
                    return value.astimezone(timezone.utc)
            return datetime.now(timezone.utc)

        def _record_refusal(reason: str) -> None:
            """A refused attempt is evidence. Digests only; best effort."""
            if self._operations is None or not request.tenant_id:
                return
            stamp = _clock_now().isoformat()
            try:
                self._operations.record_refusal(
                    request.tenant_id,
                    ExecutionOperation(
                        operation_id=f"{operation_id}-refused-{secrets.token_hex(4)}",
                        tenant_id=request.tenant_id,
                        agent_identity=str(agent_id),
                        tool_identity=str(tool),
                        action=str(action or tool),
                        target_resource=str(resource),
                        parameter_digest=request.parameter_digest,
                        state=OperationState.REFUSED,
                        started_at=stamp,
                        completed_at=stamp,
                        authorization_id=authorization.authorization_id,
                        error=reason[:2000],
                    ),
                )
            except Exception:  # noqa: BLE001 - a refusal must not gain a second failure path
                return

        def _unknown(exc: Exception) -> OutcomeUnknown:
            # Once a callback is entered, an exception does not prove absence
            # of a remote effect. Never retain its text (it may include secrets).
            reason = f"post-invocation {type(exc).__name__}; reconcile target state"
            if marks["intent_recorded"]:
                try:
                    self._operations.complete(
                        request.tenant_id, operation_id,
                        state=OperationState.UNKNOWN_AFTER_EFFECT,
                        completed_at=_clock_now().isoformat(), error=reason,
                    )
                except Exception:  # noqa: BLE001 - durable pending intent remains for the reaper
                    pass
            try:
                self._controls.record_failure(agent_id=str(agent_id), tenant_id=control_tenant)
            except Exception:  # noqa: BLE001 - do not hide the operation id with a secondary outage
                pass
            return OutcomeUnknown(operation_id, reason)

        def _bound_effect() -> T:
            verdict = verify_binding(
                authorization=authorization,
                request=request,
                now=_clock_now() if self._clock is not None else now,
                nonces=nonces,
                approved_parameters=approved_parameters,
            )
            verdict_box["verdict"] = verdict
            if not verdict.permitted:
                _record_refusal(verdict.explain())
                raise ToolExecutionRefused(
                    f"tool {tool!r} refused: the execution does not match its "
                    f"authorization.\n{verdict.explain()}"
                )
            started_at = _clock_now().isoformat()
            marks["started_at"] = started_at
            if self._operations is not None and request.tenant_id:
                # INTENT FIRST. If this write fails nothing has run yet, so a
                # refusal is safe; if it succeeds and the process dies inside
                # the effect, the pending row is what a reconciler finds.
                try:
                    self._operations.begin(
                        request.tenant_id,
                        ExecutionOperation(
                            operation_id=operation_id,
                            tenant_id=request.tenant_id,
                            agent_identity=str(agent_id),
                            tool_identity=str(tool),
                            action=str(action or tool),
                            target_resource=str(resource),
                            parameter_digest=request.parameter_digest,
                            state=OperationState.PENDING,
                            started_at=started_at,
                            authorization_id=authorization.authorization_id,
                            attributes=dict(intent_attributes or {}),
                        ),
                    )
                except Exception as exc:  # noqa: BLE001 - nothing ran; refuse rather than run unrecorded
                    raise ToolExecutionRefused(
                        f"tool {tool!r} refused: the execution intent could not be "
                        f"recorded before the effect ({type(exc).__name__}); "
                        "nothing ran"
                    ) from exc
                marks["intent_recorded"] = True
            try:
                # The VERIFIED parameters, not the caller's originals. Identical
                # here by construction; passing the checked object is what keeps
                # it that way if this method is ever edited.
                with operation_scope(operation_id):
                    return side_effect(request.parameters)
            except Exception as exc:
                if getattr(exc, "effect_known_absent", False) is True:
                    # The adapter vouches that nothing mutating left the
                    # process. That is a failure with a known outcome.
                    if marks["intent_recorded"]:
                        try:
                            self._operations.complete(
                                request.tenant_id, operation_id, state=OperationState.FAILED,
                                completed_at=_clock_now().isoformat(),
                                error=f"not attempted: {type(exc).__name__}",
                            )
                        except Exception:  # noqa: BLE001 - the pending row remains for the reaper
                            pass
                    raise ToolExecutionRefused(f"tool {tool!r} did not attempt the effect: {exc}") from exc
                raise _unknown(exc) from exc

        try:
            # `approved` is passed only when set, so a gate double that predates
            # the keyword keeps working; a real gate treats absence as False.
            outcome, result = self._gate.run_if_allowed(
                payload=payload,
                trust=trust,
                action=_bound_effect,
                **({"approved": True} if approved else {}),
                **({"tenant_id": control_tenant, "parameters": request.parameters}
                   if isinstance(self._gate, ProtectGate) else {}),
            )
        except ProtectDenied as denied:
            self._controls.record_failure(agent_id=str(agent_id), tenant_id=control_tenant)
            _record_refusal(f"protect: {denied.outcome.decision.value}: {denied.outcome.reason}")
            raise ToolExecutionRefused(
                f"tool {tool!r} refused by protect: {denied.outcome.decision.value}"
            ) from denied
        except OutcomeUnknown:
            raise
        except ToolExecutionRefused:
            self._controls.record_failure(agent_id=str(agent_id), tenant_id=control_tenant)
            raise
        except DomainRuleViolated as violated:
            self._controls.record_failure(agent_id=str(agent_id), tenant_id=control_tenant)
            raise ToolExecutionRefused(
                f"tool {tool!r} refused the effect: {violated}"
            ) from violated
        except Exception as exc:  # noqa: BLE001 - evaluation must not fail open
            self._controls.record_failure(agent_id=str(agent_id), tenant_id=control_tenant)
            if self._gate.enforce:
                raise ToolExecutionRefused(
                    f"protect evaluation failed under enforcement; "
                    f"refusing tool {tool!r} (fail closed)"
                ) from exc
            raise

        try:
            self._controls.record_success(agent_id=str(agent_id), tenant_id=control_tenant)
            verdict = verdict_box["verdict"]
            completed_at = _clock_now().isoformat()
            receipt = ExecutionReceipt(
                receipt_id=f"receipt-{authorization.authorization_id}",
                tenant_id=request.tenant_id,
                authorization_digest=authorization.digest,
                executed_request_digest=digest_of(_request_document(request)),
                actual_parameter_digest=verdict.actual_parameter_digest,
                execution_identity=str(agent_id),
                started_at=marks["started_at"] or started,
                completed_at=completed_at,
                outcome="succeeded",
                result_digest=_result_digest(result),
                side_effect=str(tool),
                bounded_mutations=verdict.bounded_mutations,
            )
            # DURABLE OUTCOME, or an honest "unknown". The effect has happened. If
            # its receipt or its terminal state cannot be recorded, the caller must
            # NOT receive a plain result -- a success with no record behind it is a
            # success the evidence cannot see. The operation stays `pending`, the
            # reaper moves it to `unknown_after_effect`, and the caller gets the
            # operation id to reconcile against.
            if request.tenant_id and (self._receipts is not None or marks["intent_recorded"]):
                try:
                    if self._receipts is not None:
                        self._receipts.record(
                            request.tenant_id,
                            receipt=receipt,
                            approved_parameter_digest=authorization.approved_parameter_digest,
                            authorization_id=authorization.authorization_id,
                            delegation_passport_digest=delegation_passport_digest,
                        )
                    if marks["intent_recorded"]:
                        settled = self._operations.complete(
                            request.tenant_id,
                            operation_id,
                            state=OperationState.SUCCEEDED,
                            completed_at=completed_at,
                            receipt_id=receipt.receipt_id,
                            result_digest=receipt.result_digest,
                        )
                        if not settled:
                            raise RuntimeError(
                                "the operation was no longer pending when its outcome "
                                "was recorded; another writer decided it"
                            )
                except Exception as exc:  # noqa: BLE001 - the effect happened; say so honestly
                    raise _unknown(exc) from exc
            return outcome, result, receipt
        except OutcomeUnknown:
            raise
        except Exception as exc:
            raise _unknown(exc) from exc
