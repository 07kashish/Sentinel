"""Issue, redeem and approve execution authorizations over HTTP.

WHAT MAKES THE FLAGSHIP CAPABILITY REACHABLE
--------------------------------------------
`execute_bound` existed and nothing over the wire could reach it: no route
issued an `ExecutionAuthorization`, so no caller could present one, so every
HTTP execution took the unbound path -- the one the binding exists to close.
This module is the seam between the two:

  * `issue_for_outcome` turns a protect verdict into a stored authorization
    and the opaque token that redeems it. Called by `/v1/protect/evaluate`
    and, inline, by the MCP wire proxy.
  * `resolve_or_refuse` turns a presented token back into the stored
    authorization under the CALLER'S tenant, refusing by name when it is
    unknown, pending or revoked. Called by `/v1/tools/execute`.
  * the approval routes are the human decision a `require_approval` verdict
    asked for: a `DECIDE_APPROVAL` holder activates or refuses a pending
    authorization, audited either way.

WHY THE TENANT ON THE LOOKUP IS THE PRINCIPAL'S
------------------------------------------------
A token names an authorization id and a secret. The store is queried under the
authenticated tenant with an explicit predicate, so a token issued to one
tenant is simply not found when presented by another -- there is no field in
the request that could redirect the lookup.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timezone
from typing import Any, Mapping

from fastapi import Depends, FastAPI, HTTPException, Query, status

from sentinel.domain.authorization import Capability
from sentinel.domain.primitives import TenantId
from sentinel.domain.change_summary import summarise_change
from sentinel.domain.execution_binding import (
    ExecutionAuthorization,
    issue_authorization,
)
from sentinel.domain.protect import ProtectDecision, ProtectOutcome
from sentinel.infrastructure.persistence.audit import Outcome
from sentinel.infrastructure.sql.authorization_store import (
    STATE_ACTIVE,
    STATE_PENDING_APPROVAL,
    STATE_REVOKED,
    StoredAuthorization,
)
from sentinel.interface.http_models import ApprovalDecision

__all__ = [
    "issue_for_outcome",
    "register_authorization_routes",
    "resolve_or_refuse",
    "state_for",
]


def state_for(outcome: ProtectOutcome) -> str | None:
    """Which lifecycle state a verdict issues into, or None for no issuance.

    `allow` and its variants that let the action proceed are ACTIVE.
    `require_approval` is PENDING: the authorization exists so the approved
    parameters and the executed parameters are one committed object, and it
    redeems for nothing until a human activates it. Anything that stops the
    action issues nothing -- an authorization for a blocked call would be a
    document that says "no" and looks like one that says "yes".
    """
    decision = outcome.decision
    if decision is ProtectDecision.REQUIRE_APPROVAL:
        return STATE_PENDING_APPROVAL
    if decision.stops_action:
        return None
    return STATE_ACTIVE


def issue_for_outcome(
    container: Any,
    *,
    tenant: str,
    actor: str,
    outcome: ProtectOutcome,
    agent_id: str,
    tool: str,
    action: str,
    resource: str,
    parameters: Mapping[str, Any],
    mcp_server: str = "",
    delegation_passport_digest: str = "",
) -> tuple[ExecutionAuthorization, str, str] | None:
    """Issue and store an authorization for a verdict, or None when it cannot.

    Returns `(authorization, token, state)`. None when the verdict stops the
    action or the payload named no tool -- there is nothing to bind an
    execution to without one, and an authorization with an empty tool
    identity is refused by the domain anyway.
    """
    state = state_for(outcome)
    if state is None or not str(tool or "").strip():
        return None
    authorization = issue_authorization(
        # The policy this verdict was produced under. Redemption compares it
        # to the tenant's CURRENT digest and refuses on any difference: an
        # approval given under one policy is not an approval under the next.
        policy_bundle_digest=active_policy_digest(container, tenant),
        authorization_id=f"auth-{secrets.token_urlsafe(12)}",
        nonce=secrets.token_urlsafe(24),
        tenant_id=tenant,
        actor_identity=actor,
        agent_identity=agent_id,
        tool_identity=tool,
        action=action or tool,
        target_resource=resource,
        parameters=parameters,
        now=container.clock.now().value,
        policy_decision=outcome.decision.value,
        mcp_server_identity=mcp_server,
        delegation_passport_digest=delegation_passport_digest,
        conditions={
            "severity": outcome.severity,
            "capped_severity": outcome.capped_severity,
            "matched_rules": list(outcome.matched_rules),
            "reason": outcome.reason,
            # The approver's view: structure, impact and target precondition,
            # with every secret-bearing value redacted. Computed here, from
            # the parameters the digest commits to, and never again.
            "change": summarise_change(
                tool=tool, action=action or tool, resource=resource, parameters=parameters
            ),
        },
    )
    token = container.authorizations.issue(authorization, state=state)
    return authorization, token, state


def authorization_response(
    authorization: ExecutionAuthorization, *, token: str, state: str
) -> dict[str, Any]:
    """The `authorization` object a response carries: the token and its fields.

    The fields are served alongside the token so a caller can see what it was
    bound to WITHOUT decoding anything, and so a mismatch between what the
    agent intended and what was authorized is visible before execution.
    """
    return {
        "token": token,
        "state": state,
        **authorization.as_document(),
        "digest": authorization.digest,
        "note": (
            "single-use. Present `token` as `authorization` on "
            "POST /v1/tools/execute with the SAME tool, action, resource and "
            "arguments; anything that differs is refused before the tool runs."
            + (
                " This authorization is PENDING: a decide_approval holder must "
                "approve it at POST /v1/authorizations/{id}/decide first."
                if state == STATE_PENDING_APPROVAL
                else ""
            )
        ),
    }


def active_policy_digest(container: Any, tenant: str) -> str:
    """The digest of the policy this tenant is evaluated under right now.

    Both the deterministic rule contents and the activated tenant policy are
    included. Version labels alone cannot identify a security policy. Existing
    v1 approvals are intentionally invalidated by this v2 binding.
    """
    with container.uow_factory.begin(TenantId(tenant)) as uow:
        active = uow.policies.active()
        uow.commit()
    material = {
        "schema": "sentinel.enforcement-policy/v2",
        "deterministic": container.protect_gate.policy_digest,
        "tenant_policy": active.digest if active is not None else None,
    }
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def check_still_redeemable(
    container: Any, *, tenant: str, stored: StoredAuthorization, now: datetime
) -> None:
    """Refuse an ACTIVE authorization that the world has moved past.

    `resolve_or_refuse` answers "is this token one we issued, and is it
    active". This answers the questions that arise AFTER activation and
    before the effect:

      * the policy changed -- an approval given under one ruleset does not
        carry over to the next, whether the change tightened or loosened it;
      * the window closed -- checked again here so the refusal names expiry
        rather than surfacing as a generic binding defect;
      * an emergency deny landed -- the deployment kill switch. Containment
        and revocation are checked by the runner and the store respectively.

    Expiry and the binding checks are repeated inside `verify_binding`
    immediately before the effect; this is the early, explicit refusal, not
    the only one.
    """
    authorization = stored.authorization
    current = active_policy_digest(container, tenant)
    if authorization.policy_bundle_digest and authorization.policy_bundle_digest != current:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail={
                "outcome": "policy_changed",
                "authorization_id": authorization.authorization_id,
                "detail": (
                    "the tenant's policy changed after this authorization was "
                    "issued; it is void. Ask POST /v1/protect/evaluate again "
                    "under the current policy."
                ),
            },
        )
    expires_at = datetime.fromisoformat(authorization.expires_at)
    if now.astimezone(timezone.utc) >= expires_at.astimezone(timezone.utc):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={
                "outcome": "expired",
                "authorization_id": authorization.authorization_id,
                "detail": "this authorization's window has closed; nothing ran",
            },
        )
    if container.settings.protect_kill_switch:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={
                "outcome": "kill_switch",
                "detail": (
                    "the protect kill switch is engaged; no authorization is "
                    "redeemable until it is released"
                ),
            },
        )


def resolve_or_refuse(
    container: Any, *, tenant: str, token: str
) -> StoredAuthorization:
    """The stored authorization a token redeems, or a 403 naming why not."""
    stored = container.authorizations.resolve(tenant, token)
    if stored is None:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail=(
                "the presented authorization is not one this tenant issued, or "
                "its secret does not match. Obtain one from "
                "POST /v1/protect/evaluate."
            ),
        )
    if stored.state == STATE_PENDING_APPROVAL:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail=(
                f"authorization {stored.authorization.authorization_id!r} is "
                "awaiting approval and redeems for nothing until a "
                "decide_approval holder activates it"
            ),
        )
    if stored.state == STATE_REVOKED:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail=(
                f"authorization {stored.authorization.authorization_id!r} was "
                "refused by an approver"
            ),
        )
    if stored.state != STATE_ACTIVE:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail=f"authorization is in state {stored.state!r}, not active",
        )
    return stored


def _approval_refusal(
    container: Any, tenant: str, stored: Any, actor: str
) -> tuple[int, dict[str, Any]] | None:
    """Why this approver may not approve this authorization now, or None.

    An approval that could never be redeemed is refused rather than recorded:
    telling a human they approved something that is already expired, or was
    judged under a policy that has since changed, is how approvals become a
    ritual. They are told to ask for a fresh evaluation instead.
    """
    authorization = stored.authorization
    if container.settings.workflow.approval_separation_of_duties and actor == authorization.actor_identity:
        return status.HTTP_403_FORBIDDEN, {
            "outcome": "separation_of_duties",
            "detail": "the requester of an authorization may not approve it; another approver must decide",
        }
    now = container.clock.now().value.astimezone(timezone.utc)
    if now >= datetime.fromisoformat(authorization.expires_at).astimezone(timezone.utc):
        return status.HTTP_409_CONFLICT, {
            "outcome": "expired",
            "detail": "this request expired before it was approved; the agent must ask again",
        }
    digest = authorization.policy_bundle_digest
    if digest and digest != active_policy_digest(container, tenant):
        return status.HTTP_409_CONFLICT, {
            "outcome": "policy_changed",
            "detail": "the policy changed after this request was evaluated; it must be evaluated again",
        }
    return None


def approver_view(
    stored: Any, *, current_policy: str, now: datetime, quorum: int
) -> dict[str, Any]:
    """Everything a human needs to decide, and nothing that is a secret.

    The exact change (redacted), the affected resource, the impact tier, the
    rule that asked for approval, whether the policy it was judged under is
    still current, how long is left, and who has already said yes.
    """
    authorization = stored.authorization
    expires = datetime.fromisoformat(authorization.expires_at).astimezone(timezone.utc)
    conditions = dict(authorization.conditions)
    change = conditions.pop("change", None)
    approvers = [a for a in str(stored.approved_by).split(",") if a]
    pending = stored.state == STATE_PENDING_APPROVAL
    return {
        "authorization_id": authorization.authorization_id,
        "state": stored.state,
        "requester": authorization.actor_identity,
        "agent": authorization.agent_identity,
        "tool": authorization.tool_identity,
        "action": authorization.action,
        "resource": authorization.target_resource,
        "mcp_server": authorization.mcp_server_identity,
        "change": change,
        "why": {
            "policy_decision": authorization.policy_decision,
            "reason": conditions.get("reason", ""),
            "matched_rules": conditions.get("matched_rules", []),
            "severity": conditions.get("capped_severity", conditions.get("severity")),
        },
        "approvals": {
            "required": quorum if pending or approvers else 0,
            "received": len(approvers),
            "approvers": approvers,
            "remaining": max(0, quorum - len(approvers)) if pending else 0,
        },
        "approved_by": stored.approved_by,
        "approved_parameter_digest": authorization.approved_parameter_digest,
        "policy_bundle_digest": authorization.policy_bundle_digest,
        "policy_current": (
            not authorization.policy_bundle_digest
            or authorization.policy_bundle_digest == current_policy
        ),
        "issued_at": authorization.issued_at,
        "expires_at": authorization.expires_at,
        "expires_in_seconds": max(0, int((expires - now).total_seconds())),
        "expired": now >= expires,
        "conditions": conditions,
        "delegation_passport_digest": authorization.delegation_passport_digest,
    }


def register_authorization_routes(app: FastAPI, container: Any, *, require: Any) -> None:
    """The approval decision for a `require_approval` verdict."""

    audit = container.security_audit

    @app.get("/v1/authorizations")
    def list_authorizations(
        state: str = Query(default=STATE_PENDING_APPROVAL),
        limit: int = Query(default=100, ge=1, le=500),
        principal=Depends(require(Capability.READ_INCIDENT)),
    ):
        """The authorization inbox. Pending by default; `state=` for others.

        Separate from the incident-remediation approvals: those are Sentinel
        proposing an action against the estate, these are an AGENT asking to
        act. Never returns tokens.
        """
        if state and state not in {STATE_ACTIVE, STATE_PENDING_APPROVAL, STATE_REVOKED}:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"unknown state {state!r}; valid: {STATE_PENDING_APPROVAL}, "
                    f"{STATE_ACTIVE}, {STATE_REVOKED}, or empty for all"
                ),
            )
        tenant = str(principal.tenant)
        current_policy = active_policy_digest(container, tenant)
        now = container.clock.now().value.astimezone(timezone.utc)
        quorum = container.settings.workflow.approval_quorum
        entries = [
            approver_view(stored, current_policy=current_policy, now=now, quorum=quorum)
            for stored in container.authorizations.list(tenant, state=state, limit=limit)
        ]
        return {
            "authorizations": entries,
            "count": len(entries),
            "policy_digest": current_policy,
            "approval_quorum": quorum,
            "separation_of_duties": container.settings.workflow.approval_separation_of_duties,
            "note": (
                "`change` lists every field of the request with secret-bearing "
                "values redacted; the digest commits to the exact values. Sentinel "
                "stores the structure and the digest so that evidence never carries "
                "secrets. What executes is refused unless it matches the digest."
            ),
        }

    @app.get("/v1/authorizations/{authorization_id}")
    def get_authorization(
        authorization_id: str,
        principal=Depends(require(Capability.READ_INCIDENT)),
    ):
        """One authorization as an approver needs to see it. Never the token."""
        tenant = str(principal.tenant)
        stored = container.authorizations.get(tenant, authorization_id)
        if stored is None:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                detail=f"no authorization {authorization_id!r} for this tenant",
            )
        return approver_view(
            stored,
            current_policy=active_policy_digest(container, tenant),
            now=container.clock.now().value.astimezone(timezone.utc),
            quorum=container.settings.workflow.approval_quorum,
        )

    @app.post("/v1/authorizations/{authorization_id}/revoke")
    def revoke_authorization(
        authorization_id: str,
        body: ApprovalDecision,
        principal=Depends(require(Capability.MANAGE_POLICY)),
    ):
        """Emergency deny. Voids an authorization in ANY state, including active.

        `MANAGE_POLICY`, not `DECIDE_APPROVAL`: an approver may decline to
        activate, but only whoever sets policy may withdraw an authorization
        that was already granted -- that is a policy act, and it is audited
        as one. Idempotent: revoking a revoked authorization is a no-op that
        still reports success, because the caller's intent is satisfied.
        """
        tenant = str(principal.tenant)
        actor = f"key:{principal.key_hash[:12]}"
        store = container.authorizations
        existing = store.get(tenant, authorization_id)
        if existing is None:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                detail=f"no authorization {authorization_id!r} for this tenant",
            )
        was = existing.state
        if was != STATE_REVOKED:
            store.revoke(tenant, authorization_id)
        audit.record(
            tenant=principal.tenant,
            actor=actor,
            action="authorization.revoke",
            resource_type="execution_authorization",
            resource_id=authorization_id,
            outcome=Outcome.SUCCESS,
            detail={"from_state": was, "role": principal.role, "reason": body.reason},
        )
        return {
            "outcome": "revoked",
            "authorization_id": authorization_id,
            "previous_state": was,
            "state": STATE_REVOKED,
        }

    @app.post("/v1/authorizations/{authorization_id}/decide")
    def decide_authorization(
        authorization_id: str,
        body: ApprovalDecision,
        principal=Depends(require(Capability.DECIDE_APPROVAL)),
    ):
        """Activate or refuse a pending authorization.

        `DECIDE_APPROVAL`, the same capability as the remediation approval
        route, because it is the same decision: a human agreeing that an
        action the policy would not allow on its own may proceed. Audited on
        both outcomes for the same reason that route is.
        """
        tenant = str(principal.tenant)
        actor = f"key:{principal.key_hash[:12]}"
        store = container.authorizations
        existing = store.get(tenant, authorization_id)
        if existing is None:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                detail=f"no authorization {authorization_id!r} for this tenant",
            )
        workflow = container.settings.workflow
        approvers: tuple[str, ...] = ()
        if body.decision == "approve":
            refusal = _approval_refusal(container, tenant, existing, actor)
            if refusal is not None:
                audit.record(
                    tenant=principal.tenant, actor=actor, action="authorization.approve",
                    resource_type="execution_authorization", resource_id=authorization_id,
                    outcome=Outcome.DENIED, detail={"refused": refusal[1]["outcome"], "role": principal.role},
                )
                raise HTTPException(refusal[0], detail=refusal[1])
            try:
                recorded = store.record_approval(
                    tenant, authorization_id, approver=actor, quorum=workflow.approval_quorum
                )
            except ValueError as exc:
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    detail={"outcome": "already_approved_by_you", "detail": str(exc)},
                ) from exc
            ok = recorded is not None
            result_state, approvers = recorded if recorded else (existing.state, ())
        else:
            ok = existing.state == STATE_PENDING_APPROVAL and store.revoke(
                tenant, authorization_id
            )
            result_state = STATE_REVOKED if ok else existing.state
        audit.record(
            tenant=principal.tenant,
            actor=actor,
            action=f"authorization.{body.decision}",
            resource_type="execution_authorization",
            resource_id=authorization_id,
            outcome=Outcome.SUCCESS if ok else Outcome.FAILED,
            detail={
                "state": result_state,
                "role": principal.role,
                "reason": body.reason,
                "approvers": list(approvers),
                "quorum": workflow.approval_quorum,
            },
        )
        if not ok:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                detail={
                    "outcome": "not_pending",
                    "state": result_state,
                    "detail": (
                        "this authorization is not awaiting a decision; it was "
                        "already decided or was never pending"
                    ),
                },
            )
        if body.decision == "approve" and result_state == STATE_PENDING_APPROVAL:
            outcome_word = "approval_recorded"
        else:
            outcome_word = "approved" if body.decision == "approve" else "refused"
        return {
            "outcome": outcome_word,
            "authorization_id": authorization_id,
            "state": result_state,
            "approvals": {
                "required": workflow.approval_quorum,
                "received": len(approvers),
                "remaining": max(0, workflow.approval_quorum - len(approvers)),
            },
        }
