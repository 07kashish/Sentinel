"""Extra HTTP routes: tools proxy, SCIM, org, console static.

Registered from create_app so http.py stays the composition point for the ASGI
app while these routes live in a dedicated module.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from fastapi import Depends, FastAPI, HTTPException, Response, status
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field, model_validator

from sentinel.application.bypass_detection import detect_possible_bypasses
from sentinel.domain.inventory import AgentClassification, ObservedEdgeKind
from sentinel.domain.sequences import detect_sequences
from sentinel.application.tool_proxy import ToolProxyRefused
from sentinel.composition.container import Container
from sentinel.domain.authorization import Capability
from sentinel.infrastructure.directory import DirectoryError
from sentinel.infrastructure.orgs import OrgError
from sentinel.application.commands.manage_containment import (
    ActivateContainment,
    LiftContainment,
)
from sentinel.infrastructure.persistence.audit import Outcome
from sentinel.application.tool_runner import ControlStateRefused
from sentinel.domain.operations import OutcomeUnknown
from sentinel.interface.authorizations import check_still_redeemable, resolve_or_refuse
from sentinel.interface.http_models import ContainmentRequest, refuse_trust_level
from sentinel.interface.principals import require_agent_identity

CONSOLE_DIR = Path(__file__).resolve().parent / "console"
CONSOLE_CSP = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "connect-src 'self'; "
    "img-src 'self' data:; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "require-trusted-types-for 'script'; "
    "trusted-types sentinel-console"
)


class ToolExecutePayload(BaseModel):
    """A tool to run. NOTE WHAT IS ABSENT: `trustLevel`.

    `authorization` is the token `POST /v1/protect/evaluate` issued. It is what
    binds this execution to the decision that permitted it: the proxy
    recomputes the digest of `arguments` immediately before the tool runs and
    refuses on any difference from what was authorized.
    """

    agentId: str = Field(min_length=1, max_length=128)
    tool: str = Field(min_length=1, max_length=128)
    arguments: Mapping[str, Any] = Field(default_factory=dict)
    resource: str = Field(default="", max_length=2048)
    action: str = Field(default="", max_length=8192)
    metadata: Mapping[str, Any] = Field(default_factory=dict)
    authorization: str | None = Field(default=None, max_length=512)

    @model_validator(mode="before")
    @classmethod
    def _no_asserted_trust(cls, data: Any) -> Any:
        return refuse_trust_level(data)


class ScimUserPayload(BaseModel):
    userName: str = Field(min_length=3, max_length=320)
    displayName: str = Field(default="", max_length=256)
    externalId: str = Field(default="", max_length=256)
    active: bool = True
    roles: list[dict[str, Any]] = Field(default_factory=list)


class OrgCreatePayload(BaseModel):
    name: str = Field(min_length=1, max_length=256)


def register_extra_routes(
    app: FastAPI,
    container: Container,
    *,
    authenticate,
    require,
) -> None:
    """Attach tool proxy, SCIM, org, and console routes."""

    @app.post("/v1/tools/execute")
    def tools_execute(
        payload: ToolExecutePayload,
        principal=Depends(require(Capability.EXECUTE_TOOL)),
    ):
        """ONLY sanctioned remote tool side-effect path (F-11 inline proxy).

        BOUND when `authorization` is presented: the token is resolved under
        the principal's tenant to the authorization `/v1/protect/evaluate`
        stored, and the proxy runs `execute_bound` against the shared nonce
        ledger. Without one, the unbound path -- which the runner refuses
        outright when `SENTINEL_REQUIRE_EXECUTION_BINDING` is set, and it is
        set by default.
        """
        tenant = str(principal.tenant)
        require_agent_identity(principal, payload.agentId, container=container)
        # The global kill switch is answered FIRST, before the caller is told
        # to go and fetch an authorization. The runner refuses under it too,
        # but a caller who could not have executed anything should not be sent
        # on a round trip to `/v1/protect/evaluate` to find that out.
        if container.settings.protect_kill_switch:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail=(
                    "refused: the protect kill switch is engaged for this "
                    "deployment; no tool side effect runs until it is released"
                ),
            )
        authorization = None
        approved = False
        if payload.authorization:
            stored = resolve_or_refuse(
                container, tenant=tenant, token=payload.authorization
            )
            # STILL redeemable NOW, not merely when issued: the policy digest it
            # was evaluated under must be the tenant's current one, the window
            # must be open, and no emergency deny may have landed since.
            check_still_redeemable(
                container, tenant=tenant, stored=stored,
                now=container.clock.now().value,
            )
            authorization = stored.authorization
            # A human activated it. That satisfies a require_approval verdict
            # at execution time; it never satisfies a block.
            approved = bool(stored.approved_by)
        elif container.settings.require_execution_binding:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail=(
                    "an `authorization` token is required: this deployment "
                    "binds every execution to the decision that permitted it. "
                    "Obtain one from POST /v1/protect/evaluate with the same "
                    "tool, action, resource and arguments, then present it here."
                ),
            )
        try:
            return container.tool_proxy.execute(
                agent_id=payload.agentId,
                tool=payload.tool,
                # From the credential, never the body.
                trust=principal.trust,
                # Tenant comes from the AUTHENTICATED PRINCIPAL, never the body.
                # Capability grants are scoped per tenant, so a tenant field a
                # caller could set would let one tenant's grants authorise
                # another tenant's agent -- the same reason `/v1/mcp/evaluate`
                # takes its tenant from the principal.
                tenant_id=tenant,
                arguments=payload.arguments,
                resource=payload.resource,
                action=payload.action,
                metadata={**dict(payload.metadata), "tenant": tenant},
                authorization=authorization,
                nonces=container.nonces if authorization is not None else None,
                now=container.clock.now().value,
                approved=approved,
            )
        except ToolProxyRefused as exc:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except ControlStateRefused as exc:
            # The shared budget/breaker could not be consulted. Refused, and
            # retryable: 503 rather than 403 so a client does not read an
            # outage as a decision.
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"outcome": "control_state_unavailable", "detail": str(exc)},
                headers={"Retry-After": "5"},
            ) from exc
        except OutcomeUnknown as exc:
            # THE EFFECT HAPPENED and its outcome could not be recorded. Never
            # a 200 -- a result with no record behind it is a success the
            # evidence cannot see -- and never a 403, which would invite a
            # retry of an action that may already have run. 500 with the
            # operation id, so the caller reconciles rather than repeats.
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "outcome": "unknown_after_effect",
                    "operation_id": exc.operation_id,
                    "detail": str(exc),
                    "reconcile": f"POST /v1/executions/operations/{exc.operation_id}/reconcile",
                },
            ) from exc

    @app.get("/v1/protect/bypass-signals")
    def protect_bypass_signals(
        principal=Depends(require(Capability.READ_DIAGNOSTICS)),
    ):
        """Loud silence signals for enrolled agents (F-11 residual visibility).

        Not network interception: only agents Sentinel already knows about, that
        have produced no observed events within the configured idle window.
        """
        now = container.clock.now()
        signals = detect_possible_bypasses(
            agents=container.agents.list_activity(principal.tenant),
            now=now,
            idle_threshold_seconds=container.settings.bypass_idle_seconds,
        )
        return {
            "idle_threshold_seconds": container.settings.bypass_idle_seconds,
            "signals": [s.as_dict() for s in signals],
            "caveat": (
                "Sentinel cannot see traffic that bypasses /v1/events, "
                "/v1/tools/execute, or the SDK interceptor"
            ),
        }

    # ── Inventory: who is actually talking to us ────────────────────────────

    @app.get("/v1/inventory/agents")
    def inventory_agents(
        classification: str | None = None,
        principal=Depends(require(Capability.READ_INCIDENT)),
    ):
        """Every agent SEEN, managed or not.

        `READ_INCIDENT` rather than a new capability: this is the same class of
        information an incident already discloses -- which agents exist and what
        they touched -- so inventing a separate capability would let a role read
        an incident naming an agent while being refused the agent's profile.

        Read-only. Declaring metadata stays on the CLI with enrolment and
        grants, because it is an assertion about an agent's ownership and this
        codebase guards assertions with shell access rather than a bearer token.
        """
        wanted = None
        if classification:
            try:
                wanted = AgentClassification(classification.strip().lower())
            except ValueError as exc:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    detail=(
                        f"unknown classification {classification!r}; valid: "
                        + ", ".join(c.value for c in AgentClassification)
                    ),
                ) from exc

        profiles = container.inventory.list_profiles(
            str(principal.tenant), classification=wanted
        )
        return {
            "agents": [p.as_dict() for p in profiles],
            "total": len(profiles),
            # Counted separately so a caller does not have to re-derive it, and
            # because "how many agents nobody enrolled" is the single number
            # this endpoint exists to surface.
            "needs_attention": sum(
                1 for p in profiles if p.classification.needs_attention
            ),
        }

    @app.get("/v1/inventory/agents/{agent_id}")
    def inventory_agent(
        agent_id: str,
        principal=Depends(require(Capability.READ_INCIDENT)),
    ):
        """One agent's profile, or 404 if nothing has ever been seen from it.

        404 rather than an empty profile: an agent that has never sent an event
        does not exist as far as this product is concerned, and returning a
        hollow record for any string a caller invents would make the inventory
        unable to distinguish a real quiet agent from a typo.
        """
        profile = container.inventory.profile(str(principal.tenant), agent_id)
        if profile is None:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                detail=f"no agent {agent_id!r} has been observed",
            )
        return profile.as_dict()

    @app.get("/v1/inventory/reach")
    def inventory_reach(
        kind: str,
        pattern: str,
        principal=Depends(require(Capability.READ_INCIDENT)),
    ):
        """Which agents reached targets matching a pattern.

        The attack-surface question, parameterised. Sentinel does not know which
        of an estate's tables hold PII or which host is production, so the
        caller supplies the pattern -- answering a security question with a
        built-in guess would be worse than declining to answer it.
        """
        try:
            edge_kind = ObservedEdgeKind(kind.strip().lower())
        except ValueError as exc:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"unknown edge kind {kind!r}; valid: "
                    + ", ".join(k.value for k in ObservedEdgeKind)
                ),
            ) from exc

        if not pattern.strip():
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, detail="pattern is required"
            )
        if len(pattern) > 512:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, detail="pattern is too long"
            )

        agents = container.inventory.agents_reaching(
            str(principal.tenant), kind=edge_kind, pattern=pattern
        )
        return {"kind": edge_kind.value, "pattern": pattern, "agents": list(agents)}


    # ── Execution graph: one security story ─────────────────────────────────

    @app.get("/v1/graph/sessions/{session_id}")
    def graph_session(
        session_id: str,
        principal=Depends(require(Capability.READ_INCIDENT)),
    ):
        """The causal trace for one session, with any sequence findings.

        `READ_INCIDENT`: this is the evidence behind an incident, and a role
        that can read the incident but not the trace it rests on would be able
        to see a conclusion without its reasoning.
        """
        graph = container.execution_graph.session(str(principal.tenant), session_id)
        if not len(graph):
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                detail=f"no session {session_id!r} has been observed",
            )
        matches = detect_sequences(graph)
        return {
            **graph.as_dict(),
            "sequence_findings": [m.as_dict() for m in matches],
            # Roots are reported because a session with several is a session
            # whose chain is broken -- steps arrived without the parent that
            # explains them, and a reader should see that rather than assume a
            # single tidy story.
            "roots": [n.event_id for n in graph.roots()],
        }

    @app.get("/v1/graph/coverage")
    def graph_coverage(
        principal=Depends(require(Capability.READ_INCIDENT)),
    ):
        """How much of this tenant's activity is actually traceable.

        A graph over 3% of events looks identical to one over 100% until
        somebody asks, and a causal trace assembled from a fraction of the
        steps is not a trace. This is the number that says which it is.
        """
        coverage = container.execution_graph.coverage(str(principal.tenant))
        return {
            **coverage.as_dict(),
            "note": (
                "unlinked nodes are events that arrived without a sessionId. "
                "They are recorded but cannot be placed in a causal chain."
            ),
        }

    @app.get("/v1/agents/{agent_id}/baseline")
    def agent_baseline(
        agent_id: str,
        principal=Depends(require(Capability.READ_INCIDENT)),
    ):
        """What this agent has usually done, derived from retained history.

        `established` is the field that matters. An agent with too little
        history has no usual behaviour, and reporting a baseline without
        saying so would let a reader treat "we have barely seen this agent" as
        "this agent looks normal" -- which is exactly backwards for one an
        attacker introduced yesterday.
        """
        baseline = container.execution_graph.baseline_for(
            str(principal.tenant), agent_id
        )
        return {
            **baseline.as_dict(),
            "note": (
                "derived from retained execution nodes, which the retention "
                "sweep reaps on age -- so this narrows as history ages out"
            ),
        }


    # ── SCIM 2.0 (Users) ────────────────────────────────────────────────────

    @app.get("/scim/v2/Users")
    def scim_list_users(
        startIndex: int = 1,
        count: int = 50,
        principal=Depends(require(Capability.MANAGE_USERS)),
    ):
        users = container.directory.list_users(
            principal.tenant, start=startIndex, count=count
        )
        resources = [u.as_scim() for u in users]
        return {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": len(resources),
            "startIndex": startIndex,
            "itemsPerPage": len(resources),
            "Resources": resources,
        }

    @app.post("/scim/v2/Users", status_code=status.HTTP_201_CREATED)
    def scim_create_user(
        payload: ScimUserPayload,
        principal=Depends(require(Capability.MANAGE_USERS)),
    ):
        role = "viewer"
        if payload.roles:
            role = str(payload.roles[0].get("value") or "viewer")
        try:
            user = container.directory.create(
                principal.tenant,
                email=payload.userName,
                display_name=payload.displayName,
                role=role,
                external_id=payload.externalId,
                at=container.clock.now(),
                active=payload.active,
            )
        except DirectoryError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        return user.as_scim()

    @app.get("/scim/v2/Users/{user_id}")
    def scim_get_user(
        user_id: str, principal=Depends(require(Capability.MANAGE_USERS))
    ):
        user = container.directory.get(principal.tenant, user_id)
        if user is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="user not found")
        return user.as_scim()

    @app.put("/scim/v2/Users/{user_id}")
    def scim_replace_user(
        user_id: str,
        payload: ScimUserPayload,
        principal=Depends(require(Capability.MANAGE_USERS)),
    ):
        role = None
        if payload.roles:
            role = str(payload.roles[0].get("value") or "viewer")
        try:
            user = container.directory.replace(
                principal.tenant,
                user_id,
                email=payload.userName,
                display_name=payload.displayName,
                role=role,
                active=payload.active,
                at=container.clock.now(),
            )
        except DirectoryError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        return user.as_scim()

    @app.delete("/scim/v2/Users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
    def scim_deactivate_user(
        user_id: str, principal=Depends(require(Capability.MANAGE_USERS))
    ):
        try:
            container.directory.deactivate(
                principal.tenant, user_id, at=container.clock.now()
            )
        except DirectoryError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    # ── Organization APIs ───────────────────────────────────────────────────

    @app.post("/v1/orgs", status_code=status.HTTP_201_CREATED)
    def create_org(
        payload: OrgCreatePayload,
        principal=Depends(require(Capability.MANAGE_USERS)),
    ):
        try:
            org = container.orgs.create_org(
                principal.tenant, name=payload.name, at=container.clock.now()
            )
        except OrgError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        return org.as_dict()

    @app.get("/v1/orgs/current")
    def get_org(principal=Depends(require(Capability.MANAGE_USERS))):
        org = container.orgs.get_org(principal.tenant)
        if org is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="no organization")
        return org.as_dict()

    @app.get("/v1/orgs/current/members")
    def list_org_members(principal=Depends(require(Capability.MANAGE_USERS))):
        users = container.directory.list_users(principal.tenant, start=1, count=200)
        members = container.orgs.list_members_from_directory(principal.tenant, users)
        return {"members": [m.as_dict() for m in members]}

    # ── Analyst console (Phase 13) ──────────────────────────────────────────

    @app.get("/console", response_class=HTMLResponse)
    def console_index():
        html_path = CONSOLE_DIR / "index.html"
        if not html_path.exists():
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="console missing")
        body = html_path.read_text(encoding="utf-8")
        return HTMLResponse(
            content=body,
            headers={
                "Content-Security-Policy": CONSOLE_CSP,
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Cache-Control": "no-store",
            },
        )

    @app.get("/console/app.js")
    def console_js():
        path = CONSOLE_DIR / "app.js"
        return FileResponse(
            path,
            media_type="application/javascript",
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )

    @app.get("/console/app.css")
    def console_css():
        path = CONSOLE_DIR / "app.css"
        return FileResponse(
            path,
            media_type="text/css",
            headers={"Cache-Control": "no-store"},
        )

    # ── Containment: the granular kill switch (section 35) ───────────────────

    @app.post("/v1/containments", status_code=status.HTTP_201_CREATED)
    def contain(
        body: ContainmentRequest,
        principal=Depends(require(Capability.MANAGE_CONTAINMENT)),
    ):
        """Stop an agent, a group, a tool, an MCP server or a credential.

        Audited unconditionally, like approvals and for the same reason: this is
        the other action that changes what happens outside this system. "Who
        stopped production at 03:14, and why" is asked immediately and cannot be
        answered by a log line that has since rotated.
        """
        result = container.commands.dispatch(
            ActivateContainment(
                tenant=principal.tenant,
                scope=body.scope,
                selector=body.selector,
                created_by=f"key:{principal.key_hash[:12]}",
                reason=body.reason,
                expires_at=body.expiresAt,
            )
        )
        container.security_audit.record(
            tenant=principal.tenant,
            actor=f"key:{principal.key_hash[:12]}",
            action="containment.activate",
            resource_type="containment",
            resource_id=str(result.detail.get("containment_id", "")),
            outcome=Outcome.SUCCESS if result.ok else Outcome.FAILED,
            detail={
                "result": result.outcome,
                "role": principal.role,
                "scope": body.scope,
                "selector": body.selector,
            },
        )
        if not result.ok:
            # 400, not 409. A rejected scope or a missing selector is a malformed
            # request, not a conflict with existing state.
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail={"outcome": result.outcome, **dict(result.detail)},
            )
        return {"outcome": result.outcome, **dict(result.detail)}

    @app.delete("/v1/containments/{containment_id}")
    def lift(
        containment_id: str,
        principal=Depends(require(Capability.MANAGE_CONTAINMENT)),
    ):
        """Lift a containment. The record survives; only its effect stops."""
        result = container.commands.dispatch(
            LiftContainment(
                tenant=principal.tenant,
                containment_id=containment_id,
                revoked_by=f"key:{principal.key_hash[:12]}",
            )
        )
        container.security_audit.record(
            tenant=principal.tenant,
            actor=f"key:{principal.key_hash[:12]}",
            action="containment.lift",
            resource_type="containment",
            resource_id=containment_id,
            outcome=Outcome.SUCCESS if result.ok else Outcome.FAILED,
            detail={"result": result.outcome, "role": principal.role},
        )
        if not result.ok:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                detail={"outcome": result.outcome, **dict(result.detail)},
            )
        return {"outcome": result.outcome, **dict(result.detail)}
