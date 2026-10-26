"""HTTP delivery. A thin adapter over the command and query buses.

WHAT A ROUTE IS ALLOWED TO DO
-----------------------------
Parse a payload, resolve a principal, dispatch one message, map the result to a
status code. Nothing else. No route constructs a domain object, opens a
transaction, reads configuration, or decides a business rule.

That constraint is the whole reason the predecessor's most serious security
defect is not expressible here. It had six ingest endpoints reaching the same
pipeline, and exactly one of them performed identity verification, replay
defence, deduplication and the unverified-severity cap. The other five called
`build_base_incident(..., severity=event.severity)` with the client's own number,
so an `ingest`-role key -- documented as "write telemetry only" -- could post
`severity: 100` and manufacture a CRITICAL incident.

The cause was that the checks lived in a route rather than in an admission use
case, so writing a new route meant re-deriving the security posture from scratch
and nothing failed when it was got wrong. Here every ingest shape dispatches
`AdmitEvent`, and `tests_arch/test_architecture_rules.py` fails the build if an
interface module ever constructs an `Incident` directly.

The app is BUILT FROM A CONTAINER, not from module globals. `create_app(container)`
is a function; importing this module starts nothing, opens nothing and reads no
environment.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware

from sentinel.application.commands.admit_event import AdmitEvent
from sentinel.application.commands.decide_approval import DecideApproval
from sentinel.application.messages import Result
from sentinel.application.queries.incident_queries import (
    GetIncident,
    GetIncidentHistory,
    GetReport,
    ListIncidents,
    TenantDashboard,
)
from sentinel.composition.container import Container
from sentinel.composition.settings import ApiKey
from sentinel.domain.authorization import Capability, capabilities_for
from sentinel.domain.errors import ExecutionFenceLost, SentinelError, TransientFailure
from sentinel.domain.mcp import McpToolDefinition
from sentinel.domain.primitives import ApprovalId, IncidentId, InvalidValue, TenantId, TrustLevel
from sentinel.infrastructure.observability import correlation_var, new_correlation
from sentinel.infrastructure.persistence.audit import Outcome
from sentinel.interface.principals import (
    principal_from_jwt,
    require_agent_identity,
    tenant_for_jwt,
)
from sentinel.interface.extra_routes import register_extra_routes
from sentinel.interface.mcp_proxy_routes import register_mcp_proxy_routes
from sentinel.interface.a2a_proxy_routes import register_a2a_proxy_routes
from sentinel.interface.analysis_routes import register_analysis_routes
from sentinel.interface.estate_routes import register_estate_routes
from sentinel.interface.transparency_routes import (
    register_transparency_routes,
)
from sentinel.interface.binding_routes import register_binding_routes
from sentinel.interface.operations_routes import register_operations_routes
from sentinel.interface.authorizations import (
    authorization_response,
    issue_for_outcome,
    register_authorization_routes,
)
from sentinel.interface.health_routes import register_health_routes
from sentinel.interface.a2a_routes import (
    register_a2a_routes,
)
from sentinel.interface.policy_routes import register_policy_routes
from sentinel.interface.app_routes import register_app_routes
from sentinel.interface.http_models import (
    SECURITY_HEADERS,
    UNKNOWN_TENANT,
    ApprovalDecision,
    EventPayload,
    Principal,
    McpCallPayload,
    ProtectPayload,
)
from sentinel.interface.console_demo import console_demo_key, register_console_demo
from sentinel.interface.throttle import ThrottlePolicy, install_throttle

__all__ = ["Principal", "create_app"]

_UNKNOWN_TENANT = UNKNOWN_TENANT
_SECURITY_HEADERS = SECURITY_HEADERS


def create_app(container: Container) -> FastAPI:
    """Build the ASGI application around an already-wired container."""
    settings = container.settings

    # The interactive docs and the schema are DISABLED unless a deployment opts
    # in. Proven against the running app before this change: `/docs`, `/redoc` and
    # `/openapi.json` all answered 200 to an unauthenticated caller and disclosed
    # all nine routes with their request shapes. That is free reconnaissance, and
    # Swagger UI additionally loads script from a third-party CDN -- the one
    # browser surface this service has, unauthenticated, with remote script.
    expose_docs = settings.expose_api_docs
    app = FastAPI(
        title="Sentinel",
        version="3.0.0",
        docs_url="/docs" if expose_docs else None,
        redoc_url="/redoc" if expose_docs else None,
        openapi_url="/openapi.json" if expose_docs else None,
    )

    def _tenant_of_credential(digest: str, token: str) -> str | None:
        """The tenant a credential belongs to, for the throttle's bucket choice.

        An API key is a table lookup on its digest. A JWT has no table entry
        -- its tenant is a VERIFIED CLAIM -- so it is verified here, before
        routing, exactly as `authenticate` will verify it again. Without this
        every SSO caller fell into the auth-failure bucket, ten requests a
        minute, throttled as a brute-force attempt for presenting a valid
        credential.
        """
        if digest in settings.api_keys:
            return settings.api_keys[digest].tenant_id
        return tenant_for_jwt(container, token)

    # Validated here, at app creation: a demo key with any role but viewer
    # refuses to start the service rather than be published.
    demo_key = console_demo_key(settings)

    # Registered BEFORE the header middleware so it runs after it in Starlette's
    # reverse order -- which means a 429 still carries the full security header set.
    install_throttle(
        app,
        limiter=container.rate_limiter,
        policy=ThrottlePolicy(
            trusted_proxy_hops=settings.trusted_proxy_hops,
            auth_failures_per_minute=settings.auth_failure_limit_per_minute,
            per_credential_per_minute=settings.credential_limit_per_minute,
            per_address_per_minute=settings.address_limit_per_minute,
        ),
        audit=container.security_audit,
        # Maps a presented credential to its tenant, or None when
        # unrecognised. Passed as a lookup so the throttle needs no knowledge of
        # how credentials are configured.
        tenant_of=lambda digest, token: _tenant_of_credential(digest, token),
        logger=container.logger,
        shared_digests=frozenset({demo_key.digest}) if demo_key is not None else frozenset(),
    )

    @app.middleware("http")
    async def _security_headers(request: Request, call_next) -> Response:
        response = await call_next(request)
        for name, value in _SECURITY_HEADERS.items():
            # `setdefault` semantics: a route that deliberately set something
            # stricter keeps it. Nothing currently does, but silently overwriting
            # a route's own header is the kind of surprise that gets middleware
            # removed rather than fixed.
            if name not in response.headers:
                response.headers[name] = value
        return response

    @app.middleware("http")
    async def _correlation_and_metrics(request: Request, call_next) -> Response:
        """Bind request correlation and record HTTP request metrics."""
        incoming = request.headers.get("x-request-id") or request.headers.get(
            "x-correlation-id"
        )
        corr = new_correlation(
            request_id=incoming,
            worker_shard=str(settings.worker_shard),
        )
        token = correlation_var.set(corr)
        started = time.perf_counter()
        method = request.method if request.method in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"} else "OTHER"
        try:
            # Paths and arbitrary request IDs never enter trace attributes.
            with container.otel.span("http.request", method=method):
                response = await call_next(request)
        finally:
            correlation_var.reset(token)
            route = getattr(request.scope.get("route"), "path", "__unmatched__")
            labels = {"method": method, "path": route}
            container.metrics.inc("sentinel_http_requests_total", labels=labels)
            container.metrics.observe("sentinel_http_request_duration_seconds",
                                      time.perf_counter() - started, labels=labels)
        response.headers["X-Request-Id"] = corr.request_id
        return response

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.cors_origins),
            # NOT credentialed. Authentication here is a bearer token that a
            # caller attaches deliberately; `allow_credentials=True` is for
            # cookies and ambient credentials, and enabling it invites exactly the
            # browser-driven cross-origin request that makes CSRF possible. With
            # this False there is no ambient credential to forge, which is why
            # CSRF is not a live class for this API rather than being mitigated by
            # a token nobody would remember to rotate.
            allow_credentials=False,
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type"],
            max_age=600,
        )

    audit = container.security_audit

    def _audit_denial(
        *, tenant: str, actor: str, action: str, outcome: Outcome, **detail: Any
    ) -> None:
        """Record a refusal in the tamper-evident trail, not only in the log.

        An authentication failure that exists only as a log line is a failure an
        attacker can erase. `tenant` is a string rather than a `TenantId` because
        an unauthenticated caller has no tenant: `_unknown_` is the honest value and
        it keeps the chain for real tenants uncontaminated by guesses.
        """
        audit.record(
            tenant=TenantId(tenant),
            actor=actor,
            action=action,
            resource_type="http_request",
            resource_id=action,
            outcome=outcome,
            detail=detail,
        )

    def authenticate(
        request: Request, authorization: str | None = Header(default=None)
    ) -> Principal:
        """Fail closed. No configuration means no access, never "allow for convenience"."""
        if not settings.api_keys and container.oidc is None:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    "no API keys are configured, so every authenticated request is "
                    "refused. This is deliberate: an unconfigured security service "
                    "must not accept traffic."
                ),
            )
        if not authorization or not authorization.startswith("Bearer "):
            _audit_denial(
                tenant=_UNKNOWN_TENANT,
                actor="anonymous",
                action=f"{request.method} {request.url.path}",
                outcome=Outcome.DENIED,
                reason="missing_bearer_token",
            )
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                detail="missing bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        raw_token = authorization.removeprefix("Bearer ").strip()

        # JWT path: the human OIDC issuer, or an agent identity provider (Okta
        # Agent SSO, Entra Agent ID). Both yield `verified` trust; the agent
        # path also BINDS the agent id. See `principals.py`.
        jwt_principal = principal_from_jwt(
            container,
            raw_token,
            action=f"{request.method} {request.url.path}",
            audit_denial=_audit_denial,
            unknown_tenant=_UNKNOWN_TENANT,
        )
        if jwt_principal is not None:
            return jwt_principal

        if not settings.api_keys:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                detail="invalid API key",
                headers={"WWW-Authenticate": "Bearer"},
            )

        presented = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        # Constant-time over every configured key, with no early exit: breaking
        # out on a match makes the comparison time depend on WHICH key matched.
        matched: ApiKey | None = None
        for digest, binding in settings.api_keys.items():
            if hmac.compare_digest(presented, digest):
                matched = binding
        if matched is None:
            # The actor is the digest PREFIX of the credential that was presented,
            # never the credential. Enough to correlate a brute-force attempt
            # across thousands of requests; not enough to authenticate with.
            _audit_denial(
                tenant=_UNKNOWN_TENANT,
                actor=f"unknown:{presented[:12]}",
                action=f"{request.method} {request.url.path}",
                outcome=Outcome.DENIED,
                reason="unrecognised_credential",
            )
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                detail="invalid API key",
                headers={"WWW-Authenticate": "Bearer"},
            )
        corr = correlation_var.get()
        if corr is not None:
            correlation_var.set(
                new_correlation(
                    request_id=corr.request_id,
                    tenant_id=matched.tenant_id,
                    worker_shard=corr.worker_shard,
                )
            )
        return Principal(
            tenant=TenantId(matched.tenant_id),
            role=matched.role,
            key_hash=matched.key_hash,
            # Resolved ONCE, here. No route re-derives the policy, which is how
            # the previous ordering bug survived: the comparison lived at each
            # call site and every site had to get it right independently.
            capabilities=capabilities_for(matched.role),
            # An API key proves possession of a shared secret, not the
            # identity of the agent it speaks for. UNSIGNED, whatever role.
            trust=TrustLevel.UNSIGNED,
        )

    def require(capability: Capability):
        """Guard a route on a CAPABILITY, never on a role name.

        `require(Capability.INGEST_EVENT)` cannot be satisfied by a viewer, which
        `require("ingest")` could when roles were ordered.
        """

        def dependency(
            request: Request, principal: Principal = Depends(authenticate)
        ) -> Principal:
            if not principal.can(capability):
                # A privilege-probing attempt is exactly a sequence of these from
                # one credential across different capabilities, which is only
                # visible if each one is recorded durably.
                audit.record(
                    tenant=principal.tenant,
                    actor=f"key:{principal.key_hash[:12]}",
                    action=f"{request.method} {request.url.path}",
                    resource_type="capability",
                    resource_id=capability.value,
                    outcome=Outcome.DENIED,
                    detail={"role": principal.role, "reason": "capability_not_held"},
                )
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN,
                    detail=(
                        f"this operation requires the {capability.value!r} "
                        f"capability, which role {principal.role!r} does not hold"
                    ),
                )
            return principal

        return dependency

    def _incident_id(raw: str) -> IncidentId:
        try:
            return IncidentId(raw)
        except InvalidValue as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    def _dispatch(command) -> Result:
        try:
            return container.commands.dispatch(command)
        except ExecutionFenceLost as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        except TransientFailure as exc:
            # Retryable is a 503 with Retry-After, not a 500. The distinction is
            # what lets a client back off correctly instead of giving up.
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(exc),
                headers={"Retry-After": "5"},
            ) from exc
        except SentinelError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    # ── Ingestion: ONE path ─────────────────────────────────────────────────

    @app.post("/v1/events", status_code=status.HTTP_202_ACCEPTED)
    def ingest(payload: EventPayload, principal: Principal = Depends(require(Capability.INGEST_EVENT))):
        require_agent_identity(principal, payload.agentId, container=container)
        result = _dispatch(
            AdmitEvent(
                tenant=principal.tenant,
                payload=payload.model_dump(exclude={"signature"}),
                signature=payload.signature,
                source="http",
                # A PREFIX of the key hash, from the authenticated principal.
                # Never the key, and never a value the client supplied: a caller
                # that could name its own credential could attribute its traffic
                # to somebody else's key and make a compromise unscopeable.
                # Twelve characters is what the audit trail already uses.
                credential=principal.key_hash[:12],
            )
        )
        if not result.ok:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                detail={"outcome": result.outcome, **dict(result.detail)},
            )
        return {"outcome": result.outcome, **dict(result.detail)}

    # ── Queries ──────────────────────────────────────────────────────────────

    @app.get("/v1/incidents")
    def list_incidents(
        # Capped. An unbounded limit is a request for the whole table, and a
        # tenant's whole incident history in one response is a scan the read
        # model was never asked to survive.
        limit: int = Query(default=50, ge=1, le=500),
        cursor: str | None = None,
        principal: Principal = Depends(require(Capability.READ_INCIDENT)),
    ):
        return container.queries.ask(
            ListIncidents(tenant=principal.tenant, limit=limit, after=cursor)
        )

    @app.get("/v1/incidents/{incident_id}")
    def get_incident(
        incident_id: str,
        principal: Principal = Depends(require(Capability.READ_INCIDENT)),
    ):
        found = container.queries.ask(
            GetIncident(tenant=principal.tenant, incident_id=_incident_id(incident_id))
        )
        if found is None:
            # A 404 on a tenant-scoped resource is the horizontal-enumeration
            # signal: one credential walking an id space looking for something it
            # can reach. Recorded as DENIED because that is what it is from the
            # caller's side, and because the detector's window query selects on it.
            #
            # Noisy in principle -- a stale dashboard link produces one of these.
            # The threshold is 20 DISTINCT ids in five minutes, which no dashboard
            # reaches and a walk reaches immediately.
            audit.record(
                tenant=principal.tenant,
                actor=f"key:{principal.key_hash[:12]}",
                action="GET /v1/incidents/{id}",
                resource_type="incident",
                resource_id=incident_id,
                outcome=Outcome.DENIED,
                detail={"reason": "resource_not_found"},
            )
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="no such incident")
        return found

    @app.get("/v1/incidents/{incident_id}/history")
    def get_history(
        incident_id: str,
        principal: Principal = Depends(require(Capability.READ_INCIDENT)),
    ):
        return {
            "incident_id": incident_id,
            "history": container.queries.ask(
                GetIncidentHistory(
                    tenant=principal.tenant, incident_id=_incident_id(incident_id)
                )
            ),
        }

    @app.get("/v1/incidents/{incident_id}/report")
    def get_report(
        incident_id: str,
        principal: Principal = Depends(require(Capability.READ_REPORT)),
    ):
        return container.queries.ask(
            GetReport(tenant=principal.tenant, incident_id=_incident_id(incident_id))
        )

    @app.get("/v1/dashboard")
    def dashboard(principal: Principal = Depends(require(Capability.READ_DASHBOARD))):
        return container.queries.ask(TenantDashboard(tenant=principal.tenant))

    # ── Approvals ────────────────────────────────────────────────────────────

    @app.post("/v1/approvals/{approval_id}")
    def decide(
        approval_id: str,
        body: ApprovalDecision,
        principal: Principal = Depends(require(Capability.DECIDE_APPROVAL)),
    ):
        try:
            identifier = ApprovalId(approval_id)
        except InvalidValue as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        result = _dispatch(
            DecideApproval(
                tenant=principal.tenant,
                approval_id=identifier,
                decision=body.decision,
                decided_by=f"key:{principal.key_hash[:12]}",
                reason=body.reason,
            )
        )
        # Audited whether it succeeded or not. An approval is the only action here
        # that causes an effect on a system outside this one, so "who approved
        # this, when, and did it take" is the question most likely to be asked
        # months later -- and a log line will not be there to answer it.
        audit.record(
            tenant=principal.tenant,
            actor=f"key:{principal.key_hash[:12]}",
            action=f"approval.{body.decision}",
            resource_type="approval",
            resource_id=identifier.value,
            outcome=Outcome.SUCCESS if result.ok else Outcome.FAILED,
            detail={"result": result.outcome, "role": principal.role},
        )
        if not result.ok:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                detail={"outcome": result.outcome, **dict(result.detail)},
            )
        return {"outcome": result.outcome, **dict(result.detail)}

    # ── Protect: pre-action gate ─────────────────────────────────────────────

    @app.post("/v1/protect/evaluate")
    def protect_evaluate(
        payload: ProtectPayload,
        principal: Principal = Depends(require(Capability.EVALUATE_PROTECT)),
    ):
        """Decide whether a proposed tool call may proceed, and authorize it.

        Uses the deterministic policy only -- never the LLM or statistical
        classifier. enforced is True only when SENTINEL_PROTECT_ENFORCE is on
        *and* the decision stops the action. Advisory deployments never claim
        enforcement.

        TRUST COMES FROM THE PRINCIPAL. The body used to carry `trustLevel`,
        and an API-key caller declaring `verified` lifted the severity cap on
        its own request. Now the cap keys on how the caller authenticated and
        a body that still carries the field is refused with the reason.

        WHEN THE VERDICT PERMITS THE ACTION, AN AUTHORIZATION IS ISSUED. It
        commits to the tool, action, resource and canonicalised arguments in
        this payload; `/v1/tools/execute` refuses anything that differs. A
        `require_approval` verdict issues a PENDING one that redeems for
        nothing until a decide_approval holder activates it.
        """
        require_agent_identity(principal, payload.agentId, container=container)
        body = payload.model_dump(exclude={"signature", "tool", "arguments", "mcpServer"})
        tool = payload.tool or str(payload.metadata.get("tool") or "")
        mcp_server = payload.mcpServer or str(payload.metadata.get("mcp_server") or "")
        if tool:
            body["tool"] = tool
            body["metadata"] = {**dict(body.get("metadata") or {}), "tool": tool}
        # THE ARGUMENTS REACH THE POLICY. An earlier version withheld them on
        # the theory that the gate needs only their digest; reproduced live,
        # `rm -rf /` in `arguments.command`, `DROP TABLE` in `arguments.sql`
        # and a POST to an attacker host in `arguments.url` all returned
        # `allow`. The digest binds the execution; it detects nothing. The
        # audit record below still carries the decision, not the payload.
        body["arguments"] = dict(payload.arguments)
        trust = principal.trust

        outcome = container.protect_gate.evaluate(
            payload=body, trust=trust, tenant_id=str(principal.tenant)
        )
        response = outcome.as_dict()
        issued = None
        try:
            issued = issue_for_outcome(
                container,
                tenant=str(principal.tenant),
                actor=f"key:{principal.key_hash[:12]}",
                outcome=outcome,
                agent_id=payload.agentId,
                tool=tool,
                action=payload.action,
                resource=payload.resource,
                parameters=dict(payload.arguments),
                mcp_server=mcp_server,
            )
        except ValueError as exc:
            # The canonicaliser refused the arguments (a float, a huge int).
            # The verdict stands; nothing can be bound to those arguments and
            # the response says so rather than issuing a digest of nothing.
            response["authorization"] = None
            response["authorization_note"] = (
                f"no authorization issued: arguments cannot be canonicalised ({exc})"
            )
        else:
            if issued is None:
                response["authorization"] = None
                response["authorization_note"] = (
                    "no authorization issued: the verdict stops the action"
                    if outcome.decision.stops_action
                    else "no authorization issued: the payload names no `tool` "
                    "to bind an execution to"
                )
            else:
                authorization, token, state = issued
                response["authorization"] = authorization_response(
                    authorization, token=token, state=state
                )
        audit.record(
            tenant=principal.tenant,
            actor=f"key:{principal.key_hash[:12]}",
            action="protect.evaluate",
            resource_type="protect",
            resource_id=payload.agentId,
            outcome=Outcome.SUCCESS,
            detail={
                "decision": outcome.decision.value,
                "enforced": outcome.enforced,
                "severity": outcome.severity,
                "trust": trust.value,
                "authorization_id": (
                    issued[0].authorization_id if issued is not None else ""
                ),
            },
        )
        return response

    # ── MCP: server trust and tool-definition drift ──────────────────────

    @app.post("/v1/mcp/evaluate")
    def mcp_evaluate(
        payload: McpCallPayload,
        principal: Principal = Depends(require(Capability.EVALUATE_PROTECT)),
    ):
        """Decide whether an MCP tool call may proceed.

        Three checks the direct protect route cannot make, then the SAME
        deterministic policy: is the server one we enrolled, is the tool the one
        that was approved, and is the tool's DESCRIPTION itself an injection.
        The third matters because a description is server-supplied prose the
        model reads as instructions -- inspecting the arguments never finds it.

        `EVALUATE_PROTECT` and not a new capability: this asks the same question
        as `/v1/protect/evaluate` about a richer subject. It does not CHANGE
        trust. Enrolling an MCP server decides what the trust anchor is, and that
        follows agent enrolment in being a CLI operation guarded by shell access
        to the host rather than by a bearer token -- see the note in
        `sentinel/domain/authorization.py`.

        The agent's trust is the principal's, derived from the credential.
        """
        require_agent_identity(principal, payload.agentId, container=container)
        trust = principal.trust

        # A DOMAIN INVARIANT VIOLATED BY CALLER INPUT IS A 400, NOT A 500.
        #
        # Found by the schema fuzzer in CI: `{"toolName": "\u00a0"}` -- a
        # single non-breaking space, written here as an escape so the comment
        # is readable -- returned 500. Pydantic accepts it, because
        # `min_length=1` is satisfied by one character, and then
        # `McpToolDefinition.__post_init__` calls `.strip()`, which treats U+00A0
        # as whitespace and leaves an empty name. The domain refuses correctly;
        # nothing translated that refusal, so a malformed request looked like a
        # server fault.
        #
        # `McpToolCall` raises the same way on a tenant mismatch, so the whole
        # construction is covered rather than just the definition.
        try:
            evaluation = container.mcp_gateway.evaluate_request(
                tenant_id=principal.tenant.value,
                server_id=payload.serverId,
                agent_id=payload.agentId,
                tool=McpToolDefinition(
                    name=payload.toolName,
                    description=payload.description,
                    input_schema=dict(payload.inputSchema),
                ),
                endpoint=payload.endpoint,
                arguments=dict(payload.arguments),
                session_id=payload.sessionId,
                trust=trust,
            )
        except ValueError as exc:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, detail=str(exc)
            ) from exc
        # Audited on both outcomes. A refusal is the more interesting record --
        # "an agent reached a server nobody enrolled" and "a tool changed after
        # approval" are both incidents, and neither leaves any other trace.
        audit.record(
            tenant=principal.tenant,
            actor=f"key:{principal.key_hash[:12]}",
            action="mcp.evaluate",
            resource_type="mcp_tool",
            resource_id=f"{payload.serverId}/{payload.toolName}",
            outcome=Outcome.SUCCESS if evaluation.allowed else Outcome.DENIED,
            detail={
                "allowed": evaluation.allowed,
                "server_trust": evaluation.server.trust.value,
                "changes": [c.kind.value for c in evaluation.changes],
                "decision": (
                    evaluation.protect.decision.value if evaluation.protect else None
                ),
            },
        )
        return evaluation.as_dict()

    # ── Probes ───────────────────────────────────────────────────────────────
    #
    # In `health_routes.py`: liveness, readiness, the memoised database probe
    # and diagnostics are one subject and share state nothing else touches.
    register_health_routes(
        app, container, settings, require=require, Principal=Principal
    )

    @app.get("/metrics/prometheus")
    def prometheus_metrics(
        authorization: str | None = Header(default=None),
    ):
        """Prometheus scrape endpoint. Authenticated; never a free data surface."""
        expected = settings.metrics_token
        if not expected:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="metrics token is not configured",
            )
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                detail="missing bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        presented = authorization.removeprefix("Bearer ").strip()
        if not hmac.compare_digest(presented, expected):
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                detail="invalid metrics token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        body = container.metrics.render_prometheus()
        return Response(content=body, media_type="text/plain; version=0.0.4")

    register_policy_routes(app, container, require=require)
    register_a2a_routes(app, container, require=require)
    # A no-op unless the container carries a wire client, which only happens
    # when SENTINEL_MCP_PROXY_ENABLED is set (or a test injects one). A
    # deployment without the proxy does not even advertise the route.
    register_mcp_proxy_routes(app, container, require=require)
    # Same rule: a no-op unless the container carries an A2A wire client.
    register_a2a_proxy_routes(app, container, require=require)
    # Read-only analysis over stored state. Registered unconditionally:
    # it needs no credential and no new store, and a capability with no
    # HTTP surface is one an operator does not have.
    register_analysis_routes(app, container, require=require)
    # The AI-BOM, exposure graph and reachability surfaces. Registered for
    # the same reason as the line above: five domain modules were written,
    # tested and committed with ZERO references from anywhere else in the
    # system. Library code, not product.
    register_estate_routes(app, container, require=require)
    # The transparency log's root and proofs. Read-only: appending is a
    # consequence of recording an execution, and a POST here would let
    # anyone holding the ingest credential write history.
    register_transparency_routes(app, container, require=require)
    # The approved-versus-executed diff. Read-only for the same reason as the
    # transparency routes: a receipt is a consequence of an execution, not
    # something a caller asks to create.
    register_binding_routes(app, container, require=require)
    register_operations_routes(app, container, require=require)
    # The approval decision for a `require_approval` verdict, so a pending
    # authorization has a route that can activate it.
    register_authorization_routes(app, container, require=require)
    register_extra_routes(
        app,
        container,
        authenticate=authenticate,
        require=require,
    )
    register_console_demo(app, demo_key)
    register_app_routes(app, container, require=require)

    return app
