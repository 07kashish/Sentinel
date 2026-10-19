"""The composition root. The ONE place that knows how everything is wired.

WHY A CONTAINER AND NOT A FRAMEWORK
------------------------------------
This is explicit constructor injection, written out. There is no decorator, no
registry populated by import side effects, no service locator and no reflection.
A reader can follow every dependency by reading top to bottom, and a
`grep` for any adapter finds exactly one construction site.

That is the entire point. In the predecessor, importing `api.main` executed
configuration parsing, deployment validation, schema DDL, additive migrations, a
full ledger backfill and tenant synchronisation as import side effects, then
constructed a queue, a monitor and a worker as module globals. Importing the
module to read its routes applied a schema. Nothing could be constructed twice,
so nothing could be tested in isolation.

Here `sentinel.composition` is the only package that may import from every
layer. Everything else obeys the dependency rule, and
`tests_arch/test_architecture_rules.py` fails the build if that stops being true.

LIFETIME
--------
The container owns the pool and the background workers. `close()` releases them.
Two containers can exist simultaneously in one process with no interference,
which is what makes a test suite able to build a real application per test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

from sentinel.application.bus import CommandBus, EventBus, QueryBus
from sentinel.application.a2a_gateway import A2AGateway
from sentinel.infrastructure.a2a_registry import (
    SqlAgentCardRegistry,
    SqlTaskLedger,
)
from sentinel.application.mcp_gateway import McpGateway
from sentinel.application.reconciliation import OperationReconciler
from sentinel.application.protect_gate import ProtectGate
from sentinel.application.skill_detonation import SkillDetonationService
from sentinel.application.tool_runner import ProtectedToolRunner
from sentinel.application.tool_proxy import InlineToolProxy, RegisteredSideEffect
from sentinel.application.commands.admit_event import AdmitEvent, AdmitEventHandler
from sentinel.application.commands.manage_containment import (
    ActivateContainment,
    ActivateContainmentHandler,
    LiftContainment,
    LiftContainmentHandler,
)
from sentinel.application.commands.decide_approval import (
    DecideApproval,
    DecideApprovalHandler,
)
from sentinel.application.commands.dispatch_outbox import (
    DispatchOutbox,
    DispatchOutboxHandler,
)
from sentinel.application.execution.engine import ExecutionEngine
from sentinel.application.execution.handler import ProcessIncident, ProcessIncidentHandler
from sentinel.application.execution.pipeline import INCIDENT_PLAN, PipelineSteps
from sentinel.application.ports import (
    AttestationGateway,
    Clock,
    IdGenerator,
    Logger,
    ModelAdvisor,
    RemediationExecutor,
    SecurityAudit,
)
from sentinel.application.queries.incident_queries import (
    GetIncident,
    GetIncidentHandler,
    GetIncidentHistory,
    GetIncidentHistoryHandler,
    GetReport,
    GetReportHandler,
    ListIncidents,
    ListIncidentsHandler,
    TenantDashboard,
    TenantDashboardHandler,
)
from sentinel.composition.advisor_wiring import build_advisor
from sentinel.composition.app_wiring import build_connected_apps, connected_app_effect
from sentinel.composition.evidence_wiring import evidence_cipher
from sentinel.composition.settings import Settings
from sentinel.domain.events import (
    DomainEvent,
)
from sentinel.domain.primitives import TenantId
from sentinel.application.ports import DetectionPolicy
from sentinel.infrastructure.soft_detection import (
    DetectionMode,
)
from sentinel.infrastructure.directory import SqlDirectory
from sentinel.infrastructure.orgs import SqlOrgRegistry
from sentinel.infrastructure.observability import MetricsRegistry, OtelHooks
from sentinel.infrastructure.oidc import OidcVerifier
from sentinel.infrastructure.agent_identity_providers import (
    AgentIdentityProviders,
    hardened_jwks_fetch,
)
from sentinel.composition.root_sink_wiring import build_root_sink
from sentinel.domain.root_sink import RootSink
from sentinel.infrastructure.evidence import (
    CanonicalEvidenceBuilder,
    MarkdownReportRenderer,
    RuleBasedPlanner,
)
from sentinel.infrastructure.identity import (
    Secp256k1IdentityVerifier,
    SqlAgentRegistry,
    SqlReplayGuard,
)
from sentinel.infrastructure.runtime import StructuredLogger, SystemClock, UuidIdGenerator
from sentinel.infrastructure.persistence.cache import (
    RateLimiter,
)
from sentinel.infrastructure.security_audit import SqlSecurityAudit
from sentinel.composition.siem_wiring import build_siem_deliverer
from sentinel.infrastructure.mcp_registry import SqlMcpRegistry
from sentinel.infrastructure.sql.evidence_commitments import SqlEvidenceCommitments
from sentinel.infrastructure.sql.transparency_store import SqlTransparencyStore
from sentinel.infrastructure.sql.workflow_metrics import SqlWorkflowMetrics
from sentinel.infrastructure.sql.receipt_store import SqlReceiptStore
from sentinel.infrastructure.sql.nonce_ledger import SqlNonceLedger
from sentinel.infrastructure.sql.operation_store import SqlOperationStore
from sentinel.infrastructure.sql.coverage import SqlCoverageReader
from sentinel.infrastructure.sql.protect_controls_store import SqlProtectControls
from sentinel.infrastructure.sql.authorization_store import SqlAuthorizationStore
from sentinel.infrastructure.delegation_signing import KeyRingVerifier
from sentinel.composition.delegation_wiring import build_delegation_verifier
from sentinel.application.agent_capabilities import AgentCapabilityGate
from sentinel.infrastructure.agent_capabilities import SqlAgentCapabilities
from sentinel.infrastructure.execution_graph import SqlExecutionGraph
from sentinel.infrastructure.inventory import SqlAgentInventory
from sentinel.infrastructure.tool_adapters import build_tool_adapters
from sentinel.composition.platform_wiring import build_platform_effects
from sentinel.composition.proxy_wiring import build_a2a_upstream, build_mcp_upstream
from sentinel.composition.detonation_wiring import build_detonation_service
from sentinel.composition.discovery_wiring import build_discovery_connectors
from sentinel.composition.remediation_wiring import build_executor
from sentinel.infrastructure.containment import ContainmentGuard
from sentinel.infrastructure.a2a_wire import A2AUpstreamClient
from sentinel.infrastructure.mcp_wire import McpUpstreamClient
from sentinel.composition.notifications import subscribers_with_soar
from sentinel.infrastructure.sql.engine import ConnectionPool, build_engine
from sentinel.infrastructure.sql.migrate import verify
from sentinel.infrastructure.sql.read_model import SqlReadModel
from sentinel.infrastructure.sql.retention import SqlRetention
from sentinel.infrastructure.sql.unit_of_work import SqlUnitOfWorkFactory
from sentinel.infrastructure.sql.work_queue import SqlWorkQueue

# The adapter-selection helpers, moved to `adapters.py` when this module
# reached the 800-line fitness limit. Imported back so every call site
# here is unchanged -- a split, not a migration.
from sentinel.composition.adapters import (  # noqa: E402,F401
    # The four adapter-selection helpers, plus the module-level constants that
    # travelled with them. RE-EXPORTED, not merely imported: callers and tests
    # already reach for these on `container`, and a split that broke those
    # imports would be a migration wearing a refactor's name.
    DEFAULT_SOFT_PROMPT_ARTIFACT,
    _RULES_ONLY_RECALL,
    _SOFT_AND_RULES_RECALL,
    _attestation_for,
    _default_subscribers,
    _detection_policy_for,
    _limiter_for,
)

__all__ = ["Container", "build_container"]


@dataclass(frozen=True, slots=True)
class Container:
    """Every constructed collaborator, exposed for the interface layer to use.

    Frozen: once wired, the graph does not change. A container whose members can
    be reassigned at runtime is a service locator with extra steps, and a service
    locator is a global by another name.
    """

    settings: Settings
    pool: ConnectionPool
    clock: Clock
    ids: IdGenerator
    logger: Logger
    commands: CommandBus
    queries: QueryBus
    events: EventBus
    read_model: SqlReadModel
    #: Exposed so interface modules that manage tenant configuration
    #: (policy versions, retention, keys) can open a scoped
    #: transaction. Routes still may not construct domain objects --
    #: the architecture rule that forbids it is unchanged.
    uow_factory: SqlUnitOfWorkFactory
    work_queue: SqlWorkQueue
    attestation: AttestationGateway
    advisor: ModelAdvisor
    #: Connected applications registry (sealed credentials); the `app_call` effect reads it.
    connected_apps: Any
    executor: RemediationExecutor
    engine: ExecutionEngine
    #: The tamper-evident trail for authentication and authorisation decisions.
    #: Not optional and never None: a conditional around a security control is how
    #: the control comes to be skipped. A deployment that does not want auditing
    #: injects `NullSecurityAudit` explicitly.
    security_audit: SecurityAudit
    #: The edge rate limiter. Shared through Redis when configured, per-process
    #: otherwise -- and production refuses to start multi-shard without Redis,
    #: because a per-process limiter across N replicas permits N times the
    #: configured rate while looking correct.
    rate_limiter: RateLimiter
    #: Deterministic detection ruleset. Used by admission and by protect evaluate.
    policy: DetectionPolicy
    #: Which detector is actually running. Reported by `/health/ready` so that a
    #: silent fallback to rules-only is alertable rather than archaeological.
    detection_mode: DetectionMode
    #: Synchronous protect gate. Same policy + enforce flag as the HTTP route.
    protect_gate: ProtectGate
    #: Fail-closed tool wrapper: agents must call this before side effects.
    tool_runner: ProtectedToolRunner
    #: Inline tool proxy backing POST /v1/tools/execute.
    tool_proxy: InlineToolProxy
    #: What each agent is authorised to INVOKE, as opposed to who it is.
    #: Enrolment answers identity; this answers capability.
    agent_capabilities: SqlAgentCapabilities
    #: Every agent SEEN, enrolled or not, and what it reached. Answers "who is
    #: actually talking to us" rather than "who did we register".
    inventory: SqlAgentInventory
    #: The durable transparency log, so its roots describe something that
    #: survives the process rather than one worker's memory.
    transparency: SqlTransparencyStore
    #: Commits execution receipts to the transparency log, once each.
    evidence: SqlEvidenceCommitments
    workflow_metrics: SqlWorkflowMetrics
    #: Tenants this process has already given a directory row (see principals.py).
    enrolled_tenants: set = field(default_factory=set, kw_only=True)
    #: Durable execution receipts. Without them the approved-versus-executed
    #: diff could only describe the one receipt a caller happened to be
    #: holding, and the question the binding exists to answer -- which
    #: executions this week differed -- would need the receipts to still be
    #: there.
    receipts: SqlReceiptStore
    #: Intent-before-effect record for every bound execution; the honest
    #: `unknown_after_effect` state lives here.
    operations: SqlOperationStore
    operation_reconciler: OperationReconciler
    #: Deployment-wide budget and breaker. Exposed for diagnostics only.
    protect_controls: SqlProtectControls
    #: The counts the coverage route needs that no other store exposes.
    coverage_reader: SqlCoverageReader
    #: The SHARED nonce ledger. Single-use enforcement for authorizations has
    #: to be atomic across every replica, so it is a table and not a set --
    #: and it replaces `RejectingNonceLedger`, which refused everything and
    #: therefore made a bound execution impossible rather than enforced.
    nonces: SqlNonceLedger
    #: Issued authorizations, tenant-scoped, so a token minted by one replica
    #: redeems on another. The store is what binds a token to a row; there is
    #: no shared HMAC secret to distribute.
    authorizations: SqlAuthorizationStore
    #: What each agent may INVOKE, as a gate. Exposed alongside the store so
    #: the MCP wire proxy asks the same capability question the inline proxy
    #: does rather than routing around it.
    capability_gate: AgentCapabilityGate
    #: The delegation key ring. Verifies signed hops on `/v1/a2a/evaluate` and
    #: the A2A proxy; empty refuses every signed chain as UNKNOWN_KEY.
    delegation_verifier: KeyRingVerifier
    #: Skill detonation, with the scope comparison attached. Not optional and
    #: never None: an absent service reads as "nothing to check", so a
    #: deployment with no sandbox gets one that REFUSES rather than one that
    #: is missing. Whether it can observe scope depends on tracing being on --
    #: and when it cannot, it says UNOBSERVED rather than clean.
    detonation: SkillDetonationService
    #: Discovery connectors, keyed by name. EMPTY when nothing is configured,
    #: and that emptiness is load-bearing: an absent connector means no
    #: credential was supplied, not that the platform is clean. Five of these
    #: have never authenticated against a real tenant, which
    #: `describe_discovery` reports alongside the names.
    discovery: Mapping[str, Any]
    #: Causal traces: what followed what, per session. Evidence for an
    #: investigation, never consulted by the enforcement path.
    execution_graph: SqlExecutionGraph
    #: MCP gateway: server trust and tool-definition drift, in front of the same
    #: `protect_gate` above. It does not decide ALLOW/BLOCK itself -- one ruleset
    #: governs both the direct and the MCP path, so they cannot disagree.
    mcp_gateway: McpGateway
    #: A2A gateway: delegation-chain checks in front of the SAME
    #: `protect_gate`. Privilege amplification, delegation loops, agent-card
    #: drift and cross-agent injection are the questions a single tool call
    #: cannot raise; the ALLOW/BLOCK decision stays with one ruleset, so the
    #: protect, MCP and A2A paths cannot disagree.
    #:
    #: The card store is IN-PROCESS. That is a real limit and it is stated
    #: rather than implied: a pin one replica holds is not a pin the next
    #: request sees, so multi-replica A2A enforcement needs the SQL-backed
    #: store this does not yet have. `docs/A2A_GATEWAY.md` records it.
    a2a_gateway: A2AGateway
    #: Durable, tenant-scoped MCP enrolment. Backs `mcp_gateway`; also read
    #: directly for the operator listing, which the gateway has no reason to know
    #: how to produce.
    mcp_registry: SqlMcpRegistry
    #: The MCP wire client, present only when `SENTINEL_MCP_PROXY_ENABLED` is
    #: set. None means the proxy routes are not registered and this process
    #: makes no MCP network calls at all -- the evaluation API keeps working
    #: either way. Absence is the default because the proxy is a new outbound
    #: capability, and those are opted into, never inherited.
    mcp_upstream: McpUpstreamClient | None
    #: The A2A wire client, present only when `SENTINEL_A2A_PROXY_ENABLED` is
    #: set. `None` is the honest state for a deployment that did not ask for the
    #: proxy: the route is not registered at all, so there is nothing to reach.
    a2a_upstream: A2AUpstreamClient | None
    #: Deletes finished operational rows past the retention window. Never the
    #: incident record or the ledger -- that is a compliance decision.
    retention: SqlRetention
    #: Enrolled agent addresses + last observed event times (bypass silence).
    agents: SqlAgentRegistry
    #: SCIM user directory.
    directory: SqlDirectory
    #: Organization registry.
    orgs: SqlOrgRegistry
    #: Process-local Prometheus registry (authenticated scrape).
    metrics: MetricsRegistry
    #: Optional OTLP-shaped span hooks (no-op without endpoint).
    otel: OtelHooks
    #: OIDC JWT verifier when configured; None otherwise.
    oidc: OidcVerifier | None
    #: Agent identity providers (Okta Agent SSO, Entra Agent ID); None when
    #: none is registered. Their tokens authenticate an AGENT, bound by id.
    agent_idps: AgentIdentityProviders | None
    #: Where transparency roots are published. Refusing until configured.
    root_sink: RootSink

    def close(self) -> None:
        """Release infrastructure. Idempotent."""
        try:
            self.otel.close()
        finally:
            self.pool.close()


def build_container(
    settings: Settings,
    *,
    clock: Clock | None = None,
    ids: IdGenerator | None = None,
    logger: Logger | None = None,
    attestation: AttestationGateway | None = None,
    advisor: ModelAdvisor | None = None,
    security_audit: SecurityAudit | None = None,
    rate_limiter: RateLimiter | None = None,
    executor: RemediationExecutor | None = None,
    mcp_upstream: McpUpstreamClient | None = None,
    event_subscribers: Mapping[type[DomainEvent], Sequence[Callable[[TenantId, DomainEvent], None]]]
    | None = None,
    verify_schema: bool = True,
    root_sink: RootSink | None = None,
) -> Container:
    """Wire the application.

    Every overridable collaborator is a keyword argument with a real default, so
    a test substitutes one by passing it rather than by patching a module. That
    is the practical difference between injected dependencies and ambient ones.
    """
    resolved_clock: Clock = clock or SystemClock()
    resolved_ids: IdGenerator = ids or UuidIdGenerator()
    resolved_logger: Logger = logger or StructuredLogger("sentinel")

    pool = build_engine(settings.engine)
    otel: OtelHooks | None = None
    try:
        if verify_schema:
            # O(1). A startup check may read one indexed row; it may never scan.
            verify(pool)

        # ── Event fan-out ────────────────────────────────────────────────────
        # Subscribers are supplied by the caller. The container does not invent
        # side effects: if nothing subscribes, events are still durably recorded
        # in `domain_events` by the unit of work, which is the audit guarantee.
        events = EventBus(
            subscribers=dict(
                event_subscribers
                or subscribers_with_soar(
                    settings,
                    logger=resolved_logger,
                    defaults=_default_subscribers(resolved_logger),
                )
            ),
            logger=resolved_logger,
        )

        uow_factory = SqlUnitOfWorkFactory(
            pool=pool, publisher=events, clock=resolved_clock,
            evidence_cipher=evidence_cipher(settings),
        )
        read_model = SqlReadModel(pool=pool)
        work_queue = SqlWorkQueue(
            pool=pool,
            shard_count=settings.worker_shard_count,
            max_attempts=settings.queue_max_attempts,
            lease_seconds=settings.queue_lease_seconds,
        )

        agents = SqlAgentRegistry(pool=pool)
        identity = Secp256k1IdentityVerifier()
        replay = SqlReplayGuard(pool=pool, window_seconds=settings.replay_window_seconds)
        policy: DetectionPolicy
        detection_mode: DetectionMode
        policy, detection_mode = _detection_policy_for(
            settings, logger=resolved_logger
        )

        resolved_attestation: AttestationGateway = attestation or _attestation_for(settings)
        resolved_advisor: ModelAdvisor = advisor or build_advisor(settings)
        resolved_audit: SecurityAudit = security_audit or SqlSecurityAudit(
            pool=pool, clock=resolved_clock, logger=resolved_logger
        )
        resolved_limiter: RateLimiter = rate_limiter or _limiter_for(
            settings, logger=resolved_logger
        )

        def _active_tenant_policy(tenant: str):
            with uow_factory.begin(TenantId(tenant)) as uow:
                current = uow.policies.active()
                uow.commit()
            return current

        # Statistical detection remains advisory. Only deterministic rules
        # and the tenant's activated policy enter the execution control gate.
        from sentinel.infrastructure.detection import DeterministicPolicy
        protect_gate = ProtectGate(
            policy=DeterministicPolicy.default(), enforce=settings.protect_enforcement,
            tenant_policy=_active_tenant_policy,
        )
        # SHARED across replicas, in the database. The in-process
        # `ProtectControls` gave every replica its own budget and breaker, so
        # a deployment of N pods permitted N times the configured budget and a
        # breaker opened on one pod was closed on the next. When the state
        # cannot be read the runner refuses (retryable); see the store.
        protect_controls = SqlProtectControls(
            pool=pool,
            kill_switch=settings.protect_kill_switch,
            budget_per_minute=settings.tool_budget_per_minute,
            circuit_threshold=settings.protect_circuit_threshold,
            clock=resolved_clock,
        )
        # Built BEFORE the runner so the runner records receipts and
        # operations itself, between the effect and the response. The proxy
        # used to write the receipt afterwards, which left a window in which an
        # effect had happened and nothing durable said so.
        receipts = SqlReceiptStore(pool=pool)
        operations = SqlOperationStore(pool=pool)
        # The granular kill switch's read side. Built here so the command
        # handlers and the tool runner share ONE cache -- two guards would
        # mean an operator's activation invalidating a cache the enforcement
        # path does not consult.
        containment_guard = ContainmentGuard(
            uow_factory=uow_factory, logger=resolved_logger
        )

        tool_runner = ProtectedToolRunner(
            gate=protect_gate,
            controls=protect_controls,
            containment=containment_guard,
            clock=resolved_clock,
            # Passed through rather than defaulted here. The runner defaults to
            # False so existing construction sites keep working, but the
            # DEPLOYMENT's answer has to reach the object that enforces it --
            # a setting nothing reads is the shape of an integration that can be
            # claimed and bypassed.
            require_binding=settings.require_execution_binding,
            operations=operations,
            receipts=receipts,
        )
        # `echo` and `noop` stay: they are how the enforcement path itself is
        # tested without performing an effect. The real adapters are added only
        # where an operator configured them -- an unconfigured adapter is ABSENT,
        # and InlineToolProxy already refuses unregistered tools, so absence is
        # enforced by code rather than by a flag one boolean away from being on.
        effects: dict[str, RegisteredSideEffect] = {
            "echo": RegisteredSideEffect(
                name="echo",
                runner=lambda args: {"echo": dict(args)},
            ),
            "noop": RegisteredSideEffect(
                name="noop",
                runner=lambda args: {"ok": True},
            ),
        }
        effects.update(
            build_tool_adapters(
                file_root=settings.tool_file_root,
                http_allowed_hosts=settings.tool_http_allowed_hosts,
            )
        )
        # Tier-1 platforms: AWS, GitHub, Kubernetes, PostgreSQL. Registered into
        # the SAME effects mapping as the file and HTTP adapters, so they reach
        # an agent only through `InlineToolProxy` -- kill switch, capability
        # grant, ProtectGate, budget and circuit breaker all ahead of them.
        # There is no second execution path for the higher-privilege effects,
        # which is the point: the enforcement that had only ever governed
        # `read_file` now governs `iam:CreateAccessKey`.
        effects.update(build_platform_effects(settings))
        # Connected applications: the agent asks, Sentinel presents the credential.
        connected_apps = build_connected_apps(settings, pool)
        effects["app_call"] = connected_app_effect(connected_apps)
        agent_capabilities = SqlAgentCapabilities(pool=pool)
        execution_graph = SqlExecutionGraph(pool=pool)
        transparency = SqlTransparencyStore(pool=pool)
        # Lazily created: the audited migration list is owned elsewhere and
        # these two tables belong in it. Idempotent DDL, run once here.
        nonces = SqlNonceLedger(pool=pool)
        nonces.ensure_schema()
        authorizations = SqlAuthorizationStore(pool=pool)
        authorizations.ensure_schema()
        inventory = SqlAgentInventory(
            pool=pool,
            # What actually governed this agent's traffic, recorded so a profile
            # says which detector and posture produced its findings rather than
            # leaving a reader to assume the current one applied historically.
            policy_label=(
                f"{detection_mode.value}; "
                f"protect={'enforce' if settings.protect_enforcement else 'advisory'}; "
                f"capabilities={'enforced' if settings.agent_require_grant else 'observe'}"
            ),
        )
        capability_gate = AgentCapabilityGate(
            store=agent_capabilities,
            require_grant=settings.agent_require_grant,
        )
        tool_proxy = InlineToolProxy(
            tool_runner=tool_runner,
            effects=effects,
            capabilities=capability_gate,
            # Every bound execution through the proxy leaves a durable receipt,
            # so the approved-versus-executed diff sees HTTP executions too.
            receipts=receipts,
        )
        # Durable and tenant-scoped, not the in-memory defaults. Process-local
        # pins would mean an operator enrols a server on one replica and every
        # other replica still sees it as UNKNOWN -- a trust decision that looks
        # made and is not.
        mcp_registry = SqlMcpRegistry(pool=pool)

        # BUILT HERE, NOT WHERE THE OTHER ADAPTERS ARE, and the reason is a
        # dependency rather than a preference: the Sentinel-native
        # integrations below act on the agent registry, the capability
        # grants and the MCP registry, and two of those three are
        # constructed above this line. Building the executor earlier read
        # more tidily and referenced names that did not exist yet.
        # SECTION 34, WIRED, and now from three sources rather than one.
        # `sentinel/composition/remediation_wiring.py` owns the precedence:
        # Sentinel's own state, then cloud credentials, then the operator's
        # explicit webhooks, which win over anything this process could do
        # itself because configuring one was a decision somebody made.
        resolved_executor: RemediationExecutor = executor or build_executor(
            settings,
            registry=agents,
            capabilities=agent_capabilities,
            mcp_registry=mcp_registry,
            audit=resolved_audit,
            clock=resolved_clock,
        )
        if settings.remediation_endpoints:
            resolved_logger.info(
                "remediation_integrations_configured",
                actions=sorted(settings.remediation_endpoints),
                dry_run=settings.remediation_dry_run,
            )
        mcp_gateway = McpGateway(
            protect=protect_gate,
            pins=mcp_registry,
            servers=mcp_registry,
            require_pin=settings.mcp_require_pin,
        )
        # DURABLE, not in-process. The predecessor held card pins in one
        # worker's memory, so a card enrolled through one replica was invisible
        # to the next -- which meant `card_drift` could not fire at all in any
        # deployment running more than one, and `unenrolled_agent` fired for
        # agents that WERE enrolled, just not here.
        a2a_gateway = A2AGateway(
            gate=protect_gate,
            cards=SqlAgentCardRegistry(pool=pool),
            tasks=SqlTaskLedger(
                pool=pool, window_seconds=settings.replay_window_seconds
            ),
        )
        # The two wire clients, and the egress policy each is allowed, live in
        # `proxy_wiring.py`. They decide WHAT THIS PROCESS MAY DIAL, which is a
        # security decision worth a file somebody can read end to end rather
        # than one buried between a database pool and a metrics registry.
        # `mcp_upstream` stays injectable so a test can supply its own.
        resolved_mcp_upstream: McpUpstreamClient | None = (
            mcp_upstream if mcp_upstream is not None else build_mcp_upstream(settings)
        )
        resolved_a2a_upstream: A2AUpstreamClient | None = build_a2a_upstream(settings)
        directory = SqlDirectory(pool=pool)
        orgs = SqlOrgRegistry(pool=pool)
        metrics = MetricsRegistry()
        # The always-on alerting surface for detection degradation. The CRITICAL
        # log says it once at startup; this says it for as long as it is true,
        # which is what an alert rule needs. `sentinel_detection_degraded` is the
        # one to page on -- it is 1 only when detection fell back unintentionally,
        # never when an operator chose rules-only.
        metrics.set_gauge(
            "sentinel_detection_mode",
            1.0,
            labels={"mode": detection_mode.value},
        )
        metrics.set_gauge(
            "sentinel_detection_degraded",
            1.0 if detection_mode is DetectionMode.RULES_ONLY_DEGRADED else 0.0,
        )
        otel = OtelHooks(endpoint=settings.otlp_endpoint, metrics=metrics,
                         allow_http=not settings.is_production)
        oidc: OidcVerifier | None = None
        if settings.oidc_enabled:
            oidc = OidcVerifier.from_jwks_json(
                issuer=settings.oidc_issuer,
                audience=settings.oidc_audience,
                jwks_json=settings.oidc_jwks_json,
                tenant_claim=settings.oidc_tenant_claim,
                role_claim=settings.oidc_role_claim,
            )

        # Agent identity providers. Parsed again here (settings already
        # validated the JSON at startup) so the verifiers live on the container
        # and the settings object stays a plain record.
        agent_idps: AgentIdentityProviders | None = None
        if settings.agent_idp_json:
            agent_idps = AgentIdentityProviders.from_json(
                settings.agent_idp_json, fetch=hardened_jwks_fetch
            )
        resolved_root_sink: RootSink = root_sink or build_root_sink(settings)

        # The execution engine. Its plan, handlers and compensators are built
        # here and nowhere else, so the saga shape is decided in one readable
        # place rather than assembled by import side effects.
        # Real-time SIEM delivery, constructed only when a collector is
        # configured. `None` means no export intent is ever enqueued -- not
        # that exports are enqueued and dropped, which is why the flag below
        # is derived from the SAME condition rather than set independently.
        siem_deliverer = build_siem_deliverer(settings)
        steps = PipelineSteps(
            siem_export=siem_deliverer is not None,
            advisor=resolved_advisor,
            evidence_builder=CanonicalEvidenceBuilder(),
            report_renderer=MarkdownReportRenderer(),
            planner=RuleBasedPlanner(),
            attestation=resolved_attestation,
            ids=resolved_ids,
            logger=resolved_logger,
        )
        engine = ExecutionEngine(
            uow_factory=uow_factory,
            plan=INCIDENT_PLAN,
            handlers=steps.handlers(),
            compensators=steps.compensators(),
            hydrators=steps.hydrators(),
            clock=resolved_clock,
            logger=resolved_logger,
        )

        commands = CommandBus(
            {
                AdmitEvent: AdmitEventHandler(
                    uow_factory=uow_factory,
                    agents=agents,
                    inventory=inventory,
                    graph=execution_graph,
                    identity=identity,
                    replay=replay,
                    policy=policy,
                    queue=work_queue,
                    clock=resolved_clock,
                    ids=resolved_ids,
                    logger=resolved_logger,
                ),
                ProcessIncident: ProcessIncidentHandler(
                    engine=engine, logger=resolved_logger
                ),
                ActivateContainment: ActivateContainmentHandler(
                    uow_factory=uow_factory,
                    guard=containment_guard,
                    clock=resolved_clock,
                    ids=resolved_ids,
                    logger=resolved_logger,
                ),
                LiftContainment: LiftContainmentHandler(
                    uow_factory=uow_factory,
                    guard=containment_guard,
                    clock=resolved_clock,
                    logger=resolved_logger,
                ),
                DecideApproval: DecideApprovalHandler(
                    uow_factory=uow_factory,
                    executor=resolved_executor,
                    tool_runner=tool_runner,
                    clock=resolved_clock,
                    ids=resolved_ids,
                    logger=resolved_logger,
                    # The approved remediation runs BOUND: the authorization
                    # minted at approval time commits to the target the
                    # analyst approved, and the shared ledger makes it
                    # single-use across replicas.
                    nonces=nonces,
                    receipts=receipts,
                ),
                DispatchOutbox: DispatchOutboxHandler(
                    uow_factory=uow_factory,
                    attestation=resolved_attestation,
                    siem_deliverer=siem_deliverer,
                    clock=resolved_clock,
                    logger=resolved_logger,
                    batch_size=settings.outbox_batch_size,
                    lease_seconds=settings.outbox_lease_seconds,
                ),
            },
            logger=resolved_logger,
        )

        queries = QueryBus(
            {
                GetIncident: GetIncidentHandler(read_model=read_model),
                ListIncidents: ListIncidentsHandler(read_model=read_model),
                GetIncidentHistory: GetIncidentHistoryHandler(read_model=read_model),
                GetReport: GetReportHandler(read_model=read_model),
                TenantDashboard: TenantDashboardHandler(read_model=read_model),
            }
        )

        return Container(
            settings=settings,
            pool=pool,
            clock=resolved_clock,
            ids=resolved_ids,
            logger=resolved_logger,
            commands=commands,
            queries=queries,
            events=events,
            read_model=read_model,
            uow_factory=uow_factory,
            work_queue=work_queue,
            attestation=resolved_attestation,
            advisor=resolved_advisor,
            connected_apps=connected_apps,
            executor=resolved_executor,
            engine=engine,
            security_audit=resolved_audit,
            rate_limiter=resolved_limiter,
            policy=policy,
            detection_mode=detection_mode,
            protect_gate=protect_gate,
            tool_runner=tool_runner,
            tool_proxy=tool_proxy,
            agent_capabilities=agent_capabilities,
            inventory=inventory,
            transparency=transparency,
            evidence=SqlEvidenceCommitments(pool=pool),
            workflow_metrics=SqlWorkflowMetrics(pool=pool),
            receipts=receipts,
            nonces=nonces,
            authorizations=authorizations,
            capability_gate=capability_gate,
            delegation_verifier=build_delegation_verifier(settings),
            detonation=build_detonation_service(settings),
            discovery=build_discovery_connectors(settings.discovery_credentials),
            execution_graph=execution_graph,
            mcp_gateway=mcp_gateway,
            a2a_gateway=a2a_gateway,
            mcp_registry=mcp_registry,
            mcp_upstream=resolved_mcp_upstream,
            a2a_upstream=resolved_a2a_upstream,
            retention=SqlRetention(pool=pool),
            agents=agents,
            directory=directory,
            orgs=orgs,
            metrics=metrics,
            otel=otel,
            oidc=oidc,
            agent_idps=agent_idps,
            root_sink=resolved_root_sink,
            operations=operations,
            operation_reconciler=OperationReconciler(
                store=operations, reconcilers=tool_proxy.reconciler_for,
                max_attempts=settings.workflow.reconcile_max_attempts,
            ),
            protect_controls=protect_controls,
            coverage_reader=SqlCoverageReader(pool=pool),
        )
    except BaseException:
        # Partially built containers own both the export thread and SQL pool.
        try:
            if otel is not None:
                otel.close()
        finally:
            pool.close()
        raise
