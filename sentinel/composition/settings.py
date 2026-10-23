"""Configuration: parsed once, immutable, and passed as an argument.

WHY THIS IS A VALUE AND NOT A MODULE
------------------------------------
The predecessor read `os.getenv` at call time in fourteen modules and cached one
parsed object behind an `lru_cache`, which meant configuration was ambient: any
function could reach for it, tests had to remember to clear the cache, and two
different parsers of the same string once disagreed about duplicate keys, so a
key could authenticate as one tenant and inherit another's role.

`Settings` is a frozen value constructed once, at the edge of the process, by
`from_environment()`. Nothing else in the codebase calls `os.getenv`; that is
enforced by `tests_arch/test_architecture_rules.py`. Everything that needs a
setting receives it.

FAIL CLOSED AT CONSTRUCTION
---------------------------
A misconfigured security product must refuse to boot, not discover the problem
mid-incident. Validation happens here, once, and raises. In production mode the
bar is higher than in development, and the differences are stated explicitly
rather than implied by a default.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from sentinel.composition import settings_parsers as _parsers
from sentinel.composition.settings_advisor import AdvisorSettings
from sentinel.domain.modes import AmbiguousMode, ProtectionMode, parse_mode
from sentinel.domain.residency import Region
from sentinel.domain.authorization import VALID_ROLES as _GRANTED_ROLES
from sentinel.infrastructure.sql.engine import Dialect, EngineConfig

__all__ = [
    "ApiKey",
    "ConfigurationError",
    "Settings",
    "VALID_ROLES",
    "read_environment",
]

class ConfigurationError(RuntimeError):
    """Configuration is invalid. The process must not start."""

def read_environment() -> dict[str, str]:
    """The process environment, as a plain mapping.

    Exists so that `os.environ` is touched in exactly one module. Anything else
    that needs the raw environment -- the production preflight, for one -- takes
    it from here rather than reading it independently, because two readers of
    one input eventually disagree about what it says. Enforced by
    `test_only_the_settings_module_reads_the_environment`.
    """
    return dict(os.environ)

#: Re-exported from the grant table rather than restated.
#:
#: Two lists of role names is two lists that can disagree. The failure is
#: asymmetric and both directions are bad: a role accepted here but absent from
#: the grant table authenticates and then raises `UnknownRole` on every request,
#: and a role in the table but missing here can never be configured at all.
VALID_ROLES = _GRANTED_ROLES
MIN_KEY_LENGTH = 32

@dataclass(frozen=True, slots=True)
class ApiKey:
    """A credential binding, keyed by the SHA-256 of the presented material.

    The raw key is never stored on this object. The predecessor's docstring
    claimed keys were held only as hashes while the dict was keyed by the key
    itself; here it is structurally true.
    """

    tenant_id: str
    role: str
    key_hash: str

@dataclass(frozen=True, slots=True)
class Settings:
    """Everything the process needs to run, resolved and validated."""

    environment: str
    engine: EngineConfig
    api_keys: Mapping[str, ApiKey]
    cors_origins: tuple[str, ...]
    worker_shard: int
    worker_shard_count: int
    worker_poll_seconds: float
    queue_max_attempts: int
    queue_lease_seconds: int
    outbox_batch_size: int
    outbox_lease_seconds: int
    #: How long finished OPERATIONAL rows are kept: completed queue work,
    #: delivered outbox records, the dedup journal. Not the incident record and
    #: not the ledger -- see `sentinel/infrastructure/sql/retention.py`.
    retention_days: int
    #: Seconds between retention sweeps. The Helm chart has always set
    #: `SENTINEL_RETENTION_INTERVAL`; until now nothing parsed it, so the value an
    #: operator configured went nowhere.
    retention_interval_seconds: int
    #: How long the INCIDENT RECORD is kept: `incidents`, `domain_events`,
    #: `incident_transitions`. `None` means never delete, and that is the shipped
    #: default on purpose.
    #:
    #: How long a SOC retains incident history is a compliance decision with legal
    #: weight -- SOC 2, GDPR Article 5(1)(e) and sector rules all bear on it, and
    #: they do not agree. Any concrete default here would be an agent picking a
    #: number that an auditor later reads as policy. So there is no default: an
    #: operator sets `SENTINEL_INCIDENT_RETENTION_DAYS`, or nothing is ever
    #: deleted. See `sentinel/infrastructure/sql/retention.py`.
    incident_retention_days: int | None
    attestation_endpoint: str
    attestation_token: str
    #: HTTPS collector for real-time SIEM delivery. Empty (the default)
    #: means no export intent is enqueued at all -- not that exports are
    #: enqueued and dropped. A configured URL turns the outbox into the
    #: delivery path, with its retry, lease and dead-letter machinery.
    siem_webhook_url: str
    #: Per-tenant SIEM sinks. When non-empty the outbox routes each tenant's
    #: events to that tenant's own endpoint, and a tenant absent from this list
    #: exports NOWHERE -- it does not fall back to `siem_webhook_url`.
    #:
    #: `siem_webhook_url` remains the single-tenant answer and is unchanged.
    tenant_siem_sinks: tuple[tuple[str, str, str], ...]
    #: credential_ref -> token, for the refs named in `tenant_siem_sinks`.
    #: A ref present in a sink and absent here is a refusal at wiring time,
    #: not an unauthenticated sink.
    tenant_siem_credentials: Mapping[str, str]
    siem_webhook_token: str
    replay_window_seconds: int
    log_level: str
    #: Serve `/docs`, `/redoc` and `/openapi.json`. OFF unless asked for.
    #:
    #: These were previously always on and always unauthenticated: a probe of the
    #: running app returned 200 for all three and disclosed every route with its
    #: request shape. Swagger UI also loads script from a third-party CDN, which
    #: makes it the only browser surface this service has -- unauthenticated, with
    #: remote script. Refused outright in production.
    expose_api_docs: bool
    #: When the rate limiter is unreachable: allow (losing the limit) or deny
    #: (losing availability)?
    #:
    #: There is no safe default, so production REFUSES TO START unless this is
    #: stated. Development defaults to fail-open because a developer without Redis
    #: should not be locked out of their own service -- and that asymmetry is the
    #: whole reason the production case must be explicit rather than inherited.
    rate_limit_fail_open: bool
    #: `X-Forwarded-For` hops to trust. Zero means the header is ignored entirely,
    #: because trusting a client-supplied header for a security decision means the
    #: limiter is bypassed by adding a header.
    trusted_proxy_hops: int
    auth_failure_limit_per_minute: int
    credential_limit_per_minute: int
    address_limit_per_minute: int
    #: A Redis URL for a SHARED limiter. Without one the limiter is per-process, so
    #: for N replicas the effective limit is N times what is configured --
    #: correct-looking and wrong. Production refuses to start with more than one
    #: shard and no Redis.
    redis_url: str
    #: When True, protect decisions that stop an action set enforced=True and
    #: callers are under contract to abort. When False (default), every response
    #: carries enforced=False even on block -- advisory only.
    protect_enforcement: bool
    #: The deployment's operating mode (section 31).
    #:
    #: `protect_enforcement` above is the older boolean and remains the value the
    #: gate reads, so this does not change behaviour on its own -- it names what
    #: the deployment IS, in the five-mode vocabulary the specification requires,
    #: and `protection_mode.enforces` must agree with the boolean. Startup
    #: refuses when they disagree rather than silently preferring one.
    protection_mode: ProtectionMode
    #: Which region this deployment serves (section 79).
    #:
    #: A deployment refuses to operate on tenants resident elsewhere. That is
    #: what makes regional separation a property of the running system rather
    #: than a column nobody reads.
    region: Region
    #: Global kill switch: every ProtectedToolRunner side effect is refused.
    #: Fail closed. Independent of advisory/enforce mode so operators can halt
    #: remediation without redeploying policy.
    protect_kill_switch: bool
    #: When True the unbound `ProtectedToolRunner.execute` refuses, so every tool
    #: side effect must carry an ExecutionAuthorization. This is the difference
    #: between the binding being available and being ENFORCED: while False, a
    #: deployment is only as bound as its call sites happen to be. Defaults
    #: TRUE: every in-product execution path -- the tools proxy, the MCP wire
    #: proxy and approved remediation -- now runs bound, so the unbound path
    #: has no production caller left to protect. Production still refuses to
    #: start unless the value is stated, same reasoning as
    #: `rate_limit_fail_open`. See docs/ARCHITECTURE.md.
    require_execution_binding: bool
    #: Ed25519 public keys that may sign delegation hops, as
    #: `(key_id, base64 raw public key)` pairs from `SENTINEL_DELEGATION_KEYS`.
    #: The key id is `issuer#version`, which is what lets `verify_chain` tell
    #: whose key signed a hop by reading the id. Empty means no key ring, so
    #: every signed hop presented is refused as UNKNOWN_KEY -- an unverifiable
    #: chain is not a valid one.
    delegation_keys: tuple[tuple[str, str], ...]
    #: action -> HTTPS endpoint that performs it. Empty means this deployment has
    #: no remediation integrations, which is a supported and explicit state:
    #: `NullRemediationExecutor` then refuses every action and says why, rather
    #: than pretending.
    remediation_endpoints: Mapping[str, str]
    #: When true, remediation is evaluated and audited but never performed. For
    #: rehearsing a response plan against production without touching it.
    remediation_dry_run: bool
    #: connector name -> endpoint URL. Empty means no SOAR fan-out, which is a
    #: supported state: incidents still land in the console and the API.
    soar_endpoints: Mapping[str, str]
    #: PagerDuty's Events API takes the routing key in the body, not the URL.
    #: OCI image the skill detonation sandbox runs. Empty means no isolation
    #: boundary is configured, which yields `RefusingDetonator` -- never a
    #: subprocess on this host, because the "degraded" mode would be the exact
    #: attack the sandbox exists to prevent.
    #: Every `SENTINEL_DISCOVERY_*` variable, passed to
    #: `build_discovery_connectors`. ONE field rather than ten, because which
    #: combination of variables makes a usable credential is each connector's
    #: own rule and duplicating it here would be two places to disagree.
    #: Absent variables mean an absent connector, never an empty one.
    discovery_credentials: Mapping[str, str]
    #: OCI image the skill detonation sandbox runs. Empty means no isolation
    #: boundary is configured, which yields `RefusingDetonator` -- never a
    #: subprocess on this host, because the "degraded" mode would be the exact
    #: attack the sandbox exists to prevent.
    detonation_image: str
    #: Whether to trace syscalls in the sandbox. Default FALSE because it costs
    #: `CAP_SYS_PTRACE` on an otherwise `--cap-drop=ALL` container, and that
    #: widening should be chosen rather than inherited. Without it the scope
    #: verdict is UNOBSERVED rather than clean.
    detonation_tracing: bool
    soar_pagerduty_routing_key: str
    #: Only incidents at or above this priority are dispatched. HIGH by default:
    #: this codebase measured a detector firing on 51.7% of ordinary tool calls,
    #: and the same rate with a ticket queue attached is worse.
    soar_min_priority: str
    #: When True (default), the MCP gateway refuses a call to a server that has
    #: no pinned tool definitions. Set False only for an OBSERVE-mode rollout,
    #: while an operator is still discovering which servers exist -- it relaxes
    #: the definition-drift check ONLY. Server trust and description scanning are
    #: unaffected, so an unknown server is still refused either way.
    mcp_require_pin: bool
    #: When True, the MCP wire proxy route is registered and this process will
    #: forward JSON-RPC to ENROLLED servers. OFF by default: a new outbound
    #: network capability is opted into, never inherited.
    mcp_proxy_enabled: bool
    #: Serve the A2A wire proxy. OFF by default, and absent rather than
    #: disabled when off: `register_a2a_proxy_routes` returns without adding a
    #: route, so a deployment that has not asked for it does not advertise it.
    #:
    #: Separate from `mcp_proxy_enabled` on purpose. They are different egress
    #: surfaces to different classes of peer, and an operator who wants Sentinel
    #: between their agents should not thereby be dialling MCP servers.
    a2a_proxy_enabled: bool
    #: Hosts the A2A proxy may dial. Empty means "any public address", which the
    #: hardened client still bounds -- but an allowlist is the control to reach
    #: for, and it is required when private destinations are permitted.
    a2a_proxy_allowed_hosts: frozenset[str]
    a2a_proxy_allow_private: bool
    #: Non-empty narrows the proxy below "any enrolled server": the endpoint's
    #: host must also appear here. Deployment-wide, on top of per-tenant
    #: enrolment; the stricter of the two wins.
    mcp_proxy_allowed_hosts: frozenset[str]
    #: Permit dialling RFC1918/loopback endpoints (on-prem MCP servers). OFF by
    #: default — an enrolled endpoint of 169.254.169.254 must not become SSRF.
    #: Enable only with `mcp_proxy_allowed_hosts` narrowed to the hosts meant.
    mcp_proxy_allow_private: bool
    #: Refuse to forward a JWT upstream credential whose `aud` claim names no
    #: origin matching the enrolled endpoint -- the credential-audience
    #: restriction of the MCP authorization spec, stopping a token minted for
    #: server A being replayed against server B through the proxy. Opaque
    #: (non-JWT) tokens are not inspectable and always pass; this is a
    #: structural check, never signature verification.
    mcp_proxy_require_token_audience: bool
    #: Seconds a server's tools/list may be reused for tools/call evaluation.
    #: 0 (default) fetches the LIVE listing on every call -- the most rug-pull-
    #: sensitive setting. Non-zero trades a detection window of at most this
    #: many seconds for one fewer upstream round trip per call. Per-process.
    mcp_proxy_definition_cache_seconds: float
    #: means read_file/write_file are NOT REGISTERED at all, and the inline
    #: proxy refuses them as unknown tools. There is deliberately no default
    #: root: the obvious one is the working directory, which is the application.
    tool_file_root: str
    #: Hosts the http_request tool adapter may reach. Empty (the default) means
    #: the adapter is not registered. Required rather than optional because
    #: "any public address" is still an egress channel, and an agent talked into
    #: exfiltrating data does not need a private address to do it.
    tool_http_allowed_hosts: frozenset[str]
    #: Tier-1 platform adapter credentials, keyed by platform, as PLAIN DATA --
    #: the container turns them into credential objects, keeping infrastructure
    #: types out of `Settings` the way `remediation_endpoints` already does.
    #:
    #: A platform absent from this mapping has NO adapter built, and the inline
    #: proxy refuses its tool as unregistered. There is deliberately no enable
    #: flag: a flag is one boolean away from granting an agent AWS.
    platform_adapters: Mapping[str, Mapping[str, str]]
    #: Additional SIEM sinks beyond the webhook, keyed by transport, as plain
    #: data. Empty means the webhook alone (or no export at all). An unsupported
    #: transport never reaches here: the parser refuses it by name at start-up.
    siem_transports: Mapping[str, Mapping[str, str]]
    #: Refuse a tool call from an agent that was never granted it.
    #:
    #: Defaults to FALSE, unlike the MCP pin requirement, and the difference is
    #: deliberate: MCP enrolment was new so requiring pins broke nothing, while
    #: agents already exist in every deployment. Defaulting to deny would stop
    #: every working agent on upgrade, and the response to that is an operator
    #: switching it off permanently -- off AND unwatched, which is worse than an
    #: honest observe mode that records what agents actually invoke.
    agent_require_grant: bool
    #: Soft tool-execution budget per agent per rolling minute. Zero disables.
    tool_budget_per_minute: int
    #: Consecutive protect refusals/failures before the circuit opens.
    protect_circuit_threshold: int
    #: Seconds a `pending` execution operation may wait before the maintenance
    #: loop moves it to `unknown_after_effect` for a reconciler to look at.
    operation_pending_deadline_seconds: int
    #: Silence window (seconds) before an enrolled agent with no observed events
    #: raises a `possible_bypass` signal. Not packet interception.
    bypass_idle_seconds: int
    #: Publish detection mode on unauthenticated readiness only with opt-in.
    #: Diagnostics and metrics retain their authenticated disclosure boundary.
    ready_exposes_detection_mode: bool
    #: OIDC issuer URL. Empty disables the JWT auth path.
    oidc_issuer: str
    #: Expected JWT audience.
    oidc_audience: str
    #: Static JWKS JSON (tests / air-gapped). Prefer this over ambient fetch.
    oidc_jwks_json: str
    #: Claim name carrying the tenant id. Missing claim → auth failure (no default).
    oidc_tenant_claim: str
    #: Claim name carrying the Sentinel role.
    oidc_role_claim: str
    #: Bearer token required for `/metrics/prometheus`. Empty → metrics route 503.
    metrics_token: str
    #: Optional OTLP endpoint. Empty → observability hooks are no-ops.
    otlp_endpoint: str
    #: Agent identity providers JSON, validated at startup; empty means none.
    agent_idp_json: str
    #: Transparency root sink and its publication schedule.
    root_sink: _parsers.RootSinkSettings
    workflow: _parsers.WorkflowSettings = _parsers.WorkflowSettings()
    advisor: AdvisorSettings = AdvisorSettings()

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.oidc_issuer and self.oidc_audience and self.oidc_jwks_json)

    def tenants(self) -> frozenset[str]:
        return frozenset(binding.tenant_id for binding in self.api_keys.values())

    # ── Construction ─────────────────────────────────────────────────────────

    @classmethod
    def from_environment(cls, env: Mapping[str, str] | None = None) -> "Settings":
        """Parse and validate. The ONE place this process reads its environment.

        `env` is a parameter so tests construct settings from a dict instead of
        mutating `os.environ` — which is process-global state that leaks between
        tests and cannot be run in parallel.
        """
        source = dict(env if env is not None else os.environ)

        environment = source.get("SENTINEL_ENV", "development").strip().lower()
        if environment not in {"development", "staging", "production"}:
            raise ConfigurationError(
                f"SENTINEL_ENV must be development, staging or production; "
                f"got {environment!r}"
            )
        production = environment == "production"

        api_keys = cls._parse_api_keys(source, production=production)
        engine = cls._parse_engine(source, production=production)

        origins = tuple(
            o.strip()
            for o in source.get("SENTINEL_CORS_ORIGINS", "").split(",")
            if o.strip() and o.strip() != "*"
        )
        if production and not origins:
            raise ConfigurationError(
                "SENTINEL_CORS_ORIGINS must list explicit origins in production. "
                "A wildcard origin on a credentialed API is not a configuration "
                "this service will accept."
            )

        shard_count = _parsers.positive_int(source, "SENTINEL_WORKER_SHARD_COUNT", 1)
        shard = _parsers.positive_int(source, "SENTINEL_WORKER_SHARD", 0, allow_zero=True)
        if shard >= shard_count:
            raise ConfigurationError(
                f"SENTINEL_WORKER_SHARD ({shard}) must be less than "
                f"SENTINEL_WORKER_SHARD_COUNT ({shard_count}); this replica would "
                "own no shard and silently process nothing"
            )

        endpoint = source.get("SENTINEL_ATTESTATION_ENDPOINT", "").strip()
        token = source.get("SENTINEL_ATTESTATION_TOKEN", "").strip()
        if endpoint and not token:
            raise ConfigurationError(
                "SENTINEL_ATTESTATION_ENDPOINT is set without "
                "SENTINEL_ATTESTATION_TOKEN; refusing to call an attestation "
                "gateway unauthenticated"
            )
        if endpoint and not endpoint.startswith("https://"):
            raise ConfigurationError(
                "SENTINEL_ATTESTATION_ENDPOINT must be https"
            )

        expose_docs = _parsers.flag(source, "SENTINEL_EXPOSE_API_DOCS", default=False)
        if production and expose_docs:
            raise ConfigurationError(
                "SENTINEL_EXPOSE_API_DOCS cannot be enabled with "
                "SENTINEL_ENV=production. The docs routes are unauthenticated by "
                "construction -- FastAPI serves them before any dependency runs -- "
                "so enabling them publishes every route and request shape to "
                "anyone who can reach the port, and Swagger UI additionally loads "
                "script from a third-party CDN. Read the schema from a "
                "non-production deployment or generate it offline."
            )

        redis_url = source.get("SENTINEL_REDIS_URL", "").strip()
        if redis_url and not redis_url.startswith(("redis://", "rediss://")):
            raise ConfigurationError(
                "SENTINEL_REDIS_URL must be a redis:// or rediss:// URL"
            )
        if production and shard_count > 1 and not redis_url:
            raise ConfigurationError(
                f"SENTINEL_WORKER_SHARD_COUNT is {shard_count} but "
                "SENTINEL_REDIS_URL is unset, so the rate limiter would be "
                "per-process. With N replicas that makes the effective limit N "
                "times what is configured -- a limiter that looks correct and is "
                "not. Configure Redis, or run a single shard."
            )

        raw_fail_open = source.get("SENTINEL_RATE_LIMIT_FAIL_OPEN", "").strip()
        if production and not raw_fail_open:
            raise ConfigurationError(
                "SENTINEL_RATE_LIMIT_FAIL_OPEN must be set explicitly in "
                "production. When the limiter is unreachable, allowing loses the "
                "limit and denying loses availability; both are defensible and the "
                "wrong one is a silent bypass or a silent outage. There is no safe "
                "default, so this refuses to guess."
            )
        fail_open = _parsers.flag(source, "SENTINEL_RATE_LIMIT_FAIL_OPEN", default=True)

        raw_require_binding = source.get(
            "SENTINEL_REQUIRE_EXECUTION_BINDING", ""
        ).strip()
        if production and not raw_require_binding:
            raise ConfigurationError(
                "SENTINEL_REQUIRE_EXECUTION_BINDING must be set explicitly in "
                "production. False leaves `ProtectedToolRunner.execute` usable, "
                "and that path takes an opaque closure and binds nothing -- so "
                "an agent authorized against one resource can act on another "
                "and every passport, signature and transparency proof still "
                "verifies, because each attests to the DECISION rather than to "
                "what ran. True refuses that path, which stops any call site "
                "not yet migrated to `execute_bound`. Both are defensible and "
                "neither is safe to guess, so this refuses to."
            )
        require_execution_binding = _parsers.flag(
            source, "SENTINEL_REQUIRE_EXECUTION_BINDING", default=True
        )

        try:
            root_sink = _parsers.root_sink_settings(source)
            agent_idp_json = _parsers.agent_idp_json(source)
        except ValueError as exc:
            raise ConfigurationError(str(exc)) from exc
        settings = cls(
            environment=environment,
            engine=engine,
            api_keys=api_keys,
            cors_origins=origins or ("http://localhost:8000",),
            worker_shard=shard,
            worker_shard_count=shard_count,
            worker_poll_seconds=_parsers.float_value(source, "SENTINEL_WORKER_POLL_SECONDS", 0.5),
            queue_max_attempts=_parsers.positive_int(source, "SENTINEL_QUEUE_MAX_ATTEMPTS", 5),
            queue_lease_seconds=_parsers.positive_int(source, "SENTINEL_QUEUE_LEASE_SECONDS", 300),
            outbox_batch_size=_parsers.positive_int(source, "SENTINEL_OUTBOX_BATCH", 50),
            outbox_lease_seconds=_parsers.positive_int(source, "SENTINEL_OUTBOX_LEASE_SECONDS", 120),
            retention_days=_parsers.positive_int(source, "SENTINEL_RETENTION_DAYS", 90),
            retention_interval_seconds=_parsers.positive_int(
                source, "SENTINEL_RETENTION_INTERVAL", 3600
            ),
            incident_retention_days=_parsers.optional_positive_int(
                source, "SENTINEL_INCIDENT_RETENTION_DAYS"
            ),
            attestation_endpoint=endpoint,
            attestation_token=token,
            tenant_siem_sinks=_parsers.tenant_siem_sinks(source),
            tenant_siem_credentials=_parsers.tenant_siem_credentials(source),
            siem_webhook_url=(
                source.get("SENTINEL_SIEM_WEBHOOK_URL", "") or ""
            ).strip(),
            siem_webhook_token=(
                source.get("SENTINEL_SIEM_WEBHOOK_TOKEN", "") or ""
            ).strip(),
            replay_window_seconds=_parsers.positive_int(source, "SENTINEL_REPLAY_WINDOW", 300),
            log_level=source.get("SENTINEL_LOG_LEVEL", "INFO").strip().upper(),
            expose_api_docs=expose_docs,
            rate_limit_fail_open=fail_open,
            require_execution_binding=require_execution_binding,
            delegation_keys=cls._delegation_keys(source),
            trusted_proxy_hops=_parsers.positive_int(
                source, "SENTINEL_TRUSTED_PROXY_HOPS", 0, allow_zero=True
            ),
            auth_failure_limit_per_minute=_parsers.positive_int(
                source, "SENTINEL_AUTH_FAILURE_LIMIT", 10
            ),
            credential_limit_per_minute=_parsers.positive_int(
                source, "SENTINEL_CREDENTIAL_LIMIT", 600
            ),
            address_limit_per_minute=_parsers.positive_int(
                source, "SENTINEL_ADDRESS_LIMIT", 120
            ),
            redis_url=redis_url,
            protection_mode=cls._protection_mode(source),
            region=cls._region(source),
            protect_enforcement=_parsers.flag(source, "SENTINEL_PROTECT_ENFORCE", default=False),
            protect_kill_switch=_parsers.flag(source, "SENTINEL_PROTECT_KILL_SWITCH", default=False),
            remediation_endpoints=_parsers.remediation_endpoints(source),
            remediation_dry_run=_parsers.flag(source, "SENTINEL_REMEDIATION_DRY_RUN", default=False),
            discovery_credentials=_parsers.discovery_credentials(source),
            detonation_image=(
                source.get("SENTINEL_DETONATION_IMAGE") or ""
            ).strip(),
            detonation_tracing=_parsers.flag(
                source, "SENTINEL_DETONATION_TRACING", default=False
            ),
            soar_endpoints=_parsers.soar_endpoints(source),
            soar_pagerduty_routing_key=(
                source.get("SENTINEL_SOAR_PAGERDUTY_ROUTING_KEY") or ""
            ).strip(),
            soar_min_priority=(
                source.get("SENTINEL_SOAR_MIN_PRIORITY") or "HIGH"
            ).strip().upper(),
            mcp_require_pin=_parsers.flag(source, "SENTINEL_MCP_REQUIRE_PIN", default=True),
            mcp_proxy_enabled=_parsers.flag(source, "SENTINEL_MCP_PROXY_ENABLED", default=False),
            a2a_proxy_enabled=_parsers.flag(source, "SENTINEL_A2A_PROXY_ENABLED", default=False),
            a2a_proxy_allowed_hosts=_parsers.host_set(source, "SENTINEL_A2A_PROXY_ALLOWED_HOSTS"),
            a2a_proxy_allow_private=_parsers.flag(
                source, "SENTINEL_A2A_PROXY_ALLOW_PRIVATE", default=False
            ),
            mcp_proxy_allowed_hosts=_parsers.host_set(source, "SENTINEL_MCP_PROXY_ALLOWED_HOSTS"),
            mcp_proxy_allow_private=_parsers.flag(source, "SENTINEL_MCP_PROXY_ALLOW_PRIVATE", default=False),
            mcp_proxy_require_token_audience=_parsers.flag(
                source, "SENTINEL_MCP_PROXY_REQUIRE_TOKEN_AUDIENCE", default=True
            ),
            mcp_proxy_definition_cache_seconds=_parsers.float_value(
                source, "SENTINEL_MCP_PROXY_DEFINITION_CACHE_SECONDS", 0.0
            ),
            agent_require_grant=_parsers.flag(source, "SENTINEL_AGENT_REQUIRE_GRANT", default=False),
            tool_file_root=source.get("SENTINEL_TOOL_FILE_ROOT", "").strip(),
            tool_http_allowed_hosts=_parsers.host_set(source, "SENTINEL_TOOL_HTTP_ALLOWED_HOSTS"),
            platform_adapters=_parsers.platform_adapters(source),
            siem_transports=_parsers.siem_transports(source),
            tool_budget_per_minute=_parsers.positive_int(
                source, "SENTINEL_TOOL_BUDGET_PER_MINUTE", 0, allow_zero=True
            ),
            protect_circuit_threshold=_parsers.positive_int(
                source, "SENTINEL_PROTECT_CIRCUIT_THRESHOLD", 20
            ),
            operation_pending_deadline_seconds=_parsers.positive_int(
                source, "SENTINEL_OPERATION_PENDING_DEADLINE_SECONDS", 900
            ),
            bypass_idle_seconds=_parsers.positive_int(
                source, "SENTINEL_BYPASS_IDLE_SECONDS", 15 * 60
            ),
            ready_exposes_detection_mode=_parsers.flag(source, "SENTINEL_READY_EXPOSE_DETECTION_MODE", default=False),
            oidc_issuer=source.get("SENTINEL_OIDC_ISSUER", "").strip(),
            oidc_audience=source.get("SENTINEL_OIDC_AUDIENCE", "").strip(),
            oidc_jwks_json=source.get("SENTINEL_OIDC_JWKS_JSON", "").strip(),
            oidc_tenant_claim=source.get(
                "SENTINEL_OIDC_TENANT_CLAIM", "tenant_id"
            ).strip()
            or "tenant_id",
            oidc_role_claim=source.get("SENTINEL_OIDC_ROLE_CLAIM", "role").strip()
            or "role",
            metrics_token=_parsers.metrics_token_from(source),
            otlp_endpoint=source.get("SENTINEL_OTLP_ENDPOINT", "").strip(),
            agent_idp_json=agent_idp_json,
            root_sink=root_sink,
            workflow=_parsers.workflow_settings(source),
            advisor=AdvisorSettings.parse(source, error_type=ConfigurationError),
        )

        # OIDC is all-or-nothing: a half-configured IdP is worse than none.
        oidc_bits = (
            bool(settings.oidc_issuer),
            bool(settings.oidc_audience),
            bool(settings.oidc_jwks_json),
        )
        if any(oidc_bits) and not all(oidc_bits):
            raise ConfigurationError(
                "OIDC requires SENTINEL_OIDC_ISSUER, SENTINEL_OIDC_AUDIENCE and "
                "SENTINEL_OIDC_JWKS_JSON together. Partial OIDC config is refused."
            )
        return settings

    # ── Parsing helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _parse_api_keys(
        source: Mapping[str, str], *, production: bool
    ) -> Mapping[str, ApiKey]:
        """Parse `tenant:key:role` entries exactly once.

        Duplicate key material is REFUSED rather than resolved. The predecessor
        had two parsers for this string, one last-match-wins and one
        first-match-wins, so a duplicated key authenticated as one tenant and
        inherited another's role.
        """
        raw = source.get("SENTINEL_API_KEYS", "")
        bindings: dict[str, ApiKey] = {}
        for entry in (e.strip() for e in raw.split(",") if e.strip()):
            parts = [p.strip() for p in entry.split(":")]
            if len(parts) not in (2, 3):
                raise ConfigurationError(
                    f"SENTINEL_API_KEYS entry {entry!r} must be 'tenant:key' or "
                    "'tenant:key:role'"
                )
            tenant, key = parts[0], parts[1]
            role = (parts[2] if len(parts) == 3 else "ingest").lower()
            if not tenant or not key:
                raise ConfigurationError(f"SENTINEL_API_KEYS entry {entry!r} has an empty field")
            if role not in VALID_ROLES:
                raise ConfigurationError(
                    f"unknown role {role!r}; valid roles are {', '.join(sorted(VALID_ROLES))}"
                )
            if production and len(key) < MIN_KEY_LENGTH:
                raise ConfigurationError(
                    f"API key for tenant {tenant!r} is shorter than {MIN_KEY_LENGTH} "
                    "characters; short keys are not permitted in production"
                )
            digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
            if digest in bindings:
                raise ConfigurationError(
                    f"duplicate API key material shared by tenants "
                    f"{bindings[digest].tenant_id!r} and {tenant!r}. Key material "
                    "must be unique per tenant, otherwise authentication and "
                    "authorization can resolve to different entries."
                )
            bindings[digest] = ApiKey(tenant_id=tenant, role=role, key_hash=digest)

        if production and not bindings:
            raise ConfigurationError(
                "no API keys are configured. An unconfigured security service "
                "must not accept traffic; refusing to start."
            )
        return bindings

    @staticmethod
    def _parse_engine(source: Mapping[str, str], *, production: bool) -> EngineConfig:
        url = source.get("SENTINEL_DATABASE_URL", "").strip()
        if url:
            if not url.startswith(("postgresql://", "postgresql+psycopg://")):
                raise ConfigurationError(
                    "SENTINEL_DATABASE_URL must be a PostgreSQL URL. Sentinel will "
                    "not silently substitute a different backend."
                )
            return EngineConfig(
                dialect=Dialect.POSTGRES,
                dsn=url,
                pool_min=_parsers.positive_int(source, "SENTINEL_DB_POOL_MIN", 2),
                pool_max=_parsers.positive_int(source, "SENTINEL_DB_POOL_MAX", 20),
            )
        if production:
            raise ConfigurationError(
                "SENTINEL_ENV=production requires SENTINEL_DATABASE_URL to name a "
                "PostgreSQL server. SQLite is single-writer and cannot serve "
                "multiple replicas."
            )
        path = source.get("SENTINEL_DB_PATH", "").strip() or str(
            Path.cwd() / "data" / "sentinel.db"
        )
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        return EngineConfig(dialect=Dialect.SQLITE, dsn=path, pool_min=1, pool_max=4)

    @staticmethod
    def _delegation_keys(source: Mapping[str, str]) -> tuple[tuple[str, str], ...]:
        """`SENTINEL_DELEGATION_KEYS`: comma-separated `issuer#version=base64`.

        Only the SHAPE is validated here; the bytes are decoded into keys by
        the composition root, which is where a malformed key fails at startup
        rather than at the first chain that names it. The `#` namespace
        separator is required because `verify_chain` reads the issuer off the
        key id, and a key id without one belongs to nobody.
        """
        raw = source.get("SENTINEL_DELEGATION_KEYS", "") or ""
        pairs: list[tuple[str, str]] = []
        for entry in (e.strip() for e in raw.split(",") if e.strip()):
            key_id, separator, material = entry.partition("=")
            key_id = key_id.strip()
            material = material.strip()
            if not separator or not key_id or not material:
                raise ConfigurationError(
                    "SENTINEL_DELEGATION_KEYS entries must be "
                    f"`issuer#version=base64-public-key`; got {entry!r}"
                )
            if "#" not in key_id or key_id.startswith("#") or key_id.endswith("#"):
                raise ConfigurationError(
                    f"SENTINEL_DELEGATION_KEYS key id {key_id!r} is not "
                    "namespaced as `issuer#version`, so no issuer owns it"
                )
            pairs.append((key_id, material))
        return tuple(pairs)

    @staticmethod
    def _region(source: Mapping[str, str]) -> Region:
        """Which region this deployment serves. Defaults to US.

        A closed set, so a typo fails at startup rather than assigning the
        deployment to a region no tenant matches -- which would make every
        residency check refuse and read as a total outage.
        """
        raw = (source.get("SENTINEL_REGION") or "us").strip().lower()
        try:
            return Region(raw)
        except ValueError as exc:
            raise ConfigurationError(
                f"SENTINEL_REGION={raw!r} is not a known region; use one of: "
                + ", ".join(r.value for r in Region)
            ) from exc

    @staticmethod
    def _protection_mode(source: Mapping[str, str]) -> ProtectionMode:
        """Resolve the operating mode, and refuse a self-contradicting config.

        `SENTINEL_PROTECT_ENFORCE` predates this and is what the gate actually
        reads. Two settings that both describe enforcement can disagree, and a
        deployment that believes it is in PROTECT while the gate is permissive
        is the worst of the available outcomes -- so the disagreement is a
        startup failure, not a precedence rule.

        Unset defaults to the mode implied by the existing boolean, so nothing
        that works today needs a new variable to keep working.
        """
        raw = (source.get("SENTINEL_PROTECTION_MODE") or "").strip()
        enforcing = str(source.get("SENTINEL_PROTECT_ENFORCE", "")).strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        if not raw:
            return ProtectionMode.PROTECT if enforcing else ProtectionMode.MONITOR

        try:
            mode = parse_mode(raw)
        except AmbiguousMode as exc:
            raise ConfigurationError(str(exc)) from exc

        if mode.enforces != enforcing:
            raise ConfigurationError(
                f"SENTINEL_PROTECTION_MODE={mode.value!r} "
                f"{'enforces' if mode.enforces else 'does not enforce'}, but "
                f"SENTINEL_PROTECT_ENFORCE is "
                f"{'set' if enforcing else 'unset'}. These describe the same "
                f"thing and must agree; a deployment that believes it is "
                f"enforcing while the gate is permissive is the worst outcome."
            )
        return mode
