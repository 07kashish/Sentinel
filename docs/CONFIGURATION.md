# Configuration reference

Sentinel reads configuration at startup. This reference covers the kept service,
SDK bridge and operational tools; it does not claim parked features are available.
The [example environment](../.env.example) supplies deployment examples. Example
assignments are not necessarily parser defaults: an optional integration must be
fully configured or entirely unset.

## Minimal local service

Use `SENTINEL_API_KEYS=tenant:token:admin` and `SENTINEL_DB_PATH` pointing to a
writable SQLite file. The environment defaults to development. Migrate before
starting the service. The [README](../README.md) contains the tested commands.
Do not copy a partial OIDC or platform configuration into a working environment.

## Security and production

Production requires PostgreSQL, API keys at least 32 characters long, explicit
CORS origins, explicit limiter failure and execution-binding choices, and an
explicit evidence-encryption decision. Multiple processes require a shared Redis
limiter; topology checks refuse ambiguous deployments unless single-process
operation is explicitly attested. Production refuses interactive API docs.

Decisions default to advisory mode. Enforcement and execution binding are separate
controls: binding defaults on, while protect enforcement defaults off. Keep
remediation dry-run, kill-switch, workload-identity and capability-grant choices
explicit when operating the corresponding paths. Retention of incident records
is unlimited unless an operator sets a positive incident-retention period.

`SENTINEL_REGION` is retained and validated as requested by the cleanup plan, but
Settings.region currently has no runtime consumer. Do not treat that setting
alone as proof that a request was checked for residency.

Secrets accept a `_FILE` variant only where that exact name is listed below;
there is no universal file-loader suffix. For supported secret-file inputs, a
nonempty direct value wins over the mounted file. Never include real credentials
in committed environment files.

## Service fields and unchanged defaults

These are parser defaults with no environment overrides. Empty integration
configuration means no integration is built. Aggregate settings are expanded in
the environment-name reference below. The SQLite path is relative to the process
working directory; PostgreSQL defaults to a pool of 2–20 connections.

| Settings field | Default | Environment input(s) |
|---|---|---|
| `environment` | "development" | `SENTINEL_ENV` |
| `engine` | SQLite: `./data/sentinel.db`; pool 1–4 | `SENTINEL_DATABASE_URL`, `SENTINEL_DB_PATH`, `SENTINEL_DB_POOL_MAX`, `SENTINEL_DB_POOL_MIN`, `SENTINEL_ENV` |
| `api_keys` | unset / empty | `SENTINEL_API_KEYS`, `SENTINEL_ENV` |
| `cors_origins` | ["http://localhost:8000"] | `SENTINEL_CORS_ORIGINS` |
| `worker_shard` | 0 | `SENTINEL_WORKER_SHARD` |
| `worker_shard_count` | 1 | `SENTINEL_WORKER_SHARD_COUNT` |
| `worker_poll_seconds` | 0.5 | `SENTINEL_WORKER_POLL_SECONDS` |
| `queue_max_attempts` | 5 | `SENTINEL_QUEUE_MAX_ATTEMPTS` |
| `queue_lease_seconds` | 300 | `SENTINEL_QUEUE_LEASE_SECONDS` |
| `outbox_batch_size` | 50 | `SENTINEL_OUTBOX_BATCH` |
| `outbox_lease_seconds` | 120 | `SENTINEL_OUTBOX_LEASE_SECONDS` |
| `retention_days` | 90 | `SENTINEL_RETENTION_DAYS` |
| `retention_interval_seconds` | 3600 | `SENTINEL_RETENTION_INTERVAL` |
| `incident_retention_days` | null | `SENTINEL_INCIDENT_RETENTION_DAYS` |
| `attestation_endpoint` | unset / empty | `SENTINEL_ATTESTATION_ENDPOINT` |
| `attestation_token` | unset / empty | `SENTINEL_ATTESTATION_TOKEN` |
| `tenant_siem_sinks` | unset / empty | `SENTINEL_TENANT_SIEM_SINKS` |
| `tenant_siem_credentials` | unset / empty | nested mapping; see below |
| `siem_webhook_url` | unset / empty | `SENTINEL_SIEM_WEBHOOK_URL` |
| `siem_webhook_token` | unset / empty | `SENTINEL_SIEM_WEBHOOK_TOKEN` |
| `replay_window_seconds` | 300 | `SENTINEL_REPLAY_WINDOW` |
| `expose_api_docs` | false | `SENTINEL_EXPOSE_API_DOCS` |
| `rate_limit_fail_open` | true | `SENTINEL_RATE_LIMIT_FAIL_OPEN` |
| `require_execution_binding` | true | `SENTINEL_REQUIRE_EXECUTION_BINDING` |
| `trusted_proxy_hops` | 0 | `SENTINEL_TRUSTED_PROXY_HOPS` |
| `auth_failure_limit_per_minute` | 10 | `SENTINEL_AUTH_FAILURE_LIMIT` |
| `credential_limit_per_minute` | 600 | `SENTINEL_CREDENTIAL_LIMIT` |
| `address_limit_per_minute` | 120 | `SENTINEL_ADDRESS_LIMIT` |
| `redis_url` | unset / empty | `SENTINEL_REDIS_URL` |
| `protection_mode` | "monitor" | `SENTINEL_PROTECTION_MODE`, `SENTINEL_PROTECT_ENFORCE` |
| `region` | "us" | `SENTINEL_REGION` |
| `protect_enforcement` | false | `SENTINEL_PROTECT_ENFORCE` |
| `protect_kill_switch` | false | `SENTINEL_PROTECT_KILL_SWITCH` |
| `remediation_endpoints` | unset / empty | `SENTINEL_REMEDIATION_ENDPOINTS` |
| `remediation_dry_run` | false | `SENTINEL_REMEDIATION_DRY_RUN` |
| `mcp_require_pin` | true | `SENTINEL_MCP_REQUIRE_PIN` |
| `mcp_proxy_enabled` | false | `SENTINEL_MCP_PROXY_ENABLED` |
| `mcp_proxy_allowed_hosts` | unset / empty | `SENTINEL_MCP_PROXY_ALLOWED_HOSTS` |
| `mcp_proxy_allow_private` | false | `SENTINEL_MCP_PROXY_ALLOW_PRIVATE` |
| `mcp_proxy_require_token_audience` | true | `SENTINEL_MCP_PROXY_REQUIRE_TOKEN_AUDIENCE` |
| `mcp_proxy_definition_cache_seconds` | 0.0 | `SENTINEL_MCP_PROXY_DEFINITION_CACHE_SECONDS` |
| `agent_require_grant` | false | `SENTINEL_AGENT_REQUIRE_GRANT` |
| `tool_file_root` | unset / empty | `SENTINEL_TOOL_FILE_ROOT` |
| `tool_http_allowed_hosts` | unset / empty | `SENTINEL_TOOL_HTTP_ALLOWED_HOSTS` |
| `platform_adapters` | unset / empty | `SENTINEL_AWS_ACCESS_KEY_ID`, `SENTINEL_AWS_CEILING`, `SENTINEL_AWS_EXECUTOR_ROLE_ARN`, `SENTINEL_AWS_REGION`, `SENTINEL_AWS_SECRET_ACCESS_KEY`, `SENTINEL_AWS_SECRET_ACCESS_KEY_FILE`, `SENTINEL_AWS_SESSION_TOKEN`, `SENTINEL_AWS_SESSION_TOKEN_FILE`, `SENTINEL_GITHUB_API_HOST`, `SENTINEL_GITHUB_APP_ID`, `SENTINEL_GITHUB_APP_PRIVATE_KEY`, `SENTINEL_GITHUB_APP_PRIVATE_KEY_FILE`, `SENTINEL_GITHUB_CEILING`, `SENTINEL_GITHUB_INSTALLATION_ID`, `SENTINEL_GITHUB_TOKEN`, `SENTINEL_GITHUB_TOKEN_FILE`, `SENTINEL_KUBERNETES_API_SERVER`, `SENTINEL_KUBERNETES_CA_FILE`, `SENTINEL_KUBERNETES_CEILING`, `SENTINEL_KUBERNETES_EXECUTOR_NAMESPACE`, `SENTINEL_KUBERNETES_EXECUTOR_SERVICE_ACCOUNT`, `SENTINEL_KUBERNETES_TOKEN`, `SENTINEL_KUBERNETES_TOKEN_AUDIENCE`, `SENTINEL_KUBERNETES_TOKEN_FILE`, `SENTINEL_KUBERNETES_TOKEN_TTL_SECONDS`, `SENTINEL_POSTGRES_CEILING`, `SENTINEL_POSTGRES_DSN`, `SENTINEL_POSTGRES_DSN_FILE`, `SENTINEL_POSTGRES_STATEMENT_TIMEOUT_MS` |
| `siem_transports` | unset / empty | `SENTINEL_SIEM_`, `SENTINEL_SIEM_KAFKA_`, `SENTINEL_SIEM_OTLP_SERVICE_NAME`, `SENTINEL_SIEM_OTLP_TOKEN`, `SENTINEL_SIEM_OTLP_TOKEN_FILE`, `SENTINEL_SIEM_OTLP_URL`, `SENTINEL_SIEM_SYSLOG_APP_NAME`, `SENTINEL_SIEM_SYSLOG_HOST`, `SENTINEL_SIEM_SYSLOG_PORT` |
| `tool_budget_per_minute` | 0 | `SENTINEL_TOOL_BUDGET_PER_MINUTE` |
| `protect_circuit_threshold` | 20 | `SENTINEL_PROTECT_CIRCUIT_THRESHOLD` |
| `operation_pending_deadline_seconds` | 900 | `SENTINEL_OPERATION_PENDING_DEADLINE_SECONDS` |
| `bypass_idle_seconds` | 900 | `SENTINEL_BYPASS_IDLE_SECONDS` |
| `ready_exposes_detection_mode` | false | `SENTINEL_READY_EXPOSE_DETECTION_MODE` |
| `oidc_issuer` | unset / empty | `SENTINEL_OIDC_ISSUER` |
| `oidc_audience` | unset / empty | `SENTINEL_OIDC_AUDIENCE` |
| `oidc_jwks_json` | unset / empty | `SENTINEL_OIDC_JWKS_JSON` |
| `oidc_tenant_claim` | "tenant_id" | `SENTINEL_OIDC_TENANT_CLAIM` |
| `oidc_role_claim` | "role" | `SENTINEL_OIDC_ROLE_CLAIM` |
| `metrics_token` | unset / empty | `SENTINEL_METRICS_TOKEN`, `SENTINEL_METRICS_TOKEN_FILE` |
| `otlp_endpoint` | unset / empty | `SENTINEL_OTLP_ENDPOINT` |
| `agent_idp_json` | unset / empty | `SENTINEL_AGENT_IDP_JSON` |
| `root_sink` | {"bucket": "", "region": "", "access_key_id": "", "secret_access_key": "", "session_token": "", "container_credentials_uri": "", "container_authorization": "", "retention_days": 3650, "publish_tenants": [], "publish_interval_seconds": 86400} | `SENTINEL_ROOT_PUBLISH_INTERVAL_SECONDS`, `SENTINEL_ROOT_PUBLISH_TENANTS`, `SENTINEL_S3_ROOT_ACCESS_KEY_ID`, `SENTINEL_S3_ROOT_BUCKET`, `SENTINEL_S3_ROOT_REGION`, `SENTINEL_S3_ROOT_RETENTION_DAYS`, `SENTINEL_S3_ROOT_SECRET_ACCESS_KEY`, `SENTINEL_S3_ROOT_SESSION_TOKEN` |
| `workflow` | {"require_workload_identity": false, "approval_quorum": 1, "approval_separation_of_duties": true, "reconcile_max_attempts": 5, "mcp_proxy_streaming": false, "evidence_keys": {}, "evidence_active_key": ""} | `SENTINEL_ACTIVE_KEY_ID`, `SENTINEL_APPROVAL_QUORUM`, `SENTINEL_APPROVAL_SEPARATION_OF_DUTIES`, `SENTINEL_DATA_KEY_`, `SENTINEL_ENV`, `SENTINEL_EVIDENCE_ENCRYPTION`, `SENTINEL_MCP_PROXY_STREAMING`, `SENTINEL_RECONCILE_MAX_ATTEMPTS`, `SENTINEL_REQUIRE_WORKLOAD_IDENTITY` |
| `advisor` | {"endpoint": "", "model": "", "token": "", "cli_command": "", "cli_home": ""} | `SENTINEL_ADVISOR_CLI_COMMAND`, `SENTINEL_ADVISOR_CLI_HOME`, `SENTINEL_ADVISOR_ENDPOINT`, `SENTINEL_ADVISOR_MODEL`, `SENTINEL_ADVISOR_TOKEN` |

## Environment-name reference

The consumer column identifies where parsed values reach kept behavior, rather
than counting the parser itself as a consumer. Locations are from the Phase 4
input audit. Operational-only and example shell variables are labeled separately.
The unsupported SIEM transport family is a startup refusal, not a Kafka exporter.

Platform groups are all-or-nothing. AWS needs access key, secret and region;
GitHub accepts a token or an App id, installation id and private key together;
Kubernetes needs API server and token; PostgreSQL needs its target DSN. Optional
ceilings default to low, the GitHub host to api.github.com, PostgreSQL statement
timeout to 5000 ms, and Kubernetes token TTL to 600 seconds. These defaults are
unchanged. Do not point the agent PostgreSQL adapter at Sentinel's own database.

SIEM OTLP needs its URL (service name defaults to sentinel); TLS syslog needs its
host (port 6514, app name sentinel). OIDC requires issuer, audience and JWKS
JSON together. The advisor requires endpoint, model and token together, or the
configured local CLI and model; it provides advisory text and has no decision
authority. Root publication requires a sink and explicitly selected tenants.

| Name | Purpose / scope | Kept consumer |
|---|---|---|
| `SENTINEL_ACTIVE_KEY_ID` | workflow | sentinel/composition/evidence_wiring.py:17 |
| `SENTINEL_ADDRESS_LIMIT` | address_limit_per_minute | sentinel/composition/adapters.py:72; sentinel/interface/http.py:136 |
| `SENTINEL_ADVISOR_CLI_COMMAND` | advisor | sentinel/composition/advisor_wiring.py:14 |
| `SENTINEL_ADVISOR_CLI_HOME` | advisor | sentinel/composition/advisor_wiring.py:14 |
| `SENTINEL_ADVISOR_ENDPOINT` | advisor | sentinel/composition/advisor_wiring.py:14 |
| `SENTINEL_ADVISOR_MODEL` | advisor | sentinel/composition/advisor_wiring.py:14 |
| `SENTINEL_ADVISOR_TOKEN` | advisor | sentinel/composition/advisor_wiring.py:14 |
| `SENTINEL_AGENT_ID` | CLI/operational input | sentinel/sdk/mcp_stdio.py:288; sentinel/sdk/mcp_stdio.py:330 |
| `SENTINEL_AGENT_IDP_JSON` | agent_idp_json | sentinel/composition/container.py:550; sentinel/composition/container.py:552 |
| `SENTINEL_AGENT_REQUIRE_GRANT` | agent_require_grant | sentinel/composition/container.py:468; sentinel/composition/container.py:473 |
| `SENTINEL_API_KEY` | CLI/operational input | sentinel/sdk/mcp_stdio.py:292 |
| `SENTINEL_API_KEYS` | api_keys | sentinel/interface/health_routes.py:120; sentinel/interface/health_routes.py:148 |
| `SENTINEL_APPROVAL_QUORUM` | workflow | sentinel/interface/authorizations.py:395 |
| `SENTINEL_APPROVAL_SEPARATION_OF_DUTIES` | workflow | sentinel/interface/authorizations.py:294 |
| `SENTINEL_ATTESTATION_ENDPOINT` | attestation_endpoint | sentinel/composition/adapters.py:116; sentinel/composition/adapters.py:118 |
| `SENTINEL_ATTESTATION_TOKEN` | attestation_token | sentinel/composition/adapters.py:118 |
| `SENTINEL_AUTH_FAILURE_LIMIT` | auth_failure_limit_per_minute | sentinel/composition/adapters.py:70; sentinel/interface/http.py:134 |
| `SENTINEL_AWS_ACCESS_KEY_ID` | platform_adapters | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 |
| `SENTINEL_AWS_CEILING` | platform_adapters | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 |
| `SENTINEL_AWS_EXECUTOR_ROLE_ARN` | platform_adapters | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 |
| `SENTINEL_AWS_REGION` | platform_adapters | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 |
| `SENTINEL_AWS_SECRET_ACCESS_KEY` | platform_adapters | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 |
| `SENTINEL_AWS_SECRET_ACCESS_KEY_FILE` | platform_adapters | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 |
| `SENTINEL_AWS_SESSION_TOKEN` | platform_adapters | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 |
| `SENTINEL_AWS_SESSION_TOKEN_FILE` | platform_adapters | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 |
| `SENTINEL_BOOTSTRAP_TENANT` | CLI/operational input | scripts/quickstart.py:225 |
| `SENTINEL_BYPASS_IDLE_SECONDS` | bypass_idle_seconds | sentinel/interface/extra_routes.py:200; sentinel/interface/extra_routes.py:203 |
| `SENTINEL_CORS_ORIGINS` | cors_origins | sentinel/interface/http.py:185; sentinel/interface/http.py:188 |
| `SENTINEL_CREDENTIAL_LIMIT` | credential_limit_per_minute | sentinel/composition/adapters.py:71; sentinel/interface/http.py:135 |
| `SENTINEL_DATABASE_URL` | engine | sentinel/composition/container.py:317; sentinel/composition/platform_wiring.py:143 |
| `SENTINEL_DATA_KEY_` | workflow | sentinel/composition/evidence_wiring.py:17 |
| `SENTINEL_DATA_KEY_K1` | evidence key family | sentinel/composition/evidence_wiring.py:17 |
| `SENTINEL_DB_PATH` | engine | sentinel/composition/container.py:317; sentinel/composition/platform_wiring.py:143 |
| `SENTINEL_DB_POOL_MAX` | engine | sentinel/composition/container.py:317; sentinel/composition/platform_wiring.py:143 |
| `SENTINEL_DB_POOL_MIN` | engine | sentinel/composition/container.py:317; sentinel/composition/platform_wiring.py:143 |
| `SENTINEL_ENV` | environment, engine, api_keys, workflow | sentinel/interface/asgi.py:123; sentinel/composition/container.py:317; sentinel/composition/platform_wiring.py:143; sentinel/interface/health_routes.py:120; sentinel/interface/health_routes.py:148; sentinel/composition/container.py:699; sentinel/composition/evidence_wiring.py:17 |
| `SENTINEL_EVIDENCE_ENCRYPTION` | workflow | sentinel/composition/evidence_wiring.py:17 |
| `SENTINEL_EXPOSE_API_DOCS` | expose_api_docs | sentinel/interface/http.py:103 |
| `SENTINEL_GITHUB_API_HOST` | platform_adapters | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 |
| `SENTINEL_GITHUB_APP_ID` | platform_adapters | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 |
| `SENTINEL_GITHUB_APP_PRIVATE_KEY` | platform_adapters | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 |
| `SENTINEL_GITHUB_APP_PRIVATE_KEY_FILE` | platform_adapters | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 |
| `SENTINEL_GITHUB_CEILING` | platform_adapters | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 |
| `SENTINEL_GITHUB_INSTALLATION_ID` | platform_adapters | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 |
| `SENTINEL_GITHUB_TOKEN` | platform_adapters | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 |
| `SENTINEL_GITHUB_TOKEN_FILE` | platform_adapters | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 |
| `SENTINEL_HELM_VALUES` | shell variable passed to Helm, not a service setting | docs/OPERATIONS.md:126 |
| `SENTINEL_INCIDENT_RETENTION_DAYS` | incident_retention_days | sentinel/interface/worker.py:542 |
| `SENTINEL_INGEST_KEY` | curl token placeholder, not a service setting | docs/INTEGRATIONS.md:876 |
| `SENTINEL_KUBERNETES_API_SERVER` | platform_adapters | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 |
| `SENTINEL_KUBERNETES_CA_FILE` | platform_adapters | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 |
| `SENTINEL_KUBERNETES_CEILING` | platform_adapters | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 |
| `SENTINEL_KUBERNETES_EXECUTOR_NAMESPACE` | platform_adapters | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 |
| `SENTINEL_KUBERNETES_EXECUTOR_SERVICE_ACCOUNT` | platform_adapters | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 |
| `SENTINEL_KUBERNETES_TOKEN` | platform_adapters | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 |
| `SENTINEL_KUBERNETES_TOKEN_AUDIENCE` | platform_adapters | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 |
| `SENTINEL_KUBERNETES_TOKEN_FILE` | platform_adapters | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 |
| `SENTINEL_KUBERNETES_TOKEN_TTL_SECONDS` | platform_adapters | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 |
| `SENTINEL_MCP_PROXY_ALLOWED_HOSTS` | mcp_proxy_allowed_hosts | sentinel/composition/proxy_wiring.py:30; sentinel/interface/mcp_proxy_routes.py:266 |
| `SENTINEL_MCP_PROXY_ALLOW_PRIVATE` | mcp_proxy_allow_private | sentinel/composition/proxy_wiring.py:31 |
| `SENTINEL_MCP_PROXY_DEFINITION_CACHE_SECONDS` | mcp_proxy_definition_cache_seconds | sentinel/interface/mcp_proxy_routes.py:399; scripts/run_mcp_proxy_bench.py:192 |
| `SENTINEL_MCP_PROXY_ENABLED` | mcp_proxy_enabled | sentinel/composition/proxy_wiring.py:25 |
| `SENTINEL_MCP_PROXY_REQUIRE_TOKEN_AUDIENCE` | mcp_proxy_require_token_audience | sentinel/interface/mcp_proxy_routes.py:276 |
| `SENTINEL_MCP_PROXY_STREAMING` | workflow | sentinel/interface/mcp_proxy_routes.py:159 |
| `SENTINEL_MCP_REQUIRE_PIN` | mcp_require_pin | sentinel/composition/container.py:518 |
| `SENTINEL_METRICS_TOKEN` | metrics_token | sentinel/interface/http.py:704 |
| `SENTINEL_METRICS_TOKEN_FILE` | metrics_token | sentinel/interface/http.py:704 |
| `SENTINEL_OIDC_AUDIENCE` | oidc_audience | sentinel/composition/container.py:540 |
| `SENTINEL_OIDC_ISSUER` | oidc_issuer | sentinel/composition/container.py:539 |
| `SENTINEL_OIDC_JWKS_JSON` | oidc_jwks_json | sentinel/composition/container.py:541 |
| `SENTINEL_OIDC_ROLE_CLAIM` | oidc_role_claim | sentinel/composition/container.py:543 |
| `SENTINEL_OIDC_TENANT_CLAIM` | oidc_tenant_claim | sentinel/composition/container.py:542 |
| `SENTINEL_OPERATION_PENDING_DEADLINE_SECONDS` | operation_pending_deadline_seconds | sentinel/interface/worker.py:432 |
| `SENTINEL_OTLP_ENDPOINT` | otlp_endpoint | sentinel/composition/container.py:534 |
| `SENTINEL_OUTBOX_BATCH` | outbox_batch_size | sentinel/composition/container.py:635 |
| `SENTINEL_OUTBOX_LEASE_SECONDS` | outbox_lease_seconds | sentinel/composition/container.py:636 |
| `SENTINEL_PIPELINE_WORKERS` | process topology/worker control | sentinel/interface/asgi.py:57 |
| `SENTINEL_POSTGRES_CEILING` | platform_adapters | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 |
| `SENTINEL_POSTGRES_DSN` | platform_adapters | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 |
| `SENTINEL_POSTGRES_DSN_FILE` | platform_adapters | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 |
| `SENTINEL_POSTGRES_STATEMENT_TIMEOUT_MS` | platform_adapters | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 |
| `SENTINEL_PROTECTION_MODE` | protection_mode | sentinel/interface/health_routes.py:165; sentinel/interface/health_routes.py:166 |
| `SENTINEL_PROTECT_CIRCUIT_THRESHOLD` | protect_circuit_threshold | sentinel/composition/container.py:388 |
| `SENTINEL_PROTECT_ENFORCE` | protection_mode, protect_enforcement | sentinel/interface/health_routes.py:165; sentinel/interface/health_routes.py:166; sentinel/composition/container.py:376; sentinel/composition/container.py:467 |
| `SENTINEL_PROTECT_KILL_SWITCH` | protect_kill_switch | sentinel/composition/container.py:386; sentinel/interface/authorizations.py:231 |
| `SENTINEL_PUBLISH_TENANTS` | CLI/operational input | scripts/publish_transparency_root.py:151; scripts/publish_transparency_root.py:146 |
| `SENTINEL_QUEUE_LEASE_SECONDS` | queue_lease_seconds | sentinel/composition/container.py:345; sentinel/interface/worker.py:376 |
| `SENTINEL_QUEUE_MAX_ATTEMPTS` | queue_max_attempts | sentinel/composition/container.py:344 |
| `SENTINEL_RATE_LIMIT_FAIL_OPEN` | rate_limit_fail_open | sentinel/composition/adapters.py:88 |
| `SENTINEL_READY_EXPOSE_DETECTION_MODE` | ready_exposes_detection_mode | sentinel/interface/health_routes.py:123 |
| `SENTINEL_RECONCILE_MAX_ATTEMPTS` | workflow | sentinel/composition/container.py:699 |
| `SENTINEL_REDIS_URL` | redis_url | sentinel/composition/adapters.py:74; sentinel/composition/adapters.py:75 |
| `SENTINEL_REGION` | explicit user preservation; parsed/validated, no runtime consumer | none |
| `SENTINEL_REMEDIATION_DRY_RUN` | remediation_dry_run | sentinel/composition/container.py:512; sentinel/composition/remediation_wiring.py:91 |
| `SENTINEL_REMEDIATION_ENDPOINTS` | remediation_endpoints | sentinel/composition/container.py:508; sentinel/composition/container.py:511 |
| `SENTINEL_REPLAY_WINDOW` | replay_window_seconds | sentinel/composition/container.py:350 |
| `SENTINEL_REQUIRE_EXECUTION_BINDING` | require_execution_binding | sentinel/composition/container.py:415; sentinel/interface/extra_routes.py:129 |
| `SENTINEL_REQUIRE_WORKLOAD_IDENTITY` | workflow | sentinel/interface/principals.py:210 |
| `SENTINEL_RETENTION_DAYS` | retention_days | sentinel/interface/worker.py:512 |
| `SENTINEL_RETENTION_INTERVAL` | retention_interval_seconds | sentinel/interface/worker.py:504 |
| `SENTINEL_ROOT_PUBLISH_INTERVAL_SECONDS` | root_sink | sentinel/interface/worker.py:330 |
| `SENTINEL_ROOT_PUBLISH_TENANTS` | root_sink | sentinel/interface/worker.py:327 |
| `SENTINEL_S3_ROOT_` | documented family prefix | sentinel/composition/root_sink_wiring.py:27 |
| `SENTINEL_S3_ROOT_ACCESS_KEY_ID` | root_sink | sentinel/composition/root_sink_wiring.py:20; sentinel/composition/root_sink_wiring.py:27 |
| `SENTINEL_S3_ROOT_BUCKET` | root_sink | sentinel/composition/root_sink_wiring.py:20; sentinel/composition/root_sink_wiring.py:27 |
| `SENTINEL_S3_ROOT_REGION` | root_sink | sentinel/composition/root_sink_wiring.py:20; sentinel/composition/root_sink_wiring.py:27 |
| `SENTINEL_S3_ROOT_RETENTION_DAYS` | root_sink | sentinel/composition/root_sink_wiring.py:20; sentinel/composition/root_sink_wiring.py:27 |
| `SENTINEL_S3_ROOT_SECRET_ACCESS_KEY` | root_sink | sentinel/composition/root_sink_wiring.py:20; sentinel/composition/root_sink_wiring.py:27 |
| `SENTINEL_S3_ROOT_SESSION_TOKEN` | root_sink | sentinel/composition/root_sink_wiring.py:20; sentinel/composition/root_sink_wiring.py:27 |
| `SENTINEL_SIEM_KAFKA_` | security refusal for unsupported transport; no Kafka integration | sentinel/composition/settings_parsers.py:272 |
| `SENTINEL_SIEM_OTLP_SERVICE_NAME` | siem_transports | sentinel/composition/siem_wiring.py:135 |
| `SENTINEL_SIEM_OTLP_TOKEN` | siem_transports | sentinel/composition/siem_wiring.py:135 |
| `SENTINEL_SIEM_OTLP_TOKEN_FILE` | siem_transports | sentinel/composition/siem_wiring.py:135 |
| `SENTINEL_SIEM_OTLP_URL` | siem_transports | sentinel/composition/siem_wiring.py:135 |
| `SENTINEL_SIEM_SYSLOG_APP_NAME` | siem_transports | sentinel/composition/siem_wiring.py:135 |
| `SENTINEL_SIEM_SYSLOG_HOST` | siem_transports | sentinel/composition/siem_wiring.py:135 |
| `SENTINEL_SIEM_SYSLOG_PORT` | siem_transports | sentinel/composition/siem_wiring.py:135 |
| `SENTINEL_SIEM_WEBHOOK_TOKEN` | siem_webhook_token | sentinel/composition/siem_wiring.py:132 |
| `SENTINEL_SIEM_WEBHOOK_URL` | siem_webhook_url | sentinel/composition/siem_wiring.py:128; sentinel/composition/siem_wiring.py:131 |
| `SENTINEL_SINGLE_PROCESS_ATTESTED` | process topology/worker control | sentinel/interface/asgi.py:99 |
| `SENTINEL_TENANT_SIEM_SECRET_` | tenant SIEM credential family | sentinel/composition/siem_wiring.py:114 |
| `SENTINEL_TENANT_SIEM_SINKS` | tenant_siem_sinks | sentinel/composition/siem_wiring.py:68; sentinel/composition/siem_wiring.py:76 |
| `SENTINEL_TEST_PG_BIN` | live verification infrastructure selector | scripts/run_dr_postgres_wal_pitr_drill.py:94 |
| `SENTINEL_TEST_POSTGRES_DSN` | live verification infrastructure selector | scripts/run_dr_test.py:82; scripts/_embedded_postgres.py:128 |
| `SENTINEL_TEST_REDIS_URL` | live verification infrastructure selector | scripts/run_release_gates.py:219; scripts/run_release_gates.py:221 |
| `SENTINEL_TOOL_BUDGET_PER_MINUTE` | tool_budget_per_minute | sentinel/composition/container.py:387 |
| `SENTINEL_TOOL_FILE_ROOT` | tool_file_root | sentinel/composition/container.py:436 |
| `SENTINEL_TOOL_HTTP_ALLOWED_HOSTS` | tool_http_allowed_hosts | sentinel/composition/container.py:437 |
| `SENTINEL_TRUSTED_PROXY_HOPS` | trusted_proxy_hops | sentinel/interface/http.py:133 |
| `SENTINEL_UPSTREAM_AUTHORIZATION` | CLI/operational input | sentinel/sdk/mcp_stdio.py:300 |
| `SENTINEL_WAL_S3_` | documented family prefix | deploy/wal-archive/wal_s3.py:90 |
| `SENTINEL_WAL_S3_ACCESS_KEY` | protected WAL archiver configuration | deploy/wal-archive/wal_s3.py:92 |
| `SENTINEL_WAL_S3_ALLOW_PRIVATE` | protected WAL archiver configuration | deploy/wal-archive/wal_s3.py:111 |
| `SENTINEL_WAL_S3_BUCKET` | protected WAL archiver configuration | deploy/wal-archive/wal_s3.py:91 |
| `SENTINEL_WAL_S3_CLUSTER` | protected WAL archiver configuration | deploy/wal-archive/wal_s3.py:135 |
| `SENTINEL_WAL_S3_ENDPOINT` | protected WAL archiver configuration | deploy/wal-archive/wal_s3.py:90 |
| `SENTINEL_WAL_S3_REGION` | protected WAL archiver configuration | deploy/wal-archive/wal_s3.py:125 |
| `SENTINEL_WAL_S3_SECRET_KEY` | protected WAL archiver configuration | deploy/wal-archive/wal_s3.py:93 |
| `SENTINEL_WORKER_POLL_SECONDS` | worker_poll_seconds | sentinel/interface/worker.py:76 |
| `SENTINEL_WORKER_SHARD` | worker_shard | sentinel/interface/asgi.py:125; sentinel/interface/http.py:166 |
| `SENTINEL_WORKER_SHARD_COUNT` | worker_shard_count | sentinel/composition/container.py:343; sentinel/interface/asgi.py:126 |

## Operational inputs

The WAL archiver reads its own endpoint, bucket, access key, secret key, optional
region (us-east-1), cluster prefix and private-destination opt-in (false).
These are backup controls, not ASGI service flags. See
[operations](OPERATIONS.md) for recovery procedures and failure-domain limits.
The live PostgreSQL/Redis selectors choose verification infrastructure; they do
not turn unavailable infrastructure into passing evidence. The Helm-values and
curl-token variables shown in operating examples are shell placeholders.

For integrations, see [INTEGRATIONS.md](INTEGRATIONS.md). For the retired feature
inventory and removed configuration names, see [PARKED.md](PARKED.md).
