# Parked features

Phase 3 removes the features listed here from the current product. Their original
implementations remain recoverable from the immutable `archive/pre-cleanup` tag.
An entry is marked complete only after its routes, configuration, runtime and
feature-only tests are removed and the required checks pass.

## MCP compatibility decision

MCP reply inspection retains the deterministic ProtectGate, unsigned trust,
bounded text extraction, refusal handling, receipts and streaming. Its policy
payload preserves eventType, action, resource, agentId and metadata.prompt;
synthetic metadata.a2a is retired.

Custom policy rules matching metadata.a2a.* (or eventType agent_delegation from A2A) no longer match anything; no shipped rule used them.

This retirement applies to A2A-originated events when A2A is parked. MCP reply
events retain `eventType: agent_delegation` for compatibility. Operators with
custom rules depending on the retired A2A metadata must migrate those rules.

## Removed environment settings

The executable scan reads this catalog and also checks `_FILE` variants. A name
ending in an underscore represents a retired configuration prefix. Removal
records retain full names in exactly CHANGES.md, CLEANUP_PLAN.md and this file;
the scan checks every other tracked or unignored product file.

<!-- removed-settings:start -->
```json
[
  "SENTINEL_A2A_PROXY_ALLOWED_HOSTS",
  "SENTINEL_A2A_PROXY_ALLOW_PRIVATE",
  "SENTINEL_A2A_PROXY_ENABLED",
  "SENTINEL_CONSOLE_DEMO_TOKEN",
  "SENTINEL_DELEGATION_KEYS",
  "SENTINEL_DEMO_",
  "SENTINEL_DEMO_ADMIN_KEY",
  "SENTINEL_DEMO_ANALYST_KEY",
  "SENTINEL_DEMO_INGEST_KEY",
  "SENTINEL_DETONATION_IMAGE",
  "SENTINEL_DETONATION_TRACING",
  "SENTINEL_DISCOVERY_",
  "SENTINEL_DISCOVERY_AWS",
  "SENTINEL_DISCOVERY_AWS_ACCESS_KEY_ID",
  "SENTINEL_DISCOVERY_AWS_PATH_PREFIX",
  "SENTINEL_DISCOVERY_AWS_REGION",
  "SENTINEL_DISCOVERY_AWS_SECRET_ACCESS_KEY",
  "SENTINEL_DISCOVERY_BEDROCK",
  "SENTINEL_DISCOVERY_BEDROCK_ACCESS_KEY_ID",
  "SENTINEL_DISCOVERY_BEDROCK_REGION",
  "SENTINEL_DISCOVERY_BEDROCK_SECRET_ACCESS_KEY",
  "SENTINEL_DISCOVERY_COPILOT_ENVIRONMENTS",
  "SENTINEL_DISCOVERY_COPILOT_TOKEN",
  "SENTINEL_DISCOVERY_DATABRICKS",
  "SENTINEL_DISCOVERY_DATABRICKS_HOST",
  "SENTINEL_DISCOVERY_DATABRICKS_WORKSPACE",
  "SENTINEL_DISCOVERY_ENTRA_AGENT_ID_TENANT",
  "SENTINEL_DISCOVERY_ENTRA_AGENT_ID_TOKEN",
  "SENTINEL_DISCOVERY_ENTRA_TENANT",
  "SENTINEL_DISCOVERY_ENTRA_TOKEN",
  "SENTINEL_DISCOVERY_GITLAB",
  "SENTINEL_DISCOVERY_GITLAB_GROUP",
  "SENTINEL_DISCOVERY_GITLAB_HOST",
  "SENTINEL_DISCOVERY_GITLAB_PROJECTS",
  "SENTINEL_DISCOVERY_K8S_NAMESPACES",
  "SENTINEL_DISCOVERY_K8S_SERVER",
  "SENTINEL_DISCOVERY_K8S_TOKEN",
  "SENTINEL_DISCOVERY_MCP_CONFIG_PATHS",
  "SENTINEL_DISCOVERY_MCP_ENDPOINTS",
  "SENTINEL_DISCOVERY_MCP_TOKEN_",
  "SENTINEL_DISCOVERY_OKTA",
  "SENTINEL_DISCOVERY_OKTA_HOST",
  "SENTINEL_DISCOVERY_OKTA_ORG",
  "SENTINEL_DISCOVERY_OPENAI_ORG",
  "SENTINEL_DISCOVERY_OPENAI_TOKEN",
  "SENTINEL_DISCOVERY_SALESFORCE",
  "SENTINEL_DISCOVERY_SALESFORCE_HOST",
  "SENTINEL_DISCOVERY_SALESFORCE_ORG",
  "SENTINEL_DISCOVERY_SERVICENOW",
  "SENTINEL_DISCOVERY_SERVICENOW_HOST",
  "SENTINEL_DISCOVERY_SERVICENOW_INSTANCE",
  "SENTINEL_DISCOVERY_SLACK_BOT_IDS",
  "SENTINEL_DISCOVERY_SLACK_ENTERPRISE_ID",
  "SENTINEL_DISCOVERY_SLACK_TEAM_ID",
  "SENTINEL_DISCOVERY_SLACK_TOKEN",
  "SENTINEL_DISCOVERY_SLACK_WORKSPACE",
  "SENTINEL_DISCOVERY_VERTEX_LOCATION",
  "SENTINEL_DISCOVERY_VERTEX_PROJECT",
  "SENTINEL_DISCOVERY_VERTEX_TOKEN",
  "SENTINEL_SOAR_ENDPOINTS",
  "SENTINEL_SOAR_MIN_PRIORITY",
  "SENTINEL_SOAR_PAGERDUTY_ROUTING_KEY"
]
```
<!-- removed-settings:end -->

## Detonation and skill assessment

Purpose: isolated skill execution, syscall tracing and skill manifest/source assessment.
Removed 19 whole files (6,205 physical lines); shared-file cuts are reported in CLEANUP_PLAN.md.
Removed route: `POST /v1/skills/assess`. Removed settings: `SENTINEL_DETONATION_IMAGE`, `SENTINEL_DETONATION_TRACING` (including `_FILE` variants). No dedicated tables.
Restore signal: a contracted customer requires running untrusted third-party skills in an isolated sandbox with independently verified syscall evidence.

Recovery paths at `archive/pre-cleanup`:

- `deploy/detonation/Dockerfile`
- `sentinel/application/skill_detonation.py`
- `sentinel/composition/detonation_wiring.py`
- `sentinel/domain/detonation.py`
- `sentinel/domain/observed_binding.py`
- `sentinel/domain/skills.py`
- `sentinel/infrastructure/detonation_container.py`
- `sentinel/infrastructure/detonation_tracing.py`
- `sentinel/infrastructure/skill_scanner.py`
- `sentinel/infrastructure/strace_parse.py`

Test recovery directory: `tests_arch/` at the same archive tag. Exact retired test paths are listed in [the cleanup inventory](../CLEANUP_PLAN.md).

## Local endpoint and device discovery

Purpose: local presence scanning, endpoint inventory and consented device-report import.
Removed 8 whole files (2,327 physical lines), the sentinel-discover entrypoint, and the pilot console screen.
Removed routes: GET /v1/pilot/setup, GET /v1/pilot/discovery-script, GET and POST /v1/pilot/devices, DELETE /v1/pilot/devices/{device_id}.
Removed setting: `SENTINEL_DISCOVERY_MCP_CONFIG_PATHS` and its `_FILE` variant.
Table scheduled for the single final migration: `device_discovery`. Historical DEVICE_STATEMENTS and maintenance remain until that migration; the runtime store is removed.
Restore signal: a contracted customer requires consented endpoint-installed-tool inventory and can validate its incomplete, self-reported coverage.
Remote MCP enrollment/discovery, inventory/observation, identity and execution controls remain supported.

Recovery paths at `archive/pre-cleanup`:

- `scripts/run_endpoint_sensor.py`
- `sentinel/domain/endpoint_sensor.py`
- `sentinel/infrastructure/endpoint_scan.py`
- `sentinel/infrastructure/platforms/local_mcp_configs.py`
- `sentinel/sdk/discovery.py`
- `sentinel/sdk/discovery_app.py`
- `sentinel/interface/pilot_routes.py`

Runtime store recovery: `sentinel/infrastructure/sql/device_discovery.py`. Tests recover from `tests_arch/`; exact retired paths are in [the cleanup inventory](../CLEANUP_PLAN.md).

## Vendor inventory discovery

Purpose: vendor asset enumeration and reconciliation, distinct from the retained event-observation inventory.
Removed 21 whole files (7,261 physical lines), container discovery wiring, the agent-discover CLI, and the dedicated Terraform discovery identity. No HTTP routes or dedicated tables.
Removed settings: all names in the retired `SENTINEL_DISCOVERY_` family, including dynamic credentials and `_FILE` forms; exact observed names are in the catalog above.
Restore signal: a contracted customer needs continuous asset enumeration for a named platform and can validate coverage, permissions and pagination against a real tenant.

Recovery paths at `archive/pre-cleanup`:

- `scripts/run_discovery.py`
- `sentinel/composition/discovery_wiring.py`
- `sentinel/infrastructure/platforms/ai_connectors.py`
- `sentinel/infrastructure/platforms/ai_discovery.py`
- `sentinel/infrastructure/platforms/connectors.py`
- `sentinel/infrastructure/platforms/copilot_studio.py`
- `sentinel/infrastructure/platforms/databricks_agents.py`
- `sentinel/infrastructure/platforms/discovery.py`
- `sentinel/infrastructure/platforms/discovery_breadth.py`
- `sentinel/infrastructure/platforms/discovery_support.py`
- `sentinel/infrastructure/platforms/github_discovery.py`
- `sentinel/infrastructure/platforms/gitlab_discovery.py`
- `sentinel/infrastructure/platforms/identity_agents.py`
- `sentinel/infrastructure/platforms/salesforce_agentforce.py`
- `sentinel/infrastructure/platforms/servicenow_agents.py`
- `sentinel/infrastructure/platforms/slack_apps.py`

Tests recover from `tests_arch/`; exact retired paths and case deltas are in the cleanup inventory and group evidence.

### Reuse candidates for Phase 5

- `sentinel/infrastructure/platforms/github_discovery.py`: AI-agent markers in GitHub Actions; reference for GitHub 5.1/5.2.
- `sentinel/infrastructure/platforms/slack_apps.py`: Slack apps/bot users and HTTP-200 `ok:false` handling; reference for Slack 5.1/5.2.
- `sentinel/infrastructure/platforms/identity_agents.py` and `sentinel/infrastructure/platforms/discovery_support.py`: shared paging and credential-handling patterns.

These archived modules are reference material. Phase 5 implements cursor-based audit-log connectors; it does not reinstate the old discovery contract.

## Estate analysis and shared console demo

Purpose: AI bill of materials, adoption/value reports, exposure and blast-radius scoring, MCP estate analytics and pre-seeded shared demonstrations. Removed 19 whole files (6,394 physical lines) plus their console panels and wiring.
Removed routes: `/v1/analysis/mcp-estate`, `/v1/analysis/blast-radius/{agent_id}`, `/v1/estate/ai-bom`, `/v1/estate/ai-bom/cyclonedx`, `/v1/estate/adoption`, `/v1/estate/exposure`, `/console/demo.json`. No dedicated tables. The workflow-metrics route retains counted activity and SLOs; only its commercial value report is retired.
Removed settings: `SENTINEL_CONSOLE_DEMO_TOKEN`, `SENTINEL_DEMO_INGEST_KEY`, `SENTINEL_DEMO_ANALYST_KEY`, `SENTINEL_DEMO_ADMIN_KEY`, the `SENTINEL_DEMO_` family and their `_FILE` forms.
Restore signal: a paying customer needs a named inventory analysis with verifiable source coverage, or a maintained isolated demonstration tenant with an explicit owner.

Recovery paths at `archive/pre-cleanup`:

- `scripts/seed_console_demo.py`
- `sentinel/domain/adoption.py`
- `sentinel/domain/ai_bom.py`
- `sentinel/domain/blast_radius.py`
- `sentinel/domain/exposure_graph.py`
- `sentinel/domain/mcp_estate.py`
- `sentinel/domain/value_metrics.py`
- `sentinel/interface/analysis_routes.py`
- `sentinel/interface/console_demo.py`
- `sentinel/interface/estate_routes.py`

Feature tests recover from `tests_arch/`; exact paths and case deltas are recorded in the cleanup inventory and evidence. Core workflow, SLO, transport and authorization assertions are retained.

## Retained Act remediation webhooks — 2026-10-31

Remediation webhooks were deliberately retained as Act execution adapters:
SENTINEL_REMEDIATION_ENDPOINTS, its parser, remediation wiring,
HttpRemediationIntegration, build_remediation_executor and explicit endpoint
precedence remain. They support the approved, execution-bound remediation path;
SOAR playbooks and notification automation are the parking target. Native
remediation tests remain unchanged. Unclear shared executor helpers are kept.

## SOAR incident fan-out

Removed 2 source files (680 lines): `sentinel/composition/notifications.py`
and `sentinel/infrastructure/soar.py`, recoverable from `archive/pre-cleanup`.
Retired settings: SENTINEL_SOAR_ENDPOINTS, SENTINEL_SOAR_MIN_PRIORITY, SENTINEL_SOAR_PAGERDUTY_ROUTING_KEY (including their _FILE variants).
Routes/tables: none. SOAR-only cases were removed from mixed tests; retained
executor, containment, approval and outbound failure assertions remain.
Return signal: a customer needs approved, tenant-scoped incident delivery with
durable retry and bounded latency. Remediation webhooks are retained Act adapters,
not this parked incident-triggered fan-out.

## Organization management and SCIM Users

Parked the five `/scim/v2/Users` collection/item routes and three `/v1/orgs`
create/current/members routes, with the console organization/member panels.
Removed `sentinel/infrastructure/orgs.py` (127 lines), recoverable from
`archive/pre-cleanup`. No feature-specific settings. Tables `organizations`
and SCIM identity tables await the final migration. Directory storage remains
temporarily for A2A; tenant provisioning and its tests remain core.
Return signal: a customer needs managed human membership and lifecycle sync,
with a defined tenant boundary and audit contract.

## A2A delegation and the SCIM directory adapter

Removed 18 whole files (6711 lines), including the now-unshared
directory adapter. Recover source paths from `archive/pre-cleanup`:
`sentinel/application/a2a_gateway.py`, `sentinel/composition/delegation_wiring.py`, `sentinel/domain/a2a.py`, `sentinel/domain/delegation_constraints.py`, `sentinel/domain/delegation_passport.py`, `sentinel/infrastructure/a2a_registry.py`, `sentinel/infrastructure/a2a_wire.py`, `sentinel/infrastructure/delegation_signing.py`, `sentinel/interface/a2a_proxy_routes.py`, `sentinel/interface/a2a_routes.py`, `sentinel/interface/delegation_verification.py`, `sentinel/infrastructure/directory.py`.
Feature-only test recovery paths are in CLEANUP_PLAN.md and the archived
tests_arch/ directory. Retired settings: SENTINEL_A2A_PROXY_ALLOWED_HOSTS, SENTINEL_A2A_PROXY_ALLOW_PRIVATE, SENTINEL_A2A_PROXY_ENABLED, SENTINEL_DELEGATION_KEYS and _FILE variants.
Routes removed: POST `/v1/a2a/cards`, POST `/v1/a2a/evaluate`, conditional POST
`/v1/a2a/proxy/{agent_id}`. Skills assessment was removed with detonation.
Tables await the single cleanup migration. Stable execution-binding and Passport
delegation evidence fields remain; they are not the removed A2A protocol.
Return signal: a customer needs cross-agent delegation with a specified trust,
identity and credential boundary, measured against real peers.

## Final table cleanup (migration 40)

One appended migration drops `user_credentials`, `user_sessions`,
`enrolment_tickets`, `webauthn_challenges`, `users`, `organizations`,
`a2a_agent_cards`, and `device_discovery`, in that order without CASCADE.
Historical DDL and migrations 1–39 remain available for replay. No tenant,
approval, operation, receipt, remediation, policy, observation, audit or
transparency table is dropped. Retained tables' indexes, grants, roles and RLS
policies are covered by before/after local upgrade tests. This migration removes
parked-feature data when an operator runs it; archive the old DB if that data
must be recovered. No production database was changed in this cleanup.

## Discovery vocabulary follow-up

`sentinel/domain/assets.py` (251 lines) became unused after discovery removal;
fresh import and symbol searches found no retained consumer. It is parked and
recoverable from `archive/pre-cleanup`. No settings/routes/tables changed.
Return signal: a future connector needs a shared asset and scan-coverage contract;
evaluate this archived vocabulary then, rather than shipping unused definitions.
