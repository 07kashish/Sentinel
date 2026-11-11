# Sentinel cleanup plan — Phase 4 recorded; Checkpoint 2 blocked

Phase 4 cleanup is implemented and Linux verification is complete on cleanup/oversight-core: 3,321 passed, 41 skipped, 0 failed, 0 errors, 0 timeouts. Ready for Checkpoint 2: no, because Docker is unavailable in WSL. Current results and measurements are in the Phase 4 results section. Earlier inventories and checkpoint conditions are historical. No Phase 5 work is authorized or performed.

**Product constraint:** independent, cross-vendor company oversight through Observe → Decide → Act → Prove. Deterministic rules remain the decision authority. Preserve the semantics and existing assertions for protect_gate, authorizations, tool_runner, execution_binding, operation storage/reconciliation, transparency and Execution Passport. Keep AWS, GitHub and Kubernetes controlled execution.

## Phase 0 preservation and execution status (historical)

- This folder arrived without Git history. The user explicitly authorized initializing it and making a baseline snapshot. This is a new import, not recovery of upstream history.
- Baseline commit and recovery tag: `archive/pre-cleanup` → `d63463cd3bc49bcd3e420ff4a100cc52fe6f4ad6`. Working branch: `cleanup/oversight-core`. No remote was added and nothing was pushed; do not move or delete the recovery tag.
- The initial snapshot was scanned before commit: `python scripts/scan_release_for_secrets.py --tree`, **989 members, zero findings**. This is the repository scanner, not an independent review or a gitleaks run.
- The initial inventory changed no pre-existing source. The completed Phase 0 baseline includes minimal SDK probe and atomic inbox-result fixes plus regression coverage, described below. No application code was deleted, moved or refactored. Raw logs/inventory helpers are ignored under `reports/`.
- No Phase 0 completion commit is allowed while the required full suite is red. The separately authorized archive snapshot preserves the original input; it does not assert a green suite.

## Baseline and counting method

The original Python 3.14 environment lacked pytest/Ruff. The pinned install failed on unavailable `pgserver==0.1.4`; PyYAML/lupa also needed native builds on 3.14. A Python 3.13.16 environment was created under ignored `reports/.phase0-venv/`, with the repository runtime/dev pins except pgserver. The requested requirements files are unchanged. No PostgreSQL result is claimed: the harness reports skips where no server is available. This is Windows, whereas the main CI runs Linux/Python 3.12.

This original inventory is historical; its empty after column is superseded by
the consistently measured [Phase 4 results](#phase-4-results) below.

| Measurement | Before cleanup |
| --- | ---: |
| Tracked files (archive snapshot) | 989 |
| Python modules under sentinel, including initializers | 258 (246 excluding initializers) |
| sentinel Python physical LOC | 78,965 |
| tests_arch Python physical LOC | 70,429 |
| test_*.py files | 205 |
| Pytest cases collected/executed, including skips | 4609 |
| Static route declarations (including conditional routes) | 78 |
| .env.example assignments / distinct documented SENTINEL names | 69 / 138 |
| Settings annotated fields | 76 |
| CI jobs across both workflows | 20 |
| Unreachable / never imported sentinel modules | 39 / 26 |
| ruff baseline | exit 0; 1.323 s |
| pytest baseline | exit 1; 407.607 s |

Pytest result: **3,867 passed, 20 failed, 0 errors, 722 skipped; 4,609 total in 407.607 s**

Commands were run through that environment with `python -m pytest -q tests_arch/ --junitxml=reports/baseline-junit.xml` and `python -m ruff check sentinel tests_arch`. The JUnit argument only records counts; pytest.ini already adds -q, which otherwise hides the aggregate terminal summary. Raw output, exit codes and wall durations are in ignored reports/baseline-*.txt, baseline-results.json and baseline-junit.xml.

The first full attempt returned 21 failures in 1,068.770 s. Two source-hygiene failures were introduced by putting third-party Python files under non-hidden reports subdirectories. Those directories were moved to dot-directories already excluded by the existing hygiene policy, without changing any tests. The table above reports the fresh full rerun. The suite also rewrites docs/dr_sqlite_drill.json; its generated output is preserved under ignored reports and the tracked artifact is restored before the checkpoint.

### Failure diagnosis and verification limits

| Failures | Area | Observed cause / next investigation |
|---:|---|---|
| 9 | CLI advisor | POSIX /opt/agy fixtures fail the absolute-path check on Windows/Python 3.13. Preserve sandbox/credential isolation assertions when making fixtures portable. |
| 2 | Helm configuration alignment | Path.read_text() uses cp1252 here; the UTF-8 BOM becomes part of replicaCount. A separate read-only probe parses the same file correctly with explicit UTF-8. Preserve schema refusals. |
| 6 | Container context, pilot scanning and runtime topology | Creating test symlinks raises WinError 1314: this Windows account lacks the privilege. Resolve the environment or use the supported Linux CI runner; do not mark these invariants passed. |
| 1 | MCP stdio smoke | The test subprocess clears the OS environment; SSL initialization fails. An isolated no-network probe reproduces it and succeeds when SystemRoot is supplied. Preserve restricted credentials and actual loopback forwarding assertions. |
| 1 | SDK live-server smoke | The execution/replay checks print their expected results, but TemporaryDirectory cleanup fails on smoke.sqlite with WinError 32. Diagnose the still-open file/process lifecycle; this test did not pass. |
| 1 | Multi-tenant ingest soak | p95 = 2,199.413 ms exceeds the unchanged 2,000 ms ceiling. This case passed in the first full attempt; timing variability is observed, its cause is not established. Do not relax the ceiling or infer service capacity from this local run. |

Of the 722 skips, 678 explicitly report absent PostgreSQL or pgserver. Other skips include live kind/Kubernetes, Redis, Docker, Helm, gitleaks and unavailable generated artifacts, plus PostgreSQL-specific checks on SQLite. No live PostgreSQL, cluster, image, external tenant or independent secret-scan result is claimed.

The permanent graph tool has **7 passing standard-library regression tests** (1.558 s command wall time), and `ruff check scripts/dev` passes (0.118 s). An independent syntax-only recount also finds 258 modules and 41 unreachable before lazy exports; resolving sentinel.sdk.local and sentinel.sdk.interceptor explains the final 39. All 39 have dispositions below. A separate agent review was attempted but unavailable because of a tool usage limit; self-review and the regression checks were completed.

The repository secret scanner found zero findings in the three new Phase 0 files as well as in the original archive snapshot. These checks are not a substitute for the unavailable gitleaks run. At the initial inventory checkpoint, Phase 0 remained uncommitted because the required full-suite gate was red. The failure list below is retained; the later Phase 0 Linux baseline section records the current outcome.

Failing test identities (unmodified baseline):

- `FAILED tests_arch/test_cli_advisor.py::test_the_call_is_sandboxed_isolated_and_never_auto_approves`
- `FAILED tests_arch/test_cli_advisor.py::test_every_failure_is_stated_unavailability_never_an_exception[run0-no successful result]`
- `FAILED tests_arch/test_cli_advisor.py::test_every_failure_is_stated_unavailability_never_an_exception[run1-no successful result]`
- `FAILED tests_arch/test_cli_advisor.py::test_every_failure_is_stated_unavailability_never_an_exception[run2-failed shape validation]`
- `FAILED tests_arch/test_cli_advisor.py::test_every_failure_is_stated_unavailability_never_an_exception[run3-exited with status 3]`
- `FAILED tests_arch/test_cli_advisor.py::test_every_failure_is_stated_unavailability_never_an_exception[run4-did not answer within its timeout]`
- `FAILED tests_arch/test_cli_advisor.py::test_every_failure_is_stated_unavailability_never_an_exception[run5-could not be started]`
- `FAILED tests_arch/test_cli_advisor.py::test_cli_and_endpoint_are_mutually_exclusive_and_the_container_wires_the_cli`
- `FAILED tests_arch/test_cli_advisor.py::test_the_check_command_reports_a_cli_answer`
- `FAILED tests_arch/test_config_alignment.py::test_chart_refuses_unbound_or_fail_open_values[requireExecutionBinding-False]`
- `FAILED tests_arch/test_config_alignment.py::test_chart_refuses_unbound_or_fail_open_values[rateLimitFailOpen-True]`
- `FAILED tests_arch/test_container_context.py::test_symlink_is_refused_without_reading_its_target`
- `FAILED tests_arch/test_multi_tenant_soak.py::test_multi_tenant_concurrent_ingest_soak`
- `FAILED tests_arch/test_pilot_onboarding.py::test_scanner_never_opens_content_or_follows_symlinks`
- `FAILED tests_arch/test_pilot_onboarding.py::test_commands_are_found_by_name_without_following_or_running_them`
- `FAILED tests_arch/test_runtime_topology.py::test_a_fabricated_tree_with_a_workers_parent_is_observed`
- `FAILED tests_arch/test_runtime_topology.py::test_siblings_are_counted_from_a_real_tree`
- `FAILED tests_arch/test_runtime_topology.py::test_a_sibling_running_something_else_is_not_counted`
- `FAILED tests_arch/test_sdk_mcp_stdio.py::test_mcp_stdio_subprocess_forwards_one_request_to_sentinel`
- `FAILED tests_arch/test_sdk_remote.py::test_the_sdk_completes_the_journey_against_a_real_server`

Physical LOC includes blank/comment lines; binary artifacts are measured in bytes, never fabricated LOC. Route numbers are AST declarations, not a claim that all optional routes are enabled in one deployment. The Phase 4 README table must be checked against the constructed app for the declared configuration. Test collection/runtime count comes from pytest, not counting function names.

## Independent import graph

Run `python scripts/dev/import_graph.py --json reports/import-graph.json`. It parses every sentinel Python file (including namespace-package descendants), handles relative imports, parent package initialization, imports inside functions/conditions and simple literal lazy-export maps. It imports no Sentinel code. It prints LOC for every module, roots, unreachable modules and modules with no incoming imports. `--check` fails on unexplained unreachability, missing internal imports, unresolved dynamic imports or stale exceptions; use repeatable `--allow-unreachable` only for documented external entrypoints. `--entrypoint` replaces the default root set.

The supplied “52 of 261” count is **not reproduced** in this snapshot: **39 of 258** after resolving the SDK lazy map (41 before that resolution). There are 12 package initializer files. Conservative conditional/type-only imports count as edges. The provided roots are exactly `sentinel.interface.asgi`, `.http`, `.worker`, `.cli`, and `sentinel.sdk`. There are zero unresolved dynamic or internal imports in this snapshot. Reachable is not synonymous with core, and unreachable is not synonymous with unused.

Regression command: `python -m unittest discover -s scripts/dev -p test_import_graph.py`. It covers nonexecution, relative/namespace imports, isolated cycles, lazy exports, unknown dynamic imports, missing internal dependencies, syntax/missing-root errors and stale exception handling. Run it alongside the architectural suite; it uses only the standard library.

| Unreachable module | LOC | Disposition |
|---|---:|---|
| `sentinel.application.deployment_contract` | 110 | Phase 2: delete (dead-tooling) |
| `sentinel.domain.attack_campaign` | 547 | Phase 2: delete (dead-tooling) |
| `sentinel.domain.detection_metrics` | 238 | Keep: deterministic measurement CLI support; see exceptions. |
| `sentinel.domain.endpoint_sensor` | 425 | Phase 3: park (endpoint) |
| `sentinel.domain.identity` | 366 | Phase 2: delete (dead-security) |
| `sentinel.domain.mfa` | 230 | Phase 2: delete (dead-security) |
| `sentinel.domain.threat_intel` | 440 | Phase 2: delete (dead-security) |
| `sentinel.infrastructure.cbor` | 179 | Phase 2: delete (dead-security) |
| `sentinel.infrastructure.endpoint_scan` | 434 | Phase 3: park (endpoint) |
| `sentinel.infrastructure.openapi_risk` | 291 | Phase 2: delete (dead-security) |
| `sentinel.infrastructure.persistence.backup` | 616 | Keep: backup/PITR verify_restore supports Stage 4; external-support exception like objectstore. |
| `sentinel.infrastructure.persistence.diagnostics` | 248 | Phase 2: remove under the explicit Phase 2 schema decision below. |
| `sentinel.infrastructure.persistence.migrations` | 417 | Phase 2: remove under the explicit Phase 2 schema decision below. |
| `sentinel.infrastructure.persistence.objectstore` | 470 | Keep: external WAL archive command imports it; see exceptions. |
| `sentinel.infrastructure.persistence.schema` | 557 | Phase 2: remove under the explicit Phase 2 schema decision below. |
| `sentinel.infrastructure.platforms.copilot_studio` | 330 | Phase 3: park (discovery) |
| `sentinel.infrastructure.platforms.databricks_agents` | 195 | Phase 3: park (discovery) |
| `sentinel.infrastructure.platforms.discovery_breadth` | 244 | Phase 3: park (discovery) |
| `sentinel.infrastructure.platforms.discovery_support` | 300 | Phase 3: park (discovery) |
| `sentinel.infrastructure.platforms.github_discovery` | 356 | Phase 3: park (discovery) |
| `sentinel.infrastructure.platforms.gitlab_discovery` | 232 | Phase 3: park (discovery) |
| `sentinel.infrastructure.platforms.identity_agents` | 395 | Phase 3: park (discovery) |
| `sentinel.infrastructure.platforms.local_mcp_configs` | 207 | Phase 3: park (endpoint) |
| `sentinel.infrastructure.platforms.salesforce_agentforce` | 227 | Phase 3: park (discovery) |
| `sentinel.infrastructure.platforms.servicenow_agents` | 241 | Phase 3: park (discovery) |
| `sentinel.infrastructure.platforms.slack_apps` | 239 | Phase 3: park (discovery) |
| `sentinel.infrastructure.saml` | 224 | Phase 2: delete (dead-security) |
| `sentinel.infrastructure.secrets` | 361 | Phase 2: delete (dead-security) |
| `sentinel.infrastructure.threat_detection` | 273 | Phase 2: delete (dead-security) |
| `sentinel.infrastructure.webauthn` | 551 | Phase 2: delete (dead-security) |
| `sentinel.interface.advisor_check` | 101 | Phase 2: delete (dead-tooling) |
| `sentinel.sdk.adapters` | 33 | Keep: externally imported SDK adapter/helper or explicit MCP stdio entrypoint. |
| `sentinel.sdk.adapters._gate` | 249 | Keep: externally imported SDK adapter/helper or explicit MCP stdio entrypoint. |
| `sentinel.sdk.adapters.anthropic` | 140 | Keep: externally imported SDK adapter/helper or explicit MCP stdio entrypoint. |
| `sentinel.sdk.adapters.gemini` | 121 | Keep: externally imported SDK adapter/helper or explicit MCP stdio entrypoint. |
| `sentinel.sdk.adapters.langchain` | 152 | Keep: externally imported SDK adapter/helper or explicit MCP stdio entrypoint. |
| `sentinel.sdk.adapters.openai_agents` | 176 | Keep: externally imported SDK adapter/helper or explicit MCP stdio entrypoint. |
| `sentinel.sdk.discovery_app` | 182 | Phase 3: park (endpoint) |
| `sentinel.sdk.mcp_stdio` | 361 | Keep: externally imported SDK adapter/helper or explicit MCP stdio entrypoint. |

Never imported by any other sentinel module (including legitimate roots): `sentinel.application.deployment_contract`, `sentinel.domain.attack_campaign`, `sentinel.domain.detection_metrics`, `sentinel.domain.identity`, `sentinel.domain.mfa`, `sentinel.domain.threat_intel`, `sentinel.infrastructure.endpoint_scan`, `sentinel.infrastructure.openapi_risk`, `sentinel.infrastructure.persistence.backup`, `sentinel.infrastructure.persistence.diagnostics`, `sentinel.infrastructure.persistence.objectstore`, `sentinel.infrastructure.persistence.schema`, `sentinel.infrastructure.platforms.discovery_breadth`, `sentinel.infrastructure.saml`, `sentinel.infrastructure.secrets`, `sentinel.infrastructure.threat_detection`, `sentinel.infrastructure.webauthn`, `sentinel.interface.advisor_check`, `sentinel.interface.asgi`, `sentinel.interface.cli`, `sentinel.sdk.adapters.anthropic`, `sentinel.sdk.adapters.gemini`, `sentinel.sdk.adapters.langchain`, `sentinel.sdk.adapters.openai_agents`, `sentinel.sdk.discovery_app`, `sentinel.sdk.mcp_stdio`.

## Corrections and explicit dependency decisions

| File | LOC | Decision and why |
|---|---:|---|
| `sentinel/infrastructure/attestation.py` | 273 | **KEEP**. composition/adapters.py imports the generic HTTP/unconfigured gateways. It preserves evidence disposition/reconciliation; it does not call the Solidity contract. Keep SENTINEL_ATTESTATION_ENDPOINT/TOKEN and generic anchoring. |
| `sentinel/infrastructure/persistence/objectstore.py` | 470 | **KEEP — prompt exception**. deploy/wal-archive/wal_s3.py imports S3ObjectStore/BlobKey/BlobMissing (lines 85, 133, 141, 201); the WAL/PITR drill and live-MinIO/storage tests use this adapter. It is not dead despite having no sentinel importer. Keep as documented external CLI support; removal would disable off-host WAL recovery. |
| `sentinel/infrastructure/persistence/backup.py` | 616 | **KEEP — Checkpoint 1**. backup/PITR verify_restore supports Stage 4 ("backup restore tested"). Keep test_persistence_backup_pitr.py; treat it like objectstore.py. |
| `sentinel/interface/advisor_check.py` | 101 | **Console entrypoint**. If removed in Phase 2, remove sentinel-advisor-check from pyproject.toml and only test_the_check_command_reports_a_cli_answer from mixed test_cli_advisor.py in the same commit. Preserve its other CLI-advisor assertions. |
| `sentinel/infrastructure/persistence/schema.py`, `migrations.py`, `diagnostics.py` | 1,222 | **Removed in Phase 2 under the explicit schema decision below**. Non-partition assertions run on live SQL; partition-only cases were retired by user decision. |
| `sentinel/infrastructure/secrets.py` | 361 | **DELETE after checks**. No kept consumer found. Connected-app sealing instead uses persistence/crypto.py through sql/connected_apps.py and composition, which remain unchanged. |
| `sentinel/infrastructure/enterprise.py` | 399 | **KEEP — prompt condition not met**. sql/unit_of_work.py and sql/retention.py use SqlPolicyStore, SqlTenantKeys and SqlTenantSettings. It is not SCIM/multi-org-only infrastructure. |
| `sentinel/domain/residency.py` | 211 | **KEEP shared types**. composition/settings.py imports Region; enterprise.py imports Region, RetentionPolicy and assert_no_cross_region_read. Retention and tenant isolation are core. Do not erase these to remove an analytics screen. |
| `sentinel/domain/remediation.py` | 631 | **KEEP core planning subset**. infrastructure/evidence.py imports EvidenceOrigin/decide_response; settings_parsers and the guarded executor use the action catalog. Preserve deterministic evidence/approval semantics and containment catalog; park unrelated playbooks only. |
| `sentinel/infrastructure/remediation.py` | 734 | **KEEP guarded executor subset**. composition/remediation_wiring.py builds the executor consumed by the existing approved, bound execution path. Keep authorization/idempotency/audit/refusal behavior and native containment. Webhook-only automation may be parked after cutting its incidental configuration. |
| `sentinel/composition/remediation_wiring.py` | 93 | **KEEP native containment wiring**. It is the only constructor for native_containment integrations used by container.py. Remove optional playbook/webhook assembly without disconnecting native or platform containment actions. |
| `sentinel/infrastructure/platforms/remediation.py` | 471 | **KEEP — native kill-switch exception**. Despite its name, it performs AWS session revocation and Kubernetes pod termination, quarantine and release through approved protected execution. composition/platform_wiring.py and remediation_wiring.py construct these integrations. Preserve this module and test_native_remediation.py; removing it would amputate the required kill switch, not merely park SOAR playbooks. |
| `sentinel/interface/mcp_proxy_routes.py` | 729 | **KEEP; extract incidental A2A coupling first**. Lines 94, 318-320 and 584-589 import _inspect_reply from a2a_proxy_routes and invoke container.a2a_gateway for both streaming and non-streaming replies. Extract vendor-neutral deterministic reply inspection and text extraction into retained MCP/common code before parking A2A. Preserve the same detection policy, refusal, receipt and stream behavior; do not bypass inspection or weaken MCP assertions. |
| `tests_arch/test_cli_advisor.py` | 135 | **KEEP mixed test file**. Only the advisor_check import and test_the_check_command_reports_a_cli_answer belong to the removed CLI. Other cases exercise the retained optional advisory adapter, credential isolation and API-only worker behavior. Remove only that CLI case; retain decision-authority and worker assertions. |
| `tests_arch/test_persistence_benchmarks.py` | 523 | **REWRITE mixed tests**. It imports the duplicate schema/diagnostic runner, but also tests the kept persistence engine isolation and lock timeout. Retarget those core cases to live sql migrations; remove only duplicate-schema diagnostics and partition assumptions. Do not drop the whole file to dispose of a removed import. |
| `sentinel/infrastructure/sql/device_discovery.py` | 61 | **PARTIAL PARK; KEEP historical DDL**. migrate.py:_add_device_discovery imports DEVICE_STATEMENTS for already-defined migration 38. Park SqlDeviceDiscovery and its routes, but preserve the historical DDL helper so a fresh DB can replay old migrations unchanged before a new drop migration runs. |
| `sentinel/domain/inventory.py` | 544 | **KEEP**. admit_event.py uses ObservedEdgeKind; inventory.py and extra_routes also consume this passive observation model. Removing vendor discovery does not justify deleting the existing normalized observation inventory. |
| `sentinel/infrastructure/inventory.py` | 582 | **KEEP**. Container and CLI use the observation registry. Audit-connector attribution can build on its observations without reinstating vendor-discovery stubs. |
| `sentinel/domain/detection_metrics.py` | 238 | **KEEP external benchmark helper**. scripts/measure_benign_tool_call_false_positives.py imports it; rewrite that script to run deterministic rules only and retain its provenance/count safeguards. It is documented CLI support even though not service-root reachable. |
| `scripts/build_attack_surface.py` | 164 | **REMOVE path; KEEP pure scanner**. test_attack_surface.py and test_console_bundle.py import collect(). Move the pure route/capability inventory to scripts/dev/route_inventory.py and retarget those tests before deleting the report generator. Do not delete the route-authorization fitness check. |
| `scripts/release_binding.py` | 403 | **CUT incidental imports before removal**. Retained build_sbom_and_licenses.py, build_and_scan_image.py, check_helm_chart.py, run_dast.py and verify_guards.py import it for report stamping. Remove only stamping and update artifact expectations; keep scanning, DAST, mutation checks and image signing. |
| `scripts/build_release_artifact.py` | 334 | **REMOVE generator; preserve security checks**. test_release_hygiene.py compares packaging refusal constants against this file. Move the shared artifact contract into the retained scanner or a small packaging helper, and retain equivalent tests. CI already uses python -m build and helm package for actual release packaging. |
| `scripts/smoke_sdks.py` | 114 | **KEEP SDK journey; replace demo-only seeding**. It invokes scripts/seed_console_demo.py to load its sample policy. Before parking that script, seed the same minimal policy through a retained fixture/helper or the existing API. Preserve the real-server SDK authorization/execution/replay-refusal assertions. |
| `docs/ADVERSARIAL_REVIEW.md` | 371 | **MERGE core findings**. It covers forced RLS, signature verification and tenant-isolation issues as well as classifier evaluation. Preserve still-current core threat findings in docs/SECURITY.md; remove obsolete classifier discussion. |

Additional omissions corrected: park `domain/observed_binding.py` (all importers are detonation), `composition/notifications.py` (SOAR-only), `infrastructure/platforms/connectors.py`, `ai_connectors.py`, `ai_discovery.py`, and `platforms/discovery.py` (the last is the actual CLI discovery module). `infrastructure/discovery.py` does not exist. Park `infrastructure/directory.py` after SCIM/org removal; it is not the OIDC tenant provisioning helper in interface/principals.py. Keep agent_identity_providers, agent_identity_wiring, workload identity, tenant provisioning, operation/receipt stores, evidence commitments, execution graph and all controlled-execution adapter/outcome modules.

The two Passport directories are **not interchangeable corpora**: `spec/` contains 16 canonicalization/digest vectors plus verify.mjs; `standard/` has 10 signed-envelope vectors and Python verifiers. sdk-ts already owns copies under test/fixtures. Preserve all conformance cases and the independent JS verifier under the retained standard tree (e.g. vectors/canonical and verify_canonical.mjs), retarget both kept build_passport scripts and test_passport_conformance.py, and retain public schema identifiers/canonicalization semantics. Remove the duplicate documentation only after merging still-valid material.

The soft classifier is live and defaults to true in settings.py; it is not dead code. Removing it is an intentional product change in Phase 1. Keep deterministic evaluation/metrics.py, benchmark.py, run_benchmark.py without its soft branch, corpora, sequence/baseline machinery and their benign-corpus assertions. evaluation/validate.py is classifier-only LOSO evaluation and is an additional deletion. Mixed protect tests must still prove deterministic authority after the classifier-specific inspection is rewritten.

## Checkpoint 1 decisions

These decisions amend the future Phase 2 plan only. Phase 1 removes the listed
non-product groups; no Phase 2 or Phase 3 work is authorized in this execution.

- Keep persistence/backup.py and test_persistence_backup_pitr.py because Stage 4
  ("backup restore tested") depends on backup/PITR verify_restore. It is an
  external-support exception like objectstore.py, regardless of static reachability.
- advisor_check.py is the sentinel-advisor-check console entrypoint in pyproject.toml.
  Any Phase 2 removal must remove that entry and only the CLI case in the mixed
  test_cli_advisor.py file in the same commit. Its retained advisory, isolation,
  decision-authority and worker assertions remain.
- Before Phase 2 removes persistence/schema.py, migrations.py or diagnostics.py,
  prove the live sql migrations already supply everything their PostgreSQL tests
  require, including RLS and partitioning. Review skip messages naming schema.py;
  no parity result is claimed here.

The Phase 2 removal inventory excludes the two retained backup files: 26 files,
8,487 text LOC. Other historical measurements remain point-in-time observations.

## Proposed removals and impact inventory

Each table names every existing file selected for deletion, merging or parking, with physical LOC. “Merge” removes the source document only after its still-true content has moved. Test files listed in a feature group are proposed removals because they exercise that removed feature; shared tests listed under impacts must instead be adapted. These are proposals, not deletions already performed. Paths absent from this snapshot are listed separately below.

| Phase | Unique proposed removed/merged/parked files | Text LOC | Binary bytes |
|---|---:|---:|---:|
| 1 | 319 | 76,409 | 5,379,130 |
| 2 | 26 | 8,487 | 0 |
| 3 | 89 | 30,030 | 0 |

References were searched with `rg -n --with-filename -F -f <group-patterns>` across all requested roots (`sentinel/ tests_arch/ scripts/ evaluation/ .github/ Dockerfile docker-compose.yml deploy/ pyproject.toml`) plus `.env.example`, README, CONTRIBUTING, docs, sdk-ts, config and requirements files. This is the Windows equivalent of the requested recursive grep. Import edges independently identify code dependencies, including from-package imports. Text hits also include comments/fixtures; they are review locations, not proof of runtime use. Rerun both checks immediately before each deletion; this inventory alone is not a deletion certificate.

### Phase 1: council

AI review transcripts, reports and generators are not product runtime or operator documentation.

| Proposed path | LOC / binary size | Action |
|---|---:|---|
| `council/COUNCIL_REPORT.md` | 1164 | delete |
| `council/COUNCIL_REPORT.pdf` | binary (157,243 bytes) | delete |
| `council/COUNCIL_REPORT_v1.md` | 1033 | delete |
| `council/COUNCIL_REPORT_v1.pdf` | binary (76,942 bytes) | delete |
| `council/COUNCIL_REPORT_v2.md` | 375 | delete |
| `council/COUNCIL_REPORT_v3.md` | 239 | delete |
| `council/COUNCIL_REPORT_v3.pdf` | binary (27,150 bytes) | delete |
| `council/COUNCIL_REPORT_v4.md` | 235 | delete |
| `council/COUNCIL_REPORT_v4.pdf` | binary (24,486 bytes) | delete |
| `council/COUNCIL_REPORT_v6.md` | 487 | delete |
| `council/COUNCIL_REPORT_v6.pdf` | binary (82,878 bytes) | delete |
| `council/COUNCIL_REPORT_v7.md` | 1122 | delete |
| `council/COUNCIL_REPORT_v7.pdf` | binary (116,675 bytes) | delete |
| `council/COUNCIL_REPORT_v8.md` | 1164 | delete |
| `council/COUNCIL_REPORT_v8.pdf` | binary (157,243 bytes) | delete |
| `council/REMEDIATION_V7.md` | 193 | delete |
| `council/REMEDIATION_V8.md` | 166 | delete |
| `council/antigravity_seat.py` | 355 | delete |
| `council/brief.md` | 435 | delete |
| `council/council.py` | 375 | delete |
| `council/make_pdf.py` | 979 | delete |
| `council/prompts/prompt_0ca3a59c.md` | 681 | delete |
| `council/prompts/prompt_0fe228f8.md` | 562 | delete |
| `council/prompts/prompt_2783efa6.md` | 782 | delete |
| `council/prompts/prompt_293241c0.md` | 598 | delete |
| `council/prompts/prompt_3b967474.md` | 338 | delete |
| `council/prompts/prompt_4a91e4fb.md` | 991 | delete |
| `council/prompts/prompt_6a8ef4dd.md` | 694 | delete |
| `council/prompts/prompt_846eb893.md` | 1 | delete |
| `council/prompts/prompt_864b3138.md` | 1 | delete |
| `council/prompts/prompt_89de69df.md` | 870 | delete |
| `council/prompts/prompt_8c18ff05.md` | 726 | delete |
| `council/prompts/prompt_a4c1fd14.md` | 1 | delete |
| `council/prompts/prompt_b0023b1f.md` | 1 | delete |
| `council/prompts/prompt_b0be6fc2.md` | 738 | delete |
| `council/prompts/prompt_c0cb8319.md` | 363 | delete |
| `council/prompts/prompt_c77f8681.md` | 537 | delete |
| `council/prompts/prompt_c9625d62.md` | 568 | delete |
| `council/prompts/prompt_c9aca19b.md` | 1 | delete |
| `council/prompts/prompt_ccda03fa.md` | 382 | delete |
| `council/prompts/prompt_d7ed3a36.md` | 1 | delete |
| `council/prompts/prompt_dc288287.md` | 514 | delete |
| `council/prompts/prompt_e301be4d.md` | 1 | delete |
| `council/prompts/prompt_e586b438.md` | 451 | delete |
| `council/prompts/prompt_f4e30218.md` | 389 | delete |
| `council/seats.py` | 217 | delete |
| `council/transcript/r1_antigravity.md` | 91 | delete |
| `council/transcript/r1_claude.md` | 103 | delete |
| `council/transcript/r1_codex.md` | 110 | delete |
| `council/transcript/r2_antigravity.md` | 97 | delete |
| `council/transcript/r2_claude.md` | 48 | delete |
| `council/transcript/r2_codex.md` | 118 | delete |
| `council/transcript/r3_antigravity.md` | 67 | delete |
| `council/transcript/r3_claude.md` | 55 | delete |
| `council/transcript/r3_codex.ERROR.txt` | 9 | delete |
| `council/transcript/run_summary.json` | 88 | delete |
| `council/transcript_2seat/r1_claude.md` | 48 | delete |
| `council/transcript_2seat/r1_codex.md` | 100 | delete |
| `council/transcript_2seat/r2_claude.md` | 45 | delete |
| `council/transcript_2seat/r2_codex.md` | 63 | delete |
| `council/transcript_2seat/r3_claude.md` | 41 | delete |
| `council/transcript_2seat/r3_codex.md` | 48 | delete |
| `council/transcript_2seat/run_summary.json` | 70 | delete |
| `council/transcript_v1_prefix/r1_antigravity.md` | 46 | delete |
| `council/transcript_v1_prefix/r1_claude.md` | 65 | delete |
| `council/transcript_v1_prefix/r1_codex.md` | 96 | delete |
| `council/transcript_v1_prefix/r2_antigravity.md` | 55 | delete |
| `council/transcript_v1_prefix/r2_claude.md` | 56 | delete |
| `council/transcript_v1_prefix/r2_codex.md` | 55 | delete |
| `council/transcript_v1_prefix/r3_antigravity.md` | 26 | delete |
| `council/transcript_v1_prefix/r3_claude.md` | 29 | delete |
| `council/transcript_v1_prefix/r3_codex.md` | 48 | delete |
| `council/transcript_v1_prefix/run_summary.json` | 94 | delete |
| `council/transcript_v2_archive/r1_antigravity.md` | 52 | delete |
| `council/transcript_v2_archive/r1_claude.md` | 66 | delete |
| `council/transcript_v2_archive/r1_codex.md` | 84 | delete |
| `council/transcript_v2_archive/r2_antigravity.md` | 48 | delete |
| `council/transcript_v2_archive/r2_claude.md` | 43 | delete |
| `council/transcript_v2_archive/r2_codex.md` | 61 | delete |
| `council/transcript_v2_archive/r3_antigravity.md` | 55 | delete |
| `council/transcript_v2_archive/r3_claude.md` | 46 | delete |
| `council/transcript_v2_archive/r3_codex.md` | 46 | delete |
| `council/transcript_v2_archive/run_summary.json` | 94 | delete |
| `council/transcript_v3_archive/r1_antigravity.md` | 42 | delete |
| `council/transcript_v3_archive/r1_claude.md` | 75 | delete |
| `council/transcript_v3_archive/r1_codex.md` | 103 | delete |
| `council/transcript_v3_archive/r2_antigravity.md` | 39 | delete |
| `council/transcript_v3_archive/r2_claude.md` | 47 | delete |
| `council/transcript_v3_archive/r2_codex.md` | 75 | delete |
| `council/transcript_v3_archive/r3_antigravity.md` | 57 | delete |
| `council/transcript_v3_archive/r3_claude.md` | 46 | delete |
| `council/transcript_v3_archive/r3_codex.md` | 43 | delete |
| `council/transcript_v3_archive/run_summary.json` | 94 | delete |
| `council/transcript_v4_archive/r1_antigravity.md` | 51 | delete |
| `council/transcript_v4_archive/r1_claude.md` | 68 | delete |
| `council/transcript_v4_archive/r1_codex.md` | 97 | delete |
| `council/transcript_v4_archive/r2_antigravity.md` | 33 | delete |
| `council/transcript_v4_archive/r2_claude.md` | 39 | delete |
| `council/transcript_v4_archive/r2_codex.md` | 67 | delete |
| `council/transcript_v4_archive/r3_antigravity.md` | 58 | delete |
| `council/transcript_v4_archive/r3_claude.md` | 36 | delete |
| `council/transcript_v4_archive/r3_codex.md` | 47 | delete |
| `council/transcript_v4_archive/run_summary.json` | 94 | delete |
| `council/transcript_v5_stale/r1_claude.md` | 0 | delete |
| `council/transcript_v6_archive/r1_antigravity.md` | 118 | delete |
| `council/transcript_v6_archive/r1_claude.md` | 102 | delete |
| `council/transcript_v6_archive/r1_codex.md` | 129 | delete |
| `council/transcript_v6_archive/r2_antigravity.md` | 58 | delete |
| `council/transcript_v6_archive/r2_claude.md` | 51 | delete |
| `council/transcript_v6_archive/r2_codex.md` | 101 | delete |
| `council/transcript_v6_archive/r3_antigravity.md` | 48 | delete |
| `council/transcript_v6_archive/r3_claude.md` | 51 | delete |
| `council/transcript_v6_archive/r3_codex.md` | 67 | delete |
| `council/transcript_v6_archive/run_summary.json` | 88 | delete |
| `council/transcript_v7_archive/r1_antigravity.md` | 113 | delete |
| `council/transcript_v7_archive/r1_claude.md` | 73 | delete |
| `council/transcript_v7_archive/r1_codex.md` | 105 | delete |
| `council/transcript_v7_archive/r2_antigravity.md` | 104 | delete |
| `council/transcript_v7_archive/r2_claude.md` | 57 | delete |
| `council/transcript_v7_archive/r2_codex.md` | 108 | delete |
| `council/transcript_v7_archive/r3_antigravity.md` | 50 | delete |
| `council/transcript_v7_archive/r3_claude.md` | 52 | delete |
| `council/transcript_v7_archive/r3_codex.md` | 64 | delete |
| `council/transcript_v7_archive/run_summary.json` | 88 | delete |

**Settings to review/remove for this feature:** No feature-specific SENTINEL names identified by this group scan; shared settings are covered by the dependency decisions.

**Kept files requiring reference/expectation review (line numbers at archive snapshot):**

- `tests_arch/test_architecture_rules.py`: 12

### Phase 1: blockchain

Unused Solidity/Hardhat backend; keep the generic attestation gateway and its evidence semantics.

| Proposed path | LOC / binary size | Action |
|---|---:|---|
| `blockchain/contracts/AgentTrustRegistry.sol` | 135 | delete |
| `blockchain/deploy.js` | 27 | delete |
| `blockchain/hardhat.config.js` | 13 | delete |
| `blockchain/package-lock.json` | 7892 | delete |
| `blockchain/package.json` | 11 | delete |

**Settings to review/remove for this feature:** No feature-specific SENTINEL names identified by this group scan; shared settings are covered by the dependency decisions.

**Kept files requiring reference/expectation review (line numbers at archive snapshot):**

- `README.md`: 14, 21
- `tests_arch/test_passport_conformance.py`: 330

### Phase 1: desktop

Desktop packaging serves a separate delivery surface; remove its CI and documentation.

| Proposed path | LOC / binary size | Action |
|---|---:|---|
| `.github/workflows/desktop.yml` | 94 | delete |
| `docs/current/WINDOWS_APP_README.txt` | 28 | delete |
| `scripts/build_desktop_app.py` | 95 | delete |
| `scripts/publish_root_daily.cmd` | 47 | delete |

**Settings to review/remove for this feature:** No feature-specific SENTINEL names identified by this group scan; shared settings are covered by the dependency decisions.

**Kept files requiring reference/expectation review (line numbers at archive snapshot):**

- `docs/current/README.md`: 17
- `docs/current/RELEASE_CHANGES.md`: 265, 267, 279
- `docs/current/TRY_SENTINEL.md`: 32, 58

### Phase 1: classifier

Remove statistical classifier/training-only validation; preserve deterministic benchmark cases and metrics machinery.

| Proposed path | LOC / binary size | Action |
|---|---:|---|
| `evaluation/artifacts/soft_prompt_model.pkl` | binary (4,273,752 bytes) | delete |
| `evaluation/artifacts/soft_prompt_model_card.json` | 15 | delete |
| `evaluation/soft_prompt.py` | 47 | delete |
| `evaluation/train_classifier.py` | 101 | delete |
| `evaluation/validate.py` | 346 | delete |
| `scripts/strip_model_stop_words.py` | 140 | delete |
| `sentinel/infrastructure/soft_detection.py` | 161 | delete |
| `tests_arch/test_model_artifact_carries_no_training_data.py` | 136 | delete |
| `tests_arch/test_soft_detection_independent.py` | 135 | delete |

**Kept-module dependencies requiring an explicit cut before removal:**

- `sentinel.infrastructure.soft_detection` ← `sentinel.composition.adapters`, `sentinel.composition.container`

These are incidental feature wiring unless identified as retained shared core above. Remove the feature-specific field/call/import together; do not replace a core collaborator with a no-op.

**Settings to review/remove for this feature:** `SENTINEL_SOFT_PROMPT_DETECT`, `SENTINEL_SOFT_PROMPT_MODEL`, `SENTINEL_SOFT_PROMPT_THRESHOLD`.

**Kept files requiring reference/expectation review (line numbers at archive snapshot):**

- `.env.example`: 38, 41, 42, 43, 44
- `.github/workflows/ci.yml`: 94
- `Dockerfile`: 45
- `deploy/alerts/sentinel.rules.yml`: 37, 39, 40
- `docs/aws/COMPUTE_DECISION.md`: 54
- `docs/sentinel.cdx.json`: 146, 151, 154, 155
- `evaluation/BENCHMARK.md`: 99
- `evaluation/run_benchmark.py`: 9, 105, 111, 176, 212, 216
- `pyproject.toml`: 57
- `requirements.lock`: 380, 384, 453, 703, 798, 808
- `requirements.txt`: 30, 94, 95, 96, 101, 102, 116
- `scripts/check_container_context.py`: 22, 23
- `scripts/measure_benign_tool_call_false_positives.py`: 47
- `scripts/quickstart.py`: 225
- `scripts/run_deployed_journey.py`: 266
- `scripts/run_ingest_loadtest.py`: 199, 203, 358
- `scripts/run_workflow_loadtest.py`: 79
- `scripts/smoke_clean_install.py`: 214
- `sentinel/composition/adapters.py`: 43, 103, 107, 122, 124, 126, 132, 133, 138, 142, 147, 155 (+5 more)
- `sentinel/composition/container.py`: 93
- `sentinel/composition/settings.py`: 327, 329, 331, 597, 598, 599, 601, 602
- `sentinel/domain/mcp.py`: 114
- `tests_arch/test_agent_identity_providers.py`: 112
- `tests_arch/test_agent_tool_spec.py`: 64
- `tests_arch/test_connected_apps.py`: 53, 229
- `tests_arch/test_console_bundle.py`: 586
- `tests_arch/test_containment_http_seam.py`: 51
- `tests_arch/test_detection_mode.py`: 10, 43, 89, 108, 124, 138, 151, 155, 156, 162, 172, 216 (+6 more)
- `tests_arch/test_execution_contract.py`: 103
- `tests_arch/test_mcp_gateway.py`: 262
- `tests_arch/test_observability_bounds.py`: 58
- `tests_arch/test_openapi_ingestion.py`: 192
- `tests_arch/test_phase4_wiring.py`: 174
- `tests_arch/test_policy_as_code_seam.py`: 43
- `tests_arch/test_protect_decisions.py`: 185, 187
- `tests_arch/test_red_team_suite.py`: 198
- `tests_arch/test_retention_sweep.py`: 127, 132
- `tests_arch/test_root_publication.py`: 115
- `tests_arch/test_sequence_escalation.py`: 95
- `tests_arch/test_tool_names_are_not_prompts.py`: 47, 165, 183
- `tests_arch/test_trace_export.py`: 144
- `tests_arch/test_transparency_routes.py`: 44

### Phase 1: generated-evidence

Generated measurements and old evidence belong in CI artifacts, not a mutable readiness claim.

| Proposed path | LOC / binary size | Action |
|---|---:|---|
| `docs/benign_tool_call_false_positives.json` | 397 | delete |
| `docs/current/Sentinel-Product-Dossier.pdf` | binary (43,019 bytes) | delete |
| `docs/current/evidence/local-0c989af/run.json` | 908 | delete |
| `docs/current/evidence/local-60b5109/run.json` | 916 | delete |
| `docs/current/evidence/local-7141e82/run.json` | 916 | delete |
| `docs/current/evidence/local-765c0e6/README.md` | 8 | delete |
| `docs/current/evidence/local-765c0e6/cloud-proof.json` | 68 | delete |
| `docs/current/evidence/local-765c0e6/run.json` | 894 | delete |
| `docs/current/evidence/local-77c1303/README.md` | 9 | delete |
| `docs/current/evidence/local-77c1303/deployed-journey.json` | 36 | delete |
| `docs/current/evidence/local-77c1303/run.json` | 885 | delete |
| `docs/current/evidence/local-77c1303/workflow-loadtest.json` | 45 | delete |
| `docs/current/evidence/local-89598e3/README.md` | 8 | delete |
| `docs/current/evidence/local-89598e3/image-gate.json` | 14 | delete |
| `docs/current/evidence/local-89598e3/run.json` | 871 | delete |
| `docs/current/evidence/local-ab9fb6d/run.json` | 916 | delete |
| `docs/current/evidence/local-ad13718/README.md` | 10 | delete |
| `docs/current/evidence/local-ad13718/run.json` | 899 | delete |
| `docs/current/evidence/local-b477495/README.md` | 11 | delete |
| `docs/current/evidence/local-b477495/aws-proof-journey.json` | 83 | delete |
| `docs/current/evidence/local-b477495/aws-sts-proof.json` | 27 | delete |
| `docs/current/evidence/local-b477495/run.json` | 899 | delete |
| `docs/current/evidence/local-b477495/tofu-outputs.json` | 72 | delete |
| `docs/current/evidence/local-b8cbd8f/run.json` | 926 | delete |
| `docs/current/evidence/local-e025799/README.md` | 5 | delete |
| `docs/current/evidence/local-e025799/cluster-smoke.json` | 41 | delete |
| `docs/current/evidence/local-e025799/image-gate.json` | 279 | delete |
| `docs/current/evidence/local-e025799/image-layer-secret-scan.json` | 32 | delete |
| `docs/current/evidence/local-e025799/image-layer-triage.json` | 34 | delete |
| `docs/current/evidence/local-e025799/image-runtime-binding.json` | 10 | delete |
| `docs/current/evidence/local-e025799/provenance.json` | 214 | delete |
| `docs/current/evidence/local-e025799/run.json` | 830 | delete |
| `docs/current/evidence/local-e025799/secret-scan.json` | 10 | delete |
| `docs/current/evidence/local-e025799/skipped-tests.json` | 90 | delete |
| `docs/current/evidence/local-e025799/smoke.json` | 63 | delete |
| `docs/current/evidence/local-e025799/trivy-version.txt` | 9 | delete |
| `docs/current/evidence/local-e30b3f2/README.md` | 8 | delete |
| `docs/current/evidence/local-e30b3f2/deployed-journey.json` | 38 | delete |
| `docs/current/evidence/local-e30b3f2/run.json` | 885 | delete |
| `docs/current/evidence/local-fe6103f/run.json` | 916 | delete |
| `docs/dr_postgres_pitr_drill.json` | 19 | delete |
| `docs/dr_postgres_wal_pitr_drill.json` | 63 | delete |
| `docs/dr_postgres_wal_pitr_quiet_drill.json` | 54 | delete |
| `docs/dr_postgres_wal_pitr_s3_drill.json` | 78 | delete |
| `docs/dr_sqlite_drill.json` | 13 | delete |
| `docs/evidence/attack_campaign.json` | 103 | delete |
| `docs/history/PILOT_OFFER.md` | 97 | delete |
| `docs/history/PILOT_README.md` | 228 | delete |
| `docs/history/README.md` | 32 | delete |
| `docs/history/YC_APPLICATION_NOTES.md` | 58 | delete |
| `docs/history/YC_DEMO_SCRIPT.md` | 27 | delete |
| `docs/history/after_baseline_bandit_session.txt` | binary (135,484 bytes) | delete |
| `docs/history/after_baseline_pytest.txt` | binary (3,520 bytes) | delete |
| `docs/history/after_baseline_pytest_session.txt` | binary (3,520 bytes) | delete |
| `docs/history/after_baseline_ruff_session.txt` | binary (42 bytes) | delete |
| `docs/history/after_junit.xml` | 1 | delete |
| `docs/history/baseline_bandit.txt` | binary (132,798 bytes) | delete |
| `docs/history/baseline_bandit_session.txt` | binary (135,470 bytes) | delete |
| `docs/history/baseline_pytest.txt` | binary (3,520 bytes) | delete |
| `docs/history/baseline_pytest_session.txt` | binary (3,520 bytes) | delete |
| `docs/history/baseline_ruff.txt` | binary (42 bytes) | delete |
| `docs/history/baseline_ruff_session.txt` | binary (42 bytes) | delete |
| `docs/history/focused_tests.txt` | binary (1,784 bytes) | delete |
| `docs/history/run_jobs.json` | 1 | delete |
| `docs/ingest_loadtest_postgres.json` | 60 | delete |
| `docs/ingest_loadtest_postgres_benign.json` | 51 | delete |
| `docs/ingest_profile.json` | 1068 | delete |
| `docs/ingest_profile_postgres_6w.json` | 716 | delete |
| `docs/mcp_proxy_bench.json` | 73 | delete |
| `docs/performance_microbench.json` | 67 | delete |
| `docs/readiness/GAP_LEDGER.md` | 618 | delete |
| `docs/retention_effect.json` | 49 | delete |
| `release/baseline/b63e11d/manifest.json` | 1471 | delete |
| `release/baseline/b63e11d/pytest-junit.xml` | 1 | delete |
| `release/baseline/b63e11d/pytest-summary.txt` | 43 | delete |
| `release/gap_ledger.json` | 1299 | delete |

**Settings to review/remove for this feature:** No feature-specific SENTINEL names identified by this group scan; shared settings are covered by the dependency decisions.

**Kept files requiring reference/expectation review (line numbers at archive snapshot):**

- `.github/workflows/ci.yml`: 115, 133, 146, 706, 726, 733, 743, 744, 941, 1215, 1299, 1300 (+7 more)
- `deploy/terraform/aws/modules/database/main.tf`: 138
- `docs/PERFORMANCE_REPORT.md`: 39, 216
- `docs/SCALE_AND_ASSURANCE.md`: 159
- `docs/current/DETECTION_EVIDENCE.md`: 12, 13
- `docs/current/PRODUCTION_ACCEPTANCE.md`: 40
- `docs/current/README.md`: 16
- `docs/current/RELEASE_CHANGES.md`: 49, 177
- `evaluation/BENCHMARK.md`: 75
- `evaluation/benchmark.py`: 58
- `scripts/build_and_scan_image.py`: 199, 253
- `scripts/measure_benign_tool_call_false_positives.py`: 48
- `scripts/measure_retention_effect.py`: 38
- `scripts/profile_ingest.py`: 39, 63
- `scripts/run_authorization_bench.py`: 12, 13
- `scripts/run_dast.py`: 250
- `scripts/run_dr_postgres_pitr_drill.py`: 27
- `scripts/run_dr_postgres_wal_pitr_drill.py`: 59, 63, 68
- `scripts/run_dr_sqlite_drill.py`: 99
- `scripts/run_ingest_loadtest.py`: 64
- `scripts/run_mcp_proxy_bench.py`: 26, 145
- `scripts/run_perf_microbench.py`: 128
- `sentinel/interface/http_models.py`: 102, 114
- `tests_arch/test_dr_postgres_pitr_drill.py`: 27
- `tests_arch/test_dr_postgres_wal_pitr_drill.py`: 3, 31, 32, 98, 186
- `tests_arch/test_release_gate_runner.py`: 324
- `tests_arch/test_tool_names_are_not_prompts.py`: 54

### Phase 1: duplicate-passport

Use standard/execution-passport-v1 as the canonical specification; preserve vector/conformance tests and move unique fixtures before deletion.

| Proposed path | LOC / binary size | Action |
|---|---:|---|
| `spec/execution-passport/README.md` | 244 | delete |
| `spec/execution-passport/schema.json` | 147 | delete |
| `spec/execution-passport/vectors/malicious/attestation-names-a-different-passport.json` | 69 | delete |
| `spec/execution-passport/vectors/malicious/digest-does-not-match-document.json` | 68 | delete |
| `spec/execution-passport/vectors/malicious/empty-required-field.json` | 67 | delete |
| `spec/execution-passport/vectors/malicious/float-inside-an-array.json` | 71 | delete |
| `spec/execution-passport/vectors/malicious/float-nested-deep-in-an-object.json` | 68 | delete |
| `spec/execution-passport/vectors/malicious/float-risk-score.json` | 67 | delete |
| `spec/execution-passport/vectors/malicious/integer-beyond-the-json-safe-range.json` | 67 | delete |
| `spec/execution-passport/vectors/malicious/missing-required-field.json` | 66 | delete |
| `spec/execution-passport/vectors/malicious/parent-commitment-with-no-parent-supplied.json` | 68 | delete |
| `spec/execution-passport/vectors/malicious/parent-edited-after-being-committed-to.json` | 124 | delete |
| `spec/execution-passport/vectors/valid/complete-passport.json` | 66 | delete |
| `spec/execution-passport/vectors/valid/integer-at-the-exact-safe-boundary.json` | 66 | delete |
| `spec/execution-passport/vectors/valid/minimal-required-fields-only.json` | 21 | delete |
| `spec/execution-passport/vectors/valid/non-ascii-emitted-not-escaped.json` | 66 | delete |
| `spec/execution-passport/vectors/valid/unknown-field-is-preserved-in-the-digest.json` | 67 | delete |
| `spec/execution-passport/vectors/valid/valid-parent-chain.json` | 122 | delete |
| `spec/execution-passport/verify.mjs` | 284 | delete |

**Settings to review/remove for this feature:** No feature-specific SENTINEL names identified by this group scan; shared settings are covered by the dependency decisions.

**Kept files requiring reference/expectation review (line numbers at archive snapshot):**

- `deploy/helm/sentinel/values.yaml`: 30
- `docs/sentinel.cdx.json`: 335
- `requirements-dev.txt`: 44
- `scripts/build_passport_schema.py`: 1, 58, 83
- `scripts/build_passport_vectors.py`: 228
- `scripts/demo_execution_trust.py`: 576, 578
- `sdk-ts/test/fixtures/malicious/integer-beyond-the-json-safe-range.json`: 3
- `sentinel/domain/passport.py`: 182
- `tests_arch/test_config_alignment.py`: 36
- `tests_arch/test_helm_postgres_archive.py`: 15, 46
- `tests_arch/test_passport_conformance.py`: 11, 188, 199, 248, 279, 313, 321, 337, 342, 353, 365, 374 (+1 more)

### Phase 1: report-scripts

Remove repo-status/report generators and cloud-proof orchestration; retain security checks and the five explicitly permitted build scripts.

| Proposed path | LOC / binary size | Action |
|---|---:|---|
| `scripts/build_attack_surface.py` | 164 | delete |
| `scripts/build_baseline_manifest.py` | 383 | delete |
| `scripts/build_current_status.py` | 446 | delete |
| `scripts/build_desktop_app.py` | 95 | delete |
| `scripts/build_dossier.py` | 389 | delete |
| `scripts/build_gap_ledger.py` | 2135 | delete |
| `scripts/build_provenance.py` | 215 | delete |
| `scripts/build_release_artifact.py` | 334 | delete |
| `scripts/build_release_evidence.py` | 526 | delete |
| `scripts/build_scoreboard.py` | 356 | delete |
| `scripts/build_scorecard.py` | 216 | delete |
| `scripts/build_state_audit.py` | 370 | delete |
| `scripts/current_test_evidence.py` | 114 | delete |
| `scripts/ingest_aws_costs.py` | 395 | delete |
| `scripts/release_binding.py` | 403 | delete |
| `scripts/run_aws_proof_journey.py` | 299 | delete |
| `scripts/run_aws_sts_proof.py` | 120 | delete |
| `scripts/run_cloud_proof.py` | 213 | delete |
| `scripts/run_cross_region_dr_drill.py` | 339 | delete |
| `scripts/run_throughput_tiers.py` | 302 | delete |
| `tests_arch/test_cost_ingestion.py` | 233 | delete |
| `tests_arch/test_cross_region_dr.py` | 290 | delete |
| `tests_arch/test_current_status.py` | 103 | delete |
| `tests_arch/test_current_test_evidence.py` | 76 | delete |
| `tests_arch/test_release_binding.py` | 466 | delete |

**Settings to review/remove for this feature:** No feature-specific SENTINEL names identified by this group scan; shared settings are covered by the dependency decisions.

**Kept files requiring reference/expectation review (line numbers at archive snapshot):**

- `.github/workflows/ci.yml`: 115, 119, 127, 140, 729, 733, 735, 810, 935, 1184, 1217, 1238 (+3 more)
- `README.md`: 226
- `config/performance_targets.json`: 14
- `docs/DESIGN_PARTNER_RUNBOOK.md`: 115
- `docs/SCALE_AND_ASSURANCE.md`: 110
- `docs/current/DETECTION_EVIDENCE.md`: 35
- `docs/current/INCIDENT_ROTATION_CHECKLIST.md`: 60
- `docs/current/PILOT_KIT.md`: 76
- `docs/current/README.md`: 7, 16, 25, 41
- `docs/current/RELEASE_CHANGES.md`: 157, 267, 279
- `docs/current/TRY_SENTINEL.md`: 32
- `docs/engineering/CURRENT_STATE_AUDIT.md`: 3
- `evaluation/run_blind.py`: 30
- `scripts/build_and_scan_image.py`: 48, 113, 115
- `scripts/build_sbom_and_licenses.py`: 44, 129, 132
- `scripts/check_helm_chart.py`: 46, 149, 151
- `scripts/run_authorization_bench.py`: 59, 246, 248
- `scripts/run_dast.py`: 51, 305, 307
- `scripts/run_release_gates.py`: 5, 71, 630, 655, 743, 746
- `scripts/scan_release_for_secrets.py`: 79
- `scripts/verify_guards.py`: 76, 122, 186, 763, 765
- `sentinel/domain/detection_metrics.py`: 101, 214
- `tests_arch/test_attack_surface.py`: 30
- `tests_arch/test_components_are_reachable.py`: 90
- `tests_arch/test_console_bundle.py`: 281
- `tests_arch/test_ga_gates_cannot_be_faked.py`: 16, 45, 55, 57, 155
- `tests_arch/test_mcp_wire_proxy.py`: 650
- `tests_arch/test_release_gate_runner.py`: 41, 139, 140, 242, 297, 307, 314
- `tests_arch/test_release_packaging.py`: 6, 35, 209

### Phase 1: terraform

Keep shared modules and dev only; retain posture validation and its negative tests adapted to dev.

| Proposed path | LOC / binary size | Action |
|---|---:|---|
| `deploy/terraform/aws/envs/pilot/.terraform.lock.hcl` | 46 | delete |
| `deploy/terraform/aws/envs/pilot/main.tf` | 185 | delete |
| `deploy/terraform/aws/envs/production/.terraform.lock.hcl` | 46 | delete |
| `deploy/terraform/aws/envs/production/main.tf` | 217 | delete |
| `deploy/terraform/aws/envs/proof/.terraform.lock.hcl` | 66 | delete |
| `deploy/terraform/aws/envs/proof/main.tf` | 184 | delete |

**Settings to review/remove for this feature:** No feature-specific SENTINEL names identified by this group scan; shared settings are covered by the dependency decisions.

**Kept files requiring reference/expectation review (line numbers at archive snapshot):**

- `deploy/terraform/aws/modules/stack/variables.tf`: 5
- `tests_arch/test_release_packaging.py`: 16, 138, 144, 151
- `tests_arch/test_terraform_posture.py`: 72, 90, 126, 129, 237, 320, 417, 480

### Phase 1: docs-architecture

Merge still-true content into existing docs/ARCHITECTURE.md; retain sentinel/ARCHITECTURE.md as the package dependency contract.

| Proposed path | LOC / binary size | Action |
|---|---:|---|
| `docs/ARCHITECTURE_BASELINE.md` | 77 | merge |
| `docs/ARCHITECTURE_DECISIONS.md` | 168 | merge |
| `docs/ARCHITECTURE_REVIEW.md` | 1646 | merge |
| `docs/AWS_PRODUCTION_ARCHITECTURE.md` | 228 | merge |
| `docs/EXECUTION_TRUST_ARCHITECTURE.md` | 240 | merge |
| `docs/aws/AWS_ARCHITECTURE.md` | 153 | merge |

**Settings to review/remove for this feature:** No feature-specific SENTINEL names identified by this group scan; shared settings are covered by the dependency decisions.

**Kept files requiring reference/expectation review (line numbers at archive snapshot):**

- `README.md`: 185
- `deploy/helm/sentinel/templates/NOTES.txt`: 21
- `deploy/k8s/sentinel.yaml`: 115
- `deploy/terraform/aws/modules/stack/variables.tf`: 216
- `docker-compose.yml`: 4
- `docs/ARCHITECTURE.md`: 7
- `docs/aws/AWS_COST_MODEL.md`: 145
- `docs/aws/AWS_SECURITY_MODEL.md`: 165
- `docs/aws/COMPUTE_DECISION.md`: 168
- `docs/current/DECISION_LOG.md`: 39
- `scripts/demo_execution_trust.py`: 670
- `sentinel/ARCHITECTURE.md`: 134
- `sentinel/composition/settings.py`: 195
- `sentinel/interface/binding_routes.py`: 239

### Phase 1: docs-security

Merge into existing docs/SECURITY.md. ADVERSARIAL_REVIEW also covers core isolation and signature findings; preserve these rather than deleting it wholesale.

| Proposed path | LOC / binary size | Action |
|---|---:|---|
| `docs/ADVERSARIAL_REVIEW.md` | 371 | merge |
| `docs/ASI_THREAT_CONTROL_MATRIX.md` | 21 | merge |
| `docs/PENTEST_PACKAGE.md` | 156 | merge |
| `docs/SECURITY_ASSURANCE.md` | 135 | merge |
| `docs/THREAT_MODEL.md` | 509 | merge |

**Settings to review/remove for this feature:** No feature-specific SENTINEL names identified by this group scan; shared settings are covered by the dependency decisions.

**Kept files requiring reference/expectation review (line numbers at archive snapshot):**

- `README.md`: 74, 188
- `docs/PERFORMANCE_REPORT.md`: 107
- `docs/current/OWNER_ACTIONS.md`: 17
- `docs/engineering/CURRENT_STATE_AUDIT.md`: 52
- `scripts/quickstart.py`: 397
- `sentinel/ARCHITECTURE.md`: 134
- `tests_arch/test_documentation_cites_real_tests.py`: 5
- `tests_arch/test_ledger_multi_replica.py`: 5
- `tests_arch/test_retention_sweep.py`: 737
- `tests_arch/test_tenant_isolation_rls.py`: 5, 86
- `tests_arch/test_tool_names_are_not_prompts.py`: 3

### Phase 1: docs-compliance

Merge supported control mappings and limitations into docs/COMPLIANCE.md without compliance claims.

| Proposed path | LOC / binary size | Action |
|---|---:|---|
| `docs/COMPLIANCE_MAP.md` | 201 | merge |
| `docs/COMPLIANCE_MATRIX.md` | 151 | merge |

**Settings to review/remove for this feature:** No feature-specific SENTINEL names identified by this group scan; shared settings are covered by the dependency decisions.

**Kept files requiring reference/expectation review (line numbers at archive snapshot):**

- `tests_arch/test_documentation_cites_real_tests.py`: 70, 83

### Phase 1: docs-operations

Merge operating procedures into docs/OPERATIONS.md, including PostgreSQL-native backup/PITR procedures.

| Proposed path | LOC / binary size | Action |
|---|---:|---|
| `docs/DEPLOYMENT.md` | 183 | merge |
| `docs/DISASTER_RECOVERY.md` | 389 | merge |
| `docs/DR_RUNBOOK.md` | 147 | merge |
| `docs/MONITORING.md` | 4 | merge |
| `docs/OBSERVABILITY.md` | 351 | merge |
| `docs/PRODUCTION_RUNBOOK.md` | 162 | merge |
| `docs/SOAK_RUNBOOK.md` | 115 | merge |

**Settings to review/remove for this feature:** No feature-specific SENTINEL names identified by this group scan; shared settings are covered by the dependency decisions.

**Kept files requiring reference/expectation review (line numbers at archive snapshot):**

- `deploy/helm/sentinel/templates/NOTES.txt`: 10
- `deploy/helm/sentinel/values.yaml`: 26
- `deploy/terraform/aws/modules/backup/main.tf`: 38
- `docker-compose.yml`: 30
- `docs/DESIGN_PARTNER_RUNBOOK.md`: 129
- `scripts/_minio_harness.py`: 112
- `scripts/check_helm_chart.py`: 10
- `scripts/evaluate_slos.py`: 5, 59, 114
- `scripts/run_dr_postgres_pitr_drill.py`: 12
- `scripts/run_dr_postgres_wal_pitr_drill.py`: 808
- `scripts/run_observability_soak.py`: 2, 6
- `sentinel/domain/slo.py`: 5
- `sentinel/interface/cli.py`: 219
- `tests_arch/test_detection_mode.py`: 258
- `tests_arch/test_dr_postgres_wal_pitr_drill.py`: 5, 34
- `tests_arch/test_helm_postgres_archive.py`: 5, 108
- `tests_arch/test_multi_tenant_soak.py`: 79
- `tests_arch/test_slo_evaluation.py`: 5

### Phase 1: docs-integrations

Merge supported integrations and boundaries into docs/INTEGRATIONS.md.

| Proposed path | LOC / binary size | Action |
|---|---:|---|
| `docs/CONNECTOR_MATRIX.md` | 200 | merge |
| `docs/MCP_GATEWAY.md` | 358 | merge |
| `docs/TOOL_GATEWAY.md` | 407 | merge |
| `docs/current/AGENT_PLATFORMS.md` | 65 | merge |

**Settings to review/remove for this feature:** No feature-specific SENTINEL names identified by this group scan; shared settings are covered by the dependency decisions.

**Kept files requiring reference/expectation review (line numbers at archive snapshot):**

- `.env.example`: 115
- `README.md`: 189, 190
- `docs/DESIGN_PARTNER_RUNBOOK.md`: 128
- `docs/current/README.md`: 19
- `docs/current/RELEASE_CHANGES.md`: 233
- `sentinel/application/mcp_gateway.py`: 45
- `sentinel/infrastructure/mcp_wire.py`: 257
- `sentinel/interface/mcp_proxy_routes.py`: 21

### Phase 1: docs-status

Replace historic/generated readiness claims with one honest docs/STATUS.md.

| Proposed path | LOC / binary size | Action |
|---|---:|---|
| `docs/DELIVERY_STATUS.md` | 115 | merge |
| `docs/PRODUCTION_READINESS_REPORT.md` | 556 | merge |
| `docs/READINESS.md` | 236 | merge |
| `docs/RELEASE_GATES.md` | 247 | merge |
| `docs/RELEASE_READINESS.md` | 99 | merge |
| `docs/REMEDIATION_MATRIX.md` | 142 | merge |
| `docs/SENTINEL_PRODUCT_READINESS.md` | 262 | merge |
| `docs/current/RELEASE_STATUS.json` | 430 | merge |
| `docs/current/RELEASE_STATUS.md` | 70 | merge |
| `docs/current/RISK_REGISTER.json` | 502 | merge |
| `docs/current/RISK_REGISTER.md` | 257 | merge |
| `tests_arch/test_delivery_status.py` | 273 | merge |
| `tests_arch/test_product_readiness.py` | 246 | merge |
| `tests_arch/test_readiness_doc_matches_ledger.py` | 203 | merge |
| `tests_arch/test_readiness_matrix.py` | 156 | merge |

**Settings to review/remove for this feature:** No feature-specific SENTINEL names identified by this group scan; shared settings are covered by the dependency decisions.

**Kept files requiring reference/expectation review (line numbers at archive snapshot):**

- `.github/branch-protection.md`: 11
- `.github/workflows/ci.yml`: 331, 471, 735, 957
- `README.md`: 186, 236, 237
- `deploy/wal-archive/wal_s3.py`: 10
- `docker-compose.yml`: 37
- `docs/DESIGN_PARTNER_RUNBOOK.md`: 127
- `docs/TRANSPARENCY_SINK.md`: 181
- `docs/current/DEMO_RUNBOOK.md`: 7, 111
- `docs/current/INCIDENT_ROTATION_CHECKLIST.md`: 84
- `docs/current/OWNER_ACTIONS.md`: 4
- `docs/current/PILOT_KIT.md`: 85
- `docs/current/PRODUCTION_ACCEPTANCE.md`: 5
- `docs/current/PRODUCT_DEFINITION.md`: 35
- `docs/current/README.md`: 7, 8, 35
- `docs/current/TRY_SENTINEL.md`: 5
- `docs/engineering/CURRENT_STATE_AUDIT.md`: 51
- `scripts/run_ingest_loadtest.py`: 6
- `sentinel/ARCHITECTURE.md`: 134, 143, 151
- `sentinel/application/mcp_gateway.py`: 34
- `sentinel/infrastructure/sql/retention.py`: 182
- `tests_arch/test_documentation_cites_real_tests.py`: 101
- `tests_arch/test_retention_sweep.py`: 438

### Phase 1: market-docs

Remove commercial/research positioning and fundraising material from code documentation.

| Proposed path | LOC / binary size | Action |
|---|---:|---|
| `docs/COMPETITIVE_GAP_MATRIX.md` | 80 | delete |
| `docs/EXECUTIVE_SUMMARY.md` | 151 | delete |
| `docs/RESEARCH.md` | 258 | delete |
| `docs/current/COMMERCIAL_METRICS_TEMPLATE.csv` | 14 | delete |
| `docs/current/COMPETITIVE_MATRIX.md` | 62 | delete |
| `docs/current/DISCOVERY_INTERVIEW_TEMPLATE.md` | 59 | delete |
| `docs/current/GEMINI_ANTIGRAVITY.md` | 64 | delete |
| `docs/current/USP_VALIDATION.md` | 40 | delete |
| `tests_arch/test_research_page.py` | 263 | delete |

**Settings to review/remove for this feature:** No feature-specific SENTINEL names identified by this group scan; shared settings are covered by the dependency decisions.

**Kept files requiring reference/expectation review (line numbers at archive snapshot):**

- `.github/workflows/ci.yml`: 106
- `README.md`: 30, 37
- `docs/TRANSPARENCY_SINK.md`: 180
- `docs/current/FIRST_WORKFLOW.md`: 32
- `docs/current/OWNER_ACTIONS.md`: 19
- `docs/current/PILOT_KIT.md`: 66
- `docs/current/PRODUCT_DEFINITION.md`: 54
- `docs/current/README.md`: 13, 15, 23
- `docs/current/RELEASE_CHANGES.md`: 143
- `docs/current/TRY_SENTINEL.md`: 84
- `docs/engineering/CURRENT_STATE_AUDIT.md`: 53
- `sentinel/infrastructure/sql/workflow_metrics.py`: 7
- `sentinel/interface/operations_routes.py`: 37

### Phase 1: parked-docs

Remove documentation for features parked in Phases 2â€“3; record recovery and customer signals in docs/PARKED.md in Phase 3.

| Proposed path | LOC / binary size | Action |
|---|---:|---|
| `docs/A2A_GATEWAY.md` | 310 | delete |
| `docs/AGENT_DISCOVERY.md` | 243 | delete |
| `docs/AI_MODEL_EVALUATION.md` | 85 | delete |
| `docs/SKILL_REGISTRY.md` | 171 | delete |

**Settings to review/remove for this feature:** No feature-specific SENTINEL names identified by this group scan; shared settings are covered by the dependency decisions.

**Kept files requiring reference/expectation review (line numbers at archive snapshot):**

- `README.md`: 113, 191, 192, 193
- `sentinel/composition/container.py`: 298

### Phase 2: dead-security

Unreachable security subsystems; keep API-key/OIDC auth and persistence.crypto used for sealed connected-app credentials.

| Proposed path | LOC / binary size | Action |
|---|---:|---|
| `sentinel/domain/identity.py` | 366 | delete |
| `sentinel/domain/mfa.py` | 230 | delete |
| `sentinel/domain/threat_intel.py` | 440 | delete |
| `sentinel/infrastructure/cbor.py` | 179 | delete |
| `sentinel/infrastructure/openapi_risk.py` | 291 | delete |
| `sentinel/infrastructure/saml.py` | 224 | delete |
| `sentinel/infrastructure/secrets.py` | 361 | delete |
| `sentinel/infrastructure/threat_detection.py` | 273 | delete |
| `sentinel/infrastructure/webauthn.py` | 551 | delete |
| `tests_arch/authenticator.py` | 243 | delete |
| `tests_arch/test_openapi_risk.py` | 171 | delete |
| `tests_arch/test_saml_xml_hardening.py` | 219 | delete |
| `tests_arch/test_security_mfa.py` | 280 | delete |
| `tests_arch/test_security_passkeys.py` | 595 | delete |
| `tests_arch/test_security_secrets.py` | 373 | delete |
| `tests_arch/test_security_threat_detection.py` | 325 | delete |
| `tests_arch/test_threat_intel.py` | 404 | delete |

**Settings to review/remove for this feature:** No feature-specific SENTINEL names identified by this group scan; shared settings are covered by the dependency decisions.

**Kept files requiring reference/expectation review (line numbers at archive snapshot):**

- `docs/SECURITY.md`: 8
- `sentinel/infrastructure/sql/schema.py`: 530
- `tests_arch/test_gap_closures.py`: 25
- `tests_arch/test_sql_is_never_built_from_data.py`: 9

### Phase 2: dead-tooling

Unused campaign/admission helper and advisor-only CLI; remove the advisor console-script entry, preserve protect/authorization assertions in mixed tests.

| Proposed path | LOC / binary size | Action |
|---|---:|---|
| `scripts/run_attack_campaign.py` | 323 | delete |
| `sentinel/application/deployment_contract.py` | 110 | delete |
| `sentinel/domain/attack_campaign.py` | 547 | delete |
| `sentinel/interface/advisor_check.py` | 101 | delete |
| `tests_arch/test_advisor_check.py` | 63 | delete |
| `tests_arch/test_attack_campaign.py` | 596 | delete |

**Settings to review/remove for this feature:** No feature-specific SENTINEL names identified by this group scan; shared settings are covered by the dependency decisions.

**Kept files requiring reference/expectation review (line numbers at archive snapshot):**

- `docs/PROTECT_ENFORCEMENT.md`: 46
- `docs/current/DETECTION_EVIDENCE.md`: 13
- `docs/current/RELEASE_CHANGES.md`: 312
- `pyproject.toml`: 68
- `tests_arch/test_cli_advisor.py`: 15
- `tests_arch/test_component_status.py`: 26
- `tests_arch/test_security_bypass_detection.py`: 173, 184, 197

### Phase 2: dead-persistence

Retain backup.py and test_persistence_backup_pitr.py. Remove the duplicate schema/migration/diagnostic implementation under the later Phase 2 schema decision. Preserve non-partition assertions on live SQL; delete only the two partition-specific cases and correct partitioning claims.

| Proposed path | LOC / binary size | Action |
|---|---:|---|
| `sentinel/infrastructure/persistence/backup.py` | 616 | KEEP — Checkpoint 1 exception |
| `sentinel/infrastructure/persistence/diagnostics.py` | 248 | delete |
| `sentinel/infrastructure/persistence/migrations.py` | 417 | delete |
| `sentinel/infrastructure/persistence/schema.py` | 557 | delete |
| `tests_arch/test_persistence_backup_pitr.py` | 856 | KEEP — backup/PITR restore verification |

**Settings to review/remove for this feature:** No feature-specific SENTINEL names identified by this group scan; shared settings are covered by the dependency decisions.

**Kept files requiring reference/expectation review (line numbers at archive snapshot):**

- `sentinel/interface/cli.py`: 235, 241
- `tests_arch/test_persistence_benchmarks.py`: 29, 41, 42
- `tests_arch/test_persistence_crypto_audit.py`: 36, 37

### Phase 3: a2a

Agent-to-agent delegation is outside company oversight MVP; remove enrollment, proxy, verification and settings together.

| Proposed path | LOC / binary size | Action |
|---|---:|---|
| `sentinel/application/a2a_gateway.py` | 441 | park |
| `sentinel/composition/delegation_wiring.py` | 66 | park |
| `sentinel/domain/a2a.py` | 619 | park |
| `sentinel/domain/delegation_constraints.py` | 314 | park |
| `sentinel/domain/delegation_passport.py` | 782 | park |
| `sentinel/infrastructure/a2a_registry.py` | 214 | park |
| `sentinel/infrastructure/a2a_wire.py` | 332 | park |
| `sentinel/infrastructure/delegation_signing.py` | 245 | park |
| `sentinel/interface/a2a_proxy_routes.py` | 477 | park |
| `sentinel/interface/a2a_routes.py` | 430 | park |
| `sentinel/interface/delegation_verification.py` | 130 | park |
| `tests_arch/test_a2a_delegation.py` | 448 | park |
| `tests_arch/test_a2a_malformed_hops.py` | 87 | park |
| `tests_arch/test_a2a_proxy.py` | 538 | park |
| `tests_arch/test_a2a_registry.py` | 226 | park |
| `tests_arch/test_delegation_constraints.py` | 443 | park |
| `tests_arch/test_delegation_passport.py` | 815 | park |

**Kept-module dependencies requiring an explicit cut before removal:**

- `sentinel.application.a2a_gateway` ← `sentinel.composition.container`
- `sentinel.composition.delegation_wiring` ← `sentinel.composition.container`
- `sentinel.infrastructure.a2a_registry` ← `sentinel.composition.container`
- `sentinel.infrastructure.a2a_wire` ← `sentinel.composition.container`, `sentinel.composition.proxy_wiring`
- `sentinel.infrastructure.delegation_signing` ← `sentinel.composition.container`
- `sentinel.interface.a2a_proxy_routes` ← `sentinel.interface.http`, `sentinel.interface.mcp_proxy_routes`
- `sentinel.interface.a2a_routes` ← `sentinel.interface.http`

These are incidental feature wiring unless identified as retained shared core above. Remove the feature-specific field/call/import together; do not replace a core collaborator with a no-op.

**Settings to review/remove for this feature:** `SENTINEL_A2A_PROXY_ALLOWED_HOSTS`, `SENTINEL_A2A_PROXY_ALLOW_PRIVATE`, `SENTINEL_A2A_PROXY_ENABLED`, `SENTINEL_DELEGATION_KEYS`.

**Routes:** `POST /v1/a2a/cards`, `POST /v1/a2a/evaluate`, `POST /v1/a2a/proxy/{agent_id}`, `POST /v1/skills/assess`.

**Kept files requiring reference/expectation review (line numbers at archive snapshot):**

- `.env.example`: 406, 407, 408, 425
- `README.md`: 111, 112, 113
- `docs/current/INCIDENT_ROTATION_CHECKLIST.md`: 44
- `scripts/demo_execution_trust.py`: 61
- `sentinel/composition/container.py`: 34, 35, 132, 133, 145, 267, 269, 310, 766
- `sentinel/composition/proxy_wiring.py`: 19, 36
- `sentinel/composition/settings.py`: 198, 567, 568, 570, 716, 724, 732, 737
- `sentinel/interface/http.py`: 63, 77
- `sentinel/interface/mcp_proxy_routes.py`: 94

### Phase 3: detonation

Skill execution/sandboxing serves a different buyer; remove skills routes, sandbox configuration and console panes.

| Proposed path | LOC / binary size | Action |
|---|---:|---|
| `deploy/detonation/Dockerfile` | 65 | park |
| `sentinel/application/skill_detonation.py` | 136 | park |
| `sentinel/composition/detonation_wiring.py` | 74 | park |
| `sentinel/domain/detonation.py` | 559 | park |
| `sentinel/domain/observed_binding.py` | 403 | park |
| `sentinel/domain/skills.py` | 470 | park |
| `sentinel/infrastructure/detonation_container.py` | 374 | park |
| `sentinel/infrastructure/detonation_tracing.py` | 407 | park |
| `sentinel/infrastructure/skill_scanner.py` | 464 | park |
| `sentinel/infrastructure/strace_parse.py` | 303 | park |
| `tests_arch/fixtures/strace_live_detonation.log` | 184 | park |
| `tests_arch/fixtures/strace_real.log` | 39 | park |
| `tests_arch/test_container_detonation.py` | 459 | park |
| `tests_arch/test_detonation.py` | 348 | park |
| `tests_arch/test_detonation_tracing.py` | 504 | park |
| `tests_arch/test_observed_binding.py` | 334 | park |
| `tests_arch/test_skill_detonation.py` | 448 | park |
| `tests_arch/test_skill_registry.py` | 363 | park |
| `tests_arch/test_strace_parse.py` | 271 | park |

**Kept-module dependencies requiring an explicit cut before removal:**

- `sentinel.application.skill_detonation` ← `sentinel.composition.container`
- `sentinel.composition.detonation_wiring` ← `sentinel.composition.container`

These are incidental feature wiring unless identified as retained shared core above. Remove the feature-specific field/call/import together; do not replace a core collaborator with a no-op.

**Settings to review/remove for this feature:** `SENTINEL_DETONATION_IMAGE`, `SENTINEL_DETONATION_TRACING`.

**Routes:** `POST /v1/skills/assess`.

**Kept files requiring reference/expectation review (line numbers at archive snapshot):**

- `.env.example`: 426, 427
- `.github/workflows/ci.yml`: 867
- `README.md`: 114
- `docs/PERFORMANCE_REPORT.md`: 80
- `docs/aws/FINOPS_RUNBOOK.md`: 89
- `docs/current/DECISION_LOG.md`: 48
- `docs/current/PRODUCTION_ACCEPTANCE.md`: 56
- `docs/current/RELEASE_CHANGES.md`: 115
- `docs/current/TOPOLOGY.md`: 9
- `scripts/build_and_scan_image.py`: 26, 192, 239
- `scripts/check_config_alignment.py`: 19, 53
- `scripts/check_container_context.py`: 21
- `scripts/run_ingest_loadtest.py`: 147
- `scripts/verify_guards.py`: 437, 441, 454, 458, 469, 473
- `sentinel/composition/container.py`: 42, 141
- `sentinel/composition/settings.py`: 553, 556
- `sentinel/interface/console/app.js`: 49, 2417
- `sentinel/interface/console/index.html`: 10
- `tests_arch/test_components_are_reachable.py`: 82, 84, 85, 86, 87, 88
- `tests_arch/test_console_bundle.py`: 705
- `tests_arch/test_release_hygiene.py`: 186

### Phase 3: endpoint

Endpoint scanning/local device inventory is outside the cross-vendor service; remove its CLI and device-discovery tables with a new migration.

| Proposed path | LOC / binary size | Action |
|---|---:|---|
| `scripts/run_endpoint_sensor.py` | 160 | park |
| `sentinel/domain/endpoint_sensor.py` | 425 | park |
| `sentinel/infrastructure/endpoint_scan.py` | 434 | park |
| `sentinel/infrastructure/platforms/local_mcp_configs.py` | 207 | park |
| `sentinel/sdk/discovery.py` | 313 | park |
| `sentinel/sdk/discovery_app.py` | 182 | park |
| `tests_arch/test_endpoint_sensor.py` | 529 | park |

**Settings to review/remove for this feature:** No feature-specific SENTINEL names identified by this group scan; shared settings are covered by the dependency decisions.

**Kept files requiring reference/expectation review (line numbers at archive snapshot):**

- `docs/current/RELEASE_CHANGES.md`: 279, 330, 332, 342
- `docs/current/TRY_SENTINEL.md`: 36, 39, 45
- `pyproject.toml`: 67
- `scripts/scan_release_for_secrets.py`: 122, 123
- `scripts/try_sentinel.py`: 13, 92
- `sentinel/infrastructure/sql/device_discovery.py`: 9, 28, 30, 32, 36, 47, 58
- `sentinel/infrastructure/sql/migrate.py`: 53, 61, 622
- `sentinel/infrastructure/sql/retention.py`: 311, 329, 347, 464, 609, 610, 670
- `sentinel/infrastructure/sql/schema.py`: 58, 120
- `sentinel/interface/console/app.js`: 2045
- `sentinel/interface/console/index.html`: 3, 4
- `sentinel/interface/mcp_cli.py`: 288, 293, 311

### Phase 3: discovery

Park vendor inventory connectors, including additional reachable connector families; Phase 5 needs a cursor-based audit port, not this discovery contract.

| Proposed path | LOC / binary size | Action |
|---|---:|---|
| `scripts/run_discovery.py` | 146 | park |
| `sentinel/composition/discovery_wiring.py` | 256 | park |
| `sentinel/infrastructure/platforms/ai_connectors.py` | 779 | park |
| `sentinel/infrastructure/platforms/ai_discovery.py` | 169 | park |
| `sentinel/infrastructure/platforms/connectors.py` | 402 | park |
| `sentinel/infrastructure/platforms/copilot_studio.py` | 330 | park |
| `sentinel/infrastructure/platforms/databricks_agents.py` | 195 | park |
| `sentinel/infrastructure/platforms/discovery.py` | 440 | park |
| `sentinel/infrastructure/platforms/discovery_breadth.py` | 244 | park |
| `sentinel/infrastructure/platforms/discovery_support.py` | 300 | park |
| `sentinel/infrastructure/platforms/github_discovery.py` | 356 | park |
| `sentinel/infrastructure/platforms/gitlab_discovery.py` | 232 | park |
| `sentinel/infrastructure/platforms/identity_agents.py` | 395 | park |
| `sentinel/infrastructure/platforms/salesforce_agentforce.py` | 227 | park |
| `sentinel/infrastructure/platforms/servicenow_agents.py` | 241 | park |
| `sentinel/infrastructure/platforms/slack_apps.py` | 239 | park |
| `tests_arch/test_ai_connectors.py` | 618 | park |
| `tests_arch/test_connectors.py` | 406 | park |
| `tests_arch/test_discovery_wiring.py` | 369 | park |
| `tests_arch/test_github_discovery.py` | 518 | park |
| `tests_arch/test_platform_discovery.py` | 422 | park |

**Kept-module dependencies requiring an explicit cut before removal:**

- `sentinel.composition.discovery_wiring` ← `sentinel.composition.container`
- `sentinel.infrastructure.platforms.discovery` ← `sentinel.interface.cli`

These are incidental feature wiring unless identified as retained shared core above. Remove the feature-specific field/call/import together; do not replace a core collaborator with a no-op.

**Settings to review/remove for this feature:** `SENTINEL_DISCOVERY_`, `SENTINEL_DISCOVERY_AWS`, `SENTINEL_DISCOVERY_AWS_ACCESS_KEY_ID`, `SENTINEL_DISCOVERY_AWS_PATH_PREFIX`, `SENTINEL_DISCOVERY_AWS_REGION`, `SENTINEL_DISCOVERY_AWS_SECRET_ACCESS_KEY`, `SENTINEL_DISCOVERY_BEDROCK`, `SENTINEL_DISCOVERY_BEDROCK_ACCESS_KEY_ID`, `SENTINEL_DISCOVERY_BEDROCK_REGION`, `SENTINEL_DISCOVERY_BEDROCK_SECRET_ACCESS_KEY`, `SENTINEL_DISCOVERY_COPILOT_ENVIRONMENTS`, `SENTINEL_DISCOVERY_COPILOT_TOKEN`, `SENTINEL_DISCOVERY_DATABRICKS`, `SENTINEL_DISCOVERY_DATABRICKS_HOST`, `SENTINEL_DISCOVERY_DATABRICKS_WORKSPACE`, `SENTINEL_DISCOVERY_ENTRA_AGENT_ID_TENANT`, `SENTINEL_DISCOVERY_ENTRA_AGENT_ID_TOKEN`, `SENTINEL_DISCOVERY_ENTRA_TENANT`, `SENTINEL_DISCOVERY_ENTRA_TOKEN`, `SENTINEL_DISCOVERY_GITLAB`, `SENTINEL_DISCOVERY_GITLAB_GROUP`, `SENTINEL_DISCOVERY_GITLAB_HOST`, `SENTINEL_DISCOVERY_GITLAB_PROJECTS`, `SENTINEL_DISCOVERY_K8S_NAMESPACES`, `SENTINEL_DISCOVERY_K8S_SERVER`, `SENTINEL_DISCOVERY_K8S_TOKEN`, `SENTINEL_DISCOVERY_MCP_CONFIG_PATHS`, `SENTINEL_DISCOVERY_MCP_ENDPOINTS`, `SENTINEL_DISCOVERY_MCP_TOKEN_`, `SENTINEL_DISCOVERY_OKTA`, `SENTINEL_DISCOVERY_OKTA_HOST`, `SENTINEL_DISCOVERY_OKTA_ORG`, `SENTINEL_DISCOVERY_OPENAI_ORG`, `SENTINEL_DISCOVERY_OPENAI_TOKEN`, `SENTINEL_DISCOVERY_SALESFORCE`, `SENTINEL_DISCOVERY_SALESFORCE_HOST`, `SENTINEL_DISCOVERY_SALESFORCE_ORG`, `SENTINEL_DISCOVERY_SERVICENOW`, `SENTINEL_DISCOVERY_SERVICENOW_HOST`, `SENTINEL_DISCOVERY_SERVICENOW_INSTANCE`, `SENTINEL_DISCOVERY_SLACK_BOT_IDS`, `SENTINEL_DISCOVERY_SLACK_ENTERPRISE_ID`, `SENTINEL_DISCOVERY_SLACK_TEAM_ID`, `SENTINEL_DISCOVERY_SLACK_TOKEN`, `SENTINEL_DISCOVERY_SLACK_WORKSPACE`, `SENTINEL_DISCOVERY_VERTEX_LOCATION`, `SENTINEL_DISCOVERY_VERTEX_PROJECT`, `SENTINEL_DISCOVERY_VERTEX_TOKEN`.

**Kept files requiring reference/expectation review (line numbers at archive snapshot):**

- `scripts/check_config_alignment.py`: 59
- `sentinel/composition/container.py`: 142, 768
- `sentinel/composition/settings.py`: 220, 221
- `sentinel/composition/settings_parsers.py`: 38, 42
- `sentinel/interface/cli.py`: 35
- `tests_arch/test_components_are_reachable.py`: 93, 94, 95

### Phase 3: soar

Park outbound SOAR dispatch. Shared deterministic planning and guarded containment executor are retained exceptions, not deleted wholesale.

| Proposed path | LOC / binary size | Action |
|---|---:|---|
| `sentinel/composition/notifications.py` | 144 | park |
| `sentinel/infrastructure/soar.py` | 536 | park |

**Kept-module dependencies requiring an explicit cut before removal:**

- `sentinel.composition.notifications` ← `sentinel.composition.container`

These are incidental feature wiring unless identified as retained shared core above. Remove the feature-specific field/call/import together; do not replace a core collaborator with a no-op.

**Settings to review/remove for this feature:** `SENTINEL_SOAR_ENDPOINTS`, `SENTINEL_SOAR_MIN_PRIORITY`, `SENTINEL_SOAR_PAGERDUTY_ROUTING_KEY`.

**Kept files requiring reference/expectation review (line numbers at archive snapshot):**

- `.env.example`: 460, 461, 462
- `docs/RESPONSE_AND_CONTAINMENT.md`: 446, 447, 448
- `sentinel/composition/container.py`: 147, 384
- `sentinel/composition/settings.py`: 560, 563
- `sentinel/composition/settings_parsers.py`: 142, 155
- `tests_arch/test_components_are_reachable.py`: 60
- `tests_arch/test_outbound_chaos.py`: 52, 209
- `tests_arch/test_phase4_wiring.py`: 287, 297, 301, 302, 314, 339
- `tests_arch/test_remediation_execution.py`: 61, 1195, 1212, 1221

### Phase 3: analysis

Park estate analytics, commercial pilot metrics and demo-console features; keep core event identity, baseline and sequence engines.

| Proposed path | LOC / binary size | Action |
|---|---:|---|
| `scripts/seed_console_demo.py` | 142 | park |
| `sentinel/domain/adoption.py` | 383 | park |
| `sentinel/domain/ai_bom.py` | 613 | park |
| `sentinel/domain/blast_radius.py` | 260 | park |
| `sentinel/domain/exposure_graph.py` | 560 | park |
| `sentinel/domain/mcp_estate.py` | 293 | park |
| `sentinel/domain/value_metrics.py` | 386 | park |
| `sentinel/interface/analysis_routes.py` | 197 | park |
| `sentinel/interface/console_demo.py` | 91 | park |
| `sentinel/interface/estate_routes.py` | 398 | park |
| `sentinel/interface/pilot_routes.py` | 77 | park |
| `tests_arch/test_adoption.py` | 343 | park |
| `tests_arch/test_ai_bom.py` | 617 | park |
| `tests_arch/test_analysis_routes.py` | 307 | park |
| `tests_arch/test_console_demo.py` | 95 | park |
| `tests_arch/test_estate_routes.py` | 470 | park |
| `tests_arch/test_exposure_graph.py` | 475 | park |
| `tests_arch/test_mcp_estate.py` | 255 | park |
| `tests_arch/test_pilot_onboarding.py` | 292 | park |
| `tests_arch/test_value_metrics.py` | 305 | park |

**Kept-module dependencies requiring an explicit cut before removal:**

- `sentinel.domain.value_metrics` ← `sentinel.interface.operations_routes`
- `sentinel.interface.analysis_routes` ← `sentinel.interface.http`
- `sentinel.interface.console_demo` ← `sentinel.interface.http`
- `sentinel.interface.estate_routes` ← `sentinel.interface.http`
- `sentinel.interface.pilot_routes` ← `sentinel.interface.http`

These are incidental feature wiring unless identified as retained shared core above. Remove the feature-specific field/call/import together; do not replace a core collaborator with a no-op.

**Settings to review/remove for this feature:** `SENTINEL_CONSOLE_DEMO_TOKEN`.

**Routes:** `GET /console/demo.json`, `POST /v1/analysis/blast-radius/{agent_id}`, `GET /v1/analysis/mcp-estate`, `GET /v1/estate/adoption`, `GET /v1/estate/ai-bom`, `GET /v1/estate/ai-bom/cyclonedx`, `GET /v1/estate/exposure`, `GET /v1/estate/exposure/reach/{node}`, `GET /v1/pilot/devices`, `POST /v1/pilot/devices`, `DELETE /v1/pilot/devices/{device_id}`, `GET /v1/pilot/discovery-script`, `GET /v1/pilot/setup`.

**Kept files requiring reference/expectation review (line numbers at archive snapshot):**

- `.env.example`: 156
- `deploy/terraform/aws/modules/stack/main.tf`: 79, 80, 214, 215
- `deploy/terraform/aws/modules/stack/variables.tf`: 316
- `docs/current/RELEASE_CHANGES.md`: 193, 195, 199, 281, 332
- `docs/current/TRY_SENTINEL.md`: 54, 84
- `scripts/smoke_sdks.py`: 92
- `scripts/try_sentinel.py`: 69, 94, 99, 110
- `scripts/verify_guards.py`: 289, 293, 306, 310, 322, 326, 337, 341, 388, 392, 404, 408 (+2 more)
- `sentinel/composition/settings_parsers.py`: 735, 774
- `sentinel/interface/console/app.js`: 9, 10, 11, 12, 1993, 2004, 2026, 2038, 2095
- `sentinel/interface/http.py`: 64, 65, 83, 93, 137, 775
- `sentinel/interface/operations_routes.py`: 25
- `tests_arch/test_attack_surface.py`: 71
- `tests_arch/test_policy_diff_and_blast_radius.py`: 24, 203
- `tests_arch/test_terraform_posture.py`: 475, 481, 482

### Phase 3: orgs

Remove multi-org management and SCIM routes from the shared extra_routes module while preserving its tools, containment and console routes.

| Proposed path | LOC / binary size | Action |
|---|---:|---|
| `sentinel/infrastructure/directory.py` | 234 | park |
| `sentinel/infrastructure/orgs.py` | 127 | park |
| `tests_arch/test_tenant_directory.py` | 84 | park |

**Kept-module dependencies requiring an explicit cut before removal:**

- `sentinel.infrastructure.directory` ← `sentinel.composition.container`, `sentinel.interface.extra_routes`
- `sentinel.infrastructure.orgs` ← `sentinel.composition.container`, `sentinel.interface.extra_routes`

These are incidental feature wiring unless identified as retained shared core above. Remove the feature-specific field/call/import together; do not replace a core collaborator with a no-op.

**Settings to review/remove for this feature:** No feature-specific SENTINEL names identified by this group scan; shared settings are covered by the dependency decisions.

**Routes:** `GET /scim/v2/Users`, `POST /scim/v2/Users`, `DELETE /scim/v2/Users/{user_id}`, `GET /scim/v2/Users/{user_id}`, `PUT /scim/v2/Users/{user_id}`, `POST /v1/orgs`, `GET /v1/orgs/current`, `GET /v1/orgs/current/members`.

**Kept files requiring reference/expectation review (line numbers at archive snapshot):**

- `docs/SECURITY.md`: 9
- `sentinel/composition/container.py`: 96, 97, 320, 322, 598, 599
- `sentinel/interface/console/app.js`: 47, 48, 2452, 2465
- `sentinel/interface/console/index.html`: 10
- `sentinel/interface/extra_routes.py`: 22, 23, 401, 419, 441, 450, 473, 487, 500, 507
- `tests_arch/test_console_bundle.py`: 641, 648
- `tests_arch/test_gap_closures.py`: 220, 232, 237, 242, 249, 262, 268, 272, 280, 386, 390, 404 (+3 more)

## Deployment, CI and data migration decisions

**CI:** remove desktop.yml (windows/trial), ci.yml release-evidence and provenance jobs, classifier --soft benchmark branch and status/provenance stamping/download/upload steps. Keep test, verification, guard-mutation, security, docker, sign-image, deployment-validation, dynamic-api-security, types, license-scan, release-hygiene, live-postgres/service/redis/minio and kind-helm smoke, updating removed-surface expectations. Preserve artifact uploads for raw measurements and security scans. In particular keep image signing/verification in sign-image even though the separate provenance manifest job goes away.

Current job declarations for before/after comparison:

- `.github/workflows/ci.yml`:46: `test`
- `.github/workflows/ci.yml`:157: `live-postgres`
- `.github/workflows/ci.yml`:175: `live-postgres-service`
- `.github/workflows/ci.yml`:208: `live-redis`
- `.github/workflows/ci.yml`:236: `live-minio`
- `.github/workflows/ci.yml`:310: `kind-helm-smoke`
- `.github/workflows/ci.yml`:579: `verification`
- `.github/workflows/ci.yml`:618: `guard-mutation`
- `.github/workflows/ci.yml`:637: `security`
- `.github/workflows/ci.yml`:684: `release-hygiene`
- `.github/workflows/ci.yml`:771: `sign-image`
- `.github/workflows/ci.yml`:858: `docker`
- `.github/workflows/ci.yml`:945: `deployment-validation`
- `.github/workflows/ci.yml`:1076: `dynamic-api-security`
- `.github/workflows/ci.yml`:1136: `types`
- `.github/workflows/ci.yml`:1166: `license-scan`
- `.github/workflows/ci.yml`:1217: `release-evidence`
- `.github/workflows/ci.yml`:1244: `provenance`
- `.github/workflows/desktop.yml`:45: `windows`
- `.github/workflows/desktop.yml`:67: `trial`

**Image:** Dockerfile line 45 comment and 46 libstdc++ requirement must be rechecked after scikit-learn/scipy removal; line 76 sklearn import must go. Keep runtime dependency imports, source-context validation and standard/ copy. Narrow the evaluation copy only after the deterministic benchmark/runtime boundary is verified. Update scripts/check_container_context.py REQUIRED inputs and test_container_context.py; do not disable the context gate.

**Classifier dependencies:** remove scikit-learn from requirements.txt (pin at line 116 and stale explanatory comments), requirements.lock (pin at line 703) and pyproject.toml server extra (line 57) together. Regenerate the hash lock using the existing lock workflow, pruning classifier-only transitive dependencies only after verifying other consumers. Keep the direct runtime dependency lists in lockstep and retain their consistency test; requirements.lock remains a hash-pinned transitive resolution rather than a byte-identical copy.

**Configuration:** remove classifier (SOFT_PROMPT_*), A2A proxy, delegation keys, detonation, discovery family, SOAR and console-demo settings; remove their Settings fields, constructor keywords, parsers and validation branches together. Remove webhook-only REMEDIATION_ENDPOINTS if no kept executor reads it; retain remediation dry-run/containment controls while the guarded executor reads them. Keep REGION/RETENTION_* as documented shared core, not analysis extras. Search all template indirections and dynamic discovery prefixes, including *_FILE variants; no exact Phase 4 count is promised until unused readers are removed.

**Deployment surfaces:** update .env.example, docker-compose.yml, deploy/helm/sentinel/values.yaml, values.schema.json and templates/configmap.yaml plus secret templates, deploy/k8s/sentinel.yaml, docker-entrypoint.sh and deploy/terraform/aws/modules/stack where relevant. Most removed feature flags are documented only in .env.example; do not invent absent Helm/compose settings. The per-group line references above identify actual occurrences. Keep required core auth/binding/database/Redis/egress/attestation/telemetry settings and their schema validation.

**SQL:** the current live migration registry ends at version 39. Append a new cleanup migration; do not edit prior callbacks/entries. Remove feature runtime readers first. Drop a2a_agent_cards, device_discovery and organizations once their consumers are gone. Evaluate SCIM-only users/user_credentials/user_sessions/enrolment_tickets/webauthn_challenges as a related group, preserving FK order, tenant isolation and historical DDL. Keep tenants/agents, approvals, execution_authorizations, execution_operations, execution_receipts, remediation_idempotency, containments, policy_versions/tenant settings/keys, observations/execution graph, security audit and transparency tables. There are no dedicated skills/detonation/SOAR tables to invent a drop for.

Migration callbacks call the shared historical schema and RLS lists. A new drop migration must leave fresh installs and upgrades equivalent without retroactively changing applied migration behavior. Retain historical definitions/helper imports needed for replay, introduce an explicit current-table view for retention/readiness/fitness checks after drops, and test both an old-schema upgrade and a fresh database on SQLite and PostgreSQL. “One schema” means one live sql/ migration system, not rewriting history to remove every historical CREATE statement. Remove the unused persistence/schema.py system and adapt persistence crypto/audit tests to sql/ migrations.

**DR:** keep scripts/run_dr_postgres_wal_pitr_drill.py and the WAL archive adapter; document standard PostgreSQL backup/restore/PITR in docs/OPERATIONS.md. Retain core backup/restore integrity tests for this path. Keep persistence/backup.py and test_persistence_backup_pitr.py: verify_restore is required for Stage 4 ("backup restore tested"), like the retained objectstore.py adapter. Evaluate redundant drill scripts after retaining the one complete sql/-based WAL/PITR path; never silently downgrade off-host archive behavior.

## Fitness tests and invariants that must survive

Keep test_architecture_rules.py, test_components_are_reachable.py and test_component_status.py with registries updated for retained controls; remove only entries for actually removed symbols. Keep scripts/check_empty_modules.py unchanged unless a concrete expectation changes (it already discovers files). Keep scripts/check_config_alignment.py and its tests, adapting removed prefix families/surfaces. Keep route authorization tests (test_attack_surface.py) and console API-contract tests by extracting the pure collector before deleting build_attack_surface.py. Keep test_terraform_posture.py and check_terraform_posture.py; update the environment list and negative controls instead of disabling checks.

Keep health/readiness endpoint tests (test_readiness_probe_cache.py, runtime topology/preflight and SQL schema checks), ledger/retention/RLS/security-audit tests, execution binding/authorization/operation uncertainty tests, all Passport/SDK conformance tests, controlled-execution adapters and clean-install smoke. Delete only document-ledger/status fitness tests listed in removal groups. Mixed tests such as test_gap_closures.py, test_phase_closures.py, test_phase4_wiring.py, test_security_bypass_detection.py, test_protect_decisions.py, test_response_and_containment.py and test_gated_remediation.py require function-level edits: remove feature-only cases and preserve core assertions.

Archive-existing source assertions are not relaxed to get a pass. A baseline failure is recorded and diagnosed; it is not evidence that an invariant may be removed. Graph tests live alongside the permanent developer script and must be run separately in addition to the requested suite. Phase 1 should add that command to the retained verification job.

## Paths/list assumptions absent or different in this snapshot

- `docs/observability_soak*.json` (generated-evidence): no tracked match; no deletion to perform.
- `sentinel/infrastructure/discovery.py` (discovery): no tracked match; no deletion to perform.

Other differences: docs/ARCHITECTURE.md and docs/SECURITY.md already exist and must be merged into, not overwritten blindly. sdk-ts has all 16 copied canonical vectors already. The graph contains 258 files, not 261. .env assignment count differs from the approximate 150 because assignments and comment-only documented names are distinct. No service CONTRACT_ADDRESS/RPC setting was found; blockchain gateway references in docs do not justify deleting generic attestation settings.

## Phase 0 baseline — 2026-10-22

**Baseline ready for Phase 1: yes.** Phase 1 has not started. The user's latest
instruction limits this task to establishing and documenting Phase 0, then stopping.
This section supersedes the older continuation status and Windows baseline as the
reference result. The archive tag remains at `d63463cd3bc49bcd3e420ff4a100cc52fe6f4ad6`
and the branch remains `cleanup/oversight-core`.

### Environment and reproducible command

Ubuntu 24.04.3 LTS, WSL distro `Ubuntu`, WSL2 kernel
`6.6.87.2-microsoft-standard-WSL2`, Python **3.12.3**. Repository cloned to
`/home/lenovo2/sentinel` on ext4, with a fresh `.venv` installed from
`requirements-dev.txt` plus `pytest-timeout==2.4.0`. Tests run on the native Linux
filesystem. Dependency pins, installation output, OS information, source hashes,
raw logs, JUnit results and exit codes are retained in ignored reports.
`pgserver==0.1.4` supplies real local PostgreSQL for its fixtures.

```bash
source .venv/bin/activate
run_dir=baseline/verification-new
mkdir "$run_dir" || exit 1  # Refuse to overwrite earlier evidence.
pytest tests_arch/ -q --timeout=120 --timeout_method=thread --durations=30 -rA --junitxml="$run_dir/junit.xml" 2>&1 | tee "$run_dir/pytest.log"
pytest_status=${PIPESTATUS[0]}
printf 'pytest exit: %s\n' "$pytest_status"
ruff check sentinel tests_arch scripts/dev scripts/smoke_clean_install.py
python -m unittest discover -s scripts/dev -p test_import_graph.py
```

Saved runs use distinct subdirectories under `baseline/` so no earlier evidence
is overwritten. The pipeline records pytest's exit code through `PIPESTATUS[0]`.
Completed runs did not hit the timeout; per-file fallback was unnecessary.

### Results and limits

| Run | Total | Passed | Failed | Errors | Skipped | Timed out | JUnit seconds | Wall seconds | Exit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Fresh Linux before fix | 4609 | 4567 | 1 | 0 | 41 | 0 | 2269.808 | 6670 | 1 |
| After SDK probe fix (inbox race found) | 4615 | 4573 | 1 | 0 | 41 | 0 | 2551.481 | 2583 | 1 |
| Final Linux | 4617 | 4576 | 0 | 0 | 41 | 0 | 2013.038 | 2034 | 0 |

The eight extra architectural cases are six SDK probe regressions plus the
deterministic inbox-race regression on SQLite and PostgreSQL. The independent
standard-library graph suite has **10 passing tests**, including three added
regressions covering seven review-found failure cases. Ruff covers `sentinel`,
`tests_arch`, `scripts/dev`, and `scripts/smoke_clean_install.py`.
JUnit elapsed time and shell wall time are separate measurements; the reason for
the older run's large gap is not established. Skips remain unverified, not passes.

The final raw evidence is in `reports/phase0-linux-verified/`; the original fresh
Linux run and the SDK RED/GREEN plus soak reruns are in
`reports/phase0-linux-before/`. The first post-fix full run and its targeted
reruns are retained under `reports/phase0-linux-final/` even if a later full run
became the final baseline. Deliberately failing regression-development runs are
proof that the new guards can fail, not additional baseline failures.

The verification run started on October 21 ended around 63% without a final
JUnit report or exit code. On October 22, WSL was stopped and no pytest process
remained after startup. Its log is preserved in
`reports/phase0-linux-interrupted-20261021/`; the cause of interruption is unknown.
The final run restarted the full suite after verifying that 990 source files
matched the Windows workspace, allowing only Git newline conversion and excluding
the generated SQLite drill timing artifact. No partial run is counted as a pass.

### Ten slowest tests in the final full run

| Test ID | Seconds | Outcome |
| --- | --- | --- |
| `tests_arch/test_observability_bounds.py::test_ten_thousand_unknown_http_paths_use_one_bucket[postgres]` | 50.024 | passed |
| `tests_arch/test_observability_bounds.py::test_ten_thousand_unknown_http_paths_use_one_bucket[sqlite]` | 43.743 | passed |
| `tests_arch/test_workload_identity.py::test_discovery_over_cleartext_refuses_to_start` | 32.494 | passed |
| `tests_arch/test_persistence_backup_pitr.py::test_verify_restore_reports_a_rejecting_probe_instead_of_hanging` | 15.614 | passed |
| `tests_arch/test_persistence_backup_pitr.py::test_a_target_beyond_the_archived_wal_is_never_reported_as_verified` | 13.308 | passed |
| `tests_arch/test_dr_postgres_wal_pitr_drill.py::test_live_wal_archive_pitr_drill_runs_and_meets_targets` | 9.649 | passed |
| `tests_arch/test_persistence_backup_pitr.py::test_recovery_stops_at_the_requested_instant` | 9.321 | passed |
| `tests_arch/test_persistence_backup_pitr.py::test_verify_restore_performs_the_restore_and_reports_how_long_it_took` | 8.594 | passed |
| `tests_arch/test_sdk_remote.py::test_the_sdk_completes_the_journey_against_a_real_server` | 5.956 | passed |
| `tests_arch/test_red_team_suite.py::test_no_tracked_attack_returns_a_server_error_on_the_ingest_surface[postgres]` | 4.973 | passed |

### Failure classification

Counts are unique historical failing test IDs across the saved Windows and Linux
runs, not remaining failures in the final result. Each ID has exactly one category.
Windows-only failures are classified ENV-WINDOWS after confirming their unmodified
Linux tests pass, even when that feature is planned for later removal.

| Category | Historical failing test IDs |
| --- | --- |
| ENV-WINDOWS | 19 |
| ENV-SERVICE | 0 |
| REMOVED-LATER | 0 |
| FLAKY | 1 |
| CORE-BUG | 2 |

| Test ID | Category | Observed error | Resolution / Linux evidence |
| --- | --- | --- | --- |
| `tests_arch/test_cli_advisor.py::test_the_call_is_sandboxed_isolated_and_never_auto_approves` | ENV-WINDOWS | POSIX /opt/agy rejected by Windows absolute-path validation. | Unmodified test passed on Linux before the fix; final Linux outcome: passed. No Windows fix. |
| `tests_arch/test_cli_advisor.py::test_every_failure_is_stated_unavailability_never_an_exception[run0-no successful result]` | ENV-WINDOWS | POSIX /opt/agy rejected by Windows absolute-path validation. | Unmodified test passed on Linux before the fix; final Linux outcome: passed. No Windows fix. |
| `tests_arch/test_cli_advisor.py::test_every_failure_is_stated_unavailability_never_an_exception[run1-no successful result]` | ENV-WINDOWS | POSIX /opt/agy rejected by Windows absolute-path validation. | Unmodified test passed on Linux before the fix; final Linux outcome: passed. No Windows fix. |
| `tests_arch/test_cli_advisor.py::test_every_failure_is_stated_unavailability_never_an_exception[run2-failed shape validation]` | ENV-WINDOWS | POSIX /opt/agy rejected by Windows absolute-path validation. | Unmodified test passed on Linux before the fix; final Linux outcome: passed. No Windows fix. |
| `tests_arch/test_cli_advisor.py::test_every_failure_is_stated_unavailability_never_an_exception[run3-exited with status 3]` | ENV-WINDOWS | POSIX /opt/agy rejected by Windows absolute-path validation. | Unmodified test passed on Linux before the fix; final Linux outcome: passed. No Windows fix. |
| `tests_arch/test_cli_advisor.py::test_every_failure_is_stated_unavailability_never_an_exception[run4-did not answer within its timeout]` | ENV-WINDOWS | POSIX /opt/agy rejected by Windows absolute-path validation. | Unmodified test passed on Linux before the fix; final Linux outcome: passed. No Windows fix. |
| `tests_arch/test_cli_advisor.py::test_every_failure_is_stated_unavailability_never_an_exception[run5-could not be started]` | ENV-WINDOWS | POSIX /opt/agy rejected by Windows absolute-path validation. | Unmodified test passed on Linux before the fix; final Linux outcome: passed. No Windows fix. |
| `tests_arch/test_cli_advisor.py::test_cli_and_endpoint_are_mutually_exclusive_and_the_container_wires_the_cli` | ENV-WINDOWS | POSIX /opt/agy rejected by Windows absolute-path validation. | Unmodified test passed on Linux before the fix; final Linux outcome: passed. No Windows fix. |
| `tests_arch/test_cli_advisor.py::test_the_check_command_reports_a_cli_answer` | ENV-WINDOWS | POSIX /opt/agy rejected by Windows absolute-path validation. | Unmodified test passed on Linux before the fix; final Linux outcome: passed. No Windows fix. |
| `tests_arch/test_config_alignment.py::test_chart_refuses_unbound_or_fail_open_values[requireExecutionBinding-False]` | ENV-WINDOWS | Windows default decoding turns the UTF-8 BOM into part of replicaCount. | Unmodified test passed on Linux before the fix; final Linux outcome: passed. No Windows fix. |
| `tests_arch/test_config_alignment.py::test_chart_refuses_unbound_or_fail_open_values[rateLimitFailOpen-True]` | ENV-WINDOWS | Windows default decoding turns the UTF-8 BOM into part of replicaCount. | Unmodified test passed on Linux before the fix; final Linux outcome: passed. No Windows fix. |
| `tests_arch/test_container_context.py::test_symlink_is_refused_without_reading_its_target` | ENV-WINDOWS | Symlink creation denied by Windows privilege policy (WinError 1314). | Unmodified test passed on Linux before the fix; final Linux outcome: passed. No Windows fix. |
| `tests_arch/test_multi_tenant_soak.py::test_multi_tenant_concurrent_ingest_soak` | FLAKY | Windows p95 2,199.413 ms exceeded the unchanged 2,000 ms ceiling. | Three independent Linux reruns passed; final Linux outcome: passed. No threshold change. |
| `tests_arch/test_pilot_onboarding.py::test_scanner_never_opens_content_or_follows_symlinks` | ENV-WINDOWS | Symlink creation denied by Windows privilege policy (WinError 1314). | Unmodified test passed on Linux before the fix; final Linux outcome: passed. No Windows fix. |
| `tests_arch/test_pilot_onboarding.py::test_commands_are_found_by_name_without_following_or_running_them` | ENV-WINDOWS | Symlink creation denied by Windows privilege policy (WinError 1314). | Unmodified test passed on Linux before the fix; final Linux outcome: passed. No Windows fix. |
| `tests_arch/test_runtime_topology.py::test_a_fabricated_tree_with_a_workers_parent_is_observed` | ENV-WINDOWS | Symlink creation denied by Windows privilege policy (WinError 1314). | Unmodified test passed on Linux before the fix; final Linux outcome: passed. No Windows fix. |
| `tests_arch/test_runtime_topology.py::test_siblings_are_counted_from_a_real_tree` | ENV-WINDOWS | Symlink creation denied by Windows privilege policy (WinError 1314). | Unmodified test passed on Linux before the fix; final Linux outcome: passed. No Windows fix. |
| `tests_arch/test_runtime_topology.py::test_a_sibling_running_something_else_is_not_counted` | ENV-WINDOWS | Symlink creation denied by Windows privilege policy (WinError 1314). | Unmodified test passed on Linux before the fix; final Linux outcome: passed. No Windows fix. |
| `tests_arch/test_sdk_mcp_stdio.py::test_mcp_stdio_subprocess_forwards_one_request_to_sentinel` | ENV-WINDOWS | Sanitized child environment lacks SystemRoot; Windows SSL initialization fails. | Unmodified test passed on Linux before the fix; final Linux outcome: passed. No Windows fix. |
| `tests_arch/test_sdk_remote.py::test_the_sdk_completes_the_journey_against_a_real_server` | ENV-WINDOWS | Windows cannot remove still-open smoke.sqlite (WinError 32). | Unmodified test passed on Linux before the fix; final Linux outcome: passed. No Windows fix. |
| `tests_arch/test_release_hygiene.py::test_importing_the_sdk_loads_nothing_outside_the_standard_library` | CORE-BUG | Retained release probe misattributes Ubuntu's preloaded sitecustomize to SDK imports. | Fixed probe attribution; original assertion retained, six regressions added. Final outcome: passed. |
| `tests_arch/test_execution_concurrency.py::test_concurrent_redeliveries_are_accepted_exactly_once[sqlite]` | CORE-BUG | AssertionError: 2 threads accepted the same message; exactly one may assert 2 == 1  +  where 2 = len([ExecutionOutcome(accepted=True, executed=('policy', 'detect', 'evidence', 'report', 'approvals', 'attest', 'complete'...('validate', 'identity', 'replay'), replayed=('policy',), compensated=(), final_state='completed_attested', detail='')]) | Reproduced in 1/3 reruns and deterministically on both databases. Fixed engine to return the atomic inbox acceptance result; two backend regression cases added. Final outcome: passed. |

### Fixes made within Phase 0

1. **Thin SDK release probe:** measure imports attributable to the probe, excluding
   unrelated interpreter startup modules. Record explicit builtin and importlib
   requests too, so already-loaded dependencies still fail. Restore both import
   hooks in `finally`. Preserve the original `NONSTDLIB=` assertion. Six controlled
   subprocess cases cover startup hooks, new and cached dependencies, explicit hook
   imports, unrelated preloads and dynamic imports. All 36 release-hygiene tests pass.
2. **New graph tool, review finding:** reject unresolved dynamic targets shadowed by
   parameters/loop variables or sourced from unrelated scopes; invalidate visibly
   mutated maps and simple aliases. Do not infer a complete target set from those
   expressions.
3. **New graph tool, review finding:** report absent imported children of known
   namespace packages. Preserve the distinction between symbols and child modules
   in ordinary packages. Three added graph tests reproduced seven failures before
   the corrections and pass afterward; the real inventory is unchanged.
4. **Atomic inbox acceptance outcome:** the full post-probe-fix run exposed two
   workers reporting acceptance of the same message. One of three targeted reruns
   reproduced it. The engine ignored the boolean from the unique-key INSERT and
   returned `accepted=True` unconditionally after completing the plan. Return the
   actual INSERT result for terminal/parked outcomes. Keep the final-only write,
   fences, journal, and recovery ordering. A deterministic regression forces both
   preliminary reads to miss after their transactions close, and uses real SQL;
   it failed with two winners on both databases before the fix. Existing concurrency
   and crash-recovery assertions remain unchanged.

No application module was deleted, moved or refactored. The only application edit
is the three-line acceptance-result correction above. No existing assertion,
timing ceiling or service skip condition was weakened. No ENV-WINDOWS or
REMOVED-LATER application code was fixed. No new ENV-SERVICE failure required a fix.
The graph remains a syntax-based inventory, not an interprocedural proof of Python
behavior or authorization to delete. External consumers still require recursive
search and review before any removal.

### Live-service and artifact skips

The completed run reported absent services/tools cleanly rather than hanging.
It does not establish live Redis, MinIO, Docker tracing, Helm or kind coverage.
PostgreSQL fixtures did execute; platform-specific SQLite skips remain expected.

| Reason reported by pytest | Skipped cases |
| --- | --- |
| Helm binary unavailable; chart rendering is unverified | 1 |
| needs docker and the sentinel/detonate-trace:test image on PATH. Skipped rather than faked: a live-run test that silently substituted a mock would report the container path as verified when nothing ran. The path IS verified, just not from here. On the development machine Docker lives inside WSL and is not on the Windows PATH, so this skips -- but the run was performed by hand and its output is committed as tests_arch/fixtures/strace_live_detonation.log, which every test above parses. That fixture is the evidence; this test is the regression guard for a host that can run it. | 1 |
| dedicated local kind cluster not configured; real Kubernetes effects UNVERIFIED | 10 |
| SQLite has no row-level security to interrogate | 6 |
| SQLite has no declarative partitioning; see schema.py | 1 |
| SQLite has no declarative partitioning | 1 |
| SQLite has one isolation level | 1 |
| SQLite serialises writers with a busy timeout instead | 1 |
| SQLite has no row-level security | 1 |
| SENTINEL_TEST_REDIS_URL unset — real Redis unexercised in this run (fakeredis covers unit logic) | 2 |
| SENTINEL_TEST_S3_ENDPOINT/ACCESS_KEY/SECRET_KEY unset — live S3/MinIO round-trip UNVERIFIED in this run | 1 |
| dedicated local kind cluster not configured; the deployed journey is UNVERIFIED | 2 |
| gitleaks not installed; reported rather than passed silently | 2 |
| no .env in this checkout, so there is nothing to leak | 1 |
| isolated real Redis URL required | 1 |
| soak artifact not present in this checkout | 5 |
| UNVERIFIED: the independent-English promotion floor was not checked. evaluation/results/benchmark_test_english_soft.json is absent, which means the benchmark corpus could not be fetched (it is downloaded from a third-party dataset service and cached under evaluation/.cache, which is not committed). Regenerate with: python evaluation/run_benchmark.py --test --english --soft | 1 |
| SQLite has no WITH CHECK; the application predicate is all there is | 1 |
| no roles on SQLite | 1 |
| catalogue query is PostgreSQL-specific | 1 |

### Module reconciliation

All **30 of the requested modules are in the 39** unreachable modules. There are
no requested paths missing from that list. Inventory remains **258 modules,
219 reachable, 39 unreachable**, 26 with no incoming imports, and zero unresolved
internal/dynamic imports for this snapshot. Physical Sentinel LOC is 78,966
(78,965 at the archive snapshot; the core correction adds one physical line).

| Requested module | In the 39? | Disposition after separate consumer review |
| --- | --- | --- |
| `sentinel/infrastructure/webauthn.py` | yes | Phase 2: remove after recursive consumer verification. |
| `sentinel/infrastructure/cbor.py` | yes | Phase 2: remove after recursive consumer verification. |
| `sentinel/infrastructure/saml.py` | yes | Phase 2: remove after recursive consumer verification. |
| `sentinel/domain/mfa.py` | yes | Phase 2: remove after recursive consumer verification. |
| `sentinel/domain/identity.py` | yes | Phase 2: remove after recursive consumer verification. |
| `sentinel/infrastructure/secrets.py` | yes | Phase 2: remove after recursive consumer verification. |
| `sentinel/domain/threat_intel.py` | yes | Phase 2: remove after recursive consumer verification. |
| `sentinel/infrastructure/threat_detection.py` | yes | Phase 2: remove after recursive consumer verification. |
| `sentinel/infrastructure/openapi_risk.py` | yes | Phase 2: remove after recursive consumer verification. |
| `sentinel/domain/attack_campaign.py` | yes | Phase 2: remove after recursive consumer verification. |
| `sentinel/application/deployment_contract.py` | yes | Phase 2: remove after recursive consumer verification. |
| `sentinel/interface/advisor_check.py` | yes | Console entrypoint: any Phase 2 removal must remove sentinel-advisor-check from pyproject.toml and only the CLI case from mixed test_cli_advisor.py in the same commit. |
| `sentinel/infrastructure/persistence/backup.py` | yes | KEEP: Stage 4 backup/PITR verify_restore and its tests; Checkpoint 1 exception. |
| `sentinel/infrastructure/persistence/schema.py` | yes | Removed in Phase 2 under the later explicit schema decision; non-partition coverage retained on live SQL. |
| `sentinel/infrastructure/persistence/objectstore.py` | yes | Keep: external WAL archive adapter; service-root reachability is not the deletion criterion. |
| `sentinel/infrastructure/persistence/migrations.py` | yes | Removed in Phase 2 under the later explicit schema decision; non-partition coverage retained on live SQL. |
| `sentinel/infrastructure/persistence/diagnostics.py` | yes | Removed in Phase 2 under the later explicit schema decision; non-partition coverage retained on live SQL. |
| `sentinel/infrastructure/platforms/discovery_breadth.py` | yes | Phase 3: park vendor discovery. |
| `sentinel/infrastructure/platforms/copilot_studio.py` | yes | Phase 3: park vendor discovery. |
| `sentinel/infrastructure/platforms/databricks_agents.py` | yes | Phase 3: park vendor discovery. |
| `sentinel/infrastructure/platforms/salesforce_agentforce.py` | yes | Phase 3: park vendor discovery. |
| `sentinel/infrastructure/platforms/servicenow_agents.py` | yes | Phase 3: park vendor discovery. |
| `sentinel/infrastructure/platforms/gitlab_discovery.py` | yes | Phase 3: park vendor discovery. |
| `sentinel/infrastructure/platforms/slack_apps.py` | yes | Phase 3: park vendor discovery. |
| `sentinel/infrastructure/platforms/identity_agents.py` | yes | Phase 3: park vendor discovery. |
| `sentinel/infrastructure/platforms/local_mcp_configs.py` | yes | Phase 3: park endpoint. |
| `sentinel/infrastructure/platforms/discovery_support.py` | yes | Phase 3: park vendor discovery. |
| `sentinel/infrastructure/platforms/github_discovery.py` | yes | Phase 3: park vendor discovery. |
| `sentinel/domain/endpoint_sensor.py` | yes | Phase 3: park endpoint. |
| `sentinel/infrastructure/endpoint_scan.py` | yes | Phase 3: park endpoint. |

The other **nine** modules are:

| Additional unreachable module | Why unreachable from these roots / disposition |
| --- | --- |
| `sentinel.domain.detection_metrics` | Used by the external deterministic false-positive measurement CLI, outside the service roots; keep. |
| `sentinel.sdk.adapters` | Public SDK adapter package or shared adapter helper imported by external SDK clients, not by the service roots; keep. |
| `sentinel.sdk.adapters._gate` | Public SDK adapter package or shared adapter helper imported by external SDK clients, not by the service roots; keep. |
| `sentinel.sdk.adapters.anthropic` | Public SDK adapter package or shared adapter helper imported by external SDK clients, not by the service roots; keep. |
| `sentinel.sdk.adapters.gemini` | Public SDK adapter package or shared adapter helper imported by external SDK clients, not by the service roots; keep. |
| `sentinel.sdk.adapters.langchain` | Public SDK adapter package or shared adapter helper imported by external SDK clients, not by the service roots; keep. |
| `sentinel.sdk.adapters.openai_agents` | Public SDK adapter package or shared adapter helper imported by external SDK clients, not by the service roots; keep. |
| `sentinel.sdk.discovery_app` | Desktop discovery application launched and packaged separately; Phase 3 endpoint parking. |
| `sentinel.sdk.mcp_stdio` | Explicit sentinel-mcp-stdio console entrypoint, outside the selected graph roots; keep. |

Unreachable means unreachable from ASGI/HTTP/worker/CLI/SDK roots, not unused.
The inventory command succeeds; bare `--check` still refuses the 39 unexplained
unreachable modules. Phase 0 does not add blanket exceptions to make it green.
In particular, preserve `persistence.objectstore` for external WAL archival, public
SDK adapters and MCP stdio, and the external deterministic measurement helper.

### Verdict and stop point

**Baseline ready for Phase 1: yes.** There are no unresolved CORE-BUG baseline failures.
Commit message requested by the latest brief:
`chore(phase0): establish Linux test baseline`.
Stop after Phase 0; no Phase 1 deletion is authorized by this record.

## Ordered execution after confirmation

### Historical continuation status — 2026-10-20 (superseded above)

The working-tree changes and verification history are consolidated in [CHANGES.md](CHANGES.md). Later evidence exists beyond the Windows baseline above: `reports/phase0-linux-results.json` records an interrupted Linux run (exit 2, 2,354 passed, 13 skipped), and the native-filesystem Linux pytest run was still active when inspected during this continuation. Neither establishes a completed passing full suite.

Fresh continuation checks passed all seven graph regression tests and Ruff over `sentinel`, `tests_arch`, and `scripts/dev`. The regenerated graph still reports 258 modules, 39 unreachable modules, 26 modules with no incoming imports, and no unresolved internal or dynamic imports. The existing generated timing change in `docs/dr_sqlite_drill.json` remains in the working tree. Product cleanup remains unstarted; the first unchecked item below is still the resumption point.

- [x] Establish the Linux baseline and complete the required checks; see the Phase 0 baseline section above.
- [x] Phase 1: cut incidental consumers, preserve shared security/route helpers, migrate Passport fixtures, remove non-product material, consolidate docs and all inbound links; run full pytest and Ruff before the requested commit.
- [ ] Phase 2: re-run graph plus recursive text searches per module; remove only proven unused modules/tests, keep documented external WAL/benchmark/SDK support, and record any new exceptions; full suite and Ruff before commit.
- [ ] Phase 3: remove routes/config/console/screens and feature-only tests atomically, preserve shared core subsets listed above, append drop migration with upgrade/fresh-install coverage, write PARKED.md with LOC/tag/customer return signals; full suite and Ruff before commit.
- [ ] Phase 4: eliminate unused settings, count actual routes/settings/jobs/files/LOC/tests, verify thin SDK imports and core invariants, update README and results table, run checks, commit and STOP for user review.
- [ ] Only after the Phase 4 confirmation: implement 5.1–5.6 with current official API verification, fixture-only connector tests and unchanged approval/execution authority, then Phase 6 verification/report. No connector, credential broker or new source integration is implemented in Phase 0.

Requested phase commit messages remain as specified in the user brief. Latest requested Phase 0 commit: `chore(phase0): establish Linux test baseline`. No Phase 1 deletion is authorized by writing this file.

## Phase 5 — deferred follow-up (not started)

Phase 5 must restore answers to demo questions 1–4 (actor, authenticated identity, delegator, granted permissions) through the agent registry and retained identity/authorization paths; oversight_demo.py (5.6) must answer them.

This records the approved future obligation only. Phase 5 implementation remains
outside the authorized Phase 4 cleanup; it has not started.

## Open decisions

- **Passport integer range** — service/JS/schema bound to ±(2^53−1); standard
  verifier unbounded. Must be resolved before any external party verifies Passports.
  Recommended direction: adopt the bounded rule everywhere, because the issuer
  and the JS verifier already enforce it. Phase 1 preserves both corpora, all
  verifier results (including `10-large-integer.json`), the service, TS SDK,
  schema and the existing SPEC.md integer rules. The user approved documenting
  this incompatibility while consolidating the files on 2026-10-22.

<!-- phase1-results:start -->
## Phase 1 results — 2026-10-23

**Ready for Phase 2: yes.** This means the authorized Phase 1 cleanup is verified;
it is not production readiness or authorization to start Phase 2. Work remains on
`cleanup/oversight-core`. No main merge or pull request is part of this phase.
Recovery tag `archive/pre-cleanup` remains
`d63463cd3bc49bcd3e420ff4a100cc52fe6f4ad6`; Phase 0 reference is `d45b220`.

### Per-group accounting

| Group | Files removed | Source LOC removed | Binary bytes removed | Test IDs removed / added | Commit |
|---|---:|---:|---:|---:|---|
| council | 124 | 23,934 | 642,617 | 0 / 0 | `dbe4642` |
| blockchain | 5 | 8,078 | 0 | 0 / 0 | `0c321f3` |
| market-docs | 9 | 991 | 0 | 18 / 0 | `53e685b` |
| parked-docs | 4 | 809 | 0 | 0 / 0 | `2924536` |
| generated-evidence | 76 | 19,557 | 462,761 | 0 / 0 | `dae101f` |
| report-scripts | 27 | 9,314 | 0 | 135 / 0 | `4ba1a58` |
| duplicate-passport | 19 | 1,818 | 0 | 0 / 0 | `363886d` |
| terraform | 6 | 744 | 0 | 7 / 3 | `09eb178` |
| desktop | 3 | 123 | 0 | 0 / 0 | `41798ed` |
| classifier | 9 | 1,081 | 4,273,752 | 26 / 6 | `935ddfc` |
| docs-architecture | 6 | 2,510 | 0 | 0 / 0 | `ac74111` |
| docs-security | 5 | 986 | 0 | 0 / 0 | `327297b` |
| docs-compliance | 2 | 352 | 0 | 0 / 0 | `9e7c7d8` |
| docs-operations | 7 | 1,312 | 0 | 0 / 0 | `179b158` |
| docs-integrations | 4 | 1,030 | 0 | 0 / 0 | `3b72127` |
| docs-status | 14 | 3,366 | 0 | 35 / 0 | `fffc924` |
| Final verification/review fixes | 0 | — | 0 | 0 / 1 | `1840538` |

File/LOC/byte columns count removed source paths, including sources consolidated
or moved into retained documents and Passport corpora. They are gross removals;
the before/after table gives net repository size, including this result record.
Test ID columns include renamed/replaced cases as removals and additions.

The test-count reduction is reconciled: market-only checks −18; report-only
checks −135; Terraform environment cases −7/+3 (net −4); classifier-only and
replaced mixed checks −26/+6 (net −20); status-document checks −35 (including
the obsolete retraction-banner assertion after the citation backlog reached
zero); current-SBOM signing regression +1. Net: −211. Core authority, retention,
RLS, evidence, execution, Passport and restore assertions remain.
The report-scripts group removed one docs-status test file early because its
imports depended on removed report code; it is counted once, under report-scripts.

### Before and after

| Metric | Phase 0 reference | Phase 1 |
|---|---:|---:|
| Tracked files | 993 | 697 |
| Tracked text physical LOC | 328,736 | 256,948 |
| Tracked binary bytes | 5,379,130 | 0 |
| sentinel Python physical LOC | 78,966 | 78,684 |
| Settings fields | 76 | 73 |
| .env.example assignments | 69 | 66 |
| CI jobs | 20 | 16 |
| Direct runtime requirements | 12 | 11 |
| Hash-locked packages | 42 | 35 |
| Collected/executed tests_arch cases | 4,617 | 4,406 |
| Passed / skipped | 4,576 / 41 | 4,362 / 44 |


The three removed fields/environment assignments are `SOFT_PROMPT_DETECT`,
`SOFT_PROMPT_MODEL` and `SOFT_PROMPT_THRESHOLD` (with the `SENTINEL_` prefix in
environment variables). Their exact identifiers have no remaining active
source/configuration/documentation references outside this historical audit.
`scikit-learn` was removed from both direct runtime dependency declarations.
The lock was regenerated using CI's `uv==0.9.5`, with universal Python 3.12
resolution and generated hashes, without manual lock edits. Removed lock
packages: `cloudpickle`, `joblib`, `narwhals`, `numpy`, `scikit-learn`, `scipy`, `threadpoolctl`.
Other locked-version changes: {}.
The existing checked-in CycloneDX inventory was regenerated with the pinned
`cyclonedx-bom==7.3.0`; it contains the 11 remaining direct runtime dependencies.

### Classifier comparison

The same deterministic independent-English benchmark ran before and after removal:
1,467 cases, TP 111, FP 13, TN 451, FN 892; precision 0.8952, recall 0.1107,
false-positive rate 0.028, F1 0.197. All deterministic JSON results match after
excluding the retired `soft_threshold: null` metadata key. Promotion remains
**false**; low recall has not been represented as a passing promotion gate.

The same 60 benign tool-call payloads produced exactly the same deterministic
verdicts: 2/60 fired (3.33%), `run_migration` and `run tests`, via the existing
privileged-operation rule. Synthetic provenance and unknown real-world recall
remain explicit. The earlier 31/60 (51.7%) raw-model diagnostic is a different
measurement: it is **not** a service false-positive-rate improvement.

### Verification and CI

Final native Linux run, WSL Ubuntu ext4 `/home/lenovo2/sentinel`, Python 3.12.3:

```bash
pytest tests_arch/ -q --timeout=120 --timeout_method=thread --durations=30 -rA --junitxml=baseline/phase1/junit.xml 2>&1 | tee baseline/phase1/pytest.log
```

**4,406 cases: 4,362 passed, 44 skipped, 0 failed, 0 errors,
0 timeouts; exit 0; JUnit duration 2,266.552 seconds.** Raw output/JUnit,
per-group reference scans, import graphs and benchmark comparisons are retained
under ignored `baseline/phase1/`; no raw baseline/report files were committed.
The preceding full run had two stale binding-document-name expectations fail;
both were corrected to require the new document section URL, retaining the
DECLARED residual assertion, and the suite was rerun from the beginning.

- Ruff passed for `sentinel`, `tests_arch` and `scripts/dev`.
- Import-graph regression tests: 10 passed separately; the retained verification
  CI job now runs `python -m unittest scripts.dev.test_import_graph -q`.
- Import inventory: 258 → 257 modules;
  39 → 39 unreachable, no new unreachable modules.
- Tree secret scanner: passed, zero findings. It is the repository scanner,
  not an independent history or deployed-secret assessment.
- YAML parsed and actionlint v1.7.12 passed. Optional external shellcheck/pyflakes
  integrations were disabled; their checks are not claimed.
- All 62 relative Markdown file links across tracked Markdown resolve.
  The citation backlog ratchet fell from 23 to 0; retained positive scanner
  controls still run.
- The generated Docker allowlist matches `.dockerignore`; all 317 staged
  allowlisted inputs passed the container-context scanner. Docker is unavailable
  in this WSL environment, so an actual image build/start remains unverified.
- Review-fix checks: 71 binding/signing/document/context cases passed. The new
  SBOM-origin regression failed before the workflow fix and passed afterward.
  Blind-evaluation checks also passed after explanatory metadata was corrected.

CI jobs removed: `release-evidence`, `provenance`, and desktop `windows`/`trial`.
Retained jobs: `test`, `live-postgres`, `live-postgres-service`, `live-redis`,
`live-minio`, `kind-helm-smoke`, `verification`, `guard-mutation`, `security`,
`release-hygiene`, `sign-image`, `docker`, `deployment-validation`,
`dynamic-api-security`, `types`, `license-scan`.
Changed retained jobs: `test`, `verification`, `release-hygiene`, `docker`,
`license-scan`, `sign-image`. Removed obsolete classifier benchmarking and
report/provenance production, retained raw/security artifacts, added graph
regressions, and made signing download the current docker-job SBOM before
attesting it. Digest signing and identity/issuer verification remain.

### Skip accounting, review and rulings

The 41 → 44 skip change is fully explained: removing the classifier eliminated
one independent-soft-benchmark skip; removing checked-in DR evidence introduced
four absent-artifact skips in `test_dr_postgres_wal_pitr_drill.py` (record
consistency, dump separation, quiet RPO attribution, and deployment timeout
comparison). Those assertions were retained. Live backup/restore integrity
tests were not removed or replaced by skipped artifact checks. Other skip
reasons match the Phase 0 baseline.

A fresh whole-branch review found no critical issues and four important issues;
all were addressed in the single review-fix pass. Recovery instructions now
distinguish synthetic drills from deployment recovery, use supported Passport
verification syntax and inspect the actual restored database's role/RLS
catalogues. CI no longer signs an obsolete dependency snapshot. Remaining active
classifier claims were removed. Two documentation findings initially labelled
minor were treated as operational correctness issues and fixed. No review
minors remain deferred.

Rulings and limits:

- Keep the existing `baseline/phase1` ledger/audit layout rather than create or
  delete a second skill workspace; this preserves the established evidence.
- Omit obsolete predecessor `api/`/`app/` inventories and dated readiness claims
  from merged current guides; retain core findings/invariants and use the archive
  for historical detail. Historical measurements are not fresh deployment proof.
- Keep the user's Passport integer exception: service/JS/schema bound integers
  to ±(2^53−1), while the independent standard verifier accepts larger integers.
  Both corpora/verifiers remain unchanged. The open decision and recommended
  bounded direction are recorded; reconcile it before external verification.
- Retain the four absent-DR-artifact checks with explicit skips rather than
  weaken their assertions or invent current recovery measurements.
- The classifier removal is an authorized product change. Saved before/after
  measurements establish deterministic equality; the reviewer did not rerun
  that benchmark independently. The 31/60 raw-model diagnostic is not a service
  improvement claim.
- Docker runtime, cloud deployment, image publication/signing and external
  production assurance were not executed locally. CI gates remain; these are
  unverified capabilities, not inferred passes.
- The container scanner initially rejected an unfiltered checkout, as its
  contract requires Docker's filtered input; the exact staged allowlist passed
  without relaxing the gate.
- The two old document-link failures and three earlier classifier verification
  failures were diagnosed and corrected, not waived. The latter were a
  provenance-assignment source contract plus two obsolete test citations;
  700 other cases passed in that 703-case run, then all 28 affected-file cases
  passed before the final complete suite.
- Phase 2/3 implementation, a main merge and a PR remain outside this phase.

<!-- phase1-results:end -->

## Phase 2 schema decision

On 2026-10-24 the user explicitly overrode the earlier schema-parity stop
condition and authorized removal of `persistence/schema.py`, `migrations.py`
and `diagnostics.py`. Partitioning was designed only in the legacy schema and
was never wired into the live SQL migrations used by production. Live tables
are not partitioned; retention is a DELETE sweep in
`sentinel/infrastructure/sql/retention.py`. Preserve `backup.py`, `objectstore.py`
and all non-partition assertions, retargeted to the live SQL layer. The original
code remains recoverable from `archive/pre-cleanup`.

The pre-deletion capability proof below is preserved from
`reports/PHASE2_CAPABILITY_BLOCKER.md`. Reports and raw evidence stay uncommitted.

A temporary diagnostic under ignored `baseline/phase2/test_schema_probe.py`
created separate fresh PostgreSQL databases using the existing test fixtures.
It migrated one through `sql.migrate.migrate` and the other through the legacy
`MigrationRunner` with `persistence.schema.MIGRATIONS`. Both used the configured
application role, neither superuser nor BYPASSRLS. Both diagnostic cases passed;
that establishes successful measurement, not schema parity.

| Capability | Live SQL observation / existing coverage | Legacy observation | Result |
|---|---|---|---|
| RLS and forced RLS | Both catalogue flags present on probed tables; `test_every_protected_table_actually_carries_a_forced_policy` covers the protected set | Both flags present | Present in both |
| USING and WITH CHECK | Both policy expressions present; `test_rls_alone_blocks_the_leak_with_the_application_predicate_removed` and `test_a_write_cannot_be_attributed_to_another_tenant` cover enforcement | Both expressions present | Present in both |
| Application role | Diagnostic confirms `rolsuper=false`, `rolbypassrls=false`; `test_the_application_role_is_not_a_superuser` guards against vacuous RLS coverage | Same application role | Roles come from fixtures/deployment, not either migration system |
| Range-partitioned events and transitions | `domain_events` and `incident_transitions`: `pg_class.relkind='r'`, no partition catalogue entry | Both have `relkind='p'`, range strategy `r` | **Parity missing** |
| Create monthly partition | `CREATE TABLE ... PARTITION OF domain_events` fails with SQLSTATE `42P17`: `"domain_events" is not partitioned` | Same operation succeeds; probe rolled back | **Parity missing** |
| Audit storage | Ordinary `security_audit`; no legacy `audit_log` table | Range-partitioned `audit_log` | Direct fixture replacement is insufficient; core audit cases still need deliberate retargeting |

The existing test references above are mapped from unchanged source and Phase 1
coverage. This preflight did not rerun the full RLS suite or the final Phase 2
suite. The fresh diagnostic checked actual catalogue state, role properties and
partition creation against both migration systems.

`test_persistence_benchmarks.py::test_partition_pruning_happens` and
`test_partitions_can_be_created_and_dropped_in_constant_time` depend on the
legacy partitioned schema. The latter actually creates and drops a partition.
They cannot simply be retargeted to live SQL while preserving their assertions.
Legacy `persistence/schema.py` declares range partitioning for `domain_events`,
`incident_transitions` and `audit_log`; the recursive search found no equivalent
in the live SQL migration path.

Evidence is retained under ignored `baseline/phase2/`: `schema-probe.xml`,
`schema-probe.log`, `live-schema-capabilities.json`,
`legacy-schema-capabilities.json`, `schema-capability-references.txt` and
`import-graph-before.json`. The search covered all requested roots.

### Authorized test and schema changes

Only these partition-specific test IDs are deleted (each previously collected
on SQLite and PostgreSQL; four parametrized cases in total):

- `tests_arch/test_persistence_benchmarks.py::test_partition_pruning_happens`
- `tests_arch/test_persistence_benchmarks.py::test_partitions_can_be_created_and_dropped_in_constant_time`

All non-partition benchmark and crypto/audit cases are retained. Their assertion
expressions and thresholds stay unchanged while fixtures, SQL and connection
APIs are retargeted to live SQL. RLS, forced RLS and WITH CHECK continue to be
covered by the unchanged `test_tenant_isolation_rls.py` cases named above.
Isolation and lock-timeout checks run on the live engine; crypto still uses
the retained encryption implementation. Audit chaining, tamper detection,
tenant separation, pagination and rollback use the live `security_audit` table.

### Parked list for Phase 3

Range partitioning of domain_events/incident_transitions — designed in legacy
schema.py (recoverable from archive/pre-cleanup), never wired into live migrations.
Revisit when event volume makes DELETE sweeps too slow.

Phase 3 has not started. This item will become part of `docs/PARKED.md` in Phase 3.

<!-- phase2-results:start -->
## Phase 2 results — 2026-10-24

**Ready for Phase 3: yes.** Phase 2 is complete; Phase 3 has not started.
This is cleanup readiness, not production readiness. Work is on
`cleanup/oversight-core`; no merge or PR is part of this task.

### Per-group accounting

| Group | Modules removed | Files removed | Gross LOC removed | Test cases removed / added | Cases after | Commit |
|---|---:|---:|---:|---:|---:|---|
| dead-persistence | 3 | 3 | 1,222 | 4 / 2 | 4,404 | `742e86d` |
| dead-security | 9 | 17 | 5,525 | 209 / 0 | 4,195 | `1414eb3` |
| dead-tooling | 3 | 6 | 1,739 | 52 / 0 | 4,143 | `df3e863` |

Gross deleted paths contain 8,486 text lines; net repository size below includes
the retained adaptations and result prose. All 15 deleted Sentinel modules were
unreachable from service roots immediately before deletion. Per-path import
graphs and recursive consumer searches across every requested root are saved
under ignored `baseline/phase2/<group>/`. `reports/` and `baseline/` are uncommitted.
The recovery tag remains `archive/pre-cleanup` at `d63463cd3bc49bcd3e420ff4a100cc52fe6f4ad6`.
The reviewed documentation and generated container-manifest corrections were
committed separately as `e895f28` while final verification completed; that commit
is preserved. The final results commit contains only this plan and CHANGES.

| Metric | Before (`b66a8ca`) | After Phase 2 |
|---|---:|---:|
| Tracked files | 697 | 671 |
| Tracked text physical LOC | 256,948 | 248,649 |
| Sentinel modules | 257 | 242 |
| Sentinel Python physical LOC | 78,684 | 73,787 |
| Test files | 192 | 183 |
| Settings fields | 73 | 73 |
| .env.example assignments | 66 | 66 |
| CI jobs | 16 | 16 |
| Collected/executed cases | 4,406 | 4,143 |
| Passed / skipped | 4,362 / 44 | 4,101 / 42 |

Dependency manifests/lock versions, live SQL migrations, route registrations,
settings and CI jobs are unchanged, except removal of the advisor-check console
entry from `pyproject.toml`. Backup/PITR, WAL object-store support, public SDK
adapters, MCP stdio, deterministic metrics and all Phase 3 features remain.

### Test-count reconciliation and retained assertions

The net reduction is 263 cases: persistence −4/+2, security −209, tooling −52.
The two additions exercise interoperability between the real service audit
writer and the retained audit helper on SQLite and PostgreSQL.

| Group / test file | Cases removed |
|---|---:|
| dead-persistence: `tests_arch/test_persistence_benchmarks.py` | 4 |
| dead-security: `tests_arch/test_component_status.py` | 4 |
| dead-security: `tests_arch/test_gap_closures.py` | 2 |
| dead-security: `tests_arch/test_openapi_risk.py` | 17 |
| dead-security: `tests_arch/test_saml_xml_hardening.py` | 7 |
| dead-security: `tests_arch/test_security_mfa.py` | 47 |
| dead-security: `tests_arch/test_security_passkeys.py` | 49 |
| dead-security: `tests_arch/test_security_secrets.py` | 26 |
| dead-security: `tests_arch/test_security_threat_detection.py` | 16 |
| dead-security: `tests_arch/test_threat_intel.py` | 41 |
| dead-tooling: `tests_arch/test_advisor_check.py` | 4 |
| dead-tooling: `tests_arch/test_attack_campaign.py` | 43 |
| dead-tooling: `tests_arch/test_cli_advisor.py` | 1 |
| dead-tooling: `tests_arch/test_component_status.py` | 1 |
| dead-tooling: `tests_arch/test_security_bypass_detection.py` | 3 |

The four exact partition-specific case IDs removed are:

- `tests_arch/test_persistence_benchmarks.py::test_partition_pruning_happens[postgres]`
- `tests_arch/test_persistence_benchmarks.py::test_partition_pruning_happens[sqlite]`
- `tests_arch/test_persistence_benchmarks.py::test_partitions_can_be_created_and_dropped_in_constant_time[postgres]`
- `tests_arch/test_persistence_benchmarks.py::test_partitions_can_be_created_and_dropped_in_constant_time[sqlite]`

Adapted mixed test files (all surviving original assertion ASTs are identical
where retargeting touches core behavior; fixture/API/query inputs changed):

- dead-persistence: `tests_arch/test_helm_postgres_archive.py`, `tests_arch/test_persistence_benchmarks.py`, `tests_arch/test_persistence_crypto_audit.py`, `tests_arch/test_retention_sweep.py`.
- dead-security: `tests_arch/test_architecture_rules.py`, `tests_arch/test_component_status.py`, `tests_arch/test_documentation_cites_real_tests.py`, `tests_arch/test_gap_closures.py`, `tests_arch/test_sql_is_never_built_from_data.py`.
- dead-tooling: `tests_arch/test_cli_advisor.py`, `tests_arch/test_component_status.py`, `tests_arch/test_security_bypass_detection.py`.

The security group removes two SAML cases from the mixed gap-closure file,
three dormant-module parameter cases and their feature-only documentation case.
The tooling group removes only the advisor-check case from the mixed CLI file,
three cases for the unused admission helper, and the attack-campaign tooling
classification case. All other advisory isolation, credentials, worker,
authorization and network-admission manifest assertions remain.
The removed SAML citation anchor is replaced by the retained audit test; the
citation regex, assertions and zero-backlog requirement are unchanged.
The stale deleted-module exception was removed from the single-engine ratchet.

### Live-schema capability proof and deliberate differences

The earlier **Phase 2 schema decision** preserves the original fresh-database
PostgreSQL proof and the user's explicit override of partition parity. Live
tables are not partitioned; retention is a DELETE sweep. No partition migration
was introduced. The parked range-partitioning entry remains in this plan for
Phase 3's `docs/PARKED.md`.

| Retained capability | Executed proof |
|---|---|
| RLS without application predicate | `test_tenant_isolation_rls.py::test_rls_alone_blocks_the_leak_with_the_application_predicate_removed`; cross-tenant update/delete cases |
| Forced RLS / protected catalogue | `test_every_protected_table_actually_carries_a_forced_policy`; `test_no_tenant_owned_table_was_left_out_of_the_protected_set` |
| WITH CHECK | `test_a_write_cannot_be_attributed_to_another_tenant` |
| Non-superuser application role | `test_the_application_role_is_not_a_superuser`; original diagnostic also records no BYPASSRLS |
| Isolation levels / lock timeout | `test_persistence_benchmarks.py::test_isolation_levels_are_actually_applied`; `test_a_blocked_writer_fails_fast_rather_than_queueing` |
| Index plans / timing / query count | All nine non-partition benchmark functions retained, including the unindexed negative control; 250 ms median ceiling unchanged |
| Crypto and audit chain | All 26 original functions in `test_persistence_crypto_audit.py`; edits/deletions, per-tenant chains, keyset pagination, rollback and canonicalization |
| Live audit producer interoperability | `test_audit_log_and_live_service_writer_share_one_verifiable_chain` on both engines; existing live audit trail tests also retained |
| Real retention | Original count assertions now run the live DELETE sweep; all `test_retention_sweep.py` cases retained |

Implementation decisions: the live schema has no `deleted_at`, so the legacy
soft-delete-named benchmark retains its ID and both count assertions but ages
exactly a tenth of its incidents and invokes `SqlRetention.sweep_incident_history`.
The query set uses live columns and the real shard-scoped lease predicate.
EXPLAIN analysis, query observation and timing are now test-local helpers;
observation always calls the original live connection method. AuditLog now uses
the live `security_audit`/`detail` layout and the same `security_audit` advisory-lock
purpose as the service writer; it still joins the caller's transaction.
The two implementations' canonical hash/value objects are unchanged.

### Verification

Full Linux suite: **4,101 passed, 42 skipped,
0 failed, 0 errors, 0 timeouts**, exit 0; JUnit 2242.210 s,
approximate wall 2252.789 s. Same Phase 0 command and timeout settings:

```bash
pytest tests_arch/ -q --timeout=120 --timeout_method=thread --durations=30 -rA --junitxml=baseline/phase2/junit.xml
```

Before group commits: persistence 149 passed/10 skipped; security 65 passed
plus 33 architecture cases passed; tooling 123 passed/3 skipped. Ruff passed for
each group. The final Ruff run, 10 import-graph regression tests, actionlint,
secret scanner (671 members, zero findings) and 63 relative Markdown
links pass. This is the repository secret scanner, not an independent gitleaks run.
After writing the results, all 51 documentation, container-context and architecture
cases passed; the secret scan, 63-link check and diff whitespace check passed again.
Docker is absent from WSL PATH; image build/start/healthcheck remain **unverified**.
Other skipped live services and generated artifacts remain unverified.

Skips change from 44 to 42. Removed skipped IDs:

- `tests_arch/test_persistence_benchmarks.py::test_partition_pruning_happens[sqlite]`
- `tests_arch/test_persistence_benchmarks.py::test_partitions_can_be_created_and_dropped_in_constant_time[sqlite]`

New skipped IDs:

- None.

The Helm archive test now skips when `initdb` returns failure, matching the PITR
fixture. A real root invocation failed before the change and reports the explicit
`initdb: cannot be run as root` skip afterward. The normal-user test executes its
unchanged running-server assertions. Root-only diagnostic skips are not included
in the full-suite totals. The resumed runner's shell printed a literal zero;
the recorded exit is instead the actual pytest status observed from its parent
shell's wait4 result (`observed-exit.json`). Full per-ID skip reasons/comparison are in ignored
`baseline/phase2/skip-comparison.json` and JUnit/log files.

### Import graph: zero unexplained orphans

242 modules; 217 reachable;
25 unreachable, all explicitly classified below. Zero unresolved
internal/dynamic imports and zero stale allowances. `import_graph.py --check`
passed with one `--allow-unreachable` per documented module (exact command saved
as `baseline/phase2/graph-check-command.json`). The bare command intentionally
refuses documented external entrypoints/Phase 3 modules without those flags.

| Remaining unreachable module | Disposition |
|---|---|
| `sentinel.domain.detection_metrics` | Keep: deterministic measurement CLI used outside the service roots. |
| `sentinel.domain.endpoint_sensor` | Phase 3: endpoint feature; deliberately untouched in Phase 2. |
| `sentinel.infrastructure.endpoint_scan` | Phase 3: endpoint feature; deliberately untouched in Phase 2. |
| `sentinel.infrastructure.persistence.backup` | Keep: explicitly retained backup/PITR verify_restore capability and tests. |
| `sentinel.infrastructure.persistence.engine` | Keep: real PostgreSQL backup/PITR preflight tests use this engine; the user explicitly retained those tests. No service root uses it after audit retargeting. |
| `sentinel.infrastructure.persistence.objectstore` | Keep: external WAL archive adapter. |
| `sentinel.infrastructure.platforms.copilot_studio` | Phase 3: vendor discovery feature; deliberately untouched in Phase 2. |
| `sentinel.infrastructure.platforms.databricks_agents` | Phase 3: vendor discovery feature; deliberately untouched in Phase 2. |
| `sentinel.infrastructure.platforms.discovery_breadth` | Phase 3: vendor discovery feature; deliberately untouched in Phase 2. |
| `sentinel.infrastructure.platforms.discovery_support` | Phase 3: vendor discovery feature; deliberately untouched in Phase 2. |
| `sentinel.infrastructure.platforms.github_discovery` | Phase 3: vendor discovery feature; deliberately untouched in Phase 2. |
| `sentinel.infrastructure.platforms.gitlab_discovery` | Phase 3: vendor discovery feature; deliberately untouched in Phase 2. |
| `sentinel.infrastructure.platforms.identity_agents` | Phase 3: vendor discovery feature; deliberately untouched in Phase 2. |
| `sentinel.infrastructure.platforms.local_mcp_configs` | Phase 3: endpoint feature; deliberately untouched in Phase 2. |
| `sentinel.infrastructure.platforms.salesforce_agentforce` | Phase 3: vendor discovery feature; deliberately untouched in Phase 2. |
| `sentinel.infrastructure.platforms.servicenow_agents` | Phase 3: vendor discovery feature; deliberately untouched in Phase 2. |
| `sentinel.infrastructure.platforms.slack_apps` | Phase 3: vendor discovery feature; deliberately untouched in Phase 2. |
| `sentinel.sdk.adapters` | Keep: public SDK adapter/helper imported by external SDK clients. |
| `sentinel.sdk.adapters._gate` | Keep: public SDK adapter/helper imported by external SDK clients. |
| `sentinel.sdk.adapters.anthropic` | Keep: public SDK adapter/helper imported by external SDK clients. |
| `sentinel.sdk.adapters.gemini` | Keep: public SDK adapter/helper imported by external SDK clients. |
| `sentinel.sdk.adapters.langchain` | Keep: public SDK adapter/helper imported by external SDK clients. |
| `sentinel.sdk.adapters.openai_agents` | Keep: public SDK adapter/helper imported by external SDK clients. |
| `sentinel.sdk.discovery_app` | Phase 3: endpoint feature; deliberately untouched in Phase 2. |
| `sentinel.sdk.mcp_stdio` | Keep: explicit sentinel-mcp-stdio console entrypoint outside graph roots. |


### Review, corrections and limits

Review complete: fresh read-only review of `b66a8ca..df3e863` found no
critical issues or runtime regression. Two important findings concerned current
SAML claims in SECURITY and ENTERPRISE_CONTROLS. Three related descriptions
(verification-suite coverage in SECURITY/TESTING and a current-passkey schema
comment) were initially labelled minor.

Ruling: treat all five stale capability/verification statements as important
documentation correctness findings: they contradict the authorized cleanup and
could mislead an operator or security reviewer about shipped authentication or
test coverage. Corrected in one pass; no executable behavior or live migration
changed. Documentation-citation and architecture checks were rerun. No review
minors remain deferred.

The reviewer confirmed deletion scope, unchanged retained assertions, real SQL
observation, DELETE retention, audit table/detail/shared-lock adaptation and the
initdb-only skip boundary. The reviewer also caught a JUnit/pytest spelling
difference for Hypothesis TestLifecycleModel.runTest: normalized accounting
records four partition cases removed and two audit cases added, rather than a
false execution-model removal/addition. The model case remains unchanged.

Rulings on matters the reviewer set aside:

- Dated release notes and the dated engineering audit describe their original
  snapshots; retain their historical meaning rather than claim fresh verification.
- The added audit interoperability case is sequential. It proves both writers
  share the table and chain format; it is not new contention proof. Shared locking
  is aligned by inspection; the existing concurrency tests remain in the full suite.
- Full-suite completion, Docker, deletion chronology, result commit and push are
  established by this execution's own evidence, not inferred from the review.
  Docker remains unavailable; per-path pre-deletion evidence is preserved.
- Partition parity was deliberately waived by the user. The legacy engine is a
  documented keep for explicitly retained backup/PITR tests; deleting it would
  break that coverage. Neither decision authorizes Phase 3 work.

The first full run at `df3e863` exposed a stale generated `.dockerignore`: it
still listed 16 removed runtime/script paths. Its failure was reproduced, then
the repository generator refreshed the manifest and all 14 unchanged container-
context tests passed. That full run was interrupted and preserved separately;
the final full run completed with the manifest and review corrections applied.
The review corrections change only prose and a schema comment; their 37
documentation/architecture cases passed separately. Executable code and
retained assertions are unchanged by these final corrections.


Initial retargeting exposed the expected missing `audit_log` dependency; the
live-table adaptation made the retained cases pass. A fixture keyword error was
fixed before the passing run. An initial verification command named a nonexistent
audit test file and collected nothing; the corrected list ran the real audit trail.
Security verification caught stale compliance citations and a SAML anchor, which
were corrected without relaxing the documentation gate. A replacement comment
temporarily exceeded the existing 800-line module limit by one line; shortening
that comment restored the unchanged gate. The first full run exposed the stale
generated container manifest and was interrupted; all 14 container-context cases
passed after regeneration, and the reported full suite is a fresh complete run.
None of those failed attempts is represented as a passing run; their evidence
is retained separately. The established `baseline/phase2` ledger was reused
instead of creating a second skill workspace.

The previously agreed Passport integer-range discrepancy remains outside Phase 2.
No deterministic decision authority, approval/execution behavior, live migration,
Phase 3 feature, external production deployment, PR or main merge changed.

<!-- phase2-results:end -->


## Phase 3 execution decisions

The user's Phase 3 authorization supersedes the historical not-started notices.
The binding instructions received before work are recorded below.

# Phase 3 authorized execution brief

Start from ff627fa0617751cdd174d556041ffabb8390367a on cleanup/oversight-core,
WSL /home/lenovo2/sentinel. Phase 2: 4101 passed, 42 skipped, no failures.
Use CLEANUP_PLAN.md Phase 3 groups and Corrections and explicit dependency
decisions. Park means remove now, document in docs/PARKED.md, recoverable from
archive/pre-cleanup. Never commit main; no Phase 4, merge or PR. Write every
received or made decision into CLEANUP_PLAN.md before acting.

Order and commits:
1. MCP reply inspection/text extraction from A2A, its own commit:
   refactor(phase3): extract MCP reply inspection from A2A
2. detonation; 3. endpoint; 4. discovery; 5. analysis; 6. soar; 7. orgs; 8. a2a;
9. one appended drop migration. Each parking group: chore(phase3): park <group>.

MCP detection policy, refusal, receipts and streaming stay the same; MCP tests
stay unchanged and green before any A2A removal. Keep native AWS/Kubernetes
kill switch: platforms/remediation.py, remediation_wiring.py, guarded executor
subsets of infrastructure/remediation.py and domain/remediation.py. Keep
test_native_remediation.py unchanged and green. Park only webhook/playbook SOAR.

Keep domain/inventory.py, infrastructure/inventory.py, domain/residency.py,
infrastructure/enterprise.py, attestation, agent identity providers/wiring,
workload identity, tenant provisioning, operation/receipt stores, evidence,
execution graph and controlled-execution adapters. Park SqlDeviceDiscovery and
its routes; retain DEVICE_STATEMENTS required by historical migration 38.
Endpoint includes local_mcp_configs, sdk/discovery_app and sentinel-discover
if its only purpose is parked discovery. Park directory.py after SCIM/orgs.

Never edit existing migrations. Append exactly one new migration dropping
parked-feature tables; list every dropped table before editing. Test fresh
install and previous-head upgrade on SQLite/PostgreSQL, and prove kept tables,
indexes, RLS policies and roles are untouched.

For each group immediately before removal: rerun import graph and recursive
consumer search. Cut routes, settings including all listed env names and _FILE
variants, parsers, validation, wiring, console screens, Helm/.env/compose, CI
steps and docs together. Never replace a core collaborator with a no-op. If a
cut is not obvious, stop and ask. Delete feature-only tests; retain assertions
in adapted mixed tests. Ruff and touched tests must pass before each commit.

docs/PARKED.md: one entry per feature, purpose, removed LOC, archive paths,
removed settings/routes/tables and concrete customer signal to restore it.
Include the plan's range-partitioning entry. Add Reuse candidates for Phase 5:
github_discovery.py (AI agents in GitHub Actions; 5.1/5.2 GitHub), slack_apps.py
(Slack apps/bot users and HTTP-200 ok:false; 5.1/5.2 Slack), identity_agents.py
and discovery_support.py (shared paging/credential helpers). Phase 5 uses
audit-log connectors; these modules are reference material only.

Final Linux verification: Phase 0 pytest command with timeout=120 and
timeout_method=thread, durations=30, -rA, JUnit and logs baseline/phase3/;
zero failures/errors/timeouts. Reconcile per-group test and skip changes.
Run Ruff, 10 import-graph regressions, graph --check with zero unexplained
orphans, actionlint, secret scan and relative Markdown links. Record route
counts via AST and constructed app, settings count before/after. No removed
SENTINEL_* name remains anywhere, including Helm/docs. If Docker is available,
build and run healthcheck; otherwise explicitly unverified.

Final Phase 3 results in CLEANUP_PLAN.md and CHANGES.md: group files/LOC/routes/
settings/tables/tests removed/adapted/commit; deviations; Ready for Phase 4 yes/no.
Commit chore(phase3): record results, push -u origin cleanup/oversight-core,
verify remote SHA and clean tree, STOP.


### Execution rulings recorded before implementation

- Ruling P3-001: use the explicitly selected WSL clone and named branch, without
  creating another worktree or changing the Windows product checkout — this is
  the authorized source of truth; the cost of choosing another clone is divergent
  commits and misleading verification.
- Ruling P3-002: execute the ordered groups inline because they share settings,
  container wiring, routes and migrations; use one fresh whole-branch reviewer
  at the end — concurrent mutations would conflict with the required order.
- Ruling P3-003: keep decisions in this plan before each change and raw commands,
  graphs, test IDs/counts and logs in ignored baseline/phase3, reusing the established
  audit layout instead of a second skill workspace — evidence must survive
  compaction and remain uncommitted as in earlier phases.
- Ruling P3-004: keep the user's existing MCP/native-remediation tests byte-for-byte;
  any additional regression coverage goes in separate tests. Use the requested
  touched-test/Ruff gate per commit and one full-suite gate at completion; do not
  substitute a no-op, change a kept assertion or edit an existing migration.
- Pre-flight interfaces: MCP consumes A2A inspection today; extract before A2A.
  Endpoint/discovery share discovery helpers and CLI entrypoints; handle endpoint
  entrypoints first, then discovery. SOAR shares native execution/evidence types;
  retain that subset. Orgs consumes directory; remove directory only after orgs.
  Every group contributes candidate tables to the one final migration; historical
  DDL, including device migration 38, must remain replayable until that migration.

### Progress

Phase 3 baseline and MCP extraction pending. No feature has been parked yet.

### MCP preflight finding — compatibility decision required before extraction

The existing MCP route calls a2a_proxy_routes._inspect_reply, which extracts
bounded text and asks A2AGateway.evaluate to inspect a synthetic self-hop.
Besides metadata.prompt, agentId, resource, eventType=agent_delegation and
action=delegate, that sends metadata.a2a to ProtectGate. Its findings/severity
depend on the tenant's A2A card registry and pins: an unenrolled caller yields
unenrolled_agent/self_delegation, and drift anywhere in the registry can appear.
Those artifacts are not directly enforced by the reply helper, but custom
detection rules can read them. The default prompt detector reads the text.

Decision pending: ask the user whether MCP may retire only the synthetic
metadata.a2a inputs when A2A is parked while retaining the same ProtectGate,
trust, event/action/agent/resource/text inputs, stop/refusal rule, receipts and
streaming behavior. Do not make this core cut before the answer; the user
explicitly requires stopping and asking when a cut is not obvious. Preserving
registry-dependent inputs after dropping the A2A registry would require a
different compatibility design, not an invented no-op or fabricated registry.
Baseline measurement and read-only inspection may continue independently.

Another pending clarification concerns historical removed-setting inventories:
exact environment names conflict with the requirement for no full-name matches
anywhere. Suffix-only inventories with the prefix convention documented were
proposed; ignored historical logs and the archive remain intact. No settings
removal or inventory rewrite has been performed while the answer is pending.

### Phase 3 preflight results — awaiting MCP compatibility decision

- Starting commit remains ff627fa; no Phase 3 product commit or feature removal.
- Baseline: 4,143 collected cases; 73 settings; 78 AST routes; 76 constructed
  routes by default and 78 with both proxies enabled; migration head 39.
- All 285 unchanged MCP and native-remediation baseline cases passed on Linux:
  zero failures, errors or skips. Evidence: baseline/phase3/mcp-native-before.xml
  and .log. The first helper invocation used system Python and lacked defusedxml;
  rerunning with the repository virtual environment produced these results.
- A real in-memory diagnostic using ProtectGate, DeterministicPolicy and the
  existing reply helper proved the compatibility issue. An operator rule on
  metadata.a2a.findings matching unenrolled_agent refuses a benign reply before
  enrollment and permits the identical reply afterward. The ruleset loader
  supports operator-edited nested-field rules; this is an observable policy
  behavior, not an assumed future extension. Evidence is saved in
  baseline/phase3/reply-compatibility-probe.json; no product/config/database or
  network mutation was used for the diagnostic.
- Status: stop before MCP extraction until the user resolves the synthetic A2A
  metadata boundary. The removed-setting inventory clarification is also pending.
  Only this plan has changed in the tracked WSL tree. No Phase 4 work has started.

## Phase 3 decisions

### Confirmed audit scope — 2026-11-11

The user accepted `868bbf8` as the continuation point. The five existing commits
were backed up first; origin was confirmed at
`868bbf8fa135a34be4b0cfe3466a42a93a019ac1` before this audit changed anything.

1. Remediation webhooks remain Act: keep `SENTINEL_REMEDIATION_ENDPOINTS`, its
   parser, `composition/remediation_wiring.py`, `HttpRemediationIntegration`,
   `build_remediation_executor`, and explicit endpoint precedence over native
   integration. Keep native-remediation tests unchanged.
2. Park SOAR playbooks, notification composition and automation outside the
   approval plus execution-binding path. Shared remediation executors,
   deterministic planning, integration metadata and supplied event subscribers
   remain; P3-012 lists the retained shared contracts.
3. Retire `metadata.a2a` policy inputs. Preserve the extracted MCP reply inspector
   and every pre-existing MCP proxy assertion; restore any shared helper coverage
   accidentally removed with A2A-only files.
4. Full retired `SENTINEL_*` names appear only in `CHANGES.md`, this plan and
   `docs/PARKED.md`. `scripts/dev/scan_removed_settings.py` owns exactly those
   three executable exemptions and includes `_FILE` variants and dynamic prefixes.
5. Leave unchanged: `platforms/remediation.py`, guarded domain/infrastructure
   remediation, domain/infrastructure inventory, domain residency,
   infrastructure enterprise and attestation, agent identity providers/wiring,
   workload identity, OIDC tenant provisioning, operation/receipt stores,
   evidence, execution graph, controlled-execution adapters, and
   `persistence/backup.py` / `persistence/objectstore.py`.
6. Preserve historical `DEVICE_STATEMENTS` in `sql/device_discovery.py` for
   migration 38. Preserve migrations 1–39; only migration 40 removes parked tables.

Phase 4 is not authorized. The old file `tests_arch/test_phase4_wiring.py` is
pre-existing retained-remediation coverage; running it does not begin cleanup
Phase 4. No merge, PR, production migration or infrastructure apply is authorized.


### User decision — 2026-10-31: remediation webhooks are Act

Keep SENTINEL_REMEDIATION_ENDPOINTS, its settings parser, composition/remediation_wiring.py,
HttpRemediationIntegration, build_remediation_executor and explicit-endpoint-wins
precedence. test_native_remediation.py remains unchanged and must pass.
Park only SOAR playbooks, composition/notifications.py and automation triggering
actions outside approval plus execution binding. Keep unclear shared pieces and
list them here before acting. Remediation webhooks are deliberately retained as
Act execution adapters, not SOAR notification/automation.
Push existing commits through c3c8eb1 before SOAR edits. Then complete SOAR, orgs,
A2A, one appended drop migration, full Phase 3 verification, records and push;
STOP before Phase 4. Update CHANGES.md after each completed group.


The user approved the following decisions on 2026-10-25, before implementation.

1. Retire the A2A-specific policy inputs. The extracted MCP reply inspector must
   build the same policy payload as today EXCEPT the metadata.a2a block: keep
   eventType, action, resource, agentId and metadata.prompt byte-for-byte identical,
   and run the same deterministic detector/ruleset. All existing MCP proxy tests
   (refusal, receipt, streaming and non-streaming reply inspection) must pass
   unchanged. Add one regression test proving an injection in an MCP reply is
   still refused after A2A is parked. Record in docs/PARKED.md and CHANGES.md:
   "Custom policy rules matching metadata.a2a.* (or eventType agent_delegation
   from A2A) no longer match anything; no shipped rule used them."
   The eventType of retained MCP reply events remains agent_delegation; the
   quoted retirement of eventType inputs refers to events originating from A2A.
2. Keep full SENTINEL_* names wherever a removal is recorded. The removed-name
   scan exempts exactly CHANGES.md, CLEANUP_PLAN.md and docs/PARKED.md. All other
   tracked files, including code, tests, .env.example, Helm, compose, CI, README
   and other documentation, must contain zero removed names. The exemption list
   must be executable scan data, not a comment. Ignored diagnostic logs and the
   immutable recovery archive remain evidence, not current product surfaces.

Continue Phase 3 in the authorized WSL checkout and the order in
reports/PHASE3_TASK.md. These decisions resolve the two preflight questions.

### Ruling P3-005: independent MCP reply inspection

Keep bounded text extraction in a pure domain helper, re-exported by the A2A
wire module until that feature is parked. Add an interface reply inspector
calling the existing container.protect_gate with TrustLevel.UNSIGNED and the
same five payload values; do not introduce tenant-policy evaluation, change
normalization, or alter the A2A route while extracting MCP. The legacy helper
did not pass tenant_id to ProtectGate.evaluate, so the extracted call must not
silently add it. Preserve depth and length limits and refusal wording.
Test the real MCP route with its A2A collaborator absent, and independently
check the detector payload and trust. All pre-existing MCP/native tests remain
unmodified in this extraction commit. If this ruling is wrong, policy
compatibility or reply enforcement could change, so both are explicit gates.

### Phase 3 step 1 complete: MCP reply extraction

The real proxy regression failed on SQLite/PostgreSQL with HTTP 500 when its
A2A collaborator was absent, then passed after extraction. A separate policy
contract test proves the exact remaining payload, Unicode prompt normalization,
unsigned trust and deterministic refusal. Existing MCP/native tests are unchanged
by SHA-256 comparison. Targeted MCP proxy/streaming/attacks, native remediation
and A2A helper tests: 174 passed. Container-context checks: 14 passed. The final
new-regression rerun: 3 passed. Ruff and the repository secret scan passed.
The final full Phase 3 suite remains pending. No feature has been parked yet.

### Ruling P3-006: detonation parking boundary

The fresh graph and recursive consumer search are recorded under
baseline/phase3/detonation. Remove the 19 planned detonation/skill sandbox
files and their one skills assessment route. Cut only the skill section from
a2a_routes.py; leave the A2A routes intact until the final feature group.
Remove detonation settings/constructors, console assessment form/handler,
container allowlist entries and the three sandbox-only mutation checks.
Remove the captured-strace packaging case because its only fixtures and
consumer are being parked; keep the packaging refusal tests and Terraform
lockfile coverage. In the mixed live-console test, remove only the skill
request and score assertion; preserve all core route assertions.
No live detonation CI job or Helm/compose values remain at this head; the
consumer search verifies that rather than inventing deployment changes.
Remove stale sandbox claims and its obsolete canary exception. Retain native
containment, remediation and controlled execution. There are no detonation
tables to drop. Record full removed names, original paths and LOC in PARKED.md.
If this boundary is wrong, a shared helper could be lost; imports, touched
tests, route checks and the unchanged native-remediation suite gate the cut.

### Ruling P3-007: archived test recovery paths are not coverage claims

The documentation-citation guard correctly rejects deleted test module names
in docs/PARKED.md as if they were current coverage claims. Keep its assertions,
zero-debt threshold and scan scope unchanged. PARKED.md records exact source
recovery paths and the tests_arch/ recovery directory, linking this plan's exact
retired test-path inventory. This plan and ignored per-group collection records
retain the individual removed test identities. No file is exempted from the
coverage-citation guard and no archived test is presented as current coverage.
The removed-environment-name exemption list remains exactly the user's three
files; it is a separate scanner with separate semantics.

Repository commits continue to use the same per-command Codex identity as the
prior cleanup commits; no user or global Git configuration is changed.

### Phase 3 group complete: detonation

- Removed 19 whole files (6,205 lines); changed-path and numstat records: baseline/phase3/detonation/result.json.
- Collection: 3963 cases; 183 removed IDs and 3 added IDs since the preceding collection (baseline/phase3/detonation/test-delta.json).
- Verified touched cases, with corrected reruns superseding earlier failures: 169 passed, 4 skipped, zero remaining failures/errors. Reports: targeted.xml, citations-fixed.xml.
- Ruff, removed-setting scan and diff check pass. Settings remaining: 71. Existing retained MCP/native tests are byte-identical to Phase 2.
- Full Phase 3 Linux verification and the single drop migration remain pending.
- The three added cases belong to the preceding MCP extraction; detonation adds no architectural cases. The documentation citation failure is corrected without changing the guard.

### Ruling P3-008: endpoint parking and retained migration/MCP seams

The fresh graph and recursive consumers are in baseline/phase3/endpoint. Park
the local endpoint sensor, companion SDK, desktop discovery app and
sentinel-discover entrypoint. The pilot route module exclusively serves this
local device feature, so move its removal from the later analysis group to
this group, including setup/download/import/list/delete routes and the pilot
console screen. Preserve the console's shared privateTransportAllowed helper
and land sign-in on the existing overview screen.

Keep the separate mcp-discover command and all its tests unchanged: it observes
an explicitly supplied remote MCP server under the existing egress policy and
never enrolls it. It is not the local sentinel-discover companion being parked.
Remove local_mcp_configs wiring from discovery_breadth before deleting it;
the remaining vendor connectors are parked next. Record the now-retired local
configuration setting and its _FILE variant.

Retain DEVICE_STATEMENTS byte-for-byte in sql/device_discovery.py for historical
migration 38; remove only SqlDeviceDiscovery and its imports. Remove the device
retention reader/counts now, with the table drop deferred to the single final
migration. No existing migration callback or schema DDL is changed.

The mixed pilot test module contains independent advisor credential/HTTPS tests
and a historical schema-upgrade test: retain those functions and every assertion
while removing only local scanner/route tests. Keep the generic local trial
launcher; remove its --scan option and make --check query the retained dashboard.
Its demo options are handled with the analysis group. If this boundary is wrong,
enrollment or identity checks could be lost; unchanged MCP/native tests plus
retention, migration, advisor and console tests cover the retained behavior.

### Ruling P3-009: keep housekeeping until the final table drop

Refinement of P3-008 before editing retention: migration head 39 still creates
device_discovery, and the retention fitness guard requires every current table
to have an explicit lifetime policy. Keep its existing housekeeping reader and
counts until the single final drop migration, then remove them together with
the live-table view update. Endpoint collection/storage routes and runtime
store methods are removed now. This avoids an intermediate schema with an
unmaintained table and preserves migration-history semantics; no new device
observations can enter through the removed routes.

### Phase 3 group complete: endpoint

- Removed 8 whole files (2,327 lines); changed-path and numstat records: baseline/phase3/endpoint/result.json.
- Collection: 3901 cases; 62 removed IDs and 0 added IDs since the preceding collection (baseline/phase3/endpoint/test-delta.json).
- Verified touched cases, with corrected reruns superseding earlier failures: 193 passed, 0 skipped, zero remaining failures/errors. Reports: targeted.xml.
- Ruff, removed-setting scan and diff check pass. Settings remaining: 71. Existing retained MCP/native tests are byte-identical to Phase 2.
- Full Phase 3 Linux verification and the single drop migration remain pending.

### Ruling P3-010: vendor discovery parking boundary

Park the 21 discovery files in the fresh graph/consumer inventory, the
container discovery field/builder, the Settings credential collector and
its dynamic environment prefix, and the agent-discover CLI command. Keep
agent-inventory/reach/declarations and telemetry observation, all MCP
enrollment/proxy commands, domain/inventory.py, infrastructure/inventory.py,
and AWS/GitHub/Kubernetes controlled-execution adapters and their credentials.
The similarly named test_agent_discovery.py covers retained observation and
must remain unchanged. The five connector-specific test files are removed.

Remove the dedicated Terraform discovery policy/role/attachment/output and
its documentation; preserve runtime, audit and release identities. This is
source cleanup only: no Terraform apply or external infrastructure mutation.
Replace the discovery section in INTEGRATIONS.md with its parked status while
retaining old anchors for inbound links; keep the MCP sections intact. Remove
all retired environment names outside the three allowed removal records.
There are no discovery-specific SQL tables or new migration changes.

Record GitHub, Slack and identity/paging helpers as Phase 5 reference candidates
in PARKED.md; those future integrations are audit-log connectors, not restoration
of the old discovery contract. If this boundary is wrong, an inventory or effect
adapter might be lost; retained inventory, platform, CLI and architecture tests
are the group gate, with original MCP/native assertions left unchanged.

### Phase 3 group complete: discovery

- Removed 21 whole files (7,260 lines); changed-path and numstat records: baseline/phase3/discovery/result.json.
- Collection: 3789 cases; 112 removed IDs and 0 added IDs since the preceding collection (baseline/phase3/discovery/test-delta.json).
- Verified touched cases, with corrected reruns superseding earlier failures: 322 passed, 1 skipped, zero remaining failures/errors. Reports: targeted.xml.
- Ruff, removed-setting scan and diff check pass. Settings remaining: 70. Existing retained MCP/native tests are byte-identical to Phase 2.
- Full Phase 3 Linux verification and the single drop migration remain pending.

### P3-011 — analysis boundary (before removal)

Park the plan's analysis modules, their routes, estate/supply-chain/blast-radius console panels, shared demo publication and seeder, their deployment inputs and feature-only tests. The preflight found that the remaining test_policy_diff_and_blast_radius.py contains eleven blast-radius tests and unused policy helpers, but no policy-diff tests; remove that feature-only file as well. Retain the two core tests already preserved in test_pilot_onboarding.py, all native-remediation BlastRadius types/tests, and the separate policy-diff implementation and coverage wherever retained.

Keep /v1/workflow/metrics and its counted execution, approval, interruption, adoption and reconciliation data, plus domain.slo and every SLO assertion. Remove only its commercial value_metrics enrichment and the sole value assertion; remove the now-unused evidence export used only to count that report. Keep the trial launcher and advisor options, removing only seeding/demo options. Keep transport-safe operator sign-in, credential throttling, capability gates, all core console panels and their tests. Remove the demo-specific Terraform input and secret map entries without applying infrastructure changes. No tables are dropped in this group.

### Phase 3 group complete: analysis

- Removed 19 whole files (6,394 lines); changed-path and numstat records: baseline/phase3/analysis/result.json.
- Collection: 3532 cases; 259 removed IDs and 2 added IDs since the preceding collection (baseline/phase3/analysis/test-delta.json).
- Verified touched cases, with corrected reruns superseding earlier failures: 162 passed, 6 skipped, zero remaining failures/errors. Reports: targeted.xml, security.xml.
- Ruff, removed-setting scan and diff check pass. Settings remaining: 70. Existing retained MCP/native tests are byte-identical to Phase 2.
- Full Phase 3 Linux verification and the single drop migration remain pending.

### P3-012: SOAR removal boundary

The fresh graph/consumer scan is in baseline/phase3/soar. Remove notification
composition and the six-connector SOAR dispatcher; no separate production
playbook module exists in the current tree. Keep deterministic planning,
tenant integration metadata (including its legacy SOAR enum), domain and
infrastructure remediation, native integrations, and all supplied event
subscribers: these are shared core contracts, not automatic SOAR execution.
Default incident subscribers become the existing audit/log subscribers directly.
Keep remediation endpoint configuration and explicit HTTP endpoint precedence.
Remove only SOAR sections from mixed tests; native remediation stays byte-identical.
No SOAR tables or routes are dropped. The three SOAR settings are retired.

### Phase 3 group complete: soar

- Removed 2 whole files (680 lines); changed-path and numstat records: baseline/phase3/soar/result.json.
- Collection: 3512 cases; 20 removed IDs and 0 added IDs since the preceding collection (baseline/phase3/soar/test-delta.json).
- Verified touched cases, with corrected reruns superseding earlier failures: 123 passed, 0 skipped, zero remaining failures/errors. Reports: targeted.xml.
- Ruff, removed-setting scan and diff check pass. Settings remaining: 67. Existing retained MCP/native tests are byte-identical to Phase 2.
- Full Phase 3 Linux verification and the single drop migration remain pending.

### P3-013: org/SCIM boundary and shared directory

Remove all eight org/SCIM routes, their models, organization store and console
org/member panels; retain diagnostics, tools, containment, tenant provisioning,
inventory and identity. Keep test_tenant_directory.py unchanged: it verifies
configured/OIDC tenant provisioning and maintenance coverage, not SCIM.
Keep SqlDirectory/container.directory temporarily because A2A known-principal
inspection still reads it; remove it in the next A2A group once that reader is
gone. Tables and historical DDL remain until the one final migration.
Remove only the three SCIM/org cases from test_gap_closures.py. Retain every
tool execution, budget, CSP and transport assertion. Native/MCP tests unchanged.

Org verification found one remaining organization-only empty-state test; removed it with its parked panel. Other 86 targeted checks passed; console rerun required.

### Phase 3 group complete: orgs

- Removed 1 whole files (127 lines); changed-path and numstat records: baseline/phase3/orgs/result.json.
- Collection: 3508 cases; 4 removed IDs and 0 added IDs since the preceding collection (baseline/phase3/orgs/test-delta.json).
- Verified touched cases, with corrected reruns superseding earlier failures: 86 passed, 0 skipped, zero remaining failures/errors. Reports: targeted.xml, console-fixed.xml.
- Ruff, removed-setting scan and diff check pass. Settings remaining: 67. Existing retained MCP/native tests are byte-identical to Phase 2.
- Full Phase 3 Linux verification and the single drop migration remain pending.

### P3-014: A2A boundary

Fresh graph/consumer evidence is in baseline/phase3/a2a. Park all 17 planned
A2A files and the now-unshared SqlDirectory adapter. Remove A2A settings,
constructors, routes and signing-key parsing. Keep the independent MCP reply
inspector/text extraction and all pre-existing MCP/native tests unchanged.
Keep delegation_passport_digest/delegation_chain fields in core execution binding,
Passport, storage, serializers and their tests: those are stable evidence and
authorization contracts, not the parked A2A verifier. Keep the generic task nonce
table until the final consumer audit; no schema edits in this group.
Remove only the delegation-constraint step from the mixed execution-trust demo;
retain execution, binding, negative controls and evidence verification.
Directory's tenant-provisioning tests remain; directory store tables are considered
in the final migration together with organizations and A2A cards.

### Phase 3 group complete: a2a

- Removed 18 whole files (6,711 lines); changed-path and numstat records: baseline/phase3/a2a/result.json.
- Collection: 3354 cases; 154 removed IDs and 0 added IDs since the preceding collection (baseline/phase3/a2a/test-delta.json).
- Verified touched cases, with corrected reruns superseding earlier failures: 252 passed, 0 skipped, zero remaining failures/errors. Reports: targeted.xml.
- Ruff, removed-setting scan and diff check pass. Settings remaining: 63. Existing retained MCP/native tests are byte-identical to Phase 2.
- Full Phase 3 Linux verification and the single drop migration remain pending.

### P3-015: exact appended migration and current schema

Append migration 40 only. Drop in this order: user_credentials, user_sessions,
enrolment_tickets, webauthn_challenges, users, organizations, a2a_agent_cards,
device_discovery. Fresh recursive SQL consumer search found no retained feature
reader; only historical DDL and housekeeping remain. No CASCADE. Preserve
migrations 1–39 and their DDL/helper inputs byte-for-byte. Keep replay_nonces:
it is shared with retained execution replay prevention, not A2A-only storage.
Keep all tenant/core tables, indexes, roles and RLS policies unchanged.
Introduce current_schema inventories for live fitness checks; historical
SCHEMA_STATEMENTS and PROTECTED_TABLES still replay the old migrations unchanged.
Remove only parked-table housekeeping/counts. Update historical-upgrade fixtures
to actually build the previous schema before replay, not delete version rows
under an already-cleaned schema. Keep all retained schema/retention/RLS assertions.
The production migration is operator-run; this work exercises local test DBs only.

Migration verification: all four new real-database cases passed after migration 40.
The SQL identifier guard flagged the metadata-only comprehension's `table` name;
that name is reserved for audited SQL construction, so use `current_name` for
the non-SQL inventory projection. No guard assertion or SQL interpolation changed.

### Phase 3 group complete: migration

- Removed 0 whole files (0 lines); changed-path and numstat records: baseline/phase3/migration/result.json.
- Collection: 3358 cases; 0 removed IDs and 4 added IDs since the preceding collection (baseline/phase3/migration/test-delta.json).
- Verified touched cases, with corrected reruns superseding earlier failures: 132 passed, 8 skipped, zero remaining failures/errors. Reports: targeted.xml, guard-fixed.xml.
- Ruff, removed-setting scan and diff check pass. Settings remaining: 63. Existing retained MCP/native tests are byte-identical to Phase 2.
- Migration 40 is implemented; full Phase 3 Linux verification remains pending.

### P3-016: final discovery orphan

The final graph exposes domain/assets.py after vendor discovery was parked.
Fresh recursive symbol/import search finds only its own definitions, no retained
code, script or test consumers. Park this discovery vocabulary and its Docker
allowlist entry; do not add a blanket graph exception. Keep the 11 documented
external SDK, measurement and backup/PITR entrypoints. No settings/routes/tables
or tests change in this final discovery follow-up.

### P3-017: keep the schema module size guard

The new live inventory pushed historical schema.py to 823 lines; the unchanged
architecture guard rejected it. Move the new migration-40 callback and inventory
to sql/schema_cleanup.py, imported by migrate.py. Restore schema.py byte-for-byte
to the Phase 2 version. No historical callback, DDL or architecture limit changes.
This is a final cleanup adjustment, with schema/security regressions rerun.

The generated Docker allowlist requires canonical ordering; regenerated it with its existing generator after adding schema_cleanup.py. The manifest guard remains unchanged.

### Phase 3 group complete: discovery-remainder

- Removed 1 whole files (251 lines); changed-path and numstat records: baseline/phase3/discovery-remainder/result.json.
- Collection: 3358 cases; 0 removed IDs and 0 added IDs since the preceding collection (baseline/phase3/discovery-remainder/test-delta.json).
- Verified touched cases, with corrected reruns superseding earlier failures: 82 passed, 0 skipped, zero remaining failures/errors. Reports: targeted.xml, fixed.xml, manifest-fixed.xml.
- Ruff, removed-setting scan and diff check pass. Settings remaining: 63. Existing retained MCP/native tests are byte-identical to Phase 2.
- Migration 40 is implemented; full Phase 3 Linux verification remains pending.

### P3-018: current documentation follows removed surfaces

Final reference audit found old README/first-workflow A2A and skill-scanner claims
and an unqualified pilot release note. Replace current claims with parked status
and label release notes historical. No behavior or test contract changes.

### P3-020: remaining migration-test fixtures

The first uninterrupted run after the approved demo fix completed with 3,318
passed, 41 skipped and three failures, all in `tests_arch/test_migrations.py`.
Two cases still queried the parked `a2a_agent_cards` table. The PostgreSQL resume
case built migration 40's dropped schema, then rewound only its ledger to 37,
so historical RLS replay tried to protect an already-dropped `users` table.

Resolved in `73af863`: the resume fixture genuinely builds version 39 before
rewinding its ledger, then replays historical DDL and advances through migration
40. Only `a2a_agent_cards` was removed from the spot-check table list. Every kept
table check, original assertion and all production migration/DDL code remain
unchanged. This is the historical-fixture correction already authorized in
P3-015. Focused migration/demo verification passed (35 passed, 1 SQLite RLS
skip), followed by the complete green Linux suite recorded below.

## Phase 3 results

**Ready for Phase 4: yes. Phase 3 is complete; Phase 4 has not started.**

All planned feature parking and migration 40 are committed. PARKED.md now includes
the eight requested feature entries, retained Act webhooks, the metadata.a2a
behavior change and Phase 5 reference candidates. The initial five commits were
backed up and origin confirmed at `868bbf8fa135a34be4b0cfe3466a42a93a019ac1`.
The original four documentation changes were reviewed and committed separately as
`e6fc483`. Two small coverage restorations are listed below. The approved demo
scope and remaining historical migration fixtures were corrected in `73af863`.
The final Linux suite ran uninterrupted to completion with zero failures, errors
or timeouts. P3-019 and P3-020 are resolved; there are no open Phase 3 questions.

### Six-check audit

| Audit | Result | Evidence |
|---|---|---|
| a. Act remediation webhooks | PASS | Native remediation test diff `c3c8eb1..868bbf8` is empty. Endpoint setting/parser, wiring, HTTP integration, executor builder and explicit-endpoint precedence remain; native tests pass. |
| b. MCP | PASS | Every `tests_arch/*mcp*` diff in the five-commit range is empty. Independent reply-inspection tests pass; no proxy assertion was removed. |
| c. Migration history | PASS | All original migration function ASTs and entries 1–39 are identical. Historical DDL is unchanged. Only migration 40 is appended (plus its helper import; a nonfunctional trailing blank-line difference remains). All four SQLite/PostgreSQL fresh/v39-upgrade cases pass, including unchanged kept catalog/index/RLS/role snapshots. |
| d. Kept modules | PASS | Required remediation, inventory, residency, enterprise, attestation, backup/objectstore, DEVICE_STATEMENTS and OIDC principal modules are present and have empty diffs in the five-commit range. |
| e. Kept test assertions | PASS after fix | Initial audit FAIL: three shared text-extraction tests were deleted with A2A. `036c392` restores them with original assertions. The exhaustive 154-function inventory below attributes the other 151 to parked features. An expanded review also restored two private-credential throttle cases from the earlier analysis cut in `767bee6`. No kept assertion was weakened. |
| f. Removed settings | PASS | Executable scanner checks 62 names/prefixes plus `_FILE` forms; zero findings. Exactly CHANGES.md, CLEANUP_PLAN.md and docs/PARKED.md are exempted in scanner code. |

### Per-group accounting

Counts are from each commit's Git diff, including source, tests, deployment and
documentation. Files changed includes additions/deletions; LOC counts physical
text lines added/deleted, not just whole-file removals. Settings means annotated
Settings fields, not individual environment names or dynamic prefix expansions.
MCP's three added cases are attributed to extraction, even though the first
historical case-delta file also carried them under detonation.

| Group | Files changed / deleted | LOC added / deleted | Routes removed | Settings fields removed | Tables dropped | Tests removed / adapted | Commit |
|---|---:|---:|---:|---:|---:|---|---|
| MCP extraction | 9 / 0 | +403 / -45 | 0 | 0 | 0 | +3 cases; 1 new test file | `0c57dd3` |
| Detonation | 46 / 19 | +183 / -6,520 | 1 | 2 | 0 | -183 cases; 3 mixed files adapted | `b7292c1` |
| Endpoint | 22 / 8 | +91 / -2,849 | 5 | 0 | 0 | -62 cases; 1 mixed file adapted | `d75b1bd` |
| Discovery | 35 / 21 | +127 / -7,704 | 0 | 1 | 0 | -112 cases; 1 mixed file adapted | `c15703c` |
| Analysis | 43 / 19 | +80 / -7,078 | 8 | 0 | 0 | -259/+2 case IDs (2 SLO renames); 5 mixed files adapted | `c3c8eb1` |
| SOAR | 16 / 2 | +97 / -1,138 | 0 | 3 | 0 | -20 cases; 4 mixed files adapted | `2e8a36d` |
| Orgs/SCIM | 14 / 1 | +55 / -415 | 8 | 0 | 0 | -4 cases; 2 mixed files adapted | `34332da` |
| A2A | 32 / 18 | +58 / -6,994 | 3 | 4 | 0 | -154 cases; 6 feature test files deleted | `557b217` |
| Migration 40 | 11 / 0 | +207 / -96 | 0 | 0 | 8 | +4 cases; 4 existing files adapted | `16227fd` |
| Discovery/schema follow-up | 12 / 1 | +92 / -291 | 0 | 0 | 0 | 0 cases; 4 test imports adapted | `868bbf8` |
| Shared reply test repair | 1 / 0 | +31 / -0 | 0 | 0 | 0 | +3 restored cases | `036c392` |
| Reference documentation | 4 / 0 | +23 / -16 | 0 | 0 | 0 | 0 cases | `e6fc483` |
| Private credential test repair | 1 / 0 | +37 / -0 | 0 | 0 | 0 | +2 restored database cases | `767bee6` |
| Approved demo scope / migration fixtures | 5 / 0 | +108 / -35 | 0 | 0 | 0 | -1 A2A-only case; count test renamed/adapted; 2 migration functions adapted | `73af863` |

### Counts and verification limits

- Static route declarations: **78 before Phase 3 -> 53 after**; Settings fields:
  **73 -> 63**. Before means `ff627fa`, counted with the same AST method including
  conditional route declarations. This is not a claim that all routes are enabled
  simultaneously.
- Full Linux suite: **3,321 passed, 41 skipped, 0 failed, 0 errors, 0 timeouts**,
  **3,362 total**, exit **0**. It ran uninterrupted to completion with the Phase 0
  command below. JUnit time: **1,592.684 seconds**; command wall time:
  **1,600.443 seconds**. Results are saved under `baseline/phase3/pytest.log` and
  `baseline/phase3/junit.xml`; machine-readable verification and skip comparison
  are saved alongside them. Reports and raw baseline logs are not committed.
- Phase 2 was **4,101 passed / 42 skipped / 4,143 total**. Collected cases fell by
  **781**: original parking groups removed 794 case IDs and added 9 (including
  two retained SLO renames), audit fixes restored 5 cases, and approved P3-019
  removed one A2A-only negative-control case. Renaming the demo count test has no
  net effect. P3-020 changes fixtures without removing a test or kept assertion.
- Skips changed **42 -> 41**. Only the parked live detonation case,
  `tests_arch.test_detonation_tracing::test_a_live_traced_detonation_observes_a_real_payload`,
  disappeared. **No new skips and no changed reasons** among retained skips.
  All other Phase 3 groups changed the skip count by zero.
- Approved demo: **12/18 answered**, questions **1, 2, 3, 4, 14 and 18** explicitly
  out of scope, exit **0**, limitations printed. Questions 1–4 explain the parked
  delegation verifier and Phase 5 obligation. Its **11 tests pass**. Apart from
  the approved count assertion and deletion, every existing demo assertion is
  unchanged; AST comparison verifies the other ten test functions and fixture.
- Historical runs are not completion evidence: the earlier interrupted run is
  archived under `baseline/phase3/interrupted-before-p3019-approval/`; the first
  complete run after P3-019 (3,318 passed, 41 skipped, three migration-fixture
  failures) is archived under `baseline/phase3/before-migration-test-update/`.
  The final green run supersedes both; it was not interrupted.
- Focused migration/demo verification: **35 passed, 1 skipped** (SQLite does not
  implement PostgreSQL RLS). The complete suite includes real SQLite/PostgreSQL
  fresh installs and previous-head upgrades, plus unchanged kept schema/index/
  RLS/role snapshots. Independent MCP, native remediation, restored shared reply
  and credential-throttle checks also pass in the complete suite.
- Ruff passes. Import-graph regressions: **10 passed**; removed-name scanner
  regressions: **2 passed**. The graph gate passes with the same 11 documented
  external measurement/SDK/persistence exceptions, zero unexplained orphans,
  zero unresolved imports and zero stale allowances.
- actionlint **1.7.12** passes; its official release binary checksum was verified.
  Release secret scan passes with zero findings. Relative Markdown link check
  passes; removed-setting scan checks **62 names/prefixes**, including `_FILE`
  variants, with zero findings and exactly the three documented exemptions.
- **Docker build and container healthcheck remain unverified:** no Docker CLI is
  installed or on PATH in WSL. No production database or infrastructure changed.
- `docs/dr_sqlite_drill.json` was absent at entry and remains absent. Its initial
  state is preserved; no generated drill report is staged.

```sh
pytest tests_arch/ -q --timeout=120 --timeout_method=thread --durations=30 -rA --junitxml=baseline/phase3/junit.xml 2>&1 | tee baseline/phase3/pytest.log
```

The command ran in Linux/WSL with the repository virtual environment and shell
`pipefail`, so the successful tee process cannot mask a pytest failure.

### Dropped tables

Migration 40 drops exactly, in order: `user_credentials`, `user_sessions`,
`enrolment_tickets`, `webauthn_challenges`, `users`, `organizations`,
`a2a_agent_cards`, `device_discovery`. Identity/directory tables belong to retired
human-auth/SCIM/org functionality; the card table belongs to A2A, and device
inventory to endpoint discovery. No kept tenant, workload/agent identity,
remediation, policy, inventory/observation, operation, receipt, evidence,
execution-graph or transparency table is dropped. Shared `replay_nonces` remains.
There is no CASCADE; existing migrations and DEVICE_STATEMENTS remain unchanged.

### Deviations and review findings

- Directory removal landed in A2A after its last shared reader disappeared,
  rather than in the orgs commit. OIDC tenant provisioning is unchanged.
- `domain/assets.py` became a discovery orphan and was removed in `868bbf8`.
  That commit also moved the new live-schema inventory and migration callback to
  `schema_cleanup.py`, restoring historical `schema.py` unchanged and preserving
  the existing module-size guard.
- `036c392` restores three shared text-extraction tests accidentally removed with
  A2A. `767bee6` restores the rotated-address private-credential assertion from
  the earlier demo removal (two database cases); only the retired demo dependency
  is omitted. Neither repair changes production behavior.
- The existing partitioning entry was carried from the Phase 2 plan into
  PARKED.md; no live partitioning work was performed. Discovery LOC and the
  omitted exposure-reach route were corrected in that document.
- A documentation-edit shell-quoting error was corrected before review; the final
  documentation was rebuilt from its committed source using literal encoded input.
- One independent read-only review found the additional credential-test omission;
  it is fixed. No minor findings were deferred. The reviewer left full-suite and
  Docker results to the executor; the executor records both limits above.
- Full verification exposed the demo boundary in P3-019. The user explicitly
  approved the narrower demonstration before implementation: questions 1–4 are
  unverified and deferred, without fabricated answers or changes to retained
  execution/binding/evidence assertions. Phase 5 must restore those answers.
- P3-020 corrected two remaining migration-test fixtures after a complete failing
  run. No production DDL or kept assertion changed; the next complete run passed.

### Resolved P3-019: execution-trust demo contract

#### User decision — approved with conditions, 2026-11-11

The user approved this scope change before implementation:

1. Narrow `scripts/demo_execution_trust.py` to **12/18 answered, exactly six out
   of scope**: questions **1, 2, 3, 4, 14 and 18**. Questions 1–4 must plainly say
   they are NOT answered yet and explain: "the delegation chain verifier was parked with
   A2A; this will be answered from the agent registry and identity records in Phase 5
   (items 5.1 and 5.6)". Do not fabricate answers from declared fields.
2. Update the count test to expect exactly six and explicitly identify those six
   question numbers. Remove only
   `test_the_delegation_step_carries_its_own_negative_control`. Every other demo
   assertion stays unchanged. The demo must exit 0 and print its limitations.
3. Record in PARKED.md and the Phase 5 section: "Phase 5 must restore answers to demo questions 1–4 (actor, authenticated identity, delegator, granted permissions) through the agent registry and retained identity/authorization paths; oversight_demo.py (5.6) must answer them."
4. Run the entire Linux suite with the original Phase 0 verification command,
   uninterrupted to completion, saving logs/JUnit under `baseline/phase3/`.
   Require zero failed, errors and timeouts; report passed/skipped totals and
   skip changes against Phase 2. Update Phase 3 results and the readiness verdict,
   commit, push, confirm the remote SHA and stop. Do not start Phase 4.

Implemented and verified in `73af863`. The demo exits 0, prints its limitations
and labels exactly questions 1, 2, 3, 4, 14 and 18 out of scope. All 11 remaining
demo tests pass, and the complete Linux suite passes as recorded above. The
Phase 5 restoration obligation is recorded in both this plan and PARKED.md.
The original blocker and question below are historical; no decision is pending.


**Original blocker (resolved by the approved decision above):**
A2A commit `557b217` removed `_step_delegation()` from
`scripts/demo_execution_trust.py`. That step supplied answers 1–4 in the
18-question report: actor, authenticated identity, delegator and granted scope.
The report still requires 16 answers, so it emits four UNANSWERED entries,
exits 1 and never prints its final limitations. The A2A-specific negative-control
test also still expects the removed staging-to-production delegation refusal.

An isolated, uninterrupted reproduction of
`pytest tests_arch/test_demo_execution_trust.py -q -o addopts=` gives
**7 passed, 5 failed, 0 errors, 0 skipped**. The five failures are:

- `test_the_demo_exits_zero`
- `test_exactly_two_questions_are_out_of_scope`
- `test_no_question_is_left_unanswered_without_a_reason`
- `test_the_demo_states_what_it_does_not_show`
- `test_the_delegation_step_carries_its_own_negative_control`

The ordinary execution, parameter-substitution refusal, tamper detection and
independent-verifier checks still pass. No assertion or demo implementation was
changed to hide these failures. Fabricating answers from declared chain fields
would misrepresent verification; restoring the parked A2A verifier is outside
scope. Reducing the pinned answer count is an explicit demo-contract decision,
not a mechanical reference edit.

**Original question (answered by the approval above):** approve narrowing this demo to 12/18 answers with six explicitly
out-of-scope questions (the four retired step answers plus the existing two),
and remove only its A2A-specific negative-control test while preserving every
kept execution/binding/evidence assertion? Alternatively, require a replacement
demonstration through retained identity/authorization paths before changing the
promised coverage. No such redesign is performed without the user's decision.

The requested focused verification and uninterrupted full-suite rerun are now
complete. Phase 4 remains outside this task and has not started.

### Five-commit audit: deleted test-function inventory

AST comparison of `c3c8eb1..868bbf8` found 154 deleted test functions. The list below is exhaustive. Of these, 151 cover parked features; three shared reply-text functions were recovered in `036c392`, with their original assertions and the retained helper import. No kept assertion was weakened. Parametrized case counts are separate from function counts.

#### tests_arch/test_a2a_delegation.py — A2A

- `test_a_card_that_changed_after_approval_is_drift` — A2A
- `test_a_chain_deeper_than_the_limit_is_reported` — A2A
- `test_a_clean_delegation_is_allowed` — A2A
- `test_a_correctly_narrowing_chain_produces_no_amplification` — A2A
- `test_a_critical_structural_finding_refuses_regardless_of_policy` — A2A
- `test_a_grant_the_target_never_advertised_is_reported_even_when_authorised` — A2A
- `test_a_hop_cannot_grant_what_its_delegator_does_not_hold` — A2A
- `test_a_refused_delegation_does_not_burn_its_task_id` — A2A
- `test_a_replay_is_scoped_to_one_tenant` — A2A
- `test_a_scope_dropped_at_one_hop_cannot_be_regained_later` — A2A
- `test_a_scope_that_is_not_a_scope_is_refused_at_construction` — A2A
- `test_a_task_id_cannot_be_replayed` — A2A
- `test_a_wildcard_covers_one_segment_and_not_a_deeper_one` — A2A
- `test_amplification_is_projected_as_its_own_flag` — A2A
- `test_an_agent_appearing_twice_is_a_loop` — A2A
- `test_an_agent_with_no_pin_is_not_reported_as_drift` — A2A
- `test_an_unattributable_principal_is_critical` — A2A
- `test_delegating_to_an_agent_nobody_enrolled_is_critical` — A2A
- `test_effective_scopes_narrow_monotonically` — A2A
- `test_enrolment_pins_the_fingerprint` — A2A
- `test_narrowing_is_an_intersection_not_a_union` — A2A
- `test_self_delegation_is_reported_separately_and_rated_lower` — A2A
- `test_the_fingerprint_covers_capabilities_and_ignores_prose` — A2A
- `test_the_fingerprint_does_not_depend_on_key_order` — A2A
- `test_the_instruction_reaches_the_injection_detector` — A2A
- `test_the_projection_names_both_the_terminal_agent_and_the_principal` — A2A

#### tests_arch/test_a2a_malformed_hops.py — A2A

- `test_a_signed_hop_with_a_wrongly_typed_field_is_a_400` — A2A
- `test_a_signed_hop_with_an_empty_document_is_a_400_not_a_500` — A2A

#### tests_arch/test_a2a_proxy.py — A2A

- `test_a_batch_reply_is_refused` — A2A
- `test_a_benign_reply_is_returned_verbatim` — A2A
- `test_a_card_document_maps_skills_to_capabilities` — A2A
- `test_a_deeply_nested_message_does_not_recurse_forever` — shared MCP reply-text behavior; restored in `tests_arch/test_reply_text.py` (not retired)
- `test_a_moved_endpoint_is_drift` — A2A
- `test_a_refusal_travels_in_band_as_json_rpc` — A2A
- `test_a_refused_reply_is_not_returned_even_sanitised` — A2A
- `test_a_widened_card_is_caught_at_call_time` — A2A
- `test_an_injection_in_the_reply_is_refused` — A2A
- `test_an_unconfigured_deployment_has_no_route_at_all` — A2A
- `test_an_unenrolled_agent_is_refused_before_any_network_activity` — A2A
- `test_an_unenrolled_caller_holds_nothing_so_any_grant_is_amplification` — A2A
- `test_an_unfetchable_card_refuses_rather_than_skipping_the_check` — A2A
- `test_an_unknown_method_is_refused_rather_than_passed_through` — A2A
- `test_privilege_amplification_is_refused_upstream_of_the_network` — A2A
- `test_streaming_is_refused_by_name_with_a_reason` — A2A
- `test_text_extraction_is_bounded` — shared MCP reply-text behavior; restored in `tests_arch/test_reply_text.py` (not retired)
- `test_text_parts_extracts_prose_and_ignores_binary` — shared MCP reply-text behavior; restored in `tests_arch/test_reply_text.py` (not retired)
- `test_the_caller_cannot_widen_its_own_authority_with_a_header` — A2A
- `test_the_card_fingerprint_ignores_the_description` — A2A
- `test_the_forwardable_set_is_small_and_explicit` — A2A
- `test_the_message_goes_to_the_enrolled_endpoint_and_nowhere_else` — A2A
- `test_there_is_no_url_parameter_to_aim_this_process_with` — A2A

#### tests_arch/test_a2a_registry.py — A2A

- `test_a_card_enrolled_on_one_replica_is_visible_to_another` — A2A
- `test_a_card_survives_a_round_trip_with_its_capabilities_intact` — A2A
- `test_a_replayed_task_is_caught_by_a_different_replica` — A2A
- `test_a_task_id_is_namespaced_so_it_cannot_collide_with_an_event_digest` — A2A
- `test_cards_do_not_cross_a_tenant_boundary` — A2A
- `test_drift_is_detectable_because_the_pin_outlives_the_process` — A2A
- `test_enrolment_pins_the_fingerprint_in_the_same_write` — A2A
- `test_one_unparseable_row_does_not_blind_the_rest` — A2A
- `test_re_enrolment_re_pins_and_that_is_the_point` — A2A
- `test_recording_nothing_touches_no_connection` — A2A
- `test_recording_the_same_task_twice_is_not_an_error` — A2A
- `test_task_ids_do_not_cross_a_tenant_boundary` — A2A

#### tests_arch/test_console_bundle.py — orgs/SCIM

- `test_a_404_on_the_organisation_is_shown_as_a_state_not_a_failure` — orgs/SCIM

#### tests_arch/test_delegation_constraints.py — A2A

- `test_a_chain_from_another_tenant_is_critical` — A2A
- `test_a_constraint_without_a_clock_is_refused_rather_than_guessed` — A2A
- `test_a_cross_tenant_chain_is_refused_structurally_whatever_policy_says` — A2A
- `test_a_delegation_issued_in_the_future_is_refused` — A2A
- `test_a_delegation_that_expires_before_it_is_issued_cannot_be_constructed` — A2A
- `test_a_delegation_with_no_expiry_is_reported_but_not_treated_as_worst` — A2A
- `test_a_dev_delegation_presented_against_production_is_escalation` — A2A
- `test_a_fully_constrained_valid_delegation_reports_nothing` — A2A
- `test_a_missing_purpose_is_reported_at_the_lowest_severity` — A2A
- `test_a_normal_lifetime_is_not_reported` — A2A
- `test_a_permitted_resource_passes` — A2A
- `test_a_production_delegation_used_in_dev_is_not_escalation` — A2A
- `test_a_resource_outside_the_permitted_pattern_is_reported` — A2A
- `test_a_very_long_lifetime_is_reported_as_a_standing_credential` — A2A
- `test_an_environment_escalation_is_refused_structurally` — A2A
- `test_an_expired_delegation_is_reported` — A2A
- `test_an_expired_delegation_is_reported_but_left_to_policy` — A2A
- `test_an_unknown_environment_ranks_above_production` — A2A
- `test_constraints_reach_policy_under_their_own_key` — A2A
- `test_environment_names_are_matched_case_and_space_insensitively` — A2A
- `test_every_kind_has_a_severity` — A2A
- `test_every_violation_is_reported_not_only_the_first` — A2A
- `test_findings_serialise_for_evidence` — A2A
- `test_matching_is_by_pattern_not_by_string_prefix` — A2A
- `test_no_constraint_means_the_old_behaviour_is_unchanged` — A2A
- `test_no_declared_resources_means_the_check_does_not_apply` — A2A
- `test_require_allowed_forwards_every_argument_it_accepts` — A2A
- `test_the_clock_is_passed_in_and_never_read` — A2A

#### tests_arch/test_delegation_passport.py — A2A

- `test_a_chain_deeper_than_permitted_is_refused` — A2A
- `test_a_chain_not_rooted_at_the_expected_principal_is_refused` — A2A
- `test_a_cross_tenant_hop_is_refused` — A2A
- `test_a_dropped_middle_hop_is_refused` — A2A
- `test_a_hop_escalating_the_environment_is_refused` — A2A
- `test_a_hop_granting_a_capability_its_issuer_lacked_is_refused` — A2A
- `test_a_hop_outliving_its_issuer_is_refused` — A2A
- `test_a_hop_signed_by_the_wrong_party_is_refused` — A2A
- `test_a_hop_whose_issuer_was_not_the_previous_subject_is_refused` — A2A
- `test_a_hop_widening_the_resource_scope_is_refused` — A2A
- `test_a_key_id_is_namespaced_by_its_issuer` — A2A
- `test_a_key_signing_outside_its_window_is_refused` — A2A
- `test_a_key_whose_owner_merely_begins_with_the_issuer_is_refused` — A2A
- `test_a_lookalike_scope_is_not_treated_as_narrower` — A2A
- `test_a_loop_is_refused` — A2A
- `test_a_prohibited_capability_cannot_be_granted_downstream` — A2A
- `test_a_prohibition_survives_hops_that_held_the_capability` — A2A
- `test_a_refused_chain_grants_no_capabilities` — A2A
- `test_a_reordered_chain_is_refused` — A2A
- `test_a_self_hop_is_refused_at_construction` — A2A
- `test_a_single_hop_chain_is_sound` — A2A
- `test_a_sound_chain_establishes_authority` — A2A
- `test_an_agent_presenting_somebody_elses_chain_is_refused` — A2A
- `test_an_altered_hop_fails_its_signature` — A2A
- `test_an_empty_chain_grants_nothing` — A2A
- `test_an_empty_key_id_is_refused_as_nobodys` — A2A
- `test_an_expired_hop_is_refused` — A2A
- `test_an_issuer_name_containing_the_separator_is_refused` — A2A
- `test_an_omitted_presenter_leaves_the_holder_unchecked` — A2A
- `test_an_unknown_key_is_not_a_valid_key` — A2A
- `test_clock_skew_within_tolerance_is_permitted` — A2A
- `test_established_is_derived_and_cannot_be_set` — A2A
- `test_every_defect_is_reported_not_just_the_first` — A2A
- `test_key_owner_parses_issuer_hash_version_exactly` — A2A
- `test_no_defect_member_is_falsy_and_all_explain_themselves` — A2A
- `test_permitting_and_prohibiting_the_same_capability_is_refused` — A2A
- `test_signing_a_hop_for_another_issuer_is_refused_at_source` — A2A
- `test_the_chain_digest_covers_the_signatures` — A2A
- `test_the_two_environment_tables_agree` — A2A
- `test_two_different_chains_have_different_digests` — A2A

#### tests_arch/test_gap_closures.py — orgs/SCIM

- `test_org_create_and_members` — orgs/SCIM
- `test_scim_pagination_bounds_do_not_overflow_the_database` — orgs/SCIM
- `test_scim_user_lifecycle_tenant_bound` — orgs/SCIM

#### tests_arch/test_outbound_chaos.py — SOAR

- `test_a_hanging_soar_connector_does_not_raise_into_the_caller` — SOAR
- `test_a_total_soar_outage_is_reported_rather_than_silent` — SOAR
- `test_one_hanging_connector_does_not_stop_the_rest` — SOAR

#### tests_arch/test_phase4_wiring.py — SOAR

- `test_a_soar_connector_failure_cannot_fail_the_admission_that_produced_it` — SOAR
- `test_configured_connectors_are_subscribed_to_incident_admission` — SOAR
- `test_low_priority_incidents_are_not_dispatched` — SOAR
- `test_without_endpoints_no_soar_dispatcher_is_built` — SOAR

#### tests_arch/test_remediation_execution.py — SOAR

- `test_a_broadcast_mention_in_incident_text_cannot_page_the_channel` — SOAR
- `test_a_malformed_severity_does_not_raise_inside_the_notification_path` — SOAR
- `test_a_newline_cannot_forge_a_ticket_field` — SOAR
- `test_ampersand_is_escaped_before_the_angle_brackets` — SOAR
- `test_an_approval_request_reaches_a_chat_channel_with_its_deadline` — SOAR
- `test_an_approval_target_cannot_page_the_channel` — SOAR
- `test_an_approval_with_no_expiry_says_so_rather_than_showing_a_blank` — SOAR
- `test_an_oversized_field_is_clipped_rather_than_failing_the_notification` — SOAR
- `test_low_severity_incidents_do_not_open_tickets_by_default` — SOAR
- `test_markup_in_incident_text_cannot_reformat_the_message` — SOAR
- `test_one_failing_connector_does_not_stop_the_others` — SOAR
- `test_partial_delivery_is_logged_rather_than_silent` — SOAR


## Phase 4 decisions

Phase 4 is the last cleanup phase. The user's 2026-11-12 instructions are the
binding execution specification: tighten the existing core, add no features,
perform no Phase 5 work, never commit to main, and stop at Checkpoint 2.

### P4-001 — starting state, workspace and execution order

Ruling: work in the existing `/home/lenovo2/sentinel` checkout on
`cleanup/oversight-core`, as explicitly requested. Before any change, the worktree
was clean and both HEAD and the remote branch were
`142025ca106f808c303de5283ecfecb2ac3349cf`. No AGENTS.md applies. Preserve the
completed Phase 3 results as history. Execute settings, routes, invariant audit,
README/clean-install verification, Docker check, measurements, full suite and
final records in that order. Record every further decision here before acting.
The current user specification supersedes historical "Phase 4 unauthorized"
checkpoint text elsewhere in this plan. No Phase 5 implementation is authorized.

### P4-002 — Docker gate

`docker version` failed in WSL because the executable is absent. Record
**Docker: UNVERIFIED (not installed in WSL)**. Continue all other authorized work;
**Ready for Checkpoint 2: no** while Docker remains unverified. Do not install a
container runtime or claim a container build/healthcheck was performed.

### P4-003 — audit and preservation boundaries

Ruling: a settings reader must be executable kept code or an operational script,
not a declaration, parser, test, or historical comment. Trace nested settings and
raw-environment consumers as well as Settings fields, including `_FILE` forms.
Keep all specified security, residency, retention, remediation, attestation,
database and backup/WAL controls. Document read-but-undocumented settings without
changing defaults. Only proven unused settings/routes may be removed; a default
change that alters kept behavior requires the user's decision first.

Keep the route-authorization fitness test unchanged. Invariant checks do not
modify production code unless a check fails. Preserve all kept assertions and
record any historical approved test edits. Keep raw evidence only under ignored
`baseline/phase4/`; do not commit reports or baseline logs. The main working
checkout remains the explicit branch above; clean-checkout verification uses a
separate temporary local clone and must not touch production resources.

### P4-004 — measurement and verification contract

Use one reproducible measurement implementation on `archive/pre-cleanup`
(`d63463c`) and the final tracked tree. Count physical text lines, binary bytes,
AST declarations and real constructed routes separately; do not treat static
route counts as enabled routes. Record explicit app configurations and collection
commands, and count real pytest cases. Full verification uses the user's original
Phase 0 command uninterrupted, with pipefail, saving output under
`baseline/phase4/`. Preserve the initial absent state of
`docs/dr_sqlite_drill.json`. No merge, PR, deployment or Phase 5 work is performed.

### Phase 4 execution ledger

- Preflight complete: clean local/remote starting commit confirmed; Docker absent.
- Settings complete: `aecd2a3`; 66 passed, 1 skipped; unchanged retained defaults.
- Routes complete: optional UIs removed, schema authenticated; 125 focused tests passed.
- Invariants complete: SDK/decision probes pass; historical test edits and all skip reasons recorded.
- README complete: clean-clone install/migrate/start/health verified; 4 citation tests pass.
- Final full suite complete: 3,321 passed, 41 skipped, 0 failed/errors/timeouts; skip IDs/reasons unchanged.
- Archive/final measurements and result records complete; final committed-tree verification is required before push.
- Docker unavailable; Ready for Checkpoint 2: no.


### P4-005 — settings removal and documentation decision

Ruling before implementation: remove the unused `log_level` field and
`SENTINEL_LOG_LEVEL` parser/compose entry. No logger, ASGI entrypoint, script or
security control consumes the field; StructuredLogger construction ignores it.
Its parsed INFO value never selected runtime behavior. No kept default changes.
There is no field-specific validation or supported `_FILE` parser to remove.

Also remove two ignored benchmark environment entries,
`SENTINEL_ADDRESS_LIMIT_PER_MINUTE` and
`SENTINEL_CREDENTIAL_LIMIT_PER_MINUTE`, and their misleading bypass comment.
They never affected Settings, so the benchmark's effective limiter defaults stay
unchanged. Remove the unsupported `SENTINEL_REQUIRE_LIVE` claim from SECURITY.md;
no kept harness reads it. Record all four names in PARKED.md's removal catalog.
Do not replace the misspelled benchmark names with working controls: that would
change behavior beyond this cleanup decision.

Retain `region` / `SENTINEL_REGION` exactly as instructed, despite no runtime
consumer of Settings.region. Record this limitation; do not invent residency
wiring. Keep historical invalid spelling examples and their regression guards
(they are not supported settings), shell variables used in documented commands,
and live infrastructure selectors. A family that refuses unsupported SIEM
transports is a kept validation control, not an unused integration.

Add a full configuration reference covering every kept field and every active
name, including dynamic secret families and operational inputs. Correct stale
configuration comments without changing assignments or defaults. Existing tests
are preserved; the source of truth for the inventories is the Phase 4 start
commit, and line references below refer to that audited tree. Historical parked
names in PARKED.md describe previous removals, not active configuration.

#### Settings field decisions (Phase 4 input: 63 fields)

| Field | Kept reader (file:line) | Decision |
|---|---|---|
| `environment` | sentinel/interface/asgi.py:123 | KEEP: active reader |
| `engine` | sentinel/composition/container.py:317; sentinel/composition/platform_wiring.py:143 | KEEP: active reader |
| `api_keys` | sentinel/interface/health_routes.py:120; sentinel/interface/health_routes.py:148 | KEEP: active reader |
| `cors_origins` | sentinel/interface/http.py:185; sentinel/interface/http.py:188 | KEEP: active reader |
| `worker_shard` | sentinel/interface/asgi.py:125; sentinel/interface/http.py:166 | KEEP: active reader |
| `worker_shard_count` | sentinel/composition/container.py:343; sentinel/interface/asgi.py:126 | KEEP: active reader |
| `worker_poll_seconds` | sentinel/interface/worker.py:76 | KEEP: active reader |
| `queue_max_attempts` | sentinel/composition/container.py:344 | KEEP: active reader |
| `queue_lease_seconds` | sentinel/composition/container.py:345; sentinel/interface/worker.py:376 | KEEP: active reader |
| `outbox_batch_size` | sentinel/composition/container.py:635 | KEEP: active reader |
| `outbox_lease_seconds` | sentinel/composition/container.py:636 | KEEP: active reader |
| `retention_days` | sentinel/interface/worker.py:512 | KEEP: active reader |
| `retention_interval_seconds` | sentinel/interface/worker.py:504 | KEEP: active reader |
| `incident_retention_days` | sentinel/interface/worker.py:542 | KEEP: active reader |
| `attestation_endpoint` | sentinel/composition/adapters.py:116; sentinel/composition/adapters.py:118 | KEEP: active reader |
| `attestation_token` | sentinel/composition/adapters.py:118 | KEEP: active reader |
| `tenant_siem_sinks` | sentinel/composition/siem_wiring.py:68; sentinel/composition/siem_wiring.py:76 | KEEP: active reader |
| `tenant_siem_credentials` | sentinel/composition/siem_wiring.py:96; sentinel/composition/siem_wiring.py:114 | KEEP: active reader |
| `siem_webhook_url` | sentinel/composition/siem_wiring.py:128; sentinel/composition/siem_wiring.py:131 | KEEP: active reader |
| `siem_webhook_token` | sentinel/composition/siem_wiring.py:132 | KEEP: active reader |
| `replay_window_seconds` | sentinel/composition/container.py:350 | KEEP: active reader |
| `log_level` | none | REMOVE: no kept reader |
| `expose_api_docs` | sentinel/interface/http.py:103 | KEEP: active reader |
| `rate_limit_fail_open` | sentinel/composition/adapters.py:88 | KEEP: active reader |
| `require_execution_binding` | sentinel/composition/container.py:415; sentinel/interface/extra_routes.py:129 | KEEP: active reader |
| `trusted_proxy_hops` | sentinel/interface/http.py:133 | KEEP: active reader |
| `auth_failure_limit_per_minute` | sentinel/composition/adapters.py:70; sentinel/interface/http.py:134 | KEEP: active reader |
| `credential_limit_per_minute` | sentinel/composition/adapters.py:71; sentinel/interface/http.py:135 | KEEP: active reader |
| `address_limit_per_minute` | sentinel/composition/adapters.py:72; sentinel/interface/http.py:136 | KEEP: active reader |
| `redis_url` | sentinel/composition/adapters.py:74; sentinel/composition/adapters.py:75 | KEEP: active reader |
| `protection_mode` | sentinel/interface/health_routes.py:165; sentinel/interface/health_routes.py:166 | KEEP: active reader |
| `region` | none | KEEP: explicitly protected residency setting; parsed/validated only |
| `protect_enforcement` | sentinel/composition/container.py:376; sentinel/composition/container.py:467 | KEEP: active reader |
| `protect_kill_switch` | sentinel/composition/container.py:386; sentinel/interface/authorizations.py:231 | KEEP: active reader |
| `remediation_endpoints` | sentinel/composition/container.py:508; sentinel/composition/container.py:511 | KEEP: active reader |
| `remediation_dry_run` | sentinel/composition/container.py:512; sentinel/composition/remediation_wiring.py:91 | KEEP: active reader |
| `mcp_require_pin` | sentinel/composition/container.py:518 | KEEP: active reader |
| `mcp_proxy_enabled` | sentinel/composition/proxy_wiring.py:25 | KEEP: active reader |
| `mcp_proxy_allowed_hosts` | sentinel/composition/proxy_wiring.py:30; sentinel/interface/mcp_proxy_routes.py:266 | KEEP: active reader |
| `mcp_proxy_allow_private` | sentinel/composition/proxy_wiring.py:31 | KEEP: active reader |
| `mcp_proxy_require_token_audience` | sentinel/interface/mcp_proxy_routes.py:276 | KEEP: active reader |
| `mcp_proxy_definition_cache_seconds` | sentinel/interface/mcp_proxy_routes.py:399; scripts/run_mcp_proxy_bench.py:192 | KEEP: active reader |
| `agent_require_grant` | sentinel/composition/container.py:468; sentinel/composition/container.py:473 | KEEP: active reader |
| `tool_file_root` | sentinel/composition/container.py:436 | KEEP: active reader |
| `tool_http_allowed_hosts` | sentinel/composition/container.py:437 | KEEP: active reader |
| `platform_adapters` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: active reader |
| `siem_transports` | sentinel/composition/siem_wiring.py:135 | KEEP: active reader |
| `tool_budget_per_minute` | sentinel/composition/container.py:387 | KEEP: active reader |
| `protect_circuit_threshold` | sentinel/composition/container.py:388 | KEEP: active reader |
| `operation_pending_deadline_seconds` | sentinel/interface/worker.py:432 | KEEP: active reader |
| `bypass_idle_seconds` | sentinel/interface/extra_routes.py:200; sentinel/interface/extra_routes.py:203 | KEEP: active reader |
| `ready_exposes_detection_mode` | sentinel/interface/health_routes.py:123 | KEEP: active reader |
| `oidc_issuer` | sentinel/composition/container.py:539 | KEEP: active reader |
| `oidc_audience` | sentinel/composition/container.py:540 | KEEP: active reader |
| `oidc_jwks_json` | sentinel/composition/container.py:541 | KEEP: active reader |
| `oidc_tenant_claim` | sentinel/composition/container.py:542 | KEEP: active reader |
| `oidc_role_claim` | sentinel/composition/container.py:543 | KEEP: active reader |
| `metrics_token` | sentinel/interface/http.py:704 | KEEP: active reader |
| `otlp_endpoint` | sentinel/composition/container.py:534 | KEEP: active reader |
| `agent_idp_json` | sentinel/composition/container.py:550; sentinel/composition/container.py:552 | KEEP: active reader |
| `root_sink` | sentinel/composition/root_sink_wiring.py:20; sentinel/composition/root_sink_wiring.py:27 | KEEP: active reader |
| `workflow` | sentinel/composition/container.py:699; sentinel/composition/evidence_wiring.py:17 | KEEP: active reader |
| `advisor` | sentinel/composition/advisor_wiring.py:14 | KEEP: active reader |

#### Environment-name decisions

Includes the union of names in .env.example, Helm, compose and active docs, plus
service/parser and operational names needed to make the full reference complete.
A parser-to-aggregate-to-consumer chain counts only when the consumer is kept.

| Name | Kept reader (file:line) or none | Decision |
|---|---|---|
| `SENTINEL_ACTIVE_KEY_ID` | sentinel/composition/evidence_wiring.py:17 | KEEP: workflow |
| `SENTINEL_ADDRESS_LIMIT` | sentinel/composition/adapters.py:72; sentinel/interface/http.py:136 | KEEP: address_limit_per_minute |
| `SENTINEL_ADDRESS_LIMIT_PER_MINUTE` | none | REMOVE: ignored benchmark inputs; preserve current effective defaults |
| `SENTINEL_ADVISOR_CLI_COMMAND` | sentinel/composition/advisor_wiring.py:14 | KEEP: advisor |
| `SENTINEL_ADVISOR_CLI_HOME` | sentinel/composition/advisor_wiring.py:14 | KEEP: advisor |
| `SENTINEL_ADVISOR_ENDPOINT` | sentinel/composition/advisor_wiring.py:14 | KEEP: advisor |
| `SENTINEL_ADVISOR_MODEL` | sentinel/composition/advisor_wiring.py:14 | KEEP: advisor |
| `SENTINEL_ADVISOR_TOKEN` | sentinel/composition/advisor_wiring.py:14 | KEEP: advisor |
| `SENTINEL_AGENT_ID` | sentinel/sdk/mcp_stdio.py:288; sentinel/sdk/mcp_stdio.py:330 | KEEP: CLI/operational input |
| `SENTINEL_AGENT_IDP_JSON` | sentinel/composition/container.py:550; sentinel/composition/container.py:552 | KEEP: agent_idp_json |
| `SENTINEL_AGENT_REQUIRE_GRANT` | sentinel/composition/container.py:468; sentinel/composition/container.py:473 | KEEP: agent_require_grant |
| `SENTINEL_API_KEY` | sentinel/sdk/mcp_stdio.py:292 | KEEP: CLI/operational input |
| `SENTINEL_API_KEYS` | sentinel/interface/health_routes.py:120; sentinel/interface/health_routes.py:148 | KEEP: api_keys |
| `SENTINEL_APPROVAL_QUORUM` | sentinel/interface/authorizations.py:395 | KEEP: workflow |
| `SENTINEL_APPROVAL_SEPARATION_OF_DUTIES` | sentinel/interface/authorizations.py:294 | KEEP: workflow |
| `SENTINEL_ATTESTATION_ENDPOINT` | sentinel/composition/adapters.py:116; sentinel/composition/adapters.py:118 | KEEP: attestation_endpoint |
| `SENTINEL_ATTESTATION_TOKEN` | sentinel/composition/adapters.py:118 | KEEP: attestation_token |
| `SENTINEL_AUTH_FAILURE_LIMIT` | sentinel/composition/adapters.py:70; sentinel/interface/http.py:134 | KEEP: auth_failure_limit_per_minute |
| `SENTINEL_AWS_ACCESS_KEY_ID` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: platform_adapters |
| `SENTINEL_AWS_CEILING` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: platform_adapters |
| `SENTINEL_AWS_EXECUTOR_ROLE_ARN` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: platform_adapters |
| `SENTINEL_AWS_REGION` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: platform_adapters |
| `SENTINEL_AWS_SECRET_ACCESS_KEY` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: platform_adapters |
| `SENTINEL_AWS_SECRET_ACCESS_KEY_FILE` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: platform_adapters |
| `SENTINEL_AWS_SESSION_TOKEN` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: platform_adapters |
| `SENTINEL_AWS_SESSION_TOKEN_FILE` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: platform_adapters |
| `SENTINEL_BOOTSTRAP_TENANT` | scripts/quickstart.py:225 | KEEP: CLI/operational input |
| `SENTINEL_BYPASS_IDLE_SECONDS` | sentinel/interface/extra_routes.py:200; sentinel/interface/extra_routes.py:203 | KEEP: bypass_idle_seconds |
| `SENTINEL_CORS_ORIGINS` | sentinel/interface/http.py:185; sentinel/interface/http.py:188 | KEEP: cors_origins |
| `SENTINEL_CREDENTIAL_LIMIT` | sentinel/composition/adapters.py:71; sentinel/interface/http.py:135 | KEEP: credential_limit_per_minute |
| `SENTINEL_CREDENTIAL_LIMIT_PER_MINUTE` | none | REMOVE: ignored benchmark inputs; preserve current effective defaults |
| `SENTINEL_DATABASE_URL` | sentinel/composition/container.py:317; sentinel/composition/platform_wiring.py:143 | KEEP: engine |
| `SENTINEL_DATA_KEY_` | sentinel/composition/evidence_wiring.py:17 | KEEP: workflow |
| `SENTINEL_DATA_KEY_K1` | sentinel/composition/evidence_wiring.py:17 | KEEP: evidence key family |
| `SENTINEL_DB_PATH` | sentinel/composition/container.py:317; sentinel/composition/platform_wiring.py:143 | KEEP: engine |
| `SENTINEL_DB_POOL_MAX` | sentinel/composition/container.py:317; sentinel/composition/platform_wiring.py:143 | KEEP: engine |
| `SENTINEL_DB_POOL_MIN` | sentinel/composition/container.py:317; sentinel/composition/platform_wiring.py:143 | KEEP: engine |
| `SENTINEL_ENV` | sentinel/interface/asgi.py:123; sentinel/composition/container.py:317; sentinel/composition/platform_wiring.py:143; sentinel/interface/health_routes.py:120; sentinel/interface/health_routes.py:148; sentinel/composition/container.py:699; sentinel/composition/evidence_wiring.py:17 | KEEP: environment, engine, api_keys, workflow |
| `SENTINEL_EVIDENCE_ENCRYPTION` | sentinel/composition/evidence_wiring.py:17 | KEEP: workflow |
| `SENTINEL_EXPOSE_API_DOCS` | sentinel/interface/http.py:103 | KEEP: expose_api_docs |
| `SENTINEL_GITHUB_API_HOST` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: platform_adapters |
| `SENTINEL_GITHUB_APP_ID` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: platform_adapters |
| `SENTINEL_GITHUB_APP_PRIVATE_KEY` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: platform_adapters |
| `SENTINEL_GITHUB_APP_PRIVATE_KEY_FILE` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: platform_adapters |
| `SENTINEL_GITHUB_CEILING` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: platform_adapters |
| `SENTINEL_GITHUB_INSTALLATION_ID` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: platform_adapters |
| `SENTINEL_GITHUB_TOKEN` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: platform_adapters |
| `SENTINEL_GITHUB_TOKEN_FILE` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: platform_adapters |
| `SENTINEL_HELM_VALUES` | docs/OPERATIONS.md:126 | KEEP: shell variable passed to Helm, not a service setting |
| `SENTINEL_INCIDENT_RETENTION_DAYS` | sentinel/interface/worker.py:542 | KEEP: incident_retention_days |
| `SENTINEL_INGEST_KEY` | docs/INTEGRATIONS.md:876 | KEEP: curl token placeholder, not a service setting |
| `SENTINEL_KUBERNETES_API_SERVER` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: platform_adapters |
| `SENTINEL_KUBERNETES_CA_FILE` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: platform_adapters |
| `SENTINEL_KUBERNETES_CEILING` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: platform_adapters |
| `SENTINEL_KUBERNETES_EXECUTOR_NAMESPACE` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: platform_adapters |
| `SENTINEL_KUBERNETES_EXECUTOR_SERVICE_ACCOUNT` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: platform_adapters |
| `SENTINEL_KUBERNETES_TOKEN` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: platform_adapters |
| `SENTINEL_KUBERNETES_TOKEN_AUDIENCE` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: platform_adapters |
| `SENTINEL_KUBERNETES_TOKEN_FILE` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: platform_adapters |
| `SENTINEL_KUBERNETES_TOKEN_TTL_SECONDS` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: platform_adapters |
| `SENTINEL_LOG_LEVEL` | none | REMOVE: no kept reader |
| `SENTINEL_MCP_PROXY_ALLOWED_HOSTS` | sentinel/composition/proxy_wiring.py:30; sentinel/interface/mcp_proxy_routes.py:266 | KEEP: mcp_proxy_allowed_hosts |
| `SENTINEL_MCP_PROXY_ALLOW_PRIVATE` | sentinel/composition/proxy_wiring.py:31 | KEEP: mcp_proxy_allow_private |
| `SENTINEL_MCP_PROXY_DEFINITION_CACHE_SECONDS` | sentinel/interface/mcp_proxy_routes.py:399; scripts/run_mcp_proxy_bench.py:192 | KEEP: mcp_proxy_definition_cache_seconds |
| `SENTINEL_MCP_PROXY_ENABLED` | sentinel/composition/proxy_wiring.py:25 | KEEP: mcp_proxy_enabled |
| `SENTINEL_MCP_PROXY_REQUIRE_TOKEN_AUDIENCE` | sentinel/interface/mcp_proxy_routes.py:276 | KEEP: mcp_proxy_require_token_audience |
| `SENTINEL_MCP_PROXY_STREAMING` | sentinel/interface/mcp_proxy_routes.py:159 | KEEP: workflow |
| `SENTINEL_MCP_REQUIRE_PIN` | sentinel/composition/container.py:518 | KEEP: mcp_require_pin |
| `SENTINEL_METRICS_TOKEN` | sentinel/interface/http.py:704 | KEEP: metrics_token |
| `SENTINEL_METRICS_TOKEN_FILE` | sentinel/interface/http.py:704 | KEEP: metrics_token |
| `SENTINEL_MODE` | none | KEEP: historical rejected spelling and regression guard; no setting |
| `SENTINEL_OIDC_AUDIENCE` | sentinel/composition/container.py:540 | KEEP: oidc_audience |
| `SENTINEL_OIDC_ISSUER` | sentinel/composition/container.py:539 | KEEP: oidc_issuer |
| `SENTINEL_OIDC_JWKS_JSON` | sentinel/composition/container.py:541 | KEEP: oidc_jwks_json |
| `SENTINEL_OIDC_ROLE_CLAIM` | sentinel/composition/container.py:543 | KEEP: oidc_role_claim |
| `SENTINEL_OIDC_TENANT_CLAIM` | sentinel/composition/container.py:542 | KEEP: oidc_tenant_claim |
| `SENTINEL_OPERATION_PENDING_DEADLINE_SECONDS` | sentinel/interface/worker.py:432 | KEEP: operation_pending_deadline_seconds |
| `SENTINEL_OTLP_ENDPOINT` | sentinel/composition/container.py:534 | KEEP: otlp_endpoint |
| `SENTINEL_OUTBOX_BATCH` | sentinel/composition/container.py:635 | KEEP: outbox_batch_size |
| `SENTINEL_OUTBOX_LEASE_SECONDS` | sentinel/composition/container.py:636 | KEEP: outbox_lease_seconds |
| `SENTINEL_PIPELINE_WORKERS` | sentinel/interface/asgi.py:57 | KEEP: process topology/worker control |
| `SENTINEL_POSTGRES_CEILING` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: platform_adapters |
| `SENTINEL_POSTGRES_DSN` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: platform_adapters |
| `SENTINEL_POSTGRES_DSN_FILE` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: platform_adapters |
| `SENTINEL_POSTGRES_STATEMENT_TIMEOUT_MS` | sentinel/composition/platform_wiring.py:103; sentinel/composition/platform_wiring.py:213 | KEEP: platform_adapters |
| `SENTINEL_PROTECTION_MODE` | sentinel/interface/health_routes.py:165; sentinel/interface/health_routes.py:166 | KEEP: protection_mode |
| `SENTINEL_PROTECT_CIRCUIT_THRESHOLD` | sentinel/composition/container.py:388 | KEEP: protect_circuit_threshold |
| `SENTINEL_PROTECT_ENFORCE` | sentinel/interface/health_routes.py:165; sentinel/interface/health_routes.py:166; sentinel/composition/container.py:376; sentinel/composition/container.py:467 | KEEP: protection_mode, protect_enforcement |
| `SENTINEL_PROTECT_KILL_SWITCH` | sentinel/composition/container.py:386; sentinel/interface/authorizations.py:231 | KEEP: protect_kill_switch |
| `SENTINEL_PUBLISH_TENANTS` | scripts/publish_transparency_root.py:151; scripts/publish_transparency_root.py:146 | KEEP: CLI/operational input |
| `SENTINEL_QUEUE_LEASE_SECONDS` | sentinel/composition/container.py:345; sentinel/interface/worker.py:376 | KEEP: queue_lease_seconds |
| `SENTINEL_QUEUE_MAX_ATTEMPTS` | sentinel/composition/container.py:344 | KEEP: queue_max_attempts |
| `SENTINEL_RATE_LIMIT_FAIL_OPEN` | sentinel/composition/adapters.py:88 | KEEP: rate_limit_fail_open |
| `SENTINEL_READY_EXPOSE_DETECTION_MODE` | sentinel/interface/health_routes.py:123 | KEEP: ready_exposes_detection_mode |
| `SENTINEL_RECONCILE_MAX_ATTEMPTS` | sentinel/composition/container.py:699 | KEEP: workflow |
| `SENTINEL_REDIS_URL` | sentinel/composition/adapters.py:74; sentinel/composition/adapters.py:75 | KEEP: redis_url |
| `SENTINEL_REGION` | none | KEEP: explicit user preservation; parsed/validated, no runtime consumer |
| `SENTINEL_REMEDIATION_DRY_RUN` | sentinel/composition/container.py:512; sentinel/composition/remediation_wiring.py:91 | KEEP: remediation_dry_run |
| `SENTINEL_REMEDIATION_ENDPOINTS` | sentinel/composition/container.py:508; sentinel/composition/container.py:511 | KEEP: remediation_endpoints |
| `SENTINEL_REPLAY_WINDOW` | sentinel/composition/container.py:350 | KEEP: replay_window_seconds |
| `SENTINEL_REQUIRE_EXECUTION_BINDING` | sentinel/composition/container.py:415; sentinel/interface/extra_routes.py:129 | KEEP: require_execution_binding |
| `SENTINEL_REQUIRE_LIVE` | none | REMOVE: unsupported documentation claim |
| `SENTINEL_REQUIRE_WORKLOAD_IDENTITY` | sentinel/interface/principals.py:210 | KEEP: workflow |
| `SENTINEL_RETENTION_DAYS` | sentinel/interface/worker.py:512 | KEEP: retention_days |
| `SENTINEL_RETENTION_INTERVAL` | sentinel/interface/worker.py:504 | KEEP: retention_interval_seconds |
| `SENTINEL_ROOT_PUBLISH_INTERVAL_SECONDS` | sentinel/interface/worker.py:330 | KEEP: root_sink |
| `SENTINEL_ROOT_PUBLISH_TENANTS` | sentinel/interface/worker.py:327 | KEEP: root_sink |
| `SENTINEL_S3_ROOT_` | sentinel/composition/root_sink_wiring.py:27 | KEEP: documented family prefix |
| `SENTINEL_S3_ROOT_ACCESS_KEY_ID` | sentinel/composition/root_sink_wiring.py:20; sentinel/composition/root_sink_wiring.py:27 | KEEP: root_sink |
| `SENTINEL_S3_ROOT_BUCKET` | sentinel/composition/root_sink_wiring.py:20; sentinel/composition/root_sink_wiring.py:27 | KEEP: root_sink |
| `SENTINEL_S3_ROOT_REGION` | sentinel/composition/root_sink_wiring.py:20; sentinel/composition/root_sink_wiring.py:27 | KEEP: root_sink |
| `SENTINEL_S3_ROOT_RETENTION_DAYS` | sentinel/composition/root_sink_wiring.py:20; sentinel/composition/root_sink_wiring.py:27 | KEEP: root_sink |
| `SENTINEL_S3_ROOT_SECRET_ACCESS_KEY` | sentinel/composition/root_sink_wiring.py:20; sentinel/composition/root_sink_wiring.py:27 | KEEP: root_sink |
| `SENTINEL_S3_ROOT_SESSION_TOKEN` | sentinel/composition/root_sink_wiring.py:20; sentinel/composition/root_sink_wiring.py:27 | KEEP: root_sink |
| `SENTINEL_SIEM_KAFKA_` | sentinel/composition/settings_parsers.py:272 | KEEP: security refusal for unsupported transport; no Kafka integration |
| `SENTINEL_SIEM_OTLP_SERVICE_NAME` | sentinel/composition/siem_wiring.py:135 | KEEP: siem_transports |
| `SENTINEL_SIEM_OTLP_TOKEN` | sentinel/composition/siem_wiring.py:135 | KEEP: siem_transports |
| `SENTINEL_SIEM_OTLP_TOKEN_FILE` | sentinel/composition/siem_wiring.py:135 | KEEP: siem_transports |
| `SENTINEL_SIEM_OTLP_URL` | sentinel/composition/siem_wiring.py:135 | KEEP: siem_transports |
| `SENTINEL_SIEM_SYSLOG_APP_NAME` | sentinel/composition/siem_wiring.py:135 | KEEP: siem_transports |
| `SENTINEL_SIEM_SYSLOG_HOST` | sentinel/composition/siem_wiring.py:135 | KEEP: siem_transports |
| `SENTINEL_SIEM_SYSLOG_PORT` | sentinel/composition/siem_wiring.py:135 | KEEP: siem_transports |
| `SENTINEL_SIEM_WEBHOOK_TOKEN` | sentinel/composition/siem_wiring.py:132 | KEEP: siem_webhook_token |
| `SENTINEL_SIEM_WEBHOOK_URL` | sentinel/composition/siem_wiring.py:128; sentinel/composition/siem_wiring.py:131 | KEEP: siem_webhook_url |
| `SENTINEL_SINGLE_PROCESS_ATTESTED` | sentinel/interface/asgi.py:99 | KEEP: process topology/worker control |
| `SENTINEL_TENANT_SIEM_SECRET_` | sentinel/composition/siem_wiring.py:114 | KEEP: tenant SIEM credential family |
| `SENTINEL_TENANT_SIEM_SINKS` | sentinel/composition/siem_wiring.py:68; sentinel/composition/siem_wiring.py:76 | KEEP: tenant_siem_sinks |
| `SENTINEL_TEST_PG_BIN` | scripts/run_dr_postgres_wal_pitr_drill.py:94 | KEEP: live verification infrastructure selector |
| `SENTINEL_TEST_POSTGRES_DSN` | scripts/run_dr_test.py:82; scripts/_embedded_postgres.py:128 | KEEP: live verification infrastructure selector |
| `SENTINEL_TEST_REDIS_URL` | scripts/run_release_gates.py:219; scripts/run_release_gates.py:221 | KEEP: live verification infrastructure selector |
| `SENTINEL_TOOL_BUDGET_PER_MINUTE` | sentinel/composition/container.py:387 | KEEP: tool_budget_per_minute |
| `SENTINEL_TOOL_FILE_ROOT` | sentinel/composition/container.py:436 | KEEP: tool_file_root |
| `SENTINEL_TOOL_HTTP_ALLOWED_HOSTS` | sentinel/composition/container.py:437 | KEEP: tool_http_allowed_hosts |
| `SENTINEL_TRUSTED_PROXY_HOPS` | sentinel/interface/http.py:133 | KEEP: trusted_proxy_hops |
| `SENTINEL_UPSTREAM_AUTHORIZATION` | sentinel/sdk/mcp_stdio.py:300 | KEEP: CLI/operational input |
| `SENTINEL_WAL_S3_` | deploy/wal-archive/wal_s3.py:90 | KEEP: documented family prefix |
| `SENTINEL_WAL_S3_ACCESS_KEY` | deploy/wal-archive/wal_s3.py:92 | KEEP: protected WAL archiver configuration |
| `SENTINEL_WAL_S3_ALLOW_PRIVATE` | deploy/wal-archive/wal_s3.py:111 | KEEP: protected WAL archiver configuration |
| `SENTINEL_WAL_S3_BUCKET` | deploy/wal-archive/wal_s3.py:91 | KEEP: protected WAL archiver configuration |
| `SENTINEL_WAL_S3_CLUSTER` | deploy/wal-archive/wal_s3.py:135 | KEEP: protected WAL archiver configuration |
| `SENTINEL_WAL_S3_ENDPOINT` | deploy/wal-archive/wal_s3.py:90 | KEEP: protected WAL archiver configuration |
| `SENTINEL_WAL_S3_REGION` | deploy/wal-archive/wal_s3.py:125 | KEEP: protected WAL archiver configuration |
| `SENTINEL_WAL_S3_SECRET_KEY` | deploy/wal-archive/wal_s3.py:93 | KEEP: protected WAL archiver configuration |
| `SENTINEL_WORKER_POLL_SECONDS` | sentinel/interface/worker.py:76 | KEEP: worker_poll_seconds |
| `SENTINEL_WORKER_SHARD` | sentinel/interface/asgi.py:125; sentinel/interface/http.py:166 | KEEP: worker_shard |
| `SENTINEL_WORKER_SHARD_COUNT` | sentinel/composition/container.py:343; sentinel/interface/asgi.py:126 | KEEP: worker_shard_count |

Settings verification: retained parsed values match `142025c` in development,
staging and production scenarios; the removed field is the only structural
difference. Ruff and the settings/deployment/preflight/native-remediation tests
pass. The retired-name scan moved from seven findings before removal to zero
after removal. No test function or assertion was changed.


### P4-006 — route scope and authentication decision

Ruling before implementation: retain the 52 default routes and the optional MCP
proxy. A missing literal client URL is not sufficient evidence to remove a kept
safety capability: emergency authorization revocation, manual outcome
reconciliation, coverage reporting, MCP evaluation, and connected-application
registration/read/delete are documented operator or gateway APIs. Their kept
execution, approval, operation-store and MCP assertions remain unchanged.
Connected-app registration is the provisioning path for the retained `app_call`
controlled-execution adapter. Manual reconciliation is explicitly returned by
execution refusals and the worker's unknown-outcome diagnostic.

Remove the three optional framework-owned interactive UI routes `/docs`,
`/docs/oauth2-redirect` and `/redoc` (GET/HEAD). No kept console, SDK, CLI or worker
uses them. Keep `/openapi.json` because the schema-fuzzing CI job consumes it;
replace its unauthenticated framework handler with a normal route requiring
`READ_DIAGNOSTICS`. The existing opt-in flag and its false default stay unchanged,
and production still refuses the flag. CI already sends an admin bearer token.
This tightens the requested authentication boundary without adding a capability
or changing a default. Update only the mixed docs-exposure test to retain the
valid schema response assertion with an authenticated caller and additionally
prove anonymous/ingest refusal and absence of the three unused UI routes.
Keep the route-authorization fitness test byte-for-byte unchanged.

Explicit public allowlist: GET `/health/live`, `/health/ready`, `/console`,
`/console/app.js`, `/console/app.css`. Probes must work when authentication is
unavailable; the console shell/assets contain no tenant data or credentials and
must load before a user supplies a token. `/metrics/prometheus` is not public:
it requires its separate scrape bearer token and refuses when no token is set.
Every remaining API route, including optional schema and MCP proxy, requires an
authenticated principal and a declared capability. Preserve default headers,
rate limits and all kept authorization assertions.

#### Constructed app configurations before route cleanup

Each boolean Settings field and boolean workflow field was flipped individually
against an isolated migrated SQLite database; no background workers or external
connectors were started. Flags that do not add routes still exercise constructed
app registration. The default, docs+proxy combination and all individual
configurations constructed successfully. Counts below are route objects, with
GET/HEAD pairs represented as one framework route, not two declarations.

| Configuration | Constructed routes before |
|---|---:|
| `default` | 52 |
| `expose_api_docs=true` | 56 |
| `rate_limit_fail_open=false` | 52 |
| `protect_enforcement=true` | 52 |
| `protect_kill_switch=true` | 52 |
| `require_execution_binding=false` | 52 |
| `remediation_dry_run=true` | 52 |
| `mcp_require_pin=false` | 52 |
| `mcp_proxy_enabled=true` | 53 |
| `mcp_proxy_allow_private=true` | 52 |
| `mcp_proxy_require_token_audience=false` | 52 |
| `agent_require_grant=true` | 52 |
| `ready_exposes_detection_mode=true` | 52 |
| `workflow.require_workload_identity=true` | 52 |
| `workflow.approval_separation_of_duties=false` | 52 |
| `workflow.mcp_proxy_streaming=true` | 52 |
| `docs+proxy` | 57 |

#### Route decisions (constructed union)

Default: **52** routes; MCP proxy: **53**; authenticated schema: **53**; both: **54**.
All other boolean variants remain at 52. Static declarations are **54**, up from
53 because the retained framework schema is now an explicit guarded declaration.
Three optional framework UI routes were removed; no core route was deleted.

| Method | Path | Handler (file:line) | Authentication | Kept capability / consumer | Decision |
|---|---|---|---|---|---|
| GET | `/openapi.json` | `openapi_schema` (sentinel/interface/http.py:347) | bearer + READ_DIAGNOSTICS | CI / SDK integration schema: .github/workflows/ci.yml:1057; authenticated schema fuzzer | KEEP |
| POST | `/v1/events` | `ingest` (sentinel/interface/http.py:376) | bearer + INGEST_EVENT | SDK / MCP gateway: sentinel/sdk/remote.py:431 | KEEP |
| GET | `/v1/incidents` | `list_incidents` (sentinel/interface/http.py:402) | bearer + READ_INCIDENT | console: sentinel/interface/console/app.js:530 | KEEP |
| GET | `/v1/incidents/{incident_id}` | `get_incident` (sentinel/interface/http.py:415) | bearer + READ_INCIDENT | console: sentinel/interface/console/app.js:530 | KEEP |
| GET | `/v1/incidents/{incident_id}/history` | `get_history` (sentinel/interface/http.py:444) | bearer + READ_INCIDENT | console: sentinel/interface/console/app.js:549 | KEEP |
| GET | `/v1/incidents/{incident_id}/report` | `get_report` (sentinel/interface/http.py:458) | bearer + READ_REPORT | console: sentinel/interface/console/app.js:568 | KEEP |
| GET | `/v1/dashboard` | `dashboard` (sentinel/interface/http.py:467) | bearer + READ_DASHBOARD | console: sentinel/interface/console/app.js:588 | KEEP |
| POST | `/v1/approvals/{approval_id}` | `decide` (sentinel/interface/http.py:473) | bearer + DECIDE_APPROVAL | console: sentinel/interface/console/app.js:803 | KEEP |
| POST | `/v1/protect/evaluate` | `protect_evaluate` (sentinel/interface/http.py:514) | bearer + EVALUATE_PROTECT | SDK / MCP gateway: sentinel/sdk/remote.py:138 | KEEP |
| POST | `/v1/mcp/evaluate` | `mcp_evaluate` (sentinel/interface/http.py:614) | bearer + EVALUATE_PROTECT | MCP gateway: sentinel/application/mcp_gateway.py; docs/INTEGRATIONS.md evaluation contract | KEEP |
| GET | `/health/live` | `liveness` (sentinel/interface/health_routes.py:47) | public allowlist | health/metrics: .github/workflows/ci.yml:254 | KEEP |
| GET | `/health/ready` | `readiness` (sentinel/interface/health_routes.py:111) | public allowlist | health/metrics: .github/workflows/ci.yml:485 | KEEP |
| GET | `/health/diagnostics` | `diagnostics` (sentinel/interface/health_routes.py:135) | bearer + READ_DIAGNOSTICS | console: sentinel/interface/console/app.js:2034 | KEEP |
| GET | `/metrics/prometheus` | `prometheus_metrics` (sentinel/interface/http.py:700) | scrape bearer token | health/metrics: .github/workflows/ci.yml:1041 | KEEP |
| POST | `/v1/policy/validate` | `policy_validate` (sentinel/interface/policy_routes.py:142) | bearer + MANAGE_POLICY | console: sentinel/interface/console/app.js:1728 | KEEP |
| POST | `/v1/policy/versions` | `policy_deploy` (sentinel/interface/policy_routes.py:151) | bearer + MANAGE_POLICY | console: sentinel/interface/console/app.js:1569 | KEEP |
| POST | `/v1/policy/versions/{version}/activate` | `policy_activate` (sentinel/interface/policy_routes.py:176) | bearer + MANAGE_POLICY | console: sentinel/interface/console/app.js:1700 | KEEP |
| GET | `/v1/policy/versions` | `policy_history` (sentinel/interface/policy_routes.py:204) | bearer + MANAGE_POLICY | console: sentinel/interface/console/app.js:1569 | KEEP |
| GET | `/v1/policy/diff` | `policy_diff` (sentinel/interface/policy_routes.py:225) | bearer + MANAGE_POLICY | console: sentinel/interface/console/app.js:1609 | KEEP |
| POST | `/v1/policy/versions/{version}/simulate` | `policy_simulate` (sentinel/interface/policy_routes.py:243) | bearer + MANAGE_POLICY | console: sentinel/interface/console/app.js:1635 | KEEP |
| POST | `/v1/mcp/proxy/{server_id}` | `mcp_proxy` (sentinel/interface/mcp_proxy_routes.py:139) | bearer + EXECUTE_TOOL | SDK / MCP gateway: sentinel/sdk/mcp_stdio.py:7 | KEEP |
| GET | `/v1/transparency/root` | `current_root` (sentinel/interface/transparency_routes.py:112) | bearer + READ_INCIDENT | console: sentinel/interface/console/app.js:1789 | KEEP |
| GET | `/v1/transparency/inclusion/{index}` | `inclusion` (sentinel/interface/transparency_routes.py:140) | bearer + READ_INCIDENT | console: sentinel/interface/console/app.js:1827 | KEEP |
| GET | `/v1/transparency/consistency` | `consistency` (sentinel/interface/transparency_routes.py:191) | bearer + READ_INCIDENT | console: sentinel/interface/console/app.js:1844 | KEEP |
| GET | `/v1/transparency/published` | `published` (sentinel/interface/transparency_routes.py:262) | bearer + READ_INCIDENT | console: sentinel/interface/console/app.js:1792 | KEEP |
| GET | `/v1/executions/binding/coverage` | `binding_coverage` (sentinel/interface/binding_routes.py:93) | bearer + READ_INCIDENT | console: sentinel/interface/console/app.js:1329 | KEEP |
| GET | `/v1/executions/binding/diff` | `binding_diff` (sentinel/interface/binding_routes.py:120) | bearer + READ_INCIDENT | console: sentinel/interface/console/app.js:1361 | KEEP |
| GET | `/v1/executions/binding/{receipt_id}` | `binding_detail` (sentinel/interface/binding_routes.py:187) | bearer + READ_INCIDENT | console: sentinel/interface/console/app.js:1329 | KEEP |
| GET | `/v1/executions/operations` | `list_operations` (sentinel/interface/operations_routes.py:60) | bearer + READ_INCIDENT | console: sentinel/interface/console/app.js:688 | KEEP |
| GET | `/v1/executions/operations/{operation_id}` | `get_operation` (sentinel/interface/operations_routes.py:95) | bearer + READ_INCIDENT | operator/console operation inspection: sentinel/interface/console/app.js:34; retained operation-store API | KEEP |
| POST | `/v1/executions/operations/{operation_id}/reconcile` | `reconcile_operation` (sentinel/interface/operations_routes.py:108) | bearer + DECIDE_APPROVAL | worker/operator recovery: sentinel/interface/worker.py:453; sentinel/interface/extra_routes.py:183 | KEEP |
| GET | `/v1/evidence/export` | `export_evidence` (sentinel/interface/operations_routes.py:168) | bearer + READ_INCIDENT | CLI / operational tooling: scripts/run_deployed_journey.py:420 | KEEP |
| GET | `/v1/workflow/metrics` | `workflow_metrics` (sentinel/interface/operations_routes.py:209) | bearer + READ_INCIDENT | CLI / operational tooling: scripts/run_deployed_journey.py:435 | KEEP |
| GET | `/v1/coverage` | `coverage` (sentinel/interface/operations_routes.py:226) | bearer + READ_INCIDENT | operator workflow coverage: docs/current/FIRST_WORKFLOW.md:20; retained coverage reader | KEEP |
| GET | `/v1/authorizations` | `list_authorizations` (sentinel/interface/authorizations.py:372) | bearer + READ_INCIDENT | console: sentinel/interface/console/app.js:680 | KEEP |
| GET | `/v1/authorizations/{authorization_id}` | `get_authorization` (sentinel/interface/authorizations.py:414) | bearer + READ_INCIDENT | console: sentinel/interface/console/app.js:842 | KEEP |
| POST | `/v1/authorizations/{authorization_id}/revoke` | `revoke_authorization` (sentinel/interface/authorizations.py:434) | bearer + MANAGE_POLICY | operator emergency authorization denial: docs/current/FIRST_WORKFLOW.md:15; retained authorization store | KEEP |
| POST | `/v1/authorizations/{authorization_id}/decide` | `decide_authorization` (sentinel/interface/authorizations.py:476) | bearer + DECIDE_APPROVAL | console: sentinel/interface/console/app.js:842 | KEEP |
| POST | `/v1/tools/execute` | `tools_execute` (sentinel/interface/extra_routes.py:84) | bearer + EXECUTE_TOOL | SDK / MCP gateway: sentinel/sdk/__init__.py:25 | KEEP |
| GET | `/v1/protect/bypass-signals` | `protect_bypass_signals` (sentinel/interface/extra_routes.py:187) | bearer + READ_DIAGNOSTICS | console: sentinel/interface/console/app.js:634 | KEEP |
| GET | `/v1/inventory/agents` | `inventory_agents` (sentinel/interface/extra_routes.py:213) | bearer + READ_INCIDENT | console: sentinel/interface/console/app.js:650 | KEEP |
| GET | `/v1/inventory/agents/{agent_id}` | `inventory_agent` (sentinel/interface/extra_routes.py:256) | bearer + READ_INCIDENT | console: sentinel/interface/console/app.js:1944 | KEEP |
| GET | `/v1/inventory/reach` | `inventory_reach` (sentinel/interface/extra_routes.py:276) | bearer + READ_INCIDENT | console: sentinel/interface/console/app.js:2007 | KEEP |
| GET | `/v1/graph/sessions/{session_id}` | `graph_session` (sentinel/interface/extra_routes.py:317) | bearer + READ_INCIDENT | console: sentinel/interface/console/app.js:1256 | KEEP |
| GET | `/v1/graph/coverage` | `graph_coverage` (sentinel/interface/extra_routes.py:345) | bearer + READ_INCIDENT | console: sentinel/interface/console/app.js:618 | KEEP |
| GET | `/v1/agents/{agent_id}/baseline` | `agent_baseline` (sentinel/interface/extra_routes.py:364) | bearer + READ_INCIDENT | console: sentinel/interface/console/app.js:1975 | KEEP |
| GET | `/console` | `console_index` (sentinel/interface/extra_routes.py:401) | public allowlist | console: sentinel/interface/console/index.html | KEEP |
| GET | `/console/app.js` | `console_js` (sentinel/interface/extra_routes.py:417) | public allowlist | console: sentinel/interface/console/index.html | KEEP |
| GET | `/console/app.css` | `console_css` (sentinel/interface/extra_routes.py:426) | public allowlist | console: sentinel/interface/console/index.html | KEEP |
| POST | `/v1/containments` | `contain` (sentinel/interface/extra_routes.py:437) | bearer + MANAGE_CONTAINMENT | console: sentinel/interface/console/app.js:1503 | KEEP |
| DELETE | `/v1/containments/{containment_id}` | `lift` (sentinel/interface/extra_routes.py:482) | bearer + MANAGE_CONTAINMENT | console: sentinel/interface/console/app.js:1531 | KEEP |
| GET | `/v1/apps` | `list_apps` (sentinel/interface/app_routes.py:22) | bearer + READ_DASHBOARD | operator / controlled-execution adapter: sentinel/infrastructure/app_call.py; docs/INTEGRATIONS.md connected apps | KEEP |
| PUT | `/v1/apps/{app_id}` | `register` (sentinel/interface/app_routes.py:31) | bearer + MANAGE_USERS | operator / controlled-execution adapter: sentinel/infrastructure/app_call.py; docs/INTEGRATIONS.md connected apps | KEEP |
| DELETE | `/v1/apps/{app_id}` | `remove` (sentinel/interface/app_routes.py:56) | bearer + MANAGE_USERS | operator / controlled-execution adapter: sentinel/infrastructure/app_call.py; docs/INTEGRATIONS.md connected apps | KEEP |
| GET, HEAD | `/docs` | `swagger_ui_html` (FastAPI-generated) | previously unauthenticated | none: none | REMOVE |
| GET, HEAD | `/docs/oauth2-redirect` | `swagger_ui_redirect` (FastAPI-generated) | previously unauthenticated | none: none | REMOVE |
| GET, HEAD | `/redoc` | `redoc_html` (FastAPI-generated) | previously unauthenticated | none: none | REMOVE |


Route verification: the tightened schema test first failed because anonymous
access returned 200, then passed after the guarded route replaced the framework
handler. Focused security, unchanged attack-surface fitness and MCP verification:
**125 passed**. All 17 constructed-app scenarios pass; every non-allowlisted API
has an authentication dependency and capability. No route test was deleted and
no core assertion was weakened. Three UI routes were removed; the schema response
200 assertion remains for the authorized caller, with added 401/403 checks.


### P4-007 — core invariant audit scope

Before the audit: inspect the SDK release-hygiene probe and execute it without
changing code. Compare archived and current tests covering protect, authorization,
execution binding/operations/reconciliation, transparency and Passport, including
mixed files and SDK conformance. Attribute every changed/deleted function to an
already recorded cleanup decision; do not infer approval from a green test alone.
Inspect the gate and execution pipeline to establish whether any model result
can choose a decision or authorize an effect. Group every Phase 3 skip by its
explicit JUnit reason, then compare those same cases with the final Phase 4 run.
Only a failed invariant permits a production correction in this step.


#### Core invariant results

| Invariant | Result | Evidence |
|---|---|---|
| Thin SDK imports only the standard library | PASS | Existing release-hygiene probe executes all SDK imports under an isolated interpreter and finds no non-stdlib dependency; release-hygiene/protect probes: 49 passed. |
| Protected test preservation | PASS with recorded approved edits | 52 relevant test files audited against archive/pre-cleanup: 37 byte-identical, 14 changed as listed below, 1 added (independent MCP reply coverage). No unapproved loss of kept assertions found. |
| Deterministic decision authority | PASS | ProtectGate.evaluate calls the deterministic policy at protect_gate.py:81; tenant rules may only strengthen the outcome. The pipeline computes actionable severity before advisory enrichment and records model outputs only under advisory fields (pipeline.py:246–288). Four direct priority/model-authority/outage checks pass. No model call exists in the gate's decision or execution-authorization path. A model call may still run as non-authoritative incident enrichment; this is not claimed absent. |
| Explicit skip reasons | PASS | All 41 Phase 3 skipped cases have nonempty explicit reasons, grouped below. Final Phase 4 matches these exact IDs and reasons; no skip is counted as tested behavior. |

#### Approved protected-test edits since archive/pre-cleanup

The full changed/deleted function inventory for earlier feature parking remains
in the Phase 3 results. This table enumerates every changed file in the core
invariant audit, including fixture-only and documentation-only changes.

| Test file | Edits and approval basis | Commits |
|---|---|---|
| `tests_arch/test_binding_routes.py` | Phase 1 architecture consolidation: update the residual documentation path; the DECLARED assertion remains. | `1840538` |
| `tests_arch/test_demo_execution_trust.py` | User-approved P3-019: rename/adapt the count test to six specified out-of-scope questions; remove only the A2A delegation negative-control function; all other assertions unchanged. | `73af863` |
| `tests_arch/test_execution_concurrency.py` | Phase 0 d45b220: add terminal-redelivery atomic-inbox-winner regression; no original test function changed. | `d45b220` |
| `tests_arch/test_execution_contract.py` | Phase 1 classifier removal: delete only its fixture toggle; every test function is unchanged. | `935ddfc` |
| `tests_arch/test_gap_closures.py` | Approved SAML and orgs/SCIM parking removes five feature-only functions; all kept functions are unchanged. | `34332da`, `1414eb3` |
| `tests_arch/test_mcp_gateway.py` | Phase 1 classifier removal: replace the deleted prompt extractor assertion with a real deterministic-policy detection assertion; retain exact prompt projection. | `935ddfc` |
| `tests_arch/test_passport_conformance.py` | Phase 1 Passport consolidation: canonical vectors and verifier/spec paths move to standard/execution-passport-v1; equality, malicious-vector, integer-bound and dependency assertions remain. | `363886d` |
| `tests_arch/test_protect_decisions.py` | Phase 1 classifier removal: replace classifier-specific severity inspection with composed deterministic-policy equivalence; rename advisory case while retaining its REQUIRE_APPROVAL/non-block assertions. | `935ddfc` |
| `tests_arch/test_remediation_execution.py` | Phase 3 SOAR parking removes twelve notification-only functions; all kept executor functions and assertions remain. | `2e8a36d` |
| `tests_arch/test_root_publication.py` | Phase 1 classifier removal: delete only its fixture toggle; every test function is unchanged. | `935ddfc` |
| `tests_arch/test_security_edge.py` | P4-006: preserve default 404 checks, require authenticated opt-in schema success, add anonymous/ingest refusal and unused-UI absence; no permission assertion is weakened. | `3756559` |
| `tests_arch/test_sql_infrastructure.py` | Phase 3 migration 40: historical upgrade fixture and current schema-inventory import; parked tables excluded, all kept schema assertions remain. | `868bbf8`, `16227fd` |
| `tests_arch/test_tenant_isolation_rls.py` | Phase 1 security-doc relocation and Phase 3 migration 40: use current protected-table inventory, retaining every kept table and RLS/isolation assertion. | `868bbf8`, `16227fd`, `327297b` |
| `tests_arch/test_transparency_routes.py` | Phase 1 removed only the classifier fixture toggle. Phase 4 P4-013 adds an admin schema credential to two inspectors and explicit 200 checks; all original transparency assertions remain unchanged. | `935ddfc`; `a80efe7` |

The added `test_mcp_reply_independent.py` is the approved Phase 3 extraction
regression (`0c57dd3`), not replacement or removal of a kept assertion.

#### Phase 3 skips grouped by reason (41 cases)

Reason: Helm binary unavailable; chart rendering is unverified (1 case).

- `tests_arch.test_config_alignment::test_rendered_helm_controls_activate_real_settings`

Reason: drill has not been run in this tree (1 case).

- `tests_arch.test_dr_postgres_wal_pitr_drill::test_recorded_result_is_internally_consistent`

Reason: both drills have not been run in this tree (1 case).

- `tests_arch.test_dr_postgres_wal_pitr_drill::test_the_dump_drill_result_is_not_overwritten_by_this_one`

Reason: quiet drill has not been run in this tree (2 cases).

- `tests_arch.test_dr_postgres_wal_pitr_drill::test_quiet_record_attributes_its_rpo_to_archive_timeout`
- `tests_arch.test_dr_postgres_wal_pitr_drill::test_the_quiet_value_matches_the_value_the_deployment_sets`

Reason: dedicated local kind cluster not configured; real Kubernetes effects UNVERIFIED (10 cases).

- `tests_arch.test_kubernetes_live_contract::test_approved_update_reaches_real_target_and_replay_cannot_change_it[sqlite]`
- `tests_arch.test_kubernetes_live_contract::test_approved_update_reaches_real_target_and_replay_cannot_change_it[postgres]`
- `tests_arch.test_kubernetes_live_contract::test_concurrent_change_invalidates_approved_target_version[sqlite-update-update]`
- `tests_arch.test_kubernetes_live_contract::test_concurrent_change_invalidates_approved_target_version[sqlite-update-delete]`
- `tests_arch.test_kubernetes_live_contract::test_concurrent_change_invalidates_approved_target_version[sqlite-replace-update]`
- `tests_arch.test_kubernetes_live_contract::test_concurrent_change_invalidates_approved_target_version[sqlite-replace-delete]`
- `tests_arch.test_kubernetes_live_contract::test_concurrent_change_invalidates_approved_target_version[postgres-update-update]`
- `tests_arch.test_kubernetes_live_contract::test_concurrent_change_invalidates_approved_target_version[postgres-update-delete]`
- `tests_arch.test_kubernetes_live_contract::test_concurrent_change_invalidates_approved_target_version[postgres-replace-update]`
- `tests_arch.test_kubernetes_live_contract::test_concurrent_change_invalidates_approved_target_version[postgres-replace-delete]`

Reason: SQLite has no row-level security to interrogate (6 cases).

- `tests_arch.test_migrations::test_row_level_security_is_on_after_a_fresh_migration[sqlite]`
- `tests_arch.test_sql_infrastructure::test_a_tenant_scoped_table_added_late_is_still_protected[sqlite]`
- `tests_arch.test_tenant_isolation_rls::test_every_protected_table_actually_carries_a_forced_policy[sqlite]`
- `tests_arch.test_tenant_isolation_rls::test_an_unscoped_connection_still_sees_no_queue_rows[sqlite]`
- `tests_arch.test_tenant_isolation_rls::test_the_worker_scope_sees_every_tenants_queue_rows_and_nothing_else[sqlite]`
- `tests_arch.test_tenant_isolation_rls::test_the_worker_scope_does_not_outlive_its_transaction[sqlite]`

Reason: SQLite has one isolation level (1 case).

- `tests_arch.test_persistence_benchmarks::test_isolation_levels_are_actually_applied[sqlite]`

Reason: SQLite serialises writers with a busy timeout instead (1 case).

- `tests_arch.test_persistence_benchmarks::test_a_blocked_writer_fails_fast_rather_than_queueing[sqlite]`

Reason: SQLite has no row-level security (1 case).

- `tests_arch.test_persistence_benchmarks::test_row_level_security_does_not_degrade_into_a_scan[sqlite]`

Reason: SENTINEL_TEST_REDIS_URL unset — real Redis unexercised in this run (fakeredis covers unit logic) (2 cases).

- `tests_arch.test_persistence_storage_cache::test_live_redis_adapter_round_trips_without_fakeredis`
- `tests_arch.test_persistence_storage_cache::test_live_redis_token_bucket_is_atomic`

Reason: SENTINEL_TEST_S3_ENDPOINT/ACCESS_KEY/SECRET_KEY unset — live S3/MinIO round-trip UNVERIFIED in this run (1 case).

- `tests_arch.test_persistence_storage_cache::test_live_minio_object_store_round_trips`

Reason: dedicated local kind cluster not configured; the deployed journey is UNVERIFIED (2 cases).

- `tests_arch.test_protected_change_journey::test_one_protected_change_end_to_end[sqlite]`
- `tests_arch.test_protected_change_journey::test_one_protected_change_end_to_end[postgres]`

Reason: gitleaks not installed; reported rather than passed silently (2 cases).

- `tests_arch.test_release_packaging::test_the_real_scanner_reports_a_planted_secret`
- `tests_arch.test_release_packaging::test_the_scan_failure_does_not_echo_the_secret`

Reason: no .env in this checkout, so there is nothing to leak (1 case).

- `tests_arch.test_release_packaging::test_no_allowlisted_file_contains_the_live_aws_credentials`

Reason: isolated real Redis URL required (1 case).

- `tests_arch.test_shared_process_controls::test_real_redis_limits_are_shared_and_tenant_scoped_across_processes`

Reason: soak artifact not present in this checkout (5 cases).

- `tests_arch.test_slo_evaluation::test_the_mapper_reads_the_real_soak_artifact`
- `tests_arch.test_slo_evaluation::test_the_real_artifact_yields_a_met_ingest_and_an_unmeasurable_availability`
- `tests_arch.test_slo_evaluation::test_the_cli_exits_one_when_a_target_is_unmeasurable`
- `tests_arch.test_slo_evaluation::test_the_cli_prints_the_artifacts_own_claim_beside_the_computed_verdict`
- `tests_arch.test_slo_evaluation::test_the_cli_states_that_the_soak_gate_stays_open`

Reason: SQLite has no WITH CHECK; the application predicate is all there is (1 case).

- `tests_arch.test_tenant_isolation_rls::test_a_write_cannot_be_attributed_to_another_tenant[sqlite]`

Reason: no roles on SQLite (1 case).

- `tests_arch.test_tenant_isolation_rls::test_the_application_role_is_not_a_superuser[sqlite]`

Reason: catalogue query is PostgreSQL-specific (1 case).

- `tests_arch.test_tenant_isolation_rls::test_no_tenant_owned_table_was_left_out_of_the_protected_set[sqlite]`

Invariant audit complete. No production code was changed in this step.


### P4-008 — README and clean-checkout quickstart decision

Rewrite README for the existing Observe → Decide → Act → Prove core, explicitly
separating observed telemetry, deterministic decisions, guarded execution and
recorded proof from future discovery/connectors. Describe Phase 5 items only as
not built; implement none. Link the full configuration reference and PARKED.md.

Before writing command claims, create a clean local clone of the current branch
in a unique temporary directory, install the server extra into a new venv, use
an isolated SQLite database and a generated local API token, migrate, start the
actual ASGI app on loopback, and check liveness/readiness. Stop the test process
and preserve command/result logs under baseline/phase4. README will show only
commands executed in this phase. Do not present an unverified Docker command as
a tested quickstart; record the unavailable runtime explicitly instead.


README quickstart verification: clean clone of `3756559`, fresh venv,
server-extra install, SQLite migration and actual ASGI start all succeeded.
Liveness and readiness returned HTTP 200 with the documented bodies. Startup
including migration took **1.24 seconds**; the server was stopped.
All README command lines are recorded in baseline/phase4/quickstart-result.json
and were executed in this phase. Docker/Compose commands are not presented as
verified. No Phase 5 implementation was performed.


### P4-009 — reproducible archive/final measurement decisions

Before measurement: add a repository-local developer measurement command, using
Git tree blobs for both refs so ignored logs, virtual environments and temporary
checkouts never inflate source size. Text means UTF-8 without NUL bytes; physical
LOC uses splitlines (including blank/comment lines). All other blobs contribute
their actual byte length to binary bytes. Count Python modules as tracked .py
files under sentinel/, annotated fields on the Settings class, literal route
decorators on interface functions, direct requirements.txt entries, and YAML jobs
across .github/workflows. Documented names are unique full SENTINEL_* tokens in
README, .env.example, Helm, Compose and docs, excluding the three historical
removal records; report family prefixes separately rather than calling a wildcard
a concrete setting. Use these identical definitions for archive and final refs.

Construct apps and collect tests using the same interpreter and commands: use a
clean detached clone for the archive and the current checkout for the candidate
(only documentation and the measurement helper were pending). Repeat final
measurements on the clean committed current checkout before pushing. Report the default route count and union across individually
flipped boolean settings (including nested workflow flags); do not conflate the
union with one deployment. Historical archive counts may differ from the later
Phase 0 verified baseline because that baseline included approved initial fixes.
Final tracked-tree measurements are recalculated after staging the final results
and checked again after the final commit, so this record includes its own files
and physical lines. Docker image size is unverified, not zero.

Measurement scratch adjustment: WSL removed the temporary /tmp checkout between
invocations. Use a uniquely named clone under the user cache for persistence
across WSL restarts; never modify an existing directory. This changes only
scratch placement, not the measurement commands, source refs or definitions.


### P4-010 — final review and full-suite order

The executing-plans/requesting-code-review skills require one independent,
read-only review of the completed change range. Review Phase 4 from `142025c`
through the current branch and the staged measurement helper; no reviewer may
edit this checkout or delegate further. Complete any material fix and focused
verification before starting the final uninterrupted suite. Documentation result
numbers are finalized only after that suite completes. A review does not waive
the Docker gate or authorize Phase 5, a merge or a PR.

Preliminary measurements succeeded with identical commands on both trees.
The archive contains 4,609 collected cases, 76 default / 82 optional-union routes,
76 Settings fields and 989 tracked files. These are direct measurements of
`d63463c`, not the later Phase 0 baseline. The Phase 4 candidate collects 3,362
cases, has 52 default / 54 optional-union routes, 62 Settings fields and 594
tracked files. Final LOC will be recomputed after the result record is staged.


### P4-011 — independent review dispositions and final verification

The independent read-only review found no critical or important issues. Correct
P4-009 to distinguish the clean archive clone from the candidate working checkout;
repeat measurements against HEAD with a clean tree after the final commit. This
resolves the sole minor finding without changing application behavior.

Retain the unsupported historical SENTINEL_MODE spelling only in negative
examples and its regression guard: it is not a supported setting being removed,
and the guard prevents reintroducing it. Do not add a scan exemption. Retain
REGION, the documented manual operator APIs, and effective benchmark defaults
under P4-005/P4-006. GET is the only kept OpenAPI consumer; removal of the
framework HEAD response is accepted with the unused documentation UI routes.
The measurement helper's independent ref/checkout inputs will be checked by
recording the actual archive commit and final clean HEAD alongside results.

Run the entire Linux suite once, uninterrupted, with the Phase 0 command under
baseline/phase4. Record actual totals and compare every skip with Phase 3. Restore
the prior absence of docs/dr_sqlite_drill.json if generated. No raw logs or reports
will be committed. Docker remains unavailable and blocks Checkpoint 2. No Phase 5
work is authorized or performed.


### P4-012 — final result record structure

Keep the original Phase 0 measurements as historical evidence, but replace their
obsolete empty Phase 4 column with a link to the new, consistently measured
before/after table. Put the current Phase 4 result, settings/route decisions,
invariant verdicts, full-suite outcome and Docker limitation in both this plan
and CHANGES.md. Link the exhaustive reader and route inventories rather than
duplicating their line-level evidence in the change summary. Final numeric
results will be inserted only after the uninterrupted suite finishes.

Use the final committed source tree for the after measurements, including these
records and the measurement helper. After committing, check the checkout is
clean, its application/test tree matches the measured commit, and the archive
clone is still the recovery tag before repeating the same measurement command.
The Docker limitation is the only expected open checkpoint condition; never
substitute a native health check for container verification.


### P4-013 — authenticated schema test callers after the first full run

The first full Linux suite completed uninterrupted: 3,317 passed, 41 skipped,
4 failed, 0 errors, 0 timeouts. The four failures are the SQLite/PostgreSQL cases
of test_the_routes_appear_in_the_openapi_document and
test_no_route_can_append_to_the_log in tests_arch/test_transparency_routes.py.
Both issue anonymous GET /openapi.json, then fail with KeyError: paths because
P4-006 now requires the existing admin-only READ_DIAGNOSTICS capability. The
transparency route/policy assertions themselves did not fail. This test consumer
was missed in the focused route check; retain the failed full-run evidence.

Before changing tests, verify the anonymous/viewer/admin schema responses with an
isolated real app. Then add a dedicated admin fixture credential and authenticate
only the two schema inspections, with explicit HTTP 200 assertions. Keep every
original transparency assertion, the viewer/ingest roles and all refusal tests
unchanged. This follows the user's required route-authentication boundary and
does not relax it. Make no production change, skip or default change. Record
this necessary fixture adaptation in the protected-test audit. Run Ruff and the
whole touched file plus schema-security/route-fitness checks before committing
fix(phase4): authenticate transparency schema checks. Preserve other pending
result/measurement work. Rerun the entire Linux suite uninterrupted afterwards;
only a complete zero-failure run may be reported as final verification.

P4-013 diagnosis confirmed with an isolated real app: anonymous schema access
returns 401, viewer access 403, and admin access 200 with paths. The fixture
adaptation preserves every original assert AST, changes only the two named test
functions, and adds two explicit success assertions. No test function or case is
added/deleted and no production code changes.

P4-013 verification: Ruff passes; the complete transparency-route, security-edge
and unchanged attack-surface files pass **112 tests** on the configured SQLite
and PostgreSQL harness. The four former failures are green. No test cases or
skips were added or removed. The final full run must now be repeated.


## Phase 4 results

**Ready for Checkpoint 2: no — blocked on Docker verification.**
The cleanup implementation, native quickstart and complete Linux verification
are finished. No Phase 5 work is started. The full per-reader/per-route evidence,
protected-test edit inventory and all skipped case identities are retained in
the Phase 4 decisions above (P4-005 through P4-013).

| Group | Result | Commit |
|---|---|---|
| Settings | Remove one unused field and four unsupported/unused names; document retained inputs without changing defaults. | `aecd2a3` |
| Routes | Remove three unused optional UIs; authenticate the retained schema. | `3756559` |
| README | Current core, verified clean-venv quickstart, configuration/parked links and clearly unbuilt next work. | `5afaab9` |
| Schema test callers | Authenticate two schema inspectors; preserve every original transparency assertion. | `a80efe7` |
| Final records | Full-suite outcome, invariant/skip evidence, consistent measurements and Docker blocker. | `chore(phase4): record results` (this commit) |

### Settings and route decisions

The complete per-field/per-name reader audit and every constructed route are in
[CLEANUP_PLAN.md](CLEANUP_PLAN.md#phase-4-decisions), decisions P4-005/P4-006.
All 63 input Settings fields and 146 documented name/prefix entries were audited.
The new [configuration reference](docs/CONFIGURATION.md) documents kept inputs
and unchanged defaults, including operational and dynamic secret inputs.

| Setting/name | Kept reader | Decision |
|---|---|---|
| `Settings.log_level` / `SENTINEL_LOG_LEVEL` | none; parsed value never reached the logger | Remove field, parser, example and Compose entry. |
| `SENTINEL_REQUIRE_LIVE` | none | Remove unsupported documentation claim. |
| `SENTINEL_ADDRESS_LIMIT_PER_MINUTE` | none | Remove ignored benchmark spelling; effective limiter defaults unchanged. |
| `SENTINEL_CREDENTIAL_LIMIT_PER_MINUTE` | none | Remove ignored benchmark spelling; effective limiter defaults unchanged. |
| `region` / `SENTINEL_REGION` | none in runtime code | Keep by explicit user instruction; document limitation. |
| Other 61 Settings fields | executable kept readers, listed in P4-005 | Keep; no default changes. |
| Remediation, retention, attestation, DB/backup/WAL and security controls | kept consumers documented in P4-005 | Keep all specified controls. |

The four removed names are catalogued in PARKED.md. The retired-name scanner
has exactly three exemptions: CHANGES.md, CLEANUP_PLAN.md and docs/PARKED.md.
Historical unsupported spelling examples remain negative examples, not settings.
There was no supported log-level `_FILE` parser or validation branch to remove.

| Method | Route(s) | Decision and consumer/authentication |
|---|---|---|
| GET, HEAD | `/docs` | Remove unused framework documentation UI. |
| GET, HEAD | `/docs/oauth2-redirect` | Remove unused framework documentation redirect. |
| GET, HEAD | `/redoc` | Remove unused framework documentation UI. |
| GET | `/openapi.json` | Keep for CI schema fuzzing; opt-in, now bearer + READ_DIAGNOSTICS. No kept HEAD consumer; framework HEAD removed. |
| GET | `/health/live`, `/health/ready` | Keep public health/readiness allowlist. |
| GET | `/console`, `/console/app.js`, `/console/app.css` | Keep public static console allowlist; its data/action APIs remain authenticated. |
| GET | `/metrics/prometheus` | Keep separate scrape bearer protection; returns 503 when not configured. |
| Various | Other retained APIs, individually listed in P4-006 | Keep for console, SDK, CLI, worker, MCP or documented manual operator use; principal authentication and capabilities required. |

All 17 constructed-app scenarios passed their authentication/capability audit.
The default app remains 52 routes; the optional union falls from 57 to 54.
AST declarations rise from 53 to 54 because the retained schema is now an explicit
protected handler. No test function was removed. The schema test retains the
successful authorized response and adds 401/403 and removed-UI checks.
The route-authorization fitness test is byte-identical to the Phase 4 input.

### Core invariants

| Check | Verdict | Evidence |
|---|---|---|
| Thin SDK uses only the standard library | PASS | Isolated release-hygiene import probe; release-hygiene/protect probes: 49 passed. |
| Protected tests preserve kept assertions | PASS with recorded approved edits | 52 files against archive/pre-cleanup: 37 byte-identical, 14 changed, 1 added. Every historical edit and its commit is listed under P4-007. Phase 4 strengthens optional-schema authentication coverage and supplies admin credentials to two schema inspectors, preserving every original transparency assertion (P4-013). |
| Deterministic rules are the decision authority | PASS | Gate/execution authorization has no model call; four priority/model-authority/outage checks pass. Optional incident enrichment remains advisory and cannot choose authority. |
| Every skip has an explicit reason | PASS | All 41 cases have exactly the same IDs and reasons as Phase 3, grouped under 19 reasons. All case IDs and reasons are listed under P4-007. Skips are not claimed as verified behavior. |

### Archive-to-final measurements

| Measurement | archive/pre-cleanup (`d63463c`) | Final Phase 4 tree |
|---|---:|---:|
| Tracked files | 989 | 594 |
| Text LOC: sentinel/ | 82,226 | 57,885 |
| Text LOC: tests_arch/ | 70,652 | 52,003 |
| Text LOC: total | 326,506 | 219,055 |
| Binary bytes | 5,379,130 | 0 |
| Python modules under sentinel/ | 258 | 190 |
| Test cases collected | 4,609 | 3,362 |
| Routes: AST declarations | 78 | 54 |
| Routes: constructed default | 76 | 52 |
| Routes: union across optional flags | 82 | 54 |
| Settings fields | 76 | 62 |
| Documented concrete SENTINEL names | 155 | 137 |
| Direct runtime dependencies | 12 | 11 |
| CI jobs | 20 | 16 |
| Docker image size | not measured | UNVERIFIED |

Identical measurement implementation and interpreter for both refs:

```bash
.venv/bin/python scripts/dev/cleanup_metrics.py --ref archive/pre-cleanup --checkout /home/lenovo2/.cache/sentinel-cleanup-phase4/archive-42mt4hu7/sentinel --out baseline/phase4/archive-metrics.json
.venv/bin/python scripts/dev/cleanup_metrics.py --ref HEAD --checkout /home/lenovo2/sentinel --out baseline/phase4/final-metrics.json
```

The helper reads tracked blobs with `git ls-tree -rz --full-tree REF` and
`git cat-file --batch`. Text means UTF-8 without NUL bytes; physical LOC includes
comments and blanks. Other blobs contribute binary bytes. Module counts include
initializers. It parses literal interface route decorators and Settings annotated
fields with Python AST, counts direct requirements.txt entries and YAML workflow
jobs, and counts unique concrete documented names across README, example env,
Helm, Compose and Markdown docs, excluding the three historical removal records.
Wildcard family prefixes are separate: 4 before, 6 after. Each tree uses the same
isolated SQLite migration/app construction and each boolean optional flag,
including nested workflow flags. Route counts count route objects/method sets;
the union is not one deployment. Collection uses the same interpreter and command
in each checkout:

```bash
/home/lenovo2/sentinel/.venv/bin/python -m pytest tests_arch/ --collect-only -q -o addopts=
```

Archive counts are from the exact recovery tag, not the later Phase 0 baseline
that included approved initial fixes. Final tracked counts include this result
record and the measurement helper. Runtime/collection measurements are repeated
on the clean committed final checkout before pushing.

### Verification, Docker and remaining condition

The final Phase 0 command ran uninterrupted in Linux/WSL, exiting 0:

```bash
pytest tests_arch/ -q --timeout=120 --timeout_method=thread --durations=30 -rA --junitxml=baseline/phase4/junit.xml 2>&1 | tee baseline/phase4/pytest.log
```

A shell pipefail guard preserved pytest's status. Final result: **3,321 passed,
41 skipped, 0 failed, 0 errors, 0 timeouts**
(3,362 cases; JUnit 1,554.076 seconds). Case count, passed total and skipped total are unchanged from Phase 3; no skip reason changed. The archive-to-final case reduction belongs to earlier cleanup phases.
The first complete run had 3,317 passed / 41 skipped / 4 failed: two transparency
schema inspectors were still anonymous, on both databases. P4-013 fixed only
those test callers, retained every original assertion and added explicit 200
checks (`a80efe7`). That failed run is preserved under
baseline/phase4/attempt-1-failed and is superseded by the final complete run.
Raw logs, JUnit, inventories and measurement JSON remain ignored under
baseline/phase4; reports and raw logs are not committed.

Ruff, 10 import-graph unit tests, 2 removed-name scanner tests, actionlint and the
release secret scan all pass. The graph gate has zero unexplained orphans,
zero unresolved internal imports and zero stale allowances; the 11 retained
library/entry-point allowances remain explicitly recorded. The retired-name
scan checks 66 names/prefixes with zero findings outside the exact three-file
exemption list. Relative Markdown links: 89 checked, zero broken.
The SQLite drill artifact remains absent, matching its initial state.

The README's ten commands were run in a clean clone with a fresh venv/server
install, migration and real ASGI startup. Liveness/readiness both returned 200;
native startup including migration took 1.24 seconds, then the server stopped.
The README describes existing behavior and marks Phase 5 work as not built.

**Docker: UNVERIFIED (not installed in WSL)**. `docker version` exits 127; no
server, image build, image size, container startup time, healthcheck or Compose
verification is claimed. This is the remaining Checkpoint 2 blocker.

Deviations/explicit exceptions: retain REGION without a runtime consumer as
instructed; retain documented manual safety/operator APIs even without a literal
first-party client call; preserve ignored benchmark limits' effective defaults.
Remove only the unused UI routes and protect the retained schema. Historical
negative spelling examples remain guarded. The review's sole minor record issue
was corrected to distinguish the archive clone from the candidate checkout;
there were no critical or important findings in the reviewed implementation.
The later P4-013 fixture correction was checked against every original assertion,
112 focused tests and the complete final suite. No Phase 5 code, merge or PR.
