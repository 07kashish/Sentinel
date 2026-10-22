# Sentinel cleanup plan — Phase 0 checkpoint

This is an inventory and proposed removal plan, not authorization to delete. Phases 1–6 have not started. The user requires confirmation here and again after Phase 4.

**Product constraint:** independent, cross-vendor company oversight through Observe → Decide → Act → Prove. Deterministic rules remain the decision authority. Preserve the semantics and existing assertions for protect_gate, authorizations, tool_runner, execution_binding, operation storage/reconciliation, transparency and Execution Passport. Keep AWS, GitHub and Kubernetes controlled execution.

## Preservation and execution status

- This folder arrived without Git history. The user explicitly authorized initializing it and making a baseline snapshot. This is a new import, not recovery of upstream history.
- Baseline commit and recovery tag: `archive/pre-cleanup` → `d63463cd3bc49bcd3e420ff4a100cc52fe6f4ad6`. Working branch: `cleanup/oversight-core`. No remote was added and nothing was pushed; do not move or delete the recovery tag.
- The initial snapshot was scanned before commit: `python scripts/scan_release_for_secrets.py --tree`, **989 members, zero findings**. This is the repository scanner, not an independent review or a gitleaks run.
- The initial inventory changed no pre-existing source. The completed Phase 0 baseline includes minimal SDK probe and atomic inbox-result fixes plus regression coverage, described below. No application code was deleted, moved or refactored. Raw logs/inventory helpers are ignored under `reports/`.
- No Phase 0 completion commit is allowed while the required full suite is red. The separately authorized archive snapshot preserves the original input; it does not assert a green suite.

## Baseline and counting method

The original Python 3.14 environment lacked pytest/Ruff. The pinned install failed on unavailable `pgserver==0.1.4`; PyYAML/lupa also needed native builds on 3.14. A Python 3.13.16 environment was created under ignored `reports/.phase0-venv/`, with the repository runtime/dev pins except pgserver. The requested requirements files are unchanged. No PostgreSQL result is claimed: the harness reports skips where no server is available. This is Windows, whereas the main CI runs Linux/Python 3.12.

| Measurement | Before cleanup | After Phase 4 |
|---|---:|---|
| Tracked files (archive snapshot) | 989 | pending |
| Python modules under sentinel, including initializers | 258 (246 excluding initializers) | pending |
| sentinel Python physical LOC | 78,965 | pending |
| tests_arch Python physical LOC | 70,429 | pending |
| test_*.py files | 205 | pending |
| Pytest cases collected/executed, including skips | 4609 | pending |
| Static route declarations (including conditional routes) | 78 | pending |
| .env.example assignments / distinct documented SENTINEL names | 69 / 138 | pending |
| Settings annotated fields | 76 | pending |
| CI jobs across both workflows | 20 | pending |
| Unreachable / never imported sentinel modules | 39 / 26 | pending |
| ruff baseline | exit 0; 1.323 s | pending |
| pytest baseline | exit 1; 407.607 s | pending |

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
| `sentinel.infrastructure.persistence.backup` | 616 | Phase 2: delete (dead-persistence) |
| `sentinel.infrastructure.persistence.diagnostics` | 248 | Phase 2: delete (dead-persistence) |
| `sentinel.infrastructure.persistence.migrations` | 417 | Phase 2: delete (dead-persistence) |
| `sentinel.infrastructure.persistence.objectstore` | 470 | Keep: external WAL archive command imports it; see exceptions. |
| `sentinel.infrastructure.persistence.schema` | 557 | Phase 2: delete (dead-persistence) |
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

## Proposed removals and impact inventory

Each table names every existing file selected for deletion, merging or parking, with physical LOC. “Merge” removes the source document only after its still-true content has moved. Test files listed in a feature group are proposed removals because they exercise that removed feature; shared tests listed under impacts must instead be adapted. These are proposals, not deletions already performed. Paths absent from this snapshot are listed separately below.

| Phase | Unique proposed removed/merged/parked files | Text LOC | Binary bytes |
|---|---:|---:|---:|
| 1 | 319 | 76,409 | 5,379,130 |
| 2 | 28 | 9,959 | 0 |
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

Remove duplicate schema/backup/diagnostic implementation; retain live sql layer and retarget shared crypto/audit tests.

| Proposed path | LOC / binary size | Action |
|---|---:|---|
| `sentinel/infrastructure/persistence/backup.py` | 616 | delete |
| `sentinel/infrastructure/persistence/diagnostics.py` | 248 | delete |
| `sentinel/infrastructure/persistence/migrations.py` | 417 | delete |
| `sentinel/infrastructure/persistence/schema.py` | 557 | delete |
| `tests_arch/test_persistence_backup_pitr.py` | 856 | delete |

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

**DR:** keep scripts/run_dr_postgres_wal_pitr_drill.py and the WAL archive adapter; document standard PostgreSQL backup/restore/PITR in docs/OPERATIONS.md. Retain core backup/restore integrity tests for this path. The separate persistence/backup.py implementation can go. Evaluate redundant drill scripts after retaining the one complete sql/-based WAL/PITR path; never silently downgrade off-host archive behavior.

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
| `sentinel/interface/advisor_check.py` | yes | Phase 2: remove after recursive consumer verification. |
| `sentinel/infrastructure/persistence/backup.py` | yes | Phase 2: remove after recursive consumer verification. |
| `sentinel/infrastructure/persistence/schema.py` | yes | Phase 2: remove after recursive consumer verification. |
| `sentinel/infrastructure/persistence/objectstore.py` | yes | Keep: external WAL archive adapter; service-root reachability is not the deletion criterion. |
| `sentinel/infrastructure/persistence/migrations.py` | yes | Phase 2: remove after recursive consumer verification. |
| `sentinel/infrastructure/persistence/diagnostics.py` | yes | Phase 2: remove after recursive consumer verification. |
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
- [ ] Phase 1: cut incidental consumers, preserve shared security/route helpers, migrate Passport fixtures, remove non-product material, consolidate docs and all inbound links; run full pytest and Ruff before the requested commit.
- [ ] Phase 2: re-run graph plus recursive text searches per module; remove only proven unused modules/tests, keep documented external WAL/benchmark/SDK support, and record any new exceptions; full suite and Ruff before commit.
- [ ] Phase 3: remove routes/config/console/screens and feature-only tests atomically, preserve shared core subsets listed above, append drop migration with upgrade/fresh-install coverage, write PARKED.md with LOC/tag/customer return signals; full suite and Ruff before commit.
- [ ] Phase 4: eliminate unused settings, count actual routes/settings/jobs/files/LOC/tests, verify thin SDK imports and core invariants, update README and results table, run checks, commit and STOP for user review.
- [ ] Only after the Phase 4 confirmation: implement 5.1–5.6 with current official API verification, fixture-only connector tests and unchanged approval/execution authority, then Phase 6 verification/report. No connector, credential broker or new source integration is implemented in Phase 0.

Requested phase commit messages remain as specified in the user brief. Latest requested Phase 0 commit: `chore(phase0): establish Linux test baseline`. No Phase 1 deletion is authorized by writing this file.
