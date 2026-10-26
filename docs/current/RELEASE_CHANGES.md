# Release changes — production-readiness branch

## 2026-09-17: CI dependency and distribution repair

Changes: replace unavailable Docker Hub MinIO test image with the official Quay multi-platform manifest, pinned to sha256:1dce27c494a16bae114774f1cec295493f3613142713130c2d22dd5696be6ad3. Generate the synthetic scanner fixture at runtime; exempt only its exact historical fingerprint. Package the three advertised console assets explicitly and request each over real HTTP in the clean-install smoke.

Evidence: local release-hygiene and packaging tests passed with one existing optional skip; gitleaks scanned 220 commits with no findings under the configured exceptions. Fresh wheel smoke passed on Python 3.13, including thin SDK, migration, schema verification, console assets, policy evaluation and refusal of unbound execution. The new Quay image has been resolved through the registry API; runtime validation remains a GitHub CI gate. This is no assessment of cloud production behavior.

Migration: none; no database or evidence-schema change. Upgrade wheel/container together with the configured static assets. Compatibility: API and SDK interfaces unchanged.

Rollback: redeploy the previous artifact by its recorded digest. This reintroduces the missing-console wheel limitation; do not downgrade to repair a security finding. The CI registry pin is independent of production object storage. Preserve all local and customer data.

## Evidence integrity repair (verification in progress)

Collected tests and configured workflow names no longer grant a tested tier. Actual JUnit outcomes must match their JSON report digest, commit, and a digest over code, tests, policy, dependencies and deployment inputs. Unsigned production/assessment JSON sidecars do not establish external verification. The five evidence levels remain distinct.

Migration: report readers should consume the additional passed-count and inputs-identity fields. No change to customer execution receipts. Rollback: stop publishing current readiness claims if evidence intake cannot validate; never restore the collection-based promotion rule.

## 2026-09-17: protected execution semantics

Reproduced defects: a target callback that performed a counted effect and then timed out returned HTTP 403 and stored FAILED; a post-effect control-store error returned an unstructured 500; receipt errors exposed raw exception text. Activated tenant deny rules did not govern fresh evaluation, and policy changes that reused a version label did not change the approval binding.

Changes: invoked-callback exceptions and post-effect bookkeeping failures return a structured unknown outcome with the stable operation ID. The operation is immediately marked unknown when storage permits; otherwise its durable pending intent remains for deadline reconciliation. Raw exception messages are not persisted or returned. Activated tenant rules now govern evaluation and bound execution, with existing first-match semantics and deterministic policy as a minimum restriction. Statistical detection is outside this enforcement gate. Human approval does not satisfy step-up authentication.

Evidence: counted-side-effect HTTP regressions, receipt/operation tests, approval/replay tests, and forced-RLS tests passed against local SQLite and PostgreSQL 17. PostgreSQL-only checks are skipped on SQLite. No remote Kubernetes effect, multi-pod deployment, or independent security assessment was established by these tests.

Compatibility: enforcement-policy binding changes to v2 and includes both deterministic rule contents and tenant policy contents. Every outstanding authorization using the old binding must be reevaluated and, where needed, approved again. The stored receipt schema is unchanged. Unknown outcomes retain their prior schema and reconciliation API.

Rollout: pause protected action admission; let known in-flight operations settle; reconcile unknown operations; deploy the same version to all gateway replicas; reject stale authorizations; require fresh evaluation/approval; resume admission after smoke checks. Do not run mixed v1/v2 approval evaluators as a supported topology.

Rollback: pause admission first. Preserve operation, receipt, authorization, and audit rows. Use an independently reviewed corrective release; if reverting binaries, expire/revoke outstanding authorizations via tenant-scoped controls before resuming. Never re-enable the old policy binding to make stale approvals execute. Remote effects cannot be undone by a database or binary rollback.

## 2026-09-17: private policy evaluation and bounded metrics

Parameter values enter the local deterministic policy through a separate transient argument. Audit payloads retain their digest; returned policy reasons contain rule identifiers rather than matched sensitive text. Parameter-substitution tests still require the mismatch refusal; restricted-path content is also reevaluated before invocation. Local SQLite/PostgreSQL contract tests and privacy regressions exercise these boundaries.

Metrics use route templates and a fixed unmatched bucket, cap total label sets, exclude tenant/agent labels, escape Prometheus values, synchronize recording and scraping, and expose cumulative duration buckets plus a dropped-sample counter. A local HTTP test sent 10,000 distinct paths without growing path series; concurrent record/scrape counts also passed. This proves bounded local behavior, not a production soak or multiprocess aggregation.

Migration: dashboards can retain sum/count queries; percentile queries must use the new buckets. Raw-path label values disappear and become route templates. Candidate pilot validation uses one API process per pod, scraped individually; multiple gunicorn workers behind one metrics endpoint are not a certified aggregation topology.

Rollback: preserve execution records. If telemetry compatibility fails, adjust queries or temporarily stop metric consumption; do not restore unbounded labels or sensitive policy-match output. The execution/evidence database schema is unchanged.

## Verified local checkpoint: 9efccc3 (2026-09-17)

The complete suite passed on Python 3.13.14 with PostgreSQL 17.11 UTF-8: 4,138 passed, 38 skipped, including 585 passed PostgreSQL cases. Test reports bind commit and release-input digest. The clean-checkout wheel passed archive scanning and a fresh installation smoke, and two clean builds produced identical bytes. The 28-component locked runtime dependency audit reported no known vulnerabilities. All evidence is local and unsigned; image, cloud, independent assessment, customer and CI gates remain unverified.

A resumed run without PostgreSQL and a run against a newly created SQL_ASCII test cluster are invalid release evidence. A raw-workspace wheel differed from the clean wheel only in file mode metadata; use the retained clean-checkout artifact identified in RELEASE_STATUS.

GitHub Actions is deferred until 2026-10-02 at the owner's request. The documentation checkpoint uses a CI-skip marker to avoid requesting another run during that hold; this is not a passing gate or permission to release. The original docs/dr_sqlite_drill.json modification remains unstaged.

## 2026-09-17: bounded operational tracing and enforced deployment defaults

Changes: replace process-local span history with the standard OpenTelemetry SDK and OTLP/HTTP protobuf exporter over Sentinel's hardened transport. Queue capacity is 256 spans plus at most 32 in-flight; overflow, failed export and shutdown loss are counted. Export only fixed operation names and bounded HTTP method labels, without tenant identifiers, request paths, payloads, exception text or customer-supplied correlation identifiers. Collector partial acknowledgement is conservatively counted as failed delivery. An alert selects actual exposed drop counters.

Configuration: Helm and raw Kubernetes manifests enable enforcement and require bound execution. Helm schema refuses binding=false and limiter fail-open=true. Shared Redis comes from a managed secret reference and gets an explicit same-namespace network-policy path. One API worker per pod permits a meaningful per-pod metrics scrape. Unread signer/RLS/replica/nonce/proxy options were removed; the Terraform publisher name now matches the runtime maintenance setting. Optional configuration names are catalogued without activating them. Static configuration checking is a future CI gate; no Actions run was requested during the owner's hold.

Evidence so far: targeted regression suite, real local OTLP HTTP/protobuf receiver, saturated queue and failed/partial collector tests, settings parsed from the raw deployment, chart-schema refusals, and Helm 3.16.3 strict lint. Full-suite and clean-package evidence must bind the subsequent code commit; this paragraph does not grant those gates.

Migration: no database or receipt-schema migration. Install the newly locked server dependencies. Before rolling out, provision shared Redis and a collector HTTPS endpoint trusted by the system CA store, verify network policies and scrape each pod. The adapter deliberately does not support proxy environment variables, custom collector headers or client-certificate overrides. A collector mesh termination must present a trusted server certificate. Pause consequential-action admission, finish/reconcile pending operations and migrate callers to bound authorizations before enabling this chart. Roll all replicas to one version, then run approved/refused/replay/Redis-outage smoke tests before resuming.

Rollback: preserve all authorizations, intents, receipts and remote effects. Disable optional tracing while repairing collector configuration if necessary; do not restore unbounded span retention. A telemetry outage does not waive authorization or evidence persistence. Do not disable binding or enable fail-open to make old callers run. Restore an independently reviewed artifact/configuration pair only with admission paused and stale approvals revoked or expired. Removed configuration keys have no compatibility effect because they had no runtime reader; Redis, enforcement and required binding do change behavior intentionally.

Limits: flush means the bounded queue has drained, not that a collector persisted every span. Export and shutdown deadlines bound waits, but DNS or stalled OS calls can outlive the daemon's join deadline; remaining delivery is not guaranteed. Process-local metrics require separate scrape targets and aggregation. Chart rendering does not validate a live CNI, Redis, mesh, secret mount or independent failure domain. No production availability, latency or readiness claim follows.

## 2026-09-18: portable recovery checks and startup cleanup

An explicit `SENTINEL_TEST_PG_BIN` selects a same-major local PostgreSQL tool installation when pgserver is unavailable. The archive and PITR checks now run on macOS rather than skipping for the missing package; 34 targeted checks passed against local PostgreSQL 17.11. They use temporary local clusters, not an independent failure domain. Test clusters explicitly initialize UTF-8. Development dependencies now include the pinned wheel build backend, and a wheel-build failure fails the packaging test instead of reporting a skip.

Application wiring now closes the bounded trace worker when later OIDC initialization fails, and closes the database pool even if trace shutdown raises. Regression coverage deliberately supplies malformed synthetic JWKS after exporter construction and checks that no exporter thread survives. No credentials or customer services are used.

The status generator and deployment notes no longer present configured CI jobs or archive_timeout as deployed evidence or an RPO guarantee. Migration: install development tools only in the development/test environment; runtime schemas and interfaces are unchanged. Rollback: preserve source/test evidence and data, repair the selected local tool path if unavailable, and retain cleanup and failing packaging gates rather than restoring skipped verification.

## Verified local checkpoint: 57b6f66 (2026-09-18)

A clean checkout passed 4,175 tests with 23 skips, including 587 PostgreSQL passes. Two clean wheel builds match byte-for-byte; fresh installation, allowlist/secret scans, local WAL/PITR, bounded OTLP HTTP, shared-process controls and Helm/settings checks passed. RELEASE_STATUS binds the reports and exact artifacts. The nine non-dialect skips and all external gates are listed in SECURITY_AND_DR_EVIDENCE. The local evidence is unsigned; CI remains held until October 2.

This checkpoint changes evidence only. No schema, policy or verifier migration is introduced. Preserve the executable commit and artifact digests when rolling out; a documentation rollback cannot change or establish control behavior.

## 2026-09-19: container input isolation and live local deployment harness

The Docker context now defaults to deny and names runtime files explicitly. A build-time gate rejects missing mandatory modules, extra files, symlinks and configured credential patterns without disclosing matched values. The base image is digest-pinned, dependency downloads remain hash-locked, the runtime uses UID/GID 10001 like Helm, and imports of server/CLI modules must succeed as that user. A real build caught wildcard traversal omitting Python packages; the literal manifest and completeness/import gates repair it.

The local kind harness restricts itself to a loopback API, expected node names and a harness-owned namespace on resume. It provisions only synthetic credentials, non-superuser PostgreSQL, Redis and two gateway pods; tests harmless bound execution, replay across pods, tenant refusal and Redis outage. Reports preserve failure stages and explicitly withhold real infrastructure-change, CNI, mesh, independent recovery and production claims.

Migration: regenerate .dockerignore with the documented command when adding runtime source; build and scan the image before rollout. No schema or authorization change. Existing volumes mounted with a different UID must be checked for UID/GID 10001 access before deployment; do not change ownership of customer storage automatically. Rollback: pause admission, preserve data and receipts, then redeploy a reviewed image/configuration pair. Do not restore broad source copying, omit modules, disable binding or suppress vulnerability findings to pass a gate.

## 2026-09-19: existing Kubernetes object preconditions

Updates now require metadata.uid, a nonzero metadata.resourceVersion, and an exact name/namespace match. Deletes require both UID and resourceVersion in DeleteOptions.preconditions. The original approved fields go unchanged to the Kubernetes API for atomic validation; Sentinel never fetches a newer version and silently retries. API PUT is classified as a Kubernetes write, fixing the previously unrecognized update verb. Non-2xx API responses no longer return a successful adapter result; the outer tracker conservatively records uncertainty after invocation for reconciliation. Returned confirmation is explicitly API-response-only, not proof of final controller convergence.

Migration: clients must read the intended object, include its UID/version in the change, request a fresh approval and execute those exact arguments. Do not send server-owned managedFields/status back as desired state. Existing approvals without preconditions cannot execute updates/deletes; obtain fresh approval. Resource version zero is refused because it can request unconditional update semantics. Create/read behavior and the evidence schema are unchanged.

Verification: unit regressions check missing/zero/malformed preconditions, target substitution and no retry on conflict. Opt-in HTTP contract tests use a real local kind API, scoped ten-minute service-account tokens and both database backends; actual target state is read after approval, parameter substitution, replay and concurrent change. This does not establish production workload identity, CNI enforcement, a deployment rollout or an independently witnessed outcome.

Rollback: pause mutation admission and retain all intents/receipts. Reconcile unknown operations with target records. Repair clients rather than reverting to unconditioned writes; never automatically refresh a stale resourceVersion or replay the same remote effect.

## 2026-09-19 — fail-closed image vulnerability gate

The local image gate and configured CI gate now block every HIGH/CRITICAL vulnerability, including findings without an upstream fix. They also reject scanner errors, malformed/missing reports, mismatched image IDs, secret findings and high-severity misconfigurations. Scanner matches and surrounding raw output are not written into release gate evidence. CI writes raw results to a temporary file and removes it after sanitized evaluation; Actions remains held until October 2.

Migration: no application/schema change. Existing image candidates may correctly move from passing to blocked. No vulnerability exception is approved. Rollback: retain the blocked candidate and halt distribution; reverting the gate is not an approved way to release. Validation: `tests_arch/test_image_scan_gate.py` includes an undisclosed synthetic credential, unfixed vulnerability, scanner failure and wrong-artifact rejection.

## 2026-09-20: workload identity, constrained credentials, reconciliation, approvals, evidence, image base

**Workload identity.** `SENTINEL_AGENT_IDP_JSON` accepts kinds `spiffe` and `kubernetes`. `SENTINEL_REQUIRE_WORKLOAD_IDENTITY=true` refuses API keys on the agent path. Default false. Migration: register the issuer, move agents to tokens, then turn the requirement on. Rollback: set it false.

**Constrained credentials and outcome.** With `SENTINEL_KUBERNETES_EXECUTOR_SERVICE_ACCOUNT` and `_NAMESPACE` set, `SENTINEL_KUBERNETES_TOKEN` becomes a broker that only mints per-operation tokens. Creates and updates carry `fieldManager=sentinel-op-<digest>`. A definitive 4xx is a FAILED operation; unknown outcomes are reconciled from the target by the maintenance loop. Migration: apply `deploy/protected-changes/rbac.yaml`, give Sentinel the broker token, then apply `admission-policy.yaml` and label protected namespaces. Apply the admission policy only after the executor settings are live, or the executor's own writes are refused. Rollback: remove the namespace label, then unset the executor settings.

**Approvals.** Authorizations carry a redacted change summary. `SENTINEL_APPROVAL_QUORUM` (default 1) and `SENTINEL_APPROVAL_SEPARATION_OF_DUTIES` (default true) are enforced; approvals of expired or policy-stale requests are refused. Behaviour change: a requester holding `DECIDE_APPROVAL` can no longer approve their own request. Rollback: set separation to false. Authorizations issued before this release have no summary and show `change: null`.

**Evidence.** Migration 37 adds `evidence_commitments` (additive, tenant-scoped, append-only). The maintenance loop commits receipts to the transparency log; `GET /v1/evidence/export` returns a bundle that `standard/execution-passport-v1/verify_evidence_bundle.py` verifies offline. Existing receipts are committed on the first pass, in completion order. Rollback: deploy the previous image; the table and the new leaves are ignored by it. Leaves are never removed.

**Measurement.** `GET /v1/workflow/metrics` counts approval latency, interruptions and unknown outcomes from records.

**Image.** The runtime base is a digest-pinned Wolfi image with Python 3.12; no pip or compiler in the runtime. Local Trivy scan: 0 HIGH or CRITICAL. Migration: rebuild; the UID stays 10001. `apt`-based customisations of the image no longer apply. Rollback: the previous Dockerfile.

**Verification.** Recorded in `RELEASE_STATUS`. The end-to-end journey ran against a local Kubernetes 1.37 API server with the application in-process. CI has not run (RISK R-019).

## 2026-09-20 (second pass): deployment defects, stamped deletes, key rotation, adapter outcomes, customer witness

**Two defects found by deploying.** (1) The Kubernetes tool could not work in a real cluster: its client refused private addresses and trusted only public CAs. It now gets a client that may reach exactly the API server's host, with `SENTINEL_KUBERNETES_CA_FILE` as the only added trust anchor. (2) Nothing wrote rows to `tenants`, which the maintenance loop iterates, so a real deployment ran retention, reaping, reconciliation, root publication and evidence commitment for nobody. Tenants named by API keys and agent identity providers are now enrolled at startup. Migration: none; on first start after upgrade, maintenance begins sweeping existing tenants, so expect retention deletions and evidence commits that never happened before. Review retention settings before upgrading. Rollback: the previous image stops sweeping again.

**Stamped deletes.** With brokered credentials a delete first rewrites the approved version with `sentinel.io/delete-operation`, then deletes that version; the admission policy requires the mark. Migration: reapply `deploy/protected-changes/admission-policy.yaml` AFTER upgrading Sentinel, or executor deletes are refused. The executor role needs `get` and `update` as well as `delete` (the shipped role has them). Rollback: reapply the previous policy.

**Key rotation.** Agent issuers may use `jwks_uri`. No change for pinned registrations.

**Adapter outcomes.** Behaviour change: a GitHub or AWS mutation answered with 4xx now fails the execution (HTTP 403 from `/v1/tools/execute`, operation FAILED) instead of returning the platform's error as a successful result; a 5xx becomes an unknown outcome. Callers that inspected `result.status` for errors must handle the refusal instead. Reads are unchanged. Rollback: previous image.

**Customer witness and recovery.** `witness_root.py` and `verify_evidence_bundle.py` are customer-side tools with no dependency on Sentinel. No service change.

**Deployed journey and load baseline.** `scripts/run_deployed_journey.py` and `scripts/run_workflow_loadtest.py` are harnesses; they change no runtime behaviour.

## 2026-09-20 (third pass): AWS and GitHub constrained credentials, discovery, sign-in enrolment, TLS journey

**AWS.** `SENTINEL_AWS_EXECUTOR_ROLE_ARN` makes the configured key a broker: each operation assumes that role for fifteen minutes under a session named after the operation, and unknown outcomes are reconciled from CloudTrail by that name. Migration: create the role with the permissions agents' changes need, trust the broker principal, and reduce the broker's own policy to `sts:AssumeRole` on that role plus `cloudtrail:LookupEvents`. Rollback: unset the variable. Never sent to real AWS (RISK R-021).

**GitHub.** `SENTINEL_GITHUB_APP_ID`, `_INSTALLATION_ID` and `_APP_PRIVATE_KEY_FILE` replace `SENTINEL_GITHUB_TOKEN`: each call mints an installation token scoped to its repository and permission family. `SENTINEL_GITHUB_TOKEN` is no longer required when App mode is configured; setting neither is refused. Rollback: set the token again. Never sent to real GitHub (RISK R-021).

**Discovery and enrolment.** Agent issuers may use `"discover": true`. Tenants first named by a verified human sign-in get their directory row then. No migration.

**Deployed journey.** Runs over TLS under a private CA. Harness only.

**Documents.** `PILOT_KIT.md` is the procedure a design partner follows and the evidence each step must leave.

## 2026-09-20 (fourth pass): evidence encryption, live value and SLO judges, shadow MCP detection, AWS cloud proof

**Evidence encryption. BREAKING for production.** Evidence bodies are sealed per record when `SENTINEL_DATA_KEY_<id>` and `SENTINEL_ACTIVE_KEY_ID` are set. Production now REFUSES to start with neither a key nor `SENTINEL_EVIDENCE_ENCRYPTION=off`. Migration: generate a key (command in `.env.example`), store it in the `sentinel-data-key` secret (Helm) or the `dataKey` entry of `sentinel-secrets` (raw manifest), deploy, then run `python -m sentinel.interface.cli evidence-reseal <tenant>` per tenant to seal existing rows. Rotation: add the new key, move the active id, restart, reseal until it reports 0, remove the old key. BACK UP THE KEY: losing every key loses the bodies; digests, receipts and the transparency log still verify. Rollback: the previous image cannot read sealed bodies, so roll back only before resealing, or keep the key and roll forward.

**Workflow metrics.** `GET /v1/workflow/metrics` adds a `value` report and `slo` verdicts. Additive.

**MCP estate.** `GET /v1/analysis/mcp-estate` now reports shadow and unused servers from the proxy's audit rows over `?days=` (default 30). `observed_source` changed wording; anything matching on `NOT_SUPPLIED` must be updated.

**Console.** The overview's attention list includes agent requests awaiting a decision and executions with an unknown outcome.

**Dormant modules.** `threat_intel`, `mfa` and `domain/identity` (and, until the streaming change below, `stream_guard`) are classified dormant by `tests_arch/test_component_status.py`; nothing may describe them as product capabilities.

**Cloud proof.** `archive/pre-cleanup:scripts/run_cloud_proof.py` ran the deployed journey on AWS EC2 and removed everything. Harness only; see RISK R-004 for what it does not establish.

## 2026-09-20: two owner decisions implemented

Both were decided by the owner on 2026-09-20 (OWNER_ACTIONS item 7).

**Containment requires a reason and a bounded expiry. BREAKING for API callers.** `POST` activation of a containment now refuses a reason shorter than 8 characters (`reason_required`), a missing expiry (`expiry_required`), an expiry that is not in the future (`expiry_invalid`) and one more than 30 days out (`expiry_too_far`). The rule is enforced in the activation handler only: containments stored before this change still load, list and release. Migration: none. Callers that activate containments programmatically must send both fields before upgrading; the console form already does. Rollback: redeploy the previous artifact; containments created under the new rule remain valid under the old one.

**Incremental MCP streaming, off by default.** `SENTINEL_MCP_PROXY_STREAMING=true` relays `notifications/progress` and `notifications/message` to a client that sends `Accept: text/event-stream` on `tools/call`. Each notification is inspected by the detector that inspects tool results before it is released; after one refusal nothing further is relayed, and the upstream is still read to its response so a known outcome is not turned into an unknown one. Server-initiated requests (`sampling/createMessage`, `elicitation/create`, `roots/list`) are never relayed and are counted in the audit row. The bound runner, the receipt, the inspection of the final result and the audit row are the same code as for a buffered call. `HardenedHttpClient.stream` yields bounded byte strings, not a socket: 64 KiB per event, the policy's response limit in total, 120 s of wall time. Migration: none; the default is the previous behaviour. Rollback: unset the variable.

Evidence: `tests_arch/test_mcp_streaming.py` on SQLite and PostgreSQL 17, against scripted upstreams. Not established: behaviour against any third-party MCP server, behaviour under many concurrent long streams (each holds a worker thread for its duration), and any server that needs sampling or elicitation, which will not work through the proxy.

## 2026-09-24/25: the declared AWS stack applied for the first time, and what it found

The pilot stack (`deploy/terraform/aws`) had only ever been read as text; `terraform plan` had never run because no Terraform binary and no account existed. It was applied on a free-plan AWS account as the new `proof` environment (same stack module, free-tier sizes: single-AZ `db.t4g.micro`, one `cache.t4g.micro`, two Fargate tasks) and the protected-change journey was driven over the load balancer. Sixteen defects were found by the run and fixed, each with a comment naming the run:

**Stack (Terraform).** Two alarms used `count` over a value unknown until apply (the stack could not plan). The task environment lacked an evidence data key, a root-sink region, and enforcement (`SENTINEL_PROTECT_ENFORCE`, `SENTINEL_PROTECTION_MODE`); every task would have refused to start or gated nothing. RDS had retired the pinned PostgreSQL minor. Old task-definition revisions were deregistered under a service that ignores revision changes ("TaskDefinition is inactive"). The task and execution roles' trust condition matched the cluster ARN, which ECS never presents. The execution role could decrypt only the log key, not the key the secrets are sealed with. The application security group permitted egress to 443 only, so the database and cache were unreachable. The database password and the cache auth token were interpolated into URLs without encoding; both generators produced characters that break a URL. The DSN secret followed the password generator while the instance ignored it, so a generator change desynchronised them. Four gunicorn workers with a pool of twenty exhausted a micro database's connection slots.

**Application.** The hardened outbound client refused every public host on a DNS64 network (`64:ff9b::/96`), including STS; it now judges the embedded IPv4 address. The AWS adapter signed global endpoints (STS, IAM) with the configured region; STS answered `SignatureDoesNotMatch` — exactly where RISK R-021 said a documentation-derived signer would be wrong. A PostgreSQL connection error quoted the driver's message, and for an unparseable URL the driver quotes the password; the message is now scrubbed. The image had no writable temp directory under a read-only root filesystem with a root-owned bind mount; `/tmp` is now a declared volume. The S3 root sink knew only static keys; it can now use an ECS task role through the container credential endpoint (documented hosts only, bounded, cached), and a bucket with no credential yields a sink that refuses loudly rather than a service that will not start.

**Evidence** (`docs/current/evidence/local-<sha>/aws-proof-journey.json`, `aws-sts-proof.json`, `tofu-outputs.json`): migration by one-off task; two healthy tasks in two availability zones behind the ALB; secrets injected by the agent and absent from the task definition; managed PostgreSQL 16.11 encrypted and private; managed Valkey with at-rest and in-transit encryption; the evidence bucket with COMPLIANCE object lock under KMS; production mode serving; a tenant policy activated; a protected change pending for a human, invisible to another tenant, refused before approval, executed after, refused on replay; the receipt committed and the bundle verified offline; workflow metrics. Separately, one real `AssumeRole` per operation under the operation's session name, the operation signed with the temporary credential, and CloudTrail settling the outcome as succeeded within two minutes.

**Not established:** AZ-loss survival (single-AZ sizes; `posture.survives_az_loss=false`), TLS (no domain), workload identity on ECS (an API key acted as the agent), root publication to S3 (`SENTINEL_ROOT_PUBLISH_TENANTS` is empty in the stack), cost (no bill yet), the GitHub App path (RISK R-021, still fakes only), CI (RISK R-019). One generated database password was written to CloudWatch by the driver error before the scrub existed; the environment, its log group and the password were destroyed the same day.

Migration: none for existing deployments; the stack changes affect new applies (a second apply of an existing stack keeps its DSN and cache secret versions by design). Rollback: the previous artifact; none of the application changes alter stored data.

## 2026-09-25: developer-preview release artifacts

Built from commit 42eadd9 on one laptop, because GitHub Actions is still held by billing (RISK R-019): the allowlisted source archive (748 files, scanned clean by gitleaks), the Helm chart 0.3.0, the wheel, and the linux/arm64 image as a tarball (0 HIGH/CRITICAL findings, Trivy). Each file is signed with a **locally held cosign key** whose public half is committed as `release/cosign.pub`; verify with `cosign verify-blob --key release/cosign.pub --signature <file>.sig --insecure-ignore-tlog <file>`. This is not the keyless, transparency-logged signature the CI job produces, and no SLSA provenance attestation exists for it. The local release gates passed except `type_check`, which counts 29 known errors outside the blocking `sentinel/domain` scope, and `redis_tests`, which had no Redis. Nothing was deployed.

## 2026-09-26: console theme

The operator console adopts the visual language of the owner's marketing site (joinsentinelai.com): a dark-only canvas (`#050505`), `#0b0b0d` cards with hairline borders and 14px radii, one red accent (`#ff2a1f`), Space Grotesk for titles and JetBrains Mono for data, with system fallbacks because the CSP allows no external fonts. Colours, type and shapes only: the console keeps its own name, copy and structure, and every semantic colour (ok/warn/bad/critical) stays distinct from the accent so a primary button and an error never look the same. No behaviour changed; the bundle tests (no external resources, no inline styles, every nav entry has a view) pass unchanged.

## 2026-09-27: shareable read-only console

**Server.** `SENTINEL_CONSOLE_DEMO_TOKEN` names one key from `SENTINEL_API_KEYS` that the console may publish on its sign-in page, served unauthenticated at `/console/demo.json` (`Cache-Control: no-store`). The service refuses to start if that key's role is anything but `viewer`, so a misconfiguration fails at boot instead of publishing an approver key. The throttle gives a published key one bucket per client address. Tests: `tests_arch/test_console_demo.py` (both refusals, the read/decide boundary, per-address buckets, private keys unaffected).

**Stack.** The ECS task now trusts one proxy hop (`SENTINEL_TRUSTED_PROXY_HOPS=1`); before this, every client behind the load balancer shared one address bucket and the audit trail recorded the balancer's address. `console_demo_enabled` adds an injected secret for the published key.

**Console.** A sign-in screen replaces the header token box; "Explore the live demo" appears only when a key is published; the token is verified before entering; a session badge and sign-out (a page reload) sit in the header; the navigation is grouped. In demo mode the console polls every 30 seconds, states on every view that it is a read-only demonstration with sample data, hides the operator capability diagnostics, and disables decision controls.

**Deployed** on the `proof` environment on 2026-09-27 with a `demo` tenant seeded by `scripts/seed_console_demo.py` through the public API. Verified from outside: `/console/demo.json` publishes the viewer key; it reads (200); approving and containing are refused (403).

**Limits.** Plain HTTP (no domain, so browsers mark it "Not secure"); pending demo requests expire after five minutes by design and the seeder must be rerun to refresh them; the demo keys and the published key live in Secrets Manager (`sentinel/proof/api-keys`, `sentinel/proof/console-demo-token`); the environment costs roughly $40 a month while it stays up. The in-app browser of the Claude desktop app blocks the page's subresources for an unapproved site; ordinary browsers load them.

## 2026-10-13: fuzzer health check, certificate timed out

The Monday scheduled run on `main` failed only in `dynamic-api-security`: schemathesis generated 2,625 cases, all passed, zero findings, and then reported `filter_too_much` health-check errors for three tightly constrained operations (approve, decide, revoke). The same commit had passed the day before; the check is the generator's luck, not the API's behaviour, and is now suppressed while every real check still runs. The merge run for #68 on `main` was cancelled by hand before its suite finished, so `main` has no green run for the connected-applications code until the next push.

**An alarm that could never speak.** `sentinel-proof-transparency-publisher-silent` watched `Sentinel/Transparency RootPublished`, a metric no code emitted; it had been in ALARM since the stack was applied, including after two real publications. The metric is now derived from the service's own `transparency_roots_published` log event by a CloudWatch Logs metric filter in the observability module, so the alarm means what its description says.

The ACM certificate for `app.joinsentinelai.com` expired unvalidated (`VALIDATION_TIMED_OUT`, 72 hours without the DNS records). A new request yields new record values; OWNER_ACTIONS 11 updated.

## 2026-10-12: connected applications — the last mechanism in the product definition

"The connected tool executes the approved request" now holds for any HTTPS business application, not only Kubernetes, GitHub and AWS. An administrator registers the application once (`PUT /v1/apps/<id>`: base URL, allowed methods, allowed path prefixes, and a credential — bearer, header or basic — that is sealed under the evidence data key before it reaches the database and is never returned by any route). An agent asks for `tool=app_call, resource=app://<id><path>` with `{app, method, path, body, query}`; policy decides over the resource as for any tool; execution goes through the same binding (digest, single use, approval). The `app_call` effect refuses unless the authorized resource names exactly the application and path, so an approval cannot be redirected by the arguments; the caller's headers are never forwarded; the request is made with a hardened client pinned to the registered host.

Outcomes are classified honestly: refused before anything was sent (unknown application, method or path not allowed, policy) is a known failure; a 4xx is a definitive rejection; a 5xx or a lost answer on a mutating method becomes `unknown_after_effect` for a person, while on a read it is not-attempted. Without a data key the registry still lists and deletes but refuses to store a secret. Schema version 39 (`connected_apps`, tenant-scoped, forced RLS, configuration rather than log). The inline proxy gained tenant-aware effects (`RegisteredSideEffect.tenant_runner`) so an effect knows which tenant and which authorized resource it serves. `tests_arch/test_connected_apps.py` (both engines) covers sealing, tenant isolation, the full ask → approve → execute-once journey with the credential presented by Sentinel, credential aiming, every outcome class, and the unknown-operation path. Container wiring moved into `advisor_wiring.py` and `app_wiring.py` to stay under the module size limit.

**Live the same day**: deployed to the proof environment (schema 39 migrated by the one-off task, task definition 18). The demo tenant registered `https://httpbin.org` as a connected application and the agent key ran one real call through Sentinel: httpbin's echo shows the exact request Sentinel sent; the receipt was issued; replay, a changed resource and a disguised resource were each refused (`sentinel_program_evidence/2026-10-12-connected-apps/`).

Not established: a credential presented to a real application (httpbin has none; the fake-upstream tests cover it); automatic reconciliation of an unknown outcome for an arbitrary application.

## 2026-10-11: the product definition adopted, and production evidence taken from the live environment

**`docs/current/PRODUCT_DEFINITION.md`** adopts the 9 October business definition as the canonical scope and maps every sentence of it to what is implemented, its evidence and what falls short. The one piece of the definition with no implementation: executing a business application that is not Kubernetes, GitHub or AWS through Sentinel (the general approved web-API call).

**Evidence from the environment that has run since 27 September** (`sentinel_program_evidence/2026-10-11-production-evidence/`): memory flat over 8 days; load balancer p50 2.8 ms / p95 13.5 ms / p99 42.4 ms over 5,104 requests with no 5xx; decision path measured from outside (server-side p95 25 ms); the demo tenant's transparency root witnessed from a laptop, the exported bundle verified offline, a tampered bundle rejected; the rotation checklist exercised on the demo tenant (old keys refused in 2 min 26 s). `PRODUCTION_ACCEPTANCE.md` rows C1, C2, C4, D1, D3, E2 and A14 updated accordingly.

**Stack:** `root_publish_tenants` publishes a tenant's transparency root daily to the object-locked evidence bucket (enabled for `demo`); database deletion protection on. Backup retention could not be raised: the account's free plan refuses more than one day (`FreeTierRestrictionError`); AWS Backup's seven daily recovery points remain. After the key permission landed, the service published the demo tenant's root at size 16 to the object-locked bucket (COMPLIANCE, retained until 2036-10-08) on its first start and reports it independently verifiable; the publisher-silent alarm had been the only one in ALARM. The task definition was being replaced on every plan because the provider now reports `enable_fault_injection` and the volume's `configure_at_launch`; both are now stated explicitly.

Not established: anything requiring a customer, another region, an assessor, or a person on the alarm topic (OWNER_ACTIONS 13, 14).

## 2026-10-05: one tool definition for GPTs and the cloud agent platforms

`docs/integrations/sentinel-agent-tool.openapi.json` (OpenAPI 3.1, two operations: `checkAction`, `executeApprovedAction`) is what a custom GPT's Actions, a Bedrock Agents action group, an Azure AI Foundry / Copilot Studio OpenAPI tool and a Vertex AI Agent Builder OpenAPI tool import. `archive/pre-cleanup:scripts/build_agent_tool_spec.py` derives the request schemas from the running application's own models, narrowed to the fields an agent should fill, and refuses to name a field the route does not have; `--check` fails on drift. `tests_arch/test_agent_tool_spec.py` drives the real routes with only what the document offers through the whole journey on both engines. `docs/INTEGRATIONS.md` has the per-platform steps and the instruction text.

Not established: the document imported into any of those platforms (no account used; all of them require HTTPS, which waits on the owner's DNS records). Stated in the guide: the gate is asked because the assistant's instructions say so; it does not stop an assistant that skips the call unless its consequential tools are reachable only through Sentinel.

## 2026-10-04: nothing is published, and a name collision on PyPI

Checked at the owner's request ("no SDK of any language published"): this project is on no package registry. npm has no such package; the repository is private and its release assets answer 404 without a login; no workflow publishes a package; image publishing is a manual opt-in that has not been used; the deployment exposes no API description without a key.

**A package named `sentinel-agent-trust` — this project's own package name — exists on PyPI**, three releases uploaded 14-16 July 2026 by a different publisher, described as a client SDK for "Sentinel AI". The README told readers they could `pip install "sentinel-agent-trust[server]"`, which would have installed that package, not this code. The instruction is removed and replaced with a warning. Whether to rename this project's package is an owner decision (RISK: dependency confusion and a name/trademark conflict).

What IS reachable by anyone with a link: the Windows scanner app (the owner's request) and, through the public demo's read-only key, the scanner's Python source via the console's download button.

## 2026-10-04: three wire bugs in the Python SDK

**The Python SDK could not perform a bound execution against a real server, and nobody knew.** `scripts/smoke_sdks.py` starts a real Sentinel and runs one journey through `SentinelClient` (allow, require approval, refused before approval, approve, execute once, replay refused, wrong key is no decision). Its first run failed, and the cause was in `sentinel/sdk/remote.py`:

* `execute` sent `authorization` as `{"token": ...}` (the shape the gate RETURNS); the route declares a string and answered 422.
* `execute` always sent `trustLevel`, which the route refuses outright since trust became credential-derived.
* `check` placed `tool` and `arguments` inside `metadata`; the route binds the authorization to the TOP-LEVEL `arguments` only, so the policy was shown an empty argument set and the authorization committed to the digest of nothing.

Every SDK test used a fake transport, which accepts anything. All three are fixed; `tests_arch/test_sdk_remote.py` now validates what the client sends against the real routes' pydantic models and runs the live journey. The adapters (`openai_agents`, `anthropic`, `gemini`, `langchain`) call through the same client and inherit the fix; none has been run against its real framework.

A JavaScript/TypeScript client was drafted alongside (it is what first exposed the bugs) and removed at the owner's instruction before merge; there is no JavaScript SDK in this repository.

**HTTPS.** A certificate for `app.joinsentinelai.com` is requested in ACM (ap-south-1) and is waiting on the owner's DNS records; the provisioning role gained ACM-only permissions for this.

**Live smoke of the AWS deployment** the same hour: console, liveness and readiness 200; the published key is refused a decision (403); no key is refused (401); a freshly seeded incident's report carries the `antigravity-cli:gemini-3.1-pro-high` note.

Not established: a person using the app on their own Windows PC; the Windows install-folder list against real installed tools; either app signed.

## 2026-10-03 (runbook)

`docs/current/DEMO_RUNBOOK.md`: how the owner prepares and gives the demo, a minute-by-minute script using the console's real view names, how to show a live approval locally, what to send people, how to run it for a partner, and the gaps between an invited preview and a public launch. `scripts/try_sentinel.py --demo` loads the sample story into the local trial. `TRY_SENTINEL.md` named two views that do not exist (*Protected changes*, *Incidents*); corrected to the console's labels. First fully green hosted run on `main` since mid-September: run 37117421791, all 18 jobs.


Not established: either app signed or notarised (both show an operating-system warning on first open; signing needs the owner's Apple Developer ID and a Windows certificate); the Windows app opened on a real Windows desktop; the Windows folder list checked against real installs; a public download location.

## 2026-10-03 (CI, first hosted runs since the allowance reset)

GitHub ran the workflow for the first time since 25 September and found three things the local recorded suite could not:

* `tests_arch/test_evidence_recovery.py` read `SENTINEL_TEST_POSTGRES_DSN` directly. The local run always sets it; the hosted suite job uses the embedded server and does not, so the test died with `KeyError`. It now takes the administrator DSN from the session fixture.
* The kind smoke never created the `sentinel-data-key` secret the chart has required since evidence sealing; the pod sat in `CreateContainerConfigError` and the probe saw a closed port. The job now generates one.
* `release-hygiene` could not install: the workflow named `build==1.2.2` while `requirements-dev.txt` pins `build==1.6.1`. The duplicate pin is gone. Its lock check would have failed next for a reason unrelated to this repository (indirect dependencies released upstream); it now compiles seeded with the committed lock, so it fails only when `requirements.txt` and the lock disagree. The job's build, chart packaging, allowlist/secret scan and clean-install smoke were run locally and pass.
* The pinned MinIO image is no longer published (`unauthorized` from quay.io and Docker Hub with a valid anonymous token). The job attempts the pull and, when refused, emits a named warning and skips the round-trip instead of failing. **The live S3-compatible round-trip therefore does not run in CI** until another signature-verifying server is pinned; a SeaweedFS replacement was started and not validated (its image would not download on the developer network).

## 2026-10-03 (later): a tester's path, scanner v2, and a host for the brain on AWS

**Tester's path.** `docs/current/TRY_SENTINEL.md` and `scripts/try_sentinel.py`: one command creates a trial directory with fresh keys and SQLite, migrates, optionally scans the device and imports the report, and serves the console on localhost (where operator sign-in is allowed). Run end to end on the developer's Mac.


**Brain on AWS.** `SENTINEL_PIPELINE_WORKERS` (0–32, default 4) makes a replica API-only at zero. The stack's `brain_host` variable adds one instance (no public address, no inbound rule, no key pair, IMDSv2 hop limit one, encrypted volume) that mirrors the ECS task definition — image digest, environment, secret references — and runs it as the pipeline replica with the advisor CLI mounted read-only; Fargate replicas then run zero pipeline threads. The module downloads no third-party software: an earlier draft fetched the vendor's installer at boot and was withdrawn, because an unverified, self-updating binary on a host that can read the service's secrets is the owner's decision to make by hand, not a bootstrap's. `SENTINEL_ADVISOR_CLI_HOME` separates the CLI's sign-in directory from the process's HOME. Verified locally that the Linux arm64 CLI runs inside the unmodified hardened image (read-only root, uid 10001) and reports "please sign in".

**Applied on the proof stack the same day**: instance `sentinel-proof-brain-host` (t4g.small, private subnet, no public address), task definition 16 with zero pipeline threads on Fargate. The seeded incidents were processed by the brain host and each report states `the advisor CLI could not be started: FileNotFoundError` — the accurate state until the owner installs and signs in to the CLI there (OWNER_ACTIONS 12). The AMI is found by name through `ec2:DescribeImages`; the first plan used the public SSM parameter, which the provisioning role cannot read.

**The owner installed and signed in to the CLI on the brain host the same day** (Session Manager; the vendor's installer run by hand). A sample event sent to the demo tenant produced, 23 seconds later, an incident report whose advisory section names `antigravity-cli:gemini-3.1-pro-high` and carries its stamped reasoning (`sentinel_program_evidence/2026-10-03-advisor/aws-brain-incident-report.md`). One event, one note: latency, quota and behaviour under volume are unmeasured.

Not established: the scanner on Windows or Linux desktops (logic is tested with synthetic homes; only macOS was run for real); a packaged installer — the scanner is a Python file and needs Python on the device.

## 2026-10-03: the advisory brain gets a socket, a proof command and a stack variable; CI fits the free allowance

**Advisor on the stack.** `advisor = { endpoint, model }` on the stack module and the proof root. When an endpoint is named the stack creates the `advisor-token` secret and injects `SENTINEL_ADVISOR_ENDPOINT/_MODEL` (environment) and `SENTINEL_ADVISOR_TOKEN` (secret). The service's all-or-none rule still holds, so the owner fills the secret BEFORE the service rolls, or the task refuses to start and the circuit breaker rolls back. Any OpenAI-compatible chat-completions provider fits; Gemini's is `https://generativelanguage.googleapis.com/v1beta/openai`. The advisor stays advisory by architecture: its text reaches `advisory_*` facts and the incident report's *Reasoning* line, never priority.

**Standalone advisor-check CLI removed in Phase 2.** Its historical implementation is recoverable from `archive/pre-cleanup`. Service advisory output and credential isolation remain covered by `tests_arch/test_cli_advisor.py`.

**Antigravity CLI as the advisor** (`sentinel/infrastructure/cli_advisor.py`, `SENTINEL_ADVISOR_CLI_COMMAND` + `SENTINEL_ADVISOR_MODEL`, mutually exclusive with the endpoint form). Runs the locally signed-in `agy` once per incident in print mode, the way the owner's other project consults it, with the differences a security product needs: no `--dangerously-skip-permissions`, `--sandbox`, `--disable-slash-commands`, an empty per-call working directory, a child environment of HOME and PATH only (the service's keys and DSN are not inherited), the prompt on stdin rather than argv, a two-minute timeout, and the same shape validation and `[unverified-model-output]` stamp as the HTTP adapter. An agent CLI reading hostile text is still an agent; the control remains that the advisor cannot move triage. Proven locally end to end with Gemini 3.1 Pro (`sentinel_program_evidence/2026-10-03-advisor/`). `tests_arch/test_cli_advisor.py`.

**Advice survived only in memory.** `ctx.advice` was set during detection, but the evidence, report and approval steps run in a later execution with a fresh context, so every report said "Not consulted" even when the advisor had answered. The advisory facts (now including `advisory_reasoning`) are the durable copy and the later steps rebuild the advice from them. Found by the first real end-to-end run with a live advisor; no test had a live advisor AND a multi-execution pipeline.

**Known cost.** The advisor is called inside the pipeline's unit of work. A CLI answer takes 10-60 seconds, during which SQLite serialises other writers behind it and PostgreSQL holds the incident's transaction open. Acceptable for a pilot's volume; moving the call outside the transaction is the next change if volume grows.

**Approval context fix.** `advisory_summary` on an approval record read `advice.summary`, a field `ModelAdvice` never had, so it was always empty; it now carries the model's note (or its unavailability reason), capped at 1 KiB.

**CI budget.** Every job of every run since 26 September was refused by GitHub ("recent account payments have failed or your spending limit needs to be increased"): a private repository on the free plan has 2,000 Linux minutes a month and the workflow spent them (17 jobs, ~40 minutes, rounded up per job, 28 runs). Pull requests now run the gate (suite on both engines, types, security, verification, licences, image build, deployment manifests); pushes to `main`, a Monday schedule and manual dispatch run the full set including the seven live-service, kind, guard-mutation and dynamic-security jobs. The repository stays private.

Not established: a live advisory call from the AWS deployment (Fargate tasks have no `agy` and no signed-in account; a CLI advisor needs a host where the owner has run `agy` and signed in, as on the owner's other project's EC2 host); CI green on GitHub (the allowance resets on the billing cycle, not on a code change).

## 2026-09-29: pilot onboarding — consented local discovery, a pilot setup view, an advisor slot

Written to answer "people download the product, it asks permission, and the dashboard shows the AI on the computer". What ships is exactly that and no more; the distinction between *found*, *observed* and *enforced* is stated on every surface.


**Server** (`/v1/pilot/*`, migration 38, `device_discovery` table, tenant-scoped with forced RLS). An administrator previews a report in the console, ticks consent, and imports it; viewers list it; administrators delete it. Imports are validated strictly and rejections never echo the submitted values; reports are capped at 32 KiB and 1,000 devices per tenant. Every stored row is marked `trust: self_reported, enforced: false`; importing never enrols an agent or grants a tool access.

**Advisor slot** (`SENTINEL_ADVISOR_ENDPOINT/_MODEL/_TOKEN`, all three or none, HTTPS only, token excluded from repr). Wires the existing `HttpModelAdvisor`; it adds investigation notes and holds no authority. The control path remains the deterministic policy.

**Console.** New *Pilot setup* view (the default for operators): status, limits, the five-step acceptance journey, download → run → preview → consent → import. Sign-in now refuses a rejected credential and, on a remote plain-HTTP page, refuses private sign-in altogether — the public read-only demo still works there. A customer pilot therefore needs an HTTPS domain and certificate on the load balancer (`certificate_arn` in the proof root; RISK R-004's TLS clause).

**Stack.** `mcp_proxy` variable (off by default; enabling requires explicit upstream host names) and `certificate_arn` exposed on the proof root. Not applied with the proxy on.

**Test harness.** `_with_credentials` and `_with_dbname` in `tests_arch/conftest.py` now strip `user`, `password` and `dbname` from the DSN query: libpq lets query parameters override URI userinfo, so an admin DSN carrying `?user=postgres` would have run the row-level-security suite as a superuser and passed it vacuously.

**What the full recorded suite found in the pilot work, and the fixes** (same day). Three architecture guards failed on the first full run (`full-suite-c7e0588-FAILED.run.xml` in `sentinel_program_evidence/2026-09-29-pilot-onboarding/`): `/console/demo.json` was reachable without a declared capability and not on the reviewed public list — it is now listed with its reason (a published viewer key is the feature, the boot-time role check and the per-address throttle are the guards); `device_discovery` was neither reaped nor declared append-only — it is now REAPED by the retention sweep on `received_at`, because a report is a dated snapshot of one machine and a device that stopped reporting must stop being listed; and migration 38 applied RLS by naming the table rather than through `_apply_rls` over `PROTECTED_TABLES` — corrected, same effect, provable by the guard. On AWS the first rollout of the pilot image was rolled back by the ECS circuit breaker because the service refuses to serve a schema at version 37 when the build requires 38 (fail closed, as designed); the migration was run as a one-off Fargate task on the new task definition and the second rollout completed.

Not established: any run of the discovery companion on a customer machine; the advisor against a real model endpoint; the MCP proxy on AWS; HTTPS on the deployment.
