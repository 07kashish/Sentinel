# Release status

 This snapshot binds the listed evidence to its recorded inputs and artifacts. Local results are not CI, production or independent-assessment evidence.

- commit: `b8cbd8fbc2be07291ca2520850a7cd7ef3949d04` on `program/production-readiness` (DIRTY working tree: this snapshot describes uncommitted changes)
- legacy Python-source sha256: `66c326c80b8d05018d0756d73e30ea4b6e3048ad9513277733742f2880fa81a5`
- release inputs sha256 (code, tests, policy, packages, deployment): `62a3876a6c6357e65e538510546e4c66197ae4e163038613225d3fa331326a44`
- accepted test reports: 1; collected counts alone grant no tier
- generated: 2026-10-12T18:08:38.948337+00:00
- tests collected: **4609** (688 parametrised on PostgreSQL)

## What this document will not say

It will not say *production-ready*, *market-leading*, *compliant*, *secure*, *superior to a named competitor*. Each of those needs evidence that does not exist in this repository at this commit. The tiers below are the evidence that does.

## Evidence tiers

| Tier | Means | Evidence source |
|---|---|---|
| implemented | the modules exist | file on disk |
| unit_tested | mapped tests executed successfully on these exact inputs | verified JSON + JUnit digest from `archive/pre-cleanup:current_test_evidence.py` |
| integration_tested | mapped PostgreSQL cases executed and passed on these inputs | verified JSON + JUnit outcomes; does not certify a deployment |
| production_observed | verified real-tenant observation | unverified; unsigned sidecars do not qualify |
| externally_verified | verified independent assessment | unverified; assessor identity and attestation intake required |

| Tier | Capabilities |
|---|---:|
| not_implemented | 0 |
| implemented | 0 |
| unit_tested | 4 |
| integration_tested | 12 |
| production_observed | 0 |
| externally_verified | 0 |

## Capabilities

| Capability | Tier | Collected (PG) | Passed (PG) | CI jobs configured | Limits |
|---|---|---|---|---|---|
| **Execution authorization and binding** | integration_tested | 165 (55) | 164 (55) | test, live-postgres | Bound to tenant, agent, tool, action, resource, parameter digest, policy digest, expiry and single-use nonce. The agent can be an attested workload (see Workload identity); that is off until a customer issuer is registered. |
| **Approval semantics under enforcement** | integration_tested | 109 (44) | 109 (44) | test, live-postgres | A recorded approval satisfies require_approval only; never step_up_auth, block or contain. Approvers see a redacted structural view of the change. A quorum of distinct approvers and requester/approver separation are enforced. No integration with an external ticketing or paging system. |
| **Durable intent and outcome, reconcilable unknown state** | integration_tested | 146 (51) | 146 (51) | test, live-postgres | A definitive target rejection is a recorded failure; a lost response is unknown and is reconciled from the target automatically for the Kubernetes tool, with bounded attempts and a quiescence window. GitHub contents writes and deletes are reconciled from the blob sha without attribution; AWS operations run under a brokered role session are reconciled from CloudTrail by session name, where absence of an event is never read as failure; GitHub POSTs, other PUTs, AWS data events and AWS without a brokered role still need a human (RISK R-012). For GitHub and AWS a 4xx is now a recorded failure instead of a succeeded operation. |
| **Shared, tenant-scoped budget and circuit breaker** | integration_tested | 86 (41) | 86 (41) | test, live-postgres | State lives in the database with a row lock; fails closed when the store is unavailable. Not yet load-tested across more than two pools. |
| **Workload identity for agents** | integration_tested | 62 (12) | 62 (12) | test | SPIFFE JWT-SVIDs and pod-bound Kubernetes service-account tokens are verified against registered keys; SENTINEL_REQUIRE_WORKLOAD_IDENTITY refuses API keys on the agent path. Keys are pinned or fetched from a stated or DISCOVERED https jwks_uri (OIDC metadata, which is how SPIRE, Okta and Entra publish keys) with rate-limited rotation that keeps the last good keys; the SPIRE Workload API itself is not spoken. A pod-bound token was accepted from a real agent pod on a local cluster. Default is off (DECISION_LOG FCX-006). No customer identity provider has been integrated. |
| **Constrained credentials and bypass prevention** | integration_tested | 70 (10) | 70 (10) | test | Sentinel holds a broker token that can only mint ten-minute tokens for one executor account; the API server refuses agent writes and unstamped executor writes in protected namespaces. Deletes are stamped on the object and admission requires the stamp. Proven in-process against a real API server and DEPLOYED (two pods, production mode, pod-bound agent token, kindnet enforcing the agent egress policy) by scripts/run_deployed_journey.py on one local node. The deployed run uses TLS between agent and Sentinel under a private CA. A cloud cluster, another CNI, mutual TLS and a customer are unverified. AWS gets a fifteen-minute role session per operation and GitHub a per-call App installation token scoped to one repository and permission family; both are tested against fakes only, never against the real services, and neither has a target-side bypass control like the Kubernetes admission policy. |
| **Workflow measurement** | integration_tested | 17 (3) | 17 (3) | test | Approval latency, interruptions, refusals and unknown outcomes are counted from records with sample sizes. Gateway overhead, refusal legitimacy and onboarding effort are not derivable from records and are named as such. scripts/run_workflow_loadtest.py measures the bound path on one machine as a regression baseline, not a capacity claim. No customer data exists. |
| **Tenant isolation in storage** | integration_tested | 138 (41) | 130 (41) | test, live-postgres, live-postgres-service | Forced row-level security on PostgreSQL; explicit tenant predicates on SQLite. Operational telemetry omits tenant/agent identifiers; durable records are tenant-scoped. Per-pod aggregation and soak remain unverified (RISK R-008). |
| **Execution receipts and Execution Passport** | integration_tested | 128 (29) | 128 (29) | test, verification | Receipts are committed to the tenant transparency log by the maintenance loop and export as a bundle that verifies offline with the standard library. Commitment is asynchronous; the export reports the uncommitted count. Evidence BODIES are sealed per record (AES-256-GCM envelope, bound to tenant and incident) when a data key is configured, production refuses to start without a key or an explicit opt-out, and rotation rewraps without decrypting payloads; keys come from the environment or a Kubernetes secret, not yet from a KMS. A customer can witness roots with a standalone tool that verifies consistency locally, and a drill restores evidence into a new database and verifies an old bundle against the customer-held root. One host: not an independent failure domain (RISK R-003); no customer runs the witness (RISK R-018). |
| **Coverage model (observed vs routed vs enforced)** | integration_tested | 69 (34) | 69 (34) | test | Reports counts per tenant and refuses to combine them into a percentage. Bypass signals depend on the endpoint sensor being deployed. |
| **Deterministic policy and policy versions** | unit_tested | 42 (0) | 42 (0) | test | Deterministic rule contents and active tenant policy bind authorizations. Tenant policy can tighten the baseline; ML remains advisory. The optional classifier is repository-only (RISK R-010) and its corpus is curated (RISK R-005). |
| **MCP tool gateway** | integration_tested | 180 (74) | 180 (74) | test | Pinned tool definitions and drift detection. Shadow and unused servers are derived from the proxy's audit rows, which include refused calls to unenrolled servers; traffic that bypasses the proxy is invisible to it. With SENTINEL_MCP_PROXY_STREAMING (off by default) progress and log notifications are relayed incrementally on tools/call, each inspected before release and bounded per event, in total and in time; server-initiated requests (sampling, elicitation, roots) and the standalone GET stream are never relayed. Streaming has been exercised against scripted upstreams only, not a third-party MCP server. |
| **SIEM export** | unit_tested | 48 (0) | 48 (0) | test | Syslog, OTLP and webhook sinks with per-tenant configuration. No named-vendor certification; no real tenant has consumed the export (RISK R-001). |
| **Backup, restore and point-in-time recovery** | unit_tested | 44 (6) | 26 (0) | test | Local test and historical drill evidence does not establish independent failure-domain recovery (RISK R-003). |
| **Deployment configuration and operational telemetry** | integration_tested | 80 (13) | 79 (5) | docker, kind-helm-smoke, deployment-validation | Local chart/settings, OTLP HTTP and separately retained two-pod kind smoke evidence. The image moved to a minimal digest-pinned base and the local vulnerability gate reports no HIGH or CRITICAL findings; CI and a published, signed image have not confirmed it (RISK R-015). archive/pre-cleanup:scripts/run_cloud_proof.py ran the whole deployed journey on an AWS EC2 host (ap-south-1, Ubuntu 24.04, k3s with containerd, flannel plus kube-router policy) and removed it; that is a real cloud host and a second Kubernetes distribution and network plugin, NOT the declared topology: no managed PostgreSQL or Redis, load balancer, object store, second node or IAM integration. Collector TLS, the Terraform topology and soak remain unverified. Actions held until 2026-10-02. |
| **Release hygiene** | unit_tested | 79 (0) | 79 (0) | release-hygiene, security | Allowlisted artifact contents, secret scan that never echoes, hash-pinned lock, clean-install smoke with a thin SDK. Image signing is opt-in and unverified until publishing is enabled. |

## External gates with no evidence at this commit

- independent security assessment (RISK R-002)
- production observation by a real tenant (RISK R-001)
- independent-failure-domain disaster recovery (RISK R-003)
- applied cloud environment (RISK R-004)
- blind detection evaluation (RISK R-005)

## Artifacts this status was generated against

None were passed. Run with `--artifact dist/<wheel>` in the release job to bind the status to what shipped.

## Historical documents

Everything under `docs/` outside `docs/current/` predates this status and is not bound to a commit. Treat it as history: useful for why a decision was made, not for what is true now. `docs/current/README.md` lists what is current.
