# Production acceptance

A deployment of Sentinel is accepted for the first workflow only when every
condition in this document is met by the named evidence. Each row states
whether the evidence exists at the commit in `STATUS.md`. A row
with "no evidence" is not a soft pass.

Conditions are grouped by what they protect. Targets marked *proposed* have
not been agreed with a customer and are the program's own; they become
binding when a design partner signs the engagement.

Authorized scope: local and GitHub only; first workflow is an approved Kubernetes infrastructure change for midmarket SaaS/fintech infrastructure teams. All “met (tested)” entries below refer to test behavior and require a matching passed report in RELEASE_STATUS; they are not independent or customer observations.

## A. Execution control (the promise itself)

| Condition | Evidence | Status at this commit |
|---|---|---|
| A1. An unbound execution never runs a side effect | `tests_arch/test_execution_contract.py` on SQLite and PostgreSQL; `scripts/smoke_clean_install.py` step `server.unbound_execute_refused` | met (tested) |
| A2. Substitution of agent, tool, resource or parameters after authorization is refused and recorded | same, the `parameters/tool/resource/agent` cases | met (tested) |
| A3. Replay of a redeemed authorization is refused | `test_an_allowed_action_executes_exactly_once` | met (tested) |
| A4. Expiry, revocation, policy change and kill switch refuse by name | `tests_arch/test_execution_contract.py` | met (tested) |
| A5. An approval satisfies `require_approval` under enforcement and never `block` | `test_approval_flow_evaluate_pending_approve_execute`, `test_an_approval_never_satisfies_a_block` | met (tested) |
| A6. Same-named agents in two tenants share no control state | `test_same_named_agents_in_two_tenants_have_separate_budgets`, `test_a_breaker_opened_in_one_tenant_stays_closed_in_the_other` | met (tested) |
| A7. A post-effect storage failure yields a reconcilable unknown, never a silent error | `tests_arch/test_operation_store.py` | met (tested) |
| A9. The agent is an attested workload and an API key cannot act as one | `tests_arch/test_workload_identity.py`; `tests_arch/test_protected_change_journey.py` | met (tested); off by default, no customer issuer (RISK R-016) |
| A10. The target refuses changes that did not come through Sentinel | `deploy/protected-changes/`; `tests_arch/test_protected_change_journey.py` | met on a local API server; CNI, DELETE and non-Kubernetes targets open (RISK R-017) |
| A11. The executing credential is minted per operation and the stored credential can change nothing | `tests_arch/test_kubernetes_outcome.py` | met (tested) |
| A12. A lost response is settled from the target without a second write | `tests_arch/test_kubernetes_outcome.py`; the journey test | met for Kubernetes only (RISK R-012) |
| A13. Approvers see the redacted change; quorum and separation of duties hold | `tests_arch/test_approval_experience.py` | met (tested) |
| A14. Receipts verify offline against a root held outside the environment | `tests_arch/test_evidence_commitments.py` | met for the demo tenant: root witnessed from the developer's laptop, 14/14 receipts verified offline, a tampered receipt rejected (`2026-10-11-production-evidence/`); root at size 16 published 2026-10-11 to the object-locked evidence bucket (COMPLIANCE, retained until 2036-10-08), reported `is_independently_verifiable: true` (RISK R-018 narrowed: the copy is outside the database but inside the same AWS account) |
| A8. All of A1 to A7 and A9 to A14 observed on a real tenant's traffic for 30 days | `docs/current/evidence/production/<tenant>.json` | no evidence |

## B. Tenancy and data

| Condition | Evidence | Status |
|---|---|---|
| B1. Forced row-level security on every tenant-scoped table on PostgreSQL | `tests_arch/test_tenant_isolation_rls.py`; `PROTECTED_TABLES` in `sentinel/infrastructure/sql/schema.py` | met (tested) |
| B2. Schema fingerprint pinned to the migration version | `tests_arch/test_sql_infrastructure.py` | met (tested) |
| B3. Retention never reaps pending or unknown operations | `sentinel/infrastructure/sql/retention.py`; `tests_arch/test_retention_sweep.py` | met (tested) |
| B4. Backup and point-in-time restore proven in an independent failure domain | `docs/current/evidence/dr/` | no evidence (local drills only: `archive/pre-cleanup:docs/dr_postgres_wal_pitr_drill.json`) |

## C. Availability and performance (proposed targets)

| Condition | Target | Evidence | Status |
|---|---|---|---|
| C1. `POST /v1/protect/evaluate` latency | per `config/performance_targets.json`, measured in CI on the runner | `docs/authorization_bench.json` with provenance sidecar; live: `sentinel_program_evidence/2026-10-11-production-evidence/decision-latency-aws.json` | live AWS environment, server-side, one hour of demonstration traffic: p50 15 ms, p95 25 ms, p99 39 ms (target p95 50 / p99 100); not a capacity measurement |
| C2. Decision-path availability | 99.9% monthly *(proposed)* | tenant probe plus Sentinel metrics | 7 days of load-balancer metrics: 5,104 requests, 0 target 5xx, 0 unhealthy-host minutes (`aws-operations-8-days.json`); no probe from outside the environment yet |
| C3. Shared limiter and controls across replicas | required in production by `sentinel/interface/asgi.py` topology check | `tests_arch/test_runtime_topology.py`; `test_budget_and_breaker_are_shared_across_two_pools` | met (tested) |
| C4. Memory flat under tracing and metrics for 24 h | observability soak with `SENTINEL_OTLP_ENDPOINT` set | `aws-operations-8-days.json`: 8 days, 314–337 MB per task, no growth | met on the live environment without OTLP export configured; the bounded exporter itself remains unsoaked (RISK R-007, R-008) |

## D. Supply chain and release

| Condition | Evidence | Status |
|---|---|---|
| D1. Artifact contents allowlisted; no secret-shaped content in what ships | `release-hygiene` CI job; `tests_arch/test_release_hygiene.py` | met: the CI job passes on `main` since 2026-10-03 |
| D2. Dependencies hash-pinned and installed with `--require-hashes` | `requirements.lock`, `Dockerfile` | met |
| D3. Clean install works: thin SDK loads only the standard library; server migrates, serves, decides, refuses unbound execution | `scripts/smoke_clean_install.py` report | met: runs in the `release-hygiene` CI job on `main` |
| D4. Image signed with a verifiable identity | `sign-image` CI job (opt-in) | no evidence until publishing is enabled |
| D5. Independent security assessment | `docs/current/evidence/external/` | no evidence |

## E. Operations

| Condition | Evidence | Status |
|---|---|---|
| E1. Every configuration surface names only variables the code reads, and names every production-required one | `scripts/check_config_alignment.py` exit 0 in CI | local parser/lint and limited two-pod deployment pass; full production topology and CI unverified (RISK R-009) |
| E2. Rotation checklist exists and was exercised once | `docs/current/INCIDENT_ROTATION_CHECKLIST.md` | exercised on the demo tenant 2026-10-11 (`demo-key-rotation.json`): keys rotated, old refused, new accepted, 2 min 26 s |
| E3. Fail-closed exceptions each have owner, scope, expiry, metric | `docs/current/DECISION_LOG.md` | incomplete: role owners are recorded; accountable named owners, expiry and customer approvals require review |
| E4. Rollback plan per release-impacting change | `docs/current/RELEASE_GOVERNANCE.md` | see that document |

## Sign-off

Acceptance requires every condition above, no unresolved P0/P1 workflow defect, an independently assessed release, verified signatures on the delivered artifacts, fault-tested multi-replica identity/storage/telemetry controls, and completed paid design-partner workflows. Three paid design partners is the proposed cohort; none is evidenced here. CTO and CISO sign-off must identify accountable people and the exact release. Until then the deployment status is **developer preview with
tested execution control**, which is the phrase to use externally.

## 2026-09-19 local deployment and remaining blockers

A local kind cluster exercised two gateway pods, shared Redis, non-superuser PostgreSQL, chart secret injection, migration and the archive-settings hook. Replay across pods and cross-tenant reuse were refused; both pods returned HTTP 429 during a Redis outage. Separate in-process HTTP tests drove actual scoped Kubernetes ConfigMap mutations, including approval, replay, concurrent updates and replacement. These two tests are distinct scopes and must not be combined into a claim of a fully deployed production workflow.

The local shape skips the production Helm schema for two replicas on one node with no service mesh. NetworkPolicy objects exist, but CNI enforcement is unverified. First-party container scans found unresolved high OS-package advisories (R-015). Production acceptance remains withheld; available patches, validated exceptions or a reviewed alternative runtime are required alongside the pre-existing independent-assurance, recovery, identity and paid-pilot gates.

## 2026-09-20 image gate and CI

The image moved to a minimal digest-pinned base and the local Trivy gate reports no HIGH or CRITICAL finding (RISK R-015, mitigated, not closed). D4 and D5 are unchanged. No CI run has executed since 2026-09-15 because of the hosting account's billing state (RISK R-019), so every "met" above is a local result on one machine.
