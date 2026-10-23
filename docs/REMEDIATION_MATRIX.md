# Remediation Matrix — Eighth Review F-1..F-12

CLOSED requires automated tests executed against this tree.
Do **not** conflate with `docs/SECURITY.md` F-numbers (different scheme).

## Session 2026-08-18/19 — what changed, and what did not

No F-row's status changed this pass. F-4 remains **PARTIAL**, and the
access-blocked rows were not touched: they need a human decision or human
infrastructure access, not code, and any document claiming otherwise is a defect
by this matrix's own F-4 precedent.

One of those three did resolve itself, and honesty requires saying how: the
**kind/Helm cluster smoke passes in CI** and always could have — it was recorded
as unverified partly because `gh` was unauthenticated and the job's history was
unreadable from here. Authenticating `gh` to read CI logs was enough to see it
green. The blocker was partly the absence of tooling on this machine and partly
the absence of a way to look.

What this session did produce is a defect of the same *class* as F-4 — a claim of
evidence with no executed command behind it — found in a different document, plus
one measured functional defect in a gate row that had been marked `pass`:

| Finding | Where | Evidence |
|---|---|---|
| **The retention sweep deleted nothing on PostgreSQL** and reported zero rather than failing. Unscoped pooled connection under `FORCE ROW LEVEL SECURITY`; `tenant_id = NULL` matched no rows. Same shape as the `delivery_queue` defect the codebase documents. | `sql/retention.py` | Probe: `before: work_queue = 1 → sweep reported 0 → after: work_queue = 1`. Fixed per-tenant; `test_retention_sweep.py` now runs on both engines and asserts `before − after == reported` |
| **Three artifacts cited as existing evidence did not exist**: `test_tenant_isolation_is_enforced_by_the_real_database`, `test_every_table_is_either_reaped_or_declared_append_only` (and `APPEND_ONLY_TABLES`), and `tests/test_failure_classes_are_structural.py` (no `tests/` directory). | `docs/SECURITY.md` | Searched for; absent. Retraction recorded at the top of that document. The first two now exist and pass; **the third is still absent and its claim is withdrawn** |
| **`domain_events` had no index on `(tenant_id, incident_id)`** in the live schema, making the per-incident read and the new retention delete sequential scans — i.e. a retention job that degrades quadratically in the history it exists to bound. | `sql/schema.py` | `ix_events_incident` added; migration 12 |
| **`webauthn_challenges` was unbounded**: ships `ix_challenges_issued(issued_at)`, an index whose only purpose is an age purge, with no caller. Same signature as `ix_inbox_age`/`ix_nonces_expiry`. | `sql/schema.py` | Found by the new declared-or-reaped gate; now swept |
| **`tests_arch/conftest.py` handed out a PostgreSQL DSN before the server accepted connections**, producing 13 unrelated failures on a loaded machine. | `tests_arch/conftest.py` | `FATAL: the database system is not yet accepting connections`; readiness wait added |
| **`test_retention_sweep.py` inserted the string `'HIGH'` into an `INTEGER` column** — accepted by SQLite's dynamic typing, rejected by PostgreSQL. One of several ways that file was only ever a SQLite test. | `tests_arch/test_retention_sweep.py` | `InvalidTextRepresentation: invalid input syntax for type integer: "HIGH"` |
| **The PostgreSQL half of the test suite had never run in CI.** `_fresh_database` built its DSN by string-slicing, which works on the TCP DSN Windows produces and corrupts the Unix-socket DSN Linux produces — the last `/` is inside the `host=` query parameter. Green locally, erroring on every push. | `tests_arch/conftest.py` | `connection to server on socket ".../sentinel_3ba8d0396f45/.s.PGSQL.5432" failed: No such file or directory`. Now parses the URI; `test_dsn_rewriting.py` (7 tests) exercises both shapes on any platform |
| **Pre-authentication XML denial of service in the SSO path.** `SamlValidator.validate` parsed an attacker-supplied assertion with `xml.etree.ElementTree` *before* it could check the signature, and ElementTree expands internal entities. | `sentinel/infrastructure/saml.py` | Measured: 3 nested entities, ~30 bytes in → 1000 characters expanded. Fixed with `defusedxml`, explicit `forbid_dtd=True`, 512 KB cap; `test_saml_xml_hardening.py` (8 tests) |
| **A permanently-failing static scan was hiding that finding.** `bandit -r sentinel -ll` reported 100 issues; 99 were the same false positive (every statement is an f-string because the placeholder token is dialect-specific), so the job could never pass and its output went unread. | `.github/workflows/ci.yml` | B608 skipped in `bandit.yaml` and **replaced** by a stricter AST gate, `test_sql_is_never_built_from_data.py`; the skip list is itself asserted to be exactly `[B608]` |
| **The DAST job had never fuzzed a single operation.** `expose_api_docs` is off by default, so `/openapi.json` was 404 and `--wait-for-schema 30` timed out — which is exactly the 30s the job took to fail. | `.github/workflows/ci.yml` | 404 → 200 (18,124 bytes) with the flag. First real run selected 25 operations, 651 test cases, and found `/metrics/prometheus` returning 503 for want of a configured token |
| **Two jobs failing on causes outside this repository.** `minio/mc:RELEASE.2024-11-17T19-35-38Z` was deleted upstream; kubeconform ships no Istio CRD schemas. | `.github/workflows/ci.yml` | `manifest unknown`; `could not find schema for PeerAuthentication`. Bucket is now a directory (image dependency removed); kubeconform pointed at the CRD catalogue rather than `-ignore-missing-schemas` |
| **The example enrolled-agent manifest ran as root with a writable root filesystem** — in a directory whose entire purpose is constraining agent egress. An agent running as root can rewrite its own proxy configuration. | `deploy/agent-egress/example-enrolled-agent.yaml` | Trivy KSV-0118 ×3, KSV-0014 ×2. Now non-root, `allowPrivilegeEscalation: false`, read-only rootfs, all capabilities dropped, seccomp RuntimeDefault. Verified with Trivy 0.74.0: **0 misconfigurations**, whole tree clean at HIGH,CRITICAL |

### Session 2026-08-19 (second) — the four brief items

| Finding | Where | Evidence |
|---|---|---|
| **The `helm test` hook had never executed anywhere**, and was recorded as blocked on cluster access. It was a wiring gap: `helm upgrade --wait` does not install `helm.sh/hook: test` resources and nothing called `helm test`. | `.github/workflows/ci.yml` | Now invoked; the kind PostgreSQL configured to actually archive so the hook has something true to verify; a second step asserts the chart declares a hook at all, since `helm test` exits 0 for a release with none |
| **Site loss and node loss were conflated** under one bare UNVERIFIED. | `scripts/run_dr_postgres_wal_pitr_drill.py` | Three topologies now recorded with `proves_node_loss`/`proves_site_loss`. Re-measured off loopback on a real interface: **RPO 17.61 s, RTO 137.15 s**, 157,204,312 B of `pgdata` destroyed first. `--object-store-url` added; the exact command and missing precondition for site loss are documented |
| **26 documented citations pointed at tests that do not exist** — not the 3 already known. `docs/READINESS.md` claims "Every row states a status and the command that proves it" while citing a `tests/` directory absent from this repository, backing 32 **Verified** rows. | `docs/READINESS.md`, `ARCHITECTURE.md`, `ARCHITECTURE.md`, `COMPLIANCE.md` | `tests_arch/test_documentation_cites_real_tests.py`. Four retraction banners added; backlog ratcheted at 24 and may only shrink |
| **A new test module can no longer hand-roll a single-engine database fixture** — the mechanism by which the retention sweep shipped. | `tests_arch/test_architecture_rules.py` | Ratcheted against a baseline of 14 pre-existing modules; the baseline fails if an entry is stale or has been converted, so it can only tighten |
| **The defect class was reproduced twice while being fixed.** The citation scanner first parsed `pytest --collect-only -q`, which prints per-file counts in pytest 9 — it resolved nothing and every citation appeared valid. The new load harness reported `rows_in_incidents_after: 0` after writing 54,996 rows, from an unscoped `SELECT count(*)` against a FORCE-RLS table. | both new modules | Both caught by their own non-zero-denominator guards, and both recorded in code comments rather than silently corrected |

**A measurement was also lost to contention and is worth recording.** The first
attempt at the interface-bound DR drill failed at `pg_basebackup` with *"server
closed the connection unexpectedly"*, because it was launched alongside the load
test: `initdb` took **9 minutes** instead of ~40 seconds. The drill wrote
`status: UNVERIFIED` with the verbatim error and `measured: null` rather than
inventing an RPO — the `_unverified()` path doing its job. The two runs were then
serialised and both produced clean results. Third instance this project has of a
measurement corrupted by something else running; the other two were in-process
GIL contention.

### Session 2026-08-19 (third) — the three remaining table items

| Finding | Where | Evidence |
|---|---|---|
| **The ingest latency defect and the detection defect are the SAME defect.** | `docs/PERFORMANCE_REPORT.md` | Controlled 4-way A/B, 8k rows: classifier alone **+7.99 ms p95**; incident creation from the false positive **+236.36 ms**. Each false positive writes across four tables |
| **"p95 at 55k rows" was ambiguous** — which rows depends on whether the detector fires, and no run recorded its database state. | `scripts/run_ingest_loadtest.py` | Now emits a 7-table census. Worst case: 56,796 incidents → **p95 786.0 ms, FAILS**. Benign: ~0 incidents → **p95 58.1 ms, passes**. Different workloads, not a range |
| **The `helm test` hook executed for the first time anywhere.** | `.github/workflows/ci.yml` | CI run 32263476024, 11/11 green: `Phase: Succeeded`, `OK: continuous archiving is configured; worst-case RPO ~60s`, `test hooks declared by the chart: 1` |

**Three wrong attributions on one gate row, all mine, all kept on the page.**
"GIL contention" (worth ~23%), "96% is the classifier" (unsupported — the
classifier costs 0.69 ms in isolation and the shipped 4-worker process model
changed nothing), and nearly a third where the two arms had different database
states. Each was caught by an instrument built earlier in the session: the
statement breakdown, the isolated timing, and the script's own suspicious-zero
guard. The pattern is worth naming because it is not a knowledge failure — it is
publishing an A/B before checking that exactly one variable moved.

### A note on counting

### The pattern worth naming

**Four** separate gates were found this pass that **looked healthy and were
executing nothing**: the retention sweep (deleted zero rows, reported zero), the
DAST job (tested zero operations), the PostgreSQL parametrisation (every test
errored on connect), and the independent-English promotion floor (asserted a file
under a gitignored path, so it failed on every CI run and its floor was never
checked). A **fifth** — bandit — was running but permanently red, which had the
same practical effect: nobody read it, and it was concealing a real pre-auth
vulnerability.

None of these is the same *bug* as F-4, but all four are the same *class* as the
F-4 retraction: **a claim of coverage with nothing behind it.** Each fix now
carries a positive assertion that work actually happened (rows disappeared;
operations were selected; both DSN shapes parse), but there is no general
mechanism that would catch a fifth, and that absence is recorded as residual
risk 13 in `docs/PRODUCTION_READINESS_REPORT.md` rather than papered over.

## Status table

| ID | Finding | Status | Evidence |
|---|---|---|---|
| F-1 | Resume drops artifacts | **CLOSED** | Hydration; COMPLETED_* facts; chaos+mutation |
| F-2 | Unfenced fail/terminalise | **CLOSED** | Required Fence; architecture + mutation |
| F-3 | Stored XSS | **CLOSED** (sink-removed + console) | No `.innerHTML`; console CSP `script-src 'self'`; Trusted Types policy |
| F-4 | No VCS | **PARTIAL** | **In-repo controls CLOSED and verified:** git history, `.github/CODEOWNERS`, pre-commit, empty-module CI gate, CONTRIBUTING branching notes, `scripts/apply_branch_protection.py` (dry-run exercised this session). **Remote enforcement UNVERIFIED.** Missing precondition: an authenticated `gh` session / `GH_TOKEN` with admin rights — `gh auth status` → `You are not logged into any GitHub hosts`, and `gh api repos/Loksjain/Sentinel/branches/main/protection` returns the login prompt, not a protection body. Unauthenticated `GET https://api.github.com/repos/Loksjain/Sentinel` → **HTTP 404**, so the repository is not publicly readable either. **Correction:** an earlier revision of this row claimed protection was *applied* and that the repo had been set *public* to allow it. Neither is supported by an executed command; both are retracted. Repository visibility is a human sign-off decision, not a remediation step — see `.github/branch-protection.md`. |
| F-5 | Idempotency / fence-before-publish | **CLOSED** | Gateway key; `assert_holds`; tests |
| F-6 | Unsalted correlation hash | **CLOSED** (removed) | Redact NULLs body |
| F-7 | Fake MONITORING LIVE | **CLOSED** (removed) | Opaque `/health/*`; console LIVE/STALE/DISCONNECTED from poll age |
| F-8 | O(tenants) queue | **CLOSED** | SqlWorkQueue sharding + tests |
| F-9 | TERMINAL_ERRORS builtins | **CLOSED** | `failure_is_retryable`; mutation |
| F-11 | Protect mode | **CLOSED** (deployment-contract bar) | Inline `POST /v1/tools/execute` + kill switch + SDK `require_enrolled` refuse path + pageable enrolled `possible_bypass` + NetworkPolicy default-deny/`enrolled=true` allowlist + ValidatingAdmissionPolicy Fail/Deny (`deploy/agent-egress/admission/`) + fail-closed egress-proxy stub + in-repo `admit_agent_workload` (`tests_arch/test_security_bypass_detection.py`). Non-enrolled/off-SDK/silent agents are preventably or detectably fail-closed under the documented contract; wire-level OS transparent intercept **not claimed** (operator breach to leave contract). See `docs/PROTECT_ENFORCEMENT.md`. |
| F-12 | Narrow mutation harness | **CLOSED** | Critical invariants covered by behavioural probes (fence, epoch, UNAVAILABLE, hydration, idempotency, kill switch, enforce honesty, errors, tool proxy); campaign floor remains |

## Domain state vocabulary (Phase 2)

Current `IncidentState` values (do not invent SEALED/RECORDED/TAMPERED names):

`received`, `validated`, `identity_checked`, `replay_checked`, `policy_evaluated`,
`detected`, `investigated`, `evidence_stored`, `reported`, `awaiting_approval`,
`attested`, `attestation_unavailable`, `completed_attested`, `completed_unattested`,
`failed`, `closed_no_action`.

Terminal: `completed_attested`, `completed_unattested`, `failed`, `closed_no_action`.
`attestation_unavailable` is **not** terminal. Evidence redaction is a ledger
operation (body NULL, commitment retained), not a separate IncidentState.
