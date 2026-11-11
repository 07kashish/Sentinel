# Sentinel change record

Updated: 2026-11-12 (Asia/Calcutta).

## Current checkpoint

## Checkpoint 2 verification

**Ready for Checkpoint 2: yes.** The approved cleanup-checkpoint checks pass.
The pre-existing Trivy gate remains open before pilot deployment; Compose remains
unverified. No Phase 5 work, merge or PR was performed.

Evidence: [cleanup CI run 43107663818](https://github.com/07kashish/Sentinel/actions/runs/43107663818)
ran manually at `c5fb0b4d0c6bf1c9f8d192f29c285e76a5d18c09` on
cleanup/oversight-core (publish_image=false, as supplied by the operator).
[Main baseline run 42609831971](https://github.com/07kashish/Sentinel/actions/runs/42609831971)
ran at `d45b22031dd3280abd2072968162417b3870c2b3`. Public Actions run/job
metadata was checked for every result below. Both complete workflows failed;
only the build and smoke steps of the Docker job passed. No new CI rerun is claimed.

| CI job | Cleanup c5fb0b4 | Main d45b220 | Evidence / disposition |
|---|---|---|---|
| deployment-validation | success | success | Passed in both runs. |
| docker | failure | failure | Build and smoke steps pass in both; step 6 Trivy gate fails in both: pre-existing, not caused by the cleanup. |
| dynamic-api-security | success | success | Passed in both runs. |
| guard-mutation | success | success | Passed in both runs. |
| kind-helm-smoke | success | success | Passed in both runs. |
| license-scan | success | success | Passed in both runs. |
| live-minio | success | success | Passed in both runs. |
| live-postgres | success | success | Passed in both runs. |
| live-postgres-service | success | success | Passed in both runs. |
| live-redis | success | success | Passed in both runs. |
| provenance | absent | success | Removed in earlier cleanup; absent from the cleanup workflow. |
| release-evidence | absent | success | Removed in earlier cleanup; absent from the cleanup workflow. |
| release-hygiene | skipped | success | Cleanup skipped because test failed; main passed. |
| security | failure | failure | Step 3 secret history scan fails in both: pre-existing, not caused by the cleanup; local diagnosis and approved fix below. |
| sign-image | skipped | skipped | Skipped in both; no image publication claimed (dispatch requested publish_image=false). |
| test | failure | success | New stale wheel-count failure on cleanup; fixed and verified locally below. |
| types | success | success | Passed in both runs. |
| verification | success | success | Passed in both runs. |

### Docker evidence and remaining deployment gate

Docker job step 3 builds `sentinel:ci`. Step 4 creates a fresh SQLite volume,
migrates using that same image, starts it through the shipped entrypoint, and
requires an HTTP success from /health/live within 30 attempts at 2-second intervals
(60 seconds). Both steps passed in both runs. Step 5 runs Trivy for vulnerabilities,
secrets and misconfiguration, including unfixed findings; step 6 fails closed
on the scan report. Step 6 failed in both runs at the same gate. This is not a
passing complete Docker job or a claim that the image is ready for deployment.
Docker was not run locally; Compose remains **UNVERIFIED**. Image size is
**not measured**: no size measurement is present in the available CI evidence.
No Dockerfile, entrypoint, base-image digest, dependency pin or healthcheck changed.

Open pre-existing item for **Phase 6 / Stage 4**: Container image has HIGH/CRITICAL
findings per the CI Trivy gate; fails identically on main; findings to be reviewed
from the CI log and fixed before the first pilot deployment.

### Wheel correction and clean-build proof

Commit `0b25065` (`fix(release): wheel must contain only tracked sources`) reads
the wheel member list before scanning, requires scanned == len(names) and
scanned >= 150, and rejects every sentinel/ member missing from git ls-files
sentinel. The existing findings == [] and default_policy.json assertions are
unchanged. Operations now requires release builds from a clean checkout, as CI does.

The original WSL wheel had 271 members versus 200 from a fresh c5fb0b4 clone.
All 71 extra Python members came from ignored build/lib/sentinel output left by
an earlier build; they were present in the actual wheel, not tracked sources.
The approved cleanup removed only build/ and sentinel_agent_trust.egg-info/;
targeted git status --ignored showed both before and neither afterwards.
Other ignored files were preserved. The new guard failed and named the planted
`sentinel/_checkpoint2_stale_canary.py`. After removing only build/, the same
test passed and the planted file was gone. Both fixed working-tree and fresh-clone
wheels now contain the same 200 members. All 36 release-hygiene tests pass from
the fresh clone at b495ca2. The three affected release/security modules pass
62 tests with 1 existing skip because this checkout has no .env to check.

### Redacted full-history gitleaks diagnosis

The CI command uses fetch-depth: 0 and the pinned gitleaks v8.30.1 image
with `git --redact --no-banner --config /repo/.gitleaks.toml
--gitleaks-ignore-path /repo/.gitleaksignore /repo`. The local equivalent uses the
checksum-verified v8.30.1 Linux release binary with the same policy and ignore
files, plus private JSON report flags. No Docker or history rewrite was needed.

| Rule | File and line | Commit | Date (UTC) | File at HEAD | Classification |
|---|---|---|---|---|---|
| generic-api-key | CLEANUP_PLAN.md:1326 | d45b22031dd3280abd2072968162417b3870c2b3 | 2026-10-22T06:48:08Z | yes | Documentation false positive: prose listing retained SQL tables, not a credential assignment. |
| generic-api-key | tests_arch/test_detonation.py:46 | d63463cd3bc49bcd3e420ff4a100cc52fe6f4ad6 | 2026-10-19T12:22:02Z | no | Synthetic CANARIES test fixture; never used for external authentication. |

Zero possible real credentials were found. Commit `b495ca2` applies exactly the
two user-approved commit + path + rule + line fingerprints in .gitleaksignore.
No path-wide or rule-wide exclusion was added; .gitleaks.toml is unchanged.
The redacted full-history scan passed with exit 0 and zero findings over the
original 47 commits, and again over all 49 commits through b495ca2 after both fixes.
The post-record-commit scan is also a mandatory push gate; its redacted report is
retained as baseline/checkpoint2/gitleaks-final.redacted.json.
No matched values appear in these records.

### Final Linux verification

One uninterrupted Phase 0 run completed with exit 0: **3,323 passed, 39 skipped,
0 failed, 0 errors, 0 timeouts** across 3,362 cases. JUnit duration: 1,861.392 seconds.
The process ran from 2026-11-11T22:59:54Z to 2026-11-11T23:37:50Z; a progress-tool
connection timeout did not interrupt or restart pytest. The command was run with
pipefail enabled, saving baseline/checkpoint2/junit.xml and pytest.log:

```bash
PATH="$PWD/baseline/checkpoint2/tools:$PWD/.venv/bin:$PATH" pytest tests_arch/ -q --timeout=120 --timeout_method=thread --durations=30 -rA --junitxml=baseline/checkpoint2/junit.xml 2>&1 | tee baseline/checkpoint2/pytest.log
```

The pinned scanner was exposed only through an ignored local tools alias. The
case count stays at 3,362: no test was added or removed. Compared with Phase 4,
passes increase from 3,321 to 3,323 and skips decrease from 41 to 39 because
`test_the_real_scanner_reports_a_planted_secret` and
`test_the_scan_failure_does_not_echo_the_secret` now run and pass. There are no
new skips and no changed reasons among the remaining 39. Compared with Phase 2's
42 skips, the third reduction is the previously removed parked detonation test;
that removal happened in Phase 3, not this checkpoint.

Ruff (`ruff check sentinel tests_arch scripts/dev`), git diff --check and the
relative Markdown path check pass (90 links in 47 tracked Markdown files, zero
missing targets). The final independent review found no critical or important
issue. The tests regenerated only clean build/ and project egg-info output; both
were removed again with the same tracked-file/path guards and before/after ignored
status checks. The seeded stale file is absent. docs/dr_sqlite_drill.json remains
absent, matching its pre-run state. Raw evidence remains ignored under baseline/;
no reports or raw logs are committed.

The wheel fix is 0b25065 and the two-fingerprint exclusion fix is b495ca2. The
final record commit uses `chore(checkpoint2): record CI docker verification`.
The authorized finish is a normal push to cleanup/oversight-core and comparison
of the remote SHA with local HEAD. No history rewrite or force-push is needed.

## Phase 4 results

**Historical Phase 4 verdict: Ready for Checkpoint 2: no — blocked on Docker verification.**
The later Checkpoint 2 verification above supersedes this checkpoint status.
The cleanup implementation, native quickstart and complete Linux verification
are finished. No Phase 5 work is started. The full per-reader/per-route evidence,
protected-test edit inventory and all skipped case identities are retained in
[CLEANUP_PLAN.md](CLEANUP_PLAN.md#phase-4-decisions), P4-005 through P4-013.

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
| Docker image size | not measured | not measured |

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


## Phase 3 results

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

Route declarations **78 -> 53**; annotated Settings fields **73 -> 63**; collected
cases **4,143 -> 3,362**, a net reduction of **781**. The table counts all text diff
lines and changed/deleted files per commit. The analysis +2 IDs rename retained
SLO checks. Five cases were restored during audit; the user-approved demo scope
removed one A2A-only case. Two migration functions had fixtures adapted without
removing any original assertion or changing production DDL.

Phase 2 was **4,101 passed / 42 skipped**; final Phase 3 is **3,321 passed /
41 skipped**. Only the live detonation skip was removed; no other group changed
the skip total. No new skips or changed reasons exist among retained cases.
The full Phase 0 command ran uninterrupted on Linux/WSL, exited 0, and saved
`baseline/phase3/pytest.log` and `junit.xml` (JUnit: **1,592.684 seconds**).
Earlier interrupted and failing runs are archived separately and superseded.

Migration 40 drops `user_credentials`, `user_sessions`, `enrolment_tickets`,
`webauthn_challenges`, `users`, `organizations`, `a2a_agent_cards` and
`device_discovery`, without CASCADE. Fresh and previous-head upgrades pass on
SQLite and PostgreSQL; kept tables/indexes/RLS policies/roles and migrations
1–39 remain unchanged. `DEVICE_STATEMENTS` is retained for historical replay.

Act webhooks remain: `SENTINEL_REMEDIATION_ENDPOINTS`, parser, wiring,
`HttpRemediationIntegration`, `build_remediation_executor` and explicit endpoint
precedence. MCP/native tests remain unchanged. Custom rules matching
`metadata.a2a.*` no longer match anything; no shipped rule used those inputs.
MCP retains its pre-existing event type and deterministic reply inspection.

The execution-trust demo now answers **12/18 questions** and explicitly marks
**1, 2, 3, 4, 14 and 18** out of scope. Questions 1–4 are NOT answered yet because
the delegation verifier was parked with A2A; no answers are fabricated from
declared fields. The demo exits 0 and prints its limitations. Only the approved
count assertion and A2A-only negative-control test changed; every other demo
assertion remains unchanged. Phase 5 must restore those answers through the
agent registry and retained identity/authorization paths, including
`oversight_demo.py` (5.6); this obligation is recorded in the plan and PARKED.md.

Ruff, 10 import-graph regressions, 2 scanner regressions, graph gate with 11
documented exceptions, actionlint, release-secret scan, relative Markdown links
and the 62-name/prefix removed-setting scan pass. Docker is unavailable in WSL;
image build and healthcheck remain unverified. PARKED.md contains all eight
feature entries, retained-webhook rationale and Phase 5 reference candidates.
The SQLite drill artifact's original absent state is restored.

Deviations: shared directory removal waited for A2A; the final discovery orphan
was removed separately; the new schema inventory moved to its own module to keep
the historical schema and size guard unchanged; four shared test functions were
recovered (five cases). P3-019 records the approved narrower demo, and P3-020
records historical migration-fixture corrections. No open Phase 3 question remains.
No merge, PR, deployment, production migration or Phase 4 work was performed.
Reports and baseline logs stay uncommitted. Older sections below are historical.

## Phase 2 results — 2026-10-24

**Ready for Phase 3: yes; Phase 3 has not started.** Cleanup on
`cleanup/oversight-core` removed 15 unused modules and 26 files while retaining
backup/PITR, object-store support and all non-partition core assertions.

| Group | Modules removed | Files removed | Gross LOC removed | Test cases removed / added | Cases after | Commit |
|---|---:|---:|---:|---:|---:|---|
| dead-persistence | 3 | 3 | 1,222 | 4 / 2 | 4,404 | `742e86d` |
| dead-security | 9 | 17 | 5,525 | 209 / 0 | 4,195 | `1414eb3` |
| dead-tooling | 3 | 6 | 1,739 | 52 / 0 | 4,143 | `df3e863` |

Full Linux verification: **4,101 passed, 42 skipped,
0 failures/errors/timeouts**. Ruff, 10 graph tests, graph check with documented
keep/Phase 3 allowances, actionlint, secret scan and 63 relative Markdown links pass.
Files: 697 → 671; Sentinel modules: 257 → 242; test cases: 4,406 → 4,143.
Tracked text LOC including the final result record: 256,948 → 248,649.
Settings (73), environment assignments (66), CI jobs (16) and live migrations are unchanged.

The user explicitly retired legacy partitioning: live tables are not partitioned,
and retention is a DELETE sweep. Four partition cases were removed, all other
benchmark/crypto/audit assertions were retargeted, and two real audit interoperability
cases were added. The original capability proof, exact deleted partition IDs,
per-file test reductions, all remaining orphan dispositions and the parked
range-partitioning entry are in [CLEANUP_PLAN.md](CLEANUP_PLAN.md#phase-2-results--2026-10-24).

The Helm test reports an explicit skip when initdb cannot run; root failure/skip
was reproduced, and normal-user server assertions passed. Docker is unavailable,
so image build/start remains unverified. Other service/artifact skips and the
previous Passport integer-range discrepancy remain explicit limits.
Reports stay uncommitted. No Phase 3, PR, main merge or deployment was performed.

<!-- phase2-summary:end -->

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

## Earlier Phase 0 record (historical)

<!-- phase0-record:start -->

## Phase 0 checkpoint (historical)

**Phase 0 baseline ready for Phase 1: yes.** Cleanup Phases 1–6 have not started.
The branch is `cleanup/oversight-core`; the recovery tag `archive/pre-cleanup`
still points to `d63463cd3bc49bcd3e420ff4a100cc52fe6f4ad6`, the 989-file import
snapshot. No remote was added and nothing was pushed.

## Changes since the archive snapshot

| File | Change |
|---|---|
| [CLEANUP_PLAN.md](CLEANUP_PLAN.md) | Original cleanup inventory plus the completed Linux baseline, complete failure classification, slowest tests, skip reasons and all 39 module dispositions. |
| [scripts/dev/import_graph.py](scripts/dev/import_graph.py) | Added nonexecuting AST import inventory and a check mode; review fixes make literal resolution conservative across scope/mutation and detect missing namespace children. |
| [scripts/dev/test_import_graph.py](scripts/dev/test_import_graph.py) | Ten standard-library regression tests for the graph tool, including seven review-found failing subcases. |
| [scripts/smoke_clean_install.py](scripts/smoke_clean_install.py) | Correct SDK probe attribution of startup modules while retaining checks for real, preloaded and dynamic dependencies. |
| [tests_arch/test_release_hygiene.py](tests_arch/test_release_hygiene.py) | Six SDK-probe regression cases; existing assertions preserved. |
| [sentinel/application/execution/engine.py](sentinel/application/execution/engine.py) | Return the atomic inbox acceptance result so two racing workers cannot both report winning the same message. Preserve final-only inbox writes and execution ordering. |
| [tests_arch/test_execution_concurrency.py](tests_arch/test_execution_concurrency.py) | Deterministic real-SQL race regression on both SQLite and PostgreSQL; original concurrency assertions preserved. |
| [CHANGES.md](CHANGES.md) | Consolidated current changes, results, limitations and stop point. |

The pre-existing working-tree change to `docs/dr_sqlite_drill.json` is generated
timing data and was preserved separately from the intended Phase 0 commit. It is
not an application change or a performance guarantee. The only application change
is the minimal inbox-result correction above. Dependency manifests, deployment
configuration and CI workflows are unchanged; there are no deletions or refactors.

## Verification

| Run | Total | Passed | Failed | Errors | Skipped | Timed out | JUnit seconds | Wall seconds | Exit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Fresh Linux before fix | 4609 | 4567 | 1 | 0 | 41 | 0 | 2269.808 | 6670 | 1 |
| After SDK probe fix (inbox race found) | 4615 | 4573 | 1 | 0 | 41 | 0 | 2551.481 | 2583 | 1 |
| Final Linux | 4617 | 4576 | 0 | 0 | 41 | 0 | 2013.038 | 2034 | 0 |

- Release-hygiene tests: 36 passed; original failure reproduced before the fix.
- Import-graph tests: 10 passed; review failures reproduced before their fixes.
- Ruff: passed for application, architectural tests and changed tooling.
- Static inventory: 258 modules, 219 reachable, 39 unreachable, no unresolved
  internal/dynamic imports in this snapshot. All 30 requested paths are in the 39.
- Three independent Linux reruns of the original soak failure passed without
  changing the 2,000 ms limit.

Historical failure classification (remaining outcomes are in the plan):

| Category | Historical failing test IDs |
| --- | --- |
| ENV-WINDOWS | 19 |
| ENV-SERVICE | 0 |
| REMOVED-LATER | 0 |
| FLAKY | 1 |
| CORE-BUG | 2 |

Linux reference environment: Ubuntu 24.04.3 under WSL2, Python 3.12.3, fresh venv
in `/home/lenovo2/sentinel` on ext4. Full tests use a 120-second per-test timeout.
Raw before/final reports and reruns live under ignored `reports/phase0-linux-*`.
The plan records every historical failing test ID, final slowest tests, service
skip reasons, review fixes and module reconciliation.

Earlier Windows results (3,867 passed, 20 failed, 722 skipped) are diagnostic
history, not the reference baseline. An earlier Linux attempt was interrupted;
the subsequent untimed native run completed with 4,567 passed, one failed and
41 skipped. Those records are retained and are not represented as successful
full runs.

The October 21 verification run was also interrupted around 63%, without a final
JUnit report or exit code. Its evidence is preserved under
`reports/phase0-linux-interrupted-20261021/`. The completed October 22 run above
started from the beginning after checking 990 source files against this workspace.

## Scope and next step

No application cleanup or new integration was implemented. PostgreSQL fixtures
ran locally; absent Redis, MinIO, Docker, Helm/kind and other skipped capabilities
remain unverified. Static reachability does not justify deleting external SDK,
WAL archive or measurement entrypoints.

Requested commit: `chore(phase0): establish Linux test baseline`.
Stop here after Phase 0. Phase 1 has not begun.

## Phase 3 MCP compatibility decision — 2026-10-25

MCP reply inspection is being extracted from A2A while preserving the existing
policy payload except for metadata.a2a, and using the same ProtectGate and ruleset.

Custom policy rules matching metadata.a2a.* (or eventType agent_delegation from A2A) no longer match anything; no shipped rule used them.

A2A-originated events cease when A2A is parked. MCP reply events retain the existing
agent_delegation eventType. All pre-existing MCP proxy tests remain unchanged.
The removed-setting scan exempts exactly CHANGES.md, CLEANUP_PLAN.md and
docs/PARKED.md; full environment-variable names remain in removal records.

### Phase 3 group complete: soar

- Removed 2 whole files (680 lines); changed-path and numstat records: baseline/phase3/soar/result.json.
- Collection: 3512 cases; 20 removed IDs and 0 added IDs since the preceding collection (baseline/phase3/soar/test-delta.json).
- Verified touched cases, with corrected reruns superseding earlier failures: 123 passed, 0 skipped, zero remaining failures/errors. Reports: targeted.xml.
- Ruff, removed-setting scan and diff check pass. Settings remaining: 67. Existing retained MCP/native tests are byte-identical to Phase 2.
- Full Phase 3 Linux verification and the single drop migration remain pending.

### Phase 3 group complete: orgs

- Removed 1 whole files (127 lines); changed-path and numstat records: baseline/phase3/orgs/result.json.
- Collection: 3508 cases; 4 removed IDs and 0 added IDs since the preceding collection (baseline/phase3/orgs/test-delta.json).
- Verified touched cases, with corrected reruns superseding earlier failures: 86 passed, 0 skipped, zero remaining failures/errors. Reports: targeted.xml, console-fixed.xml.
- Ruff, removed-setting scan and diff check pass. Settings remaining: 67. Existing retained MCP/native tests are byte-identical to Phase 2.
- Full Phase 3 Linux verification and the single drop migration remain pending.

### Phase 3 group complete: a2a

- Removed 18 whole files (6,711 lines); changed-path and numstat records: baseline/phase3/a2a/result.json.
- Collection: 3354 cases; 154 removed IDs and 0 added IDs since the preceding collection (baseline/phase3/a2a/test-delta.json).
- Verified touched cases, with corrected reruns superseding earlier failures: 252 passed, 0 skipped, zero remaining failures/errors. Reports: targeted.xml.
- Ruff, removed-setting scan and diff check pass. Settings remaining: 63. Existing retained MCP/native tests are byte-identical to Phase 2.
- Full Phase 3 Linux verification and the single drop migration remain pending.

### Phase 3 group complete: migration

- Removed 0 whole files (0 lines); changed-path and numstat records: baseline/phase3/migration/result.json.
- Collection: 3358 cases; 0 removed IDs and 4 added IDs since the preceding collection (baseline/phase3/migration/test-delta.json).
- Verified touched cases, with corrected reruns superseding earlier failures: 132 passed, 8 skipped, zero remaining failures/errors. Reports: targeted.xml, guard-fixed.xml.
- Ruff, removed-setting scan and diff check pass. Settings remaining: 63. Existing retained MCP/native tests are byte-identical to Phase 2.
- Migration 40 is implemented; full Phase 3 Linux verification remains pending.

### Phase 3 group complete: discovery-remainder

- Removed 1 whole files (251 lines); changed-path and numstat records: baseline/phase3/discovery-remainder/result.json.
- Collection: 3358 cases; 0 removed IDs and 0 added IDs since the preceding collection (baseline/phase3/discovery-remainder/test-delta.json).
- Verified touched cases, with corrected reruns superseding earlier failures: 82 passed, 0 skipped, zero remaining failures/errors. Reports: targeted.xml, fixed.xml, manifest-fixed.xml.
- Ruff, removed-setting scan and diff check pass. Settings remaining: 63. Existing retained MCP/native tests are byte-identical to Phase 2.
- Migration 40 is implemented; full Phase 3 Linux verification remains pending.
