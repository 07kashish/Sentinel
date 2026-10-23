# Sentinel change record

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
