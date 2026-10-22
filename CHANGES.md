# Sentinel change record

Updated: 2026-10-22 (Asia/Calcutta).

## Current checkpoint

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
