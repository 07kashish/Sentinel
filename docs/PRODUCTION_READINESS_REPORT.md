# Production readiness report

**Verdict: NOT production-ready.**

**Two** rows are still open, each naming its own blocking precondition rather
than a missing effort. (It was three; the kind/Helm row closed on 2026-08-19.)

1. **Branch protection on GitHub — UNVERIFIED, and the reason has CHANGED.**
   A prior claim that protection had been *applied*, and that the repo had been
   made public to allow it, was false and has been retracted from
   `.github/branch-protection.md` and `docs/REMEDIATION_MATRIX.md`.

   The blocker recorded here was "no authenticated `gh` session exists in this
   environment". **That is no longer true.** `gh` was authenticated on
   2026-08-19 (scopes `gist`, `read:org`, `repo`, `workflow`) in order to read
   CI logs, and the account is the repository owner — so applying branch
   protection is now technically within reach. The repository remains private;
   unauthenticated `GET /repos/Loksjain/Sentinel` still returns HTTP 404.

   It is still UNVERIFIED because **it was deliberately not done.** Branch
   protection changes who can push to `main` and under what conditions; that is
   a repository-governance decision for a human, and the standing instruction
   for this work was to leave this row alone rather than close it. Recording it
   as "blocked on access" when access now exists would be exactly the kind of
   stale precondition this document keeps having to retract.
2. ~~**kind/Helm cluster smoke — UNVERIFIED.**~~ **RESOLVED 2026-08-19 — it
   passes in CI.** The blocker described here was partly real and partly an
   artefact of not being able to look: Docker, kind, helm and kubectl are still
   absent from the development machine, but `gh` is now authenticated and the
   job's history is readable. `kind-helm-smoke` **passes** on GitHub's runners,
   which have all four. The one failure observed this session was
   `curl: (35) Recv failure: Connection reset by peer` **while installing kind**
   — a runner network flake, not a chart or manifest defect; the chart itself
   renders clean under helm 4.2.4 with the job's own values (234 lines,
   `--skip-schema-validation`), verified locally.

   What remains unverified is narrower and should be stated as such: no cluster
   smoke has ever been run *on this machine*. The `helm test` hook
   (`templates/tests/postgres-archive-check.yaml`) had **never executed
   anywhere** — `helm upgrade --wait` does not install `helm.sh/hook: test`
   resources and nothing invoked `helm test`. That was a wiring gap, not an
   access gap. **It is now wired AND witnessed**: CI run 32263476024 reports
   `Phase: Succeeded` and `OK: continuous archiving is configured; worst-case
   RPO ~60s` from the hook pod, against a live server in a kind cluster.
3. **API availability 99.9% / 30d — UNVERIFIED.** A 40-minute soak is real
   evidence and is recorded below, but it cannot observe a 30-day SLO.

Neither is blocked on engineering effort, and nothing in this session touched
them. Row 1 is now blocked on a human *decision* rather than on human *access* —
a distinction worth keeping straight, because the two expire differently.

**Further rows are open on their own merits.** Unlike the three above, these are
measured failures rather than access problems. As of 2026-08-18 the list is
shorter than it was, and it has one entry nobody expected:

   ```console
   TEST SUITE:  sentinel-postgres-archive-check
   Phase:       Succeeded
   POD LOGS:    archive_command=test ! -f /tmp/wal-archive/%f && cp %p /tmp/wal-archive/%f
                OK: continuous archiving is configured; worst-case RPO ~60s
   test hooks declared by the chart: 1
   ```

   It read `wal_level`, `archive_mode`, `archive_timeout` and `archive_command`
   from the **running server** in a kind cluster, and the anti-vacuous step
   confirmed the chart declares 1 test hook — so `helm test` had something to
   run rather than exiting 0 over an empty set.
- ~~**WAL archive shares a failure domain with the database — fail.**~~
   **Node loss closed 2026-08-18 and re-measured off loopback 2026-08-19**
   (RPO 17.6 s, RTO 137.1 s, 157,204,312 bytes of `pgdata` destroyed before
   recovery, object store on a real interface at `192.168.1.12`). **Site loss
   remains UNVERIFIED, and the precise reason is now recorded rather than left
   bare** — see the DR section. Compose's default is deliberately unchanged and
   still archives beside `pgdata`.
- **NEW — the operational retention sweep never worked on PostgreSQL.** A gate
   row that read `pass` was verified on SQLite only. On the production engine the
   sweep deleted zero rows and reported zero, which reads as success. Fixed, and
   regression-tested on both engines.

F-11 remains PARTIAL by design (deployment-contract bar, no wire interception —
explicitly out of scope). That one is a scope decision, so it stays in prose and
is deliberately not a gate row.

**What changed in this pass** (2026-08-18):

- **A row that read `pass` was measured on the production engine for the first
  time, and it was false.** The retention sweep — "Operational tables are
  bounded", 110,000 rows swept, database halved — deletes **nothing on
  PostgreSQL**. It took a pooled connection and never established a tenant, so
  under `FORCE ROW LEVEL SECURITY` every `DELETE` matched no rows and the sweep
  returned zero rather than failing. The previous pass verified it on SQLite,
  which has no RLS for it to fall foul of. This is the same defect shape the
  codebase's own docstrings hold up as the reason the SQL suites run on both
  engines; `test_retention_sweep.py` was the suite that did not.
- **`docs/SECURITY.md` cited three artifacts as evidence that were not
  in the tree** — two tests and a whole `tests/` directory. Same class as the F-4
  claim this project retracted. Two now exist and pass; the third's claim is
  withdrawn rather than reconstructed.
- **Incident/event retention is implemented and still off by default.** The
  previous pass declined to pick a number, which was right; declining to build
  the mechanism was not. `SENTINEL_INCIDENT_RETENTION_DAYS` is unset by default,
  `0` is refused as ambiguous, and the choice of number remains a human's.
- **The WAL archive now has a measured path off the database node**, with the
  data directory deleted before recovery so nothing could quietly come from it.
- **Two of the three "what a fifth council would find" candidates are closed**
  with executed tests: RLS-alone tenant isolation, and multi-replica ledger fork
  safety. The third — calibration — is untouched and out of scope.
- **The PostgreSQL half of the test suite had never run in CI.** Every
  `[postgres]` test errored on connect because the fixture built its DSN by
  string-slicing, which works on the TCP DSN Windows produces and corrupts the
  Unix-socket DSN Linux produces. So the dual-engine parametrisation this
  codebase calls non-optional — "a test that only ever runs on SQLite cannot see
  that class of bug" — was itself only ever running on SQLite in CI, while
  passing locally on Windows. This is the third of *four* instances this pass of
  *a gate that existed on paper and was executing nothing*, after the retention
  sweep and the DAST job and before the promotion-floor test. See residual risk
  13.
- **A pre-authentication denial of service in SAML, found by bandit and real.**
  `SamlValidator.validate` parsed an attacker-supplied assertion with
  `xml.etree.ElementTree` *before* it could check the signature (the signature is
  inside the document). ElementTree expands internal entities: measured, three
  nested entities turned ~30 bytes into 1000 characters. Fixed with `defusedxml`,
  `forbid_dtd=True`, and a size cap. **Writing the test found a second gap** —
  defusedxml permits a bare DTD by default, so an external-DTD document parsed
  cleanly and was only refused later by the signature check.
- **The `security` job's bandit step could never pass** — 99 of its 100 findings
  were the same false positive (every statement is an f-string because the
  placeholder token is dialect-specific). Replaced with a stricter AST gate that
  allowlists what may be interpolated rather than flagging that anything is.

**What changed in this pass** (2026-08-19, second session):

  (The specific filenames are deliberately not repeated here. The citation gate
  cannot distinguish a name quoted as an *example of a bad citation* from a
  real one — and it should not try, because a reader grepping for the name
  cannot either. It caught this very paragraph on the first run.)
- **I reproduced the defect class while fixing it, twice.** The citation
  scanner's first implementation parsed `pytest --collect-only -q`, which prints
  per-file *counts* in pytest 9 — it resolved nothing and every citation looked
  valid. And the new load-test harness reported `rows_in_incidents_after: 0`
  after writing 54,996 rows, because I wrote an unscoped `SELECT count(*)`
  against a FORCE-RLS table — the retention-sweep defect, verbatim, in the same
  session that documented it four times. Both were caught by guards, and both
  are recorded in the code rather than quietly fixed.

**Prior pass** (2026-08-13):

- **Found the cause of the ingest p95 regression, and it was not the expected
  one.** The read-path microbench could never have caught it: the soak issues no
  reads. Statement-level profiling showed table growth costing **3.5× on p95
  with a single writer and zero contention** (30.4 → 106.8 ms from 11k to 55k
  rows), which the soak's six-way write contention then multiplied.
- **Retention existed as configuration and nowhere else.**
  `SENTINEL_RETENTION_DAYS` was parsed and read by no code; the chart also set
  `SENTINEL_RETENTION_INTERVAL`, which `Settings` did not parse. `complete()`
  marked work `done` and nothing ever deleted it; `inbox` and `replay_nonces`
  shipped purge primitives with dedicated indexes and zero callers. Four tables
  grew for the life of a deployment. Now implemented and swept by
  `MaintenanceLoop`: **p95 −39.6%, database −49%** in a controlled run.
- **The Helm/Postgres DR gap is now enforced rather than hinted**, and the
  archive settings were verified by starting PostgreSQL with the compose flags
  and asking the server what it applied.
- **The gate table now carries every known failure as a row**, including the two
  this pass found and the two that were previously prose-only.

## Phase completion table

| Phase | Topic | Status | Notes |
|---|---|---|---|
| 0–5 | Baseline / domain / security | **DONE** | Prior work preserved |
| 6 | AuthZ / SAML / SCIM / org | **DONE** | OIDC+SAML validator+SCIM Users+org APIs+tests; full IdP product still external |
| 7–9 | Monitoring / queue / errors | **DONE** | |
| 11 | Protect inline | **DONE** (in-product) | `/v1/tools/execute` + pageable `possible_bypass` + SDK enrollment checks + `deploy/agent-egress`; F-11 PARTIAL |
| 12 | ASI | **DONE** | Honest matrix |
| 13 | Analyst UI | **DONE** | Secure console; no `.innerHTML` |
| 14 | Observability | **PARTIAL** | Metrics+correlation+alert rules; 40-minute soak measured (below); 30d SLO **UNVERIFIED**; ingest p95 under concurrency **fails** its target |
| 15 | Performance | **PARTIAL** | Real benches + multi-tenant soak; unbounded operational growth **fixed** (retention sweep, p95 −39.6%), but `incidents`/`domain_events` still grow by design and the p95 target is not yet met under concurrency |
| 16 | K8s | **DONE** manifests | Cluster deploy **UNVERIFIED** — no Docker/kind/helm/kubectl, no WSL distro, **not admin** so none installable; CI run history unreadable |
| 17 | DR | **DONE local + node-loss** | SQLite drill measured; Postgres dump round-trip measured; continuous WAL archive PITR measured (RPO 1.42 s, RTO 13.02 s); **archive to object storage now measured with the data directory destroyed first** (RPO 18.27 s, RTO 127.83 s, PITR selection exact). Cross-region/site failover still not measured — the object store was on the same host |
| 18–21 | Testing / mutation / security / integrity | **DONE** | F-12 critical probes CLOSED |
| 22–25 | Docs / gate | **DONE** | This document |

## F-1…F-12

## Production gate checklist

| Gate | Result |
|---|---|
| Architecture fitness | pass |
| Protect inline route + kill switch | pass |
| SCIM/org fail-closed tenant binding | pass |
| Console no `.innerHTML` + CSP | pass |
| Detection unexpected_misses empty | pass |
| Promotion gate floor 0.70 | pass (floor preserved; refuses recall&lt;0.70; hand corpus 0.786; independent EN soft 0.855 allowed) |
| External agents cannot skip Sentinel | **PARTIAL** (F-11 — deployment contract + SDK enrollment checks tested; wire intercept out of scope) |
| Detection degrades loudly, never silently | **pass (new)** — CRITICAL log + `sentinel_detection_degraded` gauge + `/health/diagnostics`; opt-in on `/health/ready`. 12 tests in `tests_arch/test_detection_mode.py` |
| Branch protection on GitHub | **UNVERIFIED** — `gh auth status` → `You are not logged into any GitHub hosts`; no `GH_TOKEN`; unauthenticated `GET /repos/Loksjain/Sentinel` → **HTTP 404** (not public). Prior "applied/verified" claim **retracted**. Dry-run applicator prints `DRY-RUN only. Protection was NOT applied.` |
| kind/k3d deploy + probes | **UNVERIFIED** — docker/kind/helm/kubectl all absent; `wsl -l -v` → `no installed distributions`; `IsAdmin: False`, so none installable here. CI run history unreadable (`gh` unauthenticated; runs API → HTTP 404). Workflow file exists; **a green file is not a green run** |
| postgres:16 service | **pass (live)** — `pytest -k postgres` via embedded `pgserver` this session (exit 0); Docker `postgres:16` image not used (no Docker) |
| Redis live adapter | **pass (live)** — Redis 8.10 via scoop + `SENTINEL_TEST_REDIS_URL`; `live_redis` tests exit 0 (wire-compatible; not the Redis:7 container image) |
| MinIO round-trip | **pass (live)** — scoop MinIO + SigV4 put/get/delete; `live_minio` exit 0 after Host-header strip fix |
| Postgres PITR live drill (dump round-trip) | **pass (measured)** — `scripts/run_dr_postgres_pitr_with_pgserver.py`; RPO 0s / RTO ~0.05s vs ≤5m/≤30m |
| Postgres PITR live drill (continuous WAL archive) | **pass (measured, new)** — `scripts/run_dr_postgres_wal_pitr_drill.py`: real `archive_mode=on`, crash via `pg_ctl stop -m immediate`, recovery from base backup + archive only. **RPO 1.4184 s** (200 rows lost with the unarchived segment), **RTO 13.02 s**. PITR selection verified: target after batch 2 → recovered max batch **2** of 4. See `archive_timeout` caveat in `docs/DISASTER_RECOVERY.md` |
| API availability 99.9% / 30d | **UNVERIFIED** — 40-minute soak recorded (see below); a short window cannot observe a 30-day SLO |
| Ingest p95 `< 500 ms` at stated load | see the row below — split, because one number was passing and one was failing under the same heading |
| ↳ Ingest p95, single writer at 55k rows | **pass** — 106.8 ms measured (`archive/pre-cleanup:docs/ingest_profile.json`) |
| ↳ Ingest p95, 6 concurrent writers at 55k events | **PASS — 37.99 ms** (`archive/pre-cleanup:docs/ingest_loadtest_postgres.json`, 2026-08-19). Was **786.0 ms and failing**; the cause was F-10, not the database and not the harness. Same run, same payload, same 55,000 events, before → after the F-10 fix:<br><br>p50 75.71 → **28.40 ms** · **p95 786.02 → 37.99 ms** · p99 2230.09 → **68.57 ms** · max 5951.55 → **100.95 ms** · throughput 30.77 → **191.32 req/s** (6.2×)<br><br>**The census is the proof of mechanism: 56,796 incidents → 0.** Every one was a false positive on the tool name `read_file`, each writing across four tables. Two earlier figures for this row — 624 ms (SQLite) and 995.2 ms (PostgreSQL) — are **withdrawn**: both from an in-process `TestClient` driven by threads, neither recording its database state |
| ↳ **F-10: the detector fires on 51.7% of ordinary tool calls** | **fail (new, high).** 31 of 60 benign tool-call actions fire at the shipped 0.5 threshold — `http_get` 0.709, `write_file` 0.657, `db_insert` 0.651, `send_email` 0.602 (`archive/pre-cleanup:docs/benign_tool_call_false_positives.json`). A SOC product that raises `prompt_injection_attempt` for over half of routine agent activity trains operators to dismiss the alert. **Each false positive is also a full incident write**, which is where the ingest latency above actually goes. Not fixed: the three options (raise threshold / drop the `action` fallback / retrain with benign tool vocabulary) change detection coverage and are a product decision with a named owner, not a refactor. See `docs/SECURITY.md` F-10 |
| Operational tables are bounded | **pass, but the cited number is SQLite-only** — `SqlRetention` run by `MaintenanceLoop`; 110,000 rows swept and DB halved (75.9 → 38.5 MB) in the controlled run. `SENTINEL_RETENTION_DAYS` previously had no reader at all. **That run measured SQLite; on PostgreSQL the same sweep deleted nothing at all until 2026-08-18** — see the row above. `webauthn_challenges` was also found unbounded this pass (a purge index, `ix_challenges_issued`, with no caller — the same signature as `ix_inbox_age` before this module existed) and is now swept |
| Incident/event history retention policy | **pass (new, 2026-08-18)** — implemented as an explicit operator switch, `SENTINEL_INCIDENT_RETENTION_DAYS`, with **no default**: unset means never delete, which is the shipped behaviour. `0` is **refused** rather than read as "forever", because it is ambiguous between "keep nothing" and "keep everything" and those are opposites. The reaper deletes only TERMINAL incidents and their `domain_events` / `incident_transitions` / `execution_steps` / `reports`, children first, in one transaction. Evidence: `tests_arch/test_retention_sweep.py`, **both engines** — untouched when unset (including through `MaintenanceLoop.run_once`, which issues no DELETE at all), reaped when set, every non-terminal state survives, ledger + evidence + audit trail survive. **The compliance number itself is still a human's to choose** — that part was never an engineering question and is not claimed as answered |
| Operational retention actually works on the production engine | **fail → pass (new, 2026-08-18)** — the previous `pass` was SQLite-only. On PostgreSQL the sweep used an unscoped pooled connection under `FORCE ROW LEVEL SECURITY`, so `tenant_id = NULL` matched nothing and it deleted **zero rows while reporting zero**: `before: work_queue = 1 → sweep reported 0 → after: work_queue = 1`. Now runs per tenant with `set_tenant` **and** an explicit `tenant_id = ?`. The regression asserts `before − after == reported` against a non-zero `before`, so agreeing zeroes can no longer pass |
| Tenant isolation holds with the application predicate REMOVED | **pass (new, 2026-08-18)** — `tests_arch/test_tenant_isolation_rls.py`, 18 tests (14 passed + 4 skipped SQLite-only, 0 failed). With no `WHERE` clause at all on PostgreSQL: `SELECT` returns 1 row not 3, `UPDATE` touches 1 not 3, `DELETE` removes 1 and leaves the other tenant's 2, and an INSERT labelled with another tenant's id is refused by the policy. Asserts the app role is **not** a superuser (which would make all of it vacuous) and interrogates `pg_class`/`pg_policy` for ENABLE+FORCE+policy on all 19 `PROTECTED_TABLES`. SQLite has no RLS and that column is asserted, not skipped |
| Evidence ledger cannot fork under multi-replica append | **pass (new, 2026-08-18)** — `tests_arch/test_ledger_multi_replica.py`, both engines. Two INDEPENDENT `ConnectionPool`s (no shared Python object, so every guard under test is server-side), 12 threads released on a `threading.Barrier`. The chain is read back and checked: no shared predecessor, `seq` dense from 1, every link recomputes, and every append either committed or raised a **retryable** error. A deliberate fork inserted directly, bypassing `append()`, is refused by `ux_ledger_chain`. **Limit stated:** the pools share an interpreter, so a real cluster's interleavings are a superset of these |
| Helm chart deploys or confirms a correctly-configured Postgres | **partial** — the chart does not deploy PostgreSQL by design. `values.schema.json` now **refuses to render** without `externalPostgres.archiveTimeoutConfirmed: true`, and a `helm test` hook interrogates the live server (`SHOW archive_mode/archive_command/archive_timeout/wal_level`). Verified here by starting PostgreSQL with `docker-compose.yml`'s own flags and asserting the server reports them (`tests_arch/test_helm_postgres_archive.py`, 9 tests). **The hook itself has never run against a cluster** — same blocker as the kind/Helm row |
| WAL archive survives loss of the database node | **fail → pass for node loss, UNVERIFIED for site loss (2026-08-18)** — `deploy/wal-archive/wal_s3.py` archives each completed segment to S3-compatible object storage via the same `S3ObjectStore` adapter the evidence store uses, and exits 0 only after reading the segment back and matching its SHA-256 (PostgreSQL may recycle it the instant it does). Measured by `run_dr_postgres_wal_pitr_drill.py --archive-to s3`, which **deletes the data directory (140,435,288 bytes) and the local archive directory before recovering**: **RPO 18.27 s** (≤300 s), **RTO 127.83 s** (≤1800 s), PITR selection exact (target after batch 2 of 4 → recovered max batch 2, 400 rows). `archive/pre-cleanup:docs/dr_postgres_wal_pitr_s3_drill.json`. **Compose's default is unchanged and still archives beside `pgdata`** — the object-storage path is documented and commented in, not switched on for you. **UNVERIFIED:** MinIO ran on the same host, so this does not demonstrate survival of a datacentre or region; no object-lock or cross-region replication was exercised |
| Cost of moving the archive off-host | **measured (new)** — object storage is **12.9× worse on RPO** (1.42 s → 18.27 s) and **9.8× worse on RTO** (13.02 s → 127.83 s) than the local directory, on the same workload over loopback. Cause is not the network: `archive_command`/`restore_command` spawn a Python process **per segment** which imports `sentinel` before moving a byte. Still an order of magnitude inside both targets. A deployment needing single-digit-second RPO wants a long-lived archiver (pgBackRest, WAL-G) against the same bucket |
| No false production-ready claim | pass — and one false claim found and retracted this pass (F-4) |

## Session baseline diff (2026-08-12)

Start of session, before any change:

```console
$ PYTHONPATH=. pytest tests_arch/ -k "not postgres"
FAILED tests_arch/test_architecture_rules.py::test_there_is_no_mutable_module_level_state
1 failed, 700 passed, 8 skipped, 82 deselected in 354.14s (0:05:54)

$ ruff check sentinel tests_arch
All checks passed!

$ bandit -r sentinel -q
Total issues (by severity): Undefined: 0  Low: 6  Medium: 92  High: 0
```

End of session:

```console
$ PYTHONPATH=. pytest tests_arch/ -k "not postgres"
712 passed, 8 skipped, 86 deselected in 244.42s (0:04:04)

$ ruff check sentinel tests_arch
All checks passed!

$ bandit -r sentinel -q
Total issues (by severity): Undefined: 0  Low: 6  Medium: 92  High: 0
```

| Change | Detail |
|---|---|
| 1 failed → 0 failed | `REQUIRED_AGENT_LABELS` is now a `MappingProxyType`, matching the convention in `domain/authorization.py`, `domain/incident.py`, `sql/work_queue.py`. The test was not touched |
| 700 → 712 passed | +12 new tests in `tests_arch/test_detection_mode.py` |
| 82 → 86 deselected | +4 in `tests_arch/test_dr_postgres_wal_pitr_drill.py`, deselected by `-k "not postgres"` on the filename, like the existing `test_dr_postgres_pitr_drill.py`. Run separately: `3 passed, 1 deselected`, plus the live drill exit 0 |
| bandit | unchanged: 0 high |

**Note on the stated snapshot.** The task described the prior baseline as
`687 passed, 21 skipped, 1 failed`. This session measured
`700 passed, 8 skipped, 1 failed` — same total of 708, with 13 tests moved from
skipped to passed because live Redis, MinIO and `pgserver` were reachable here.
The one failure was identical.

## Supply chain: dependency advisories (2026-08-19)

The `security` job's `pip-audit` step is BLOCKING and had been failing. Counted
precisely, because it was miscounted twice while writing this up:

| Package | Rows reported | Distinct advisories | Action |
|---|---|---|---|
| `cryptography` 42.0.5 | 8 | **7** | upgraded to **50.0.0** (highest fix required: 49.0.0) |
| `starlette` 0.47.3 | 8 | **6** | **pinned at 1.6.0** (highest fix required: 1.3.1 — no 0.x release clears them) |
| **Total** | **18** | **14** | |

`pip-audit` prints one row per *(advisory, fixed version)* pair, so an advisory
with two fix branches appears twice. Counting rows overstates the number — which
is exactly the mistake made here, twice, before the IDs were counted with
`sort -u`.

`starlette` was previously **unpinned**, floating in behind FastAPI's
`starlette>=0.46.0` with no upper bound. It is now pinned explicitly, so the
version in the image is the version that was audited.

### The result is "clean **with one recorded exception**", not "clean"

```console
$ pip-audit -r requirements.txt --ignore-vuln PYSEC-2024-110
No known vulnerabilities found, 2 ignored
```

**"2 ignored" rather than 1** because `pip-audit` counts the suppressed rows,
and PYSEC-2024-110 occupied two of them.

## Defects found this pass that were not on the checklist

## Residual risks (honest)

   That is the signature of thread contention, not of query cost: six Python
   threads driving an in-process `TestClient` share one GIL. **So this row's
   number is an upper bound on the harness, not a measurement of the service**,
   and that was equally true of the 624 ms figure — nobody noticed because it
   was never broken down. Closing the row honestly requires an out-of-process
   load generator against a served instance; until then `fail` is the correct
   status but the *cause* is not established. *Gate rows: "Ingest p95, 6
   concurrent writers" (fail), "Where the ingest latency actually goes"
   (measured), "Operational tables are bounded" (pass).*
9. **Incident and event history grows without bound UNTIL AN OPERATOR SETS A
   WINDOW, and that is now the whole of the risk.** As of 2026-08-18 the switch
   exists (`SENTINEL_INCIDENT_RETENTION_DAYS`) and the reaper behind it is tested
   on both engines. It is unset by default and therefore deletes nothing by
   default, which is deliberate: how long a SOC keeps incident records is a
   compliance decision with legal weight and no correct default. The residual is
   that a deployment which never sets it grows for ever — a decision an operator
   has to take, not a defect the code can remove.
   *Two things it deliberately does NOT bound, and they still grow with incident
   volume:* `evidence` (governed by the ledger's redaction path — body NULL,
   digest retained — because deleting the row would make chain verification fail
   rather than pass over a redaction) and `approvals` (deleting it would leave an
   executed remediation with no recorded approver). Both are declared in
   `APPEND_ONLY_TABLES` with those reasons; neither is an oversight, and neither
   is bounded. *Gate row: "Incident/event history retention policy" (pass).*

10. Reclaiming freed space is a second step the sweep does not take. On SQLite
    only `VACUUM` returns pages to the filesystem; on PostgreSQL the cheap path is
    dropping a partition, as `schema.py` describes. Neither runs automatically.

11. **A `pass` row was wrong for five days and nothing caught it.** The
    operational retention sweep was verified on SQLite and shipped as bounded;
    on PostgreSQL it deleted nothing. The mechanical cause is fixed. The
    *process* cause is not fully fixed: `tests_arch/conftest.py` provides an
    `engine_config` fixture that parametrises over both engines, and nothing
    forces a new SQL-touching test module to use it. `test_retention_sweep.py`
    built its own SQLite-only fixture and no gate objected. A rule that every
    module touching `sentinel/infrastructure/sql/` must parametrise over both
    engines would close that, and does not exist yet.

12. **The object-storage WAL archive costs an order of magnitude on RPO and RTO**
    (18.27 s / 127.83 s versus 1.42 s / 13.02 s locally) because the archive and
    restore commands spawn a Python process per segment. Both remain well inside
    target, and a deployment with a tighter RPO should run a long-lived archiver
    against the same bucket instead. *Gate row: "Cost of moving the archive
    off-host" (measured).*

13. **Four gates existed on paper and executed nothing, all found in one
    pass — and a fifth was running but permanently red.** The retention sweep
    (deleted zero rows on PostgreSQL and reported zero); the DAST job (timed out
    waiting for a schema the app was configured not to serve, having tested zero
    operations); the entire PostgreSQL parametrisation of the test suite (every
    test errored on connect in CI); and the independent-English promotion floor
    (asserted a file under a **gitignored** path, so it failed on every CI run
    and the floor it enforces was never checked there). The fifth was `bandit`,
    permanently red on 99 false positives — which had the same practical effect,
    because nobody read its output, and it was concealing a real
    pre-authentication XML denial of service in the SAML path.

    Each looked healthy from the outside: a `pass` row, a job that ran, a suite
    that was green locally, a test in the file. The common shape is that
    **nothing checked the gates were doing work** — a sweep that deletes nothing
    satisfies an assertion of "no rows remain", a fuzzer that tests nothing
    reports no failures, an erroring parametrisation is invisible if you only
    read the exit code of a local run, and a file assertion that never runs
    never fails.

    Each fix now carries a positive check (rows actually disappeared; operations
    actually selected; both DSN shapes actually parse; an absent benchmark
    reports UNVERIFIED rather than passing).

    **Two general mechanisms now exist** (2026-08-19), and it is worth being
    precise about what they do and do not cover:

    * `tests_arch/test_documentation_cites_real_tests.py` — no document may cite
      a test pytest does not collect. Closes the *documentation* half of the
      class. Found 26 dangling citations on its first run.
    * `test_no_new_test_module_drives_the_database_on_one_engine_only` — a new
      test module may not hand-roll a single-engine database fixture, which is
      precisely how the retention sweep shipped. Ratcheted against a recorded
      baseline of 14 pre-existing modules.

    **What was NOT built, and remains the residual.** The brief also asked to
    "prefer positive assertions over absence-of-failure assertions". That was
    *followed* in every test written this pass — each carries a non-zero
    denominator check — but it is a **practice, not a mechanism**. Nothing
    forces the next author to do it, and no linter can reliably tell an
    assertion that proves work happened from one that merely observed no
    failure. So the class is narrowed at two specific chokepoints and is **not
    closed**. A sixth instance is still possible; it just has two fewer doors.

14. **A pre-auth XML DoS shipped in the SSO path.** It was found by a static
    analyser whose job had been failing for unrelated reasons for long enough
    that nobody read its output — 99 false positives hid one real finding.
    That is the argument for keeping a scan *runnable* rather than merely
    *configured*, and it is now the documented reason `bandit.yaml` exists.

15. **`docs/SECURITY.md` claimed evidence that did not exist**, in
    three places, including one whole directory. Two of the three now exist and
    pass; the third's claim is withdrawn. The residual is that no mechanism stops
    a document citing a test by a name nothing answers to — the same gap that
    allowed the F-4 "protection was applied" claim. A CI check that every
    `test_*` identifier named in `docs/` resolves to a collected test would close
    it, and does not exist.
