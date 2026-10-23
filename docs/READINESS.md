# Enterprise readiness: what is implemented, what is verified, what is out of scope

<!-- unbacked-citations-retracted -->

> ## ⚠️ RETRACTION — the evidence column in this document is not backed by this repository
>
> **Added 2026-08-19 by an automated check, not by a reviewer's judgement.**
>
> `tests_arch/test_documentation_cites_real_tests.py` scans every document for
> test identifiers and requires each to resolve to a test `pytest` actually
> collects. It found that this document cites a **`tests/` directory that does
> not exist in this repository** — for example `pytest tests/live/test_postgres_live.py`
> and `pytest tests/test_schema_ownership.py`. The suite here lives in
> `tests_arch/`, and those files are not in it under any name.
>
> The commands in the Evidence column below therefore **cannot be run**, and the
> **Verified** statuses that rest on them are **not currently backed** by
> anything in this tree. They appear to describe the predecessor implementation
> that this codebase replaced.
>
> This is the same defect class as the F-4 retraction and the retention-sweep
> correction: *a claim of coverage with nothing behind it*. It is recorded here
> rather than deleted, because silently removing the rows would destroy the
> record of what was once claimed — which is the thing the F-4 retraction exists
> to preserve.
>
> **What is actually verified in this tree** is in
> [`PRODUCTION_READINESS_REPORT.md`](PRODUCTION_READINESS_REPORT.md), whose rows
> cite commands that run. Read that document, not this one, for current status.
>
> The unbacked citations are counted and ratcheted: they may be reduced by
> writing the test or deleting the row, and the count may not grow.

---


Every row states a status and the command that proves it. A capability marked
**verified** has been exercised against real infrastructure, not a mock. A
capability with no evidence column is not claimed.

Three statuses, used strictly:

- **Verified** â€” exercised against real infrastructure in a reproducible test.
- **Implemented, not production-verified** â€” the code runs and is unit-tested, but
  no live third-party system has been driven by it.
- **Out of scope** â€” a decision, with a reason, recorded in
  [`ARCHITECTURE.md`](ARCHITECTURE.md#architecture_decisions).

Test counts as of this report: **280 standard + 31 live**. Run the live suite with `SENTINEL_REQUIRE_LIVE=1` so unavailable infrastructure FAILS instead of skipping quietly.

> A late self-audit found `/protect/evaluate` calling a function that does not
> exist â€” every request raised `NameError`. It is fixed and now returns a real
> allow/deny decision. It survived because the council's regression test checked
> one variable name (`run_id`) rather than the class; that test is now generalised
> to every undefined reference in every route, and was itself found to have two
> scope bugs before it worked. Details in `tests/test_council_v3_regressions.py`.

---

## Data layer

| Capability | Status | Evidence |
|---|---|---|
| PostgreSQL backend | **Verified** | `pytest tests/live/test_postgres_live.py` â€” 7 tests against real PostgreSQL 16.2: schema creation, full incident lifecycle, artifact guard, metrics queries, tenant isolation, 10-thread write race, reconnection durability |
| Row-level write serialisation | **Verified** | `test_concurrent_writers_do_not_corrupt_state` â€” 10 threads, exactly one winner via `SELECT â€¦ FOR UPDATE` |
| SQLite backend (single node) | **Verified** | `pytest tests/` â€” the entire standard suite runs on SQLite |
| No silent engine downgrade | **Verified** | `test_postgres_failure_never_falls_back_to_sqlite` â€” raises `PostgresUnavailable` rather than using SQLite |
| Multi-tenant isolation | **Verified** | `test_tenant_isolation_is_enforced_by_the_real_database` â€” same incident id, two tenants, no bleed |
| Schema single-ownership | **Verified** | `pytest tests/test_schema_ownership.py` â€” no module may declare its own DDL |
| Retention | **Implemented, not production-verified** | Scheduled behind leader election; never run against a database with 90 days of real history |

**How PostgreSQL was verified without Docker:** the `pgserver` wheel ships real
PostgreSQL binaries, so `tests/live/` starts an actual server. No container
runtime exists in this environment, which is why every earlier report had to say
Postgres was unverified.

**What the live run found that unit tests could not:** a foreign key referencing a
column that had stopped being unique (SQLite accepted it silently for months;
PostgreSQL refused to create the table), and `row[0]` raising `KeyError` on
psycopg dict rows. Both are fixed structurally.

---

## Work distribution and availability

| Capability | Status | Evidence |
|---|---|---|
| Durable work queue | **Verified** | `pytest tests/live/test_durable_queue_live.py` â€” 12 concurrent workers, 40 items, zero double-delivery |
| Survives process restart | **Verified** | `test_enqueued_work_survives_process_restart`, `test_incident_state_survives_full_restart` |
| Crashed-worker recovery | **Verified** | `test_no_work_is_lost_when_workers_die_randomly` â€” 6 workers abandoning 50% of claims, 60 incidents, none lost |
| Multi-replica exactly-once | **Verified** | `test_three_replicas_process_each_incident_exactly_once` â€” 90 incidents, 3 replicas |
| Poison-message handling | **Verified** | `test_repeatedly_failing_work_stops_retrying` â€” bounded attempts, then dead-lettered |
| Leader election | **Verified** | `test_only_one_replica_is_elected_leader` â€” 10 contending threads, one leader, via `pg_try_advisory_lock` |
| Graceful shutdown | **Verified** | `stop_background_workers()` drains on ASGI shutdown; `test_lifespan_actually_starts_the_worker` |
| Dead-letter queue | **Implemented, not production-verified** | Unit-tested; never driven by a real failing downstream provider |
| Webhook execution proof | **Verified** | `pytest tests/live/test_real_services.py` â€” a real HTTP receiver computing the receipt HMAC; an endpoint that returns 200 with a reference but no signature is recorded as NOT executed |
| Atomic acceptance + fenced leases | **Verified** | `pytest tests/test_f7_atomicity_and_fencing.py` â€” incident and queue item in one commit; a stale worker's completion is refused with `LeaseLost` |
| Redis | **Superseded** | Was removed from the old runtime as unused. The rewritten persistence layer has a real adapter with a purpose â€” see *Persistence layer (rewritten)* below |
| Kafka / broker | **Out of scope** | Would be a second queue beside the database queue â€” the split-authority class again |

---

## Persistence layer (rewritten)

Scoped to `sentinel/infrastructure/persistence/`. **This package is not yet wired
into the running application**, which still uses `sentinel/infrastructure/sql/`.
Every row below is about the new package in isolation; none of it is on a request
path yet, and that migration is unstarted.

| Capability | Status | Evidence |
|---|---|---|
| Point-in-time recovery | **Verified** | `pytest tests_arch/test_persistence_backup_pitr.py` â€” 19 tests against a real PostgreSQL 16.2 cluster this file initialises with `initdb`. `test_recovery_stops_at_the_requested_instant` takes a `pg_basebackup`, writes, records an instant, writes more, restores to that instant on a second port and asserts the later rows are **absent**. A restore that returned everything would pass a weaker check and fail the only question that matters |
| WAL archiving | **Verified** | `test_wal_segments_actually_reach_the_archive` â€” asserts on the archive directory's **contents** and on a named segment, not on `pg_stat_archiver` |
| Verified restore as a job | **Verified** | `verify_restore()` restores, starts, probes, tears down and records `duration_seconds` â€” a recovery objective nobody has measured is a guess. `test_verify_restore_reports_a_rejecting_probe_instead_of_hanging` proves a bad restore yields a verdict rather than a hang, and `test_a_target_beyond_the_archived_wal_is_never_reported_as_verified` proves an unreachable target is never reported as recovered |
| Envelope encryption | **Verified** | `pytest tests_arch/test_persistence_crypto_audit.py` â€” per-record AES-256-GCM DEK wrapped by a KEK, AAD bound to (tenant, record type, record id); `rewrap` rotates the KEK without touching plaintext. Uses `cryptography`, not `pgcrypto`, so the database never sees a key |
| Hash-chained audit log | **Verified** | same file â€” append-only, each entry chaining the previous digest; `verify()` detects insertion, mutation and deletion. Concurrent appends serialise on `pg_advisory_xact_lock`, because `SELECT â€¦ FOR UPDATE` cannot lock a head row that does not exist yet and every writer would otherwise chain from GENESIS |
| Object storage | **Verified** | `pytest tests_arch/test_persistence_storage_cache.py` â€” filesystem adapter with temp-and-rename atomicity; S3 adapter signs SigV4 over stdlib `urllib` (no boto3). Keys are tenant-first and refuse traversal. **The S3 adapter has never been run against real S3** |
| Redis cache and rate limiting | **Verified** | same file â€” the token bucket is a single Lua script using server `TIME`, so it is atomic under 16 racing threads. `fail_open` is a required argument: whether losing Redis blocks or admits traffic is a decision that must be made explicitly. Verified against `fakeredis` + `lupa`, **not a real Redis server** |

**What the live PITR run found that no unit test could:** `postgresql.conf` treats
backslash as an escape inside a quoted value, so the Windows `archive_command`
reached the server as `copy "%p" "E:pgtmppitr0wal_archive%f"` â€” every separator
stripped. That path is drive-relative, so `copy` **succeeded** into the data
directory, PostgreSQL marked each segment archived, `archived_count` reached 2 and
`failed_count` stayed at 0. The archive was empty. Every signal said archiving
worked. Only listing the archive directory showed otherwise, which is why the test
asserts on directory contents and `preflight` reads settings back from the running
server rather than trusting the file it wrote.

**And why the suite could not have found it earlier:** `subprocess.run(capture_output=True)`
deadlocks on `pg_ctl start`. The postmaster inherits the pipe's write handle, so it
never reaches EOF, and the timeout path drains the pipe again on its way out and
blocks there too. Output goes to a temporary file now.

---

## Identity, authentication, authorisation

| Capability | Status | Evidence |
|---|---|---|
| Fail-closed API-key auth | **Verified** | `test_unauthenticated_request_is_refused` (through HTTP, not by calling the guard) |
| RBAC with ordered roles | **Implemented, not production-verified** | Unit-tested |
| Agent identity (secp256k1) | **Implemented, not production-verified** | Unit-tested. **The ECDSA recovery primitive has not been independently audited** â€” flagged by two council seats and still true |
| Replay protection | **Implemented, not production-verified** | Nonce + freshness window + monotonic ordering; unit-tested |
| OIDC / JWT | **Verified** | `pytest tests/live/test_real_services.py` â€” a real RSA issuer serving a real discovery document and JWKS over real HTTP; a token signed by a different key is refused |
| SAML | **Out of scope** | OIDC covers the need; SAML's XML signature-wrapping surface is not worth shipping unexercised |
| SCIM | **Out of scope** | Sentinel has no user directory to provision into |
| mTLS / x509 service identity | **Implemented, not cluster-verified** | Helm renders Istio `PeerAuthentication` STRICT plus `DestinationRule` `ISTIO_MUTUAL`; not installed on a real mesh |

---

## Detection

| Capability | Status | Evidence |
|---|---|---|
| Policy rules (MITRE / OWASP mapped) | **Verified** | `pytest tests/test_rules.py` |
| Statistical classifier | **Verified on benchmark** | `PYTHONPATH=. py evaluation/run_benchmark.py --test` |
| Cross-source detection quality | **Measured, weak** | AUC **0.763** holding out an entire corpus. The former 0.855 random-split figure is RETRACTED: it was provenance leakage, and the model behind it inverts under leave-one-source-out |
| Multilingual detection | **NOT VALIDATED** | Benchmark reports ~1.000 recall on nine languages; it is an artifact of a class-language confound, demonstrated in `evaluation/BENCHMARK.md`. A test fails CI if any document claims it |
| Layer attribution | **Verified** | `test_incident_records_which_layer_fired` â€” policy and classifier verdicts never merged |
| Detection latency | **Measured** | 16.6 ms/event including the classifier (`test_detection_latency_under_load`) |
| Production traffic | **Never evaluated** | No customer data has been processed. Public benchmarks are not a customer's distribution |

**Baseline for comparison.** The policy rules alone score **0.022** recall on the
full held-out split and **0.067** on English. Those figures stand; the classifier
figures that once accompanied them do not. The previous README reported 0.643
against 22 self-authored cases. The handcrafted corpus overstated capability by
roughly 25Ã—; that gap is the most important finding of this work.

**The FPR trade is real.** Rules alone had FPR 0.002. With the classifier it is
0.044 on English. On high-volume traffic that is an alert-fatigue cost, and it is
a deliberate trade, not an improvement on every axis.

---

## Observability

| Capability | Status | Evidence |
|---|---|---|
| Structured logging with redaction | **Implemented, not production-verified** | Unit-tested |
| OpenTelemetry tracing | **Implemented, not production-verified** | Configured at startup. **Never sent to a live collector** |
| Prometheus metrics | **Implemented, not production-verified** | Counters defined and incremented. **Never scraped by a live Prometheus** |
| Dashboard metrics correctness | **Verified** | `test_metrics_endpoint_reflects_real_incidents` â€” end-to-end through HTTP |

---

## Deployment

| Capability | Status | Evidence |
|---|---|---|
| Helm chart | **Verified (lint + render)** | `pytest tests/live/test_real_services.py` â€” real Helm 3.16.3 `lint` passes and `template` renders 3 replicas with the replica-count env var and a read-only root filesystem. **Never installed on a cluster** |
| Kubernetes manifests | **Implemented, not deployed** | `deploy/k8s/sentinel.yaml`. Never applied |
| Multi-replica safety | **Verified at the application layer** | Queue and leader election tested with concurrent workers; **not tested as real pods** |
| Refuses unsafe topology | **Verified** | `SENTINEL_REPLICA_COUNT>1` on SQLite exits at startup with an explanation |
| Container hardening | **Implemented, not verified** | Non-root, read-only rootfs, dropped capabilities â€” never run |

---

## Measured performance

Local PostgreSQL, developer hardware, single thread. Recorded so the figures are
knowable, **not published as a performance claim**:

| Measure | Value |
|---|---|
| Queue enqueue | ~37/s |
| Queue dequeue | ~18/s |
| Detection latency | ~16.6 ms/event (rules + classifier) |

Queue throughput is modest and would need batching and a connection pool before
any volume claim. Nobody has profiled it under realistic concurrency.

---

## The honest summary

**What genuinely improved.** PostgreSQL is real and verified against a live
server. Work survives restarts, crashes and multiple replicas â€” properties the
in-memory queue could never have had, and which no previous report was entitled
to claim. Detection is measured against third-party data nobody here wrote â€” and
that measurement retracted its own headline: the 0.855 random-split figure was
provenance leakage, and the honest cross-source number is AUC 0.763.
Dead scaffolding is gone rather than documented.

**What is still unproven.** No live identity provider, telemetry collector,
Kubernetes cluster or message broker has been driven by this code. The ECDSA
recovery primitive remains unaudited. No production traffic has ever been
processed. Multilingual detection is not validated and is enforced as
unclaimable.

**The pattern worth stating.** Almost every defect fixed in this pass was found by
running the code against something real: live PostgreSQL found two schema bugs,
third-party data found that the detection numbers were off by 25Ã—, and a
ten-line probe found that a 1.000 multilingual score was a language detector.
None of them were found by adding more unit tests to code that already passed.
