# Observability

## Surfaces

| Surface | Auth | Notes |
|---|---|---|
| `GET /health/live` | none | Opaque liveness for kubelet. The only throttle-exempt path |
| `GET /health/ready` | none | Opaque readiness (`ready` bool only). Adds `detection_mode` **only** when `SENTINEL_READY_EXPOSE_DETECTION_MODE=true` |
| `GET /health/diagnostics` | capability `read_diagnostics` | Backend detail, incl. `detection_mode` and `detector_version` |
| `GET /metrics/prometheus` | Bearer `SENTINEL_METRICS_TOKEN` | Process metrics; never unauthenticated |
| Structured logs | n/a | JSON lines via `StructuredLogger` |
| Correlation | `X-Request-Id` | Also tenant / incident / epoch / worker on worker path |
| OTLP hooks | `SENTINEL_OTLP_ENDPOINT` | No-op when unset; no extra OTel package required |

## Correlation fields

HTTP middleware binds `request_id` (from `X-Request-Id` / `X-Correlation-Id` or minted).
Authenticated requests enrich `tenant_id`. Workers bind `tenant_id`, `incident_id`,
`epoch` (lease), and `worker_shard`.

## Prometheus scrape

`deploy/prometheus.yml` scrapes `/metrics/prometheus` with a bearer token file.
Docker Compose includes a prometheus service.

## SLIs / SLOs

The Status column below used to be prose somebody typed. It is now **computed**
by `scripts/evaluate_slos.py` from a soak artifact, against the targets encoded
as numbers in that script and evaluated by `sentinel/domain/slo.py`:

```
PYTHONPATH=. python scripts/evaluate_slos.py docs/observability_soak_postgres.json
```

Three verdicts, and the third is the point. **UNMEASURABLE** is not a pass: a
420-second run against a 99.9%/30d target cannot report MET, because that
target permits ~2,592 seconds of failure — the entire error budget could be
spent in a window longer than the run. A **VIOLATED** verdict, by contrast, is
reported from any window, because falsifying an SLO needs less evidence than
confirming one.

Exit codes: `0` every target met, `1` at least one unmeasurable, `2` at least
one violated. A soak that exited 0 because it was too short to fail is how an
unverified SLO becomes a green build.

The soak artifact also carries `meets_ingest_p95_target`, a boolean the
producer wrote about itself. The evaluator prints it beside the computed
verdict so the two can disagree visibly rather than depending on which file you
read.

| SLI | Suggested SLO | Status |
|---|---|---|
| API availability (`/health/ready` success ratio) | 99.9% / 30d | **UNVERIFIED** — soaks observed 100% (6,595/6,595 in 40 min on SQLite; 17,953/17,953 in 7 min on PostgreSQL), and a 30-day SLO cannot be inferred from either. 99.9% permits ~43 min of downtime per 30 days |
| Ingest p95 latency | < 500 ms at stated load | **MET on PostgreSQL** — 7-minute production-shaped soak measured p95 **71.6 ms** at 38 rps (2026-09-01). Still **MISSED on SQLite**: 624 ms at ~23 rps. Production is PostgreSQL; SQLite is a development engine and the gap is the point |
| Worker claim success / poison rate | < 1% dead-letter of attempts | **UNVERIFIED** |
| Attestation gateway error rate | reported, not a readiness gate | degraded OK |

## Measured soak (2026-09-01, 7 minutes, PostgreSQL, production-shaped)

Command:
`PYTHONPATH=. python scripts/run_observability_soak.py --seconds 420 --production-shaped --postgres`
Raw: `docs/observability_soak_postgres.json` (generated; not tracked).

The 40-minute run below was **SQLite** and missed the ingest target at 624 ms.
This one is the engine production uses.

| Surface | Requests | Failures | p50 | p95 | p99 |
|---|---|---|---|---|---|
| ingest | 16,082 | 0 | 34.0 ms | **71.6 ms** | 96.3 ms |
| `/health/ready` | 1,871 | 0 | 19.9 ms | 45.9 ms | 58.1 ms |

Throughput 38.3 rps. Backend: pgserver-embedded PostgreSQL 16.2 over a real TCP
socket, connected as `sentinel_app` — **NOSUPERUSER, so FORCE row-level
security applies and its predicate is part of the measured cost**. Docker is
absent on that machine, so the `postgres:16` container image was not used.
`--production-shaped` runs the WorkerPool and MaintenanceLoop, so the queue
drains and the retention sweep runs, which the original 624 ms measurement did
not.

**Ingest p95 is 71.6 ms against a 500 ms target — met, with 7× headroom.**

### What this does not show

Availability observed 100% (17,953/17,953). The 30-day SLO row stays
**UNVERIFIED** and cannot be otherwise: 99.9% permits roughly 43 minutes of
downtime per 30 days, and a 7-minute window cannot sample that. A clean short
run is *consistent with* the SLO; it does not demonstrate it. It rules out gross
unavailability, which is all a short run can do.

It is also an **upper bound** on production availability. The harness drives the
app through an in-process client: no network, no ingress, no load balancer, no
second replica, no rolling deploy. Every one of those is a real source of
production unavailability this cannot see.

### Finding: readiness is throttled and liveness is not

`sentinel/interface/throttle.py` exempts only `/health/live`. The reason is
written there: a kubelet polling every second must not be able to exhaust a
bucket and get the pod killed.

The same argument applies to `/health/ready`, and the consequence is worse. A
throttled readiness probe marks the pod **NotReady**, which sheds it from the
Service, which moves its share of traffic onto the remaining pods — under
exactly the load that caused the throttling. That is a cascading failure, and it
is the shape of failure this product exists to reason about.

This run saw **0 throttled probes at 38 rps**. An earlier run of the same script
at ~180 rps from a single address had **27 of 270** readiness probes answered
429. In a cluster the kubelet probes from the node address while client traffic
arrives from elsewhere, so the buckets usually differ — but *usually* is doing
real work in that sentence.

It is left as-is deliberately, because the obvious fix is not free:

1. **Exempt `/health/ready`.** It calls `_probe_database()`, so exempting it
   creates an unauthenticated, unmetered database-load amplifier. That trades a
   cascading-failure risk for a denial-of-service one.
2. **Leave it throttled.** Accepts the cascade under single-address load.
3. **Cache the probe for ~1 second, then exempt.** A kubelet polls every 1–10 s,
   so a short cache makes unlimited probing harmless and keeps the answer fresh
   enough. This is the option worth building, and it changes health-check
   semantics, so it wants a deliberate decision rather than a drive-by edit.

Recorded here rather than fixed silently: the measurement found it, and the
choice belongs to whoever owns the deployment.

## Measured soak (2026-08-12, 40 minutes)

Command: `PYTHONPATH=. python scripts/run_observability_soak.py --seconds 2400 --rps 40`
Raw: `docs/observability_soak.json`.

| Metric | Ingest `POST /v1/events` | Readiness `GET /health/ready` |
|---|---|---|
| requests | 55,501 | 6,595 |
| failures | **0** | **0** |
| throttled (429) | 0 | 0 |
| success ratio | 1.000000 | 1.000000 |
| p50 | 122.9 ms | 85.2 ms |
| p95 | **624.2 ms** | 454.1 ms |
| p99 | 1371.9 ms | 1254.2 ms |
| max | 6697.4 ms | 4394.7 ms |

Sustained throughput 23.1 rps; every ingest response was `202`, every probe `200`.

### Diagnosis (2026-08-13): unbounded table growth, and it was real

The first hypothesis was a missing index on the queries
`tests_arch/test_persistence_benchmarks.py` profiles. It was wrong, and the
reason is worth recording: that microbench profiles **reads**
(`events.stream_tail`, `events.for_incident`), both of which already have
covering indexes and a fitness test forbidding sequential scans. The soak issues
**no reads at all** — only `POST /v1/events` and `GET /health/ready`. No amount
of care on the read path could have caught this.

`scripts/profile_ingest.py` attributes cost per SQL statement by hooking
SQLite's trace callback and driving real requests at increasing table sizes.
Raw: `docs/ingest_profile.json`. Single-threaded, so table growth is isolated
from lock contention:

| rows | ingest p50 | ingest p95 |
|---|---|---|
| 11,250 | 24.1 ms | 30.4 ms |
| 22,500 | 26.4 ms | 40.2 ms |
| 33,750 | 37.9 ms | 42.5 ms |
| 45,000 | 42.4 ms | 50.3 ms |
| 55,250 | 66.5 ms | **106.8 ms** |

Growth alone costs **3.5× on p95** with one writer and zero contention, so the
soak's 624 ms is that curve multiplied by six-way write contention on a single
SQLite writer — two compounding effects, not one. No individual statement
dominated; `COMMIT` did, at 7.5–10 ms of a ~15 ms request, which is fsync and
does not grow with N.

What grew was everything: `incidents`, `incident_transitions`, `domain_events`
and `work_queue` all reached 55,250 rows, and the database reached **147 MB**.
None of it was ever reclaimed, because:

- `SENTINEL_RETENTION_DAYS` was parsed into `Settings.retention_days` and read
  by **no code at all**. The Helm chart also set `SENTINEL_RETENTION_INTERVAL`,
  which `Settings` did not parse.
- `work_queue.complete()` sets `state='done'` and leaves the row. There was no
  `DELETE FROM work_queue` anywhere in the tree, nor from `outbox`.
- `inbox.purge_before()` and `SqlReplayGuard.purge_expired()` existed, each with
  an index built to serve it (`ix_inbox_age`, `ix_nonces_expiry`), and neither
  had a single production caller.

### The fix, measured (partial — see the limit below)

> **Correction, 2026-08-18.** Everything in this subsection was measured on
> **SQLite**, and on PostgreSQL the sweep it describes deleted **nothing at all**
> until this date. It used a pooled connection with no tenant context, so under
> `FORCE ROW LEVEL SECURITY` every `DELETE` matched zero rows and returned zero
> without raising:
>
> ```console
> before: work_queue = 1  inbox = 1
> sweep reported: {... 'retention_rows_deleted': 0}
> after : work_queue = 1  inbox = 1
> ```
>
> The −39.6% p95 and −49% database figures below are real, reproducible, and
> **describe an engine production does not run**. The sweep now runs per tenant
> with `set_tenant` and an explicit `tenant_id = ?`, and
> `tests_arch/test_retention_sweep.py` runs on both engines. The controlled
> experiment below has **not** been re-run on PostgreSQL, so no equivalent
> PostgreSQL percentage is claimed here.

`sentinel/infrastructure/sql/retention.py`, run by `MaintenanceLoop` every
`SENTINEL_RETENTION_INTERVAL`. Controlled single-variable experiment —
`scripts/measure_retention_effect.py`, raw in `docs/retention_effect.json` —
against a database seeded to 55k rows with operational work aged past the
window, measuring the real HTTP ingest path before and after one sweep in the
same process:

| | before sweep | after sweep | change |
|---|---|---|---|
| ingest p50 | 20.29 ms | 18.43 ms | −9% |
| **ingest p95** | **44.93 ms** | **27.13 ms** | **−39.6%** |
| ingest p99 | 104.25 ms | 46.04 ms | −56% |
| database size | 75.9 MB | 38.5 MB (after VACUUM) | −49% |

The sweep deleted 110,000 rows (55k completed work items, 55k delivered outbox
records) in under a second.

**This only partially closes the gap, and the remainder is by design.** The
sweep removes the operational tables. `incidents`, `domain_events` and
`incident_transitions` are *not* touched by it — how long a SOC keeps incident
history is a compliance decision with legal weight, not a disk-space one, and it
is not an agent's to pick a number for.

**Since 2026-08-18 those three do have a policy, and it is still off by
default.** `SENTINEL_INCIDENT_RETENTION_DAYS` has no default value: unset means
never delete, which is what a fresh deployment does. `0` is refused rather than
interpreted, because it is ambiguous between "keep nothing" and "keep
everything". When it is set, the reaper deletes only TERMINAL incidents and
their `domain_events`, `incident_transitions`, `execution_steps` and `reports`,
children first, in one transaction — and never the evidence ledger. So the
mechanism is no longer the missing piece; the number is, and that is a human's
signature rather than a code change.

Two tables still grow with incident volume and are declared, not bounded:
`evidence` (governed by the ledger's redaction path, because deleting the row
would make chain verification fail rather than pass over a redaction) and
`approvals` (deleting it would leave an executed remediation with no recorded
approver). Both carry those reasons in `APPEND_ONLY_TABLES`.

Reclaiming disk is also a second, separate step: the sweep frees pages logically,
but on SQLite only `VACUUM` returns them to the filesystem, and on PostgreSQL the
partition-drop path described in `schema.py` is the cheap one. Neither is run
automatically.

### The p95 target was missed, and the earlier number was misleading

This table replaces a claim of "p95 **238 ms**" taken from
`tests_arch/test_multi_tenant_soak.py`, which issues **80 requests in under a
second**. That is not a soak, and its p95 is a sample of a cold, empty database.

Latency degraded monotonically as the event table grew, observed live during
the run:

| Elapsed | Ingest p95 |
|---|---|
| 5 min (~11.5k events) | 83.4 ms |
| 35 min (~51k events) | 599.2 ms |
| 40 min (~55.5k events) | 624.2 ms |

A 7.5× increase over 40 minutes is a growth curve, not noise, and the run ends
**above** the 500 ms target. Two honest caveats in the other direction:

- **This is SQLite on local disk.** The soak harness uses the SQLite engine;
  production is Postgres, which is what `psycopg` is a hard requirement for.
  The curve may be an artefact of SQLite's write path and index growth rather
  than of Sentinel's ingest logic. It has **not** been re-measured on Postgres.
- **In-process `TestClient`, one machine, no retention job running.** Real
  deployments run `MaintenanceLoop` with `SENTINEL_RETENTION_DAYS` trimming the
  table; this run accumulated 55k events with nothing pruning them.

So the correct reading is: *the p95 SLO is unproven and currently missed under
the only sustained measurement that exists.* Re-running this against Postgres
with retention enabled is the next step, and until that happens the row above
says MISSED rather than PARTIAL.

### What a 40-minute clean window does and does not show

Zero failures across 62,096 requests rules out gross unavailability. It cannot
demonstrate 99.9% over 30 days: that budget permits ~43 minutes of downtime per
30 days, so a single clean 40-minute window is consistent with the SLO and also
consistent with far worse. It is an **upper bound** in any case — no network,
ingress, load balancer, second replica or rolling deploy is exercised.

Short local soak (80 requests, CI-cheap):
`PYTHONPATH=. pytest -q tests_arch/test_multi_tenant_soak.py -s`

## Detection degradation (page on this)

The soft prompt classifier is the difference between ~0.855 and ~0.067 measured
independent English recall. Losing it used to be silent: `build_container`
returned the rules-only policy and nothing anywhere said so. It is now reported
on three surfaces, and the metric is the one to bind an alert to because it
stays true for as long as the condition does:

| Signal | Surface | Auth |
|---|---|---|
| `sentinel_detection_degraded 1.0` | `/metrics/prometheus` | Bearer |
| `sentinel_detection_mode{mode="…"} 1.0` | `/metrics/prometheus` | Bearer |
| `detection_mode`, `detector_version` | `/health/diagnostics` | capability |
| `detection_mode` | `/health/ready` | none — **opt-in only** |
| `detection_degraded_soft_prompt_{missing,unloadable}` at CRITICAL | logs | n/a |

Modes: `soft+rules` (healthy) · `rules-only-degraded` (the artifact was wanted
and did not load — **page**) · `rules-only-configured` (an operator turned it off
on purpose — do not page, or the alert becomes noise nobody reads).

`SENTINEL_READY_EXPOSE_DETECTION_MODE` defaults to **false**. Readiness is
unauthenticated, and "the ML detector is down right now" is exactly the
reconnaissance that tells an attacker when to act. Enable it only where the
readiness port is genuinely cluster-internal.

## Alerts (suggested)

- `sentinel_detection_degraded == 1` — detection silently fell back to rules-only
- Ready probe failing on all replicas
- Metrics scrape auth failures spike (token rotation)
- Protect kill switch engaged (`diagnostics.protect_kill_switch`)
- Outbox / queue depth growth sustained

Wire alertmanager separately; this tree does not claim live paging.

## Readiness is not exempt from the rate limiter

`sentinel/interface/throttle.py` exempts exactly one path:

```python
exempt_paths: tuple[str, ...] = ("/health/live",)
```

`/health/ready` therefore consumes the per-address budget
(`SENTINEL_ADDRESS_LIMIT`, default **120/min**). Measured, not theorised: an
unpaced soak at ~180 rps from a single address had **27 of 270** readiness
probes answered `429`.

In a cluster the kubelet probes from the node address while client traffic
arrives from elsewhere, so the two usually land in different buckets and this
does not bite. Where they coincide — a NAT, a service mesh sidecar, a
single-address load test — throttled readiness marks pods NotReady under load,
sheds them from the Service, and moves their traffic onto the pods that are
left. Left as-is deliberately: exempting readiness makes it a free
unauthenticated surface, and that trade is a design decision, not a bug fix.
Operators who front Sentinel with a NAT should raise `SENTINEL_ADDRESS_LIMIT`
accordingly.
