# Operations

<a id="deployment"></a>
<a id="deployment--deployment"></a>
## Deployment

<a id="deployment--runtime-entry"></a>
### Runtime entry

```bash
python -m sentinel.interface.cli migrate   # deployment step, not boot
python -m sentinel.interface.cli verify    # O(1) schema version check
gunicorn "sentinel.interface.asgi:create_application()" \
  --worker-class uvicorn.workers.UvicornWorker
```

Importing modules starts nothing. Workers attach in ASGI lifespan.

<a id="deployment--required-configuration"></a>
### Required configuration

| Variable | Purpose |
|---|---|
| `SENTINEL_ENV` | development / staging / production |
| `SENTINEL_API_KEYS` | `tenant:key:role` (min length enforced in production) |
| DB | `SENTINEL_DB_PATH` (SQLite) or Postgres DSN settings |
| `SENTINEL_PROTECT_ENFORCE` | `true` only when callers honour protect / tool_runner |
| `SENTINEL_PROTECT_KILL_SWITCH` | `true` refuses all tool side effects (fail closed) |
| `SENTINEL_TOOL_BUDGET_PER_MINUTE` | per-agent tool execution budget (0 = off) |
| `SENTINEL_OIDC_ISSUER` / `AUDIENCE` / `JWKS_JSON` | optional JWT path (all-or-nothing) |
| `SENTINEL_METRICS_TOKEN` or `_FILE` | required for `/metrics/prometheus` scrape |
| `SENTINEL_OTLP_ENDPOINT` | optional; enables in-process OTel-shaped hooks |
| `SENTINEL_ATTESTATION_ENDPOINT` + token | optional; https only |
| `SENTINEL_REDIS_URL` | required whenever more than one process serves traffic — see below |
| `SENTINEL_RATE_LIMIT_FAIL_OPEN` | required explicit in production |
| `SENTINEL_SINGLE_PROCESS_ATTESTED` | only consulted when the topology cannot be observed |
| `SENTINEL_REQUIRE_EXECUTION_BINDING` | required explicit in production — see below |

<a id="deployment--binding-every-execution-to-an-authorization"></a>
#### Binding every execution to an authorization

`SENTINEL_REQUIRE_EXECUTION_BINDING` decides whether the **unbound** tool path
still works.

`ProtectedToolRunner.execute` takes a description of the intended action and,
separately, an opaque zero-argument closure. Policy is evaluated over the
description; the closure then runs and can do anything. So an agent approved to
write one bucket can write another, and the passport, its signature and the
transparency proof all still verify — because each is a true statement about
the *decision*, and the decision was never about what ran.

`execute_bound` closes that: it takes an `ExecutionAuthorization` committing to
a parameter digest, re-checks the digest immediately before the side effect, and
passes the **verified** parameters into the tool.

| Value | Effect |
|---|---|
| `false` | both paths work. The deployment is only as bound as its call sites happen to be |
| `true` | the unbound path refuses. Every side effect needs an authorization |

**Production refuses to start unless you state one.** There is no safe default:
`false` leaves unbound executions possible, `true` stops any call site not yet
migrated, and a security control that takes the service down on upgrade gets
reverted rather than adopted. Same reasoning as
`SENTINEL_RATE_LIMIT_FAIL_OPEN`.

Migrate call sites to `execute_bound`, then set this to `true`. Until it is
`true`, do not describe the deployment as binding authorization to execution —
see [`ARCHITECTURE.md`](ARCHITECTURE.md#execution_trust_architecture) for the
residual that remains even when it is.

<a id="deployment--the-process-count-is-observed-not-declared"></a>
#### The process count is observed, not declared

A per-process rate limiter is only the whole limiter if there is one process.
`SENTINEL_WORKER_SHARD_COUNT` used to be the only signal, and it is a
declaration — so

```bash
uvicorn sentinel.interface.asgi:app --workers 4
```

with that variable unset left the declared count at 1, passed every check, and
gave you four independent limiters each permitting the full configured rate.

Startup now reads the process table instead: the worker flag on the launch
command, and sibling processes sharing the same parent and executable. If more
than one process is serving and `SENTINEL_REDIS_URL` is unset, **the service
refuses to start** and says how many processes it saw. Correcting
`SENTINEL_WORKER_SHARD_COUNT` will not clear that refusal, because it is not
what was read.

**On Windows there is no `/proc`, so the count is `UNOBSERVABLE`** — which is
deliberately not treated as "one process". In production that also refuses,
unless you set `SENTINEL_SINGLE_PROCESS_ATTESTED=true` to state on the record
that this deployment runs a single process. An attestation cannot override a
contradicting observation; if the process table says four, four is the answer.

Outside production the unobservable case passes, because a developer machine
that cannot be inspected is also not serving traffic.

`sentinel preflight` cannot check any of this and says so in its own output.
Running the observation from a CLI would report on the CLI — one process, every
time, whatever the deployment looks like.

<a id="deployment--kubernetes--helm"></a>
### Kubernetes / Helm

- Manifests: `deploy/k8s/sentinel.yaml`, `deploy/helm/sentinel/`
- CI validates: `helm lint`, `kubeconform`, probe paths against live router
- Probes must hit `/health/live` and `/health/ready` (not a generic `/health`)
- Chart includes NetworkPolicy, PDB, HPA templates

<a id="deployment--local-kind--k3d-validation-operator"></a>
### Local kind / k3d validation (operator)

```bash
# kind example
kind create cluster --name sentinel
helm lint deploy/helm/sentinel --strict
helm template sentinel deploy/helm/sentinel > /tmp/sentinel-rendered.yaml
kubeconform -strict -summary /tmp/sentinel-rendered.yaml
# After secrets exist for postgres/auth/metrics/signer:
# helm upgrade --install sentinel deploy/helm/sentinel -n sentinel --create-namespace
# kubectl -n sentinel rollout status deploy/sentinel
# kubectl -n sentinel get --raw /api/v1/namespaces/sentinel/services/http:sentinel:8000/proxy/health/ready
```

<a id="deployment--cluster-drills"></a>
### Cluster drills

**UNVERIFIED in this environment** — no live cluster was exercised for this report.
Operators must: apply manifests in a staging cluster, confirm probes, rolling
restart, and multi-replica rate-limit behaviour with Redis.


<a id="disaster_recovery"></a>
<a id="disaster_recovery--disaster-recovery"></a>
## Disaster recovery

<a id="disaster_recovery--design-intent"></a>
### Design intent

- SQLite/Postgres durable state; work queue and outbox are DB-backed.
- Backup module: `sentinel/infrastructure/persistence/backup.py`
- Tests: `tests_arch/test_persistence_backup_pitr.py`
- CLI: `python -m sentinel.interface.cli backup-help`

<a id="disaster_recovery--suggested-rpo--rto-targets"></a>
### Suggested RPO / RTO targets

| Objective | Suggested target | Status |
|---|---|---|
| RPO (Postgres PITR, busy system) | ≤ 5 minutes | **measured: 1.42 s** after an unclean crash, write volume rotating segments (also: dump round-trip 0 s) |
| RPO (Postgres PITR, quiet system) | ≤ 5 minutes | **measured: 57.19 s** worst case, bounded by `archive_timeout = 60s` |
| RTO (API restore) | ≤ 30 minutes | **measured: 8.4–13.0 s** restore+replay+promote (also: dump round-trip ~0.05 s). Cross-region failover still not measured |
| RPO/RTO (SQLite file drill) | see below | **measured locally** |

The quiet row is the one that governs a real deployment's promise: it is the
worst case for a system that is not writing hard enough to rotate WAL segments
by itself, and it is bounded by a setting rather than by luck. Set
`archive_timeout` to the RPO you intend to promise.

The two Postgres rows are backed by two different drills that prove different
things, and both records are kept. A dump round-trip measures restore
correctness for a snapshot you took on purpose; its RPO is 0 by construction,
because nothing is written between the backup and the "failure". Continuous WAL
archiving is the claim the ≤5m RPO target is actually about — how much committed
data is lost when a running server dies without warning — and its RPO cannot be
0, because the segment being written at the moment of the crash was never
archived.

<a id="disaster_recovery--local-sqlite-drill-this-run"></a>
### Local SQLite drill (this run)

Command: `PYTHONPATH=. python scripts/run_dr_sqlite_drill.py`

| Metric | Value |
|---|---|
| ok | true |
| schema_version | 10 |
| backup_seconds | 0.0084 |
| restore_seconds | 0.0035 |
| verify_seconds | 0.0002 |
| experimental_rto_seconds | 0.0037 |
| experimental_rpo_seconds | 0.0 |
| notes | Offline file-copy after writers stopped; not multi-AZ failover |

Raw: `archive/pre-cleanup:docs/dr_sqlite_drill.json`.

<a id="disaster_recovery--postgres-pitr--region-loss"></a>
### Postgres PITR / region loss

**Measured this session** via embedded `pgserver` +
`scripts/run_dr_postgres_pitr_with_pgserver.py` → `archive/pre-cleanup:docs/dr_postgres_pitr_drill.json`:

| Metric | Value |
|---|---|
| status | measured_dump_roundtrip |
| experimental_rpo_seconds | 0.0 |
| experimental_rto_seconds | ~0.05 |
| meets_rpo_target (≤300s) | true |
| meets_rto_target (≤1800s) | true |
| notes | SQL dump round-trip of probe table only — NOT continuous WAL archive PITR / region failover |

<a id="disaster_recovery--postgres-continuous-wal-archive-pitr-measured-2026-08-12"></a>
### Postgres continuous WAL archive PITR (measured 2026-08-12)

Command: `PYTHONPATH=. python scripts/run_dr_postgres_wal_pitr_drill.py`
Raw: `archive/pre-cleanup:docs/dr_postgres_wal_pitr_drill.json`. Guarded by
`tests_arch/test_dr_postgres_wal_pitr_drill.py`.

What the drill actually does, in order: `initdb`; enable `wal_level=replica`
and `archive_mode=on` with a real `archive_command`; `pg_basebackup`; write
4 batches × 200 rows, forcing a segment switch after each batch **except the
last**; kill the server with `pg_ctl stop -m immediate` (no checkpoint, no clean
shutdown, no final archive push); then recover **twice** from the base backup and
the archive alone, with the crashed data directory left untouched.

| Metric | Value |
|---|---|
| status | measured_continuous_wal_archive |
| rows committed before crash | 800 |
| WAL segments archived before crash | 6 |
| crash mode | `pg_ctl stop -m immediate` |
| **experimental_rpo_seconds** | **1.4184** |
| rows lost to the unarchived open segment | 200 (all of batch 4) |
| last recoverable commit | `2026-08-12 11:01:55.741331+00` |
| last commit before crash | `2026-08-12 11:01:57.159688+00` |
| **experimental_rto_seconds** (restore + replay + promote) | **13.0248** |
| meets_rpo_target (≤ 300 s) | true |
| meets_rto_target (≤ 1800 s) | true |
| total drill wall-clock | 41.53 s |

**Point-in-time selection was verified, not assumed.** A second recovery
targeted `recovery_target_time = 2026-08-12T11:01:54.655810+00:00`, just after
batch 2:

| Check | Value |
|---|---|
| pitr_target_batch | 2 |
| pitr_observed_max_batch | 2 |
| pitr_rows_at_target | 400 of 800 |
| pitr_selected_point_in_time | true |

Batches 3 and 4 were absent from that recovery and present in the
recover-to-latest run (max batch 3). A restore that replays to the end would
have returned all of them; this one stopped where it was told.

<a id="disaster_recovery--the-quiet-system-case-archive_timeout-is-what-bounds-rpo-measured"></a>
#### The quiet-system case: `archive_timeout` is what bounds RPO (measured)

The 1.42 s above is a property of *that workload*, not of the configuration. It
was produced by writing hard enough to force a segment switch every ~1.3 s. A
quiet production system fills a 16 MB segment slowly, and everything sitting in
that open segment is lost in a crash however long ago it was committed — so
without `archive_timeout` the data-loss window is bounded by write volume, which
is to say not bounded at all.

`archive_timeout = 60s` is now set in `docker-compose.yml`, and the low-traffic
case has been measured against that exact value:

Command: `PYTHONPATH=. python scripts/run_dr_postgres_wal_pitr_drill.py --quiet --archive-timeout 60`
Raw: `archive/pre-cleanup:docs/dr_postgres_wal_pitr_quiet_drill.json`.

The run writes 20 rows, then **idles with no writes at all** and watches the
archive; then writes 20 more and crashes just *before* the next timeout fires,
which is the worst moment to lose the node rather than a lucky one.

| Metric | Value |
|---|---|
| status | measured_continuous_wal_archive_quiet |
| archive_timeout | 60 s |
| segments archived before the idle window | 3 |
| segments archived after the idle window | 4 |
| **timeout forced a switch with zero writes** | **true** |
| rows committed before crash | 40 |
| **experimental_rpo_seconds (worst case)** | **57.19** |
| rows lost to the unarchived segment | 20 |
| last recoverable commit | `2026-08-12 12:17:13.194836+00` |
| last commit before crash | `2026-08-12 12:18:10.383213+00` |
| experimental_rto_seconds | 8.4 |
| meets_rpo_target (≤ 300 s) | true |

Two things are established, and they are different claims:

1. **The mechanism works.** The archive gained a segment during a window in
   which the drill issued no writes whatsoever (3 → 4). Nothing but
   `archive_timeout` could have caused that switch.
2. **The worst-case RPO for a quiet system is ~`archive_timeout`.** 57.19 s
   against a 60 s setting, leaving ~5× margin under the ≤5 m target. Set the
   timeout to the RPO you intend to promise; that is the knob.

<a id="disaster_recovery--which-number-applies-to-you"></a>
#### Which number applies to you

| Situation | Measured RPO | What sets it |
|---|---|---|
| Busy: write volume rotates segments | **1.42 s** | how fast segments fill |
| Quiet: nothing but the timeout rotates | **57.19 s** | `archive_timeout` (60 s) |
| Quiet, `archive_timeout` unset | **not measured — unbounded** | segment fills eventually, or never |

The third row is the one to avoid, and it is what this repository shipped before
2026-08-12.

<a id="disaster_recovery--two-caveats-from-the-measurement-itself"></a>
#### Two caveats from the measurement itself

- **You cannot recover to a point past your last archived segment.** An early
  quiet run targeted a time 250 ms after the last archived commit and Postgres
  refused outright: `FATAL: recovery ended before configured recovery target was
  reached`. The recoverable window ends at the archive, not at the crash.
- **`recovery_target_time` compares against WAL commit timestamps, not your
  columns.** Targeting the exact value of the application's `written_at` (which
  is transaction-*start* time) recovered 19 of 20 rows in that batch, because the
  final row's commit landed fractionally after its own `written_at`. Choose
  recovery targets with a margin, and verify by row count rather than by
  assuming.

<a id="disaster_recovery--where-to-set-it-and-how-it-is-now-enforced"></a>
#### Where to set it, and how it is now enforced

`docker-compose.yml` sets `archive_mode`, `archive_command`, `archive_timeout=60s`
and a separate archive volume. **The Helm chart cannot**: it does not deploy
PostgreSQL, it consumes a DSN from an existing secret, so these must be set on
whatever runs the database.

That used to be communicated by a line in `NOTES.txt`, printed *after* a
successful install — i.e. after the point where it could prevent anything. Two
mechanisms replace it:

1. **The chart refuses to render** without
   `externalPostgres.archiveTimeoutConfirmed: true`. `values.schema.json` demands
   the literal `true` and the shipped default is `false`, so a default
   `helm install` fails rather than silently producing a deployment with no
   bounded RPO. CI sets it explicitly and separately asserts that the default
   render still fails, so the gate cannot rot into a no-op.
2. **`helm test` checks the claim against the server.** An acknowledgement is
   only a statement; `templates/tests/postgres-archive-check.yaml` connects using
   the same DSN secret the application uses and runs `SHOW archive_mode`,
   `SHOW archive_command`, `SHOW archive_timeout`, `SHOW wal_level`. It fails on
   the two configurations that look correct and are not: `archive_mode=on` with
   an empty `archive_command` (segments are marked archived and discarded), and
   `archive_timeout=0` (a quiet database archives only when a segment fills).

Verified this session, executed: `tests_arch/test_helm_postgres_archive.py`
starts PostgreSQL with the flags parsed out of `docker-compose.yml` and asserts
the running server reports them — `archive_mode=on`, `wal_level=replica`,
`archive_timeout` in `{60s, 1min}`, a non-empty non-overwriting
`archive_command`. That is the settings landing in a live server's configuration
rather than in a values file.

**Not verified:** the `helm test` hook has never run against a real cluster, for
the same reason the kind/Helm smoke row is UNVERIFIED — there is no Docker,
kubectl or helm in this environment and no rights to install them.

<a id="disaster_recovery--the-archive-shares-a-failure-domain-with-the-database-default-and-the-way-off-it-measured-2026-08-18"></a>
#### The archive shares a failure domain with the database (default), and the way off it (measured 2026-08-18)

`docker-compose.yml`'s **default** archives WAL to the `pgwalarchive` volume,
which lives on the same host and the same disk as `pgdata`. Losing that disk
loses the database **and** every WAL segment needed to recover it, so what the
default configures is point-in-time recovery from operator error, not survival of
hardware loss. It is better than no archive and it is not a backup. That default
is unchanged, and it remains labelled as such.

What is new is a documented, working, **measured** path off it.

<a id="disaster_recovery--the-mechanism"></a>
##### The mechanism

`deploy/wal-archive/wal_s3.py` is an `archive_command`/`restore_command` pair over
`S3ObjectStore` — the same adapter the evidence blob store uses, so the archive
path is not a second, less-tested implementation of the S3 protocol. Configure it
in `postgresql.conf`:

```
archive_mode = on
archive_timeout = 60s
archive_command = 'python3 /opt/sentinel/wal-archive/wal_s3.py archive %p %f'
restore_command = 'python3 /opt/sentinel/wal-archive/wal_s3.py restore %f %p'
```

Credentials come from the environment (`SENTINEL_WAL_S3_*`), never the command
line — `archive_command` is world-readable to anyone who can run
`SHOW archive_command`.

Three contract properties, each verified against a live MinIO rather than argued:

| Behaviour | Why it matters | Observed |
|---|---|---|
| Exit 0 only after read-back + SHA-256 match | PostgreSQL may recycle the segment the instant it exits 0 | `archive rc: 0` |
| Re-archiving identical bytes exits 0 | A retry after an ambiguous failure must be safe | `re-archive identical rc: 0` |
| Archiving **different** bytes under an existing name is refused | Clobbering an archived segment destroys the recovery source for that timeline | `overwrite-with-different rc: 1` |
| Missing segment on restore exits 1, transport failure exits 2 | Exit 1 is how PostgreSQL learns the archive is exhausted; conflating the two truncates recovery at the first blip | `restore missing rc: 1` |

<a id="disaster_recovery--the-drill-with-the-node-actually-destroyed"></a>
##### The drill, with the node actually destroyed

`scripts/run_dr_postgres_wal_pitr_drill.py --archive-to s3`. Unlike the local
drill, which merely leaves the crashed directory untouched, this one **deletes
it** — along with any local archive directory — before recovering. A dependency
on the failed node is therefore a hard failure rather than a subtle one.

| | Measured | Target |
|---|---|---|
| Data directory destroyed before recovery | **140,435,288 bytes** | — |
| Local archive directory destroyed | yes | — |
| WAL segments archived to object storage | 7 | — |
| **RPO** | **18.27 s** | ≤ 300 s ✅ |
| **RTO** | **127.83 s** | ≤ 1800 s ✅ |
| PITR selection (target after batch 2 of 4) | recovered max batch **2**, 400 rows | exact ✅ |
| Rows lost to the unarchived segment | 200 | — |

Raw: `archive/pre-cleanup:docs/dr_postgres_wal_pitr_s3_drill.json`.

<a id="disaster_recovery--object-storage-costs-rpo-and-rto-and-here-is-by-how-much"></a>
##### Object storage costs RPO and RTO, and here is by how much

Against the local-directory drill on the same workload, both numbers got
**worse**, and that is the useful part of the result:

| | Local directory | Object storage | Ratio |
|---|---|---|---|
| RPO | 1.42 s | **18.27 s** | 12.9× |
| RTO | 13.02 s | **127.83 s** | 9.8× |

The cause is not the network — everything here is loopback. It is that
`archive_command` and `restore_command` each **spawn a Python process per
segment**, and that process imports the `sentinel` package before it moves a
byte. Archiving falls behind, so more committed data sits in an unarchived
segment when the crash lands (RPO), and replay pays the same startup cost once
per segment (RTO). Both are still inside target with an order of magnitude to
spare, so this is a cost to know about rather than a blocker — but a deployment
that needs single-digit-second RPO should use a long-lived archiver process
(pgBackRest, WAL-G) speaking to the same bucket, not this script. The script's
value is that it is auditable, has no new dependencies, and is measured.

<a id="disaster_recovery--node-loss-vs-site-loss--the-three-topologies-kept-distinct"></a>
##### Node loss vs SITE loss — the three topologies, kept distinct

Re-run on 2026-08-19 with the object store moved **off loopback** onto a real
network interface. The drill now records which topology produced a result, so a
reader cannot mistake one for another:

| `topology` | What it is | `proves_node_loss` | `proves_site_loss` |
|---|---|---|---|
| `same_host_loopback` | MinIO on `127.0.0.1`. Same kernel; the TCP never reaches a NIC | ✅ | ❌ |
| `same_host_real_interface` | MinIO bound to a real interface. Through the NIC and routing table, **still one host** | ✅ | ❌ |
| `external` | An endpoint the drill did not start (`--object-store-url`). The drill claims nothing about where it lives | ✅ | operator-attested |

Measured, both on the same workload:

| | loopback (2026-08-18) | **real interface (2026-08-19)** |
|---|---|---|
| Endpoint | `http://127.0.0.1:…` | `http://192.168.1.12:65034` |
| **RPO** | 18.27 s | **17.61 s** |
| **RTO** | 127.83 s | **137.15 s** |
| PITR selection exact | ✅ | ✅ |
| `pgdata` destroyed before recovery | 140,435,288 B | **157,204,312 B** |

Taking the archive off loopback cost ~9 s of RTO and left RPO essentially
unchanged. That is the useful result: **the loopback shortcut was not what made
the earlier numbers look good.** The archive path holds up when it goes through
a real NIC and routing table.

<a id="disaster_recovery--exactly-what-site-loss-would-require-and-why-it-is-not-achievable-here"></a>
##### Exactly what site loss would require, and why it is not achievable here

"UNVERIFIED" on its own is not useful, so here is the narrow version.

**What is missing is one thing: a second failure domain.** Every topology above
runs PostgreSQL and the object store on the same physical machine, so a fire,
a power cut, a disk-controller failure or a stolen laptop takes both regardless
of which interface the bytes crossed.

**Why not here:** this development machine has **no Docker** (`docker: NOT
INSTALLED`), **no WSL distribution** (`wsl -l -q` returns nothing), and the
account is **not an administrator**, so neither can be installed. A second
container is not a second host either — it would share the same kernel, disk
and power supply — so even with Docker present the claim would not improve.

**The exact command that would close it**, once a bucket exists in a different
datacentre or region:

```bash
export SENTINEL_WAL_S3_ACCESS_KEY=...      # credentials for the remote bucket
export SENTINEL_WAL_S3_SECRET_KEY=...
export SENTINEL_WAL_S3_BUCKET=sentinel-wal-prod
PYTHONPATH=. python scripts/run_dr_postgres_wal_pitr_drill.py     --archive-to s3     --object-store-url https://s3.eu-west-1.amazonaws.com
```

That run records `topology: external` and `proves_site_loss: true`. The drill
still will not assert *how far* away the bucket is — it cannot know — so the
operator running it must record the region alongside the result.

**Minimum bar for the claim:** the object store must be in a different
availability zone from the database, with no shared power, cooling or network
spine. Two regions is stronger. A second VM in the same rack is not.

<a id="disaster_recovery--what-this-does-not-establish"></a>
##### What this does NOT establish

Stated plainly, in the same terms the kind/Helm row uses:

- **MinIO ran on the same host as the database.** This proves the archive path
  works over the S3 protocol, and that recovery needs *nothing* from the
  database's data directory. It does **not** prove survival of a datacentre, a
  region or an availability zone. That needs a genuinely remote bucket, which
  this environment does not have.
- **No cross-region replication, object-lock or lifecycle policy was exercised.**
  Those are bucket-side configuration. An archive in a bucket an attacker can
  delete is not a backup either; object-lock is the control, and it is
  unverified here.
- The `postgres:16` **container image** was not used — no Docker in this
  environment; the server was the embedded `pgserver` PostgreSQL 16.2 binaries.

<a id="disaster_recovery--still-not-measured"></a>
#### Still not measured

- Cross-region / multi-AZ failover. One host, even with the archive in object
  storage.
- Object-lock / immutability on the archive bucket.
- `postgres:16` container image (no Docker here — embedded `pgserver` binaries).

Handoff for docker postgres:16:

```powershell
$env:SENTINEL_TEST_POSTGRES_DSN = "postgresql://postgres:postgres@127.0.0.1:5432/postgres"
$env:PYTHONPATH = "."
py -3 scripts/run_dr_postgres_pitr_drill.py
# or without an external DSN:
py -3 scripts/run_dr_postgres_pitr_with_pgserver.py
```

Without a DSN the drill script records `status=UNVERIFIED` and exits 2 (does not invent RPO/RTO).

<a id="disaster_recovery--restore-outline"></a>
### Restore outline

1. Scale writers to 0.
2. Restore DB / PITR.
3. `python -m sentinel.interface.cli verify`
4. Start one API; `/health/ready`
5. Reap leases; scale workers.


<a id="dr_runbook"></a>
<a id="dr_runbook--disaster-recovery-runbook"></a>
## Disaster recovery runbook

**`disaster_recovery_proof` is `UNVERIFIED` and this document does not change
that.** What follows is a tested mechanism and an untested boundary, and the
difference is the whole point.

---

<a id="dr_runbook--what-is-measured"></a>
### What is measured

Automated PITR drills exist and run:

```bash
python scripts/run_dr_postgres_wal_pitr_drill.py
```

| Measured | Value |
|---|---|
| **RPO with `archive_timeout = 60s`** | **≈ 57 s** |
| RPO without it | **Unbounded** |
| Recovery to a requested instant | Verified |
| A target beyond the archived WAL | **Refused, never reported as verified** |
| A target before the backup | Refused before copying anything |

That last pair matters more than the successful restore. A drill that reports
success for a recovery point it cannot actually reach is worse than no drill,
because the RPO number it produces is fiction.

<a id="dr_runbook--why-the-gate-still-fails"></a>
### Why the gate still fails

The drill's own artifact says it, in its own words:

> `"failure_domain": "SAME HOST AND SAME DISK as pgdata. This is
> docker-compose.yml's current shape and is why the gate row reads fail."`

**The WAL archive sits on the same host and the same disk as the data it
protects.** A drill that does not cross a failure boundary has not tested one.
Losing that disk loses the database *and* the archive.

The mechanism is proven. The boundary is not. Those are different claims and
conflating them is how a DR posture becomes a slide instead of a capability.

<a id="dr_runbook--what-would-make-it-pass"></a>
### What would make it PASS

1. **A second region or account must exist.** Not configured — existing. This is
   the actual blocker and it is a provisioning decision, not an engineering one.
2. Continuous WAL archiving to storage in that domain — S3 cross-region
   replication, Object Lock enabled.
3. A drill executed **across** the boundary, restoring into the second domain
   from nothing but the archive.
4. Measured RPO and RTO from that drill.
5. **Execution Passports verified after recovery** — the evidence chain must
   survive, or the recovery restored data without restoring the thing that makes
   the data trustworthy.

Step 5 is the one specific to Sentinel. Any database restore proves rows came
back. Only passport verification proves the *evidence* came back intact, and
`sentinel passport verify` runs without a Sentinel server, so it works on a
restored dataset before the service is up.

<a id="dr_runbook--recovery-procedure"></a>
### Recovery procedure

<a id="dr_runbook--1-assess"></a>
#### 1. Assess

```bash
python -m sentinel.interface.cli preflight
```

Determine what was lost: the database, the evidence objects, or both. They fail
independently — evidence is in S3, and the database holds digests that
*reference* those objects.

<a id="dr_runbook--2-restore-the-database"></a>
#### 2. Restore the database

Restore to the latest consistent point, or a specific instant:

```bash
python scripts/run_dr_postgres_wal_pitr_drill.py --target-time "<ISO-8601>"
```

The restore is configured to **pause** and listen on its own port, so it can be
inspected before anything is promoted. A restore that immediately becomes
authoritative is a restore you cannot check.

**A restore never archives into the archive it came from.** That is tested,
because a restored instance writing WAL into the source archive corrupts the
thing you are recovering from.

<a id="dr_runbook--3-verify-the-evidence-chain"></a>
#### 3. Verify the evidence chain

```bash
python -m sentinel.interface.cli passport verify <passport.json>
```

Restored rows with a broken hash chain are not recovered evidence. Check
`previous_passport_digest` linkage across the restore boundary — a gap there
means passports were lost, and the honest report is that the chain has a hole,
not that recovery succeeded.

<a id="dr_runbook--4-confirm-tenant-isolation-survived"></a>
#### 4. Confirm tenant isolation survived

Row-level security is schema state and comes back with the schema. **Confirm it
rather than assume it:**

```bash
pytest tests_arch/test_tenant_isolation_rls.py
```

A restore that dropped `FORCE` on a policy would leave the database working and
the isolation boundary gone — the worst possible combination, because nothing
visibly fails.

<a id="dr_runbook--5-start-and-watch"></a>
#### 5. Start, and watch

Bring up one replica. Watch `authorization_latency_p99`, `dlq_depth` and
`evidence_chain_breaks` before rolling the rest.

<a id="dr_runbook--rto"></a>
### RTO

**`UNVERIFIED`.** No cross-domain drill has run, so no RTO has been measured.

The PITR drill measures restore time within a single host, which is not an RTO —
it excludes provisioning the second domain, DNS, and bringing dependencies up.
Publishing that number as an RTO would be the same species of claim as a green
gate that measured nothing.

<a id="dr_runbook--what-is-not-automated"></a>
### What is not automated

| Not automated | Why |
|---|---|
| Infrastructure reconstruction | Terraform is `plan`-only; nothing has been applied |
| Cross-region failover | The second domain does not exist |
| DNS cutover | Deployment-specific |
| Tenant-selective restore | Restore is whole-database; per-tenant would need export/import per tenant |

That last one is worth knowing before an incident: if one tenant needs a
point-in-time restore and the others do not, the current mechanism does not
offer it.

---

<a id="dr_runbook--related"></a>
### Related

- [`DISASTER_RECOVERY.md`](OPERATIONS.md#disaster_recovery) — drill detail and artifacts
- [`PRODUCTION_RUNBOOK.md`](OPERATIONS.md#production_runbook)
- [`RELEASE_READINESS.md`](RELEASE_READINESS.md) — why this gate stays UNVERIFIED
- [`aws/ARCHITECTURE.md`](ARCHITECTURE.md#aws_architecture)


<a id="monitoring"></a>
<a id="monitoring--monitoring"></a>
## Monitoring

See [OBSERVABILITY.md](OPERATIONS.md#observability) for SLIs/SLOs, correlation IDs, Prometheus,
and health probe contracts. Legacy “LIVE monitoring” surfaces were removed (F-7).


<a id="observability"></a>
<a id="observability--observability"></a>
## Observability

<a id="observability--surfaces"></a>
### Surfaces

| Surface | Auth | Notes |
|---|---|---|
| `GET /health/live` | none | Opaque liveness for kubelet. The only throttle-exempt path |
| `GET /health/ready` | none | Opaque readiness (`ready` bool only). Adds `detection_mode` **only** when `SENTINEL_READY_EXPOSE_DETECTION_MODE=true` |
| `GET /health/diagnostics` | capability `read_diagnostics` | Backend detail, incl. `detection_mode` and `detector_version` |
| `GET /metrics/prometheus` | Bearer `SENTINEL_METRICS_TOKEN` | Process metrics; never unauthenticated |
| Structured logs | n/a | JSON lines via `StructuredLogger` |
| Correlation | `X-Request-Id` | Also tenant / incident / epoch / worker on worker path |
| OTLP hooks | `SENTINEL_OTLP_ENDPOINT` | No-op when unset; no extra OTel package required |

<a id="observability--correlation-fields"></a>
### Correlation fields

HTTP middleware binds `request_id` (from `X-Request-Id` / `X-Correlation-Id` or minted).
Authenticated requests enrich `tenant_id`. Workers bind `tenant_id`, `incident_id`,
`epoch` (lease), and `worker_shard`.

<a id="observability--prometheus-scrape"></a>
### Prometheus scrape

`deploy/prometheus.yml` scrapes `/metrics/prometheus` with a bearer token file.
Docker Compose includes a prometheus service.

<a id="observability--slis--slos"></a>
### SLIs / SLOs

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

<a id="observability--detection-status"></a>
### Detection status

| Signal | Surface | Auth |
|---|---|---|
| `sentinel_detection_mode{mode="rules-only-configured"} 1.0` | `/metrics/prometheus` | Bearer |
| `detection_mode`, `detector_version` | `/health/diagnostics` | capability |
| `detection_mode` | `/health/ready` | none — **opt-in only** |

`SENTINEL_READY_EXPOSE_DETECTION_MODE` defaults to **false**. Readiness is
unauthenticated. Enable it only where the readiness port is genuinely
cluster-internal.

<a id="observability--alerts-suggested"></a>
### Alerts (suggested)

- Ready probe failing on all replicas
- Metrics scrape auth failures spike (token rotation)
- Protect kill switch engaged (`diagnostics.protect_kill_switch`)
- Outbox / queue depth growth sustained

Wire alertmanager separately; this tree does not claim live paging.


<a id="production_runbook"></a>
<a id="production_runbook--production-runbook"></a>
## Production runbook

Operating Sentinel in production, and what to do when it refuses to start.

---

<a id="production_runbook--preflight-refuses-deliberately"></a>
### Preflight refuses, deliberately

Sentinel **will not boot** in production with an unsafe configuration. That is
not defensive programming; a security control plane that starts degraded is
worse than one that does not start, because the first is trusted.

`production_preflight` is a release gate with 22 tests. It fails on:

| Refusal | Why |
|---|---|
| Wildcard CORS | A credentialed API with `*` origin is a cross-origin read of everything |
| Exposed API docs | Reconnaissance, free |
| Missing metrics token | An unauthenticated metrics scrape is a data surface |
| Keys under 32 characters | Brute-forceable |
| **SQLite** | Production semantics were never proven on it, and the predecessor's worst defect was invisible there |
| Schema behind or ahead of the build | Ahead is the rollback case people forget — `verify` compares for equality, not `>=` |
| Unresolvable SIEM credential | Silent unauthenticated export of a tenant's security events |

Each refusal names the variable to set. "Configuration invalid" sends an
operator to read the source during an incident.

<a id="production_runbook--startup"></a>
### Startup

```bash
python -m sentinel.interface.cli migrate      # never automatic
python -m sentinel.interface.cli preflight    # read the output
gunicorn 'sentinel.interface.asgi:create_application()' \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 --workers 4 --timeout 120
```

**Migrations are never automatic on startup.** Four workers booting
concurrently would race, and a migration that half-applies under contention is
the failure that takes a schema somewhere no rollback describes. `verify()`
refuses to serve a schema it did not expect, which turns that race into a
failed deploy instead of a corrupted database.

<a id="production_runbook--health-endpoints-and-what-each-means"></a>
### Health endpoints, and what each means

| Endpoint | Answers | Auth |
|---|---|---|
| `/health/live` | Is the process alive | None; throttle-exempt |
| `/health/ready` | Can it serve traffic | None; **throttle-exempt, probe memoised 1s** |
| `/health/diagnostics` | *Why* not | `READ_DIAGNOSTICS` |

Readiness returns booleans only. The exception text from a failed probe carries
the DSN, the internal hostname and the driver version, and this endpoint is
unauthenticated — so the detail lives behind a capability. The answer to
reconnaissance is not to withhold what an operator needs; it is to require a
credential for it.

**The readiness cache is a security precondition, not an optimisation.**
`/health/ready` queries the database and is exempt from rate limiting. Without
the 1-second memo, that is an unauthenticated unmetered load amplifier anyone
can aim at your database. Remove the cache and the exemption must go with it —
a test fails if either module stops naming the other.

<a id="production_runbook--when-things-go-wrong"></a>
### When things go wrong

<a id="production_runbook--readiness-is-failing"></a>
#### Readiness is failing

`/health/diagnostics` names the component. Most often the database. The pod
marks itself NotReady and sheds traffic, which is correct.

Watch for the **cascade**: a throttled readiness probe also marks a pod
NotReady, shedding it and moving its load onto the remaining pods — under
exactly the load that caused the throttling. The soak measured 27 of 270 probes
answered 429 at ~180 rps from a single address. That is why readiness is
throttle-exempt now.

<a id="production_runbook--the-dead-letter-queue-is-filling"></a>
#### The dead-letter queue is filling

Something downstream is refusing delivery. **The events are not lost** — that is
what the outbox is for.

```bash
python -m sentinel.interface.cli dlq list
```

A `siem` record in the DLQ usually means an unresolvable `credential_ref`. The
error names the variable. `SiemNotConfigured` is **retryable** on purpose: the
fix is an operator configuring the tenant, and a non-retryable failure would
move the record past the window in which somebody notices while the event still
matters.

<a id="production_runbook--backups"></a>
### Backups

- WAL archiving to durable storage, `archive_timeout = 60s`
- **Measured RPO ≈ 57s** with the timeout set; **unbounded without it**

The Helm chart refuses to render until an operator confirms continuous
archiving is configured, because the chart consumes a DSN it cannot configure
and the RPO depends on settings it cannot apply.

**Restore is tested. Cross-region recovery is not** — see
[`DR_RUNBOOK.md`](OPERATIONS.md#dr_runbook). `disaster_recovery_proof` is `UNVERIFIED` and
the drill artifact says why in its own words.
<a id="production_runbook--upgrades"></a>
### Upgrades

1. Build once, sign once. **Production runs the artifact CI tested** — never a
   rebuild.
2. Apply migrations before rolling pods.
3. Roll one replica; watch readiness and authorization latency.
4. Roll the rest.

Rolling back **past a migration** needs a plan written before the deploy.
`verify()` refuses a schema ahead of the build, so an old binary against a new
schema fails at boot rather than at the first query that touches a moved
column.

---

<a id="production_runbook--related"></a>
### Related

- [`DR_RUNBOOK.md`](OPERATIONS.md#dr_runbook) · [`SOAK_RUNBOOK.md`](OPERATIONS.md#soak_runbook)
- [`OBSERVABILITY.md`](OPERATIONS.md#observability) · [`RELEASE_GATES.md`](RELEASE_GATES.md)
- [`aws/ARCHITECTURE.md`](ARCHITECTURE.md#aws_architecture)


<a id="soak_runbook"></a>
<a id="soak_runbook--soak-runbook"></a>
## Soak runbook

**`production_soak` is `UNVERIFIED`. The elapsed time *is* the evidence, and no
amount of engineering compresses thirty days into an afternoon.**

---

<a id="soak_runbook--running-it"></a>
### Running it

```bash
PYTHONPATH=. python scripts/run_observability_soak.py \
  --seconds 2592000 --production-shaped --postgres
```

`--production-shaped` runs the WorkerPool and MaintenanceLoop, so the queue
drains and the retention sweep runs. Without it the queue grows unboundedly and
the numbers describe a system nobody would deploy — which is how the original
624 ms measurement was taken.

`--postgres` runs against a real PostgreSQL 16 server as a **non-superuser**, so
`FORCE` row-level security applies and its predicate is inside the measured
cost. On SQLite the same workload measured 624 ms p95 and missed the target;
production is PostgreSQL, and the gap between the two is the point of testing
both.

The report is **rewritten every `--report-interval`**, so a run stopped early
still leaves a truthful record of the window it actually covered. A soak that
only produces output on clean completion produces nothing from the runs that
matter most.

<a id="soak_runbook--what-has-been-measured"></a>
### What has been measured

7 minutes, production-shaped, PostgreSQL 16:

| Surface | Requests | Failures | p50 | p95 | p99 |
|---|---|---|---|---|---|
| ingest | 16,082 | **0** | 34.0 ms | **71.6 ms** | 96.3 ms |
| `/health/ready` | 1,871 | **0** | 19.9 ms | 45.9 ms | 58.1 ms |

Throughput 38.3 rps. Availability observed 100% (17,953/17,953).

**Ingest p95 is 71.6 ms against a 500 ms target — met, with 7× headroom.**

<a id="soak_runbook--what-that-does-not-establish"></a>
### What that does not establish

**It is a floor, not a capacity figure.** The harness drove the load it was
configured to drive and never found the point where the service degrades. That
is why cost-per-event stays `UNVERIFIED` — dividing a monthly cost by a floor
produces an authoritative-looking number that is invented.

**It is an upper bound on availability.** The harness drives the app through an
in-process client: no network, no ingress, no load balancer, no second replica,
no rolling deploy. Every one of those is a real source of production
unavailability this cannot see.

**Seven minutes cannot sample a 30-day SLO.** 99.9% permits roughly 43 minutes
of downtime per month. A clean seven-minute window is *consistent with* the
target and does not demonstrate it. It rules out gross unavailability, which is
all a short run can do.

<a id="soak_runbook--what-a-real-soak-must-track"></a>
### What a real soak must track

| Signal | Failure it catches |
|---|---|
| **Event loss** | Any non-zero value is a product-defining failure. The outbox exists to make it impossible |
| Memory growth | A slow leak invisible in a short run — the single most common thing a soak finds |
| Queue depth trend | Detection falling behind faster than it catches up |
| Worker restarts | Crash-looping under sustained load |
| Database growth | Retention not actually reclaiming |
| Connection count | Pool exhaustion under sustained concurrency |
| **Evidence chain integrity** | A break here invalidates the product's core claim |
| Latency drift | Degradation that a p95 snapshot hides |
| Error-rate drift | Intermittent faults that a short run misses |
| Disk | The thing that ended three measurement attempts on this machine |

Memory growth and evidence-chain integrity are the two worth staring at. A leak
that takes 100 hours to matter is invisible in every other test in the suite,
and a chain break under sustained load would mean the evidence guarantee holds
only when the system is idle.

<a id="soak_runbook--do-not-fake-elapsed-time"></a>
### Do not fake elapsed time

Stated plainly because it is the obvious shortcut: **running for an hour and
extrapolating to thirty days is fabricating soak evidence.** So is running
thirty separate one-hour windows and summing them. A leak, a slow index bloat
and a certificate expiry all need continuous elapsed time to appear.

`production_soak` moves from `UNVERIFIED` when a real run has covered the
declared period. Nothing in this repository can write that gate —


<a id="soak_runbook--a-finding-the-soak-already-produced"></a>
### A finding the soak already produced

At ~180 rps from a single address, **27 of 270 readiness probes were answered
429**. `/health/ready` was not throttle-exempt, and a throttled readiness probe
marks the pod NotReady, sheds it from the Service, and moves its traffic onto
the remaining pods — under exactly the load that caused the throttling.

That cascade is now closed: readiness is exempt, and safely so because the
database probe is memoised for one second. Without the cache, exempting an
unauthenticated route that queries the database would trade a cascade risk for
a denial-of-service one.

**This is what a soak is for.** No unit test would have found it, because it
only appears under sustained load from one source.

---

<a id="soak_runbook--related"></a>
### Related

- [`OBSERVABILITY.md`](OPERATIONS.md#observability) — the SLI table and both soak records
- [`PERFORMANCE_REPORT.md`](PERFORMANCE_REPORT.md)
- [`PRODUCTION_RUNBOOK.md`](OPERATIONS.md#production_runbook)
- [`RELEASE_READINESS.md`](RELEASE_READINESS.md)
