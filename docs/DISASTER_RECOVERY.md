# Disaster recovery

## Design intent

- SQLite/Postgres durable state; work queue and outbox are DB-backed.
- Backup module: `sentinel/infrastructure/persistence/backup.py`
- Tests: `tests_arch/test_persistence_backup_pitr.py`
- CLI: `python -m sentinel.interface.cli backup-help`

## Suggested RPO / RTO targets

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

## Local SQLite drill (this run)

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

Raw: `docs/dr_sqlite_drill.json`.

## Postgres PITR / region loss

**Measured this session** via embedded `pgserver` +
`scripts/run_dr_postgres_pitr_with_pgserver.py` → `docs/dr_postgres_pitr_drill.json`:

| Metric | Value |
|---|---|
| status | measured_dump_roundtrip |
| experimental_rpo_seconds | 0.0 |
| experimental_rto_seconds | ~0.05 |
| meets_rpo_target (≤300s) | true |
| meets_rto_target (≤1800s) | true |
| notes | SQL dump round-trip of probe table only — NOT continuous WAL archive PITR / region failover |

## Postgres continuous WAL archive PITR (measured 2026-08-12)

Command: `PYTHONPATH=. python scripts/run_dr_postgres_wal_pitr_drill.py`
Raw: `docs/dr_postgres_wal_pitr_drill.json`. Guarded by
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

### The quiet-system case: `archive_timeout` is what bounds RPO (measured)

The 1.42 s above is a property of *that workload*, not of the configuration. It
was produced by writing hard enough to force a segment switch every ~1.3 s. A
quiet production system fills a 16 MB segment slowly, and everything sitting in
that open segment is lost in a crash however long ago it was committed — so
without `archive_timeout` the data-loss window is bounded by write volume, which
is to say not bounded at all.

`archive_timeout = 60s` is now set in `docker-compose.yml`, and the low-traffic
case has been measured against that exact value:

Command: `PYTHONPATH=. python scripts/run_dr_postgres_wal_pitr_drill.py --quiet --archive-timeout 60`
Raw: `docs/dr_postgres_wal_pitr_quiet_drill.json`.

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

### Which number applies to you

| Situation | Measured RPO | What sets it |
|---|---|---|
| Busy: write volume rotates segments | **1.42 s** | how fast segments fill |
| Quiet: nothing but the timeout rotates | **57.19 s** | `archive_timeout` (60 s) |
| Quiet, `archive_timeout` unset | **not measured — unbounded** | segment fills eventually, or never |

The third row is the one to avoid, and it is what this repository shipped before
2026-08-12.

### Two caveats from the measurement itself

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

### Where to set it, and how it is now enforced

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

### The archive shares a failure domain with the database (default), and the way off it (measured 2026-08-18)

`docker-compose.yml`'s **default** archives WAL to the `pgwalarchive` volume,
which lives on the same host and the same disk as `pgdata`. Losing that disk
loses the database **and** every WAL segment needed to recover it, so what the
default configures is point-in-time recovery from operator error, not survival of
hardware loss. It is better than no archive and it is not a backup. That default
is unchanged, and it remains labelled as such.

What is new is a documented, working, **measured** path off it.

#### The mechanism

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

#### The drill, with the node actually destroyed

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

Raw: `docs/dr_postgres_wal_pitr_s3_drill.json`.

#### Object storage costs RPO and RTO, and here is by how much

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

#### Node loss vs SITE loss — the three topologies, kept distinct

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

#### Exactly what site loss would require, and why it is not achievable here

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

#### What this does NOT establish

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

### Still not measured

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

## Restore outline

1. Scale writers to 0.
2. Restore DB / PITR.
3. `python -m sentinel.interface.cli verify`
4. Start one API; `/health/ready`
5. Reap leases; scale workers.
