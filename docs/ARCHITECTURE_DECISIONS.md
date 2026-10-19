# Architecture decisions: what was built, what was deleted, what is out of scope

<!-- unbacked-citations-retracted -->

> ## ⚠️ RETRACTION — the evidence column in this document is not backed by this repository
>
> **Added 2026-08-19 by an automated check, not by a reviewer's judgement.**
>
> `tests_arch/test_documentation_cites_real_tests.py` scans every document for
> test identifiers and requires each to resolve to a test `pytest` actually
> collects. It found that this document cites a **`tests/` directory that does
> not exist in this repository** — for example `test_postgres_live`, `test_durable_queue_live` and
> `test_no_overclaiming`. The suite here lives in
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


Every enterprise capability below was either **implemented and verified**,
**deliberately removed**, or **declared out of scope with a reason**. Nothing is
left half-present, because half-present infrastructure is what produced three
consecutive council findings: a component appears in the deployment files, is
never read by any code, and a reader reasonably concludes it works.

The rule applied throughout: *if it is not wired and verified, it does not appear
in a manifest, a banner, a dashboard, or a README.*

---

## Implemented and verified against live infrastructure

### PostgreSQL â€” implemented, verified
`app/storage/adapter.py` opens a real `psycopg` connection and translates the
canonical SQL dialect. Verified against a live PostgreSQL 16.2 server by
`tests/live/test_postgres_live.py`: schema creation, full incident lifecycle,
the `ArtifactMissing` guard, metrics queries, tenant isolation, a ten-thread
write race, and reconnection durability.

The live run found two defects that no unit test could have:

1. The dead `incidents` table carried a foreign key to `events(event_digest)`,
   which stopped being unique when the key became
   `(tenant_id, event_digest, trust_level)`. SQLite accepted the dangling
   constraint silently; PostgreSQL refused to create the table.
2. `row[0]` worked on `sqlite3.Row` but raised `KeyError` on psycopg dict rows.

Both were fixed structurally rather than per-site â€” see *Failure classes* below.

### Durable work queue â€” implemented, verified (replaces Redis)
`app/queue/durable_queue.py`. `SELECT â€¦ FOR UPDATE SKIP LOCKED` on PostgreSQL.
Verified by `tests/live/test_durable_queue_live.py`: 12 concurrent workers claim
40 items with zero double-delivery, work survives a simulated pod restart,
orphaned claims are recovered, and poison messages stop retrying.

**Why not Redis**, which was already provisioned in `docker-compose.yml` and the
network policy: the database is already the single incident authority. Putting
queue state in a second stateful store re-creates the split-authority class the
council named three times â€” two stores, two truths, silent divergence. A queue
in the same database as the incident row cannot disagree with it. Redis had
**no reader anywhere in the codebase**, so it was deleted rather than wired.

### Leader election â€” implemented, verified
`app/core/leader.py`, using `pg_try_advisory_lock`. The lock is session-held, so
a dead process releases it automatically â€” no TTL guesswork, no stale-lock
cleanup. Verified by `tests/live/test_durable_queue_live.py`: exactly one leader
elected from ten contending threads, and leadership correctly released between
runs.

This existed to solve a concrete problem: `db.apply_retention` and
`db.purge_expired_nonces` had **zero callers**. `apply_retention`'s own docstring
claimed it was "applied on write, not a cron nobody runs" â€” it was neither. They
could not be scheduled safely with `replicas: 3` until something guaranteed
exactly-once execution. They now run as `leader.PeriodicJob`s.

### Helm chart â€” implemented
`deploy/helm/sentinel/`. Packaging for the manifests that already existed. No new
claims; it templates what `deploy/k8s/sentinel.yaml` already deployed.

---

## Deliberately removed

### Redis â€” removed
Provisioned in `docker-compose.yml`, referenced in the Kubernetes network policy,
and read by **nothing**. `grep -r REDIS --include=*.py` returned no matches.
Replaced by the database-backed queue above.

### The `incidents` table â€” removed
A second incident store with no production writer. `db.metrics()` counted it
while the pipeline wrote `incident_state`, which is why every dashboard total was
permanently zero (council v3, F3). Deleting the table â€” rather than repointing
the metrics query â€” is what makes the divergence unrepresentable.

---

## Intentionally out of scope

These are not "not done yet". They are decisions, with reasons, and they are
recorded here so that no one has to rediscover them.

### SAML â€” out of scope
OIDC is implemented (`api/oidc.py`, asymmetric algorithms only, JWKS validation).
SAML is a second protocol solving the same problem with a substantially larger
attack surface â€” XML canonicalisation and signature-wrapping vulnerabilities have
a long history. It is worth adding when a customer requires it and can be
tested against their IdP. Adding it speculatively means shipping unexercised
security-critical XML parsing.

### SCIM â€” out of scope
SCIM provisions **users** into a directory. Sentinel has no user directory: its
identity model is tenants plus API keys plus OIDC claims mapped to roles. There
is nothing for SCIM to provision. Implementing it would require inventing a user
store first, which is a product decision, not an integration.

### Kafka / message broker â€” out of scope
The durable queue handles the current ingest model. A broker becomes correct when
ingest is multi-producer across systems that need independent consumer groups and
replay. Adding it now would mean a second queue alongside the database queue â€”
the split-authority class again. The queue interface is narrow enough
(`put`/`claim`/`complete`/`fail`) to swap later.

### mTLS / x509 service identity â€” implemented at the service mesh layer
Mutual TLS is enforced in Kubernetes through the Helm chart, not duplicated in
FastAPI. `deploy/helm/sentinel/templates/mtls.yaml` renders an Istio
`PeerAuthentication` with `STRICT` mode for Sentinel pods and a `DestinationRule`
using `ISTIO_MUTUAL` for in-mesh calls to the Sentinel service. The chart schema
requires this block and restricts the mode to `STRICT`, so a production render
cannot silently downgrade to permissive transport.

Sentinel still authenticates callers by API key, OIDC bearer token, or the
browser OIDC session. mTLS supplies workload-to-workload transport identity and
encryption; application RBAC remains the authorization boundary.

---

## Failure classes and the structural fixes applied

The instruction throughout has been to fix the *class*, not the instance.

| Failure class | Where it appeared | Structural fix |
|---|---|---|
| Positional coupling | Queue tuple transposed `tenant_id`/`incident_id`, dropping 100% of work | Named-field payload; positional access impossible |
| Split authority | `incidents` vs `incident_state`; Redis queue vs DB state | Second store deleted; queue moved into the one authority |
| Fabricated state | `COMPLETED` reachable with a made-up `report_id` | `ArtifactMissing` â€” transitions verify the row inside the transaction |
| Driver-dependent row access | `row[0]` worked on SQLite, `KeyError` on psycopg | One `Row` type returned by both engines |
| Ephemeral state in a replicated deployment | In-memory queue with `replicas: 3` | Database-backed queue shared across replicas |
| Unelected singletons | Retention and nonce purge had no caller | `leader.PeriodicJob` with advisory locks |
| Unverified infrastructure | Postgres asserted by unit tests only | `tests/live/` runs against a real server |
| Stale documentation | Banners and docstrings claiming absent features | `tests/test_no_overclaiming.py` fails CI on drift |

