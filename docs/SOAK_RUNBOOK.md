# Soak runbook

**`production_soak` is `UNVERIFIED`. The elapsed time *is* the evidence, and no
amount of engineering compresses thirty days into an afternoon.**

---

## Running it

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

## What has been measured

7 minutes, production-shaped, PostgreSQL 16:

| Surface | Requests | Failures | p50 | p95 | p99 |
|---|---|---|---|---|---|
| ingest | 16,082 | **0** | 34.0 ms | **71.6 ms** | 96.3 ms |
| `/health/ready` | 1,871 | **0** | 19.9 ms | 45.9 ms | 58.1 ms |

Throughput 38.3 rps. Availability observed 100% (17,953/17,953).

**Ingest p95 is 71.6 ms against a 500 ms target — met, with 7× headroom.**

## What that does not establish

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

## What a real soak must track

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

## Do not fake elapsed time

Stated plainly because it is the obvious shortcut: **running for an hour and
extrapolating to thirty days is fabricating soak evidence.** So is running
thirty separate one-hour windows and summing them. A leak, a slow index bloat
and a certificate expiry all need continuous elapsed time to appear.

`production_soak` moves from `UNVERIFIED` when a real run has covered the
declared period. Nothing in this repository can write that gate —
`test_ga_gates_cannot_be_faked.py` plants a correctly bound artifact claiming
success and requires the verdict to stay `UNVERIFIED`.

## A finding the soak already produced

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

## Related

- [`OBSERVABILITY.md`](OBSERVABILITY.md) — the SLI table and both soak records
- [`PERFORMANCE_REPORT.md`](PERFORMANCE_REPORT.md)
- [`PRODUCTION_RUNBOOK.md`](PRODUCTION_RUNBOOK.md)
- [`RELEASE_READINESS.md`](RELEASE_READINESS.md)
