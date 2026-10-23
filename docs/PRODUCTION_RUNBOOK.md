# Production runbook

Operating Sentinel in production, and what to do when it refuses to start.

---

## Preflight refuses, deliberately

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

## Startup

```bash
python -m sentinel.interface.cli migrate      # never automatic
python -m sentinel.interface.cli preflight    # read the output
gunicorn sentinel.interface.asgi:create_application() \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 --workers 4 --timeout 120
```

**Migrations are never automatic on startup.** Four workers booting
concurrently would race, and a migration that half-applies under contention is
the failure that takes a schema somewhere no rollback describes. `verify()`
refuses to serve a schema it did not expect, which turns that race into a
failed deploy instead of a corrupted database.

## Health endpoints, and what each means

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

## When things go wrong

### Readiness is failing

`/health/diagnostics` names the component. Most often the database. The pod
marks itself NotReady and sheds traffic, which is correct.

Watch for the **cascade**: a throttled readiness probe also marks a pod
NotReady, shedding it and moving its load onto the remaining pods — under
exactly the load that caused the throttling. The soak measured 27 of 270 probes
answered 429 at ~180 rps from a single address. That is why readiness is
throttle-exempt now.

### The dead-letter queue is filling

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

### Authorization latency has risen

Check the database first. The authorization path is deterministic and does no
network I/O — measured p99 **0.393 ms** — so a rise is almost always the
database or connection pool, not policy evaluation.

**Detection cannot be the cause.** It is asynchronous behind the outbox, and a
detection worker backlog cannot slow a decision.

### A third party is down

Nothing happens to authorization. SIEM, Slack, PagerDuty and the attestation
gateway are all consumers of a durable outbox. An attestation outage produces
incidents marked `completed_unattested` — degraded evidence, honestly labelled,
rather than a blocked request or a false claim of attestation.

## Kill switch

`SENTINEL_PROTECT_KILL_SWITCH` disables enforcement without a restart. Every
use is attributed and audited. It exists because an enforcement bug that blocks
legitimate traffic needs a faster remedy than a deploy — and because an
operator who cannot turn a control off will route around it permanently.

## Backups

- Automated RDS backups; **PITR 35 days** in Profile C
- WAL archiving to durable storage, `archive_timeout = 60s`
- **Measured RPO ≈ 57s** with the timeout set; **unbounded without it**

The Helm chart refuses to render until an operator confirms continuous
archiving is configured, because the chart consumes a DSN it cannot configure
and the RPO depends on settings it cannot apply.

**Restore is tested. Cross-region recovery is not** — see
[`DR_RUNBOOK.md`](DR_RUNBOOK.md). `disaster_recovery_proof` is `UNVERIFIED` and
the drill artifact says why in its own words.

## What to watch

| Signal | Meaning |
|---|---|
| `authorization_latency_p99` | The only latency an agent waits on |
| `dlq_depth` | Delivery is failing somewhere |
| `queue_lag` | Detection is falling behind (does not affect enforcement) |
| `completed_unattested` | Attestation is degraded |
| Readiness 429s | The cascade condition |
| `evidence_chain_breaks` | **Investigate immediately** — the chain should never break |

Never sample `AUDIT` or `SECURITY` logs. Sample noisy application traces
instead.

## Upgrades

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

## Related

- [`DR_RUNBOOK.md`](DR_RUNBOOK.md) · [`SOAK_RUNBOOK.md`](SOAK_RUNBOOK.md)
- [`OBSERVABILITY.md`](OBSERVABILITY.md) · [`RELEASE_GATES.md`](RELEASE_GATES.md)
- [`aws/ARCHITECTURE.md`](ARCHITECTURE.md#aws_architecture)
