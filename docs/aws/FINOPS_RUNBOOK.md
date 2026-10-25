# FinOps runbook

How Sentinel's AWS spend is controlled, in the order that actually saves money.

Status: **no AWS resource exists**, so there is no measured spend. Every figure
here is `CALCULATED` from published pricing. A dashboard reporting `$0.00`
because nothing is deployed is not a cost achievement, and this document does
not present it as one.

---

## The order matters

Optimising in the wrong order wastes effort and can lock in mistakes. Work down
this list, never up:

1. **Delete what is not needed.** A resource removed costs nothing and needs no
   further reasoning. This is the only step with no trade-off.
2. **Right-size.** An oversized instance is a recurring donation.
3. **Stop idle resources.** Development environments overnight and at weekends.
4. **Scale to zero** where a cold start is acceptable — workers, not the
   authorization path.
5. **Reduce retention.** Log retention is a silent compounding cost.
6. **Reduce network transfer.** Cross-AZ and NAT processing are invisible until
   the bill arrives.
7. **Move to Graviton** where the dependency set is ARM-clean.
8. **Use Spot** for interruptible work only.
9. **Add caching** only where it demonstrably reduces cost, not because caching
   is generally good.
10. **Buy Savings Plans** — last, and only after 30–60 days of stable measured
    utilisation.

**Never start at step 10.** A one-year commitment bought on projected growth is
a bet on a forecast, and a pre-revenue forecast is a guess. Committing early
converts a variable cost you can cut into a fixed cost you cannot.

## What must never be optimised away

Cost discipline has a floor, and these sit below it:

| Never cut | Because |
|---|---|
| Multi-AZ RDS in production | The availability target depends on automatic failover. Cutting it makes the SLO a claim rather than an architecture |
| PITR / backup retention | Recovery is the whole point. An untested cheap backup is worse than none, because it is believed |
| Security audit log retention | Sampling security evidence to save on ingestion destroys the product. Sample noisy application traces instead |
| KMS envelope encryption | Per-tenant data-key separation is an isolation control |
| S3 Object Lock on evidence | Immutability is what makes the evidence worth anything |
| On-Demand for the authorization path | A Spot interruption mid-decision is a security event, not a cost saving |

The general rule: **reduce cost by removing things that do not carry a security
or reliability guarantee.** Never by weakening one that does.

## Spot: where yes and where absolutely not

| Workload | Spot? | Why |
|---|---|---|
| Batch discovery scans | **Yes** | Resumable; partial coverage is already reported honestly |
| Async detection workers | **Careful** | Only with idempotent consumers, visibility timeouts and a DLQ — all of which exist |
| API / authorization path | **No** | An interruption mid-decision is a fail-closed event. Saving 60% on the component whose availability is the product is a bad trade |
| PostgreSQL | **No** | Not applicable, and not desirable |

## Cost circuit breakers

Every serverless and queue-driven component needs a ceiling, because the
failure mode is not slowness — it is an unbounded bill:

| Control | Prevents |
|---|---|
| Lambda timeout + memory ceiling | A hung invocation billed to the wall |
| Reserved concurrency | Fan-out explosion |
| SQS `maxReceiveCount` + DLQ | A poison message retried forever |
| Visibility timeout > processing time | Duplicate processing of the same message |
| Max event size | A pathological payload amplified across every consumer |
| Per-tenant LLM budget | One tenant's traffic consuming the inference budget |

The recursion case deserves naming: a worker that writes to the queue it reads
from, with no guard, is the classic runaway-bill pattern. `dispatch_outbox`
raises rather than re-enqueueing on terminal failure, which is what stops it.

## Tags — required, not encouraged

Untagged resources cannot be attributed, and unattributed cost cannot be
reduced because nobody knows what it is for.

```
Project=Sentinel
Environment=dev|pilot|prod
Service=api|worker|db|evidence|detonator
Owner=<team>
TenantScope=shared|dedicated:<id>
CostCenter=<code>
DataClassification=public|internal|confidential|restricted
ManagedBy=terraform
```

`DataClassification` earns its place: it is what tells a lifecycle policy
whether an object may transition to Glacier, and what tells a reviewer whether
a bucket's access policy is proportionate.

## Budgets and alerts

| Threshold | Action |
|---|---|
| 50% | Informational |
| 75% | Review the top three services |
| 90% | Freeze non-essential provisioning |
| 100% | Escalate |
| Forecast > budget | Investigate before month end, not after |

Also enable **Cost Anomaly Detection**. A budget catches a slow drift; an
anomaly detector catches the NAT Gateway that started processing a terabyte
because a retry loop pointed at the internet.

## Scheduled analysis

`scripts/finops_report.py` is designed to run on a schedule and report:

- idle compute, oversized instances
- unattached EBS volumes and old snapshots
- idle load balancers, unassociated Elastic IPs (public IPv4 now bills)
- NAT data-processing hotspots
- log groups with no retention set
- untagged resources
- cost per Sentinel event, once a measured throughput figure exists

**It recommends. It does not delete.** Destructive cost remediation on
production infrastructure requires human approval — the same principle the
product applies to irreversible agent actions, applied to itself. An automated
cleanup that removes a snapshot somebody needed has cost more than it saved.

## Observability cost, specifically

CloudWatch ingestion is the line that surprises people, because it scales with
verbosity rather than traffic.

| Class | Retention | Sampling |
|---|---|---|
| `AUDIT` / `SECURITY` | Long, archived to S3 | **Never sampled** |
| `APPLICATION` | 30 days | Sampled under load |
| `DEBUG` | 1–3 days | Off by default in production |

Two hard rules: never sample security audit evidence, and never put
high-cardinality values — tenant id, execution id, agent id — into *metric
labels*. Cardinality is what makes a metrics bill explode, and those belong in
traces and logs where they are queryable rather than multiplied.

---

## Related

- [`COMPUTE_DECISION.md`](COMPUTE_DECISION.md)
- [`AWS_COST_MODEL.md`](AWS_COST_MODEL.md)
- [`AWS_SECURITY_MODEL.md`](AWS_SECURITY_MODEL.md)
