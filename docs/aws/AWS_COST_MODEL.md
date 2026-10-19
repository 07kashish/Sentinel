# AWS cost model

Status: **`CALCULATED`, not `MEASURED`.** No AWS resource exists, so no bill
exists. Every figure below is derived from published on-demand `us-east-1`
pricing. None of it is a quote, and none of it substitutes for running
`terraform plan` and the AWS Pricing Calculator against your own account.

Where a figure cannot be derived honestly, it is marked `UNVERIFIED` rather
than estimated.

---

## Monthly floor by profile

| | A — dev | B — pilot | C — production |
|---|---|---|---|
| Compute | ~$4 | ~$30 | ~$180 |
| Database | ~$13 | ~$30 | ~$480 |
| Load balancer | — | ~$18 | ~$25 |
| **NAT Gateway** | — | **~$33** | **~$66** |
| Cache | — | — | ~$50 |
| Evidence (S3) | ~$1 | ~$3 | ~$15 |
| Queue | — | ~$1 | ~$5 |
| Observability | — | ~$10 | ~$60 |
| KMS | ~$0 | ~$2 | ~$5 |
| WAF | — | — | ~$15 |
| **Total** | **~$18** | **~$127** | **~$900** |

## The two lines worth arguing about

### 1. RDS Multi-AZ is 53% of the production bill

~$480 of ~$900. Single-AZ would roughly halve it.

**It stays.** The 99.9% availability target is an architectural claim, and
without automatic failover it becomes a hope. Cutting the component the SLO
depends on to save money, then continuing to publish the SLO, is precisely the
kind of unearned claim this repository is built to prevent.

Reduce cost elsewhere.

### 2. NAT Gateway costs more than the database in Profile B

~$33/mo plus $0.045/GB processed, versus ~$30 for the pilot database. It is the
first thing to question and the last thing most people look at.

If Sentinel's outbound need is only S3, ECR, Secrets Manager and CloudWatch
Logs, then:

| Option | Fixed | Per GB |
|---|---|---|
| 1 NAT Gateway | ~$33/mo | $0.045 |
| 2 gateway endpoints (S3, DynamoDB) | **$0** | **$0** |
| 4 interface endpoints (ECR ×2, Secrets, Logs) | ~$29/mo | $0.01 |

Similar fixed cost, a quarter of the per-GB rate, and traffic never leaves the
AWS network — which is a better security posture independent of the money.

**Measure your actual egress before choosing.** A deployment that genuinely
needs arbitrary internet access (customer webhooks, third-party SIEM endpoints)
needs the NAT and the endpoints will not replace it.

## Per-unit cost — `UNVERIFIED`

Cost per 1M events, cost per protected agent and cost per tenant **cannot be
calculated honestly today.**

What is measured: **38 rps sustained, 16,082 requests, zero failures**, ingest
p95 **71.6 ms** against a 500 ms target, on PostgreSQL 16 as a non-superuser
with `FORCE` RLS applied — so the row-level-security predicate is inside the
measured cost.

That is a **floor, not a capacity figure.** The soak drove the load it was
configured to drive; it did not find the point where the service degrades.
Dividing a monthly cost by a floor produces a number that looks authoritative
and is not — the "invent a benchmark measurement" failure the engineering rules
forbid.

What would resolve it: a saturation test that raises offered load until p95
crosses the target, giving requests-per-second-per-task. Cost per event then
follows from arithmetic rather than assumption.

## Scaling shape

Sentinel's cost does not scale linearly with customers, because the fixed floor
dominates early and the variable component dominates late.

| Scale | Dominant cost | Lever |
|---|---|---|
| 1–10 tenants | **Fixed floor** — NAT, ALB, RDS baseline | Remove infrastructure; shared tenancy |
| 10–100 | Compute + database IOPS | Right-size; Graviton; read replicas before a bigger primary |
| 100–1,000 | Storage + observability ingestion | Lifecycle to Glacier; sample application traces (never audit) |
| Dedicated enterprise | Per-customer floor | Charge for it. A dedicated VPC is a pricing tier, not an engineering problem |

The trap at the low end: **one small AWS account per tiny customer multiplies
the fixed floor by the customer count.** Ten pilots at ~$127 is ~$1,270/mo of
mostly-idle NAT Gateways and load balancers. Logical multi-tenancy — which the
RLS work already makes defensible — is what avoids that, and dedicated
deployment stays available for customers who require and fund it.

## Savings Plans

**Do not buy any yet.**

A Compute Savings Plan is a 1- or 3-year commitment. Bought against projected
growth, it converts a variable cost you can cut into a fixed cost you cannot,
on the strength of a forecast that does not yet have a customer behind it.

The condition to revisit: **30–60 days of stable, measured utilisation** in a
real deployment. Until then, On-Demand plus Spot for interruptible work is
correct — it costs more per hour and preserves the ability to change your mind,
which is worth more than the discount at this stage.

## Every paid component, and what would remove it

| Component | Why needed | Remove when |
|---|---|---|
| ECS Fargate | Runs the service | Never (replaced, not removed) |
| RDS PostgreSQL | Authoritative store; RLS is a security control | Never |
| Multi-AZ | Automatic failover; the SLO depends on it | Never in Profile C |
| NAT Gateway | Outbound to integrations | Egress narrow enough for VPC endpoints — **measure** |
| ALB | TLS, health checks | An upstream CDN terminates instead |
| ElastiCache | Distributed rate limiting, locks | Both fit in PostgreSQL at observed volume |
| S3 + Object Lock | Immutable evidence | Never — immutability is what makes evidence worth anything |
| SQS | Decouples integrations from authorization | Never; this is the structural rule |
| KMS | Envelope encryption, per-tenant context | Never |
| WAF | Managed rules at the edge | The customer's own edge already filters |
| CloudWatch | Audit + operational visibility | Never for audit; app logs can move to cheaper storage |

## What this document is not

It is not a bill, a quote, or evidence of a deployment. `aws_cost_measured`
stays **`UNVERIFIED`** until a real account has run for a real billing period.

A cost dashboard reporting `$0.00` because nothing is deployed is not a cost
achievement, and presenting it as one would be the same species of claim as a
green gate that measured nothing.

---

## Related

- [`COMPUTE_DECISION.md`](COMPUTE_DECISION.md) — why Fargate ARM, not EKS
- [`FINOPS_RUNBOOK.md`](FINOPS_RUNBOOK.md) — optimisation order, circuit breakers
- [`AWS_ARCHITECTURE.md`](AWS_ARCHITECTURE.md)
- [`AWS_SECURITY_MODEL.md`](AWS_SECURITY_MODEL.md)
