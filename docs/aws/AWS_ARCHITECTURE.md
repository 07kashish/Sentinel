# AWS architecture

Status: **no AWS resource has been created.** This is a design and a Terraform
plan. Nothing is running, nothing is billing.

---

## Topology

```
Route53
   │
CloudFront ─── AWS WAF          (Profile C only)
   │
  ALB  (TLS terminates here)
   │
   ├─────────────────────────────┐
   ▼                             ▼
Sentinel API                  Sentinel Worker
ECS Fargate ARM64             ECS Fargate ARM64
(On-Demand, never Spot)       (Spot-eligible)
   │                             │
   │  ┌──────────────────────────┘
   ▼  ▼
RDS PostgreSQL ── Multi-AZ, PITR      ElastiCache Valkey (only if needed)
   │
   ▼
SQS ── DLQ
   │
   ▼
S3 evidence ── Object Lock ── lifecycle → IA → Glacier
```

Out of band:

```
EventBridge (cron) → Lambda → FinOps analysis  (recommends, never deletes)
Detonation sandbox → isolated subnet, no AWS identity, no metadata access
```

## The one structural rule

**Nothing on the authorization path may depend on a third party.**

```
request → authorize → decide → commit → OUTBOX → SQS → worker → integrations
                                   ↑
                        the transaction ends here
```

A SIEM outage, a Slack outage, an attestation gateway timeout — none of them can
delay or fail an authorization decision. They are consumers of a durable outbox,
not participants in the request.

This is why the queue is between the decision and the integrations rather than
beside them, and it is the reason `SiemNotConfigured` is *retryable*: a security
export that cannot be delivered stays on its retry budget and becomes visible in
the dead-letter queue, rather than being dropped or blocking the caller.

## Component decisions

| Component | Choice | Why not the alternative |
|---|---|---|
| Compute | ECS Fargate ARM64 | EKS costs $73/mo per cluster before a pod runs and needs continuous upgrading. See [`COMPUTE_DECISION.md`](COMPUTE_DECISION.md) |
| Database | RDS PostgreSQL Graviton | Aurora is not automatically cheaper. At Sentinel's write volume the burstable Graviton instance is materially less, and Aurora's per-IO charge is unbounded on a workload nobody has profiled yet |
| Queue | SQS | Kafka/MSK/Kinesis add a fixed monthly floor and an operational surface for a workload SQS handles. Revisit with measured ordering or replay requirements |
| Evidence | S3 + Object Lock | Retaining immutable history in PostgreSQL is expensive per GB and makes the table the thing you cannot prune. Database rows reference object digests |
| Cache | Valkey, **conditional** | Only for distributed rate limiting and locks. Never authoritative for evidence, passports or authorization state |
| Secrets | SSM SecureString, Secrets Manager where rotation is required | Secrets Manager is ~$0.40/secret/mo; SSM SecureString is free. Pay for rotation, not for storage |
| Edge | ALB; CloudFront + WAF in Profile C | API Gateway's per-request pricing exceeds ALB above modest volume |

## Why SQLite is still in the tree

SQLite is a development and unit-test engine, and production **refuses to boot
on it**. That refusal is tested.

Both engines matter because they disagree in ways that matter. The predecessor's
worst defect was invisible on SQLite and fatal on PostgreSQL: terminal delivery
operations used an unscoped connection, and under `FORCE` row-level security
their statements matched no rows — every one silently failed on the production
engine while the whole suite passed on the development one.

So the SQL, chaos and concurrency suites are parametrised over both, and
`postgres_tests` is its own release gate. A test that only ever runs on SQLite
cannot see that class of bug.

## Tenant isolation, in layers

1. An application predicate on every query.
2. PostgreSQL row-level security, `FORCE`d, with `USING` **and** `WITH CHECK`.
3. Tenant-scoped S3 key prefixes.
4. Per-tenant KMS encryption context.
5. Tenant-scoped integration credentials.

The suite deletes layer 1 and requires layer 2 alone to block the leak — for
reads, updates *and* deletes. It connects as a **non-superuser**, because a
superuser bypasses RLS entirely and every assertion would otherwise pass
vacuously.

**The tenant comes from the credential, never from the request.** Any code path
where a caller can name their own tenant is a defect, not a feature.

## Availability

| Profile | Shape |
|---|---|
| A — dev | Single task, single-AZ. No availability claim |
| B — pilot | 2 tasks across AZs, single-AZ RDS. Survives a task loss, not an AZ loss |
| C — production | 3 API + 2 workers across 3 AZs, **Multi-AZ RDS with automatic failover** |

The API is stateless. No evidence depends on local disk — it is in PostgreSQL
and S3 — so a task can be destroyed at any point without losing anything.

**The 99.9%/30d SLO is `UNVERIFIED` and will stay that way until a real
deployment has run for 30 days.** 99.9% permits ~43 minutes of downtime per
month; the longest observation so far is seven minutes. A clean short window is
*consistent with* the target and does not demonstrate it.

## Disaster recovery

Automated PITR drills exist and measured **RPO ≈ 57s** with `archive_timeout`
set, unbounded without it. The Helm chart refuses to render until an operator
confirms continuous archiving is configured — the acknowledgement is required
because the chart consumes a database DSN it cannot configure, and the RPO
depends on settings it cannot apply.

`disaster_recovery_proof` remains `UNVERIFIED`, and the drill artifact says why
in its own words: the WAL archive currently sits on the **same host and disk**
as `pgdata`. Recovery across an independent failure domain requires a second
region to exist first, and a drill that does not cross a boundary has not tested
one.

## What is not built

Stated plainly, because a diagram implies more than a repository contains:

| Not built | Consequence |
|---|---|
| Terraform is `plan`-only | Nothing has been applied; no resource, no role, no bucket |
| A2A streaming transport | The security guard exists; nothing streams |
| Per-server MCP usage table | Shadow-server detection cannot fire, and the endpoint says so rather than reporting zero |
| Persistent asset declarations | Blast radius takes declarations per request and reports `coverage`, so a low score over low coverage cannot read as "safe" |
| Firecracker/gVisor detonation | The contract, canary and refusal exist. The isolation mechanism does not |

---

## Related

- [`COMPUTE_DECISION.md`](COMPUTE_DECISION.md)
- [`AWS_COST_MODEL.md`](AWS_COST_MODEL.md)
- [`AWS_SECURITY_MODEL.md`](AWS_SECURITY_MODEL.md)
- [`FINOPS_RUNBOOK.md`](FINOPS_RUNBOOK.md)
- [`../ARCHITECTURE.md`](../ARCHITECTURE.md)
