# AWS compute decision

**Decision: ECS Fargate on ARM64 (Graviton) for the API and workers. Not EKS.**

Status: **architecture decision, no infrastructure created.** The cost figures
below are calculated from published AWS on-demand pricing, not measured on a
running deployment. They are labelled `CALCULATED`, and a figure that has been
measured will be labelled `MEASURED` when one exists.

---

## Why not EKS

EKS is the reflexive answer for anything described as "enterprise", and it is
the wrong one here at this stage. The reasoning is not that Kubernetes is bad —
it is that Sentinel does not currently need what Kubernetes charges for.

| | EKS | ECS Fargate |
|---|---|---|
| Control-plane fee | **$73/mo per cluster**, before a single pod runs | $0 |
| Idle cost with no traffic | Control plane + any node group | $0 with scale-to-zero on workers |
| Operational burden | Version upgrades, add-on compatibility, CNI, node lifecycle | Task definitions |
| Scale-to-zero | Requires Karpenter or manual node management | Native |
| Team required to run it | A platform engineer | None |

$73/month is trivial for a funded platform team and material for a
pre-revenue product. More importantly, an EKS cluster is a thing that needs
*maintaining* — Kubernetes minor versions leave standard support and enter paid
extended support, and a cluster nobody upgrades becomes both a security
liability and a surprise line item.

Sentinel's workload shape does not justify it:

- One API service, one worker pool, one scheduled job.
- No service mesh requirement.
- No per-pod network policy requirement that a security group cannot express.
- No custom scheduler, no GPU, no operator ecosystem.

**When EKS becomes correct:** a customer requires in-cluster deployment,
already runs EKS, and wants Sentinel beside their own workloads. The Helm chart
exists for exactly that case and is tested — `kubernetes_helm` is a release
gate, and the chart refuses to render until an operator confirms continuous
archiving is configured. So EKS is a *supported deployment target* without being
the *default hosting choice*, and those are different decisions that get
conflated.

## Why ARM64

Graviton is roughly 20% cheaper per vCPU-hour than the x86 equivalent for the
same nominal size. For a Python service that is I/O-bound on PostgreSQL, the
per-core performance difference is not the deciding factor — cost is.

Sentinel's dependency set is ARM-clean: `cryptography` and `psycopg` both ship
manylinux aarch64 wheels.

CI builds `linux/amd64` and `linux/arm64`. Nothing forces a choice at deploy
time.

**Not yet measured on ARM.** The 0.393 ms p99 authorization figure in
`PERFORMANCE_REPORT.md` was measured on Windows x86 in a single process with no
HTTP. It rules out a gross regression; it is not an ARM benchmark, and it is not
a production latency. The honest position: ARM is chosen on cost, and the
performance claim stays `UNVERIFIED` until it runs on the target.

## Why not Lambda for the API

Lambda is attractive for the idle cost and is wrong for this shape:

- **Connection behaviour.** Concurrent Lambda executions each want a PostgreSQL
  connection. That is the classic connection-storm, and solving it means RDS
  Proxy — which reintroduces a fixed hourly cost, so the idle saving evaporates.
- **Cold start on the authorization path.** The whole product promise is that
  authorization is fast and synchronous. A cold start on a policy decision is
  the one place latency is least acceptable.
- **The 15-minute ceiling** rules out discovery scans over a large estate.

Lambda **is** right for the scheduled FinOps analysis and other cron-shaped
work: infrequent, short, no connection pool. That is where it is used.

## Calculated monthly cost by profile

`CALCULATED` from published on-demand pricing, `us-east-1`, excluding data
transfer and free-tier effects. Not a quote.

### Profile A — lean development

| Item | Config | $/mo |
|---|---|---|
| ECS Fargate ARM | 0.25 vCPU / 0.5 GB, ~8h/day | ~4 |
| RDS PostgreSQL | `db.t4g.micro`, single-AZ, 20 GB | ~13 |
| S3 | < 1 GB | ~1 |
| Secrets/SSM | SSM SecureString | ~0 |
| **Total** | | **~18** |

No NAT Gateway. No load balancer. No cache. Public subnet with a security
group, scheduled shutdown outside working hours.

### Profile B — design partner / pilot

| Item | Config | $/mo |
|---|---|---|
| ECS Fargate ARM | 2 tasks, 0.5 vCPU / 1 GB | ~30 |
| ALB | 1, low LCU | ~18 |
| RDS PostgreSQL | `db.t4g.small`, single-AZ, 50 GB, 7-day PITR | ~30 |
| **NAT Gateway** | 1 | **~33 + data** |
| S3 + lifecycle | evidence | ~3 |
| SQS | low volume | ~1 |
| CloudWatch | filtered logs, 30-day | ~10 |
| KMS | 1 CMK, envelope | ~2 |
| **Total** | | **~127** |

**The NAT Gateway is the largest single line and the first thing to question.**
At this scale, VPC gateway endpoints for S3 and DynamoDB are free, and interface
endpoints cost ~$7/mo each. If outbound need is only S3 + ECR + Secrets
Manager + CloudWatch Logs, four interface endpoints plus two gateway endpoints
land near NAT cost without per-GB processing — and they keep traffic off the
public internet, which is the better security posture regardless. Measure actual
egress before deciding; do not assume either way.

### Profile C — enterprise production

| Item | Config | $/mo |
|---|---|---|
| ECS Fargate ARM | 3 API + 2 workers, autoscaled | ~180 |
| ALB | multi-AZ | ~25 |
| RDS PostgreSQL | `db.r7g.large` **Multi-AZ**, 200 GB gp3, 35-day PITR | ~480 |
| NAT Gateway | 2 (one per AZ) | ~66 + data |
| ElastiCache Valkey | `cache.t4g.small` × 2 | ~50 |
| S3 + Object Lock | evidence, lifecycle to IA/Glacier | ~15 |
| SQS + DLQ | | ~5 |
| CloudWatch | audit retained, app sampled | ~60 |
| KMS | | ~5 |
| WAF | managed rules | ~15 |
| **Total** | | **~900** |

Multi-AZ RDS roughly doubles the database line and is the largest cost in the
profile. It buys automatic failover, which is the thing that makes the
availability target credible — so it stays, and cost is reduced elsewhere.

### Cost per unit — `UNVERIFIED`

Cost per 1M events and cost per protected agent **cannot be calculated
honestly** without a measured events-per-second-per-task figure under
production-shaped load. The observability soak measured 38 rps sustained on a
single process with zero failures, which is a floor, not a capacity number.

Publishing a cost-per-event figure derived from a floor would be inventing a
benchmark. It stays `UNVERIFIED`.

## Removal conditions

Each paid component states what would justify removing it:

| Component | Remove when |
|---|---|
| ElastiCache | Rate limiting and lock coordination fit in PostgreSQL at observed volume |
| NAT Gateway | Egress is narrow enough that VPC endpoints are cheaper — measure first |
| WAF | An upstream CDN or the customer's own edge already terminates and filters |
| Multi-AZ RDS | Never, in Profile C. The availability claim depends on it |
| Second NAT | Single-AZ egress is acceptable for the workload's availability target |

---

## Related

- [`AWS_ARCHITECTURE.md`](AWS_ARCHITECTURE.md)
- [`AWS_COST_MODEL.md`](AWS_COST_MODEL.md)
- [`AWS_SECURITY_MODEL.md`](AWS_SECURITY_MODEL.md)
- [`FINOPS_RUNBOOK.md`](FINOPS_RUNBOOK.md)
