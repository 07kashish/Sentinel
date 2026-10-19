# AWS production architecture

**Status: the configuration validates and has never been applied.** No
resource described here exists except one hand-built S3 bucket. That is not a
caveat at the bottom of the page — it is the most important fact on it, because
everything downstream of an applied environment (soak, capacity, cross-region
DR, measured unit economics) is an open external gate that stays open until
somebody runs `terraform apply` and waits.

---

## What exists

```
deploy/terraform/aws/
├── identity/          GitHub OIDC role. Free. Applyable today.
├── modules/
│   ├── network        VPC, three subnet tiers, VPC endpoints, flow logs
│   ├── kms            four CMKs, split along compromise lines
│   ├── secrets        containers only — never values
│   ├── database       RDS PostgreSQL, Graviton, RLS-capable
│   ├── cache          Valkey, for shared security state
│   ├── queue          SQS with DLQs, long-polled
│   ├── storage        evidence bucket with Object Lock COMPLIANCE
│   ├── ecs            Fargate ARM64, ALB, two IAM roles
│   ├── waf            count-mode-first web ACL
│   ├── observability  log groups, SNS, seven alarms
│   ├── backup         separate vault, optional COMPLIANCE lock
│   ├── budgets        monthly + daily guard + anomaly detection
│   └── stack          the wiring, once
└── envs/
    ├── dev            ~$55/month   ESTIMATED
    ├── pilot          ~$220/month  ESTIMATED
    └── production     ~$700/month  ESTIMATED
```

`terraform validate` passes on all three environments.
`scripts/check_terraform_posture.py` passes on all three.
`tests_arch/test_terraform_posture.py` — 20 tests — proves the posture checker
can actually fail, by mutating each production control and requiring it to be
caught.

---

## The four decisions that shaped this

### 1. NAT is off by default, and that is a real constraint

A NAT Gateway costs **~$32/month per AZ before a single byte moves**. Three AZs
of NAT is ~$100/month — more than the database on a small footprint, and the
largest single line item.

So private subnets reach AWS through VPC endpoints instead. The S3 gateway
endpoint is **free**; interface endpoints are ~$7.20/month each per AZ.

**The trade-off, stated rather than buried:** with NAT off, tasks cannot reach
the public internet *at all*. In dev, `interface_endpoints` is also empty — so
a dev task cannot reach ECR or Secrets Manager either, and therefore cannot
actually start without enabling one or the other. That is a genuine limitation
of the cheapest configuration, and it is written in the dev root rather than
discovered during a first apply.

Pilot and production turn NAT on because a real deployment must reach a
partner's OIDC issuer.

### 2. Four KMS keys, not one

One key is $3/month cheaper and gives everyone who can decrypt anything the
ability to decrypt everything. The split follows the lines a compromise would:

| Key | Protects |
|---|---|
| `data` | database, snapshots, queue messages |
| `secrets` | Secrets Manager entries |
| `evidence` | transparency roots, evidence bucket |
| `logs` | CloudWatch log groups |

**The `evidence` key is the one that matters.** Evidence encrypted under the
same key as application data means an attacker who can read the database can
also read and re-encrypt the record of what they did.

### 3. Two IAM roles per task, and the distinction is load-bearing

- **execution role** — used by the ECS *agent* before the container starts:
  pull the image, fetch secrets, create log streams.
- **task role** — used by the *application* at runtime.

Collapsing them gives the application the ability to pull any image and read
any secret the agent could. The task role is assembled from policies the other
modules **export** (`consumer_policy_json`, `reader_policy_json`,
`publisher_policy_json`) rather than written by hand, so a least-privilege
policy cannot drift from the resource it governs.

### 4. The WAF starts in count mode, everywhere

Including production. `AWSManagedRulesCommonRuleSet` contains
`SizeRestrictions_BODY`, which blocks bodies over 8 KB — and a passport with a
delegation chain routinely exceeds that. Left on, it silently drops exactly the
traffic this service exists to receive, as a 403 from a load balancer with no
application log line to explain it.

That one rule is overridden to `count` and the rest of the group stays on.
Removing the whole group to solve one rule is how a WAF becomes decorative.

Then: read the count metrics against real traffic for a week, *then* set
`waf_blocking = true`. A WAF switched straight to blocking on unfamiliar
traffic causes an outage, a rollback, and a permanent reluctance to try again.

---

## What each environment gives up

| | dev | pilot | production |
|---|---|---|---|
| NAT | none | single AZ | per AZ |
| Multi-AZ database | no | **yes** | **yes** |
| Cache replica | no | **yes** | **yes** |
| TLS | no | operator-supplied | **required** |
| Execution binding | no | **yes** | **yes** |
| Rate limiter | fails open | **fails closed** | **fails closed** |
| WAF | count | count *(deliberate)* | count → block |
| Vault lock | no | no | **yes, irreversible** |
| Deletion protection | no | **yes** | **yes** |
| Evidence retention | 365d | 3650d | 3650d |

Pilot keeps the WAF in count mode **on purpose**. The false-positive rate
against a real design partner's traffic shape cannot be learned any other way,
and switching to blocking before you have it means blocking the partner.

Pilot leaves vault lock off for one reason: a pilot that ends otherwise leaves
recovery points nobody can delete for a year.

---

## Three irreversible settings

Think about each before applying, not after.

1. **`object_lock_enabled` cannot be added to an existing bucket.** If it is
   forgotten the fix is a new bucket. There is no setting to turn on
   afterwards.
2. **Object Lock COMPLIANCE retention cannot be shortened.** Not by the
   account root, not by AWS support. Ten years of transparency roots is ~0.7 MB
   and ten years of anything else may not be what you want.
3. **Backup vault lock cannot be disabled** once its grace window passes. That
   is what makes a backup survive an attacker holding admin credentials — and
   it is also why getting the retention wrong means paying to store recovery
   points you cannot delete.

---

## Cost, and why the numbers are estimates

**No bill for this platform has ever existed.**
`MEASURED_AWS_UNIT_ECONOMICS` is an open external gate, and
`posture.budget_is_measured` is a hardcoded `false` in the budgets module so
that no dashboard can present a chosen ceiling as a cost model.

Where the money actually goes, so a reduction targets the right thing:

| | production |
|---|---:|
| RDS m7g.large multi-AZ | ~$260 |
| ECS 3 × 1 vCPU ARM64 | ~$180 |
| Valkey 2 × t4g.medium | ~$100 |
| NAT × 3 AZ | ~$96 |
| ALB | ~$16 |
| Backup, KMS, logs, budgets | ~$50 |

**The ALB is the floor.** It bills hourly whether or not anything calls it,
which is why an idle environment is not free and why "scale to zero" still
costs $16.

**Graviton throughout** — `t4g`, `m7g`, ARM64 tasks. Roughly 20% cheaper for
the same work. The container must be built `--platform linux/arm64`; a task
definition claiming ARM64 with an x86 image fails with an exec format error
that never mentions architecture, which is why `runtime_platform` is set
explicitly rather than defaulted.

**Fargate Spot is offered for workers and refused for the API.** Spot is ~70%
cheaper and reclaimable with a two-minute warning. Fine for a queue worker
whose message returns to the queue. Not fine on the authorization path, where
a reclaimed task mid-decision is a request that fails closed for no reason the
operator can explain.

---

## A first apply, in order

1. Apply `identity/` and stop using a static access key. It is free.
2. Build and push an **ARM64** image. Note its **digest** — the ecs module
   refuses a tag, because a tag can be repointed after review.
3. Apply with `waf_blocking = false`.
4. Set the secret **values** out of band. `terraform output how_to_set_secrets`
   prints the commands; this repository never puts a secret value in Terraform
   state.
5. Run the migration. The app refuses to serve against an unmigrated schema, so
   `/health/live` will fail until you do — which is the correct behaviour and
   the most common cause of a first-deploy target-group failure.
6. Read the WAF count metrics for a week. Then set `waf_blocking = true`.
7. **Start the soak clock.** This is the point of all of it.

---

## What this does not prove

`terraform validate` proves the configuration is *coherent*. It does not prove
it works, and nothing in this repository can:

- `PRODUCTION_SOAK` — no sustained traffic has ever run
- `INDEPENDENT_FAILURE_DOMAIN_DR` — every restore drill ran in one failure
  domain
- `MEASURED_AWS_UNIT_ECONOMICS` — no bill exists

Applying this is the beginning of collecting that evidence, not the end of it.
See [`readiness/GAP_LEDGER.md`](readiness/GAP_LEDGER.md).

---

## Related

- [`DEPLOYMENT.md`](DEPLOYMENT.md) — the environment variables and what
  production refuses to start without
- [`TRANSPARENCY_SINK.md`](TRANSPARENCY_SINK.md) — the evidence bucket and why
  COMPLIANCE mode is the only mode worth having
- [`EXECUTION_TRUST_ARCHITECTURE.md`](EXECUTION_TRUST_ARCHITECTURE.md) — what
  `require_execution_binding` turns on, and what remains open even then
- [`DR_RUNBOOK.md`](DR_RUNBOOK.md) — restoring, as distinct from backing up
