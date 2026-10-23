# AWS security model

How Sentinel authenticates to AWS, and why it must never hold a long-lived
access key.

---

## The rule

**Sentinel does not accept static AWS credentials for any deployment
environment.** Not as a convenience, not for a demo, not "temporarily".

That is not cloud-security orthodoxy repeated for its own sake. It is the
product's own thesis applied to itself. Sentinel exists to establish that
*autonomous agents should not possess permanent production privileges* — and a
platform that reads `AWS_SECRET_ACCESS_KEY` from its environment is an
autonomous system holding a permanent production privilege. Every argument
Sentinel makes to a customer about JIT authority applies to Sentinel first.

There is also a plainer reason. A static key cannot answer the questions in the
acceptance test:

> WHICH CLOUD IDENTITY WAS USED? WAS THE DELEGATION VALID? WHEN DID THE
> AUTHORITY EXPIRE?

A key has no expiry, no delegation chain and no session. An assumed role has
all three, and CloudTrail records them.

## What Sentinel uses instead

| Runtime | Identity mechanism |
|---|---|
| ECS Fargate / ECS EC2 | **Task Role** — credentials delivered by the task metadata endpoint, rotated automatically |
| EKS | **Pod Identity** (preferred) or **IRSA** |
| Lambda | **Execution Role** |
| GitHub Actions | **OIDC federation** to a role with a trust policy scoped to the repository and branch |
| Local development | A named profile the developer owns. **Never** a key in the repository, image, or `.env` |

None of these produces a credential that outlives the workload.

### GitHub Actions trust policy

The CI role trusts GitHub's OIDC provider and nothing else. The `sub` condition
is what stops any other repository — or a fork, or a pull request from a fork —
assuming it:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::<ACCOUNT>:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub":
          "repo:<OWNER>/<REPO>:ref:refs/heads/main"
      }
    }
  }]
}
```

`StringEquals` on `sub`, not `StringLike` with a wildcard. `repo:owner/repo:*`
would let a pull-request workflow from a fork assume the release role, which is
the standard way this configuration is got wrong.

## Roles, and the one that is deliberately narrow

| Role | May do | Must not |
|---|---|---|
| `SentinelAPI` | Read config, decrypt with its KMS key, write evidence to its S3 prefix, read/write its database | Assume other roles; touch IAM; read other tenants' prefixes |
| `SentinelWorker` | Consume SQS, write evidence, call integrations | Modify policy; delete evidence |
| `SentinelDiscovery` | **Read-only** across the estate | Write anything, anywhere |
| `SentinelDetonator` | Nothing outside its sandbox | Reach the control plane, the database, or the network beyond its allowlist |
| `SentinelRelease` | Push images, sign artifacts | Touch runtime data |
| `SentinelReadOnlyAudit` | Read evidence and audit logs | Write |

`SentinelDiscovery` is the interesting one. It is the role a customer grants
into *their* account, so it is the role a customer's security team will actually
read. It must be describable in one sentence — *"it can list and describe, and
it can change nothing"* — because a discovery role that also writes is a role
no security team should approve.

The AWS-managed `ReadOnlyAccess` policy is **not** what to attach: it grants
read on Secrets Manager and S3 object contents, which means data, not
inventory. Discovery needs `List*` and `Describe*` and `Get*Policy`, not
`GetSecretValue` or `GetObject`.

## Detonation is the exception that proves the rule

The skill sandbox executes untrusted code. It therefore gets **no AWS identity
at all** — no task role, no instance profile, no metadata access.

That last one matters and is easy to miss: on EC2 and ECS, an untrusted process
that can reach `169.254.169.254` can request the workload's credentials. A
sandbox with a blocked egress allowlist but reachable metadata is a sandbox with
a credential exfiltration path.

## Encryption

Envelope encryption, so that per-event volume does not become per-event KMS
cost:

```
KMS CMK  →  encrypted data key (stored)  →  bounded in-process cache  →  AES-GCM
```

Encryption context carries `tenant_id`, so a data key decrypted for one tenant
cannot be used to read another's ciphertext even if the ciphertext is
mis-addressed. That is a real isolation control, not bookkeeping: without it, a
key-scoping bug is a cross-tenant read.

Per-tenant CMKs are available and are **not** the default. They cost per key
per month and per API call, and they only pay for themselves where a customer
requires cryptographic separation or the ability to revoke their own data by
destroying a key. That is a customer requirement, not an architecture default.

## What is NOT set up, and why

**No AWS resource has been created.** Not a VPC, not a role, not a bucket.
This document, the Terraform, and the cost model are all `plan`-time artifacts.

Two reasons:

1. You asked for setup without incurring cost, and a NAT Gateway starts billing
   the moment it exists whether or not a packet crosses it.
2. Creating IAM roles requires credentials, and the only credentials offered
   were a static admin access key pasted into a chat transcript. Using it would
   have contradicted every paragraph above.

### To apply this yourself

The Terraform is split by what it costs, so the part that ends your dependence
on static keys can be applied today without starting a bill.

**The identity layer is free to apply.** IAM roles, policies and OIDC providers
cost nothing. There is no NAT Gateway, no load balancer, no database and no
compute in it:

```bash
aws configure sso                        # or a named profile you control
cd deploy/terraform/aws/identity
terraform init
terraform plan -var github_owner=<owner> -var github_repo=<repo>
terraform apply                          # $0/month, and no more static keys
```

It outputs `monthly_cost_usd = 0` beside the resources, so the claim appears in
the plan rather than only in this document.

**The compute and data layers are not written yet, deliberately.** Those are
the ones that bill from the moment they exist, and the shape depends on which
profile you are deploying — see [`COMPUTE_DECISION.md`](COMPUTE_DECISION.md)
and [`AWS_COST_MODEL.md`](AWS_COST_MODEL.md). `terraform plan` is free; a NAT
Gateway is not.

---

## Related

- [`ARCHITECTURE.md`](../ARCHITECTURE.md#aws_architecture)
- [`AWS_COST_MODEL.md`](AWS_COST_MODEL.md)
- [`COMPUTE_DECISION.md`](COMPUTE_DECISION.md)
- [`../SECURITY.md`](../SECURITY.md)
