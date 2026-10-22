# Publishing transparency roots to S3 Object Lock

Cost at the recommended settings: **about $0.002 per year.** The free tier
covers it outright. The numbers are at the bottom.

---

## Why this is the one step that cannot be done in code

The Merkle log detects deletion, reordering and forked histories against
everyone **except the party running it** — that party serves both the history
and the root you check it against. Rewrite both and every proof still verifies.

Publishing the root somewhere its writer cannot alter is what closes that. It
needs a bucket in your account, so it is yours to create; the code is written
and refuses honestly until you do.

Until then `/v1/transparency/root` answers `independently_verifiable: false`
with a reason. **That is a supported state, not a broken one** — the log still
catches a mistake, a partial restore, or a diverging replica. It just does not
catch a determined operator.

---

## The two commands

Replace `acme-transparency` with a globally-unique name and `eu-west-2` with
your region.

```bash
aws s3api create-bucket \
  --bucket acme-transparency \
  --region eu-west-2 \
  --create-bucket-configuration LocationConstraint=eu-west-2 \
  --object-lock-enabled-for-bucket
```

```bash
aws s3api put-object-lock-configuration \
  --bucket acme-transparency \
  --object-lock-configuration '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":3650}}}'
```

**`--object-lock-enabled-for-bucket` cannot be added later.** If you forget it,
the fix is a new bucket — there is no setting to turn on afterwards. The sink
reports this specifically when a PUT returns 400, because it is the mistake
everyone makes once.

### COMPLIANCE, not GOVERNANCE

Governance mode looks identical in the console and can be bypassed by any
principal holding `s3:BypassGovernanceRetention`. A root written in governance
mode is still yours to delete, so it proves nothing about you — and
`is_independently_verifiable` would be reporting a guarantee that does not
exist. The sink writes `COMPLIANCE` and nothing else.

**Compliance mode is irreversible.** You cannot shorten a retention period, you
cannot delete the object, and neither can AWS support. That is the point, and
it is also the reason to think about `Days` before running the second command.
At 200 bytes a day, ten years is about 0.7 MB.

---

## The minimal IAM policy

Two actions, one prefix. `s3:PutObjectRetention` is the one people leave out,
and its absence produces a 403 that reads like a bucket problem — the sink says
so explicitly when it sees one.

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "PublishTransparencyRootsOnly",
    "Effect": "Allow",
    "Action": ["s3:PutObject", "s3:PutObjectRetention"],
    "Resource": "arn:aws:s3:::acme-transparency/sentinel/transparency/*"
  }]
}
```

No `s3:GetObject`, no `s3:ListBucket`, no `s3:DeleteObject`. The sink never
reads and never lists — listing is the call that costs real money as a bucket
grows, and a credential that can delete defeats the purpose of the lock.

**Prefer a role over a long-lived user.** `deploy/terraform/aws/identity`
already provisions a GitHub-OIDC role and costs nothing to apply; add this
policy to it and set `SENTINEL_S3_ROOT_SESSION_TOKEN` from the assumed
credentials. A static access key in a `.env` file is the fallback, not the
recommendation.

---

## Configuring it

Copy `.env.example` to `.env` and fill in the `SENTINEL_S3_ROOT_*` values.
`.env` is gitignored — verify before you paste anything:

```bash
git check-ignore -v .env
```

Then publish on a schedule:

```bash
PYTHONPATH=. SENTINEL_PUBLISH_TENANTS=acme python scripts/publish_transparency_root.py
```

```cron
0 2 * * * cd /srv/sentinel && PYTHONPATH=. SENTINEL_PUBLISH_TENANTS=acme python scripts/publish_transparency_root.py
```

`SENTINEL_PUBLISH_TENANTS` is required. The script refuses to enumerate every
tenant rather than publishing roots for estates nobody asked about — each write
is irreversible under compliance retention.

---

## What it costs, and the two ways to make it expensive

Once a day, at S3 Standard pricing:

| | |
|---|---|
| 365 PUTs/year at $0.005 per 1,000 | **$0.002** |
| 365 × 200 bytes = 73 KB at $0.023/GB-month | **$0.00002** |
| GETs made by this code | none |

Check it against your own assumptions:

```bash
python -c "from sentinel.infrastructure.s3_root_sink import estimated_annual_cost_usd as c; print(c(publications_per_day=1))"
```

**Mistake one: publishing per event.** At 100 events a day that is ~$16/year
instead of $0.002 — and it buys nothing, because a later root already proves
every earlier one via a consistency proof. The cost function exists so this is
a number rather than an argument.

**Mistake two: reaching for Glacier.** Glacier bills a 40 KB minimum per object
and a 90–180 day minimum duration. Against a 200-byte object that is roughly
200× more expensive than Standard. Cheap-sounding storage classes are a trap at
this size.

---

## Verifying it worked

```bash
curl -H "Authorization: Bearer $VIEWER_KEY" https://your-host/v1/transparency/root
```

`independently_verifiable` should now be `true`, with a `published_root`
naming the sink and an `s3://bucket/key?versionId=…` reference. An auditor
fetches that object directly from S3 and checks a proof against it without
asking your deployment anything.

If it is still `false`, the response says why — no root published at this size,
or a sink that returned no reference. Both are read from the recorded
publications rather than from your configuration, because a configured sink
that has never successfully published is not a published root.

---

## Alternatives, if S3 is not right for you

| Option | Trade-off |
|---|---|
| RFC 3161 timestamping authority | Free public TSAs exist. Needs egress and a token store; no bucket to manage |
| WORM appliance | You either have one or you do not |
| Public transparency service | Strongest third-party property, but the roots become public |

All four satisfy the same `RootSink` contract in `sentinel/domain/root_sink.py`.
Implementing another is one method.

---

## Related

- [`DELIVERY_STATUS.md`](DELIVERY_STATUS.md) — what is built and what is blocked
- `sentinel/domain/root_sink.py` — the contract, and why the default refuses
