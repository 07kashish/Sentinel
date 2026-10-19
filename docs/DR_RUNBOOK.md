# Disaster recovery runbook

**`disaster_recovery_proof` is `UNVERIFIED` and this document does not change
that.** What follows is a tested mechanism and an untested boundary, and the
difference is the whole point.

---

## What is measured

Automated PITR drills exist and run:

```bash
python scripts/run_dr_postgres_wal_pitr_drill.py
```

| Measured | Value |
|---|---|
| **RPO with `archive_timeout = 60s`** | **≈ 57 s** |
| RPO without it | **Unbounded** |
| Recovery to a requested instant | Verified |
| A target beyond the archived WAL | **Refused, never reported as verified** |
| A target before the backup | Refused before copying anything |

That last pair matters more than the successful restore. A drill that reports
success for a recovery point it cannot actually reach is worse than no drill,
because the RPO number it produces is fiction.

## Why the gate still fails

The drill's own artifact says it, in its own words:

> `"failure_domain": "SAME HOST AND SAME DISK as pgdata. This is
> docker-compose.yml's current shape and is why the gate row reads fail."`

**The WAL archive sits on the same host and the same disk as the data it
protects.** A drill that does not cross a failure boundary has not tested one.
Losing that disk loses the database *and* the archive.

The mechanism is proven. The boundary is not. Those are different claims and
conflating them is how a DR posture becomes a slide instead of a capability.

## What would make it PASS

1. **A second region or account must exist.** Not configured — existing. This is
   the actual blocker and it is a provisioning decision, not an engineering one.
2. Continuous WAL archiving to storage in that domain — S3 cross-region
   replication, Object Lock enabled.
3. A drill executed **across** the boundary, restoring into the second domain
   from nothing but the archive.
4. Measured RPO and RTO from that drill.
5. **Execution Passports verified after recovery** — the evidence chain must
   survive, or the recovery restored data without restoring the thing that makes
   the data trustworthy.

Step 5 is the one specific to Sentinel. Any database restore proves rows came
back. Only passport verification proves the *evidence* came back intact, and
`sentinel passport verify` runs without a Sentinel server, so it works on a
restored dataset before the service is up.

## Recovery procedure

### 1. Assess

```bash
python -m sentinel.interface.cli preflight
```

Determine what was lost: the database, the evidence objects, or both. They fail
independently — evidence is in S3, and the database holds digests that
*reference* those objects.

### 2. Restore the database

Restore to the latest consistent point, or a specific instant:

```bash
python scripts/run_dr_postgres_wal_pitr_drill.py --target-time "<ISO-8601>"
```

The restore is configured to **pause** and listen on its own port, so it can be
inspected before anything is promoted. A restore that immediately becomes
authoritative is a restore you cannot check.

**A restore never archives into the archive it came from.** That is tested,
because a restored instance writing WAL into the source archive corrupts the
thing you are recovering from.

### 3. Verify the evidence chain

```bash
python -m sentinel.interface.cli passport verify <passport.json>
```

Restored rows with a broken hash chain are not recovered evidence. Check
`previous_passport_digest` linkage across the restore boundary — a gap there
means passports were lost, and the honest report is that the chain has a hole,
not that recovery succeeded.

### 4. Confirm tenant isolation survived

Row-level security is schema state and comes back with the schema. **Confirm it
rather than assume it:**

```bash
pytest tests_arch/test_tenant_isolation_rls.py
```

A restore that dropped `FORCE` on a policy would leave the database working and
the isolation boundary gone — the worst possible combination, because nothing
visibly fails.

### 5. Start, and watch

Bring up one replica. Watch `authorization_latency_p99`, `dlq_depth` and
`evidence_chain_breaks` before rolling the rest.

## RTO

**`UNVERIFIED`.** No cross-domain drill has run, so no RTO has been measured.

The PITR drill measures restore time within a single host, which is not an RTO —
it excludes provisioning the second domain, DNS, and bringing dependencies up.
Publishing that number as an RTO would be the same species of claim as a green
gate that measured nothing.

## What is not automated

| Not automated | Why |
|---|---|
| Infrastructure reconstruction | Terraform is `plan`-only; nothing has been applied |
| Cross-region failover | The second domain does not exist |
| DNS cutover | Deployment-specific |
| Tenant-selective restore | Restore is whole-database; per-tenant would need export/import per tenant |

That last one is worth knowing before an incident: if one tenant needs a
point-in-time restore and the others do not, the current mechanism does not
offer it.

---

## Related

- [`DISASTER_RECOVERY.md`](DISASTER_RECOVERY.md) — drill detail and artifacts
- [`PRODUCTION_RUNBOOK.md`](PRODUCTION_RUNBOOK.md)
- [`RELEASE_READINESS.md`](RELEASE_READINESS.md) — why this gate stays UNVERIFIED
- [`aws/AWS_ARCHITECTURE.md`](aws/AWS_ARCHITECTURE.md)
