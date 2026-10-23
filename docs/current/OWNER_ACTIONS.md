# What only the owner can do

Everything a repository and a laptop can close has been closed or is listed in
`RISK_REGISTER.json` with the evidence that would close it. The items below
need an account, a contract, money or a person. They are ordered by how much
each one unblocks.

| # | Action | Why nobody else can | What it closes | Effort |
|---|---|---|---|---|
| 1 | Fix GitHub billing (Settings, Billing and plans) so Actions runs, then push any commit without a skip marker | Every job has failed before starting since 2026-09-15 with a payment message | RISK R-019; first run of `release-hygiene` and the `docker` gate on the new image base | Minutes |
| 2 | DONE 2026-09-25: `Instance_User` deleted (its key had been exposed in a session transcript); the `sentinel-provisioner` user and `sentinel-provision` role used for the proof run were deleted after it, on the owner's instruction | — | Part of RISK R-011 | Done |
| 3 | Rotate every other credential in the local `.env` that was ever real | Only the issuer can revoke them | RISK R-011 | An hour, per `INCIDENT_ROTATION_CHECKLIST.md` |
| 4 | DONE 2026-09-25 at free-plan sizes: the declared stack was applied as `proof`, the journey passed, everything was destroyed. STILL OPEN: the paid `pilot` sizing (multi-AZ database, cache replica) needs an account off the free plan | The free plan refuses those sizes | RISK R-004's last clause (AZ-loss survival) | A day; tens of dollars |
| 5 | HALF DONE 2026-09-25: the real AWS STS and CloudTrail path ran and passed. STILL OPEN: a sandbox GitHub App installed on a test repository | No request has reached the real GitHub App API | RISK R-021 | An hour to create; an hour for me to run |
| 6 | Generate, store and BACK UP a production evidence data key | Production now refuses to start without one; losing it loses evidence bodies | Evidence encryption in production | Minutes, but the backup matters |
| 7 | DONE 2026-09-20: owner decided yes to both. Guarded incremental MCP streaming is implemented (off by default); containments require a reason and an expiry of at most 30 days | Was the owner's decision | See `RELEASE_CHANGES.md`, 2026-09-20 | None |
| 8 | Contract an independent security assessment against `docs/SECURITY.md` | It has to be someone other than the author | RISK R-002 | Weeks; the largest single cost |
| 9 | Ask someone outside the team to assemble and seal a detection corpus with `evaluation/run_blind.py seal` | A corpus the authors have seen is not blind | RISK R-005 | Days |
| 11 | Add the two DNS records for `app.joinsentinelai.com` at GoDaddy (the certificate requested on 2026-10-04 expired unvalidated after 72 h: status `VALIDATION_TIMED_OUT`; a new request issues new record values, so say when you are ready and they will be given again) | Only the owner controls DNS; without HTTPS the console refuses operator sign-in on the deployment, so a pilot partner cannot use it | The TLS clause of RISK R-004; the pilot entry condition "confirm HTTPS" in `PILOT_KIT.md` | An hour: one DNS validation record, one CNAME |
| 12 | On the brain host (`sentinel-proof-brain-host`, EC2 → Connect → Session Manager): place your advisor CLI at `/opt/agy/agy`, then run `sudo -u sentinel env HOME=/var/lib/sentinel-agy /opt/agy/agy` and sign in | The CLI answers as a signed-in person; only that person can install it and sign in, and the stack deliberately downloads no third-party software | The advisory note on every AWS incident (until then each report says the advisor CLI could not be started) | Done 2026-10-03 (signed in as the owner; first note observed) |
| 13 | Subscribe a person to the `sentinel-proof-alarms` SNS topic (tell me the address, confirm the email AWS sends) | Nine alarms fire into a topic nobody reads | C2; an outage would currently be noticed by a visitor | Five minutes |
| 14 | Decide on a Multi-AZ database for the shared environment (roughly doubles the database cost) and on leaving the free plan (automated backups are capped at 1 day on it) | Single-AZ and 1-day backups are the two largest operational gaps the stack itself can close | R-003, R-004, B4 | A decision; an hour to apply |
Until 1, 4, 8 and 10 are done the accurate external description is
**developer preview with tested execution control, demonstrated on one cloud
host**. No amount of further code changes that sentence.

## How to do item 4 (the broader AWS identity)

The Free Tier instance restriction is a property of the ACCOUNT PLAN, not of
the IAM user. Accounts opened since mid-2025 start on the "free plan", which
limits instance types and refuses several services. Lifting it:

1. Sign in as the root user or an administrator. Open Billing and Cost
   Management, then the account plan panel, and choose **Upgrade plan** to the
   paid plan. Remaining credits are kept. Nothing is charged until something
   billable runs.
2. In Billing, create a **budget** (for example 50 USD with an email alert at
   50 and 80 percent) before anything else. This is the guard against a
   forgotten resource.

Then the identity, which should be a ROLE with a short session rather than
another long-lived key:

3. IAM, Users, create `sentinel-provisioner`. No console access. Attach no
   permissions directly except the right to assume the role in step 4.
4. IAM, Roles, create `sentinel-provision`, trusted entity "this account",
   require MFA if you can. Attach these AWS managed policies:
   `AmazonEC2FullAccess`, `AmazonRDSFullAccess`, `AmazonElastiCacheFullAccess`,
   `AmazonS3FullAccess`, `AWSKeyManagementServicePowerUser`,
   `ElasticLoadBalancingFullAccess` and `IAMFullAccess`. If the run is to use
   EKS rather than k3s on EC2, add an inline policy allowing `eks:*` (there is
   no managed policy that permits creating a cluster). `IAMFullAccess` is the
   dangerous one: it is needed because the topology creates service roles, and
   it is the reason this role must be deleted afterwards.
5. Add a permissions boundary or an inline deny on the role so it cannot touch
   what is not Sentinel's: deny every action on resources carrying the tag of
   your other project, and restrict `aws:RequestedRegion` to the two regions
   the DR test needs. The provisioning scripts only act on resources tagged
   `Project=sentinel-*`; the deny makes that a guarantee instead of a habit.
6. Create one access key for `sentinel-provisioner`, put it in the local
   `.env` as `AWS_PROVISION_ACCESS_KEY_ID` / `AWS_PROVISION_SECRET_ACCESS_KEY`,
   and add `AWS_PROVISION_ROLE_ARN=<the role ARN>`. Never paste the values into
   a chat, an issue or a commit.
7. When the run is finished and teardown is verified: delete the access key,
   the user and the role. Check the Billing console the next day for anything
   still accruing.

The existing `Instance_User` (EC2 only) should be deleted now; see item 2.
