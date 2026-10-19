# Credential exposure: rotation checklist

Use this the moment a credential is found somewhere it should not be: a
repository, a build log, a ticket, a chat message, a release artifact, a
laptop that left the building. The checklist is ordered so that the actions
that stop harm come before the actions that explain it.

**Rules that apply throughout**

- Never paste the credential anywhere, including into this checklist, the
  ticket, or the commit that removes it. Reference it by variable name and
  by the first 8 hex characters of `sha256(value)` (the `fp=` value
  `scripts/scan_release_for_secrets.py` prints).
- Rotation is done by the credential's owner in the issuing system. A
  reviewer, a bot or an engineer who "has access" does not rotate someone
  else's credential; they open the incident and hand it over.
- Removing a secret from a file does not remove it from history, caches,
  mirrors, CI logs or artifact stores. Assume it is still readable until the
  issuer confirms the old value no longer works.

## 0. Open the incident (first 15 minutes)

- [ ] Create an incident ticket titled `credential-exposure <VARIABLE_NAME> <fp>`.
- [ ] Record: where it was found (path, commit, artifact digest, log URL), who
      found it, when, and whether the location is public, org-internal or local.
- [ ] Name the owner of the credential (the person or team who can rotate it).
- [ ] Do not commit, push, publish or deploy anything containing the value from
      this point on. Pause any release in flight that includes the location.

## 1. Rotate at the issuer (owner, first hour)

Rotate first, investigate second. Every issuer below invalidates the OLD
value only once a NEW one exists and is deployed, so the order is
issue new → deploy new → revoke old.

| Kind (variable) | Issuer action | Verify revoked |
|---|---|---|
| Sentinel API keys (`SENTINEL_API_KEYS`) | Generate new ≥32-char keys, update the secret in every deployment, restart | An HTTP call with the old key returns 401 and a `security_audit` row records it |
| Cloud access keys (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, `SENTINEL_S3_ROOT_*`) | Create a new access key for the principal, update consumers, deactivate then delete the old key in IAM | `aws sts get-caller-identity` with the old key fails; CloudTrail shows no calls after revocation |
| Database (`POSTGRES_PASSWORD`, DSNs) | `ALTER ROLE ... PASSWORD`, update the secret, roll pods | A connection with the old password is refused; `pg_stat_activity` shows only new sessions |
| Redis (`REDIS_PASSWORD`, `SENTINEL_REDIS_URL`) | Set a new `requirepass`/ACL password, update consumers, restart | `AUTH` with the old password returns `WRONGPASS` |
| Console / IdP admin (`GRAFANA_PASSWORD`, `KEYCLOAK_PASSWORD`, OIDC client secrets) | Reset in the product's admin UI, rotate the OIDC client secret, update consumers | Old password login fails; IdP audit log shows the rotation |
| Third-party API keys (`VT_API_KEY`, `ABUSEIPDB_API_KEY`, PagerDuty routing keys) | Regenerate in the vendor console, update the secret | Vendor console shows the old key deleted |
| Signing / attestation material (`SENTINEL_DELEGATION_KEYS`, attestation tokens, signer TLS) | Issue a new key pair, publish the new public key, re-enrol, revoke the old key id | Verifier rejects signatures made with the old key id after the revocation timestamp |
| Metrics scrape token (`SENTINEL_METRICS_TOKEN`) | Write a new token file, roll the scraper and the pods | Scrape with the old token returns 401 |

- [ ] Every row above that applies has "verify revoked" evidence attached to the ticket.

## 2. Contain the copies (first day)

- [ ] Git: if the value was committed, rewrite history on a branch, force-push
      **only with the repository owner's written approval** in the ticket,
      and ask every collaborator to re-clone. (Rewriting history is a
      destructive operation; rotation in step 1 is what actually protects you.
      The rewrite only limits how long the old value stays discoverable.)
- [ ] CI: delete workflow run logs and artifacts that contain the value; note
      that GitHub retains deleted logs for a period and treat them as exposed.
- [ ] Artifacts: yank or delete the wheel, image, chart or release zip that
      carried it; publish a new version built from a clean tree with
      `scripts/build_release_artifact.py` and scanned by
      `scripts/scan_release_for_secrets.py`.
- [ ] Chat, tickets, docs: edit or delete the messages. Record the URLs.
- [ ] Local machines: ask the finder and anyone who pulled the location to
      delete local copies; `.env` files are not tracked here and are refused by
      the packager, but they are still on disks.

## 3. Assess use (first week)

- [ ] Pull the issuer's audit trail for the exposure window: CloudTrail, IdP
      logs, database logs, Sentinel's `security_audit` table for API keys.
- [ ] List every action taken with the credential during the window. If any
      action is one Sentinel authorises (a bound execution), find its
      `execution_operations` row and receipt and record the operation ids.
- [ ] Decide, and write down, whether customer data was reachable with the
      credential. If yes, the customer-notification process starts now.

## 4. Close (with evidence)

- [ ] `scripts/scan_release_for_secrets.py --tree --known-secrets-from <rotated dotenv>`
      run on the tip of the default branch reports no `known-secret:*`
      findings for the rotated names. Attach the JSON report.
- [ ] The fingerprint of the old value is added to the ticket so a future
      finding of the same value is recognised as historical.
- [ ] A row is added to `docs/current/RISK_REGISTER.json` if a control gap
      allowed the exposure, with the control change that closes it.
- [ ] The incident ticket is closed by the credential owner, not the finder.

## Local finding recorded on 2026-09-15

During the production-readiness program an untracked `.env` file was found in
the working tree of the development machine. It is not tracked by git, does
not appear in any commit, is refused by the release packager, and none of its
values appear in any tracked file (checked with the known-values scan, values
never printed). It contains variables of the kinds listed in section 1:
cloud access keys, S3 root-publication keys, database, Redis, Grafana and
Keycloak passwords, third-party API keys and Sentinel API keys. Whether the
values are live is not knowable from the repository. **Action for the owner:
treat every value in that file as exposed to the local machine and rotate per
section 1 if any of them were ever real.** No value from that file was
printed, copied or used by this program.
