# Enterprise controls

Phase 5: sections 29 (policy-as-code), 30 (policy simulation), 31 (protection
modes), 55 (customer-managed keys), 78 (data retention) and 79 (data residency).

Phase 4 decides what the product does. This phase decides **who gets to decide**
— and every item here is a promise made to somebody outside the engineering
team: a regulator's residency rule, an auditor's retention schedule, a security
team's key custody.

That changes the failure mode. A missed detection is a bad day. A residency
guarantee that turns out to be a column nobody reads is a breach of contract.

---

## 1. Protection modes (§31)

```
OBSERVE → MONITOR → WARN → PROTECT → LOCKDOWN
```

**A mode is not a decision.** `ProtectDecision` already had ALLOW/WARN/BLOCK —
answers about one tool call. A mode is a statement about the whole deployment:
how much authority the product has been granted over this estate.

Keeping them separate is what makes the pair useful. A policy can decide BLOCK
while the deployment is in MONITOR, and the correct outcome is a recorded
decision and an unblocked call. Collapsing them would mean the only way to stop
blocking is to weaken the rules — which is how a rollout ends with a detector
nobody trusts.

Capabilities are **derived from the ranking**, not written per mode
(`test_capabilities_are_monotonic_in_the_ranking`). A table of independent
booleans is where "PROTECT blocks but MONITOR also blocks" comes from: two
people edit two rows months apart and no test asserts a relationship that was
never expressed.

### Ambiguous names are refused

The spec says "do not allow ambiguous mode names", and this takes it literally.
`on`, `off`, `enabled`, `true`, `enforce`, `block`, `audit`, `strict` are all
**rejected with an explanation**, because every one of them has been used in
this industry to mean both *watch* and *block*. A deployment that guesses will
eventually guess in the direction that either leaves an estate unprotected or
takes it down.

An unrecognised mode is a **startup failure**, where a human is present to fix
it — not a runtime default, where nobody is.

### The contradiction check

`SENTINEL_PROTECT_ENFORCE` predates this and is what the gate actually reads. Two
settings that both describe enforcement can disagree, so startup **refuses when
they do**:

```
SENTINEL_PROTECTION_MODE='protect' enforces, but SENTINEL_PROTECT_ENFORCE is unset.
These describe the same thing and must agree.
```

A deployment that believes it is in PROTECT while the gate is permissive is the
worst available outcome, so it is not a precedence rule — it is a failure.

Unset defaults to the mode implied by the existing boolean, so nothing that
works today needs a new variable to keep working.

---

## 2. Policy-as-code (§29) and simulation (§30)

> Never silently apply malformed policies.

Everything here follows from taking that sentence literally, because **there are
two ways to break it and only one is obvious.**

The obvious one is accepting a policy that fails to parse. The subtle one — and
the one that actually happens — is accepting a policy that parses fine and
**matches nothing**. A rule written for `read_sensitive_file` when agents emit
`read_file` is perfectly well-formed and completely inert.

This is not hypothetical in this codebase. Phase 3's sequence rules hit exactly
this, and Phase 4's `RuleBasedPlanner` proposed four action names that were not
in the remediation catalogue. So `validate` refuses a rule naming an action no
agent in the tenant has ever emitted
(`test_a_policy_naming_an_action_no_agent_emits_is_refused`), and it runs on
**both** write paths — validate and deploy — because a malformed policy reaching
storage through the door nobody tested is the whole failure mode
(`test_the_same_malformed_policy_is_refused_by_deploy`).

Also refused: a catch-all BLOCK with no selectors (an estate-wide outage in a
document that reviews cleanly), duplicate rule names (a finding becomes
ambiguous and a diff becomes meaningless), and `min_severity=100` (fires only on
the single maximum score — almost always a misread of the scale).

### No regular expressions, on purpose

A policy file is operator-supplied text evaluated against every event. A regex
in that position is a catastrophic-backtracking denial of service an operator
can introduce **by accident**, in a file that reviews cleanly. Prefix globs cover
what policies actually need and cannot blow up.
(`test_a_selector_is_matched_by_prefix_never_by_regular_expression`)

### Versions, diff, rollback

A `PolicyVersion` is content-addressed by a digest over its **canonical** form,
so a reformat in an editor is not a "new policy" whose diff is noise. Two
consequences:

- **Rollback is "activate version N again"**, not "undo the edit". The bytes
  that ran last Tuesday still exist.
- **A diff is a fact, not a reconstruction.** An operator reviewing a change is
  reviewing the change that will actually be applied.

Rollback has **no code path of its own** — it is
`POST /v1/policy/versions/{older}/activate`. There is therefore nothing that can
be correct for deployment and wrong for rollback, which is the usual way a
rollback fails on the night it is needed.
(`test_rolling_back_is_the_same_call_with_an_older_version`)

Deploy and activate are separate calls. Storing is reviewable and reversible;
activating changes what the estate enforces. Collapsing them would mean the only
way to review a policy is to run it.

### Simulation

> What would this policy have done during the last 7 days?

`POST /v1/policy/versions/{n}/simulate` replays recorded execution-graph steps
against a candidate **without activating it**
(`test_simulating_does_not_activate_the_candidate`), and reports every §30 field.

It also reports one the spec does not ask for: `is_estimate`, always true, with
a caveat string. A number presented without that gets quoted in a change review
as though it were a measurement. `potential_false_positives` counts events the
candidate would newly restrict that raised no incident — the closest available
proxy, and a proxy is what it is: an event nobody complained about is not proof
it was harmless.

---

## 3. Customer-managed keys (§55)

**What already existed:** `persistence/crypto.py` implements envelope encryption
with a `KeyProvider` port. The unused standalone KMS wrapper was removed in
Phase 2. The retained encryption layer
does the cryptography and is **not duplicated** — a second `KeyProvider` would be
a second answer to "which key wraps this".

**What was missing:** a tenant dimension. Those keys belong to the deployment —
`current_key_id()` takes no tenant, and there is no state in which a key exists
but may no longer be used. That is fine for a vendor-managed service and is
exactly what BYOK replaces.

### The property BYOK actually sells

**The customer can make their data unreadable, unilaterally, without asking the
vendor.** Everything else — rotation, audit, per-tenant separation — is table
stakes a vendor-managed key also provides.

That is why `REVOKED` is terminal and `revoke()` has no inverse. A revocation
support can undo is a *suspension with a misleading name*, and a customer who
believed the first would be wrong in a way that matters legally.
(`test_revocation_is_terminal`)

Revocation applies to **every version**, not just the active one — revoking only
the active version would leave the tenant's history readable, which is not what
a customer means. (`test_revocation_makes_every_version_unreadable`)

### Rotation is not revocation

A system that treats rotation as "revoke then create" destroys the tenant's
history on a routine operation, and this has happened to real products. So
rotation demotes the previous version to `DECRYPT_ONLY`: new writes use the new
key, old reads still work.
(`test_rotation_keeps_prior_versions_readable`)

`KeyVersion` holds a **reference** — an ARN, a Key Vault URI, an HSM label —
never material. A vendor that holds the bytes can decrypt after revocation
regardless of what its state machine says, so a test asserts no field named
`key`, `material`, `secret`, or `private_key` exists on it.

---

## 4. Retention (§78) and residency (§79)

### These two obligations genuinely conflict

"Support deletion requirements while preserving authorized audit evidence" is
two requirements pulling opposite ways, and pretending otherwise produces a
product that fails one of them silently.

So `RetentionPolicy` separates *what a tenant may configure* from *what the
system will not delete regardless*. A tenant can set events to 30 days. A tenant
**cannot** set the hash-chained audit trail to 30 days, because deleting from it
breaks verification of everything after it — a compliance feature that destroys
the evidence chain is not the feature anybody wanted. `IMMUTABLE_CLASSES` names
each one with its reason, and a test rejects placeholder reasons because "n/a"
is how a declaration requirement gets satisfied without a decision being made.

Bounds have **minima as well as maxima**. A tenant that sets incident retention
to one day has disabled their own incident history and will discover it during
the investigation that needed it. And raw payloads may not outlive the events
that reference them — an orphan nothing can interpret, and the most sensitive
thing stored.

The deployment-wide window is a **floor**: a tenant may ask for less retention,
never more, or one tenant's preference becomes every tenant's storage bill.

### Residency is an architectural constraint, not a field

Storing a region on a tenant proves nothing. What §79 actually asks is that no
code path *needs* to see every tenant at once — such a path forces one database
holding every region's data, and that database can only be in one place.

`assert_no_cross_region_read` **raises rather than filtering**. Silently
returning the reachable subset would give a caller a partial answer they would
reasonably treat as complete, and "the report showed 4 of 7 regions and said
nothing" is worse than an error.

It is enforced on the **retention sweep** specifically, because that is the path
that deletes: a US deployment reaching into EU rows is bad enough when reading
and unrecoverable when deleting.

The existing design already helps — every table is tenant-scoped under FORCE ROW
LEVEL SECURITY and every repository takes a `TenantId`. This makes that property
named and testable rather than incidental.

---

## 5. Configuration

```bash
SENTINEL_PROTECTION_MODE=protect      # observe|monitor|warn|protect|lockdown
SENTINEL_PROTECT_ENFORCE=true         # must agree with the mode
SENTINEL_REGION=eu                    # us|eu|in|customer
```

Both region and mode are validated at startup against closed sets. A typo
assigns the deployment to a region no tenant matches, which would make every
residency check refuse and read as a total outage — so it fails to boot instead.

## 6. Authorization

| Capability | Held by | Why |
|---|---|---|
| `MANAGE_CONTAINMENT` | analyst, admin | Emergency control; worst case is over-blocking somebody notices in minutes |
| `MANAGE_POLICY` | **admin only** | Durable and silent; a permissive policy can sit undetected for months |

Different failure shape, different grant. An analyst can stop an agent at 3am
and cannot quietly widen what the estate permits.

## 7. Known limits

- **Existing OIDC and SCIM routes remain.** The unused SAML validator was
  removed in cleanup Phase 2; SAML support is not counted as a shipped capability.
- **The enterprise console** is the existing `interface/console`. The Phase 5
  controls above are API-only; no console screens were added for policy
  versioning, key state or retention.
- **BYOK is the tenant key *lifecycle*, not a per-tenant KMS adapter.** Which key
  a tenant's data is under, and whether it may be used, is modelled and stored.
  Wiring a specific customer's AWS KMS or Key Vault to a specific tenant's
  `key_ref` still needs the same per-provider authentication work that §34's
  remediation adapters need, and for the same reason: it cannot be tested
  without real credentials against real accounts.
- **Residency is enforced on the sweep, not on every read.** A per-read check
  would be a database lookup on the hot path; the current placement covers the
  destructive path and the configuration paths.
