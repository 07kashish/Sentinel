# Security assurance

What is checked, what each check can and cannot see, and what remains
`UNVERIFIED`.

Commit `879e29f` · **21 of 26 gates PASS, 0 FAIL** · verdict **RELEASE
CANDIDATE**

---

## Automated assurance, and its limits

| Check | Tool | Result | What it cannot see |
|---|---|---|---|
| SAST | bandit `-ll` | **PASS** | Logic flaws; anything requiring cross-file reasoning |
| DAST | schemathesis 4.23 | **PASS** — 45/45 operations, **1,880/1,880 cases** | Anything absent from the OpenAPI document |
| Dependency | pip-audit | **PASS** | Vulnerabilities with no published advisory |
| Secrets | gitleaks, full history | **PASS** | A secret that does not match a pattern |
| Container | trivy `vuln,secret,misconfig` | **PASS** — 0 fixable, 0 secrets | Application logic; anything newer than its database |
| Types | mypy on `sentinel/domain` | **PASS** | The rest of the tree, which carries known errors |
| Architecture | fitness suite | **PASS** | Whether the boundaries are the *right* ones |
| Tenant isolation | RLS suite on real PostgreSQL | **PASS** | Isolation in systems Sentinel does not own |

Two of those deserve expansion.

**`ignored_auth` is the DAST check worth having.** It re-sends every request
*without* credentials and fails if the answer is unchanged. That catches a route
declaring a capability it does not enforce — which no amount of reading the
decorator can prove, because the decorator is the thing being doubted.

**The RLS suite deletes the application predicate** and requires row-level
security alone to block the leak, for reads, updates *and* deletes. It connects
as a **non-superuser**, because a superuser bypasses RLS entirely and every
assertion would pass vacuously. That distinction is the whole test.

## Known exposure, recorded rather than suppressed

**16 unfixed CVEs in `python:3.12-slim`** — 3 CRITICAL, 13 HIGH, across `gzip`,
`libacl1`, `ncurses`, `libsqlite3-0` and `perl-base`. **No upstream patch
exists for any of them.**

The scan fails on *fixable* CRITICAL/HIGH and records the unfixed ones as
standing exposure. `ci.yml` uses `ignore-unfixed: true`, which is right in
policy and lossy in practice — the findings vanish and nobody can see what they
are living with. So the image is scanned for everything and judged on what is
actionable, and both halves are in
`release/gates/gate_container_scanning.json`.

They become fixable the moment the base image ships a patch. The artifact is
what tells somebody to look.

**An embedded secret is never excused by the unfixed rule.** It has no fixed
version and is a defect in this image, not upstream.

## The assurance that assures the assurance

The dominant defect class found building this was **a check that reads
something other than what it appears to read**. Fifteen instances, every one
reporting success, none found by reading the tests.

Four were in the release machinery itself:

| Defect | Reported |
|---|---|
| 21 of 26 gates resolved to `filename = None` | `UNVERIFIED` forever, with a message inviting someone to produce an artifact nothing would look for |
| The runner stamped the tree digest once | Artifacts that *verified* while describing code the commands never ran against |
| The runner's own tests deleted real evidence | A green check erased by its verifier |
| DAST captured UTF-8 with the locale codec | Empty output — so a real finding would have been filed as a tool crash and **suppressed** |

`scripts/verify_guards.py` now breaks each protected property on purpose and
requires its guard to **fail**. Seven mutations, all detecting. A guard that
stays green while its property is broken is reported as **vacuous**.

**A guard that cannot fail is not a guard.**

## Environment faults are not defects

Three times an environmental problem was recorded as a code failure:

| Fault | Was recorded as |
|---|---|
| Scanner crashed on console encoding | A security finding |
| Two pytest processes contending | Two failing gates |
| Disk exhaustion (0.1 GB free) | Four failing gates |

All three now **refuse** rather than produce a result, each verified in both
directions. The principle: a fabricated defect is worse than no measurement,
because somebody acts on it. `UNVERIFIED` is the honest answer when the
environment could not support the check.

## Deterministic authority

No ML or LLM output can authorize anything.

- `ModelAdvice` **cannot express a decision** — the type has no field for one.
- Model output carries an `[unverified-model-output]` prefix that survives
  copying.
- `stops_action` uses an allowlist of what *proceeds*, so a new decision type
  stops by default rather than being forgotten into `allow`.
- Detection findings cannot move a triage state.

If a path is ever found where a model score alone causes a destructive action,
that is a critical finding — and the most valuable single thing an external
tester could report.

## What remains UNVERIFIED

| Gate | Status | Blocker |
|---|---|---|
| `artifact_signing` | UNVERIFIED | cosign keyless needs a CI OIDC identity. A local key would sign the artifact and prove nothing about who built it |
| `independent_pentest` | UNVERIFIED | Contracted third party, agreed scope, report, **and a remediation retest** |
| `production_soak` | UNVERIFIED | The elapsed time *is* the evidence. 30 days minimum |
| `disaster_recovery_proof` | UNVERIFIED | An independent failure domain must exist before crossing it proves anything |
| `design_partner_validation` | UNVERIFIED | A real organisation, real traffic, a real agreement |

**No risk exception has been filed** for any Critical or High finding, because
none is outstanding in Sentinel's own code. The 16 base-image CVEs are recorded
exposure with no available fix — which is a different thing from an accepted
risk, and is not presented as one.

## Unaudited primitive

The **secp256k1 ECDSA recovery** primitive is unaudited. It is the only source
of an `Address`, so a flaw there is an identity-forgery path. Stated here
because a pentest report that rediscovers a documented limitation has spent the
engagement badly.

---

## Related

- [`PENTEST_PACKAGE.md`](PENTEST_PACKAGE.md) — scope and where the soft ground is
- [`RELEASE_GATES.md`](RELEASE_GATES.md) — how evidence binds to a build
- [`RELEASE_READINESS.md`](RELEASE_READINESS.md) — the two scoreboards
- [`COMPLIANCE_MAP.md`](COMPLIANCE_MAP.md)
