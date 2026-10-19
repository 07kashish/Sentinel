# Sentinel — executive summary

**The authorization, enforcement and verifiable execution layer between
autonomous AI agents and consequential enterprise systems.**

Every consequential autonomous action is identified, contextualised,
authorized, enforced, observed, attributed, evidenced — and verifiable by
somebody who does not trust us.

---

## The claim, and its limits

Sentinel answers, for any action an agent took:

> Who acted? Which human authorized it? Was the delegation valid? Which tool,
> which credential, which resource? Did the tool change after approval? Which
> policy version decided? Was approval required, and who gave it? Did it
> actually execute? What is the causal lineage? What is the blast radius? **Can
> a third party verify the answer without trusting Sentinel?**

The last question is the differentiator. An Execution Passport is a signed,
canonically serialised record that a **reference verifier sharing no code with
this system** can check with a public key. Two independently written
canonicalisers agree byte-for-byte on the cases implementers get wrong:
non-ASCII, explicit nulls, deep nesting, 2⁵³+1 integers, and floats — which are
refused outright, because `0.1 + 0.2` renders two ways and a passport with two
valid signatures lets an adversary present whichever one the verifier will
accept.

**What Sentinel does not claim.** It does not detect all malicious behaviour.
Its detection model is advisory and structurally incapable of moving a triage
state or authorizing anything: an ML score alone can never cause a destructive
action. Recall figures come from a hand-written corpus and are an **upper
bound** — the corpus contains the evasions already known.

---

## Architecture, in one page

Deterministic authorization is synchronous and in the path. Everything
expensive is not.

```
event admission → durable event → outbox → detection worker → correlation → incident
```

Enforcement never waits on a model, a SIEM, or a third party. Nine security
invariants hold regardless of load:

1. Authorization is deterministic. No LLM sits in a control path.
2. Fail-closed. `stops_action` uses an allowlist of what *proceeds*, so a new
   decision type stops by default rather than being forgotten into `allow`.
3. The tenant comes from the credential, never the request.
4. Row-level security is `FORCE`d, and the suite proves it blocks with the
   application predicate **deleted**, connecting as a non-superuser — a
   superuser bypasses RLS and every assertion would pass vacuously.
5. Capability grants, never role ordering. An agent credential can read nothing.
6. Approval is a separate capability and a separate state transition.
7. An attestation error is never execution success.
8. Evidence is hash-chained; a modified record breaks the chain.
9. No global mutable security state.

---

## Measured, on the engine production uses

| | Measured | Target |
|---|---|---|
| Authorization decision p99 | **0.393 ms** | 100 ms |
| Ingest p95 (PostgreSQL, production-shaped) | **71.6 ms** | 500 ms |
| Ingest requests, zero failures | 16,082 | — |
| Schema-driven fuzzing | **1,880 / 1,880** across 45 operations | — |

The 30-day availability SLO stays **UNVERIFIED**: 99.9% permits ~43 minutes of
downtime per 30 days, and a seven-minute window cannot sample that. A clean
short run is *consistent with* the SLO and does not demonstrate it.

---

## Release readiness — two scoreboards, deliberately

**A. Engineering readiness** — 22 gates, 17 categories, reachable through
reproducible work.

**B. External assurance** — 4 gates that **no build can ever satisfy**:
independent pentest, production soak, cross-region DR, design partner
validation. They accrue from a contract, a calendar, a second failure domain
and other organisations' traffic.

Combining them into one number was wrong in both directions at once — it
understated finished engineering and overstated commercial readiness. See
[`RELEASE_READINESS.md`](RELEASE_READINESS.md) for what discharges each
external gate, with owner, elapsed time and cost.

`test_ga_gates_cannot_be_faked.py` plants a correctly-bound artifact claiming
success for each and requires the verdict to remain `UNVERIFIED`. Those four
are exactly the gates somebody under commercial pressure would want to turn.

---

## Why the evidence is worth believing

Every artifact is bound to the commit and source tree that produced it.
**Unbound is `UNVERIFIED`, never `PASS`** — an artifact whose origin nobody
recorded is epistemically identical to one that does not exist. Producers stamp
their own output immediately; stamping later would let a sidecar claim a build
the measurement did not come from.

If the tree changes *while* gates run, the runner deletes everything it wrote
and exits 2 — the gates did not fail, the run is void.

### And the checks are checked

The dominant defect class found building this was **a check that reads
something other than what it appears to read**. Fifteen instances, every one
reporting success. Twenty-one gates that resolved to no filename. A test that
scanned for `PASS` and matched the prose promising it. A console that rendered
blank on every tab while a check clicked all nine views and found text — because
`innerText` returns text from hidden elements.

`scripts/verify_guards.py` now breaks each protected property on purpose and
requires its guard to **fail**. A guard that stays green while its property is
broken is reported as vacuous. Seven mutations, all detecting.

**A guard that cannot fail is not a guard.**

---

## Honest status

| | |
|---|---|
| **Ready** | Deterministic authorization, tenant isolation, evidence chain, MCP and A2A controls, release binding |
| **Working, bounded** | Detection (advisory, corpus-limited), discovery (per-connector coverage stated), blast radius (needs declared sensitivity) |
| **Not built** | A2A streaming transport, per-server MCP usage, persistent asset declarations |
| **Not ours to finish** | The four external gates |

Known exposure: **16 unfixed CVEs** (3 CRITICAL, 13 HIGH) in `python:3.12-slim`
with no upstream patch — recorded rather than suppressed, because
`--ignore-unfixed` makes a gate actionable and the exposure invisible, and only
the first is desirable.

---

## Related

- [`RELEASE_READINESS.md`](RELEASE_READINESS.md) · [`ARCHITECTURE.md`](ARCHITECTURE.md) · [`THREAT_MODEL.md`](THREAT_MODEL.md)
- [`PENTEST_PACKAGE.md`](PENTEST_PACKAGE.md) · [`DESIGN_PARTNER_RUNBOOK.md`](DESIGN_PARTNER_RUNBOOK.md)
- [`RELEASE_GATES.md`](RELEASE_GATES.md) · [`COMPLIANCE_MAP.md`](COMPLIANCE_MAP.md)
- [`../standard/execution-passport-v1/SPEC.md`](../standard/execution-passport-v1/SPEC.md)
