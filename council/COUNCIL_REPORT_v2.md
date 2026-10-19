# Sentinel SOC — AI Strategy Council Report v2

**Adversarial re-review of the remediated codebase**

Prepared 21 July 2026 · Repository: `sentinel_soc-main` · Supersedes v1 (same day)

---

## The finding, stated first

The remediation fixed the component-level dishonesty the first council found, and
then **reproduced the same class of dishonesty one abstraction layer up**.

All three seats reached this independently and voted it a regression. It is not a
rhetorical flourish — it was verified against running code for this report:

> The pipeline writes incident state to an **in-memory** store. Every customer-facing
> API read comes from the **durable** store. `db.save_report` has **zero production
> call sites**. Therefore `/incidents/{id}/report` returns *"Report not yet generated.
> Pipeline is still running"* for **every completed incident, forever.**

A trust product that cannot report what it did has failed at the one property it
sells. The first council's core finding was *"this codebase misrepresents its own
state."* That finding survives. Only its location moved.

---

## How this review was conducted

Same three vendors, same harness, three rounds. The charge was inverted: seats
were told their task was to **falsify** the remediation's claims and to find what
it broke, and were given the 12 claims plus a required claim-by-claim verdict
table. A round that merely confirmed the fix list was declared worthless in the
charge itself.

| Seat | Model | Rounds | Round-1 time |
|---|---|---|---|
| Claude Opus 4.8 | `claude-opus-4-8` | 3 | 409s |
| Codex | `gpt-5.6-sol` | 3 | 652s |
| Antigravity (Gemini) | `agentapi --model=pro` → `MODEL_PLACEHOLDER_M36` | 3 | 435s |

### Two conflicts of interest, both disclosed to the seats

**Claude Opus 4.8 implemented the remediation and holds a seat.** It was reviewing
its own work. **Antigravity authored the original codebase.** Two of three seats
are therefore interested parties, and this is the principal methodological
weakness of this round.

Both conflicts cut against the reviewed party rather than for it, which is the
useful direction. Claude's closing states: *"As the seat that wrote this, I weight
these harder, not softer."* Antigravity explicitly attacked Claude's one piece of
optimism. Neither seat's self-interest produced a favourable verdict — every vote
below is NO or PARTIAL.

Every load-bearing finding in this report was **re-verified against running code
by the report author** before inclusion. Five are reproduced with executable
proofs.

---

## The recorded votes

| Question | Claude | Codex | Antigravity |
|---|---|---|---|
| Remediation claims hold up? | **PARTIAL** | **PARTIAL** | **PARTIAL** |
| Honest about its own state? | **NO** | **NO** | **NO** |
| Safe to run a real pilot? | **NO** | **NO** | **NO** |
| Viable commercial product? | **NO** | **NO** | **NO** |
| Viable venture company? | **NO** | **NO** | **NO** |
| Evidence ledger a real moat? | **NO** | **NO** | **NO** |
| **Regression introduced?** | **YES** | **YES** | **YES** |

**Seven of seven unanimous across three vendors.** No split votes this round — a
harder result than v1, where "honest demo today" and "keep attestation" both split.

Biggest single risk, per seat:
- Claude — *"Trust product that misreports its own state — same disease, moved up a layer."*
- Codex — *"The product presents stale durable state as current operational truth."*
- Antigravity — *"Trust downgrade via unsigned deduplication front-running."*

---

## Part I — The regressions the remediation introduced

Five defects that **did not exist before the remediation**. Each was verified for
this report by executing the code, not by reading it.

### R1 — Split-brain state (Critical)

The remediation moved reads to durable storage but left writes in memory.

```
db.save_report      → 0 production call sites (only its own __all__ export)
db.save_incident    → 1 call site (ingestion, api/main.py:699)
push()              → writes only store.update_incident (api/main.py:152-156)
report endpoint     → reads db.get_report (api/main.py:877), never written
```

**Consequences:** every pipeline status transition is invisible to the API;
completed incidents read as pending; the report endpoint is permanently broken;
dashboard metrics count only ingestion-time state; everything the pipeline did is
lost on restart, which **falsifies the marquee durability claim (Claim 7)**.

Under the shipped `Dockerfile` this compounds — 4 Gunicorn workers each hold a
private in-memory store, so which answer you get depends on which worker serves
the request. *(Read from the config; not empirically reproduced.)*

### R2 — Phantom mitigation execution (Critical)

The v1 report's Finding 2 was remediation theater. The remediation reintroduced it
on a different branch. **Executed proof:**

```
$ SENTINEL_FIREWALL_URL="https://firewall.example/api"
  status  : success
  executed: True
  detail  : executed against configured integration
  metric remediations_executed: 1
```

Nothing was blocked. `_INTEGRATIONS` is empty, so `handler` is `None`, and
`outcome = handler(...) if handler else {}` falls through to a hardcoded
`status="success", executed=True` (`mitigation.py:171-181`). Setting an
environment variable is sufficient to manufacture a fabricated containment record.

Compounding it, `remediations_executed` counts `state='approved'`
(`db.py:610-611`) while *simulated non-executions are also stored as approved*
(`mitigation.py:168`) — so the dashboard's execution metric counts actions that
provably never ran.

**This is the exact failure the entire council exists to catch, reintroduced by
the fix for it.**

### R3 — Cross-tenant event suppression (High)

`events.event_digest` is a table-wide `PRIMARY KEY` (`db.py:67`), not scoped by
tenant. **Executed proof:**

```
acme   ingests: True
globex ingests: False
globex can see it: False
```

One tenant's ingestion silently drops another's identical event. This is a
multi-tenancy isolation break introduced by the content-addressed dedupe added for
Finding 17.

Antigravity extended it into an attack the author had not considered: an attacker
who **front-runs an unsigned copy** of an event causes the legitimate *signed*
event to be dropped as a duplicate — downgrading it below the severity cap and
below the attestation threshold. It voted this the single biggest risk.

### R4 — Auth/RBAC parser divergence (High)

`auth.py` builds a `{key: tenant}` dict (**last match wins**); `rbac.py` scans a
list (**first match wins**). **Executed proof:**

```
SENTINEL_API_KEYS="acme:sharedkey:viewer,globex:sharedkey:admin"
  auth resolves tenant: globex   (last match)
  rbac resolves role  : viewer   (first match)
```

Tenant and role are resolved from *different configuration entries*. Antigravity
classified this as privilege escalation. The author's assessment: exploitable only
under duplicate key material, which a startup check should reject outright — but
the divergence is real and was introduced when roles were bolted onto the existing
key scheme.

### R5 — Evidence verifier fails open (High)

Two flaws, both executed:

```
package with NO inclusion proof   → VERIFIED (warning only)
empty proof, leaf == claimed root → verifies; leaf_index 9999 / tree_size 1 ignored
```

`verify_package` returns `ok=True` when `inclusion_proof` is absent
(`ledger.py:179-182`), and `verify_proof` never validates `leaf_index` against
`tree_size` (`merkle.py:178-195`). An auditor handed an unsealed package gets
**VERIFIED**.

Worse, and agreed by all three seats: the package is **self-authenticating**. The
evidence, the proof, and the root all come from the same party. Without an
externally retained or signed checkpoint it proves internal self-consistency, not
non-repudiation — which is why the ledger moat vote was unanimously NO.

---

## Part II — Claim-by-claim verdict

The 12 claims put to the council, with the consolidated verdict.

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| 1 | Attestation REAL/MOCK decided in one place | **PARTIAL** | `is_anchored` gate is genuinely correct; the surfaced `attestation_mode` label still leaks REAL on a configured-but-unmined path |
| 2 | Auth fails closed, all routes, CORS allow-list | **VERIFIED** | 503 unconfigured, 18/20 routes, allow-list confirmed |
| 3 | No mitigation auto-executes | **FALSE** | R2 — phantom execution with a configured URL |
| 4 | Event fabrication deleted from monitor | **VERIFIED** | `generate_mock_real_event` gone; `monitor_loop` demo-gated |
| 5 | No random address minted; Skipped instead | **VERIFIED** | Refusal path confirmed |
| 6 | Client-asserted trust non-authoritative | **PARTIAL** | Holds on `/events/ingest`; legacy `/analyze`, `/ingest-event`, `/ingest/*` bypass it |
| 7 | State durable, survives restart | **FALSE** | R1 — pipeline state is memory-only |
| 8 | Real confusion matrix on labeled corpus | **PARTIAL** | Harness is arithmetically sound; corpus too small to support the published FPR |
| 9 | Evidence persisted before URI published | **VERIFIED** | `unstored:` sentinel until write confirmed |
| 10 | Replay protection, durable | **PARTIAL** | Works; strict ordering rejects legitimate late arrivals |
| 11 | Merkle ledger, offline-verifiable | **PARTIAL** | Cryptography sound; verifier fails open (R5); no external anchor |
| 12 | RBAC + rate limiting, least privilege | **PARTIAL** | Correct in isolation; diverges from auth on duplicate keys (R4) |

**4 verified · 6 partial · 2 false.** The two false claims are the two the
remediation most prominently advertised.

---

## Part III — What genuinely held

The seats were not uniformly negative, and the credit is specific.

**The identity subsystem is sound.** secp256k1 → EVM address binding, canonical
serialisation, the trust ladder, and domain-separated hashing were verified by all
three seats. Claude: *"the spine is sound."* Antigravity, reviewing a competitor's
replacement of its own code, conceded the primitive *"demonstrate[s] technical
competence and correctly implement[s] domain separation."*

**Fail-closed auth is real** and was verified by every seat.

**The honest-signal pattern spread.** Threat-intel tools returning `unavailable`
rather than `clean`, the `unstored:` evidence sentinel, and `is_anchored` were all
confirmed as genuine improvements.

**Merkle cryptography is correct** — second-preimage separation and odd-node
promotion were checked and passed. The flaw is in the *verifier's* permissiveness,
not the tree.

But all three seats attached the same caveat: **the identity layer is unreachable
through the product.** There is no enrollment endpoint, five routes bypass
verification, and the benchmark injects `trust_level` directly rather than signing
real events. Claude: *"an asset you cannot reach through your own API and never
test is a design, not an asset."*

---

## Part IV — Where the seats disagreed

**Is the identity primitive an acqui-hire asset?** Claude argued the honest ceiling
is *"an acqui-hire for the identity primitive."* Antigravity rejected this hard:
*"A platform giant like Cisco or Palo Alto will not acquire a 7,600-line codebase
just for an incomplete secp256k1 canonicalization module that their own engineers
could rewrite securely in two weeks."* Codex sided closer to Antigravity, dissenting
from *"treating the identity and Merkle components as acquisition-grade assets."*

**Assessment:** Antigravity has the better of it on current evidence, and notably
this is the seat with an incentive to defend the original code arguing it should be
rewritten. Claude's counter — that these are *"integration failures a competent
team fixes in a sprint"* — is a point about the team, not the asset, and Claude
concedes it: *"That is the strongest argument for the team and against funding it:
these are not a moat."*

**Claim 1: false or partial?** Claude alone argued PARTIAL rather than FALSE,
distinguishing the *decision core* (`is_anchored`, correct) from the *reporting
surface* (the label, leaky). That distinction is right, and it localises the
remaining dishonesty precisely: **it is in the reporting surfaces — labels,
metrics, endpoint messages, split-brain reads — not in the decision cores.**

---

## Part V — The 90-day plan

All three seats converged on the same first two items, in the same order.

1. **Unify on one authoritative store.** Route every `push()` and report write
   through `db.save_incident` / `db.save_report`; demote `api/store.py` to a cache
   or delete it. Add restart and multi-worker tests proving a completed incident
   stays completed. *(3–5 days. Fixes R1, falsified Claim 7, the broken report
   endpoint, and the pinned metrics.)*

2. **Close every ingestion bypass.** Force `/analyze`, `/ingest-event` and the
   three `/ingest/*` routes through the same verify → dedupe → replay → policy →
   persist path, or delete them. Scope the dedupe key to `(tenant_id,
   event_digest)` and resolve conflicts by **highest trust** to defeat the
   front-running downgrade. *(2–3 days. Fixes R3 and Claim 6.)*

3. **Make identity operational.** Ship admin-gated `/agents/enroll` and
   `/agents/revoke`; have the evaluation harness sign real events through the
   verifier instead of injecting `trust_level`. *(2 days. Turns the only genuine
   asset into a reachable one.)*

4. **Make dishonest surfaces unreachable.** Delete the phantom-execution branch so
   `executed=True` is impossible without a real handler; count
   `remediations_executed` from `result_json.executed`; report `configured` rather
   than `REAL` until a mined receipt exists; fail the verifier closed on a missing
   proof and validate `leaf_index`/`tree_size`. Unify auth and RBAC on one parsed
   config object and reject duplicate keys at startup. *(3 days. Fixes R2, R4, R5.)*

5. **One real integration and an honest efficacy study.** A webhook or single SIEM
   destination with retries, idempotency and a dead-letter path; structured metrics
   and traces; a larger independently curated corpus. Fail CI on precision drops
   and new false positives, not only on non-gap misses. *(4–6 weeks.)*

Items 1–4 total roughly **12–15 engineering days.**

---

## Part VI — What could not be verified

- **The claimed 74 passing tests.** Codex reported 48 pass / 11 fail / 15 errors in
  its sandbox, from SQLite temp-directory failures. The author observes 74/74 green
  on Windows with Python 3.12. Unresolved: **the suite has not been proven green in
  the shipped Linux container**, and CI has never run.
- **Any mined on-chain transaction.** Only label logic was verified.
- **Multi-worker divergence** — read from the Dockerfile, not reproduced.
- **Whether `_INTEGRATIONS` is ever populated dynamically.** Confirmed empty in
  source; dynamic registration not exhaustively traced.
- **Production precision/recall.** The 22-case corpus supports neither the
  published 0.0 FPR (7 benign cases) nor any customer-facing claim.
- **Read-only container behaviour** when the reporting layer writes to disk —
  Antigravity flagged a probable crash loop against `docker-compose.yml`.

---

## Part VII — Honest bottom line

The remediation was real work: 21 findings addressed, 74 tests where there were 5,
a genuine identity layer, fail-closed auth, and cryptography that three vendors
checked and passed. Measured against v1, the *component* honesty problem is largely
solved.

It is also true that **it introduced a critical regression that breaks the product's
central promise**, and reintroduced fabricated success in the exact subsystem the
first council flagged for it. Two of the twelve headline claims are false, and they
are the two most prominently advertised.

The verdict is unchanged and now unanimous on all seven questions: not pilot-safe,
not a product, not a company. The distance to *pilot-safe* is now measured in days
rather than a rewrite — which is genuine progress, and is also, as Claude put it,
the strongest argument against funding it: **defects a competent team clears in a
sprint are not a moat.**

Nothing in this repository should be described as production-ready, enterprise-grade,
or investor-ready on this evidence.

---

## Appendix A — Verification method

Five findings were reproduced by executing code for this report rather than by
accepting a seat's word: phantom execution (R2), cross-tenant suppression (R3),
auth/RBAC divergence (R4), and both verifier failures (R5). R1 was confirmed by
exhaustive call-site grep. Every proof appears inline above.

Where a seat's claim did not survive checking, it is marked PARTIAL rather than
FALSE in Part II — notably Claim 1, where the decision core is correct and only the
label leaks.

## Appendix B — Artifacts

```
council/
├── brief.md                     re-review brief incl. the 12 claims
├── COUNCIL_REPORT.md / .pdf     this report (v2)
├── COUNCIL_REPORT_v1.md / .pdf  the original review, retained for comparison
├── transcript/                  r1-r3 × claude, codex, antigravity + run_summary
└── transcript_v1_prefix/        the first review's transcripts
```

Re-run: `py council/council.py --rounds 3 --timeout 2700`. The Antigravity seat
requires the Antigravity IDE to be running.

---

*Three vendors, three rounds, seven unanimous votes. Two of the three seats were
reviewing their own work and both argued against it. Findings were independently
re-verified before publication; the five most serious are reproduced with
executable proofs.*
