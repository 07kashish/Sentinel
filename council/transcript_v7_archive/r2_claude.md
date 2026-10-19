I've verified enough to adjudicate. Writing the debate.

---

## Where a peer is right and I was wrong

As the seat that wrote all six remediation passes, I audited my own work against the peers' citations. Five of Codex's findings survive verification and are defects I shipped:

- **Retry is non-resumable (Codex W1).** `process()` opens with an unconditional `advance(State.VALIDATED)` (`api/pipeline.py:194`) with no current-state check. A transient failure at, say, `EVIDENCE_STORED` re-queues the item (`api/main.py:133,138`), and the second run immediately attempts a backward transition to `VALIDATED`, which the lifecycle rejects as illegal → `TERMINAL_ERRORS` → `repository.fail()` (`api/pipeline.py:327-336`). One transient blip becomes permanent loss. This is the relocation the board asked me to hunt: the DLQ-bypass fix (propagate instead of swallow) created a retry path that cannot resume, so it terminalizes. **Codex is right; I was wrong.**
- **Execution fence dropped at the finish line (Codex W2).** Every intermediate `advance()` passes `epoch=lease_epoch` (`api/pipeline.py:186`); the final `COMPLETED` transition bypasses `advance()` and calls `repository.transition(...)` directly with no epoch (`api/pipeline.py:320`). A reclaimed stale worker can complete an incident another worker owns. Correct.
- **Evidence package permits authenticated relabelling (Codex W3).** The leaf is `leaf_hash(evidence)` over the body only; `incident_id` is a separate column (`app/attestation/ledger.py:59-61`), and the signature binds `(merkle_root, tenant_id, batch_id)` only (`ledger.py:291-296`). Genuine, signed evidence can be re-presented under a different `incident_id`/sequence and `verify_package` still returns `True`. My Critical-6 fix hardened *body* provenance and left *metadata* provenance open — a second-order relocation of the same forgeability class. Correct.
- **Protect mode cannot emit `block` (Codex W5).** `protect_evaluate` forces `trust_level="unsigned"` (`api/main.py:792`), unsigned severity is capped at 79 (`app/monitoring/rules.py:42`), and `block` needs ≥85 (`api/main.py:806`). The documented strongest state is unreachable. Correct — though I'll contest its severity below.
- **K8s egress drops PostgreSQL (Codex W6).** `deploy/k8s/sentinel.yaml:87-88` has a duplicate `ports:` key in one map; YAML last-key-wins keeps the removed Redis `6379` and discards `5432`. Under the default-deny egress policy, pods cannot reach their database. Correct and embarrassing.

Antigravity is right that the **redaction tombstone** (`app/storage/db.py:786-816`) is the genuinely novel, defensible mechanism here, and right that **RLS-defaults-off** is effectively RLS-absent — though that one is on the brief's explicit "NOT done" list, not a discovery.

## Where a peer is wrong

**Antigravity, "Rate Limiter DoS… the fix became a weapon" (Critical).** Quote: *"updates `updated_at` to `now` even when a request is rejected… the bucket never refills, permanently locking out the tenant."* This is a misread. `ratelimit.py:69` credits elapsed refill into `tokens` **unconditionally, before** the allow check, and the write-back stores that already-refilled value alongside `now` (`ratelimit.py:82-86`). Because each write bakes the accrued refill into the stored token count, the next call adds refill for the new interval on top — accumulation is continuous. A rejected tenant keeps gaining tokens and recovers. The classic bug Antigravity describes requires writing back the *pre-refill* token count on reject; the code does the opposite. **Not a defect, not a launch blocker.**

**Antigravity, "fundamentally capped by SQLite… single-node SQLite with locked queues caps horizontal scaling" (Scalability 50, Architecture rationale).** Factually wrong for this tree. `app/storage/engine.py:14-29` documents — and `tests/live/test_postgres_live.py` verifies against PostgreSQL 16.2 — a wired Postgres path using `SELECT … FOR UPDATE`; the prior "resolved but never used" defect is closed. `engine.py:154-178` *refuses to boot* multi-replica on SQLite. SQLite is the local-dev default, not the production ceiling. Codex got this right ("PostgreSQL queue is credible"). Antigravity's Architecture-70-but-SQLite-capped position is internally inconsistent.

**Antigravity, "DLQ is a Black Hole… delivery_queue has no consumer" (Critical).** Partly conflated. Pipeline retries flow through `work_queue`, which `pipeline_worker` does consume (`api/main.py:187,202`); `dlq.drain()` is the consumer abstraction (`app/core/dlq.py:217`). The valid residue is narrower: replaying a *pipeline-kind* dead-letter (`api/main.py:490`) sets a `delivery_queue` row to pending with no router back into `work_queue`, and the incident is already `FAILED`. That's a misleading replay endpoint — real, but **Medium**, not a Critical black hole, and it rests on Codex W1 (the incident being terminal), not on a missing consumer.

**Codex, W4 "erased evidence can be resurrected" (Critical).** Mechanism confirmed — `save_evidence` upserts `content_json` with no tombstone guard (`app/storage/db.py:743-749`). But the live trigger Codex names ("retry/stale work can restore erased content") is largely closed by Codex's *own* W1: a retry never re-reaches `save_evidence` (`pipeline.py:257`) because it dies at `VALIDATED` first, and `incident_id` is a UUID so no new incident collides. It's a defensive gap worth a one-line guard, not a Critical erasure-reversal in practice. The two findings partially cancel.

## Component-by-component contest

**1. Lifecycle / retry.** Strongest claim: Codex — "retry is retry theatre." Challenge: none survives; verified at `pipeline.py:194,327-336`. Resolved: **CONFIRMED Critical.** Problem: non-resumable retry terminalizes transient failures. Evidence: `pipeline.py:194` unconditional `advance(VALIDATED)`. Risk: silent incident loss on any transient infra blip post-validation — for a SOC tool, dropped incidents are the cardinal sin. Solution: resumable stage dispatcher keyed on durable state, each stage idempotent. Tradeoffs: migration + heavy test rework. Effort: 3–5 wks. Priority: **Critical.**

**2. Execution fence.** Strongest claim: Codex — epoch omitted at `COMPLETED`. Resolved: **CONFIRMED.** Problem: `pipeline.py:320` bypasses the fenced `advance()`. Risk: stale worker completes a reclaimed incident. Solution: make execution context mandatory (a capability object), not an optional kwarg, so a call site *cannot* omit it. Effort: 1–2 wks. Priority: **High.** (See "what we missed" — this is the mutation harness's blind spot made flesh.)

**3. Attestation / ledger.** Strongest claim: Codex — relabelling. Resolved: **CONFIRMED.** Problem: leaf and signature bind body/tenant/batch, not `incident_id`/sequence/chain-head (`ledger.py:59,291-296`). Risk: genuine evidence presented as a different incident verifies `True`. Solution: sign a canonical manifest {schema, tenant, incident, seq, chain-head, leaf-count, root}; verify equality end-to-end. Effort: 2–3 wks + crypto review. Priority: **Critical** — this is the product's core promise.

**4. Protect mode.** Strongest claim: Codex — `block` unreachable. Resolved: **CONFIRMED but downgraded to Medium.** Every protect response carries `enforced: false` (advisory only), so an unreachable `block` label is a spec/telemetry defect, not an exploitable enforcement gap. It becomes High the day enforcement ships. Solution: verify event identity in protect mode; decide fail-closed policy for unverified high-risk. Effort: 3–5 days.

**5. Storage / scale.** Strongest claim: Antigravity — SQLite cap. Resolved: **REFUTED** (`engine.py:14-29,154-178`). The real residual bottleneck is Codex's: a transactional DB token-bucket on every request (`ratelimit.py:56-86`) and per-pod pollers. Priority: Medium, deferrable past first customers.

**6. Rate limiter.** Strongest claim: Antigravity — DoS weapon. Resolved: **REFUTED** (`ratelimit.py:69`). No action.

## What ALL of us missed entirely

**The mutation harness has a structural blind spot, and `pipeline.py:320` is live proof.** The harness (the brief's central trust claim) mutates by *deleting a guard inside `repository`* and checks a probe goes red — it proves guards are load-bearing *when invoked*. It cannot catch a **call site that never invokes the guard**. The fence omission at `COMPLETED` is exactly that: the guard exists, is mutation-tested, and a real call site bypasses it anyway. So the answer to "is the mutation harness real or theatre?" is: real, but it certifies guard *presence*, not guard *coverage* — and coverage is where two of my defects live (fence omission, missing manifest binding). None of the three of us named this limit precisely.

Second miss: everyone scored AI/ML ~20 and moved on, but nobody stated the consequence — with the classifier demoted to shadow (correctly) and AUC 0.763/ECE 0.48 unchanged with no training-data path, **the product's detection value is now ~zero and structurally can't improve in-house.** What remains is an attestation/observability layer. That should reframe the whole company, not just a subscore.

## The single disagreement that most changes the investment decision

Codex vs. Antigravity on storage. Antigravity treats SQLite as an architectural death sentence gating Series A; Codex treats Postgres as credible. **Codex is right** (`engine.py:154-178`), which *raises the engineering ceiling* — scale is not architecturally blocked. But it does **not** move the investment verdict, and that is the point worth stating plainly: the binding constraint was never storage. It's zero customers, a detector that can't detect, and a relocation pattern that just repeated (W1, W2, W3). Improved engineering raised the floor under an acqui-hire; it did not create a business.

## My revised scores (moved from the prior board's 36/36/20)

- **Engineering 58** (was ~36): real state machine, live Postgres, mutation harness, fail-closed auth — but W1/W2/W3 are shipped Criticals, so not Codex's 59-with-a-clear-conscience.
- **Architecture 52** (was low): dual-engine done right; retry/fence/sealing boundaries still non-atomic.
- **Security 40**: auth/RBAC genuinely improved; relabelling, RLS-off, ASI coverage 5/10 cap it.
- **Scalability 40** (Antigravity's 50 is generous, Codex's 31 too harsh given verified Postgres).
- **AI/ML 20, UX 18, Business 12, Investment-readiness 18 — UNCHANGED.** Detection, customers, distribution did not move. Verdict holds: **NO** on $100M, Series A, launch, and production control-path. A capped pre-seed acqui-hire on the attestation/tombstone IP is the only defensible check, and only after design-partner telemetry exists.