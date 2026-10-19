I have enough verified evidence to file. Two concrete relocations found in the newest (v8) code, both in the flagship "resumable dispatcher." Writing the dossier.

---

## One-paragraph investment thesis
**No** at any stage today, and the newest code makes me *more* cautious than the prior 38/19 board, not less. The engineering hygiene is real and above hackathon grade — a durable outbox, execution fencing, an identity-bound hash chain, fail-closed provenance, 459 passing tests, clean lint. But diligence rewards the thing being sold, and the thing being sold is *trustworthy incident attestation*. I found that v8's marquee fix — the "resumable stage dispatcher" — **relocated the five-times-repeated failure a sixth time, straight into the core value path**: on the exact retry it was built to survive, the pipeline silently produces an *unanchored, evidence-less* attestation (`api/pipeline.py:569-587` never rehydrates `ctx.evidence`; `agents/attestation_agent.py:137-144` then returns `"Skipped"`). Combined with an unchanged detection model (AUC 0.763, ECE 0.48 — the AI is deliberately *out* of the decision path), zero customers, zero production runtime, and a category that consolidated ~$29B of M&A around it, this is strong systems-engineering practice in search of a business. I would fund the *engineer*, not this company. If forced to deploy capital in this space I'd back Zenity/Noma/WitnessAI tier, or acquihire this team.

## Scores
| Lens | Score | Justification |
|---|---|---|
| Engineering | 50 | Strong hygiene (tests, lint, mutation harness, outbox) undercut by a fresh relocation in the flagship v8 reconstruction. |
| AI/ML | 22 | Detection AUC 0.763 / ECE 0.48 unchanged over 3 passes; the model was demoted to advisory, so there is barely any AI in the AI product. |
| UX | 33 | OIDC PKCE dashboard + XSS/CSP fixes, but manual per-call instrumentation is a real adoption tax and no user has ever touched it. |
| Architecture | 50 | Genuinely improved primitives (fence, chain, RLS, outbox); still single-writer, no brokers, seams-not-systems. |
| Innovation | 38 | Identity-bound Merkle manifests + fail-closed provenance are legitimately good; the wedge itself is crowded. |
| Security | 47 | Fail-closed verify, RLS-on-by-default, CSP; offset by unaudited ECDSA, weak injection detection, no DAST. |
| Scalability | 28 | Per-tenant serial `claim_due()` loop, single-writer fence model, no cluster has ever run it. |
| Business | 18 | No customers, no distribution, no pricing validation, in a consolidated market. Lower than the prior board's 36 — I think 36 was unearned. |
| Investment-readiness | 14 | Down from 19: a fix relocating failure into the core value path is diligence-negative, not neutral. |

## Strengths
- **Fail-closed provenance is genuinely correct.** `verify_package` refuses to verify without an out-of-band `trusted_signer` and never falls back to the package's own `signer_address` (`app/attestation/ledger.py:358-364, 234, 390-394`). This closes the forgeable-evidence Critical properly — I could not construct a `True` for evidence Sentinel never signed.
- **Merkle/chain crypto is textbook.** Second-preimage prefixes (`0x00`/`0x01`), promote-don't-duplicate for odd nodes (avoids CVE-2012-2459), geometry checks before hashing (`app/attestation/merkle.py:26-28, 168-169, 214-234`). An auditor really can verify offline.
- **Identity-bound leaf** commits to `tenant_id + incident_id + body hash`, so relabelling a genuine proof onto another incident breaks the signature (`merkle.py:67-82`). This is the right fix for v7's C-3.
- **DLQ is a real state machine, not a log line** (`app/core/dlq.py:150-196`): claim marks `next_at` inside the same transaction that reads it (exclusive claim), backoff has jitter (anti-thundering-herd), `fail()` decides terminality under one lock.
- **RLS now defaults ON** with tenant context threaded through `_connect(tenant_id=...)` (`app/storage/db.py:352-364`) — a real correction of the prior "proven but defaults-off" trap.

## Weaknesses & architectural issues
1. **Resume produces unanchored, evidence-less attestation (RELOCATION #6, Critical).**
   - *Evidence:* `process()` rebuilds `Context` with `detection=None, evidence=None, investigation=None` (`api/pipeline.py:569-580`) and skips durable stages purely by rank (`:586-587`) — it never rehydrates the in-memory artifacts from the DB. A `RetryablePipelineError` raised *inside* `_stage_attest` (network blip in `publish_attestation`) leaves state at `REPORTED`; the queue retries; on re-entry the evidence stage is skipped, so `ctx.evidence is None`; `publish_attestation(detection, evidence=None)` hits `if not evidence: return ...status="Skipped"` (`agents/attestation_agent.py:137-144`); `complete_attestation` records `is_anchored=False` → `COMPLETED`.
   - *Risk:* The one transient RPC outage the resumable dispatcher exists to survive now silently no-ops the product's core promise. This is *exactly* the failure `AttestationUnavailable`'s own docstring warns against ("turn a transient RPC outage into permanent evidence loss", `attestation_agent.py:62-66`) — reintroduced one layer up. `_stage_report` on resume from `EVIDENCE_STORED` similarly renders "Not available" everywhere (report built from `None`).
   - *Fix:* On resume, rehydrate `ctx.evidence/detection/investigation` from durable rows before dispatching, OR make skipped stages a hydration step, not a no-op. Add a test that fails an incident *at the attest stage* and asserts the resumed run still anchors.
   - *Effort:* 1-2 days. *Priority:* **Critical.** This is the single most important finding of the review.

2. **Over-broad terminal taxonomy mis-classifies transient failures as permanent (High).**
   - *Evidence:* `TERMINAL_ERRORS = (…, ValueError, TypeError, KeyError)` (`api/pipeline.py:91-98`). Infrastructure failures routinely surface as these: `json.loads()` on a truncated HTTP body raises `ValueError`; a missing field in a degraded provider response raises `KeyError`.
   - *Risk:* A transient outage that happens to raise `ValueError/KeyError` is recorded `FAILED` with no retry — the very collapse the retry taxonomy claims to prevent (`:601-606`). The taxonomy is type-based, but the type does not reliably indicate determinism.
   - *Fix:* Classify by *origin* (raise typed `RetryablePipelineError` at I/O boundaries) rather than by broad built-in exception types; reserve `ValueError/KeyError` as terminal only when raised by lifecycle/validation code.
   - *Effort:* 1 day. *Priority:* High.

3. **`claim_due()` iterates tenants serially with a transaction each (Medium→High at scale).**
   - *Evidence:* `for tenant_id in db._tenant_ids(): with db._connect(tenant_id) …` (`app/core/dlq.py:165-196`), justified as unavoidable under FORCE RLS.
   - *Risk:* DLQ drain latency grows linearly with tenant count; at 10k tenants this is 10k transactions per poll. The RLS "no wildcard bypass" design is correct for isolation but makes fleet-wide sweeps O(tenants).
   - *Fix:* A privileged maintenance role with a scoped bypass for queue draining, or partition workers by tenant shard. *Effort:* 3-5 days. *Priority:* Medium now, High at scale.

4. **Single-writer-by-fence assumption trades correctness for a re-read (Medium).**
   - *Evidence:* `Context.state` is authoritative and "NOT re-read between stages" because the fence makes this worker the single writer (`api/pipeline.py:142-153`). That reasoning is sound *only* if every side-effecting stage actually asserts the fence on every write — which is true today but is a standing invariant one new call site can break, precisely the C-2 pattern.
   - *Fix:* Keep the AST call-site guard the brief mentions; add a runtime assertion in `repository` that every mutating call carries a non-`None` epoch when one is expected. *Effort:* 1 day. *Priority:* Medium.

## Market intelligence
This category exists and has *already consolidated*. Direct comparables: **Lakera** (→Check Point) runtime guardrails, **Protect AI** (→Palo Alto), **Prompt Security** (→SentinelOne), **Astrix** (→Cisco, non-human identity — Sentinel's exact identity-attestation wedge). Independents better-funded than this team could ever bootstrap: **Zenity, Noma ($100M B), WitnessAI, HiddenLayer**. Sentinel is *worse* on detection (competitors ship tuned injection classifiers; Sentinel's is demoted shadow at AUC 0.763), *worse* on distribution (they have design partners and platform reach; Sentinel has none), and *better* on exactly one axis: **offline-verifiable, identity-bound cryptographic evidence** (`merkle.py` + fail-closed `verify_package`). No incumbent leads with tamper-evident attestation an auditor can verify years later with a single file. That is the only defensible wedge here. What never to copy: per-event on-chain writes.

## Gap analysis
The real unsolved pains: (1) **agent identity/non-repudiation** — 53% of MCP servers use static keys; PKI-agent-identity is the most-cited ASI03 mitigation, and Sentinel's signature-recovered address model (`publish_attestation` refuses to invent identities, `attestation_agent.py:146-158`) is directly on-target. (2) **audit evidence that survives log destruction** — Sentinel's hash-chain + optional anchor genuinely addresses this. (3) **acquisition-orphaned buyers** (§5 of the brief) — the clearest opening. Sentinel *can credibly close #1 and #2 at the primitive level* but cannot close them as a product without detection accuracy, framework auto-instrumentation, and a distribution motion — none of which exist.

## Missing / critical features
- **OTel/framework auto-instrumentation.** Manual per-call SDK wiring is the adoption tax; no enterprise will hand-instrument every agent call. This alone blocks pilots.
- **A detection story that isn't 0.763 AUC.** A security buyer's first question is detection efficacy; the honest answer today loses the meeting.
- **Multi-region / broker-backed queue.** Seams exist, systems do not; the durable queue is single-DB.
- **SOC2 Type II / ISO 27001 posture, DPA, sub-processor list.** Table stakes for the enterprise buyer this is pitched at.
- **SIEM/SOAR connectors** (Splunk, Sentinel-MS, Chronicle) — a SOC tool that doesn't feed the SOC's existing pane is shelfware.

## Feature discovery — 3-5 non-obvious features
1. **Portable "evidence passport."** *Problem:* acquisition-orphaned buyers distrust vendor-locked audit logs. *Impact:* turns the wedge into a moat. *Complexity:* Low — the crypto already produces offline-verifiable packages (`verify_package.py`). *Design:* signed, self-describing export + a 200-line standalone verifier. *AI need:* none. *Defensibility:* becomes a de-facto interchange format; network effect if auditors adopt the verifier.
2. **Cross-vendor attestation notarization.** *Problem:* nobody trusts a single vendor's "we saw nothing bad." *Design:* periodic Merkle-root anchoring to a *neutral* transparency log (Sigstore/Rekor-style), not a testnet. *AI need:* none. *Defensibility:* transparency-log network effects; patent-adjacent around identity-bound leaves.
3. **Deterministic policy-diff replay.** *Problem:* "would this new policy have caught last month's incidents?" *Design:* replay durable incident facts through a candidate `active_policy()` — the resumable state model already stores everything needed. *AI need:* none. *Defensibility:* stickiness via accumulated incident corpus.
4. **Agent kill-switch attestation.** *Problem:* 55-63% of orgs have no kill switch (brief §1). *Design:* signed revocation events on the same chain; an agent can *prove* it was told to stop. *Defensibility:* ties into ASI03/ASI10.

## Security concerns
- **ASI03 (identity/privilege):** genuinely strong — signature-recovered addresses, no fabricated identities.
- **ASI06 (memory/context poisoning) & ASI01 (goal hijack):** weak — detection is the demoted 0.763 classifier; this is where competitors win.
- **Prompt injection:** the product *records* but does not reliably *detect*; ECE 0.48 means confidence scores are meaningless.
- **Supply chain (ASI04):** `pip-audit` now blocking is good; the **unaudited ECDSA recovery primitive** is a live risk in a product whose entire trust rests on signature recovery — get it audited before any pilot.
- **Privacy/GDPR:** the redaction tombstone (`db.redact_evidence`) separating commitment from body is the right design and preserves chain verification — a real strength.
- **No DAST against a deployed instance**; the app has never run in a cluster.

## Scalability & performance concerns
Single-writer-per-incident by fence is fine for correctness, poor for throughput. `claim_due()` is O(tenants) per poll (`dlq.py:165`). No Kafka/NATS; the "durable queue" is a DB table. On-chain anchoring, even batched, adds block-finality latency to any synchronous path. From single-node to millions of users this needs: a real broker, tenant sharding, read replicas, and the anchoring moved fully async (it partly is via the outbox). None of it has been load-tested; **no Kubernetes cluster has ever run this code** (brief §8, verified as unrunnable here — live tests are memory-bound).

## AI quality limitations
The defining fact: **the AI has been deliberately removed from the decision path.** Priority is `priority_for_severity()`, a pure function (`pipeline.py:229`); the model is `advisory_*` and its failure is non-fatal (`:255-259`). That is *good engineering* (attacker-influenced text can't move priority) but means the "AI agent observability" product has almost no AI in its own decisions. Detection AUC 0.763 cross-source and ECE 0.48 (essentially uncalibrated) are unchanged across six passes. Failure recovery for the model is handled gracefully; accuracy is not handled at all because no new training data exists.

## Customer experience / UX friction
Journey: landing → the pitch is honest ("pre-production"). Onboarding → **hard stop: manual per-call instrumentation**; there is no drop-in agent/proxy. Auth → OIDC PKCE + CSRF dashboard is a real improvement (v7 H-3). Dashboard → XSS closed, CSP added. AI interaction → the analyst sees deterministic findings plus an advisory second opinion clearly labelled — actually clean. Reports → on a resumed incident, "Not available" everywhere (finding #1). DLQ view → good, a countable hole. Net: the friction that kills adoption is *day-zero instrumentation*, not the dashboard.

## Monetization & business-model opportunities
Nothing has moved commercially and I won't pretend otherwise. Viable packaging *if* the product existed: per-agent-per-month for identity+attestation, usage-based for events, enterprise tier for the offline-verifiable evidence passport + compliance pack. Growth loop: the standalone verifier as free OSS → auditors demand it → buyers adopt to satisfy auditors. Moat candidates: identity-bound leaf format as an interchange standard; accumulated incident corpus for policy-replay. Realistically the strongest business outcome is **acquihire or a tuck-in of the attestation primitives** into one of the platform consolidators, not a standalone company.

## Launch blockers
- **Critical:** Resume path silently drops attestation (finding #1). Detection efficacy (0.763/0.48) unacceptable for a security claim. Zero production runtime — never run on a cluster.
- **High:** Terminal-taxonomy mis-classification (finding #2). Unaudited ECDSA primitive. No auto-instrumentation. No SOC2/DPA.
- **Medium:** `claim_due()` O(tenants). No broker/multi-region. No SIEM connectors.
- **Low:** Testnet-flavored branding history; benchmark/manifest polish.

## Hidden opportunities & patent-worthy ideas
- **Identity-bound Merkle manifest** (`merkle.py:67-82`) + fail-closed provenance is the most patent-adjacent artifact here — a defensible method for tamper-evident, relabel-proof, offline-verifiable agent evidence with per-tenant privacy via inclusion proofs.
- **Redaction-preserving chains** (GDPR erasure that keeps proofs valid) is a genuinely novel compliance primitive worth protecting.
- **Neutral transparency-log notarization** (not a testnet) reframes the blockchain question into a real differentiator.

## Three things I expect the other seats to get wrong
1. **Crediting the resumable dispatcher as a clean close of C-1.** It fixed the illegal-backward-transition, but the tests inject *before* evidence is durable (`test_pipeline_retry_taxonomy.py:71`) and never exercise a resume *after* it — so they miss that resume runs the attest/report stages with `None` artifacts. The board will likely score Engineering *up*; the flagship fix relocated failure into the core value path, so it should move *down*.
2. **Treating RLS-default-on and 459 green tests as evidence of production-readiness.** Green tests over a suite that doesn't cover the resume-artifact path is precisely the "next generation of theatre" the brief warns about; test count is not coverage of the failure modes that matter.
3. **Over-weighting the blockchain/Base Sepolia debate.** It's a distraction — the crypto is chain-agnostic and sound (`merkle.py` has no chain dependency). The real problem is detection efficacy and distribution, not which chain the anchor lands on.