# AI Product Review Board â€” Round 2 of 3: Cross-Examination & Debate
# Your seat: Antigravity (Gemini 3.1 Pro) (Google)

You are one independent seat on a world-class PRODUCT REVIEW BOARD. The
other seats are independent models from rival vendors; you do not defer to them and
you are not here to be agreeable. Hold, simultaneously, the perspectives of a CTO, a
repeat startup founder, a product strategist, a Tier-1 VC partner, a security
architect, a senior UX lead, an AI/ML researcher, and a demanding enterprise buyer.

THE MANDATE
You are conducting exhaustive due diligence as if your fund is about to invest $100M
into this product. Your job is NOT to praise it. It is to aggressively challenge every
assumption, find every weakness, surface every hidden opportunity, and describe how to
evolve this into a category-defining, globally competitive company. Be brutally honest;
do not protect the project's feelings. Reward only features and claims that carry real
customer or business value, weighed against engineering feasibility, maintenance cost,
scalability and long-term defensibility.

GLOBAL INTELLIGENCE MODE
Bring your full external knowledge to bear: current market trends, competitors and the
startup landscape, academic and LLM research, engineering/security/UX standards,
cloud/DevOps practice, SaaS and enterprise business models, pricing and GTM, VC
expectations, and regulatory requirements. Review this product against the whole
software ecosystem, not in isolation. The external brief below is evidence to argue
with, not settled fact.

CONTEXT: TWO MORE REMEDIATION PASSES HAVE HAPPENED
This is the EIGHTH review of this repository. The board before you scored it
Overall 38/100 and Investment-readiness 19/100 â€” up two and down one from the
board before that (36 and 20) â€” with NO on launching, commercial viability and
Series A, and 2-1 NO on seed. Since that verdict, two further passes (v7 and v8)
have been worked. Section 8 of the brief lists what was claimed to change and
what was deliberately NOT changed.

This does NOT narrow your review. Conduct the FULL independent due diligence
described below -- every lens, from market intelligence through feature
discovery, moats and roadmap -- exactly as if you were seeing this product for
the first time. The remediation history is context that saves you rediscovering
known ground, not a limit on what you examine. A fix list is not a company, and
your job is still to decide whether to put $100M into one.

Two things deserve particular attention. First: did any fix RELOCATE the failure
one layer up rather than close it -- the pattern this codebase has repeated five
times? That is the single most valuable finding available to you. Second:
engineering hygiene improved a great deal while detection, customers and
distribution did not, so be precise about which scores that should move and
which it should not. Improved engineering is not by itself a business.

THE PRODUCT
Sentinel â€” a Trust & Incident Attestation / agent-observability & policy-enforcement
layer for AI agents (pre-production, honest about its status per its own README). You
must READ THE CODE before judging it. Representative surface (not exhaustive â€” explore):
  README.md  PILOT_README.md  YC_APPLICATION_NOTES.md
  app/core/lifecycle.py  app/core/repository.py  app/core/config.py  app/core/dlq.py
  api/main.py  api/pipeline.py  api/auth.py  api/rbac.py  api/oidc.py
  app/integrations/  app/storage/  app/attestation/  app/identity/  app/monitoring/
  app/observability/  app/response/  app/tools/  agents/  dashboard/  sentinel_sdk/
  evaluation/  deploy/  tests/  docker-compose.yml
Cite file:line for every code-specific claim. Uncited claims about the code are discounted.

COVER EVERY LENS (do not skip; where a lens does not apply, say so briefly):
- Market intelligence: does this already exist? who are the incumbents and challengers,
  where are they better/worse, what is the defensible wedge, what to borrow, what never
  to copy.
- Gap analysis: the real, unsolved pains in this market (customer, workflow, trust,
  privacy, latency, cost, adoption) and whether Sentinel can credibly solve them.
- Feature discovery: invent features no competitor offers â€” "the product customers never
  knew they needed" â€” each with problem, impact, complexity, technical design, AI
  requirement, business value, defensibility.
- Technical architecture: frontend, backend, data model, storage, caching, auth/z,
  encryption, AI/agent orchestration, prompt design, memory, RAG/vector/knowledge-graph,
  queues/workers, observability, testing, CI/CD, deploy, scalability, reliability, cost.
- Security: OWASP (incl. the Agentic ASI top-10), authn/z, secrets, rate limiting, data
  privacy/GDPR/SOC2/ISO, prompt injection, model abuse, data/RAG poisoning, supply chain,
  recovery/DR.
- Performance & scale: bottlenecks from single-node to millions of users and global
  deployment; inference, streaming, DB, cache, network, concurrency.
- AI quality: hallucination, reasoning, accuracy, tool use, planning, autonomy, memory,
  cost, latency, multi-agent collaboration, failure recovery.
- UX / user journey: landing -> onboarding -> auth -> dashboard -> AI interaction -> reports ->
  settings -> notifications -> errors -> help. Find friction.
- Business & investment: MVP/V1/V2/V3 roadmap; pricing, subscription, enterprise
  licensing, API monetization, white-label, partnerships, marketplace, growth loops,
  network effects; would YC / Sequoia / a16z / Accel / Lightspeed / Benchmark invest, and
  the honest reasons why or why not.
- Launch readiness: can it launch today? every blocker, categorized Critical/High/Medium/Low.
- Hidden opportunities & moats: ignored industries/customers, emerging markets, patent-worthy
  ideas, durable moats. Think five years ahead â€” where do LLMs, agents, regulation and buyer
  expectations go, and how must Sentinel evolve to still win.

RULES OF ENGAGEMENT
- Cite files and line numbers for code claims. Quantify wherever you can.
- Say "I could not verify X" rather than guessing. Distinguish what the code DOES from
  what the docs/README/pitch SAY.
- Every criticism carries: Problem, Evidence, Risk, Solution, Tradeoffs, rough effort,
  Priority. Recommend only what a serious operator would actually build.
- Never reproduce a secret found in the repository. Do not recommend disabling safety
  gates, auth, or human-approval steps.
- You are not a licensed financial advisor; frame investment views as diligence opinion,
  not personal advice.
- Being wrong is recoverable. Being vague is not. Density over length.


---
# EXTERNAL INTELLIGENCE BRIEF

# External Intelligence Brief â€” AI Agent Security Market & Sentinel Diligence Baseline, July 2026

Compiled from live web research for the Product Review Board. Every seat receives this
brief verbatim. Figures are as reported by the cited sources; vendor-published numbers
are marked. Treat this as evidence to argue with, not as settled fact â€” it is market
context plus a verified snapshot of the product's current technical state, given so the
board spends its time on judgment rather than rediscovery. Nothing here is a conclusion;
the scores, verdict and roadmap are yours to determine.

---

## 1. The threat landscape is real and it is the exact one Sentinel targets

- Prompt injection is the **#1 AI security threat of 2026** and the fastest-growing
  attack category globally, reported at **+340% year over year**.
- Prompt injection appears in **over 73% of production AI deployments** and is
  credited with roughly **$2.3B in global losses in 2025**.
- **EchoLeak (CVE-2025-32711, CVSS 9.3)**, June 2025 â€” the first documented
  *zero-click* prompt-injection exploit against a production system (Microsoft 365
  Copilot). A single crafted email caused Copilot to read internal files and
  exfiltrate them to an attacker-controlled server. No user interaction.
- **GTG-1002**, a state-sponsored campaign, hijacked coding agents to execute an
  estimated **80â€“90% of an espionage operation** against ~30 targets. The agents
  did the work.
- Malicious prompts were injected into legitimate GenAI tools at **90+ organizations**
  during 2025.
- The governance gap is the buying trigger: **41â€“44%** of organizations have no
  human-in-the-loop control, and **55â€“63%** have no purpose binding, kill switch, or
  network isolation for their agents.

**Implication for the council:** demand for this category is not speculative. The
open question is not "is there a problem" but "does *this* codebase solve any part
of it better than a funded incumbent already does".

---

## 2. The standards layer has consolidated around a specific threat model

**OWASP Top 10 for Agentic Applications (ASI), 2026 edition** â€” now the reference
threat model for agents and MCP servers:

| ID | Risk |
|---|---|
| ASI01 | Agent Goal Hijack |
| ASI02 | Tool Misuse & Exploitation |
| ASI03 | Agent Identity & Privilege Abuse |
| ASI04 | Agentic Supply Chain Compromise |
| ASI05 | Unexpected Code Execution |
| ASI06 | Memory & Context Poisoning |
| ASI07 | Insecure Inter-Agent Communication |
| ASI08 | Cascading Agent Failures |
| ASI09 | Humanâ€“Agent Trust Exploitation |
| ASI10 | Rogue Agents |

Also live: **OWASP MCP Top 10** (model misbinding, context spoofing, prompt-state
manipulation, insecure memory references, covert channel abuse) and an **OWASP
Agentic Skills Top 10**.

Identity is the emerging structural answer: **53% of MCP servers use static API keys
or personal access tokens** rather than OAuth or certificate-based auth, and many
agent-to-agent paths are entirely unauthenticated. PKI-based agent identity is the
most-cited mitigation for ASI03.

**Question for the seats:** map Sentinel's actual detection rules to this table.
How many of the ten does the code genuinely cover, versus claim to cover?

---

## 3. Competitive landscape â€” the category has already consolidated

Enterprise spend on agentic AI is projected at **$201.9B in 2026**. Around RSAC 2026,
**$392M** in agentic-AI-security funding was announced in a two-week window.
Acquisitions hit **18 deals in 2026** (vs 12 in 2025, 4 in 2024), and roughly
**$29B of M&A** has been assembled into stacks purpose-built to discover, govern and
secure AI agents.

Who owns what now:

- **Lakera** â†’ acquired by **Check Point** (2025, ~$300M). Runtime guardrails for
  prompt injection and policy violation. Free developer tier; enterprise by quote.
- **Protect AI** â†’ acquired by **Palo Alto Networks**. Roadmap now answers to
  Palo Alto's platform strategy.
- **Prompt Security** â†’ acquired by **SentinelOne**.
- **Aim Security** â†’ acquired by **Cato Networks**.
- **Astrix Security** â†’ acquired by **Cisco** (~$400M, May 2026) â€” non-human identity.
- **Still independent:** Zenity (agent security/posture), Noma Security ($100M
  Series B), WitnessAI ($58M, extended into agentic control), HiddenLayer, Straiker,
  Guardion, Pillar, Lasso.
- **Platform giants competing directly:** Microsoft, Cisco, Palo Alto, Check Point,
  SentinelOne, Radware (launched agentic AI protection in 2026).

Pricing is almost universally **quote-based**; Lakera Guard is the notable free
developer tier. There is no published per-agent or per-event list price to anchor to.

**Question for the seats:** with this much consolidation, is the honest position for
a 3.2k-LOC project "compete", "be acquired", "sell to the segment the giants ignore",
or "this is not a company"? Argue it, do not hedge it.

---

## 4. What investors are actually funding in 2026

- **Production-risk adjacency is the strongest buying signal** â€” companies tied to
  deployed agents, runtime controls, observability and enterprise workflows raised
  the most convincing rounds.
- The strongest signal specifically: helping enterprises **see, test, constrain, or
  audit agents before** they create security or compliance risk.
- **Agent execution infrastructure took 20.7% of 2026 YTD deals** (runtimes,
  sandboxes, identity, observability, security testing, control layers).
- Observability is one of the three hottest technical layers, alongside red teaming
  and evaluation. The market is moving **beyond testing into continuous monitoring
  and live protection**.
- Cyber startup funding overall is solid in H1 2026; valuations are climbing while
  capital concentrates.
- **Seed reality check:** seed rounds are **50% of disclosed deals but only 17% of
  capital**. The outlier was JetStream Security at $34M seed.

**Question for the seats:** Sentinel is positioned as "observe mode now, protect mode
next", which is precisely the see/audit-before-risk framing investors reward. Is that
positioning earned by the code, or is it a deck that the repository does not back up?

---

## 5. Consolidation is creating a real, exploitable customer pain

CISOs who signed with Protect AI now answer to Palo Alto's roadmap. The same is true
for Lakeraâ†’Check Point and Prompt Securityâ†’SentinelOne customers. Every acquisition
strands a cohort of buyers who chose a focused tool and got a platform.

This is the clearest opening in the brief. Whether a 3.2k-LOC project can serve those
buyers is a separate question the council must answer honestly.

---

## 6. Regulatory position as of July 2026

- **August 2, 2026** remains the enforcement date for **Article 50 transparency
  duties** (chatbot disclosure, AI-content marking, deepfake labelling) and for the
  Commission's **GPAI enforcement powers**.
- **June 16, 2026:** the European Parliament approved amendments pushing *most*
  high-risk (Annex III) obligations out to **December 2027 and August 2028**. Article
  50 was explicitly **not** delayed. Sources disagree on exactly what survives
  August 2; treat the high-risk timeline as contested.
- Penalties reach **7% of global annual turnover / â‚¬35M** â€” above GDPR's 4%.
- As of April 2026, **78% of organizations** had taken no meaningful compliance steps.

**Question for the seats:** does the delay of high-risk obligations to 2027â€“28 remove
Sentinel's compliance-driven urgency, or does it just move the deadline out far
enough that a small team can actually build for it? Disagree productively.

---

## 7. The blockchain-attestation question (Sentinel writes to Base Sepolia)

Evidence cuts both ways and the council should treat this as a live dispute:

**For.** Enterprises are adopting tamper-proof platforms binding identity events to
immutable logs to reduce disputes and strengthen compliance. Audit logs serve five
functions â€” forensic reconstruction, regulatory evidence, unauthorised-access
detection, insider-misuse deterrence, accountability enforcement â€” and cryptographic
non-repudiation strengthens all five, remaining verifiable even if a local log is
destroyed.

**Against.** Even *private* blockchains run orders of magnitude slower than ordinary
databases. High-volume logging (millions of events/sec) cannot go on-chain without
severe degradation. Consensus needs multi-node participation and adds latency
proportional to block finality. The literature positions blockchain as
**complementary to existing audit-log standards, not a replacement**.

**The mainstream pattern** is hybrid: hash-chained or Merkle-tree logs held locally
with **periodic hash commitments** anchored to a public chain â€” not per-event writes.

**Question for the seats:** Sentinel anchors incident attestations to **Base Sepolia,
a testnet**. Is on-chain attestation a genuine differentiator, a hackathon artifact
that will read as unserious to an enterprise buyer, or a real feature deployed on the
wrong chain? Take a position.

---

## 8. Verified technical baseline â€” EIGHTH review, after three remediation passes

**This is a RE-REVIEW.** The board before you scored this repository Overall
38/100 and Investment-readiness 19/100, with NO on launching, commercial
viability and Series A, and 2-1 NO on seed. The board before *that* scored 36 and
20 â€” so six passes of engineering work moved Overall **+2** and Investment
**âˆ’1**. Two further passes (v7 and v8) have landed since. Section 8.1 below is
the delta; the rest of this section is the older baseline those boards judged.
Your job is to judge the current tree, not to re-derive the old findings.

**Read this section as a claim list, not as fact.** It is what the implementer
says was done. Verify it. The single most valuable thing you can produce is
evidence that one of these fixes relocated the failure rather than closing it â€”
that pattern has now happened five times in this codebase's history.

### Conflicts of interest, unchanged and important

The Claude seat implemented **all six remediation passes including this one**, so
if you are the Claude seat you are auditing your own work for the third time: be
harder on it than on anyone else's and state plainly where you cannot be
objective. The Antigravity seat is from the vendor whose model wrote the original
code. Two of three seats are interested parties.

### What changed since your last review (claims to verify)

**All six Criticals â€” claimed closed**

1. **Reject route 500.** `POST /approvals/{id}/decide` omitted the required
   `reason`, so every analyst rejection raised TypeError â†’ 500. Now passed;
   `tests/test_approval_reject_route.py`.
2. **Stored XSS.** The dashboard rendered `raw_payload.content` â€” the attacker's
   own payload â€” via `innerHTML`. An `esc()` helper now escapes every
   server-supplied value, `marked.parse` no longer receives raw markdown, and a
   CSP was added. `tests/test_dashboard_xss.py` executes the real escaper in node
   against live payloads.
3. **DLQ bypass (relocation #5).** `pipeline.process()` caught every exception,
   called `repository.fail()` and returned normally, so the worker completed the
   queue item and the retry/DLQ path was unreachable. Now a typed taxonomy:
   `RetryablePipelineError` propagates infrastructure failures; only lifecycle /
   validation errors are terminal. Exhausted retries also terminalise the
   incident instead of stranding it mid-lifecycle.
4. **Unfenced side effects.** The fence protected only the queue row. Added an
   `execution_epoch` on `incident_state`, `repository.claim_execution()`, a fence
   check inside the same row-locked transaction as the state guard, and
   `assert_execution()` before each externally-visible write.
5. **Ledger fork race.** `record()` read the head on one connection and inserted
   on another. Now the head is read INSIDE the insert transaction via a callback,
   plus `prev_chain_hash` and `UNIQUE(tenant_id, prev_chain_hash)` making a fork
   unstorable. A backfill migration reconstructs predecessors for legacy ledgers.
   The pre-fix defect was demonstrated: 8 concurrent writers broke the chain.
6. **Forgeable evidence package.** `verify_package()` compared the replayed proof
   root against a root carried INSIDE the package â€” self-consistency, not
   provenance. Batch roots are now signed at seal time (secp256k1, reusing the
   agent-identity primitives); `verify_package(pkg, trusted_signer=...)` requires
   an out-of-band trust root and FAILS CLOSED without one; it never falls back to
   the package's own `signer_address`.
7. **GDPR / CSAM liability.** Immutable storage of unredacted attacker payloads.
   Resolved by separating commitment from body: the ledger holds only
   `entry_hash`; `evidence.content_json` is mutable and erasable.
   `db.redact_evidence()` destroys the body and leaves an auditable tombstone;
   the chain and inclusion proofs still verify; `verify_package` reports
   `REDACTED` distinctly from tampering.

**All four Highs â€” claimed closed**

8. **Supervisor injection guard.** The component that set priority and mitigation
   received fenced payload with no standing guard. The guard is now included and
   bound to the same nonce as the fence.
9. **Protect mode.** Returned only `allow`/`deny` and persisted nothing, while
   the README documented `allow`/`warn`/`require_approval`/`block`. The four
   states are now implemented from deterministic severity bands, every decision
   (including `allow`) is persisted to `protect_decisions`, and the response
   carries `enforced: false`.
10. **LLM removed from the control path.** Priority is now
    `rules.priority_for_severity(severity)` â€” a pure function. The model's
    opinion is recorded as `advisory_*` and cannot move priority in either
    direction. Its failure is non-fatal: the pipeline completes with
    `advisory_available: false`.
11. **Classifier demoted to shadow.** A classifier-only signal no longer raises
    an incident by itself (`SENTINEL_CLASSIFIER_GATES=1` restores gating). A
    bring-your-own-detector registry (`SENTINEL_DETECTOR=module:callable`)
    replaced the hard `from app.detection import classifier` import.
12. **OIDC wired.** Previously verified JWTs but was imported by no production
    module. `require_role` now accepts an API key OR a bearer JWT; a rejected JWT
    does NOT fall through to the API-key path.
13. **Structural tests.** The two load-bearing "structural" tests were substring
    checks on `inspect.getsource`. Replaced with a mutation harness
    (`tests/mutation_support.py`) that deletes a guard and requires a behavioural
    probe to go red. 8 invariants are now mutation-guarded, including a
    self-test that a surviving mutation is reported.

**Medium and Low â€” claimed closed:** shared DB-backed rate limiting (was
per-worker, so a configured 600/min was really 1800/min across three pods);
queue backoff (was a flat 50 ms transactional poll); metric-cardinality guard;
API keys now genuinely stored only as hashes (the config map was keyed by raw key
material despite the docstring's claim); testnet branding removed; benchmark
manifest now verified rather than merely written.

### Verifiable facts about the current tree

- **405 tests pass** (`pytest tests/ --ignore=tests/live`), up from 284. Your
  previous board could not run the suite at all.
- **CI lint passes.** It did not before: `ruff check app api agents evaluation
  sentinel_sdk tests` reported 44 errors, and because Lint runs BEFORE Tests in
  `.github/workflows/ci.yml`, the entire test suite had never executed in CI.
- **5 live PostgreSQL tests pass** proving row-level security: a query with no
  tenant predicate returns only the caller's rows.
- The **dependency audit is now blocking** (`pip-audit` no longer `|| true`).

### What was explicitly NOT done â€” do not credit these

- **Detection accuracy is UNCHANGED.** Cross-source AUC 0.763 over two folds,
  ECE 0.48. The model was demoted, not improved. No new training data exists.
- **RLS is implemented and proven but DEFAULTS OFF** (`SENTINEL_ENABLE_RLS=1`).
  The policy is `tenant_id = current_setting('sentinel.tenant_id', true)`; an
  unset context is NULL, so enabling it before a tenant contextvar is threaded
  through every transaction would make every query return zero rows.
- **No OTel / framework auto-instrumentation.** Manual per-call SDK
  instrumentation remains the adoption tax.
- **Still no customers, no production traffic, no paid pilot.** No Kubernetes
  cluster has run this code. The ECDSA recovery primitive remains unaudited.
- **No positioning change.** The strategic pivot the last board recommended was
  deliberately NOT made; this was engineering remediation only.

### The questions that matter this round

- **Did any of these fixes RELOCATE rather than close?** Look hardest at the
  newest code: the execution fence, the signed-root verification path, the
  redaction tombstone, the retry taxonomy, and the shared rate limiter.
- **Is the mutation harness real, or the next generation of theatre?** It is the
  central claim that the other fixes are trustworthy. Try to write a mutation it
  would not catch.
- **Does fail-closed provenance actually hold?** `verify_package` now requires a
  trusted signer. Can you still get a `True` out of it for evidence Sentinel
  never produced?
- **Does redaction really preserve the chain,** or does it create a new way to
  strand or forge?
- **Has the commercial picture moved AT ALL?** Engineering hygiene improved
  substantially; detection, customers and distribution did not. Your previous
  scores were Overall 36, Business 36, Investment 20. Say plainly what should
  move, what should not, and why â€” and if the answer is "nothing material
  changed commercially", say that.

---

## 8.1 Delta since the last board â€” passes v7 and v8 (claims to verify)

Two further remediation passes have landed since the 38/19 verdict. As above,
**read this as a claim list, not as fact** â€” the source documents are
`council/REMEDIATION_V7.md` and `council/REMEDIATION_V8.md`, and the most
valuable finding you can produce is still evidence that a fix RELOCATED a
failure one layer up rather than closing it.

### v7 â€” the ten findings in `COUNCIL_REPORT.md` Â§6, all claimed closed

| ID | Finding | Guard claimed |
|---|---|---|
| C-1 | Retry non-resumable | `tests/test_pipeline_retry_taxonomy.py` |
| C-2 | Execution fence dropped at `COMPLETED` | mid-flight lease-steal probe + AST call-site guard |
| C-3 | Authenticated relabelling of evidence | `tests/test_evidence_provenance.py` â€” v2 identity-bound manifests |
| C-4 | K8s egress policy denied Postgres (duplicate YAML key) | `tests/test_deployment_manifests.py` â€” strict parse |
| H-1 | Concurrent seal race | atomic claim + `BatchAlreadySealed`, mutation-locked |
| H-2 | OIDC tenant collapse to `"default"` | fail-closed `tenant_from_claims`, 401 path pinned |
| H-3 | Dashboard could not authenticate | `tests/test_browser_auth.py` â€” OIDC PKCE session, CSRF |
| H-4 | Side effects preceded the fenced transition | `tests/test_execution_fencing.py` â€” attestation outbox |
| M-1 | Protect mode `block` unreachable | thresholds named and compared |
| M-2 | Redaction tombstone overwritable | `EvidenceRedacted`, mutation-locked |

The report itself was deliberately left unedited as a point-in-time artifact.

### v8 â€” data-loss recovery plus real defects found on the way

This pass **began with the repository broken mid-edit.** `api/pipeline.py` and
`app/core/dlq.py` were both **0 bytes** â€” truncated, not refactored â€” the `.pyc`
files had been recompiled after truncation, and this tree is not under git, so
nothing was recoverable. The suite could not even collect. Both modules were
reconstructed from the contract the rest of the repo pins.

That fact is itself evidence about the operation, not just the code: a
load-bearing module can be destroyed here with no version control and no CI
signal until collection fails. Weigh it.

Claims to verify in the reconstruction:

1. **`api/pipeline.py` is now a resumable stage dispatcher over durable state**,
   not a top-to-bottom script. Each stage declares the state it produces; only
   stages whose output is not already durable run. A retry *resumes* rather than
   replaying into an illegal backward transition â€” claimed as the root cause of
   C-1.
2. **No unfenced transition helper exists.** `Context.advance()` is claimed to be
   the only way to change state and always threads `epoch`, so C-2 cannot recur
   at a new call site. Check whether that is structurally true or merely current.
3. **Every side effect goes through the repository outbox**, committing artifact
   and transition together; attestation is claim â†’ publish â†’ record with an
   idempotency key (H-4).
4. **One SELECT per incident, not per stage** â€” justified by the execution fence
   making the worker the single writer. Interrogate that reasoning: it trades a
   re-read for a fence guarantee.
5. **`app/core/dlq.py`** â€” `claim_due()` pushes `next_at` forward in the same
   transaction that reads the row; `fail()` decides terminality under one lock;
   `enqueue()` type-checks arguments. Owns no DDL.
6. **`remote_signer` rejected every valid signature.** `RemoteSigner.sign()`
   gated on `signature.startswith("0x")` while the repo's own `sign_digest`
   returns bare hex â€” so the KMS happy path could not accept a well-formed
   signature from its own primitive, and the untrusted-key-substitution test
   never reached its trust check. A **string-format proxy standing in for
   cryptographic validity**; removed.
7. **Three silent exception swallows** fixed at root (`app/core/config.py`,
   `api/browser_auth.py`, `api/pipeline.py::_terminalise`).
8. **Three structural tests had gone stale** because code moved (row lock into
   `_locked_incident`; RLS threading `tenant_id` into the retention WHERE clause;
   the dashboard dropping its markdown parser for `esc()`-escaped `<pre>`). The
   claim is that each invariant was verified still to hold before its test was
   adjusted. Verify that the adjusted tests are still tight enough to fail on
   regression, or whether this is a test loosened to match drifted code.

### Current verifiable state

- **459 passed, 7 skipped, 0 failed** (`pytest tests/ --ignore=tests/live`), up
  from 405 at the last board.
- Lint clean across `app api agents evaluation sentinel_sdk tests`.
- App boots; the detection gate exits 0.
- Live tests are memory-bound on this machine (each replica imports scipy) and
  were not run.

### Claimed already-done, no work needed (verify, do not assume)

KMS/HSM signing preferred over the in-process demo key; `/health` liveness vs
`/health/ready` readiness with structured 503 reasons; session HMAC over the full
payload with constant-time compare and a file-mounted secret that fails closed
under 32 bytes; structlog + OpenTelemetry + Prometheus wired in `api/main.py`;
outbox, fencing, RLS, leader election and durable queue present and covered.

### Explicitly NOT done in v7 or v8 â€” do not credit these

- **Detection accuracy is STILL unchanged.** Cross-source AUC 0.763, ECE 0.48.
  Three more passes, zero movement. No new training data exists.
- **Still no customers, no production traffic, no paid pilot, no Kubernetes
  cluster has ever run this code.** The ECDSA recovery primitive remains
  unaudited.
- **Still no positioning change.** The strategic pivot two boards have now
  recommended was again deliberately not made.
- Infrastructure explicitly out of scope for an in-repo change: Kafka/NATS
  brokers, multi-region topology, horizontal autoscaling under real load,
  Grafana dashboards, a running OTLP collector, DAST against a deployed
  instance, a physical HSM, real mTLS certificate rotation. The *seams* exist;
  the systems do not.

### The question this board must answer plainly

Six passes moved Overall +2 and Investment âˆ’1. Two more passes have now landed,
one of which was spent recovering from self-inflicted data loss. **Does
engineering remediation have any remaining marginal value here, or is the
constraint now entirely commercial?** Say which scores that should move, which
it should not, and whether the honest recommendation is more code or a different
company.


---
# ROUND 1 DOSSIERS FROM THE OTHER SEATS

## Claude Opus 4.8 â€” independent dossier

I have enough verified evidence to file. Two concrete relocations found in the newest (v8) code, both in the flagship "resumable dispatcher." Writing the dossier.

---

## One-paragraph investment thesis
**No** at any stage today, and the newest code makes me *more* cautious than the prior 38/19 board, not less. The engineering hygiene is real and above hackathon grade â€” a durable outbox, execution fencing, an identity-bound hash chain, fail-closed provenance, 459 passing tests, clean lint. But diligence rewards the thing being sold, and the thing being sold is *trustworthy incident attestation*. I found that v8's marquee fix â€” the "resumable stage dispatcher" â€” **relocated the five-times-repeated failure a sixth time, straight into the core value path**: on the exact retry it was built to survive, the pipeline silently produces an *unanchored, evidence-less* attestation (`api/pipeline.py:569-587` never rehydrates `ctx.evidence`; `agents/attestation_agent.py:137-144` then returns `"Skipped"`). Combined with an unchanged detection model (AUC 0.763, ECE 0.48 â€” the AI is deliberately *out* of the decision path), zero customers, zero production runtime, and a category that consolidated ~$29B of M&A around it, this is strong systems-engineering practice in search of a business. I would fund the *engineer*, not this company. If forced to deploy capital in this space I'd back Zenity/Noma/WitnessAI tier, or acquihire this team.

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
| Business | 18 | No customers, no distribution, no pricing validation, in a consolidated market. Lower than the prior board's 36 â€” I think 36 was unearned. |
| Investment-readiness | 14 | Down from 19: a fix relocating failure into the core value path is diligence-negative, not neutral. |

## Strengths
- **Fail-closed provenance is genuinely correct.** `verify_package` refuses to verify without an out-of-band `trusted_signer` and never falls back to the package's own `signer_address` (`app/attestation/ledger.py:358-364, 234, 390-394`). This closes the forgeable-evidence Critical properly â€” I could not construct a `True` for evidence Sentinel never signed.
- **Merkle/chain crypto is textbook.** Second-preimage prefixes (`0x00`/`0x01`), promote-don't-duplicate for odd nodes (avoids CVE-2012-2459), geometry checks before hashing (`app/attestation/merkle.py:26-28, 168-169, 214-234`). An auditor really can verify offline.
- **Identity-bound leaf** commits to `tenant_id + incident_id + body hash`, so relabelling a genuine proof onto another incident breaks the signature (`merkle.py:67-82`). This is the right fix for v7's C-3.
- **DLQ is a real state machine, not a log line** (`app/core/dlq.py:150-196`): claim marks `next_at` inside the same transaction that reads it (exclusive claim), backoff has jitter (anti-thundering-herd), `fail()` decides terminality under one lock.
- **RLS now defaults ON** with tenant context threaded through `_connect(tenant_id=...)` (`app/storage/db.py:352-364`) â€” a real correction of the prior "proven but defaults-off" trap.

## Weaknesses & architectural issues
1. **Resume produces unanchored, evidence-less attestation (RELOCATION #6, Critical).**
   - *Evidence:* `process()` rebuilds `Context` with `detection=None, evidence=None, investigation=None` (`api/pipeline.py:569-580`) and skips durable stages purely by rank (`:586-587`) â€” it never rehydrates the in-memory artifacts from the DB. A `RetryablePipelineError` raised *inside* `_stage_attest` (network blip in `publish_attestation`) leaves state at `REPORTED`; the queue retries; on re-entry the evidence stage is skipped, so `ctx.evidence is None`; `publish_attestation(detection, evidence=None)` hits `if not evidence: return ...status="Skipped"` (`agents/attestation_agent.py:137-144`); `complete_attestation` records `is_anchored=False` â†’ `COMPLETED`.
   - *Risk:* The one transient RPC outage the resumable dispatcher exists to survive now silently no-ops the product's core promise. This is *exactly* the failure `AttestationUnavailable`'s own docstring warns against ("turn a transient RPC outage into permanent evidence loss", `attestation_agent.py:62-66`) â€” reintroduced one layer up. `_stage_report` on resume from `EVIDENCE_STORED` similarly renders "Not available" everywhere (report built from `None`).
   - *Fix:* On resume, rehydrate `ctx.evidence/detection/investigation` from durable rows before dispatching, OR make skipped stages a hydration step, not a no-op. Add a test that fails an incident *at the attest stage* and asserts the resumed run still anchors.
   - *Effort:* 1-2 days. *Priority:* **Critical.** This is the single most important finding of the review.

2. **Over-broad terminal taxonomy mis-classifies transient failures as permanent (High).**
   - *Evidence:* `TERMINAL_ERRORS = (â€¦, ValueError, TypeError, KeyError)` (`api/pipeline.py:91-98`). Infrastructure failures routinely surface as these: `json.loads()` on a truncated HTTP body raises `ValueError`; a missing field in a degraded provider response raises `KeyError`.
   - *Risk:* A transient outage that happens to raise `ValueError/KeyError` is recorded `FAILED` with no retry â€” the very collapse the retry taxonomy claims to prevent (`:601-606`). The taxonomy is type-based, but the type does not reliably indicate determinism.
   - *Fix:* Classify by *origin* (raise typed `RetryablePipelineError` at I/O boundaries) rather than by broad built-in exception types; reserve `ValueError/KeyError` as terminal only when raised by lifecycle/validation code.
   - *Effort:* 1 day. *Priority:* High.

3. **`claim_due()` iterates tenants serially with a transaction each (Mediumâ†’High at scale).**
   - *Evidence:* `for tenant_id in db._tenant_ids(): with db._connect(tenant_id) â€¦` (`app/core/dlq.py:165-196`), justified as unavoidable under FORCE RLS.
   - *Risk:* DLQ drain latency grows linearly with tenant count; at 10k tenants this is 10k transactions per poll. The RLS "no wildcard bypass" design is correct for isolation but makes fleet-wide sweeps O(tenants).
   - *Fix:* A privileged maintenance role with a scoped bypass for queue draining, or partition workers by tenant shard. *Effort:* 3-5 days. *Priority:* Medium now, High at scale.

4. **Single-writer-by-fence assumption trades correctness for a re-read (Medium).**
   - *Evidence:* `Context.state` is authoritative and "NOT re-read between stages" because the fence makes this worker the single writer (`api/pipeline.py:142-153`). That reasoning is sound *only* if every side-effecting stage actually asserts the fence on every write â€” which is true today but is a standing invariant one new call site can break, precisely the C-2 pattern.
   - *Fix:* Keep the AST call-site guard the brief mentions; add a runtime assertion in `repository` that every mutating call carries a non-`None` epoch when one is expected. *Effort:* 1 day. *Priority:* Medium.

## Market intelligence
This category exists and has *already consolidated*. Direct comparables: **Lakera** (â†’Check Point) runtime guardrails, **Protect AI** (â†’Palo Alto), **Prompt Security** (â†’SentinelOne), **Astrix** (â†’Cisco, non-human identity â€” Sentinel's exact identity-attestation wedge). Independents better-funded than this team could ever bootstrap: **Zenity, Noma ($100M B), WitnessAI, HiddenLayer**. Sentinel is *worse* on detection (competitors ship tuned injection classifiers; Sentinel's is demoted shadow at AUC 0.763), *worse* on distribution (they have design partners and platform reach; Sentinel has none), and *better* on exactly one axis: **offline-verifiable, identity-bound cryptographic evidence** (`merkle.py` + fail-closed `verify_package`). No incumbent leads with tamper-evident attestation an auditor can verify years later with a single file. That is the only defensible wedge here. What never to copy: per-event on-chain writes.

## Gap analysis
The real unsolved pains: (1) **agent identity/non-repudiation** â€” 53% of MCP servers use static keys; PKI-agent-identity is the most-cited ASI03 mitigation, and Sentinel's signature-recovered address model (`publish_attestation` refuses to invent identities, `attestation_agent.py:146-158`) is directly on-target. (2) **audit evidence that survives log destruction** â€” Sentinel's hash-chain + optional anchor genuinely addresses this. (3) **acquisition-orphaned buyers** (Â§5 of the brief) â€” the clearest opening. Sentinel *can credibly close #1 and #2 at the primitive level* but cannot close them as a product without detection accuracy, framework auto-instrumentation, and a distribution motion â€” none of which exist.

## Missing / critical features
- **OTel/framework auto-instrumentation.** Manual per-call SDK wiring is the adoption tax; no enterprise will hand-instrument every agent call. This alone blocks pilots.
- **A detection story that isn't 0.763 AUC.** A security buyer's first question is detection efficacy; the honest answer today loses the meeting.
- **Multi-region / broker-backed queue.** Seams exist, systems do not; the durable queue is single-DB.
- **SOC2 Type II / ISO 27001 posture, DPA, sub-processor list.** Table stakes for the enterprise buyer this is pitched at.
- **SIEM/SOAR connectors** (Splunk, Sentinel-MS, Chronicle) â€” a SOC tool that doesn't feed the SOC's existing pane is shelfware.

## Feature discovery â€” 3-5 non-obvious features
1. **Portable "evidence passport."** *Problem:* acquisition-orphaned buyers distrust vendor-locked audit logs. *Impact:* turns the wedge into a moat. *Complexity:* Low â€” the crypto already produces offline-verifiable packages (`verify_package.py`). *Design:* signed, self-describing export + a 200-line standalone verifier. *AI need:* none. *Defensibility:* becomes a de-facto interchange format; network effect if auditors adopt the verifier.
2. **Cross-vendor attestation notarization.** *Problem:* nobody trusts a single vendor's "we saw nothing bad." *Design:* periodic Merkle-root anchoring to a *neutral* transparency log (Sigstore/Rekor-style), not a testnet. *AI need:* none. *Defensibility:* transparency-log network effects; patent-adjacent around identity-bound leaves.
3. **Deterministic policy-diff replay.** *Problem:* "would this new policy have caught last month's incidents?" *Design:* replay durable incident facts through a candidate `active_policy()` â€” the resumable state model already stores everything needed. *AI need:* none. *Defensibility:* stickiness via accumulated incident corpus.
4. **Agent kill-switch attestation.** *Problem:* 55-63% of orgs have no kill switch (brief Â§1). *Design:* signed revocation events on the same chain; an agent can *prove* it was told to stop. *Defensibility:* ties into ASI03/ASI10.

## Security concerns
- **ASI03 (identity/privilege):** genuinely strong â€” signature-recovered addresses, no fabricated identities.
- **ASI06 (memory/context poisoning) & ASI01 (goal hijack):** weak â€” detection is the demoted 0.763 classifier; this is where competitors win.
- **Prompt injection:** the product *records* but does not reliably *detect*; ECE 0.48 means confidence scores are meaningless.
- **Supply chain (ASI04):** `pip-audit` now blocking is good; the **unaudited ECDSA recovery primitive** is a live risk in a product whose entire trust rests on signature recovery â€” get it audited before any pilot.
- **Privacy/GDPR:** the redaction tombstone (`db.redact_evidence`) separating commitment from body is the right design and preserves chain verification â€” a real strength.
- **No DAST against a deployed instance**; the app has never run in a cluster.

## Scalability & performance concerns
Single-writer-per-incident by fence is fine for correctness, poor for throughput. `claim_due()` is O(tenants) per poll (`dlq.py:165`). No Kafka/NATS; the "durable queue" is a DB table. On-chain anchoring, even batched, adds block-finality latency to any synchronous path. From single-node to millions of users this needs: a real broker, tenant sharding, read replicas, and the anchoring moved fully async (it partly is via the outbox). None of it has been load-tested; **no Kubernetes cluster has ever run this code** (brief Â§8, verified as unrunnable here â€” live tests are memory-bound).

## AI quality limitations
The defining fact: **the AI has been deliberately removed from the decision path.** Priority is `priority_for_severity()`, a pure function (`pipeline.py:229`); the model is `advisory_*` and its failure is non-fatal (`:255-259`). That is *good engineering* (attacker-influenced text can't move priority) but means the "AI agent observability" product has almost no AI in its own decisions. Detection AUC 0.763 cross-source and ECE 0.48 (essentially uncalibrated) are unchanged across six passes. Failure recovery for the model is handled gracefully; accuracy is not handled at all because no new training data exists.

## Customer experience / UX friction
Journey: landing â†’ the pitch is honest ("pre-production"). Onboarding â†’ **hard stop: manual per-call instrumentation**; there is no drop-in agent/proxy. Auth â†’ OI

...[truncated for prompt budget]...
## Codex GPT-5.6-terra â€” independent dossier

## One-paragraph investment thesis

Do not fund this as a $100M-scale company today. I would consider a tightly scoped pre-seed/customer-discovery investment only if the team stops polishing the generic â€œAI SOCâ€? and earns a wedge with 3â€“5 design partners needing independently verifiable incident evidence for regulated agent workflows. Engineering has improved meaningfully: durable state, RLS seams, signed evidence roots, and honest pre-production language are real. But Sentinel still has no proven detection, enforced runtime control, telemetry-native adoption path, customers, or distribution; it competes in a rapidly consolidated category against better-capitalized platforms. Worse, v8 still relocates fencing failure into terminalisation and external attestation. This is a promising security-engineering project, not yet an investable security business.

## Scores (0-100, one number each, with a half-line justification)

Engineering **55** â€” substantial integrity/retry/auth work, but new race escapes and no runnable validation here.  
AI/ML **17** â€” explicitly uncalibrated two-fold AUC 0.763/ECE 0.484; model is rightly non-authoritative.  
UX **40** â€” coherent analyst console, but polling, misleading attestation language, and unsafe render paths remain.  
Architecture **50** â€” good transactional boundaries and RLS design; SQLite-shaped queues and direct worker threads cap it.  
Innovation **35** â€” evidence provenance is potentially distinctive; generic agent-security detection is not.  
Security **44** â€” several strong controls, but stored-XSS gaps, unenforced protection, and fence/outbox races are unacceptable.  
Scalability **20** â€” no production deployment, benchmarks, broker, autoscaling evidence, or global topology.  
Business **20** â€” no customers, paid pilot, ICP proof, pricing, or distribution wedge.  
Investment-readiness **13** â€” materially below seed threshold; commercial and detection constraints dominate.

## Strengths

- The README is unusually candid: pre-production status, advisory-only protect mode, and the detectorâ€™s calibration failure are explicitly stated rather than marketed away (`README.md:3-10`, `README.md:111-141`, `README.md:174-185`).
- The repository has a credible durable lifecycle authority: state transition, facts, and audit-trail append are committed together (`app/core/repository.py:298-344`); evidence, ledger entry, and transition share one transaction (`app/core/repository.py:396-437`).
- Evidence-package provenance genuinely fails closed when no independent signer is supplied, and v2 binds tenant and incident to the evidence manifest (`app/attestation/ledger.py:223-236`, `app/attestation/ledger.py:252-273`, `app/attestation/ledger.py:358-398`).
- RLS is thoughtfully designed: protected tables, `FORCE ROW LEVEL SECURITY`, and transaction-local tenant context are explicit (`app/storage/rls.py:40-76`, `app/storage/rls.py:91-102`).
- OIDC rejects non-asymmetric algorithms and validates issuer/audience; tenant claim extraction now fails closed (`api/oidc.py:39-42`, `api/oidc.py:137-155`, `api/oidc.py:173-196`).
- The mutation harness is real, not merely a source-substring assertion: it loads a modified module and requires a behavioral probe to fail (`tests/mutation_support.py:50-99`). It is useful, but narrow.
- The shared database rate limiter fixes the former per-pod multiplication problem (`app/core/ratelimit.py:45-91`), and CI now includes lint, dependency audit, image scanning, live PostgreSQL tests, and limited schema fuzzing (`.github/workflows/ci.yml:25-34`, `.github/workflows/ci.yml:49-61`, `.github/workflows/ci.yml:109-155`).

I could not independently run the claimed 459-test suite: this environment has neither Python nor pytest available.

## Weaknesses & architectural issues

- **Problem:** Execution fencing is still bypassable during terminal failure. **Evidence:** `process()` catches terminal errors then calls `_terminalise()` (`api/pipeline.py:601-606`), but `_terminalise()` calls `repository.fail()` without `epoch` (`api/pipeline.py:614-617`), while `fail()` accepts fencing but defaults it to `None` (`app/core/repository.py:646-662`). **Risk:** a stale worker can mark a newer ownerâ€™s live incident `FAILED`. This is relocation, not closure, of C-2. **Fix:** thread epoch into terminalisation; make worker-path failure APIs require it structurally. **Effort:** 1â€“2 days plus concurrent fault-injection test. **Priority:** Critical.

- **Problem:** External attestation is not fenced immediately before the irreversible side effect. **Evidence:** the outbox claim is fenced (`api/pipeline.py:391-400`), but `publish_attestation()` occurs afterward with no `assert_execution()` or epoch/idempotency key (`api/pipeline.py:404-417`); `claim_attestation()` can overwrite a `delivering` claim rather than reject a different epoch (`app/core/repository.py:550-572`). **Risk:** lease steal plus network delay can create duplicate or wrongly attributed on-chain writes. H-4 is not closed. **Fix:** outbox state CAS on claim epoch; pass its idempotency key to the gateway; fence immediately before call; reconcile gateway receipt before retry. **Effort:** 1â€“2 weeks. **Priority:** Critical.

- **Problem:** The â€œall server content escapedâ€? XSS claim is false. **Evidence:** `JSON.stringify(inc.intel.external_data)` is inserted directly into `innerHTML` (`dashboard/index.html:1344-1352`), and transaction hash is injected into an href/title without escaping or URL validation (`dashboard/index.html:1270-1274`). CSP permits inline script (`dashboard/index.html:7-24`). **Risk:** stored XSS in an analyst console handling attacker-controlled intelligence, leading to session/CSRF-token theft and privileged action. **Fix:** render with `textContent`, construct links via validated DOM URLs, eliminate inline scripts with nonce/hash CSP. **Effort:** 2â€“4 days. **Priority:** Critical.

- **Problem:** â€œProtect modeâ€? is advisory, not protection. **Evidence:** it returns `enforced: false` (`api/main.py:862-873`), and README confirms no inline interception or kill switch (`README.md:174-182`). **Risk:** an enterprise buyer cannot treat it as a runtime security control. **Fix:** ship an SDK/proxy/MCP gateway that can synchronously deny, require approval, revoke credentials, and emit a receipt. **Effort:** 2â€“4 months. **Priority:** High.

- **Problem:** Detection coverage is shallow and brittle. **Evidence:** classifier gating is disabled by default because of calibration limits (`app/monitoring/rules.py:46-53`); default policy is a small set of static rules, mapping principally to ASI01, ASI02, ASI03, and ASI09 (`config/default_policy.json:20-176`). **Risk:** Sentinel does not genuinely cover ASI04 supply chain, ASI05 code execution sandboxing, ASI06 memory poisoning, ASI07 inter-agent communications, ASI08 cascades, or ASI10 rogue autonomy. **Fix:** collect partner telemetry, build scenario-based evaluation suites, and add controls/detection for each threatâ€”not labels. **Effort:** 6â€“12 months. **Priority:** High.

- **Problem:** Sensitive-content privacy is improved but correlation hashes leak low-entropy content. **Evidence:** redaction deliberately retains unsalted SHA-256 and acknowledges dictionary attack exposure (`app/attestation/redaction.py:53-69`). **Risk:** prompt fragments, identifiers, and known abusive material can be reidentified; cross-customer correlation creates purpose-limitation risk. **Fix:** tenant-keyed HMAC by default; explicit opt-in privacy-preserving threat exchange with legal controls. **Effort:** 2â€“3 weeks. **Priority:** High.

## Market intelligence

This market exists and has consolidated: Check Point/Lakera, Palo Alto/Protect AI, SentinelOne/Prompt Security, Cisco/Astrix, Microsoft, Palo Alto, Cato/Aim, Zenity, Noma, WitnessAI, HiddenLayer, Straiker, Pillar, and Lasso already sell adjacent discovery, posture, identity, runtime guardrails, and evaluation. They are better at enterprise procurement, integrations, telemetry collection, SOC workflows, threat research, and global support. Sentinel is better only in its unusually transparent prototype posture and its potentially portable evidence-verification concept.

The plausible wedge is not â€œanother AI SOCâ€? or â€œprompt injection detector.â€? It is â€œindependent, privacy-respecting incident evidence and policy receipts for high-consequence agent actionsâ€?â€”particularly for buyers stranded by consolidation who want vendor-neutral evidence. Do not copy incumbent platform bundling, black-box detection claims, or per-event blockchain logging. Borrow OTel-native instrumentation, policy-as-code, deployment templates, identity federation, and evaluation/red-team workflows.

## Gap analysis

Real unsolved pains are: proving what an autonomous agent did after evidence is redacted; mapping a decision to identity, delegated authority, policy version, tool call, approval, and outcome; preventing unsafe actions without blocking operations; and demonstrating controls to an auditor without exporting sensitive prompts.

Sentinel can credibly address evidence receipts if it completes a hybrid, signed, customer-controlled ledger. It cannot credibly claim detection or enforcement yet. The docs correctly describe Base Sepolia as demo-oriented in practice: the code still submits a per-incident `recordIncident` transaction (`agents/attestation_agent.py:247-269`), whereas the ledgerâ€™s batch design is the better hybrid architecture (`app/attestation/ledger.py:75-128`). Testnet anchoring is a hackathon artifact, not enterprise differentiation.

## Missing / critical features

Serious buyers expect OTel/OpenInference auto-instrumentation; SDKs for LangChain, OpenAI Agents SDK, MCP, Bedrock, Vertex, and agent frameworks; policy simulation and change approvals; tenant-owned keys; SIEM/SOAR integrations; streaming/event ingestion; immutable retention holds; case management; SLOs; audit exports; DLP/classification; sandboxed tool execution; jurisdictional data routing; and a real control-plane/data-plane separation. None is proven here.

## Feature discovery â€” 3-5 non-obvious features

- **Delegation passport:** bind user purpose, agent identity, delegated scopes, tool budget, expiry, and approval chain into a signed capability carried across agent-to-agent hops. Impact: solves ASI03/ASI07 accountability. Complexity: high. AI need: none. Defensibility: a cross-vendor receipt graph becomes a data moat.
- **Counterfactual control replay:** replay a historical agent trace against a proposed policy/model/tool configuration and quantify blocked actions, false blocks, latency, and approval burden. Impact: makes security adoption measurable. Complexity: high. AI need: simulation/trace normalization, not generative judgment. Defensibility: proprietary trace corpus.
- **Evidence minimization compiler:** convert raw tool calls into a cryptographic receipt containing only fields necessary for a particular audit claim, with selective disclosure. Impact: privacy plus compliance. Complexity: high. AI need: policy-guided schema extraction. Defensibility: patentable receipt/proof composition.
- **Autonomy circuit breaker:** detect rapidly expanding tool scope, privilege, spend, or agent fan-out; enforce progressive budgets before a cascade. Impact: addresses ASI08/ASI10. Complexity: medium-high. AI need: anomaly models calibrated per tenant. Defensibility: longitudinal behavioral baselines.
- **Prompt provenance quarantine:** label and track untrusted context through retrieval, memory, and inter-agent messages; prohibit it from influencing authority-bearing fields without corroboration. Impact: addresses ASI01/ASI06. Complexity: high. AI need: taint propagation plus classifier assistance. Defensibility: framework-level provenance graph.

## Security concerns

OWASP ASI mapping is presently partial, not ten-of-ten coverage. Prompt fencing is a defense-in-depth measure, not a proof against indirect injection; the supervisor still sends attacker-influenced metadata to an external model (`agents/supervisor_agent.py:82-116`). The LLM cannot move priority, which is good (`api/pipeline.py:219-272`), but it can produce recommendations that become approval proposals. Treat all model outputs as untrusted and validate against an allowlisted action schema and target authorization.

RLS is strong only on PostgreSQL; SQLite remains application-predicate isolation (`app/storage/rls.py:25-32`). Supply-chain posture is improved by CI but lacks signed releases, provenance attestations, dependency pin/update policy, runtime image admission, and independent cryptographic audit. GDPR needs data inventory, DPA/subprocessors, retention enforcement evidence, DSAR workflows, lawful-basis controls, and key destructionâ€”not merely tombstones.

## Scalability & performance concerns

The durable queue, rate limiter, lifecycle, and sealing are database-transaction-heavy. At high ingest rates, one shared Postgres becomes the queue, rate-limit coordinator, event store, evidence store, and ledger sequencer. Per-tenant hash-chain ordering is intrinsically serial. Worker threads inside API pods (`api/main.py:184-240`) are not a scalable worker plane. The supervisor makes synchronous external LLM calls with a 20-second timeout (`agents/supervisor_agent.py:25-31`).

For millions of events: ingest through Kafka/NATS, partition by tenant/agent, use an append-only object store plus compacted stream, batch Merkle commitments, separate workers, Redis/local rate-limit tiers, regional data planes, and a global control plane. Measure p95/p99 ingestion, policy decision, queue lag, evidence sealing, and cost per million events before asserting scale.

## AI quality limitations

There is no trustworthy production ML gate. The bundled model deserializes a pickle artifact (`app/detection/classifier.py:89-99`), has weak calibration, no multilingual validation, no real customer distribution, no adversarial robustness evaluation, and no false-negative economic

...[truncated for prompt budget]...
---
ROUND 2 â€” CROSS-EXAMINATION & COMPONENT DEBATE. You have now read the other seats'
Round-1 dossiers (quoted below). Debate them component by component. Be constructive,
not repetitive: only raise a point if it changes the decision.

OUTPUT FORMAT â€” plain markdown:

## Where a peer is right and I was wrong   (name the seat and the point)
## Where a peer is wrong   (quote the claim, then refute with file:line or external evidence)
## Component-by-component contest   (pick the 5-8 components that matter most â€” e.g. lifecycle/state,
   auth & RBAC, attestation/ledger, detection/eval, agent orchestration, storage/scale, SDK/API,
   dashboard/UX. For EACH: the strongest claim made, my challenge, and the resolved position, with
   Problem | Evidence | Risk | Solution | Tradeoffs | effort | Priority)
## What ALL of us missed entirely
## The single disagreement that most changes the investment decision
## My revised scores   (only the numbers that moved from Round 1, and why)

Attack the reasoning, not the model. If a peer made a claim about a file, open that file
and check before agreeing or disagreeing. Target 1200-1800 words.