# AI Strategy Council — THIRD REVIEW, Round 1 of 3
# Your seat: Antigravity (Gemini, pro) (Google)

You are one seat on an AI Strategy Council performing a THIRD review.
The other seats are independent models from rival vendors. Your job is NOT to be
agreeable, and it is NOT to confirm a fix list.

THE SITUATION
Two remediation passes have happened. Your v2 review voted 7/7 unanimously NO and
found that the v1 remediation had REPRODUCED the original sin one abstraction
layer up (split-brain state). V3 now claims to have eliminated the underlying
CLASSES architecturally.

Your task: FALSIFY that. Specifically, determine whether V3 has done the same
thing a third time -- solved the named instances while moving the failure one
layer up again. That is the single most valuable finding available this round.

CONFLICT OF INTEREST -- READ THIS
Claude Opus 4.8 implemented BOTH remediations and holds a seat here. If you are
the Claude seat you are auditing your own work for the second time: be harder on
it than on anyone else's and state plainly where you cannot be objective. If you
are not the Claude seat, treat every claim as a vendor assertion from an
interested party. The Antigravity seat authored the ORIGINAL code.

YOU MUST READ THE CODE. At minimum:
  app/core/lifecycle.py  app/core/repository.py  app/core/config.py  app/core/dlq.py
  api/main.py  api/pipeline.py  api/auth.py  api/rbac.py  api/oidc.py
  app/integrations/base.py  app/integrations/registry.py  app/integrations/webhook.py
  app/storage/db.py  app/storage/engine.py
  app/attestation/merkle.py  app/attestation/ledger.py
  app/identity/verifier.py  app/identity/replay.py
  app/monitoring/policy.py  app/monitoring/rules.py
  app/observability/telemetry.py  app/tools/providers.py
  app/response/mitigation.py  evaluation/corpus.py  evaluation/metrics.py
  deploy/k8s/sentinel.yaml  docker-compose.yml  tests/
Cite file:line. Uncited claims are discounted.

THE QUESTIONS

1. CLASS ELIMINATION OR RELOCATION? For each V3 claim in the brief, state
   ELIMINATED / RELOCATED / PARTIAL / FALSE with file:line. "Relocated" means the
   named bug is gone but the same class is now possible somewhere else.

2. ATTACK THE LIFECYCLE. Can you construct ANY path to COMPLETED without a
   durable report? Any read that can disagree with a write? Any way to bypass
   `repository.transition` and mutate state directly? Look for direct db writes,
   routes that skip the repository, and the background worker.

3. CONCURRENCY. The repository claims row-version CAS plus BEGIN IMMEDIATE makes
   multi-worker safe. Is that argument correct on SQLite? On Postgres, where
   `translate()` rewrites the SQL and lock semantics differ? Is there a TOCTOU
   between the guard check and the UPDATE?

4. COMPLEXITY DEBT. V3 added ~1400 lines and several new modules. Name anything
   that is now more complex WITHOUT being more correct, and anything a competent
   engineer would find harder to reason about than before.

5. RESIDUAL DISHONESTY. Is there ANY remaining place where a component reports
   something it has not earned, or conflates "did not run" with "found nothing"?
   Include metrics, logs, health endpoints and API responses.

6. COMMERCIAL VERDICT. Recall is unchanged at 0.643; Redis, Kafka, SAML, SCIM,
   mTLS and leader election are absent; nothing has run against a live Postgres
   or a live threat-intel API. Has your vote changed, and if not, what exactly
   would have had to be different?

RULES OF ENGAGEMENT
- Cite files and line numbers. Quantify where you can.
- Say "I could not verify X" rather than guessing.
- Never reproduce a secret found in the repository.
- Do not recommend disabling safety gates, auth, or human-approval steps.
- Distinguish what the code DOES from what the docs and the claim list SAY.
- Being wrong is recoverable. Being vague is not.


---
# EXTERNAL RESEARCH BRIEF

# External Research Brief — AI Agent Security Market, July 2026

Compiled 2026-07-21 from live web research. Every seat receives this brief verbatim.
Figures are as reported by the cited sources; vendor-published numbers are marked.
Treat this as evidence to argue with, not as settled fact.

---

## 1. The threat landscape is real and it is the exact one Sentinel targets

- Prompt injection is the **#1 AI security threat of 2026** and the fastest-growing
  attack category globally, reported at **+340% year over year**.
- Prompt injection appears in **over 73% of production AI deployments** and is
  credited with roughly **$2.3B in global losses in 2025**.
- **EchoLeak (CVE-2025-32711, CVSS 9.3)**, June 2025 — the first documented
  *zero-click* prompt-injection exploit against a production system (Microsoft 365
  Copilot). A single crafted email caused Copilot to read internal files and
  exfiltrate them to an attacker-controlled server. No user interaction.
- **GTG-1002**, a state-sponsored campaign, hijacked coding agents to execute an
  estimated **80–90% of an espionage operation** against ~30 targets. The agents
  did the work.
- Malicious prompts were injected into legitimate GenAI tools at **90+ organizations**
  during 2025.
- The governance gap is the buying trigger: **41–44%** of organizations have no
  human-in-the-loop control, and **55–63%** have no purpose binding, kill switch, or
  network isolation for their agents.

**Implication for the council:** demand for this category is not speculative. The
open question is not "is there a problem" but "does *this* codebase solve any part
of it better than a funded incumbent already does".

---

## 2. The standards layer has consolidated around a specific threat model

**OWASP Top 10 for Agentic Applications (ASI), 2026 edition** — now the reference
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
| ASI09 | Human–Agent Trust Exploitation |
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

## 3. Competitive landscape — the category has already consolidated

Enterprise spend on agentic AI is projected at **$201.9B in 2026**. Around RSAC 2026,
**$392M** in agentic-AI-security funding was announced in a two-week window.
Acquisitions hit **18 deals in 2026** (vs 12 in 2025, 4 in 2024), and roughly
**$29B of M&A** has been assembled into stacks purpose-built to discover, govern and
secure AI agents.

Who owns what now:

- **Lakera** → acquired by **Check Point** (2025, ~$300M). Runtime guardrails for
  prompt injection and policy violation. Free developer tier; enterprise by quote.
- **Protect AI** → acquired by **Palo Alto Networks**. Roadmap now answers to
  Palo Alto's platform strategy.
- **Prompt Security** → acquired by **SentinelOne**.
- **Aim Security** → acquired by **Cato Networks**.
- **Astrix Security** → acquired by **Cisco** (~$400M, May 2026) — non-human identity.
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

- **Production-risk adjacency is the strongest buying signal** — companies tied to
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
for Lakera→Check Point and Prompt Security→SentinelOne customers. Every acquisition
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
- Penalties reach **7% of global annual turnover / €35M** — above GDPR's 4%.
- As of April 2026, **78% of organizations** had taken no meaningful compliance steps.

**Question for the seats:** does the delay of high-risk obligations to 2027–28 remove
Sentinel's compliance-driven urgency, or does it just move the deadline out far
enough that a small team can actually build for it? Disagree productively.

---

## 7. The blockchain-attestation question (Sentinel writes to Base Sepolia)

Evidence cuts both ways and the council should treat this as a live dispute:

**For.** Enterprises are adopting tamper-proof platforms binding identity events to
immutable logs to reduce disputes and strengthen compliance. Audit logs serve five
functions — forensic reconstruction, regulatory evidence, unauthorised-access
detection, insider-misuse deterrence, accountability enforcement — and cryptographic
non-repudiation strengthens all five, remaining verifiable even if a local log is
destroyed.

**Against.** Even *private* blockchains run orders of magnitude slower than ordinary
databases. High-volume logging (millions of events/sec) cannot go on-chain without
severe degradation. Consensus needs multi-node participation and adds latency
proportional to block finality. The literature positions blockchain as
**complementary to existing audit-log standards, not a replacement**.

**The mainstream pattern** is hybrid: hash-chained or Merkle-tree logs held locally
with **periodic hash commitments** anchored to a public chain — not per-event writes.

**Question for the seats:** Sentinel anchors incident attestations to **Base Sepolia,
a testnet**. Is on-chain attestation a genuine differentiator, a hackathon artifact
that will read as unserious to an enterprise buyer, or a real feature deployed on the
wrong chain? Take a position.

---

## 8. FOURTH REVIEW. Three remediation passes have now happened.

You have reviewed this repository three times. Every time, you voted unanimously
NO on all counts, and every time you found that the remediation had introduced
NEW defects of the same class it claimed to have eliminated.

- **v1** — 21 findings.
- **v2** — 7/7 unanimous NO. The v1 remediation had introduced split-brain state,
  phantom mitigation execution, cross-tenant event suppression, auth/RBAC parser
  divergence, and a fail-open evidence verifier.
- **v3** — 8/8 unanimous NO, `FAILURE_RELOCATED_AGAIN: YES`. The v2 remediation
  had transposed the queue's identifiers so **100% of queued incidents were
  silently dropped** while the API answered `"processing": true`; metrics counted
  a table with no writer; `/ingest-event` raised NameError; PostgreSQL was a
  startup banner over `sqlite3.connect()`; and V3's headline claim that a bug was
  "structurally unrepresentable" was **false** — the check was a non-empty-string
  test.

A **fourth pass (V4)** has since been implemented. Your task is NOT to confirm
the fix list. It is to find where the same pattern has happened a fourth time.

**Conflict of interest, unchanged and important.** Claude Opus 4.8 implemented
all three remediations and holds a seat. Antigravity authored the original code.
Two of three seats are interested parties. If you are the Claude seat, you are
reviewing your own work three times over — be harder on it, and say plainly where
you cannot be objective. If you are not, treat every claim below as a vendor
assertion and verify it against running code.

### What V4 claims, and how to check each claim

Every claim below is checkable. Do not take any of them on trust.

1. **PostgreSQL is real and verified against a live server.** `pgserver` (a pip
   wheel shipping real PostgreSQL binaries) lets `tests/live/` start an actual
   PostgreSQL 16.2 — no Docker needed. Run `PYTHONPATH=. pytest tests/live -q`
   yourself. Claim: 23 tests pass against a live server.
2. **The in-memory queue is GONE.** `app/queue/priority_queue.py` is deleted.
   `app/queue/durable_queue.py` is database-backed using
   `SELECT … FOR UPDATE SKIP LOCKED`. Claim: work survives restart, crashed
   workers, and three replicas with no double-processing.
3. **Leader election** via `pg_try_advisory_lock` (`app/core/leader.py`), which
   exists because `apply_retention` and `purge_expired_nonces` had **zero
   callers** — retention's own docstring claimed it was scheduled when it was not.
4. **Redis DELETED**, not wired. It was provisioned in docker-compose and the k8s
   network policy and read by no code. Rejected deliberately: a second stateful
   store re-creates the split-authority class. Judge that reasoning.
5. **The 22-case corpus is replaced** by `evaluation/benchmark.py` — 7,075 cases
   from six third-party datasets (deepset, jackhhao, Lakera Gandalf, MultiJail,
   xquad, a synthetic multilingual set), group-split so translations and
   obfuscations of one prompt cannot straddle train/test.
6. **Detection numbers changed drastically.** Measured on the external benchmark,
   the OLD policy rules score **recall 0.025**, not the 0.643 the README claimed
   against its own 22 cases. A character n-gram classifier
   (`app/detection/classifier.py`), trained on the train split only, raises
   English held-out recall to **0.855** (precision 0.972, **FPR 0.044**, up from
   0.002).
7. **Anti-overclaiming is enforced by tests**, not review:
   `tests/test_no_overclaiming.py` fails CI if a document names a capability with
   no implementation behind it, or if the README quotes a metric no evaluation run
   produced.
8. **Startup validation** refuses to boot with `SENTINEL_REPLICA_COUNT>1` on
   SQLite. **Workers no longer start at import time** — they start from the ASGI
   lifespan hook, with a drain-on-shutdown path.

### What V4 explicitly did NOT do (stated so you need not discover it)

- **SAML, SCIM, Kafka, and in-app mTLS are NOT implemented.** They are declared
  out of scope with reasons in `docs/ARCHITECTURE_DECISIONS.md`. Attack that
  reasoning if it is self-serving.
- **No live identity provider, telemetry collector, Kubernetes cluster, or
  message broker has ever been driven by this code.** `helm` is not installed, so
  the new chart is not even lint-verified.
- **Multilingual detection is NOT validated** and is explicitly unclaimable. The
  benchmark reports ~1.000 recall on nine non-English languages; that is an
  artifact of a class-language confound, demonstrated in `evaluation/BENCHMARK.md`
  by a probe in which 8 of 10 innocuous everyday non-English requests are flagged
  as attacks.
- **The ECDSA recovery primitive is still unaudited.** No production traffic has
  ever been processed.
- A late self-audit found `/protect/evaluate` calling a function that does not
  exist — every request raised NameError. It survived three reviews because the
  regression test checked one variable name rather than the class.

### The questions that matter this round

- **Has the pattern happened a fourth time?** Three remediations, three sets of
  new same-class defects. Find the V4 instance. Look hardest at the newest code:
  `durable_queue.py`, `leader.py`, `adapter.py`, `classifier.py`.
- **Is the detection improvement real or an artifact?** A classifier trained and
  scored on data from the same six sources may be learning dataset provenance
  rather than attack semantics. The multilingual confound is admitted — is the
  ENGLISH number sound, or does it have its own confound? Check whether benign and
  attack English cases come from distinguishable distributions.
- **Is FPR 0.044 acceptable for a SOC product?** It rose 22× from 0.002. At
  realistic event volumes, what does that cost an analyst?
- **Does the durable queue actually give the guarantees claimed?** `SKIP LOCKED`
  plus a claim-timeout sweep is at-least-once, not exactly-once. Where does
  duplicate processing become visible to a customer? Is the sweep throttle
  (added for throughput) a correctness regression?
- **Is `_maybe_sweep`'s class-level mutable state safe** across threads and
  processes? Is the SQLite path of the durable queue correct at all, given it has
  no `SKIP LOCKED`?
- **Do the anti-overclaiming tests actually work**, or do they merely appear to?
  They have already been found with false positives (substring matches inside
  unrelated words) and false negatives. Try to add a false claim that passes.
- Is anything now MORE complex without being more correct? V4 added a classifier,
  a queue, leader election and an adapter layer.
- **Commercial reality is unchanged and is still the point.** Does any of this
  move the product toward viability, or is it engineering hygiene on a product
  with no wedge against funded incumbents?


---
OUTPUT FORMAT — plain markdown, no preamble, no closing pleasantries:

## Verdict in one paragraph
## Claim-by-claim verdict   (claim # | ELIMINATED / RELOCATED / PARTIAL / FALSE | file:line)
## Has the failure been RELOCATED one layer up again?   (the most valuable section)
## Regressions and NEW defects V3 introduced
## Residual dishonesty, if any          (anywhere the system still claims what it has not earned)
## Strongest thing in the codebase now  (with file citations)
## Most serious remaining defect        (with file citations)
## Is the evaluation harness sound?     (or does it flatter the system?)
## Which missing enterprise capabilities are disqualifying
## Company verdict — changed or unchanged since the last review, and why
## Three claims I expect the other seats to get wrong

Target 1400-2000 words. Density over length.