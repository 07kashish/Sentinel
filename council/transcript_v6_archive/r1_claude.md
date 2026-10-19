I have enough to file. I could not execute the test suite (`py` requires an approval denied in this non-interactive session; `python`/`python3` hit a nonexistent Windows Store stub) — so every claim below is from close code reading, and I flag the 315-test count as **unverified by execution**.

---

## One-paragraph investment thesis
No — not at any priced round today; a **founder/acqui-hire or note-only bet on the team's engineering discipline** is the only defensible check, and even that is speculative. What the code actually contains is a well-built durable-work substrate (transactional-outbox queue, single-authority state machine, signed agent identity, an offline-verifiable Merkle/hash-chain evidence ledger) wrapped around a **detection engine that is honestly disclosed as non-viable** (cross-source AUC 0.763 averaged over *two* folds, expected calibration error 0.48, `README.md:113-125`). The moat the pitch leans on — on-chain attestation — writes to a **testnet** and is disabled by default (`agents/attestation_agent.py:147`, `:126-133`). There is no customer, no wedge against a category that already consolidated ~$29B of M&A, and the strongest go-to-market opening (stranded acquisition buyers) has zero corresponding code. The genuinely fundable asset here is a team that, across five review rounds, learned to make failure classes fail CI — but engineering integrity is not a product, and this is not yet a company.

## Scores
| Lens | Score | Justification |
|---|---|---|
| Engineering | 76 | Outbox/fencing/config-once are textbook-correct; undercut by dead OIDC code and an unfixed ledger-fork race. |
| AI/ML | 38 | Detector is keyword-list features + logistic regression; AUC over 2 folds, ECE 0.48 = probabilities are not probabilities. |
| UX | 33 | One 53KB static `dashboard/index.html`, tenants from config not UI, manual per-call SDK instrumentation. |
| Architecture | 71 | Durable queue + single state authority are strong; single-node ledger head, app-only tenancy, per-worker rate limit cap it. |
| Innovation | 44 | Offline-verifiable evidence ledger is a real idea; not novel, and anchored to the wrong chain. |
| Security | 57 | Fail-closed constant-time auth + signed identity + injection fencing are real; no RLS, unwired OIDC, non-distributed rate limit, unaudited ECDSA. |
| Scalability | 39 | One `gpt-4o` call per incident, ledger-head contention, SQLite default, non-distributed limits. |
| Business | 19 | No customers, no wedge, consolidated market, no pricing anchor. |
| Investment-readiness | 22 | Zero production traffic, self-declared pre-production; not a priced-round profile. |

## Strengths
- **Transactional outbox is real, not claimed.** `DurableQueue.accept()` writes the incident and queue row in one `begin_immediate()` transaction (`app/queue/durable_queue.py:141-163`); the API can only answer `processing: true` after commit. This closes the "acknowledge-before-durable" class properly.
- **Fenced leases give the property that matters.** Monotonic `lease_epoch`, completion conditional on `(claimed_by, lease_epoch)`, `LeaseLost` raised on zero rows (`durable_queue.py:246-264`). Delivery stays at-least-once, but a stale worker can no longer corrupt a reclaimer's write — correctly scoped.
- **Signed agent identity is a genuine ASI03 answer.** secp256k1 keypair, `agent_id` = derived address, canonical-payload signature per event (`sentinel_sdk/client.py:55-61`, `:143-146`); unsigned clients are explicitly downgraded, never silently trusted (`:23-26`).
- **Auth is fail-closed and constant-time.** No configured keys → 503 on every authed route, not open access (`api/auth.py:73-83`); `hmac.compare_digest` match (`api/auth.py:97`); duplicate key material aborts startup (`app/core/config.py:84-91`) — the exact v2 split-parser bug, structurally killed.
- **Offline-verifiable evidence.** `verify_package()` recomputes leaf hash, replays the inclusion proof to the Merkle root, and fails closed on a missing proof (`app/attestation/ledger.py:159-213`); Merkle code uses leaf/node domain separation and promote-not-duplicate against CVE-2012-2459 (per verified map, `app/attestation/merkle.py:38-39`,`:141`). This works with **no chain at all** — the strongest real artifact in the repo.
- **Institutional honesty as an artifact.** `docs/ADVERSARIAL_REVIEW.md:85-136` names three unfixed classes and the roles that still vote NO. Rare and diligence-positive.

## Weaknesses & architectural issues
- **Ledger head is read-then-append, non-atomic → silent chain fork.** *Evidence:* `record()` calls `db.ledger_head()` then `db.append_ledger_entry()` as separate operations (`app/attestation/ledger.py:50-53`); the INSERT has an autoincrement `seq` and **no uniqueness on chain linkage** (`app/storage/db.py:405-414`). *Risk:* two replicas both chain onto head H → two "successors," a fork detected only at `verify_chain` time — the non-repudiation moat breaks under the *exact* multi-replica topology the durable queue was built for. *Fix:* single-writer sealing worker, or a `UNIQUE(tenant_id, prev_chain_hash)` constraint plus retry, or leader-gated append. *Effort:* ~1 wk. *Priority:* **Critical** (it's the product's headline claim).
- **OIDC is fully implemented and wired to nothing.** *Evidence:* `api/oidc.py` verifies asymmetric JWTs, rejects `alg=none`, checks iss/aud/exp — but `verify_token`/`role_from_claims` are imported by no route (`api/main.py`/`api/rbac.py` use API keys only). *Risk:* "SSO/OIDC" reads as a capability; enterprise POC discovers it enforces nothing. Dead security code also rots. *Fix:* wire as an auth dependency or delete and re-scope. *Effort:* 3-5 d. *Priority:* High.
- **Supervisor omits the standing injection guard.** *Evidence:* `detection_agent` puts `guard_instructions(nonce)` in its system prompt (`agents/detection_agent.py:72`); `supervisor_agent` fences the payload but never includes the guard (`agents/supervisor_agent.py:89-97`). *Risk:* the LLM that sets **priority and mitigation** sees fenced-but-unexplained attacker text; the marker→CRITICAL fallback (`:99-108`) only fires on regex hits it can evade. *Fix:* one-line addition of the guard to the supervisor prompt. *Effort:* <1 d. *Priority:* High.
- **Tenant isolation is application-code-only.** *Evidence:* correctness depends on every query carrying `WHERE tenant_id=?` (verified consistent today across ~27 predicates), with no Postgres RLS backstop (admitted, `docs/ADVERSARIAL_REVIEW.md:129-131`). *Risk:* one future query without the predicate silently bleeds cross-tenant data. *Fix:* RLS + `SET app.tenant`. *Effort:* 1-2 wk. *Priority:* High for any regulated buyer.
- **Rate limiting is per-worker in-memory.** *Evidence:* `_buckets` dict + lock, message literally says "per API worker" (`api/rbac.py:141-142`,`:181`). *Risk:* at 3 replicas effective limits triple and drift; no defense against distributed cost-exhaustion of the per-incident `gpt-4o` spend. *Fix:* shared token bucket (Postgres or the already-provisioned-but-unused Redis). *Effort:* 3-5 d. *Priority:* Medium.

## Market intelligence
This category **already exists and consolidated**: Lakera→Check Point, Protect AI→Palo Alto, Prompt Security→SentinelOne, Aim→Cato, Astrix→Cisco; still-independent Zenity, Noma, WitnessAI, HiddenLayer. Where they're better: real runtime guardrails on production traffic, trained detectors, distribution, compliance certs. Where Sentinel is arguably better on *one axis only*: **vendor-independent, offline-verifiable evidence** (`ledger.py:159`) — incumbents' audit logs are trapped in the incumbent's platform, which is precisely the pain the brief's Section 5 describes. That is the sole defensible wedge in the repo, and it is a *feature*, not yet a company. Never copy: the "on-chain attestation" positioning on a **testnet** — it will read as unserious to any CISO.

## Gap analysis
Real unsolved pains: (1) **portable, tamper-evident agent audit trails** that survive vendor churn — Sentinel's ledger genuinely addresses this; (2) **low-friction capture** of agent behavior — Sentinel *fails* this (manual per-call SDK instrumentation, `sentinel_sdk/client.py:165`); (3) **tunable detection** — Sentinel cannot close it (ECE 0.48 means no defensible threshold, `README.md:124`); (4) **enforcement without breaking agents** — Protect Mode is roadmap only (`PILOT_README.md:17-30`). Sentinel can credibly close (1) and, with a design partner's real traffic, *maybe* (3). It cannot close (2)/(4) without substantial new work.

## Missing / critical features
- **Auto-instrumentation** (OTel/LangChain/LlamaIndex callback capture) — buyers will not hand-wrap every tool call.
- **Distributed rate limiting / quota** and a cost ceiling on LLM spend.
- **Row-level security** for tenancy.
- **A working SSO path** (OIDC wired, SAML/SCIM at least on roadmap with dates).
- **A real dashboard** — one static HTML file is a demo, not an analyst console (triage queue, case management, RBAC UI).
- **Detection that degrades gracefully without OpenAI** — today a triage requires a live `gpt-4o` call (`agents/supervisor_agent.py:16`).

## Feature discovery — 3-5 non-obvious features
1. **Evidence portability / "audit-log escrow."** *Problem:* acquisition-stranded buyers can't get clean logs out of a platform. *Impact:* turns the wedge into a standalone product. *Complexity:* Med. *Design:* signed export bundles + `verify_package` as an open spec/CLI; ingest *other vendors'* logs and re-anchor. *AI need:* none — that's the point. *Defensibility:* becoming the neutral verification standard is a real moat.
2. **Injection-attempt telemetry as a shared threat feed.** *Problem:* every deployment sees novel injection phrasings; none share them. *Impact:* fixes the 0.763 generalization gap with real cross-customer distribution data. *Complexity:* Med-High. *Design:* neutralized-marker events (`sanitize.py`) → opt-in federated corpus. *AI need:* dedup/clustering. *Defensibility:* data network effect — the one durable moat in detection.
3. **Deterministic policy diff / "what-if" replay.** *Problem:* SOCs fear FPR before enabling Protect Mode. *Impact:* de-risks the observe→protect transition. *Complexity:* Med. *Design:* replay recorded events against a candidate policy, show blocks/allows delta. *AI need:* none. *Defensibility:* moderate.
4. **Agent-identity attestation registry (PKI for non-human identity).** *Problem:* 53% of MCP servers use static keys. *Impact:* rides the strongest-cited ASI03 mitigation; adjacent to Astrix's ~$400M exit. *Complexity:* Med. *Design:* extend `AgentKeypair`/enrollment into a cert-based issuance + revocation service. *Defensibility:* high if it becomes the enrollment authority.

## Security concerns
- **ASI06 memory/context poisoning & ASI01 goal hijack** partially mitigated by fencing (`sanitize.py`) but weakened by the supervisor guard gap (above).
- **ASI03 identity** — strongest area (signed events); but the **ECDSA recovery primitive is unaudited** (`docs/ADVERSARIAL_REVIEW.md:108`), a hard blocker for a security vendor.
- **Prompt-injection detection generalization** is the core product risk: ~1 in 4 unseen attacks rank below benign (`README.md:122`).
- **Privacy/compliance:** no RLS; retention deletes the audit trail with the incident (`docs/ADVERSARIAL_REVIEW.md:73-76`) — a SOC2/7-year buyer needs the ledger exported.
- **Structural tests are string-match evadable** — theatre risk. E.g. the "no counters outside the DB" test only catches `json.dump` via a `Name` node named `json` (`tests/test_failure_classes_are_structural.py:130-138`); `import json as j` evades it. They are good *regression guards*, not adversarial guarantees, and none exercise the live distributed race paths.
- **Testnet anchoring** (`attestation_agent.py:147`) provides no economic security and can be reset — do not present it as tamper-proof to enterprise.

## Scalability & performance concerns
- **One `gpt-4o` triage call per incident** (`agents/supervisor_agent.py:16`) is the dominant cost/latency bottleneck and a DoS/cost-amplification vector given per-worker rate limits.
- **Ledger head is a per-tenant serialization point** and, worse, forkable under replicas (above).
- **SQLite is the default**; startup refuses multi-replica on SQLite (`durable_queue.py:51-52`), so horizontal scale *requires* Postgres — fine, but the single-writer ledger constraint then reappears.
- **No streaming, no batching** of LLM triage; throughput is bounded by OpenAI latency × concurrency.

## AI quality limitations
- **Calibration error 0.48** — the confidence score is unusable for thresholding, the first thing a SOC does (`README.md:124`).
- **Cross-source AUC 0.763 is an average of only two mixed-class folds** (deepset, jackhhao); the other four sources are single-class (`evaluation/validate.py:197-211`). Directionally honest, statistically thin — I would not ship detection on it.
- **The "semantic features" are curated keyword lists** (`app/detection/semantic_features.py:49-96`) + logistic regression; robust to obfuscation somewhat, but multilingual is explicitly **not validated** (`:29-34`).
- **Nondeterministic LLM sets priority/mitigation** — a reliability and audit concern even with the marker fallback.
- **Benchmark requires network at runtime** (HuggingFace datasets-server, `evaluation/benchmark.py:247-283`), cache not committed — so the 0.763 figure is **not offline-reproducible from the repo alone**.

## Customer experience / UX friction
Landing→onboard: no product landing, README-driven. Auth: config-file API keys, no self-serve. Onboarding an agent: developer must generate a key, enroll the address, and **hand-instrument every tool call** (`sentinel_sdk/client.py:165-181`) — the single biggest adoption tax. Dashboard: one static `index.html` (53KB) — no case management, no RBAC UI, tenants invisible (`PILOT_README.md:201`). Notifications/help: `notify_security` is a proposed action requiring a configured provider or it reports UNAVAILABLE (`app/response/mitigation.py:77-81`). The pilot doc even instructs `SENTINEL_API_KEY=dev_test_key` (`PILOT_README.md:49`), which live mode then rejects (`config.py:130`) — a confusing first-run cliff.

## Monetization & business-model opportunities
- **Wedge product: neutral evidence/audit escrow** — price per attested incident or per retained GB; land with acquisition-stranded buyers. This is the only path where the code is ahead of the pitch.
- **Identity registry** as a per-agent/per-month SaaS (rides ASI03 demand).
- **Threat-feed network** (feature #2) as the data moat and an upsell.
- Avoid competing head-on on runtime guardrails — that market is bought.
- Growth loop: open-source `verify_package` + the evidence spec to make Sentinel the verification default; monetize issuance/retention/enforcement.

## Launch blockers
- **Critical:** ledger fork under replicas (breaks the core claim); unaudited ECDSA recovery; zero production traffic / detection not thresholdable.
- **High:** OIDC unwired; supervisor guard gap; no RLS; no auto-instrumentation.
- **Medium:** per-worker rate limiting; network-dependent, non-reproducible benchmark; static single-file dashboard.
- **Low:** pilot doc weak-key contradiction; retention deletes audit trail (needs export path).

## Hidden opportunities & patent-worthy ideas
- **Vendor-neutral, offline-verifiable evidence package format** (`ledger.py:159`) — potentially standard-setting; a defensible method claim around hash-chain + inclusion-proof + revocation for *agent* actions.
- **Federated injection-marker telemetry** turning `sanitize.py` neutralizations into a cross-customer corpus — the only route to fixing generalization, and a real data-network moat.
- **Deterministic observe→protect replay** as the trust bridge incumbents under-serve.
- Five-year view: as EU AI Act Article 50 transparency bites (Aug 2, 2026) and high-risk obligations land 2027-28, **portable machine-verifiable attestation of agent behavior** is exactly what auditors will demand — Sentinel's ledger is early to the right problem, on the wrong chain and with the wrong go-to-market.

## Three things I expect the other seats to get wrong
1. **Crediting on-chain attestation as the moat.** The chain write is testnet-only and off by default (`attestation_agent.py:126-133`,`:147`); the *actual* differentiator is the local ledger that works with no chain (`ledger.py:6-8`). A seat that praises "blockchain attestation" or dismisses the ledger as a hackathon toy both miss it.
2. **Reading "315 tests pass" / structural tests as production-readiness — or as pure theatre.** Neither. I could not execute them; more importantly they are string-match regression guards (`tests/test_failure_classes_are_structural.py:130-138`) that don't touch the live distributed race that actually threatens the ledger. They prove discipline, not correctness under concurrency.
3. **Treating the README's honesty as de-risking the investment.** Honesty about ECE 0.48 and a 2-fold AUC makes the diligence *cheaper*; it does not make an uncalibrated detector with no customers *fundable*. Conversely, a seat that fixates on "pre-production" may undervalue the genuinely reusable IP — the outbox queue and signed-identity SDK are the assets worth an acqui-hire, independent of the detection story.