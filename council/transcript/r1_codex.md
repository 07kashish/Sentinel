## One-paragraph investment thesis

Do not fund this as a $100M-scale company today. I would consider a tightly scoped pre-seed/customer-discovery investment only if the team stops polishing the generic “AI SOC” and earns a wedge with 3–5 design partners needing independently verifiable incident evidence for regulated agent workflows. Engineering has improved meaningfully: durable state, RLS seams, signed evidence roots, and honest pre-production language are real. But Sentinel still has no proven detection, enforced runtime control, telemetry-native adoption path, customers, or distribution; it competes in a rapidly consolidated category against better-capitalized platforms. Worse, v8 still relocates fencing failure into terminalisation and external attestation. This is a promising security-engineering project, not yet an investable security business.

## Scores (0-100, one number each, with a half-line justification)

Engineering **55** — substantial integrity/retry/auth work, but new race escapes and no runnable validation here.  
AI/ML **17** — explicitly uncalibrated two-fold AUC 0.763/ECE 0.484; model is rightly non-authoritative.  
UX **40** — coherent analyst console, but polling, misleading attestation language, and unsafe render paths remain.  
Architecture **50** — good transactional boundaries and RLS design; SQLite-shaped queues and direct worker threads cap it.  
Innovation **35** — evidence provenance is potentially distinctive; generic agent-security detection is not.  
Security **44** — several strong controls, but stored-XSS gaps, unenforced protection, and fence/outbox races are unacceptable.  
Scalability **20** — no production deployment, benchmarks, broker, autoscaling evidence, or global topology.  
Business **20** — no customers, paid pilot, ICP proof, pricing, or distribution wedge.  
Investment-readiness **13** — materially below seed threshold; commercial and detection constraints dominate.

## Strengths

- The README is unusually candid: pre-production status, advisory-only protect mode, and the detector’s calibration failure are explicitly stated rather than marketed away (`README.md:3-10`, `README.md:111-141`, `README.md:174-185`).
- The repository has a credible durable lifecycle authority: state transition, facts, and audit-trail append are committed together (`app/core/repository.py:298-344`); evidence, ledger entry, and transition share one transaction (`app/core/repository.py:396-437`).
- Evidence-package provenance genuinely fails closed when no independent signer is supplied, and v2 binds tenant and incident to the evidence manifest (`app/attestation/ledger.py:223-236`, `app/attestation/ledger.py:252-273`, `app/attestation/ledger.py:358-398`).
- RLS is thoughtfully designed: protected tables, `FORCE ROW LEVEL SECURITY`, and transaction-local tenant context are explicit (`app/storage/rls.py:40-76`, `app/storage/rls.py:91-102`).
- OIDC rejects non-asymmetric algorithms and validates issuer/audience; tenant claim extraction now fails closed (`api/oidc.py:39-42`, `api/oidc.py:137-155`, `api/oidc.py:173-196`).
- The mutation harness is real, not merely a source-substring assertion: it loads a modified module and requires a behavioral probe to fail (`tests/mutation_support.py:50-99`). It is useful, but narrow.
- The shared database rate limiter fixes the former per-pod multiplication problem (`app/core/ratelimit.py:45-91`), and CI now includes lint, dependency audit, image scanning, live PostgreSQL tests, and limited schema fuzzing (`.github/workflows/ci.yml:25-34`, `.github/workflows/ci.yml:49-61`, `.github/workflows/ci.yml:109-155`).

I could not independently run the claimed 459-test suite: this environment has neither Python nor pytest available.

## Weaknesses & architectural issues

- **Problem:** Execution fencing is still bypassable during terminal failure. **Evidence:** `process()` catches terminal errors then calls `_terminalise()` (`api/pipeline.py:601-606`), but `_terminalise()` calls `repository.fail()` without `epoch` (`api/pipeline.py:614-617`), while `fail()` accepts fencing but defaults it to `None` (`app/core/repository.py:646-662`). **Risk:** a stale worker can mark a newer owner’s live incident `FAILED`. This is relocation, not closure, of C-2. **Fix:** thread epoch into terminalisation; make worker-path failure APIs require it structurally. **Effort:** 1–2 days plus concurrent fault-injection test. **Priority:** Critical.

- **Problem:** External attestation is not fenced immediately before the irreversible side effect. **Evidence:** the outbox claim is fenced (`api/pipeline.py:391-400`), but `publish_attestation()` occurs afterward with no `assert_execution()` or epoch/idempotency key (`api/pipeline.py:404-417`); `claim_attestation()` can overwrite a `delivering` claim rather than reject a different epoch (`app/core/repository.py:550-572`). **Risk:** lease steal plus network delay can create duplicate or wrongly attributed on-chain writes. H-4 is not closed. **Fix:** outbox state CAS on claim epoch; pass its idempotency key to the gateway; fence immediately before call; reconcile gateway receipt before retry. **Effort:** 1–2 weeks. **Priority:** Critical.

- **Problem:** The “all server content escaped” XSS claim is false. **Evidence:** `JSON.stringify(inc.intel.external_data)` is inserted directly into `innerHTML` (`dashboard/index.html:1344-1352`), and transaction hash is injected into an href/title without escaping or URL validation (`dashboard/index.html:1270-1274`). CSP permits inline script (`dashboard/index.html:7-24`). **Risk:** stored XSS in an analyst console handling attacker-controlled intelligence, leading to session/CSRF-token theft and privileged action. **Fix:** render with `textContent`, construct links via validated DOM URLs, eliminate inline scripts with nonce/hash CSP. **Effort:** 2–4 days. **Priority:** Critical.

- **Problem:** “Protect mode” is advisory, not protection. **Evidence:** it returns `enforced: false` (`api/main.py:862-873`), and README confirms no inline interception or kill switch (`README.md:174-182`). **Risk:** an enterprise buyer cannot treat it as a runtime security control. **Fix:** ship an SDK/proxy/MCP gateway that can synchronously deny, require approval, revoke credentials, and emit a receipt. **Effort:** 2–4 months. **Priority:** High.

- **Problem:** Detection coverage is shallow and brittle. **Evidence:** classifier gating is disabled by default because of calibration limits (`app/monitoring/rules.py:46-53`); default policy is a small set of static rules, mapping principally to ASI01, ASI02, ASI03, and ASI09 (`config/default_policy.json:20-176`). **Risk:** Sentinel does not genuinely cover ASI04 supply chain, ASI05 code execution sandboxing, ASI06 memory poisoning, ASI07 inter-agent communications, ASI08 cascades, or ASI10 rogue autonomy. **Fix:** collect partner telemetry, build scenario-based evaluation suites, and add controls/detection for each threat—not labels. **Effort:** 6–12 months. **Priority:** High.

- **Problem:** Sensitive-content privacy is improved but correlation hashes leak low-entropy content. **Evidence:** redaction deliberately retains unsalted SHA-256 and acknowledges dictionary attack exposure (`app/attestation/redaction.py:53-69`). **Risk:** prompt fragments, identifiers, and known abusive material can be reidentified; cross-customer correlation creates purpose-limitation risk. **Fix:** tenant-keyed HMAC by default; explicit opt-in privacy-preserving threat exchange with legal controls. **Effort:** 2–3 weeks. **Priority:** High.

## Market intelligence

This market exists and has consolidated: Check Point/Lakera, Palo Alto/Protect AI, SentinelOne/Prompt Security, Cisco/Astrix, Microsoft, Palo Alto, Cato/Aim, Zenity, Noma, WitnessAI, HiddenLayer, Straiker, Pillar, and Lasso already sell adjacent discovery, posture, identity, runtime guardrails, and evaluation. They are better at enterprise procurement, integrations, telemetry collection, SOC workflows, threat research, and global support. Sentinel is better only in its unusually transparent prototype posture and its potentially portable evidence-verification concept.

The plausible wedge is not “another AI SOC” or “prompt injection detector.” It is “independent, privacy-respecting incident evidence and policy receipts for high-consequence agent actions”—particularly for buyers stranded by consolidation who want vendor-neutral evidence. Do not copy incumbent platform bundling, black-box detection claims, or per-event blockchain logging. Borrow OTel-native instrumentation, policy-as-code, deployment templates, identity federation, and evaluation/red-team workflows.

## Gap analysis

Real unsolved pains are: proving what an autonomous agent did after evidence is redacted; mapping a decision to identity, delegated authority, policy version, tool call, approval, and outcome; preventing unsafe actions without blocking operations; and demonstrating controls to an auditor without exporting sensitive prompts.

Sentinel can credibly address evidence receipts if it completes a hybrid, signed, customer-controlled ledger. It cannot credibly claim detection or enforcement yet. The docs correctly describe Base Sepolia as demo-oriented in practice: the code still submits a per-incident `recordIncident` transaction (`agents/attestation_agent.py:247-269`), whereas the ledger’s batch design is the better hybrid architecture (`app/attestation/ledger.py:75-128`). Testnet anchoring is a hackathon artifact, not enterprise differentiation.

## Missing / critical features

Serious buyers expect OTel/OpenInference auto-instrumentation; SDKs for LangChain, OpenAI Agents SDK, MCP, Bedrock, Vertex, and agent frameworks; policy simulation and change approvals; tenant-owned keys; SIEM/SOAR integrations; streaming/event ingestion; immutable retention holds; case management; SLOs; audit exports; DLP/classification; sandboxed tool execution; jurisdictional data routing; and a real control-plane/data-plane separation. None is proven here.

## Feature discovery — 3-5 non-obvious features

- **Delegation passport:** bind user purpose, agent identity, delegated scopes, tool budget, expiry, and approval chain into a signed capability carried across agent-to-agent hops. Impact: solves ASI03/ASI07 accountability. Complexity: high. AI need: none. Defensibility: a cross-vendor receipt graph becomes a data moat.
- **Counterfactual control replay:** replay a historical agent trace against a proposed policy/model/tool configuration and quantify blocked actions, false blocks, latency, and approval burden. Impact: makes security adoption measurable. Complexity: high. AI need: simulation/trace normalization, not generative judgment. Defensibility: proprietary trace corpus.
- **Evidence minimization compiler:** convert raw tool calls into a cryptographic receipt containing only fields necessary for a particular audit claim, with selective disclosure. Impact: privacy plus compliance. Complexity: high. AI need: policy-guided schema extraction. Defensibility: patentable receipt/proof composition.
- **Autonomy circuit breaker:** detect rapidly expanding tool scope, privilege, spend, or agent fan-out; enforce progressive budgets before a cascade. Impact: addresses ASI08/ASI10. Complexity: medium-high. AI need: anomaly models calibrated per tenant. Defensibility: longitudinal behavioral baselines.
- **Prompt provenance quarantine:** label and track untrusted context through retrieval, memory, and inter-agent messages; prohibit it from influencing authority-bearing fields without corroboration. Impact: addresses ASI01/ASI06. Complexity: high. AI need: taint propagation plus classifier assistance. Defensibility: framework-level provenance graph.

## Security concerns

OWASP ASI mapping is presently partial, not ten-of-ten coverage. Prompt fencing is a defense-in-depth measure, not a proof against indirect injection; the supervisor still sends attacker-influenced metadata to an external model (`agents/supervisor_agent.py:82-116`). The LLM cannot move priority, which is good (`api/pipeline.py:219-272`), but it can produce recommendations that become approval proposals. Treat all model outputs as untrusted and validate against an allowlisted action schema and target authorization.

RLS is strong only on PostgreSQL; SQLite remains application-predicate isolation (`app/storage/rls.py:25-32`). Supply-chain posture is improved by CI but lacks signed releases, provenance attestations, dependency pin/update policy, runtime image admission, and independent cryptographic audit. GDPR needs data inventory, DPA/subprocessors, retention enforcement evidence, DSAR workflows, lawful-basis controls, and key destruction—not merely tombstones.

## Scalability & performance concerns

The durable queue, rate limiter, lifecycle, and sealing are database-transaction-heavy. At high ingest rates, one shared Postgres becomes the queue, rate-limit coordinator, event store, evidence store, and ledger sequencer. Per-tenant hash-chain ordering is intrinsically serial. Worker threads inside API pods (`api/main.py:184-240`) are not a scalable worker plane. The supervisor makes synchronous external LLM calls with a 20-second timeout (`agents/supervisor_agent.py:25-31`).

For millions of events: ingest through Kafka/NATS, partition by tenant/agent, use an append-only object store plus compacted stream, batch Merkle commitments, separate workers, Redis/local rate-limit tiers, regional data planes, and a global control plane. Measure p95/p99 ingestion, policy decision, queue lag, evidence sealing, and cost per million events before asserting scale.

## AI quality limitations

There is no trustworthy production ML gate. The bundled model deserializes a pickle artifact (`app/detection/classifier.py:89-99`), has weak calibration, no multilingual validation, no real customer distribution, no adversarial robustness evaluation, and no false-negative economics. The LLM is optional advisory infrastructure, not autonomous investigation. That is safer, but it means “multi-agent SOC” is mostly orchestration branding, not differentiated AI capability.

## Customer experience / UX friction

Landing routes users to a dashboard, but onboarding still requires OIDC/API-key, tenant, policy, signer, integrations, and telemetry setup before value. The UI polls rather than streams (`dashboard/index.html:1141-1182`), gives no policy simulation, no approval queue workflow, no evidence-verification wizard, and no clear distinction between “recorded,” “sealed,” “signed,” and “externally anchored.” It also says “Anchoring batch root” while the attestation path records individual incidents (`dashboard/index.html:1336-1339`; `agents/attestation_agent.py:247-249`). That is a trust-damaging mismatch.

## Monetization & business-model opportunities

Do not start quote-only enterprise sales. Offer a free developer evidence SDK; paid usage by verified agent-action receipt; enterprise tiers for private deployment, retention, KMS/BYOK, SIEM/SOAR, policy simulation, and compliance exports. Sell initially to fintech, healthcare, legal, insurance, and BPO automation teams with high-consequence delegated actions—not general SOCs. The moat is accumulated, privacy-safe benchmark traces and cross-framework delegated-authority receipts, not an LLM classifier. YC might fund a sharply focused design-partner pre-seed; top-tier Series A investors would wait for repeatable retention, live enforcement, and a distribution channel.

## Launch blockers

- **Critical:** terminalisation fence bypass; fix epoch-required failure API and race test. **1–2 days.**
- **Critical:** unfenced/overclaimable external attestation; fix outbox CAS, gateway idempotency, reconciliation. **1–2 weeks.**
- **Critical:** remaining dashboard XSS paths; replace unsafe `innerHTML`, deploy strict CSP. **2–4 days.**
- **High:** no actual enforcement plane; build gateway/SDK control point. **2–4 months.**
- **High:** no validated detection or customer traffic; obtain partner corpus and run shadow pilots. **3–6 months.**
- **High:** no production operations proof—Kubernetes, OTLP, HSM, DR, and load claims are untested. **2–3 months.**
- **Medium:** Base Sepolia/per-event anchoring confuses the product; remove it from the primary workflow and batch external commitments. **2–4 weeks.**
- **Low:** dashboard presentation and accessibility need redesign around analyst queues, exports, and error recovery. **3–4 weeks.**

## Hidden opportunities & patent-worthy ideas

The strongest five-year opportunity is becoming the independent trust-receipt layer between agents, identity providers, model platforms, and regulators. Own delegated authority, purpose binding, selective disclosure, and verifiable policy decisions rather than model detection. Emerging-market opportunity: regulated outsourcing and fintech operators that need auditability but cannot buy giant security platforms. Patent-worthy work is the evidence-minimization compiler plus selective-disclosure agent delegation passports; patents alone are not a moat, but an interoperable standard plus reference SDK could be.

## Three things I expect the other seats to get wrong

1. Giving engineering remediation commercial credit. It improves Engineering/Security modestly, not Business, AI/ML, or Investment-readiness.
2. Calling signed Merkle evidence a blockchain moat. It is valuable only if customer-controlled trust roots, integrations, and audit workflows make it operationally indispensable.
3. Treating the mutation harness as complete assurance. It proves selected mutations fail; it did not catch the unfenced `_terminalise()` path or the post-claim external-side-effect race.