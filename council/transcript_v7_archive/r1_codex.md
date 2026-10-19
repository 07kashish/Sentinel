## One-paragraph investment thesis

I would not invest $100M, fund a Series A, launch publicly, or place this in a production control path. I might consider a sub-$1M pre-seed option only after 3–5 design partners produce real telemetry, measurable detection lift, and one narrow workflow customers pay for. Engineering discipline improved materially, but the remediation again relocated critical failures: retries cannot resume partial incidents; execution fencing is dropped at final completion; signed packages authenticate evidence but not the claimed incident metadata; protect-mode `block` is unreachable; and erased evidence can be resurrected. Meanwhile there are no customers, defensible detection data, automatic instrumentation, production deployments, or distribution. The credible company is not “another agent-security platform”; it is a vendor-neutral, cryptographically verifiable agent-action flight recorder for regulated and platform-stranded buyers. This is a diligence opinion, not financial advice.

## Scores

| Dimension | Score | Justification |
|---|---:|---|
| Engineering | 59 | Stronger state machine, queues, CI and honest failure types; critical lifecycle and deployment defects remain. |
| AI/ML | 23 | AUC 0.763 over only two mixed-class folds, ECE 0.484; policy recall is 0.643 on 22 authored cases (`evaluation/results/leave_one_source_out_semantic.json:1-45`, `evaluation/metrics.json:2-27`). |
| UX | 16 | Attractive console, but it cannot authenticate to its API and calls stale routes. |
| Architecture | 48 | Sound single-authority direction; retry/resume, fencing and sealing boundaries remain non-atomic. |
| Innovation | 46 | Signed evidence and agent identity are interesting, but not yet a unique product system. |
| Security | 39 | Fail-closed auth and RBAC improved; privacy, package-binding, RLS and runtime-enforcement gaps are disqualifying. |
| Scalability | 31 | PostgreSQL queue is credible; synchronous LLM/I/O, DB rate limiting and broken K8s networking are not. |
| Business | 27 | No customers, production traffic, validated ICP, pricing evidence or distribution. Engineering remediation does not change this. |
| Investment-readiness | 20 | Essentially unchanged: investable problem, unproven company, still unsafe to pilot on sensitive data. |

## Strengths

- The lifecycle encodes legal transitions and artifact prerequisites rather than free-form statuses (`app/core/lifecycle.py:37-112`), while repository transitions lock, merge and commit state plus audit history transactionally (`app/core/repository.py:279-350`).
- Atomic incident-and-queue acceptance is real (`app/queue/durable_queue.py:124-170`), as are fenced queue completion predicates (`app/queue/durable_queue.py:238-271`).
- Auth is fail-closed, raw API keys are not retained in configuration, roles default to least privilege, and rejected JWTs cannot downgrade to API-key checks (`api/auth.py:66-114`, `api/rbac.py:98-169`).
- Statistical detection is honestly demoted to shadow mode (`app/monitoring/rules.py:46-53,95-137`); the policy coverage endpoint explicitly distinguishes mapping from comprehensive detection (`app/monitoring/policy.py:205-245`).
- Signed batch roots use an out-of-band trust root and refuse unsigned/self-trusted packages (`app/attestation/ledger.py:270-308`). The generic remediation webhook also requires a cryptographically bound provider receipt before claiming execution (`app/integrations/webhook.py:113-181`).
- CI now blocks lint, tests, dependency audit and image build (`.github/workflows/ci.yml:6-48`). I could not independently verify “405 passing”: two runs were blocked by managed Windows ACLs denying pytest’s temporary directories, not by test failures.

## Weaknesses & architectural issues

1. **Retry is retry theatre.** Problem: processing always restarts at `VALIDATED`. Evidence: `process()` unconditionally replays early transitions (`api/pipeline.py:193-230`); an infrastructure error propagates, but retrying from `DETECTED`, `EVIDENCE_STORED`, etc. immediately creates an illegal transition, classified terminal (`api/pipeline.py:327-342`). Risk: ordinary transient failures become permanent loss after one nominal retry. Fix: resumable stage dispatcher keyed by durable state; make each stage idempotent. Tradeoff: migration and substantially more tests. Effort: 3–5 weeks. **Critical.**

2. **Execution fence is dropped at the finish line.** Problem: the final `COMPLETED` transition omits `epoch=lease_epoch` (`api/pipeline.py:320`), although intermediate transitions include it (`api/pipeline.py:183-187`). Risk: a stale worker can complete a reclaimed incident; the mutation harness tests removal of the repository guard, not omission at a call site (`tests/test_failure_classes_are_enforced.py:263-310`). Fix: mandatory execution context/capability rather than optional epoch arguments; mutate every side-effect call site. Effort: 1–2 weeks. **Critical.**

3. **Evidence package permits authenticated relabelling.** Problem: the signature binds tenant, batch and root (`app/attestation/signing.py:87-113`), but verification never binds `incident_id`, ledger sequence, chain hash, leaf count, sealed time or anchor reference (`app/attestation/ledger.py:193-317`). Risk: modify a genuine package’s incident ID and ledger metadata and it still returns `True`—evidence Sentinel produced can be presented as a different incident Sentinel never produced. Fix: sign a canonical manifest containing schema, tenant, incident, leaf, sequence, chain head, batch metadata and root; validate schema and equality throughout. Effort: 2–3 weeks plus crypto review. **Critical.**

4. **Redaction is bypassable and partly unwired.** Problem: `redact_payload()` exists (`app/attestation/redaction.py:93-116`) but has no production caller; pipeline directly stores and records generated evidence (`api/pipeline.py:245-265`). Worse, `save_evidence` upserts body/digest without refusing or clearing a tombstone (`app/storage/db.py:739-750`), so retry/stale work can restore erased content while `redacted_at` remains. Raw events are separately retained in immutable `payload_json` (`app/storage/db.py:67-85`). Risk: GDPR/CSAM erasure is incomplete and reversible. Fix: redact before both event/evidence persistence, prohibit updates to tombstoned rows, implement subject-scoped erasure across event copies, and use envelope encryption with per-record key destruction. Effort: 3–6 weeks plus counsel. **Critical.**

5. **Protect mode cannot block.** Problem: it evaluates every request as unsigned (`api/main.py:792`); unsigned severity is capped at 79 (`app/monitoring/rules.py:142-149`), while `block` requires 85 (`api/main.py:804-811`). Risk: the documented four-state API can never emit its strongest state. Fix: verify event identity in protect mode and decide whether unverified high-risk actions fail closed to approval or block. Effort: 3–5 days. **High.**

6. **Deployment manifest breaks PostgreSQL egress.** Problem: Kubernetes repeats the `ports` key; YAML retains the later Redis port 6379, even though Redis was removed (`deploy/k8s/sentinel.yaml:85-90`; `docker-compose.yml:1-4`). Risk: production pods cannot reach PostgreSQL under the declared policy. Fix: one ports array containing 5432, remove 6379, validate manifests with kubeconform and an ephemeral-cluster test. Effort: 1–2 days. **Critical.**

7. **Dashboard is disconnected.** Problem: API calls send no Authorization header (`dashboard/index.html:919-928,1043-1049`), local API is hardcoded to port 8000 (`dashboard/index.html:847-851`) while pilot instructions use 8001 (`PILOT_README.md:72-76`), and one simulation path calls nonexistent `/simulation/start` (`dashboard/index.html:1003-1025`). Risk: onboarding ends in zeros/401/404 while health misleadingly says online. Fix: OIDC login/session handling, one API client, generated route contract, explicit 401/403 UI. Effort: 2–4 weeks. **High.**

## Market intelligence

This category already exists and is consolidating. Microsoft Agent 365 combines inventory, identity, Purview governance, Defender investigation and real-time blocking, with OTel-based auto-instrumentation—far beyond Sentinel’s manual SDK and advisory response ([Microsoft](https://learn.microsoft.com/en-us/security/security-for-ai/agent-365-security), [Observability SDK](https://learn.microsoft.com/en-us/microsoft-agent-365/developer/observability)). Check Point/Lakera offers discovery, risk posture and runtime screening of prompts, tools, responses and MCP descriptions, with self-hosting and claimed sub-50-ms latency ([product documentation](https://docs.lakera.ai/guard)). Zenity offers cross-platform inventory, permission/dependency graphs and runtime detection ([Zenity](https://zenity.io/platform)); WitnessAI spans shadow AI, MCP/tool governance, redaction, routing and runtime enforcement ([WitnessAI](https://witness.ai/)).

Do not copy the giants’ platform breadth, proprietary “AI firewall” claims, or suite bundling. Borrow automatic OTel capture, asset inventory, policy simulation, SIEM/ITSM workflows and latency SLOs. The viable wedge is independent, portable evidence and policy receipts across vendors—especially for regulated buyers avoiding Microsoft/Palo Alto/Check Point lock-in. Competing head-on is irrational; “acquisition target” is not a strategy.

## Gap analysis

Real unsolved pains are cross-framework visibility, attribution from human intent to agent/tool action, false-positive-safe enforcement, privacy-preserving telemetry, multi-agent causal reconstruction, and proof that policy ran—not merely that logs exist. Sentinel can credibly address portable audit provenance and deterministic tool policy. It cannot yet address discovery, behavioral baselining, low-latency enforcement, data classification or reliable prompt-injection detection. Manual SDK calls (`sentinel_sdk/client.py:118-155`) impose the exact adoption tax incumbents eliminate.

## Missing / critical features

Automatic OpenTelemetry/LangGraph/OpenAI/Anthropic/MCP instrumentation; agent/MCP inventory and ownership; purpose binding; policy-as-code versioning with approval/promote/rollback; test-before-enforce shadow comparisons; DLP and secrets/PII classification; SIEM/SOAR/ServiceNow/Jira/Slack destinations; tenant administration, key rotation and audit search; SAML/SCIM where buyers require them; regional data residency/BYOK; HA backup/restore and measured RPO/RTO; streaming/event export; usage/billing; framework SDKs beyond Python; policy decision SLOs and kill switch.

## Feature discovery — 3-5 non-obvious features

- **Intent-to-action provenance graph:** Problem—logs show actions but not whether they served authorized human intent. Impact—detect off-task yet individually permitted calls. Complexity—high. Design—signed causal DAG linking user goal, planner step, memory read, tool grant and result. AI need—embedding/entailment as advisory, deterministic graph constraints as authority. Business—premium enforcement. Defensibility—proprietary longitudinal intent/action corpus.
- **Counterfactual policy simulator:** replay captured traces against proposed policies and show prevented incidents, false blocks, latency and cost. Medium complexity; no LLM required except explanation. Defensibility comes from customer-specific trace history and switching cost.
- **Privacy-preserving fleet intelligence:** share salted/OPRF-derived indicators and attack-shape sketches without raw prompts. High cryptographic complexity; ML clusters emerging campaigns. Creates a genuine network effect while respecting residency.
- **Cryptographic execution receipt:** tool adapters return signed before/after state commitments, not “HTTP 200.” High complexity; minimal AI. Converts Sentinel’s evidence idea into independently verifiable proof of enforcement and a patentable protocol.
- **Agent blast-radius twin:** continuously model identities, tools, data and downstream agents; simulate “if this agent is hijacked, what can it reach?” High complexity; graph algorithms plus optional AI extraction. Strong enterprise value and defensibility.

## Security concerns

Actual default rules map only 5/10 ASI categories; ASI04/06/07/08/10 are uncovered (`config/default_policy.json:18-176`, `app/monitoring/policy.py:211-239`). Prompt fencing does not make LLM output trustworthy; the model still chooses investigations and proposed mitigations (`api/pipeline.py:232-240,298-300`). RLS defaults off and application connections do not establish tenant context (`app/storage/db.py:329-346`), leaving isolation dependent on every query predicate. Other gaps: no CSP nonce/SRI for CDN script (`dashboard/index.html:14-30`), no immutable admin-auth audit, no detector/plugin sandbox, no SBOM/signing/provenance in CI, no encrypted fields/BYOK, no DR evidence, no data-processing controls, and unaudited ECDSA recovery.

Article 50 still applies from 2 August 2026, but it concerns interaction/content transparency—not generic security attestations—and current penalties for those duties are up to €15M/3%, not the brief’s blanket €35M/7% framing ([European Commission](https://digital-strategy.ec.europa.eu/en/factpages/quick-facts-transparency-rules-ai-systems)). Compliance supports urgency but does not manufacture product-market fit.

## Scalability & performance concerns

Every authenticated request performs a transactional database token-bucket operation (`app/core/ratelimit.py:45-91`); this becomes a hot-row and latency bottleneck. Workers poll PostgreSQL, while each incident may make serial supervisor, detection, investigation, threat-intel and attestation calls (`api/pipeline.py:202-309`). Four Gunicorn workers per pod each start worker/maintenance machinery, multiplying pollers (`Dockerfile:28-29`, `api/main.py:258-282`). Ledger proof generation loads all tenant entries and reconstructs batch leaves in memory (`app/attestation/ledger.py:111-121,147-150`). There is no partitioning, archival strategy for the deliberately unbounded ledger, regional routing, asynchronous model gateway, backpressure by tenant cost, load test, or published throughput/p95. At millions of events, separate ingestion from enrichment, partition by tenant/time, batch writes and sealing, cache policies/JWKS, and use event streaming with idempotent consumers.

## AI quality limitations

The classifier is correctly non-authoritative, but that leaves narrow regex/substring rules as the product’s detection core. Known policy misses include paraphrase, Unicode, multilingual injection, renamed secrets and novel domains (`evaluation/metrics.json:60-69`). Investigation is a shallow two-call tool loop without budgets, recursive planning, provenance validation or robust recovery (`agents/investigation_agent.py:31-50`). Model versions are hardcoded or inconsistently recorded; no prompt/version registry, eval-to-release gate for supervisor decisions, tool-result injection defense, grounded citations, cost budgets, drift monitoring, memory/RAG security, multi-agent protocol, or uncertainty calibration exists.

## Customer experience / UX friction

Landing is a static operational dashboard, not a product narrative. Setup requires manual environment editing, key generation, agent key persistence/enrolment and SDK changes. There is no working login, tenant creation, guided instrumentation, sample trace validation, integration marketplace, policy editor or “first protected action” wizard. The dashboard silently ignores non-OK incident polling (`dashboard/index.html:1043-1049`), uses stale metric names (`dashboard/index.html:919-927` versus `api/main.py:411-433`), exposes no approval workflow, settings, notification routing, help center or actionable recovery. Reports dump attacker-influenced payload summaries and generic advice rather than causal timelines or evidence-backed decisions (`agents/reporting_agent.py:114-168,196-244`).

## Monetization & business-model opportunities

Package by governed action volume, not seats: Developer free tier; Team at roughly $500–$2,000/month for observe/evals; Production at $3,000–$15,000/month for policy gating, retention and integrations; Enterprise annual contracts for self-hosting, residency, BYOK, SSO and support. Charge separately for cryptographic evidence retention/export and compliance packs; avoid per-alert pricing that rewards noise.

Roadmap: **MVP (0–3 months):** close criticals, OTel/MCP instrumentation, working console, one SIEM and one paid design partner. **V1 (3–9):** purpose-bound tool gateway, policy simulator, inventory, data controls, 5 paid pilots and measured latency/accuracy. **V2 (9–18):** causal graph, signed execution receipts, regional/self-hosted deployment, SOC 2. **V3:** privacy-preserving shared intelligence and regulated-industry packs. No serious top-tier fund should lead today: not because the market is weak, but because incumbents have distribution and Sentinel lacks proof of demand or proprietary learning.

## Launch blockers

- **Critical:** retry non-resumption; dropped completion fence; relabellable signed packages; reversible/incomplete erasure; broken PostgreSQL NetworkPolicy. Fix before handling any customer data: 6–10 engineer-weeks plus security review.
- **High:** unreachable protect `block`; nonfunctional authenticated dashboard; RLS off; no automatic instrumentation; concurrent batch sealing race because pending rows are read before the sealing transaction (`app/attestation/ledger.py:66-86`, `app/storage/db.py:630-649`). Fix before a controlled pilot: 6–10 weeks.
- **Medium:** stale and contradictory sales docs—Protect “next,” RBAC absent and persistence local despite current code (`PILOT_OFFER.md:53-66,92-97`; `YC_APPLICATION_NOTES.md:18-21,44-57`). Missing DR, policy lifecycle, billing, notifications and real integration tests. Fix during design-partner phase.
- **Low:** duplicated comments, mojibake, stale metric labels and inconsistent port instructions undermine buyer confidence. One cleanup sprint.

## Hidden opportunities & patent-worthy ideas

The strongest ignored segments are model-neutral regulated operations, industrial/robotic agents, payment and treasury agents, healthcare workflow agents, sovereign deployments and insurers underwriting agent risk. The moat is not blockchain: public-chain anchoring should remain optional periodic timestamping, never per-event storage. Patent-worthy territory lies in purpose-bound causal receipts, cryptographically attestable counterfactual policy replay, and privacy-preserving cross-tenant attack-shape exchange. Five years out, buyers will expect every non-human identity to have an owner, purpose, bounded authority, live blast-radius graph and revocable credentials; Sentinel must become that portable evidence/control protocol or disappear into a platform suite.

## Three things I expect the other seats to get wrong

1. They will over-credit “405 tests” and the mutation harness without noticing that it mutates selected guards, not omitted call-site arguments—and misses the unfenced final transition.
2. They will say signed roots close provenance. They close leaf provenance against a trusted signer, but not incident identity or package metadata; authenticated relabelling still verifies.
3. They will raise business/investment scores because engineering improved. Customers, proprietary data, detection quality, automatic adoption and distribution did not improve; commercial readiness therefore did not materially move.