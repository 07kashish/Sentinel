I've verified the peers' claims against the actual code. Here is my Round 2 statement.

## Where they are right and I was wrong

Codex is correct that the blanket "all the agents are fake" line does not survive contact with the code, and I concede the point. `agents/detection_agent.py:14-38` makes a real `ChatOpenAI(model="gpt-4o")` call with structured output; the supervisor and investigation agents do likewise. Evidence, reporting, and attestation are deterministic (`agents/evidence_agent.py`, `agents/attestation_agent.py`) — sensible engineering, dishonestly named "agents," but not vaporware. Any seat claiming zero model calls is wrong.

Codex also nailed a detail I under-weighted: the off-chain evidence URI is a dangling pointer. `agents/evidence_agent.py:31` sets `evidence_location` to `"offchain_database://local/reports/{id}.json"`, but nothing ever writes that `.json` file — the pipeline writes `.md` reports (`api/main.py:288`). So the attestation commits a Keccak hash of an artifact that does not exist at the URI it names. The entire "tamper-proof evidence" story collapses on this alone: you can verify the hash, but there is nothing to verify it against.

And Codex is right that `/ingest-event` leaves `incident.mode` at the schema default `"demo"` (`api/schemas.py:113`) because `build_base_incident` never sets it (`app/normalizers/common.py:37-48`, `api/main.py:664-673`). I verified this.

## Where they are wrong

**Claim (Codex):** *"the detector is mostly substring matching"* and separately *"without an OpenAI key or on any model error, there is no deterministic fallback: the top-level pipeline marks the incident failed (api/main.py:298-301)."*

Both statements are individually true but Codex treats them as describing one detector. They describe two, and conflating them buries the single most damning fact in the repo. The **real-time enforcement path contains no AI at all.** `/protect/evaluate` — the "Protect Mode" the docs sell — calls `protect_decision_from_event` (`api/main.py:325-364`), which calls only `evaluate_event` (`app/monitoring/rules.py:16-81`): six file substrings, six command substrings, two hardcoded domains, an `override` check, and a client-supplied `riskScore` (`rules.py:12-14, 55-59`). No model. `/events/ingest` gates incident creation on the same `evaluate_event` (`api/main.py:505`). The GPT-4o `run_detection` runs **only** in the async background pipeline (`api/main.py:178`), downstream of the decision, feeding the report. So the LLM never gates a single block/allow/approve decision. The AI is narration layered on top of a keyword matcher — this is stronger than "mostly substring matching," and it is the finding that should anchor the council's verdict.

**Claim (Codex):** *"the live store... returns stale pre-pipeline copies while monitoring is active (api/store.py:74-81, 112-136)."*

Correct but understated. In monitoring mode `/incidents` returns `get_live_incidents()` (`api/main.py:581-582`), which returns `_live_incidents` (`store.py:134-136`) — the raw `LiveIncident` dicts appended at ingestion (`api/main.py:526`). The pipeline patches `_store[incident_id]` (`store.py:59-65`), a **different** structure. Nothing ever patches `_live_incidents`. So in live mode the dashboard is frozen at the detection snapshot forever — investigation, evidence, attestation, and report status never surface. Compounding it, `get_live_metrics` hardcodes `attestations_success: 0` and `remediations_triggered: 0` (`store.py:129-130`). The live product structurally cannot display an attestation even when one occurs. This is not "stale copies"; the live UX is non-functional.

I could **not verify** Codex's `agents/tools.py:25-29` claim about `check_api_abuse` (I did not open that file), nor its file/line counts (44 files / 3,749 lines vs the brief's 42/3,237). I flag both as unverified rather than endorse them.

## What all of us missed entirely

**The demo→live leak is worse than a mislabeled `mode` field.** `ContinuousMonitor.generate_mock_real_event` (`app/monitoring/continuous_monitor.py:84-107`) fabricates fake incidents — `"rm -rf /"`, a `"500 ETH"` transfer, `"Ignore previous instructions"` — and POSTs them to `/ingest-event` (`continuous_monitor.py:109-120`) with **no auth header**. In live mode these become genuine incidents. The demo-disclaimer banner is applied only when the process-global `SENTINEL_MODE == "demo"` (`api/main.py:277-282`) — it keys off the environment variable, not the per-incident `mode` field. So in live mode, machine-fabricated attack events flow through the full pipeline and produce reports with **no demo label at all**. Simulated data reaching a path that presents it as real is exactly the boundary violation the brief asked us to hunt, and it exists via the monitor's own default behavior (a 1-in-20 fabrication on empty log files, `continuous_monitor.py:71`).

**The attestation binds the wrong data to the wrong identity.** The hash covers `detection.model_dump()` + investigation (`evidence_agent.py:15-21`) — LLM *outputs*, not the raw event. And when `detection.agent_id` is not a valid EVM address, the code mints a fresh random address (`attestation_agent.py:73-77`). So the on-chain record is: hash-of-model-output → random throwaway address. Neither the raw evidence nor the real agent is committed. Even the ideal hybrid design in Brief §7 cannot rescue this until identity and raw-evidence anchoring are fixed first.

**The contract has no authorization.** `recordIncident` is `public` with no modifier (`AgentTrustRegistry.sol:27-42`) — any address can write any hash against any agent. As a "trust registry," it is unauthenticated by construction.

## The disagreement that actually matters for the decision

Codex lands on "a sellable founder-assisted monitoring pilot here" — a $2,500 audit, $500/mo beta. I dissent on where the value sits. Strip away what does not work — the frozen live dashboard, the dangling evidence URI, the unauthenticated contract, the mock threat intel (`app/tools/threat_intel.py:17-20` is a literal `pass` then a two-row lookup) — and what remains sellable is: a 20-line substring rule engine any customer writes in an afternoon, plus GPT-4o report narration, plus a founder doing manual triage. The willingness-to-pay attaches to the founder's hands, not the artifact. That is a **security-consulting engagement**, not a product, and it does not compound into a company — every pilot resets to zero because state is in-memory (`store.py:14-22`) and the "learning" lives in the founder's head, not in labeled data the code retains.

This matters for the decision because it changes the recommendation from "run the pilot to find product-market fit" to "the pilot will succeed as a service and teach you nothing transferable about a product." Those are different companies with different failure modes.

## My revised position

**Code:** credible hackathon vertical slice; the enforcement path is 100% keyword matching with the LLM as decoration (`api/main.py:325-364`); demo fabrication can reach the live path unlabeled and unauthenticated (`continuous_monitor.py:84-120`); attestation is a testnet stub committing model output under a random address (`attestation_agent.py:73-77`).

**Detection:** I concur with Codex's 0/10-comprehensive, ~2/10-partial mapping, and `evaluation/metrics.py:64-77` grades against a hardcoded `EXPECTED_ANOMALIES = 7` — synthetic self-scoring with no recall, no true negatives.

**Company:** No moat. The honest verdict is *services business, not venture company.* The single biggest reason it fails: the value is founder labor, and nothing in the code retains it across engagements. On-chain attestation is a hackathon artifact — right instinct (non-repudiation), wrong data committed, wrong identity model, wrong chain — and fixing the chain is the last 5% of that work, not the first.

**Recommendation:** if the founder wants a company, throw away the attestation layer and the LLM-as-detector framing, and rebuild around signed agent identity + durable hash-chained evidence + a real human-approval gate — the ASI03 identity gap in Brief §2 is the only defensible wedge here, and none of the current code touches it.