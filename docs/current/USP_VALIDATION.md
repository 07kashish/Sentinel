# Differentiation candidates and claim boundaries

Reviewed 2026-09-19. **No feature has been established as absent from every competitor.** Public documentation cannot prove a universal absence, and no matched-workload comparison has been completed. These are product hypotheses for the approved Kubernetes-change workflow, not patent claims or leadership assertions. See COMPETITIVE_MATRIX for dated primary sources.

| Candidate customer outcome | Current Sentinel evidence | Missing implementation or proof | Comparative acceptance test |
|---|---|---|---|
| Approve an exact change, refuse it if the world changes before execution | Tenant/agent/tool/parameter/policy binding plus required Kubernetes UID/resourceVersion preconditions and local API tests | Independently witnessed admitted change, production identity/credential path and matched competitor trials | Concurrent controller changes and object replacement must invalidate old approval; compare interruption and bypass rates on identical tasks |
| Recover from ambiguous remote execution without blindly repeating it | Durable intent, operation ID and unknown-after-effect state under faults | Independent target lookup, trustworthy correlation and bounded automatic reconciliation | Drop each response and kill the gateway at every side-effect boundary; count mutations at the target and measure reconciliation time |
| Show where enforcement is real and where coverage is unknown | Separate observed/routed/enforced counters; no invented coverage percentage | Validated customer egress restrictions, workload identity and independent bypass signals | Attempt direct API use, stale identity, undeployed sensor and alternate tool routes; each must be blocked or visibly unknown |
| Investigate a change after Sentinel's primary failure domain is lost | Receipt signing, verification, transparency primitives and local restore | Independently controlled witness/WORM storage, key lifecycle and independent recovery | Destroy the primary test domain, restore elsewhere, verify historical evidence with separately held keys and target records |
| Permit the first useful change with low integration burden | Thin SDK, shipped console, authorization inbox and narrow workflow definition | Real IdP/short-lived credential/egress/SIEM integration and measured customer onboarding | Three paid design partners complete the same change; record elapsed time, support hours, interruption rate and investigation time against their current method |

## What is already shared with alternatives

AWS AgentCore documents Cedar tool authorization and parameter policies; Pomerium documents user delegation, tool access policy and upstream credential handling; Auth0 documents human-in-the-loop authorization. APP and execution-evidence research overlap signed scope/approval receipts. Those mechanisms alone are not exclusive USPs. A practical advantage would be a verified end-to-end outcome with less customer work and honest failure handling.

## Patent handling

A private invention-candidate brief is maintained outside this repository. Candidate mechanisms need inventor interviews, dated implementation evidence, a professional prior-art/claim search and disclosure review before any filing decision. The present review establishes neither novelty nor freedom to operate. Avoid publishing further mechanism details before that review; generic approval, hashes, signatures, Merkle trees and delegation are not sufficient novelty claims.

## Compounding advantage to measure

With customer consent, accumulate redacted failure/reconciliation cases, interoperable adapters, reproducible attack scenarios, verifier compatibility and measured onboarding improvements. Keep customer evidence portable. Review wins, losses and retention to decide what to build; feature count and an untested uniqueness slogan are not a moat.

## 2026-09-20: what moved, and what it still does not prove

| Candidate outcome | New evidence | Still missing |
|---|---|---|
| Approve an exact change, refuse it if the world changes | The agent is an attested workload (cluster-signed token), the API server refuses writes that bypass Sentinel, the change runs under a per-operation credential, and the cluster's managedFields attribute it to the operation id: one test, real local Kubernetes 1.37 API | Deployed pods, a customer identity provider, an enforcing CNI, matched trials on alternatives |
| Recover from ambiguous execution without repeating it | A lost response is settled as succeeded from the target with no second write; a definitive conflict is a recorded failure; bounded attempts and a quiescence window | Reconcilers for tools other than Kubernetes; settlement times from real traffic |
| Show where enforcement is real | Bypass is now refused at the API server, so "routed" can be made equal to "possible" inside a labelled namespace | The same for network egress and for non-Kubernetes targets |
| Investigate after losing the primary environment | Receipts are committed to the log and a bundle verifies offline against a trusted root | A root actually held outside the environment, and a restore that verifies old evidence with it |
| Low integration burden | Redacted approval view, quorum, console inbox, counted workflow metrics | Every customer number |

None of these rows establishes that an alternative lacks the capability. They establish what Sentinel can now demonstrate on request, which is the precondition for a matched trial.

## 2026-09-20 (second pass)

The exact-change outcome is now demonstrated DEPLOYED: two Sentinel pods in production mode, an agent pod identified by its kubelet-issued pod-bound token, the API server and the CNI both refusing bypass, the change attributed in managedFields, and the receipt verified offline (`scripts/run_deployed_journey.py`, one local node). Deletes are covered. The investigate-after-loss outcome has a customer-side witness and a restore drill. Reconciliation extends to GitHub contents. None of this is a customer result, and none of it shows an alternative cannot do the same.

