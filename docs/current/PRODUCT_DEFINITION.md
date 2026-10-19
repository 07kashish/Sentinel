# Product definition — and what the code does about each sentence of it

The business definition below was written on 9 October 2026 from a review of the archive. It is adopted here as the **canonical scope**: the demo, the documentation, the pricing conversation and the roadmap use these words. The second part of this file maps every claim in it to what is implemented, with the test or artifact that shows it, and says plainly where the code falls short of the definition.

## The definition (adopted)

> Sentinel is software that helps a business supervise the actions its AI agents take. It can check a proposed action against company rules, request human approval where required, control execution through connected tools, and keep a record of the result.
>
> **Think of an approval desk with an activity record.** The business sets the rules; Sentinel checks requests against those rules and keeps the relevant records. Some permitted actions proceed automatically; others require a person or are refused. The analogy has a limit: Sentinel can control only the paths that have been connected and properly restricted.
>
> **Two connected jobs.** *Observe*: receive activity reports, identify concerning behaviour and help investigate it. *Control*: check an action before it occurs and, on a configured execution path, permit or refuse it.
>
> **The workflow.** (1) The agent proposes a specific change. (2) Sentinel checks the company rules; an AI model is not the authority. (3) A person approves when required, for a specific scope. (4) The connected tool executes the approved request; a changed or reused authorization is refused. (5) Sentinel records what happened; a lost response is marked uncertain and resolved from the target where supported. (6) The business can review the record.
>
> **The recommended first product.** Help a business approve, execute and account for one type of AI-driven infrastructure change, starting with the Kubernetes workflow. Expand only when customers need another action and the corresponding controls can be demonstrated.
>
> **A precise current description.** A pre-production B2B platform for monitoring and controlling connected AI agent actions, with a particular emphasis on approved execution and traceable outcomes.

## Claim by claim: what exists, what proves it, what is missing

Tiers: **integration** = passes on PostgreSQL and SQLite in the recorded suite; **live** = additionally exercised on the AWS environment; **none** = no evidence.

| Sentence in the definition | Implemented as | Evidence | Short of the definition |
|---|---|---|---|
| Check a proposed action against company rules | `POST /v1/protect/evaluate`; deterministic baseline rules plus a per-tenant policy that can only tighten them; arguments reach the policy | `tests_arch/test_execution_contract.py`, `test_protect_*`; live journey in `scripts/smoke_sdks.py` | Rules are curated by the project; no customer has written a policy yet |
| Request human approval where required | `require_approval` issues a pending authorization; approvers see a redacted change view; quorum and requester/approver separation; expiry; stale approvals refused | `tests_arch/test_approval_experience.py`; approved live in the local console (`DEMO_RUNBOOK.md`) | Approval only in the console or API; no chat or phone approval |
| An AI model is not the authority | Priority is a pure function of severity; the advisor's output lands in `advisory_*` fields and the report, stamped unverified | `tests_arch/test_security_prompt_injection.py`; live advisor note on AWS | — |
| Control execution through connected tools | `POST /v1/tools/execute`: digest recomputed before the tool runs, single-use nonce, refused on substitution or replay; executors for Kubernetes, GitHub contents, brokered AWS, and **any HTTPS business application registered as a connected application** (`app_call`, 2026-10-12): the administrator registers the destination and the credential once, sealed under the data key; the agent asks, Sentinel presents the credential, and the credential can only be aimed at the resource the gate decided over | A1–A7, A11 in `PRODUCTION_ACCEPTANCE.md`; live replay refusal on AWS; `tests_arch/test_connected_apps.py`; one real call to httpbin.org through the live environment (`2026-10-12-connected-apps/`) | A lost answer from an application becomes an unknown operation for a person: no automatic reconciliation for arbitrary applications |
| Only connected and properly restricted paths are controlled | Workload identity can refuse plain API keys for agents; Kubernetes admission refuses writes that bypass Sentinel; coverage counts observed/routed/enforced separately | A9, A10; `tests_arch/test_workload_identity.py`, `test_protected_change_journey.py` | Restriction demonstrated on a local Kubernetes API server only; network egress and non-Kubernetes targets open (R-017) |
| Observe: receive activity reports, identify concerning behaviour | `POST /v1/events`, incident pipeline, causal execution graph, deterministic chain detection, containment | `tests_arch/test_execution_graph.py`, incidents live on AWS | Detection corpus curated, not blind-tested (R-005) |
| Approval applies to a specific scope | Authorization bound to tenant, agent, tool, action, resource, parameter digest, policy version, expiry, nonce | A2–A4 | — |
| Object-version checks for Kubernetes | UID/resourceVersion preconditions on the Kubernetes path | `tests_arch/test_kubernetes_outcome.py` | Kubernetes only |
| A lost response is marked uncertain and resolved from the target | Durable operations; `unknown_after_effect` state; bounded reconciliation for Kubernetes, GitHub contents, brokered AWS | A7, A12; console view *Outcomes that need a human* | Other targets need a person (R-012) |
| Keep a record the business can review | Receipts, per-tenant transparency log, offline bundle verifier, customer-side witness; console views for approved-vs-executed and transparency | A14; `standard/execution-passport-v1/`; the demo tenant witnessed from the developer's laptop on 2026-10-11 (`sentinel_program_evidence/2026-10-11-production-evidence/`) | A root published to object-locked storage is being enabled for the demo tenant; no customer witness exists |
| Pre-production; value to be proven in customer use | Evidence tiers in `RELEASE_STATUS.md`: `production_observed` 0, `externally_verified` 0 | — | Exactly as the definition says |
| First product: the Kubernetes change workflow | `FIRST_WORKFLOW.md`, `PILOT_KIT.md`, `deploy/protected-changes/`, `scripts/run_deployed_journey.py` | Two-pod kind deployment journey passed locally | No customer cluster |

## What "production-ready" would mean here, and the state of each condition

`PRODUCTION_ACCEPTANCE.md` is the list; this is its summary on 2026-10-11.

| Group | Met by engineering | Open, and what closes it |
|---|---|---|
| A. Execution control (A1–A7, A9–A14) | All, in tests; A9/A10/A12/A14 with named limits | **A8**: 30 days of a real tenant's traffic — a customer |
| B. Data (B1–B3) | Met | **B4**: restore in an independent failure domain — a drill the owner funds (a second region) |
| C. Performance and availability | C3 met; **C1 and C2 now have live figures** from the AWS environment (see below) | A formal availability target still needs a probe outside the environment |
| D. Supply chain | D1–D3 met, now in CI too | **D4** image signing (publishing switch); **D5** independent assessment — a contract |
| E. Operations | E1 met; **E2** rotation exercised on the demo tenant (see below) | **E3**: named accountable owners and expiry for every fail-closed exception — the owner |

Live figures recorded on 2026-10-11 (`sentinel_program_evidence/2026-10-11-production-evidence/`): load-balancer server-side response time over the previous seven days, all requests, p50 3 ms, p95 7 ms, p99 42 ms across 4,855 requests with no 5xx and no unhealthy host; service memory flat at 318–337 MB per task over eight days under continuous operation; decision-path latency measured from outside in `decision-latency-aws.json`. These are free-tier instance sizes under demonstration load, not a capacity claim.

## Against the alternatives, in the definition's own terms

The definition's differentiator is not a feature; it is the *connected chain*: rule → specific approval → bound execution → uncertain-outcome handling → reviewable, independently verifiable record. `COMPETITIVE_MATRIX.md` shows that each link exists somewhere in the market (Cedar policies at AWS AgentCore, asynchronous approval at Auth0, signed approval receipts in the Agent Permission Protocol draft). What this review did not find documented elsewhere, and what Sentinel can demonstrate on request today, is the chain end to end with (a) refusal of a changed or repeated execution at the last moment, (b) an explicit uncertain state reconciled from the target rather than retried, and (c) a receipt that a customer verifies without Sentinel. "Better than the alternatives" is a claim a matched customer trial can make; this document does not.

## The owner's decisions that this file depends on

1. Fund one Kubernetes design partner and run `PILOT_KIT.md` — the only thing that moves A8.
2. Name the first real business application to connect (CRM, ticketing, payments) so its registration and policy can be written with a customer.
3. HTTPS domain (DNS records), signing certificates, alarm recipient, multi-AZ database — each is an hour to a day and each is listed in `OWNER_ACTIONS.md`.
