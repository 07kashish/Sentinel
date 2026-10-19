# Competitive evidence matrix

Reviewed 2026-09-17; related protocol/research overlap added 2026-09-18; AWS/Auth0/Pomerium documentation refreshed 2026-09-19. Scope: midmarket SaaS/fintech teams permitting a consequential Kubernetes infrastructure change. Sources are primary documentation or research, not customer tests. “Not established” means this review has no evidence, not that the alternative lacks the capability. No head-to-head deployment, cost, latency, detection or usability benchmark has been run.

| Alternative | Documented workflow / enforcement point | Identity / deployment | Binding and remote outcome evidence examined | Sentinel gap and decision | Source (accessed 2026-09-17) |
|---|---|---|---|---|---|
| AWS AgentCore Policy/Gateway | Deterministic Cedar authorization at tool invocation; default deny and forbid wins | IAM or OAuth principals; managed AWS gateway | Parameter conditions documented; equivalent cross-system reconciliation receipt not established in this review | Native AWS identity and managed gateway operations are integration targets. Demonstrate added approval/outcome value before asking an AWS-only customer to add Sentinel | [Policy concepts](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-core-concepts.html), [gateway tutorial](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-getting-started.html) |
| Microsoft Entra Agent ID | Agent identity lifecycle, ownership, authentication and governance | Agent identities/blueprints within Entra | Exact approved parameter-to-effect binding and target evidence not established here | Sentinel has generic JWT validation, not a validated native Entra lifecycle integration. Integrate with customers' identity rather than replace it | [Agent ID concepts](https://learn.microsoft.com/en-us/entra/agent-id/key-concepts), [documentation](https://learn.microsoft.com/en-us/entra/agent-id/) |
| Auth0 for AI Agents | Authentication, Token Vault, asynchronous human authorization, FGA | Hosted identity platform with SDK integration | Human-in-loop support is documented; equivalent end-to-end outcome proof not established here | Human approval by itself is not unique. Deliver precise scope, independent target observation and reconciliation on top of identity | [Overview](https://auth0.com/ai/docs/intro/overview) |
| Teleport | Workload identities and access to protected infrastructure | Short-lived cryptographic identities, SPIFFE-compatible workload identities | Credential issuance/access audit; exact Sentinel-style lifecycle not established | Sentinel's workload attestation and constrained credential issuance lack real workflow evidence. Integrate with Teleport or cloud identity | [Workload identity](https://goteleport.com/docs/machine-workload-identity/workload-identity/introduction/) |
| Kong AI Gateway | MCP aggregation, routing, access policies, logging and rate limiting | Key/OIDC identity; upstream OAuth/JWT/AWS signing | Tool forwarding/authentication documented; target completion reconciliation not established | Gateway breadth is documented; Sentinel has not measured equivalent interoperability or operating cost. Integrate rather than rebuild routing | [MCP servers](https://developer.konghq.com/ai-gateway/entities/ai-mcp-server/) |
| Palo Alto Prisma AIRS | Runtime API/firewall, model security, red teaming and posture | API integration and network enforcement products | This review does not establish approval-to-remote-effect semantics | Sentinel has no independent detection or external red-team comparison. Avoid broad AI-security superiority claims | [Product documentation](https://docs.paloaltonetworks.com/ai-runtime-security) |
| Check Point AI Guardrails / Lakera | Screen messages, tool interactions, tool descriptions and dangerous actions through Guard API | API integration | Screening signals documented; exact execution receipt/reconciliation not established | Sentinel's curated detector tests cannot establish better protection or false-positive rates. Evaluate as an advisory integration | [API overview](https://docs.lakera.ai/docs/api) |
| Agent Permission Protocol (Crittora), draft v0.4.0 | Proposed execution-time policy verification, capability binding, delegated authority and signed human approval receipts | Protocol proposal and public implementation materials; deployment reliability not tested here | The August 14, 2026 draft specifies approval scope, expiry, revocation and audit evidence; this is direct conceptual overlap | Do not claim policy-bound approval/receipts are unique. Evaluate interoperability and a narrower, independently observed outcome/recovery advantage | [Primary whitepaper](https://agentpermissionprotocol.com/whitepaper/) (accessed 2026-09-18) |
| Proof of Execution research | Proposed runtime verification linking authorization, effect and execution evidence | Research publication; no commercial deployment assessment here | Closely related evidence-lifecycle concept; no claim that the paper or Sentinel proves arbitrary remote outcomes | Assess concrete mechanisms and prior art before claiming exclusive execution-proof differentiation | [Paper](https://arxiv.org/abs/2607.05397) (accessed 2026-09-18) |
| Pomerium MCP gateway | Per-request policy and tool-level access; upstream OAuth discovery, token refresh and delegation | User sessions, external bearer tokens and protected upstream credentials; configurable gateway | Documented tool restrictions and audit support; exact target-state reconciliation not established in this review | Sentinel cannot claim unique delegated MCP access or token isolation. Compare the full protected-change workflow and integrate existing gateways | [MCP reference](https://www.pomerium.com/docs/capabilities/mcp/reference) (accessed 2026-09-19) |
| Customer-built IdP + gateway + Kubernetes admission/audit + SIEM | Customer-specific composed workflow | Existing infrastructure and ownership | Depends on the customer's implementation; no universal deficit assumed | Sentinel must beat actual integration labor and investigation time, not a hypothetical weak DIY system | Comparison must use the design partner's actual configuration and measured workflow |

For every row: operational cost, deployment time, support burden, supported versions and limits need a dated vendor quotation and a matched-workload trial. Documentation is evidence of documented capability, not independently measured reliability. The matrix does not establish an absent feature, freedom to operate, or exclusive differentiation.

## Candidate differentiation to prove

| Outcome | Sentinel evidence today | Evidence needed to establish an advantage |
|---|---|---|
| Exact approved change remains the executed change | Execution binding code; HTTP tests for policy, tenant, parameters and replay | Real Kubernetes preconditions, admitted mutation and independently collected audit/outcome; same workload on alternatives |
| Uncertain remote effects are visible and reconcilable | Durable operation code and post-effect fault tests | Kill network/process/storage at each remote boundary; independently reconcile target state without duplicate writes |
| Coverage does not imply protection of unseen traffic | Tenant coverage counters and explicit unknowns in code | Customer-controlled egress and inventory reconciliation; reproduce bypasses and missing sensors |
| Investigation proof survives Sentinel failure | Receipt/verifier and transparency code | Independently controlled witness/storage, key verification and recovery after primary-domain loss |
| Fast first protected workflow | Packaged console/SDK and API paths | Measure onboarding, interruption rate and analyst time against each customer's existing alternative |

These are positioning hypotheses. No capability is designated unique or market-leading. Current research already describes cryptographic delegation and receiver-attested action receipts: [authenticated delegation (2025)](https://arxiv.org/abs/2501.09674), [receiver-attested receipts (2026)](https://arxiv.org/abs/2606.04193). Product advantage must come from demonstrated end-to-end outcomes and operating quality.

## 2026-09-20: gaps narrowed by implementation, and gaps that implementation cannot close

| Gap named on 2026-09-19 | State now | Who is still ahead, and why |
|---|---|---|
| Agent and workload identity | Sentinel CONSUMES SPIFFE JWT-SVIDs and pod-bound Kubernetes tokens and can refuse API keys on the agent path | Entra Agent ID, Teleport and Auth0 ISSUE and manage identities, rotate keys and govern lifecycle. Sentinel does not and should not; it has not yet been integrated with any of them |
| Credential brokering | Per-operation Kubernetes TokenRequest credentials behind a broker that can change nothing | Auth0 Token Vault, Pomerium and Teleport broker credentials for many upstreams. Sentinel does it for one target type |
| Approval workflow depth | Redacted change view, quorum, separation of duties, stale-approval refusal | ITSM and Auth0 asynchronous authorization integrate with paging, ticketing and mobile approval. Sentinel has a console and an API |
| Automatic reconciliation | Implemented for Kubernetes | Not established for any reviewed alternative; also not established for any other Sentinel tool |
| Gateway breadth and operations | Guarded incremental relay of MCP progress notifications added, off by default; otherwise unchanged | Kong and AWS AgentCore: managed operation, full streaming transports, measured scale |
| Threat detection | A blind-evaluation protocol exists; no corpus has been sealed | Prisma AIRS and Lakera: dedicated detection products with independent evaluation |
| Proof and trust | Image gate passes locally; offline evidence verifier | Every funded competitor: customers, assessments, attestations, cloud deployments |
| Distribution | Unchanged | All of them |

The first four rows were engineering gaps and are now engineering claims that need a customer to become evidence. The last four are not closable from a repository: they need an operated service, an outside evaluator, an assessor and paying customers.

## 2026-09-20 (second pass): what remains after the buildable gaps

| Remaining gap | Why a repository cannot close it | What would |
|---|---|---|
| Identity lifecycle (issue, govern, rotate agent identities) | Sentinel consumes identities by design; Entra, Okta, Auth0, Teleport and SPIRE issue them | A documented, tested integration with one of them at a design partner |
| Credential brokering beyond Kubernetes | Each target needs its own constrained-credential mechanism (AWS STS session policies, GitHub App installation tokens) | Building the one the first customer's workflow needs, not all of them |
| Managed gateway operations and full streaming transports | Requires operating a service. Guarded relay of progress and log notifications exists (2026-09-20, scripted upstreams only); server-initiated requests and the standalone GET stream are refused by design, so a server that depends on sampling or elicitation does not work through the proxy | An operated service, a run against third-party MCP servers, or integration behind Kong or AgentCore |
| Independent detection evidence | The protocol exists; a corpus must come from someone outside | An outside assembler sealing a corpus |
| Proof and trust | Customers, assessors and auditors are people | A paid pilot, a contracted assessment, an applied cloud environment |
| Distribution | Marketplaces and partners are commercial agreements | Them |

## 2026-09-20 (third pass)

Credential brokering now covers three targets, each with the mechanism that target offers: Kubernetes TokenRequest, AWS STS role sessions, GitHub App installation tokens. Only the Kubernetes path has met its real service. Auth0 Token Vault, Pomerium and Teleport remain ahead on breadth, maturity and operation. Agent identity can be consumed from any issuer that publishes OIDC metadata, including SPIRE's discovery provider; issuing and governing identities remains Entra's, Okta's and SPIRE's job. What is left is what a repository cannot produce: an operated service, an outside evaluator's corpus, an assessor's report, and customers. `PILOT_KIT.md` is the procedure for the last of those.

