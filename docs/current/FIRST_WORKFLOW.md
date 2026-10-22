# First workflow: agent-driven infrastructure change with just-in-time approval

The approved starting scope is a human-approved Kubernetes infrastructure change for midmarket B2B SaaS and fintech-infrastructure platform teams. Only local development and GitHub are authorized environments. No customer enforcement onboarding or cloud deployment is approved by this program yet.

The intended customer promise is that verified identity, delegated authority, approved scope, an enforceable tool path, observed outcome and durable verifiable evidence agree. Current repository tests establish parts of this contract; workload identity, constrained short-lived credentials, customer-controlled egress and remote Kubernetes outcome verification remain acceptance gates.

Pre-effect checks can prevent execution. A target may change state before a timeout or an evidence-store failure: Sentinel must then report an uncertain outcome and reconcile it, rather than claim the action did not run. A single-use authorization is not an exactly-once guarantee for arbitrary remote APIs.

## Implemented API journey and remaining validation

| # | Step | Enforced by | Evidence produced | Test that proves it |
|---|---|---|---|---|
| 1 | The agent's runtime asks Sentinel before acting: `POST /v1/protect/evaluate` with agent, tool, action, resource and parameters, over a bearer key scoped to a tenant | `sentinel/interface/authorizations.py`, `sentinel/application/protect_gate.py` | `security_audit` row `protect.evaluate`; an `authorizations` row with the parameter digest and the active policy digest | `tests_arch/test_execution_contract.py` |
| 2 | Policy decides. `allow` issues an active authorization; `require_approval` issues a pending one; `block` issues none | deterministic policy `config/default_policy.json` plus tenant policy versions | the decision in the response, with `enforced` stated | `tests_arch/test_execution_contract.py::test_a_blocked_action_issues_no_authorization` |
| 3 | A human decides in the authorization inbox: `GET /v1/authorizations` shows digests, never parameter values or tokens; `POST /v1/authorizations/{id}/decide` approves or rejects; `POST .../revoke` is the emergency deny from any state | `sentinel/interface/authorizations.py`; capabilities `DECIDE_APPROVAL`, `MANAGE_POLICY` | audited decision with actor and reason; `approved_by` on the authorization | `test_approval_flow_evaluate_pending_approve_execute`, `test_an_emergency_revocation_voids_an_active_authorization` |
| 4 | The runtime redeems the authorization: `POST /v1/tools/execute` with the token and the same agent, tool, action, resource and parameters | `sentinel/application/tool_runner.py::execute_bound`, `verify_binding`, single-use nonce ledger | a `refused` operation on any substitution, replay, expiry, revocation or policy change; nothing runs | the substitution, replay, expiry and policy-change cases in `tests_arch/test_execution_contract.py` |
| 5 | Intent is written before the effect; the tool runs through Sentinel's proxy with the approved parameters only | `SqlOperationStore.begin`, `ToolProxy` registered side effects | `execution_operations` row in `pending` with `started_at` from the clock | `tests_arch/test_operation_store.py::test_timestamps_come_from_the_clock_at_each_event` |
| 6 | Outcome is written after the effect: receipt plus terminal state. A storage failure after the effect becomes `unknown_after_effect`, listed for reconciliation, never a silent error | `execute_bound`, `MaintenanceLoop`, `POST /v1/executions/operations/{id}/reconcile` | `execution_receipts` row, operation `succeeded`/`failed`/`unknown_after_effect` | `test_a_storage_failure_after_the_effect_is_an_unknown_outcome` |
| 7 | The receipt and the Execution Passport are exported to the tenant's SIEM and verifiable with the tenant's own copy of the verifier | `sentinel/infrastructure/siem.py`, `standard/execution-passport-v1/verify_passport.py` | SIEM record with receipt id, operation id, digests | `tests_arch/test_passport_standard.py`, `tests_arch/test_tenant_integrations.py` |
| 8 | Coverage is reviewed weekly: what was observed, what was routed, what was enforced, what is unknown | `GET /v1/coverage` | the four counts per tenant, never one percentage | `test_same_named_agents_in_two_tenants_have_separate_budgets` |

## Onboarding ladder for a design partner

1. **Observe (week 1).** `SENTINEL_PROTECT_ENFORCE=false`. The runtime calls
   evaluate before every tool call; evaluation reports advisory decisions. Bound execution still checks authorization, replay, expiry and containment, so observe mode does not mean every execution is permitted. Success: `observed_traffic` in
   `/v1/coverage` matches the tenant's own count of agent tool calls.
2. **Route (week 2).** The one approved Kubernetes tool and namespace are registered as proxied side
   effects and the runtime redeems authorizations for them.
   Success: `routed_executions.bound_operations` for those tools equals their
   observed calls.
3. **Enforce (week 3 onward).** `SENTINEL_PROTECT_ENFORCE=true` for the deployment (this is a deployment setting, not a tenant-specific switch), with `SENTINEL_REQUIRE_EXECUTION_BINDING=true` (the default).

## What is now in the workflow (2026-09-20), and how far each is proven

| Control | What exists | Proven by | Not proven |
|---|---|---|---|
| Workload identity | SPIFFE JWT-SVIDs and pod-bound Kubernetes tokens; `SENTINEL_REQUIRE_WORKLOAD_IDENTITY` refuses API keys on the agent path | `tests_arch/test_workload_identity.py`; a token signed by a real local cluster in `tests_arch/test_protected_change_journey.py` | A customer issuer, key rotation, SPIRE Workload API. Off by default (FCX-006, RISK R-016) |
| Constrained credentials | Sentinel holds a broker token that can only mint a ten-minute token for one executor account, per operation | `tests_arch/test_kubernetes_outcome.py`; the journey test | Cloud IAM equivalents; token theft within its ten minutes is bounded by RBAC, not prevented |
| Bypass prevention | `deploy/protected-changes/`: the API server refuses agent writes and unstamped executor writes in labelled namespaces | the journey test, including an agent that holds a mistaken `edit` grant | An enforcing CNI, the DELETE gap, non-Kubernetes targets (RISK R-017) |
| Approval experience | Redacted structural change view, impact tier, rule, time left, approver list; quorum; requester may not approve; console "Agent requests" view | `tests_arch/test_approval_experience.py`; `tests_arch/test_console_bundle.py` | A usability test with a real approver; ticketing or paging integration |
| Automatic reconciliation | Field-manager correlation and a read-only reconciler for Kubernetes, bounded and quiescent | `tests_arch/test_kubernetes_outcome.py`; a lost response settled against the real API server in the journey test | Any other tool (RISK R-012) |
| Independent evidence | Receipts committed to the transparency log; offline bundle verifier with a trusted-root check | `tests_arch/test_evidence_commitments.py` | A root held outside the environment and a restore that uses it (RISK R-018, R-003) |
| Measurement | `GET /v1/workflow/metrics` | `tests_arch/test_workflow_metrics.py` | Any customer number |

## What this workflow still does not include

- A deployed proof beyond one local node. `scripts/run_deployed_journey.py`
  runs the whole chain with two Sentinel pods in production mode, a pod-bound
  agent identity, admission and network policy both refusing bypass, and
  offline evidence verification. It has not run on a cloud cluster, another
  CNI, with TLS between agent and Sentinel, or for a customer.
- Time-boxed approval windows shorter than the authorization TTL, or approval
  through an external ticketing system.
- Reconciliation beyond Kubernetes and GitHub contents; AWS mutations and GitHub POSTs still need a human.
- Any workflow other than this one. Detection, MCP gateway and A2A
  capabilities exist and are tested, and are not part of this release's
  promise.

## Console

The wheel now includes the console HTML, JavaScript and CSS, and the clean-install smoke requests all three over HTTP. Asset delivery does not prove the complete operator journey. The "Agent requests" view now shows each pending request as a card with the redacted change, impact, rule, time left and approvers, with approve and reject, and lists operations automatic reconciliation could not settle. It is covered by the bundle tests, not by a usability test with a real approver; that must happen before pilot acceptance.

## Pilot measures and entry conditions

Before customer enforcement, Phase 1 distribution and Phase 2 execution gates must pass on one identified release. Record onboarding elapsed time and support hours, routed and enforced tool counts separately, coverage gaps, approval latency, false interruptions with adjudicated denominators, uncertain operations and reconciliation time, and gateway overhead for a specified workload. Provisional cohort: three paid design partners completing the same workflow; this is a proposed success criterion, not evidence of customers or revenue. No outreach or paid engagement has been performed by this program.

## Kubernetes existing-object change contract

For an update, read the target and include its metadata.name, namespace, uid and nonzero resourceVersion in the desired body. For a deletion, include the observed uid and resourceVersion under body.preconditions. Both fields are part of the approved parameter digest. A concurrent write or object replacement requires a fresh read and approval; never substitute a new version into an old authorization. Strip server-owned managedFields/status rather than echoing an entire GET response as desired state.

The local opt-in tests use a real Kubernetes API and temporary namespaced credentials for ConfigMaps. They do not establish cloud deployment, production IdP integration or convergence of a Deployment. API acceptance and independently observed final workload state remain different evidence levels. A conflict after invocation is conservatively recorded as unknown_after_effect for human reconciliation; automatic target reconciliation remains open.
