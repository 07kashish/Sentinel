# Protect enforcement beyond in-product controls (F-11)

**Status:** CLOSED under the documented deployment-contract bar —
non-enrolled / silent / off-SDK agents are detectably or preventably fail-closed
when operators apply the in-repo contract. Wire-level OS transparent intercept is
**not claimed** and remains out of scope by architecture decision.

## Closing statement (gate bar)

Under `deploy/agent-egress/` + SDK enrollment checks + pageable silence:

- **Preventably fail-closed:** agent pods without `sentinel.io/enrolled=true`
  get default-deny egress (no allowlist); ValidatingAdmissionPolicy (Fail/Deny)
  rejects agent pods missing required labels/tool-path; SDK
  `InterceptedToolClient` refuses empty/unenrolled `agent_id`; egress-proxy
  stub denies all upstream when Sentinel `/health/live` is unreachable.
- **Detectably fail-closed:** enrolled agents that go silent raise pageable
  `possible_bypass` on `GET /v1/protect/bypass-signals`.

Bypass then requires breaking the deployment contract (disable admission,
omit NetworkPolicy, run unlabeled processes outside enrolled namespaces). That
is an operator choice, not an in-product gap for this gate.

## What Sentinel can see

- `POST /v1/events` (admission)
- `POST /v1/tools/execute` (inline tool proxy)
- SDK `InterceptedToolClient` when agents are built to use it
- Enrolled-agent silence → pageable `possible_bypass` via `GET /v1/protect/bypass-signals`

## What Sentinel cannot see

**Sentinel cannot see traffic that bypasses this.** Any process outside the
contract (no labels, no admission binding, no SDK/proxy) is outside the product
observation window. The contract makes that an explicit operator breach.

## Deployment contract (primary, in-repo)

| Artifact | Role |
|---|---|
| `deploy/agent-egress/networkpolicy.yaml` | Default-deny for `role=agent`; egress allowlist only for `role=agent` + `enrolled=true` (DNS + Sentinel) |
| `deploy/agent-egress/networkpolicy-enrolled.yaml` | Alias of enrolled allowlist selector |
| `deploy/agent-egress/admission/validating-admission-policy.yaml` | Fail/Deny unless enrolled + `sentinel.io/tool-path` ∈ {sdk, execute, egress-proxy} |
| `deploy/agent-egress/egress-proxy/fail_closed_proxy.py` | Sidecar stub: deny upstream when Sentinel unhealthy; Sentinel host allowlist |
| `deploy/agent-egress/example-enrolled-agent.yaml` | Reference enrolled agent + proxy sidecar |
| `tests_arch/test_security_bypass_detection.py` | Manifests + admission + proxy + silence + SDK refuse |

### SDK enrollment

`InterceptedToolClient` defaults to `require_enrolled=True`:

- empty `agent_id` → `InterceptorMisuse` (fail closed)
- optional `is_enrolled(agent_id)` predicate → refuse unenrolled agents

### Runtime signal

`SENTINEL_BYPASS_IDLE_SECONDS` (default 900). Enrolled agents with no observed
events for that window produce `kind=possible_bypass` with:

- `severity=page`, `pageable=true`
- `zero_observed_calls` when `last_event_at` is null
- `sla_seconds`, `agent_label`, and `recommended_action` for on-call

Newly enrolled agents do not alert until they have been enrolled at least that long.

## Not claimed

Transparent host/OS wire interception, eBPF forced redirect, or seeing processes
that never run under the contract. Those remain out of product scope.
