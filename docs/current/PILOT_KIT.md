# Pilot kit: the first protected change at a design partner

This is the procedure a design partner follows. Every step names the artifact
it uses and the observation that proves it worked. The steps close, with the
partner's own evidence, the gaps no repository can close: a real identity
provider, a real cluster and network plugin, a root held outside the
environment, and measured numbers.

**Scope:** one workflow, agent-driven Kubernetes changes in one namespace.
**Duration:** three weeks. **People:** one platform engineer, one approver,
one security reviewer at the partner; one engineer from Sentinel.

## Week 0: entry conditions (do not start without these)

| Condition | How it is checked |
|---|---|
| The release passes CI, including `release-hygiene` and `docker` | A green run on the release commit. RISK R-019 must be closed first |
| The image is the scanned one | The digest in the scan report equals the digest deployed |
| Kubernetes 1.30 or later, and a network plugin that enforces NetworkPolicy | `kubectl version`; the partner names their CNI |
| The partner's agent runs as a pod with its own service account | `kubectl get pod <agent> -o jsonpath='{.spec.serviceAccountName}'` |

## Week 1: observe

1. Deploy Sentinel with the Helm chart, `SENTINEL_PROTECT_ENFORCE=false`.
2. Register the agent's identity. For a cluster issuer that publishes OIDC
   metadata, one entry in `SENTINEL_AGENT_IDP_JSON` with `"kind": "kubernetes"`,
   `"discover": true` and the agent namespace in `allowed_namespaces`.
   Otherwise pin the JWKS from `kubectl get --raw /openid/v1/jwks`.
3. The agent mounts a projected token with Sentinel's audience and calls
   `POST /v1/protect/evaluate` before each change.
4. **Observe:** `GET /v1/coverage` `observed_traffic` matches the partner's
   own count of agent changes for the week. If it does not, stop: something
   bypasses Sentinel and week 2 would measure the wrong thing.

## Week 2: route and protect

1. Apply `deploy/protected-changes/rbac.yaml`, edited for the partner's
   namespaces. Give Sentinel the broker service account and set
   `SENTINEL_KUBERNETES_EXECUTOR_SERVICE_ACCOUNT`, `_EXECUTOR_NAMESPACE` and
   `SENTINEL_KUBERNETES_CA_FILE`.
2. Apply `deploy/protected-changes/admission-policy.yaml`, then label the
   namespace `sentinel.io/protected-changes=true`. **In this order**, or the
   executor's own writes are refused.
3. Apply the agent egress NetworkPolicy from `deploy/agent-egress/`.
4. Set `SENTINEL_REQUIRE_WORKLOAD_IDENTITY=true`.
5. **Observe, and record each as evidence:**
   - from the agent pod, a direct `kubectl patch` of a protected object is
     refused by admission;
   - from the agent pod, a TCP connection to the API server does not open;
   - a change requested through Sentinel reaches the approver's inbox with the
     redacted change, is approved by someone other than the requester, runs,
     and appears in the object's `managedFields` under `sentinel-op-...`;
   - `GET /v1/coverage` `routed_executions` equals observed changes.

## Week 3: enforce and measure

1. Set `SENTINEL_PROTECT_ENFORCE=true` and `SENTINEL_PROTECTION_MODE=protect`.
2. The partner's security reviewer, on a machine Sentinel's operator cannot
   reach, schedules
   `python witness_root.py https://<sentinel> --token-file <viewer token> --witness-file roots.jsonl`
   hourly. **This file is the evidence that closes RISK R-018.**
3. At the end of the week the reviewer exports a bundle
   (`GET /v1/evidence/export`) and runs `verify_evidence_bundle.py` against a
   root from their own witness file.
4. Pull `GET /v1/workflow/metrics?days=7`. Onboarding hours, support hours
   and whether each refusal was legitimate come from the engagement log and
   the partner's review, not from Sentinel.

## Exit: what the partner signs

A one-page statement, in their words, of: the numbers from step 4; any change
that was refused and should not have been; any change that ran and should not
have; any outcome that stayed unknown and how long it took to settle; and
whether they will keep it on.

## What to stop for

An unexplained gap between observed and routed changes; an approval that was
recorded by the requester; a witness run that exits 1; an `unknown_after_effect`
operation older than a day. Each is a finding against Sentinel first and the
deployment second, and goes into `STATUS.md` the same day.
