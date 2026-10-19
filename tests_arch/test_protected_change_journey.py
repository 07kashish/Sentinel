"""One protected change, end to end, against a REAL Kubernetes API server.

Opt-in: SENTINEL_TEST_KUBECONFIG must name the dedicated loopback kind cluster.
Everything a customer journey needs runs together here, in one test:

  workload identity      the agent authenticates with a pod-less projected
                         service-account token the CLUSTER signed, verified
                         against the cluster's own JWKS; an API key is refused
  bypass prevention      the agent's own credential is refused by the API
                         server (admission policy), as is the executor identity
                         used by hand without an operation stamp
  approval               a second human sees the redacted change and approves
  constrained credential Sentinel holds only a broker token; the change runs
                         under a ten-minute token minted for that operation
  exact change           the approved object version is the one changed
  target correlation     the cluster records the operation's field manager
  reconciliation         a change whose response is lost is settled from the
                         target, without a human and without a second write

What it is NOT: deployed Sentinel pods, a CNI, an IdP, or a customer. The
application runs in-process; the cluster, its admission control, its RBAC, its
token issuer and its API are real.
"""

from __future__ import annotations

import base64
import json
import os
import ssl
import subprocess
import uuid
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import yaml

from sentinel.infrastructure.outbound import HardenedHttpClient, OutboundPolicy
from sentinel.infrastructure.platforms.kubernetes import KubernetesCredentials, kubernetes_api_adapter
from sentinel.infrastructure.platforms.kubernetes_outcome import field_manager
from tests_arch.test_execution_contract import ADMIN, ANALYST, INGEST, _h, _make

ROOT = Path(__file__).resolve().parents[1]
AUDIENCE = "https://sentinel.local.test"


class _LossyClient:
    """The real hardened client, able to lose ONE response after it arrived."""

    def __init__(self, real: HardenedHttpClient) -> None:
        self.real = real
        self.lose_next_put = False

    def request(self, **kwargs):
        response = self.real.request(**kwargs)
        if self.lose_next_put and kwargs["method"] == "PUT":
            self.lose_next_put = False
            raise ConnectionResetError("response lost after the write was admitted")
        return response


class _Kubectl:
    def __init__(self, config: str) -> None:
        self.base = ["kubectl", "--kubeconfig", config, "--context", "kind-sentinel-local-pilot"]

    def __call__(self, *args: str, data: object = None, ok: bool = True) -> str:
        result = subprocess.run([*self.base, *args], text=True, capture_output=True, timeout=90, check=False,
                                input=(data if isinstance(data, str) else json.dumps(data)) if data else None)
        if ok and result.returncode:
            pytest.fail(f"local Kubernetes fixture command failed: kubectl {args[0]} (output withheld)")
        return result.stdout.strip() if ok else f"{result.returncode}:{result.stdout.strip()} {result.stderr.strip()}"


@pytest.fixture
def world():
    config = os.environ.get("SENTINEL_TEST_KUBECONFIG")
    if not config:
        pytest.skip("dedicated local kind cluster not configured; the deployed journey is UNVERIFIED")
    k = _Kubectl(config)
    view = json.loads(k("config", "view", "--minify", "-o", "json"))
    server = view["clusters"][0]["cluster"]["server"]
    host = urlsplit(server).hostname
    assert host in ("127.0.0.1", "localhost", "::1"), "refuse a nonlocal Kubernetes API"
    suffix = uuid.uuid4().hex[:8]
    names = {"sentinel": f"sj-sentinel-{suffix}", "agents": f"sj-agents-{suffix}", "prod": f"sj-prod-{suffix}"}
    for namespace in names.values():
        k("create", "namespace", namespace)
    try:
        k("label", "namespace", names["prod"], "sentinel.io/protected-changes=true")
        k("-n", names["agents"], "create", "serviceaccount", "infra-writer")
        rbac = (ROOT / "deploy/protected-changes/rbac.yaml").read_text(encoding="utf-8")
        policy = (ROOT / "deploy/protected-changes/admission-policy.yaml").read_text(encoding="utf-8")
        # The shipped manifests, re-pointed at this run's throwaway namespaces.
        for text in (rbac, policy):
            rendered = (text.replace("namespace: sentinel", f"namespace: {names['sentinel']}")
                            .replace("namespace: prod", f"namespace: {names['prod']}")
                            .replace('agentNamespaces: "agents"', f'agentNamespaces: "{names["agents"]}"')
                            .replace("system:serviceaccount:sentinel:", f"system:serviceaccount:{names['sentinel']}:")
                            .replace("system:serviceaccounts:agents", f"system:serviceaccounts:{names['agents']}")
                            .replace("name: sentinel-protected-changes", f"name: sentinel-protected-changes-{suffix}")
                            .replace("policyName: sentinel-protected-changes", f"policyName: sentinel-protected-changes-{suffix}"))
            k("apply", "-f", "-", data=rendered)
        # An agent that ALSO holds a mistaken write grant: admission must still refuse it.
        k("-n", names["prod"], "create", "rolebinding", "mistake", "--clusterrole=edit",
          f"--serviceaccount={names['agents']}:infra-writer")
        k("-n", names["prod"], "create", "configmap", "app", "--from-literal=flag=off")
        ca = base64.b64decode(k("config", "view", "--raw", "--minify", "-o",
                                "jsonpath={.clusters[0].cluster.certificate-authority-data}")).decode()
        client = _LossyClient(HardenedHttpClient(ssl_context=ssl.create_default_context(cadata=ca), policy=OutboundPolicy(
            allowed_hosts=frozenset({host}), allow_private_destinations=True, read_timeout_seconds=10)))
        yield {"k": k, "names": names, "server": server, "client": client, "suffix": suffix}
    finally:
        for kind in ("validatingadmissionpolicybinding", "validatingadmissionpolicy"):
            k("delete", kind, f"sentinel-protected-changes-{suffix}", "--ignore-not-found", ok=False)
        for namespace in names.values():
            k("delete", "namespace", namespace, "--wait=false", ok=False)


def _wait_for_admission(k: _Kubectl, names: dict) -> None:
    """A new policy takes a moment to be enforced; poll with the agent's write."""
    import time

    for _ in range(40):
        verdict = k("-n", names["prod"], "create", "configmap", f"probe-{uuid.uuid4().hex[:6]}",
                    f"--as=system:serviceaccount:{names['agents']}:infra-writer", ok=False)
        if "protected changes" in verdict:
            return
        time.sleep(0.5)
    pytest.fail("the admission policy never started refusing the agent's direct write")


def test_one_protected_change_end_to_end(world, tmp_path, engine_config, monkeypatch):
    k, names, server, client = world["k"], world["names"], world["server"], world["client"]
    agent_subject = f"system:serviceaccount:{names['agents']}:infra-writer"

    # ── Workload identity, signed by the cluster ────────────────────────────
    issuer = json.loads(k("get", "--raw", "/.well-known/openid-configuration"))["issuer"]
    jwks = json.loads(k("get", "--raw", "/openid/v1/jwks"))
    registration = json.dumps([{
        "name": "local-cluster", "kind": "kubernetes", "issuer": issuer, "audience": AUDIENCE,
        "tenant": "acme", "jwks": jwks, "allowed_namespaces": [names["agents"]],
        # `kubectl create token` issues a token for the account, not a pod.
        # A deployed agent presents its projected, pod-bound token instead.
        "require_pod_binding": False,
    }])
    harness = _make(tmp_path, engine_config, monkeypatch, enforce=True,
                    SENTINEL_AGENT_IDP_JSON=registration, SENTINEL_REQUIRE_WORKLOAD_IDENTITY="true")
    try:
        agent_token = k("-n", names["agents"], "create", "token", "infra-writer",
                        f"--audience={AUDIENCE}", "--duration=10m")
        agent = {"Authorization": f"Bearer {agent_token}"}

        # ── Constrained credentials: Sentinel holds a broker, nothing more ──
        broker = k("-n", names["sentinel"], "create", "token", "sentinel-broker", "--duration=10m")
        assert "no" in k("auth", "can-i", "update", "configmaps", "-n", names["prod"],
                         f"--as=system:serviceaccount:{names['sentinel']}:sentinel-broker", ok=False)
        harness.container.tool_proxy.register(kubernetes_api_adapter(
            client=client, ceiling="high",
            credentials=KubernetesCredentials(server, broker, executor_service_account="sentinel-executor",
                                              executor_namespace=names["sentinel"]),
        ))

        # ── Bypass prevention, enforced by the API server itself ────────────
        _wait_for_admission(k, names)
        direct = k("-n", names["prod"], "patch", "configmap", "app", "-p", '{"data":{"flag":"bypassed"}}',
                   f"--as={agent_subject}", ok=False)
        assert "may not change this namespace directly" in direct, direct
        # The executor holds `update`, so RBAC lets this PUT through; admission
        # refuses it because no operation stands behind it.
        current = json.loads(k("-n", names["prod"], "get", "configmap", "app", "-o", "json"))
        current["data"] = {"flag": "by-hand"}
        by_hand = k("-n", names["prod"], "replace", "-f", "-", f"--as=system:serviceaccount:{names['sentinel']}:sentinel-executor", data=current, ok=False)
        assert "operation stamp" in by_hand, by_hand

        observed = json.loads(k("-n", names["prod"], "get", "configmap", "app", "-o", "json"))
        assert observed["data"] == {"flag": "off"}
        body = {"apiVersion": "v1", "kind": "ConfigMap", "data": {"flag": "on"}, "metadata": {
            key: observed["metadata"][key] for key in ("name", "namespace", "uid", "resourceVersion")}}
        request = {"agentId": agent_subject, "tool": "kubernetes_api", "action": "update",
                   "resource": f"/needs-approval/namespaces/{names['prod']}/configmaps/app",
                   "arguments": {"verb": "update", "kind": "configmap", "namespace": names["prod"],
                                 "name": "app", "body": body}}

        # ── An API key cannot be this agent ─────────────────────────────────
        assert harness.client.post("/v1/protect/evaluate", json=request, headers=_h(INGEST)).status_code == 403

        # ── Evaluate as the attested workload; a human sees the change ──────
        gate = harness.client.post("/v1/protect/evaluate", json=request, headers=agent)
        assert gate.status_code == 200, gate.text
        auth = gate.json()["authorization"]
        assert auth["state"] == "pending_approval"
        entry = harness.client.get(f"/v1/authorizations/{auth['authorization_id']}", headers=_h(ANALYST)).json()
        assert entry["change"]["headline"] == f"update configmap {names['prod']}/app"
        assert entry["change"]["target_precondition"]["uid"] == observed["metadata"]["uid"]
        assert entry["agent"] == agent_subject
        decided = harness.client.post(f"/v1/authorizations/{auth['authorization_id']}/decide",
                                      json={"decision": "approve", "reason": "reviewed the flag change"},
                                      headers=_h(ANALYST))
        assert decided.status_code == 200, decided.text

        # ── Execute: minted credential, exact version, stamped target ───────
        ran = harness.client.post("/v1/tools/execute", json=dict(request, authorization=auth["token"]), headers=agent)
        assert ran.status_code == 200, ran.text
        assert ran.json()["result"]["credential"]["mode"] == "token_request"
        assert broker not in ran.text
        after = json.loads(k("-n", names["prod"], "get", "configmap", "app", "-o", "json", "--show-managed-fields"))
        assert after["data"] == {"flag": "on"} and after["metadata"]["uid"] == observed["metadata"]["uid"]
        operations = harness.client.get("/v1/executions/operations?state=succeeded", headers=_h(ANALYST)).json()
        operation_id = operations["operations"][0]["operation_id"]
        managers = {m["manager"] for m in after["metadata"]["managedFields"]}
        assert field_manager(operation_id) in managers, "the cluster does not attribute the change to the operation"

        # ── A lost response is settled from the target, by nobody ───────────
        second = dict(body, data={"flag": "again"}, metadata={
            **body["metadata"], "resourceVersion": after["metadata"]["resourceVersion"]})
        request2 = dict(request, arguments=dict(request["arguments"], body=second))
        auth2 = harness.client.post("/v1/protect/evaluate", json=request2, headers=agent).json()["authorization"]
        harness.client.post(f"/v1/authorizations/{auth2['authorization_id']}/decide",
                            json={"decision": "approve", "reason": "second change"}, headers=_h(ADMIN))
        client.lose_next_put = True
        lost = harness.client.post("/v1/tools/execute", json=dict(request2, authorization=auth2["token"]), headers=agent)
        assert lost.status_code == 500 and lost.json()["detail"]["outcome"] == "unknown_after_effect"
        now = harness.clock.now().value + timedelta(seconds=5)
        totals = harness.container.operation_reconciler.run("acme", now=now)
        assert totals["succeeded"] == 1, totals
        settled = harness.client.get(f"/v1/executions/operations/{lost.json()['detail']['operation_id']}",
                                     headers=_h(ANALYST)).json()
        assert settled["state"] == "succeeded" and settled["reconciled_by"] == "reconciler:kubernetes_api"
        final = json.loads(k("-n", names["prod"], "get", "configmap", "app", "-o", "json"))
        assert final["data"] == {"flag": "again"}

        # ── A protected delete: by hand refused, through Sentinel admitted ──
        by_hand_delete = k("-n", names["prod"], "delete", "configmap", "app",
                           f"--as=system:serviceaccount:{names['sentinel']}:sentinel-executor", ok=False)
        assert "operation stamp" in by_hand_delete, by_hand_delete
        removal = dict(request, action="delete", arguments={
            "verb": "delete", "kind": "configmap", "namespace": names["prod"], "name": "app",
            "body": {"preconditions": {key: final["metadata"][key] for key in ("uid", "resourceVersion")}}})
        auth3 = harness.client.post("/v1/protect/evaluate", json=removal, headers=agent).json()["authorization"]
        harness.client.post(f"/v1/authorizations/{auth3['authorization_id']}/decide",
                            json={"decision": "approve", "reason": "retire the flag"}, headers=_h(ADMIN))
        deleted = harness.client.post("/v1/tools/execute", json=dict(removal, authorization=auth3["token"]), headers=agent)
        assert deleted.status_code == 200, deleted.text
        assert "NotFound" in k("-n", names["prod"], "get", "configmap", "app", ok=False)
    finally:
        harness.container.close()


def test_the_shipped_manifests_are_the_ones_applied():
    """The journey renders the shipped files; it must not carry its own copy."""
    documents = list(yaml.safe_load_all((ROOT / "deploy/protected-changes/admission-policy.yaml").read_text()))
    assert {d["kind"] for d in documents if d} == {
        "ConfigMap", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"}
