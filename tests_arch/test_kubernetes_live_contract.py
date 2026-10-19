"""Real local Kubernetes effects through the HTTP approval/binding contract.

Opt-in only: SENTINEL_TEST_KUBECONFIG must name the dedicated loopback kind
cluster created by this program. Uses a ten-minute namespaced service account
token generated for each test, never an existing customer credential. API
authentication/approval use the local contract harness; this is not IdP proof.
"""
from __future__ import annotations

import base64
import copy
import json
import os
import ssl
import subprocess
from urllib.parse import urlsplit
import uuid

import pytest

from sentinel.infrastructure.outbound import HardenedHttpClient, OutboundPolicy
from sentinel.infrastructure.platforms.kubernetes import KubernetesCredentials, kubernetes_api_adapter
from tests_arch.test_execution_contract import _make, _h, INGEST, ANALYST


@pytest.fixture
def cluster():
    config = os.environ.get("SENTINEL_TEST_KUBECONFIG")
    if not config:
        pytest.skip("dedicated local kind cluster not configured; real Kubernetes effects UNVERIFIED")
    cli = ["kubectl", "--kubeconfig", config, "--context", "kind-sentinel-local-pilot"]

    def run(*args, data=None):
        result = subprocess.run([*cli, *args], input=json.dumps(data) if data else None,
                                text=True, capture_output=True, timeout=60, check=False)
        if result.returncode:
            pytest.fail("local Kubernetes fixture command failed (output withheld)")
        return result.stdout.strip()

    config_data = json.loads(run("config", "view", "--minify", "-o", "json"))
    server = config_data["clusters"][0]["cluster"]["server"]
    host = urlsplit(server).hostname
    assert host in ("127.0.0.1", "localhost", "::1"), "refuse nonlocal Kubernetes API"
    nodes = json.loads(run("get", "nodes", "-o", "json"))["items"]
    assert nodes and all(n["metadata"]["name"].startswith("sentinel-local-pilot-") for n in nodes)
    ns = "sentinel-contract-" + uuid.uuid4().hex[:12]
    run("create", "namespace", ns)
    try:
        run("-n", ns, "create", "serviceaccount", "actor")
        run("-n", ns, "apply", "-f", "-", data={"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
            "metadata": {"name": "actor"}, "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                "verbs": ["get", "create", "update", "delete"]}]})
        run("-n", ns, "create", "rolebinding", "actor", "--role=actor", "--serviceaccount=" + ns + ":actor")
        token = run("-n", ns, "create", "token", "actor", "--duration=10m")
        ca = run("config", "view", "--raw", "--minify", "-o",
                 "jsonpath={.clusters[0].cluster.certificate-authority-data}")
        tls = ssl.create_default_context(cadata=base64.b64decode(ca).decode())
        client = HardenedHttpClient(ssl_context=tls, policy=OutboundPolicy(
            allowed_hosts=frozenset({host}), allow_private_destinations=True, read_timeout_seconds=10))
        adapter = kubernetes_api_adapter(client=client, credentials=KubernetesCredentials(server, token), ceiling="high")

        def invoke(verb, body=None):
            return adapter.runner({"verb": verb, "kind": "configmap", "namespace": ns,
                                   **({"name": "needs-approval"} if verb != "create" else {}),
                                   **({"body": body} if body is not None else {})})["body"]

        invoke("create", {"apiVersion": "v1", "kind": "ConfigMap",
                          "metadata": {"name": "needs-approval", "namespace": ns}, "data": {"value": "initial"}})
        yield ns, adapter, invoke
    finally:
        # Only the random namespace just created here is removed. No existing
        # namespace, cluster, customer object or persistent volume is touched.
        run("delete", "namespace", ns, "--wait=false")


@pytest.fixture
def live_harness(cluster, tmp_path, engine_config, monkeypatch):
    h = _make(tmp_path, engine_config, monkeypatch, enforce=True)
    h.container.tool_proxy.register(cluster[1])
    try:
        yield h
    finally:
        h.container.close()


def payload(ns, body, verb="update"):
    return {"agentId": "agent-1", "tool": "kubernetes_api", "action": verb,
            "resource": f"/api/v1/namespaces/{ns}/configmaps/needs-approval",
            "arguments": {"verb": verb, "kind": "configmap", "namespace": ns, "name": "needs-approval", "body": body}}


def change(observed, value):
    # Do not echo server-owned managedFields/status into a change request.
    return {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {
        key: observed["metadata"][key] for key in ("name", "namespace", "uid", "resourceVersion")},
        "data": {"value": value}}


def approve(h, body):
    response = h.client.post("/v1/protect/evaluate", json=body, headers=_h(INGEST))
    assert response.status_code == 200, response.text
    auth = response.json()["authorization"]
    assert auth["state"] == "pending_approval"
    decision = h.client.post(f"/v1/authorizations/{auth['authorization_id']}/decide",
                            json={"decision": "approve", "reason": "reviewed synthetic Kubernetes change"}, headers=_h(ANALYST))
    assert decision.status_code == 200
    return auth["token"]


def execute(h, body, token):
    return h.client.post("/v1/tools/execute", json=dict(body, authorization=token), headers=_h(INGEST))


def test_approved_update_reaches_real_target_and_replay_cannot_change_it(cluster, live_harness):
    ns, _, target = cluster
    before = target("get")
    update = change(before, "approved")
    request = payload(ns, update)
    token = approve(live_harness, request)
    substituted = copy.deepcopy(request)
    substituted["arguments"]["body"]["data"]["value"] = "substituted"
    assert execute(live_harness, substituted, token).status_code == 403
    assert target("get")["data"] == {"value": "initial"}
    assert execute(live_harness, request, token).status_code == 200
    after = target("get")
    assert after["data"] == {"value": "approved"}
    assert after["metadata"]["uid"] == before["metadata"]["uid"]
    assert after["metadata"]["resourceVersion"] != before["metadata"]["resourceVersion"]
    assert execute(live_harness, request, token).status_code == 403
    assert target("get")["metadata"]["resourceVersion"] == after["metadata"]["resourceVersion"]


@pytest.mark.parametrize("verb", ["update", "delete"])
@pytest.mark.parametrize("concurrent", ["update", "replace"])
def test_concurrent_change_invalidates_approved_target_version(cluster, live_harness, verb, concurrent):
    ns, _, target = cluster
    before = target("get")
    if verb == "update":
        intended = change(before, "approved")
    else:
        intended = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {
            field: before["metadata"][field] for field in ("uid", "resourceVersion")}}
    request = payload(ns, intended, verb)
    token = approve(live_harness, request)
    if concurrent == "update":
        target("update", change(before, "concurrent-controller"))
    else:
        target("delete", {"preconditions": {key: before["metadata"][key] for key in ("uid", "resourceVersion")}})
        target("create", {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {
            "name": "needs-approval", "namespace": ns}, "data": {"value": "concurrent-controller"}})
    observed = target("get")
    response = execute(live_harness, request, token)
    # The API server ANSWERED with a conflict: that response is proof nothing
    # was admitted, so the operation is a recorded failure, not an unknown
    # outcome for a human to chase. It is never retried and never a success.
    assert response.status_code == 403, response.text
    operations = live_harness.client.get("/v1/executions/operations?state=failed", headers=_h(ANALYST)).json()
    assert operations["operations"], "the rejected change left no failed operation"
    assert live_harness.client.get("/v1/executions/operations?state=unknown_after_effect",
                                   headers=_h(ANALYST)).json()["operations"] == []
    assert target("get")["metadata"]["resourceVersion"] == observed["metadata"]["resourceVersion"]
    assert target("get")["data"] == {"value": "concurrent-controller"}
