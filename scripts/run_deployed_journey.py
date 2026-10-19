#!/usr/bin/env python3
"""One protected change with Sentinel DEPLOYED, on a disposable local kind cluster.

`tests_arch/test_protected_change_journey.py` proves the chain with the
application in-process. This runs it the way a customer would: two Sentinel
pods behind a Service with PostgreSQL and Redis, an agent in its own pod and
namespace, and the target namespace protected by the shipped admission policy.

WHAT IS REAL HERE
-----------------
  * the agent's identity is the PROJECTED, POD-BOUND service-account token the
    kubelet mounted into the agent pod, verified by Sentinel against the
    cluster's JWKS with pod binding required;
  * Sentinel reaches the API server from inside the cluster with its pod's
    token as the BROKER and mints the executor token per operation;
  * the agent pod's egress is restricted by NetworkPolicy, and the harness
    checks whether the CNI actually enforces it rather than assuming so;
  * the agent speaks TLS to Sentinel and verifies the server against a private
    CA it was given; Sentinel serves the certificate itself, so there is no
    cleartext hop between the two pods;
  * evaluation, approval and execution cross pods through the Service;
  * the exported evidence bundle is verified OFFLINE, on this machine.

WHAT IS NOT
-----------
A cloud cluster, a customer identity provider, mutual TLS or a service mesh,
certificate rotation, a second failure domain, load, or a customer. One node.
Synthetic credentials only. The report lists these under `unverified`.

Only a loopback kind API whose nodes are named `sentinel-local-pilot-*` is
accepted. Namespaces are created with a run suffix and removed afterwards
unless `--keep`. Command output is never written to the report.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
CONTEXT = "kind-sentinel-local-pilot"
AUDIENCE = "https://sentinel.deployed-journey.test"
PROTECTED_MARK = "/protected-change/"

#: Runs INSIDE the agent pod. Standard library only; reads the projected token.
AGENT_SCRIPT = r'''
import json, socket, ssl, sys, urllib.request, urllib.error
TRUST = ssl.create_default_context(cafile="/var/run/secrets/sentinel-ca/ca.crt")
step, base = sys.argv[1], sys.argv[2]
body = json.loads(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] else None
key = sys.argv[4] if len(sys.argv) > 4 else ""
if step == "reach-api-server":
    try:
        socket.create_connection(("kubernetes.default.svc", 443), timeout=5).close()
        print(json.dumps({"reached": True}))
    except OSError as exc:
        print(json.dumps({"reached": False, "error": type(exc).__name__}))
    sys.exit(0)
token = key or open("/var/run/secrets/agent/token").read().strip()
request = urllib.request.Request(base + step, data=json.dumps(body).encode() if body is not None else None,
    headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
try:
    with urllib.request.urlopen(request, timeout=30, context=TRUST) as response:
        print(json.dumps({"status": response.status, "body": json.load(response)}))
except urllib.error.HTTPError as exc:
    print(json.dumps({"status": exc.code, "body": json.loads(exc.read() or b"{}")}))
'''


def private_ca_and_server_certificate(names: list[str]) -> tuple[str, str, str]:
    """(CA certificate, server certificate, server key), all PEM. For this run only."""
    import datetime as dt
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = dt.datetime.now(dt.timezone.utc)

    def build(subject: str, issuer_name, issuer_key, key, *, ca: bool):
        builder = (x509.CertificateBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
                   .issuer_name(issuer_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(hours=6))
                   .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
                   # Strict verifiers (Python 3.13's default) require both identifiers.
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
                   .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                                data_encipherment=False, key_agreement=False, key_cert_sign=ca,
                                                crl_sign=ca, encipher_only=False, decipher_only=False), critical=True))
        if not ca:
            sans = [x509.DNSName(n) for n in names] + [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
        return builder.sign(issuer_key, hashes.SHA256())

    ca_key, server_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "deployed-journey private CA")])
    ca_cert = build("deployed-journey private CA", ca_name, ca_key, ca_key, ca=True)
    server = build(names[0], ca_cert.subject, ca_key, server_key, ca=False)
    pem = serialization.Encoding.PEM
    return (ca_cert.public_bytes(pem).decode(), server.public_bytes(pem).decode(),
            server_key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())


class Step(RuntimeError):
    """A journey step did not hold. The message is safe to report."""


def main(argv: list[str] | None = None) -> int:  # noqa: C901 - one linear journey, read top to bottom
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--kubeconfig", type=Path, required=True)
    parser.add_argument("--image", default="sentinel:deployed-journey")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--context", default=CONTEXT, help="kubeconfig context (default: the local kind cluster)")
    parser.add_argument("--node-prefix", default="sentinel-local-pilot-",
                        help="every node name must start with this; the harness refuses any other cluster")
    parser.add_argument("--image-loader", choices=("kind", "none"), default="kind",
                        help="'none' when the image is already in the cluster's runtime (k3s ctr images import)")
    parser.add_argument("--environment", default="local disposable kind, one node",
                        help="one line describing where this ran, recorded in the report")
    args = parser.parse_args(argv)

    kubectl = ["kubectl", "--kubeconfig", str(args.kubeconfig), "--context", args.context]
    run_id = secrets.token_hex(4)
    ns = {"sentinel": f"sdj-sentinel-{run_id}", "agents": f"sdj-agents-{run_id}", "prod": f"sdj-prod-{run_id}"}
    keys = {role: f"deployed-journey-{role}-fixture-" + secrets.token_hex(12) for role in ("ingest", "analyst", "admin")}
    password = "deployed-journey-db-fixture-" + secrets.token_hex(8)
    checks: dict[str, object] = {}
    forwards: list[subprocess.Popen] = []
    stage = "start"
    trust = ssl.create_default_context()
    trust.check_hostname = True
    started_at = datetime.now(timezone.utc).isoformat()

    def run(command: list[str], payload: object = None, timeout: int = 300, ok: bool = True) -> str:
        data = payload if isinstance(payload, str) else (json.dumps(payload) if payload is not None else None)
        result = subprocess.run(command, input=data, text=True, capture_output=True, timeout=timeout, check=False)
        if ok and result.returncode:
            raise Step(f"command failed during {stage}: {command[0]} {command[-1] if command[0] != 'kubectl' else ''}".strip())
        return result.stdout if ok else result.stdout + result.stderr

    def apply(obj: object, namespace: str = "") -> None:
        run(kubectl + (["-n", namespace] if namespace else []) + ["apply", "-f", "-"], obj)

    def agent(step: str, body: dict | None = None, key: str = "") -> dict:
        out = run(kubectl + ["-n", ns["agents"], "exec", "agent", "--", "python", "-c", AGENT_SCRIPT, step,
                             f"https://sentinel.{ns['sentinel']}.svc:8000", json.dumps(body) if body is not None else "", key])
        return json.loads(out.strip().splitlines()[-1])

    def operator(port: int, path: str, body: dict | None = None, key: str = "") -> tuple[int, dict]:
        request = Request(f"https://127.0.0.1:{port}{path}", data=json.dumps(body).encode() if body is not None else None,
                          headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=20, context=trust) as response:  # noqa: S310 - fixed loopback only
                return response.status, json.load(response)
        except HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    try:
        stage = "validate-local-cluster"
        view = json.loads(run(kubectl + ["config", "view", "--minify", "-o", "json"]))
        if urlsplit(view["clusters"][0]["cluster"]["server"]).hostname not in ("127.0.0.1", "localhost", "::1"):
            raise Step("only a loopback kind API is permitted")
        nodes = json.loads(run(kubectl + ["get", "nodes", "-o", "json"]))["items"]
        if not nodes or any(not n["metadata"]["name"].startswith(args.node_prefix) for n in nodes):
            raise Step("unexpected node ownership")
        checks["kubernetes_version"] = nodes[0]["status"]["nodeInfo"]["kubeletVersion"]

        stage = "image"
        if not args.skip_build:
            run(["docker", "build", "-q", "-t", args.image, str(ROOT)], timeout=1800)
        if args.image_loader == "kind":
            run(["kind", "load", "docker-image", args.image, "--name", "sentinel-local-pilot"], timeout=900)
        # Only a real image id is recorded. Where docker is absent or needs root
        # (a k3s host), an error string in this field would read like evidence.
        inspected = run(["docker", "inspect", "--format", "{{.Id}}", args.image], ok=False).strip()
        checks["image_id"] = inspected if inspected.startswith("sha256:") and len(inspected) == 71 else "not recorded on this host"
        checks["node"] = {k: nodes[0]["status"]["nodeInfo"][k] for k in ("osImage", "kernelVersion", "containerRuntimeVersion", "architecture")}

        stage = "namespaces-and-protection"
        for name in ns.values():
            run(kubectl + ["create", "namespace", name])
            run(kubectl + ["label", "namespace", name, "sentinel.local/owner=deployed-journey"])
        run(kubectl + ["label", "namespace", ns["prod"], "sentinel.io/protected-changes=true"])
        for manifest in ("rbac.yaml", "admission-policy.yaml"):
            text = (ROOT / "deploy/protected-changes" / manifest).read_text(encoding="utf-8")
            text = (text.replace("namespace: sentinel", f"namespace: {ns['sentinel']}")
                        .replace("namespace: prod", f"namespace: {ns['prod']}")
                        .replace('agentNamespaces: "agents"', f'agentNamespaces: "{ns["agents"]}"')
                        .replace("system:serviceaccount:sentinel:", f"system:serviceaccount:{ns['sentinel']}:")
                        .replace("system:serviceaccounts:agents", f"system:serviceaccounts:{ns['agents']}")
                        .replace("name: sentinel-protected-changes", f"name: sentinel-protected-changes-{run_id}")
                        .replace("policyName: sentinel-protected-changes", f"policyName: sentinel-protected-changes-{run_id}"))
            apply(text)
        run(kubectl + ["-n", ns["agents"], "create", "serviceaccount", "infra-writer"])
        run(kubectl + ["-n", ns["prod"], "create", "rolebinding", "mistake", "--clusterrole=edit",
                       f"--serviceaccount={ns['agents']}:infra-writer"])
        run(kubectl + ["-n", ns["prod"], "create", "configmap", "app", "--from-literal=flag=off"])

        stage = "postgres-redis"
        def backing(name: str, image: str, port: int, env: list, probe: list) -> None:
            apply({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name}, "spec": {
                "replicas": 1, "selector": {"matchLabels": {"app": name}}, "template": {
                    "metadata": {"labels": {"app": name}}, "spec": {"containers": [{
                        "name": name, "image": image, "env": env,
                        "readinessProbe": {"exec": {"command": probe}, "periodSeconds": 2}}]}}}}, ns["sentinel"])
            apply({"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
                   "spec": {"selector": {"app": name}, "ports": [{"port": port}]}}, ns["sentinel"])
            run(kubectl + ["-n", ns["sentinel"], "rollout", "status", "deployment/" + name, "--timeout=300s"], timeout=330)
        backing("postgres", "postgres:16-alpine", 5432,
                [{"name": "POSTGRES_PASSWORD", "value": password}, {"name": "POSTGRES_DB", "value": "sentinel"}],
                ["pg_isready", "-U", "postgres"])
        backing("redis", "redis:7.4.2-alpine", 6379, [], ["redis-cli", "ping"])
        run(kubectl + ["-n", ns["sentinel"], "exec", "deployment/postgres", "--", "psql", "-U", "postgres", "-d", "sentinel",
                       "-v", "ON_ERROR_STOP=1", "-c",
                       f"CREATE ROLE sentinel LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '{password}'; "
                       "ALTER DATABASE sentinel OWNER TO sentinel; GRANT ALL ON SCHEMA public TO sentinel; "
                       "GRANT pg_read_all_settings TO sentinel;"])

        stage = "sentinel-configuration"
        ca_pem, cert_pem, key_pem = private_ca_and_server_certificate(
            [f"sentinel.{ns['sentinel']}.svc", f"sentinel.{ns['sentinel']}.svc.cluster.local", "localhost"])
        trust.load_verify_locations(cadata=ca_pem)
        apply({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "sentinel-tls"}, "type": "kubernetes.io/tls",
               "stringData": {"tls.crt": cert_pem, "tls.key": key_pem}}, ns["sentinel"])
        apply({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "sentinel-ca"}, "data": {"ca.crt": ca_pem}}, ns["agents"])
        issuer = json.loads(run(kubectl + ["get", "--raw", "/.well-known/openid-configuration"]))["issuer"]
        jwks = json.loads(run(kubectl + ["get", "--raw", "/openid/v1/jwks"]))
        policy = json.loads((ROOT / "config/default_policy.json").read_text(encoding="utf-8"))
        policy["rules"].append({"id": "deployed-journey-protected-change", "field": "resource", "mode": "contains",
                                "description": "changes to the protected namespace need a human",
                                "values": [PROTECTED_MARK], "severity": 75, "incident_type": "protected_change"})
        apply({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "sentinel-policy"},
               "data": {"default_policy.json": json.dumps(policy)}}, ns["sentinel"])
        db = f"postgresql://sentinel:{password}@postgres:5432/sentinel"
        apply({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "sentinel-env"}, "stringData": {
            "SENTINEL_DATABASE_URL": db, "SENTINEL_REDIS_URL": "redis://redis:6379/0",
            "SENTINEL_DATA_KEY_K1": __import__("base64").b64encode(secrets.token_bytes(32)).decode(),
            "SENTINEL_ACTIVE_KEY_ID": "k1",
            "SENTINEL_API_KEYS": ",".join(f"acme:{value}:{role}" for role, value in keys.items()),
            "SENTINEL_AGENT_IDP_JSON": json.dumps([{
                "name": "this-cluster", "kind": "kubernetes", "issuer": issuer, "audience": AUDIENCE,
                "tenant": "acme", "jwks": jwks, "allowed_namespaces": [ns["agents"]]}])}}, ns["sentinel"])
        env = [{"name": k, "value": v} for k, v in {
            "SENTINEL_ENV": "production", "SENTINEL_CORS_ORIGINS": "https://console.local.invalid",
            "SENTINEL_RATE_LIMIT_FAIL_OPEN": "false", "SENTINEL_REQUIRE_EXECUTION_BINDING": "true",
            "SENTINEL_PROTECT_ENFORCE": "true", "SENTINEL_PROTECTION_MODE": "protect",
            "SENTINEL_REQUIRE_WORKLOAD_IDENTITY": "true", "SENTINEL_SOFT_PROMPT_DETECT": "false",
            "SENTINEL_KUBERNETES_API_SERVER": "https://kubernetes.default.svc",
            "SENTINEL_KUBERNETES_TOKEN_FILE": "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "SENTINEL_KUBERNETES_CA_FILE": "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
            "SENTINEL_KUBERNETES_EXECUTOR_SERVICE_ACCOUNT": "sentinel-executor",
            "SENTINEL_KUBERNETES_EXECUTOR_NAMESPACE": ns["sentinel"], "SENTINEL_KUBERNETES_CEILING": "high",
            "GUNICORN_WORKERS": "2"}.items()]
        pod_spec = {"serviceAccountName": "sentinel-broker", "containers": [{
            "name": "sentinel", "image": args.image, "imagePullPolicy": "Never", "env": env,
            "envFrom": [{"secretRef": {"name": "sentinel-env"}}], "ports": [{"containerPort": 8000}],
            # The entrypoint passes gunicorn options through: Sentinel terminates TLS itself.
            "args": ["--certfile=/tls/tls.crt", "--keyfile=/tls/tls.key"],
            "volumeMounts": [{"name": "policy", "mountPath": "/app/config/default_policy.json", "subPath": "default_policy.json"},
                             {"name": "tls", "mountPath": "/tls", "readOnly": True}],
            "readinessProbe": {"httpGet": {"path": "/health/ready", "port": 8000, "scheme": "HTTPS"}, "periodSeconds": 2}}],
            "volumes": [{"name": "policy", "configMap": {"name": "sentinel-policy"}},
                        {"name": "tls", "secret": {"secretName": "sentinel-tls"}}]}

        stage = "migration"
        migrate = json.loads(json.dumps(pod_spec))
        migrate["containers"][0].pop("readinessProbe")
        migrate["containers"][0].pop("args")
        migrate["containers"][0]["command"] = ["python", "-m", "sentinel.interface.cli", "migrate"]
        migrate["restartPolicy"] = "Never"
        apply({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": "migrate"},
               "spec": {"backoffLimit": 0, "template": {"spec": migrate}}}, ns["sentinel"])
        run(kubectl + ["-n", ns["sentinel"], "wait", "--for=condition=complete", "job/migrate", "--timeout=180s"], timeout=200)

        stage = "sentinel-deployment"
        apply({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "sentinel"}, "spec": {
            "replicas": 2, "selector": {"matchLabels": {"app": "sentinel"}},
            "template": {"metadata": {"labels": {"app": "sentinel"}}, "spec": pod_spec}}}, ns["sentinel"])
        apply({"apiVersion": "v1", "kind": "Service", "metadata": {"name": "sentinel"},
               "spec": {"selector": {"app": "sentinel"}, "ports": [{"port": 8000}]}}, ns["sentinel"])
        run(kubectl + ["-n", ns["sentinel"], "rollout", "status", "deployment/sentinel", "--timeout=300s"], timeout=330)
        pods = [p["metadata"]["name"] for p in json.loads(run(
            kubectl + ["-n", ns["sentinel"], "get", "pods", "-l", "app=sentinel", "-o", "json"]))["items"]]
        if len(pods) != 2:
            raise Step("expected exactly two Sentinel pods")
        checks["sentinel_pods"] = 2
        ports = []
        for pod in pods:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            forwards.append(subprocess.Popen(kubectl + ["-n", ns["sentinel"], "port-forward", "pod/" + pod, f"{port}:8000",
                                                        "--address", "127.0.0.1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            deadline = time.monotonic() + 30
            while True:
                try:
                    if operator(port, "/health/ready")[0] == 200:
                        break
                except OSError:
                    pass
                if time.monotonic() > deadline:
                    raise Step("a Sentinel pod never answered through the port-forward")
                time.sleep(0.3)
            ports.append(port)

        stage = "agent-pod"
        apply({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": "agents-reach-sentinel-only"},
               "spec": {"podSelector": {}, "policyTypes": ["Egress"], "egress": [
                   {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}],
                    "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]},
                   {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": ns["sentinel"]}},
                            "podSelector": {"matchLabels": {"app": "sentinel"}}}], "ports": [{"protocol": "TCP", "port": 8000}]}]}},
              ns["agents"])
        apply({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "agent", "labels": {"sentinel.io/role": "agent"}}, "spec": {
            "serviceAccountName": "infra-writer", "automountServiceAccountToken": False, "containers": [{
                "name": "agent", "image": args.image, "imagePullPolicy": "Never", "command": ["python", "-c", "import time; time.sleep(3600)"],
                "volumeMounts": [{"name": "identity", "mountPath": "/var/run/secrets/agent", "readOnly": True},
                                 {"name": "sentinel-ca", "mountPath": "/var/run/secrets/sentinel-ca", "readOnly": True}]}],
            "volumes": [{"name": "sentinel-ca", "configMap": {"name": "sentinel-ca"}}, {"name": "identity", "projected": {"sources": [{"serviceAccountToken": {
                "path": "token", "audience": AUDIENCE, "expirationSeconds": 600}}]}}]}}, ns["agents"])
        run(kubectl + ["-n", ns["agents"], "wait", "--for=condition=Ready", "pod/agent", "--timeout=180s"], timeout=200)

        stage = "bypass-prevention"
        subject = f"system:serviceaccount:{ns['agents']}:infra-writer"
        deadline = time.monotonic() + 30
        while "protected changes" not in run(kubectl + ["-n", ns["prod"], "create", "configmap", "probe-" + secrets.token_hex(3),
                                                       "--as=" + subject], ok=False):
            if time.monotonic() > deadline:
                raise Step("the admission policy never refused the agent's direct write")
            time.sleep(0.5)
        checks["admission_refuses_agent_write_despite_edit_grant"] = True
        current = json.loads(run(kubectl + ["-n", ns["prod"], "get", "configmap", "app", "-o", "json"]))
        by_hand = run(kubectl + ["-n", ns["prod"], "replace", "-f", "-",
                                 f"--as=system:serviceaccount:{ns['sentinel']}:sentinel-executor"],
                      dict(current, data={"flag": "by-hand"}), ok=False)
        if "operation stamp" not in by_hand:
            raise Step("the executor identity wrote without an operation stamp")
        checks["admission_refuses_unstamped_executor_write"] = True
        # Reported, not asserted: enforcement is a property of the CNI, and a CNI
        # takes a few seconds to program a new pod's rules.
        blocked, deadline = False, time.monotonic() + 45
        while not blocked and time.monotonic() < deadline:
            blocked = not agent("reach-api-server")["reached"]
            if not blocked:
                time.sleep(3)
        checks["cni_blocks_agent_pod_from_api_server"] = blocked

        stage = "identity"
        observed = json.loads(run(kubectl + ["-n", ns["prod"], "get", "configmap", "app", "-o", "json"]))
        request_body = {"agentId": subject, "tool": "kubernetes_api", "action": "update",
                        "resource": f"{PROTECTED_MARK}namespaces/{ns['prod']}/configmaps/app",
                        "arguments": {"verb": "update", "kind": "configmap", "namespace": ns["prod"], "name": "app", "body": {
                            "apiVersion": "v1", "kind": "ConfigMap", "data": {"flag": "on"}, "metadata": {
                                k: observed["metadata"][k] for k in ("name", "namespace", "uid", "resourceVersion")}}}}
        if agent("/v1/protect/evaluate", request_body, keys["ingest"])["status"] != 403:
            raise Step("an API key was allowed to act as an agent")
        checks["api_key_refused_on_agent_path"] = True
        other = dict(request_body, agentId=f"system:serviceaccount:{ns['agents']}:someone-else")
        if agent("/v1/protect/evaluate", other)["status"] != 403:
            raise Step("the pod's token was allowed to speak for another agent")
        checks["pod_token_cannot_speak_for_another_agent"] = True

        stage = "evaluate-approve-execute"
        gate = agent("/v1/protect/evaluate", request_body)
        authorization = (gate["body"] or {}).get("authorization") or {}
        if gate["status"] != 200 or authorization.get("state") != "pending_approval":
            raise Step(f"expected a pending authorization, got HTTP {gate['status']} decision={gate['body'].get('decision')!r}")
        checks["pod_bound_token_accepted_as_agent_identity"] = True
        checks["agent_to_sentinel_tls_verified_against_private_ca"] = True
        code, view_ = operator(ports[0], "/v1/authorizations/" + authorization["authorization_id"], key=keys["analyst"])
        if code != 200 or view_["change"]["headline"] != f"update configmap {ns['prod']}/app" or view_["agent"] != subject:
            raise Step("the approver's view does not describe the requested change")
        early = agent("/v1/tools/execute", dict(request_body, authorization=authorization["token"]))
        if early["status"] != 403:
            raise Step("an unapproved change executed")
        code, _ = operator(ports[1], f"/v1/authorizations/{authorization['authorization_id']}/decide",
                           {"decision": "approve", "reason": "reviewed the flag change"}, keys["analyst"])
        if code != 200:
            raise Step("the approval was not accepted")
        ran = agent("/v1/tools/execute", dict(request_body, authorization=authorization["token"]))
        if ran["status"] != 200 or ran["body"]["result"]["credential"]["mode"] != "token_request":
            raise Step(f"the approved change did not execute under a minted credential (HTTP {ran['status']})")
        after = json.loads(run(kubectl + ["-n", ns["prod"], "get", "configmap", "app", "-o", "json", "--show-managed-fields"]))
        if after["data"] != {"flag": "on"} or after["metadata"]["uid"] != observed["metadata"]["uid"]:
            raise Step("the target does not show the approved change")
        managers = {m["manager"] for m in after["metadata"]["managedFields"]}
        _, operations = operator(ports[0], "/v1/executions/operations?state=succeeded", key=keys["analyst"])
        operation_id = operations["operations"][0]["operation_id"]
        stamp = "sentinel-op-" + hashlib.sha256(operation_id.encode()).hexdigest()[:40]
        if stamp not in managers:
            raise Step("the cluster does not attribute the change to the operation")
        checks["approved_change_applied_stamped_and_attributed"] = True
        if agent("/v1/tools/execute", dict(request_body, authorization=authorization["token"]))["status"] != 403:
            raise Step("the authorization was redeemed twice")
        checks["replay_refused_across_pods"] = True

        stage = "evidence"
        bundle: dict = {}
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            _, bundle = operator(ports[1], "/v1/evidence/export", key=keys["analyst"])
            if bundle.get("entries"):
                break
            time.sleep(5)
        if not bundle.get("entries"):
            raise Step("the maintenance loop never committed the receipt to the transparency log")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bundle.json"
            path.write_text(json.dumps(bundle), encoding="utf-8")
            verdict = subprocess.run([sys.executable, str(ROOT / "standard/execution-passport-v1/verify_evidence_bundle.py"), str(path),
                                      "--trusted-root", bundle["root"], "--trusted-size", str(bundle["tree_size"])],
                                     capture_output=True, text=True, check=False)
        if verdict.returncode != 0:
            raise Step("the exported bundle did not verify offline")
        checks["receipt_committed_and_bundle_verified_offline"] = len(bundle["entries"])
        _, metrics = operator(ports[0], "/v1/workflow/metrics?days=1", key=keys["analyst"])
        checks["workflow_metrics"] = {"approvals": metrics["approvals"]["approved"], "succeeded": metrics["executions"]["succeeded"],
                                      "refused": metrics["executions"]["refused"]}
        passed = True
    except (Step, subprocess.TimeoutExpired, KeyError, ValueError, OSError) as exc:
        passed = False
        checks["failure"] = {"stage": stage, "type": type(exc).__name__, **({"reason": str(exc)} if isinstance(exc, Step) else {})}
    finally:
        for process in forwards:
            process.terminate()
        if not args.keep:
            for kind in ("validatingadmissionpolicybinding", "validatingadmissionpolicy"):
                run(kubectl + ["delete", kind, f"sentinel-protected-changes-{run_id}", "--ignore-not-found"], ok=False)
            for name in ns.values():
                run(kubectl + ["delete", "namespace", name, "--wait=false"], ok=False)

    report = {
        "schema": "sentinel.deployed-journey/v1", "passed": passed, "checks": checks,
        "started_at": started_at, "completed_at": datetime.now(timezone.utc).isoformat(),
        "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "scope": args.environment + "; synthetic credentials, a ConfigMap flag change",
        "unverified": ["cloud cluster", "customer identity provider", "mutual TLS or a mesh", "certificate rotation",
                       "independent failure domain", "load and soak", "external assessment", "a customer"],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
