"""Exercise the chart on an explicitly selected, disposable LOCAL kind cluster.

Uses synthetic credentials and a harmless echo operation, not a protected cloud
change. Retains resources for diagnosis; never deletes an existing namespace.
The report explicitly withholds CNI, mesh, independent DR and production claims.
"""
from __future__ import annotations

import argparse
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
import socket
import subprocess
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
NAMESPACE = "sentinel-local-smoke"
CONTEXT = "kind-sentinel-local-pilot"
KEY = "local-smoke-runtime-fixture-not-a-real-credential"
ADMIN_KEY = "local-smoke-admin-fixture-not-a-real-credential"
OTHER_KEY = "local-smoke-other-fixture-not-a-real-credential"
PASSWORD = "local-smoke-database-fixture-not-a-real-credential"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", type=Path, required=True)
    parser.add_argument("--helm", type=Path, required=True)
    parser.add_argument("--image", default="sentinel:local-pilot")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--resume", action="store_true", help="reuse only a namespace owned by this harness")
    args = parser.parse_args()
    kubectl = ["kubectl", "--kubeconfig", str(args.kubeconfig), "--context", CONTEXT]
    checks: dict[str, object] = {}
    started_at = datetime.now(timezone.utc).isoformat()
    script_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    run_id = str(time.time_ns())
    redis_stopped = False
    forwards: list[subprocess.Popen] = []

    def run(command: list[str], payload: dict | None = None, timeout: int = 300) -> str:
        result = subprocess.run(command, input=json.dumps(payload) if payload else None,
                                text=True, capture_output=True, timeout=timeout, check=False)
        if result.returncode:
            # Commands can contain synthetic secrets; keep output out of reports.
            raise RuntimeError("local cluster command failed: " + command[0])
        return result.stdout

    def apply(obj: dict) -> None:
        run(kubectl + ["-n", NAMESPACE, "apply", "-f", "-"], obj)

    def secret(name: str, values: dict) -> None:
        apply({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": name}, "stringData": values})

    def deployment(name: str, container: dict, **spec) -> None:
        apply({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name},
               "spec": {"replicas": 1, "selector": {"matchLabels": {"app": name}},
                        "template": {"metadata": {"labels": {"app": name}},
                                     "spec": {"containers": [dict(container, name=name)], **spec}}}})
        port = 5432 if name == "postgres" else 6379
        apply({"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
               "spec": {"selector": {"app": name}, "ports": [{"port": port}]}})
        run(kubectl + ["-n", NAMESPACE, "rollout", "status", "deployment/" + name, "--timeout=240s"])

    def request(port: int, path: str, body: dict | None = None, key: str = KEY):
        req = Request(f"http://127.0.0.1:{port}" + path,
                      data=json.dumps(body).encode() if body is not None else None,
                      headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=15) as response:  # noqa: S310 - fixed loopback only
                return response.status, json.load(response)
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    stage = "validate-local-cluster"
    try:
        config = json.loads(run(kubectl + ["config", "view", "--minify", "-o", "json"]))
        server = config["clusters"][0]["cluster"]["server"]
        if urlsplit(server).hostname not in ("127.0.0.1", "localhost", "::1"):
            raise RuntimeError("only a loopback kind API is permitted")
        nodes = json.loads(run(kubectl + ["get", "nodes", "-o", "json"]))["items"]
        if not nodes or any(not n["metadata"]["name"].startswith("sentinel-local-pilot-") for n in nodes):
            raise RuntimeError("unexpected node ownership")
        if args.resume:
            ns = json.loads(run(kubectl + ["get", "namespace", NAMESPACE, "-o", "json"]))
            if ns["metadata"].get("labels", {}).get("sentinel.local/owner") != CONTEXT:
                raise RuntimeError("namespace is not owned by this harness")
        else:
            run(kubectl + ["create", "namespace", NAMESPACE])
            run(kubectl + ["label", "namespace", NAMESPACE, "sentinel.local/owner=" + CONTEXT])
        print("Verified local cluster; created isolated smoke namespace.", flush=True)
        checks["kubernetes_versions"] = [n["status"]["nodeInfo"]["kubeletVersion"] for n in nodes]
        stage = "postgres-redis"
        deployment("postgres", {"image": "postgres:16-alpine", "env": [
            {"name": "POSTGRES_PASSWORD", "value": PASSWORD}, {"name": "POSTGRES_DB", "value": "sentinel"}],
            "args": ["postgres", "-c", "wal_level=replica", "-c", "archive_mode=on", "-c", "archive_timeout=60s",
                     "-c", "archive_command=test ! -f /wal/%f && cp %p /wal/%f"],
            "volumeMounts": [{"name": "wal", "mountPath": "/wal"}],
            "readinessProbe": {"exec": {"command": ["pg_isready", "-U", "postgres"]}, "periodSeconds": 2}},
            securityContext={"fsGroup": 999}, volumes=[{"name": "wal", "emptyDir": {}}])
        run(kubectl + ["-n", NAMESPACE, "exec", "deployment/postgres", "--", "psql", "-U", "postgres",
                       "-d", "sentinel", "-v", "ON_ERROR_STOP=1", "-c",
                       f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='sentinel') THEN CREATE ROLE sentinel LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '{PASSWORD}'; END IF; END $$; "
                       "ALTER DATABASE sentinel OWNER TO sentinel; GRANT ALL ON SCHEMA public TO sentinel; "
                       "GRANT pg_read_all_settings TO sentinel;"])
        deployment("redis", {"image": "redis:7.4.2-alpine", "readinessProbe": {
            "exec": {"command": ["redis-cli", "ping"]}, "periodSeconds": 2}})
        db = f"postgresql://sentinel:{PASSWORD}@postgres:5432/sentinel"
        secret("sentinel-db", {"url": db})
        secret("sentinel-auth", {"apiKeys": f"local:{KEY}:ingest,local:{ADMIN_KEY}:admin,other:{OTHER_KEY}:ingest"})
        secret("sentinel-metrics", {"token": "local-metrics-fixture-not-a-real-credential"})
        secret("sentinel-redis", {"redisUrl": "redis://redis:6379/0"})
        stage = "migration"
        apply({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": "migrate-" + run_id}, "spec": {
            "backoffLimit": 0, "template": {"spec": {"restartPolicy": "Never", "containers": [{
                "name": "migrate", "image": args.image, "imagePullPolicy": "Never",
                "command": ["python", "-m", "sentinel.interface.cli", "migrate"], "env": [
                    {"name": "SENTINEL_DATABASE_URL", "value": db},
                    {"name": "SENTINEL_ENV", "value": "development"},
                    {"name": "SENTINEL_API_KEYS", "value": f"local:{KEY}:admin"}]}]}}}})
        run(kubectl + ["-n", NAMESPACE, "wait", "--for=condition=complete", "job/migrate-" + run_id, "--timeout=120s"])
        checks["migration_non_superuser"] = True
        stage = "helm-deployment"
        values = {"replicaCount": 2, "image": {"repository": args.image.rsplit(":", 1)[0],
                  "tag": args.image.rsplit(":", 1)[1], "digest": "", "pullPolicy": "Never"},
                  "externalPostgres": {"archiveTimeoutConfirmed": True},
                  "corsOrigins": "https://console.local.invalid", "otel": {"endpoint": ""},
                  "networkPolicy": {"enabled": True}, "serviceMesh": {"enabled": False},
                  "autoscaling": {"enabled": False}, "podDisruptionBudget": {"enabled": False},
                  "resources": {"requests": {"cpu": "50m", "memory": "128Mi"},
                                "limits": {"cpu": "500m", "memory": "512Mi"}}}
        args.out.parent.mkdir(parents=True, exist_ok=True)
        values_path = args.out.with_suffix(".values.json")
        values_path.write_text(json.dumps(values, indent=2) + "\n")
        helm = [str(args.helm), "--kubeconfig", str(args.kubeconfig), "--kube-context", CONTEXT]
        run(helm + ["upgrade", "--install", "sentinel", str(ROOT / "deploy/helm/sentinel"), "-n", NAMESPACE,
                    "-f", str(values_path), "--skip-schema-validation", "--wait", "--timeout", "240s"])
        if args.resume:
            run(kubectl + ["-n", NAMESPACE, "rollout", "restart", "deployment/sentinel"])
            run(kubectl + ["-n", NAMESPACE, "rollout", "status", "deployment/sentinel", "--timeout=240s"])
        run(helm + ["test", "sentinel", "-n", NAMESPACE, "--timeout", "120s"])
        checks["chart_archive_configuration_hook"] = True
        pods = json.loads(run(kubectl + ["-n", NAMESPACE, "get", "pods", "-l", "app=sentinel", "-o", "json"]))["items"]
        if len(pods) != 2:
            raise RuntimeError("expected exactly two gateway pods")
        checks["gateway_image_ids"] = [p["status"]["containerStatuses"][0]["imageID"] for p in pods]
        checks["replicas"] = len(pods)
        print("Two gateway pods ready with PostgreSQL and Redis; checking cross-pod execution.", flush=True)
        ports = []
        for pod in pods:
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            forwards.append(subprocess.Popen(kubectl + ["-n", NAMESPACE, "port-forward", "pod/" + pod["metadata"]["name"],
                               f"{port}:8000", "--address", "127.0.0.1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            deadline = time.monotonic() + 20
            while True:
                try:
                    if request(port, "/health/ready")[0] == 200:
                        break
                except OSError:
                    pass
                if time.monotonic() > deadline:
                    raise RuntimeError("pod forwarding/readiness unavailable")
                time.sleep(0.2)
            ports.append(port)
        stage = "bound-execution-cross-pod-replay"
        body = {"agentId": "same-agent", "tool": "echo", "action": "echo", "resource": "local-smoke-" + run_id,
                "arguments": {"value": "synthetic-smoke-payload"}}
        code, evaluation = request(ports[0], "/v1/protect/evaluate", body)
        if code != 200 or evaluation.get("decision") != "allow":
            raise RuntimeError("expected allowed evaluation")
        token = evaluation["authorization"]["token"]
        code, _ = request(ports[1], "/v1/tools/execute", dict(body, authorization=token))
        if code != 200:
            raise RuntimeError("bound execution failed")
        refused = [request(ports[0], "/v1/tools/execute", dict(body, authorization=token))[0],
                   request(ports[1], "/v1/tools/execute", body)[0],
                   request(ports[1], "/v1/tools/execute", dict(body, authorization=token), OTHER_KEY)[0]]
        if refused != [403, 403, 403]:
            raise RuntimeError("replay, unbound or cross-tenant request was admitted")
        _, operations = request(ports[0], "/v1/executions/operations", key=ADMIN_KEY)
        successes = sum(op["state"] == "succeeded" and op["target_resource"] == body["resource"]
                        for op in operations["operations"])
        if successes != 1:
            raise RuntimeError("expected one durable success for this synthetic operation")
        checks["cross_pod_binding_replay_and_tenant_refusal"] = True
        checks["durable_successful_echo_operations"] = 1
        stage = "redis-outage"
        run(kubectl + ["-n", NAMESPACE, "scale", "deployment/redis", "--replicas=0"])
        redis_stopped = True
        run(kubectl + ["-n", NAMESPACE, "wait", "--for=delete", "pod", "-l", "app=redis", "--timeout=90s"])
        codes = [request(port, "/v1/protect/evaluate", body)[0] for port in ports]
        if not all(code in (429, 503) for code in codes):
            raise RuntimeError("Redis outage admitted a request")
        checks["redis_outage_statuses"] = codes
        run(kubectl + ["-n", NAMESPACE, "scale", "deployment/redis", "--replicas=1"])
        run(kubectl + ["-n", NAMESPACE, "rollout", "status", "deployment/redis", "--timeout=120s"])
        checks["redis_restored"] = True
        redis_stopped = False
        passed = True
    except Exception as exc:
        passed = False
        checks["failure"] = {"stage": stage, "type": type(exc).__name__}
        if type(exc) is RuntimeError:
            checks["failure"]["reason"] = str(exc)
    finally:
        if redis_stopped:
            try:
                run(kubectl + ["-n", NAMESPACE, "scale", "deployment/redis", "--replicas=1"])
                checks["redis_restore_requested_after_failure"] = True
            except Exception:
                checks["redis_restore_requested_after_failure"] = False
        for process in forwards:
            process.terminate()
            process.wait(timeout=5)
    report = {"schema": "sentinel.local-kind-smoke/v1", "passed": passed, "checks": checks,
              "started_at": started_at, "completed_at": datetime.now(timezone.utc).isoformat(),
              "harness_sha256": script_sha256,
              "scope": "local disposable kind, synthetic credentials, harmless echo tool",
              "unverified": ["consequential Kubernetes tool outcome", "CNI NetworkPolicy enforcement", "TLS/mesh/IdP",
                             "independent recovery", "production soak", "external assessment", "paid workflow"],
              "topology_exceptions": ["two replicas on one node", "service mesh disabled", "Helm schema skipped for local shape"]}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
