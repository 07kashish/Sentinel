#!/usr/bin/env python3
"""Drive the protected-change journey against the `proof` AWS environment, then report.

WHAT THIS PROVES, AND WHAT IT DOES NOT
--------------------------------------
Runs AFTER `deploy/terraform/aws/envs/proof` has been applied with an image
digest. It finishes what Terraform deliberately leaves to an operator, then
drives one workflow over the load balancer and inspects the managed services
by their APIs:

  * writes the secret VALUES the secrets module refuses to hold in state
    (API keys, metrics token, evidence data key) and rolls the service so the
    tasks start with them;
  * runs the schema migration as a one-off Fargate task of the same task
    definition, so the migration runs with the injected database credential
    and nothing else;
  * waits for two healthy targets behind the ALB, in two availability zones;
  * activates a tenant policy that sends `/protected-change/` resources to a
    human, evaluates a change, refuses it before approval, approves it,
    executes it, refuses the replay, exports the evidence bundle and verifies
    it OFFLINE with the standard-library verifier;
  * asks RDS, ElastiCache, S3 and ECS what they are: encryption, object lock,
    that secrets are injected rather than written into the task definition,
    that the two tasks sit in different zones.

It does NOT prove: AZ-loss survival (single-AZ sizes, stated in the root),
TLS (no domain, the listener is plain HTTP and `posture` says so), workload
identity (an API key acts as the agent; no identity provider is attached to
this environment), or anything about cost beyond the one bill that follows.

Credentials come from the environment (the standard AWS names); nothing is
printed, and the generated secret values are discarded with the process.
Needs `boto3`; everything else is the standard library.
"""

from __future__ import annotations

import argparse
import base64
import json
import secrets
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import boto3

ROOT = Path(__file__).resolve().parents[1]
NAME = "proof"
PROTECTED_MARK = "/protected-change/"


class Step(Exception):
    pass


def main(argv: list[str] | None = None) -> int:  # noqa: C901 - one linear journey, read top to bottom
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--region", default="ap-south-1")
    parser.add_argument("--skip-secrets", action="store_true", help="the secret values were already written by an earlier run")
    parser.add_argument("--skip-migrate", action="store_true")
    args = parser.parse_args(argv)

    session = boto3.Session(region_name=args.region)
    ecs, ec2, elbv2 = session.client("ecs"), session.client("ec2"), session.client("elbv2")
    rds, cache, s3, sm = session.client("rds"), session.client("elasticache"), session.client("s3"), session.client("secretsmanager")
    started = datetime.now(timezone.utc)
    checks: dict = {}
    stage = "start"
    passed = False
    keys = {f"{tenant}:{role}": f"aws-proof-{tenant}-{role}-" + secrets.token_hex(12)
            for tenant, role in (("acme", "ingest"), ("acme", "analyst"), ("acme", "admin"), ("globex", "analyst"))}

    def http(path: str, body: dict | None = None, key: str = "", base: str = "") -> tuple[int, dict]:
        request = Request(base + path, data=json.dumps(body).encode() if body is not None else None,
                          headers={"Authorization": "Bearer " + key, "Content-Type": "application/json",
                                   "X-Sentinel-Agent-Id": "agent:proof-1"})
        try:
            with urlopen(request, timeout=30) as response:  # noqa: S310 - the ALB this run created
                return response.status, json.load(response)
        except HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    try:
        stage = "discover"
        cluster = f"sentinel-{NAME}"
        alb = next(lb for lb in elbv2.describe_load_balancers()["LoadBalancers"] if lb["LoadBalancerName"] == cluster)
        base = f"http://{alb['DNSName']}"
        target_group = next(tg for tg in elbv2.describe_target_groups(LoadBalancerArn=alb["LoadBalancerArn"])["TargetGroups"])
        vpc = alb["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc]}])["Subnets"]
        private = [s["SubnetId"] for s in subnets
                   if "private" in {t["Key"]: t["Value"] for t in s.get("Tags", [])}.get("Name", "").lower()]
        tasks_sg = next(g["GroupId"] for g in ec2.describe_security_groups(
            Filters=[{"Name": "vpc-id", "Values": [vpc]}, {"Name": "group-name", "Values": [f"{cluster}-tasks"]}])["SecurityGroups"])
        # The service ignores task-definition changes by design (a deploy
        # pipeline moves it), so a Terraform apply that registers a new
        # revision leaves the service on the old one. This IS the deploy step:
        # the newest active revision of the family, applied to the service.
        task_definition = ecs.list_task_definitions(familyPrefix=cluster, status="ACTIVE", sort="DESC")["taskDefinitionArns"][0]
        if len(private) < 2:
            raise Step("expected at least two private subnets")
        checks["environment"] = {"region": args.region, "alb": alb["DNSName"], "private_subnets": len(private),
                                 "listener": "http (no certificate; posture reports tls_terminated=false)"}

        stage = "secret-values"
        if not args.skip_secrets:
            values = {
                "api-keys": ",".join(f"{tk.split(':')[0]}:{value}:{tk.split(':')[1]}" for tk, value in keys.items()),
                "metrics-token": secrets.token_urlsafe(32),
                "evidence-data-key": base64.b64encode(secrets.token_bytes(32)).decode(),
            }
            for name, value in values.items():
                sm.put_secret_value(SecretId=f"sentinel/{NAME}/{name}", SecretString=value)
            checks["secret_values_written_out_of_band"] = sorted(values)
            del values

        stage = "migrate"
        if not args.skip_migrate:
            run = ecs.run_task(cluster=cluster, taskDefinition=task_definition, launchType="FARGATE", count=1,
                               networkConfiguration={"awsvpcConfiguration": {"subnets": private[:1], "securityGroups": [tasks_sg],
                                                                             "assignPublicIp": "DISABLED"}},
                               overrides={"containerOverrides": [{"name": "sentinel",
                                                                  "command": ["python", "-m", "sentinel.interface.cli", "migrate"]}]})
            if run["failures"]:
                raise Step(f"migration task not placed: {run['failures'][0].get('reason')}")
            arn = run["tasks"][0]["taskArn"]
            ecs.get_waiter("tasks_stopped").wait(cluster=cluster, tasks=[arn], WaiterConfig={"Delay": 10, "MaxAttempts": 60})
            stopped = ecs.describe_tasks(cluster=cluster, tasks=[arn])["tasks"][0]
            code = stopped["containers"][0].get("exitCode")
            if code != 0:
                raise Step(f"migration exited {code}: {stopped.get('stoppedReason')}")
            checks["schema_migrated_by_one_off_task"] = True

        stage = "roll-service"
        ecs.update_service(cluster=cluster, service=cluster, taskDefinition=task_definition, forceNewDeployment=True)
        checks["service_moved_to_revision"] = task_definition.rsplit("/", 1)[-1]
        # Wait for the ROLLOUT, not merely for healthy targets: the old tasks
        # stay healthy (with the old secrets) until the new ones replace them,
        # and a request answered by one of those reads as a wrong API key.
        deadline = time.monotonic() + 1200
        rollout = ""
        while time.monotonic() < deadline:
            primary = next(d for d in ecs.describe_services(cluster=cluster, services=[cluster])["services"][0]["deployments"]
                           if d["status"] == "PRIMARY")
            rollout = primary.get("rolloutState", "")
            if rollout == "COMPLETED" and primary["runningCount"] >= 2 and len(
                    ecs.describe_services(cluster=cluster, services=[cluster])["services"][0]["deployments"]) == 1:
                break
            if rollout == "FAILED":
                raise Step(f"the deployment failed: {primary.get('rolloutStateReason')}")
            time.sleep(15)
        if rollout != "COMPLETED":
            raise Step(f"the deployment did not complete in 20 minutes (state {rollout})")
        healthy = [t for t in elbv2.describe_target_health(TargetGroupArn=target_group["TargetGroupArn"])["TargetHealthDescriptions"]
                   if t["TargetHealth"]["State"] == "healthy"]
        if len(healthy) < 2:
            raise Step(f"only {len(healthy)} healthy targets after the rollout completed")
        checks["alb_healthy_targets"] = len(healthy)
        running = ecs.list_tasks(cluster=cluster, serviceName=cluster, desiredStatus="RUNNING")["taskArns"]
        described = ecs.describe_tasks(cluster=cluster, tasks=running)["tasks"]
        zones = sorted({t["availabilityZone"] for t in described})
        checks["running_tasks"] = {"count": len(described), "availability_zones": zones,
                                   "cpu_architecture": ecs.describe_task_definition(taskDefinition=task_definition)["taskDefinition"]
                                   .get("runtimePlatform", {}).get("cpuArchitecture")}
        if len(zones) < 2:
            raise Step("the two tasks share an availability zone")

        stage = "managed-services"
        definition = ecs.describe_task_definition(taskDefinition=task_definition)["taskDefinition"]["containerDefinitions"][0]
        injected = sorted(s["name"] for s in definition.get("secrets", []))
        plain = {e["name"] for e in definition.get("environment", [])}
        if plain & set(injected) or "SENTINEL_API_KEYS" in plain or "SENTINEL_DATABASE_URL" in plain:
            raise Step("a secret is written into the task definition environment")
        checks["secrets_injected_by_the_agent_not_in_the_task_definition"] = injected
        db = rds.describe_db_instances(DBInstanceIdentifier=f"sentinel-{NAME}")["DBInstances"][0]
        checks["managed_postgres"] = {"engine": f"{db['Engine']} {db['EngineVersion']}", "class": db["DBInstanceClass"],
                                      "multi_az": db["MultiAZ"], "storage_encrypted": db["StorageEncrypted"],
                                      "publicly_accessible": db["PubliclyAccessible"], "backup_retention_days": db["BackupRetentionPeriod"]}
        if not db["StorageEncrypted"] or db["PubliclyAccessible"]:
            raise Step("the database is not private and encrypted")
        group = cache.describe_replication_groups(ReplicationGroupId=f"sentinel-{NAME}")["ReplicationGroups"][0]
        checks["managed_cache"] = {"nodes": len(group["MemberClusters"]), "at_rest_encryption": group.get("AtRestEncryptionEnabled"),
                                   "transit_encryption": group.get("TransitEncryptionEnabled")}
        bucket = next(b["Name"] for b in s3.list_buckets()["Buckets"] if b["Name"].startswith(f"sentinel-{NAME}-evidence"))
        lock = s3.get_object_lock_configuration(Bucket=bucket)["ObjectLockConfiguration"]
        encryption = s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"]["Rules"][0]["ApplyServerSideEncryptionByDefault"]
        checks["evidence_bucket"] = {"object_lock": lock["ObjectLockEnabled"], "default_retention": lock["Rule"]["DefaultRetention"],
                                     "sse": encryption["SSEAlgorithm"], "kms": bool(encryption.get("KMSMasterKeyID"))}

        stage = "service-answers"
        code, ready = http("/health/ready", base=base)
        if code != 200:
            raise Step(f"/health/ready answered {code}")
        checks["production_mode_serving"] = True

        stage = "tenant-policy"
        code, version = http("/v1/policy/versions", {"note": "aws proof", "rules": [{
            "name": "protected-change-needs-a-human", "effect": "require_approval",
            "resources": [PROTECTED_MARK + "*"], "description": "changes under the protected mark need a human"}]},
            keys["acme:admin"], base)
        if code != 201:
            raise Step(f"policy version not stored: {code} {version}")
        code, _ = http(f"/v1/policy/versions/{version['version']}/activate", {}, keys["acme:admin"], base)
        if code != 200:
            raise Step("policy version not activated")
        checks["tenant_policy_activated"] = version["version"]

        stage = "evaluate-approve-execute"
        request_body = {"agentId": "agent:proof-1", "tool": "echo", "action": "update",
                        "resource": f"{PROTECTED_MARK}prod/config/flag", "arguments": {"flag": "on", "target": "prod"}}
        code, gate = http("/v1/protect/evaluate", request_body, keys["acme:ingest"], base)
        authorization = (gate or {}).get("authorization") or {}
        if code != 200 or authorization.get("state") != "pending_approval":
            raise Step(f"expected a pending authorization, got HTTP {code} decision={gate.get('decision')!r}")
        checks["protected_change_pends_for_a_human"] = gate.get("decision")
        code, view = http("/v1/authorizations/" + authorization["authorization_id"], key=keys["acme:analyst"], base=base)
        if code != 200 or view.get("agent") != "agent:proof-1":
            raise Step("the approver's view does not describe the request")
        checks["approver_sees_the_change"] = view["change"]["headline"]
        code, _ = http("/v1/authorizations/" + authorization["authorization_id"], key=keys["globex:analyst"], base=base)
        if code == 200:
            raise Step("another tenant can see the authorization")
        checks["other_tenant_cannot_see_it"] = code
        code, _ = http("/v1/tools/execute", dict(request_body, authorization=authorization["token"]), keys["acme:ingest"], base)
        if code != 403:
            raise Step(f"an unapproved change executed (HTTP {code})")
        checks["refused_before_approval"] = True
        code, _ = http(f"/v1/authorizations/{authorization['authorization_id']}/decide",
                       {"decision": "approve", "reason": "reviewed the flag change"}, keys["acme:analyst"], base)
        if code != 200:
            raise Step("the approval was not accepted")
        code, ran = http("/v1/tools/execute", dict(request_body, authorization=authorization["token"]), keys["acme:ingest"], base)
        if code != 200 or ran.get("result", {}).get("echo", {}).get("flag") != "on":
            raise Step(f"the approved change did not execute (HTTP {code})")
        checks["approved_change_executed"] = True
        code, _ = http("/v1/tools/execute", dict(request_body, authorization=authorization["token"]), keys["acme:ingest"], base)
        if code != 403:
            raise Step("the authorization was redeemed twice")
        checks["replay_refused"] = True
        _, operations = http("/v1/executions/operations?state=succeeded", key=keys["acme:analyst"], base=base)
        checks["succeeded_operations"] = len(operations.get("operations", []))

        stage = "evidence"
        bundle: dict = {}
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            _, bundle = http("/v1/evidence/export", key=keys["acme:analyst"], base=base)
            if bundle.get("entries"):
                break
            time.sleep(5)
        if not bundle.get("entries"):
            raise Step("the maintenance loop never committed the receipt")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bundle.json"
            path.write_text(json.dumps(bundle), encoding="utf-8")
            verdict = subprocess.run([sys.executable, str(ROOT / "standard/execution-passport-v1/verify_evidence_bundle.py"), str(path),
                                      "--trusted-root", bundle["root"], "--trusted-size", str(bundle["tree_size"])],
                                     capture_output=True, text=True, check=False)
        if verdict.returncode != 0:
            raise Step("the exported bundle did not verify offline: " + verdict.stdout[-300:])
        checks["receipt_committed_and_bundle_verified_offline"] = len(bundle["entries"])
        _, metrics = http("/v1/workflow/metrics?days=1", key=keys["acme:analyst"], base=base)
        checks["workflow_metrics"] = {"approvals": metrics.get("approvals", {}).get("approved"),
                                      "succeeded": metrics.get("executions", {}).get("succeeded"),
                                      "refused": metrics.get("executions", {}).get("refused")}
        passed = True
    except (Step, KeyError, ValueError, OSError, URLError, StopIteration) as exc:
        checks["failure"] = {"stage": stage, "type": type(exc).__name__, **({"reason": str(exc)} if isinstance(exc, Step) else {})}

    report = {
        "schema": "sentinel.aws-proof-journey/v1",
        "passed": passed,
        "environment": "deploy/terraform/aws/envs/proof (free-plan sizes of the pilot stack)",
        "commit": subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True, check=False).stdout.strip(),
        "started_at": started.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "not_established": [
            "AZ-loss survival: single-AZ database and single cache node (free-plan sizes)",
            "TLS: no domain, the listener is plain HTTP",
            "workload identity: an API key acts as the agent; no identity provider is attached",
            "S3 root publication: SENTINEL_ROOT_PUBLISH_TENANTS is empty in the stack, so no root was published",
            "cost: nothing here measures a bill",
        ],
    }
    args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"passed": passed, "stage": stage, "checks": len(checks)}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
