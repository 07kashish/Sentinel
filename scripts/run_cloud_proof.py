#!/usr/bin/env python3
"""Run the deployed protected-change journey on a real AWS host, then remove everything.

WHAT THIS PROVES, AND WHAT IT DOES NOT
--------------------------------------
It provisions ONE EC2 instance, installs k3s on it, builds the Sentinel image
there from the committed tree, runs `scripts/run_deployed_journey.py` against
that cluster, copies the report back and terminates the instance. That is the
whole journey -- pod-bound agent identity, admission and network-policy bypass
refusal, approval, per-operation credentials, target attribution, TLS, offline
evidence verification -- on a real cloud host, a different Kubernetes
distribution (k3s) and a different network plugin (flannel with kube-router's
policy controller) from the local kind run.

It is NOT the declared pilot topology. PostgreSQL and Redis run as pods on the
same node, there is no managed database, no load balancer, no object store, no
second node and no IAM integration. Creating those needs far more than EC2
permissions and is a Terraform apply, not this script. The report says so.

COST AND SAFETY
---------------
One t4g.large and a 30 GB encrypted volume for about twenty minutes: a few US
cents. SSH is open to ONE address (this machine's). The instance requires
IMDSv2 and terminates itself on shutdown. Everything is tagged
`Project=sentinel-cloud-proof`; teardown removes the instance, the security
group and the key pair, and runs even when a step fails. `--keep` leaves it up
for debugging and prints how to remove it.

Credentials are read from the environment (AWS_PROVISION_ACCESS_KEY_ID and
AWS_PROVISION_SECRET_ACCESS_KEY, or the standard AWS names) or from
`--env-file`, and are never printed, logged or sent to the instance.

Needs `boto3` (not a project dependency: `pip install boto3` in any venv),
and `ssh`, `scp`, `git`, `curl` on this machine.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TAGS = [{"Key": "Project", "Value": "sentinel-cloud-proof"}, {"Key": "Name", "Value": "sentinel-cloud-proof"}]
K3S_VERSION = "v1.33.4+k3s1"
NODE_NAME = "sentinel-cloud-proof-1"

BOOTSTRAP = f"""set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
sudo apt-get install -y -qq docker.io python3-cryptography >/dev/null
curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION='{K3S_VERSION}' sh -s - --node-name {NODE_NAME} \\
    --write-kubeconfig-mode 644 --disable traefik >/dev/null
for i in $(seq 1 60); do kubectl get nodes 2>/dev/null | grep -q ' Ready' && break; sleep 3; done
kubectl get nodes
"""

BUILD_AND_RUN = """set -euo pipefail
cd ~/sentinel
sudo docker build -q -t sentinel:cloud-proof . >/dev/null
sudo docker save sentinel:cloud-proof | sudo k3s ctr images import - >/dev/null
python3 scripts/run_deployed_journey.py --kubeconfig /etc/rancher/k3s/k3s.yaml --context default \\
    --node-prefix sentinel-cloud-proof --image-loader none --skip-build --image sentinel:cloud-proof \\
    --environment "{environment}" --out ~/deployed-journey.json >/dev/null || true
test -f ~/deployed-journey.json
"""


def credentials(env_file: Path | None) -> dict[str, str]:
    source = dict(os.environ)
    if env_file is not None:
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, _, value = line.partition("=")
                source.setdefault(key.strip(), value.strip().strip('"').strip("'"))
    key_id = source.get("AWS_PROVISION_ACCESS_KEY_ID") or source.get("AWS_ACCESS_KEY_ID", "")
    secret = source.get("AWS_PROVISION_SECRET_ACCESS_KEY") or source.get("AWS_SECRET_ACCESS_KEY", "")
    if not key_id or not secret:
        raise SystemExit("no AWS credentials: set AWS_PROVISION_ACCESS_KEY_ID and AWS_PROVISION_SECRET_ACCESS_KEY")
    return {"aws_access_key_id": key_id, "aws_secret_access_key": secret,
            "region_name": source.get("AWS_REGION") or source.get("AWS_DEFAULT_REGION") or "us-east-1"}


def main(argv: list[str] | None = None) -> int:  # noqa: C901 - one linear procedure with a guaranteed teardown
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--env-file", type=Path, default=None)
    parser.add_argument("--out", type=Path, required=True, help="where to write the cloud proof report")
    parser.add_argument("--instance-type", default="t4g.large")
    parser.add_argument("--keep", action="store_true", help="do not tear down; prints how to")
    args = parser.parse_args(argv)
    try:
        import boto3
    except ImportError:
        raise SystemExit("boto3 is required for this script only: pip install boto3") from None

    session = boto3.Session(**credentials(args.env_file))
    ec2 = session.client("ec2")
    my_ip = subprocess.run(["curl", "-s", "--max-time", "10", "https://checkip.amazonaws.com"],
                           capture_output=True, text=True, check=True).stdout.strip()
    arch = "arm64" if args.instance_type.split(".")[0].endswith("g") else "amd64"
    work = args.out.parent
    work.mkdir(parents=True, exist_ok=True)
    key_path = work / "cloud-proof.pem"
    created: dict[str, str] = {}
    report: dict = {"schema": "sentinel.cloud-proof/v1", "started_at": datetime.now(timezone.utc).isoformat(),
                    "region": session.region_name, "instance_type": args.instance_type, "k3s": K3S_VERSION,
                    "commit": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()}
    stage = "provision"

    def remote(script: str, timeout: int) -> str:
        result = subprocess.run(ssh + [target, "bash -s"], input=script, text=True, capture_output=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError(f"remote step failed during {stage} (exit {result.returncode}): {result.stderr[-400:]}")
        return result.stdout

    try:
        vpc = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])["Vpcs"][0]["VpcId"]
        suffix = str(int(time.time()))
        key = ec2.create_key_pair(KeyName=f"sentinel-cloud-proof-{suffix}", KeyType="ed25519",
                                  TagSpecifications=[{"ResourceType": "key-pair", "Tags": TAGS}])
        created["key_name"] = key["KeyName"]
        key_path.write_text(key["KeyMaterial"], encoding="utf-8")
        key_path.chmod(0o600)
        group = ec2.create_security_group(GroupName=f"sentinel-cloud-proof-{suffix}", VpcId=vpc,
                                          Description="SSH from one address for a disposable proof run",
                                          TagSpecifications=[{"ResourceType": "security-group", "Tags": TAGS}])["GroupId"]
        created["security_group"] = group
        ec2.authorize_security_group_ingress(GroupId=group, IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": f"{my_ip}/32"}]}])
        images = ec2.describe_images(Owners=["099720109477"], Filters=[
            {"Name": "name", "Values": [f"ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-{arch}-server-*"]},
            {"Name": "state", "Values": ["available"]}])["Images"]
        ami = sorted(images, key=lambda image: image["CreationDate"])[-1]
        instance = ec2.run_instances(
            ImageId=ami["ImageId"], InstanceType=args.instance_type, MinCount=1, MaxCount=1, KeyName=key["KeyName"],
            SecurityGroupIds=[group], InstanceInitiatedShutdownBehavior="terminate",
            MetadataOptions={"HttpTokens": "required", "HttpEndpoint": "enabled"},
            BlockDeviceMappings=[{"DeviceName": ami["RootDeviceName"], "Ebs": {
                "VolumeSize": 30, "VolumeType": "gp3", "Encrypted": True, "DeleteOnTermination": True}}],
            TagSpecifications=[{"ResourceType": "instance", "Tags": TAGS}, {"ResourceType": "volume", "Tags": TAGS}],
        )["Instances"][0]
        created["instance_id"] = instance["InstanceId"]
        (work / "cloud-proof-state.json").write_text(json.dumps(created), encoding="utf-8")
        ec2.get_waiter("instance_running").wait(InstanceIds=[created["instance_id"]])
        address = ec2.describe_instances(InstanceIds=[created["instance_id"]])["Reservations"][0]["Instances"][0]["PublicIpAddress"]
        report.update(ami=ami["Name"], architecture=arch)
        print(f"instance {created['instance_id']} is running ({args.instance_type}, {ami['Name']})", flush=True)

        ssh = ["ssh", "-i", str(key_path), "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={work / 'cloud-proof-known-hosts'}",
               "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=30"]
        target = f"ubuntu@{address}"
        stage = "ssh"
        for _ in range(40):
            if subprocess.run(ssh + [target, "true"], capture_output=True, timeout=30).returncode == 0:
                break
            time.sleep(6)
        else:
            raise RuntimeError("the instance never accepted SSH")

        stage = "bootstrap"
        print("installing docker and k3s ...", flush=True)
        report["nodes"] = remote(BOOTSTRAP, 900).strip().splitlines()[-1]

        stage = "ship-source"
        archive = subprocess.run(["git", "archive", "--format=tar.gz", "HEAD"], cwd=ROOT, capture_output=True, check=True).stdout
        subprocess.run(ssh + [target, "mkdir -p ~/sentinel && tar -xz -C ~/sentinel"], input=archive, check=True, timeout=600)

        stage = "build-and-run"
        print("building the image on the instance and running the journey ...", flush=True)
        environment = f"AWS EC2 {args.instance_type} in {session.region_name}, Ubuntu 24.04 {arch}, k3s {K3S_VERSION}, one node"
        remote(BUILD_AND_RUN.format(environment=environment), 2400)
        journey = subprocess.run(ssh + [target, "cat ~/deployed-journey.json"], capture_output=True, text=True, check=True, timeout=60).stdout
        report["journey"] = json.loads(journey)
        report["passed"] = bool(report["journey"].get("passed"))
    except Exception as exc:  # noqa: BLE001 - teardown must run, and the report must say where it stopped
        report["passed"] = False
        report["failure"] = {"stage": stage, "type": type(exc).__name__, "detail": str(exc)[-500:]}
    finally:
        report["completed_at"] = datetime.now(timezone.utc).isoformat()
        if args.keep:
            report["teardown"] = "skipped (--keep); terminate " + created.get("instance_id", "?") + " and delete its security group and key pair"
        else:
            removed = []
            try:
                if "instance_id" in created:
                    ec2.terminate_instances(InstanceIds=[created["instance_id"]])
                    ec2.get_waiter("instance_terminated").wait(InstanceIds=[created["instance_id"]])
                    removed.append("instance")
                if "security_group" in created:
                    ec2.delete_security_group(GroupId=created["security_group"])
                    removed.append("security group")
                if "key_name" in created:
                    ec2.delete_key_pair(KeyName=created["key_name"])
                    removed.append("key pair")
                key_path.unlink(missing_ok=True)
            except Exception as exc:  # noqa: BLE001
                report["teardown_error"] = f"{type(exc).__name__}: {str(exc)[-300:]}"
            report["teardown"] = "removed: " + ", ".join(removed)
        report["not_established"] = ["managed PostgreSQL or Redis", "a load balancer or ingress", "object storage",
                                     "more than one node", "IAM integration", "the Terraform topology", "soak", "a customer"]
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({k: report[k] for k in ("passed", "teardown") if k in report}, indent=2))
        if report.get("failure"):
            print(json.dumps(report["failure"], indent=2))
    return 0 if report.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
