#!/usr/bin/env python3
"""Run the AWS adapter's brokered path against the real STS and CloudTrail once, and report.

WHAT THIS PROVES
----------------
RISK R-021: the per-operation AssumeRole, the session name that stamps the
operation, the SigV4 signing of the operation with the TEMPORARY credential,
and the CloudTrail `LookupEvents` reconciliation were implemented from the
vendors' documents and tested against fakes. This runs each of them, once,
against AWS itself:

  1. the configured credential (the BROKER) assumes `SENTINEL_AWS_EXECUTOR_ROLE_ARN`
     under a session named after a fresh operation id;
  2. the operation -- `ec2:DescribeVpcs`, the only action the executor role
     permits -- is signed with the temporary credential and answered;
  3. the reconciler asks CloudTrail for that session name until the event
     appears (delivery lags by up to fifteen minutes) and settles the outcome.

The report records the session name, the credential mode, the HTTP status of
the operation and the reconciler's verdict with its evidence. No key or token
is written anywhere.

WHAT IT DOES NOT PROVE
----------------------
Only a read operation is run: the executor role is deliberately permitted
nothing else. A write under the same mechanism differs only in the role's
policy. Nothing here is a deployment; the adapter runs in this process with
the repository's own outbound client.

Credentials: `SENTINEL_AWS_ACCESS_KEY_ID`, `SENTINEL_AWS_SECRET_ACCESS_KEY`,
`SENTINEL_AWS_SESSION_TOKEN` (optional), `SENTINEL_AWS_REGION` and
`SENTINEL_AWS_EXECUTOR_ROLE_ARN` in the environment. Standard library plus the
repository only.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinel.application.operation_context import operation_scope, operation_stamp  # noqa: E402
from sentinel.domain.operations import OperationState  # noqa: E402
from sentinel.infrastructure.outbound import HardenedHttpClient  # noqa: E402
from sentinel.infrastructure.platforms.aws import AwsCredentials, aws_api_adapter  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--wait-minutes", type=int, default=20, help="how long to give CloudTrail")
    args = parser.parse_args(argv)

    env = os.environ
    credentials = AwsCredentials(
        access_key_id=env["SENTINEL_AWS_ACCESS_KEY_ID"], secret_access_key=env["SENTINEL_AWS_SECRET_ACCESS_KEY"],
        session_token=env.get("SENTINEL_AWS_SESSION_TOKEN", ""), region=env["SENTINEL_AWS_REGION"],
        executor_role_arn=env["SENTINEL_AWS_EXECUTOR_ROLE_ARN"],
    )
    effect = aws_api_adapter(client=HardenedHttpClient(), credentials=credentials, ceiling="low")
    operation_id = "op-aws-proof-" + secrets.token_hex(8)
    started = datetime.now(timezone.utc)
    report: dict = {
        "schema": "sentinel.aws-sts-proof/v1",
        "commit": subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True, check=False).stdout.strip(),
        "started_at": started.isoformat(),
        "region": credentials.region,
        "executor_role": credentials.executor_role_arn.rsplit("/", 1)[-1],
        "operation_id": operation_id,
        "expected_session_name": operation_stamp(operation_id),
    }
    passed = False
    try:
        with operation_scope(operation_id):
            result = effect.runner({"action": "ec2:DescribeVpcs"})
        credential = dict(result["credential"])
        report["credential"] = {"mode": credential.get("mode"), "session": credential.get("session"),
                                "expires_at": credential.get("expires_at"), "role": credential.get("role", "").rsplit("/", 1)[-1]}
        report["operation"] = {"status": result.get("status"), "answered": bool(result.get("body"))}
        if credential.get("mode") != "assume_role" or credential.get("session") != report["expected_session_name"]:
            raise RuntimeError("the operation did not run under a session named after it")
        if int(result.get("status", 0)) != 200:
            raise RuntimeError(f"AWS answered HTTP {result.get('status')} to the operation")

        hint = effect.hint({"action": "ec2:DescribeVpcs"})
        deadline = time.monotonic() + args.wait_minutes * 60
        attempts = 0
        verdict = None
        while time.monotonic() < deadline:
            attempts += 1
            verdict = effect.reconciler(operation_id, hint)
            if verdict.state is not OperationState.UNKNOWN_AFTER_EFFECT:
                break
            time.sleep(30)
        report["reconciliation"] = {"attempts": attempts, "state": verdict.state.value if verdict else None,
                                    "evidence": verdict.evidence if verdict else None,
                                    "minutes_until_settled": round((time.monotonic() - (deadline - args.wait_minutes * 60)) / 60, 1)}
        if verdict is None or verdict.state is not OperationState.SUCCEEDED:
            raise RuntimeError("CloudTrail did not settle the operation as succeeded within the wait")
        passed = True
    except Exception as exc:  # noqa: BLE001 - recorded, never hidden
        report["failure"] = {"type": type(exc).__name__, "reason": str(exc)[:300]}
    report["passed"] = passed
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"passed": passed, "reconciliation": report.get("reconciliation", {}).get("state")}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
