#!/usr/bin/env python3
"""Idempotent GitHub branch-protection applicator (F-4 operator step).

Does NOT claim protection was applied. Prints the exact API calls and exits
non-zero when credentials/admin rights are missing or the remote refuses.

Usage:
  python scripts/apply_branch_protection.py OWNER/REPO
  python scripts/apply_branch_protection.py OWNER/REPO --apply
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

PROTECTION_PAYLOAD = {
    "required_status_checks": {
        "strict": True,
        "contexts": [
            "test",
            "live-postgres-service",
            "live-redis",
            "kind-helm-smoke",
            "verification",
            "security",
            "deployment-validation",
        ],
    },
    "enforce_admins": True,
    "required_pull_request_reviews": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews": True,
        "require_code_owner_reviews": True,
    },
    "restrictions": None,
    "allow_force_pushes": False,
    "allow_deletions": False,
}


def _run(args: list[str], *, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        input=stdin,
        capture_output=True,
        text=True,
        check=False,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", help="OWNER/REPO")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Mutate remote protection (requires gh auth with admin)",
    )
    parser.add_argument("--branch", default="main")
    args = parser.parse_args()

    print("F-4 branch protection — operator script")
    print(f"repo={args.repo} branch={args.branch}")
    print("payload:")
    print(json.dumps(PROTECTION_PAYLOAD, indent=2))
    put_cmd = [
        "gh",
        "api",
        "-X",
        "PUT",
        f"repos/{args.repo}/branches/{args.branch}/protection",
        "-H",
        "Accept: application/vnd.github+json",
        "--input",
        "-",
    ]
    verify_cmd = [
        "gh",
        "api",
        f"repos/{args.repo}/branches/{args.branch}/protection",
        "-H",
        "Accept: application/vnd.github+json",
    ]
    print("\nExact PUT:\n ", " ".join(put_cmd), "< payload.json")
    print("Exact GET:\n ", " ".join(verify_cmd))

    if not args.apply:
        print(
            "\nDRY-RUN only. Protection was NOT applied. "
            "Remote enforcement remains UNVERIFIED until an operator runs --apply."
        )
        return 0

    auth = _run(["gh", "auth", "status"])
    if not os.environ.get("GH_TOKEN") and auth.returncode != 0:
        print(
            "NOT APPLIED: no authenticated gh session / GH_TOKEN. "
            "Remote branch protection remains UNVERIFIED.",
            file=sys.stderr,
        )
        return 2

    put = _run(put_cmd, stdin=json.dumps(PROTECTION_PAYLOAD))
    if put.returncode != 0:
        print("NOT APPLIED: gh api PUT failed:", file=sys.stderr)
        print(put.stderr or put.stdout, file=sys.stderr)
        return put.returncode or 1

    verify = _run(verify_cmd)
    if verify.returncode != 0:
        print(
            "PUT succeeded but VERIFY failed — treat as UNVERIFIED:",
            file=sys.stderr,
        )
        print(verify.stderr or verify.stdout, file=sys.stderr)
        return verify.returncode or 1

    print("Applied and verified classic branch protection:")
    print(verify.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
