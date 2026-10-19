#!/usr/bin/env python3
"""Seed a demonstration tenant through the public API, so a shared console has something to show.

Everything is created the way a real deployment creates it -- agents send
events, agents ask before acting, a person approves or rejects, the agent
executes through Sentinel, an analyst contains an agent -- so every panel the
visitor opens shows the product's own records, not fixtures written into the
database. The data is SAMPLE data: invented agents, invented resources, the
`echo` tool standing in for a real side effect. The console says so.

WHAT IT CREATES, in tenant `demo`
---------------------------------
* a tenant policy: changes under `/protected-change/` need a human;
* three detected incidents, each a causal chain the Execution graph can draw:
  a staged exfiltration, a credential-file read, a secrets read by a support bot;
* five protected changes: two approved and executed (one then replayed and
  refused), one rejected, two left pending. Pending requests expire after
  five minutes by design; rerun this script to refresh them;
* one containment, with a reason and a seven-day expiry.

Keys come from the environment and are never printed:
`SENTINEL_DEMO_INGEST_KEY`, `SENTINEL_DEMO_ANALYST_KEY`, `SENTINEL_DEMO_ADMIN_KEY`.
Standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError
from urllib.request import Request, urlopen

TENANT_NOTE = "demo tenant: sample data"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", required=True, help="the Sentinel base URL, e.g. http://host")
    args = parser.parse_args(argv)
    keys = {role: os.environ.get(f"SENTINEL_DEMO_{role.upper()}_KEY", "") for role in ("ingest", "analyst", "admin")}
    missing = [role for role, value in keys.items() if not value]
    if missing:
        print(f"missing keys for: {', '.join(missing)}", file=sys.stderr)
        return 2
    base = args.base.rstrip("/")
    run = secrets.token_hex(3)
    now = datetime.now(timezone.utc)
    counts = {"events": 0, "evaluated": 0, "approved": 0, "rejected": 0, "executed": 0, "replay_refused": 0, "pending": 0}

    def call(path: str, body: dict | None, role: str, agent: str = "") -> tuple[int, dict]:
        headers = {"Authorization": "Bearer " + keys[role], "Content-Type": "application/json"}
        if agent:
            headers["X-Sentinel-Agent-Id"] = agent
        request = Request(base + path, data=json.dumps(body).encode() if body is not None else None, headers=headers,
                          method="POST" if body is not None else "GET")
        try:
            with urlopen(request, timeout=30) as response:  # noqa: S310 - the operator's own deployment
                return response.status, json.load(response)
        except HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    # ── policy ───────────────────────────────────────────────────────────────
    code, version = call("/v1/policy/versions", {"note": TENANT_NOTE, "rules": [
        {"name": "production-changes-need-a-human", "effect": "require_approval", "resources": ["/protected-change/*"],
         "description": "Any change an agent makes under /protected-change/ waits for a person."},
    ]}, "admin")
    if code == 201:
        call(f"/v1/policy/versions/{version['version']}/activate", {}, "admin")

    # ── detections: three causal chains ──────────────────────────────────────
    def chain(session: str, agent: str, steps: list[dict]) -> None:
        parent = ""
        for index, step in enumerate(steps):
            event_id = f"{session}-{run}-{index}"
            body = {"eventId": event_id, "sessionId": f"{session}-{run}", "agentId": agent, "eventType": "tool_call",
                    "timestamp": (now - timedelta(minutes=40 - index)).strftime("%Y-%m-%dT%H:%M:%SZ"), **step}
            if parent:
                body["parentEventId"] = parent
            if call("/v1/events", body, "ingest")[0] in (200, 201, 202):
                counts["events"] += 1
            parent = event_id

    chain("exfil", "agent:data-cleaner", [
        {"action": "read_file", "resource": "s3://acme-crm/exports/customers.csv"},
        {"action": "zip", "resource": "/tmp/customers.zip"},
        {"action": "http_post", "resource": "/tmp/customers.zip", "destination": "https://paste.example/upload"},
    ])
    chain("creds", "agent:ops-runner", [
        {"action": "list_dir", "resource": "/home/deploy"},
        {"action": "read_file", "resource": "/home/deploy/.aws/credentials"},
    ])
    chain("support", "agent:support-bot", [
        {"action": "search_tickets", "resource": "zendesk://tickets?q=refund"},
        {"action": "read_file", "resource": "/srv/support-bot/.env"},
    ])

    # ── protected changes ────────────────────────────────────────────────────
    def change(agent: str, resource: str, arguments: dict, outcome: str) -> None:
        body = {"agentId": agent, "tool": "echo", "action": "update", "resource": resource, "arguments": arguments}
        code, gate = call("/v1/protect/evaluate", body, "ingest", agent)
        authorization = (gate or {}).get("authorization") or {}
        if code != 200 or not authorization:
            return
        counts["evaluated"] += 1
        if outcome == "pending":
            counts["pending"] += 1
            return
        decision = "approve" if outcome in ("execute", "replay") else "reject"
        reason = {"approve": "Reviewed the change and its blast radius; within the release plan.",
                  "reject": "Opening SSH to the internet is never approved; use the bastion session manager."}[decision]
        if call(f"/v1/authorizations/{authorization['authorization_id']}/decide", {"decision": decision, "reason": reason}, "analyst")[0] != 200:
            return
        counts["approved" if decision == "approve" else "rejected"] += 1
        if decision == "approve":
            if call("/v1/tools/execute", dict(body, authorization=authorization["token"]), "ingest", agent)[0] == 200:
                counts["executed"] += 1
            if outcome == "replay" and call("/v1/tools/execute", dict(body, authorization=authorization["token"]), "ingest", agent)[0] == 403:
                counts["replay_refused"] += 1

    change("agent:release-bot", "/protected-change/prod/deployments/checkout", {"replicas": 6, "reason": "black-friday load"}, "replay")
    change("agent:infra-bot", "/protected-change/prod/certificates/api-gateway", {"action": "rotate", "valid_days": 90}, "execute")
    change("agent:infra-bot", "/protected-change/prod/security-groups/bastion", {"ingress": "0.0.0.0/0", "port": 22}, "reject")
    change("agent:release-bot", "/protected-change/staging/databases/orders", {"operation": "drop_and_restore", "snapshot": "nightly"}, "pending")
    change("agent:billing-agent", "/protected-change/prod/config/payments-rate-limit", {"requests_per_second": 450}, "pending")

    # ── containment ──────────────────────────────────────────────────────────
    contained = call("/v1/containments", {
        "scope": "agent", "selector": "agent:data-cleaner",
        "reason": "Staged exfiltration to paste.example detected; paused pending the data-owner review.",
        "expiresAt": (now + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }, "analyst")[0] in (200, 201)

    print(json.dumps({**counts, "contained": contained, "run": run}))
    return 0 if counts["events"] and counts["executed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
