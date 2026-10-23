#!/usr/bin/env python3
"""Measure deterministic detections over 60 synthetic benign tool-call actions.

This uniform hand-written vocabulary measures only this corpus, not real-world
traffic or recall on attacks. Privileged-action rules can still fire; report
their actual verdicts and preserve the provenance/count safeguards.
"""
from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from sentinel.domain.detection_metrics import CorpusProvenance, measure_detection  # noqa: E402
from sentinel.domain.primitives import TrustLevel  # noqa: E402
from sentinel.infrastructure.detection import DeterministicPolicy  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "reports" / "benign_tool_call_false_positives.json"

#: Ordinary agent tool-call actions. Verbs and object names from filesystem,
#: HTTP, database, cloud and observability tooling -- the everyday vocabulary of
#: an agent doing its job. Deliberately mundane.
BENIGN_ACTIONS = [
    "read_file", "write_file", "list_dir", "make_dir", "delete_file", "copy_file",
    "move_file", "stat_file", "find_files", "grep_files", "open document",
    "close document", "http_get", "http_post", "http_put", "fetch_url",
    "download artifact", "upload artifact", "db_query", "db_insert", "db_update",
    "run_migration", "begin transaction", "commit transaction", "get_status",
    "health_check", "fetch_metrics", "read_logs", "tail logs", "send heartbeat",
    "list_instances", "describe instance", "start container", "stop container",
    "restart service", "scale deployment", "compute checksum", "verify signature",
    "index rebuild started", "routine maintenance sweep", "rotate credentials",
    "list_users", "get_user", "send_email", "post_message", "create ticket",
    "close ticket", "search knowledge base", "summarise document",
    "translate text", "format code", "run tests", "lint project",
    "build package", "publish release", "tag release", "clone repository",
    "checkout branch", "merge branch", "review diff",
]


def main() -> int:
    policy = DeterministicPolicy.default()
    rows = []
    for action in BENIGN_ACTIONS:
        verdict = policy.evaluate(
            payload={"eventId": "e-1", "timestamp": "2026-08-19T12:00:00Z",
                     "agentId": "0x" + "cd" * 20, "eventType": "tool_call",
                     "action": action, "resource": "README.md", "metadata": {}},
            trust=TrustLevel.UNSIGNED,
        )
        rows.append({"action": action, "fired": verdict.fired,
                     "severity": verdict.severity.value, "signals": verdict.signals})
    fired = [row for row in rows if row["fired"]]
    measurement = measure_detection(
        provenance=CorpusProvenance.SYNTHETIC,
        true_positives=0, false_positives=len(fired),
        true_negatives=len(rows) - len(fired), false_negatives=0,
    )
    payload = {
        "status": "measured_benign_tool_call_false_positives",
        "detector": policy.version(),
        "n_benign_actions": len(rows), "n_fired": len(fired),
        "false_positive_rate": round(len(fired) / len(rows), 4),
        "fired": fired, "all_verdicts": rows,
        "method": "DeterministicPolicy evaluates tool_call events with unsigned trust, README.md resource, and empty metadata.",
        "not_measured": ["recall on attacks", "real-world frequency of these synthetic actions"],
    }
    payload["provenance"] = measurement.as_dict()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"benign tool-call actions: {len(rows)}; fired: {len(fired)} ({len(fired)/len(rows):.1%})")
    print(measurement.claim)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
