#!/usr/bin/env python3
"""How often does the soft detector fire on an ORDINARY agent tool call?

WHY THIS EXISTS
---------------
`SoftAugmentedPolicy` has a fallback: when an event carries no
`metadata.prompt` and its `eventType` is `tool_call`, it classifies the
**`action` field** -- the tool name. That is the common shape of agent
telemetry, so the classifier is being asked to judge strings like `read_file`
and `http_get` as though they were prompts.

Noticed while load-testing, not while reviewing detection: the load generator's
default action `read_file` scores **0.5409**, above the shipped 0.5 threshold,
so every synthetic event was raising a prompt-injection incident. That made a
performance measurement meaningless AND pointed at a detection-quality problem
worth measuring on its own.

WHAT THIS MEASURES
------------------
The false-positive rate over a corpus of unambiguously benign tool-call action
names -- the vocabulary of ordinary agent operations. None of these is an
injection attempt by any reading.

WHAT IT DOES NOT MEASURE
------------------------
Recall, or performance on actual prompts. `evaluation/` owns those. This is one
narrow question: at the shipped threshold, does routine agent traffic trip the
detector? It also does not weight by real-world frequency -- a production
distribution would have its own mix, and this corpus is uniform.
"""

from __future__ import annotations

import json
import pathlib
import pickle
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from sentinel.domain.detection_metrics import (  # noqa: E402
    CorpusProvenance,
    measure_detection,
)

ROOT = pathlib.Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "evaluation" / "artifacts" / "soft_prompt_model.pkl"
OUT = ROOT / "reports" / "benign_tool_call_false_positives.json"
THRESHOLD = 0.5

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
    if not ARTIFACT.is_file():
        print(f"artifact not found: {ARTIFACT}", file=sys.stderr)
        return 2
    pipeline = pickle.loads(ARTIFACT.read_bytes())["pipeline"]

    scores = [float(p[1]) for p in pipeline.predict_proba(BENIGN_ACTIONS)]
    rows = sorted(zip(BENIGN_ACTIONS, scores), key=lambda r: -r[1])
    fired = [(a, s) for a, s in rows if s >= THRESHOLD]

    payload = {
        "status": "measured_benign_tool_call_false_positives",
        "threshold": THRESHOLD,
        "n_benign_actions": len(BENIGN_ACTIONS),
        "n_fired": len(fired),
        "false_positive_rate": round(len(fired) / len(BENIGN_ACTIONS), 4),
        "mean_score": round(sum(scores) / len(scores), 4),
        "max_score": round(max(scores), 4),
        "min_score": round(min(scores), 4),
        "fired": [{"action": a, "score": round(s, 4)} for a, s in fired],
        "all_scores": [{"action": a, "score": round(s, 4)} for a, s in rows],
        "method": (
            "Each string is scored exactly as SoftAugmentedPolicy would score it: "
            "the tool-call `action` field, via the fallback used when an event "
            "carries no metadata.prompt. Fires at score >= threshold."
        ),
        "not_measured": [
            "recall on real injection attempts -- see evaluation/",
            "the real-world frequency mix of these actions; this corpus is uniform",
            "any prompt-bearing event; only the tool-call action fallback",
        ],
    }

    # PROVENANCE, CARRIED WITH THE NUMBER.
    #
    # This corpus is hand-written: `BENIGN_ACTIONS` is a vocabulary somebody
    # chose. The docstring has always said so, and a docstring does not travel
    # with a false-positive rate into a slide. `sentinel/domain/
    # detection_metrics.py` attaches the provenance to the measurement and
    # derives `real_world` from it, so no reader of this artifact can mistake
    # a synthetic false-positive rate for production behaviour.
    #
    # Every action here is a true negative or a false positive by
    # construction: none of them is an injection attempt by any reading, so
    # there are no actual positives in this corpus at all -- which is why
    # `recall` comes back None rather than 0.0.
    measurement = measure_detection(
        provenance=CorpusProvenance.SYNTHETIC,
        true_positives=0,
        false_positives=len(fired),
        true_negatives=len(BENIGN_ACTIONS) - len(fired),
        false_negatives=0,
    )
    payload["provenance"] = measurement.as_dict()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(
        f"benign tool-call actions: {payload['n_benign_actions']}\n"
        f"fired at threshold {THRESHOLD}: {payload['n_fired']} "
        f"({payload['false_positive_rate']:.1%})\n"
        f"mean score {payload['mean_score']}  max {payload['max_score']}"
    )
    for action, score in fired[:12]:
        print(f"  {score:.4f}  {action}")
    print()
    print(measurement.claim)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
