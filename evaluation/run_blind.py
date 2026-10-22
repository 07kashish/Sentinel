#!/usr/bin/env python3
"""Evaluate the SHIPPED policy on a corpus its authors never saw.

WHY THE EXISTING NUMBERS ARE NOT ENOUGH
---------------------------------------
`evaluation/metrics.json` is measured on a corpus assembled by the people who
tuned the rules. It shows the detector fits what it was fitted to. It says
nothing about events nobody here has looked at, and no detection claim may be
made from it (RISK R-005).

THE PROTOCOL, WHICH IS THE POINT
--------------------------------
1. SEAL. Someone who has not read `config/default_policy.json` assembles a
   corpus (JSON Lines; see FORMAT) and runs:
       python evaluation/run_blind.py seal corpus.jsonl --by "<name, org>"
   That writes `evaluation/blind/<digest12>.seal.json` holding the corpus
   sha256, the case and class counts, who sealed it and when -- and NOT the
   corpus. The seal is committed BEFORE the policy authors see any case.
2. RUN. With the corpus file in hand:
       python evaluation/run_blind.py run corpus.jsonl
   The run refuses a corpus with no committed seal, or whose bytes differ from
   the seal, so cases cannot be added, dropped or relabelled after the fact.
3. ONE SHOT. A second run against the same seal is refused unless
   `--acknowledge-rerun`, and the result then records how many runs preceded
   it. A corpus the detector has been tuned against is no longer blind, and
   the artifact must say so rather than let a tenth attempt pass as a first.

Results carry per-class recall and the benign false-positive rate with Wilson
95% intervals, the policy digest, the commit and the environment. They are
recorded with the corpus digest, commit and environment.

FORMAT
------
One JSON object per line:
    {"id": "...", "label": "malicious" | "benign", "class": "<free text>",
     "payload": {<an event as POST /v1/protect/evaluate accepts it>}}

`detected` means the shipped deterministic policy FIRED on the payload for an
unsigned caller. The optional soft classifier is not part of this measure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation.intervals import wilson  # noqa: E402
from sentinel.domain.primitives import TrustLevel  # noqa: E402
from sentinel.infrastructure.detection import DeterministicPolicy  # noqa: E402

BLIND = ROOT / "evaluation" / "blind"
LABELS = ("malicious", "benign")
MIN_CASES = 50


class BlindProtocolError(RuntimeError):
    """The protocol was not followed. Never downgraded to a warning."""


def load_cases(path: Path) -> tuple[str, list[dict]]:
    raw = path.read_bytes()
    cases: list[dict] = []
    seen: set[str] = set()
    for number, line in enumerate(raw.decode("utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            case = json.loads(line)
        except json.JSONDecodeError as exc:
            raise BlindProtocolError(f"line {number} is not JSON") from exc
        if case.get("label") not in LABELS or not isinstance(case.get("payload"), dict) \
                or not str(case.get("id", "")).strip() or not str(case.get("class", "")).strip():
            raise BlindProtocolError(f"line {number} needs id, label ({'/'.join(LABELS)}), class and payload")
        if case["id"] in seen:
            raise BlindProtocolError(f"line {number} repeats id {case['id']!r}")
        seen.add(case["id"])
        cases.append(case)
    labels = Counter(c["label"] for c in cases)
    if len(cases) < MIN_CASES or not all(labels.get(label) for label in LABELS):
        raise BlindProtocolError(
            f"a blind corpus needs at least {MIN_CASES} cases with both labels present; "
            f"got {len(cases)} ({dict(labels)}). Fewer than that supports no interval worth reading."
        )
    return hashlib.sha256(raw).hexdigest(), cases


def seal(path: Path, *, by: str, out: Path = BLIND) -> Path:
    if len(by.strip()) < 5:
        raise BlindProtocolError("--by must name who assembled the corpus and their organisation")
    digest, cases = load_cases(path)
    target = out / f"{digest[:12]}.seal.json"
    if target.exists():
        raise BlindProtocolError(f"{target.name} already exists; a corpus is sealed once")
    out.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({
        "schema": "sentinel.blind-seal/v1",
        "corpus_sha256": digest,
        "cases": len(cases),
        "labels": dict(Counter(c["label"] for c in cases)),
        "classes": dict(Counter(c["class"] for c in cases)),
        "sealed_by": by.strip(),
        "sealed_at": datetime.now(timezone.utc).isoformat(),
        "note": "Commit this file BEFORE anyone who maintains the policy sees the corpus.",
    }, indent=2) + "\n", encoding="utf-8")
    return target


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=str(ROOT), capture_output=True, text=True, check=False).stdout.strip()  # noqa: S603,S607


def _seal_is_committed(seal_path: Path) -> bool:
    try:
        relative = str(seal_path.resolve().relative_to(ROOT))
    except ValueError:
        return False  # a seal outside the repository cannot have been committed to it
    tracked = bool(_git("ls-files", "--", relative))
    clean = not _git("status", "--porcelain", "--", relative)
    return tracked and clean


def _interval(successes: int, trials: int) -> dict:
    interval = wilson(successes, trials)
    return {"successes": successes, "trials": trials, "point": round(interval.point, 4),
            "wilson95": [round(interval.lower, 4), round(interval.upper, 4)]}


def run(path: Path, *, acknowledge_rerun: bool = False, out: Path = BLIND,
        require_committed_seal: bool = True) -> dict:
    digest, cases = load_cases(path)
    seal_path = out / f"{digest[:12]}.seal.json"
    if not seal_path.is_file():
        raise BlindProtocolError("this corpus has no seal, or its bytes differ from the sealed ones; seal it first")
    sealed = json.loads(seal_path.read_text(encoding="utf-8"))
    if sealed["corpus_sha256"] != digest:
        raise BlindProtocolError("the corpus does not match its seal")
    if require_committed_seal and not _seal_is_committed(seal_path):
        raise BlindProtocolError("the seal is not committed; commit it before running, or the order of events is unprovable")
    previous = sorted(out.glob(f"{digest[:12]}.result-*.json"))
    if previous and not acknowledge_rerun:
        raise BlindProtocolError(
            f"this corpus has already been run {len(previous)} time(s). A corpus the policy was tuned "
            "against is no longer blind. Use --acknowledge-rerun; the result will record it."
        )

    policy = DeterministicPolicy.default()
    by_class: dict[str, list[bool]] = defaultdict(list)
    benign_fired = benign_total = 0
    for case in cases:
        fired = bool(policy.evaluate(payload=case["payload"], trust=TrustLevel.UNSIGNED).fired)
        if case["label"] == "malicious":
            by_class[case["class"]].append(fired)
        else:
            benign_total += 1
            benign_fired += int(fired)
    detected = sum(sum(v) for v in by_class.values())
    malicious = sum(len(v) for v in by_class.values())
    result = {
        "schema": "sentinel.blind-result/v1",
        "corpus_sha256": digest,
        "sealed_by": sealed["sealed_by"],
        "sealed_at": sealed["sealed_at"],
        "run_at": datetime.now(timezone.utc).isoformat(),
        "run_number": len(previous) + 1,
        "blind": not previous,
        "policy": {"version": policy.version(), "digest": policy.digest()},
        "commit": _git("rev-parse", "HEAD"),
        "working_tree_dirty": bool(_git("status", "--porcelain")),
        "environment": {"python": platform.python_version(), "platform": platform.platform()},
        "recall": _interval(detected, malicious),
        "recall_by_class": {name: _interval(sum(v), len(v)) for name, v in sorted(by_class.items())},
        "benign_false_positive_rate": _interval(benign_fired, benign_total),
        "limitations": [
            "deterministic policy only; the optional soft classifier is not measured",
            "unsigned caller; a verified caller sees uncapped severity but the same rule matches",
            "one corpus from one assembler is one sample of the world, not the world",
        ],
    }
    target = out / f"{digest[:12]}.result-{result['run_number']:02d}.json"
    target.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    sealing = commands.add_parser("seal")
    sealing.add_argument("corpus", type=Path)
    sealing.add_argument("--by", required=True)
    running = commands.add_parser("run")
    running.add_argument("corpus", type=Path)
    running.add_argument("--acknowledge-rerun", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "seal":
            print(f"sealed: {seal(args.corpus, by=args.by).relative_to(ROOT)} -- commit it now, before anyone reads the corpus")
            return 0
        result = run(args.corpus, acknowledge_rerun=args.acknowledge_rerun)
    except BlindProtocolError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({k: result[k] for k in ("blind", "run_number", "recall", "benign_false_positive_rate")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
