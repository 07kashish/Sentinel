"""Evaluate this deployment's SLO targets against a soak artifact.

WHY THIS SCRIPT EXISTS
----------------------
`docs/OBSERVABILITY.md` carried an SLI/SLO table whose Status column was prose:
**UNVERIFIED**, **MET on PostgreSQL**, **MISSED on SQLite**. Nothing computed
those words, so nothing could contradict them. This computes them from a soak
artifact and exits non-zero when a target is violated.

THE TARGETS ARE ENCODED ONCE, HERE
-----------------------------------
As numbers and periods rather than sentences, so a verdict can be derived. The
document quotes them; this is the definition.

WHAT IT REFUSES TO SAY
----------------------
That a 30-day availability SLO is MET on the strength of a 40-minute run. The
target permits ~2,592 seconds of failure over its period -- longer than most
soak runs -- so a short run observing zero failures has learned almost
nothing, and `sentinel/domain/slo.py` returns UNMEASURABLE for it.

A VIOLATION, though, is reported from any window. Falsifying an SLO needs less
evidence than confirming one.

EXIT CODES
----------
  0  every target MET
  1  at least one target UNMEASURABLE, none violated -- the honest result for
     a short run, and NOT a pass
  2  at least one target VIOLATED

1 rather than 0 for "could not tell" is the whole design. A soak that exits 0
because it was too short to fail is how an unverified SLO becomes a green
build.

REQUIRES EXTERNAL VALIDATION
-----------------------------
PRODUCTION_SOAK stays open regardless of what this prints. A soak on a
developer machine is not production traffic, and no exit code from here can
change that.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sentinel.domain.slo import (
    SloKind,
    SloState,
    SloTarget,
    evaluate_all,
)

THIRTY_DAYS_SECONDS = 30 * 24 * 60 * 60

#: The targets `docs/OBSERVABILITY.md` states, as numbers. `availability` is a
#: RATIO, not a percentage: `SloTarget` refuses 99.9 for exactly this field,
#: because a threshold of 99.9 compared against a ratio would be satisfied by
#: every possible measurement and would look like a stricter target.
TARGETS = (
    SloTarget(
        name="api_availability",
        kind=SloKind.AVAILABILITY,
        threshold=0.999,
        window_seconds=THIRTY_DAYS_SECONDS,
    ),
    SloTarget(
        name="ingest_p95_latency_ms",
        kind=SloKind.LATENCY_PERCENTILE,
        threshold=500.0,
        percentile=95,
    ),
    SloTarget(
        name="worker_dead_letter_rate",
        kind=SloKind.ERROR_RATE,
        threshold=0.01,
        window_seconds=THIRTY_DAYS_SECONDS,
    ),
)


def _observations(payload: dict) -> dict[str, dict]:
    """Map a real soak artifact onto the target names.

    THE SHAPE IS THE ARTIFACT'S, NOT ONE I WISHED FOR
    --------------------------------------------------
    Written against `docs/observability_soak_postgres.json` as it actually is:
    `window.elapsed_seconds`, `measured.ready.{attempts,failures}` and
    `measured.ingest.p95_ms`. My first attempt read plausible-looking keys
    (`health`, `ingest.latencies_ms`, `seconds`) that the artifact does not
    have, so every target came back UNMEASURABLE and the harness looked
    cautious while reading nothing at all. That is the defect shape this
    codebase keeps producing, so
    `test_the_mapper_reads_the_real_soak_artifact` pins it to the real file.

    Deliberately tolerant of a missing key and deliberately NOT tolerant of
    inventing one: a target with no observation is left ABSENT so
    `evaluate_all` reports it UNMEASURABLE, rather than being handed zeros that
    would evaluate to a clean 0% error rate.
    """
    observed: dict[str, dict] = {}
    window = payload.get("window") or {}
    duration = float(
        window.get("elapsed_seconds")
        or payload.get("seconds")
        or payload.get("duration_seconds")
        or 0
    )
    measured = payload.get("measured") or {}

    # `/health/ready` is the availability SLI named in docs/OBSERVABILITY.md.
    ready = measured.get("ready") or {}
    attempts = int(ready.get("attempts", 0) or 0)
    if attempts:
        failures = int(ready.get("failures", 0) or 0)
        observed["api_availability"] = {
            "successes": attempts - failures,
            "failures": failures,
            "observed_seconds": duration,
        }

    ingest = measured.get("ingest") or {}
    raw = ingest.get("latencies_ms") or ingest.get("samples_ms") or ()
    ingest_attempts = int(ingest.get("attempts", 0) or 0)
    if raw:
        observed["ingest_p95_latency_ms"] = {"latencies_ms": list(raw)}
    elif ingest.get("p95_ms") is not None and ingest_attempts:
        # The producer computed the percentile and did not keep the raw
        # values. Admissible because the SAMPLE COUNT is carried with it: the
        # arithmetic is trusted, and 16,082 samples is what makes trusting it
        # reasonable where 3 would not be.
        observed["ingest_p95_latency_ms"] = {
            "reported_percentile_ms": float(ingest["p95_ms"]),
            "sample_count": ingest_attempts,
        }

    # Nothing in the current soak measures the worker dead-letter rate, so it
    # is left absent on purpose and reports UNMEASURABLE. Supplying zeros here
    # would render a 0% dead-letter rate from a run that never enqueued work.
    worker = measured.get("worker") or payload.get("worker") or {}
    worker_attempts = int(worker.get("attempts", 0) or 0)
    if worker_attempts:
        dead = int(worker.get("dead_lettered", 0) or 0)
        observed["worker_dead_letter_rate"] = {
            "successes": worker_attempts - dead,
            "failures": dead,
            "observed_seconds": duration,
        }
    return observed


def _self_assertion(payload: dict) -> str | None:
    """The artifact's own claim about the ingest target, if it makes one.

    Reported next to the computed verdict rather than ignored. The artifact
    carries `meets_ingest_p95_target`, a boolean the producer wrote about
    itself, and the point of this harness is that such a claim is now
    checkable rather than authoritative. Printing both is how a disagreement
    becomes visible instead of a matter of which file you read.
    """
    if "meets_ingest_p95_target" not in payload:
        return None
    return str(bool(payload["meets_ingest_p95_target"]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "artifact",
        nargs="?",
        default="docs/observability_soak_postgres.json",
        help="soak artifact produced by scripts/run_observability_soak.py",
    )
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--explain",
        action="store_true",
        help="print the encoded targets and their error budgets",
    )
    args = parser.parse_args(argv)

    if args.explain:
        print("Encoded SLO targets:")
        for target in TARGETS:
            line = f"  {target.name:<26} {target.kind.value:<20}"
            if target.kind is SloKind.LATENCY_PERCENTILE:
                line += f"p{target.percentile} <= {target.threshold:.0f} ms"
            else:
                line += f"{target.threshold:.6f} over {target.window_seconds:.0f}s"
                if target.budget_seconds:
                    line += f"  (failure budget {target.budget_seconds:.0f}s)"
            print(line)
        print()
        print(
            "A run shorter than 10% of a target's period cannot report MET for "
            "it. The error budget alone is often longer than a soak run."
        )
        return 0

    path = Path(args.artifact)
    if not path.exists():
        print(f"no soak artifact at {path}.")
        print()
        print(
            "Produce one first:\n"
            "  PYTHONPATH=. python scripts/run_observability_soak.py "
            "--seconds 420 --production-shaped --postgres"
        )
        print()
        print(
            "Exiting 1: an absent measurement is not a passing one. This is "
            "the same distinction the discovery CLI makes between 'nothing "
            "configured' and 'nothing found'."
        )
        return 1

    payload = json.loads(path.read_text(encoding="utf-8"))
    observed = _observations(payload)
    verdicts = evaluate_all(TARGETS, observed)
    claimed = _self_assertion(payload)

    if args.json:
        print(
            json.dumps(
                {
                    "artifact": str(path),
                    "verdicts": [v.as_dict() for v in verdicts],
                    "artifact_self_assertion_meets_ingest_p95": claimed,
                    "gate": (
                        "PRODUCTION_SOAK remains open regardless of these "
                        "results: a soak on a developer machine is not "
                        "production traffic."
                    ),
                },
                indent=2,
            )
        )
    else:
        print(f"SLO evaluation of {path}")
        print()
        for verdict in verdicts:
            marker = {
                SloState.MET: "MET",
                SloState.VIOLATED: "VIOLATED",
                SloState.UNMEASURABLE: "UNMEASURABLE",
            }[verdict.state]
            value = (
                f"{verdict.observed:.6g}" if verdict.observed is not None else "-"
            )
            print(f"  {verdict.target.name:<26} {marker:<14} observed={value}")
            if verdict.reason:
                print(f"      {verdict.reason}")
        print()
        if claimed is not None:
            print(
                f"The artifact asserts meets_ingest_p95_target={claimed}. That "
                "is the producer's claim about itself; the verdict above is "
                "computed from the numbers, so the two can now disagree "
                "visibly."
            )
            print()
        print(
            "PRODUCTION_SOAK remains OPEN regardless of the above. A soak on a "
            "developer machine is not production traffic, and no exit code "
            "here can change that."
        )

    if any(v.state is SloState.VIOLATED for v in verdicts):
        return 2
    if any(v.state is SloState.UNMEASURABLE for v in verdicts):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
