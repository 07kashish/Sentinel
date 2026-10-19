"""One entry point for the DR drills, and one honest verdict.

WHY A WRAPPER
-------------
There are four drills and they measure different things. An operator asking
"is our recovery working" should not have to know which one to run, and --
more importantly -- should not be able to run the cheapest one and read its
success as an answer about the others.

WHAT EACH DRILL PROVES, AND WHAT IT DOES NOT
---------------------------------------------
  sqlite            a file copy and restore. Proves the restore CODE path.
                    Says nothing about PostgreSQL, WAL, or a real failure.
  postgres_dump     a pg_dump round trip. RPO is 0 by construction, because
                    the dump is a snapshot taken while you are watching -- so
                    the number it produces is not the number that matters in
                    an unplanned loss.
  postgres_wal      continuous WAL archiving and a real recovery. THIS is the
                    one whose RPO means something, and the recorded artifact
                    measures 12.77 seconds.

NONE OF THEM IS THE OPEN GATE
------------------------------
`INDEPENDENT_FAILURE_DOMAIN_DR` requires a restore into a genuinely separate
failure domain -- another region or another account. Every drill here runs in
ONE domain, on one machine, and so it cannot close that gate no matter how
many times it passes. This script says so in its verdict rather than leaving a
green run to be read as coverage it does not have.

`--strict` fails when any selected drill is skipped, which is what a CI job
should use: a drill skipped for a missing PostgreSQL is not a drill that
passed, and a pipeline that treats the two alike reports recovery it has not
exercised.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

PASS, FAIL, SKIPPED = "PASS", "FAIL", "SKIPPED"


@dataclass(frozen=True)
class Drill:
    name: str
    script: str
    #: What a PASS here actually establishes.
    proves: str
    #: What it does not, so a green run cannot be over-read.
    does_not_prove: str
    #: Whether it needs something this machine may not have.
    needs: str = ""


DRILLS: tuple[Drill, ...] = (
    Drill(
        name="sqlite",
        script="run_dr_sqlite_drill.py",
        proves="the backup and restore CODE PATH runs and the restored "
               "database passes an integrity check",
        does_not_prove="anything about PostgreSQL, WAL archiving, or recovery "
                       "from an unplanned loss. SQLite has no RLS layer, so a "
                       "restore verified here is not a restore of the "
                       "tenant-isolation guarantees",
    ),
    Drill(
        name="postgres_dump",
        script="run_dr_postgres_pitr_drill.py",
        proves="rows survive a pg_dump round trip on a real PostgreSQL",
        does_not_prove="a meaningful RPO. A dump is a snapshot taken while "
                       "you are watching, so its RPO is 0 by construction -- "
                       "which is not the number that matters when the loss is "
                       "unplanned",
        needs="a PostgreSQL server (pgserver or SENTINEL_TEST_POSTGRES_DSN)",
    ),
    Drill(
        name="postgres_wal",
        script="run_dr_postgres_wal_pitr_drill.py",
        proves="continuous WAL archiving and a real point-in-time recovery, "
               "with an RPO measured from actual archive lag",
        does_not_prove="recovery in a separate failure domain. This runs on "
                       "one machine, so it does not exercise the case where "
                       "the machine is gone",
        needs="a PostgreSQL server with archive_mode",
    ),
)

BY_NAME = {drill.name: drill for drill in DRILLS}

#: Printed in every verdict. The gate stays open however many drills pass.
OPEN_GATE_NOTE = (
    "INDEPENDENT_FAILURE_DOMAIN_DR remains OPEN. Every drill here runs in ONE "
    "failure domain on one machine. A restore into another region or account "
    "is what closes it, and no number of passes above substitutes for that."
)


@dataclass(frozen=True)
class Result:
    drill: Drill
    status: str
    detail: str


def _run(drill: Drill, *, timeout: int) -> Result:
    script = ROOT / "scripts" / drill.script
    if not script.exists():
        return Result(drill, FAIL, f"{drill.script} is missing")

    try:
        completed = subprocess.run(
            [sys.executable, str(script)],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            timeout=timeout,
            env={"PYTHONPATH": str(ROOT)},
        )
    except subprocess.TimeoutExpired:
        return Result(
            drill,
            FAIL,
            f"exceeded {timeout}s. A recovery that does not finish is a "
            "recovery that failed, so this is FAIL rather than SKIPPED.",
        )
    except OSError as error:
        return Result(drill, FAIL, f"could not be launched: {error}")

    output = (completed.stdout or "") + (completed.stderr or "")

    if completed.returncode == 0:
        return Result(drill, PASS, drill.proves)

    # A missing dependency is SKIPPED, not FAIL -- but only when the script
    # said so. Inferring "skipped" from any non-zero exit would turn a genuine
    # recovery failure into a shrug.
    lowered = output.lower()
    if any(
        marker in lowered
        for marker in ("no postgresql", "pgserver", "skipping", "not installed")
    ):
        return Result(
            drill,
            SKIPPED,
            f"needs {drill.needs or 'a dependency this machine lacks'}. NOT a "
            "pass: nothing was exercised.",
        )

    return Result(drill, FAIL, output.strip()[-600:] or "no output")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the disaster-recovery drills and report one verdict."
    )
    parser.add_argument(
        "--only",
        action="append",
        choices=sorted(BY_NAME),
        default=None,
        help="Run only these drills. Repeatable.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "Fail when any selected drill is SKIPPED. What a CI job should "
            "use: a drill skipped for a missing server is not a drill that "
            "passed."
        ),
    )
    parser.add_argument(
        "--timeout", type=int, default=900,
        help="Per-drill timeout in seconds.",
    )
    parser.add_argument(
        "--evidence", type=Path, default=None,
        help="Write the verdict as JSON here, for the release bundle.",
    )
    parser.add_argument(
        "--explain", action="store_true",
        help="Print what each drill proves and does not prove, then exit.",
    )
    args = parser.parse_args(argv)

    if args.explain:
        for drill in DRILLS:
            print(f"{drill.name}")
            print(f"  proves:          {drill.proves}")
            print(f"  does NOT prove:  {drill.does_not_prove}")
            if drill.needs:
                print(f"  needs:           {drill.needs}")
            print()
        print(OPEN_GATE_NOTE)
        return 0

    selected = [BY_NAME[name] for name in (args.only or sorted(BY_NAME))]

    results = [_run(drill, timeout=args.timeout) for drill in selected]

    print()
    for result in results:
        print(f"{result.status:<8} {result.drill.name}")
        print(f"         {result.detail}")
        if result.status == PASS:
            # The limit is printed NEXT TO the pass, not in a footnote. A green
            # line read on its own is how a drill becomes over-quoted.
            print(f"         does NOT prove: {result.drill.does_not_prove}")
        print()

    passed = sum(1 for r in results if r.status == PASS)
    failed = sum(1 for r in results if r.status == FAIL)
    skipped = sum(1 for r in results if r.status == SKIPPED)

    print(f"{passed} passed, {failed} failed, {skipped} skipped")
    print()
    print(OPEN_GATE_NOTE)

    if args.evidence is not None:
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(
            json.dumps(
                {
                    "schema": "sentinel.dr_test.v1",
                    "ran_at": datetime.now(timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    ),
                    "results": [
                        {
                            "drill": r.drill.name,
                            "status": r.status,
                            "detail": r.detail,
                            "proves": r.drill.proves,
                            "does_not_prove": r.drill.does_not_prove,
                        }
                        for r in results
                    ],
                    "passed": passed,
                    "failed": failed,
                    "skipped": skipped,
                    # A CONSTANT false. No arrangement of these drills closes
                    # the gate, so nothing here can set it true.
                    "independent_failure_domain_verified": False,
                    "open_gate": OPEN_GATE_NOTE,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"\nwrote {args.evidence}")

    if failed:
        return 1
    if skipped and args.strict:
        print(
            f"\n{skipped} drill(s) were SKIPPED and --strict was given. A "
            "drill that did not run is not a drill that passed.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
