"""Scan this machine for agent software. Read-only, allowlisted paths only.

WHAT IT READS
-------------
Run it with `--explain` to see the complete list before running it for real.
That ordering is deliberate: an endpoint tool nobody can inspect before
installing is an endpoint tool nobody should install, and printing the
allowlist is cheaper than asking somebody to read the source.

WHAT IT NEVER DOES
------------------
  * walk a home directory, or read anything not on the allowlist;
  * retain a credential VALUE -- only a 16-character digest, so the same key
    across machines is correlatable and unrecoverable;
  * write to any scanned path. There is no repair and no quarantine.

WHY IT PRINTS COVERAGE BEFORE FINDINGS
---------------------------------------
A scan that read nothing and a machine with no agents produce the same empty
list. The outcome line comes first so "0 findings" is never read as "clean"
when it means "blind".

EXIT CODE
---------
  0  scan complete
  1  scan was PARTIAL or UNREADABLE -- the absences mean nothing
  2  bad invocation

A non-zero exit on an incomplete scan is the point: a fleet rollout that
counted incomplete scans as successes would report coverage it does not have.
"""

from __future__ import annotations

import argparse
import json
import platform
import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel.domain.endpoint_sensor import (  # noqa: E402
    ScanOutcome,
    classify,
)
from sentinel.infrastructure.endpoint_scan import ALLOWLIST, scan_endpoint  # noqa: E402


def _explain() -> int:
    print("This sensor reads ONLY these paths, relative to the scan root:\n")
    for entry in ALLOWLIST:
        print(f"  {entry.path}")
        print(f"      {entry.why}")
    print(
        "\nNothing else is read. No home directory walk, no documents, no "
        "browser data,\nno shell history. Credential VALUES are never "
        "retained -- only a 16-character\ndigest, which correlates the same "
        "key across machines and cannot recover it.\n"
        "\nNothing is opened for writing: there is no repair and no "
        "quarantine."
    )
    return 0


def _host_id() -> str:
    """A stable, non-identifying host label.

    The hostname, because an operator needs to know WHICH machine. Not the
    username, not a MAC address, not a hardware serial -- a sensor that builds
    a durable device fingerprint has collected something it was not asked for.
    """
    try:
        return socket.gethostname()
    except OSError:
        return f"unknown-{platform.system().lower()}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Discover agent software on this machine. Read-only."
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Print the complete allowlist and exit. Read this first.",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.home(),
        help="Scan root. Defaults to the home directory.",
    )
    parser.add_argument(
        "--enrolled",
        type=Path,
        default=None,
        help=(
            "JSON list of enrolled agent names. WITHOUT it nothing is called "
            "shadow -- only UNKNOWN, because deciding shadow needs to know "
            "what the estate has."
        ),
    )
    parser.add_argument("--json", action="store_true", help="Machine-readable.")
    args = parser.parse_args(argv)

    if args.explain:
        return _explain()

    if not args.root.is_dir():
        print(f"{args.root} is not a directory", file=sys.stderr)
        return 2

    enrolled = None
    if args.enrolled is not None:
        try:
            enrolled = json.loads(args.enrolled.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            # Refused rather than defaulted to an empty list. An empty list
            # means "the estate has nothing", which would report every agent
            # here as shadow -- a far louder claim than "I could not read the
            # file".
            print(
                f"could not read {args.enrolled}: {error}. Refusing to treat "
                "that as an empty enrolled set, which would report every agent "
                "on this machine as shadow.",
                file=sys.stderr,
            )
            return 2
        if not isinstance(enrolled, list):
            print(f"{args.enrolled} must contain a JSON list", file=sys.stderr)
            return 2

    scan = scan_endpoint(root=args.root, host_id=_host_id())
    report = classify(scan, enrolled=enrolled)

    if args.json:
        print(json.dumps(report.as_dict(), indent=2))
    else:
        # COVERAGE FIRST. "0 findings" must never be read as "clean" when it
        # means "blind".
        print(f"coverage: {report.outcome.value} -- {report.outcome.explanation}")
        print(f"paths read: {len(report.inspected)}, unreadable: "
              f"{len(report.unreadable)}")
        print()
        print(report.render())
        if enrolled is None and report.findings:
            print(
                "\nNo enrolled set was supplied, so nothing above is called "
                "shadow. Pass --enrolled to answer that."
            )

    return 0 if report.outcome is ScanOutcome.COMPLETE else 1


if __name__ == "__main__":
    raise SystemExit(main())
