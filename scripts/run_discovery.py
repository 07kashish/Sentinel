"""Run every configured discovery connector and report what it saw.

WHY THIS SCRIPT EXISTS
----------------------
The connectors had tests and no caller. This is the entry point an operator
actually runs, and the thing that makes a zero result interpretable.

THE DISTINCTION IT IS BUILT AROUND
-----------------------------------
"No agents found" has two completely different meanings:

  * no credential was configured, so nothing was looked at;
  * a credential was configured, the platform answered, and the estate is
    clean.

A tool that renders both as `0` has taught its operator to ignore it. So this
exits NON-ZERO when nothing is configured, prints which connectors are absent,
and never prints a bare count without the coverage beside it.

EXIT CODES
----------
  0  at least one connector ran and every one completed fully
  1  nothing configured -- NOT a clean estate, an unperformed scan
  2  a connector failed, or its coverage was partial

2 rather than 0 for partial coverage is deliberate. A truncated listing that
exits 0 in CI is a subset recorded as a total.

REQUIRES EXTERNAL VALIDATION
-----------------------------
Five of these connectors have never authenticated against a real tenant. The
report says so per connector, because that caveat is worthless in a document
nobody opens at the moment they read a number.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from sentinel.composition.discovery_wiring import (
    build_discovery_connectors,
    describe_discovery,
    run_discovery,
)
from sentinel.infrastructure.platforms.discovery_breadth import (
    BREADTH_CONFIGURATION,
    build_breadth_connectors,
)

#: Printed by `--explain`. The connectors and the env vars that enable them,
#: so an operator can tell what is possible without reading the source.
CONFIGURATION = (
    ("kubernetes", "SENTINEL_DISCOVERY_K8S_SERVER + _TOKEN + _NAMESPACES"),
    ("aws_iam", "SENTINEL_DISCOVERY_AWS_ACCESS_KEY_ID + _SECRET_ACCESS_KEY + _REGION"),
    ("bedrock_agent", "SENTINEL_DISCOVERY_BEDROCK_ACCESS_KEY_ID + _SECRET_ACCESS_KEY + _REGION"),
    ("entra", "SENTINEL_DISCOVERY_ENTRA_TOKEN + _TENANT"),
    ("vertex", "SENTINEL_DISCOVERY_VERTEX_TOKEN + _PROJECT [+ _LOCATION]"),
    ("openai", "SENTINEL_DISCOVERY_OPENAI_TOKEN [+ _ORG]"),
    ("generic_mcp", "SENTINEL_DISCOVERY_MCP_ENDPOINTS=label=url,label2=url2"),
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--json", action="store_true", help="emit the report as JSON"
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="print the connectors and the variables that configure them",
    )
    args = parser.parse_args(argv)

    if args.explain:
        print("Discovery connectors and the variables that enable them:")
        for name, variables in CONFIGURATION + BREADTH_CONFIGURATION:
            print(f"  {name:<22} {variables}")
        print()
        print(
            "An unconfigured connector is ABSENT, never present-and-empty: an "
            "empty inventory cannot be told apart from a clean estate."
        )
        return 0

    # The environment is read HERE, at the script's edge, and handed in as a
    # plain mapping: `build_discovery_connectors` takes a source rather than
    # reaching for `os.environ` itself, so a test can drive it with a dict. The
    # breadth connectors merge in by name; the two registries share no keys.
    source = dict(os.environ)
    connectors = build_discovery_connectors(source)
    connectors.update(build_breadth_connectors(source))
    summary = describe_discovery(connectors)

    if not connectors:
        if args.json:
            print(json.dumps({"summary": summary, "reports": []}, indent=2))
        else:
            print("NO DISCOVERY CONNECTOR IS CONFIGURED.")
            print()
            print(summary["note"])
            print()
            print("Run with --explain to see what each connector needs.")
        # Non-zero: an unperformed scan must not read as a passing one.
        return 1

    reports = run_discovery(connectors)

    if args.json:
        print(json.dumps({"summary": summary, "reports": reports}, indent=2))
    else:
        print(f"Configured connectors: {', '.join(summary['configured'])}")
        if summary["unvalidated"]:
            print(
                "REQUIRES EXTERNAL VALIDATION (never authenticated against a "
                f"real tenant): {', '.join(summary['unvalidated'])}"
            )
        print()
        for report in reports:
            name = report["connector"]
            if report["failed"]:
                print(f"  {name}: FAILED -- {report['error']}")
                continue
            coverage = report["coverage"]
            print(
                f"  {name}: {report['assets']} asset(s) from "
                f"{coverage['examined']} examined"
                + ("  [PARTIAL]" if coverage["is_partial"] else "")
            )
            for entry in coverage["unreachable"]:
                print(f"      unreachable: {entry['target']} -- {entry['reason']}")
        print()
        print(summary["note"])

    degraded = any(
        report["failed"] or report["coverage"]["is_partial"]
        for report in reports
    )
    return 2 if degraded else 0


if __name__ == "__main__":
    sys.exit(main())
