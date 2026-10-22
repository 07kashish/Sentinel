"""Render the Helm chart, and prove its refusals actually refuse.

WHY THIS IS NOT `helm lint`
---------------------------
`helm lint deploy/helm/sentinel` FAILS on this chart, and it is supposed to.
The chart carries two deliberate refusals that fire on the default values:

  * `externalPostgres.archiveTimeoutConfirmed` must be the literal `true`.
    The chart does not deploy PostgreSQL -- it consumes a DSN -- so the RPO
    promised in DISASTER_RECOVERY.md depends on archive settings this chart
    cannot apply. Before the guard, the only thing saying so was a line in
    NOTES.txt printed after a successful install, which is after it is too
    late. Measured: RPO ~57s with `archive_timeout` set, unbounded without.

  * `corsOrigins` must be set. A production deployment refuses a wildcard CORS
    origin on a credentialed API.

A gate that ran `helm lint` and reported the failure would be reporting the
chart's safety features as defects, and the obvious way to make it green would
be to remove them. So this checks the property that actually matters:

    the guards refuse when they should, AND the chart renders when they are met.

Either half alone is worthless. A chart that always refuses is not deployable;
a chart that always renders has no guards.

WHAT THIS DOES NOT PROVE
------------------------
That the manifests work on a cluster. Nothing here talks to an API server, so
`kubernetes_helm` PASSING means the templates are valid and the guards hold --
not that a deployment would come up. Admission control, storage classes, image
pull and every runtime concern are outside what a render can see.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


CHART = ROOT / "deploy" / "helm" / "sentinel"
OUT = ROOT / "release" / "gates" / "gate_kubernetes_helm.json"

#: The minimum a deployer must state before the chart will render. Each entry is
#: an acknowledgement the chart cannot verify for itself.
ACKNOWLEDGEMENTS = (
    "--set", "externalPostgres.archiveTimeoutConfirmed=true",
    "--set", "corsOrigins={https://console.example.com}",
)

#: Guards that MUST fire. Each is (name, extra args that omit the
#: acknowledgement, a fragment the refusal must mention).
GUARDS = (
    (
        "archive_timeout_unconfirmed",
        ("--set", "corsOrigins={https://console.example.com}"),
        "archiveTimeoutConfirmed",
    ),
    (
        "wildcard_cors",
        ("--set", "externalPostgres.archiveTimeoutConfirmed=true"),
        "corsOrigins",
    ),
)


def _helm(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["helm", *args], cwd=str(ROOT), capture_output=True, text=True, check=False
    )


def main() -> int:
    if not CHART.exists():
        raise SystemExit(f"no chart at {CHART}")

    findings: list[str] = []

    # 1. Every guard must REFUSE when its acknowledgement is absent.
    guards_checked = []
    for name, args, fragment in GUARDS:
        result = _helm("template", "sentinel", str(CHART), *args)
        refused = result.returncode != 0 and fragment in (
            result.stderr + result.stdout
        )
        guards_checked.append({"guard": name, "refused": refused})
        if not refused:
            findings.append(
                f"guard {name!r} did NOT refuse: the chart rendered without the "
                f"acknowledgement, so the safety property it advertises is not "
                f"enforced (exit {result.returncode})"
            )

    # 2. With every acknowledgement supplied, the chart must render.
    rendered = _helm("template", "sentinel", str(CHART), *ACKNOWLEDGEMENTS)
    manifests = [
        line for line in rendered.stdout.splitlines() if line.startswith("kind:")
    ]
    if rendered.returncode != 0:
        findings.append(
            f"the chart does not render even with every acknowledgement "
            f"supplied: {rendered.stderr.strip()[-400:]}"
        )
    elif not manifests:
        # A render that emits nothing would satisfy an exit-code check while
        # deploying an empty release.
        findings.append("the chart rendered zero manifests")

    ok = not findings
    record = {
        "gate": "kubernetes_helm",
        "ok": ok,
        "exit_code": 0 if ok else 1,
        "summary": (
            f"kubernetes_helm: {len(GUARDS)} guards refuse as designed and the "
            f"chart renders {len(manifests)} manifests when acknowledged"
            if ok
            else "kubernetes_helm: " + "; ".join(findings)
        ),
        "command": ["helm", "template", "sentinel", str(CHART), *ACKNOWLEDGEMENTS],
        "command_rationale": (
            "NOT `helm lint`, which fails by design on this chart: two "
            "deliberate guards refuse the default values. A gate reporting "
            "those as defects would invite someone to delete them. This checks "
            "that the guards refuse AND that the chart renders once they are "
            "satisfied -- either half alone is worthless."
        ),
        "guards": guards_checked,
        "manifest_kinds": sorted({m.removeprefix("kind:").strip() for m in manifests}),
        "manifest_count": len(manifests),
        "findings": findings,
        "does_not_prove": (
            "That the manifests work on a cluster. Nothing here talks to an API "
            "server, so a PASS means the templates are valid and the guards "
            "hold -- not that a deployment would come up."
        ),
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(record["summary"])
    for guard in guards_checked:
        print(f"  guard {guard['guard']}: {'refuses' if guard['refused'] else 'DID NOT REFUSE'}")
    print(f"  manifests: {', '.join(record['manifest_kinds'])}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
