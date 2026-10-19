"""Emit `release/scorecard.json` — the flat gate verdict, and the release status.

WHY A THIRD ARTIFACT
--------------------
`readiness.json` is the per-gate evidence with provenance. `scoreboard.json`
splits engineering from external assurance and scores the categories. Neither is
a single answer to *may this ship*, and section 93 asks for exactly that: a flat
map of gate to status, plus one word.

So this reads the other two and derives a verdict. It computes nothing of its
own about any gate — three artifacts that each decide independently are three
artifacts that will eventually disagree, and the one a reader trusts is
whichever they opened first.

THE VERDICT IS DERIVED, NOT DECLARED
--------------------------------------
`BLOCKED` when any mandatory gate FAILED, or a mandatory engineering gate is
UNVERIFIED.

`RELEASE CANDIDATE` when every engineering gate that a build can satisfy has
passed, and only external gates remain.

`PRODUCTION GA APPROVED` requires the external gates too, and **nothing in this
repository can produce them**. `test_ga_gates_cannot_be_faked.py` plants a
correctly bound artifact claiming success for each and requires the verdict to
stay UNVERIFIED. So this script has no code path that emits GA, and that is
deliberate rather than an omission: the four external gates accrue from a
contract, a calendar, a second failure domain and a real customer.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

READINESS = ROOT / "release" / "readiness.json"
SCOREBOARD = ROOT / "release" / "scoreboard.json"
OUT = ROOT / "release" / "scorecard.json"

BLOCKED = "BLOCKED"
DESIGN_PARTNER = "DESIGN-PARTNER READY"
RELEASE_CANDIDATE = "RELEASE CANDIDATE"
GA = "PRODUCTION GA APPROVED"

#: Executive-language mapping, offered alongside rather than instead of the
#: canonical status. A summary that says only "GO" has discarded which of the
#: four states produced it.
EXECUTIVE: Mapping[str, str] = MappingProxyType({
    BLOCKED: "NO-GO",
    DESIGN_PARTNER: "CONDITIONAL GO",
    RELEASE_CANDIDATE: "CONDITIONAL GO",
    GA: "GO",
})

#: Gates a build can satisfy. All must PASS for a release candidate.
MANDATORY_ENGINEERING: tuple[str, ...] = (
    "lint", "type_check", "unit_tests", "architecture_tests", "security_tests",
    "chaos_tests", "migration_tests", "postgres_tests", "redis_tests",
    "sast", "dast", "dependency_scanning", "secret_scanning",
    "container_build", "container_scanning", "kubernetes_helm",
    "production_preflight", "sbom", "license_scan", "detection_evaluation",
    "performance_targets",
)

#: Satisfiable by a build in principle, and blocked here by a missing external
#: input rather than by any defect. Kept OUT of the mandatory set so a
#: workstation cannot be told it has failed something it was never able to do.
NEEDS_EXTERNAL_INPUT: Mapping[str, str] = MappingProxyType({
    "artifact_signing": (
        "cosign keyless signing needs a CI OIDC identity. A locally generated "
        "key would sign the artifact and prove nothing about who built it"
    ),
})

#: The minimum for putting Sentinel in front of a design partner in OBSERVE or
#: WARN mode, where it decides nothing in their path. Deliberately shorter than
#: the mandatory set: a pilot that cannot block does not need a container scan
#: to be safe, and requiring one would keep the product from the traffic that
#: produces the only evidence external gates accept.
DESIGN_PARTNER_MINIMUM: tuple[str, ...] = (
    "unit_tests", "architecture_tests", "security_tests",
    "postgres_tests", "migration_tests", "secret_scanning",
)


def _load(path: Path) -> dict:
    if not path.exists():
        raise SystemExit(
            f"{path.relative_to(ROOT)} is missing. Run "
            "`scripts/build_release_evidence.py` and "
            "`scripts/build_scoreboard.py` first -- this script reads them and "
            "decides nothing itself, so that three artifacts cannot disagree."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def build() -> dict[str, object]:
    readiness = _load(READINESS)
    board = _load(SCOREBOARD)
    gates = {g["gate"]: g["status"] for g in readiness["gates"]}

    flat = {
        name: gates.get(name, "UNVERIFIED")
        for name in sorted(set(gates) | set(MANDATORY_ENGINEERING))
    }

    failed = sorted(n for n, s in flat.items() if s == "FAIL")
    mandatory_unverified = sorted(
        n for n in MANDATORY_ENGINEERING if flat.get(n) != "PASS"
    )
    partner_ready = all(
        flat.get(n) == "PASS" for n in DESIGN_PARTNER_MINIMUM
    )

    if failed:
        status, reason = BLOCKED, (
            f"mandatory gate(s) FAILED: {', '.join(failed)}"
        )
    elif mandatory_unverified:
        blocked_by_external = [
            n for n in mandatory_unverified if n in NEEDS_EXTERNAL_INPUT
        ]
        genuinely_missing = [
            n for n in mandatory_unverified if n not in NEEDS_EXTERNAL_INPUT
        ]
        if genuinely_missing:
            status, reason = BLOCKED, (
                "mandatory engineering gate(s) UNVERIFIED: "
                + ", ".join(genuinely_missing)
            )
        elif partner_ready:
            # Everything a build can decide has passed; what remains needs an
            # input from outside the repository. That is a candidate, not a
            # failure -- calling it BLOCKED would make the word useless.
            status, reason = RELEASE_CANDIDATE, (
                "every engineering gate a build can satisfy has passed. "
                "Remaining: "
                + "; ".join(
                    f"{n} ({NEEDS_EXTERNAL_INPUT[n]})" for n in blocked_by_external
                )
            )
        else:
            status, reason = BLOCKED, "the design-partner minimum is not met"
    elif partner_ready:
        status, reason = RELEASE_CANDIDATE, (
            "every mandatory engineering gate has passed"
        )
    else:
        status, reason = BLOCKED, "the design-partner minimum is not met"

    # GA is never reachable from here, by construction.
    external = board["external_assurance"]["gates"]

    return {
        "commit": readiness["commit"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "executive_status": EXECUTIVE[status],
        "reason": reason,
        "gates": flat,
        "failed": failed,
        "mandatory_unverified": mandatory_unverified,
        "design_partner_minimum_met": partner_ready,
        "external_assurance": {
            name: detail["assurance_state"] for name, detail in external.items()
        },
        "why_not_ga": (
            "PRODUCTION GA APPROVED requires the four external gates, and no "
            "code path in this repository can emit it. Those gates accrue from "
            "a contract, elapsed calendar time, a second failure domain and a "
            "real customer. `test_ga_gates_cannot_be_faked.py` plants a "
            "correctly bound artifact claiming success for each and requires "
            "the verdict to remain UNVERIFIED."
        ),
        "reads": [
            "release/readiness.json",
            "release/scoreboard.json",
        ],
        "decides_nothing_itself": (
            "Gate statuses come from readiness.json. Three artifacts that each "
            "decided independently would eventually disagree, and a reader "
            "would trust whichever they opened first."
        ),
    }


def main() -> int:
    card = build()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(card, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"status            {card['status']}  ({card['executive_status']})")
    print(f"reason            {card['reason']}")
    print(f"commit            {card['commit'][:12]}")
    passed = sum(1 for s in card["gates"].values() if s == "PASS")
    print(f"gates             {passed}/{len(card['gates'])} PASS")
    if card["failed"]:
        print(f"FAILED            {', '.join(card['failed'])}")
    if card["mandatory_unverified"]:
        print(f"unverified        {', '.join(card['mandatory_unverified'])}")
    print(f"external          {card['external_assurance']}")
    print(f"\nwritten: {OUT.relative_to(ROOT)}")
    # Reports; does not gate. A reporting script that fails the build is one
    # people stop running.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
