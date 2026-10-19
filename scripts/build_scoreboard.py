"""Two scoreboards, because one of them can never be finished by engineering.

WHY THE SINGLE SCORE WAS WRONG
-------------------------------
`readiness.json` counted twenty-six gates in one denominator. Four of them --
independent penetration test, production soak, cross-region DR drill, design
partner validation -- accrue from a contract, a calendar, a second failure
domain and other organisations' traffic. No amount of engineering moves them.

So the combined figure was structurally misleading in BOTH directions. It read
as "21 of 26, nearly there", which understates finished engineering and
overstates commercial readiness. A reader could not tell whether the gap was
work somebody had not done or work code cannot do.

Section 25 of the specification asks for the split, and this is it:

  A. ENGINEERING READINESS   -- reachable through reproducible work
  B. EXTERNAL ASSURANCE      -- never auto-passed by code

Engineering can legitimately reach 100%. External assurance cannot be moved
from here at all, and the report says what WOULD move it rather than leaving a
reader to guess.

THE FOUR STATES ARE KEPT DISTINCT
----------------------------------
PASSED, FAILED, UNVERIFIED and NOT APPLICABLE mean different things and the
specification is explicit that they must not be confused:

  PASSED          evidence exists, is bound to this build, records success
  FAILED          evidence exists, is bound to this build, records failure
  UNVERIFIED      no evidence, or evidence belonging to another build
  NOT APPLICABLE  the gate cannot apply to this artefact at all

Only `external_assurance` rows can be NOT APPLICABLE, and only because a build
is the wrong kind of thing to satisfy them. That is not a pass and is never
counted as one.
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
OUT_JSON = ROOT / "release" / "scoreboard.json"
OUT_MD = ROOT / "docs" / "RELEASE_READINESS.md"

#: The four gates that a build cannot satisfy, and what actually would.
#:
#: Written as ACTIONS with an owner and a duration, not as apologies. "Not
#: satisfiable by a build" is true and useless on its own; somebody has to be
#: able to read this and start.
EXTERNAL: Mapping[str, Mapping[str, str]] = MappingProxyType({
    "independent_pentest": MappingProxyType({
        "what_would_satisfy_it": (
            "A scoped engagement by a firm with no stake in the result, "
            "followed by a remediation cycle and a RETEST of the findings. The "
            "retest is the part people skip and the part that matters: a report "
            "with open criticals is a to-do list, not assurance."
        ),
        "inputs_already_prepared": (
            "docs/PENTEST_PACKAGE.md, docs/attack_surface.json (47 routes with "
            "the capability each declares), docs/THREAT_MODEL.md, and a "
            "reproducible test deployment"
        ),
        "owner": "security leadership + external firm",
        "elapsed": "4-8 weeks including remediation and retest",
        "cost_shape": "fixed-fee engagement",
    }),
    "production_soak": MappingProxyType({
        "what_would_satisfy_it": (
            "A continuous run against production-like traffic for the declared "
            "period, tracking event loss, memory growth, queue backlog and "
            "ledger integrity. THE ELAPSED TIME IS THE EVIDENCE. A harness that "
            "runs for an hour measures something else, and no amount of "
            "engineering compresses a thirty-day observation into an afternoon."
        ),
        "inputs_already_prepared": (
            "scripts/run_observability_soak.py runs continuously and rewrites "
            "its report every interval, so a run stopped early still leaves a "
            "truthful record of the window it covered. A 7-minute "
            "production-shaped run on PostgreSQL measured ingest p95 71.6ms "
            "against a 500ms target"
        ),
        "owner": "SRE",
        "elapsed": "30 days minimum for a 99.9%/30d SLO",
        "cost_shape": "one production-like environment, running",
    }),
    "disaster_recovery_proof": MappingProxyType({
        "what_would_satisfy_it": (
            "A recovery executed across an INDEPENDENT failure domain -- a "
            "second region or account -- with measured RPO and RTO. The domain "
            "has to exist before crossing it proves anything."
        ),
        "inputs_already_prepared": (
            "PITR drills exist and measured RPO ~57s with archive_timeout set. "
            "Their own artifact states the limitation plainly: the WAL archive "
            "sits on the SAME HOST AND DISK as pgdata, which is why this gate "
            "reads fail rather than pass. The Helm chart refuses to render "
            "until an operator confirms continuous archiving is configured"
        ),
        "owner": "SRE + cloud account owner",
        "elapsed": "1-2 weeks to stand up the second domain, then a drill day",
        "cost_shape": "a second region's infrastructure",
    }),
    "design_partner_validation": MappingProxyType({
        "what_would_satisfy_it": (
            "A real organisation running this against real traffic under a real "
            "agreement, completing the agreed validation. A commercial fact, "
            "not a technical one."
        ),
        "inputs_already_prepared": (
            "docs/DESIGN_PARTNER_RUNBOOK.md defines the staged rollout the "
            "specification asks for: OBSERVE, SIMULATE, WARN, REQUIRE_APPROVAL, "
            "ENFORCE_LOW_RISK, ENFORCE_HIGH_RISK -- so a partner can start "
            "without enforcement touching their traffic"
        ),
        "owner": "founders / commercial",
        "elapsed": "one pilot cycle",
        "cost_shape": "a signed pilot agreement",
    }),
})

#: The engineering categories section 25 names, and where their evidence lives.
#:
#: A category scores PASSED only when every gate feeding it passed. There is no
#: partial credit and no rounding up: the specification says not to assign 10
#: automatically, and a category with one unverified input is not finished.
CATEGORIES: Mapping[str, tuple[str, ...]] = MappingProxyType({
    "Core architecture": ("architecture_tests", "lint", "type_check"),
    "Security engineering": ("security_tests", "sast", "secret_scanning"),
    "Code/test discipline": ("unit_tests", "architecture_tests"),
    "Runtime enforcement": ("unit_tests", "security_tests"),
    "MCP security": ("security_tests",),
    "A2A security": ("security_tests",),
    "Identity": ("unit_tests",),
    "Discovery": ("unit_tests",),
    "Skill security": ("security_tests",),
    "Evidence/attestation": ("unit_tests", "architecture_tests"),
    "Integrations": ("unit_tests", "redis_tests"),
    "Tenant isolation": ("postgres_tests", "migration_tests"),
    "Performance": ("performance_targets",),
    "HA/DR machinery": ("chaos_tests", "kubernetes_helm"),
    "UX": ("unit_tests",),
    "Compliance tooling": ("license_scan", "sbom"),
    "Release assurance": (
        "container_build", "container_scanning", "dast",
        "dependency_scanning", "production_preflight", "artifact_signing",
    ),
})

PASSED, FAILED, UNVERIFIED, NOT_APPLICABLE = (
    "PASSED", "FAILED", "UNVERIFIED", "NOT APPLICABLE"
)


def _state(status: str) -> str:
    return {"PASS": PASSED, "FAIL": FAILED}.get(status, UNVERIFIED)


def build() -> dict[str, object]:
    if not READINESS.exists():
        raise SystemExit(
            f"{READINESS.relative_to(ROOT)} does not exist. Run "
            "`python scripts/build_release_evidence.py` first -- this script "
            "reads that report rather than re-deciding any gate, so the two "
            "can never disagree."
        )
    bundle = json.loads(READINESS.read_text(encoding="utf-8"))
    gates = {g["gate"]: g for g in bundle["gates"]}

    engineering = {
        name: gate for name, gate in gates.items() if name not in EXTERNAL
    }
    engineering_states = {
        name: _state(gate["status"]) for name, gate in engineering.items()
    }
    passed = sum(1 for s in engineering_states.values() if s == PASSED)
    failed = sum(1 for s in engineering_states.values() if s == FAILED)
    unverified = sum(1 for s in engineering_states.values() if s == UNVERIFIED)

    categories = []
    for category, inputs in CATEGORIES.items():
        states = [engineering_states.get(name, UNVERIFIED) for name in inputs]
        if FAILED in states:
            verdict, severity = FAILED, "blocking"
        elif UNVERIFIED in states:
            verdict, severity = UNVERIFIED, "blocking"
        else:
            verdict, severity = PASSED, "none"
        categories.append({
            "category": category,
            "state": verdict,
            "blocking_severity": severity,
            "gates": list(inputs),
            "unverified_inputs": [
                name for name, s in zip(inputs, states) if s != PASSED
            ],
        })

    engineering_complete = failed == 0 and unverified == 0

    return {
        "commit": bundle["commit"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "state_vocabulary": {
            PASSED: "evidence exists, is bound to this build, records success",
            FAILED: "evidence exists, is bound to this build, records failure",
            UNVERIFIED: "no evidence, or evidence belonging to another build",
            NOT_APPLICABLE: "a build is the wrong kind of thing to satisfy this",
        },
        "engineering_readiness": {
            "complete": engineering_complete,
            "passed": passed,
            "failed": failed,
            "unverified": unverified,
            "total": len(engineering),
            "gates": dict(sorted(engineering_states.items())),
            "categories": categories,
        },
        "external_assurance": {
            "complete": False,
            "note": (
                "Every row here is NOT APPLICABLE to a build and UNVERIFIED as "
                "assurance. Nothing in this repository can change that, and "
                "`test_ga_gates_cannot_be_faked.py` proves it by planting a "
                "correctly bound artifact for each and requiring the verdict to "
                "stay UNVERIFIED."
            ),
            "gates": {
                name: {
                    "state": NOT_APPLICABLE,
                    "assurance_state": UNVERIFIED,
                    **{k: v for k, v in detail.items()},
                }
                for name, detail in sorted(EXTERNAL.items())
            },
        },
        "honest_summary": (
            f"Engineering readiness: {passed}/{len(engineering)} "
            f"({'COMPLETE' if engineering_complete else 'INCOMPLETE'}). "
            "External assurance: 0/4, and not reachable from a repository. "
            "The two are reported separately because combining them "
            "understates finished engineering and overstates commercial "
            "readiness at the same time."
        ),
    }


def _markdown(board: dict) -> str:
    eng = board["engineering_readiness"]
    lines = [
        "# Release readiness",
        "",
        "**Generated by `scripts/build_scoreboard.py` from "
        "`release/readiness.json`. Do not edit by hand.**",
        "",
        f"- commit: `{board['commit']}`",
        f"- generated: {board['generated_at']}",
        "",
        "## The four states",
        "",
        "| State | Means |",
        "|---|---|",
    ]
    for state, meaning in board["state_vocabulary"].items():
        lines.append(f"| `{state}` | {meaning} |")

    lines += [
        "",
        "`UNVERIFIED` is never assurance. It is the absence of it.",
        "",
        "---",
        "",
        "## A. Engineering readiness",
        "",
        f"**{eng['passed']} passed · {eng['failed']} failed · "
        f"{eng['unverified']} unverified of {eng['total']}** — "
        f"{'COMPLETE' if eng['complete'] else 'INCOMPLETE'}",
        "",
        "Reachable through reproducible work. Every row here is something this "
        "repository can move.",
        "",
        "| Category | State | Blocking | Unverified inputs |",
        "|---|---|---|---|",
    ]
    for row in eng["categories"]:
        gaps = ", ".join(f"`{g}`" for g in row["unverified_inputs"]) or "—"
        lines.append(
            f"| {row['category']} | {row['state']} | "
            f"{row['blocking_severity']} | {gaps} |"
        )

    lines += [
        "",
        "A category is `PASSED` only when every gate feeding it passed. There "
        "is no partial credit: a category with one unverified input is not "
        "finished, and rounding it up is the thing section 25 forbids.",
        "",
        "---",
        "",
        "## B. External assurance",
        "",
        "**0 of 4, and not reachable from this repository.**",
        "",
        board["external_assurance"]["note"],
        "",
    ]
    for name, detail in board["external_assurance"]["gates"].items():
        lines += [
            f"### `{name}`",
            "",
            f"- **As a build gate:** {detail['state']}",
            f"- **As assurance:** {detail['assurance_state']}",
            f"- **What would satisfy it:** {detail['what_would_satisfy_it']}",
            f"- **Already prepared:** {detail['inputs_already_prepared']}",
            f"- **Owner:** {detail['owner']}",
            f"- **Elapsed time:** {detail['elapsed']}",
            f"- **Cost shape:** {detail['cost_shape']}",
            "",
        ]

    lines += ["---", "", board["honest_summary"], ""]
    return "\n".join(lines)


def main() -> int:
    board = build()
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(
        json.dumps(board, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    OUT_MD.write_text(_markdown(board), encoding="utf-8")

    eng = board["engineering_readiness"]
    print(board["honest_summary"])
    print()
    for row in eng["categories"]:
        marker = "OK  " if row["state"] == PASSED else "GAP "
        print(f"  {marker} {row['category']:<24} {row['state']}")
    print()
    print(f"written: {OUT_JSON.relative_to(ROOT)}, {OUT_MD.relative_to(ROOT)}")
    # Exit 0 regardless: this REPORTS, it does not gate. A reporting script that
    # fails the build would make people stop running it.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
