"""Generate `docs/engineering/CURRENT_STATE_AUDIT.md` from the repository.

WHY GENERATED
-------------
A hand-maintained capability matrix is wrong within a week. Somebody adds a
module and does not update the table; somebody removes one and the row stays.
The document then reads as an inventory and functions as a wish list, which is
worse than having none — a reader cannot tell which rows are current.

So every column here is derived:

  IMPLEMENTED        the module exists, and its line count
  TESTED             tests pytest actually collects for it
  PRODUCTION PROVEN  the release gate covering it, from readiness.json

`PRODUCTION PROVEN` is the honest column and the reason this file exists. A
capability can be implemented and thoroughly tested and still have no evidence
that it works on the engine production uses. Those are three different claims
and a single "done" column collapses them.

WHAT IT CANNOT DERIVE
---------------------
Whether a capability is COMPLETE. A module with 40 tests may still be missing
the case that matters. The `gap` column is therefore hand-written per
capability and lives in `CAPABILITIES` below, where a diff shows it changing.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, NamedTuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

OUT = ROOT / "docs" / "engineering" / "CURRENT_STATE_AUDIT.md"
READINESS = ROOT / "release" / "readiness.json"


class Capability(NamedTuple):
    """One capability, and the three things that can be true of it."""

    name: str
    #: Modules that implement it, repo-relative.
    modules: tuple[str, ...]
    #: Test modules that exercise it, by stem.
    tests: tuple[str, ...]
    #: The release gate whose PASS would constitute production evidence.
    gate: str
    #: What is missing. HAND-WRITTEN: no script can derive completeness.
    gap: str
    priority: str


#: The capability map. The `gap` field is the only hand-written data here, and
#: it is deliberately blunt — a gap column full of "minor improvements" is a
#: gap column nobody reads.
CAPABILITIES: tuple[Capability, ...] = (
    Capability(
        "Deterministic authorization",
        ("sentinel/domain/protect.py", "sentinel/domain/authorization.py"),
        ("test_security_rules", "test_red_team_suite"),
        "security_tests",
        "None known. `stops_action` uses an allowlist of what proceeds, so a "
        "new decision type stops by default.",
        "P0",
    ),
    Capability(
        "Tenant isolation",
        ("sentinel/infrastructure/sql/schema.py",),
        ("test_tenant_isolation_rls", "test_security_edge"),
        "postgres_tests",
        "Proven for database, RLS and S3 prefixes. Cross-tenant isolation of "
        "metrics labels and trace attributes is asserted by convention rather "
        "than by a test.",
        "P0",
    ),
    Capability(
        "Execution Passport",
        ("sentinel/domain/passport.py",
         "sentinel/infrastructure/passport_signing.py"),
        ("test_passport_standard",),
        "unit_tests",
        "Signed, chained, independently verifiable. No transparency log, so "
        "deletion of a whole passport is undetectable without an external "
        "commitment.",
        "P0",
    ),
    Capability(
        "Independent verifier",
        ("standard/execution-passport-v1/verify_passport.py",),
        ("test_passport_standard",),
        "unit_tests",
        "None. Byte-identical canonicalisation proven against the producer.",
        "P0",
    ),
    Capability(
        "MCP trust gateway",
        ("sentinel/domain/mcp.py", "sentinel/domain/mcp_estate.py"),
        ("test_mcp_attacks", "test_mcp_estate", "test_mcp_wire_proxy"),
        "security_tests",
        "Shadow-server detection CANNOT FIRE: there is no per-server usage "
        "table, and the endpoint says so rather than reporting zero.",
        "P1",
    ),
    Capability(
        "A2A trust gateway",
        ("sentinel/domain/a2a.py", "sentinel/application/a2a_gateway.py"),
        ("test_a2a_proxy", "test_security_edge"),
        "security_tests",
        "Streaming transport is NOT WIRED. The guard exists; nothing streams.",
        "P1",
    ),
    Capability(
        "Delegation lineage",
        ("sentinel/domain/delegation_constraints.py",
         "sentinel/domain/effective_permissions.py"),
        ("test_delegation_constraints", "test_effective_permissions"),
        "unit_tests",
        "Constraint kinds and transitive reach are modelled. No integration "
        "with SPIFFE/SPIRE or STS session tags.",
        "P1",
    ),
    Capability(
        "Blast radius",
        ("sentinel/domain/blast_radius.py",),
        ("test_policy_diff_and_blast_radius", "test_analysis_routes"),
        "unit_tests",
        "No persistent asset-declaration store. Declarations are per-request "
        "and `coverage` is reported, so a low score over low coverage cannot "
        "read as safe.",
        "P1",
    ),
    Capability(
        "Policy simulation",
        ("sentinel/domain/policy_as_code.py",),
        ("test_policy_diff_and_blast_radius",),
        "unit_tests",
        "Replays immutable history and never executes. No business-impact "
        "estimate, which the specification asks for.",
        "P1",
    ),
    Capability(
        "Skill detonation",
        ("sentinel/domain/detonation.py", "sentinel/infrastructure/skill_scanner.py"),
        ("test_detonation", "test_skill_registry"),
        "security_tests",
        "CONTRACT ONLY. `RefusingDetonator` refuses rather than pretending. No "
        "Firecracker/gVisor isolation, so no untrusted code is ever executed.",
        "P2",
    ),
    Capability(
        "Threat intelligence",
        ("sentinel/domain/threat_intel.py",),
        ("test_threat_intel",),
        "unit_tests",
        "Publication decision only. No feed, client or server, and no "
        "reputation service.",
        "P2",
    ),
    Capability(
        "Cloud discovery",
        ("sentinel/infrastructure/platforms/aws.py",
         "sentinel/infrastructure/platforms/connectors.py"),
        ("test_platform_adapters", "test_agent_discovery"),
        "unit_tests",
        "AWS adapters and a connector interface exist. NO Microsoft, Google, "
        "Salesforce, Databricks or developer-agent connectors. Coverage is "
        "reported per connector so partial discovery cannot read as complete.",
        "P1",
    ),
    Capability(
        "Release assurance",
        ("scripts/run_release_gates.py", "scripts/build_release_evidence.py"),
        ("test_release_gate_runner", "test_release_binding",
         "test_ga_gates_cannot_be_faked"),
        "architecture_tests",
        "`artifact_signing` needs a CI OIDC identity. Everything else a build "
        "can decide is measured.",
        "P0",
    ),
    Capability(
        "Enterprise console",
        ("sentinel/interface/console/app.js",),
        ("test_console_bundle",),
        "unit_tests",
        "9 data-backed views against 16 of 17 GET endpoints. The "
        "specification asks for 20 pages; the remaining endpoints do not "
        "exist to back them.",
        "P1",
    ),
    Capability(
        "AWS identity",
        ("deploy/terraform/aws/identity/main.tf",),
        (),
        "",
        "Terraform validated and NOT APPLIED. No AWS resource exists. "
        "UNTESTED: there is no automated test for the IAM policy documents.",
        "P0",
    ),
)


def _line_count(rel: str) -> int | None:
    path = ROOT / rel
    if not path.exists():
        return None
    return len(path.read_text(encoding="utf-8", errors="replace").splitlines())


def _collected_tests() -> Counter:
    """Test count per module stem, from pytest's own collection.

    Collected rather than counted by regex: a `def test_` that pytest does not
    collect (wrong filename, import error, a marker that deselects it) is not a
    test, and counting it would overstate coverage in the one column a reader
    checks.
    """
    result = subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, "-m", "pytest", "--collect-only", "--no-header",
         "-p", "no:cacheprovider", "tests_arch"],
        cwd=str(ROOT), capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=False,
    )
    counts: Counter = Counter()
    for line in result.stdout.splitlines():
        match = re.match(r"tests_arch[/\\](test_[a-z0-9_]+)\.py::", line.strip())
        if match:
            counts[match.group(1)] += 1
    return counts


def _gate_status() -> Mapping[str, str]:
    if not READINESS.exists():
        return MappingProxyType({})
    bundle = json.loads(READINESS.read_text(encoding="utf-8"))
    return MappingProxyType({g["gate"]: g["status"] for g in bundle["gates"]})


def _commit() -> str:
    result = subprocess.run(  # noqa: S603,S607 - fixed command
        ["git", "rev-parse", "HEAD"], cwd=str(ROOT),
        capture_output=True, text=True, check=False,
    )
    return result.stdout.strip() or "unknown"


def main() -> int:
    tests = _collected_tests()
    gates = _gate_status()
    total_collected = sum(tests.values())

    if total_collected < 100:
        # A collection that found almost nothing would make every TESTED cell
        # read "0" and the document would understate coverage across the
        # board -- a vacuous generator, which is the defect class this
        # repository keeps finding.
        raise SystemExit(
            f"pytest collected only {total_collected} tests. Refusing to write "
            "an audit whose TESTED column would be wrong for every row."
        )

    rows = []
    for cap in CAPABILITIES:
        present = [m for m in cap.modules if (ROOT / m).exists()]
        missing = [m for m in cap.modules if not (ROOT / m).exists()]
        lines = sum(_line_count(m) or 0 for m in present)
        implemented = (
            f"yes ({len(present)} module{'s' if len(present) != 1 else ''}, "
            f"{lines} lines)" if present else "**NO**"
        )
        if missing:
            implemented += f" — missing: {', '.join(missing)}"

        test_count = sum(tests.get(t, 0) for t in cap.tests)
        tested = f"{test_count} collected" if test_count else "**NONE**"

        gate = gates.get(cap.gate, "")
        if not cap.gate:
            proven = "**NOT APPLICABLE** — no gate covers it"
        elif gate == "PASS":
            proven = f"yes — `{cap.gate}` PASS"
        elif gate:
            proven = f"**{gate}** — `{cap.gate}`"
        else:
            proven = f"**UNVERIFIED** — `{cap.gate}` not in readiness.json"

        rows.append((cap.name, implemented, tested, proven, cap.gap, cap.priority))

    passed = sum(1 for s in gates.values() if s == "PASS")
    lines_out = [
        "# Current state audit",
        "",
        "**Generated by `scripts/build_state_audit.py`. Do not edit by hand.**",
        "",
        f"- commit: `{_commit()}`",
        f"- generated: {datetime.now(timezone.utc).isoformat()}",
        f"- tests collected: **{total_collected}**",
        f"- gates: **{passed} PASS** of {len(gates)}",
        "",
        "## How to read the columns",
        "",
        "| Column | Derived from | Means |",
        "|---|---|---|",
        "| Implemented | The module existing on disk | The code is there. Not that it is complete |",
        "| Tested | Tests **pytest actually collects** | Not a `def test_` count — an uncollected test is not a test |",
        "| Production proven | The release gate, from `readiness.json` | Evidence it works on the engine production uses |",
        "| Gap | **Hand-written** | No script can derive completeness |",
        "",
        "Those first three are different claims. A capability can be "
        "implemented, thoroughly tested, and still have no evidence it works "
        "on PostgreSQL. A single \"done\" column collapses that distinction, "
        "which is why there are three.",
        "",
        "## Capabilities",
        "",
        "| Capability | Implemented | Tested | Production proven | Gap | Priority |",
        "|---|---|---|---|---|---|",
    ]
    for name, impl, tested, proven, gap, priority in rows:
        lines_out.append(
            f"| **{name}** | {impl} | {tested} | {proven} | {gap} | {priority} |"
        )

    untested = [r[0] for r in rows if "NONE" in r[2]]
    unproven = [r[0] for r in rows if "NOT APPLICABLE" in r[3] or "UNVERIFIED" in r[3]]

    lines_out += [
        "",
        "## What this audit found",
        "",
        f"**Untested capabilities ({len(untested)}):** "
        + (", ".join(f"`{u}`" for u in untested) if untested else "none"),
        "",
        f"**No production evidence ({len(unproven)}):** "
        + (", ".join(f"`{u}`" for u in unproven) if unproven else "none"),
        "",
        "The AWS identity layer is the honest example of both. The Terraform "
        "validates and no AWS resource has been created, so it is implemented, "
        "untested and unproven — three separate facts, and a matrix that "
        "reported it as \"done\" because the file exists would be the security "
        "theatre this repository is built to avoid.",
        "",
        "## Related",
        "",
        "- [`../RELEASE_READINESS.md`](../RELEASE_READINESS.md) — the two scoreboards",
        "- [`../SECURITY_ASSURANCE.md`](../SECURITY_ASSURANCE.md)",
        "- [`../COMPETITIVE_GAP_MATRIX.md`](../COMPETITIVE_GAP_MATRIX.md)",
        "",
    ]

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines_out), encoding="utf-8")

    print(f"{total_collected} tests collected, {passed} gates PASS")
    print(f"untested: {untested or 'none'}")
    print(f"unproven: {unproven or 'none'}")
    print(f"\nwritten: {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
