"""The delivery status document must not drift into a progress report.

Its failure mode is not a wrong number -- it is a `UNVERIFIED` row quietly
becoming `PASS` because the work "feels done", or a blocked item disappearing
because it looks bad in a table.

The test counts are asserted as a FLOOR rather than an equality. An equality
would fail every time somebody adds a test, which trains people to edit the
document without reading it; a floor fails only when coverage is removed,
which is the direction that matters.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "docs" / "DELIVERY_STATUS.md"


def _page() -> str:
    return PAGE.read_text(encoding="utf-8")


def _flat() -> str:
    return " ".join(PAGE.read_text(encoding="utf-8").split())


def test_every_test_count_the_page_claims_is_a_floor_that_still_holds():
    """A claimed count larger than reality means coverage was deleted.

    Counts COLLECTED tests, not `def test_` lines. Those differ: a
    parametrised test is one function and many cases, and
    `test_transparency.py` is 25 functions collecting 43. My first version
    counted definitions and reported four files as short when nothing was
    missing -- a test measuring something other than what the document claims,
    which is the defect it exists to catch, one level up.
    """
    page = _page()
    claims = dict(re.findall(r"`(test_[\w.]+\.py)` \((\d+)\)", page))
    if not claims:
        return

    missing = [n for n in claims if not (ROOT / "tests_arch" / n).exists()]
    assert not missing, f"cited test files that do not exist: {missing}"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            *[f"tests_arch/{name}" for name in sorted(claims)],
            "-p",
            "no:cacheprovider",
            "--collect-only",
            "-q",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={**os.environ, "PYTHONPATH": "."},
        timeout=600,
    )
    collected = {
        Path(path).name: int(count)
        for path, count in re.findall(
            r"^(tests_arch[\/][\w.]+\.py): (\d+)$", result.stdout, re.M
        )
    }
    assert collected, (
        "no collection counts were parsed, so this test would pass while "
        "measuring nothing. pytest said: " + result.stdout[-800:]
    )

    shortfalls = [
        f"{name}: page claims {claimed}, pytest collects "
        f"{collected.get(name, 'nothing')}"
        for name, claimed in sorted(claims.items())
        if collected.get(name, 0) < int(claimed)
    ]
    assert not shortfalls, "; ".join(shortfalls)


def test_the_mutation_count_matches_the_verifier():
    """The page quotes it, and a guard suite that shrank is a guard suite that
    stopped covering something.
    """
    verifier = (ROOT / "scripts" / "verify_guards.py").read_text(encoding="utf-8")
    actual = verifier.count("    Mutation(")

    assert f"{actual} mutations" in _page() or f"{actual} properties" in _page(), (
        f"the page does not quote the real mutation count ({actual})"
    )


def test_every_path_the_page_cites_exists():
    page = _page()
    missing = []

    for path in re.findall(r"`((?:domain|infrastructure|sdk|interface|evaluation|scripts|standard)/[\w/.-]+)`", page):
        candidates = [ROOT / path, ROOT / "sentinel" / path]
        if not any(c.exists() for c in candidates):
            missing.append(path)
    for path in re.findall(r"\]\(([\w/.-]+\.md)\)", page):
        if not (ROOT / "docs" / path).exists() and not (ROOT / path).exists():
            missing.append(path)

    assert not missing, f"cited but absent: {sorted(set(missing))}"


def test_the_blocked_rows_are_still_present():
    """The rows a progress report would delete first."""
    flat = _flat()

    for blocked in (
        "Deliberately not applied",
        "No external party has examined this system",
        "There are no design partners",
        "requires 30 days",
    ):
        assert blocked in flat, f"a blocked row was removed: {blocked!r}"


def test_no_blocked_row_has_been_promoted_to_pass():
    """`UNVERIFIED` becoming `PASS` because the work feels done is the one
    edit this document must never absorb.
    """
    page = _page()
    blocked_section = page[page.index("## Not done, with the reason") :]

    assert "`PASS`" not in blocked_section, (
        "a row in the blocked section is marked PASS"
    )
    for expected in ("`UNVERIFIED`", "`NEEDS SDK`", "`NOT_APPLICABLE`"):
        assert expected in blocked_section


def test_the_four_statuses_are_defined_and_missing_evidence_is_unverified():
    flat = _flat()

    for status in ("PASS", "FAIL", "UNVERIFIED", "NOT_APPLICABLE"):
        assert status in flat
    assert "Missing evidence is `UNVERIFIED`, never `PASS`" in flat


def test_the_stated_limits_survive():
    """Each is a property the deployment does not have, and each is the kind
    of sentence that gets trimmed for length.
    """
    flat = _flat()

    for limit in (
        "proves nothing about that party",
        "No root has been published anywhere the operator cannot change it",
        "A container is **not** a virtual machine",
        "never `complete`",
        "`unknown` rather than `not_reachable`",
        "same host and disk as the database",
    ):
        assert limit in flat, f"a stated limit was trimmed: {limit!r}"


def test_the_dead_feature_and_the_false_positive_are_both_recorded():
    """Both are findings against this codebase. A status document that
    reported only progress would omit them.
    """
    flat = _flat()

    assert "_assess_behaviour" in flat
    assert "never** run" in flat or "never run" in flat
    assert "51.7%" in flat


def test_the_recovery_figures_match_the_drill_artifact():
    """Quoted here as well as on the research page, so both must track it."""
    import json

    drill = json.loads(
        (ROOT / "docs" / "dr_postgres_wal_pitr_drill.json").read_text(
            encoding="utf-8"
        )
    )
    page = _page()

    assert f"{drill['measured']['experimental_rpo_seconds']:.2f}s" in page
    assert f"{drill['measured']['experimental_rto_seconds']:.2f}s" in page


def test_the_page_makes_no_certification_claim():
    """SOC 2 and ISO certify an organisation. A codebase cannot hold one, and
    implying otherwise would be the most consequential false claim here.
    """
    flat = _flat().lower()

    for forbidden in ("soc 2 certified", "iso 27001 certified", "we are certified"):
        assert forbidden not in flat, f"certification claim: {forbidden!r}"
    assert "certify an organisation" in flat


# ── the eight external gates keep their automation, and stay open ─────────
#
# Added after the gates were found citing NO artifacts at all, which made
# "the runbook is prepared" an assertion with no referent. The prompt asks a
# repository to prepare automation and documentation for these tests and never
# to mark them complete -- so both halves are checked here: the automation
# exists, and the status has not moved.

EXTERNAL_GATES = (
    "INDEPENDENT_PENTEST",
    "PRODUCTION_SOAK",
    "INDEPENDENT_FAILURE_DOMAIN_DR",
    "DESIGN_PARTNER_VALIDATION",
    "PRODUCTION_CUSTOMER_VALIDATION",
    "MEASURED_AWS_UNIT_ECONOMICS",
    "REAL_WORLD_DETECTION_METRICS",
    "REFERENCE_CUSTOMERS",
)


def _ledger_entries():
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    payload = json.loads(
        (root / "release" / "gap_ledger.json").read_text(encoding="utf-8")
    )
    return root, payload["entries"]


def test_all_eight_external_gates_are_present_and_none_has_closed():
    """The single most important assertion in this file. No code path may
    convert one of these to a pass, and this fails if one ever does."""
    _root, entries = _ledger_entries()
    gates = {
        e["requirement"]: e
        for e in entries
        if e["status"] == "EXTERNALLY-UNVERIFIED"
    }

    assert sorted(gates) == sorted(EXTERNAL_GATES), sorted(gates)
    for name, entry in gates.items():
        assert entry["blocks_ga"] is True, name


def test_every_gate_that_claims_prepared_automation_names_it():
    """`REFERENCE_CUSTOMERS` is the one exception and says so in its own text:
    nothing in code affects it. Every other gate must point at the runbook or
    script it claims is ready, because a claim with no referent is how
    'prepared' comes to mean nothing."""
    root, entries = _ledger_entries()

    for entry in entries:
        if entry["status"] != "EXTERNALLY-UNVERIFIED":
            continue
        name = entry["requirement"]
        artifacts = list(entry.get("docs", ()))
        if name == "REFERENCE_CUSTOMERS":
            assert artifacts == [], (
                "REFERENCE_CUSTOMERS must cite nothing: there is no artifact "
                "that could prepare for having customers"
            )
            assert "nothing in code" in entry["implementation"].lower()
            continue
        assert artifacts, f"{name} claims prepared automation but names none"
        for path in artifacts:
            assert (root / path).exists(), f"{name} cites missing {path}"
