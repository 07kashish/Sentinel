"""The readiness document cannot disagree with the ledger it summarises.

WHY THIS GUARD EXISTS
---------------------
`SENTINEL_PRODUCT_READINESS.md` is hand-written and quotes numbers that are
generated: status counts, GA blocker count, the mean score. Hand-written
numbers next to generated ones drift the first time the generated ones change,
and this document is the one an evaluator reads FIRST — so a stale figure here
is worse than a stale figure anywhere else in the repository.

That is not hypothetical. Twice in this work a claimed figure was wrong: a
test count taken from arithmetic rather than pytest (91 against 73), and a
recalled RPO that contradicted the recorded artifact. Both were caught by
guards like this one.

WHAT IS ASSERTED
----------------
Every number in the document is compared against release/gap_ledger.json, and
the honesty properties are asserted directly: that the label is not
PRODUCTION GA, that no dimension claims a 10, and that all eight external
gates are still listed as open.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOCUMENT = ROOT / "docs" / "SENTINEL_PRODUCT_READINESS.md"
LEDGER_JSON = ROOT / "release" / "gap_ledger.json"

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


@pytest.fixture(scope="module")
def document() -> str:
    return DOCUMENT.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def ledger() -> dict:
    if not LEDGER_JSON.exists():
        pytest.skip(
            "release/gap_ledger.json is generated and gitignored; run "
            "scripts/build_gap_ledger.py"
        )
    return json.loads(LEDGER_JSON.read_text(encoding="utf-8"))


def test_the_document_exists_and_is_substantial(document):
    """Control. Every substring assertion below passes against an empty file
    only if the file is missing, so this fixes the floor.
    """
    assert len(document) > 4000, f"only {len(document)} chars"


# ── the numbers match the generated ledger ────────────────────────────────


def test_the_status_counts_match(document, ledger):
    counts = ledger["status_counts"]

    for status, key in (
        ("COMPLETE", "COMPLETE"),
        ("PARTIAL", "PARTIAL"),
        ("MISSING", "MISSING"),
        ("EXTERNALLY-UNVERIFIED", "EXTERNALLY-UNVERIFIED"),
    ):
        expected = counts[key]
        # The table renders as `| COMPLETE | 22 |`, so the count follows the
        # label on the same line.
        pattern = rf"\|\s*{re.escape(status)}\s*\|\s*(\d+)\s*\|"
        match = re.search(pattern, document)
        assert match, f"no table row found for {status}"
        assert int(match.group(1)) == expected, (
            f"{status}: document says {match.group(1)}, ledger says {expected}"
        )


def test_the_ga_blocker_count_matches(document, ledger):
    expected = ledger["ga_blocker_count"]
    match = re.search(r"\*\*GA blockers\*\*\s*\|\s*\*\*(\d+)\*\*", document)

    assert match, "no GA blocker row found"
    assert int(match.group(1)) == expected, (
        f"document says {match.group(1)}, ledger says {expected}"
    )


def test_the_mean_score_matches(document, ledger):
    """Rounded to one decimal in prose, so compare at that precision."""
    expected = round(ledger["readiness_mean"], 1)
    match = re.search(r"mean across 26 dimensions: \*\*([\d.]+)/10\*\*", document)

    assert match, "no mean score found"
    assert float(match.group(1)) == expected, (
        f"document says {match.group(1)}, ledger says {expected}"
    )


def test_the_dimension_count_matches(document, ledger):
    stated = re.search(r"across (\d+) dimensions", document)

    assert stated
    assert int(stated.group(1)) == len(ledger["readiness_matrix"])


def test_the_zero_scored_dimensions_are_named(document, ledger):
    """A zero is a decision and has to be visible in the summary, not only in
    the matrix somebody may not open.
    """
    zeros = [
        row["dimension"] for row in ledger["readiness_matrix"]
        if row["score"] == 0
    ]

    assert zeros, "control: the ledger reports no zero-scored dimension"
    for dimension in zeros:
        assert dimension in document, f"{dimension} scores 0 and is not named"


# ── the honesty properties ────────────────────────────────────────────────


def test_the_label_is_not_production_ga(document):
    """The GA definition requires external evidence that does not exist. This
    is the single claim most tempting to overstate.
    """
    assert "PRIVATE BETA" in document
    assert "**Label: PRODUCTION GA**" not in document


def test_no_dimension_claims_a_ten(document, ledger):
    assert ledger["scored_ten"] == []
    assert "No dimension is scored 10" in document


def test_all_eight_external_gates_are_listed_as_open(document, ledger):
    """A closed gate would have to be closed in the ledger too, and none can
    be closed from inside this repository.
    """
    external = [
        entry for entry in ledger["entries"]
        if entry["status"] == "EXTERNALLY-UNVERIFIED"
    ]

    assert len(external) == len(EXTERNAL_GATES)
    for gate in EXTERNAL_GATES:
        assert gate in document, f"{gate} is not listed"


def test_the_document_states_what_is_behind_competitors(document):
    """A readiness summary that lists only strengths is a sales document, so
    the parity gaps are named.

    "Workflow" left this list when an audit error was corrected -- all six
    SOAR connectors already existed. A gap leaving the list is only legitimate
    when the document SAYS it left and why, which is the second assertion:
    otherwise a shrinking gap list is indistinguishable from a document
    quietly dropping bad news.
    """
    for gap in ("Connector breadth", "Endpoint", "Console UX"):
        assert gap in document, gap

    assert "Removed from this list" in document
    assert "audit error was corrected" in document


def test_the_original_score_is_not_invented(document):
    """There is no earlier machine-readable assessment, so a "before" figure
    would be fabricated -- and an invented baseline makes every improvement
    look larger than it was.
    """
    assert "Not assessable" in document


def test_the_execution_binding_residual_is_stated(document):
    """The strongest claim in the product, with its limit next to it rather
    than in a linked document somebody may not follow.
    """
    assert "caller declares" in document.lower()
    assert "defaults `false`" in document or "defaults off" in document.lower()


def test_cost_figures_are_labelled_as_estimates(document):
    assert "estimate" in document.lower()
    assert "MEASURED_AWS_UNIT_ECONOMICS" in document


# ── the deliverable mapping is real ───────────────────────────────────────


def test_every_mapped_deliverable_points_at_a_file_that_exists():
    """The mapping table names sixteen prompt deliverables and where each one
    actually lives. A table citing absent files is the same defect the ledger
    generator refuses to commit.

    Only the SECOND column is checked. The first column is the prompt's names,
    twelve of which deliberately do not exist -- that is the whole point of the
    table. The first version of this test parsed both columns and reported ten
    "missing" files that were never supposed to be there, which is a flaw in
    the test reported as a flaw in the repository.
    """
    document = DOCUMENT.read_text(encoding="utf-8")
    section = document.split("The prompt's named deliverables", 1)[1]

    targets: set[str] = set()
    for line in section.splitlines():
        if not line.startswith("|") or line.count("|") < 3:
            continue
        columns = [cell.strip() for cell in line.strip("|").split("|")]
        if len(columns) < 2 or columns[0].startswith("---"):
            continue
        actual = columns[1]
        if actual.lower().startswith("named in") or actual.startswith("---"):
            continue
        targets |= set(re.findall(r"\]\(([^)]+)\)", actual))
        targets |= set(re.findall(r"`([^`]+\.(?:md|json|py))`", actual))

    assert len(targets) >= 12, f"only parsed {len(targets)} targets: {targets}"

    missing = []
    for target in sorted(targets):
        if target.startswith(("http", "#")):
            continue
        if any(
            (root / target).exists()
            for root in (ROOT / "docs", ROOT)
        ):
            continue
        missing.append(target)

    assert missing == [], f"mapping cites absent files: {missing}"
