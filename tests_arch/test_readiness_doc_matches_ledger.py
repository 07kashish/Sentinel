"""The readiness document may not quote a better number than the generator.

WHY THIS EXISTS
---------------
`docs/SENTINEL_PRODUCT_READINESS.md` summarises `release/gap_ledger.json` by
hand, and it had drifted: the document read 28 COMPLETE / 10 PARTIAL / 10 GA
blockers against a generated 30 / 8 / 9, and still listed Endpoint discovery
among the zero-scored dimensions long after it had moved to 7.0.

A hand-maintained summary of a generated number is a number that will
eventually flatter itself. The direction of drift is not random: nobody
forgets to update a figure that got worse.

WHAT IT CHECKS
--------------
Every status count, the GA blocker count, the mean, and every dimension's
score in the distribution table, against the JSON the generator wrote.

RELATIONSHIP TO `test_product_readiness.py`
-------------------------------------------
That one already checked the mean, the dimension count and that every
zero-scored dimension is named. It did NOT check the status counts, the GA
blocker count, or any individual dimension score -- and that is precisely
where the document had drifted. Its zero-row check also only asks whether the
real zeros appear, so a document naming an EXTRA dimension as zero passes it;
this file's per-dimension comparison is what catches that.

HOW IT AVOIDS BEING A GATE THAT CHECKS NOTHING
-----------------------------------------------
The failure mode for a parser like this is matching nothing and passing.
`test_the_parser_actually_finds_the_figures` asserts it extracted a non-empty
set of counts and the full 26-dimension matrix, so a document reformatted into
unparseability fails rather than passing vacuously.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "SENTINEL_PRODUCT_READINESS.md"
LEDGER = ROOT / "release" / "gap_ledger.json"


@pytest.fixture(scope="module")
def ledger() -> dict:
    return json.loads(LEDGER.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def text() -> str:
    return DOC.read_text(encoding="utf-8")


def _counts(text: str) -> dict[str, int]:
    """Status counts from the `| NAME | 12 |` rows.

    The bold GA-blocker row is matched separately because its cells carry
    asterisks, and a pattern loose enough to catch both would also catch the
    distribution table's rows.
    """
    found = {
        name: int(value)
        for name, value in re.findall(
            r"^\|\s*(COMPLETE|PARTIAL|MISSING|EXTERNALLY-UNVERIFIED)\s*\|"
            r"\s*(\d+)\s*\|",
            text,
            re.MULTILINE,
        )
    }
    blockers = re.search(r"^\|\s*\*\*GA blockers\*\*\s*\|\s*\*\*(\d+)\*\*\s*\|",
                         text, re.MULTILINE)
    if blockers:
        found["ga_blockers"] = int(blockers.group(1))
    return found


def _mean(text: str) -> float | None:
    match = re.search(r"mean across 26 dimensions:\s*\*\*([\d.]+)/10\*\*", text)
    return float(match.group(1)) if match else None


def _distribution(text: str) -> dict[str, float]:
    """Dimension -> score, from the distribution table.

    Each row is `| 9.5 | A, B, C |` or `| **0** | **A** |`. The bold form is
    handled because the zero row is deliberately emphasised -- and a parser
    that silently skipped it would stop checking the one score that matters
    most for honesty.
    """
    scores: dict[str, float] = {}
    for raw_score, raw_names in re.findall(
        r"^\|\s*\*{0,2}([\d.]+)\*{0,2}\s*\|\s*(.+?)\s*\|\s*$",
        text,
        re.MULTILINE,
    ):
        for name in raw_names.split(","):
            cleaned = name.replace("**", "").strip()
            if cleaned:
                scores[cleaned] = float(raw_score)
    return scores


# ── the parser is not allowed to find nothing ──────────────────────────────


def test_the_parser_actually_finds_the_figures(text):
    """The failure mode for a check like this is matching nothing and passing.

    A document reformatted into unparseability must fail here rather than
    silently stop checking.
    """
    counts = _counts(text)

    assert set(counts) == {
        "COMPLETE",
        "PARTIAL",
        "MISSING",
        "EXTERNALLY-UNVERIFIED",
        "ga_blockers",
    }, counts
    assert _mean(text) is not None
    assert len(_distribution(text)) == 26, sorted(_distribution(text))


# ── the figures match ──────────────────────────────────────────────────────


def test_every_status_count_matches_the_ledger(text, ledger):
    counts = _counts(text)
    expected = ledger["status_counts"]

    for status in ("COMPLETE", "PARTIAL", "MISSING", "EXTERNALLY-UNVERIFIED"):
        assert counts[status] == expected[status], (
            f"the document says {status}={counts[status]} and the generator "
            f"says {expected[status]}. Regenerate with "
            "`python scripts/build_gap_ledger.py` and update the document -- "
            "the generator is the authority."
        )


def test_the_ga_blocker_count_matches_the_ledger(text, ledger):
    """The single number a reader is most likely to quote, and the one most
    likely to be quoted stale."""
    assert _counts(text)["ga_blockers"] == ledger["ga_blocker_count"]


def test_the_mean_matches_the_ledger(text, ledger):
    """Compared at ONE decimal, which is the precision the prose uses and the
    same comparison `test_product_readiness.py` makes. Comparing exactly would
    put the two guards in conflict -- one demanding 8.06 and the other 8.1 --
    and a pair of tests that cannot both pass gets one of them deleted."""
    assert _mean(text) == pytest.approx(round(ledger["readiness_mean"], 1))


def test_every_dimension_score_matches_the_ledger(text, ledger):
    """Per dimension, because a mean can be right while the distribution that
    produced it is wrong -- and the distribution is what a reader acts on."""
    document = _distribution(text)
    generated = {r["dimension"]: r["score"] for r in ledger["readiness_matrix"]}

    assert set(document) == set(generated), (
        "dimension names differ between the document and the generator: "
        f"only in document={sorted(set(document) - set(generated))}, "
        f"only in generator={sorted(set(generated) - set(document))}"
    )
    for dimension, score in generated.items():
        assert document[dimension] == pytest.approx(score), (
            f"{dimension}: document says {document[dimension]}, generator "
            f"says {score}"
        )


# ── the honesty claims in the document must stay true ─────────────────────


def test_the_document_does_not_claim_a_ten_that_the_ledger_does_not_have(
    text, ledger
):
    """A 10 requires objective external evidence. The document says none is
    scored 10; this asserts the generator agrees."""
    assert ledger["scored_ten"] == []
    assert "No dimension is scored 10" in text


def test_customer_validation_is_still_zero_in_both(text, ledger):
    """The score most likely to be quietly promoted. There are no customers,
    and a non-zero here would be the single most misleading number in the
    document."""
    generated = {r["dimension"]: r["score"] for r in ledger["readiness_matrix"]}

    assert generated["Customer validation"] == 0.0
    assert _distribution(text)["Customer validation"] == 0.0


def test_the_document_names_the_guard_that_checks_it(text):
    """So a reader knows the figures are enforced rather than asserted, and so
    somebody editing the numbers finds out what will fail."""
    assert "test_readiness_doc_matches_ledger" in text
