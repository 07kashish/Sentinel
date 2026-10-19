"""The readiness matrix cannot be inflated, and cannot cite nothing.

The master prompt's instruction is "score each honestly 0-10; a 10 requires
objective evidence; do not inflate". That is a rule about a document, and a
rule about a document that nobody enforces is a rule that decays the first time
a score is convenient to raise.

So the constraints are tests:

  * no dimension may be scored 10, because no dimension has the external
    evidence a 10 would require -- the eight EXTERNALLY-UNVERIFIED gates ARE
    that absence;
  * every score must name what it rests on AND what would raise it. A score
    with neither is a number, and a matrix of numbers is exactly the inflated
    document the instruction warns about;
  * "more work" is not an answer to what would raise it.

`test_the_lowest_scores_are_the_ones_with_no_implementation` is the one that
would catch the actual failure mode: quietly lifting the floor so the mean
looks better. Its bounds move only when something is actually built, and each
move records what the new ceiling is and why -- Endpoint discovery went 0 -> 7
when the sensor was written, and is capped at 8 because the sensor is not
signed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.build_gap_ledger import SCORES

ROOT = Path(__file__).resolve().parent.parent
LEDGER_JSON = ROOT / "release" / "gap_ledger.json"


def test_the_matrix_is_not_empty():
    """First, because every assertion below is vacuous over an empty tuple."""
    assert len(SCORES) >= 20, f"only {len(SCORES)} dimensions"


def test_no_dimension_is_scored_ten():
    """A 10 requires objective external evidence. This repository has none for
    any dimension, which is what the eight EXTERNALLY-UNVERIFIED gates record.
    """
    inflated = [s.dimension for s in SCORES if s.score >= 10]

    assert inflated == [], (
        f"scored 10 without external evidence: {inflated}. Every external gate "
        f"is still open, so nothing here can justify a 10."
    )


def test_no_score_is_outside_the_range():
    for score in SCORES:
        assert 0 <= score.score <= 10, f"{score.dimension}={score.score}"


def test_every_score_names_what_it_rests_on():
    """A score without evidence is a number. The threshold is deliberately
    long enough that "tested" or "it works" does not satisfy it.
    """
    for score in SCORES:
        assert len(score.evidence) > 60, (
            f"{score.dimension}: evidence is {len(score.evidence)} chars, which "
            f"is too short to name anything checkable"
        )


def test_every_score_names_what_would_raise_it():
    for score in SCORES:
        assert len(score.to_raise) > 30, score.dimension


@pytest.mark.parametrize("score", SCORES, ids=[s.dimension for s in SCORES])
def test_what_would_raise_it_is_specific(score):
    """"More work", "improvements" and "polish" are not answers. A row whose
    remedy cannot be named is a row whose score cannot be trusted.
    """
    vague = ("more work", "improvements", "polish", "tbd", "todo", "various")
    lowered = score.to_raise.lower()

    for phrase in vague:
        assert phrase not in lowered, f"{score.dimension}: {phrase!r}"


def test_the_lowest_scores_are_the_ones_with_no_implementation():
    """The failure mode this guards: quietly lifting the floor so the mean
    looks better. These three are the honest zeros and near-zeros, and if any
    of them rises, something must actually have been built.
    """
    by_name = {s.dimension: s.score for s in SCORES}

    # Raised from 0 to 7 when the sensor was built and run live. Capped at 8
    # rather than uncapped, because the remaining points are SIGNING and
    # REMOTE ATTESTATION -- the sensor is a script, not a signed binary, which
    # matters the moment it is distributed rather than run from a checkout.
    # A score above 8 would claim a property the artifact does not have.
    assert 0 < by_name["Endpoint discovery"] <= 8, (
        "above 8 claims a signed, remotely-attestable sensor. This one is a "
        "script; distributing it unsigned is the gap."
    )
    assert by_name["Customer validation"] == 0, (
        "no design partner and no customer. Code cannot raise this."
    )
    # Raised from 2 to 6 when the twelve missing modules were written and
    # validated. Capped at 6 rather than uncapped, because the remaining four
    # points are an APPLY -- and no amount of Terraform in a repository proves
    # a running deployment.
    assert by_name["AWS implementation"] <= 6, (
        "above 6 would claim something an unapplied configuration cannot "
        "support: `terraform validate` proves coherence, not that it works."
    )


def test_zero_scores_are_present_rather_than_omitted():
    """An omitted row reads as an oversight; a zero reads as a decision. The
    matrix has to contain its own worst news.
    """
    zeros = [s.dimension for s in SCORES if s.score == 0]

    assert zeros, "no dimension scored zero, which for this codebase is untrue"


def test_the_matrix_reaches_the_machine_readable_ledger():
    """A matrix that exists only in prose cannot be diffed between commits, and
    a readiness score nobody can diff is a readiness score nobody can audit.
    """
    if not LEDGER_JSON.exists():
        pytest.skip(
            "release/gap_ledger.json is generated and gitignored; run "
            "scripts/build_gap_ledger.py"
        )

    payload = json.loads(LEDGER_JSON.read_text(encoding="utf-8"))

    assert payload["scored_ten"] == []
    assert len(payload["readiness_matrix"]) == len(SCORES)
    assert payload["readiness_mean"] < 10
    # Weakest first, so the row that decides what happens next is at the top.
    scores = [row["score"] for row in payload["readiness_matrix"]]
    assert scores == sorted(scores)


def test_the_rendered_document_carries_the_no_ten_statement():
    """Somebody will read the table without the preamble. The constraint has to
    be next to the numbers.
    """
    rendered = (ROOT / "docs" / "readiness" / "GAP_LEDGER.md").read_text(
        encoding="utf-8"
    )

    assert "No dimension is scored 10" in rendered
    assert "Unweighted mean" in rendered
