"""The research page must stay tied to artifacts, not to recollection.

A security product's research page is usually a marketing surface. The failure
mode is not fabrication -- it is DRIFT: a number quoted once from memory, a
caveat trimmed for length, an `UNVERIFIED` row quietly deleted because it looks
bad next to the others.

An earlier draft of this page said "RPO ≈ 57s". The artifact says 12.77s. That
is the exact failure these tests exist to catch, so every number the page
quotes is checked against the file it came from.
"""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "docs" / "RESEARCH.md"


def _page() -> str:
    return PAGE.read_text(encoding="utf-8")


def _flat() -> str:
    """The page with whitespace normalised.

    Markdown wraps, so a literal substring search for a sentence fails on the
    line break rather than on the claim being absent -- a test about formatting
    masquerading as a test about content.
    """
    return " ".join(PAGE.read_text(encoding="utf-8").split())


def _artifact(relative: str) -> dict:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


# ── every number is checked against its artifact ─────────────────────────────


def test_the_false_positive_rate_matches_the_artifact():
    """51.7% of ordinary tool calls. The result a vendor page would omit."""
    measured = _artifact("docs/benign_tool_call_false_positives.json")[
        "false_positive_rate"
    ]

    assert f"{measured:.1%}" in _page(), (
        f"the page does not quote the measured rate {measured:.1%}"
    )


def test_the_recovery_numbers_match_the_artifact():
    """The claim that was wrong in the first draft."""
    drill = _artifact("docs/dr_postgres_wal_pitr_drill.json")
    rpo = drill["measured"]["experimental_rpo_seconds"]
    rto = drill["measured"]["experimental_rto_seconds"]

    page = _page()
    assert f"{rpo:.2f}s" in page, f"RPO {rpo:.2f}s is not the figure on the page"
    assert f"{rto:.2f}s" in page, f"RTO {rto:.2f}s is not the figure on the page"


def test_the_recovery_targets_match_the_artifact():
    drill = _artifact("docs/dr_postgres_wal_pitr_drill.json")
    page = _page()

    assert str(drill["targets"]["rpo_seconds"]) in page
    assert str(drill["targets"]["rto_seconds"]) in page


def test_the_benchmark_headline_matches_the_benchmark_document():
    """The English-only figures, which are the defensible claim."""
    benchmark = (ROOT / "evaluation" / "BENCHMARK.md").read_text(encoding="utf-8")
    page = _page()

    for number in ("0.855", "0.972", "0.044"):
        assert number in benchmark, f"{number} is not in BENCHMARK.md"
        assert number in page, f"{number} is quoted nowhere on the research page"


def test_the_page_quotes_the_lower_headline_as_the_claim():
    """The all-languages figure is higher and is marked untrustworthy in the
    benchmark. Quoting it as the headline is the easiest available dishonesty
    in this repository.
    """
    page = _page()
    english = page.index("0.855")
    all_languages = page.index("0.957")

    assert english < all_languages, (
        "the all-languages figure appears before the English one, which reads "
        "as the headline"
    )
    assert "untrustworthy" in page or "not trustworthy" in page


def test_the_self_authored_corpus_gap_is_stated_with_both_numbers():
    """The most useful result on the page: a corpus written by the people who
    wrote the rules overstated capability by ~26x.
    """
    page = _page()

    assert "0.643" in page
    assert "0.025" in page
    assert "26x" in page or "26 x" in page


def test_the_soft_detector_recall_matches_what_the_runtime_warns():
    """The runtime warns with this figure when the detector is disabled, so
    the page and the log must not disagree.

    Read from the CONSTANT in the composition root rather than from a log
    line. My first version searched `infrastructure/runtime.py`, found
    nothing, and SKIPPED -- and a skipped test proves exactly as much as an
    absent one while looking like coverage.
    """
    # Moved to `adapters.py` when container.py was split at the 800-line
    # fitness limit. Imported from where it lives, not from where it used
    # to -- a test that followed the move by being loosened would stop
    # checking anything.
    from sentinel.composition.adapters import _RULES_ONLY_RECALL

    assert str(_RULES_ONLY_RECALL) in _page(), (
        f"the page does not quote the recall the runtime warns with "
        f"({_RULES_ONLY_RECALL})"
    )


def test_the_sequence_corpus_size_matches_the_corpus():
    from evaluation.sequence_corpus import SEQUENCE_CASES

    assert f"{len(SEQUENCE_CASES)} cases" in _page()


def test_the_campaign_case_count_matches_the_artifact():
    """The page says why no defence rate is published, and the reason depends
    on the count.
    """
    from sentinel.domain.attack_campaign import MIN_CASES_TO_QUOTE_A_RATE

    campaign = _artifact("docs/evidence/attack_campaign.json")
    page = _page()

    assert str(MIN_CASES_TO_QUOTE_A_RATE) in page
    assert str(campaign["case_count"]) in page
    assert campaign["case_count"] < MIN_CASES_TO_QUOTE_A_RATE, (
        "there are now enough cases to quote a rate, so the page's refusal is "
        "stale and should be replaced with the number"
    )


def test_every_file_the_page_cites_exists():
    """A research page citing a path that does not exist is the same defect as
    a compliance matrix citing a test directory that was never in the
    repository -- which happened here, to this codebase's predecessor.
    """
    page = _page()
    missing = []
    for path in re.findall(r"`([a-z][\w/.-]+\.(?:py|md|json))`", page):
        if not (ROOT / path).exists():
            missing.append(path)
    for path in re.findall(r"\]\(\.\./([\w/.-]+)\)", page):
        if not (ROOT / path).exists():
            missing.append(path)

    assert not missing, f"cited but absent: {sorted(set(missing))}"


# ── the caveats that must not be trimmed ─────────────────────────────────────


def test_the_four_evidence_statuses_are_defined_and_used_strictly():
    page = _page()

    for status in ("PASS", "FAIL", "UNVERIFIED", "NOT_APPLICABLE"):
        assert status in page, f"{status} is not defined on the page"
    assert "never quietly converted" in _flat().lower()
    assert "different commit" in page


def test_the_unverified_rows_are_still_present():
    """The rows that look worst next to the others, and the ones a marketing
    edit would remove first.
    """
    flat = _flat()
    for unverified in (
        "No external party has examined this system",
        "no design partners",
        "requires 30 days",
    ):
        assert unverified in flat, f"an UNVERIFIED claim was trimmed: {unverified!r}"


def test_the_transparency_limit_survives_on_the_page():
    """The structure is the easy half. A page that shipped the Merkle log as
    the guarantee would be claiming a property the deployment does not have.
    """
    flat = _flat()

    assert "proves nothing about that party" in flat
    # The precise claim, which got narrower once the log had storage: the gap
    # is no longer "unpersisted" but "unpublished". A test still asserting the
    # old sentence would have to be loosened, and a loosened caveat assertion
    # is how the caveat disappears.
    assert "No root has been published anywhere the operator cannot change it" in flat
    assert "RefusingRootSink" in flat
    assert "does not detect a determined operator" in flat


def test_the_container_is_not_called_a_sandbox_on_the_page():
    """An operator who reads "sandboxed" allows a different set of skills than
    one who reads "shares the host kernel".
    """
    page = _page()

    assert "not a virtual machine" in _flat().lower()
    assert "shares the host kernel" in _flat()
    assert "observation_incomplete" in page


def test_the_known_false_positive_is_published_rather_than_omitted():
    page = _page()

    assert "backup" in page.lower()
    assert "known_gap" in page


def test_the_page_states_what_it_would_like_to_be_wrong_about():
    """An invitation to falsify is the difference between a research page and
    a brochure.
    """
    page = _page()

    assert "wrong about" in page
    assert "canonical_action" in page


def test_the_page_explains_how_to_reproduce_everything():
    page = _page()

    assert "run_release_gates.py" in page
    assert "provenance" in page
    assert "produces **no artifact**" in page or "no artifact" in page


def test_the_page_makes_no_claim_about_customers():
    """There are none. A page implying otherwise would be the most
    consequential false claim in the repository.
    """
    page = _page().lower()

    for forbidden in (
        "our customers",
        "customers report",
        "in production at",
        "trusted by",
        "deployed at scale",
    ):
        assert forbidden not in page, f"unsupported customer claim: {forbidden!r}"
