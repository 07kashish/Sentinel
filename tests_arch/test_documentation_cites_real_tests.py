"""A document may not cite a test that does not exist.

WHY THIS EXISTS
---------------
`docs/SECURITY.md` cited three artifacts as evidence. None was in the
tree:

  * `test_tenant_isolation_is_enforced_by_the_real_database`
  * `test_every_table_is_either_reaped_or_declared_append_only`
  * `tests/test_failure_classes_are_structural.py`  (no `tests/` directory)

Two now exist because they were written. The third's claim was withdrawn. But
nothing stopped any of them being written down in the first place, and nothing
would stop the next one -- which matters here more than in most repositories,
because this project's worst recorded defect (the F-4 retraction) is exactly
this: a claim of coverage with nothing behind it.

This is the general case. It scans `docs/` for anything shaped like a test
identifier and requires each one to resolve to a test pytest actually collects.

HOW IT AVOIDS BEING A GATE THAT EXECUTES NOTHING
--------------------------------------------------
The failure mode for a test like this is that its scanner quietly matches
nothing -- a bad regex, a moved directory, a docs tree that stopped using
backticks -- after which it passes for ever while checking zero citations. So:

  * `test_the_scanner_actually_finds_citations` asserts a non-trivial number of
    citations were found AND that specific known-present names are among them.
    A denominator of zero fails.
  * The collected-node set is asserted non-empty and to contain this very
    module, so a broken collection cannot make every citation "resolve".

That is the positive-assertion pattern residual risk 13 describes: prove work
happened, rather than observe that nothing failed.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

#: A test identifier as it appears in prose. Deliberately anchored on the
#: `test_` prefix rather than on backticks: the docs cite them inside code
#: spans, in tables, in `::`-qualified node ids and occasionally bare.
#: The negative lookahead rejects a GLOB. `docs/TESTING.md` writes
#: `pytest -q tests_arch/test_security_*.py`, and treating `test_security_` as a
#: citation would demand a test by that literal name. A glob is a legitimate way
#: to name a family of tests, not a claim about one.
CITATION = re.compile(r"\btest_[a-z0-9_]{4,}(?![*\w])")

#: A document may retract its unbacked citations in prose and carry this marker.
#: It is NOT a mute button -- see `RETRACTED_BACKLOG`, which ratchets.
RETRACTION_MARKER = "<!-- unbacked-citations-retracted -->"

#: How many dangling citations the retracted documents are ALLOWED to contain,
#: set to the number measured when the retraction was written. It may go DOWN
#: (delete a stale row, or write the test) and must never go UP: a NEW unbacked
#: claim in a retracted document still fails the build.
#:
#: A ratchet, not an exemption. The alternative -- listing every name in
#: `NOT_A_CITATION` -- would have gone stale silently and given no signal when
#: the backlog grew.
# Lowered from 24 on 2026-09-01: COMPLIANCE.md's single dangling
# citation was repaired and its blanket retraction withdrawn. The ratchet
# only grips if the baseline follows the debt down.
RETRACTED_BACKLOG = 20

#: Names that look like citations but are not claims about THIS suite.
#: Every entry needs a reason; an unexplained exemption is how this gate would
#: rot into the thing it exists to prevent.
NOT_A_CITATION = {
    # A retracted claim, kept visible in the prose as a retraction. The whole
    # point of the sentence is that this test does NOT exist, so requiring it to
    # exist would invert the correction.
    "test_failure_classes_are_structural",
    # Same case. `COMPLIANCE.md` and `conftest.py` both name this test in
    # prose whose entire point is that it does NOT exist -- it was inherited
    # from the predecessor implementation and cited for months. Requiring it to
    # resolve would invert the correction and force the record to be deleted
    # instead of kept.
    "test_rls_is_actually_enforced",
    # Illustrative names in explanatory prose about naming conventions, not
    # references to a specific test.
    "test_something",
    "test_example",
}


def _collected_test_names() -> set[str]:
    """Everything pytest actually collects: function names AND module stems.

    Both, because the documents legitimately cite both. `docs/TESTING.md` refers
    to `tests_arch/test_sql_infrastructure.py` (a module) while
    `docs/REMEDIATION_MATRIX.md` refers to
    `test_every_table_is_either_reaped_or_declared_append_only` (a function).
    Resolving only functions rejected every file citation in the tree, which
    would have made this gate unusable and invited someone to weaken the regex
    instead -- the exact move its own docstring forbids.
    """
    # `--collect-only` WITHOUT `-q`. In pytest 9 the quiet form prints per-file
    # COUNTS ("tests_arch/test_x.py: 50"), not node ids -- so parsing it yielded
    # an empty set, and every citation would have appeared to resolve. That is
    # the failure this module is about, met while writing this module; the guard
    # in `_collected_test_names` is what caught it.
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "pytest", "--collect-only",
         "--no-header", "-p", "no:cacheprovider", "tests_arch"],
        cwd=str(ROOT), capture_output=True, text=True, check=False,
    )
    names: set[str] = set()
    for line in result.stdout.splitlines():
        line = line.strip()
        if "::" not in line:
            continue
        # `tests_arch/test_x.py::test_y[postgres]` yields BOTH `test_x` and
        # `test_y`, so a citation of either the file or the function resolves.
        path_part, _, node = line.partition("::")
        names.add(node.split("[")[0])
        stem = path_part.replace("\\", "/").rsplit("/", 1)[-1]
        if stem.endswith(".py"):
            names.add(stem[:-3])
    if not names:
        pytest.fail(
            "pytest collected no tests at all, so every citation would appear "
            f"to resolve. stdout tail:\n{result.stdout[-800:]}\n"
            f"stderr tail:\n{result.stderr[-800:]}"
        )
    return names


def _citations(include_retracted: bool = False) -> dict[str, list[str]]:
    """Every test-shaped identifier in docs/, mapped to the files citing it.

    Documents carrying `RETRACTION_MARKER` are excluded by default: they have
    said, in prose a reader can see, that their evidence column refers to a test
    tree that does not exist in this repository. `include_retracted=True` counts
    them anyway, which is how the ratchet measures the backlog.
    """
    found: dict[str, list[str]] = {}
    for path in sorted(DOCS.rglob("*.md")):
        text = path.read_text(encoding="utf-8", errors="replace")
        if RETRACTION_MARKER in text and not include_retracted:
            continue
        for name in CITATION.findall(text):
            if name in NOT_A_CITATION:
                continue
            found.setdefault(name, []).append(str(path.relative_to(ROOT)))
    return found


def _retracted_documents() -> list[Path]:
    """Documents that have declared their citations unbacked."""
    return [
        path
        for path in sorted(DOCS.rglob("*.md"))
        if RETRACTION_MARKER in path.read_text(encoding="utf-8", errors="replace")
    ]


# ── The gate cannot pass vacuously ───────────────────────────────────────────


def test_the_scanner_actually_finds_citations():
    """A denominator of zero would make the real assertion meaningless."""
    citations = _citations()
    assert len(citations) >= 10, (
        f"only {len(citations)} test citations found across {DOCS}; the scanner "
        "is not matching what the documents actually contain, so the check below "
        "would pass while verifying nothing"
    )
    # Anchors: names known to be cited, so a regex that silently narrowed is
    # caught by something other than the count.
    for anchor in (
        "test_retention_sweep",
        "test_saml_xml_hardening",
    ):
        assert any(anchor in name for name in citations), (
            f"expected a citation containing {anchor!r}; the scanner found "
            f"{sorted(citations)[:15]}"
        )


def test_collection_returns_a_real_suite():
    """Guards the resolver the same way, from the other side."""
    names = _collected_test_names()
    assert len(names) >= 200, f"pytest collected only {len(names)} tests"
    assert "test_collection_returns_a_real_suite" in names, (
        "this very test was not in the collected set, so the resolver is not "
        "seeing the suite it claims to check against"
    )


# ── The rule ─────────────────────────────────────────────────────────────────


def test_every_test_cited_in_docs_resolves_to_a_collected_test():
    """The rule this module exists for.

    If this fails you have three honest options, and only three:
      1. write the test, as was done for the two that were missing;
      2. correct the citation to the name that actually exists;
      3. retract the claim in the prose, the way the `tests/` directory claim
         was retracted, and add the name to NOT_A_CITATION with that reason.

    Editing the regex until it stops matching is not one of them.
    """
    collected = _collected_test_names()
    citations = _citations()

    dangling = {
        name: sorted(set(files))
        for name, files in citations.items()
        if name not in collected
    }
    assert not dangling, (
        "documents cite tests that pytest does not collect:\n"
        + "\n".join(
            f"  {name}  <- cited in {', '.join(files)}"
            for name, files in sorted(dangling.items())
        )
        + "\n\nThis is the F-4 defect class: a claim of coverage with nothing "
        "behind it. Write the test, fix the name, or retract the claim."
    )


# ── Retraction is a ratchet, not a mute button ───────────────────────────────


def test_a_retracted_document_says_so_where_a_reader_will_see_it():
    """The marker is an HTML comment. On its own it would be invisible.

    A document that silences this gate must also TELL A READER that its evidence
    column is unbacked — otherwise the retraction exists only for the test
    runner, which is precisely the "claim of coverage with nothing behind it"
    shape being corrected.
    """
    retracted = _retracted_documents()
    assert retracted, (
        "no document carries the retraction marker; if the backlog is genuinely "
        "zero, set RETRACTED_BACKLOG to 0 and delete this test"
    )
    for path in retracted:
        text = path.read_text(encoding="utf-8", errors="replace")
        head = text[:4000]
        assert "RETRACTED" in head or "RETRACTION" in head.upper(), (
            f"{path.relative_to(ROOT)} carries the retraction marker but no "
            "visible retraction notice near the top. The marker is an HTML "
            "comment; a reader would never see it."
        )


def test_the_retracted_citation_backlog_does_not_grow():
    """A retracted document may not accumulate NEW unbacked claims.

    Without this, `RETRACTION_MARKER` would be an off-switch: add it once and a
    document could cite anything for ever. The count may fall — delete a stale
    row, or write the missing test — and the baseline should be lowered when it
    does. It may not rise.
    """
    collected = _collected_test_names()
    everything = _citations(include_retracted=True)
    backlog = sorted(name for name in everything if name not in collected)

    assert len(backlog) <= RETRACTED_BACKLOG, (
        f"the unbacked-citation backlog grew from {RETRACTED_BACKLOG} to "
        f"{len(backlog)}. New entries:\n"
        + "\n".join(f"  {n}  <- {', '.join(sorted(set(everything[n])))}" for n in backlog)
        + "\n\nRetraction records existing debt; it does not license more."
    )
    # And if it has FALLEN, say so, so the baseline gets lowered rather than
    # silently leaving headroom for new unbacked claims.
    assert len(backlog) >= RETRACTED_BACKLOG - 3, (
        f"the backlog is now {len(backlog)}, well below the recorded baseline of "
        f"{RETRACTED_BACKLOG}. Lower RETRACTED_BACKLOG to {len(backlog)} so the "
        "ratchet keeps its grip."
    )
