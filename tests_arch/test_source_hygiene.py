"""No source file carries an invisible control character.

WHY THIS EXISTS
---------------
A shell heredoc turned the two characters `\\b` into a single literal BACKSPACE
byte inside a regex. The result was

    re.search(r"<BS>[0-9]+ passed", output)

which matches nothing, because no program emits a backspace before its test
count. The regex was part of the check that stops a gate reporting a pass for
an all-skipped run, so every pytest gate would have failed -- and the cause
would have been invisible, because a terminal renders a backspace by moving the
cursor. `cat -A` found it; reading the file did not.

The same class covers a zero-width space pasted from a document, a non-breaking
space in an indent, and a bidirectional override -- the last of which can make
source read in one order and execute in another.

WHAT COUNTS AS ALLOWED
----------------------
Tab, newline and carriage return. Everything else in the C0 range, plus the
DEL, zero-width and bidi controls, is refused. None of them has a legitimate
reason to sit in source, and each is invisible or near-invisible in an editor,
which is precisely why a check is worth more than review here.
"""

from __future__ import annotations

import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#: The three whitespace controls that belong in text files.
ALLOWED = {"\t", "\n", "\r"}

#: Invisible characters that are not C0 controls but behave like them. The bidi
#: overrides are the dangerous ones: they can reorder how a line DISPLAYS
#: without changing how it parses, so a reviewer and the interpreter disagree.
INVISIBLE = {
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\u2060",  # word joiner
    "\ufeff",  # zero-width no-break space / BOM in the middle of a file
    "\u00a0",  # non-breaking space
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",  # bidi embedding
    "\u2066", "\u2067", "\u2068", "\u2069",  # bidi isolate
}

#: Extensions worth scanning: anything a human edits and a machine parses.
SCANNED = {".py", ".toml", ".json", ".yaml", ".yml", ".js", ".css", ".html", ".md", ".sql"}

SKIP_DIRS = {"__pycache__", "node_modules", "venv", "release"}


def _skipped(path: Path) -> bool:
    """Directories that are not hand-written source.

    Any dot-directory is excluded, which covers `.git`, the tool caches, and
    `evaluation/.cache` -- the last holding downloaded jailbreak corpora where
    a zero-width space is the DATA under test, not damage to it. Listing them
    individually meant the next cache directory arrived unscanned or noisy.
    """
    return any(
        part in SKIP_DIRS or part.startswith(".") for part in path.parts
    )


#: A file may opt out by carrying this marker with a reason, for the one
#: legitimate case: source where an invisible character IS the thing under
#: test. The whitespace-refusal fixtures and the evasion generator are real
#: examples -- a non-breaking space written as `\\u00a0` would not exercise the
#: parser the way a literal one does.
#:
#: A MARKER, not a path list. A path entry would excuse a future accidental
#: paste into the same file; the marker at least states that somebody decided.
#: `test_the_optout_requires_a_stated_reason` refuses a bare marker.
OPTOUT = "invisible-characters-are-the-subject"


def _files():
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix not in SCANNED:
            continue
        if _skipped(path.relative_to(ROOT)):
            continue
        # THIS MODULE DEFINES THE MARKER, so it contains the marker string and
        # would claim its own exemption -- and did, on the first run. A file
        # that matches a rule because it is the rule is the same self-reference
        # that made a source scan match the docstring promising the property.
        if path.name == Path(__file__).name:
            continue
        yield path


def test_no_source_file_contains_an_invisible_control_character():
    """The backspace-in-a-regex defect, and its family."""
    offenders: list[str] = []
    for path in _files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            # Not text, or unreadable. `test_every_scanned_file_is_utf8` below
            # is what objects to the first case; skipping here keeps the two
            # failures separate.
            continue
        if OPTOUT in text:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            for column, character in enumerate(line, 1):
                # A byte-order mark is legitimate at offset zero and corruption
                # anywhere else. Editors write it; a mid-file one came from a
                # bad concatenation.
                if character == "\ufeff" and number == 1 and column == 1:
                    continue
                bad = (
                    character in INVISIBLE
                    or (unicodedata.category(character) == "Cc"
                        and character not in ALLOWED)
                )
                if bad:
                    offenders.append(
                        f"{path.relative_to(ROOT)}:{number}:{column} "
                        f"U+{ord(character):04X} "
                        f"({unicodedata.name(character, 'unnamed')})"
                    )
    assert not offenders, (
        "these files contain invisible control characters:\n"
        + "\n".join(f"  {entry}" for entry in offenders)
        + "\n\nThey are almost always shell-escaping damage or a bad paste. A "
        "literal backspace inside a regex once made it match nothing while "
        "reading correctly in every editor."
    )


def test_every_scanned_file_is_utf8():
    """A file in another encoding will be misread rather than rejected.

    Several suites here parse the tree, and `errors='replace'` turns a mojibake
    byte into a replacement character that then fails to match a pattern nobody
    thinks to question.
    """
    offenders = []
    for path in _files():
        try:
            path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            offenders.append(f"{path.relative_to(ROOT)}: {exc}")
    assert not offenders, "not valid UTF-8:\n" + "\n".join(offenders)


def test_the_scan_actually_reaches_the_tree():
    """A glob that matched nothing would make both checks pass vacuously --
    which is the exact failure mode this file exists to guard against, and it
    would be embarrassing to reproduce here.
    """
    files = list(_files())
    assert len(files) > 100, f"only {len(files)} files scanned; the glob is broken"
    suffixes = {p.suffix for p in files}
    assert {".py", ".html", ".js"} <= suffixes, f"scan missed types: {suffixes}"


def test_the_detector_finds_a_planted_backspace(tmp_path):
    """Proof the check can fail, rather than trust that it would.

    Written because every defect this session was a check that could not fail.
    """
    probe = tmp_path / "probe.py"
    probe.write_text('pattern = r"' + chr(8) + '[0-9]+ passed"', encoding="utf-8")

    text = probe.read_text(encoding="utf-8")
    found = [
        character
        for character in text
        if unicodedata.category(character) == "Cc" and character not in ALLOWED
    ]
    assert found, "the detector would not notice a literal backspace"


def test_the_optout_requires_a_stated_reason():
    """A bare marker is an exemption nobody has to justify.

    The gitleaks allowlist in this repository already learned this: every entry
    names a path and a reason, because an unexplained exemption is how a gate
    rots into the thing it exists to prevent.
    """
    thin = []
    for path in _files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if OPTOUT not in text:
            continue
        line = next(
            (row for row in text.splitlines() if OPTOUT in row), ""
        )
        # The marker plus a reason. The marker alone is 37 characters.
        if len(line.strip()) < len(OPTOUT) + 30:
            thin.append(f"{path.relative_to(ROOT)}: {line.strip()!r}")
    assert not thin, (
        "these files opt out of the invisible-character check without saying "
        "why:\n" + "\n".join(f"  {entry}" for entry in thin)
    )


def test_the_optout_cannot_be_claimed_by_a_file_that_is_not_about_them():
    """Bounded to where the exemption is defensible.

    Production code under `sentinel/` has no business containing an invisible
    character, and an opt-out there would be the marker being used to silence
    the check rather than to describe the file.
    """
    misplaced = []
    for path in _files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if OPTOUT in text and path.is_relative_to(ROOT / "sentinel"):
            misplaced.append(str(path.relative_to(ROOT)))
    assert not misplaced, (
        f"shipped code claims the invisible-character opt-out: {misplaced}. "
        "The exemption exists for fixtures that TEST invisible characters, not "
        "for production source."
    )
