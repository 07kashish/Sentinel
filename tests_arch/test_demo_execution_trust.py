"""The flagship demo has to actually demonstrate something.

WHY A DEMO NEEDS TESTS
----------------------
A demo is the artefact most likely to rot and the least likely to be noticed
rotting: it is run by hand, by somebody evaluating the product, on a machine
nobody controls. And this one crashed on its first run with a
UnicodeEncodeError before printing anything, because the Windows console
defaults to cp1252 and the output had box-drawing characters in it. That is the
worst possible failure for a flagship demo and no test suite would have caught
it, so there is one now.

WHAT IS ACTUALLY ASSERTED
-------------------------
Not "it exited zero". A demo that skipped every step and printed a summary
would exit zero. These read the OUTPUT and require the specific observations
the demo exists to produce -- above all that the substituted execution was
refused, and that the tool was not invoked.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "scripts" / "demo_execution_trust.py"

ANSI = re.compile(r"\x1b\[[0-9;]*m")


@pytest.fixture(scope="module")
def run() -> tuple[int, str]:
    """One run, shared. It is deterministic and takes about a second."""
    result = subprocess.run(
        [sys.executable, str(DEMO)],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        env={**os.environ, "PYTHONPATH": str(ROOT), "PYTHONIOENCODING": "utf-8"},
        timeout=180,
    )
    return result.returncode, ANSI.sub("", result.stdout + result.stderr)


def test_the_demo_exits_zero(run):
    code, output = run

    assert code == 0, output[-3000:]


def test_the_demo_produced_output_at_all(run):
    """Control. Every assertion below is vacuous against an empty string, and
    the first version of this demo produced exactly that -- it died on an
    encoding error before printing a line.
    """
    _code, output = run

    assert len(output) > 1500, f"only {len(output)} chars: {output!r}"


def test_the_output_is_encodable_on_a_windows_console(run):
    """cp1252 is the Windows default and cannot encode box-drawing characters,
    em dashes or the horizontal ellipsis. This is the exact failure that killed
    the first run.
    """
    _code, output = run

    try:
        output.encode("cp1252")
    except UnicodeEncodeError as error:
        offending = output[error.start : error.end]
        pytest.fail(
            f"the demo prints {offending!r}, which a Windows console cannot "
            f"encode -- it will crash before showing anything"
        )


# ── the substitution, which is the whole point ────────────────────────────


def test_the_authorized_execution_succeeded(run):
    """Without this the refusal below would pass against a demo that refuses
    everything, which would be a broken build rather than a strict one.
    """
    _code, output = run

    assert "tool ran and wrote acme-reports/q3/summary.pdf" in output
    assert "the tool received exactly the approved parameters: True" in output


def test_the_substituted_execution_was_refused(run):
    _code, output = run

    assert "parameters_differ" in output
    assert "the tool was NOT invoked: True" in output


def test_question_twelve_is_answered(run):
    """The question nothing in this system could answer before Phase 3."""
    _code, output = run

    assert "12. Did approved and executed parameters differ?" in output
    assert "YES -- approved" in output


# ── the honesty properties ────────────────────────────────────────────────


def test_exactly_two_questions_are_out_of_scope(run):
    """Pinned so the count cannot drift upward quietly. A demo that answers
    fewer questions each release while still exiting zero is the failure this
    guards.
    """
    _code, output = run

    assert "16/18 answered by this run, 2 out of scope" in output


def test_no_question_is_left_unanswered_without_a_reason(run):
    """UNANSWERED means the run was supposed to produce evidence and did not.
    The demo exits non-zero on that, so its absence here is the real assertion.
    """
    _code, output = run

    assert "UNANSWERED" not in output


def test_the_demo_states_what_it_does_not_show(run):
    """A demo that shows the good news and leaves the residual to be inferred
    is a demo that oversells. The three limits are printed every run.
    """
    _code, output = run

    assert "What this demo does NOT show" in output
    assert "CALLER DECLARED" in output
    assert "nonce ledger is in-process" in output
    assert "not published to S3 in this run" in output


def test_the_delegation_step_carries_its_own_negative_control(run):
    """Every tick in the delegation step would also appear against an
    `evaluate` that returned no findings for anything.
    """
    _code, output = run

    assert "control: a staging grant presented in production is refused" in output
    assert "environment_escalation" in output


def test_tampered_evidence_fails_the_same_inclusion_proof(run):
    """Not merely that the digest changed -- that the proof FAILS. The former
    shows arithmetic; the latter shows detection.
    """
    _code, output = run

    assert "its inclusion proof now FAILS" in output


def test_the_independent_verifier_agreed_or_said_why_not(run):
    """Skipping silently would leave the question the whole passport format
    exists for looking answered.
    """
    _code, output = run

    agreed = "two independent implementations agree: True" in output
    explained = "node is not installed" in output

    assert agreed or explained, "the demo neither verified nor explained why not"
