"""The quickstart must keep demonstrating a case the gate actually asserts.

A newcomer's first impression of this product is `scripts/quickstart.py`. If
its demo attack drifts away from the tracked red-team table, that impression
stops matching what the release gate verifies -- and the most likely drift is
somebody making the demo more impressive than the evidence supports.

These tests do not RUN the quickstart: it starts a server and takes a couple of
seconds, which does not belong in a unit suite. They pin the properties that
would let it lie.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "quickstart.py"


def _source() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_the_demo_attack_matches_the_tracked_red_team_case():
    """Same actions, same order, as `staged_exfiltration`.

    Pinned so the demo cannot become a different, more flattering attack than
    the one the release gate asserts on every build.
    """
    from scripts.quickstart import DEMO_STEPS
    from tests_arch.test_red_team_suite import RED_TEAM_CASES

    tracked = next(c for c in RED_TEAM_CASES if c.name == "staged_exfiltration")

    assert [s["action"] for s in DEMO_STEPS] == [
        s["action"] for s in tracked.steps
    ], "the quickstart demo has drifted from the tracked case"


def test_the_demo_steps_form_a_causal_chain():
    """A set of three calls is not the attack; the ORDER is.

    Each step after the first must name its parent, or the sequence detector
    has nothing to correlate and the demo would be showing a coincidence.
    """
    from scripts.quickstart import DEMO_STEPS

    assert "parentEventId" not in DEMO_STEPS[0]
    for previous, step in zip(DEMO_STEPS, DEMO_STEPS[1:]):
        assert step["parentEventId"] == previous["eventId"]


def test_the_quickstart_exits_non_zero_when_no_incident_is_raised():
    """The branch that makes the script honest.

    Read from the source rather than by running it: what matters is that the
    no-incident path returns a failure, and that it says the detection did not
    fire rather than staying silent.
    """
    source = _source()

    assert "NO incident was raised" in source
    assert "detection did not fire" in source
    assert "rather than printing a tick for having got this far" in source


def test_the_quickstart_cross_checks_two_independent_sources():
    """The submission response and the incident list are separate reports of
    one fact. A demo that quietly picked the more flattering of two
    disagreeing signals would be the thing this script exists not to be.
    """
    source = _source()

    assert "admitted_at_ingest" in source
    assert "disagree" in source


def test_the_quickstart_refuses_rather_than_faking_a_server(monkeypatch):
    """No in-process fallback when uvicorn is missing.

    Falling back would demonstrate a code path no deployment uses, while
    printing the same output -- which is the shape of a demo that proves
    nothing.
    """
    source = _source()

    assert "uvicorn is not installed" in source
    assert "a code path no" in source


def test_the_quickstart_does_not_weaken_the_build_to_run():
    """Its demo credentials satisfy the real key-length check.

    A quickstart that needed the check relaxed would be demonstrating a
    weakened build, and the relaxation would outlive the demo.
    """
    from scripts.quickstart import INGEST_KEY, VIEW_KEY

    for key in (INGEST_KEY, VIEW_KEY):
        assert len(key) >= 32, f"{key!r} is shorter than the real minimum"

    source = _source()
    for weakening in ("SENTINEL_ALLOW_", "_DISABLE_", "verify=False"):
        assert weakening not in source, (
            f"the quickstart sets {weakening}, which would demonstrate a "
            "weakened build"
        )


def test_the_quickstart_states_what_did_not_happen():
    """It must explain that nothing was blocked, and why.

    Left out, a newcomer concludes either that the product failed to stop the
    attack or that it would have. Both are wrong, and the second is the one
    that turns into a support ticket after a customer's agent keeps running.
    """
    source = _source()

    assert "nothing was blocked" in source
    assert "self-reported" in source


def test_the_quickstart_cleans_up_after_itself():
    """A demo that leaves a database behind is a demo somebody runs once."""
    source = _source()

    assert "TemporaryDirectory" in source
    assert "which is now deleted" in source


def test_the_script_parses_and_declares_its_entry_point():
    tree = ast.parse(_source())
    functions = {
        node.name for node in tree.body if isinstance(node, ast.FunctionDef)
    }

    assert "main" in functions
