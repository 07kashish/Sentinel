"""No artifact can turn a GA gate green. Proven by trying.

WHAT THESE FOUR GATES ARE
-------------------------
`independent_pentest`, `production_soak`, `disaster_recovery_proof` and
`design_partner_validation` are the gates that separate a release candidate
from GA. Not one of them is code. They accrue from OPERATING the product -- from
a calendar, a contract, a second failure domain, and other organisations
running this against their own traffic.

So no build should ever report them as PASS, and the interesting question is not
whether the current code does, but whether it CAN.

WHY THIS IS NOT THE TEST THAT ALREADY EXISTED
------------------------------------------------
`test_release_binding.py` checks that the string "PASS" does not appear in the
source block near `GA_GATES`. That is a text scan, and this session has now
found four separate cases where a text scan matched the prose promising the
property rather than the property -- including one where the docstring
guaranteeing the absence of a thing was itself the match.

These tests plant a real, well-formed, correctly BOUND artifact for each GA
gate -- the strongest evidence any other gate could ask for -- and assert the
verdict is still UNVERIFIED. The claim moves from "the code does not say PASS"
to "there is no input for which it says PASS".

THE FORGERY THIS BLOCKS
-----------------------
Someone under deadline drops `gate_production_soak.json` containing
`{"ok": true}` into the evidence directory and stamps it. Every mechanism in
the pipeline reads that as a job that ran and succeeded, because for every
other gate that is exactly what it means. The readiness report then says the
product survived a production soak that never happened.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from scripts import build_release_evidence as evidence
from scripts import release_binding

ROOT = Path(__file__).resolve().parent.parent


def _plant(directory: Path, gate: str, payload: dict) -> None:
    """Write a bound artifact for `gate`, as convincing as one can be made."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"gate_{gate}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    release_binding.write_binding(
        path,
        release=release_binding.release_identity(
            evidence._git("rev-parse", "HEAD") or "0" * 40, root=ROOT
        ),
        now=datetime.now(timezone.utc),
    )


@pytest.mark.parametrize("gate", sorted(evidence.GA_GATES))
def test_a_perfect_artifact_does_not_make_a_GA_gate_pass(gate, tmp_path):
    """The core claim, one gate at a time.

    The planted artifact is bound to the real HEAD and the real source tree, so
    provenance verification succeeds. It records success in the exact shape
    every other gate uses. It is, by every mechanical test the pipeline
    applies, this build's evidence that the gate passed.

    It must still come back UNVERIFIED.
    """
    _plant(
        tmp_path / "gates",
        gate,
        {
            "gate": gate,
            "ok": True,
            "exit_code": 0,
            "summary": f"{gate}: exit 0",
        },
    )

    bundle = evidence.collect(tmp_path)
    verdict = next(g for g in bundle.gates if g.name == gate)

    assert verdict.status == evidence.UNVERIFIED, (
        f"{gate} reported {verdict.status} from a planted artifact. This gate "
        "is not satisfiable by a build, and a build that can report it as "
        "satisfied is a build that can claim a pentest nobody ran."
    )
    assert "NOT SATISFIABLE BY A BUILD" in verdict.detail


def test_the_reason_is_reported_rather_than_the_gate_being_hidden():
    """Omitting them would be worse than reporting them unverified.

    A reader seeing twenty-one green rows and no mention of pentesting could
    reasonably conclude the product was ready to sell. The four rows are what
    answer "why is this not GA", and they answer it from the generated document
    rather than from whoever is asked.
    """
    bundle = evidence.collect(ROOT / "does-not-exist")
    reported = {g.name for g in bundle.gates}
    for gate in evidence.GA_GATES:
        assert gate in reported, f"{gate} is not reported at all"


def test_no_combination_of_planted_artifacts_reaches_a_GA_tier(tmp_path):
    """All four at once, plus every other gate satisfied.

    The tier is computed rather than typed precisely so it cannot be argued up.
    With every satisfiable gate green and all four GA gates forged, the best
    reachable tier is still RELEASE CANDIDATE, and the bundle must say so.
    """
    gates = tmp_path / "gates"
    for gate in [*evidence.REQUIRED_GATES, *evidence.GA_GATES]:
        _plant(gates, gate, {"gate": gate, "ok": True, "exit_code": 0,
                             "summary": f"{gate}: exit 0"})

    bundle = evidence.collect(tmp_path)
    tier = bundle.release_tier

    assert "GA" not in tier.replace("NOT GA", ""), (
        f"a bundle of planted artifacts reported tier {tier!r}"
    )
    for gate in evidence.GA_GATES:
        verdict = next(g for g in bundle.gates if g.name == gate)
        assert verdict.status == evidence.UNVERIFIED


def test_a_GA_gate_carries_no_source_path_even_when_an_artifact_exists(tmp_path):
    """A `source` would invite a reader to go and check the artifact, which
    would show a green result and contradict the row it sits in.

    The gate is emitted from a fixed reason, never from a file, so there is
    nothing to cite -- and citing nothing is correct here rather than an
    omission.
    """
    _plant(tmp_path / "gates", "independent_pentest",
           {"gate": "independent_pentest", "ok": True, "exit_code": 0})

    bundle = evidence.collect(tmp_path)
    verdict = next(g for g in bundle.gates if g.name == "independent_pentest")
    assert verdict.source == ""
    assert verdict.binding == ""


def test_the_four_gates_are_the_four_expected_ones():
    """A gate quietly leaving this set would become satisfiable by a build.

    Pinned by NAME here, in addition to the digest pin in
    `test_release_binding.py`, so a diff that drops one is readable as what it
    is rather than as a hash change.
    """
    assert set(evidence.GA_GATES) == {
        "independent_pentest",
        "production_soak",
        "disaster_recovery_proof",
        "design_partner_validation",
    }


def test_every_GA_gate_states_why_rather_than_only_that():
    """"Not satisfiable" without a reason reads as an excuse.

    Each reason has to be specific enough that somebody could plan the work
    that would satisfy it -- a contract, a second region, a calendar.
    """
    for gate, reason in evidence.GA_GATES.items():
        assert len(reason) > 80, f"{gate} gives no usable reason"
        assert "Requires" in reason, (
            f"{gate} does not say what it requires, so nobody can act on it"
        )
