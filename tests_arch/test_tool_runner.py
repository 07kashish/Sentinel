"""F-11: ProtectedToolRunner fail-closed contracts."""

from __future__ import annotations

from pathlib import Path

from sentinel.application.protect_gate import ProtectGate
from sentinel.application.tool_runner import ProtectedToolRunner, ToolExecutionRefused
from sentinel.domain.primitives import TrustLevel
from sentinel.domain.protect import ProtectDecision
from sentinel.infrastructure.detection import DeterministicPolicy


class _BoomPolicy:
    """Policy that cannot be evaluated."""

    def evaluate(self, *, payload, trust):  # noqa: ANN001
        raise RuntimeError("policy backend down")

    def version(self) -> str:
        return "boom@1"


def _runner(*, enforce: bool, policy=None) -> ProtectedToolRunner:
    return ProtectedToolRunner(
        gate=ProtectGate(
            policy=policy or DeterministicPolicy.default(),
            enforce=enforce,
        )
    )


def test_enforced_deny_never_runs_side_effect():
    runner = _runner(enforce=True)
    ran = {"n": 0}

    try:
        runner.execute(
            agent_id="agent-1",
            tool="read_file",
            resource=".env",
            trust=TrustLevel.VERIFIED,
            side_effect=lambda: ran.__setitem__("n", ran["n"] + 1) or "ok",
        )
    except ToolExecutionRefused:
        assert ran["n"] == 0
    else:
        raise AssertionError("expected ToolExecutionRefused for .env under enforce")


def test_advisory_may_run_side_effect_but_never_claims_enforced():
    runner = _runner(enforce=False)
    ran = {"n": 0}
    outcome, result = runner.execute(
        agent_id="agent-1",
        tool="read_file",
        resource=".env",
        trust=TrustLevel.VERIFIED,
        side_effect=lambda: ran.__setitem__("n", ran["n"] + 1) or "ok",
    )
    assert outcome.enforced is False
    assert ran["n"] == 1
    assert result == "ok"
    if outcome.decision is ProtectDecision.BLOCK:
        assert outcome.enforced is False


def test_evaluation_failure_fail_closed_under_enforce():
    runner = _runner(enforce=True, policy=_BoomPolicy())
    ran = {"n": 0}
    try:
        runner.execute(
            agent_id="agent-1",
            tool="read_file",
            resource=".env",
            trust=TrustLevel.VERIFIED,
            side_effect=lambda: ran.__setitem__("n", ran["n"] + 1) or "ok",
        )
    except ToolExecutionRefused as exc:
        assert "fail closed" in str(exc).lower() or "evaluation failed" in str(exc).lower()
        assert ran["n"] == 0
    else:
        raise AssertionError("must fail closed when policy cannot evaluate")


def test_evaluation_failure_does_not_silent_allow_in_advisory():
    """Advisory still must not swallow eval errors into a successful side effect."""
    runner = _runner(enforce=False, policy=_BoomPolicy())
    ran = {"n": 0}
    try:
        runner.execute(
            agent_id="agent-1",
            tool="read_file",
            resource=".env",
            trust=TrustLevel.VERIFIED,
            side_effect=lambda: ran.__setitem__("n", ran["n"] + 1) or "ok",
        )
    except RuntimeError:
        assert ran["n"] == 0
    else:
        raise AssertionError("advisory must not silent-allow on eval failure")


def test_execute_requires_tool_and_agent():
    runner = _runner(enforce=True)
    try:
        runner.execute(
            agent_id="",
            tool="read_file",
            trust=TrustLevel.VERIFIED,
            side_effect=lambda: "x",
        )
    except ToolExecutionRefused:
        pass
    else:
        raise AssertionError("empty agent_id must refuse")


def test_source_always_calls_run_if_allowed():
    """Callers using this wrapper cannot skip the gate without editing the module."""
    source = (
        Path(__file__).resolve().parents[1]
        / "sentinel"
        / "application"
        / "tool_runner.py"
    ).read_text(encoding="utf-8")
    assert "run_if_allowed" in source
    assert "side_effect" in source
    # The side effect must not be invoked before the gate call.
    gate_at = source.find("self._gate.run_if_allowed")
    # No direct side_effect() call except via the gate action= parameter.
    assert gate_at != -1
    assert "side_effect()" not in source.replace("action=side_effect", "")


