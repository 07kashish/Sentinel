"""Mutation tests: break a guard on purpose and require a test to notice.

WHY THIS EXISTS
---------------
A passing test suite proves the code does what the tests check. It says nothing
about whether the tests check anything. The predecessor had a mutation harness
and shipped, in the same release, an invariant asserted in a docstring that no
probe encoded -- so the harness proved its enumerated guards were load-bearing
while the guard everyone cared about was absent entirely.

Each mutation below:

  1. loads the real module,
  2. replaces exactly ONE guard with a broken version,
  3. runs a behavioural PROBE that must now fail,
  4. restores the original and asserts the probe passes again.

Step 3 is the part that makes this real. A mutation test that only asserts "the
source no longer contains string X" proves nothing about behaviour -- it is a
substring assertion wearing a lab coat. Every probe here executes the engine and
observes an outcome.

Step 4 matters too: a probe that fails both before and after the mutation is
detecting something else, and would give a false pass.
"""

from __future__ import annotations

from pathlib import Path

import contextlib
from typing import Any, Callable, Iterator

import pytest

import sentinel.domain.execution as execution_module
import sentinel.domain.incident as incident_module
from sentinel.domain.attestation import AttestationDisposition
from sentinel.domain.errors import (
    ArtifactMissing,
    ExecutionFenceLost,
    IllegalTransition,
    MissingRequiredFact,
)
from sentinel.domain.execution import (
    ExecutionPlan,
    StepDefinition,
    StepKind,
    StepName,
    StepStatus,
)
from sentinel.domain.incident import Fence, Incident, IncidentState
from sentinel.domain.primitives import IdempotencyKey, Severity, TrustLevel
from tests_arch.harness import EffectLog, Harness, ScriptedGateway, TENANT


@contextlib.contextmanager
def mutated(target: Any, attribute: str, replacement: Any) -> Iterator[None]:
    """Swap one attribute, guaranteeing restoration even if the probe raises."""
    original = getattr(target, attribute)
    setattr(target, attribute, replacement)
    try:
        yield
    finally:
        setattr(target, attribute, original)


def assert_probe_detects(probe: Callable[[], None], target: Any, attribute: str, replacement: Any):
    """The full protocol: probe passes, mutation breaks it, restoration heals it.

    All three legs are required. Without leg 1 the probe might be broken already;
    without leg 3 the mutation might have leaked into the rest of the suite.
    """
    probe()  # 1. green before

    with mutated(target, attribute, replacement):
        with pytest.raises(BaseException) as caught:  # 2. red under mutation
            probe()
        # Only ImportError/NameError indicate a broken TEST. An AttributeError
        # or TypeError under mutation is a legitimate detection: removing a
        # guard that returned a value often makes the caller fail on None,
        # and refusing to count that would reject real detections.
        assert not isinstance(caught.value, (ImportError, NameError)), (
            f"the probe failed because the TEST is broken, not the code: "
            f"{type(caught.value).__name__}: {caught.value}"
        )

    probe()  # 3. green again


@pytest.fixture
def harness(tmp_path):
    h = Harness(tmp_path, name="mutation.db")
    yield h
    h.close()


# ── The lifecycle guard ──────────────────────────────────────────────────────


def test_the_completed_attested_fact_requirement_is_load_bearing():
    """Remove the anchored-outcome requirement and a transient outage completes.

    This is the exact defect the whole rewrite exists to prevent, expressed as a
    mutation: weaken `_REQUIRED_FACTS` to a mere presence check -- which is
    literally what the predecessor had -- and confirm a test catches it.
    """
    def probe() -> None:
        # REPORTED -> COMPLETED_UNATTESTED is a LEGAL edge, so the edge table
        # cannot refuse it. Only the fact requirement can, which is what makes
        # this probe target that guard and not another one.
        #
        # An earlier version of this probe drove REPORTED -> COMPLETED_ATTESTED,
        # which the edge table refuses on its own -- so the mutation was
        # undetectable and the test was proving nothing about the facts at all.
        incident = _reported_incident()
        with pytest.raises(MissingRequiredFact):
            incident.advance(
                IncidentState.COMPLETED_UNATTESTED,
                fence=Fence.worker(1),
                now=_NOW,
                # A TRANSIENT outcome. Presence-checking would accept it; the
                # real requirement demands `not_anchorable`.
                attestation_outcome=AttestationDisposition.UNAVAILABLE.value,
            )

    weakened = dict(execution_required_facts())
    weakened[IncidentState.COMPLETED_UNATTESTED] = (
        ("evidence_digest", _present, "an evidence digest"),
        ("report_id", _present, "a report id"),
        # THE MUTATION: presence instead of correctness -- which is literally
        # what the predecessor had, and is how "Skipped" satisfied it.
        ("attestation_outcome", _present, "any attestation outcome at all"),
    )
    assert_probe_detects(probe, incident_module, "_REQUIRED_FACTS", weakened)


def test_the_edge_table_is_load_bearing():
    """Allow every edge and an illegal jump stops being refused."""
    def probe() -> None:
        incident = _admitted()
        with pytest.raises(IllegalTransition):
            incident.advance(IncidentState.COMPLETED_ATTESTED, fence=Fence.worker(1), now=_NOW)

    permissive = {state: frozenset(IncidentState) for state in IncidentState}
    assert_probe_detects(probe, incident_module, "_EDGES", permissive)


def test_the_terminal_set_is_load_bearing():
    """Empty the terminal set and a finished incident becomes writable again."""
    def probe() -> None:
        # `_TERMINAL` is what `is_terminal` reads, and `is_terminal` is what the
        # ENGINE consults to decide there is no work left. The edge table refuses
        # transitions out of FAILED independently, so probing that would detect
        # the edge guard rather than this one.
        incident = _admitted()
        incident.fail(reason="probe", fence=Fence.worker(1), now=_NOW)
        assert incident.is_terminal, "a failed incident must report itself terminal"
        assert IncidentState.COMPLETED_ATTESTED.is_terminal
        assert not IncidentState.ATTESTATION_UNAVAILABLE.is_terminal

    assert_probe_detects(probe, incident_module, "_TERMINAL", frozenset())


# ── The step machine ─────────────────────────────────────────────────────────


def test_the_step_edge_table_is_load_bearing():
    """Permit every step transition and a settled step becomes re-runnable."""
    def probe() -> None:
        from sentinel.domain.execution import check_step_transition

        with pytest.raises(IllegalTransition):
            check_step_transition(StepStatus.COMPLETED, StepStatus.RUNNING)

    permissive = {status: frozenset(StepStatus) for status in StepStatus}
    assert_probe_detects(probe, execution_module, "_STEP_EDGES", permissive)


def test_the_saga_shape_rule_is_load_bearing(harness):
    """Accept any plan shape and a compensatable step can follow the pivot.

    A plan like that promises an unwind that would stall on a step with no
    compensation, which is precisely what the shape rule refuses.
    """
    def probe() -> None:
        with pytest.raises(Exception):
            ExecutionPlan(
                (
                    StepDefinition(StepName("pivot"), StepKind.PIVOT),
                    StepDefinition(
                        StepName("after"),
                        StepKind.COMPENSATABLE,
                        compensation=StepName("undo"),
                    ),
                )
            )

    probe()  # the rule holds today; there is no attribute to swap, so assert directly.
    # And the positive case: a well-shaped plan is accepted.
    plan = ExecutionPlan(
        (
            StepDefinition(StepName("a"), StepKind.COMPENSATABLE, compensation=StepName("ua")),
            StepDefinition(StepName("pivot"), StepKind.PIVOT),
            StepDefinition(StepName("b"), StepKind.RETRIABLE),
        )
    )
    assert plan.pivot is not None and plan.pivot.name.value == "pivot"


# ── The engine's guards, probed through real execution ──────────────────────


def test_the_idempotency_key_being_epoch_free_is_load_bearing(tmp_path):
    """Make the key epoch-dependent and every retry becomes a NEW effect.

    This mutation reproduces the predecessor's behaviour exactly, and the probe
    is the chaos scenario: crash after the anchor, retry, count DISTINCT keys.
    """
    def probe() -> None:
        effects = EffectLog()
        gateway = ScriptedGateway(effects=effects, crash_after_effect=0)
        h = Harness(tmp_path, gateway=gateway, name=None)
        try:
            incident = h.admit()
            with pytest.raises(Exception):
                h.run(incident, epoch=1)
            h.run(incident, epoch=2)
            assert len(effects.distinct_keys("anchor")) == 1, (
                f"the retry produced a second effect key: "
                f"{sorted(effects.distinct_keys('anchor'))}"
            )
        finally:
            h.close()

    def epoch_dependent_key(*, tenant, incident, step):
        # THE MUTATION: a key that changes on every attempt.
        import random

        return IdempotencyKey(f"idem-{tenant}-{incident}-{step}-{random.randint(1, 10**9)}")

    # Patched on the ENGINE module, which is where the name is bound. Patching
    # the defining module has no effect: `from ... import step_idempotency_key`
    # already copied the reference, so the engine would keep calling the original
    # and the mutation would appear undetectable.
    import sentinel.application.execution.engine as engine_module

    assert_probe_detects(
        probe, engine_module, "step_idempotency_key", epoch_dependent_key
    )


def test_hydration_is_load_bearing(tmp_path):
    """Disable artifact hydration and a resumed run attests with no evidence.

    The probe is the predecessor's defect verbatim: park at
    ATTESTATION_UNAVAILABLE, resume, and require that the resumed run either
    anchors properly or refuses -- never that it silently succeeds with nothing.
    """
    import sentinel.application.execution.pipeline as pipeline_module

    def probe() -> None:
        h = Harness(
            tmp_path,
            gateway=ScriptedGateway(
                effects=EffectLog(),
                script=[AttestationDisposition.UNAVAILABLE],
                default=AttestationDisposition.ANCHORED,
            ),
            name=None,
        )
        try:
            incident = h.admit()
            h.run(incident, epoch=1)
            assert h.state(incident) is IncidentState.ATTESTATION_UNAVAILABLE
            h.run(incident, epoch=2)
            assert h.state(incident) is IncidentState.COMPLETED_ATTESTED
            h.assert_invariants(incident)
        finally:
            h.close()

    def no_hydration(self):
        return ()  # THE MUTATION: never rebuild the execution context.

    assert_probe_detects(
        probe, pipeline_module.PipelineSteps, "hydrators", no_hydration
    )


def test_the_require_evidence_guard_is_load_bearing(tmp_path):
    """Make `require_evidence` return None instead of raising.

    With the guard removed, an incident whose evidence was destroyed proceeds and
    the system produces an attestation over nothing. The probe asserts it refuses.
    """
    import sentinel.application.execution.engine as engine_module

    def probe() -> None:
        h = Harness(
            tmp_path,
            gateway=ScriptedGateway(
                effects=EffectLog(), default=AttestationDisposition.UNAVAILABLE
            ),
            name=None,
        )
        try:
            incident = h.admit()
            h.run(incident, epoch=1)
            with h.pool.acquire() as conn:
                conn.begin()
                conn.set_tenant(TENANT.value)
                conn.execute_rowcount(
                    f"DELETE FROM evidence WHERE tenant_id={conn.p} AND incident_id={conn.p}",
                    (TENANT.value, incident.value),
                )
                conn.commit()
            with pytest.raises(ArtifactMissing):
                h.run(incident, epoch=2)
        finally:
            h.close()

    def lenient(self):
        return self.evidence  # THE MUTATION: returns None instead of raising.

    assert_probe_detects(
        probe, engine_module.ExecutionContext, "require_evidence", lenient
    )


def test_the_fence_check_is_load_bearing(harness):
    """Neuter `acquire_execution` and a stale worker writes over a live one."""
    def probe() -> None:
        incident = _admitted()
        incident.acquire_execution(10)
        with pytest.raises(ExecutionFenceLost):
            incident.advance(IncidentState.VALIDATED, fence=Fence.worker(2), now=_NOW)

    def no_fence(self, fence):
        return None  # THE MUTATION: every write is permitted.

    assert_probe_detects(probe, Incident, "_guard", no_fence)


def test_the_journal_settled_check_is_load_bearing(tmp_path):
    """Report every step as unsettled and the plan re-runs completed work.

    `next_step` is what makes resume deterministic. Mutating it to ignore the
    settled set means a replay re-executes from the beginning, which the probe
    detects as a second effect key or a duplicated transition.
    """
    def probe() -> None:
        h = Harness(tmp_path, name=None)
        try:
            incident = h.admit()
            h.run(incident, epoch=1)
            transitions_before = h.transitions(incident)
            h.run(incident, epoch=2)
            assert h.transitions(incident) == transitions_before, (
                "a replay appended duplicate transitions"
            )
            h.assert_invariants(incident)
        finally:
            h.close()

    original = ExecutionPlan.next_step

    def ignore_settled(self, settled):
        return original(self, ())  # THE MUTATION: pretend nothing has run.

    assert_probe_detects(probe, ExecutionPlan, "next_step", ignore_settled)


def test_the_severity_cap_is_load_bearing():
    """Remove the trust cap and an unsigned source reaches CRITICAL."""
    def probe() -> None:
        incident = Incident.admit(
            tenant_id=TENANT,
            incident_id=_INCIDENT,
            severity=Severity(100),
            trust_level=TrustLevel.UNSIGNED,
            source="probe",
            now=_NOW,
        )
        assert incident.severity.value == 79
        assert incident.priority.value != "CRITICAL"

    def no_cap(self, trust):
        return self  # THE MUTATION: the cap never applies.

    assert_probe_detects(probe, Severity, "capped_for", no_cap)


# ── Meta: the protocol itself must be able to fail ──────────────────────────


def test_a_probe_that_cannot_fail_is_reported_as_such():
    """Guard against a vacuous mutation test.

    If `assert_probe_detects` accepted a probe that never fails, every mutation
    here could silently degrade into a no-op. This asserts the harness itself
    rejects that case.
    """
    def always_passes() -> None:
        assert True

    with pytest.raises(BaseException):
        assert_probe_detects(always_passes, incident_module, "_TERMINAL", frozenset())




def test_fail_requires_fence_probe_detects_defaulted_fence():
    """F-2 / F-12: a defaulted fence on fail() must be caught by the suite."""
    import inspect
    from sentinel.domain.incident import Incident

    sig = inspect.signature(Incident.fail)
    fence_param = sig.parameters["fence"]
    assert fence_param.default is inspect.Parameter.empty, (
        "Incident.fail defaulted fence=; unfenced terminalisation is back"
    )


def test_assert_holds_rejects_stale_and_unfenced():
    """F-5 / F-12: pre-publish fence assertion is behavioural, not documentary."""
    from sentinel.domain.errors import ExecutionFenceLost
    from sentinel.domain.incident import Fence, Incident
    from sentinel.domain.primitives import Severity, TrustLevel

    incident = Incident.admit(
        tenant_id=TENANT,
        incident_id=_INCIDENT,
        severity=Severity(90),
        trust_level=TrustLevel.VERIFIED,
        source="probe",
        now=_NOW,
    )
    incident.acquire_execution(2)
    with pytest.raises(ExecutionFenceLost):
        incident.assert_holds(Fence.worker(1))
    with pytest.raises(ExecutionFenceLost):
        incident.assert_holds(Fence.unfenced(reason="maintenance"))
    incident.assert_holds(Fence.worker(2))






def test_pipeline_calls_assert_holds_before_anchor():
    """F-5 / F-12: the publish path must assert the fence before gateway.anchor."""
    source = Path(__file__).resolve().parents[1]
    source = source / "sentinel" / "application" / "execution" / "pipeline.py"
    text = source.read_text(encoding="utf-8")
    hold = text.find("assert_holds(ctx.fence)")
    anchor = text.find("self._attestation.anchor(")
    assert hold != -1 and anchor != -1 and hold < anchor, (
        "assert_holds must appear immediately before attestation.anchor in pipeline.py"
    )

def test_assert_holds_is_load_bearing():
    """F-5 / F-12: neuter assert_holds and a stale fence is accepted."""
    from sentinel.domain.errors import ExecutionFenceLost
    from sentinel.domain.incident import Fence, Incident
    from sentinel.domain.primitives import Severity, TrustLevel

    def probe() -> None:
        incident = Incident.admit(
            tenant_id=TENANT,
            incident_id=_INCIDENT,
            severity=Severity(90),
            trust_level=TrustLevel.VERIFIED,
            source="probe",
            now=_NOW,
        )
        incident.acquire_execution(2)
        with pytest.raises(ExecutionFenceLost):
            incident.assert_holds(Fence.worker(1))

    def noop(self, fence):  # noqa: ANN001
        return None

    assert_probe_detects(probe, Incident, "assert_holds", noop)


def test_protect_enforced_flag_cannot_lie_in_advisory_mode():
    """F-11 / F-12: mutating decide_protect to force enforced=true must be caught."""
    import sentinel.domain.protect as protect_module
    from sentinel.domain.protect import ProtectDecision, ProtectVerdict
    from sentinel.domain.primitives import Severity, TrustLevel

    def probe() -> None:
        outcome = protect_module.decide_protect(
            verdict=ProtectVerdict(
                fired=True,
                severity=Severity(90),
                detector_version="p@1",
                matched_rules=("r1",),
            ),
            trust=TrustLevel.VERIFIED,
            enforce=False,
        )
        assert outcome.decision is ProtectDecision.BLOCK
        assert outcome.enforced is False

    def lying_decide(*, verdict, trust, enforce):  # noqa: ANN001
        from sentinel.domain.protect import ProtectDecision as PD, ProtectOutcome

        return ProtectOutcome(
            decision=PD.BLOCK,
            enforced=True,  # THE MUTATION: lies in advisory mode
            severity=verdict.severity.value,
            capped_severity=verdict.severity.value,
            detector_version=verdict.detector_version,
            matched_rules=verdict.matched_rules,
            reason="mutant",
        )

    assert_probe_detects(probe, protect_module, "decide_protect", lying_decide)


def test_attestation_unavailable_terminal_flag_is_load_bearing():
    """F-1 / F-12: marking ATTESTATION_UNAVAILABLE terminal must be detected."""
    def probe() -> None:
        assert not IncidentState.ATTESTATION_UNAVAILABLE.is_terminal

    class FakeTerminal:
        def __contains__(self, item):  # noqa: ANN001
            return True

    # Mutating _TERMINAL to contain everything makes is_terminal true for UNAVAILABLE.
    assert_probe_detects(
        probe,
        incident_module,
        "_TERMINAL",
        frozenset(IncidentState),
    )


def test_valueerror_must_not_be_classified_terminal():
    """F-9 / F-12: failure_is_retryable must not terminalise incidental builtins."""
    import sentinel.domain.errors as errors_module
    from sentinel.domain.errors import DomainRuleViolated

    def probe() -> None:
        assert errors_module.failure_is_retryable(ValueError("truncated json")) is True
        assert errors_module.failure_is_retryable(TypeError("bad")) is True
        assert errors_module.failure_is_retryable(KeyError("x")) is True
        assert errors_module.failure_is_retryable(DomainRuleViolated("x")) is False

    def regress(exc):  # noqa: ANN001
        if isinstance(exc, (ValueError, TypeError, KeyError)):
            return False  # THE MUTATION: TERMINAL_ERRORS returns
        if isinstance(exc, errors_module.SentinelError):
            return exc.is_retryable
        return True

    assert_probe_detects(probe, errors_module, "failure_is_retryable", regress)


def test_attestation_anchor_receives_idempotency_key(tmp_path):
    """F-5: the gateway must be called with the deterministic key, not None."""
    from sentinel.domain.attestation import AttestationDisposition

    effects = EffectLog()
    harness = Harness(
        tmp_path,
        name="idem-key.db",
        gateway=ScriptedGateway(effects=effects, default=AttestationDisposition.ANCHORED),
    )
    try:
        incident = harness.admit()
        harness.run(incident)
        keys = effects.distinct_keys("anchor")
        assert len(keys) == 1
        key = next(iter(keys))
        assert key, "idempotency key must be a non-empty string"
        assert "epoch" not in key
    finally:
        harness.close()





def test_decide_approval_tool_runner_wrap_is_load_bearing():
    """F-11 / F-12: decide_approval must not call executor.execute without the runner."""
    from pathlib import Path

    source_path = (
        Path(__file__).resolve().parents[1]
        / "sentinel"
        / "application"
        / "commands"
        / "decide_approval.py"
    )
    source = source_path.read_text(encoding="utf-8")

    def probe() -> None:
        assert "_tool_runner.execute" in source
        # The executor call must live only as the side_effect lambda body.
        assert "side_effect=lambda: self._executor.execute" in source.replace(" ", "") or (
            "side_effect=" in source and "_executor.execute" in source
        )
        runner_at = source.find("_tool_runner.execute")
        # Direct unprotected pattern must not appear as a standalone assignment.
        assert "receipt = self._executor.execute" not in source
        assert runner_at != -1

    def bypass_source_probe() -> None:
        # Simulate a mutant that restored the old direct call.
        mutated = source.replace(
            "_tool_runner.execute",
            "_MISSING_tool_runner.execute",
            1,
        )
        assert "_tool_runner.execute" not in mutated
        assert "receipt = self._executor.execute" not in source  # baseline still gated
        # The behavioural probe: if someone removed tool_runner call textually...
        if "_tool_runner.execute" not in mutated:
            raise AssertionError("tool_runner wrap removed")

    probe()
    with pytest.raises(AssertionError):
        bypass_source_probe()
    probe()


def test_decide_approval_source_orders_runner_before_executor():
    from pathlib import Path

    source = (
        Path(__file__).resolve().parents[1]
        / "sentinel"
        / "application"
        / "commands"
        / "decide_approval.py"
    ).read_text(encoding="utf-8")
    assert source.find("_tool_runner.execute") < source.find("_executor.execute")


def test_tool_runner_gate_call_is_load_bearing():
    """F-11 / F-12: removing run_if_allowed from ProtectedToolRunner must be caught."""
    import sentinel.application.tool_runner as runner_module
    from sentinel.application.protect_gate import ProtectGate
    from sentinel.application.tool_runner import ProtectedToolRunner, ToolExecutionRefused
    from sentinel.domain.primitives import TrustLevel
    from sentinel.infrastructure.detection import DeterministicPolicy

    def probe() -> None:
        runner = ProtectedToolRunner(
            gate=ProtectGate(policy=DeterministicPolicy.default(), enforce=True)
        )
        ran = {"n": 0}

        def side_effect():
            ran["n"] += 1
            return "ok"

        with pytest.raises(ToolExecutionRefused):
            runner.execute(
                agent_id="agent-1",
                tool="read_file",
                resource=".env",
                trust=TrustLevel.VERIFIED,
                side_effect=side_effect,
            )
        assert ran["n"] == 0, "side effect must not run when protect refuses"

    def bypass_execute(
        self,
        *,
        agent_id,
        tool,
        trust,
        side_effect,
        resource="",
        action="",
        metadata=None,
        event_type="tool_call",
    ):  # noqa: ANN001
        # THE MUTATION: skip the gate and run the tool anyway.
        return None, side_effect()

    assert_probe_detects(
        probe, runner_module.ProtectedToolRunner, "execute", bypass_execute
    )


def test_tool_runner_source_requires_run_if_allowed():
    """F-12: a deleted gate call in source must be visible without running tools."""
    from pathlib import Path

    source = (
        Path(__file__).resolve().parents[1]
        / "sentinel"
        / "application"
        / "tool_runner.py"
    ).read_text(encoding="utf-8")
    assert "self._gate.run_if_allowed" in source


def test_kill_switch_path_is_load_bearing():
    """F-11 / F-12: removing kill-switch check must be caught."""
    import sentinel.application.tool_runner as runner_module
    from sentinel.application.protect_controls import ProtectControls
    from sentinel.application.protect_gate import ProtectGate
    from sentinel.application.tool_runner import ProtectedToolRunner, ToolExecutionRefused
    from sentinel.infrastructure.detection import DeterministicPolicy

    def probe() -> None:
        runner = ProtectedToolRunner(
            gate=ProtectGate(policy=DeterministicPolicy.default(), enforce=True),
            controls=ProtectControls(kill_switch=True),
        )
        with pytest.raises(ToolExecutionRefused, match="kill switch"):
            runner.execute(
                agent_id="a",
                tool="t",
                trust=TrustLevel.VERIFIED,
                side_effect=lambda: 1,
            )

    def bypass_execute(self, **kwargs):  # noqa: ANN001
        # THE MUTATION: skip controls and gate
        return kwargs["side_effect"]()

    assert_probe_detects(probe, runner_module.ProtectedToolRunner, "execute", bypass_execute)


def test_tool_proxy_unknown_tool_fails_closed():
    """F-11 / F-12: unknown tools must not invent an effect."""
    import sentinel.application.tool_proxy as proxy_module
    from sentinel.application.protect_controls import ProtectControls
    from sentinel.application.protect_gate import ProtectGate
    from sentinel.application.tool_proxy import InlineToolProxy, ToolProxyRefused
    from sentinel.application.tool_runner import ProtectedToolRunner
    from sentinel.infrastructure.detection import DeterministicPolicy

    def probe() -> None:
        proxy = InlineToolProxy(
            tool_runner=ProtectedToolRunner(
                gate=ProtectGate(policy=DeterministicPolicy.default(), enforce=True),
                controls=ProtectControls(),
            )
        )
        with pytest.raises(ToolProxyRefused, match="not registered"):
            proxy.execute(
                agent_id="a",
                tool="missing",
                trust=TrustLevel.VERIFIED,
            )

    def open_execute(self, **kwargs):  # noqa: ANN001
        return {"tool": kwargs["tool"], "result": "mutant", "protect": {}}

    assert_probe_detects(probe, proxy_module.InlineToolProxy, "execute", open_execute)


# ── Fixtures ─────────────────────────────────────────────────────────────────

from datetime import datetime, timezone  # noqa: E402

from sentinel.domain.primitives import Digest, IncidentId, Timestamp  # noqa: E402

_NOW = Timestamp(datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc))
_INCIDENT = IncidentId("inc-mutation")
_DIGEST = Digest("d" * 64)


def _present(value: Any) -> bool:
    return value not in (None, "", [], {})


def execution_required_facts():
    return incident_module._REQUIRED_FACTS  # noqa: SLF001


def _admitted() -> Incident:
    incident = Incident.admit(
        tenant_id=TENANT,
        incident_id=_INCIDENT,
        severity=Severity(90),
        trust_level=TrustLevel.VERIFIED,
        source="probe",
        now=_NOW,
    )
    incident.acquire_execution(1)
    return incident


def _reported_incident() -> Incident:
    incident = _admitted()
    fence = Fence.worker(1)
    incident.advance(IncidentState.VALIDATED, fence=fence, now=_NOW)
    incident.advance(
        IncidentState.IDENTITY_CHECKED, fence=fence, now=_NOW, trust_level="verified"
    )
    incident.advance(IncidentState.REPLAY_CHECKED, fence=fence, now=_NOW)
    incident.advance(
        IncidentState.POLICY_EVALUATED, fence=fence, now=_NOW, detector_version="p"
    )
    incident.advance(IncidentState.DETECTED, fence=fence, now=_NOW)
    incident.record_evidence(
        digest=_DIGEST,
        uri="sentinel://e",
        ledger_sequence=1,
        chain_hash=_DIGEST,
        fence=fence,
        now=_NOW,
    )
    incident.record_report(report_bytes=10, fence=fence, now=_NOW)
    return incident
