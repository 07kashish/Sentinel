"""The binding has to be in the execution path, not beside it.

`test_execution_binding.py` tests the comparison. This file tests that the
comparison is REACHED, and that the values reaching the tool are the verified
ones. Both matter separately: this repository has shipped five modules that
passed every test while being unreachable, and a binding nobody calls is a
comment.

The load-bearing test is `test_the_tool_never_runs_when_parameters_were_
substituted`, which counts invocations of the side effect. Asserting only that
a refusal was raised would pass against an implementation that ran the tool and
then complained.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sentinel.application.protect_gate import ProtectGate
from sentinel.application.tool_runner import ProtectedToolRunner, ToolExecutionRefused
from sentinel.domain.execution_binding import (
    ExecutionAuthorization,
    parameter_digest,
)
from sentinel.domain.primitives import TrustLevel
from sentinel.infrastructure.detection import DeterministicPolicy

NOW = datetime(2026, 9, 3, 12, 0, 0, tzinfo=timezone.utc)
PARAMETERS = {"bucket": "acme-reports", "key": "q3/summary.pdf"}


class _Tenant:
    """Minimal stand-in: the runner reads `.value` off whatever tenant it is
    handed, so the seam is exercised with the shape it will really see.
    """

    value = "acme"


class _Ledger:
    def __init__(self) -> None:
        self.used: set[tuple[str, str]] = set()

    def claim(self, *, tenant_id: str, nonce: str) -> bool:
        key = (tenant_id, nonce)
        if key in self.used:
            return False
        self.used.add(key)
        return True


def _authorization(**overrides) -> ExecutionAuthorization:
    defaults = dict(
        authorization_id="auth-1",
        tenant_id="acme",
        actor_identity="user:priya",
        agent_identity="agent:writer",
        tool_identity="s3.put_object",
        action="s3:PutObject",
        target_resource="arn:aws:s3:::acme-reports/q3/summary.pdf",
        approved_parameter_digest=parameter_digest(PARAMETERS),
        issued_at="2026-09-03T11:59:00+00:00",
        expires_at="2026-09-03T12:05:00+00:00",
        nonce="nonce-1",
    )
    defaults.update(overrides)
    return ExecutionAuthorization(**defaults)  # type: ignore[arg-type]


def _runner() -> ProtectedToolRunner:
    return ProtectedToolRunner(
        gate=ProtectGate(policy=DeterministicPolicy.default(), enforce=True),
        tenant=_Tenant(),
    )


def _run(runner, *, parameters=None, authorization=None, ledger=None, seen=None,
         **overrides):
    calls = seen if seen is not None else []

    def side_effect(verified):
        calls.append(dict(verified))
        return {"status": "written"}

    kwargs = dict(
        authorization=authorization or _authorization(),
        agent_id="agent:writer",
        tool="s3.put_object",
        action="s3:PutObject",
        resource="arn:aws:s3:::acme-reports/q3/summary.pdf",
        parameters=parameters if parameters is not None else dict(PARAMETERS),
        trust=TrustLevel.VERIFIED,
        side_effect=side_effect,
        nonces=ledger or _Ledger(),
        now=NOW,
    )
    kwargs.update(overrides)
    return runner.execute_bound(**kwargs), calls


# ── the path is reached and the happy case still works ─────────────────────


def test_a_matching_execution_runs_and_returns_a_receipt():
    """The anchor. Every refusal test below would pass against an
    `execute_bound` that refused everything.
    """
    (outcome, result, receipt), calls = _run(_runner())

    assert result == {"status": "written"}
    assert calls == [PARAMETERS]
    assert receipt.outcome == "succeeded"
    assert receipt.authorization_digest == _authorization().digest
    assert receipt.actual_parameter_digest == parameter_digest(PARAMETERS)
    assert outcome is not None


def test_the_tool_receives_the_verified_parameters():
    """Not the caller's separate copy. This is what makes the binding
    structural: the values that reach the tool are the values the digest was
    checked against.
    """
    (_, _, _), calls = _run(_runner())

    assert calls[0] == PARAMETERS


def test_the_receipt_binds_authorization_request_and_result():
    (_, _, receipt), _ = _run(_runner())

    assert receipt.authorization_digest
    assert receipt.executed_request_digest
    assert receipt.actual_parameter_digest
    # Three distinct commitments, not one value copied into three fields.
    assert len({
        receipt.authorization_digest,
        receipt.executed_request_digest,
        receipt.actual_parameter_digest,
    }) == 3


# ── the refusals, observed by whether the tool ran ──────────────────────────


def test_the_tool_never_runs_when_parameters_were_substituted():
    """THE test. Counts invocations rather than trusting the exception: an
    implementation that ran the tool and then raised would satisfy a
    `pytest.raises` assertion perfectly.
    """
    calls: list = []

    with pytest.raises(ToolExecutionRefused) as raised:
        _run(
            _runner(),
            parameters=dict(PARAMETERS) | {"bucket": "attacker-exfil"},
            seen=calls,
        )

    assert calls == []
    assert "does not match its authorization" in str(raised.value)
    assert "parameters_differ" in str(raised.value)


def test_the_tool_never_runs_when_the_tool_was_substituted():
    calls: list = []

    with pytest.raises(ToolExecutionRefused):
        _run(_runner(), tool="s3.delete_object", seen=calls)

    assert calls == []


def test_the_tool_never_runs_when_the_resource_was_substituted():
    calls: list = []

    with pytest.raises(ToolExecutionRefused):
        _run(_runner(), resource="arn:aws:s3:::acme-secrets/keys.json", seen=calls)

    assert calls == []


def test_the_tool_never_runs_for_a_replay():
    """First call must succeed. Otherwise this passes against a runner that
    refuses every call.
    """
    runner, ledger = _runner(), _Ledger()
    first_calls: list = []
    _run(runner, ledger=ledger, seen=first_calls)
    assert len(first_calls) == 1

    second_calls: list = []
    with pytest.raises(ToolExecutionRefused):
        _run(runner, ledger=ledger, seen=second_calls)

    assert second_calls == []


def test_the_tool_never_runs_on_an_expired_authorization():
    calls: list = []

    with pytest.raises(ToolExecutionRefused):
        _run(_runner(), now=NOW + timedelta(hours=1), seen=calls)

    assert calls == []


def test_the_tool_never_runs_across_tenants():
    """The runner reads the tenant off its own configured tenant, so an
    authorization issued to another one must not be usable here.
    """
    calls: list = []

    with pytest.raises(ToolExecutionRefused):
        _run(_runner(), authorization=_authorization(tenant_id="globex"), seen=calls)

    assert calls == []


def test_the_refusal_names_what_disagreed():
    """An operator who cannot see which field differed will assume the check is
    broken and route around it.
    """
    with pytest.raises(ToolExecutionRefused) as raised:
        _run(_runner(), tool="s3.delete_object")

    assert "tool_substituted" in str(raised.value)


# ── the payload that leaves this method ─────────────────────────────────────


def test_parameters_are_not_copied_into_the_detection_payload():
    """The payload reaches detection, logs and evidence. Parameters can carry
    a query, a body or a token; the digest identifies them without disclosing
    them.

    The probe value must NOT appear in the resource. The first version of this
    test searched for the object key, which is legitimately part of the
    resource ARN that detection needs -- so it reported a leak that was not
    one, and would have gone on reporting it after any fix.
    """
    seen: dict = {}

    class _RecordingGate(ProtectGate):
        def run_if_allowed(self, *, payload, trust, action, **context):
            seen.update(payload)
            return super().run_if_allowed(payload=payload, trust=trust, action=action, **context)

    runner = ProtectedToolRunner(
        gate=_RecordingGate(policy=DeterministicPolicy.default(), enforce=True),
        tenant=_Tenant(),
    )

    probe = {"bucket": "acme-reports", "body": "PATIENT-4471-DIAGNOSIS"}
    authorization = _authorization(approved_parameter_digest=parameter_digest(probe))

    _run(runner, parameters=probe, authorization=authorization)

    flattened = repr(seen)
    assert "PATIENT-4471-DIAGNOSIS" not in flattened
    assert seen["metadata"]["parameter_digest"] == parameter_digest(probe)


# ── the unbound path is still there, and is honestly weaker ────────────────


def test_the_unbound_execute_still_works_and_binds_nothing():
    """`execute` is unchanged, so existing callers keep working. It is recorded
    here as providing NO binding rather than left to be assumed equivalent --
    a deployment that believes both paths are bound has the weaker one in
    production.
    """
    runner = _runner()
    ran = {"n": 0}

    def side_effect() -> str:
        ran["n"] += 1
        return "executed"

    outcome, result = runner.execute(
        agent_id="agent:writer",
        tool="s3.put_object",
        trust=TrustLevel.VERIFIED,
        side_effect=side_effect,
        action="s3:PutObject",
        resource="arn:aws:s3:::acme-reports/q3/summary.pdf",
    )

    assert result == "executed"
    assert ran["n"] == 1
    # No receipt, no authorization, no parameter digest. That is the gap
    # `execute_bound` exists to close, and it is still open on this path.
    assert not isinstance(outcome, tuple)


# ── the flag that turns available into enforced ────────────────────────────
#
# Everything above proves execute_bound works. None of it proves a deployment
# USES it -- and `execute` was left in place unchanged, so without the flag
# below "Sentinel binds authorization to execution" is a claim about the code
# and not about any running system.


def test_the_unbound_execute_refuses_when_binding_is_required():
    """The whole point of the flag. Counts invocations rather than trusting the
    exception: an implementation that ran the tool and then raised would
    satisfy pytest.raises perfectly.
    """
    runner = ProtectedToolRunner(
        gate=ProtectGate(policy=DeterministicPolicy.default(), enforce=True),
        tenant=_Tenant(),
        require_binding=True,
    )
    ran = {"n": 0}

    def side_effect() -> str:
        ran["n"] += 1
        return "executed"

    with pytest.raises(ToolExecutionRefused) as raised:
        runner.execute(
            agent_id="agent:writer",
            tool="s3.put_object",
            trust=TrustLevel.VERIFIED,
            side_effect=side_effect,
        )

    assert ran["n"] == 0
    assert "SENTINEL_REQUIRE_EXECUTION_BINDING" in str(raised.value)
    assert "execute_bound" in str(raised.value)


def test_the_bound_path_still_works_when_binding_is_required():
    """The negative control. Without it the test above would pass against a
    runner that refused both paths, which would be an outage rather than a
    security control.
    """
    runner = ProtectedToolRunner(
        gate=ProtectGate(policy=DeterministicPolicy.default(), enforce=True),
        tenant=_Tenant(),
        require_binding=True,
    )

    (_, result, receipt), calls = _run(runner)

    assert result == {"status": "written"}
    assert len(calls) == 1
    assert receipt.authorization_digest


def test_the_unbound_path_works_when_binding_is_not_required():
    """Backwards compatibility, asserted rather than assumed. Turning this on
    by default would break every unmigrated caller, and a security control that
    takes the service down on upgrade gets reverted rather than adopted.
    """
    runner = _runner()  # require_binding defaults False
    ran = {"n": 0}

    def side_effect() -> str:
        ran["n"] += 1
        return "executed"

    _outcome, result = runner.execute(
        agent_id="agent:writer",
        tool="s3.put_object",
        trust=TrustLevel.VERIFIED,
        side_effect=side_effect,
    )

    assert result == "executed"
    assert ran["n"] == 1


def test_the_refusal_fires_before_the_kill_switch_and_budget_checks():
    """Ordering matters for the message, not the outcome. A deployment with
    binding required and an exhausted budget should be told the call site is
    wrong, because that is the thing the operator has to change -- a budget
    message would send them to raise a limit that is not the problem.
    """
    from sentinel.application.protect_controls import ProtectControls

    runner = ProtectedToolRunner(
        gate=ProtectGate(policy=DeterministicPolicy.default(), enforce=True),
        controls=ProtectControls(kill_switch=True),
        tenant=_Tenant(),
        require_binding=True,
    )

    with pytest.raises(ToolExecutionRefused) as raised:
        runner.execute(
            agent_id="agent:writer",
            tool="s3.put_object",
            trust=TrustLevel.VERIFIED,
            side_effect=lambda: "executed",
        )

    assert "SENTINEL_REQUIRE_EXECUTION_BINDING" in str(raised.value)


def test_the_container_passes_the_setting_to_the_runner(tmp_path, engine_config):
    """A setting nothing reads is the shape of an integration that can be
    claimed and bypassed. This reads the composed object, not the config.

    Parametrised over both engines because it builds a real container against a
    real database, and the fitness rule that such tests run on SQLite AND
    PostgreSQL is not one to opt out of on the grounds that this particular
    test is unlikely to care.
    """
    from dataclasses import replace

    from sentinel.composition.container import build_container
    from sentinel.composition.settings import Settings
    from sentinel.infrastructure.sql.engine import build_engine
    from sentinel.infrastructure.sql.migrate import migrate

    base = Settings.from_environment(
        {
            "SENTINEL_ENV": "development",
            "SENTINEL_DB_PATH": str(tmp_path / "wiring.db"),
            "SENTINEL_API_KEYS": f"acme:{'k' * 40}:analyst",
            "SENTINEL_CORS_ORIGINS": "https://console.example.com",
        }
    )
    assert base.require_execution_binding is True

    settings = replace(
        base, engine=engine_config, require_execution_binding=True
    )
    # `build_container` refuses an unmigrated schema, which is correct and
    # unrelated to what this test is about.
    pool = build_engine(settings.engine)
    try:
        migrate(pool)
    finally:
        pool.close()

    container = build_container(settings)
    try:
        ran = {"n": 0}

        def side_effect() -> str:
            ran["n"] += 1
            return "executed"

        with pytest.raises(ToolExecutionRefused):
            container.tool_runner.execute(
                agent_id="agent:writer",
                tool="echo",
                trust=TrustLevel.VERIFIED,
                side_effect=side_effect,
            )
        assert ran["n"] == 0
    finally:
        container.close()


# ── the proxy is the chokepoint, so the binding has to reach it ────────────
#
# `InlineToolProxy` is what the MCP gateway routes through. Until it could take
# an authorization, SENTINEL_REQUIRE_EXECUTION_BINDING refused every tool call
# in the product -- a switch that turned the service off rather than one that
# enforced binding. `test_binding_required_without_the_proxy_migration_refuses_
# everything` is that state, kept as the reason this migration exists.


def _proxy(*, require_binding: bool, effects=None):
    from sentinel.application.protect_gate import ProtectGate
    from sentinel.application.tool_proxy import InlineToolProxy, RegisteredSideEffect
    from sentinel.application.tool_runner import ProtectedToolRunner
    from sentinel.infrastructure.detection import DeterministicPolicy

    return InlineToolProxy(
        tool_runner=ProtectedToolRunner(
            gate=ProtectGate(policy=DeterministicPolicy.default(), enforce=True),
            require_binding=require_binding,
            tenant=_Tenant(),
        ),
        effects=effects
        or {
            "echo": RegisteredSideEffect(
                name="echo", runner=lambda a: {"echo": dict(a)}
            )
        },
    )


PROXY_ARGS = {"path": "/srv/reports/q3.pdf", "mode": "r"}


def _proxy_auth(**overrides):
    from sentinel.domain.execution_binding import parameter_digest

    defaults = dict(
        authorization_id="auth-proxy",
        tenant_id="acme",
        actor_identity="user:priya",
        agent_identity="agent:reader",
        tool_identity="echo",
        action="echo",
        target_resource="res",
        approved_parameter_digest=parameter_digest(PROXY_ARGS),
        issued_at="2026-09-03T11:59:00+00:00",
        expires_at="2026-09-03T12:05:00+00:00",
        nonce="nonce-proxy",
    )
    defaults.update(overrides)
    return ExecutionAuthorization(**defaults)  # type: ignore[arg-type]


def _proxy_run(proxy, *, arguments=None, authorization=None, ledger=None, **kw):
    return proxy.execute(
        agent_id="agent:reader",
        tool="echo",
        trust=TrustLevel.VERIFIED,
        resource="res",
        action="echo",
        arguments=arguments if arguments is not None else dict(PROXY_ARGS),
        authorization=authorization,
        nonces=ledger if ledger is not None else _Ledger(),
        now=NOW,
        **kw,
    )


def test_the_proxy_executes_a_matching_authorization_and_returns_a_receipt():
    """The anchor for everything below."""
    from sentinel.domain.execution_binding import parameter_digest

    response = _proxy_run(_proxy(require_binding=True),
                          authorization=_proxy_auth())

    assert response["result"] == {"echo": PROXY_ARGS}
    assert response["receipt"]["actual_parameter_digest"] == parameter_digest(
        PROXY_ARGS
    )


def test_the_proxy_refuses_substituted_arguments():
    """The parameters the proxy receives ARE the tool's arguments, which is why
    this is the right place for the binding rather than the honest-caller
    convention it replaces.
    """
    from sentinel.application.tool_proxy import ToolProxyRefused

    with pytest.raises(ToolProxyRefused) as raised:
        _proxy_run(
            _proxy(require_binding=True),
            authorization=_proxy_auth(),
            arguments={"path": "/tmp/substituted-report", "mode": "r"},
        )

    assert "does not match its authorization" in str(raised.value)
    assert "parameters_differ" in str(raised.value)


def test_the_tool_receives_the_verified_arguments():
    """Structural, not conventional: execute_bound passes the verified mapping
    into the effect, so what runs is what the digest was checked against.
    """
    from sentinel.application.tool_proxy import RegisteredSideEffect

    seen: list = []
    proxy = _proxy(
        require_binding=True,
        effects={
            "echo": RegisteredSideEffect(
                name="echo",
                runner=lambda a: seen.append(dict(a)) or {"ok": True},
            )
        },
    )

    _proxy_run(proxy, authorization=_proxy_auth())

    assert seen == [PROXY_ARGS]


def test_binding_required_without_an_authorization_refuses():
    """And this is what made the flag unusable before the migration: with no
    way to pass an authorization, EVERY call landed here.
    """
    from sentinel.application.tool_proxy import ToolProxyRefused

    with pytest.raises(ToolProxyRefused) as raised:
        _proxy_run(_proxy(require_binding=True), authorization=None)

    assert "SENTINEL_REQUIRE_EXECUTION_BINDING" in str(raised.value)


def test_an_authorization_without_a_nonce_ledger_is_refused():
    """Refused rather than defaulted. A default in-process ledger makes
    single-use per-process, which across replicas is no replay protection at
    all -- and it would pass every test in this file.
    """
    from sentinel.application.tool_proxy import ToolProxyRefused

    proxy = _proxy(require_binding=True)

    with pytest.raises(ToolProxyRefused) as raised:
        proxy.execute(
            agent_id="agent:reader",
            tool="echo",
            trust=TrustLevel.VERIFIED,
            resource="res",
            action="echo",
            arguments=dict(PROXY_ARGS),
            authorization=_proxy_auth(),
            nonces=None,
            now=NOW,
        )

    assert "no nonce ledger" in str(raised.value)


def test_the_unbound_path_still_works_when_binding_is_not_required():
    """Backwards compatibility for every existing caller, asserted."""
    response = _proxy_run(_proxy(require_binding=False), authorization=None)

    assert response["result"] == {"echo": PROXY_ARGS}
    assert "receipt" not in response


def test_replay_through_the_proxy_is_refused():
    from sentinel.application.tool_proxy import ToolProxyRefused

    proxy, ledger = _proxy(require_binding=True), _Ledger()

    assert _proxy_run(proxy, authorization=_proxy_auth(), ledger=ledger)["result"]

    with pytest.raises(ToolProxyRefused):
        _proxy_run(proxy, authorization=_proxy_auth(), ledger=ledger)


def test_an_unregistered_tool_is_refused_before_any_binding_work():
    """Fail closed on an unknown tool stays first: the proxy never invents an
    effect, and an authorization for a tool that does not exist should not get
    as far as a digest comparison.
    """
    from sentinel.application.tool_proxy import ToolProxyRefused

    with pytest.raises(ToolProxyRefused) as raised:
        _proxy(require_binding=True).execute(
            agent_id="agent:reader",
            tool="not-registered",
            trust=TrustLevel.VERIFIED,
            authorization=_proxy_auth(tool_identity="not-registered"),
            nonces=_Ledger(),
            now=NOW,
        )

    assert "not registered" in str(raised.value)


# ── the proxy carries the chain digest, or the binding is decorative ──────


def test_the_proxy_refuses_a_substituted_delegation_chain():
    """End to end through the real proxy: same parameters, same tool, same
    agent, valid authorization -- a DIFFERENT delegation chain.

    Counts invocations rather than trusting the exception, because an
    implementation that ran the tool and then complained would satisfy
    pytest.raises perfectly.
    """
    from sentinel.application.tool_proxy import RegisteredSideEffect, ToolProxyRefused

    seen: list = []
    proxy = _proxy(
        require_binding=True,
        effects={
            "echo": RegisteredSideEffect(
                name="echo", runner=lambda a: seen.append(dict(a)) or {"ok": True}
            )
        },
    )
    authorization = _proxy_auth(delegation_passport_digest="c" * 64)

    with pytest.raises(ToolProxyRefused) as raised:
        proxy.execute(
            agent_id="agent:reader",
            tool="echo",
            trust=TrustLevel.VERIFIED,
            resource="res",
            action="echo",
            arguments=dict(PROXY_ARGS),
            authorization=authorization,
            nonces=_Ledger(),
            now=NOW,
            delegation_passport_digest="d" * 64,
        )

    assert seen == []
    assert "delegation_substituted" in str(raised.value)


def test_the_proxy_executes_when_the_chain_matches():
    """The negative control. Without it the refusal above would pass against a
    proxy that refused every bound call.
    """
    chain = "c" * 64
    proxy = _proxy(require_binding=True)

    response = _proxy_run(
        proxy,
        authorization=_proxy_auth(delegation_passport_digest=chain),
        delegation_passport_digest=chain,
    )

    assert response["result"] == {"echo": PROXY_ARGS}
    assert response["receipt"]["actual_parameter_digest"]


def test_the_detection_payload_carries_the_chain_digest_not_the_chain():
    """The digest identifies which chain without putting principal names and
    grants into a payload that reaches detection, logs and evidence.
    """
    from sentinel.application.protect_gate import ProtectGate
    from sentinel.application.tool_proxy import InlineToolProxy, RegisteredSideEffect
    from sentinel.application.tool_runner import ProtectedToolRunner
    from sentinel.infrastructure.detection import DeterministicPolicy

    seen: dict = {}

    class _RecordingGate(ProtectGate):
        def run_if_allowed(self, *, payload, trust, action, **context):
            seen.update(payload)
            return super().run_if_allowed(payload=payload, trust=trust, action=action, **context)

    chain = "c" * 64
    proxy = InlineToolProxy(
        tool_runner=ProtectedToolRunner(
            gate=_RecordingGate(policy=DeterministicPolicy.default(), enforce=True),
            tenant=_Tenant(),
            require_binding=True,
        ),
        effects={
            "echo": RegisteredSideEffect(name="echo", runner=lambda a: {"ok": True})
        },
    )

    _proxy_run(
        proxy,
        authorization=_proxy_auth(delegation_passport_digest=chain),
        delegation_passport_digest=chain,
    )

    assert seen["metadata"]["delegation_passport_digest"] == chain
