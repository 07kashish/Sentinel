"""F-11 residual: possible_bypass when enrolled agents go silent.

Proves the loud pageable signal fires under simulated silence.
Does not claim packet interception. Deployment contract manifests are
validated separately as fail-closed egress references.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sentinel.application.bypass_detection import (
    AgentActivity,
    detect_possible_bypasses,
)
from sentinel.domain.primitives import Address, TenantId, Timestamp
from sentinel.infrastructure.identity import SqlAgentRegistry
from sentinel.infrastructure.sql.engine import Dialect, EngineConfig, build_engine
from sentinel.infrastructure.sql.migrate import CURRENT_VERSION, migrate

NOW = Timestamp(datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc))
TENANT = TenantId("acme")
AGENT = Address("0x" + "ab" * 20)
ROOT = Path(__file__).resolve().parents[1]


def test_possible_bypass_fires_for_silent_enrolled_agent():
    enrolled = Timestamp(NOW.value - timedelta(minutes=30))
    signals = detect_possible_bypasses(
        agents=[
            AgentActivity(
                address=AGENT.value,
                enrolled_at=enrolled,
                last_event_at=None,
                label="canary-bot",
            )
        ],
        now=NOW,
        idle_threshold_seconds=15 * 60,
    )
    assert len(signals) == 1
    assert signals[0].kind == "possible_bypass"
    assert signals[0].address == AGENT.value
    assert signals[0].last_event_at is None
    assert signals[0].idle_seconds >= 15 * 60
    assert signals[0].zero_observed_calls is True
    assert signals[0].pageable is True
    assert signals[0].severity == "page"
    assert signals[0].sla_seconds == 15 * 60
    assert signals[0].agent_label == "canary-bot"
    assert "page on-call" in signals[0].recommended_action
    assert "NetworkPolicy" in signals[0].recommended_action
    payload = signals[0].as_dict()
    assert payload["pageable"] is True
    assert payload["zero_observed_calls"] is True


def test_possible_bypass_does_not_fire_when_recent_event_exists():
    enrolled = Timestamp(NOW.value - timedelta(hours=2))
    recent = Timestamp(NOW.value - timedelta(minutes=5))
    signals = detect_possible_bypasses(
        agents=[
            AgentActivity(
                address=AGENT.value, enrolled_at=enrolled, last_event_at=recent
            )
        ],
        now=NOW,
        idle_threshold_seconds=15 * 60,
    )
    assert signals == ()


def test_possible_bypass_does_not_fire_for_fresh_enrolment():
    enrolled = Timestamp(NOW.value - timedelta(minutes=5))
    signals = detect_possible_bypasses(
        agents=[
            AgentActivity(address=AGENT.value, enrolled_at=enrolled, last_event_at=None)
        ],
        now=NOW,
        idle_threshold_seconds=15 * 60,
    )
    assert signals == ()


def test_sql_registry_silence_detection_round_trip(tmp_path):
    pool = build_engine(
        EngineConfig(
            dialect=Dialect.SQLITE,
            dsn=str(tmp_path / "bypass.db"),
            pool_min=1,
            pool_max=4,
        )
    )
    try:
        assert migrate(pool) == CURRENT_VERSION
        registry = SqlAgentRegistry(pool=pool)
        enrolled_at = Timestamp(NOW.value - timedelta(minutes=40))
        registry.enrol(TENANT, address=AGENT, label="canary", at=enrolled_at)
        activity = registry.list_activity(TENANT)
        assert len(activity) == 1
        assert activity[0].last_event_at is None
        assert activity[0].label == "canary"
        silent = detect_possible_bypasses(
            agents=activity, now=NOW, idle_threshold_seconds=15 * 60
        )
        assert silent and silent[0].kind == "possible_bypass"
        assert silent[0].pageable is True
        assert silent[0].agent_label == "canary"

        registry.record_event(TENANT, address=AGENT, at=NOW)
        after = detect_possible_bypasses(
            agents=registry.list_activity(TENANT),
            now=NOW,
            idle_threshold_seconds=15 * 60,
        )
        assert after == ()
    finally:
        pool.close()


def test_bypass_idle_threshold_must_be_positive():
    with pytest.raises(ValueError):
        detect_possible_bypasses(agents=[], now=NOW, idle_threshold_seconds=0)


def test_agent_egress_deployment_contract_manifest_fail_closed():
    """Reference NetworkPolicy exists and denies egress except to Sentinel."""
    path = ROOT / "deploy" / "agent-egress" / "networkpolicy.yaml"
    assert path.is_file(), "deploy/agent-egress/networkpolicy.yaml missing"
    text = path.read_text(encoding="utf-8")
    assert "sentinel-agent-default-deny" in text
    assert "policyTypes" in text
    assert "Egress" in text
    assert "sentinel.io/role: agent" in text
    assert 'sentinel.io/enrolled: "true"' in text
    assert "sentinel.io/deployment-contract: protect-egress-v1" in text
    # Fail closed: allowlist requires enrolled; only DNS + Sentinel
    assert "kube-dns" in text
    assert "app: sentinel" in text
    assert "sentinel-agent-egress-to-sentinel-only" in text


def test_agent_egress_enrolled_label_contract_exists():
    path = ROOT / "deploy" / "agent-egress" / "networkpolicy-enrolled.yaml"
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert 'sentinel.io/enrolled: "true"' in text
    assert "sentinel.io/deployment-contract: protect-egress-v1" in text


def test_admission_policy_manifest_fail_closed():
    path = (
        ROOT
        / "deploy"
        / "agent-egress"
        / "admission"
        / "validating-admission-policy.yaml"
    )
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert "ValidatingAdmissionPolicy" in text
    assert "failurePolicy: Fail" in text
    assert "sentinel.io/enrolled" in text
    assert "sentinel.io/tool-path" in text
    assert "validationActions: [Deny]" in text
    assert "sentinel.io/deployment-contract: protect-egress-v1" in text








def _load_fail_closed_proxy():
    import importlib.util
    import sys

    proxy_path = (
        ROOT / "deploy" / "agent-egress" / "egress-proxy" / "fail_closed_proxy.py"
    )
    spec = importlib.util.spec_from_file_location("fail_closed_proxy", proxy_path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_fail_closed_egress_proxy_denies_when_sentinel_down():
    mod = _load_fail_closed_proxy()
    gate = mod.FailClosedEgressGate(
        mod.EgressProxyConfig(sentinel_base_url="http://sentinel.example:8000"),
        probe=lambda _url, _timeout: False,
    )
    with pytest.raises(mod.ProxyDenied, match="fail-closed"):
        gate.allow_request(method="CONNECT", target_host="tools.example", target_port=443)


def test_fail_closed_egress_proxy_allowlists_sentinel_only():
    mod = _load_fail_closed_proxy()
    gate = mod.FailClosedEgressGate(
        mod.EgressProxyConfig(sentinel_base_url="http://sentinel.example:8000"),
        probe=lambda _url, _timeout: True,
    )
    gate.allow_request(method="GET", target_host="sentinel.example", target_port=8000)
    with pytest.raises(mod.ProxyDenied, match="allowlist"):
        gate.allow_request(method="CONNECT", target_host="evil.example", target_port=443)


def test_sdk_interceptor_refuses_empty_agent_id():
    from sentinel.application.protect_controls import ProtectControls
    from sentinel.application.protect_gate import ProtectGate
    from sentinel.application.tool_proxy import (
        InlineToolProxy,
        ProtectedToolRunner,
        RegisteredSideEffect,
    )
    from sentinel.domain.primitives import TrustLevel
    from sentinel.infrastructure.detection import DeterministicPolicy
    from sentinel.sdk.interceptor import InterceptedToolClient, InterceptorMisuse

    gate = ProtectGate(policy=DeterministicPolicy.default(), enforce=False)
    runner = ProtectedToolRunner(gate=gate, controls=ProtectControls())
    proxy = InlineToolProxy(
        tool_runner=runner,
        effects={"noop": RegisteredSideEffect("noop", lambda a: True)},
    )
    client = InterceptedToolClient(local=proxy, require_enrolled=True)
    with pytest.raises(InterceptorMisuse):
        client.execute(agent_id="", tool="noop", trust=TrustLevel.UNSIGNED)


def test_sdk_interceptor_refuses_unenrolled_agent():
    from sentinel.application.protect_controls import ProtectControls
    from sentinel.application.protect_gate import ProtectGate
    from sentinel.application.tool_proxy import (
        InlineToolProxy,
        ProtectedToolRunner,
        RegisteredSideEffect,
    )
    from sentinel.domain.primitives import TrustLevel
    from sentinel.infrastructure.detection import DeterministicPolicy
    from sentinel.sdk.interceptor import InterceptedToolClient, InterceptorMisuse

    gate = ProtectGate(policy=DeterministicPolicy.default(), enforce=False)
    runner = ProtectedToolRunner(gate=gate, controls=ProtectControls())
    proxy = InlineToolProxy(
        tool_runner=runner,
        effects={"noop": RegisteredSideEffect("noop", lambda a: True)},
    )
    client = InterceptedToolClient(
        local=proxy, require_enrolled=True, is_enrolled=lambda _aid: False
    )
    with pytest.raises(InterceptorMisuse):
        client.execute(agent_id="0xabc", tool="noop", trust=TrustLevel.UNSIGNED)
