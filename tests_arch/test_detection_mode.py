"""The reported detector and readiness disclosure match the running rules policy."""
from fastapi.testclient import TestClient

from sentinel.composition.container import build_container
from sentinel.composition.settings import Settings
from sentinel.domain.primitives import TrustLevel
from sentinel.infrastructure.detection import DeterministicPolicy
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.interface.http import create_app
from tests_arch.doubles import RecordingLogger

KEY = "k" * 40


def _settings(tmp_path, **overrides) -> Settings:
    env = {
        "SENTINEL_ENV": "development",
        "SENTINEL_API_KEYS": f"acme:{KEY}:admin",
        "SENTINEL_DB_PATH": str(tmp_path / "detection-mode.db"),
        # Readiness discloses the detector only with explicit opt-in.
        "SENTINEL_READY_EXPOSE_DETECTION_MODE": "true",
    }
    env.update(overrides)
    return Settings.from_environment(env)


def _container(tmp_path, logger: RecordingLogger, **overrides):
    settings = _settings(tmp_path, **overrides)
    pool = build_engine(settings.engine)
    migrate(pool)
    pool.close()
    return build_container(settings, logger=logger)


def _ready_body(container) -> dict:
    client = TestClient(create_app(container), raise_server_exceptions=False)
    return client.get("/health/ready").json()


def test_default_policy_and_readiness_are_deterministic(tmp_path):
    logger = RecordingLogger()
    container = _container(tmp_path, logger)
    try:
        body = _ready_body(container)
        assert isinstance(container.policy, DeterministicPolicy)
        assert body["detection_mode"] == "rules-only-configured"
        assert body["ready"] is True
        assert not [level for level, _, _ in logger.records if level == "critical"]
    finally:
        container.close()


def test_composed_policy_preserves_rules_without_statistical_escalation(tmp_path):
    container = _container(tmp_path, RecordingLogger())
    try:
        benign = {"eventType": "prompt", "action": "http_get", "metadata": {"prompt": "http_get"}}
        dangerous = {"eventType": "file_access", "action": "read_file", "resource": "/root/.aws/credentials"}
        rules = DeterministicPolicy.default()
        for event, fired in ((benign, False), (dangerous, True)):
            actual = container.policy.evaluate(payload=event, trust=TrustLevel.UNSIGNED)
            assert actual.fired is fired
            assert actual == rules.evaluate(payload=event, trust=TrustLevel.UNSIGNED)
    finally:
        container.close()


def test_readiness_default_body_stays_boolean_only(tmp_path):
    container = _container(tmp_path, RecordingLogger(), SENTINEL_READY_EXPOSE_DETECTION_MODE="false")
    try:
        assert set(_ready_body(container)) == {"ready"}
    finally:
        container.close()


def test_diagnostics_reports_the_mode_regardless_of_the_readiness_flag(tmp_path):
    container = _container(tmp_path, RecordingLogger(), SENTINEL_READY_EXPOSE_DETECTION_MODE="false")
    try:
        client = TestClient(create_app(container), raise_server_exceptions=False)
        res = client.get("/health/diagnostics", headers={"Authorization": f"Bearer {KEY}"})
        assert res.status_code == 200, res.text
        checks = res.json()["checks"]
        assert checks["detection_mode"] == "rules-only-configured"
        assert checks["detector_version"]
    finally:
        container.close()


def test_healthy_deployment_does_not_report_degraded_metric(tmp_path):
    container = _container(tmp_path, RecordingLogger())
    try:
        rendered = container.metrics.render_prometheus()
        assert "sentinel_detection_degraded 0.0" in rendered
        assert 'sentinel_detection_mode{mode="rules-only-configured"} 1.0' in rendered
    finally:
        container.close()
