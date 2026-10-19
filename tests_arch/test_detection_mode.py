"""Detection degradation must be loud, and must be visible from outside.

THE FAILURE THIS FILE EXISTS FOR
--------------------------------
`_detection_policy_for` used to end with:

    if clf is None:
        return base

A missing or unreadable `evaluation/artifacts/soft_prompt_model.pkl` therefore
produced a running, `{"ready": true}` deployment whose measured independent
English recall was ~0.067 instead of ~0.855 -- and produced it in total silence.
There was no log line, no metric and no field on any endpoint that differed
between the two. The only way to find out was to notice, later, the incidents
that were never raised.

That is the worst failure shape available to a detection product: it does not
look like an outage, so nobody is paged, and the evidence of it is the absence
of evidence. So these tests assert the two halves of the fix together --

  * the composition root logs CRITICAL when it degrades, and
  * `/health/ready` reports which detector is actually running --

because either one alone still permits a silent degradation. A log nobody
scrapes is not an alert, and a field nobody writes is not an observation.

The probe assertions go through a real request rather than reading
`container.detection_mode`, since the container field being right proves nothing
about whether the route was wired to it.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sentinel.composition.container import (
    DEFAULT_SOFT_PROMPT_ARTIFACT,
    build_container,
)
from sentinel.composition.settings import Settings
from sentinel.infrastructure.detection import DeterministicPolicy
from sentinel.infrastructure.soft_detection import DetectionMode, SoftAugmentedPolicy
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
        # Opt-in. Off by default, because readiness is unauthenticated and
        # "the ML detector is down" is reconnaissance -- see
        # `test_readiness_default_body_stays_boolean_only` below, and
        # `tests_arch/test_security_edge.py::test_readiness_leaks_no_internal_detail`.
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


# ── The artifact is absent ───────────────────────────────────────────────────


def test_missing_artifact_reports_rules_only_degraded_on_health_ready(tmp_path):
    """The exact silent-fallback case, observed from outside the process."""
    logger = RecordingLogger()
    container = _container(
        tmp_path,
        logger,
        SENTINEL_SOFT_PROMPT_MODEL=str(tmp_path / "does-not-exist.pkl"),
    )
    try:
        body = _ready_body(container)
    finally:
        container.close()

    assert body["detection_mode"] == DetectionMode.RULES_ONLY_DEGRADED.value
    # Degraded detection is not unreadiness: refusing to serve would convert a
    # detection regression into an outage. The pod stays up and stays honest.
    assert body["ready"] is True


def test_missing_artifact_logs_at_critical_not_warning(tmp_path):
    """A `warnings.warn` is not an alert. This has to reach the log pipeline."""
    logger = RecordingLogger()
    container = _container(
        tmp_path,
        logger,
        SENTINEL_SOFT_PROMPT_MODEL=str(tmp_path / "does-not-exist.pkl"),
    )
    try:
        critical = [
            (event, fields)
            for level, event, fields in logger.records
            if level == "critical"
        ]
    finally:
        container.close()

    assert critical, (
        "degrading to rules-only produced no CRITICAL record; "
        f"levels seen: {sorted({lvl for lvl, _, _ in logger.records})}"
    )
    event, fields = critical[0]
    assert event == "detection_degraded_soft_prompt_missing"
    assert fields["detection_mode"] == DetectionMode.RULES_ONLY_DEGRADED.value
    # The operator reading this at 3am must not have to find the benchmark to
    # learn what the fallback costs, nor guess what to do about it.
    assert fields["independent_english_recall"] < fields["expected_recall_when_loaded"]
    assert fields["remedy"]


def test_missing_artifact_actually_falls_back_to_the_rules_policy(tmp_path):
    """The reported mode must describe the policy that is really installed."""
    logger = RecordingLogger()
    container = _container(
        tmp_path,
        logger,
        SENTINEL_SOFT_PROMPT_MODEL=str(tmp_path / "does-not-exist.pkl"),
    )
    try:
        assert container.detection_mode is DetectionMode.RULES_ONLY_DEGRADED
        assert isinstance(container.policy, DeterministicPolicy)
    finally:
        container.close()


# ── The artifact is present but cannot be read ───────────────────────────────


def test_unreadable_artifact_degrades_loudly_instead_of_killing_the_process(tmp_path):
    """Version skew and a missing scikit-learn both land here.

    This path used to raise straight out of `build_container`, so a runtime that
    could not unpickle the artifact -- an image built from `requirements.txt`
    before scikit-learn was declared in it, or a pickle written by a different
    scikit-learn minor -- did not degrade, it failed to boot. Neither extreme is
    right: the process must come up, and it must come up saying what it lost.
    """
    corrupt = tmp_path / "corrupt.pkl"
    corrupt.write_bytes(b"not a pickle at all")
    logger = RecordingLogger()
    container = _container(tmp_path, logger, SENTINEL_SOFT_PROMPT_MODEL=str(corrupt))
    try:
        body = _ready_body(container)
        assert container.detection_mode is DetectionMode.RULES_ONLY_DEGRADED
    finally:
        container.close()

    assert body["detection_mode"] == DetectionMode.RULES_ONLY_DEGRADED.value
    critical = [
        fields for level, event, fields in logger.records
        if level == "critical" and event == "detection_degraded_soft_prompt_unloadable"
    ]
    assert critical, "an unreadable artifact degraded without a CRITICAL record"
    # The cause is named. "Detection is degraded" without `error_type` sends the
    # operator to the wrong runbook -- a missing file and a missing dependency
    # have different fixes.
    assert critical[0]["error_type"]
    assert critical[0]["artifact_path"] == str(corrupt)


# ── The artifact is present ──────────────────────────────────────────────────


@pytest.mark.skipif(
    not DEFAULT_SOFT_PROMPT_ARTIFACT.exists(),
    reason="soft prompt artifact not present in this tree",
)
def test_loaded_artifact_reports_soft_and_rules_on_health_ready(tmp_path):
    """The positive case. Without it, a permanently-degraded build passes."""
    logger = RecordingLogger()
    container = _container(tmp_path, logger)
    try:
        body = _ready_body(container)
        assert container.detection_mode is DetectionMode.SOFT_AND_RULES
        assert isinstance(container.policy, SoftAugmentedPolicy)
    finally:
        container.close()

    assert body["detection_mode"] == DetectionMode.SOFT_AND_RULES.value
    assert body["ready"] is True
    assert not [level for level, _, _ in logger.records if level == "critical"]


# ── The operator turned it off on purpose ────────────────────────────────────


def test_explicitly_disabled_is_reported_as_configured_not_degraded(tmp_path):
    """A deliberate choice must not fire the alert that means "something broke".

    Both modes run rules-only, so both have the same recall -- but an alert that
    fires on a supported configuration is an alert operators learn to silence,
    and a silenced alert is how the degraded case gets missed.
    """
    logger = RecordingLogger()
    container = _container(tmp_path, logger, SENTINEL_SOFT_PROMPT_DETECT="false")
    try:
        body = _ready_body(container)
    finally:
        container.close()

    assert body["detection_mode"] == DetectionMode.RULES_ONLY_CONFIGURED.value
    assert not [level for level, _, _ in logger.records if level == "critical"]
    assert "detection_soft_prompt_disabled" in logger.events("warning")


# ── The disclosure boundary ──────────────────────────────────────────────────


def test_readiness_default_body_stays_boolean_only(tmp_path):
    """Exposing the mode must be a decision, never a default.

    The whole point of naming the detector is that it is actionable, which is
    also what makes it useful to an attacker: an unauthenticated caller polling
    `/health/ready` until it reads `rules-only-degraded` has found the window in
    which the ML detector is not looking. So the default body is unchanged, and
    the always-on alerting surfaces are the CRITICAL log, the authenticated
    `/health/diagnostics`, and the authenticated metrics scrape.
    """
    logger = RecordingLogger()
    container = _container(
        tmp_path,
        logger,
        SENTINEL_READY_EXPOSE_DETECTION_MODE="false",
        SENTINEL_SOFT_PROMPT_MODEL=str(tmp_path / "does-not-exist.pkl"),
    )
    try:
        body = _ready_body(container)
        # Degraded, and still not saying so to an anonymous caller.
        assert container.detection_mode is DetectionMode.RULES_ONLY_DEGRADED
    finally:
        container.close()

    assert set(body) == {"ready"}


def test_diagnostics_reports_the_mode_regardless_of_the_readiness_flag(tmp_path):
    """`docs/OBSERVABILITY.md` lists this surface; pin it so the doc stays true."""
    logger = RecordingLogger()
    container = _container(
        tmp_path,
        logger,
        SENTINEL_READY_EXPOSE_DETECTION_MODE="false",
        SENTINEL_SOFT_PROMPT_MODEL=str(tmp_path / "does-not-exist.pkl"),
    )
    try:
        client = TestClient(create_app(container), raise_server_exceptions=False)
        res = client.get(
            "/health/diagnostics", headers={"Authorization": f"Bearer {KEY}"}
        )
    finally:
        container.close()

    assert res.status_code == 200, res.text
    checks = res.json()["checks"]
    assert checks["detection_mode"] == DetectionMode.RULES_ONLY_DEGRADED.value
    assert checks["detector_version"]


def test_degradation_is_always_visible_on_the_authenticated_surfaces(tmp_path):
    """Whatever readiness is configured to say, metrics must carry the truth.

    This is the surface an alert rule should bind to, so it is not optional and
    not configurable: `sentinel_detection_degraded 1.0` means detection fell back
    without anyone asking it to.
    """
    logger = RecordingLogger()
    container = _container(
        tmp_path,
        logger,
        SENTINEL_READY_EXPOSE_DETECTION_MODE="false",
        SENTINEL_SOFT_PROMPT_MODEL=str(tmp_path / "does-not-exist.pkl"),
    )
    try:
        rendered = container.metrics.render_prometheus()
    finally:
        container.close()

    assert "sentinel_detection_degraded 1.0" in rendered
    assert 'sentinel_detection_mode{mode="rules-only-degraded"} 1.0' in rendered


def test_healthy_deployment_does_not_report_degraded_metric(tmp_path):
    """An alert that is always firing is an alert nobody reads."""
    logger = RecordingLogger()
    container = _container(tmp_path, logger, SENTINEL_SOFT_PROMPT_DETECT="false")
    try:
        rendered = container.metrics.render_prometheus()
    finally:
        container.close()

    assert "sentinel_detection_degraded 0.0" in rendered
    assert 'sentinel_detection_mode{mode="rules-only-configured"} 1.0' in rendered


# ── The duplication guard ────────────────────────────────────────────────────


def test_default_artifact_path_matches_loader():
    """`container` restates the loader's default path; hold the two together.

    It is restated rather than imported because it has to appear in a log line
    whose cause may be that `evaluation` is not importable at all.
    """
    from evaluation.soft_prompt import DEFAULT_ARTIFACT

    assert DEFAULT_SOFT_PROMPT_ARTIFACT == DEFAULT_ARTIFACT


def test_every_detection_mode_is_reachable_from_composition():
    """No mode may be decorative: an unreachable state is a lie in the enum."""
    assert {mode.value for mode in DetectionMode} == {
        "soft+rules",
        "rules-only-degraded",
        "rules-only-configured",
    }
