"""The pilot's numbers are counted from records, with their sample sizes."""

from __future__ import annotations

import pytest

from sentinel.infrastructure.sql.workflow_metrics import percentile
from tests_arch.test_execution_contract import ANALYST, _evaluate, _execute, _h, _make


@pytest.fixture
def app(tmp_path, engine_config, monkeypatch):
    harness = _make(tmp_path, engine_config, monkeypatch, enforce=True)
    try:
        yield harness
    finally:
        harness.container.close()


def test_percentiles_are_nearest_rank_and_empty_is_none():
    assert percentile([], 0.95) is None
    assert percentile([5.0], 0.95) == 5.0
    assert percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 0.5) == 5
    assert percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 0.95) == 10


def test_the_summary_counts_what_happened(app):
    for index in range(3):                                   # three that simply proceed
        token = _evaluate(app, arguments={"value": f"v{index}"}).json()["authorization"]["token"]
        assert _execute(app, token, arguments={"value": f"v{index}"}).status_code == 200
    token = _evaluate(app).json()["authorization"]["token"]  # one substitution, refused
    assert _execute(app, token, arguments={"value": "other"}).status_code == 403

    pending = _evaluate(app, resource="/needs-approval").json()["authorization"]
    app.clock.advance(90)                                    # a human takes ninety seconds
    app.client.post(f"/v1/authorizations/{pending['authorization_id']}/decide",
                    json={"decision": "approve", "reason": "ok"}, headers=_h(ANALYST))
    assert _execute(app, pending["token"], resource="/needs-approval").status_code == 200
    rejected = _evaluate(app, resource="/needs-approval", arguments={"value": "no"}).json()["authorization"]
    app.client.post(f"/v1/authorizations/{rejected['authorization_id']}/decide",
                    json={"decision": "reject", "reason": "no"}, headers=_h(ANALYST))

    metrics = app.client.get("/v1/workflow/metrics?days=1", headers=_h(ANALYST))
    assert metrics.status_code == 200, metrics.text
    body = metrics.json()
    assert body["executions"]["succeeded"] == 4 and body["executions"]["refused"] == 1
    assert body["approvals"] == {**body["approvals"], "requested": 2, "approved": 1, "rejected": 1, "still_waiting": 0}
    assert body["approvals"]["latency_seconds"] == {"samples": 1, "p50": 90.0, "p95": 90.0, "max": 90.0}
    assert body["interruptions"]["needed_approval"] == 2 and body["interruptions"]["refused_at_execution"] == 1
    assert body["interruptions"]["per_100_attempts"] == 60.0
    assert body["adoption"]["agents_with_a_successful_execution"] == 1
    assert body["unknown_outcomes"]["open"] == 0
    assert any("overhead" in note for note in body["not_measured_here"])


def test_an_empty_window_reports_nothing_rather_than_zero_latency(app):
    body = app.client.get("/v1/workflow/metrics", headers=_h(ANALYST)).json()
    assert body["approvals"]["latency_seconds"] == {"samples": 0, "p50": None, "p95": None, "max": None}
    assert body["interruptions"]["per_100_attempts"] is None


def test_slo_verdicts_refuse_what_the_sample_cannot_support(app):
    """SLO verdicts must reflect the available live samples."""
    token = _evaluate(app).json()["authorization"]["token"]
    assert _execute(app, token).status_code == 200
    body = app.client.get("/v1/workflow/metrics?days=1", headers=_h(ANALYST)).json()
    assert "_samples" not in body
    verdicts = {v["name"]: v for v in body["slo"]}
    assert set(verdicts) == {"approval_latency_p95", "unknown_outcome_settled_p95"}
    assert all(v["state"] != "met" for v in verdicts.values()), "an SLO was declared met with no samples behind it"
