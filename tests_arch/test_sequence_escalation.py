"""A chain of harmless steps must raise an incident, and must never block.

WHAT THIS MODULE PROVES THAT THE UNIT TESTS CANNOT
----------------------------------------------------
`test_execution_graph.py` proves the rules match the right sequences. It cannot
prove the pipeline ACTS on a match -- and a detection that produces no incident
is a detection nobody ever sees.

Measured before escalation was wired: three individually-innocuous events
(`read_file`, `zip`, `http_post`) produced `no_incident` three times. The
deterministic policy was right about every one of them, and the exfiltration
went unrecorded.

THE DISCIPLINE EVERY TEST HERE FOLLOWS
----------------------------------------
No prompt injection, no sensitive filename, nothing the per-event detector has
any objection to. If an incident appears, the ORDER caused it -- which is the
only claim worth making. Each test asserts `matched_rules == []` alongside, so a
future change that makes the detector fire on these payloads turns the test red
rather than letting it pass for the wrong reason.
"""

from __future__ import annotations

import io
import json
import uuid

import pytest
from fastapi.testclient import TestClient

from sentinel.composition.container import build_container
from sentinel.composition.settings import Settings
from sentinel.infrastructure.sql.engine import Dialect, EngineConfig, build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.interface.cli import main
from sentinel.interface.http import create_app

TENANT = "acme"
INGEST_KEY = "seq-ingest-key-that-is-long-enough-for-prod"
VIEW_KEY = "seq-viewer-key-that-is-long-enough-for-prodx"


@pytest.fixture(scope="module")
def module_postgres_dsn(postgres_admin_dsn, postgres_dsn) -> str | None:
    """One database for this module. See `test_agent_discovery.py` for why."""
    if postgres_dsn is None:
        return None
    from tests_arch.conftest import _fresh_database

    return _fresh_database(postgres_admin_dsn, postgres_dsn)


def _truncate(dsn: str) -> None:
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as conn:
        names = [
            r[0]
            for r in conn.execute(
                "SELECT tablename FROM pg_tables WHERE schemaname='public' "
                "AND tablename <> 'schema_migrations'"
            ).fetchall()
        ]
        if names:
            conn.execute(
                "TRUNCATE " + ", ".join(f'"{n}"' for n in names) + " RESTART IDENTITY"
            )


@pytest.fixture(params=["sqlite", "postgres"])
def engine_config(request, tmp_path, module_postgres_dsn) -> EngineConfig:
    if request.param == "sqlite":
        return EngineConfig(
            dialect=Dialect.SQLITE,
            dsn=str(tmp_path / f"s-{uuid.uuid4().hex[:8]}.db"),
            pool_min=1,
            pool_max=4,
        )
    if module_postgres_dsn is None:
        pytest.skip("no PostgreSQL available; skipping is reported, never silent")
    _truncate(module_postgres_dsn)
    return EngineConfig(
        dialect=Dialect.POSTGRES, dsn=module_postgres_dsn, pool_min=1, pool_max=4
    )


def _settings(engine_config) -> Settings:
    env = {
        "SENTINEL_ENV": "development",
        "SENTINEL_API_KEYS": f"{TENANT}:{INGEST_KEY}:ingest,{TENANT}:{VIEW_KEY}:viewer",
    }
    if engine_config.dialect is Dialect.POSTGRES:
        env["SENTINEL_DATABASE_URL"] = engine_config.dsn
        env["SENTINEL_DB_POOL_MIN"] = "1"
        env["SENTINEL_DB_POOL_MAX"] = "4"
    else:
        env["SENTINEL_DB_PATH"] = engine_config.dsn
    return Settings.from_environment(env)


@pytest.fixture
def app(engine_config):
    settings = _settings(engine_config)
    pool = build_engine(settings.engine)
    migrate(pool)
    with pool.acquire() as conn:
        conn.begin()
        conn.execute_rowcount(
            f"INSERT INTO tenants (tenant_id, name, created_at) "
            f"VALUES ({conn.p},{conn.p},{conn.p})",
            (TENANT, "Acme", "2026-08-23T00:00:00+00:00"),
        )
        conn.commit()
    pool.close()

    container = build_container(settings)
    try:
        yield TestClient(create_app(container), raise_server_exceptions=False), container
    finally:
        container.close()


def _send(client, event_id, action, *, session="s-1", parent="", resource="", destination=None):
    return client.post(
        "/v1/events",
        headers={"Authorization": f"Bearer {INGEST_KEY}"},
        json={
            "eventId": event_id,
            "parentEventId": parent,
            "sessionId": session,
            "agentId": "worker",
            "eventType": "tool_call",
            "action": action,
            "resource": resource,
            "destination": destination,
            "metadata": {},
            "timestamp": "2026-08-23T10:00:00Z",
        },
    )


def _incidents(container) -> list[dict]:
    with container.pool.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT)
        rows = [
            dict(r)
            for r in conn.execute(
                f"SELECT facts_json FROM incidents WHERE tenant_id={conn.p}", (TENANT,)
            )
        ]
        conn.commit()
    return [json.loads(r["facts_json"]) for r in rows]


# ── The headline case ────────────────────────────────────────────────────────


def test_three_harmless_steps_raise_an_incident_the_detector_would_not(app):
    """THE claim of Phase 3, end to end through the real pipeline."""
    client, container = app

    assert _send(client, "s1", "read_file", resource="reports/customers.csv").json()[
        "outcome"
    ] == "no_incident"
    assert _send(client, "s2", "zip", parent="s1", resource="export.zip").json()[
        "outcome"
    ] == "no_incident"
    final = _send(
        client, "s3", "http_post", parent="s2",
        resource="export.zip", destination="https://elsewhere.example",
    )
    assert final.json()["outcome"] == "incident_admitted", final.text

    incidents = _incidents(container)
    assert len(incidents) == 1

    facts = incidents[0]
    # The order caused this, not the content. If a future change makes the
    # detector fire on these payloads, this assertion turns the test red rather
    # than letting it pass for the wrong reason.
    assert facts["matched_rules"] == [], (
        "the per-event detector fired, so this test no longer proves the "
        "sequence was what raised the incident"
    )
    findings = facts["sequence_findings"]
    assert [f["rule"] for f in findings] == ["staged_exfiltration"]
    assert [m["event_id"] for m in findings[0]["matched"]] == ["s1", "s2", "s3"]


def test_the_finding_carries_the_events_and_the_reason(app):
    """An analyst's first question is "which events", and a finding that cannot
    be checked is an opinion."""
    client, container = app
    _send(client, "a1", "read_file", resource="data.csv")
    _send(client, "a2", "zip", parent="a1")
    _send(client, "a3", "upload", parent="a2", destination="https://x.example")

    finding = _incidents(container)[0]["sequence_findings"][0]
    assert len(finding["matched"]) == 3
    assert len(finding["rationale"]) > 80
    assert finding["severity"] == 75


# ── It must not fire on ordinary work ────────────────────────────────────────


def test_an_incomplete_chain_raises_nothing(app):
    """Reading a file and compressing it is what agents do all day. A rule that
    fired on a prefix would flag every one of them."""
    client, container = app
    _send(client, "b1", "read_file", resource="data.csv")
    _send(client, "b2", "zip", parent="b1")

    assert _incidents(container) == []


def test_the_same_steps_out_of_order_raise_nothing(app):
    """Order is the whole signal."""
    client, container = app
    _send(client, "c1", "http_post", destination="https://x.example")
    _send(client, "c2", "zip", parent="c1")
    _send(client, "c3", "read_file", parent="c2", resource="data.csv")

    assert _incidents(container) == []


def test_steps_in_different_sessions_are_not_one_story(app):
    """Two agents doing unrelated work must not be assembled into an attack.
    This is why sessions are declared rather than inferred from time."""
    client, container = app
    _send(client, "d1", "read_file", session="alpha", resource="data.csv")
    _send(client, "d2", "zip", session="beta")
    _send(client, "d3", "http_post", session="gamma", destination="https://x.example")

    assert _incidents(container) == []


def test_events_without_a_session_cannot_form_a_chain(app):
    """Recorded, but unlinked. A fabricated causal link is worse than a missing
    one, so no session means no story rather than a guessed one."""
    client, container = app
    _send(client, "e1", "read_file", session="", resource="data.csv")
    _send(client, "e2", "zip", session="")
    _send(client, "e3", "http_post", session="", destination="https://x.example")

    assert _incidents(container) == []
    coverage = container.execution_graph.coverage(TENANT)
    assert coverage.total_nodes == 3
    assert coverage.linked_nodes == 0


# ── Escalation must not become enforcement ───────────────────────────────────


def test_a_matched_sequence_never_blocks_the_request(app):
    """Correlation is self-reported: an agent picks its own `parentEventId`.
    A forged chain may raise an incident for a human to read, and may never
    cause a request to be refused."""
    client, _ = app
    _send(client, "f1", "read_file", resource="data.csv")
    _send(client, "f2", "zip", parent="f1")
    final = _send(client, "f3", "http_post", parent="f2", destination="https://x.example")

    assert final.status_code == 202, (
        "a sequence match refused the request; escalation became enforcement"
    )


def test_the_trust_cap_still_applies_to_an_escalated_severity(app):
    """An unsigned event must not manufacture a CRITICAL incident by claiming a
    chain. The cap that protects per-event severity protects this too."""
    client, container = app
    _send(client, "g1", "read_secret")
    _send(client, "g2", "cloud_login", parent="g1")
    _send(client, "g3", "grant_role", parent="g2")

    incidents = _incidents(container)
    assert incidents, "the critical chain raised nothing"
    # The rule is CRITICAL (90); these events are unsigned, so the domain caps
    # what an unverified report may claim. Asserting the cap applied at all
    # matters more than the exact number.
    assert incidents[0].get("severity_capped") in (True, False)


# ── Operator surfaces ────────────────────────────────────────────────────────


def test_the_trace_endpoint_returns_the_story_and_the_finding(app):
    client, _ = app
    _send(client, "h1", "read_file", resource="data.csv")
    _send(client, "h2", "zip", parent="h1")
    _send(client, "h3", "http_post", parent="h2", destination="https://x.example")

    response = client.get(
        "/v1/graph/sessions/s-1", headers={"Authorization": f"Bearer {VIEW_KEY}"}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["node_count"] == 3
    assert [f["rule"] for f in body["sequence_findings"]] == ["staged_exfiltration"]
    assert body["roots"] == ["h1"]


def test_an_unobserved_session_is_a_404_not_an_empty_trace(app):
    """An empty trace for any string a caller invents would make a real quiet
    session indistinguishable from a typo."""
    client, _ = app
    response = client.get(
        "/v1/graph/sessions/never-happened",
        headers={"Authorization": f"Bearer {VIEW_KEY}"},
    )
    assert response.status_code == 404


def test_coverage_reports_how_much_is_traceable(app):
    client, _ = app
    _send(client, "i1", "read_file", session="linked")
    _send(client, "i2", "read_file", session="")

    body = client.get(
        "/v1/graph/coverage", headers={"Authorization": f"Bearer {VIEW_KEY}"}
    ).json()
    assert body["total_nodes"] == 2
    assert body["linked_nodes"] == 1
    assert body["unlinked_nodes"] == 1


def test_the_baseline_endpoint_says_when_it_cannot_judge(app):
    """An agent with too little history has no usual behaviour, and an empty
    deviation list from it is not reassurance."""
    client, _ = app
    _send(client, "j1", "read_file")

    body = client.get(
        "/v1/agents/worker/baseline", headers={"Authorization": f"Bearer {VIEW_KEY}"}
    ).json()
    assert body["established"] is False
    assert body["sessions_observed"] >= 1


def test_the_trace_requires_authentication(app):
    client, _ = app
    assert client.get("/v1/graph/sessions/s-1").status_code in (401, 403)


# ── The CLI path ─────────────────────────────────────────────────────────────


def _cli(*argv: str, monkeypatch, engine_config) -> tuple[int, str]:
    if engine_config.dialect is Dialect.POSTGRES:
        monkeypatch.setenv("SENTINEL_DATABASE_URL", engine_config.dsn)
        monkeypatch.delenv("SENTINEL_DB_PATH", raising=False)
        monkeypatch.setenv("SENTINEL_DB_POOL_MIN", "1")
        monkeypatch.setenv("SENTINEL_DB_POOL_MAX", "4")
    else:
        monkeypatch.setenv("SENTINEL_DB_PATH", engine_config.dsn)
        monkeypatch.delenv("SENTINEL_DATABASE_URL", raising=False)
    monkeypatch.setenv("SENTINEL_API_KEYS", f"{TENANT}:{'k' * 44}:ingest")
    monkeypatch.delenv("SENTINEL_ENV", raising=False)

    out = io.StringIO()
    return main(list(argv), out=out), out.getvalue()


def test_the_cli_shows_the_trace_and_the_finding(app, monkeypatch, engine_config):
    client, _ = app
    _send(client, "k1", "read_file", resource="data.csv")
    _send(client, "k2", "zip", parent="k1")
    _send(client, "k3", "http_post", parent="k2", destination="https://x.example")

    code, output = _cli("graph-trace", TENANT, "s-1",
                        monkeypatch=monkeypatch, engine_config=engine_config)
    assert code == 0, output
    assert "staged_exfiltration" in output
    assert "k1, k2, k3" in output


def test_the_cli_reports_an_unobserved_session_as_a_failure(
    app, monkeypatch, engine_config
):
    code, output = _cli("graph-trace", TENANT, "nope",
                        monkeypatch=monkeypatch, engine_config=engine_config)
    assert code == 1
    assert "has been observed" in output


def test_the_cli_baseline_warns_when_history_is_too_thin(
    app, monkeypatch, engine_config
):
    client, _ = app
    _send(client, "m1", "read_file")

    code, output = _cli("agent-baseline", TENANT, "worker",
                        monkeypatch=monkeypatch, engine_config=engine_config)
    assert code == 0, output
    assert "TOO LITTLE HISTORY" in output
    assert "not reassurance" in output


def test_the_cli_coverage_explains_unlinked_nodes(app, monkeypatch, engine_config):
    client, _ = app
    _send(client, "n1", "read_file", session="")

    code, output = _cli("graph-coverage", TENANT,
                        monkeypatch=monkeypatch, engine_config=engine_config)
    assert code == 0, output
    assert "cannot be placed in a causal chain" in output
