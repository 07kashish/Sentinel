"""Detections derived from the audit trail, driven by real refused requests.

Every fixture below produces its audit entries by making requests that are actually
refused, not by inserting rows. A detector tested against hand-written rows proves
that the detector parses its own fixtures; a detector tested against traffic proves
the shape it looks for is the shape the system produces.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sentinel.composition.container import build_container
from sentinel.composition.settings import Settings
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.infrastructure.threat_detection import (
    UNAUTHENTICATED_TENANT,
    Detection,
    Thresholds,
    ThreatDetector,
)
from sentinel.interface.http import _UNKNOWN_TENANT, create_app

VIEWER_KEY = "v" * 40
INGEST_KEY = "i" * 40


@pytest.fixture
def app(tmp_path):
    settings = Settings.from_environment(
        {
            "SENTINEL_API_KEYS": f"acme:{VIEWER_KEY}:viewer,acme:{INGEST_KEY}:ingest",
            "SENTINEL_DB_PATH": str(tmp_path / "detect.db"),
            # Limits raised out of the way: these tests are about detection, and a
            # 429 would stop the refusals that detection is computed from.
            "SENTINEL_AUTH_FAILURE_LIMIT": "10000",
            "SENTINEL_CREDENTIAL_LIMIT": "10000",
            "SENTINEL_ADDRESS_LIMIT": "10000",
        }
    )
    pool = build_engine(settings.engine)
    migrate(pool)
    pool.close()
    container = build_container(settings)
    try:
        yield TestClient(create_app(container), raise_server_exceptions=False), container
    finally:
        container.close()


def _detector(container, **overrides) -> ThreatDetector:
    return ThreatDetector(
        pool=container.pool,
        clock=container.clock,
        thresholds=Thresholds(**overrides) if overrides else None,
    )


# ── The constant that must not drift ─────────────────────────────────────────


def test_the_unauthenticated_tenant_constant_matches_the_http_layer():
    """Two constants that must be equal are two constants that can drift, and the
    failure would be silent: the detector would scan an empty chain forever."""
    assert UNAUTHENTICATED_TENANT == _UNKNOWN_TENANT


# ── Credential stuffing ──────────────────────────────────────────────────────


def test_repeated_unrecognised_credentials_are_detected(app):
    """Rate limiting slows this. Detection is what reports that it happened."""
    client, container = app
    for _ in range(30):
        client.get("/v1/incidents", headers={"Authorization": "Bearer " + "z" * 40})

    findings = _detector(container, stuffing_attempts=25).scan(tenants=["acme"])
    stuffing = [f for f in findings if f.kind == "credential_stuffing"]
    assert stuffing, f"stuffing was not detected: {findings}"
    assert stuffing[0].tenant_id == UNAUTHENTICATED_TENANT
    assert stuffing[0].count >= 25
    assert stuffing[0].sample_seqs, "a finding with no evidence is an assertion"


def test_stuffing_is_found_even_when_no_real_tenant_is_scanned(app):
    """A guessed credential has no tenant, so the unauthenticated chain must
    always be scanned. Passing an empty tenant list is the strongest form of this
    test: if the detector only walks what it is given, it finds nothing."""
    client, container = app
    for _ in range(30):
        client.get("/v1/incidents", headers={"Authorization": "Bearer " + "y" * 40})

    findings = _detector(container, stuffing_attempts=25).scan(tenants=[])
    assert any(f.kind == "credential_stuffing" for f in findings)


def test_a_handful_of_failures_is_not_a_finding(app):
    """Four bad credentials is a Monday morning, not an attack. A detector that
    fires on it is a detector that gets muted."""
    client, container = app
    for _ in range(4):
        client.get("/v1/incidents", headers={"Authorization": "Bearer " + "z" * 40})
    findings = _detector(container).scan(tenants=["acme"])
    assert not [f for f in findings if f.kind == "credential_stuffing"]


# ── Privilege probing ────────────────────────────────────────────────────────


def test_one_credential_denied_across_distinct_capabilities_is_detected(app):
    """The signal that matters most: what a stolen key looks like being mapped.

    An `ingest` credential holds exactly one capability, so every read it attempts
    is refused for a DIFFERENT capability -- which is precisely the shape.
    """
    client, container = app
    auth = {"Authorization": f"Bearer {INGEST_KEY}"}
    client.get("/v1/incidents", headers=auth)            # read_incident
    client.get("/v1/incidents/inc-1/report", headers=auth)  # read_report
    client.get("/v1/dashboard", headers=auth)            # read_dashboard
    client.get("/health/diagnostics", headers=auth)       # read_diagnostics

    findings = _detector(container, probing_distinct_capabilities=4).scan(
        tenants=["acme"]
    )
    probing = [f for f in findings if f.kind == "privilege_probing"]
    assert probing, f"privilege probing was not detected: {findings}"
    assert probing[0].count >= 4
    assert set(probing[0].detail["capabilities"]) >= {
        "read_incident",
        "read_report",
        "read_dashboard",
        "read_diagnostics",
    }


def test_many_denials_for_the_SAME_capability_are_not_probing(app):
    """Distinctness is what makes this a signal.

    Twenty refusals for one capability is a broken client retrying. Treating it as
    probing would bury the real finding under noise from misconfigured integrations.
    """
    client, container = app
    for _ in range(20):
        client.get("/v1/incidents", headers={"Authorization": f"Bearer {INGEST_KEY}"})
    findings = _detector(container, probing_distinct_capabilities=4).scan(
        tenants=["acme"]
    )
    assert not [f for f in findings if f.kind == "privilege_probing"]


def test_a_probing_finding_names_the_capabilities_that_were_tried(app):
    """An operator has to be able to act on it. "Suspicious activity" is not
    actionable; "this key tried read_report and read_diagnostics" is."""
    client, container = app
    auth = {"Authorization": f"Bearer {INGEST_KEY}"}
    for path in ("/v1/incidents", "/v1/dashboard", "/v1/incidents/x/report",
                 "/health/diagnostics"):
        client.get(path, headers=auth)
    finding = [
        f
        for f in _detector(container, probing_distinct_capabilities=4).scan(
            tenants=["acme"]
        )
        if f.kind == "privilege_probing"
    ][0]
    assert "stolen key" in finding.detail["note"]
    assert str(finding).startswith("privilege_probing:")


# ── Enumeration ──────────────────────────────────────────────────────────────


def test_walking_an_incident_id_space_is_detected(app):
    """How a caller finds the one resource it can reach: try them all.

    A `viewer` holds `read_incident`, so these are not capability denials -- each is
    a 404 for a DIFFERENT id, which is the horizontal-enumeration shape.
    """
    client, container = app
    for index in range(25):
        client.get(
            f"/v1/incidents/inc-{index}",
            headers={"Authorization": f"Bearer {VIEWER_KEY}"},
        )

    findings = _detector(container, enumeration_distinct_resources=20).scan(
        tenants=["acme"]
    )
    enumeration = [f for f in findings if f.kind == "resource_enumeration"]
    assert enumeration, f"an id-space walk was not detected: {findings}"
    assert enumeration[0].count >= 20
    assert enumeration[0].actor.startswith("key:")
    assert all(s.startswith("incident:") for s in enumeration[0].detail["sample"])


def test_reading_the_same_missing_incident_repeatedly_is_not_enumeration(app):
    """A stale dashboard link produces one id over and over. Distinctness is the
    signal, so a retry loop must not fire it."""
    client, container = app
    for _ in range(30):
        client.get(
            "/v1/incidents/inc-gone", headers={"Authorization": f"Bearer {VIEWER_KEY}"}
        )
    findings = _detector(container, enumeration_distinct_resources=20).scan(
        tenants=["acme"]
    )
    assert not [f for f in findings if f.kind == "resource_enumeration"]


def test_capability_denials_are_not_double_counted_as_enumeration(app):
    """Counting them in both would make every probing finding also an enumeration
    finding, and halve the value of each."""
    client, container = app
    auth = {"Authorization": f"Bearer {INGEST_KEY}"}
    for path in ("/v1/incidents", "/v1/dashboard", "/v1/incidents/x/report",
                 "/health/diagnostics"):
        client.get(path, headers=auth)
    findings = _detector(
        container, probing_distinct_capabilities=2, enumeration_distinct_resources=2
    ).scan(tenants=["acme"])
    kinds = {f.kind for f in findings}
    assert "privilege_probing" in kinds
    assert "resource_enumeration" not in kinds


# ── Properties of the detector itself ────────────────────────────────────────


def test_a_clean_trail_produces_no_findings(app):
    """The negative control. Without it a detector that always fires would pass
    every test above."""
    client, container = app
    assert client.get(
        "/v1/incidents", headers={"Authorization": f"Bearer {VIEWER_KEY}"}
    ).status_code == 200
    assert _detector(container).scan(tenants=["acme"]) == ()


def test_findings_carry_the_audit_sequences_they_were_computed_from(app):
    """So a reviewer verifies the conclusion against the hash-chained entries
    rather than re-running the detector and trusting it is deterministic."""
    client, container = app
    for _ in range(30):
        client.get("/v1/incidents", headers={"Authorization": "Bearer " + "z" * 40})
    finding = _detector(container, stuffing_attempts=25).scan(tenants=[])[0]

    with container.pool.acquire() as conn:
        conn.begin()
        conn.set_tenant(UNAUTHENTICATED_TENANT)
        rows = conn.execute(
            f"SELECT seq FROM security_audit WHERE tenant_id={conn.p}",
            (UNAUTHENTICATED_TENANT,),
        )
        conn.commit()
    real = {int(r["seq"]) for r in rows}
    assert set(finding.sample_seqs) <= real, "a finding cited entries that do not exist"


def test_entries_outside_the_window_are_not_counted(app):
    """A window that silently covers everything makes "25 in five minutes"
    indistinguishable from "25 since installation"."""
    client, container = app
    for _ in range(30):
        client.get("/v1/incidents", headers={"Authorization": "Bearer " + "z" * 40})

    # Threshold of 1, so ONLY the window can be what excludes these. A window whose
    # cutoff is an hour in the future covers nothing that has already been written.
    inside = ThreatDetector(
        pool=container.pool,
        clock=container.clock,
        thresholds=Thresholds(window_seconds=300, stuffing_attempts=1),
    )
    assert inside.scan(tenants=[]), "the control case found nothing, so this proves nothing"

    outside = ThreatDetector(
        pool=container.pool,
        clock=container.clock,
        thresholds=Thresholds(window_seconds=-3600, stuffing_attempts=1),
    )
    assert outside.scan(tenants=[]) == ()


def test_a_malformed_detail_does_not_stop_the_scan(app):
    """A detector that raises on one bad row stops detecting, and that row is the
    one an attacker would want it to choke on."""
    client, container = app
    for _ in range(30):
        client.get("/v1/incidents", headers={"Authorization": "Bearer " + "z" * 40})
    with container.pool.acquire() as conn:
        conn.begin()
        conn.set_tenant(UNAUTHENTICATED_TENANT)
        conn.execute_rowcount(
            f"UPDATE security_audit SET detail={conn.p} WHERE seq={conn.p}",
            ("{not json at all", 1),
        )
        conn.commit()
    # Still finds the rest rather than raising.
    findings = _detector(container, stuffing_attempts=25).scan(tenants=[])
    assert any(f.kind == "credential_stuffing" for f in findings)


def test_the_detector_blocks_nothing(app):
    """A detector that revokes credentials on a threshold is a denial-of-service
    primitive an attacker aims at a legitimate tenant by guessing a key prefix.
    Detections are recorded; a human decides."""
    client, container = app
    for _ in range(30):
        client.get("/v1/incidents", headers={"Authorization": "Bearer " + "z" * 40})
    _detector(container, stuffing_attempts=25).scan(tenants=["acme"])
    # The valid credential is unaffected by the scan.
    assert client.get(
        "/v1/incidents", headers={"Authorization": f"Bearer {VIEWER_KEY}"}
    ).status_code == 200


def test_a_detection_is_immutable():
    finding = Detection(
        kind="k", tenant_id="t", actor="a", count=1, window_seconds=1,
        detail={}, sample_seqs=(1,),
    )
    with pytest.raises((AttributeError, TypeError)):
        finding.count = 99  # type: ignore[misc]
