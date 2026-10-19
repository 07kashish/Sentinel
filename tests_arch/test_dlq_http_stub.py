"""DLQ integration: deliberately failing HTTP attestation stub (not a mock)."""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

from sentinel.application.commands.dispatch_outbox import DispatchOutbox, DispatchOutboxHandler
from sentinel.domain.incident import Incident
from sentinel.domain.primitives import (
    Digest,
    IdempotencyKey,
    IncidentId,
    Severity,
    TenantId,
    Timestamp,
    TrustLevel,
)
from sentinel.infrastructure.attestation import HttpAttestationGateway
from sentinel.infrastructure.outbound import HardenedHttpClient, OutboundPolicy
from sentinel.infrastructure.sql.engine import Dialect, EngineConfig, build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.infrastructure.sql.unit_of_work import SqlUnitOfWorkFactory
from tests_arch.doubles import FakeClock, RecordingLogger

TENANT = TenantId("acme")
NOW = Timestamp(datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc))
DIGEST = Digest("a" * 64)


class _AlwaysFailHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        self.send_response(503)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"error":"deliberate stub failure"}')

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


class _Publisher:
    def publish(self, tenant, events) -> None:
        return


def test_outbox_reaches_dead_letter_against_failing_http_stub(tmp_path):
    server = HTTPServer(("127.0.0.1", 0), _AlwaysFailHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = HardenedHttpClient(
            policy=OutboundPolicy(
                allowed_schemes=frozenset({"http"}),
                allow_private_destinations=True,
                allowed_hosts=frozenset({"127.0.0.1"}),
                read_timeout_seconds=2.0,
                connect_timeout_seconds=2.0,
            )
        )
        gateway = HttpAttestationGateway(
            endpoint=f"http://127.0.0.1:{port}",
            token="stub-token-not-a-secret-for-tests-32",
            client=client,
        )
        pool = build_engine(
            EngineConfig(
                dialect=Dialect.SQLITE,
                dsn=str(tmp_path / "dlq.db"),
                pool_min=1,
                pool_max=4,
            )
        )
        migrate(pool)
        with pool.acquire() as conn:
            conn.begin()
            conn.execute_rowcount(
                f"INSERT INTO tenants (tenant_id, name, created_at) "
                f"VALUES ({conn.p},{conn.p},{conn.p}) "
                f"ON CONFLICT (tenant_id) DO NOTHING",
                (TENANT.value, TENANT.value, NOW.isoformat()),
            )
            conn.commit()

        clock = FakeClock(NOW.value)
        uows = SqlUnitOfWorkFactory(pool=pool, publisher=_Publisher(), clock=clock)
        incident_id = IncidentId("inc-dlq-1")
        with uows.begin(TENANT) as uow:
            incident = Incident.admit(
                tenant_id=TENANT,
                incident_id=incident_id,
                severity=Severity(50),
                trust_level=TrustLevel.VERIFIED,
                source="test",
                now=NOW,
                event_digest=DIGEST,
                facts={"signer_address": "0x" + "ab" * 20},
            )
            uow.incidents.add(incident)
            uow.outbox.enqueue(
                incident_id=incident_id,
                kind="attestation",
                payload={
                    "evidence_digest": DIGEST.value,
                    "subject": "0x" + "ab" * 20,
                },
                idempotency_key=IdempotencyKey("dlq-stub-1"),
                at=NOW,
            )
            uow.commit()

        handler = DispatchOutboxHandler(
            uow_factory=uows,
            attestation=gateway,
            clock=clock,
            logger=RecordingLogger(),
            batch_size=10,
            lease_seconds=30,
        )
        dead = 0
        for _ in range(8):
            clock.advance(120)
            result = handler.handle(DispatchOutbox(tenant=TENANT))
            dead += int(result.detail.get("dead") or 0)
            if dead:
                break
        assert dead >= 1, "failing HTTP stub must exhaust attempts into dead letters"
        with uows.begin(TENANT) as uow:
            letters = uow.outbox.dead_letters(limit=10)
            assert len(letters) == 1
            assert letters[0].state == "dead"
        pool.close()
    finally:
        server.shutdown()
