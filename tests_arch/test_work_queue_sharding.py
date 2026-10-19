"""F-8: work is sharded by tenant hash; claim is O(1) query, not O(tenants)."""

from __future__ import annotations

from datetime import datetime, timezone

from sentinel.domain.primitives import IncidentId, TenantId, Timestamp
from sentinel.infrastructure.sql.unit_of_work import SqlUnitOfWorkFactory
from sentinel.infrastructure.sql.work_queue import SqlWorkQueue, shard_for
from tests_arch.doubles import FakeClock


def test_shard_for_is_stable_across_calls():
    tenant = TenantId("acme-tenant-001")
    assert shard_for(tenant, 8) == shard_for(tenant, 8)


def test_shard_for_spreads_distinct_tenants():
    shards = {shard_for(TenantId(f"tenant-{i:04d}"), 16) for i in range(64)}
    assert len(shards) > 1


def test_claim_sql_filters_by_shard_not_tenant_loop():
    import inspect
    source = inspect.getsource(SqlWorkQueue.claim)
    assert "shard" in source
    assert "_tenant_ids" not in source
    assert "for tenant" not in source


# ── The claim actually finds work on the production engine ──────────────────


class _NoPublisher:
    def publish(self, tenant, events) -> None:
        return None


def _submit(uows, queue, tenant: TenantId, incident_id: str) -> None:
    with uows.begin(tenant) as uow:
        queue.submit(
            tenant=tenant,
            incident_id=IncidentId(incident_id),
            payload={"event_digest": "d"},
            priority="HIGH",
            uow=uow,
        )
        uow.commit()


def test_a_submitted_item_can_be_claimed_on_every_engine(migrated_pool, engine_config):
    """THE regression. `work_queue` has been in PROTECTED_TABLES since v1 and
    the claim never bound a tenant -- it cannot, a shard holds every tenant --
    so under FORCE RLS on PostgreSQL the claim matched nothing. Submitted work
    was never claimed, and every SQLite test passed.

    Runs on both engines; on PostgreSQL the fixture connects as the
    non-superuser role, so FORCE RLS is actually enforced here (a superuser
    would make this pass vacuously -- see `conftest.postgres_dsn`).
    """
    clock = FakeClock()
    uows = SqlUnitOfWorkFactory(pool=migrated_pool, publisher=_NoPublisher(), clock=clock)
    queue = SqlWorkQueue(pool=migrated_pool, shard_count=1, worker_id="w-test")
    tenant = TenantId("acme")

    _submit(uows, queue, tenant, "inc-1")
    assert queue.depth(state="pending") == 1

    claimed = queue.claim(shard=0, shard_count=1, now=clock.now())

    assert claimed is not None, (
        f"submit() succeeded and claim() found nothing on {engine_config.dialect.value}: "
        "the queue is protected by row-level security and the claim is not scoped"
    )
    assert claimed.tenant_id == tenant
    assert claimed.incident_id == IncidentId("inc-1")
    assert claimed.lease_epoch == 1
    assert queue.depth(state="claimed") == 1


def test_the_claim_is_cross_tenant_and_the_finish_is_fenced(migrated_pool):
    """Two tenants in one shard: both items are claimable by one worker, and
    completing one touches only its own row."""
    clock = FakeClock()
    uows = SqlUnitOfWorkFactory(pool=migrated_pool, publisher=_NoPublisher(), clock=clock)
    queue = SqlWorkQueue(pool=migrated_pool, shard_count=1, worker_id="w-test")

    _submit(uows, queue, TenantId("acme"), "inc-a")
    _submit(uows, queue, TenantId("globex"), "inc-b")

    first = queue.claim(shard=0, shard_count=1, now=clock.now())
    second = queue.claim(shard=0, shard_count=1, now=clock.now())
    assert first is not None and second is not None
    assert {first.tenant_id.value, second.tenant_id.value} == {"acme", "globex"}

    queue.complete(first)
    assert queue.depth(state="done") == 1
    assert queue.depth(state="claimed") == 1
    assert queue.claim(shard=0, shard_count=1, now=clock.now()) is None


def test_an_expired_lease_is_reaped_across_tenants(migrated_pool):
    clock = FakeClock()
    uows = SqlUnitOfWorkFactory(pool=migrated_pool, publisher=_NoPublisher(), clock=clock)
    queue = SqlWorkQueue(pool=migrated_pool, shard_count=1, worker_id="w-dead", lease_seconds=10)

    _submit(uows, queue, TenantId("acme"), "inc-a")
    _submit(uows, queue, TenantId("globex"), "inc-b")
    assert queue.claim(shard=0, shard_count=1, now=clock.now()) is not None
    assert queue.claim(shard=0, shard_count=1, now=clock.now()) is not None

    later = Timestamp(datetime(2030, 1, 1, tzinfo=timezone.utc))
    assert queue.reap_expired_leases(now=later, shard=0, shard_count=1) == 2
    assert queue.depth(state="pending") == 2
