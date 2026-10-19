"""Transparency roots are published by the RUNNING SERVICE, on a schedule.

Until now the only publisher was a script on a cron line. A deployment that
never ran it served proofs whose `independently_verifiable` stayed false
forever, and nothing inside the service could say so. These tests hold the
in-process job to the same rules the script had, on both engines.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from fastapi.testclient import TestClient

from sentinel.composition.container import build_container
from sentinel.composition.settings import Settings
from sentinel.domain.primitives import TenantId
from sentinel.domain.root_sink import PublicationReceipt, RootSinkUnavailable
from sentinel.infrastructure.root_publication import publish_roots
from sentinel.infrastructure.sql.engine import Dialect, build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.infrastructure.sql.transparency_store import SqlTransparencyStore
from sentinel.interface.http import create_app
from sentinel.interface.worker import MaintenanceLoop

TENANT = "acme"
VIEWER = "v" * 40


@dataclass
class _WormSink:
    """A sink that returns a fetchable reference, like S3 Object Lock does."""

    published: list[tuple[str, int, str]] = field(default_factory=list)
    refuse: bool = False

    @property
    def name(self) -> str:
        return "fake-worm"

    def publish(self, *, tenant_id: str, tree_size: int, root_hash: str) -> PublicationReceipt:
        if self.refuse:
            raise RootSinkUnavailable("the WORM appliance is unreachable")
        self.published.append((tenant_id, tree_size, root_hash))
        return PublicationReceipt(
            sink="fake-worm",
            reference=f"worm://{tenant_id}/{tree_size}",
            published_at="2026-09-11T10:00:00+00:00",
        )


def _leaf(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


def _append(store: SqlTransparencyStore, *labels: str) -> None:
    for index, label in enumerate(labels):
        store.append(TENANT, digest=_leaf(label), at=f"2026-09-11T09:00:{index:02d}+00:00")


# ── The function ─────────────────────────────────────────────────────────────


def test_an_empty_log_publishes_nothing(migrated_pool):
    store = SqlTransparencyStore(pool=migrated_pool)
    sink = _WormSink()
    report = publish_roots(store=store, sink=sink, tenants=[TENANT])
    assert report.skipped_empty == 1 and report.published == 0
    assert sink.published == []


def test_the_current_root_is_published_once_and_recorded(migrated_pool):
    store = SqlTransparencyStore(pool=migrated_pool)
    sink = _WormSink()
    _append(store, "a", "b", "c")

    first = publish_roots(store=store, sink=sink, tenants=[TENANT])
    assert first.published == 1 and first.failed == 0
    assert sink.published == [(TENANT, 3, store.load(TENANT).root().hex())]
    roots = store.published_roots(TENANT)
    assert [r.tree_size for r in roots] == [3]
    assert roots[0].is_independently_verifiable
    assert roots[0].external_reference == f"worm://{TENANT}/3"

    # Nothing changed: nothing is re-published.
    second = publish_roots(store=store, sink=sink, tenants=[TENANT])
    assert second.skipped_current == 1 and second.published == 0
    assert len(sink.published) == 1

    # The log grew: the NEW root is published, the old record stays.
    _append(store, "d")
    third = publish_roots(store=store, sink=sink, tenants=[TENANT])
    assert third.published == 1
    assert [r.tree_size for r in store.published_roots(TENANT)] == [3, 4]


def test_a_sink_refusal_leaves_the_root_unpublished_and_is_reported(migrated_pool):
    store = SqlTransparencyStore(pool=migrated_pool)
    sink = _WormSink(refuse=True)
    _append(store, "a")
    report = publish_roots(store=store, sink=sink, tenants=[TENANT])
    assert report.failed == 1 and report.published == 0
    assert "NOT published" in report.details[0]
    assert store.published_roots(TENANT) == ()


# ── The maintenance loop ─────────────────────────────────────────────────────


def _container(engine_config, tmp_path, sink, **extra):
    env = {
        "SENTINEL_ENV": "development",
        "SENTINEL_API_KEYS": f"{TENANT}:{VIEWER}:viewer",
        "SENTINEL_SOFT_PROMPT_DETECT": "false",
        # A bucket is named so the settings accept the publish list; the sink
        # itself is injected, so no S3 client is ever built.
        "SENTINEL_S3_ROOT_BUCKET": "acme-transparency-roots",
        "SENTINEL_S3_ROOT_REGION": "eu-west-1",
        "SENTINEL_ROOT_PUBLISH_TENANTS": TENANT,
        "SENTINEL_ROOT_PUBLISH_INTERVAL_SECONDS": "3600",
    }
    if engine_config.dialect is Dialect.SQLITE:
        env["SENTINEL_DB_PATH"] = engine_config.dsn
    else:
        env["SENTINEL_DATABASE_URL"] = engine_config.dsn
    env.update(extra)
    settings = Settings.from_environment(env)
    pool = build_engine(settings.engine)
    migrate(pool)
    pool.close()
    return build_container(settings, root_sink=sink)


def test_the_maintenance_loop_publishes_and_the_proof_becomes_verifiable(
    engine_config, tmp_path
):
    sink = _WormSink()
    container = _container(engine_config, tmp_path, sink)
    try:
        _append(container.transparency, "a", "b")
        loop = MaintenanceLoop(container, tenants=lambda: [TenantId(TENANT)])

        totals = loop.run_once()
        assert totals["roots_published"] == 1
        assert sink.published[0][:2] == (TENANT, 2)

        # Within the interval the job does not run again.
        again = loop.run_once()
        assert "roots_published" not in again

        # And the proof served over HTTP now says a third party can check it.
        client = TestClient(create_app(container))
        body = client.get(
            "/v1/transparency/root", headers={"Authorization": f"Bearer {VIEWER}"}
        ).json()
        assert body["independently_verifiable"] is True
        assert f"worm://{TENANT}/2" in body["reason"]
    finally:
        container.close()


def test_without_a_publish_list_the_loop_publishes_nothing(engine_config, tmp_path):
    """Irreversible under COMPLIANCE retention, so never by default."""
    sink = _WormSink()
    container = _container(
        engine_config, tmp_path, sink,
        SENTINEL_ROOT_PUBLISH_TENANTS="", SENTINEL_S3_ROOT_BUCKET="", SENTINEL_S3_ROOT_REGION="",
    )
    try:
        _append(container.transparency, "a")
        totals = MaintenanceLoop(container, tenants=lambda: [TenantId(TENANT)]).run_once()
        assert "roots_published" not in totals
        assert sink.published == []
    finally:
        container.close()


def test_a_refusing_sink_is_loud_every_interval(engine_config, tmp_path):
    sink = _WormSink(refuse=True)
    container = _container(engine_config, tmp_path, sink)
    try:
        _append(container.transparency, "a")
        totals = MaintenanceLoop(container, tenants=lambda: [TenantId(TENANT)]).run_once()
        assert totals["roots_failed"] == 1
        assert container.transparency.published_roots(TENANT) == ()
    finally:
        container.close()
