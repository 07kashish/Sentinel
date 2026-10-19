"""The production ASGI entrypoint.

WHY THIS IS A FUNCTION AND NOT A MODULE-LEVEL `app`
----------------------------------------------------
Gunicorn and uvicorn both accept `module:callable`, so an application FACTORY is
as usable as a module-level object and does not require importing this module to
have side effects.

That distinction is the whole reason this file is three lines of logic. In the
predecessor, importing `api.main` executed configuration parsing, deployment
validation, schema DDL, additive migrations, a full ledger backfill and tenant
synchronisation, then started a queue consumer and a monitor thread. Importing
the module to read its routes applied a schema and began doing work.

Here, importing does nothing. `create_application()` builds a container, wires an
app around it, and registers lifespan hooks that start and stop the background
workers with the SERVER rather than with the import.

    gunicorn "sentinel.interface.asgi:create_application()" \
        --worker-class uvicorn.workers.UvicornWorker

The schema is NOT migrated here. `verify()` runs inside `build_container` and
refuses to serve against an unexpected version; applying the migration is a
deployment step (`python -m sentinel.interface.cli migrate`), because a migration
that runs at boot on every replica is one that cannot be restarted during an
incident.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from sentinel.composition.container import Container, build_container
from sentinel.composition.settings import Settings, read_environment
from sentinel.composition.topology import (
    ATTESTED_SINGLE_PROCESS,
    observe_topology,
    require_shared_limiter_or_refuse,
)
from sentinel.domain.primitives import TenantId
from sentinel.interface.http import create_app
from sentinel.interface.worker import MaintenanceLoop, WorkerPool

__all__ = ["create_application"]


def _pipeline_workers(default: int = 4) -> int:
    """`SENTINEL_PIPELINE_WORKERS`: how many pipeline threads THIS process runs.

    Zero makes a replica API-only, so the pipeline (and with it the advisory
    model call) can run on a designated host instead of on whichever replica
    claims the work first. Anything unparsable or out of range is refused: a
    typo that silently meant "four" or "none" is how incidents stop moving.
    """
    raw = read_environment().get("SENTINEL_PIPELINE_WORKERS", "").strip()
    if not raw:
        return default
    if not raw.isdigit() or int(raw) > 32:
        raise ValueError("SENTINEL_PIPELINE_WORKERS must be an integer from 0 to 32")
    return int(raw)


def create_application(
    *, settings: Settings | None = None, worker_threads: int | None = None
) -> FastAPI:
    """Build the served application, with its background workers attached."""
    resolved = settings or Settings.from_environment()
    worker_threads = _pipeline_workers() if worker_threads is None else worker_threads
    container = build_container(resolved)
    app = create_app(container)

    workers = WorkerPool(container, size=worker_threads)
    maintenance = MaintenanceLoop(
        container, tenants=lambda: _tenants(container), interval_seconds=30.0
    )

    @asynccontextmanager
    async def _lifespan(_app: FastAPI):
        # TOPOLOGY IS CHECKED HERE AND NOT IN create_application.
        #
        # This runs when the SERVER starts, which is the only moment the answer
        # is knowable: at import time the supervisor may not have spawned its
        # workers yet, and a tool that imports this app to enumerate routes
        # would be refused for a topology it is not creating.
        #
        # It runs BEFORE workers.start(), so a deployment whose rate limiter
        # would be per-process across replicas never serves a request. The
        # refusal propagates out of the lifespan, which is what fails the
        # startup -- swallowing it would leave the process running with the
        # control it was told to refuse.
        topology = observe_topology()
        environment = read_environment()
        require_shared_limiter_or_refuse(
            topology=topology,
            redis_url=resolved.redis_url,
            production=resolved.is_production,
            attested_single_process=environment.get(
                ATTESTED_SINGLE_PROCESS, ""
            ).strip().lower()
            in {"1", "true", "yes", "on"},
        )
        container.logger.info(
            "topology_observed",
            observation=topology.observation.value,
            process_count=topology.process_count,
            how=topology.how,
        )

        # Every tenant the configuration names gets its directory row BEFORE the
        # maintenance loop starts reading the directory.
        enrolled = ensure_configured_tenants(container)
        if enrolled:
            container.logger.info("tenants_enrolled_from_configuration", count=len(enrolled))

        # Started when the SERVER starts, not when the module is imported. A tool
        # that imports this app to enumerate its routes starts no threads.
        workers.start()
        maintenance.start()
        container.logger.info(
            "service_started",
            environment=resolved.environment,
            backend=resolved.engine.safe_description(),
            shard=resolved.worker_shard,
            shard_count=resolved.worker_shard_count,
            worker_threads=worker_threads,
        )
        try:
            yield
        finally:
            # Kubernetes sends SIGTERM and waits. A worker with no stop path
            # either loses in-flight work or lingers polling a database that has
            # gone away; both are avoidable and neither is acceptable.
            maintenance.stop()
            workers.stop()
            container.close()
            container.logger.info("service_stopped")

    app.router.lifespan_context = _lifespan
    return app


def ensure_configured_tenants(container: Container) -> list[str]:
    """Create the directory row for every tenant the CONFIGURATION names.

    Maintenance iterates the `tenants` table: retention, reaping of stale
    operations, outcome reconciliation, evidence commitment and root
    publication all run per row. Nothing in the service ever wrote a row, so a
    real deployment swept no tenant at all while every test, which inserts its
    own, passed. A tenant named by an API key or by an agent identity provider
    is a tenant this deployment serves; it is enrolled here, idempotently, by
    every replica. Tenants that appear only in human OIDC claims are not known
    until someone signs in and are NOT covered by this.
    """
    named = set(container.settings.tenants())
    providers = getattr(container, "agent_idps", None)
    if providers is not None:
        named.update(providers.tenants())
    created: list[str] = []
    now = container.clock.now().value.isoformat()
    with container.pool.acquire() as conn:
        p = conn.p
        conn.begin()
        for tenant in sorted(named):
            created += [tenant] * conn.execute_rowcount(
                f"INSERT INTO tenants (tenant_id, name, created_at) VALUES ({p},{p},{p}) "
                "ON CONFLICT (tenant_id) DO NOTHING",
                (tenant, tenant, now),
            )
        conn.commit()
    return created


def _tenants(container: Container) -> list[TenantId]:
    """The tenant directory, read fresh.

    Maintenance sweeps iterate tenants, so the list must reflect enrolments made
    since start-up. Caching it would silently stop sweeping for any tenant
    onboarded after the process booted.
    """
    with container.pool.acquire() as conn:
        conn.begin()
        rows = conn.execute("SELECT tenant_id FROM tenants ORDER BY tenant_id")
        conn.commit()
    return [TenantId(row["tenant_id"]) for row in rows]
