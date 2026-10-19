"""The background worker. A delivery mechanism, not business logic.

WHAT THIS OWNS AND WHAT IT DOES NOT
------------------------------------
It owns a loop, a shutdown signal and a retry decision. It owns no rules: what
happens to an incident is `ProcessIncident`, and whether a failure is worth
retrying is a property the error declares.

That second point is the substantive change from the predecessor, whose worker
inferred retryability from a tuple of exception TYPES:

    TERMINAL_ERRORS = (IllegalTransition, MissingRequiredFact, ArtifactMissing,
                       ValueError, TypeError, KeyError)

`ValueError`, `TypeError` and `KeyError` are the three most common incidental
exceptions in Python -- `json.loads()` on a truncated body raises ValueError, a
degraded provider response raises KeyError -- and each was recorded as a
permanent failure with no retry. Determinism is a property of ORIGIN, not of
type, so here the code that failed says whether repeating could help, and this
loop reads the declaration.

CONCURRENCY
-----------
`WorkerPool` runs N threads, each claiming from the shard this replica owns. The
predecessor ran exactly one worker thread per replica, so cluster throughput was
`replicas / mean incident duration` -- roughly 0.6 incidents per second at three
replicas -- while its documentation described millions of events.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Callable, Mapping, Sequence

from sentinel.application.bypass_detection import detect_possible_bypasses
from sentinel.application.commands.dispatch_outbox import DispatchOutbox
from sentinel.application.execution.handler import ProcessIncident
from sentinel.composition.container import Container
from sentinel.domain.errors import ExecutionFenceLost, SentinelError, failure_is_retryable
from sentinel.domain.primitives import TenantId, Timestamp
from sentinel.infrastructure.observability import correlation_var, new_correlation
from sentinel.infrastructure.root_publication import publish_roots

__all__ = ["MaintenanceLoop", "WorkerPool"]


@dataclass(frozen=True, slots=True)
class _Backoff:
    """Retry delay. A real interval, because the budget is worthless without one.

    The predecessor's queue `fail()` returned an item straight to `pending` with
    no delay, and the idle poll floor was 50 ms -- so three attempts burned in
    about 150 milliseconds, long before any transient dependency could recover.
    The retry budget existed; the retry *window* did not.
    """

    base_seconds: int = 5
    cap_seconds: int = 600

    def for_attempt(self, attempt: int) -> int:
        return min(self.cap_seconds, self.base_seconds * (2 ** max(0, attempt - 1)))


class WorkerPool:
    """Runs the incident pipeline for the shard this replica owns."""

    __slots__ = ("_container", "_threads", "_stop", "_size", "_backoff", "_poll")

    def __init__(self, container: Container, *, size: int = 4) -> None:
        self._container = container
        self._size = max(0, size)  # zero: an API-only replica; another process drains the queue
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._backoff = _Backoff()
        self._poll = container.settings.worker_poll_seconds

    def start(self) -> None:
        if self._threads:
            return
        self._stop.clear()
        for index in range(self._size):
            thread = threading.Thread(
                target=self._run, name=f"sentinel-worker-{index}", daemon=True
            )
            thread.start()
            self._threads.append(thread)

    def stop(self, *, timeout: float = 30.0) -> None:
        """Drain and stop. Kubernetes sends SIGTERM and waits; a worker with no
        stop path either loses in-flight work or lingers polling a database that
        has gone away."""
        self._stop.set()
        for thread in self._threads:
            thread.join(timeout=timeout)
        self._threads.clear()

    def run_once(self) -> bool:
        """Claim and process at most one item. Returns whether work was found.

        Public so the loop body is directly testable. In the predecessor this
        logic lived inline in a `while True:` thread body and nothing exercised
        the exhausted-retry path at all.
        """
        settings = self._container.settings
        queue = self._container.work_queue
        now = self._container.clock.now()

        work = queue.claim(
            shard=settings.worker_shard,
            shard_count=settings.worker_shard_count,
            now=now,
        )
        if work is None:
            return False

        corr = new_correlation(
            tenant_id=str(work.tenant_id),
            incident_id=str(work.incident_id),
            epoch=str(work.lease_epoch),
            worker_shard=str(settings.worker_shard),
        )
        token = correlation_var.set(corr)
        self._container.metrics.inc("sentinel_worker_claims_total")
        try:
            with self._container.otel.span(
                "worker.process_incident",
                incident_id=str(work.incident_id),
                tenant_id=str(work.tenant_id),
            ):
                self._container.commands.dispatch(
                    ProcessIncident(
                        tenant=work.tenant_id,
                        incident_id=work.incident_id,
                        lease_epoch=work.lease_epoch,
                        # The queue item id, so a redelivery is recognised by the
                        # inbox before any step is even considered.
                        message_id=work.work_id,
                    )
                )
        except ExecutionFenceLost:
            # A newer worker owns this incident and is already redoing the work.
            # Abandon WITHOUT writing and WITHOUT retrying: doing either would
            # duplicate or overwrite the current owner.
            self._container.logger.warning(
                "execution_fence_lost",
                incident_id=str(work.incident_id),
                lease_epoch=work.lease_epoch,
            )
            return True
        except SentinelError as exc:
            self._fail(work, exc, retryable=exc.is_retryable)
            return True
        except Exception as exc:  # noqa: BLE001
            # Unclassified failures default to RETRYABLE via failure_is_retryable.
            # Never classify ValueError/TypeError/KeyError as terminal by type.
            self._fail(work, exc, retryable=failure_is_retryable(exc))
            return True
        finally:
            correlation_var.reset(token)

        try:
            queue.complete(work)
        except ExecutionFenceLost:
            self._container.logger.warning(
                "lease_lost_on_complete", incident_id=str(work.incident_id)
            )
        return True

    def _fail(self, work, exc: BaseException, *, retryable: bool) -> None:
        delay = self._backoff.for_attempt(work.attempts) if retryable else 0
        try:
            will_retry = self._container.work_queue.fail(
                work,
                error=f"{type(exc).__name__}: {exc}",
                now=self._container.clock.now(),
                retry_in_seconds=delay if retryable else self._backoff.cap_seconds,
            )
        except ExecutionFenceLost:
            self._container.logger.warning(
                "lease_lost_during_fail", incident_id=str(work.incident_id)
            )
            return
        self._container.logger.error(
            "pipeline_failed",
            incident_id=str(work.incident_id),
            attempts=work.attempts,
            retryable=retryable,
            will_retry=will_retry and retryable,
            retry_in_seconds=delay,
            error=f"{type(exc).__name__}: {exc}",
        )

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                if not self.run_once():
                    # Nothing to do. Wait on the stop event rather than sleeping,
                    # so shutdown is immediate instead of up to one poll late.
                    self._stop.wait(self._poll)
            except Exception as exc:  # noqa: BLE001 - the loop must survive anything
                self._container.logger.error(
                    "worker_loop_error", error=f"{type(exc).__name__}: {exc}"
                )
                self._stop.wait(1.0)


class MaintenanceLoop:
    """Periodic, cluster-singleton work: outbox dispatch and lease reaping.

    Two properties the predecessor's scheduler lacked:

    * **It runs once at startup, then on the interval.** `PeriodicJob.run()`
      waited a full interval BEFORE its first execution, so on a cluster that
      deploys more often than hourly its retention job had likely never executed
      -- and the readiness probe reported it healthy, because zero runs means
      zero consecutive failures.
    * **The outbox is actually drained.** `dlq.drain()` had zero callers, which
      made the dead-letter queue write-only and turned the operator's "replay"
      button into a control that removed a failure from view without delivering
      it.
    """

    __slots__ = (
        "_container", "_tenants", "_interval", "_stop", "_thread",
        "_last_retention", "_last_root_publication",
    )

    def __init__(
        self,
        container: Container,
        *,
        tenants: Callable[[], list[TenantId]],
        interval_seconds: float = 30.0,
    ) -> None:
        self._container = container
        self._tenants = tenants
        self._interval = interval_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        #: None means "never swept", so the first tick sweeps immediately rather
        #: than waiting a full interval -- the same reason this loop runs its
        #: other work at startup.
        self._last_retention: Timestamp | None = None
        #: Same convention: None means "never published", so the first tick
        #: publishes rather than waiting a day.
        self._last_root_publication: Timestamp | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="sentinel-maintenance", daemon=True
        )
        self._thread.start()

    def stop(self, *, timeout: float = 30.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    def run_once(self) -> dict[str, int]:
        """One maintenance sweep across every tenant. Returns aggregate counts."""
        totals = {"claimed": 0, "delivered": 0, "failed": 0, "dead": 0, "reaped": 0}
        settings = self._container.settings
        now = self._container.clock.now()
        silent_agents = 0
        tenants = list(self._tenants())
        for tenant in tenants:
            result = self._container.commands.dispatch(DispatchOutbox(tenant=tenant))
            for key in totals:
                totals[key] += int(result.detail.get(key, 0))
            silent_agents += len(
                detect_possible_bypasses(
                    agents=self._container.agents.list_activity(tenant),
                    now=now,
                    idle_threshold_seconds=settings.bypass_idle_seconds,
                )
            )
        reclaimed = self._container.work_queue.reap_expired_leases(
            now=now,
            shard=settings.worker_shard,
            shard_count=settings.worker_shard_count,
        )
        totals["work_leases_reaped"] = reclaimed
        totals["parked_incidents_requeued"] = self._requeue_parked_attestations(
            now, tenants
        )
        totals["approval_claims_released"] = self._release_stale_approval_claims(
            now, tenants
        )
        totals["operations_marked_unknown"] = self._mark_stale_operations_unknown(
            now, tenants
        )
        totals.update(self._reconcile_unknown_operations(now, tenants))
        totals["receipts_committed"] = self._commit_evidence(now, tenants)
        totals["possible_bypass_agents"] = silent_agents
        self._publish_bypass_metrics(silent_agents, now)
        # `tenants` is resolved once and passed down, rather than each sweep
        # calling the callable again: two sweeps in one tick that disagreed about
        # the tenant list would delete from a set of tenants that never existed
        # at any single moment.
        totals.update(self._sweep_retention(now, tenants))
        totals.update(self._publish_roots(now, tenants))
        return totals

    def _publish_roots(
        self, now: Timestamp, tenants: Sequence[TenantId]
    ) -> Mapping[str, int]:
        """Publish each configured tenant's transparency root, on the interval.

        Until this job existed the only publisher was a script on a cron line,
        and a deployment that never ran it served proofs whose
        `independently_verifiable` stayed false forever with nothing in the
        running service able to say so. Now the service publishes, and a
        refusal from the sink is an ERROR in the service log every interval --
        loud, because a log whose roots only the operator serves is not
        evidence, and that state should not be quiet.

        Publishes NOTHING unless `SENTINEL_ROOT_PUBLISH_TENANTS` names tenants
        (or `*`): a publication under COMPLIANCE retention is irreversible, so
        it is a decision an operator makes by name rather than a default.
        """
        settings = self._container.settings
        wanted = settings.root_sink.publish_tenants
        if not wanted:
            return {}
        interval = settings.root_sink.publish_interval_seconds
        if self._last_root_publication is not None:
            elapsed = (now.value - self._last_root_publication.value).total_seconds()
            if elapsed < interval:
                return {}
        targets = [t.value for t in tenants] if wanted == ("*",) else list(wanted)
        try:
            report = publish_roots(
                store=self._container.transparency,
                sink=self._container.root_sink,
                tenants=targets,
            )
        except Exception as exc:  # noqa: BLE001 - housekeeping must not kill the sweep
            self._container.logger.error(
                "transparency_root_publication_failed",
                error=f"{type(exc).__name__}: {exc}",
            )
            return {}
        self._last_root_publication = now
        if report.failed:
            self._container.logger.error(
                "transparency_roots_not_published",
                sink=self._container.root_sink.name,
                details=list(report.details),
                **report.as_dict(),
            )
        elif report.published:
            self._container.logger.info(
                "transparency_roots_published",
                sink=self._container.root_sink.name,
                details=list(report.details),
                **report.as_dict(),
            )
        return report.as_dict()

    def _requeue_parked_attestations(
        self, now: Timestamp, tenants: Sequence[TenantId]
    ) -> int:
        try:
            requeue = getattr(
                self._container.work_queue, "reenqueue_parked_attestations"
            )
            return int(
                requeue(
                    tenants=tuple(tenants),
                    now=now,
                    older_than_seconds=self._container.settings.queue_lease_seconds,
                )
            )
        except Exception as exc:  # noqa: BLE001 - maintenance must keep sweeping
            self._container.logger.error(
                "parked_attestation_requeue_failed",
                error=f"{type(exc).__name__}: {exc}",
            )
            return 0

    def _commit_evidence(self, now: Timestamp, tenants: Sequence[TenantId]) -> int:
        """Append every uncommitted execution receipt to the transparency log."""
        evidence = getattr(self._container, "evidence", None)
        if evidence is None:
            return 0
        committed = 0
        for tenant in tenants:
            try:
                committed += evidence.commit_pending(tenant.value, at=now.value.isoformat())
            except Exception as exc:  # noqa: BLE001 - maintenance must keep sweeping
                self._container.logger.error(
                    "evidence_commit_failed", tenant=tenant.value, error=type(exc).__name__
                )
        return committed

    def _reconcile_unknown_operations(
        self, now: Timestamp, tenants: Sequence[TenantId]
    ) -> Mapping[str, int]:
        """Ask each target whether its unknown operations landed. Reads only."""
        settled = {"operations_reconciled": 0, "operations_awaiting_human": 0}
        reconciler = getattr(self._container, "operation_reconciler", None)
        if reconciler is None:
            return settled
        for tenant in tenants:
            try:
                result = reconciler.run(tenant.value, now=now.value)
            except Exception as exc:  # noqa: BLE001 - maintenance must keep sweeping
                self._container.logger.error(
                    "operation_reconcile_failed", tenant=tenant.value, error=type(exc).__name__
                )
                continue
            settled["operations_reconciled"] += result["succeeded"] + result["failed"]
            settled["operations_awaiting_human"] += result["exhausted"] + result["no_reconciler"]
        if settled["operations_awaiting_human"]:
            self._container.logger.error("operations_await_human_reconciliation", **settled)
        return settled

    def _mark_stale_operations_unknown(
        self, now: Timestamp, tenants: Sequence[TenantId]
    ) -> int:
        """Operations still `pending` past the deadline become UNKNOWN.

        Loud when it happens: an operation whose outcome was never recorded
        is the one row an investigation needs, and a reconciler has to be
        told rather than left to notice.
        """
        deadline = self._container.settings.operation_pending_deadline_seconds
        moved = 0
        for tenant in tenants:
            try:
                count = self._container.operations.mark_stale_pending_unknown(
                    tenant.value, now=now.value, pending_deadline_seconds=deadline
                )
            except Exception as exc:  # noqa: BLE001 - maintenance must keep sweeping
                self._container.logger.error(
                    "operation_unknown_sweep_failed",
                    tenant=tenant.value,
                    error=f"{type(exc).__name__}: {exc}",
                )
                continue
            if count:
                self._container.logger.error(
                    "operations_outcome_unknown",
                    tenant=tenant.value,
                    count=count,
                    detail=(
                        "these effects were invoked and their outcomes were never "
                        "recorded; reconcile via POST /v1/executions/operations/{id}/reconcile"
                    ),
                )
            moved += count
        return moved

    def _release_stale_approval_claims(
        self, now: Timestamp, tenants: Sequence[TenantId]
    ) -> int:
        from datetime import timedelta

        cutoff = Timestamp(
            now.value
            - timedelta(seconds=max(1, self._container.settings.queue_lease_seconds))
        )
        released = 0
        for tenant in tenants:
            try:
                with self._container.uow_factory.begin(tenant) as uow:
                    release = getattr(uow.approvals, "reap_stale_execution_claims")
                    released += int(release(older_than=cutoff, at=now))
                    uow.commit()
            except AttributeError:
                return released
            except Exception as exc:  # noqa: BLE001 - one tenant must not stop all
                self._container.logger.error(
                    "approval_claim_reap_failed",
                    tenant=str(tenant),
                    error=f"{type(exc).__name__}: {exc}",
                )
        return released

    def _sweep_retention(
        self, now: Timestamp, tenants: Sequence[TenantId]
    ) -> Mapping[str, int]:
        """Delete finished operational rows past the retention window.

        This is the job `SENTINEL_RETENTION_DAYS` has always implied and never
        had. Completed work items and delivered outbox records were never
        deleted by anything, and the two tables that DO have purge primitives --
        `inbox` and `replay_nonces` -- had no production caller for them, despite
        carrying indexes built to serve exactly those deletes.

        Rate-limited to `retention_interval_seconds` rather than run on every
        sweep: the maintenance loop ticks every 30s by default and there is no
        reason to issue four DELETEs a minute against tables measured in days.

        A failure here must not stop outbox dispatch or lease reaping, which are
        liveness-critical; retention is housekeeping and can wait for the next
        tick.
        """
        interval = self._container.settings.retention_interval_seconds
        if self._last_retention is not None:
            elapsed = (now.value - self._last_retention.value).total_seconds()
            if elapsed < interval:
                return {}
        try:
            swept = self._container.retention.sweep(
                now=now,
                retention_days=self._container.settings.retention_days,
                tenants=tenants,
            )
        except Exception as exc:  # noqa: BLE001 - housekeeping must not kill the sweep
            self._container.logger.error(
                "retention_sweep_failed", error=f"{type(exc).__name__}: {exc}"
            )
            return {}
        self._last_retention = now
        if swept.total:
            self._container.logger.info("retention_swept", **swept.as_dict())
        totals: dict[str, int] = dict(swept.as_dict())
        totals.update(self._sweep_incident_history(now, tenants))
        return totals

    def _sweep_incident_history(
        self, now: Timestamp, tenants: Sequence[TenantId]
    ) -> Mapping[str, int]:
        """The second, separately-owned retention policy: the incident record.

        Kept apart from `_sweep_retention` above even though both run on the same
        tick, because they are not the same decision. Operational housekeeping is
        an engineering choice with a default; how long incident history is kept is
        a compliance choice with no default -- `SENTINEL_INCIDENT_RETENTION_DAYS`
        is unset unless an operator sets it, and while it is unset this issues no
        DELETE at all.

        Reported separately for the same reason, so a log line that says rows were
        deleted always says WHICH policy deleted them.
        """
        configured = self._container.settings.incident_retention_days
        if configured is None:
            return {}
        try:
            swept = self._container.retention.sweep_incident_history(
                now=now, incident_retention_days=configured, tenants=tenants
            )
        except Exception as exc:  # noqa: BLE001 - housekeeping must not kill the loop
            self._container.logger.error(
                "incident_retention_sweep_failed", error=f"{type(exc).__name__}: {exc}"
            )
            return {}
        if swept.total:
            self._container.logger.info(
                "incident_history_swept",
                retention_days=configured,
                **swept.as_dict(),
            )
        return {k: int(v) for k, v in swept.as_dict().items() if not isinstance(v, bool)}

    def _publish_bypass_metrics(self, silent_agents: int, now: Timestamp) -> None:
        """Make `possible_bypass` alertable rather than merely queryable.

        `GET /v1/protect/bypass-signals` returns the same finding, but it is a
        capability-gated JSON route: an alerting system cannot poll it without
        being given a Sentinel credential, so in practice nothing did. Until
        this sweep published the count, the only way an enrolled agent going
        silent came to anyone's attention was somebody choosing to look.

        The timestamp is published alongside the count and matters as much. A
        count of zero is indistinguishable from a sweep that stopped running,
        and "no signal" is precisely what a bypass looks like -- so the alert
        rules watch the freshness of this gauge as well as its value.
        """
        metrics = self._container.metrics
        metrics.set_gauge("sentinel_possible_bypass_agents", float(silent_agents))
        metrics.set_gauge(
            "sentinel_bypass_sweep_timestamp_seconds", now.value.timestamp()
        )

    def _run(self) -> None:
        # Run IMMEDIATELY, then on the interval.
        while True:
            try:
                self.run_once()
            except Exception as exc:  # noqa: BLE001 - a sweep must not kill the loop
                self._container.logger.error(
                    "maintenance_failed", error=f"{type(exc).__name__}: {exc}"
                )
            if self._stop.wait(self._interval):
                return
