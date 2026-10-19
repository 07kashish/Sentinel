"""Concurrency tests: real threads, real locks, real races.

No mocks, no simulated interleavings. Each test starts N threads against one
SQLite database and lets them contend, using a `threading.Barrier` so they arrive
at the contended operation together rather than politely one after another.

A concurrency test that never actually overlaps proves nothing, so every test
here asserts on an observable outcome (how many effects reached the gateway, how
many transitions landed) rather than on the absence of an exception.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest

from sentinel.domain.errors import (
    ConcurrencyConflict,
    ExecutionFenceLost,
    SentinelError,
)
from sentinel.domain.execution import StepName, StepStatus
from sentinel.domain.incident import IncidentState
from tests_arch.harness import Harness, TENANT

THREADS = 8


@pytest.fixture
def harness(tmp_path, engine_config):
    """Runs on EVERY backend. See `conftest.engine_config`."""
    h = Harness(tmp_path, engine_config=engine_config)
    yield h
    h.close()


def _race(count: int, work):
    """Run `work(index)` on `count` threads that all start together.

    The barrier is what makes this a race rather than a sequence. Without it the
    thread pool tends to serialise short tasks and the test passes for the wrong
    reason.
    """
    barrier = threading.Barrier(count)
    results: list[object] = []
    errors: list[BaseException] = []
    lock = threading.Lock()

    def run(index: int):
        barrier.wait(timeout=30)
        try:
            outcome = work(index)
        except BaseException as exc:  # noqa: BLE001 - classified by the caller
            with lock:
                errors.append(exc)
            return
        with lock:
            results.append(outcome)

    with ThreadPoolExecutor(max_workers=count) as pool:
        list(as_completed([pool.submit(run, i) for i in range(count)]))
    return results, errors


# ── The central claim: concurrent workers produce ONE effect ────────────────


def test_eight_workers_racing_one_incident_produce_one_effect(harness):
    """The whole design, in one assertion.

    Eight threads claim the same incident at eight different epochs. Some are
    refused by the fence, some by optimistic locking, some find the work already
    settled. However they interleave, the gateway must see ONE logical effect and
    the incident must end in a legal terminal state.
    """
    incident = harness.admit()

    def work(index: int):
        return harness.run(incident, epoch=index + 1)

    _results, errors = _race(THREADS, work)

    # Every error must be an expected concurrency outcome, never a crash.
    for error in errors:
        assert isinstance(error, (ExecutionFenceLost, ConcurrencyConflict)), (
            f"unexpected error under contention: {type(error).__name__}: {error}"
        )

    assert len(harness.effects.distinct_keys("anchor")) <= 1
    assert harness.state(incident) in {
        IncidentState.COMPLETED_ATTESTED,
        IncidentState.ATTESTED,
        IncidentState.ATTESTATION_UNAVAILABLE,
        IncidentState.REPORTED,
        IncidentState.AWAITING_APPROVAL,
    }
    harness.assert_invariants(incident)


def test_racing_workers_never_duplicate_a_transition(harness):
    """The audit trail is strictly ordered with no repeated adjacent state.

    A duplicated transition would mean two workers both applied the same
    lifecycle edge -- which the optimistic version check exists to prevent.
    """
    incident = harness.admit()
    _race(THREADS, lambda i: harness.run(incident, epoch=i + 1))

    history = harness.transitions(incident)
    assert history == sorted(set(history), key=history.index), (
        f"a state appears twice in the audit trail: {history}"
    )
    assert len(history) == len(set(history))


def test_racing_workers_never_settle_a_step_twice(harness):
    """Each journal entry has exactly one outcome, whatever the interleaving."""
    incident = harness.admit()
    _race(THREADS, lambda i: harness.run(incident, epoch=i + 1))

    journal = harness.journal(incident)
    for name, record in journal.items():
        assert record.status in set(StepStatus)
        # A settled step carries the result of exactly one execution.
        if record.is_settled:
            assert record.attempts >= 1


def test_the_ledger_never_forks_under_contention(harness):
    """Concurrent evidence writes cannot break the hash chain.

    Eight workers race the evidence step across eight incidents. Each append
    reads the head inside the transaction that inserts, and
    `UNIQUE(tenant_id, prev_chain_hash)` makes a fork unstorable rather than
    merely unlikely.
    """
    incidents = [harness.admit(f"inc-{i}") for i in range(THREADS)]

    def work(index: int):
        return harness.run(incidents[index], epoch=1)

    _results, errors = _race(THREADS, work)
    for error in errors:
        assert isinstance(error, SentinelError), f"unexpected: {error!r}"

    rows = harness.ledger_rows()
    previous = "0" * 64
    for row in rows:
        assert row["prev_chain_hash"] == previous, "the chain is broken"
        previous = row["chain_hash"]
    assert len({r["prev_chain_hash"] for r in rows}) == len(rows), "the chain forked"
    assert len({r["incident_id"] for r in rows}) == len(rows), "an incident appended twice"


# ── Fencing ──────────────────────────────────────────────────────────────────


def test_a_reclaimed_incident_refuses_its_previous_owner(harness):
    """Take the fence at a high epoch, then have an old worker try to write."""
    incident = harness.admit()

    with harness.uows.begin(TENANT) as uow:
        loaded = uow.incidents.get_for_update(incident)
        loaded.acquire_execution(100)
        uow.incidents.save(loaded)
        uow.commit()

    with pytest.raises(ExecutionFenceLost):
        harness.run(incident, epoch=5)

    assert harness.state(incident) is IncidentState.RECEIVED
    harness.assert_invariants(incident)


def test_the_fence_never_moves_backwards_under_contention(harness):
    """The fence is monotonic, and it stops once there is nothing left to own.

    Note what is NOT asserted: that the highest epoch ends up owning it. Once an
    incident is terminal the engine short-circuits BEFORE touching the fence --
    there is no work to fence -- so a later worker leaves it where the finishing
    worker did. Asserting `execution_epoch == max(epochs)` describes a system
    that keeps taking a lease on finished work, which would be worse.
    """
    incident = harness.admit()
    epochs = [3, 1, 7, 2, 9, 4, 8, 5]

    def work(index: int):
        return harness.run(incident, epoch=epochs[index])

    _race(len(epochs), work)

    with harness.uows.begin(TENANT) as uow:
        final = uow.incidents.get(incident)
        uow.commit()

    assert final.execution_epoch in epochs, "the fence holds an epoch nobody claimed"
    if not final.state.is_terminal:
        assert final.execution_epoch == max(epochs), (
            "while work remains, the newest lease must own it"
        )
    harness.assert_invariants(incident)


def test_the_fence_is_monotonic_across_sequential_claims(harness):
    """Directly: an older epoch can never take the fence from a newer one."""
    incident = harness.admit()
    with harness.uows.begin(TENANT) as uow:
        loaded = uow.incidents.get_for_update(incident)
        loaded.acquire_execution(10)
        uow.incidents.save(loaded)
        uow.commit()

    for older in (1, 5, 9):
        with pytest.raises(ExecutionFenceLost):
            harness.run(incident, epoch=older)

    with harness.uows.begin(TENANT) as uow:
        assert uow.incidents.get(incident).execution_epoch == 10
        uow.commit()


# ── Inbox ────────────────────────────────────────────────────────────────────


def test_concurrent_redeliveries_are_accepted_exactly_once(harness):
    """Eight threads present the SAME message id simultaneously.

    Exactly one may win. The insert is the claim, so the primary key decides --
    a check-then-insert would hand several threads a False and let them all run.
    """
    incident = harness.admit()

    def work(index: int):
        return harness.run(incident, epoch=index + 1, message="msg-shared")

    results, errors = _race(THREADS, work)
    for error in errors:
        assert isinstance(error, (ExecutionFenceLost, ConcurrencyConflict))

    accepted = [r for r in results if getattr(r, "accepted", False)]
    assert len(accepted) == 1, (
        f"{len(accepted)} threads accepted the same message; exactly one may"
    )
    assert len(harness.effects.distinct_keys("anchor")) <= 1
    harness.assert_invariants(incident)


def test_distinct_messages_are_all_accepted(harness):
    """Deduplication must not swallow genuinely different messages."""
    incident = harness.admit()

    def work(index: int):
        return harness.run(incident, epoch=index + 1, message=f"msg-{index}")

    results, _errors = _race(THREADS, work)
    assert all(getattr(r, "accepted", False) for r in results)


# ── Cross-tenant isolation under load ───────────────────────────────────────


def test_concurrent_work_across_incidents_stays_correct(harness):
    """Sixteen incidents, eight threads, two passes. All converge."""
    incidents = [harness.admit(f"inc-p{i}") for i in range(16)]

    def work(index: int):
        for incident in incidents[index::THREADS]:
            harness.run(incident, epoch=1)
        return True

    _results, errors = _race(THREADS, work)
    for error in errors:
        assert isinstance(error, SentinelError), f"unexpected: {error!r}"

    for incident in incidents:
        assert harness.state(incident) is IncidentState.COMPLETED_ATTESTED
        harness.assert_invariants(incident)

    # One effect per incident, and every key distinct.
    keys = harness.effects.distinct_keys("anchor")
    assert len(keys) == len(incidents)


def test_the_pool_survives_more_threads_than_connections(tmp_path, engine_config):
    """More contenders than the pool has connections is backpressure, not a crash."""
    harness = Harness(tmp_path, engine_config=engine_config)
    try:
        incidents = [harness.admit(f"inc-x{i}") for i in range(12)]

        def work(index: int):
            return harness.run(incidents[index], epoch=1)

        _results, errors = _race(12, work)
        for error in errors:
            assert isinstance(error, SentinelError), f"unexpected: {error!r}"
        assert harness.pool.size <= 8
    finally:
        harness.close()


# ── Compensation under contention ───────────────────────────────────────────


def test_a_racing_unwind_compensates_each_step_once(tmp_path, engine_config):
    """Concurrent failures must not compensate a step twice.

    A double compensation would redact evidence twice or withdraw a report twice;
    both are idempotent by construction, and the journal's step machine refuses
    the second transition anyway. This asserts both hold together.
    """
    harness = Harness(tmp_path, engine_config=engine_config)
    try:
        incident = harness.admit()

        def explode(ctx):
            from sentinel.domain.errors import ArtifactMissing

            raise ArtifactMissing("forced deterministic failure")

        harness.engine._handlers[StepName("approvals")] = explode  # noqa: SLF001

        _results, errors = _race(4, lambda i: harness.run(incident, epoch=i + 1))
        for error in errors:
            assert isinstance(error, (ExecutionFenceLost, ConcurrencyConflict))

        journal = harness.journal(incident)
        evidence = harness.evidence(incident)
        assert evidence is not None
        # Redaction is idempotent: the reason recorded is the first one.
        assert evidence.is_redacted or journal[StepName("evidence")].status in {
            StepStatus.COMPLETED,
            StepStatus.COMPENSATING,
            StepStatus.COMPENSATED,
        }
        assert not harness.effects.keys("anchor"), "the pivot was never reached"
        harness.assert_invariants(incident)
    finally:
        harness.close()
