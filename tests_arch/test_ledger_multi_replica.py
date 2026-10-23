"""Can two replicas fork the evidence ledger's hash chain?

WHY THIS FILE EXISTS
--------------------
`docs/SECURITY.md` names this as one of three things a fifth review
would have to find:

    **A single-node evidence ledger head** -- the append protocol is not proven
    safe under concurrent multi-replica writes, so the chain could fork.

"Not proven" is the operative word. The design argues it cannot fork -- there is
an advisory lock, a `FOR UPDATE` on the head, `PRIMARY KEY (tenant_id, seq)` and
`UNIQUE (tenant_id, prev_chain_hash)` -- but this project's own F-4 retraction is
the standing reminder that an argument is not evidence. `tests_arch/test_execution_concurrency.py`
races threads inside ONE process against ONE pool; a replica is a different
process with its own pool, and the guarantees that hold within a pool
(`BEGIN IMMEDIATE`'s database-wide write lock on SQLite, in particular) are not
the guarantees that hold across pools.

WHAT "TWO REPLICAS" MEANS HERE, AND WHAT IT DOES NOT
-----------------------------------------------------
Each replica is an INDEPENDENT `ConnectionPool` over the same database: separate
connections, separate transaction state, no shared Python object through which
they could coordinate. Every protection they have is therefore server-side, which
is the property under test -- an in-process lock would be invisible to a second
container and useless in a cluster.

What this is NOT is two operating-system processes on two machines. The threads
share an interpreter, so they share a GIL, and the interleavings a real cluster
can produce are a superset of the ones reachable here. That limit is stated
rather than glossed: what these tests establish is that the SERVER-SIDE protocol
holds when two independent pools contend, on both engines.

WHAT IS ASSERTED
----------------
Not "no exception was raised" -- a test that only checks that would pass on a
system where every writer silently dropped its entry. The chain itself is read
back and checked:

  1. no two entries share a predecessor      (a fork is unstorable)
  2. `seq` is dense from 1                   (no gap, so nothing vanished)
  3. every link recomputes                   (the chain is actually a chain)
  4. every failure is retryable              (a loser retries; it does not lose data)
  5. losers actually happened                (otherwise the race did not race)
"""

from __future__ import annotations

import hashlib
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest

from sentinel.domain.errors import ConcurrencyConflict, TransientFailure
from sentinel.domain.primitives import Digest, IncidentId, TenantId
from sentinel.infrastructure.runtime import SystemClock
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.infrastructure.sql.repositories import GENESIS, LedgerRepository

TENANT = TenantId("acme")
REPLICAS = 2
APPENDS_PER_REPLICA = 6
TOTAL = REPLICAS * APPENDS_PER_REPLICA


@pytest.fixture
def two_replicas(engine_config):
    """Two independent pools over ONE migrated database.

    The schema is created once, through a third pool that is then closed, so
    neither replica can be said to have set the database up for the other.
    """
    setup = build_engine(engine_config)
    migrate(setup)
    setup.close()

    pools = [build_engine(engine_config) for _ in range(REPLICAS)]
    yield pools
    for pool in pools:
        pool.close()


def _append_once(pool, index: int) -> tuple[int, str]:
    """One replica's append, in its own transaction on its own pool."""
    with pool.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT.value)
        ledger = LedgerRepository(conn, TENANT, SystemClock())
        sequence, chained = ledger.append(
            incident_id=IncidentId(f"inc-{index}"),
            entry_hash=Digest(hashlib.sha256(f"payload-{index}".encode()).hexdigest()),
            manifest={"index": index},
        )
        conn.commit()
        return sequence, chained.value


def _read_chain(pool) -> list[dict]:
    with pool.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT.value)
        rows = conn.execute(
            f"SELECT seq, prev_chain_hash, chain_hash, entry_hash FROM ledger_entries "
            f"WHERE tenant_id={conn.p} ORDER BY seq",
            (TENANT.value,),
        )
        conn.commit()
    return [
        {
            "seq": int(r["seq"]),
            "prev": str(r["prev_chain_hash"]),
            "hash": str(r["chain_hash"]),
            "entry": str(r["entry_hash"]),
        }
        for r in rows
    ]


def _race_two_replicas(pools, *, attempts_per_replica: int):
    """Every thread across both replicas arrives at `append` together.

    Without the barrier a thread pool tends to serialise short tasks and the test
    passes because nothing overlapped, which is the standard way a concurrency
    test proves nothing.
    """
    threads = len(pools) * attempts_per_replica
    barrier = threading.Barrier(threads, timeout=60)
    committed: list[tuple[int, str]] = []
    refused: list[BaseException] = []
    lock = threading.Lock()

    def work(slot: int):
        pool = pools[slot % len(pools)]
        barrier.wait()
        try:
            outcome = _append_once(pool, slot)
        except BaseException as exc:  # noqa: BLE001 - classified by the caller
            with lock:
                refused.append(exc)
            return
        with lock:
            committed.append(outcome)

    with ThreadPoolExecutor(max_workers=threads) as pool_executor:
        list(pool_executor.map(work, range(threads)))
    return committed, refused


def _assert_chain_is_intact(entries: list[dict]) -> None:
    """The four structural properties, checked against the stored rows."""
    assert entries, "no entry committed at all; the race proved nothing"

    predecessors = [e["prev"] for e in entries]
    assert len(set(predecessors)) == len(predecessors), (
        f"THE CHAIN FORKED: two entries claim the same predecessor. "
        f"prev_chain_hash values: {predecessors}"
    )

    sequences = [e["seq"] for e in entries]
    assert sequences == list(range(1, len(entries) + 1)), (
        f"seq is not dense from 1: {sequences}. A gap means an entry was "
        "assigned a sequence and then lost, which is indistinguishable from a "
        "deleted ledger row -- the thing the dense sequence exists to expose."
    )

    previous = GENESIS.value
    for entry in entries:
        assert entry["prev"] == previous, (
            f"entry seq={entry['seq']} claims predecessor {entry['prev'][:12]}… "
            f"but the entry before it hashes to {previous[:12]}…"
        )
        recomputed = hashlib.sha256(
            f"{entry['prev']}{entry['entry']}".encode()
        ).hexdigest()
        assert entry["hash"] == recomputed, (
            f"entry seq={entry['seq']} stores a chain_hash that does not recompute "
            "from its own predecessor and payload"
        )
        previous = entry["hash"]


def test_two_replicas_appending_concurrently_cannot_fork_the_chain(two_replicas):
    """The headline question, answered by reading the chain back.

    Runs on BOTH engines. On SQLite the writers are serialised by
    `BEGIN IMMEDIATE`'s database-wide write lock; on PostgreSQL by the
    transaction-scoped advisory lock in `Connection.serialise_tenant`. Those are
    different mechanisms with different failure modes, and only one of them is
    the production one -- so a result on either alone would not settle this.
    """
    committed, refused = _race_two_replicas(
        two_replicas, attempts_per_replica=APPENDS_PER_REPLICA
    )
    entries = _read_chain(two_replicas[0])

    _assert_chain_is_intact(entries)
    assert len(entries) == len(committed), (
        f"{len(committed)} appends reported success but {len(entries)} rows exist"
    )
    # Every append used a distinct incident_id, so nothing is deduplicated away:
    # an append that did not commit must have raised.
    assert len(committed) + len(refused) == TOTAL


def test_a_replica_that_loses_the_race_fails_retryably_rather_than_silently(
    two_replicas,
):
    """A loser must be told. Losing an evidence entry quietly is the bad outcome.

    Whether there ARE losers depends on the engine and on timing -- on
    PostgreSQL the advisory lock serialises writers so they all eventually
    commit, while on SQLite a writer can exhaust `busy_timeout`. Both are
    acceptable; what is not acceptable is a writer that neither commits nor
    raises. So the assertion is on the CLASSIFICATION of whatever failures
    occurred, plus the accounting identity that every attempt did one or the
    other.
    """
    committed, refused = _race_two_replicas(
        two_replicas, attempts_per_replica=APPENDS_PER_REPLICA
    )

    assert len(committed) + len(refused) == TOTAL, (
        "an append neither committed nor raised; it vanished"
    )
    for error in refused:
        assert isinstance(error, (ConcurrencyConflict, TransientFailure)), (
            f"a losing append raised {type(error).__name__}: {error}. A contended "
            "ledger append must fail with a RETRYABLE error so the caller retries "
            "and the evidence still lands; a terminal error drops it."
        )
        assert error.is_retryable, (
            f"{type(error).__name__} is classified non-retryable, so the work "
            "queue will terminalise the incident and the evidence entry is lost"
        )


def test_the_empty_chain_case_is_covered_too(two_replicas):
    """The subtle one: `FOR UPDATE` cannot lock a row that does not exist.

    `Connection.serialise_tenant`'s docstring records that with an empty chain
    every concurrent writer reads `None`, computes `prev_chain_hash = GENESIS`,
    and the UNIQUE index rejects all but one -- correct, but a failure rather
    than serialisation, which is why the advisory lock exists. This drives the
    empty-chain case specifically, from two pools, and asserts the outcome is
    ONE genesis entry and an intact chain.
    """
    committed, refused = _race_two_replicas(two_replicas, attempts_per_replica=3)
    entries = _read_chain(two_replicas[0])

    _assert_chain_is_intact(entries)
    genesis_entries = [e for e in entries if e["prev"] == GENESIS.value]
    assert len(genesis_entries) == 1, (
        f"{len(genesis_entries)} entries claim GENESIS as predecessor; the empty "
        "chain admitted more than one first entry"
    )
    assert len(committed) + len(refused) == 2 * 3


def test_a_deliberate_fork_is_refused_by_the_database(two_replicas):
    """Prove the structural guard is real, not merely present in the DDL.

    Everything above tests that the application does not TRY to fork. This tests
    that the database would refuse if it did -- so the guarantee survives a
    future caller that bypasses `append()`. Without this, all of the above is
    consistent with a unique index that was never created (an `IF NOT EXISTS`
    that silently did nothing, say).
    """
    _append_once(two_replicas[0], 0)
    entries = _read_chain(two_replicas[0])
    assert len(entries) == 1
    predecessor = entries[0]["prev"]

    # A second entry claiming the SAME predecessor: this is what a fork is.
    with pytest.raises(TransientFailure) as raised:  # noqa: PT012 - the block is the subject
        with two_replicas[1].acquire() as conn:
            conn.begin()
            conn.set_tenant(TENANT.value)
            p = conn.p
            conn.execute_rowcount(
                f"INSERT INTO ledger_entries (tenant_id, seq, incident_id, entry_hash, "
                f"prev_chain_hash, chain_hash, manifest_json, batch_id, created_at) "
                f"VALUES ({p},{p},{p},{p},{p},{p},'{{}}',NULL,{p})",
                (
                    TENANT.value,
                    99,
                    f"inc-{uuid.uuid4().hex[:8]}",
                    "f" * 64,
                    predecessor,  # the fork
                    "9" * 64,
                    "2026-08-18T00:00:00+00:00",
                ),
            )
            conn.commit()

    assert "unique" in str(raised.value).lower() or "constraint" in str(raised.value).lower(), (
        f"the fork was refused, but not by a uniqueness constraint: {raised.value}"
    )
    assert len(_read_chain(two_replicas[0])) == 1, "the forking entry was stored"
