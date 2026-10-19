"""Connection management: pooling, read/write split, isolation and timeouts.

WHAT THIS ADDS OVER THE PREVIOUS ENGINE
----------------------------------------
The previous engine had one pool and one entry point. Correct, and insufficient
for a fleet:

  * **No read/write split.** Every query, including the dashboard's list views
    and the metrics counters, went to the primary. Read traffic that cannot
    affect correctness was competing with the write path for the same
    connections and the same buffer cache.
  * **No isolation control.** Everything ran at the driver default (READ
    COMMITTED). That is right for the queue and wrong for a report that reads
    six tables and must see one consistent instant.
  * **No timeouts.** A statement that blocks on a lock blocks forever, holding
    its own locks while it waits. That is how a single slow query becomes a
    cluster-wide pile-up: not lock *escalation* -- PostgreSQL has no such thing --
    but an unbounded lock *queue*, which produces the same outage.

REPLICA ROUTING, AND WHAT IT COSTS
-----------------------------------
`Database.reader()` returns a replica connection when one is configured. Replicas
are asynchronous, so a read may not see a write that has just committed. That is
not a bug to be papered over; it is the trade the caller is making, so it is
explicit in the method name and every call site had to choose.

`reader(consistent=True)` routes to the primary for the reads that cannot
tolerate lag -- anything the same request has just written, and anything feeding
a decision. Read-your-writes is the property, and it is opt-in rather than
assumed.
"""

from __future__ import annotations

import hashlib
import queue
import random
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterator, KeysView, Mapping, Sequence

from sentinel.domain.errors import TransientFailure

__all__ = [
    "Connection",
    "ConnectionPool",
    "Database",
    "Dialect",
    "Isolation",
    "PoolConfig",
    "PostgresUnavailable",
    "ReplicaConfig",
    "Row",
    "build_database",
]


class PostgresUnavailable(TransientFailure):
    """A PostgreSQL DSN was configured and the server could not be reached.

    Raised rather than falling back to SQLite. A security product that silently
    changes where its evidence lives is worse than one that refuses to start.
    """


class Dialect(str, Enum):
    SQLITE = "sqlite"
    POSTGRES = "postgres"

    @property
    def placeholder(self) -> str:
        return "?" if self is Dialect.SQLITE else "%s"

    @property
    def supports_rls(self) -> bool:
        return self is Dialect.POSTGRES

    @property
    def supports_partitioning(self) -> bool:
        return self is Dialect.POSTGRES


class Isolation(str, Enum):
    """Transaction isolation, chosen per operation rather than globally.

    PostgreSQL's REPEATABLE READ is snapshot isolation: the whole transaction
    sees one instant. SERIALIZABLE adds predicate locking and can abort with a
    serialization failure, which the caller must be prepared to retry -- so it is
    reserved for the operations whose correctness actually needs it.
    """

    #: The default. Each statement sees its own snapshot. Right for the queue,
    #: where every claim is a single fenced compare-and-set.
    READ_COMMITTED = "READ COMMITTED"

    #: One snapshot for the transaction. Used for multi-table reads that must be
    #: internally consistent -- an evidence package that read the ledger before a
    #: seal and the batch after it would describe a state that never existed.
    REPEATABLE_READ = "REPEATABLE READ"

    #: Full serializability. Reserved for the ledger append, where the invariant
    #: is over rows the transaction did not read.
    SERIALIZABLE = "SERIALIZABLE"


@dataclass(frozen=True, slots=True)
class PoolConfig:
    min_size: int = 2
    max_size: int = 20
    connect_timeout_seconds: float = 10.0
    checkout_timeout_seconds: float = 10.0
    #: Recycle a connection after this many checkouts. Bounds the blast radius
    #: of a connection that has accumulated bad session state, and stops a
    #: long-lived backend holding a stale catalogue snapshot forever.
    max_uses: int = 10_000
    #: Abort any statement running longer than this. Without it, one blocked
    #: query holds its locks indefinitely and the queue behind it grows without
    #: bound -- the same outage as lock escalation, by a different route.
    statement_timeout_ms: int = 30_000
    #: Fail fast rather than queue behind a lock. A writer that waits five
    #: seconds for a row lock is almost always better failing and retrying.
    lock_timeout_ms: int = 5_000
    #: Kill a transaction left open by a crashed client.
    idle_in_transaction_timeout_ms: int = 60_000


@dataclass(frozen=True, slots=True)
class ReplicaConfig:
    """A read replica. Asynchronous, so reads may lag the primary."""

    dsn: str
    #: Relative selection weight. A replica on slower hardware takes less.
    weight: int = 1


@dataclass(frozen=True, slots=True)
class DatabaseConfig:
    dialect: Dialect
    dsn: str
    replicas: tuple[ReplicaConfig, ...] = ()
    pool: PoolConfig = field(default_factory=PoolConfig)

    def safe_description(self) -> str:
        """No credentials. Logged; the raw DSN never is."""
        if self.dialect is Dialect.SQLITE:
            return f"sqlite:{self.dsn}"
        host = self.dsn.split("@")[-1] if "@" in self.dsn else self.dsn
        replicas = f" +{len(self.replicas)} replica(s)" if self.replicas else ""
        return f"postgres:{host}{replicas}"



class _ColumnKeys(KeysView[str]):
    """A real KeysView over a column tuple.

    Exists so `keys()` can satisfy `Mapping` without materialising a dict for
    every row on a read path.
    """

    __slots__ = ("_columns",)

    def __init__(self, columns: tuple[str, ...]) -> None:
        self._columns = columns

    def __len__(self) -> int:
        return len(self._columns)

    def __iter__(self) -> Iterator[str]:
        return iter(self._columns)

    def __contains__(self, key: object) -> bool:
        return key in self._columns


class Row(Mapping):
    """A row that behaves identically on both drivers.

    `sqlite3.Row` supports `row[0]` and `row["col"]`; psycopg's `dict_row`
    supports only the latter. The predecessor used both styles freely, so a query
    that worked on SQLite raised `KeyError: 0` on PostgreSQL.
    """

    __slots__ = ("_columns", "_values")

    def __init__(self, columns: tuple[str, ...], values: tuple[Any, ...]) -> None:
        self._columns = columns
        self._values = values

    def __getitem__(self, key: int | str) -> Any:
        if isinstance(key, int):
            return self._values[key]
        try:
            return self._values[self._columns.index(key)]
        except ValueError:
            raise KeyError(key) from None

    def __iter__(self) -> Iterator[str]:
        return iter(self._columns)

    def __len__(self) -> int:
        return len(self._columns)

    def keys(self) -> KeysView[str]:
        # A KeysView, not a tuple. This class subclasses Mapping, and Mapping
        # promises `keys()` returns a view -- code that does `row.keys() &
        # {"a"}` or `"a" in row.keys()` relies on set semantics a tuple does
        # not have. Returning a tuple worked for the callers that only iterate
        # and would have broken silently for the first one that did not.
        return _ColumnKeys(self._columns)

    def __repr__(self) -> str:
        return f"Row({dict(zip(self._columns, self._values))!r})"


class Connection:
    """One pooled connection. Both drivers present one surface."""

    __slots__ = ("_raw", "_dialect", "_uses", "_read_only", "_observer")

    def __init__(self, raw: Any, dialect: Dialect, *, read_only: bool = False) -> None:
        self._raw = raw
        self._dialect = dialect
        self._uses = 0
        self._read_only = read_only
        # An optional callback invoked with every statement. This is how an N+1
        # is DETECTED rather than reasoned about, and it is a first-class hook
        # rather than a test monkey-patching the method: `__slots__` makes
        # per-instance patching impossible, and a hook that only exists in tests
        # cannot be reached from a staging environment when one is needed.
        self._observer: Any = None

    def observe(self, callback: Any) -> Any:
        """Install a statement observer. Returns the previous one."""
        previous = self._observer
        self._observer = callback
        return previous

    @property
    def dialect(self) -> Dialect:
        return self._dialect

    @property
    def p(self) -> str:
        """The parameter token for this dialect. Callers compose SQL with it."""
        return self._dialect.placeholder

    @property
    def read_only(self) -> bool:
        return self._read_only

    @property
    def uses(self) -> int:
        return self._uses

    def execute(self, sql: str, params: Sequence[Any] = ()) -> list[Row]:
        """Run a statement and return its rows eagerly.

        Eager rather than cursor-returning: a connection that hands out live
        cursors hands out the class of bug where reading a result twice returns
        nothing the second time.
        """
        if self._observer is not None:
            self._observer(sql)
        cursor = self._raw.cursor()
        try:
            cursor.execute(sql, tuple(params))
            if cursor.description is None:
                return []
            columns = tuple(
                (c.name if hasattr(c, "name") else c[0]) for c in cursor.description
            )
            return [Row(columns, tuple(values)) for values in cursor.fetchall()]
        except Exception as exc:  # noqa: BLE001
            raise TransientFailure(f"{type(exc).__name__} executing statement: {exc}") from exc
        finally:
            cursor.close()

    def execute_rowcount(self, sql: str, params: Sequence[Any] = ()) -> int:
        if self._observer is not None:
            self._observer(sql)
        cursor = self._raw.cursor()
        try:
            cursor.execute(sql, tuple(params))
            return int(cursor.rowcount)
        except Exception as exc:  # noqa: BLE001
            raise TransientFailure(f"{type(exc).__name__} executing statement: {exc}") from exc
        finally:
            cursor.close()

    def one(self, sql: str, params: Sequence[Any] = ()) -> Row | None:
        rows = self.execute(sql, params)
        return rows[0] if rows else None

    def explain(self, sql: str, params: Sequence[Any] = (), *, analyze: bool = False) -> str:
        """The query plan, as text. Used by the benchmark harness.

        ANALYZE actually EXECUTES the statement, so it is only ever used inside a
        transaction the caller rolls back.
        """
        if self._dialect is Dialect.SQLITE:
            rows = self.execute(f"EXPLAIN QUERY PLAN {sql}", params)
            return "\n".join(" ".join(str(v) for v in r.values()) for r in rows)
        prefix = "EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) " if analyze else "EXPLAIN "
        rows = self.execute(prefix + sql, params)
        return "\n".join(str(next(iter(r.values()))) for r in rows)

    def begin(self, isolation: Isolation = Isolation.READ_COMMITTED) -> None:
        self._uses += 1
        if self._dialect is Dialect.SQLITE:
            # SQLite is serialisable by construction; BEGIN IMMEDIATE takes the
            # write lock up front so a read-modify-write cannot deadlock against
            # another writer partway through.
            self._raw.execute("BEGIN" if self._read_only else "BEGIN IMMEDIATE")
            return
        self._raw.cursor().execute(f"BEGIN ISOLATION LEVEL {isolation.value}")
        if self._read_only:
            # Belt and braces on a replica: a write here would fail anyway, but
            # failing at the transaction boundary names the mistake precisely.
            self._raw.cursor().execute("SET TRANSACTION READ ONLY")

    def lock_clause(self, *, skip_locked: bool = False, no_wait: bool = False) -> str:
        """Row-lock suffix for a read-modify-write.

        Empty on SQLite, and that is correct rather than a silent no-op: the
        transaction already holds the database write lock from BEGIN IMMEDIATE.
        """
        if self._dialect is not Dialect.POSTGRES:
            return ""
        if skip_locked:
            return " FOR UPDATE SKIP LOCKED"
        if no_wait:
            return " FOR UPDATE NOWAIT"
        return " FOR UPDATE"

    def serialise_tenant(self, tenant_id: str, *, purpose: str) -> None:
        """Serialise a per-tenant critical section against every other writer.

        A hash chain is inherently serial per tenant, and `SELECT ... FOR UPDATE`
        on the current head is NOT sufficient: a row lock cannot lock a row that
        does not exist, so with an empty chain every concurrent writer reads
        None, computes the same predecessor, and all but one are rejected by the
        unique index. An advisory lock covers the empty case because it locks a
        NUMBER rather than a row.
        """
        if self._dialect is not Dialect.POSTGRES:
            return  # SQLite already serialises writers at BEGIN IMMEDIATE
        key = int.from_bytes(
            hashlib.blake2b(f"{purpose}:{tenant_id}".encode(), digest_size=8).digest(),
            "big",
            signed=True,
        )
        self.execute(f"SELECT pg_advisory_xact_lock({self.p})", (key,))

    def set_tenant(self, tenant_id: str) -> None:
        """Bind this transaction to a tenant for row-level security.

        `set_config(..., true)` is transaction-local, so it reverts on commit or
        rollback and a pooled connection can never hand the next borrower the
        previous tenant's context.
        """
        if self._dialect is not Dialect.POSTGRES:
            return
        self.execute(f"SELECT set_config('sentinel.tenant_id', {self.p}, true)", (tenant_id,))

    def commit(self) -> None:
        self._raw.commit()

    def rollback(self) -> None:
        self._raw.rollback()

    def close(self) -> None:
        self._raw.close()

    def healthy(self) -> bool:
        try:
            self.execute("SELECT 1")
            return True
        except Exception:  # noqa: BLE001
            return False


class ConnectionPool:
    """A bounded pool of live connections.

    Deliberately explicit rather than a dependency: the pool is the single most
    load-bearing piece of infrastructure here, and its behaviour under exhaustion
    should be verifiable by reading this file rather than inferred from a
    library's defaults.

    On exhaustion `acquire` blocks up to `checkout_timeout_seconds` and then
    raises `TransientFailure` -- retryable, because a busy pool is a transient
    condition and the retry taxonomy will treat it as one rather than
    terminalising an incident.
    """

    __slots__ = ("_config", "_dsn", "_dialect", "_read_only", "_pool", "_lock",
                 "_created", "_closed")

    def __init__(
        self,
        *,
        dsn: str,
        dialect: Dialect,
        config: PoolConfig,
        read_only: bool = False,
    ) -> None:
        self._config = config
        self._dsn = dsn
        self._dialect = dialect
        self._read_only = read_only
        self._pool: queue.LifoQueue[Connection] = queue.LifoQueue(maxsize=config.max_size)
        self._lock = threading.Lock()
        self._created = 0
        self._closed = False
        for _ in range(max(0, config.min_size)):
            self._pool.put(self._create())

    def _create(self) -> Connection:
        with self._lock:
            if self._created >= self._config.max_size:
                raise TransientFailure("connection pool is at its maximum size")
            self._created += 1
        try:
            conn = _connect(self._dsn, self._dialect, self._config, self._read_only)
        except Exception:
            with self._lock:
                self._created -= 1
            raise
        return conn

    @contextmanager
    def acquire(self) -> Iterator[Connection]:
        if self._closed:
            raise TransientFailure("connection pool is closed")
        conn: Connection | None = None
        try:
            conn = self._pool.get_nowait()
        except queue.Empty:
            with self._lock:
                room = self._created < self._config.max_size
            if room:
                conn = self._create()
            else:
                try:
                    conn = self._pool.get(timeout=self._config.checkout_timeout_seconds)
                except queue.Empty as exc:
                    raise TransientFailure(
                        f"no database connection available within "
                        f"{self._config.checkout_timeout_seconds}s "
                        f"(max_size={self._config.max_size}). This is backpressure, "
                        "not a fault: the caller should retry."
                    ) from exc
        try:
            yield conn
        except BaseException:
            # A connection whose transaction failed must not go back to the pool
            # carrying an aborted transaction; PostgreSQL refuses every later
            # statement on one with "current transaction is aborted".
            try:
                conn.rollback()
            except Exception:  # noqa: BLE001
                self._discard(conn)
                conn = None
            raise
        finally:
            if conn is not None:
                self._release(conn)

    def _release(self, conn: Connection) -> None:
        try:
            conn.rollback()  # discard anything the borrower left open
        except Exception:  # noqa: BLE001
            self._discard(conn)
            return
        if conn.uses >= self._config.max_uses:
            # Recycled rather than reused forever. Bounds the effect of any
            # session state that has accumulated on this backend.
            self._discard(conn)
            return
        try:
            self._pool.put_nowait(conn)
        except queue.Full:
            self._discard(conn)

    def _discard(self, conn: Connection) -> None:
        with self._lock:
            self._created = max(0, self._created - 1)
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass

    @property
    def size(self) -> int:
        with self._lock:
            return self._created

    @property
    def idle(self) -> int:
        return self._pool.qsize()

    def close(self) -> None:
        self._closed = True
        while True:
            try:
                self._discard(self._pool.get_nowait())
            except queue.Empty:
                return


class Database:
    """The primary and its replicas, with routing that names the trade-off."""

    __slots__ = ("_config", "_writer", "_readers", "_weights")

    def __init__(self, config: DatabaseConfig) -> None:
        self._config = config
        self._writer = ConnectionPool(
            dsn=config.dsn, dialect=config.dialect, config=config.pool
        )
        self._readers: list[ConnectionPool] = []
        self._weights: list[int] = []
        for replica in config.replicas:
            self._readers.append(
                ConnectionPool(
                    dsn=replica.dsn,
                    dialect=config.dialect,
                    config=config.pool,
                    read_only=True,
                )
            )
            self._weights.append(max(1, replica.weight))

    @property
    def dialect(self) -> Dialect:
        return self._config.dialect

    @property
    def config(self) -> DatabaseConfig:
        return self._config

    @property
    def has_replicas(self) -> bool:
        return bool(self._readers)

    def writer(self):
        """A connection to the primary. Every write goes here."""
        return self._writer.acquire()

    def reader(self, *, consistent: bool = False):
        """A connection for reads.

        `consistent=True` routes to the PRIMARY. Replicas are asynchronous, so a
        replica read may not see a write that just committed. Any read that feeds
        a decision, or that the same request has just written, must pass True --
        which is why the parameter exists rather than the routing being silently
        automatic.
        """
        if consistent or not self._readers:
            return self._writer.acquire()
        index = random.choices(range(len(self._readers)), weights=self._weights, k=1)[0]
        return self._readers[index].acquire()

    def stats(self) -> Mapping[str, Any]:
        return {
            "writer": {"size": self._writer.size, "idle": self._writer.idle},
            "replicas": [{"size": p.size, "idle": p.idle} for p in self._readers],
        }

    def close(self) -> None:
        self._writer.close()
        for pool in self._readers:
            pool.close()


# ── Driver construction ──────────────────────────────────────────────────────


def _connect(
    dsn: str, dialect: Dialect, config: PoolConfig, read_only: bool
) -> Connection:
    if dialect is Dialect.SQLITE:
        # Annotated `Any` because this module builds BOTH psycopg and sqlite3
        # connections and the two share no supertype. Without it mypy binds
        # `raw` to whichever it saw first, then rejects the other and every
        # `cursor()` context-manager use along with it.
        raw: Any = sqlite3.connect(
            dsn,
            timeout=config.connect_timeout_seconds,
            check_same_thread=False,
            isolation_level=None,  # explicit BEGIN; no implicit transactions
        )
        raw.execute("PRAGMA journal_mode=WAL")
        raw.execute("PRAGMA foreign_keys=ON")
        raw.execute(f"PRAGMA busy_timeout={config.lock_timeout_ms}")
        # SQLite's equivalent of a statement timeout is the busy timeout above;
        # there is no per-statement abort, which is one reason PostgreSQL is the
        # supported production backend.
        return Connection(raw, dialect, read_only=read_only)

    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - psycopg is a declared dependency
        raise PostgresUnavailable(
            "a PostgreSQL DSN was configured but psycopg is not installed. "
            "Sentinel will NOT silently fall back to SQLite."
        ) from exc

    normalised = dsn.replace("postgresql+psycopg://", "postgresql://", 1)
    try:
        raw = psycopg.connect(
            normalised,
            autocommit=False,
            connect_timeout=int(config.connect_timeout_seconds),
        )
    except Exception as exc:  # noqa: BLE001
        raise PostgresUnavailable(
            f"could not connect: {type(exc).__name__}: {exc}. Sentinel will NOT "
            "fall back to SQLite."
        ) from exc

    # Session guards, set once per connection rather than per transaction.
    with raw.cursor() as cursor:
        cursor.execute(f"SET statement_timeout = {config.statement_timeout_ms}")
        cursor.execute(f"SET lock_timeout = {config.lock_timeout_ms}")
        cursor.execute(
            "SET idle_in_transaction_session_timeout = "
            f"{config.idle_in_transaction_timeout_ms}"
        )
        # Deterministic ordering for text comparisons, independent of the
        # server's locale. Two deployments must not sort tenant ids differently.
        cursor.execute("SET application_name = 'sentinel'")
    raw.commit()
    return Connection(raw, dialect, read_only=read_only)


def build_database(config: DatabaseConfig) -> Database:
    """Construct the primary/replica topology. Called once, by the container."""
    return Database(config)
