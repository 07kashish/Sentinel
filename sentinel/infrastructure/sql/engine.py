"""Database engine: dialect, connection pool, and the tenant-scoped session.

THE TWO DEFECTS THIS IS SHAPED AGAINST
--------------------------------------

**1. There was no connection pool.**

The predecessor's `db._connect()` called `psycopg.connect(dsn, ...)` and
`conn.close()` on every single database operation -- a TCP connection, TLS
handshake, PostgreSQL authentication and backend process fork, per query. Every
authenticated API request cost at least three of them (a `tenants` upsert on the
auth path, a rate-limit row lock, and the route's own query), and a single queue
dequeue at 1,000 tenants cost 1,002.

At a modest 100 requests/second that is 300 new backends per second. PostgreSQL's
default `max_connections` of 100 is exhausted in well under a second of normal
traffic, at which point every `_connect` raises, the readiness probe fails too,
and Kubernetes removes every pod from service simultaneously. The system did not
degrade under load; it disappeared.

**2. SQL was translated between dialects with regular expressions.**

`to_postgres()` ended with `out.replace("?", "%s")` -- a blind textual
substitution across the whole statement, including inside string literals. It
worked only because no query in that codebase happened to contain a literal `?`
or `%`. It was correct by coincidence of the current query set, not by
construction: a future `LIKE '%foo%'` would have broken parameter binding
silently, and `RETURNING seq` was appended whenever the substring
`"ledger_entries"` appeared anywhere in a statement, comments included.

Here there is no translation. Each dialect states its own placeholder token and
callers compose SQL with it. Nothing scans or rewrites a statement, so nothing
can rewrite the wrong part of one.
"""

from __future__ import annotations

import hashlib
import queue
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterator, KeysView, Mapping, Sequence

from sentinel.domain.errors import TransientFailure

__all__ = [
    "Connection",
    "ConnectionPool",
    "Dialect",
    "EngineConfig",
    "PostgresUnavailable",
    "Row",
    "build_engine",
]


class PostgresUnavailable(TransientFailure):
    """A PostgreSQL URL was configured and the server could not be reached.

    Raised rather than falling back to SQLite. A security product that silently
    changes where its evidence lives is worse than one that refuses to start.
    """


class Dialect(str, Enum):
    SQLITE = "sqlite"
    POSTGRES = "postgres"

    @property
    def placeholder(self) -> str:
        """The parameter token. Callers compose SQL with this, never with `?`."""
        return "?" if self is Dialect.SQLITE else "%s"

    @property
    def supports_rls(self) -> bool:
        return self is Dialect.POSTGRES

    @property
    def supports_skip_locked(self) -> bool:
        return self is Dialect.POSTGRES


@dataclass(frozen=True, slots=True)
class EngineConfig:
    """Everything needed to reach the database. Injected, never read from env here."""

    dialect: Dialect
    dsn: str
    pool_min: int = 2
    pool_max: int = 20
    connect_timeout_seconds: float = 10.0
    checkout_timeout_seconds: float = 10.0

    def safe_description(self) -> str:
        """A description with no credentials in it. Logged; never the raw DSN."""
        if self.dialect is Dialect.SQLITE:
            return f"sqlite:{self.dsn}"
        host = self.dsn.split("@")[-1] if "@" in self.dsn else self.dsn
        return f"postgres:{host}"



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
    supports only the latter and its `tuple_row` only the former. The predecessor
    used both styles freely, so a query that worked on SQLite raised `KeyError: 0`
    on PostgreSQL -- found by the first live-server run and by no unit test.
    Both drivers yield THIS type, so the divergence has nowhere to appear.
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
    """One pooled connection, wrapped so both drivers present one surface."""

    __slots__ = ("_raw", "_dialect", "_in_transaction")

    def __init__(self, raw: Any, dialect: Dialect) -> None:
        self._raw = raw
        self._dialect = dialect
        self._in_transaction = False

    @property
    def dialect(self) -> Dialect:
        return self._dialect

    @property
    def p(self) -> str:
        """The placeholder token for this dialect."""
        return self._dialect.placeholder

    def execute(self, sql: str, params: Sequence[Any] = ()) -> list[Row]:
        """Run a statement. Returns rows (empty for non-SELECT).

        Fetching eagerly rather than returning a cursor is deliberate: the
        predecessor's `Cursor.lastrowid` called `fetchone()` on PostgreSQL to
        read an appended `RETURNING`, which consumed a row, so reading it twice
        returned None the second time. A connection that hands out live cursors
        hands out that class of bug.
        """
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
            raise TransientFailure(
                f"{type(exc).__name__} executing statement: {exc}"
            ) from exc
        finally:
            cursor.close()

    def execute_rowcount(self, sql: str, params: Sequence[Any] = ()) -> int:
        cursor = self._raw.cursor()
        try:
            cursor.execute(sql, tuple(params))
            return int(cursor.rowcount)
        except Exception as exc:  # noqa: BLE001
            raise TransientFailure(
                f"{type(exc).__name__} executing statement: {exc}"
            ) from exc
        finally:
            cursor.close()

    def one(self, sql: str, params: Sequence[Any] = ()) -> Row | None:
        rows = self.execute(sql, params)
        return rows[0] if rows else None

    def begin(self) -> None:
        if self._dialect is Dialect.SQLITE:
            self._raw.execute("BEGIN IMMEDIATE")
        self._in_transaction = True

    def lock_clause(self, *, skip_locked: bool = False) -> str:
        """Row-lock suffix for a SELECT inside a read-modify-write.

        On SQLite the transaction already holds the database write lock from
        `BEGIN IMMEDIATE`, so this is empty and that is CORRECT rather than a
        no-op that leaves the write unprotected -- the difference the
        predecessor's `begin_immediate()` blurred, where callers that used it
        without `lock_suffix()` had no lock at all on PostgreSQL.
        """
        if self._dialect is not Dialect.POSTGRES:
            return ""
        return " FOR UPDATE SKIP LOCKED" if skip_locked else " FOR UPDATE"

    def serialise_tenant(self, tenant_id: str, *, purpose: str) -> None:
        """Serialise a per-tenant append against every other writer.

        A hash chain is inherently serial per tenant: entry N+1 commits to N, so
        two concurrent appends cannot both be correct. `SELECT ... FOR UPDATE` on
        the current head is NOT sufficient, and the reason is subtle enough that
        it survived a full test suite:

            **A row lock cannot lock a row that does not exist.** With an empty
            chain there is no head to lock, so every concurrent writer reads
            `None`, every one computes `prev_chain_hash = GENESIS`, and the
            UNIQUE index rejects all but one. The chain stays correct -- a fork is
            unstorable -- but the losers fail instead of serialising.

        SQLite hid this completely: `BEGIN IMMEDIATE` takes a database-wide write
        lock, so its writers were already serialised for unrelated reasons. The
        defect was PostgreSQL-only and was found by running the concurrency suite
        on both engines.

        A transaction-scoped advisory lock covers the empty case because it locks
        a NUMBER, not a row. It is released automatically at commit or rollback,
        so a crashed worker cannot strand it.
        """
        if self._dialect is not Dialect.POSTGRES:
            # SQLite already serialises every writer at BEGIN IMMEDIATE.
            return
        key = int.from_bytes(
            hashlib.blake2b(
                f"{purpose}:{tenant_id}".encode("utf-8"), digest_size=8
            ).digest(),
            "big",
            signed=True,
        )
        self.execute(f"SELECT pg_advisory_xact_lock({self.p})", (key,))

    def set_tenant(self, tenant_id: str) -> None:
        """Bind this transaction to a tenant for row-level security.

        `set_config(..., true)` is transaction-local, so it reverts on commit or
        rollback and a pooled connection can never hand the next borrower the
        previous tenant's context -- the classic way session-scoped tenant state
        becomes a cross-tenant read.
        """
        if self._dialect is not Dialect.POSTGRES:
            return
        self.execute(
            f"SELECT set_config('sentinel.tenant_id', {self.p}, true)", (tenant_id,)
        )

    def set_worker_scope(self) -> None:
        """Declare this transaction a cross-tenant WORKER scan.

        The only writer of `sentinel.worker_scope`, and the only value it
        writes. Tables in `schema.WORKER_SCOPED_TABLES` carry a policy that
        admits rows under this setting; nothing else does, so a caller that
        sets it on a transaction touching `incidents` gains nothing.

        Transaction-local for the same reason `set_tenant` is: a pooled
        connection must not hand the next borrower a scope it did not ask for.
        Callers set it explicitly, per statement group, on the queue's
        cross-tenant paths -- never in `acquire()`, never by default.
        """
        if self._dialect is not Dialect.POSTGRES:
            return
        self.execute("SELECT set_config('sentinel.worker_scope', 'all', true)")

    def commit(self) -> None:
        self._raw.commit()
        self._in_transaction = False

    def rollback(self) -> None:
        self._raw.rollback()
        self._in_transaction = False

    def close(self) -> None:
        self._raw.close()

    def ping(self) -> bool:
        try:
            self.execute("SELECT 1")
            return True
        except Exception:  # noqa: BLE001
            return False


class ConnectionPool:
    """A bounded pool of live connections.

    Deliberately small and explicit rather than a dependency: the pool is the
    single most load-bearing piece of infrastructure in the system, and its
    behaviour under exhaustion needs to be one that a reader can verify in the
    file rather than infer from a library's defaults.

    On exhaustion `acquire` blocks up to `checkout_timeout_seconds` and then
    raises `TransientFailure` -- retryable, because a busy pool is a transient
    condition, and the retry taxonomy will treat it as such rather than
    terminalising the incident.
    """

    __slots__ = ("_config", "_factory", "_pool", "_lock", "_created", "_closed")

    def __init__(self, config: EngineConfig, factory: Any) -> None:
        self._config = config
        self._factory = factory
        self._pool: queue.LifoQueue[Connection] = queue.LifoQueue(maxsize=config.pool_max)
        self._lock = threading.Lock()
        self._created = 0
        self._closed = False
        for _ in range(max(0, config.pool_min)):
            self._pool.put(self._create())

    def _create(self) -> Connection:
        with self._lock:
            if self._created >= self._config.pool_max:
                raise TransientFailure("connection pool is at its maximum size")
            self._created += 1
        try:
            return self._factory(self._config)
        except Exception:
            with self._lock:
                self._created -= 1
            raise

    @contextmanager
    def acquire(self) -> Iterator[Connection]:
        if self._closed:
            raise TransientFailure("connection pool is closed")
        conn: Connection | None = None
        try:
            conn = self._pool.get_nowait()
        except queue.Empty:
            with self._lock:
                room = self._created < self._config.pool_max
            if room:
                conn = self._create()
            else:
                try:
                    conn = self._pool.get(timeout=self._config.checkout_timeout_seconds)
                except queue.Empty as exc:
                    raise TransientFailure(
                        f"no database connection available within "
                        f"{self._config.checkout_timeout_seconds}s "
                        f"(pool_max={self._config.pool_max}). This is backpressure, "
                        "not a fault: the caller should retry."
                    ) from exc
        try:
            yield conn
        except BaseException:
            # A connection whose transaction failed must not be returned to the
            # pool carrying an aborted transaction; PostgreSQL refuses every
            # subsequent statement on one with "current transaction is aborted".
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


# ── Driver factories ─────────────────────────────────────────────────────────


def _sqlite_factory(config: EngineConfig) -> Connection:
    raw = sqlite3.connect(
        config.dsn,
        timeout=config.connect_timeout_seconds,
        check_same_thread=False,
        isolation_level=None,  # explicit BEGIN IMMEDIATE; no implicit transactions
    )
    raw.execute("PRAGMA journal_mode=WAL")
    raw.execute("PRAGMA foreign_keys=ON")
    raw.execute("PRAGMA busy_timeout=10000")
    return Connection(raw, Dialect.SQLITE)


def _postgres_factory(config: EngineConfig) -> Connection:
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - psycopg is a declared dependency
        raise PostgresUnavailable(
            "a PostgreSQL DSN was configured but psycopg is not installed. "
            "Sentinel will NOT silently fall back to SQLite."
        ) from exc
    dsn = config.dsn.replace("postgresql+psycopg://", "postgresql://", 1)
    try:
        raw = psycopg.connect(
            dsn, autocommit=False, connect_timeout=int(config.connect_timeout_seconds)
        )
    except Exception as exc:  # noqa: BLE001
        raise PostgresUnavailable(
            f"could not connect to {config.safe_description()}: "
            f"{type(exc).__name__}: {_scrubbed(str(exc), dsn)}. Sentinel will NOT fall back to SQLite."
        ) from exc
    return Connection(raw, Dialect.POSTGRES)


def _scrubbed(message: str, dsn: str) -> str:
    """The driver's message with every credential-bearing part of the DSN removed.

    psycopg quotes the offending token when it cannot parse a URL -- for a
    password it cannot percent-decode, the token IS the password. The first
    real deployment wrote one into CloudWatch that way. The password, its
    encoded and decoded forms, the userinfo and the whole DSN are all
    replaced before the message goes anywhere.
    """
    import urllib.parse

    try:
        parts = urllib.parse.urlsplit(dsn)
    except ValueError:
        return "<driver message withheld: the DSN could not be parsed for scrubbing>"
    secrets = [dsn]
    if parts.username or parts.password:
        secrets.append(f"{parts.username or ''}:{parts.password or ''}")
    for value in (parts.password, parts.username):
        if value:
            secrets.extend({value, urllib.parse.unquote(value), urllib.parse.quote(value, safe="")})
    for secret in sorted(set(secrets), key=len, reverse=True):
        if len(secret) >= 4:
            message = message.replace(secret, "***")
    return message


def build_engine(config: EngineConfig) -> ConnectionPool:
    """Construct the pool for a configured engine. Called once, by the container."""
    factory = _sqlite_factory if config.dialect is Dialect.SQLITE else _postgres_factory
    return ConnectionPool(config, factory)
