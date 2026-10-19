"""Migration framework: ordered, checksummed, reversible, and singly-applied.

WHAT THE PREVIOUS RUNNER LACKED
--------------------------------
It applied an ordered list of callables and recorded a version integer. That is
enough to move a schema forward on one machine and not enough to run a fleet:

  * **No checksum.** A migration edited after release applied differently on a
    fresh database than on an upgraded one, and nothing detected the divergence.
    The two deployments then disagreed about their schema while both reported
    the same version.
  * **No lock.** Three replicas starting together all ran the pending set. Most
    DDL is transactional on PostgreSQL so the losers rolled back, but `CREATE
    INDEX CONCURRENTLY` is not, and neither is a data backfill.
  * **No down path.** A bad release could only be rolled forward, which is the
    worst moment to be writing a migration.
  * **No separation of DDL from backfill.** A migration that adds a column and
    rewrites ten million rows in one transaction holds locks for the duration of
    the rewrite.

THE MODEL
---------
A migration is a dataclass with an `up`, an optional `down`, and a declared
`concurrency` mode:

    TRANSACTIONAL   wrapped in BEGIN/COMMIT; the default and almost always right
    AUTOCOMMIT      for statements PostgreSQL forbids in a transaction, chiefly
                    CREATE INDEX CONCURRENTLY and ALTER TYPE ... ADD VALUE

The runner takes a session-scoped advisory lock for the whole run, so exactly
one process migrates however many start at once. The lock is released when the
connection closes, including on a crash, so a dead migrator cannot wedge a
deployment.

Checksums are over the migration's own SQL text. A change to an applied
migration is refused at startup with the two checksums printed, rather than
discovered as a behavioural difference weeks later.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Sequence

from sentinel.domain.errors import SentinelError
from sentinel.infrastructure.persistence.engine import Connection, Database, Dialect

__all__ = [
    "Concurrency",
    "Migration",
    "MigrationError",
    "MigrationRunner",
    "SchemaDrift",
]

#: Migrations legitimately wait for an ACCESS EXCLUSIVE lock, unlike ordinary
#: writers. Bounded so a migration still cannot wedge a cluster forever.
MIGRATION_LOCK_TIMEOUT_MS = 60_000

#: A stable 63-bit key for `pg_advisory_lock`. Derived from a fixed string so
#: every replica of every version computes the same number.
_LOCK_KEY = int.from_bytes(
    hashlib.blake2b(b"sentinel.schema.migration", digest_size=8).digest(),
    "big",
    signed=True,
)


class MigrationError(SentinelError):
    """A migration could not be applied. Deterministic: never retried blindly."""

    is_retryable = False


class SchemaDrift(MigrationError):
    """An applied migration's text has changed since it was applied.

    Raised rather than reconciled. The two databases now differ in a way their
    recorded version does not express, and guessing which is correct is how a
    fleet ends up with three shapes and one version number.
    """


class Concurrency(str, Enum):
    """How a migration must be executed."""

    #: Wrapped in a transaction. Rolls back cleanly on failure.
    TRANSACTIONAL = "transactional"

    #: Run outside a transaction. Required for CREATE INDEX CONCURRENTLY and
    #: ALTER TYPE ... ADD VALUE, which PostgreSQL refuses inside one. A failure
    #: here leaves partial work, so such a migration must be idempotent -- which
    #: `MigrationRunner` asserts by requiring an `is_applied` probe.
    AUTOCOMMIT = "autocommit"


@dataclass(frozen=True, slots=True)
class Migration:
    """One ordered, checksummed schema change."""

    version: int
    name: str
    up: tuple[str, ...]
    down: tuple[str, ...] = ()
    concurrency: Concurrency = Concurrency.TRANSACTIONAL
    #: Dialects this migration applies to. A migration using PostgreSQL-only
    #: syntax declares POSTGRES and is skipped elsewhere, rather than failing.
    dialects: tuple[Dialect, ...] = (Dialect.POSTGRES, Dialect.SQLITE)
    #: For AUTOCOMMIT migrations: a query returning one row if already applied.
    #: Required, because a non-transactional migration that fails halfway must be
    #: safe to re-run.
    is_applied: str | None = None

    def __post_init__(self) -> None:
        if self.version < 1:
            raise MigrationError(f"migration version must be >= 1, got {self.version}")
        if not self.up:
            raise MigrationError(f"migration {self.version} has no statements")
        if self.concurrency is Concurrency.AUTOCOMMIT and not self.is_applied:
            raise MigrationError(
                f"migration {self.version} ({self.name}) runs outside a transaction "
                "and must declare `is_applied`: a non-transactional migration can "
                "fail halfway, so re-running it has to be safe."
            )

    @property
    def checksum(self) -> str:
        """SHA-256 over the statements. Changing one changes this."""
        joined = "\n".join(s.strip() for s in self.up)
        return hashlib.sha256(joined.encode("utf-8")).hexdigest()

    @property
    def reversible(self) -> bool:
        return bool(self.down)

    def applies_to(self, dialect: Dialect) -> bool:
        return dialect in self.dialects


@dataclass
class MigrationRunner:
    """Applies pending migrations under a cluster-wide lock."""

    database: Database
    migrations: Sequence[Migration]

    def __post_init__(self) -> None:
        versions = [m.version for m in self.migrations]
        if len(set(versions)) != len(versions):
            duplicated = sorted({v for v in versions if versions.count(v) > 1})
            raise MigrationError(f"duplicate migration versions: {duplicated}")
        if versions != sorted(versions):
            raise MigrationError(
                "migrations must be declared in ascending version order; found "
                f"{versions}"
            )

    # ── Public API ───────────────────────────────────────────────────────────

    @property
    def target_version(self) -> int:
        applicable = [m for m in self.migrations if m.applies_to(self.database.dialect)]
        return max((m.version for m in applicable), default=0)

    def current_version(self, conn: Connection | None = None) -> int:
        """The highest applied version.

        Takes an optional connection so a caller already holding one can reuse
        it. Opening a second connection while the first holds uncommitted DDL is
        how this deadlocked: `CREATE TABLE IF NOT EXISTS schema_migrations` on
        connection A takes a lock on `pg_type`, and the same statement on
        connection B waits for it until `lock_timeout` fires. The benchmark suite
        found it; a single-connection test never would.
        """
        if conn is not None:
            self._ensure_ledger(conn)
            row = conn.one("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations")
            return int(row["v"]) if row else 0
        with self.database.writer() as owned:
            owned.begin()
            self._ensure_ledger(owned)
            row = owned.one("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations")
            owned.commit()
        return int(row["v"]) if row else 0

    def upgrade(self, *, to: int | None = None) -> int:
        """Apply every pending migration. Returns the resulting version."""
        ceiling = self.target_version if to is None else to
        with self.database.writer() as lock_conn:
            self._acquire(lock_conn)
            try:
                lock_conn.begin()
                self._verify_checksums(lock_conn)
                applied = self.current_version(lock_conn)
                # COMMITTED before any migration runs. The ledger DDL above takes
                # catalogue locks, and the per-migration connections below would
                # block on them until `lock_timeout` fired.
                lock_conn.commit()
                for migration in self.migrations:
                    if migration.version <= applied or migration.version > ceiling:
                        continue
                    if not migration.applies_to(self.database.dialect):
                        continue
                    self._apply(migration)
            finally:
                self._release(lock_conn)
        return self.current_version()

    def downgrade(self, *, to: int) -> int:
        """Roll back to `to`, newest first. Refuses an irreversible migration."""
        with self.database.writer() as lock_conn:
            self._acquire(lock_conn)
            try:
                lock_conn.begin()
                applied = self.current_version(lock_conn)
                lock_conn.commit()
                pending = [
                    m
                    for m in reversed(self.migrations)
                    if to < m.version <= applied and m.applies_to(self.database.dialect)
                ]
                irreversible = [m for m in pending if not m.reversible]
                if irreversible:
                    raise MigrationError(
                        "cannot roll back past irreversible migration(s): "
                        + ", ".join(f"{m.version} ({m.name})" for m in irreversible)
                        + ". A migration that drops data declares no `down` on "
                        "purpose; restore from a backup instead of pretending the "
                        "data can be reconstructed."
                    )
                for migration in pending:
                    self._revert(migration)
            finally:
                self._release(lock_conn)
        return self.current_version()

    def verify(self) -> int:
        """Assert the schema is exactly the expected version. O(1).

        Safe at startup: one indexed read, no DDL, no scan. The application
        refuses to serve against an unexpected schema rather than discovering the
        mismatch mid-incident.
        """
        found = self.current_version()
        if found != self.target_version:
            raise MigrationError(
                f"database schema is at version {found}, this build requires "
                f"{self.target_version}. Run `python -m sentinel.interface.cli "
                "migrate` before starting. Refusing to serve against an "
                "unverified schema is deliberate."
            )
        with self.database.writer() as conn:
            conn.begin()
            self._verify_checksums(conn)
            conn.commit()
        return found

    def pending(self) -> list[Migration]:
        applied = self.current_version()
        return [
            m
            for m in self.migrations
            if m.version > applied and m.applies_to(self.database.dialect)
        ]

    # ── Internals ────────────────────────────────────────────────────────────

    def _acquire(self, conn: Connection) -> None:
        """Take the cluster-wide migration lock, and relax the lock timeout.

        The pool sets a short `lock_timeout` so ordinary writers fail fast rather
        than queue. A migration is the one operation that legitimately WAITS: it
        needs an ACCESS EXCLUSIVE lock, and failing after five seconds because a
        read was in flight would make deployments flaky. The relaxed value is
        still bounded, so a migration cannot block a cluster indefinitely.

        The advisory lock is session-scoped, so it survives the per-migration
        transactions below and is released automatically if this process dies --
        no stale-lock cleanup and no TTL to guess.
        """
        if conn.dialect is not Dialect.POSTGRES:
            return  # SQLite serialises writers at the database level already
        conn.execute_rowcount(f"SET lock_timeout = {MIGRATION_LOCK_TIMEOUT_MS}")
        conn.execute(f"SELECT pg_advisory_lock({conn.p})", (_LOCK_KEY,))
        conn.commit()

    def _release(self, conn: Connection) -> None:
        if conn.dialect is not Dialect.POSTGRES:
            return
        conn.execute(f"SELECT pg_advisory_unlock({conn.p})", (_LOCK_KEY,))
        conn.commit()

    def _relax_lock_timeout(self, conn: Connection) -> None:
        if conn.dialect is Dialect.POSTGRES:
            conn.execute_rowcount(f"SET lock_timeout = {MIGRATION_LOCK_TIMEOUT_MS}")
            conn.commit()

    def _ensure_ledger(self, conn: Connection) -> None:
        conn.execute_rowcount(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "  version    INTEGER PRIMARY KEY,"
            "  name       TEXT NOT NULL,"
            "  checksum   TEXT NOT NULL,"
            "  applied_at TEXT NOT NULL,"
            "  duration_ms INTEGER NOT NULL DEFAULT 0"
            ")"
        )

    def _verify_checksums(self, conn: Connection) -> None:
        self._ensure_ledger(conn)
        rows = conn.execute("SELECT version, name, checksum FROM schema_migrations")
        recorded = {int(r["version"]): (r["name"], r["checksum"]) for r in rows}
        declared = {m.version: m for m in self.migrations}

        for version, (name, checksum) in sorted(recorded.items()):
            migration = declared.get(version)
            if migration is None:
                raise SchemaDrift(
                    f"the database has migration {version} ({name}) applied, but "
                    "this build does not declare it. The deployment is older than "
                    "the database; roll the code forward rather than the schema back."
                )
            if migration.checksum != checksum:
                raise SchemaDrift(
                    f"migration {version} ({migration.name}) has changed since it "
                    f"was applied.\n  recorded: {checksum}\n  declared: "
                    f"{migration.checksum}\nAn applied migration is immutable. Add "
                    "a new migration instead of editing this one."
                )

    def _apply(self, migration: Migration) -> None:
        started = datetime.now(timezone.utc)
        if migration.concurrency is Concurrency.AUTOCOMMIT:
            self._apply_autocommit(migration)
        else:
            self._apply_transactional(migration)
        elapsed_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)

        with self.database.writer() as conn:
            self._relax_lock_timeout(conn)
            conn.begin()
            self._ensure_ledger(conn)
            conn.execute_rowcount(
                f"INSERT INTO schema_migrations (version, name, checksum, applied_at, "
                f"duration_ms) VALUES ({conn.p},{conn.p},{conn.p},{conn.p},{conn.p})",
                (
                    migration.version,
                    migration.name,
                    migration.checksum,
                    started.isoformat(),
                    elapsed_ms,
                ),
            )
            conn.commit()

    def _apply_transactional(self, migration: Migration) -> None:
        with self.database.writer() as conn:
            self._relax_lock_timeout(conn)
            conn.begin()
            try:
                for statement in migration.up:
                    conn.execute_rowcount(statement)
            except Exception as exc:
                conn.rollback()
                raise MigrationError(
                    f"migration {migration.version} ({migration.name}) failed and "
                    f"was rolled back: {exc}"
                ) from exc
            conn.commit()

    def _apply_autocommit(self, migration: Migration) -> None:
        """Run outside a transaction, skipping statements already applied.

        `CREATE INDEX CONCURRENTLY` cannot run inside a transaction and leaves an
        INVALID index behind if it fails. The `is_applied` probe is what makes a
        re-run safe rather than a duplicate-object error.
        """
        with self.database.writer() as conn:
            conn.begin()
            already = conn.one(migration.is_applied or "SELECT 1 WHERE false")
            conn.commit()
            if already is not None:
                return
        for statement in migration.up:
            with self.database.writer() as conn:
                self._relax_lock_timeout(conn)
                try:
                    conn.execute_rowcount(statement)
                    conn.commit()
                except Exception as exc:
                    raise MigrationError(
                        f"migration {migration.version} ({migration.name}) failed "
                        f"outside a transaction; partial work may remain and the "
                        f"migration must be re-run: {exc}"
                    ) from exc

    def _revert(self, migration: Migration) -> None:
        with self.database.writer() as conn:
            self._relax_lock_timeout(conn)
            conn.begin()
            try:
                for statement in migration.down:
                    conn.execute_rowcount(statement)
                conn.execute_rowcount(
                    f"DELETE FROM schema_migrations WHERE version={conn.p}",
                    (migration.version,),
                )
            except Exception as exc:
                conn.rollback()
                raise MigrationError(
                    f"rollback of migration {migration.version} ({migration.name}) "
                    f"failed and was itself rolled back: {exc}"
                ) from exc
            conn.commit()
