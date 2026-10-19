"""Start a real PostgreSQL 16 for the measurement scripts, as a non-superuser.

WHY THIS EXISTS
---------------
`scripts/profile_ingest.py` and `scripts/run_observability_soak.py` both hard-wired
`SENTINEL_DB_PATH`, so every number they ever produced was a SQLite number. The
gate row they feed says "ingest p95 under concurrent load", and production runs
PostgreSQL. A SQLite measurement standing in for a PostgreSQL one is the same
shape of defect as a green workflow file standing in for a green run.

Docker is absent in this environment (`docker --version` -> `command not found`),
so `postgres:16` the *image* cannot be started. `pgserver` ships the actual
PostgreSQL 16 server binaries and is already a declared dev dependency used by
`tests_arch/conftest.py` and both DR drills. What it starts is a genuine
PostgreSQL 16 backend -- verified per run by recording `SELECT version()` in the
report -- reached over a real TCP socket by psycopg. It is not the container
image, and every report produced through here says so rather than implying a
container ran.

THE SUPERUSER TRAP, AGAIN
-------------------------
`pgserver` connects as `postgres`, and a superuser BYPASSES row-level security
even with FORCE. Measuring ingest latency as a superuser would measure a query
plan the production role never gets: RLS adds a predicate to every statement, and
that predicate is part of the cost being measured. So this creates the same
NOSUPERUSER `sentinel_app` role `tests_arch/conftest.py` uses and hands back a DSN
for it.
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit

APP_ROLE = "sentinel_app"
APP_PASSWORD = "sentinel_measurement_password"

__all__ = ["EmbeddedPostgres", "PostgresUnavailableHere", "start_embedded_postgres"]


class PostgresUnavailableHere(RuntimeError):
    """No PostgreSQL could be started. Callers record UNVERIFIED, never a number."""


@dataclass
class EmbeddedPostgres:
    """A running server plus the two DSNs a measurement needs."""

    admin_dsn: str
    app_dsn: str
    version: str
    data_directory: str
    #: None when `SENTINEL_TEST_POSTGRES_DSN` pointed at a server we did not start.
    _server: object | None = None

    def fresh_database(self, prefix: str = "sentinel") -> str:
        """An empty database owned by the app role. Returns its app DSN."""
        import psycopg
        from psycopg import sql

        name = f"{prefix}_{uuid.uuid4().hex[:12]}"
        with psycopg.connect(self.admin_dsn, autocommit=True) as conn:
            conn.execute(
                sql.SQL("CREATE DATABASE {db} OWNER {role}").format(
                    db=sql.Identifier(name), role=sql.Identifier(APP_ROLE)
                )
            )
        return _with_dbname(self.app_dsn, name)

    def close(self) -> None:
        if self._server is not None:
            try:
                self._server.cleanup()
            except Exception:  # noqa: BLE001 - teardown must not mask a result
                pass


# ── DSN rewriting ────────────────────────────────────────────────────────────
#
# Parsed, not sliced. `pgserver` returns a TCP DSN on Windows and a UNIX-SOCKET
# DSN on Linux:
#
#     postgresql://postgres:@127.0.0.1:54931/postgres          (Windows)
#     postgresql:///postgres?host=/tmp/.../pgdata0             (Linux)
#
# The obvious `dsn.rsplit("/", 1)[0] + "/" + name` swaps the database name in
# the first and CORRUPTS THE SOCKET PATH in the second, because the last "/" is
# inside the `host=` query parameter. That defect shipped in `tests_arch/
# conftest.py`, where it silently disabled the entire PostgreSQL half of the
# test suite in CI while passing on the Windows machine it was written on. Same
# pattern, same fix, stated here too so the next person copying this file does
# not reintroduce it.
#
# URI form is preserved rather than psycopg's `make_conninfo` keyword form,
# because `Settings._parse_engine` requires SENTINEL_DATABASE_URL to begin with
# `postgresql://` or `postgresql+psycopg://`.


def _with_dbname(dsn: str, name: str) -> str:
    parts = urlsplit(dsn)
    return urlunsplit((parts.scheme, parts.netloc, f"/{name}", parts.query, parts.fragment))


def _app_dsn_from(admin_dsn: str) -> str:
    """Swap in the non-superuser role, preserving host, port and query."""
    parts = urlsplit(admin_dsn)
    host = parts.hostname or ""
    port = f":{parts.port}" if parts.port else ""
    netloc = f"{quote(APP_ROLE, safe='')}:{quote(APP_PASSWORD, safe='')}@{host}{port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def start_embedded_postgres(data_dir: Path | None = None) -> EmbeddedPostgres:
    """Start PostgreSQL 16 and return admin + non-superuser DSNs.

    Raises `PostgresUnavailableHere` with the exact reason rather than falling
    back to SQLite. A measurement script that quietly changed engine would
    produce a number labelled PostgreSQL that was not one.
    """
    import psycopg
    from psycopg import sql

    server = None
    override = os.getenv("SENTINEL_TEST_POSTGRES_DSN", "").strip()
    if override:
        admin_dsn = override
    else:
        try:
            import pgserver
        except ImportError as exc:
            raise PostgresUnavailableHere(
                "neither SENTINEL_TEST_POSTGRES_DSN nor the `pgserver` package is "
                f"available, so no PostgreSQL server can be started here: {exc}"
            ) from exc
        target = Path(data_dir) if data_dir is not None else None
        if target is None:
            import tempfile

            target = Path(tempfile.mkdtemp(prefix="sentinel_pgdata_"))
        try:
            server = pgserver.get_server(target)
            admin_dsn = server.get_uri()
        except Exception as exc:  # noqa: BLE001 - the reason is the deliverable
            raise PostgresUnavailableHere(
                f"pgserver could not start a server in {target}: "
                f"{type(exc).__name__}: {exc}"
            ) from exc

    # `get_server` returns once the postmaster EXISTS, which is earlier than it
    # accepting connections ("FATAL: the database system is not yet accepting
    # connections"). For a measurement script the consequence is worse than a
    # failed test: the run would abort partway and leave a half-written report.
    deadline = time.monotonic() + 180.0
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with psycopg.connect(admin_dsn, connect_timeout=5) as probe:
                probe.execute("SELECT 1")
            break
        except Exception as exc:  # noqa: BLE001 - retried until the deadline
            last = exc
            time.sleep(0.5)
    else:
        raise PostgresUnavailableHere(
            f"PostgreSQL did not accept connections within 180s; last error: "
            f"{type(last).__name__}: {last}"
        )

    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        version = str(conn.execute("SELECT version()").fetchone()[0])
        data_directory = str(conn.execute("SHOW data_directory").fetchone()[0])
        exists = conn.execute(
            "SELECT 1 FROM pg_roles WHERE rolname=%s", (APP_ROLE,)
        ).fetchone()
        if not exists:
            # Composed, not interpolated: DDL takes no bound parameters and this
            # file is read as an example of how to write one.
            conn.execute(
                sql.SQL(
                    "CREATE ROLE {role} LOGIN PASSWORD {password} "
                    "NOSUPERUSER NOCREATEDB"
                ).format(
                    role=sql.Identifier(APP_ROLE), password=sql.Literal(APP_PASSWORD)
                )
            )

    return EmbeddedPostgres(
        admin_dsn=admin_dsn,
        app_dsn=_app_dsn_from(admin_dsn),
        version=version,
        data_directory=data_directory,
        _server=server,
    )
