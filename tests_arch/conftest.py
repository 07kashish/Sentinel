"""Shared fixtures, including a real PostgreSQL server.

WHY POSTGRES IS NOT OPTIONAL HERE
----------------------------------
The predecessor's single most subtle defect was invisible on SQLite and fatal on
PostgreSQL: `dlq.succeed()` and `dlq.fail()` used an unscoped connection, and
under FORCE row-level security their statements matched no rows. Every terminal
delivery operation silently failed on the production engine while the whole test
suite passed on the development one.

So the SQL, chaos and concurrency suites are parametrised over BOTH engines. A
test that only ever runs on SQLite is a test that cannot see that class of bug.

THE SUPERUSER TRAP
------------------
A PostgreSQL superuser BYPASSES row-level security entirely, even with FORCE.
`pgserver` connects as one. Running the isolation tests as superuser would make
every RLS assertion vacuously pass -- the exact failure mode that would let a
production deployment connect as `postgres` and silently lose its isolation
boundary with no test able to notice.

So `postgres_dsn` creates a dedicated NON-superuser role and hands back a DSN for
it. `test_tenant_isolation_rls.py` proves the distinction is real by showing the
same query returns different rows for the two roles -- see
`test_the_application_role_is_not_a_superuser`. (This paragraph named a
`test_rls_is_actually_enforced` that exists nowhere in this tree; the name
came from the predecessor implementation and had been repeated here.)
"""

from __future__ import annotations

import os
import pathlib
import time
import uuid
from typing import Iterator
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import pytest

from sentinel.infrastructure.sql.engine import Dialect, EngineConfig, build_engine
from sentinel.infrastructure.sql.migrate import migrate

# macOS writes AppleDouble metadata ("._name") next to every file it touches on
# a FAT/exFAT volume. They are resource forks, not source: they are not UTF-8,
# not Python, and not part of the repository. Several suites here sweep the tree
# with rglob("*.py") at MODULE IMPORT TIME and parse what they find, so the junk
# has to be gone before collection — a fixture runs too late, while this
# conftest imports before any test module does. Removing them is safe by
# construction: the prefix is reserved by macOS for its metadata mirror and no
# tracked file uses it (.gitignore refuses the pattern).
for _junk in pathlib.Path(__file__).resolve().parent.parent.rglob("._*"):
    if _junk.is_file():
        _junk.unlink(missing_ok=True)

APP_ROLE = "sentinel_app"
APP_PASSWORD = "sentinel_test_password"


def _wait_until_accepting(dsn: str, *, timeout: float = 180.0) -> None:
    """Block until the server answers, or fail with what it last said.

    `pgserver.get_server()` returns once the postmaster process exists, which is
    not the same as the postmaster being ready. On a loaded machine the gap is
    wide enough to matter: an entire parametrised suite failed here with

        FATAL: the database system is not yet accepting connections

    -- thirteen errors that say nothing about the code under test. A start-up
    race that surfaces as a wall of unrelated failures is worse than a slow
    fixture, because the next person spends their time reading the wrong tests.
    """
    import psycopg

    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with psycopg.connect(dsn, connect_timeout=5) as conn:
                conn.execute("SELECT 1")
            return
        except Exception as exc:  # noqa: BLE001 - retried until the deadline
            last = exc
            time.sleep(0.5)
    raise RuntimeError(
        f"embedded PostgreSQL did not accept connections within {timeout:.0f}s; "
        f"last error: {type(last).__name__}: {last}"
    )


def _try_start_server(tmp_path_factory):
    """Start an embedded PostgreSQL, or return None with the reason."""
    override = os.getenv("SENTINEL_TEST_POSTGRES_DSN", "").strip()
    if override:
        _wait_until_accepting(override)
        return None, override

    try:
        import pgserver
    except ImportError:
        return None, None

    data_dir = tmp_path_factory.mktemp("pgdata")
    server = pgserver.get_server(data_dir)
    uri = server.get_uri()
    _wait_until_accepting(uri)
    return server, uri


@pytest.fixture(scope="session")
def postgres_admin_dsn(tmp_path_factory) -> Iterator[str | None]:
    """A superuser DSN for the session's server, or None if unavailable."""
    server, dsn = _try_start_server(tmp_path_factory)
    if dsn is None:
        yield None
        return
    try:
        yield dsn
    finally:
        if server is not None:
            server.cleanup()


@pytest.fixture(scope="session")
def postgres_dsn(postgres_admin_dsn) -> str | None:
    """A NON-superuser DSN. RLS binds only for a role that cannot bypass it."""
    if postgres_admin_dsn is None:
        return None
    import psycopg
    from psycopg import sql

    with psycopg.connect(postgres_admin_dsn, autocommit=True) as conn:
        exists = conn.execute(
            "SELECT 1 FROM pg_roles WHERE rolname=%s", (APP_ROLE,)
        ).fetchone()
        if not exists:
            # DDL cannot take a bound parameter, so the identifier and the
            # literal are COMPOSED with psycopg.sql rather than interpolated.
            # An f-string here would be a SQL-injection shape even for a
            # constant, and this file is read as an example.
            conn.execute(
                sql.SQL(
                    "CREATE ROLE {role} LOGIN PASSWORD {password} "
                    "NOSUPERUSER NOCREATEDB"
                ).format(
                    role=sql.Identifier(APP_ROLE),
                    password=sql.Literal(APP_PASSWORD),
                )
            )
    return _with_credentials(postgres_admin_dsn, APP_ROLE, APP_PASSWORD)


# ── DSN rewriting ────────────────────────────────────────────────────────────
#
# THE DEFECT THESE TWO HELPERS EXIST TO FIX
# ------------------------------------------
# Both of them used to do string surgery on the DSN:
#
#     app_dsn.rsplit("/", 1)[0] + f"/{name}"      # swap the database name
#     postgres_admin_dsn.rpartition("@")          # inject credentials
#
# That works on Windows, where `pgserver` hands back a TCP DSN
# (`postgresql://postgres:@127.0.0.1:54931/postgres`) and the last "/" really
# does precede the database name. On LINUX -- which is what CI runs -- pgserver
# hands back a UNIX-SOCKET DSN:
#
#     postgresql:///postgres?host=/tmp/pytest-of-runner/pytest-0/pgdata0
#
# The last "/" is now inside the `host=` query parameter, so `rsplit` cut the
# socket directory in half and pasted the database name onto it. Every single
# `[postgres]` test then failed to connect:
#
#     connection to server on socket
#     "/tmp/pytest-of-runner/pytest-0/sentinel_3ba8d0396f45/.s.PGSQL.5432"
#     failed: No such file or directory
#
# The consequence is worth stating plainly: the PostgreSQL half of this suite
# HAS NEVER RUN IN CI. The docstring at the top of this file calls that
# parametrisation non-optional, because the predecessor's worst defect was
# invisible on SQLite -- and the parametrisation was silently erroring out on
# the very engine it exists to cover, on every push, while passing locally.
#
# So: parse the URI and rebuild it. `urlsplit` keeps the query string intact,
# which is the whole point.
#
# URI form is preserved deliberately rather than switching to psycopg's
# `make_conninfo` keyword form ("dbname=x host=y"), because
# `Settings._parse_engine` requires the value of SENTINEL_DATABASE_URL to start
# with `postgresql://` or `postgresql+psycopg://` and refuses anything else.


def _with_dbname(dsn: str, name: str) -> str:
    """Point a DSN at a different database, leaving host/query untouched."""
    parts = urlsplit(dsn)
    query = urlencode([(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != "dbname"], safe="/")
    return urlunsplit((parts.scheme, parts.netloc, f"/{name}", query, parts.fragment))


def _with_credentials(dsn: str, user: str, password: str) -> str:
    """Rewrite the userinfo, preserving host, port and query.

    For a Unix-socket DSN there is no host in the netloc at all -- it lives in
    `?host=` -- so `parts.hostname` is None and the netloc becomes just
    `user:password@`. That is a valid libpq URI and is exactly what is wanted.
    """
    parts = urlsplit(dsn)
    host = parts.hostname or ""
    port = f":{parts.port}" if parts.port else ""
    netloc = f"{quote(user, safe='')}:{quote(password, safe='')}@{host}{port}"
    # libpq query credentials override URI userinfo. Keeping ?user=postgres
    # would silently run the RLS suite as a superuser despite the replacement.
    query = urlencode([(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
                       if k not in {"user", "password"}], safe="/")
    return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))


def _fresh_database(admin_dsn: str, app_dsn: str) -> str:
    """Create an isolated database and grant the app role full rights on it."""
    import psycopg

    from psycopg import sql

    name = f"sentinel_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        conn.execute(
            sql.SQL("CREATE DATABASE {db} OWNER {role}").format(
                db=sql.Identifier(name), role=sql.Identifier(APP_ROLE)
            )
        )
    return _with_dbname(app_dsn, name)


def _drop_database(admin_dsn: str, dsn: str) -> None:
    """Drop a per-test database once the test is done with it.

    WHY THIS EXISTS
    ---------------
    `_fresh_database` created one database per test and nothing ever removed
    them. Across a long run the embedded server accumulated databases and the
    backends that go with them until new connections started timing out, and the
    symptom was a `ConnectionTimeout` in whichever test happened to be unlucky --
    a different one each run, at fixture setup or inside the test body, reading
    as flakiness while actually being resource exhaustion with a fixed cause.

    It was reported as environmental four times before anyone looked. It is not.

    `WITH (FORCE)` because a test that builds its own pool from `engine_config`
    may not have closed it, and a DROP that fails on an open connection would
    reintroduce the accumulation it exists to prevent. Terminating a backend
    belonging to a finished test is safe by definition.

    Failure here is swallowed deliberately: a database that cannot be dropped is
    a slow cleanup, while an exception in teardown would fail a test that has
    already passed and send the next reader to the wrong place entirely.
    """
    import psycopg

    from psycopg import sql

    name = dsn.rsplit("/", 1)[-1].split("?")[0]
    if not name.startswith("sentinel_"):
        # Never drop something this helper did not create. The module-scoped
        # fixtures share one database across a file, and dropping a name we do
        # not recognise would take out a database still in use.
        return
    try:
        with psycopg.connect(admin_dsn, autocommit=True) as conn:
            conn.execute(
                sql.SQL("DROP DATABASE IF EXISTS {db} WITH (FORCE)").format(
                    db=sql.Identifier(name)
                )
            )
    except Exception:  # noqa: BLE001 - cleanup must never fail a passing test
        pass


@pytest.fixture(params=["sqlite", "postgres"])
def engine_config(request, tmp_path, postgres_admin_dsn, postgres_dsn):
    """One config per backend. Every test using this runs twice.

    A GENERATOR, so the PostgreSQL database it creates is dropped afterwards.
    It used to return, and nothing ever removed the databases -- which is why
    long runs ended in ConnectionTimeout.
    """
    if request.param == "sqlite":
        yield EngineConfig(
            dialect=Dialect.SQLITE,
            dsn=str(tmp_path / f"s-{uuid.uuid4().hex[:8]}.db"),
            pool_min=1,
            pool_max=8,
        )
        return
    if postgres_dsn is None:
        pytest.skip(
            "no PostgreSQL available: install `pgserver` or set "
            "SENTINEL_TEST_POSTGRES_DSN. Skipping is reported, never silent."
        )
    dsn = _fresh_database(postgres_admin_dsn, postgres_dsn)
    try:
        yield EngineConfig(
            dialect=Dialect.POSTGRES,
            dsn=dsn,
            pool_min=1,
            pool_max=8,
        )
    finally:
        # Dropped, not left behind. Teardown runs in reverse setup order, so a
        # pool built on this config (`migrated_pool`) is already closed by the
        # time this runs.
        _drop_database(postgres_admin_dsn, dsn)


@pytest.fixture
def migrated_pool(engine_config):
    """A migrated pool on whichever backend this parametrisation selected."""
    pool = build_engine(engine_config)
    migrate(pool)
    yield pool
    pool.close()
