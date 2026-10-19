"""The test harness's own DSN rewriting, checked on both DSN shapes.

WHY THIS FILE EXISTS
--------------------
`tests_arch/conftest.py` rewrites the DSN twice: once to swap the superuser for
the non-superuser role (so FORCE row-level security actually binds), and once
per test to point at a freshly created database. Both used to do string surgery:

    app_dsn.rsplit("/", 1)[0] + f"/{name}"

`pgserver` returns a TCP DSN on Windows and a UNIX-SOCKET DSN on Linux:

    postgresql://postgres:@127.0.0.1:54931/postgres          (Windows)
    postgresql:///postgres?host=/tmp/.../pgdata0             (Linux)

On the first, the last "/" precedes the database name and the slicing works. On
the second the last "/" is inside the `host=` query parameter, so the slice cut
the socket directory in half and pasted the database name onto the end of it.
Every `[postgres]` test then died on connect:

    connection to server on socket
    "/tmp/pytest-of-runner/pytest-0/sentinel_3ba8d0396f45/.s.PGSQL.5432"
    failed: No such file or directory

The PostgreSQL half of this suite had therefore never run in CI, on any push,
while passing on the Windows machine the code was written on. That is precisely
the failure mode `conftest.py`'s own docstring says the dual-engine
parametrisation exists to prevent -- and it was the parametrisation itself that
had it.

WHY THE ASSERTIONS ARE ON BOTH SHAPES REGARDLESS OF PLATFORM
--------------------------------------------------------------
These are pure string functions, so both DSN shapes can be exercised anywhere.
That is the entire point: a Windows developer must be able to catch a
Linux-only regression here without a Linux machine, because the previous version
of this code was correct on the platform it was written on and broken on the
platform that matters.
"""

from __future__ import annotations

import pytest
from urllib.parse import parse_qs, urlsplit

from tests_arch.conftest import APP_PASSWORD, APP_ROLE, _with_credentials, _with_dbname

#: What pgserver hands back on Linux. The socket directory lives in the query
#: string, and it contains slashes.
UNIX_SOCKET_DSN = "postgresql:///postgres?host=/tmp/pytest-of-runner/pytest-0/pgdata0"
#: What pgserver hands back on Windows.
TCP_DSN = "postgresql://postgres:@127.0.0.1:54931/postgres"


def test_query_credentials_cannot_override_the_rls_test_role():
    dsn = _with_credentials(UNIX_SOCKET_DSN + "&user=postgres&password=synthetic", APP_ROLE, APP_PASSWORD)
    query = parse_qs(urlsplit(dsn).query)
    assert "user" not in query and "password" not in query
    assert urlsplit(dsn).username == APP_ROLE


def test_query_database_cannot_override_the_isolated_database():
    dsn = _with_dbname(UNIX_SOCKET_DSN + "&dbname=postgres", "isolated")
    assert "dbname" not in parse_qs(urlsplit(dsn).query)
    assert urlsplit(dsn).path == "/isolated"


# ── Swapping the database name ───────────────────────────────────────────────


def test_the_socket_directory_survives_a_database_swap():
    """The regression. `rsplit` corrupted this and nothing noticed for weeks."""
    result = _with_dbname(UNIX_SOCKET_DSN, "sentinel_abc123")

    assert "host=/tmp/pytest-of-runner/pytest-0/pgdata0" in result, (
        f"the socket directory was mangled: {result}. This is the exact defect "
        "that disabled every PostgreSQL test in CI."
    )
    assert result.endswith("?host=/tmp/pytest-of-runner/pytest-0/pgdata0")
    assert "/sentinel_abc123?" in result, f"database name not applied: {result}"
    # The failure signature, stated as a negative so it can never come back:
    # the database name must NOT end up appended to the socket path.
    assert "pgdata0/sentinel_abc123" not in result


def test_a_tcp_dsn_still_has_its_database_swapped():
    result = _with_dbname(TCP_DSN, "sentinel_abc123")
    assert result == "postgresql://postgres:@127.0.0.1:54931/sentinel_abc123"


# ── Swapping the credentials ─────────────────────────────────────────────────


def test_credentials_are_injected_into_a_unix_socket_dsn():
    """No host in the netloc at all -- it is in `?host=`. Still a valid URI."""
    result = _with_credentials(UNIX_SOCKET_DSN, APP_ROLE, APP_PASSWORD)

    assert result.startswith(f"postgresql://{APP_ROLE}:{APP_PASSWORD}@/postgres")
    assert result.endswith("?host=/tmp/pytest-of-runner/pytest-0/pgdata0")


def test_credentials_are_injected_into_a_tcp_dsn_keeping_host_and_port():
    result = _with_credentials(TCP_DSN, APP_ROLE, APP_PASSWORD)
    assert result == (
        f"postgresql://{APP_ROLE}:{APP_PASSWORD}@127.0.0.1:54931/postgres"
    )


# ── The two together, in the order the fixtures apply them ───────────────────


@pytest.mark.parametrize("dsn", [UNIX_SOCKET_DSN, TCP_DSN], ids=["unix-socket", "tcp"])
def test_the_full_fixture_chain_produces_a_connectable_dsn(dsn):
    """`postgres_dsn` then `_fresh_database`, which is what actually runs.

    Asserted as a chain rather than separately because the defect was in the
    COMPOSITION: each rewrite looked reasonable, and applying the second to the
    output of the first is what destroyed the socket path.
    """
    chained = _with_dbname(_with_credentials(dsn, APP_ROLE, APP_PASSWORD), "sentinel_x")

    assert chained.startswith(f"postgresql://{APP_ROLE}:{APP_PASSWORD}@")
    assert chained.count("?") <= 1, f"query string duplicated: {chained}"
    # `Settings._parse_engine` refuses anything not starting with this prefix,
    # which is why URI form is preserved instead of psycopg's keyword form.
    assert chained.startswith("postgresql://")
    if "host=" in dsn:
        assert chained.endswith("?host=/tmp/pytest-of-runner/pytest-0/pgdata0")
        assert "pgdata0/sentinel_x" not in chained


def test_the_rewritten_dsn_is_accepted_by_the_applications_own_settings_parser():
    """The end-to-end constraint: this string is fed to SENTINEL_DATABASE_URL.

    `tests_arch/test_retention_sweep.py` passes the rewritten DSN through
    `Settings.from_environment`, which refuses a URL that does not start with
    `postgresql://` or `postgresql+psycopg://`. Switching these helpers to
    psycopg's `make_conninfo` keyword form ("dbname=x host=y") would be a
    perfectly good DSN and would fail here -- so the constraint is pinned.
    """
    from sentinel.composition.settings import Settings

    dsn = _with_dbname(_with_credentials(UNIX_SOCKET_DSN, APP_ROLE, APP_PASSWORD), "d1")
    settings = Settings.from_environment(
        {
            "SENTINEL_ENV": "development",
            "SENTINEL_API_KEYS": f"acme:{'k' * 40}:admin",
            "SENTINEL_DATABASE_URL": dsn,
        }
    )
    assert settings.engine.dsn == dsn


# ── The connection error never carries the password (found in CloudWatch, 2026-09-24) ──


def test_a_driver_error_that_quotes_the_password_is_scrubbed():
    from sentinel.infrastructure.sql.engine import _scrubbed

    password = ")W}*s(:W}3mm" + "K%h-tTLbbE0c4"
    dsn = f"postgresql://sentinel:{password}@db.internal:5432/sentinel?sslmode=require"
    message = _scrubbed(f'invalid percent-encoded token: "{password}"', dsn)
    assert password not in message and "***" in message
    assert password not in _scrubbed(f"could not parse {dsn}", dsn)
    assert "sentinel:" + password not in _scrubbed(f"bad userinfo sentinel:{password}", dsn)


def test_scrubbing_leaves_an_ordinary_message_alone():
    from sentinel.infrastructure.sql.engine import _scrubbed

    assert _scrubbed("connection refused", "postgresql://u:p@h/d") == "connection refused"
