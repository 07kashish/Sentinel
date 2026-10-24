"""The archive settings the RPO depends on must be enforced, not suggested.

THE GAP THIS CLOSES
-------------------
`docs/OPERATIONS.md` promises a bounded RPO. That promise rests entirely
on `archive_mode`, `archive_command` and `archive_timeout` being set on the
PostgreSQL server. `docker-compose.yml` sets them. The Helm chart **cannot** --
it does not deploy PostgreSQL, it consumes a DSN from a secret -- so for every
cluster install the promise rested on an operator reading a line of `NOTES.txt`
printed *after* a successful install.

Two mechanisms replace that hint, and this file holds both to their claims:

  * `externalPostgres.archiveTimeoutConfirmed` is required to be literally
    `true` by `values.schema.json`, so Helm refuses to render until an operator
    states that the external database is configured. The shipped default is
    `false`, which means the refusal is the out-of-the-box behaviour rather than
    something you opt into.
  * `templates/tests/postgres-archive-check.yaml` is a `helm test` hook that
    asks the running server via `SHOW` and fails the release test if the answer
    disagrees with the acknowledgement.

The second is the important one, because the first only checks that somebody
said yes. Verifying it needs a cluster, so the test here that runs *in this
environment* proves the equivalent for the path that is reachable: a PostgreSQL
started with the exact flags `docker-compose.yml` passes really does report
those settings. That is the "settings land in the deployed config, not just the
values file" check, executed against a real server rather than asserted.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft7Validator

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deploy" / "helm" / "sentinel"
VALUES = CHART / "values.yaml"
SCHEMA = CHART / "values.schema.json"
TEST_HOOK = CHART / "templates" / "tests" / "postgres-archive-check.yaml"
COMPOSE = ROOT / "docker-compose.yml"


def _values() -> dict:
    return yaml.safe_load(VALUES.read_text(encoding="utf-8"))


def _schema() -> dict:
    return json.loads(SCHEMA.read_text(encoding="utf-8"))


def _validator() -> Draft7Validator:
    return Draft7Validator(_schema())


# ── The values gate ──────────────────────────────────────────────────────────


def test_the_shipped_default_refuses_to_render():
    """Out of the box the chart must NOT install.

    If the default were `true`, the acknowledgement would be a field nobody ever
    looked at -- which is the state NOTES.txt was already in.
    """
    values = _values()
    assert values["externalPostgres"]["archiveTimeoutConfirmed"] is False
    errors = list(_validator().iter_errors(values))
    assert errors, (
        "values.yaml validates as shipped, so `helm install` would proceed "
        "without anyone confirming the database archives WAL"
    )
    assert any("archiveTimeoutConfirmed" in str(e.path) or "archiveTimeoutConfirmed" in e.message
               for e in errors), [e.message for e in errors]


def test_acknowledging_makes_it_render():
    """The gate has to be passable, or it is just a broken chart."""
    values = _values()
    values["externalPostgres"]["archiveTimeoutConfirmed"] = True
    assert not list(_validator().iter_errors(values)), [
        e.message for e in _validator().iter_errors(values)
    ]


def test_only_literal_true_satisfies_the_gate():
    """`"true"`, `1` and truthy junk must not pass for a safety acknowledgement."""
    for bogus in ("true", 1, "yes", [], {}):
        values = _values()
        values["externalPostgres"]["archiveTimeoutConfirmed"] = bogus
        assert list(_validator().iter_errors(values)), (
            f"{bogus!r} was accepted as an archiving acknowledgement"
        )


def test_the_declared_bound_is_within_the_documented_rpo_target():
    """A 5-minute RPO target cannot be honoured by a 10-minute archive timeout."""
    schema = _schema()["properties"]["externalPostgres"]["properties"]
    bound = schema["maxArchiveTimeoutSeconds"]
    assert bound["maximum"] <= 300, (
        "maxArchiveTimeoutSeconds may exceed the ≤5m RPO target in "
        "docs/OPERATIONS.md; worst-case RPO is approximately this value"
    )
    assert _values()["externalPostgres"]["maxArchiveTimeoutSeconds"] == 60


def test_external_postgres_is_required_by_the_schema():
    assert "externalPostgres" in _schema()["required"]


# ── The helm test hook ───────────────────────────────────────────────────────


def test_the_release_test_interrogates_the_server_not_the_values():
    """An acknowledgement is a claim; this hook is what checks it."""
    assert TEST_HOOK.exists(), "no helm test hook verifying the archiving claim"
    # Read as text, not YAML: a Helm template is Go templating first and only
    # becomes YAML after rendering, and `{{` is a flow mapping to a YAML parser.
    body = TEST_HOOK.read_text(encoding="utf-8")
    assert "helm.sh/hook: test" in body

    # It must ask the SERVER. A hook that re-reads values proves nothing.
    for setting in ("archive_mode", "archive_command", "archive_timeout", "wal_level"):
        assert f"SHOW {setting}" in body, f"the hook never asks the server for {setting}"
    # And it must read the same DSN the app uses, not a separately-configured one.
    assert "{{ .Values.postgres.existingSecret }}" in body
    # The two shapes that look configured but are not.
    assert "archive_command is empty" in body
    assert "archive_timeout is unset" in body


def test_ci_acknowledges_explicitly_and_proves_the_gate_bites():
    """CI is an operator too, and must demonstrate the refusal still happens."""
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "externalPostgres.archiveTimeoutConfirmed=true" in ci
    assert "chart refuses to render without the archiving acknowledgement" in ci


# ── The part that is actually executed against a server ──────────────────────


def _compose_postgres_args() -> list[str]:
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    command = compose["services"]["postgres"]["command"]
    # ["postgres", "-c", "k=v", "-c", ...] -> ["-c", "k=v", ...]
    return [str(a) for a in command[1:]]


def test_compose_declares_the_archiving_settings():
    args = _compose_postgres_args()
    joined = " ".join(args)
    assert "archive_mode=on" in joined
    assert "archive_timeout=60s" in joined
    assert "wal_level=replica" in joined
    assert "archive_command=" in joined
    # Refusing to overwrite is what keeps the archive a recovery source.
    assert "test ! -f" in joined


@pytest.mark.slow
def test_a_server_started_with_compose_args_really_reports_them(tmp_path):
    """The settings must land in the RUNNING config, not only in the file.

    This is the claim `helm test` makes about a cluster's database, executed here
    against the one server this environment can start. It parses the flags out of
    `docker-compose.yml` rather than restating them, so drift between the compose
    file and this assertion is impossible.
    """
    configured = os.environ.get("SENTINEL_TEST_PG_BIN", "").strip()
    if configured:
        bin_dir = Path(configured).resolve()
    else:
        pgserver = pytest.importorskip("pgserver")
        bin_dir = Path(pgserver.__file__).parent / "pginstall" / "bin"
    initdb = bin_dir / ("initdb.exe" if sys.platform == "win32" else "initdb")
    pg_ctl = bin_dir / ("pg_ctl.exe" if sys.platform == "win32" else "pg_ctl")
    psql = bin_dir / ("psql.exe" if sys.platform == "win32" else "psql")
    if not initdb.exists():
        pytest.skip(f"embedded postgres binaries not present at {bin_dir}")

    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = int(s.getsockname()[1])

    pgdata = tmp_path / "pgdata"
    archive = tmp_path / "archive"
    archive.mkdir()
    init = subprocess.run(  # noqa: S603
        [str(initdb), "-D", str(pgdata), "-U", "postgres", "--auth=trust", "--encoding=UTF8", "--no-locale", "--no-sync"],
        capture_output=True, text=True, check=False,
    )
    if init.returncode != 0:
        pytest.skip(f"initdb failed, cannot test compose archive settings:\n{init.stderr[-2000:]}")

    # Applied through postgresql.conf rather than `pg_ctl -o`, because -o hands
    # the whole string to a splitter and `archive_command` contains spaces and
    # `&&`. The values themselves still come from docker-compose.yml unchanged;
    # only the archive DESTINATION is repointed from the container path to a
    # temp directory.
    settings: list[str] = []
    for raw in _compose_postgres_args():
        if raw == "-c":
            continue
        key, _, value = raw.partition("=")
        if key == "archive_command":
            value = f"test ! -f {archive}/%f && cp %p {archive}/%f"
        settings.append(f"{key} = '{value}'")
    with (pgdata / "postgresql.conf").open("a", encoding="utf-8") as fh:
        fh.write("\n# --- from docker-compose.yml ---\n" + "\n".join(settings) + "\n")

    started = subprocess.run(  # noqa: S603
        [str(pg_ctl), "-D", str(pgdata), "-l", str(tmp_path / "pg.log"), "-w", "-t", "90",
         "-o", f"-p {port}", "start"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
        check=False,
    )
    log = (tmp_path / "pg.log")
    assert started.returncode == 0, (
        "postgres refused to start with docker-compose's own flags:\n"
        + (log.read_text(encoding="utf-8", errors="replace") if log.exists() else "")
    )
    try:
        def show(setting: str) -> str:
            proc = subprocess.run(  # noqa: S603
                [str(psql), "-h", "127.0.0.1", "-p", str(port), "-U", "postgres",
                 "-d", "postgres", "-tAc", f"SHOW {setting}"],
                capture_output=True, text=True, check=True,
            )
            return proc.stdout.strip()

        assert show("archive_mode") == "on"
        assert show("wal_level") == "replica"
        # PostgreSQL normalises 60s to "1min"; both mean 60 seconds.
        assert show("archive_timeout") in {"60s", "1min"}
        assert show("archive_command"), "archive_command came back empty"
        assert "test ! -f" in show("archive_command")
    finally:
        subprocess.run(  # noqa: S603
            [str(pg_ctl), "-D", str(pgdata), "-m", "immediate", "-w", "-t", "60", "stop"],
            capture_output=True, text=True, check=False,
        )
