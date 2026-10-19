"""Backups and point-in-time recovery, actually performed.

This is not a runbook test. It initialises a real PostgreSQL cluster, enables WAL
archiving, takes a `pg_basebackup`, writes data, records the wall-clock time,
writes MORE data, then restores to the recorded instant on a second port and
asserts the second batch is absent while the first is present.

That last assertion is the whole point. A restore that brings back everything
proves only that the backup exists; a restore that STOPS at the target proves the
recovery target was honoured, which is the property "point-in-time" names and the
one that matters when the reason for restoring is that somebody dropped a table at
a known time.

WHY THIS OWNS ITS CLUSTER INSTEAD OF USING THE SESSION FIXTURE
--------------------------------------------------------------
`conftest.postgres_admin_dsn` is shared by the whole suite and is managed by
`pgserver`, which passes the port on the postmaster command line rather than
writing it to `postgresql.conf`. Enabling archiving needs a restart, and a restart
performed with `pg_ctl` behind pgserver's back would come back on the default port
5432 -- possibly colliding with a real installation. So this module runs `initdb`
itself and pins the port in the config file, which is also what makes the restored
copy addressable on a port of its own.

WHY IT IS SLOW AND STILL WORTH RUNNING
--------------------------------------
It initialises a cluster, restarts it, copies a data directory and replays WAL.
That is tens of seconds. The alternative is a backup nobody has restored, which is
the exact failure this exists to prevent: the job goes green for two years and the
first real restore is attempted during an incident, against a procedure written
from memory by someone who has left.
"""

from __future__ import annotations

import os
import socket
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sentinel.infrastructure.persistence.backup import BackupError, PostgresBackup

pytestmark = pytest.mark.slow

#: How long to wait for the archiver to ship segments, or for a restored server to
#: finish replaying. Generous because both are I/O bound and this runs on shared CI
#: hardware; a tight bound here produces flakes that get the test deleted.
PATIENCE_SECONDS = 90


def _bin_dir() -> Path:
    configured = os.environ.get("SENTINEL_TEST_PG_BIN", "").strip()
    if configured:
        root = Path(configured).resolve()
        for tool in ("initdb", "pg_ctl", "pg_basebackup", "psql"):
            assert _tool(root, tool).is_file(), f"Configured PostgreSQL tool missing: {tool}"
        return root
    pgserver = pytest.importorskip("pgserver", reason="pgserver ships the binaries")
    root = Path(pgserver.__file__).parent
    for candidate in (root / "pginstall" / "bin", root / "bin"):
        if any((candidate / f"initdb{ext}").exists() for ext in ("", ".exe")):
            return candidate
    pytest.skip(f"PostgreSQL binaries not found under {root}")


def _tool(bin_dir: Path, name: str) -> Path:
    direct = bin_dir / name
    return direct if direct.exists() else bin_dir / f"{name}.exe"


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _dsn(port: int) -> str:
    return f"postgresql://postgres@127.0.0.1:{port}/postgres"


def _connect(dsn: str):
    psycopg = pytest.importorskip("psycopg")
    return psycopg.connect(dsn, autocommit=True, connect_timeout=10)


@pytest.fixture(scope="module")
def cluster(tmp_path_factory):
    """A live PostgreSQL with WAL archiving on, plus a backup manager for it.

    Archiving cannot be enabled without a restart, so this starts the server,
    appends the settings, stops it and starts it again -- which is exactly the
    sequence an operator performs and is therefore worth exercising rather than
    assuming.

    Module-scoped: `initdb` costs more than every assertion in this file put
    together, and the tests are written not to depend on each other's state. They
    do share the WAL archive, which is realistic -- one archive serves every backup
    of a cluster.
    """
    bin_dir = _bin_dir()
    root = tmp_path_factory.mktemp("pitr")
    data_dir = root / "primary"
    port = _free_port()

    init = subprocess.run(  # noqa: S603 - argv is constructed, never shell
        [
            str(_tool(bin_dir, "initdb")),
            "--pgdata", str(data_dir),
            "--username", "postgres",
            "--auth-local=trust",
            "--auth-host=trust",
            "--encoding=UTF8",
            "--no-sync",  # this cluster is thrown away; durability is not the point
        ],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if init.returncode != 0:
        pytest.skip(f"initdb failed, cannot test PITR:\n{init.stderr[-2000:]}")

    manager = PostgresBackup(
        bin_dir=bin_dir,
        data_dir=data_dir,
        archive_dir=root / "wal_archive",
        backup_root=root / "backups",
    )

    with (data_dir / "postgresql.conf").open("a", encoding="utf-8") as conf:
        conf.write(
            "\n# --- test harness ---\n"
            "listen_addresses = '127.0.0.1'\n"
            f"port = {port}\n"
            # Read-only queries against a server still in recovery are how the
            # restored copy is inspected without promoting it.
            "hot_standby = 'on'\n"
        )
    manager.apply_archive_settings()
    manager.start(data_dir, log_file=root / "primary.log", timeout=180)

    try:
        yield manager, _dsn(port), data_dir, root
    finally:
        try:
            manager.stop(data_dir, mode="immediate")
        except BackupError:
            pass


def _wait_for_archive(manager: PostgresBackup, *, at_least: int = 1) -> tuple[str, ...]:
    deadline = time.monotonic() + PATIENCE_SECONDS
    while time.monotonic() < deadline:
        segments = manager.archive_segments()
        if len(segments) >= at_least:
            return segments
        time.sleep(1)
    return manager.archive_segments()


def _wait_until_the_current_segment_is_archived(dsn: str) -> str:
    """Switch WAL and wait for THAT segment to reach the archive.

    Counting files is not a usable condition once earlier tests have filled the
    archive: the count is already high, so a "wait for two segments" returns
    immediately without the segment holding the writes just made. Recovery replays
    only what the archive has, so the wait has to name the segment and watch
    `last_archived_wal` pass it -- otherwise the restore silently starts from a
    point before the data under test and the failure is blamed on the target logic.
    """
    with _connect(dsn) as conn:
        segment = conn.execute(
            "SELECT pg_walfile_name(pg_current_wal_lsn())"
        ).fetchone()[0]
        conn.execute("SELECT pg_switch_wal()")

    deadline = time.monotonic() + PATIENCE_SECONDS
    last = None
    while time.monotonic() < deadline:
        with _connect(dsn) as conn:
            last, failed = conn.execute(
                "SELECT last_archived_wal, failed_count FROM pg_stat_archiver"
            ).fetchone()
        if last is not None and last >= segment:
            return segment
        assert failed == 0, f"the archiver is failing ({failed} times); last={last}"
        time.sleep(1)
    raise AssertionError(
        f"segment {segment} never reached the archive within {PATIENCE_SECONDS}s "
        f"(last archived: {last}). Recovery cannot replay past it."
    )


def _wait_until_recovery_paused(dsn: str) -> None:
    """Wait for replay to reach the recovery target and stop there.

    "Queryable" is NOT the same as "finished". A restored server begins accepting
    read-only connections the moment it reaches a CONSISTENT state, which is
    typically the end of the base backup -- long before it has replayed to the
    recovery target. Querying then reads a database that is still mid-replay, and
    reports the data as missing when it has merely not arrived yet.

    With `recovery_target_action = 'pause'`, `pg_get_wal_replay_pause_state()`
    returning 'paused' is the signal that replay stopped AT the target and the
    contents are final. That is the condition to wait on.
    """
    deadline = time.monotonic() + PATIENCE_SECONDS
    last = "no connection yet"
    while time.monotonic() < deadline:
        try:
            with _connect(dsn) as conn:
                if conn.execute("SELECT pg_is_in_recovery()").fetchone()[0] is False:
                    raise AssertionError(
                        "recovery ended and the server promoted itself rather than "
                        "pausing: the target lies beyond the end of the archived WAL, "
                        "so nothing stopped the replay"
                    )
                state = conn.execute(
                    "SELECT pg_get_wal_replay_pause_state()"
                ).fetchone()[0]
                if state == "paused":
                    return
                last = f"replay state is {state!r}"
        except AssertionError:
            raise
        except Exception as exc:  # noqa: BLE001 - not accepting connections yet
            last = repr(exc)
        time.sleep(1)
    raise AssertionError(
        f"replay never paused at the recovery target within {PATIENCE_SECONDS}s: {last}"
    )


# ── Preflight: can this server support PITR at all ───────────────────────────


def test_preflight_confirms_pitr_against_the_live_server(cluster):
    """Asked of the running server, not of the config file we wrote.

    The two differ whenever a setting failed to parse, was overridden by an
    `include`, or needed a restart that never happened -- and the config file is
    the one that lies.
    """
    manager, dsn, _data, root = cluster
    from sentinel.infrastructure.persistence.engine import (
        Database,
        DatabaseConfig,
        Dialect,
        PoolConfig,
    )

    database = Database(
        DatabaseConfig(
            dialect=Dialect.POSTGRES, dsn=dsn, pool=PoolConfig(min_size=1, max_size=2)
        )
    )
    try:
        with database.writer() as conn:
            report = manager.preflight(conn)
    finally:
        database.close()

    assert report.pitr_capable, str(report)
    assert report.wal_level in ("replica", "logical")
    assert report.archive_mode in ("on", "always")
    assert report.archive_command.strip()
    assert "PITR capable" in str(report)

    # The archive path must survive the config parser INTACT. It treats backslash
    # as an escape inside a quoted value, so an unescaped Windows path is read back
    # with every separator removed -- and the resulting drive-relative path makes
    # `copy` SUCCEED into the data directory, so PostgreSQL increments
    # archived_count, leaves failed_count at zero, and the archive stays empty.
    # Reading the setting back from the server is the only way to see it.
    assert str(root / "wal_archive") in report.archive_command, (
        "the archive directory did not survive postgresql.conf quoting: the server "
        f"reports archive_command={report.archive_command!r}"
    )


def test_preflight_names_every_missing_prerequisite(tmp_path):
    """A negative report has to be actionable, not merely negative."""
    manager = PostgresBackup(
        bin_dir=_bin_dir(),
        data_dir=tmp_path,
        archive_dir=tmp_path / "wal",
        backup_root=tmp_path / "backups",
    )
    off = {"wal_level": "minimal", "archive_mode": "off", "archive_command": "   "}

    class _Off:
        def one(self, sql, params=()):
            setting = sql.split()[-1]
            return {setting: off[setting]}

    report = manager.preflight(_Off())

    assert not report.pitr_capable
    joined = " ".join(report.problems)
    assert "wal_level" in joined
    assert "archive_mode" in joined
    assert "archive_command" in joined
    assert "NOT capable" in str(report)


def test_config_values_escape_separators_and_quotes(tmp_path):
    r"""Both backslash and apostrophe are escapes inside a quoted conf value.

    Written verbatim, `E:\wal\%f` is read back by PostgreSQL as `E:wal%f`. The
    mangled form is a valid drive-relative path, so `copy` succeeds and archiving
    reports success -- which is why this needs pinning at the unit level as well as
    against a live server.
    """
    escape = PostgresBackup._conf_value
    assert escape(r"E:\wal\%f") == r"E:\\wal\\%f"
    assert escape("it's") == "it''s"
    assert escape("/var/lib/wal/%f") == "/var/lib/wal/%f"

    manager = PostgresBackup(
        bin_dir=_bin_dir(),
        data_dir=tmp_path,
        archive_dir=tmp_path / "wal",
        backup_root=tmp_path / "backups",
    )
    (tmp_path / "postgresql.conf").write_text("# base\n", encoding="utf-8")
    manager.apply_archive_settings()
    written = (tmp_path / "postgresql.conf").read_text(encoding="utf-8")

    command_line = next(
        line for line in written.splitlines() if line.startswith("archive_command")
    )
    # Undo the config parser's own unescaping and the original path must reappear.
    assert str(tmp_path / "wal") in command_line.replace("\\\\", "\\")


@pytest.mark.parametrize("windows", [True, False], ids=["windows", "posix"])
def test_both_platform_branches_refuse_to_overwrite_an_archived_segment(
    tmp_path, monkeypatch, windows
):
    """Neither branch may clobber a segment already in the archive.

    Overwriting can destroy the WAL a concurrent restore is reading. The guard is
    `test ! -f` on POSIX and `if not exist` on Windows, and only one of those two
    branches ever runs on any given machine -- so the other is dead code until CI
    reaches it, which for an archive command means its first real execution is in
    production.

    Patched through the module's `_IS_WINDOWS` constant rather than `os.name`:
    `pathlib` reads `os.name` to decide whether `Path` is a `WindowsPath`, so
    overriding it breaks every path in the process.
    """
    monkeypatch.setattr(
        "sentinel.infrastructure.persistence.backup._IS_WINDOWS", windows
    )
    manager = PostgresBackup(
        bin_dir=_bin_dir(),
        data_dir=tmp_path,
        archive_dir=tmp_path / "wal",
        backup_root=tmp_path / "backups",
    )
    settings = manager.archive_settings()

    assert settings["wal_level"] == "replica"
    assert settings["archive_mode"] == "on"
    command = settings["archive_command"]
    assert "%f" in command and "%p" in command
    guard = "if not exist" if windows else "test ! -f"
    assert guard in command, f"this archive_command would overwrite: {command}"
    # A path with a space must not split into two arguments.
    assert command.count('"') >= 4, f"paths are not quoted: {command}"
    # Every setting must survive being written to postgresql.conf.
    assert manager._conf_value(command).replace("\\\\", "\\") == command


def test_missing_binaries_are_refused_at_construction(tmp_path):
    """A restore run with a pg_ctl from another major version fails opaquely."""
    empty = tmp_path / "no-binaries"
    empty.mkdir()
    with pytest.raises(BackupError) as caught:
        PostgresBackup(
            bin_dir=empty,
            data_dir=tmp_path,
            archive_dir=tmp_path / "wal",
            backup_root=tmp_path / "backups",
        )
    assert "SAME major version" in str(caught.value)


# ── Base backup ──────────────────────────────────────────────────────────────


def test_a_base_backup_is_taken_and_manifested(cluster):
    manager, dsn, _data, _root = cluster
    manifest = manager.base_backup(dsn=dsn, label="manifested")

    assert manifest.path.is_dir()
    assert (manifest.path / "PG_VERSION").exists()
    assert (manifest.path / "backup_label").exists(), (
        "no backup_label: this is a file copy, not a recoverable base backup"
    )
    assert manifest.size_bytes > 1_000_000, "a base backup should not be tiny"
    assert manifest.finished_at >= manifest.started_at
    # The earliest reachable target is when the backup COMPLETED, not when it
    # started: inside the backup window different files were copied at different
    # instants, so no single target there is consistent.
    assert manifest.earliest_target == manifest.finished_at
    assert manifest.as_dict()["label"] == "manifested"


def test_a_base_backup_streams_its_own_wal(cluster):
    """`--wal-method=stream` is what makes the backup self-contained.

    Without it a backup can finish needing segments the archive has not received
    yet, and is unrestorable until they arrive -- a window during which the backup
    exists and does not work.
    """
    manager, dsn, _data, _root = cluster
    manifest = manager.base_backup(dsn=dsn, label="self-contained")
    shipped = list((manifest.path / "pg_wal").glob("0*"))
    assert shipped, "no WAL inside the backup; it depends on the archive to restore"


def test_a_duplicate_backup_label_is_refused(cluster):
    """Overwriting a backup in place destroys the only copy while writing the next."""
    manager, dsn, _data, _root = cluster
    manager.base_backup(dsn=dsn, label="only-once")
    with pytest.raises(BackupError) as caught:
        manager.base_backup(dsn=dsn, label="only-once")
    assert "already exists" in str(caught.value)


def test_a_backup_compresses_for_off_site_retention(cluster):
    manager, dsn, _data, _root = cluster
    manifest = manager.base_backup(dsn=dsn, label="compressible")
    archive = manager.compress(manifest)

    assert archive.name.endswith(".tar.gz")
    assert 0 < archive.stat().st_size < manifest.size_bytes, (
        "the compressed archive is not smaller than the directory it came from"
    )
    import tarfile

    with tarfile.open(archive) as tar:
        names = set(tar.getnames())
    assert f"{manifest.label}/PG_VERSION" in names


# ── WAL archiving ────────────────────────────────────────────────────────────


def test_wal_segments_actually_reach_the_archive(cluster):
    """Configured is not the same as working, and the archiver's own stats can lie.

    Two failure modes, and the noisy one is the lesser. A command that exits
    non-zero makes PostgreSQL retry forever while `pg_wal` grows until the volume
    fills -- bad, but `failed_count` says so. A command whose destination path was
    mangled by the config parser exits ZERO, having written the segment somewhere
    useless: `archived_count` climbs, `failed_count` stays at zero, and the archive
    is empty.

    So this asserts on the CONTENTS of the archive directory, and on a named segment
    it caused to be written. Trusting `pg_stat_archiver` here would pass in exactly
    the case that loses the backup.
    """
    manager, dsn, _data, root = cluster
    with _connect(dsn) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS churn (id int, payload text)")
        for _ in range(3):
            conn.execute(
                "INSERT INTO churn SELECT g, repeat('x', 500) "
                "FROM generate_series(1, 5000) g"
            )
            conn.execute("SELECT pg_switch_wal()")
        conn.execute("CHECKPOINT")

    expected = _wait_until_the_current_segment_is_archived(dsn)
    segments = manager.archive_segments()

    with _connect(dsn) as conn:
        archived, failed, last_failed = conn.execute(
            "SELECT archived_count, failed_count, last_failed_wal FROM pg_stat_archiver"
        ).fetchone()

    assert segments, (
        "the archive directory is EMPTY even though the archiver reports "
        f"archived_count={archived}, failed_count={failed}. The archive_command is "
        "exiting zero while writing nowhere useful -- check that the destination "
        "path survived postgresql.conf quoting. Recovery has nothing to replay."
    )
    assert expected in segments, (
        f"segment {expected} is not in the archive directory, though the archiver "
        f"reported it as archived. Present: {segments[-5:]}"
    )
    assert (root / "wal_archive" / expected).stat().st_size > 0, (
        f"{expected} is present but empty; the copy created the file and wrote nothing"
    )
    assert archived > 0
    assert failed == 0, (
        f"the archiver reported {failed} failures (last: {last_failed}); segments are "
        "being retried and pg_wal will grow until the volume fills"
    )


# ── Point-in-time recovery ───────────────────────────────────────────────────


def test_recovery_stops_at_the_requested_instant(cluster):
    """THE test: restore to a chosen time and prove the later writes are absent.

    Recovery replaying everything would pass a "did the restore work" check while
    failing the only question that matters during the incident this exists for:
    can we get the database back to the state it was in one minute before the
    mistake.
    """
    manager, dsn, _data, root = cluster

    with _connect(dsn) as conn:
        conn.execute("DROP TABLE IF EXISTS snapshot")
        conn.execute("CREATE TABLE snapshot (id int primary key, tag text)")
        conn.execute("INSERT INTO snapshot VALUES (1, 'before-backup')")

    manifest = manager.base_backup(dsn=dsn, label="pitr")

    # Batch one: after the backup, before the target. Must survive.
    with _connect(dsn) as conn:
        conn.execute("INSERT INTO snapshot VALUES (2, 'keep-me')")
        conn.execute("SELECT pg_switch_wal()")

    # Let the clock clear the writes on both sides. PostgreSQL stops at the first
    # commit AFTER the target, so a target landing inside the same instant as a
    # commit makes the assertion a coin flip rather than a test.
    time.sleep(2)
    target = datetime.now(timezone.utc)
    time.sleep(2)

    # Batch two: after the target. Must NOT survive.
    with _connect(dsn) as conn:
        conn.execute("INSERT INTO snapshot VALUES (3, 'lose-me')")
        conn.execute("INSERT INTO snapshot VALUES (4, 'lose-me-too')")

    # Recovery replays only what the archive has. Without the segment spanning the
    # target, replay stops early and the test would fail claiming the target logic
    # is broken when the data simply had not been shipped.
    _wait_until_the_current_segment_is_archived(dsn)

    restore_dir = root / "restore-target"
    port = _free_port()
    manager.restore_to(manifest, target_time=target, restore_dir=restore_dir, port=port)

    conf = (restore_dir / "postgresql.conf").read_text(encoding="utf-8")
    assert f"recovery_target_time = '{target.isoformat()}'" in conf
    assert (restore_dir / "recovery.signal").exists(), (
        "without recovery.signal PostgreSQL treats this as crash recovery and the "
        "recovery target is silently inert"
    )

    manager.start(restore_dir, log_file=root / "restore.log", timeout=300)
    try:
        # Not "queryable" -- PAUSED. The server answers queries from the consistent
        # point onward, and reading there sees a half-replayed database.
        _wait_until_recovery_paused(_dsn(port))
        with _connect(_dsn(port)) as conn:
            rows = conn.execute("SELECT id FROM snapshot ORDER BY id").fetchall()
        recovered = {row[0] for row in rows}

        assert 1 in recovered, "data committed before the base backup was lost"
        assert 2 in recovered, (
            "the write committed between the backup and the target was not replayed: "
            "recovery stopped at the base backup, so the WAL archive is not being read"
        )
        assert not ({3, 4} & recovered), (
            f"the recovery target was NOT honoured -- restored ids {sorted(recovered)} "
            f"include writes committed after {target.isoformat()}"
        )

        # Having reached the target, the server must STAY in recovery. Promotion
        # generates a new timeline and cannot be rewound, so it is a decision an
        # operator makes after inspecting the result -- which is why `promote()` is
        # a separate call and `recovery_target_action` is 'pause'.
        with _connect(_dsn(port)) as conn:
            assert conn.execute("SELECT pg_is_in_recovery()").fetchone()[0] is True, (
                "the restored server promoted itself; the recovery is no longer "
                "inspectable and the timeline cannot be rewound"
            )
            with pytest.raises(Exception) as refused:
                conn.execute("CREATE TABLE should_not_exist (id int)")
        assert "read-only" in str(refused.value).lower()
    finally:
        try:
            manager.stop(restore_dir, mode="immediate")
        except BackupError:
            pass


def test_verify_restore_performs_the_restore_and_reports_how_long_it_took(cluster):
    """The scheduled entry point: restore, prove it, tear it down, record the time.

    `duration_seconds` is the number that matters at planning time. A recovery
    objective nobody has measured is a guess, and it is always optimistic.
    """
    manager, dsn, _data, root = cluster

    with _connect(dsn) as conn:
        conn.execute("DROP TABLE IF EXISTS verified")
        conn.execute("CREATE TABLE verified (id int primary key)")
        conn.execute("INSERT INTO verified VALUES (1)")

    manifest = manager.base_backup(dsn=dsn, label="verified")

    with _connect(dsn) as conn:
        conn.execute("INSERT INTO verified VALUES (2)")
    time.sleep(2)
    target = datetime.now(timezone.utc)
    time.sleep(2)
    with _connect(dsn) as conn:
        conn.execute("INSERT INTO verified VALUES (3)")
    _wait_until_the_current_segment_is_archived(dsn)

    seen: list[set[int]] = []

    def probe(restored_dsn: str) -> None:
        _wait_until_recovery_paused(restored_dsn)
        with _connect(restored_dsn) as conn:
            ids = {row[0] for row in conn.execute("SELECT id FROM verified")}
        seen.append(ids)
        assert ids == {1, 2}, f"restored to the wrong point: {sorted(ids)}"

    port = _free_port()
    result = manager.verify_restore(
        manifest,
        target_time=target,
        restore_dir=root / "restore-verified",
        port=port,
        probe=probe,
        patience_seconds=120.0,
    )

    assert result.recovered, str(result)
    assert result.manifest_label == "verified"
    assert result.duration_seconds > 0
    assert "RESTORED" in str(result)
    assert seen == [{1, 2}]

    # It must not leave a paused instance holding the port. A verification run that
    # does is one nobody schedules twice.
    with pytest.raises(Exception):
        _connect(_dsn(port))


def test_verify_restore_reports_a_rejecting_probe_instead_of_hanging(cluster):
    """A probe that never passes must produce a verdict, not a hang.

    This runs on a schedule. A verification that blocks forever on a bad restore is
    indistinguishable from one still in progress, and the alert never fires.
    """
    manager, dsn, _data, root = cluster
    manifest = manager.base_backup(dsn=dsn, label="unverifiable")

    # The target must be REACHABLE, or the server never starts and the probe is
    # never reached -- which tests a different thing (see the FATAL case below).
    # Reaching a target requires a commit after it for replay to stop at.
    with _connect(dsn) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS reachable (id serial primary key)")
        conn.execute("INSERT INTO reachable DEFAULT VALUES")
    time.sleep(2)
    target = datetime.now(timezone.utc)
    time.sleep(1)
    with _connect(dsn) as conn:
        conn.execute("INSERT INTO reachable DEFAULT VALUES")
    _wait_until_the_current_segment_is_archived(dsn)

    attempts: list[str] = []

    def never_passes(restored_dsn: str) -> None:
        attempts.append(restored_dsn)
        raise AssertionError("this restore is not acceptable")

    result = manager.verify_restore(
        manifest,
        target_time=target,
        restore_dir=root / "restore-unverifiable",
        port=_free_port(),
        probe=never_passes,
        # Short deliberately: the point is that the deadline is honoured.
        patience_seconds=8.0,
    )

    assert attempts, "the probe was never called, so this tested nothing"
    assert not result.recovered
    assert "not acceptable" in result.detail
    assert "FAILED" in str(result)
    assert result.duration_seconds < 120, "the deadline was not honoured"


def test_a_target_beyond_the_archived_wal_is_never_reported_as_verified(cluster):
    """PostgreSQL 13+ refuses to stay up rather than promoting.

    Asking for a target later than anything in the archive is an easy operator
    mistake -- "restore to now" after the primary has been down for an hour.
    PostgreSQL replays what it has and exits `FATAL: recovery ended before
    configured recovery target was reached`.

    WHICH failure the verification observes is a race -- the server accepts
    read-only connections at the consistent point and dies tens of milliseconds
    later, so `pg_ctl --wait` may catch it up or already shutting down. What must
    NOT vary is the verdict, so this asserts the verdict and accepts either
    observation rather than pinning a 50ms window.
    """
    manager, dsn, _data, root = cluster
    manifest = manager.base_backup(dsn=dsn, label="beyond-the-wal")

    unreachable = datetime.now(timezone.utc) + timedelta(days=1)

    def probe(restored_dsn: str) -> None:
        # Checks that replay REACHED the requested point, not merely that something
        # answered. A probe that only opens a connection is satisfied by a server
        # that is fifty milliseconds from a FATAL exit -- which is how this test
        # first "passed" while proving nothing. An unreachable target never pauses,
        # so this probe fails whether or not the connection lands.
        with _connect(restored_dsn) as conn:
            state = conn.execute(
                "SELECT pg_get_wal_replay_pause_state()"
            ).fetchone()[0]
        assert state == "paused", f"replay never reached the target: {state}"

    result = manager.verify_restore(
        manifest,
        target_time=unreachable,
        restore_dir=root / "restore-beyond",
        port=_free_port(),
        probe=probe,
        patience_seconds=10.0,
    )

    assert not result.recovered, (
        "a target beyond the end of the archived WAL was reported as a successful "
        f"restore: {result}"
    )
    assert (
        "recovery ended before configured recovery target" in result.detail
        or "never reached the target" in result.detail
        or "probe never succeeded" in result.detail
    ), f"the detail explains neither failure path: {result.detail!r}"


def test_a_failed_start_carries_the_server_log_into_the_result(tmp_path):
    """`pg_ctl` says "Examine the log output". The result must not stop there.

    A scheduled verification is read hours later, if at all. If its result does not
    contain the reason, someone has to find a log directory on a host that may no
    longer exist. Tested directly rather than through a real failed restore, because
    which failure path a restore takes is a race -- but the plumbing is not.
    """
    from sentinel.infrastructure.persistence.backup import _tail

    log = tmp_path / "server.log"
    log.write_text(
        "\n".join(f"line {n}" for n in range(60))
        + "\nFATAL:  recovery ended before configured recovery target was reached\n",
        encoding="utf-8",
    )

    tail = _tail(log)
    assert "recovery ended before configured recovery target" in tail
    assert "line 59" in tail
    assert "line 0" not in tail, "the tail is unbounded; a huge log would be inlined"

    # A missing log must not mask the failure it was being read to explain.
    assert "could not read" in _tail(tmp_path / "absent.log")


def test_the_restore_is_configured_to_pause_and_addressable_on_its_own_port(cluster):
    """A restore must not come up on the port the primary is serving.

    Recovery is a copy of a live cluster, and a copy that binds the primary's port
    either fails to start or -- worse, if the primary is down and being restored
    onto the same host -- accepts application traffic while still replaying.
    """
    manager, dsn, _data, root = cluster
    manifest = manager.base_backup(dsn=dsn, label="addressable")
    port = _free_port()
    restore_dir = manager.restore_to(
        manifest,
        target_time=manifest.earliest_target + timedelta(seconds=1),
        restore_dir=root / "restore-config",
        port=port,
    )
    conf = (restore_dir / "postgresql.conf").read_text(encoding="utf-8")

    assert "recovery_target_action = 'pause'" in conf
    # Last occurrence wins, and the restore settings are appended last.
    effective_port = [
        line for line in conf.splitlines() if line.strip().startswith("port")
    ][-1]
    assert str(port) in effective_port
    assert str(port) not in dsn, "the free port collided with the primary's"


def test_a_target_before_the_backup_is_refused_before_copying_anything(cluster):
    """Validated up front, not after a two-hour restore.

    A target preceding the base backup is unreachable from it however much WAL
    exists, and learning that after copying gigabytes is the difference between a
    ten-minute recovery and a wasted afternoon.
    """
    manager, dsn, _data, root = cluster
    manifest = manager.base_backup(dsn=dsn, label="bounds")
    impossible = manifest.earliest_target - timedelta(hours=1)

    restore_dir = root / "never-created"
    with pytest.raises(BackupError) as caught:
        manager.restore_to(
            manifest, target_time=impossible, restore_dir=restore_dir, port=_free_port()
        )
    message = str(caught.value)
    assert "not reachable" in message
    assert manifest.label in message
    assert not restore_dir.exists(), (
        "the restore copied the data directory despite an unreachable target"
    )


def test_a_restore_does_not_archive_into_the_archive_it_came_from(cluster):
    """Inheriting `archive_mode = on` would corrupt the source archive.

    The restored instance runs on a new timeline; archiving it into the same
    directory writes segments the next restore will try to replay, and takes the
    original backup down with it.
    """
    manager, dsn, _data, root = cluster
    manifest = manager.base_backup(dsn=dsn, label="isolated")
    restore_dir = root / "restore-isolation"

    manager.restore_to(
        manifest,
        target_time=manifest.earliest_target + timedelta(seconds=1),
        restore_dir=restore_dir,
        port=_free_port(),
    )
    conf = (restore_dir / "postgresql.conf").read_text(encoding="utf-8")

    # PostgreSQL takes the LAST occurrence of a setting, and the restore settings
    # are appended after the source's -- so the last line is the effective one.
    effective = [
        line for line in conf.splitlines() if line.strip().startswith("archive_mode")
    ][-1]
    assert "off" in effective, (
        f"the restored server would archive into the source archive: {effective}"
    )
    assert "restore_command" in conf
    assert not (restore_dir / "postmaster.pid").exists(), (
        "a stale postmaster.pid from the source cluster blocks startup"
    )
