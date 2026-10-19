r"""Backups and point-in-time recovery, as code rather than a runbook.

WHY THIS IS A MODULE AND NOT A WIKI PAGE
-----------------------------------------
A backup nobody has restored is not a backup. It is a file that might be one.

The failure mode is always the same: the backup job is monitored, so it goes green
for two years, and the first restore anyone attempts is during an incident,
against a procedure written from memory by someone who has left. Making this a
module means `verify_restore` can run on a schedule and in CI, and the answer to
"can we recover" comes from having just done it.

WHAT PITR ACTUALLY REQUIRES
---------------------------
Three things, and missing any one silently reduces recovery to "the last base
backup":

  1. `wal_level = replica` (or higher). Anything less does not log enough to
     replay.
  2. `archive_mode = on` with an `archive_command` that SUCCEEDS. A command that
     exits non-zero makes PostgreSQL retry forever and `pg_wal` grows until the
     volume fills -- a backup misconfiguration that presents as a disk outage.
  3. A base backup, plus every WAL segment from the moment it started. A gap in
     the WAL is a hard stop: recovery replays to the gap and no further.

`preflight` checks all three against the LIVE server and reports which are
missing, rather than discovering it at restore time.

AND A COMMAND THAT SUCCEEDS INTO NOWHERE IS WORSE THAN ONE THAT FAILS
---------------------------------------------------------------------
A failing `archive_command` at least raises `failed_count`. The quiet variant does
not: `postgresql.conf` treats backslash as an escape inside a quoted value, so a
Windows path written verbatim comes back with every separator stripped --
`'copy "%p" "E:\wal\%f"'` is read as `copy "%p" "E:wal%f"`. That is a valid
DRIVE-RELATIVE path, so the copy SUCCEEDS into the data directory under a
run-together name. PostgreSQL marks the segment archived, `archived_count` climbs,
`failed_count` stays at zero, and the archive stays empty. Every dashboard is green
and there is nothing to recover from.

This is why `_conf_value` escapes what it writes, why `preflight` reads settings
back from the running server instead of trusting the file, and why the test for
this asserts on the CONTENTS of the archive directory rather than on the archiver's
own statistics.

THE RECOVERY TARGET
-------------------
`restore_to` writes `recovery.signal` and a `recovery_target_time`, which is what
makes this point-in-time rather than merely restore-the-backup. The target must lie
between the base backup and the end of the archived WAL, and the two ends fail
differently:

  * BEFORE the base backup: unreachable however much WAL exists. `restore_to`
    rejects this up front, because discovering it after copying gigabytes is the
    difference between a ten-minute recovery and a wasted afternoon.
  * AFTER the end of the archived WAL: PostgreSQL 13+ replays everything it has and
    then exits with `FATAL: recovery ended before configured recovery target was
    reached`. It does NOT promote and it does NOT stay up -- so the symptom is a
    server that will not start, and the reason is only in the server log. This end
    cannot be validated in advance without reading the archive, so `verify_restore`
    puts the log tail into its result instead.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tarfile
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping, Sequence

from sentinel.domain.errors import SentinelError

__all__ = [
    "BackupError",
    "BackupManifest",
    "Preflight",
    "PostgresBackup",
    "RestoreVerification",
]


#: Which shell dialect the archive and restore commands are written for.
#:
#: Read from here rather than from `os.name` at each call site so a test can drive
#: the branch that does not match the host. Only one of the two ever runs on any
#: given machine, which makes the other dead code until CI reaches it -- and an
#: archive command whose first real execution is in production is the thing this
#: module exists to prevent. Patching `os.name` itself is not an option: `pathlib`
#: reads it to decide whether `Path` is a `WindowsPath`, so overriding it breaks
#: every path in the process.
_IS_WINDOWS = os.name == "nt"


class BackupError(SentinelError):
    """A backup or restore failed. Never retried blindly: the cause is structural."""

    is_retryable = False


def _tail(path: Path, *, lines: int = 25) -> str:
    """The end of a server log, for putting a cause where the failure is reported."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"(could not read {path}: {exc})"
    return "\n".join(text.splitlines()[-lines:])


@dataclass(frozen=True, slots=True)
class Preflight:
    """Whether this server can actually support point-in-time recovery."""

    wal_level: str
    archive_mode: str
    archive_command: str
    #: True only if all three prerequisites hold.
    pitr_capable: bool
    problems: tuple[str, ...] = ()

    def __str__(self) -> str:
        if self.pitr_capable:
            return (
                f"PITR capable: wal_level={self.wal_level}, "
                f"archive_mode={self.archive_mode}"
            )
        return "PITR NOT capable: " + "; ".join(self.problems)


@dataclass(frozen=True, slots=True)
class BackupManifest:
    """What a base backup contains, recorded beside it.

    Written at backup time because the facts needed to plan a restore -- the LSN
    it starts from, the earliest target it can reach -- are knowable then and
    expensive to reconstruct later.
    """

    label: str
    path: Path
    started_at: datetime
    finished_at: datetime
    size_bytes: int
    wal_archive: Path
    #: The earliest point-in-time this backup can recover to. A target before this
    #: is not reachable from this backup, however much WAL exists.
    earliest_target: datetime

    def as_dict(self) -> Mapping[str, object]:
        return {
            "label": self.label,
            "path": str(self.path),
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "size_bytes": self.size_bytes,
            "wal_archive": str(self.wal_archive),
            "earliest_target": self.earliest_target.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class RestoreVerification:
    """The outcome of an actually-performed restore.

    Recorded so the answer to "can we recover" is a timestamp and a duration
    rather than an opinion. `duration_seconds` is the number that matters at
    planning time: a recovery objective nobody has measured is a guess, and it is
    always optimistic.
    """

    manifest_label: str
    target_time: datetime
    verified_at: datetime
    duration_seconds: float
    recovered: bool
    detail: str

    def __str__(self) -> str:
        verdict = "RESTORED" if self.recovered else "FAILED"
        return (
            f"{verdict} {self.manifest_label} -> {self.target_time.isoformat()} "
            f"in {self.duration_seconds:.1f}s: {self.detail}"
        )


class PostgresBackup:
    """Base backups, WAL archiving and point-in-time restore.

    Takes explicit paths to the PostgreSQL binaries rather than trusting `PATH`.
    A restore that silently used a `pg_ctl` from a different major version would
    fail in a way whose error message points nowhere near the cause.
    """

    __slots__ = ("_bin", "_data_dir", "_archive_dir", "_backup_root")

    def __init__(
        self,
        *,
        bin_dir: Path,
        data_dir: Path,
        archive_dir: Path,
        backup_root: Path,
    ) -> None:
        self._bin = Path(bin_dir)
        self._data_dir = Path(data_dir)
        self._archive_dir = Path(archive_dir)
        self._backup_root = Path(backup_root)
        for required in ("pg_basebackup", "pg_ctl"):
            if not self._tool(required).exists():
                raise BackupError(
                    f"{required} not found in {self._bin}. Backups need the "
                    "PostgreSQL binaries of the SAME major version as the server."
                )
        self._archive_dir.mkdir(parents=True, exist_ok=True)
        self._backup_root.mkdir(parents=True, exist_ok=True)

    # Callers wrap this in `str(...)`: a subprocess argument vector is a list
    # of strings, and a Path in one is accepted by CPython while being wrong
    # for anything that inspects the command -- logging, an allowlist check, or
    # a future move to a remote runner.
    def _tool(self, name: str) -> Path:
        candidate = self._bin / name
        return candidate if candidate.exists() else self._bin / f"{name}.exe"

    def _run(self, argv: Sequence[str], *, what: str, timeout: int = 600) -> str:
        """Run a PostgreSQL binary, capturing output to a FILE rather than a pipe.

        `capture_output=True` deadlocks here, and the deadlock survives its own
        timeout. `pg_ctl start` leaves a postmaster running, and on Windows that
        postmaster inherits the parent's handles -- including the write end of the
        capture pipe. `pg_ctl` exits, but the pipe never reaches EOF because the
        postmaster still holds it, so `subprocess.run` blocks reading it forever;
        and when the timeout fires it drains the pipe again on the way out, so it
        blocks there too. A regular file has no EOF to wait for.
        """
        with tempfile.TemporaryFile() as sink:
            try:
                completed = subprocess.run(  # noqa: S603 - argv is constructed, never shell
                    [str(a) for a in argv],
                    stdout=sink,
                    stderr=subprocess.STDOUT,
                    timeout=timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise BackupError(f"{what} timed out after {timeout}s") from exc
            sink.seek(0)
            output = sink.read().decode("utf-8", "replace")
        if completed.returncode != 0:
            raise BackupError(
                f"{what} failed (exit {completed.returncode}):\n{output[-3000:]}"
            )
        return output

    @staticmethod
    def _conf_value(value: str) -> str:
        r"""Escape a value for a single-quoted postgresql.conf setting.

        The config parser treats BOTH backslash and single quote as escapes inside
        a quoted value, so a Windows path written verbatim loses every separator:
        `'copy "%p" "E:\wal\%f"'` is read back as `copy "%p" "E:wal%f"`.

        That is not a cosmetic bug. The mangled path is drive-relative, so `copy`
        SUCCEEDS -- it writes the segment into the data directory under a
        run-together name. PostgreSQL sees exit 0, marks the segment archived and
        increments `archived_count`; `failed_count` stays at zero. Every signal
        says archiving works while the archive stays empty and recovery has
        nothing to replay. Doubling the separators here is what prevents a backup
        that is monitored green and does not exist.
        """
        return value.replace("\\", "\\\\").replace("'", "''")

    # ── Configuration ────────────────────────────────────────────────────────

    def archive_settings(self) -> Mapping[str, str]:
        """The settings PITR requires, as a mapping to append to postgresql.conf.

        `archive_command` is a copy that REFUSES to overwrite. An archive command
        that clobbers an existing segment can destroy the WAL a concurrent restore
        is reading, and the standard `test ! -f && cp` idiom is the documented
        guard against exactly that.
        """
        if _IS_WINDOWS:
            # `copy` overwrites by default; the existence test is what prevents it.
            #
            # Quoting here is deliberately flat -- individual paths are quoted and
            # nothing else is. PostgreSQL runs this through `cmd /c`, whose parser
            # treats `\"` as a literal backslash followed by a quote toggle rather
            # than an escaped quote (that is an MSVC argv convention, not a cmd
            # one), so a command wrapped in its own escaped quotes is mangled into
            # something that always exits non-zero -- which PostgreSQL retries
            # forever while `pg_wal` grows until the volume fills.
            destination = f'"{self._archive_dir}\\%f"'
            command = f'cmd /c if not exist {destination} copy "%p" {destination}'
        else:
            # Double-quoted rather than bare. The documented idiom is unquoted, which
            # silently breaks the moment the archive directory contains a space --
            # `test` then sees two arguments and the command fails on every segment.
            destination = f'"{self._archive_dir.as_posix()}/%f"'
            command = f"test ! -f {destination} && cp %p {destination}"
        return {
            "wal_level": "replica",
            "archive_mode": "on",
            "archive_command": command,
            # Bound how long a segment can sit unarchived. Without it a quiet
            # database can leave the current segment unarchived indefinitely, so
            # the recoverable window lags real time by however long it stays quiet.
            "archive_timeout": "60",
            # Retain enough WAL that a replica or a backup can catch up.
            "wal_keep_size": "128MB",
        }

    def apply_archive_settings(self, *, conf_path: Path | None = None) -> Path:
        """Append the PITR settings to postgresql.conf. Requires a restart.

        Appends rather than rewrites: PostgreSQL takes the LAST occurrence of a
        setting, so appending overrides cleanly without parsing a file that may
        contain includes, comments and operator edits.
        """
        target = conf_path or (self._data_dir / "postgresql.conf")
        if not target.exists():
            raise BackupError(f"no postgresql.conf at {target}")
        lines = [
            "",
            f"# --- Sentinel PITR settings, appended {datetime.now(timezone.utc).isoformat()} ---",
        ]
        lines.extend(
            f"{key} = '{self._conf_value(value)}'"
            for key, value in self.archive_settings().items()
        )
        with target.open("a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        return target

    def preflight(self, conn) -> Preflight:
        """Ask the LIVE server whether PITR is actually possible."""
        wal_level = conn.one("SHOW wal_level")["wal_level"]
        archive_mode = conn.one("SHOW archive_mode")["archive_mode"]
        archive_command = conn.one("SHOW archive_command")["archive_command"]

        problems: list[str] = []
        if wal_level not in ("replica", "logical"):
            problems.append(
                f"wal_level is {wal_level!r}; PITR needs 'replica' or 'logical'"
            )
        if archive_mode not in ("on", "always"):
            problems.append(
                f"archive_mode is {archive_mode!r}; without archiving, recovery "
                "stops at the base backup"
            )
        if not archive_command.strip():
            problems.append(
                "archive_command is empty; segments are recycled rather than kept"
            )
        return Preflight(
            wal_level=wal_level,
            archive_mode=archive_mode,
            archive_command=archive_command,
            pitr_capable=not problems,
            problems=tuple(problems),
        )

    # ── Backup ───────────────────────────────────────────────────────────────

    def base_backup(self, *, dsn: str, label: str | None = None) -> BackupManifest:
        """Take a base backup with `pg_basebackup`.

        `--wal-method=stream` streams the WAL generated DURING the backup
        alongside it, so the result is self-consistent even if archiving is
        lagging. Without it a backup can finish needing segments the archive does
        not have yet, and is unrestorable until they arrive.
        """
        started = datetime.now(timezone.utc)
        name = label or f"base-{started.strftime('%Y%m%dT%H%M%SZ')}"
        target = self._backup_root / name
        if target.exists():
            raise BackupError(f"a backup named {name} already exists at {target}")

        self._run(
            [
                str(self._tool("pg_basebackup")),
                "--dbname", dsn,
                "--pgdata", str(target),
                "--format=plain",
                "--wal-method=stream",
                "--checkpoint=fast",
                "--progress",
                "--no-password",
                f"--label={name}",
            ],
            what=f"pg_basebackup ({name})",
        )
        finished = datetime.now(timezone.utc)
        size = sum(f.stat().st_size for f in target.rglob("*") if f.is_file())
        return BackupManifest(
            label=name,
            path=target,
            started_at=started,
            finished_at=finished,
            size_bytes=size,
            wal_archive=self._archive_dir,
            # The earliest reachable target is the moment the backup COMPLETED.
            # A target inside the backup window is not consistent, because
            # different files were copied at different instants.
            earliest_target=finished,
        )

    def archive_segments(self) -> tuple[str, ...]:
        """WAL segments currently archived, in order."""
        if not self._archive_dir.is_dir():
            return ()
        return tuple(
            sorted(f.name for f in self._archive_dir.iterdir() if f.is_file())
        )

    def compress(self, manifest: BackupManifest, *, destination: Path | None = None) -> Path:
        """Compress a base backup for off-site retention.

        `tar.gz` rather than a database-level dump: a base backup is already the
        physical files, and compressing them is a transfer concern rather than a
        format conversion. gzip because it is readable by anything, on any host,
        in ten years -- which is the only property that matters for an archive
        nobody looks at until they need it badly.
        """
        target = destination or (self._backup_root / f"{manifest.label}.tar.gz")
        with tarfile.open(target, "w:gz") as archive:
            archive.add(manifest.path, arcname=manifest.label)
        return target

    # ── Restore ──────────────────────────────────────────────────────────────

    def restore_to(
        self,
        manifest: BackupManifest,
        *,
        target_time: datetime,
        restore_dir: Path,
        port: int,
    ) -> Path:
        """Restore the backup and replay WAL to `target_time`.

        Validates the target is reachable BEFORE copying gigabytes. A target
        before the backup completed cannot be reached from it, and finding that
        out after a two-hour restore is the difference between a ten-minute
        recovery and a wasted afternoon.
        """
        if target_time < manifest.earliest_target:
            raise BackupError(
                f"recovery target {target_time.isoformat()} precedes the end of "
                f"base backup {manifest.label} ({manifest.earliest_target.isoformat()}). "
                "This target is not reachable from this backup; use an earlier one."
            )

        restore_dir = Path(restore_dir)
        if restore_dir.exists():
            shutil.rmtree(restore_dir)
        shutil.copytree(manifest.path, restore_dir)

        # A restored data directory must not inherit the source's archive
        # settings: it would archive its OWN recovery WAL into the same directory
        # and corrupt the archive it is restoring from.
        conf = restore_dir / "postgresql.conf"
        restore_command = (
            f'cmd /c copy "{self._archive_dir}\\%f" "%p"'
            if os.name == "nt"
            else f"cp {self._archive_dir.as_posix()}/%f %p"
        )
        with conf.open("a", encoding="utf-8") as handle:
            handle.write(
                "\n".join(
                    (
                        "",
                        "# --- Sentinel restore settings ---",
                        "archive_mode = 'off'",
                        f"restore_command = '{self._conf_value(restore_command)}'",
                        f"recovery_target_time = '{target_time.isoformat()}'",
                        # Stop AT the target and stay stopped, rather than
                        # promoting straight to read/write. An operator must be
                        # able to inspect the result before it accepts writes.
                        "recovery_target_action = 'pause'",
                        f"port = {port}",
                    )
                )
                + "\n"
            )

        # `recovery.signal` is what tells PostgreSQL 12+ this is a PITR rather
        # than a crash recovery. Its absence makes the recovery_target_time above
        # silently inert.
        (restore_dir / "recovery.signal").write_text("", encoding="utf-8")
        for stale in ("postmaster.pid", "standby.signal"):
            (restore_dir / stale).unlink(missing_ok=True)
        return restore_dir

    def start(self, data_dir: Path, *, log_file: Path, timeout: int = 120) -> None:
        self._run(
            [
                str(self._tool("pg_ctl")),
                "--pgdata", str(data_dir),
                "--log", str(log_file),
                "--timeout", str(timeout),
                "--wait",
                "start",
            ],
            what=f"pg_ctl start ({data_dir.name})",
            timeout=timeout + 30,
        )

    def stop(self, data_dir: Path, *, mode: str = "fast", timeout: int = 120) -> None:
        self._run(
            [
                str(self._tool("pg_ctl")),
                "--pgdata", str(data_dir),
                "--mode", mode,
                "--timeout", str(timeout),
                "--wait",
                "stop",
            ],
            what=f"pg_ctl stop ({data_dir.name})",
            timeout=timeout + 30,
        )

    def verify_restore(
        self,
        manifest: BackupManifest,
        *,
        target_time: datetime,
        restore_dir: Path,
        port: int,
        probe: Callable[[str], None],
        patience_seconds: float = 180.0,
        start_timeout_seconds: int = 180,
    ) -> RestoreVerification:
        """Restore, start, prove it works, shut it down. The whole point.

        `probe` receives a DSN for the restored server and raises if the data is
        not what the caller expected. It is a callable rather than a query so this
        module keeps no database driver dependency -- the caller owns its schema
        and its definition of "correct", and this owns the mechanics.

        The probe is RETRIED until `patience_seconds` expires, because a server
        replaying WAL refuses connections until it reaches a consistent state. The
        retry is what distinguishes "still replaying" from "never came up"; the
        deadline is what stops the latter hanging a scheduled job forever.

        `start_timeout_seconds` is deliberately separate from `patience_seconds`.
        They bound different things -- how long the postmaster may take to accept
        connections, versus how long the data may take to become correct -- and
        deriving one from the other means a caller who wants a strict probe deadline
        silently gets a startup deadline too short for the server to come up, and a
        result that blames the probe for a failure that never reached it.

        Always stops the restored server, including on failure. A verification run
        that leaves a paused instance holding a port is a verification run nobody
        schedules twice.
        """
        began = time.monotonic()
        self.restore_to(
            manifest, target_time=target_time, restore_dir=restore_dir, port=port
        )
        log = Path(restore_dir).parent / f"{Path(restore_dir).name}.log"
        dsn = f"postgresql://postgres@127.0.0.1:{port}/postgres"
        detail = ""
        recovered = False
        try:
            self.start(restore_dir, log_file=log, timeout=start_timeout_seconds)
            deadline = time.monotonic() + patience_seconds
            last: Exception | None = None
            while time.monotonic() < deadline:
                try:
                    probe(dsn)
                    recovered, detail = True, "probe satisfied"
                    break
                except Exception as exc:  # noqa: BLE001 - any failure means "not yet"
                    last = exc
                    time.sleep(2.0)
            if not recovered:
                detail = f"probe never succeeded within {patience_seconds}s: {last!r}"
        except BackupError as exc:
            # pg_ctl's own message is "Examine the log output", which is no use to
            # a scheduled job that will not be read by a human for hours. The
            # reason a restore refuses to start is always in the server log -- most
            # often a target beyond the end of the archived WAL, which PostgreSQL
            # 13+ treats as FATAL rather than promoting -- so put it in the result.
            detail = f"restored server did not start: {exc}\n{_tail(log)}"
        finally:
            try:
                self.stop(restore_dir, mode="immediate")
            except BackupError:
                # The server may never have started. Failing to stop it must not
                # mask why the verification failed.
                pass
        return RestoreVerification(
            manifest_label=manifest.label,
            target_time=target_time,
            verified_at=datetime.now(timezone.utc),
            duration_seconds=time.monotonic() - began,
            recovered=recovered,
            detail=detail,
        )

    def promote(self, data_dir: Path) -> None:
        """End recovery and accept writes.

        Separate from `restore_to` deliberately. A paused recovery can be
        inspected; a promoted one has generated a new timeline and cannot be
        rewound. Promotion is a decision, so it is a distinct call.
        """
        self._run(
            [str(self._tool("pg_ctl")), "--pgdata", str(data_dir), "promote"],
            what=f"pg_ctl promote ({data_dir.name})",
        )
