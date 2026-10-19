"""Run the release gates this machine can actually run, and record what happened.

WHY THIS EXISTS
---------------
`build_release_evidence.py` reads gate artifacts; nothing wrote most of them.
Twenty of the twenty-six required gates had no producer at all, so the readiness
report said "no artifact was produced for this gate" in perpetuity. That reads
as "not measured yet" when the truth was "cannot be measured", and the two look
identical to anyone holding the report.

This is the producer. It runs a real command per gate, records the command, the
exit code and the tail of the output, and stamps the result with the commit and
source tree that produced it.

THE ONE RULE
------------
A GATE THAT DID NOT RUN GETS NO ARTIFACT.

Not a passing artifact, not a failing one -- nothing. `build_release_evidence`
reports a gate with no artifact as UNVERIFIED, which is the correct statement
about a check nobody performed. Writing a file for a tool that is not installed
would convert "we did not look" into "we looked and it was fine", and that is
the single most valuable lie a release report can tell.

So `mypy` missing means `type_check` stays UNVERIFIED. It does not mean the
types are fine.

A FAILING GATE DOES GET AN ARTIFACT
-----------------------------------
The inverse matters just as much. If the artifact only appeared on success, a
red gate and an unrun gate would produce the same evidence directory, and the
report would say UNVERIFIED for a check that ran and failed. So the file is
written either way, carrying `"ok": false` and the exit code, and
`build_release_evidence._judge` reads that field rather than the file's mere
existence.

WHAT IS DELIBERATELY NOT HERE
-----------------------------
`postgres_tests` is available behind `--with-postgres` and off by default. The
embedded-PostgreSQL fixture leaks a cluster per parametrisation on this
platform, and a default that quietly consumes the machine is a default nobody
runs twice. Off by default and UNVERIFIED is honest; on by default and hung is
not.

`container_build`, `kubernetes_helm`, `dast`, `container_scanning`,
`production_preflight`, `sbom`, `license_scan`, `artifact_signing`,
`migration_tests` and `redis_tests` have no runner here. They need a registry, a
cluster, a running deployment or a signing key, none of which a developer
workstation has by definition. They stay UNVERIFIED, and that is the accurate
report.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts import release_binding  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
GATE_DIR = ROOT / "release" / "gates"

#: How much of a failing command's output to keep.
#:
#: Enough to identify the failure, bounded so a thousand-line pytest dump does
#: not become the release artifact. The full output stays on the console; this
#: file is evidence that the gate ran and what it concluded, not a log store.
TAIL_LINES = 40

#: WHY NO `-q` ON THE PYTEST COMMANDS BELOW
#:
#: `pytest.ini` already sets `addopts = -q`. Passing it a second time makes
#: pytest DOUBLE-quiet, which drops the "N passed" summary line entirely --
#: leaving nothing but progress dots. `_run` reads that line to distinguish a
#: real pass from an all-skipped run, so the extra flag silently disabled the
#: check that stops a hollow gate from reporting green.
#:
#: It looked harmless. It read as "be quiet", and it was already quiet.


@dataclass(frozen=True)
class GateSpec:
    """One gate, and the command that decides it."""

    name: str
    command: tuple[str, ...]
    #: Executable that must be resolvable for this gate to be attempted. When it
    #: is missing the gate is SKIPPED and no artifact is written.
    requires: str
    why: str
    #: Environment variable that must be SET for this gate to mean anything.
    #: Absent -> the gate is skipped and no artifact is written, so it reports
    #: UNVERIFIED. Used where the tests SKIP without it: pytest exits 0 on an
    #: all-skipped run, so without this the gate would report PASS for checks
    #: that never executed.
    requires_env: str = ""


def _py() -> str:
    """This interpreter, not whatever `python` resolves to on PATH.

    A gate run against a different interpreter than the one holding the
    dependencies is a gate that reports an import error as a code failure.
    """
    return sys.executable


def _audit_ignores() -> tuple[str, ...]:
    """The documented pip-audit exceptions, read from the file that holds them.

    Read rather than duplicated: an exception list that exists in two places is
    one that will disagree with itself, and the copy in a gate runner is the one
    nobody thinks to update when a CVE is resolved.
    """
    path = ROOT / "security" / "pip-audit-ignore.txt"
    if not path.exists():
        return ()
    out: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        entry = line.strip()
        if entry and not entry.startswith("#"):
            out.extend(("--ignore-vuln", entry))
    return tuple(out)


def _tests_matching(pattern: str) -> tuple[str, ...]:
    """Test modules by glob, as repo-relative POSIX paths.

    Globbed rather than listed so a new security or chaos suite is covered by
    the gate the day it is added. A hardcoded list is a gate that silently
    stops covering the thing it names.
    """
    return tuple(
        sorted(
            str(p.relative_to(ROOT)).replace("\\", "/")
            for p in (ROOT / "tests_arch").glob(pattern)
        )
    )


def _specs() -> tuple[GateSpec, ...]:
    """The gates a workstation or CI runner can decide.

    Commands mirror `.github/workflows/ci.yml` rather than being invented here.
    Where they differ, the difference is recorded in the artifact so a reader
    comparing a local bundle against a CI one can see why.
    """
    py = _py()
    return (
        GateSpec(
            name="lint",
            command=(py, "-m", "ruff", "check", "sentinel", "tests_arch"),
            requires=py,
            why="ci.yml: ruff check sentinel tests_arch",
        ),
        GateSpec(
            name="type_check",
            # THE WHOLE PACKAGE, not just the domain.
            #
            # This gate used to check `sentinel/domain` alone. mypy was
            # therefore reporting `"AdmitEventHandler" has no attribute
            # "_assess_behaviour"` -- an entire behavioural-analytics feature
            # that was dead code nested inside another function, after that
            # function's return -- and nobody ever saw the line. The call site
            # wrapped it in `except Exception` and logged a warning, so ingest
            # kept working and every test kept passing.
            #
            # A type checker pointed at a third of the codebase is a type
            # checker that will miss the two thirds where the wiring lives.
            command=(
                py,
                "-m",
                "mypy",
                "sentinel",
                "--ignore-missing-imports",
            ),
            requires=py,
            why=(
                "ci.yml treats only sentinel/domain as blocking; the rest of the "
                "tree carries known errors that are counted, not gated"
            ),
        ),
        GateSpec(
            name="unit_tests",
            command=(
                py, "-m", "pytest", "-p", "no:cacheprovider",
                "-k", "not postgres",
            ),
            requires=py,
            why=(
                "ci.yml runs `pytest -q` with a PostgreSQL service; this runner "
                "excludes the postgres parametrisations and reports them under "
                "the separate postgres_tests gate, which stays UNVERIFIED unless "
                "--with-postgres is given"
            ),
        ),
        GateSpec(
            name="architecture_tests",
            command=(
                py, "-m", "pytest", "-p", "no:cacheprovider",
                "tests_arch/test_architecture_rules.py",
            ),
            requires=py,
            why="ci.yml: pytest -q tests_arch/test_architecture_rules.py",
        ),
        GateSpec(
            name="security_tests",
            command=(
                py, "-m", "pytest", "-p", "no:cacheprovider",
                "-k", "not postgres",
                "tests_arch/test_red_team_suite.py",
                "tests_arch/test_mcp_attacks.py",
                *_tests_matching("test_security_*.py"),
            ),
            requires=py,
            why="the red-team, MCP-attack and security_* suites",
        ),
        GateSpec(
            name="chaos_tests",
            command=(
                py, "-m", "pytest", "-p", "no:cacheprovider",
                "-k", "not postgres",
                *_tests_matching("test_*chaos*.py"),
            ),
            requires=py,
            why="every chaos suite in tests_arch",
        ),
        GateSpec(
            name="migration_tests",
            command=(
                py, "-m", "pytest", "-p", "no:cacheprovider",
                "-k", "not postgres",
                "tests_arch/test_migrations.py",
            ),
            requires=py,
            why=(
                "the migration suite. The PostgreSQL half is excluded here for "
                "the same reason unit_tests excludes it, and the RLS-after-"
                "fresh-migration check only runs there -- so a green gate on "
                "this runner does not cover it"
            ),
        ),
        GateSpec(
            name="redis_tests",
            command=(
                py, "-m", "pytest", "-p", "no:cacheprovider",
                "-k", "live_redis",
                "tests_arch/test_persistence_storage_cache.py",
            ),
            requires=py,
            requires_env="SENTINEL_TEST_REDIS_URL",
            why=(
                "ci.yml runs these against a redis:7 service. They SKIP unless "
                "SENTINEL_TEST_REDIS_URL points at a real server -- and a skip "
                "is not a pass, which is why `_run` checks that something "
                "actually executed"
            ),
        ),
        GateSpec(
            name="kubernetes_helm",
            command=(py, "scripts/check_helm_chart.py"),
            requires=py,
            why=(
                "NOT `helm lint`, which fails by design here: two deliberate "
                "guards refuse the default values. The script checks that the "
                "guards refuse AND that the chart renders once satisfied"
            ),
        ),
        GateSpec(
            name="production_preflight",
            command=(
                py, "-m", "pytest", "-p", "no:cacheprovider",
                "tests_arch/test_production_preflight.py",
            ),
            requires=py,
            why=(
                "the preflight suite: the checks a deployment must pass before "
                "it serves traffic. It reads configuration and refuses shapes "
                "production must not run, so it needs no environment of its own"
            ),
        ),
        GateSpec(
            name="dast",
            command=(py, "scripts/run_dast.py"),
            requires=py,
            why=(
                "schema-driven fuzzing of the RUNNING service, mirroring the "
                "dast job in ci.yml. The script starts uvicorn, migrates a "
                "throwaway database and writes its own gate artifact"
            ),
        ),
        GateSpec(
            name="sast",
            command=(py, "-m", "bandit", "-c", "bandit.yaml", "-r", "sentinel", "-ll"),
            requires=py,
            why="ci.yml: bandit -c bandit.yaml -r sentinel -ll",
        ),
        GateSpec(
            name="dependency_scanning",
            command=(
                py, "-m", "pip_audit", "-r", "requirements.txt", *_audit_ignores()
            ),
            requires=py,
            why=(
                "ci.yml: pip-audit with the exceptions in "
                "security/pip-audit-ignore.txt, which are recorded there rather "
                "than swallowed by the command"
            ),
        ),
        GateSpec(
            name="secret_scanning",
            command=(
                "gitleaks", "git", "--redact", "--no-banner",
                "--config", str(ROOT / ".gitleaks.toml"), str(ROOT),
            ),
            requires="gitleaks",
            why="ci.yml runs the pinned gitleaks image over the repository",
        ),
    )


#: Gates with no runner here, and the reason. Reported so `--list` explains the
#: gaps rather than leaving a reader to infer them from an absence.
NO_RUNNER: Mapping[str, str] = MappingProxyType({
    "postgres_tests": (
        "available behind --with-postgres; off by default because the embedded "
        "server leaks a cluster per parametrisation on this platform"
    ),
    "container_build": "needs a container runtime and a registry",
    "container_scanning": "needs a built image",
    "sbom": (
        "produced by scripts/build_sbom_and_licenses.py, which is a build "
        "step rather than a check -- it has no pass or fail to report"
    ),
    "license_scan": (
        "produced by scripts/build_sbom_and_licenses.py alongside the SBOM"
    ),
    "artifact_signing": (
        # The old reason here was "needs a signing key this runner does not
        # hold", which was a key-management objection and is no longer true:
        # the signing is KEYLESS, so there is no key. What is actually missing
        # locally is an OIDC identity and a registry, which is narrower and
        # honest. See scripts/verify_image_signature.py.
        "signed keylessly by the sign-image CI job, which needs a GitHub OIDC "
        "identity and a registry to push to -- neither of which a local runner "
        "has. Verify a signed image with scripts/verify_image_signature.py"
    ),
    "detection_evaluation": "produced by the evaluation harness, not by this runner",
    "performance_targets": (
        "produced by scripts/run_authorization_bench.py, which is a "
        "measurement rather than a check -- running it here would take a "
        "latency reading on whatever else this machine is doing"
    ),
})


def _postgres_spec() -> GateSpec:
    """The opt-in gate. Separate so the default path cannot reach it."""
    py = _py()
    return GateSpec(
        name="postgres_tests",
        command=(py, "-m", "pytest", "-p", "no:cacheprovider", "-k", "postgres"),
        requires=py,
        why="ci.yml: pytest -q -k postgres against a real server",
    )


def _run(spec: GateSpec, *, now: datetime) -> dict[str, object]:
    """Run one gate and describe the outcome. Never raises on failure."""
    started = now
    try:
        proc = subprocess.run(  # noqa: S603 - fixed commands from _specs()
            list(spec.command),
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": str(ROOT)},
            timeout=3600,
        )
        exit_code: int | None = proc.returncode
        output = (proc.stdout or "") + (proc.stderr or "")
        timed_out = False
    except subprocess.TimeoutExpired:
        # A timeout is a FAILURE, not an absence. The gate ran; it did not
        # finish. Reporting UNVERIFIED here would hide a hang behind the same
        # word used for a check nobody attempted.
        exit_code = None
        output = "the command exceeded the one-hour limit and was killed"
        timed_out = True

    tail = "\n".join(output.splitlines()[-TAIL_LINES:])
    ok = exit_code == 0

    # A PYTEST RUN THAT VERIFIED NOTHING IS NOT A PASS.
    #
    # pytest exits 0 when every selected test SKIPS, and 5 when it collects
    # none at all. Both are indistinguishable from success to an exit-code
    # check, and both mean the gate examined nothing -- the easiest way for a
    # green row to be meaningless. `redis_tests` is the live example: its tests
    # skip unless SENTINEL_TEST_REDIS_URL is set, so a machine with no Redis
    # would have reported PASS.
    #
    # Reported as a FAILURE, not a skip: the gate DID run and its selection
    # matched nothing, which is a broken gate and should be loud.
    verified_nothing = ""
    if ok and any("pytest" in part for part in spec.command):
        if exit_code == 5:
            verified_nothing = "pytest collected no tests"
        elif not re.search(r"[1-9][0-9]* passed", output):
            # `[1-9][0-9]*` and not a digit class: pytest prints
            # "0 passed, 5 skipped" for an all-skipped run, so a pattern
            # accepting a leading zero would match the exact case this
            # exists to catch.
            #
            # Written without a word-boundary escape ON PURPOSE. The first
            # version used one, a shell heredoc turned it into a literal
            # backspace byte, and the resulting regex matched nothing --
            # which would have failed EVERY pytest gate. It read correctly
            # in a terminal, because a backspace is invisible.
            verified_nothing = (
                "pytest reported no passing tests; every selected test was "
                "skipped or deselected"
            )
    if verified_nothing:
        ok = False
    if verified_nothing:
        summary = (
            f"{spec.name}: the command succeeded but VERIFIED NOTHING -- "
            f"{verified_nothing}. A gate whose selection matched nothing is a "
            "broken gate, not a passing one."
        )
    elif ok:
        summary = f"{spec.name}: exit 0"
    elif timed_out:
        summary = f"{spec.name}: TIMED OUT running `{' '.join(spec.command)}`"
    else:
        summary = f"{spec.name}: exit {exit_code} running `{' '.join(spec.command)}`"
    return {
        "gate": spec.name,
        "ok": ok,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "verified_nothing": verified_nothing or None,
        "command": list(spec.command),
        "command_rationale": spec.why,
        "summary": summary,
        "output_tail": tail,
        "output_truncated": len(output.splitlines()) > TAIL_LINES,
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            # RECORDED BECAUSE ONE GATE READS SOMETHING ELSE.
            #
            # `secret_scanning` runs `gitleaks git`, which scans COMMITTED
            # HISTORY. Every other gate reads the working tree. On a dirty tree
            # those are different things, and the difference is not academic: a
            # secret-shaped line in an uncommitted file passes this gate and
            # then fails it on the next run, as a history finding that needs an
            # exception rather than an edit. That happened here.
            #
            # A reader of the bundle can see which situation produced it.
            "working_tree_dirty": _working_tree_is_dirty(),
        },
        "started_at": started.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }


#: A process that IS pytest, rather than one that merely mentions it.
#:
#: The first version matched the bare substring "pytest" anywhere in a command
#: line, and the embedded PostgreSQL fixture stores its data directory under
#: `pytest-of-<user>/pytest-<n>/pgdata`. Every postmaster and background worker
#: therefore carried "pytest" in its `-D` argument and was counted as a
#: competing test run -- so the guard refused during the very suite it was
#: meant to protect, failing three of its own tests.
#:
#: `pytest` must appear as an executable or a `-m` module argument: preceded by
#: a path separator, whitespace or start-of-string, and followed by whitespace,
#: `.exe` or end-of-string. `pytest-of-pc` and `pytest-3` both have a hyphen
#: next and no longer match.
_RUNS_PYTEST = re.compile(
    r"(?:^|[\\/\s\"'])pytest(?:\.exe)?(?:[\s\"']|$)|-m\s+pytest\b",
    re.IGNORECASE,
)


#: Free space the temp volume needs before a run means anything.
#:
#: The embedded PostgreSQL fixture calls `initdb` per parametrisation and each
#: cluster is tens of megabytes; the container build and the DAST database want
#: room too. Five gigabytes is not a measurement, it is a floor below which
#: failures stop being about the code.
MIN_FREE_TEMP_BYTES = 5 * 1024**3


def _temp_free_bytes() -> tuple[int, str]:
    """Free bytes on the volume pytest will write to, and which volume."""
    import shutil
    import tempfile

    location = tempfile.gettempdir()
    try:
        return shutil.disk_usage(location).free, location
    except OSError:
        return -1, location


def _process_table() -> list[tuple[int, int, str]]:
    """(pid, parent_pid, command_line) for every process, or [] if unavailable."""
    if sys.platform == "win32":
        probe = [
            "powershell", "-NoProfile", "-Command",
            "Get-CimInstance Win32_Process | ForEach-Object "
            "{ \"$($_.ProcessId)|$($_.ParentProcessId)|$($_.CommandLine)\" }",
        ]
    else:
        probe = ["bash", "-lc", "ps -eo pid=,ppid=,args= | tr -s ' '"]

    try:
        result = subprocess.run(  # noqa: S603 - fixed argv
            probe, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=90, check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return []

    rows: list[tuple[int, int, str]] = []
    for line in (result.stdout or "").splitlines():
        parts = line.strip().split("|", 2) if "|" in line else line.split(None, 2)
        if len(parts) < 2:
            continue
        try:
            rows.append((int(parts[0]), int(parts[1]), parts[2] if len(parts) > 2 else ""))
        except ValueError:
            continue
    return rows


def _other_test_processes() -> tuple[int, str]:
    """How many pytest processes are running that are NOT this one's own.

    A second pytest sharing this machine fights this one for temp directories,
    ports and the embedded PostgreSQL fixture, and the losses surface as
    collection ERRORS. The runner then records `unit_tests: FAILED` for a suite
    that passes cleanly alone -- a fabricated defect, and the mirror of the DAST
    bug where a crashed scanner was filed as a security finding.

    It happened: a docs check run by hand during a gate run produced 66 errors
    across two gates, and both suites passed in isolation immediately after.

    SELF AND ANCESTORS ARE EXCLUDED.
    -----------------------------------
    `main()` is also called BY the runner's own test suite, so when this check
    counted every pytest it found, it counted the pytest running the test and
    refused -- failing three of its own tests. Ancestors are excluded for that
    reason; a pytest that is this process's parent is the harness, not a
    competitor.

    Returns `(-1, reason)` when the count cannot be taken. UNKNOWN is recorded
    as unknown: a check that cannot run must not report zero.

    IT CAN UNDER-COUNT, AND THAT IS NOT A SILENT FAILURE.
    --------------------------------------------------------
    A process owned by another user returns an EMPTY command line to an
    unelevated query, so a pytest run by somebody else on the same machine is
    invisible here. This guard therefore catches the common case -- a second
    run by the same operator, which is what actually happens -- and not a
    hostile or cross-account one.

    It is a convenience against a self-inflicted mistake, not a security
    control, and nothing should treat it as one. The measurement that matters
    is still the artifact, and a contended run remains detectable afterwards by
    the collection errors it records.
    """
    table = _process_table()
    if not table:
        return -1, "the process table could not be read"

    parents = {pid: ppid for pid, ppid, _cmd in table}
    mine = {os.getpid()}
    walker = os.getpid()
    # Bounded: a corrupt table with a parent cycle would otherwise spin here.
    for _hop in range(64):
        walker = parents.get(walker, 0)
        if not walker or walker in mine:
            break
        mine.add(walker)

    others = [
        pid
        for pid, _ppid, cmd in table
        if pid not in mine and _RUNS_PYTEST.search(cmd)
    ]
    return len(others), f"{len(table)} processes examined, own ancestry excluded"


def _working_tree_is_dirty() -> bool:
    """Whether tracked files differ from HEAD."""
    status = subprocess.run(  # noqa: S603,S607 - fixed command
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    return bool(status.stdout.strip())


def _write(record: Mapping[str, object], *, identity, now: datetime) -> Path:
    """Write the gate artifact and bind it to this build."""
    GATE_DIR.mkdir(parents=True, exist_ok=True)
    path = GATE_DIR / f"gate_{record['gate']}.json"
    path.write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    release_binding.write_binding(path, release=identity, now=now)
    return path


def _identity(now: datetime):
    """What this build IS, read from git rather than accepted as an argument."""
    head = subprocess.run(  # noqa: S603,S607 - fixed command
        ["git", "rev-parse", "HEAD"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    commit = head.stdout.strip()
    if not commit:
        raise SystemExit(
            "cannot determine HEAD. A gate artifact that cannot name the commit "
            "it came from is unbound evidence, which the release report treats "
            "as UNVERIFIED anyway -- so refusing here is the same verdict, "
            "reached before writing a misleading file."
        )
    # The SAME function the report uses to verify. A second implementation
    # here would drift, and a drifted tree digest makes every artifact verify
    # as UNBOUND -- reported as UNVERIFIED, indistinguishable from never having
    # run the gate at all.
    return release_binding.release_identity(commit, root=ROOT)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="run and record the release gates")
    parser.add_argument(
        "--with-postgres",
        action="store_true",
        help="also run the postgres parametrisations (slow; leaks clusters)",
    )
    parser.add_argument(
        "--only", action="append", default=[], help="run only these gates"
    )
    parser.add_argument("--list", action="store_true", help="show gates and exit")
    args = parser.parse_args(argv)

    specs = list(_specs())
    if args.with_postgres:
        specs.append(_postgres_spec())
    if args.only:
        wanted = set(args.only)
        specs = [s for s in specs if s.name in wanted]

    if args.list:
        for spec in specs:
            print(f"RUNS       {spec.name:<24} {' '.join(spec.command[:6])}")
        for name, reason in NO_RUNNER.items():
            print(f"NO RUNNER  {name:<24} {reason}")
        return 0

    now = datetime.now(timezone.utc)
    identity = _identity(now)

    # REFUSE TO MEASURE WHILE SOMETHING ELSE IS TESTING.
    #
    # Contention does not produce a wrong number, it produces a WRONG VERDICT:
    # collection errors are recorded as a failing gate, and a suite that passes
    # cleanly gets a FAILED artifact bound to this build.
    failures: list[str] = []
    skipped: list[str] = []

    for spec in specs:
        if spec.requires_env and not os.environ.get(spec.requires_env, "").strip():
            # No artifact. The tests would SKIP, pytest would exit 0, and the
            # gate would claim a pass for a check nobody performed.
            skipped.append(f"{spec.name} ({spec.requires_env} unset)")
            print(
                f"SKIP  {spec.name}: {spec.requires_env} is unset, so its tests "
                "would skip and report a hollow pass; leaving UNVERIFIED"
            )
            continue
        if shutil.which(spec.requires) is None and not Path(spec.requires).exists():
            # NO ARTIFACT. A missing tool is not a passing gate and not a
            # failing one -- it is a check nobody performed, and UNVERIFIED is
            # what the report should say.
            skipped.append(f"{spec.name} (missing {spec.requires})")
            print(f"SKIP  {spec.name}: {spec.requires} not found; leaving UNVERIFIED")
            continue
        print(f"RUN   {spec.name}: {' '.join(spec.command)}", flush=True)
        record = _run(spec, now=datetime.now(timezone.utc))
        path = _write(record, identity=identity, now=now)
        verdict = "PASS" if record["ok"] else "FAIL"
        # `relative_to` raises for a path outside the repository, which is the
        # case whenever GATE_DIR is redirected. A crash in a progress line
        # would abort a run whose gates had all succeeded.
        shown = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
        print(f"{verdict:<5} {spec.name} -> {shown}")
        if not record["ok"]:
            failures.append(spec.name)

    # THE TREE MUST NOT HAVE MOVED WHILE THE GATES RAN.
    #
    # `identity` is stamped once, before the first command. A full run takes
    # tens of minutes, and anyone editing the tree during it produces artifacts
    # that claim a source digest the commands did not actually run against.
    # The provenance sidecars would verify -- the digest is real, it is simply
    # a digest of a tree that no longer exists -- so the report would show green
    # gates bound to this build for code that was never tested.
    #
    # That is the exact failure the whole binding mechanism exists to prevent,
    # reproduced by the tool meant to feed it. It happened on this runner's
    # first full run.
    #
    # The artifacts are DELETED rather than marked. A file explaining why it is
    # not evidence is still a file the collector will find, and the collector's
    # job is to read artifacts, not to adjudicate their notes. Removing them
    # leaves the gates UNVERIFIED, which is the accurate report: nobody has
    # measured this tree.
    after = release_binding.release_identity(identity.commit, root=ROOT)
    if after.source_tree_sha256 != identity.source_tree_sha256:
        for spec in specs:
            for suffix in ("", release_binding.PROVENANCE_SUFFIX):
                stale = GATE_DIR / f"gate_{spec.name}.json{suffix}"
                stale.unlink(missing_ok=True)
        print()
        print(
            "REFUSED: the source tree changed while the gates were running, so "
            "these results describe no single version of the code. Every "
            "artifact this run wrote has been deleted; the gates stay "
            "UNVERIFIED, which is the accurate report. Re-run against a still "
            "tree."
        )
        return 2

    ran = len(specs) - len(skipped)
    print()
    print(f"ran {ran}, failed {len(failures)}, skipped {len(skipped)}")
    for entry in skipped:
        print(f"  UNVERIFIED (not run): {entry}")
    for name in failures:
        print(f"  FAILED: {name}")
    # Exit non-zero on a failing gate so CI notices, but the artifacts are
    # already written -- the report must be able to show a red gate.
    return 1 if failures else 0


def check_environment() -> None:
    """Refuse to measure on a machine that cannot support a measurement.

    Asked HERE rather than inside `main()`, because `main()` is called
    in-process by this runner's own test suite. A precondition living there has
    now twice failed the wrong thing: the concurrency guard counted the pytest
    running the test, and the disk guard refused because the machine under test
    was full. Both were right about the machine and wrong about what to do
    with that.

    Nothing is bypassed by the split. A test calling `main()` is not producing
    release evidence, and every real run goes through `cli()`.
    """
    # A FULL DISK IS NOT A FAILING GATE.
    #
    # `initdb` cannot create a cluster with no space, so every test needing the
    # embedded PostgreSQL fixture ERRORS -- and the runner would record
    # `migration_tests: FAILED`, `chaos_tests: FAILED` and two more, for suites
    # that pass immediately once there is room. That happened: four gates went
    # red at 0.1GB free and all of them passed with the temp directory moved to
    # a volume with space.
    #
    # Refused rather than warned, for the same reason a moving tree is refused:
    # the results would be about the environment, not the build, and nothing
    # downstream could tell.
    free, where = _temp_free_bytes()
    if 0 <= free < MIN_FREE_TEMP_BYTES:
        raise SystemExit(
            f"REFUSING: only {free / 1024**3:.2f} GB free on the temp volume "
            f"({where}).\n\n"
            "The embedded PostgreSQL fixture runs `initdb` per parametrisation "
            "and cannot with no space, so suites that pass on a machine with "
            "room would be recorded as FAILING GATES. A fabricated defect is "
            "worse than no measurement.\n\n"
            "Free space, or point TEMP/TMPDIR at a volume that has some."
        )
    if free < 0:
        print(f"NOTE: could not read free space on {where}.")

    concurrent, how = _other_test_processes()
    if concurrent > 0:
        raise SystemExit(
            f"REFUSING: {concurrent} other pytest process(es) are running "
            f"({how}).\n\n"
            "A second test process competes for temp directories, ports and "
            "the embedded PostgreSQL fixture, and the losses appear as "
            "collection errors -- which this runner would record as a failing "
            "gate. A fabricated defect is worse than no measurement.\n\n"
            "Wait for it to finish, then re-run."
        )
    if concurrent < 0:
        print(
            f"NOTE: could not count other test processes ({how}). If something "
            "else is running pytest, this run may record contention as gate "
            "failures."
        )
    if _working_tree_is_dirty():
        print(
            "NOTE: the working tree differs from HEAD. `secret_scanning` reads "
            "COMMITTED HISTORY, so an uncommitted secret-shaped line will pass "
            "here and fail on the next run as a history finding. Every "
            "artifact records working_tree_dirty=true."
        )


def cli(argv: Sequence[str] | None = None) -> int:
    """What a human or CI runs: preconditions, then the work."""
    check_environment()
    return main(argv)


if __name__ == "__main__":
    raise SystemExit(cli())
