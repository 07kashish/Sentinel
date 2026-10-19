"""The DR wrapper cannot report coverage it does not have.

WHAT THIS GUARDS
----------------
Three ways a DR runner flatters itself, all of which produce a green line:

  1. Treating a SKIPPED drill as a pass. A drill skipped because PostgreSQL is
     absent exercised nothing, and a pipeline that counts it as a success
     reports recovery it has never performed.
  2. Inferring "skipped" from any non-zero exit, which turns a genuine
     recovery failure into a shrug.
  3. Letting a pass be read as coverage of the open gate.
     `INDEPENDENT_FAILURE_DOMAIN_DR` needs a restore into another region or
     account; every drill here runs on one machine, so no arrangement of them
     closes it. The verdict says so and the evidence field is a hardcoded
     false.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


from scripts.run_dr_test import (
    DRILLS,
    FAIL,
    OPEN_GATE_NOTE,
    PASS,
    SKIPPED,
    Result,
    _run,
)

ROOT = Path(__file__).resolve().parent.parent


class _Completed:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


# ── the catalogue is honest about each drill ───────────────────────────────


def test_every_drill_says_what_it_does_not_prove():
    """A drill described only by what it proves is a drill that gets
    over-quoted. The limit travels with it.
    """
    assert len(DRILLS) >= 3
    for drill in DRILLS:
        assert len(drill.proves) > 30, drill.name
        assert len(drill.does_not_prove) > 40, drill.name


def test_the_sqlite_drill_disclaims_postgres_and_rls():
    """The cheapest drill is the one most likely to be run and quoted. SQLite
    has no RLS layer, so a restore verified there is not a restore of the
    tenant-isolation guarantees.
    """
    sqlite = next(d for d in DRILLS if d.name == "sqlite")

    assert "PostgreSQL" in sqlite.does_not_prove
    assert "RLS" in sqlite.does_not_prove


def test_the_dump_drill_disclaims_its_own_rpo():
    """A pg_dump RPO is 0 by construction, which is not the number that
    matters when the loss is unplanned.
    """
    dump = next(d for d in DRILLS if d.name == "postgres_dump")

    assert "0 by construction" in dump.does_not_prove


def test_every_named_script_exists():
    """A catalogue entry pointing at an absent script would report FAIL for a
    reason that looks like a broken recovery.
    """
    for drill in DRILLS:
        assert (ROOT / "scripts" / drill.script).exists(), drill.script


# ── a skip is never a pass ────────────────────────────────────────────────


def test_a_missing_postgres_is_skipped_not_passed(monkeypatch):
    import scripts.run_dr_test as module

    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *a, **k: _Completed(1, stderr="no PostgreSQL available"),
    )
    drill = next(d for d in DRILLS if d.name == "postgres_wal")

    result = _run(drill, timeout=10)

    assert result.status == SKIPPED
    assert result.status != PASS
    assert "NOT a pass" in result.detail


def test_a_genuine_failure_is_not_mistaken_for_a_skip(monkeypatch):
    """Inferring "skipped" from any non-zero exit would turn a real recovery
    failure into a shrug. The marker has to be in the output.
    """
    import scripts.run_dr_test as module

    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *a, **k: _Completed(1, stderr="restored database failed integrity check"),
    )

    result = _run(DRILLS[0], timeout=10)

    assert result.status == FAIL
    assert "integrity" in result.detail


def test_a_timeout_is_a_failure_not_a_skip(monkeypatch):
    """A recovery that does not finish is a recovery that failed."""
    import scripts.run_dr_test as module

    def explode(*_a, **_k):
        raise subprocess.TimeoutExpired(cmd="x", timeout=1)

    monkeypatch.setattr(module.subprocess, "run", explode)

    result = _run(DRILLS[0], timeout=1)

    assert result.status == FAIL
    assert "does not finish" in result.detail


def test_strict_fails_on_a_skip(monkeypatch, capsys):
    """What a CI job should use. Without it a pipeline reports recovery it has
    not exercised.
    """
    import scripts.run_dr_test as module

    monkeypatch.setattr(
        module,
        "_run",
        lambda drill, timeout: Result(drill, SKIPPED, "needs a server"),
    )

    assert module.main(["--strict"]) == 1
    assert module.main([]) == 0, "a skip without --strict is not a failure"


def test_a_failure_fails_regardless_of_strict(monkeypatch):
    import scripts.run_dr_test as module

    monkeypatch.setattr(
        module, "_run", lambda drill, timeout: Result(drill, FAIL, "broken")
    )

    assert module.main([]) == 1


# ── the open gate stays open ───────────────────────────────────────────────


def test_the_verdict_always_says_the_gate_is_open(monkeypatch, capsys):
    """No arrangement of these drills closes
    INDEPENDENT_FAILURE_DOMAIN_DR, so a run in which everything passes must
    still say so.
    """
    import scripts.run_dr_test as module

    monkeypatch.setattr(
        module, "_run", lambda drill, timeout: Result(drill, PASS, "ok")
    )

    assert module.main([]) == 0
    output = capsys.readouterr().out

    assert "remains OPEN" in output
    # The note has to name the gate and what would close it. Checked against
    # the actual wording rather than a phrase I expected it to contain.
    assert "INDEPENDENT_FAILURE_DOMAIN_DR" in OPEN_GATE_NOTE
    assert "another region or account" in OPEN_GATE_NOTE
    assert "ONE failure domain" in OPEN_GATE_NOTE


def test_the_limit_is_printed_beside_each_pass(monkeypatch, capsys):
    """Not in a footnote. A green line read on its own is how a drill becomes
    over-quoted.
    """
    import scripts.run_dr_test as module

    monkeypatch.setattr(
        module, "_run", lambda drill, timeout: Result(drill, PASS, "ok")
    )
    module.main(["--only", "sqlite"])

    output = capsys.readouterr().out

    assert "does NOT prove" in output


def test_the_evidence_records_a_hardcoded_false(monkeypatch, tmp_path):
    """The field cannot be set true by any run, because nothing here can
    verify a separate failure domain.
    """
    import scripts.run_dr_test as module

    monkeypatch.setattr(
        module, "_run", lambda drill, timeout: Result(drill, PASS, "ok")
    )
    evidence = tmp_path / "dr.json"

    module.main(["--evidence", str(evidence)])
    payload = json.loads(evidence.read_text(encoding="utf-8"))

    assert payload["independent_failure_domain_verified"] is False
    assert payload["passed"] == len(DRILLS)
    # Each result carries its own limit, so the artifact cannot be quoted
    # without it either.
    for row in payload["results"]:
        assert row["does_not_prove"]


# ── it actually runs ──────────────────────────────────────────────────────


def test_explain_runs_without_touching_a_database():
    """An operator should be able to read what each drill does before running
    one that spins up a server.
    """
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "run_dr_test.py"), "--explain"],
        capture_output=True, text=True, cwd=str(ROOT),
        env={"PYTHONPATH": str(ROOT)}, timeout=60,
    )

    assert result.returncode == 0, result.stderr
    assert "does NOT prove" in result.stdout
    assert "remains OPEN" in result.stdout


def test_the_sqlite_drill_really_passes():
    """The one drill that needs nothing. If this fails, the restore code path
    is broken and every other verdict here is about a broken foundation.
    """
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "run_dr_test.py"),
            "--only", "sqlite",
        ],
        capture_output=True, text=True, cwd=str(ROOT),
        env={"PYTHONPATH": str(ROOT)}, timeout=300,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "1 passed, 0 failed, 0 skipped" in result.stdout
