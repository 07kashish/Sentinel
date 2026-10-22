"""Release checks must run, fail honestly and discard results after source edits."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts import run_release_gates

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _isolated_gate_dir(tmp_path, monkeypatch):
    """Never touch the real `release/gates/`.

    WHY THIS IS AUTOUSE AND NOT PER-TEST
    -------------------------------------
    Two tests below drive `run_release_gates.main`, which WRITES gate artifacts
    and, on a void run, DELETES them. Pointed at the real directory they did
    exactly that: a full gate run executed `lint` first, then `unit_tests` ran
    the suite, and this module deleted `gate_lint.json` from underneath it. The
    readiness report then said UNVERIFIED for a gate that had passed twenty
    minutes earlier -- a green check erased by the tests that verify the thing
    that writes it.

    Autouse because the next test to call `main()` would reintroduce it, and
    the failure is silent: nothing errors, a gate simply goes missing.
    """
    monkeypatch.setattr(run_release_gates, "GATE_DIR", tmp_path / "gates")


# ── no gate may be unable to fire ────────────────────────────────────────────








# ── a red gate reads as red ──────────────────────────────────────────────────












# ── the runner never invents evidence ────────────────────────────────────────


def test_the_runner_writes_no_artifact_for_a_tool_it_cannot_find(tmp_path, capsys):
    """A missing scanner is not a clean scan.

    Driven through `main` with a gate whose `requires` cannot resolve, so the
    property is proven at the level that decides it rather than by reading the
    branch.
    """
    absent = run_release_gates.GateSpec(
        name="secret_scanning",
        command=("definitely-not-installed-xyzzy", "--version"),
        requires="definitely-not-installed-xyzzy",
        why="a tool that is not here",
    )
    written: list[Path] = []
    original_write = run_release_gates._write

    def _spy(record, *, identity, now):
        path = original_write(record, identity=identity, now=now)
        written.append(path)
        return path

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(run_release_gates, "_specs", lambda: (absent,))
        mp.setattr(run_release_gates, "_write", _spy)
        exit_code = run_release_gates.main([])

    assert written == [], "an artifact was written for a gate that never ran"
    # Zero, not one: nothing failed. A missing tool is unknown, not bad.
    assert exit_code == 0
    assert "UNVERIFIED (not run)" in capsys.readouterr().out




def test_the_pip_audit_exceptions_are_read_from_the_file_that_holds_them():
    """Not duplicated into the runner, where nobody would update them."""
    ignores = run_release_gates._audit_ignores()
    path = ROOT / "security" / "pip-audit-ignore.txt"
    if not path.exists():
        assert ignores == ()
        return
    declared = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert list(ignores).count("--ignore-vuln") == len(declared)
    for entry in declared:
        assert entry in ignores


def test_the_test_globs_pick_up_a_newly_added_suite(tmp_path, monkeypatch):
    """A hardcoded module list is a gate that stops covering what it names."""
    new = ROOT / "tests_arch" / "test_security_zzz_probe_tmp.py"
    new.write_text("def test_placeholder():\n    assert True\n", encoding="utf-8")
    try:
        matched = run_release_gates._tests_matching("test_security_*.py")
        assert "tests_arch/test_security_zzz_probe_tmp.py" in matched
    finally:
        new.unlink()


def test_results_are_discarded_if_the_tree_changes_mid_run(monkeypatch):
    """Evidence about a moving target is not evidence.

    `identity` is stamped once, before the first command, and a full run takes
    tens of minutes. Editing the tree during one produces artifacts whose
    provenance sidecar VERIFIES -- the digest is real -- while describing a tree
    the commands never ran against. The report would then show green gates
    bound to this build for code that was never tested, which is precisely what
    the binding mechanism exists to prevent. It happened on the runner's first
    full run.

    The divergence is SIMULATED rather than caused. An earlier version of this
    test wrote a real file into `sentinel/` to move the digest, which meant a
    test of the runner perturbed the tree that other gates were measuring --
    reproducing, inside the test suite, the very hazard under test.
    """
    quick = run_release_gates.GateSpec(
        name="lint",
        command=(run_release_gates._py(), "-c", "pass"),
        requires=run_release_gates._py(),
        why="a command that always succeeds",
    )

    real_identity = run_release_gates._identity
    calls = {"n": 0}

    def _drifting(now):
        calls["n"] += 1
        identity = real_identity(now)
        if calls["n"] == 1:
            return identity
        # The second call is the post-run re-read. A different digest is what
        # an edit during the run would have produced.
        return identity[0], "f" * 64

    monkeypatch.setattr(run_release_gates, "_specs", lambda: (quick,))
    monkeypatch.setattr(run_release_gates, "_identity", _drifting)
    exit_code = run_release_gates.main([])

    # 2, not 1: the gates did not fail, the run is void.
    assert exit_code == 2
    artifact = run_release_gates.GATE_DIR / "gate_lint.json"
    assert not artifact.exists(), (
        "an artifact survived a run whose tree changed underneath it; the "
        "collector would read it as this build's evidence"
    )
    assert not artifact.with_name(artifact.name + ".provenance.json").exists()


def test_the_suite_never_writes_to_the_real_evidence_directory():
    """The regression for the defect this module caused.

    A test that deletes real release evidence produces a readiness report that
    is wrong in the safe-looking direction: UNVERIFIED for a gate that passed.
    Nothing errors, so the only way to notice is to compare the runner's own
    output against the report -- which is how it was found.
    """
    assert run_release_gates.GATE_DIR != ROOT / "release" / "gates", (
        "the autouse fixture is not in effect; this suite would write to and "
        "delete from the real evidence directory"
    )


# ── a gate that verified nothing is not a gate that passed ───────────────────


def test_an_all_skipped_pytest_run_is_not_a_pass():
    """THE hollow pass.

    pytest exits 0 when every selected test SKIPS. To an exit-code check that
    is indistinguishable from success, and it is the easiest way for a green
    row to mean nothing at all. `redis_tests` is the live example: its tests
    skip unless SENTINEL_TEST_REDIS_URL points at a real server, so any machine
    without Redis would have reported PASS for a check that never ran.
    """
    import os
    from datetime import datetime, timezone

    with pytest.MonkeyPatch.context() as mp:
        mp.delenv("SENTINEL_TEST_REDIS_URL", raising=False)
        spec = run_release_gates.GateSpec(
            name="redis_tests",
            command=(
                run_release_gates._py(), "-m", "pytest", "-p", "no:cacheprovider",
                "-k", "live_redis",
                "tests_arch/test_persistence_storage_cache.py",
            ),
            requires=run_release_gates._py(),
            why="probe",
        )
        record = run_release_gates._run(spec, now=datetime.now(timezone.utc))

    assert record["exit_code"] == 0, "the probe did not reproduce an exit-0 skip"
    assert record["ok"] is False, (
        "a run in which every test skipped was reported as a pass"
    )
    assert "VERIFIED NOTHING" in record["summary"]
    assert os.environ.get("SENTINEL_TEST_REDIS_URL") is None or True


def test_a_selection_that_matches_no_test_is_not_a_pass():
    """pytest exits 5 when it collects nothing. A gate whose selector has gone
    stale -- a renamed module, a changed marker -- would otherwise sit green
    forever while testing nothing.
    """
    from datetime import datetime, timezone

    spec = run_release_gates.GateSpec(
        name="unit_tests",
        command=(
            run_release_gates._py(), "-m", "pytest", "-p", "no:cacheprovider",
            "-k", "zzz_this_matches_no_test_anywhere",
            "tests_arch/test_migrations.py",
        ),
        requires=run_release_gates._py(),
        why="probe",
    )
    record = run_release_gates._run(spec, now=datetime.now(timezone.utc))
    assert record["ok"] is False


def test_no_pytest_gate_passes_the_redundant_quiet_flag():
    """`pytest.ini` already sets `addopts = -q`. A second `-q` makes pytest
    DOUBLE-quiet and drops the "N passed" summary entirely.

    That line is the only thing distinguishing a real pass from an all-skipped
    run, so the extra flag silently disables the check above. It looked
    harmless -- it read as "be quiet", and pytest was already quiet -- and it
    made every pytest gate fail once the check existed.
    """
    source = (ROOT / "scripts" / "run_release_gates.py").read_text(encoding="utf-8")
    assert '"pytest", "-q"' not in source, (
        "a pytest gate passes -q on top of pytest.ini's addopts, which "
        "suppresses the summary line the hollow-pass check depends on"
    )


def test_the_pass_pattern_refuses_a_zero_count():
    """Read from the source rather than retyped.

    The first version of this pattern used a word-boundary escape, a shell
    heredoc turned it into a literal backspace byte, and the regex then matched
    nothing -- which would have failed every pytest gate. It was invisible in a
    terminal, and a retyped copy of the pattern tested fine while the one on
    disk was broken. So this reads the real one.
    """
    import re

    source = (ROOT / "scripts" / "run_release_gates.py").read_text(encoding="utf-8")
    found = re.search(r'not re\.search\((r"[^"]+")', source)
    assert found, "the pass-count pattern is no longer where this test looks"
    pattern = eval(found.group(1))  # noqa: S307 - a literal from our own source

    assert re.search(pattern, "12 passed, 3 skipped")
    assert re.search(pattern, "1 passed")
    # The case the whole check exists for.
    assert not re.search(pattern, "0 passed, 5 skipped")
    assert not re.search(pattern, "5 skipped")
    assert chr(8) not in pattern, "the pattern contains a literal backspace"


def test_a_gate_needing_an_absent_environment_writes_no_artifact(tmp_path, capsys):
    """`requires_env` exists so a gate cannot report on tests that would skip.

    No artifact means UNVERIFIED, which is the accurate word for a check this
    machine is not configured to perform.
    """
    spec = run_release_gates.GateSpec(
        name="redis_tests",
        command=(run_release_gates._py(), "-c", "pass"),
        requires=run_release_gates._py(),
        requires_env="SENTINEL_TEST_REDIS_URL",
        why="probe",
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.delenv("SENTINEL_TEST_REDIS_URL", raising=False)
        mp.setattr(run_release_gates, "_specs", lambda: (spec,))
        exit_code = run_release_gates.main([])

    assert exit_code == 0, "an unconfigured gate is unknown, not failed"
    assert not (run_release_gates.GATE_DIR / "gate_redis_tests.json").exists()
    assert "hollow pass" in capsys.readouterr().out
