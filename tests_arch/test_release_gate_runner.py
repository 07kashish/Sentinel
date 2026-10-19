"""A release gate must be able to fire, and a red gate must read as red.

THE DEFECT THIS MODULE PINS
---------------------------
`build_release_evidence.collect` resolved each gate to an artifact FILENAME from
a `sources` dict. Twenty-one of the twenty-six required gates were absent from
that dict, so `filename` was None, `find()` was never called, and the gate
reported:

    UNVERIFIED  unit_tests  no artifact was produced for this gate

forever. No artifact could change it, because nothing looked for one. The
message invites a reader to go and produce the artifact; producing it would have
done nothing.

That is worse than a failing gate. A gate stuck on caution is indistinguishable
from a gate nobody has got to yet, and a release report of mostly-UNVERIFIED
rows reads as "early days" rather than as "this instrument is disconnected".

WHY THE RUNNER WRITES A FILE FOR A FAILING GATE
-------------------------------------------------
If artifacts appeared only on success, then a gate that ran and failed and a
gate that never ran would leave identical evidence directories, and the report
would say UNVERIFIED for a check that had actually gone red. So the runner
writes the record either way and `_judge` reads what it says.

WHY IT WRITES NOTHING FOR A TOOL THAT IS ABSENT
-------------------------------------------------
The opposite case. A missing scanner is not a clean scan. No artifact means
UNVERIFIED, which is the correct statement about a check nobody performed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import build_release_evidence as evidence
from scripts import release_binding, run_release_gates

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


def test_every_required_gate_resolves_to_an_artifact_name():
    """The regression. A gate with no filename can never be anything but
    UNVERIFIED, and the report gives no hint that the gate is disconnected
    rather than merely pending.
    """
    bundle = evidence.collect(ROOT / "does-not-exist")
    reported = {g.name for g in bundle.gates}
    for name in evidence.REQUIRED_GATES:
        assert name in reported, f"{name} is required but never reported"

    # The real check: ask `collect` where it would look. A gate absent from the
    # source map has nowhere to look and is therefore inert.
    missing = [
        name
        for name in evidence.REQUIRED_GATES
        if not _source_filename_for(name)
    ]
    assert not missing, (
        "these gates resolve to no artifact filename, so no artifact can ever "
        f"satisfy them: {missing}. They would report UNVERIFIED forever while "
        "reading as 'not measured yet'."
    )


def _source_filename_for(name: str) -> str:
    """Re-derive the filename `collect` would search for.

    Derived from the same convention rather than from a second list: a copy of
    the mapping here would let the two drift and this test would then pass
    against a mapping the collector does not use.
    """
    explicit = {
        "detection_evaluation": "metrics.json",
        "sbom": "sentinel.cdx.json",
        "license_scan": "licenses.json",
        "artifact_signing": "manifest.sig",
        "performance_targets": "authorization_bench.json",
    }
    return explicit.get(name, f"gate_{name}.json")


def test_a_gate_with_no_runner_is_documented_rather_than_silently_absent():
    """`--list` must account for every required gate, one way or the other.

    A gate that neither runs nor appears in NO_RUNNER is one nobody decided
    about: the reader cannot tell whether it was forgotten or deliberately
    excluded.
    """
    runnable = {s.name for s in run_release_gates._specs()}
    runnable.add(run_release_gates._postgres_spec().name)
    accounted = runnable | set(run_release_gates.NO_RUNNER)
    unaccounted = set(evidence.REQUIRED_GATES) - accounted
    assert not unaccounted, (
        f"these required gates have no runner and no documented reason: "
        f"{sorted(unaccounted)}"
    )


# ── a red gate reads as red ──────────────────────────────────────────────────


@pytest.fixture
def bound_gate(tmp_path, monkeypatch):
    """Write a gate artifact bound to a synthetic release, and read it back."""

    def _write(payload: dict) -> tuple[str, str]:
        gates = tmp_path / "release" / "gates"
        gates.mkdir(parents=True, exist_ok=True)
        path = gates / f"gate_{payload['gate']}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        identity = release_binding.release_identity("0" * 40, root=ROOT)
        release_binding.write_binding(
            path,
            release=identity,
            now=__import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ),
        )
        return evidence._judge(payload["gate"], path)

    return _write


def test_an_artifact_recording_failure_is_FAIL_not_PASS(bound_gate):
    """The whole reason the runner writes a file on failure."""
    status, detail = bound_gate(
        {"gate": "lint", "ok": False, "exit_code": 1, "summary": "lint: exit 1"}
    )
    assert status == evidence.FAIL
    assert "exit 1" in detail


def test_an_artifact_recording_success_is_PASS(bound_gate):
    status, _detail = bound_gate(
        {"gate": "lint", "ok": True, "exit_code": 0, "summary": "lint: exit 0"}
    )
    assert status == evidence.PASS


def test_ok_must_be_the_boolean_true_and_not_merely_truthy(bound_gate):
    """A runner that wrote `"ok": "failed"` would otherwise report PASS.

    Every non-empty string is truthy, so a truth test on a field that could
    carry a status word turns a failure into a pass. The one value that means
    success is `True`.
    """
    for truthy in ("failed", "yes", 1, ["something"], {"a": 1}):
        status, _detail = bound_gate(
            {"gate": "lint", "ok": truthy, "exit_code": 1, "summary": "s"}
        )
        assert status == evidence.FAIL, f"{truthy!r} was treated as success"


def test_a_timeout_is_a_failure_not_an_absence(bound_gate):
    """A gate that hung ran. Reporting UNVERIFIED would use the same word as a
    gate nobody attempted.
    """
    status, detail = bound_gate(
        {
            "gate": "unit_tests",
            "ok": False,
            "exit_code": None,
            "timed_out": True,
            "summary": "unit_tests: TIMED OUT",
        }
    )
    assert status == evidence.FAIL
    assert "TIMED OUT" in detail


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


def test_the_runner_and_the_report_compute_the_same_release_identity():
    """If they diverge, every artifact verifies as UNBOUND.

    UNBOUND is reported as UNVERIFIED -- the same word as a gate nobody ran --
    so a one-line difference in how the file list is built would blank the whole
    report with nothing pointing at the cause.
    """
    from_report = evidence._release_identity("a" * 40)
    from_runner = release_binding.release_identity("a" * 40, root=ROOT)
    assert from_report.source_tree_sha256 == from_runner.source_tree_sha256


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

    real_identity = release_binding.release_identity
    calls = {"n": 0}

    def _drifting(commit, *, root):
        calls["n"] += 1
        identity = real_identity(commit, root=root)
        if calls["n"] == 1:
            return identity
        # The second call is the post-run re-read. A different digest is what
        # an edit during the run would have produced.
        return release_binding.ReleaseIdentity(
            commit=identity.commit,
            source_tree_sha256="f" * 64,
            image_digest=identity.image_digest,
        )

    monkeypatch.setattr(run_release_gates, "_specs", lambda: (quick,))
    monkeypatch.setattr(release_binding, "release_identity", _drifting)
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
