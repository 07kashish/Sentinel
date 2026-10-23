"""The continuous-WAL PITR drill must measure, or say it did not.

`reports/dr_postgres_pitr_drill.json` records a `pg_dump` round-trip whose RPO is
0 by construction: nothing is written between the backup and the "failure". That
number is real but it does not test the claim `docs/OPERATIONS.md` makes,
which is about a continuously running system losing a node without warning.

`scripts/run_dr_postgres_wal_pitr_drill.py` measures that instead. These tests
guard the two ways its record could become untrustworthy:

  * it could report numbers when it never ran a server, and
  * it could report a "PITR" that merely replayed everything to the end, which
    is a restore, not a point-in-time recovery.

The drill itself is slow (it initdbs, base-backs-up, crashes and recovers a real
cluster twice), so the live run is marked `slow` and the honesty checks are not.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_dr_postgres_wal_pitr_drill.py"
RESULT = ROOT / "reports" / "dr_postgres_wal_pitr_drill.json"
QUIET_RESULT = ROOT / "reports" / "dr_postgres_wal_pitr_quiet_drill.json"

#: Targets stated in docs/OPERATIONS.md.
RPO_TARGET_SECONDS = 300
RTO_TARGET_SECONDS = 1800


def test_the_drill_script_exists_and_declares_its_targets():
    source = SCRIPT.read_text(encoding="utf-8")
    assert f"RPO_TARGET_SECONDS = {RPO_TARGET_SECONDS}" in source
    assert f"RTO_TARGET_SECONDS = {RTO_TARGET_SECONDS}" in source
    # The failure must be a crash. A clean shutdown archives the open segment and
    # would report an RPO of 0 -- the same flattering non-answer as the dump drill.
    assert '"immediate"' in source
    assert "archive_mode = on" in source


def test_recorded_result_is_internally_consistent():
    """Whatever the file claims, it must not claim measurement without numbers."""
    if not RESULT.exists():
        pytest.skip("drill has not been run in this tree")
    out = json.loads(RESULT.read_text(encoding="utf-8"))

    if out["status"] == "UNVERIFIED":
        # The honest failure shape: a named precondition and no numbers at all.
        assert out["measured"] is None
        assert out["precondition"]
        assert out["ok"] is False
        return

    assert out["status"] == "measured_continuous_wal_archive"
    measured = out["measured"]

    # A point-in-time recovery that returns every batch is not a point-in-time
    # recovery. This is the assertion that separates PITR from "restore latest".
    assert measured["pitr_selected_point_in_time"] is True
    assert measured["pitr_observed_max_batch"] == measured["pitr_target_batch"], (
        "recovery to a target time returned batches beyond the target: "
        f"{measured['pitr_observed_max_batch']} > {measured['pitr_target_batch']}"
    )

    # Crash recovery from an archive cannot be lossless: the segment being
    # written when the server died was never archived. An RPO of exactly 0 here
    # would mean the drill did not actually crash anything.
    assert measured["experimental_rpo_seconds"] > 0.0, (
        "continuous-archive RPO reported as 0 -- that is the dump drill's answer, "
        "not a crash's; the server was probably shut down cleanly"
    )
    assert measured["rows_lost_to_unarchived_segment"] > 0

    assert measured["experimental_rpo_seconds"] <= RPO_TARGET_SECONDS
    assert measured["experimental_rto_seconds"] <= RTO_TARGET_SECONDS
    assert out["meets_rpo_target"] is True
    assert out["meets_rto_target"] is True

    # The measurement must not silently be re-described as something stronger.
    assert "NOT a cross-region failover" in measured["notes"]


def test_the_dump_drill_result_is_not_overwritten_by_this_one():
    """Both records must survive: they prove different things.

    The dump round-trip demonstrates restore correctness for a snapshot; the WAL
    drill demonstrates recovery from an unplanned crash. Collapsing them into one
    file would lose whichever claim the last run did not make.
    """
    dump = ROOT / "reports" / "dr_postgres_pitr_drill.json"
    if not dump.exists() or not RESULT.exists():
        pytest.skip("both drills have not been run in this tree")
    assert dump != RESULT, "the two drills must not write the same file"
    dump_status = json.loads(dump.read_text(encoding="utf-8"))["status"]
    wal_status = json.loads(RESULT.read_text(encoding="utf-8"))["status"]
    assert dump_status in {"measured_dump_roundtrip", "UNVERIFIED"}
    assert wal_status in {"measured_continuous_wal_archive", "UNVERIFIED"}
    assert dump_status != wal_status or wal_status == "UNVERIFIED", (
        "the two records collapsed onto the same claim; they prove different things"
    )


def test_quiet_record_attributes_its_rpo_to_archive_timeout():
    """The low-traffic case, where `archive_timeout` is the only rotator.

    The busy drill forces `pg_switch_wal()` between batches, so its RPO reflects
    a system writing hard enough to rotate segments on its own. A quiet Sentinel
    does not: it fills a 16 MB segment slowly, and everything sitting in that open
    segment is lost on a crash however old it is. `archive_timeout` is what bounds
    that window, and this record has to show it doing so rather than assert it.
    """
    if not QUIET_RESULT.exists():
        pytest.skip("quiet drill has not been run in this tree")
    out = json.loads(QUIET_RESULT.read_text(encoding="utf-8"))
    if out["status"] == "UNVERIFIED":
        assert out["measured"] is None
        assert out["precondition"]
        return

    assert out["status"] == "measured_continuous_wal_archive_quiet"
    detail = out["workload"]["quiet_detail"]
    measured = out["measured"]

    # The load-bearing observation: the archive gained a segment during a window
    # in which the drill issued no writes at all. Nothing but the timeout could
    # have caused that, so the RPO below is attributable to the setting.
    assert detail["timeout_forced_switch_with_no_writes"] is True
    assert detail["segments_archived_after_idle"] > detail["segments_archived_before_idle"]

    timeout = detail["archive_timeout_seconds"]
    rpo = measured["experimental_rpo_seconds"]
    # Worst case, by construction: the crash is timed to land just before the
    # next switch. A zero here means the crash landed on the lucky side of the
    # cycle and the number is the best case wearing the worst case's label.
    assert rpo > 0.0, (
        "quiet RPO of 0 means the crash happened after a timeout-driven archive; "
        "that is the favourable half of the cycle, not the bound"
    )
    # RPO is bounded by the timeout, plus room for the archive command itself.
    assert rpo <= timeout + 15, (
        f"quiet RPO {rpo}s exceeds archive_timeout {timeout}s — the setting is "
        "not bounding the data-loss window it exists to bound"
    )
    assert measured["rows_lost_to_unarchived_segment"] > 0
    assert rpo <= RPO_TARGET_SECONDS
    assert out["meets_rpo_target"] is True


def test_the_quiet_value_matches_the_value_the_deployment_sets():
    """A drill is evidence for production only if it runs production's number."""
    if not QUIET_RESULT.exists():
        pytest.skip("quiet drill has not been run in this tree")
    out = json.loads(QUIET_RESULT.read_text(encoding="utf-8"))
    if out["status"] == "UNVERIFIED":
        pytest.skip("quiet drill unverified here")
    measured_timeout = out["workload"]["quiet_detail"]["archive_timeout_seconds"]

    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert f"archive_timeout={measured_timeout}s" in compose, (
        f"the drill measured archive_timeout={measured_timeout}s but "
        "docker-compose.yml sets a different value; the measurement would not "
        "describe the deployment"
    )
    assert "archive_mode=on" in compose, (
        "archive_timeout does nothing without archive_mode=on"
    )


@pytest.mark.slow
def test_live_wal_archive_pitr_drill_runs_and_meets_targets(tmp_path):
    """The live drill. Initdbs, archives, crashes and recovers a real cluster."""
    if not os.environ.get("SENTINEL_TEST_PG_BIN", "").strip():
        pytest.importorskip("pgserver")
    pytest.importorskip("psycopg")
    # Writes to a TEMPORARY path, not the committed evidence file.
    #
    # This test used to invoke the drill with no `--out`, so it rewrote
    # `reports/dr_postgres_wal_pitr_drill.json` on every run and left a spurious
    # git diff behind. An artifact that changes whenever the suite runs cannot
    # serve as the baseline it is committed to be -- and the two jobs are
    # different: `test_recorded_result_is_internally_consistent` validates the
    # committed baseline, while this one proves the drill still works.
    evidence = tmp_path / "wal_pitr_drill.json"
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--out", str(evidence)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
        timeout=900,
    )
    out = json.loads(evidence.read_text(encoding="utf-8"))
    if proc.returncode == 2:
        pytest.skip(f"drill unverifiable here: {out.get('precondition')}")
    assert proc.returncode == 0, f"drill failed:\n{proc.stdout}\n{proc.stderr}"
    assert out["status"] == "measured_continuous_wal_archive"
    assert out["measured"]["pitr_selected_point_in_time"] is True
    assert out["ok"] is True
