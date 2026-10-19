"""SLO verdicts, computed rather than authored.

WHAT THIS GUARDS
----------------
`docs/OBSERVABILITY.md` carried an SLI/SLO table whose Status column was prose
somebody typed: **UNVERIFIED**, **MET on PostgreSQL**, **MISSED on SQLite**.
Nothing computed those words, so nothing could contradict them, and a
hand-authored verdict on a generated measurement drifts in one direction --
nobody forgets to downgrade a MET.

THE LOAD-BEARING TEST
---------------------
`test_a_short_window_cannot_report_met_for_a_thirty_day_target`. A 99.9%/30d
target permits ~2,592 seconds of failure; a 420-second run that saw zero
failures could have its entire error budget spent in a window longer than the
run. Reporting that as MET is the single most misleading thing this module
could do.

THE SECOND MOST IMPORTANT ONE
-----------------------------
`test_the_mapper_reads_the_real_soak_artifact`. My first mapper read
plausible-looking keys the artifact does not have (`health`, `seconds`,
`ingest.latencies_ms`), so every target came back UNMEASURABLE -- the harness
looked cautious while reading nothing at all. A check that reads something
other than what it appears to read is this codebase's most repeated defect,
and it fails toward a confident answer every time.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.domain.slo import (
    MINIMUM_SAMPLES,
    SloKind,
    SloState,
    SloTarget,
    SloVerdict,
    evaluate_all,
    evaluate_slo,
)

THIRTY_DAYS = 30 * 24 * 60 * 60

AVAILABILITY = SloTarget(
    name="api_availability",
    kind=SloKind.AVAILABILITY,
    threshold=0.999,
    window_seconds=THIRTY_DAYS,
)
LATENCY = SloTarget(
    name="ingest_p95_latency_ms",
    kind=SloKind.LATENCY_PERCENTILE,
    threshold=500.0,
)
ERROR_RATE = SloTarget(
    name="worker_dead_letter_rate",
    kind=SloKind.ERROR_RATE,
    threshold=0.01,
    window_seconds=THIRTY_DAYS,
)


# ── a short window cannot confirm a long SLO ───────────────────────────────


def test_a_short_window_cannot_report_met_for_a_thirty_day_target():
    """THE load-bearing test. 1,871 successes over 420 seconds against a
    target whose error budget is 2,592 seconds is close to no evidence.
    """
    verdict = evaluate_slo(
        AVAILABILITY, successes=1871, failures=0, observed_seconds=420.08
    )

    assert verdict.state is SloState.UNMEASURABLE
    assert verdict.met is False
    assert "error budget" in verdict.reason


def test_a_long_enough_window_with_no_failures_is_met():
    """The positive control. Without it the test above could be satisfied by
    a module that never returns MET at all.
    """
    verdict = evaluate_slo(
        AVAILABILITY,
        successes=1_000_000,
        failures=0,
        observed_seconds=THIRTY_DAYS,
    )

    assert verdict.state is SloState.MET
    assert verdict.met is True
    assert verdict.observed == pytest.approx(1.0)


def test_a_violation_is_reported_from_a_short_window():
    """Deliberately asymmetric. Falsifying an SLO needs less evidence than
    confirming one, so requiring the full window before reporting a breach
    would hide real violations behind a duration technicality.
    """
    verdict = evaluate_slo(
        AVAILABILITY, successes=900, failures=100, observed_seconds=60.0
    )

    assert verdict.state is SloState.VIOLATED
    assert verdict.observed == pytest.approx(0.9)
    assert "whatever the duration" in verdict.reason


def test_the_failure_budget_is_reported_so_the_window_can_be_judged():
    """It is the number that makes a short run's uninformativeness obvious."""
    assert AVAILABILITY.budget_seconds == pytest.approx(THIRTY_DAYS * 0.001)
    assert AVAILABILITY.budget_seconds > 2500


# ── too few samples is not a pass ──────────────────────────────────────────


def test_a_ratio_over_too_few_attempts_is_unmeasurable():
    """A ratio over a near-empty denominator rendered as a percentage is the
    most quotable wrong number a report can contain.
    """
    verdict = evaluate_slo(
        AVAILABILITY, successes=2, failures=0, observed_seconds=THIRTY_DAYS
    )

    assert verdict.state is SloState.UNMEASURABLE
    assert verdict.observed is None


def test_a_percentile_over_too_few_samples_is_unmeasurable():
    verdict = evaluate_slo(LATENCY, latencies_ms=(10.0, 20.0))

    assert verdict.state is SloState.UNMEASURABLE
    assert str(MINIMUM_SAMPLES) in verdict.reason


def test_an_empty_error_rate_denominator_is_unmeasurable_not_zero_percent():
    """0/0 shown as 0% looks like a good result, which is why it is refused."""
    verdict = evaluate_slo(
        ERROR_RATE, successes=0, failures=0, observed_seconds=THIRTY_DAYS
    )

    assert verdict.state is SloState.UNMEASURABLE


# ── latency ────────────────────────────────────────────────────────────────


def test_a_percentile_is_nearest_rank_not_interpolated():
    """An interpolated percentile reports a latency no request experienced,
    and the point of a p95 is that some real request was that slow.
    """
    verdict = evaluate_slo(
        LATENCY, latencies_ms=tuple(float(n) for n in range(1, 101))
    )

    assert verdict.observed in {95.0, 96.0}
    assert verdict.state is SloState.MET


def test_a_latency_ceiling_breach_is_violated():
    verdict = evaluate_slo(
        LATENCY, latencies_ms=(600.0, 700.0, 800.0, 900.0, 1000.0)
    )

    assert verdict.state is SloState.VIOLATED
    assert "exceeds" in verdict.reason


def test_a_reported_percentile_is_admissible_when_a_sample_count_backs_it():
    """The real artifacts keep a computed p95 and drop the raw values. The
    sample count is what makes trusting the producer's arithmetic reasonable.
    """
    verdict = evaluate_slo(
        LATENCY, reported_percentile_ms=71.562, sample_count=16082
    )

    assert verdict.state is SloState.MET
    assert verdict.observed == pytest.approx(71.562)
    assert "16082 samples" in verdict.reason


def test_a_reported_percentile_with_too_few_samples_is_refused():
    """A p95 over three numbers is not a statistic, however it was computed."""
    verdict = evaluate_slo(LATENCY, reported_percentile_ms=10.0, sample_count=3)

    assert verdict.state is SloState.UNMEASURABLE


def test_raw_samples_win_over_a_reported_percentile():
    """With raw values the arithmetic can be CHECKED rather than trusted, so
    a producer's disagreeing claim must not override them.
    """
    verdict = evaluate_slo(
        LATENCY,
        latencies_ms=(600.0, 700.0, 800.0, 900.0, 1000.0),
        reported_percentile_ms=1.0,
        sample_count=999999,
    )

    assert verdict.state is SloState.VIOLATED, (
        "a producer claiming 1 ms must not override raw samples showing 900"
    )


# ── a target nothing measured is reported, not dropped ────────────────────


def test_a_target_with_no_observation_is_unmeasurable_not_omitted():
    """Omitting it would shorten the report by exactly the SLOs nothing was
    watching, and a missing SLO reads as one fewer thing to worry about.
    """
    verdicts = evaluate_all((AVAILABILITY, LATENCY, ERROR_RATE), {})

    assert len(verdicts) == 3
    assert all(v.state is SloState.UNMEASURABLE for v in verdicts)
    assert all("rather than omitted" in v.reason for v in verdicts)


# ── a target cannot be stated in a way that is trivially satisfied ────────


def test_an_availability_target_stated_as_a_percentage_is_refused():
    """99.9 compared against a ratio would be satisfied by every possible
    measurement while LOOKING like a stricter target.
    """
    with pytest.raises(ValueError) as raised:
        SloTarget(name="x", kind=SloKind.AVAILABILITY, threshold=99.9)

    assert "trivially satisfied" in str(raised.value)


def test_a_verdict_cannot_omit_the_value_it_was_based_on():
    with pytest.raises(ValueError) as raised:
        SloVerdict(target=LATENCY, state=SloState.MET)

    assert "nobody can check it" in str(raised.value)


def test_unmeasurable_without_a_reason_is_refused():
    with pytest.raises(ValueError) as raised:
        SloVerdict(target=LATENCY, state=SloState.UNMEASURABLE)

    assert "operator will stop running it" in str(raised.value)


def test_met_is_derived_and_false_for_unmeasurable():
    verdict = SloVerdict(
        target=LATENCY, state=SloState.UNMEASURABLE, reason="too short"
    )

    assert verdict.met is False


# ── the mapper reads the artifact that actually exists ────────────────────


def test_the_mapper_reads_the_real_soak_artifact():
    """THE second load-bearing test. My first mapper read keys the artifact
    does not have, so every target came back UNMEASURABLE and the harness
    looked cautious while reading nothing at all.

    This asserts it extracts real numbers from the real file, so a reformatted
    artifact fails here rather than silently reporting a clean unknown.
    """
    import scripts.evaluate_slos as cli

    artifact = Path("docs/observability_soak_postgres.json")
    if not artifact.exists():  # pragma: no cover - artifact is generated
        pytest.skip("soak artifact not present in this checkout")

    payload = json.loads(artifact.read_text(encoding="utf-8"))
    observed = cli._observations(payload)

    assert "api_availability" in observed, (
        "the availability SLI was not extracted; the mapper is reading keys "
        "the artifact does not have"
    )
    assert observed["api_availability"]["successes"] > 0
    assert observed["api_availability"]["observed_seconds"] > 0
    assert "ingest_p95_latency_ms" in observed
    assert observed["ingest_p95_latency_ms"]["sample_count"] > MINIMUM_SAMPLES


def test_the_real_artifact_yields_a_met_ingest_and_an_unmeasurable_availability():
    """The verdicts the real numbers actually support: 71.6 ms against a
    500 ms ceiling is MET; 420 seconds against a 30-day target is not.
    """
    import scripts.evaluate_slos as cli

    artifact = Path("docs/observability_soak_postgres.json")
    if not artifact.exists():  # pragma: no cover
        pytest.skip("soak artifact not present in this checkout")

    payload = json.loads(artifact.read_text(encoding="utf-8"))
    verdicts = {
        v.target.name: v
        for v in evaluate_all(cli.TARGETS, cli._observations(payload))
    }

    assert verdicts["ingest_p95_latency_ms"].state is SloState.MET
    assert verdicts["api_availability"].state is SloState.UNMEASURABLE
    assert verdicts["worker_dead_letter_rate"].state is SloState.UNMEASURABLE


def test_the_worker_rate_is_absent_rather_than_a_clean_zero():
    """Nothing in the soak measures it. Supplying zeros would render a 0%
    dead-letter rate from a run that never enqueued work.
    """
    import scripts.evaluate_slos as cli

    observed = cli._observations({"window": {"elapsed_seconds": 420}})

    assert "worker_dead_letter_rate" not in observed


# ── the CLI never lets "could not tell" exit zero ─────────────────────────


def test_the_cli_exits_one_when_a_target_is_unmeasurable():
    """1, not 0. A soak that exits 0 because it was too short to fail is how
    an unverified SLO becomes a green build.
    """
    import scripts.evaluate_slos as cli

    artifact = Path("docs/observability_soak_postgres.json")
    if not artifact.exists():  # pragma: no cover
        pytest.skip("soak artifact not present in this checkout")

    assert cli.main([str(artifact)]) == 1


def test_the_cli_exits_two_when_a_target_is_violated(tmp_path, capsys):
    """A violation must outrank an unknown, because it is actionable now."""
    import scripts.evaluate_slos as cli

    artifact = tmp_path / "soak.json"
    artifact.write_text(
        json.dumps(
            {
                "window": {"elapsed_seconds": 420},
                "measured": {
                    "ready": {"attempts": 1000, "failures": 500},
                    "ingest": {"attempts": 1000, "p95_ms": 71.0},
                },
            }
        ),
        encoding="utf-8",
    )

    code = cli.main([str(artifact)])
    capsys.readouterr()

    assert code == 2


def test_the_cli_exits_one_when_the_artifact_is_missing(tmp_path, capsys):
    """An absent measurement is not a passing one."""
    import scripts.evaluate_slos as cli

    code = cli.main([str(tmp_path / "nope.json")])
    output = capsys.readouterr().out

    assert code == 1
    assert "not a passing one" in output


def test_the_cli_prints_the_artifacts_own_claim_beside_the_computed_verdict(
    capsys,
):
    """The artifact asserts `meets_ingest_p95_target` about itself. Printing
    both is how a disagreement becomes visible rather than a matter of which
    file you happened to read.
    """
    import scripts.evaluate_slos as cli

    artifact = Path("docs/observability_soak_postgres.json")
    if not artifact.exists():  # pragma: no cover
        pytest.skip("soak artifact not present in this checkout")

    cli.main([str(artifact)])
    output = capsys.readouterr().out

    assert "meets_ingest_p95_target" in output
    assert "producer's claim about itself" in output


def test_the_cli_states_that_the_soak_gate_stays_open(capsys):
    """No exit code from a developer machine can close PRODUCTION_SOAK, and
    the output has to say so where somebody reading a green result sees it.
    """
    import scripts.evaluate_slos as cli

    artifact = Path("docs/observability_soak_postgres.json")
    if not artifact.exists():  # pragma: no cover
        pytest.skip("soak artifact not present in this checkout")

    cli.main([str(artifact)])
    output = capsys.readouterr().out

    assert "PRODUCTION_SOAK remains OPEN" in output


def test_the_cli_explains_the_encoded_targets(capsys):
    import scripts.evaluate_slos as cli

    assert cli.main(["--explain"]) == 0
    output = capsys.readouterr().out

    assert "api_availability" in output
    assert "failure budget" in output
