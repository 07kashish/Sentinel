"""The cross-region drill refuses everything that would produce a hollow PASS.

WHY THE REFUSALS ARE THE FEATURE
---------------------------------
`INDEPENDENT_FAILURE_DOMAIN_DR` is the GA gate whose evidence a repository can
nearly produce, and the failure mode is a drill that thinks it crossed a region
and did not: same bucket with a different prefix, two names for one location, a
defaulted destination. Each yields a PASS that means nothing, and a passing DR
drill is exactly the artifact nobody re-checks.

So most of this file is negative cases, each paired against the positive built
from the same parameters -- otherwise every one of them would pass against a
checker that refused unconditionally.
"""

from __future__ import annotations

import pytest

from scripts.run_cross_region_dr_drill import (
    GATE,
    INDEPENDENT_VERIFIED,
    PreconditionResult,
    check_preconditions,
    main,
)

VALID = dict(
    source_region="eu-west-2",
    destination_region="us-east-1",
    source_archive="s3://sentinel-wal-eu/wal",
    destination_archive="s3://sentinel-wal-us/wal",
    archive_objects=412,
)


def _check(**overrides):
    options = dict(VALID)
    options.update(overrides)
    return check_preconditions(**options)


# ── the control ────────────────────────────────────────────────────────────


def test_a_genuinely_cross_region_setup_passes_preconditions():
    """THE control. Every refusal below would pass against a checker that
    refused unconditionally, which is the easiest way to write a useless gate.
    """
    result = _check()

    assert result.ok is True
    assert result.refusals == ()


# ── the region has to actually differ ──────────────────────────────────────


def test_the_same_region_twice_is_refused():
    result = _check(destination_region="eu-west-2")

    assert result.ok is False
    assert any("being GONE" in r for r in result.refusals)


def test_the_same_region_in_different_case_is_refused():
    """`EU-WEST-2` and `eu-west-2` are one region. A case-sensitive comparison
    would accept it.
    """
    result = _check(destination_region="EU-WEST-2")

    assert result.ok is False


def test_two_names_for_one_location_are_refused():
    """`us-standard` IS `us-east-1`. A textual inequality check accepts this
    pair, which is the entire reason the alias table exists.
    """
    result = _check(source_region="us-standard", destination_region="us-east-1")

    assert result.ok is False
    assert any("different\nnames" in r or "different names" in r
               for r in result.refusals)


def test_an_empty_region_is_refused_rather_than_defaulted():
    """A defaulted region is how a drill comes to restore into the region it
    started in.
    """
    assert _check(destination_region="").ok is False
    assert _check(source_region="").ok is False


# ── the destination has to be outside the source ──────────────────────────


def test_a_destination_inside_the_source_bucket_is_refused():
    """Same bucket, different prefix: the most common way a cross-region
    drill passes without crossing anything.
    """
    result = _check(
        destination_archive="s3://sentinel-wal-eu/wal/restore-target"
    )

    assert result.ok is False
    assert any("Same bucket" in r for r in result.refusals)


def test_an_identical_destination_and_source_archive_is_refused():
    result = _check(destination_archive=VALID["source_archive"])

    assert result.ok is False


def test_a_similarly_named_but_separate_bucket_is_allowed():
    """The complement, and the reason the prefix check compares against
    `source + "/"` rather than using a bare `startswith`.

    THE SOURCE HERE HAS NO TRAILING PATH SEGMENT ON PURPOSE. With a source of
    `s3://sentinel-wal-eu/wal`, a bare `startswith` already rejects
    `s3://sentinel-wal-eu2/wal` for unrelated reasons, so such a case does not
    exercise the bug at all -- a mutation proved my first version of this test
    passed with the bare check reinstated. Bare-prefix against
    `s3://sentinel-wal-eu` DOES match `s3://sentinel-wal-eu2`, which is the
    lookalike defect this codebase has now fixed in a file sandbox, a
    delegation resource check, a trace comparator and here.
    """
    result = _check(
        source_archive="s3://sentinel-wal-eu",
        destination_archive="s3://sentinel-wal-eu2/wal",
    )

    assert result.ok is True, result.refusals


def test_a_true_subpath_of_a_bare_source_is_still_refused():
    """The other half of the pair: with the same bare source, a destination
    genuinely inside it must still be caught."""
    result = _check(
        source_archive="s3://sentinel-wal-eu",
        destination_archive="s3://sentinel-wal-eu/restore",
    )

    assert result.ok is False
    assert any("Same bucket" in r for r in result.refusals)


def test_an_empty_destination_archive_is_refused():
    result = _check(destination_archive="")

    assert result.ok is False
    assert any("nowhere to write" in r for r in result.refusals)


# ── unreadable is not empty ────────────────────────────────────────────────


def test_an_unlistable_archive_is_refused_distinctly_from_an_empty_one():
    """THE three-valued case. `None` means the listing FAILED, which is not an
    empty archive -- different faults, different fixes, and a restore
    attempted from either would fail for reasons nobody could tell apart
    afterwards.
    """
    unreadable = _check(archive_objects=None)
    empty = _check(archive_objects=0)

    assert unreadable.ok is False
    assert empty.ok is False
    assert any("could not be listed" in r for r in unreadable.refusals)
    assert any("is empty" in r for r in empty.refusals)
    # The two must not produce the same message, or the distinction is
    # decorative.
    assert unreadable.refusals != empty.refusals


def test_an_empty_archive_would_verify_an_empty_database():
    result = _check(archive_objects=0)

    assert any("empty database" in r for r in result.refusals)


# ── the result cannot contradict itself ───────────────────────────────────


def test_ok_with_refusals_is_refused():
    with pytest.raises(ValueError) as raised:
        PreconditionResult(ok=True, refusals=("something",))

    assert "read as a pass" in str(raised.value)


def test_a_refusal_with_no_reason_is_refused():
    with pytest.raises(ValueError) as raised:
        PreconditionResult(ok=False)

    assert "tool is broken" in str(raised.value)


# ── it cannot self-certify ────────────────────────────────────────────────


def test_the_cross_region_drill_cannot_self_certify():
    """The gate flag is a hardcoded false and no argument may change it. A
    successful restore performed by the authors of the system is not
    independent verification, which is the whole content of the word.
    """
    assert INDEPENDENT_VERIFIED is False

    from pathlib import Path

    source = Path("scripts/run_cross_region_dr_drill.py").read_text(
        encoding="utf-8"
    )
    assert "INDEPENDENT_VERIFIED = False" in source
    assert "INDEPENDENT_VERIFIED = True" not in source


def test_no_valid_invocation_exits_zero_without_executing(capsys):
    """Preconditions passing is not the gate closing. A zero exit would be
    read as one by whatever ran this.
    """
    code = main(
        [
            "--source-region", "eu-west-2",
            "--destination-region", "us-east-1",
            "--source-archive", "s3://a/wal",
            "--destination-archive", "s3://b/wal",
            "--archive-objects", "412",
            "--i-accept-cross-region-costs",
        ]
    )
    capsys.readouterr()

    assert code == 1


def test_a_valid_setup_without_the_cost_acknowledgement_runs_nothing(capsys):
    """Cross-region transfer and a second database instance cost real money,
    so this cannot happen by accident.
    """
    code = main(
        [
            "--source-region", "eu-west-2",
            "--destination-region", "us-east-1",
            "--source-archive", "s3://a/wal",
            "--destination-archive", "s3://b/wal",
            "--archive-objects", "412",
        ]
    )
    output = capsys.readouterr().out

    assert code == 1
    assert "cost real money" in output


def test_the_evidence_reports_observed_regions_rather_than_arguments(capsys):
    """An operator can pass any two region names; only a real connection can
    show where the data went. So the honesty flag is derived from observed
    endpoints, which are empty here -- and therefore false.
    """
    import json as _json

    main(
        [
            "--source-region", "eu-west-2",
            "--destination-region", "us-east-1",
            "--source-archive", "s3://a/wal",
            "--destination-archive", "s3://b/wal",
            "--archive-objects", "412",
            "--json",
        ]
    )
    payload = _json.loads(capsys.readouterr().out)

    assert payload["preconditions_ok"] is True
    assert payload["observed_regions_differ"] is False, (
        "no endpoint was observed, so this must not claim the regions differed"
    )
    assert payload["independent_failure_domain_verified"] is False
    assert payload["gate"] == GATE


def test_the_explain_output_names_every_refusal(capsys):
    assert main(["--explain"]) == 0
    output = capsys.readouterr().out

    for expected in ("same region", "alias table", "inside the source",
                     "could not be LISTED"):
        assert expected in output
    assert "not independent verification" in output
