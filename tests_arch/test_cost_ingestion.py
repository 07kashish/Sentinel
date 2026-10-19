"""Cost data that is measured or absent, never inferred.

WHY THIS SCRIPT EXISTS BEFORE THE DATA DOES
--------------------------------------------
`MEASURED_AWS_UNIT_ECONOMICS` is an open external gate: no bill for this
platform exists. Writing the collection procedure first means closing that
gate is a matter of running something rather than building something -- and it
means the honest UNVERIFIED result is what a readiness check reads today,
rather than an absent script somebody has to remember about.

THE THREE THINGS TESTED
-----------------------
  1. A missing credential is UNVERIFIED and exits non-zero. "We could not
     measure it" and "it cost nothing" are different facts, and only one of
     them closes a gate.
  2. A unit cost over zero volume is refused. Cost-per-event of infinity
     rendered as a large number would be quoted, and whoever quoted it would
     not know the denominator was zero.
  3. `--dry-run` makes no request. A cost tool that charges you for asking
     what it would ask is a cost tool people stop running.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import date
from pathlib import Path

from scripts.ingest_aws_costs import (
    COST_PER_QUERY_USD,
    PASS,
    PROJECT_TAG,
    PROJECT_VALUE,
    UNVERIFIED,
    Outcome,
    _query_body,
    _redact,
    _unit_costs,
    main,
)

ROOT = Path(__file__).resolve().parent.parent
SOURCE = (ROOT / "scripts" / "ingest_aws_costs.py").read_text(encoding="utf-8")


# ── the query is scoped, or the figure is somebody else's bill ────────────


def test_the_query_filters_on_the_project_tag():
    """Without it a shared account's other spend drowns the signal, and the
    resulting figure is somebody else's bill divided by our event count.
    """
    body = _query_body(date(2026, 8, 1), date(2026, 9, 1))

    assert body["Filter"]["Tags"]["Key"] == PROJECT_TAG
    assert body["Filter"]["Tags"]["Values"] == [PROJECT_VALUE]
    assert body["Filter"]["Tags"]["MatchOptions"] == ["EQUALS"]


def test_the_query_asks_for_unblended_cost():
    """Amortized spreads a reservation across the period -- the right number
    for a finance report and the wrong one for "what did this month cost".
    """
    body = _query_body(date(2026, 8, 1), date(2026, 9, 1))

    assert body["Metrics"] == ["UnblendedCost"]


def test_the_query_groups_by_service():
    """A single total says the bill is too high. A per-service breakdown says
    which lever to pull.
    """
    body = _query_body(date(2026, 8, 1), date(2026, 9, 1))

    assert body["GroupBy"] == [{"Type": "DIMENSION", "Key": "SERVICE"}]


# ── a missing credential is never a zero ─────────────────────────────────


def test_a_missing_credential_is_unverified_and_exits_non_zero(monkeypatch):
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.delenv(name, raising=False)

    assert main([]) == 1


def test_only_a_pass_exits_zero():
    assert Outcome(PASS, "x", {}).exit_code == 0
    assert Outcome(UNVERIFIED, "x", {}).exit_code != 0


def test_the_evidence_marks_measured_false_when_unverified(
    monkeypatch, tmp_path
):
    """The field a readiness check reads. An UNVERIFIED run must not leave an
    artifact that looks like a measurement.
    """
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.delenv(name, raising=False)
    evidence = tmp_path / "cost.json"

    main(["--evidence", str(evidence)])
    payload = json.loads(evidence.read_text(encoding="utf-8"))

    assert payload["status"] == UNVERIFIED
    assert payload["measured"] is False
    assert "MEASURED_AWS_UNIT_ECONOMICS" in payload["gate"]


# ── a unit cost over nothing is refused ──────────────────────────────────


def test_a_unit_cost_over_zero_volume_is_refused():
    """Cost-per-event of infinity rendered as a large number would be quoted,
    and whoever quoted it would not know the denominator was zero.
    """
    costs = _unit_costs(120.0, events=0, decisions=0)

    assert costs["usd_per_million_events"]["value"] is None
    assert "nothing to divide by" in costs["usd_per_million_events"]["reason"]


def test_a_unit_cost_with_volume_is_computed():
    """The control. Without it the test above would pass against a function
    that always returned None.
    """
    costs = _unit_costs(100.0, events=2_000_000, decisions=500_000)

    assert costs["usd_per_million_events"]["value"] == 50.0
    assert costs["usd_per_million_decisions"]["value"] == 200.0


def test_each_volume_is_judged_independently():
    """Events measured and decisions not is a real state, and collapsing the
    two would discard the half that was measurable.
    """
    costs = _unit_costs(100.0, events=1_000_000, decisions=0)

    assert costs["usd_per_million_events"]["value"] == 100.0
    assert costs["usd_per_million_decisions"]["value"] is None


# ── credentials never reach the output ───────────────────────────────────


def test_a_credential_in_a_message_is_redacted(monkeypatch):
    """An operator pasting this output into an issue must not be pasting their
    secret key with it.
    """
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "SUPER-SECRET-VALUE-XYZ")

    assert "SUPER-SECRET-VALUE-XYZ" not in _redact(
        "failed with SUPER-SECRET-VALUE-XYZ in the URL"
    )
    assert "[redacted]" in _redact("x SUPER-SECRET-VALUE-XYZ y")


def test_redaction_leaves_an_unrelated_message_alone(monkeypatch):
    """The control: a redactor that blanked everything would pass the test
    above.
    """
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "SUPER-SECRET-VALUE-XYZ")

    assert _redact("a network error occurred") == "a network error occurred"


def test_the_script_does_not_read_dotenv():
    """Deliberate, and the opposite of the publisher's choice. A real run
    costs money and reads billing data, so the credential has to come from the
    environment of the person invoking it -- otherwise an exploratory session
    becomes a charged query against whichever account was last configured.
    """
    assert "_load_dotenv" not in SOURCE
    assert "IT DOES NOT READ" in SOURCE


# ── the dry run costs nothing ────────────────────────────────────────────


def test_the_dry_run_makes_no_request_and_exits_zero():
    """A cost tool that charges you for asking what it would ask is a cost
    tool people stop running.
    """
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "ingest_aws_costs.py"),
            "--dry-run",
        ],
        capture_output=True, text=True, cwd=str(ROOT),
        env={"PYTHONPATH": str(ROOT)}, timeout=120,
    )

    assert result.returncode == 0, result.stderr
    assert "DRY RUN" in result.stdout
    assert "nothing charged" in result.stdout
    assert PROJECT_VALUE in result.stdout


def test_the_per_query_cost_is_stated():
    """Small and not zero. Stated so nobody writes the polling loop."""
    assert COST_PER_QUERY_USD > 0
    assert "ONE request" in SOURCE


def test_cost_explorer_is_signed_for_us_east_1():
    """It is a global endpoint served from us-east-1 regardless of where the
    resources are, and signing for another region returns a 403 that reads
    like a permissions problem.
    """
    assert 'region = "us-east-1"' in SOURCE
    assert "GLOBAL" in SOURCE


def test_the_signer_is_reused_rather_than_reimplemented():
    """Two implementations of a signature eventually disagree, and the
    disagreement presents as a 403 that reads like a permissions problem.
    """
    assert "from sentinel.infrastructure.s3_root_sink import _signing_key" in SOURCE
    assert "HardenedHttpClient" in SOURCE


def test_the_newline_is_a_named_constant():
    """SigV4's canonical request is newline-joined, and every editing layer
    between the author and this file mangled the escape sequence at least
    once. Naming the character is cheaper than getting the escaping right
    again, and a regression would silently change the signature.
    """
    assert "NEWLINE = chr(10)" in SOURCE
    assert "NEWLINE.join([" in SOURCE
