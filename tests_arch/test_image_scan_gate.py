"""A release scanner must not silently waive an unfixed risk or leak a match."""
import json

import pytest

from scripts.build_and_scan_image import evaluate_scan

IMAGE = "sha256:" + "a" * 64


def report(result=None):
    return {"SchemaVersion": 2, "Metadata": {"ImageID": IMAGE},
            "Results": [{} if result is None else result]}


@pytest.mark.parametrize("fixed", ["", "2.0"])
def test_high_risk_blocks_even_without_upstream_fix(fixed):
    raw = report({"Vulnerabilities": [{"VulnerabilityID": "CVE-test", "PkgName": "fixture",
                                       "Severity": "HIGH", "FixedVersion": fixed}]})
    assert not evaluate_scan(json.dumps(raw), returncode=0, image_id=IMAGE)["ok"]


def test_low_vulnerability_does_not_change_declared_threshold():
    raw = report({"Vulnerabilities": [{"Severity": "LOW"}]})
    assert evaluate_scan(json.dumps(raw), returncode=0, image_id=IMAGE)["ok"]


def test_secret_blocks_without_echoing_match_or_context():
    canary = "AKIA" + "Q7ZP3M9XK2VL8RTN"
    raw = report({"Secrets": [{"RuleID": "fixture", "Severity": "LOW", "Match": canary,
                               "Code": {"Lines": [{"Content": canary}]}}]})
    result = evaluate_scan(json.dumps(raw), returncode=0, image_id=IMAGE)
    assert not result["ok"]
    assert canary not in json.dumps(result)
    assert "Code" not in result and "output_tail" not in result


def test_high_misconfiguration_blocks():
    raw = report({"Misconfigurations": [{"ID": "fixture", "Severity": "HIGH", "Status": "FAIL"}]})
    assert not evaluate_scan(json.dumps(raw), returncode=0, image_id=IMAGE)["ok"]


@pytest.mark.parametrize("raw", ["", "{}", "null", "[]", '{"Results": []}', "not json"])
def test_missing_malformed_or_empty_report_fails_closed(raw):
    assert not evaluate_scan(raw, returncode=0, image_id=IMAGE)["ok"]


def test_tool_failure_and_wrong_artifact_cannot_pass():
    raw = json.dumps(report())
    assert not evaluate_scan(raw, returncode=1, image_id=IMAGE)["ok"]
    assert not evaluate_scan(raw, returncode=0, image_id="sha256:" + "b" * 64)["ok"]
    assert evaluate_scan(raw, returncode=0, image_id=IMAGE)["ok"]
