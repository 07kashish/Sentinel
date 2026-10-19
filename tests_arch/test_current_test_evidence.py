"""Reject invented, stale, skipped and altered readiness evidence."""
import hashlib
import json
from collections import Counter

import pytest

from scripts import build_current_status as status
from scripts import current_test_evidence as evidence

IDENTITY = {"commit": "abc", "inputs_sha256": "def"}


def make_report(tmp_path, children="", code=0, name="test_control[postgres]"):
    xml = tmp_path / "run.xml"
    xml.write_text(f'<testsuites><testsuite><testcase classname="tests_arch.test_execution_contract" name="{name}">{children}</testcase></testsuite></testsuites>')
    payload = {"schema": "sentinel.test-evidence/v1", "identity": IDENTITY,
               "exit_code": code, "inputs_changed_during_run": False,
               "junit_sha256": hashlib.sha256(xml.read_bytes()).hexdigest(),
               "modules": evidence.outcomes(xml)}
    path = tmp_path / "run.json"
    path.write_text(json.dumps(payload))
    return path, payload, xml


def tier(executed):
    return status._tier(status.CAPABILITIES[0], total=Counter(test_execution_contract=100),
                        postgres=Counter(test_execution_contract=50), jobs={"test", "live-postgres"},
                        production={}, external={}, executed=executed)[0]


def test_collection_and_configured_ci_do_not_prove_a_test_ran():
    assert tier({}) == "implemented"


def test_successful_execution_can_support_an_integration_tier(tmp_path):
    path, _, _ = make_report(tmp_path)
    assert tier(evidence.read_verified(path, IDENTITY)) == "integration_tested"


def test_skipped_postgres_is_not_an_integration_pass(tmp_path):
    path, _, _ = make_report(tmp_path, '<skipped message="backend absent"/>')
    assert tier(evidence.read_verified(path, IDENTITY)) == "implemented"


@pytest.mark.parametrize("field,value", [
    ("exit_code", 1), ("inputs_changed_during_run", True),
    ("identity", {"commit": "old", "inputs_sha256": "def"}),
    ("identity", {"commit": "abc", "inputs_sha256": "changed-policy"}),
    ("modules", {"test_execution_contract": {"passed": 999}}),
])
def test_forged_or_stale_claims_are_rejected(tmp_path, field, value):
    path, payload, _ = make_report(tmp_path)
    payload[field] = value
    path.write_text(json.dumps(payload))
    assert evidence.read_verified(path, IDENTITY) == {}


def test_report_tampering_is_rejected(tmp_path):
    path, _, xml = make_report(tmp_path)
    xml.write_text(xml.read_text().replace("test_control", "test_fake"))
    assert evidence.read_verified(path, IDENTITY) == {}


def test_failure_cannot_be_hidden_by_exit_zero(tmp_path):
    path, _, _ = make_report(tmp_path, '<failure message="denial bypass"/>')
    assert evidence.read_verified(path, IDENTITY) == {}


def test_unsigned_sidecar_does_not_establish_independent_verification(tmp_path, monkeypatch):
    monkeypatch.setattr(status, "CURRENT", tmp_path)
    folder = tmp_path / "evidence" / "external"
    folder.mkdir(parents=True)
    (folder / "claimed.json").write_text('{"capabilities":["authorization"]}')
    (folder / "claimed.json.provenance.json").write_text('{}')
    assert status._bound_evidence("external") == {}
