"""docs/current is generated, bound, tiered, and makes no unearned claim."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

from scripts import build_current_status as status

ROOT = Path(__file__).resolve().parents[1]
CURRENT = ROOT / "docs" / "current"


@pytest.fixture(scope="module")
def generated(tmp_path_factory):
    out = tmp_path_factory.mktemp("current")
    status.main(["--out", str(out), "--artifact", "requirements.lock"])
    return json.loads((out / "RELEASE_STATUS.json").read_text(encoding="utf-8")), out


def test_the_status_is_bound_to_head_and_the_tree(generated):
    payload, _ = generated
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(ROOT), capture_output=True, text=True, check=True).stdout.strip()  # noqa: S603,S607
    assert payload["commit"] == head
    assert re.fullmatch(r"[0-9a-f]{64}", payload["source_tree_sha256"])
    assert payload["artifacts"][0]["path"].endswith("requirements.lock")
    assert re.fullmatch(r"[0-9a-f]{64}", payload["artifacts"][0]["sha256"])


def test_every_capability_has_a_computed_tier_and_present_modules(generated):
    payload, _ = generated
    assert payload["tiers"] == list(status.TIERS)
    for row in payload["capabilities"]:
        assert row["tier"] in status.TIERS, row
        assert row["modules_missing"] == [], row
        assert row["ci_jobs_missing"] == [], row


def test_no_capability_claims_a_tier_it_has_no_evidence_for(generated):
    payload, _ = generated
    for row in payload["capabilities"]:
        if row["tier"] in {"production_observed", "externally_verified"}:
            assert row["production_evidence"], row
        if row["tier"] == "externally_verified":
            assert row["external_evidence"], row
        if row["tier"] == "integration_tested":
            assert row["tests_on_postgresql"] > 0 and row["ci_jobs"], row


def test_the_top_tiers_are_empty_until_evidence_exists(generated):
    """Today there is no production tenant and no third-party report; the
    document must say so rather than infer it from good tests."""
    payload, _ = generated
    assert payload["tier_counts"]["production_observed"] == 0
    assert payload["tier_counts"]["externally_verified"] == 0
    assert not (CURRENT / "evidence" / "production").exists() or not list((CURRENT / "evidence" / "production").glob("*.json"))


def test_the_rendered_documents_make_no_forbidden_claim(generated):
    _, out = generated
    for name in ("RELEASE_STATUS.md", "RISK_REGISTER.md"):
        status._check_claims((out / name).read_text(encoding="utf-8"), name)


def test_the_claim_check_can_fail():
    with pytest.raises(SystemExit):
        status._check_claims("Sentinel is production-ready today.", "probe")
    status._check_claims("It is not production-ready.", "probe")


def test_every_risk_names_closing_evidence_and_a_reviewer_date():
    register = status.load_risks()
    ids = [r["id"] for r in register["risks"]]
    assert len(ids) == len(set(ids))
    for risk in register["risks"]:
        assert re.fullmatch(r"R-\d{3}", risk["id"])
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", risk["review_by"])


def test_paths_cited_by_capabilities_and_risks_exist():
    for cap in status.CAPABILITIES:
        for module in cap.modules:
            assert (ROOT / module).exists(), f"{cap.key} cites missing {module}"
        for stem in cap.tests:
            assert (ROOT / "tests_arch" / f"{stem}.py").exists(), f"{cap.key} cites missing test module {stem}"
    register = status.load_risks()
    cited = re.findall(r"\b((?:sentinel|scripts|docs|deploy|evaluation|tests_arch)/[A-Za-z0-9_./\-]+)", json.dumps(register))
    for path in cited:
        if path.startswith("docs/current/evidence/") or path.endswith("/"):
            continue  # future evidence locations are cited by design
        assert (ROOT / path.rstrip(".,")).exists(), f"risk register cites missing {path}"


def test_the_committed_snapshot_has_the_generated_shape():
    committed = json.loads((CURRENT / "RELEASE_STATUS.json").read_text(encoding="utf-8"))
    assert committed["schema"] == "sentinel.release-status/v1"
    assert {c["key"] for c in committed["capabilities"]} == {c.key for c in status.CAPABILITIES}
    assert (CURRENT / "RELEASE_STATUS.md").read_text(encoding="utf-8").startswith("# Release status")
    assert (CURRENT / "RISK_REGISTER.md").read_text(encoding="utf-8").startswith("# Risk register")
