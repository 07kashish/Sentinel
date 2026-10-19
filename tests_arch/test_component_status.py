"""Every domain module is either ON the service path, TOOLING, or dormant by decision.

A module that exists, has passing tests and is called by nothing reads, to a
buyer or a reviewer, like a capability. Several did. This test makes the
classification explicit and keeps it true: a module listed as live must be
imported by the service, one listed as tooling must be imported by a script,
and one listed as dormant must be imported by neither -- so the day somebody
wires it (or unwires it) this file has to be told.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

#: On the request or maintenance path of the running service.
LIVE = {"slo": "judges the workflow targets in GET /v1/workflow/metrics",
        "value_metrics": "value report in GET /v1/workflow/metrics",
        "stream_guard": "interface/mcp_streaming.py: every MCP notification relayed to a client is offered to RelayGuard first"}

#: Used by operator or assurance scripts, never by the running service.
TOOLING = {"attack_campaign": "scripts/run_attack_campaign.py: red-team campaign outcomes and regression",
           "detection_metrics": "scripts/measure_benign_tool_call_false_positives.py: corpus provenance on detection numbers"}

#: Implemented and tested, deliberately NOT part of the product today.
DORMANT = {
    "threat_intel": "needs a pooled indicator service across deployments; none exists, so nothing may claim threat-intelligence enrichment",
    "mfa": "operator TOTP is not part of the supported workflow; operators authenticate through the customer's identity provider",
    "identity": "superseded as the workload trust root by infrastructure/agent_identity_providers.py",
}


def _importers(module: str, *folders: str) -> list[str]:
    pattern = re.compile(rf"sentinel\.domain\.{module}\b|from sentinel\.domain import[^\n]*\b{module}\b")
    found = []
    for folder in folders:
        for path in (ROOT / folder).rglob("*.py"):
            if path.name == f"{module}.py" and path.parent.name == "domain":
                continue
            if pattern.search(path.read_text(encoding="utf-8", errors="replace")):
                found.append(str(path.relative_to(ROOT)))
    return found


@pytest.mark.parametrize("module", sorted(LIVE))
def test_a_live_module_is_imported_by_the_service(module):
    assert _importers(module, "sentinel"), f"{module} is listed as live and nothing in sentinel/ imports it"


@pytest.mark.parametrize("module", sorted(TOOLING))
def test_a_tooling_module_is_used_by_a_script_and_not_by_the_service(module):
    assert _importers(module, "scripts"), f"{module} is listed as tooling and no script imports it"
    assert not _importers(module, "sentinel"), f"{module} is now on the service path; move it to LIVE"


@pytest.mark.parametrize("module", sorted(DORMANT))
def test_a_dormant_module_is_imported_by_nothing_that_ships(module):
    assert (ROOT / "sentinel" / "domain" / f"{module}.py").exists(), f"{module} is gone; remove it from DORMANT"
    users = _importers(module, "sentinel", "scripts")
    assert not users, f"{module} is listed as dormant and is imported by {users}; reclassify it"


def test_no_module_is_classified_twice():
    assert not (set(LIVE) & set(TOOLING)) and not (set(LIVE) & set(DORMANT)) and not (set(TOOLING) & set(DORMANT))


def test_current_documents_do_not_sell_a_dormant_module():
    """docs/current may mention a dormant module only to say it is not in use."""
    offenders = []
    for path in (ROOT / "docs" / "current").glob("*.md"):
        text = path.read_text(encoding="utf-8").lower()
        for module in DORMANT:
            # By file name: `identity` and `mfa` are also ordinary words.
            for match in re.finditer(rf"\b{module}\.py\b|domain/{module}\b", text):
                window = text[max(0, match.start() - 160): match.end() + 160]
                if not any(word in window for word in ("dormant", "not wired", "not part", "not in use", "not used", "superseded")):
                    offenders.append(f"{path.name}: {module}")
    assert not offenders, offenders
