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
DORMANT = {}  # The three unused domain primitives were removed in Phase 2.


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




def test_no_module_is_classified_twice():
    assert not (set(LIVE) & set(TOOLING)) and not (set(LIVE) & set(DORMANT)) and not (set(TOOLING) & set(DORMANT))
