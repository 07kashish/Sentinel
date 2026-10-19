"""An endpoint sensor that would not get uninstalled.

WHAT KILLS AN ENDPOINT SENSOR
-----------------------------
Not a bug. One engineer discovering it read something personal, or collected
their credentials -- after which it is uninstalled everywhere and never
reinstalled. So the privacy properties are asserted here as hard constraints,
not documented as intentions:

  * only allowlisted paths are read, and the allowlist is agent configuration;
  * credential VALUES never leave the machine, only 16-character digests;
  * nothing is opened for writing.

THE OTHER HALF IS COVERAGE HONESTY
----------------------------------
A sensor that could not read anything and a machine with no agents produce the
SAME empty finding list. Reporting the first as the second is how an endpoint
fleet appears clean while blind, so `ScanOutcome` is three-valued and
`FleetSummary.shadow_findings` counts only hosts whose absences mean
something -- a total mixing in unreadable hosts would FALL as the sensor broke
on more of them.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.domain.endpoint_sensor import (
    AgentKind,
    ClassifiedFinding,
    EndpointFinding,
    Enrolment,
    FleetSummary,
    ScanOutcome,
    SecretPresence,
    SensorScan,
    classify,
    secret_digest,
)
from sentinel.infrastructure.endpoint_scan import (
    ALLOWLIST,
    SECRET_KEY_MARKERS,
    scan_endpoint,
)

REAL_TOKEN = "sk-ant-api03-NOT-A-REAL-KEY-just-a-fixture-value"


def _tree(base: Path, files: dict[str, str]) -> Path:
    for relative, content in files.items():
        path = base / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return base


def _mcp_config(**servers) -> str:
    return json.dumps({"mcpServers": servers})


# ── the allowlist is the whole surface ─────────────────────────────────────


def test_a_file_outside_the_allowlist_is_never_read(tmp_path):
    """THE privacy property. A directory walk would find these; the allowlist
    does not look at them.
    """
    _tree(tmp_path, {
        ".mcp.json": _mcp_config(aws={"command": "mcp-aws"}),
        ".bash_history": "ssh production\npsql -h db\n",
        "Documents/diary.txt": "personal",
        ".ssh/id_rsa": "PRIVATE KEY",
        ".aws/credentials": "[default]\naws_secret_access_key=x",
    })

    scan = scan_endpoint(root=tmp_path, host_id="laptop-1")

    assert scan.inspected == (".mcp.json",), "control: nothing was inspected"
    joined = repr(scan)
    for private in ("bash_history", "diary", "id_rsa", "credentials"):
        assert private not in joined


def test_the_allowlist_holds_no_absolute_paths():
    """An absolute path would embed a username, which then travels off the
    machine in every finding.
    """
    for entry in ALLOWLIST:
        assert not entry.path.startswith(("/", "~")), entry.path
        assert ":" not in entry.path, entry.path


def test_every_allowlist_entry_says_why_it_is_there():
    """An entry nobody can justify is an entry nobody dares remove, and this
    list is the sensor's entire privacy boundary.
    """
    assert len(ALLOWLIST) >= 8
    for entry in ALLOWLIST:
        assert len(entry.why) > 20, entry.path


def test_a_finding_records_a_relative_path_not_an_absolute_one(tmp_path):
    _tree(tmp_path, {".mcp.json": _mcp_config(aws={"command": "mcp-aws"})})

    scan = scan_endpoint(root=tmp_path, host_id="laptop-1")

    assert scan.findings[0].source == ".mcp.json"
    assert str(tmp_path) not in scan.findings[0].source


# ── credentials are digested, never retained ──────────────────────────────


def test_a_credential_value_never_appears_in_the_scan(tmp_path):
    """The property that decides whether this is deployable. A sensor that
    collected credentials would centralise every developer's keys into one
    database -- a worse problem than the one it was deployed to solve.
    """
    _tree(tmp_path, {
        ".mcp.json": _mcp_config(
            anthropic={
                "command": "mcp-anthropic",
                "env": {"ANTHROPIC_API_KEY": REAL_TOKEN},
            }
        )
    })

    scan = scan_endpoint(root=tmp_path, host_id="laptop-1")

    assert scan.findings, "control: nothing was found, so nothing was checked"
    assert REAL_TOKEN not in repr(scan)
    assert REAL_TOKEN not in json.dumps(
        classify(scan, enrolled=[]).as_dict()
    )


def test_the_presence_of_a_secret_is_still_reported(tmp_path):
    """Digesting it must not mean losing the finding. "This config carries a
    credential" is the actionable half.
    """
    _tree(tmp_path, {
        ".mcp.json": _mcp_config(
            anthropic={"env": {"ANTHROPIC_API_KEY": REAL_TOKEN}}
        )
    })

    finding = scan_endpoint(root=tmp_path, host_id="h").findings[0]

    assert finding.secrets is SecretPresence.PRESENT
    assert finding.secret_digests == (secret_digest(REAL_TOKEN),)


def test_the_same_key_on_two_machines_correlates(tmp_path):
    """Which is the question the digest exists to answer: a credential shared
    across twelve laptops is a different problem from twelve credentials.
    """
    first = _tree(
        tmp_path / "a",
        {".mcp.json": _mcp_config(x={"env": {"API_KEY": REAL_TOKEN}})},
    )
    second = _tree(
        tmp_path / "b",
        {".mcp.json": _mcp_config(y={"env": {"TOKEN": REAL_TOKEN}})},
    )

    one = scan_endpoint(root=first, host_id="a").findings[0]
    other = scan_endpoint(root=second, host_id="b").findings[0]

    assert one.secret_digests == other.secret_digests


def test_a_digest_is_truncated(tmp_path):
    """A full SHA-256 of a short or low-entropy token is a token somebody can
    grind offline. 16 hex characters correlate and do not recover.
    """
    assert len(secret_digest("hunter2")) == 16


def test_a_finding_refuses_a_full_length_digest():
    """Which is what a raw value or an untruncated hash would look like."""
    with pytest.raises(ValueError) as raised:
        EndpointFinding(
            kind=AgentKind.MCP_SERVER,
            name="x",
            source=".mcp.json",
            secret_digests=("a" * 64,),
            secrets=SecretPresence.PRESENT,
        )

    assert "grind" in str(raised.value)


def test_a_finding_cannot_claim_no_secrets_while_holding_digests():
    """The combination would let a reader conclude a config is clean while the
    row holds evidence it is not.
    """
    with pytest.raises(ValueError) as raised:
        EndpointFinding(
            kind=AgentKind.MCP_SERVER,
            name="x",
            source=".mcp.json",
            secret_digests=(secret_digest("t"),),
            secrets=SecretPresence.ABSENT,
        )

    assert "one of the two is wrong" in str(raised.value).lower()


def test_a_non_secret_env_var_is_not_digested(tmp_path):
    """Decided by KEY NAME, not entropy. An entropy rule reports a long base64
    project id as a key and misses `pw=hunter2`.
    """
    _tree(tmp_path, {
        ".mcp.json": _mcp_config(
            x={"env": {"AWS_REGION": "eu-west-2", "LOG_LEVEL": "debug"}}
        )
    })

    finding = scan_endpoint(root=tmp_path, host_id="h").findings[0]

    assert finding.secrets is SecretPresence.ABSENT
    assert finding.secret_digests == ()


def test_the_secret_marker_list_is_auditable():
    """It is the whole credential rule, so it has to be short enough to read
    and specific enough to mean something.
    """
    assert "token" in SECRET_KEY_MARKERS
    assert "password" in SECRET_KEY_MARKERS
    assert len(SECRET_KEY_MARKERS) < 30
    for marker in SECRET_KEY_MARKERS:
        assert marker == marker.lower()


# ── nothing is written ─────────────────────────────────────────────────────


def test_the_scan_does_not_modify_anything(tmp_path):
    """An endpoint tool that can modify a developer's configuration has a
    blast radius. Containment lives server-side where it is authorised.
    """
    files = {
        ".mcp.json": _mcp_config(aws={"command": "mcp-aws"}),
        "requirements.txt": "langgraph>=0.2\n",
    }
    _tree(tmp_path, files)
    before = {
        name: (tmp_path / name).read_bytes() for name in files
    }

    scan_endpoint(root=tmp_path, host_id="h")

    for name, content in before.items():
        assert (tmp_path / name).read_bytes() == content, name


def test_the_scanner_opens_nothing_for_writing():
    """Asserted against the source, because a write introduced later would
    pass every behavioural test above until it hit the wrong file.
    """
    import ast
    import inspect

    from sentinel.infrastructure import endpoint_scan

    tree = ast.parse(inspect.getsource(endpoint_scan))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = getattr(node.func, "attr", getattr(node.func, "id", ""))
            assert name not in {
                "write_text", "write_bytes", "unlink", "rmdir", "mkdir",
                "rename", "replace", "chmod",
            }, f"the scanner calls {name}"


# ── coverage honesty ───────────────────────────────────────────────────────


def test_an_empty_machine_is_unreadable_not_clean(tmp_path):
    """The failure this guards: a sensor that read nothing and a machine with
    no agents produce the same empty finding list.
    """
    scan = scan_endpoint(root=tmp_path, host_id="h")

    assert scan.findings == ()
    assert scan.outcome is ScanOutcome.UNREADABLE
    assert classify(scan).trustworthy is False


def test_a_readable_machine_with_no_agents_is_complete(tmp_path):
    """The other side. A file that exists, parses and declares nothing is a
    genuine clean result -- and it must be distinguishable from the above.
    """
    _tree(tmp_path, {"requirements.txt": "flask==3.0\n"})

    scan = scan_endpoint(root=tmp_path, host_id="h")

    assert scan.findings == ()
    assert scan.outcome is ScanOutcome.COMPLETE
    assert classify(scan, enrolled=[]).trustworthy is True


def test_a_malformed_config_is_unreadable_not_empty(tmp_path):
    """A config the sensor could not parse may declare a dozen servers.
    Treating it as zero is the difference between a gap and a clean bill.
    """
    _tree(tmp_path, {".mcp.json": "{ not json at all"})

    scan = scan_endpoint(root=tmp_path, host_id="h")

    assert ".mcp.json" in scan.unreadable
    assert ".mcp.json" not in scan.inspected
    assert scan.outcome is ScanOutcome.UNREADABLE


def test_a_partially_readable_machine_says_so(tmp_path):
    _tree(tmp_path, {
        ".mcp.json": _mcp_config(aws={"command": "mcp-aws"}),
        ".cursor/mcp.json": "{ broken",
    })

    scan = scan_endpoint(root=tmp_path, host_id="h")

    assert scan.outcome is ScanOutcome.PARTIAL
    assert scan.findings, "control: the readable half produced nothing"
    assert classify(scan, enrolled=[]).trustworthy is False


def test_an_absent_path_is_neither_inspected_nor_unreadable(tmp_path):
    """Counting absence as inspection would make an empty machine look
    thoroughly scanned.
    """
    _tree(tmp_path, {".mcp.json": _mcp_config(aws={})})

    scan = scan_endpoint(root=tmp_path, host_id="h")

    assert scan.inspected == (".mcp.json",)
    assert scan.unreadable == ()


# ── shadow is three-valued ─────────────────────────────────────────────────


def test_without_an_enrolled_set_nothing_is_called_shadow(tmp_path):
    """A two-valued answer reports every agent on every machine as shadow on
    the first run, which is the report that gets a sensor ignored.
    """
    _tree(tmp_path, {".mcp.json": _mcp_config(aws={}, github={})})

    report = classify(scan_endpoint(root=tmp_path, host_id="h"), enrolled=None)

    assert {item.enrolment for item in report.findings} == {Enrolment.UNKNOWN}
    assert report.shadow == ()


def test_an_empty_enrolled_set_is_not_the_same_as_no_set(tmp_path):
    """Passing [] means the estate genuinely has nothing enrolled. Passing None
    means nobody asked. Conflating them is the bug above.
    """
    _tree(tmp_path, {".mcp.json": _mcp_config(aws={})})
    scan = scan_endpoint(root=tmp_path, host_id="h")

    assert classify(scan, enrolled=[]).findings[0].enrolment is Enrolment.SHADOW
    assert classify(scan, enrolled=None).findings[0].enrolment is Enrolment.UNKNOWN


def test_an_enrolled_agent_is_not_shadow(tmp_path):
    _tree(tmp_path, {".mcp.json": _mcp_config(aws={}, rogue={})})

    report = classify(
        scan_endpoint(root=tmp_path, host_id="h"), enrolled=["aws"]
    )
    by_name = {item.finding.name: item.enrolment for item in report.findings}

    assert by_name["aws"] is Enrolment.ENROLLED
    assert by_name["rogue"] is Enrolment.SHADOW
    assert len(report.shadow) == 1


def test_every_enrolment_and_outcome_explains_itself():
    for value in list(Enrolment) + list(ScanOutcome) + list(AgentKind):
        assert len(value.explanation) > 25, value.name


# ── what the parsers actually find ────────────────────────────────────────


def test_mcp_servers_are_found_with_their_reachable_hosts(tmp_path):
    _tree(tmp_path, {
        ".mcp.json": _mcp_config(
            remote={"url": "https://mcp.example.com/sse"},
            local={"command": "mcp-local", "args": ["--port", "9000"]},
        )
    })

    scan = scan_endpoint(root=tmp_path, host_id="h")
    by_name = {f.name: f for f in scan.findings}

    assert by_name["remote"].reaches == ("https://mcp.example.com/sse",)
    assert by_name["local"].command == "mcp-local"
    assert by_name["local"].reaches == ()


def test_a_framework_is_found_with_its_version_specifier(tmp_path):
    _tree(tmp_path, {"requirements.txt": "langgraph>=0.2.1\nflask==3.0\n"})

    scan = scan_endpoint(root=tmp_path, host_id="h")

    assert [f.name for f in scan.findings] == ["langgraph"]
    assert ">=0.2.1" in scan.findings[0].version


def test_a_lookalike_package_is_not_reported_as_a_framework(tmp_path):
    """A substring match on "agent" would report `useragent`. The marker list
    is exact names for that reason.
    """
    _tree(tmp_path, {"requirements.txt": "useragent==1.0\npytest-agent==2\n"})

    scan = scan_endpoint(root=tmp_path, host_id="h")

    assert scan.findings == ()
    assert scan.outcome is ScanOutcome.COMPLETE


def test_javascript_agent_packages_are_found(tmp_path):
    _tree(tmp_path, {
        "package.json": json.dumps({
            "dependencies": {"@modelcontextprotocol/sdk": "^1.0", "react": "^18"}
        })
    })

    scan = scan_endpoint(root=tmp_path, host_id="h")

    assert [f.name for f in scan.findings] == ["@modelcontextprotocol/sdk"]


def test_ci_workflows_are_named_but_not_parsed(tmp_path):
    """Presence of a runner is the endpoint finding. What it runs is a
    repository question, and parsing it would mean reading arbitrary YAML off
    a developer's disk for no additional decision.
    """
    _tree(tmp_path, {
        ".github/workflows/ci.yml": "jobs:\n  x:\n    steps: []\n",
        ".github/workflows/deploy.yaml": "jobs: {}\n",
    })

    scan = scan_endpoint(root=tmp_path, host_id="h")

    assert sorted(f.name for f in scan.findings) == ["ci.yml", "deploy.yaml"]
    assert all(
        f.secrets is SecretPresence.NOT_INSPECTED for f in scan.findings
    )


# ── the fleet total cannot flatter itself ─────────────────────────────────


def test_the_fleet_total_counts_only_hosts_whose_absences_mean_something():
    """A total mixing in unreadable hosts would FALL as the sensor broke on
    more of them, which is a metric that rewards its own failure.
    """
    good = classify(
        SensorScan(
            host_id="a",
            findings=(
                EndpointFinding(
                    kind=AgentKind.MCP_SERVER, name="rogue", source=".mcp.json"
                ),
            ),
            inspected=(".mcp.json",),
        ),
        enrolled=[],
    )
    blind = classify(SensorScan(host_id="b"), enrolled=[])

    summary = FleetSummary(reports=(good, blind))

    assert summary.trustworthy_hosts == 1
    assert summary.blind_hosts == 1
    assert summary.shadow_findings == 1
    assert "would fall" in summary.as_dict()["coverage_note"]


def test_a_blind_host_contributes_no_shadow_findings():
    blind = classify(
        SensorScan(
            host_id="b",
            findings=(
                EndpointFinding(
                    kind=AgentKind.MCP_SERVER, name="rogue", source=".mcp.json"
                ),
            ),
            unreadable=(".cursor/mcp.json",),
        ),
        enrolled=[],
    )

    # It found something, and its scan is not trustworthy, so the fleet total
    # must not count it -- an incomplete host's numbers are not comparable.
    assert blind.shadow
    assert FleetSummary(reports=(blind,)).shadow_findings == 0


def test_the_report_renders_its_own_warning():
    """Somebody will read the rendered output and not the dict."""
    rendered = classify(SensorScan(host_id="b"), enrolled=[]).render()

    assert "WARNING" in rendered
    assert "sensor failed" in rendered


def test_an_unnamed_finding_is_refused():
    with pytest.raises(ValueError):
        EndpointFinding(kind=AgentKind.MCP_SERVER, name="  ", source=".mcp.json")


def test_a_classified_finding_carries_the_enrolment_explanation():
    item = ClassifiedFinding(
        finding=EndpointFinding(
            kind=AgentKind.MCP_SERVER, name="x", source=".mcp.json"
        ),
        enrolment=Enrolment.UNKNOWN,
    )

    assert "NOT determined" in item.as_dict()["enrolment_explanation"]
