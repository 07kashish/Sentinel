"""The seam that makes the discovery connectors reachable.

WHAT THIS GUARDS
----------------
`build_connectors` and `build_ai_connectors` had tests and NO production
caller. The connectors were cited in the gap ledger and audited by
`scripts/build_state_audit.py`, which is exactly how a subsystem comes to look
delivered while being unreachable.

THE PROPERTY THIS FILE IS REALLY ABOUT
---------------------------------------
An unconfigured connector must be ABSENT, and the absence must be reported as
an unperformed scan rather than a clean estate. Every other test here supports
that one, because it is the difference between a discovery product and a
number nobody trusts.
"""

from __future__ import annotations

from sentinel.composition.discovery_wiring import (
    build_discovery_connectors,
    describe_discovery,
    run_discovery,
)

K8S = {
    "SENTINEL_DISCOVERY_K8S_SERVER": "https://cluster.internal",
    "SENTINEL_DISCOVERY_K8S_TOKEN": "not-a-real-token",
    "SENTINEL_DISCOVERY_K8S_NAMESPACES": "default,prod",
}
AWS = {
    "SENTINEL_DISCOVERY_AWS_ACCESS_KEY_ID": "AKIDEXAMPLENOTREAL",
    "SENTINEL_DISCOVERY_AWS_SECRET_ACCESS_KEY": "not-a-real-secret",
    "SENTINEL_DISCOVERY_AWS_REGION": "eu-west-2",
}
BEDROCK = {
    "SENTINEL_DISCOVERY_BEDROCK_ACCESS_KEY_ID": "AKIDEXAMPLENOTREAL",
    "SENTINEL_DISCOVERY_BEDROCK_SECRET_ACCESS_KEY": "not-a-real-secret",
    "SENTINEL_DISCOVERY_BEDROCK_REGION": "eu-west-2",
}


# ── absent, never present-and-empty ────────────────────────────────────────


def test_an_empty_environment_configures_nothing():
    """THE rule. Not one connector, rather than seven that return nothing."""
    assert build_discovery_connectors({}) == {}


def test_the_description_of_nothing_says_a_scan_did_not_HAPPEN():
    """An operator reading this must not be able to mistake it for a clean
    estate, which is the entire reason `describe_discovery` exists.
    """
    summary = describe_discovery(build_discovery_connectors({}))

    assert summary["configured"] == []
    assert "different facts" in summary["note"]
    assert "observed nothing" in summary["note"]


def test_each_credential_set_enables_exactly_its_own_connector():
    assert sorted(build_discovery_connectors(K8S)) == ["kubernetes"]
    assert sorted(build_discovery_connectors(AWS)) == ["aws_iam"]
    assert sorted(build_discovery_connectors(BEDROCK)) == ["bedrock_agent"]
    assert sorted(
        build_discovery_connectors(
            {"SENTINEL_DISCOVERY_ENTRA_TOKEN": "t",
             "SENTINEL_DISCOVERY_ENTRA_TENANT": "tenant"}
        )
    ) == ["entra"]
    assert sorted(
        build_discovery_connectors(
            {"SENTINEL_DISCOVERY_VERTEX_TOKEN": "t",
             "SENTINEL_DISCOVERY_VERTEX_PROJECT": "my-project"}
        )
    ) == ["vertex"]
    assert sorted(
        build_discovery_connectors({"SENTINEL_DISCOVERY_OPENAI_TOKEN": "t"})
    ) == ["openai"]


def test_everything_configured_builds_every_connector():
    """The control: every test above would pass against a builder that
    returned nothing at all.
    """
    built = build_discovery_connectors(
        {
            **K8S,
            **AWS,
            **BEDROCK,
            "SENTINEL_DISCOVERY_ENTRA_TOKEN": "t",
            "SENTINEL_DISCOVERY_VERTEX_TOKEN": "t",
            "SENTINEL_DISCOVERY_VERTEX_PROJECT": "my-project",
            "SENTINEL_DISCOVERY_OPENAI_TOKEN": "t",
            "SENTINEL_DISCOVERY_MCP_ENDPOINTS": "files=https://mcp.internal/rpc",
        }
    )

    assert sorted(built) == [
        "aws_iam",
        "bedrock_agent",
        "entra",
        "generic_mcp",
        "kubernetes",
        "openai",
        "vertex",
    ]


# ── a partial credential is refused, not completed ─────────────────────────


def test_a_partial_aws_credential_builds_no_connector():
    """A key with no region fails at request time and is recorded as
    `unreachable`, which reads as an outage rather than a config mistake.
    """
    for dropped in AWS:
        partial = {k: v for k, v in AWS.items() if k != dropped}
        assert build_discovery_connectors(partial) == {}, dropped


def test_kubernetes_needs_both_server_and_token():
    assert build_discovery_connectors(
        {"SENTINEL_DISCOVERY_K8S_SERVER": "https://cluster.internal"}
    ) == {}
    assert build_discovery_connectors(
        {"SENTINEL_DISCOVERY_K8S_TOKEN": "t"}
    ) == {}


def test_kubernetes_without_namespaces_is_not_built():
    """`build_connectors` requires namespaces, because a Kubernetes connector
    pointed at no namespace would examine nothing and report zero.
    """
    without = {k: v for k, v in K8S.items()
               if k != "SENTINEL_DISCOVERY_K8S_NAMESPACES"}

    assert build_discovery_connectors(without) == {}


# ── MCP endpoint parsing ───────────────────────────────────────────────────


def test_mcp_accepts_a_bare_url_and_a_labelled_one():
    built = build_discovery_connectors(
        {
            "SENTINEL_DISCOVERY_MCP_ENDPOINTS": (
                "https://a.internal/rpc,files=https://b.internal/rpc"
            )
        }
    )

    assert sorted(built) == ["generic_mcp"]


def test_an_empty_mcp_entry_is_skipped_not_defaulted():
    """A connector pointed at nothing would report a server that does not
    exist.
    """
    assert build_discovery_connectors(
        {"SENTINEL_DISCOVERY_MCP_ENDPOINTS": " , ,"}
    ) == {}


# ── the report names what has never been validated ─────────────────────────


def test_the_five_unvalidated_connectors_are_named_in_the_report():
    """The caveat has to travel WITH the number. In a document it is worthless
    at the moment somebody reads a count.
    """
    built = build_discovery_connectors(
        {
            **BEDROCK,
            "SENTINEL_DISCOVERY_ENTRA_TOKEN": "t",
            "SENTINEL_DISCOVERY_VERTEX_TOKEN": "t",
            "SENTINEL_DISCOVERY_VERTEX_PROJECT": "my-project",
            "SENTINEL_DISCOVERY_OPENAI_TOKEN": "t",
            "SENTINEL_DISCOVERY_MCP_ENDPOINTS": "files=https://mcp.internal/rpc",
        }
    )
    summary = describe_discovery(built)

    assert summary["unvalidated"] == [
        "bedrock_agent",
        "entra",
        "generic_mcp",
        "openai",
        "vertex",
    ]
    assert "says nothing at all" in summary["note"]


def test_the_two_validated_connectors_are_not_flagged_unvalidated():
    """The control for the test above: it would pass if every connector were
    flagged. Kubernetes and AWS IAM predate this work and are not marked.
    """
    summary = describe_discovery(build_discovery_connectors({**K8S, **AWS}))

    assert summary["configured"] == ["aws_iam", "kubernetes"]
    assert summary["unvalidated"] == []


# ── a failing connector is reported, never omitted ─────────────────────────


def test_a_connector_that_raises_is_reported_as_a_failure():
    """Omitting it would shorten the report by exactly the entries that went
    wrong, which is how a broken scan comes to look like a clean one.
    """

    class _Exploding:
        name = "exploding"

        def discover(self):
            raise RuntimeError("credential expired")

    reports = run_discovery({"exploding": _Exploding()})

    assert len(reports) == 1
    assert reports[0]["failed"] is True
    assert "credential expired" in reports[0]["error"]


def test_a_working_connector_reports_assets_beside_its_coverage():
    """A count without a denominator is a number with no scale."""
    from sentinel.domain.assets import (
        AssetInventory,
        AssetKind,
        AssetRecord,
        DiscoveryCoverage,
    )

    class _Working:
        name = "working"

        def discover(self):
            return AssetInventory(
                connector="working",
                assets=(
                    AssetRecord(
                        kind=AssetKind.AGENT,
                        identifier="x://1",
                        source="working",
                    ),
                ),
                coverage=DiscoveryCoverage(
                    scope=("everything",), examined=7, retrieved_at="now"
                ),
            )

    reports = run_discovery({"working": _Working()})

    assert reports[0]["failed"] is False
    assert reports[0]["assets"] == 1
    assert reports[0]["coverage"]["examined"] == 7


def test_every_connector_is_run_even_when_an_earlier_one_fails():
    """A single failure must not truncate the pass."""

    class _Exploding:
        def discover(self):
            raise RuntimeError("nope")

    reports = run_discovery(
        {"a_explodes": _Exploding(), "b_explodes": _Exploding()}
    )

    assert [r["connector"] for r in reports] == ["a_explodes", "b_explodes"]


# ── the CLI refuses to make an unperformed scan look clean ────────────────


def test_the_cli_exits_non_zero_when_nothing_is_configured(monkeypatch, capsys):
    """1, not 0. An unperformed scan that exits 0 in CI is indistinguishable
    from a passing one.
    """
    import scripts.run_discovery as cli

    monkeypatch.setattr(cli, "build_discovery_connectors", lambda source: {})
    monkeypatch.setattr(cli, "build_breadth_connectors", lambda source: {})

    code = cli.main([])
    output = capsys.readouterr().out

    assert code == 1
    assert "NO DISCOVERY CONNECTOR IS CONFIGURED" in output


def test_the_cli_exits_two_when_coverage_was_partial(monkeypatch, capsys):
    """A truncated listing that exits 0 in CI is a subset recorded as a
    total.
    """
    import scripts.run_discovery as cli

    monkeypatch.setattr(cli, "build_discovery_connectors", lambda source: {"x": object()})
    monkeypatch.setattr(cli, "build_breadth_connectors", lambda source: {})
    monkeypatch.setattr(cli, "describe_discovery", lambda c: {
        "configured": ["x"], "configured_count": 1, "unvalidated": [],
        "note": "note",
    })
    monkeypatch.setattr(cli, "run_discovery", lambda c: [
        {"connector": "x", "failed": False, "assets": 3,
         "coverage": {"examined": 3, "is_partial": True, "unreachable": [
             {"target": "x:list", "reason": "truncated; this is a subset"}
         ]}}
    ])

    code = cli.main([])
    output = capsys.readouterr().out

    assert code == 2
    assert "PARTIAL" in output
    assert "subset" in output


def test_the_cli_exits_zero_only_on_complete_coverage(monkeypatch, capsys):
    """The control. Without this the exit codes above could come from a CLI
    that never returns 0.
    """
    import scripts.run_discovery as cli

    monkeypatch.setattr(cli, "build_discovery_connectors", lambda source: {"x": object()})
    monkeypatch.setattr(cli, "build_breadth_connectors", lambda source: {})
    monkeypatch.setattr(cli, "describe_discovery", lambda c: {
        "configured": ["x"], "configured_count": 1, "unvalidated": [],
        "note": "note",
    })
    monkeypatch.setattr(cli, "run_discovery", lambda c: [
        {"connector": "x", "failed": False, "assets": 3,
         "coverage": {"examined": 3, "is_partial": False, "unreachable": []}}
    ])

    assert cli.main([]) == 0
    capsys.readouterr()


def test_the_cli_explains_what_each_connector_needs(capsys):
    import scripts.run_discovery as cli

    assert cli.main(["--explain"]) == 0
    output = capsys.readouterr().out

    for name in (
        "kubernetes", "aws_iam", "bedrock_agent", "entra", "vertex",
        "openai", "generic_mcp",
    ):
        assert name in output
    assert "ABSENT" in output


def test_no_credential_value_reaches_the_report():
    """`describe_discovery` reports names. A token in a report is a token in
    whatever the report was pasted into.
    """
    secret = "super-secret-discovery-token"
    built = build_discovery_connectors(
        {
            "SENTINEL_DISCOVERY_OPENAI_TOKEN": secret,
            "SENTINEL_DISCOVERY_OPENAI_ORG": "org-visible",
        }
    )
    rendered = repr(describe_discovery(built))

    assert "openai" in rendered, "control: the connector name IS reported"
    assert secret not in rendered
