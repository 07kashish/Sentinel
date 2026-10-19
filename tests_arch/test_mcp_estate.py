"""MCP failures that no single call can reveal.

WHY THESE ARE NOT MORE PROXY CHECKS
-------------------------------------
`mcp_proxy_checks.py` judges one call against one server and does it well:
drifted listings, duplicate names within a server, changed identity, foreign
issuers. All answerable from the request in hand.

Three are not, and each one passes every per-call check while it happens:

  * a hostile server offering `read_file` alongside a trusted one's `read_file`
    — neither listing drifted, neither contains a duplicate, both pass;
  * an agent reaching a server nobody enrolled — the proxy refuses those, but
    only sees traffic that came through the proxy;
  * one credential presented to eight servers — every call individually fine.

`test_a_collision_passes_every_per_call_check` is the one that states the first
of those directly, because it is the reason this module exists at all.
"""

from __future__ import annotations

from sentinel.domain.mcp_estate import (
    EstateFindingKind,
    ObservedServerUse,
    ServerRecord,
    assess_estate,
)


def _server(server_id, *tools, trust="enrolled", credential="") -> ServerRecord:
    return ServerRecord(
        server_id=server_id,
        trust=trust,
        tool_names=tuple(tools),
        credential_id=credential,
    )


def _kinds(report) -> set[EstateFindingKind]:
    return {f.kind for f in report.findings}


# ── cross-server collision ───────────────────────────────────────────────────


def test_two_reachable_servers_offering_one_tool_name_collide():
    report = assess_estate(
        enrolled=[
            _server("trusted-fs", "read_file", "write_file"),
            _server("newcomer", "read_file"),
        ]
    )
    collisions = report.of_kind(EstateFindingKind.CROSS_SERVER_COLLISION)
    assert len(collisions) == 1
    assert "read_file" in collisions[0].subjects
    assert collisions[0].severity == "high"


def test_a_collision_passes_every_per_call_check():
    """THE reason this module exists. Both listings are clean, neither is
    drifted, neither contains an internal duplicate — and an agent configured
    with both resolves the name to whichever its client picks.
    """
    from sentinel.domain.mcp import McpToolDefinition
    from sentinel.interface.mcp_proxy_checks import duplicate_tool_name

    listing_a = (McpToolDefinition(name="read_file", description="", input_schema={}),)
    listing_b = (McpToolDefinition(name="read_file", description="", input_schema={}),)

    # Each server's own listing is clean by the per-call rule.
    assert duplicate_tool_name(listing_a) == ""
    assert duplicate_tool_name(listing_b) == ""

    # The estate view is the only place the ambiguity is visible.
    report = assess_estate(
        enrolled=[_server("a", "read_file"), _server("b", "read_file")]
    )
    assert report.of_kind(EstateFindingKind.CROSS_SERVER_COLLISION)


def test_distinct_tool_names_do_not_collide():
    report = assess_estate(
        enrolled=[_server("a", "read_file"), _server("b", "send_email")]
    )
    assert EstateFindingKind.CROSS_SERVER_COLLISION not in _kinds(report)


def test_a_blocked_server_does_not_collide_with_anything():
    """Its tools are unreachable. Reporting the collision would send an operator
    to resolve an ambiguity that cannot occur.
    """
    report = assess_estate(
        enrolled=[
            _server("trusted", "read_file"),
            _server("refused", "read_file", trust="blocked"),
        ]
    )
    assert EstateFindingKind.CROSS_SERVER_COLLISION not in _kinds(report)


# ── shadow servers ───────────────────────────────────────────────────────────


def test_a_server_nobody_enrolled_is_shadow():
    report = assess_estate(
        enrolled=[_server("known", "read_file")],
        observed=[ObservedServerUse(server_id="mystery", agent_ids=("finance-agent",))],
    )
    shadow = report.of_kind(EstateFindingKind.SHADOW_SERVER)
    assert shadow and "mystery" in shadow[0].subjects
    assert "finance-agent" in shadow[0].subjects


def test_a_blocked_server_still_being_used_outranks_a_shadow_one():
    """A shadow server is one nobody assessed. A blocked one is a server
    somebody assessed and REFUSED, still being reached — a control that is not
    holding, which is worse than a control nobody applied.
    """
    report = assess_estate(
        enrolled=[_server("refused", "x", trust="blocked")],
        observed=[
            ObservedServerUse(server_id="refused", call_count=12),
            ObservedServerUse(server_id="mystery"),
        ],
    )
    assert report.findings[0].kind is EstateFindingKind.BLOCKED_SERVER_STILL_USED
    assert report.findings[0].severity == "critical"


def test_an_enrolled_server_in_use_is_not_a_finding():
    report = assess_estate(
        enrolled=[_server("known", "read_file")],
        observed=[ObservedServerUse(server_id="known", call_count=5)],
    )
    assert report.findings == ()


# ── credential sprawl ────────────────────────────────────────────────────────


def test_one_credential_across_several_servers_is_sprawl():
    report = assess_estate(
        enrolled=[
            _server("a", credential="shared-token"),
            _server("b", credential="shared-token"),
            _server("c", credential="shared-token"),
        ]
    )
    sprawl = report.of_kind(EstateFindingKind.CREDENTIAL_SPRAWL)
    assert sprawl and "shared-token" in sprawl[0].subjects


def test_sprawl_counts_shadow_servers_too():
    """A credential shared between one enrolled server and several shadow ones
    is exactly the case worth catching, and counting only enrolments misses it.
    """
    report = assess_estate(
        enrolled=[_server("known", credential="tok")],
        observed=[
            ObservedServerUse(server_id="s1", credential_id="tok"),
            ObservedServerUse(server_id="s2", credential_id="tok"),
        ],
    )
    assert report.of_kind(EstateFindingKind.CREDENTIAL_SPRAWL)


def test_a_credential_on_one_server_is_not_sprawl():
    report = assess_estate(enrolled=[_server("a", credential="dedicated")])
    assert EstateFindingKind.CREDENTIAL_SPRAWL not in _kinds(report)


def test_the_sprawl_threshold_is_a_parameter_not_a_belief():
    """Three is not a magic number and does not pretend to be. A deployment may
    reasonably disagree, and one that cannot adjust it will ignore the finding.
    """
    servers = [_server(f"s{i}", credential="tok") for i in range(2)]
    assert not assess_estate(enrolled=servers).of_kind(
        EstateFindingKind.CREDENTIAL_SPRAWL
    )
    assert assess_estate(enrolled=servers, sprawl_threshold=2).of_kind(
        EstateFindingKind.CREDENTIAL_SPRAWL
    )


# ── unused enrolments ────────────────────────────────────────────────────────


def test_an_enrolled_server_nothing_calls_is_standing_trust():
    """The cheapest thing to remove from an estate before it becomes the thing
    an attacker impersonates.
    """
    report = assess_estate(
        enrolled=[_server("used", "a"), _server("forgotten", "b")],
        observed=[ObservedServerUse(server_id="used", call_count=3)],
    )
    unused = report.of_kind(EstateFindingKind.UNUSED_ENROLMENT)
    assert unused and unused[0].subjects == ("forgotten",)
    assert unused[0].severity == "low"


def test_no_observed_traffic_at_all_reports_no_unused_enrolments():
    """With no telemetry, EVERY server would look unused. Reporting them all
    would be reporting the absence of data as a finding about the estate.
    """
    report = assess_estate(enrolled=[_server("a"), _server("b")])
    assert EstateFindingKind.UNUSED_ENROLMENT not in _kinds(report)


# ── honesty ──────────────────────────────────────────────────────────────────


def test_the_report_states_what_shadow_detection_cannot_see():
    """Shadow servers come from comparing enrolled to OBSERVED. A server reached
    by an agent that reports nothing is invisible, and absence of a finding is
    not evidence of absence.
    """
    document = assess_estate(enrolled=[]).as_dict()
    assert "not evidence" in document["limits"]


def test_findings_are_ordered_worst_first():
    report = assess_estate(
        enrolled=[
            _server("blocked-one", "x", trust="blocked"),
            _server("a", "read_file"),
            _server("b", "read_file"),
        ],
        observed=[ObservedServerUse(server_id="blocked-one", call_count=1)],
    )
    severities = [f.severity for f in report.findings]
    assert severities == sorted(
        severities, key=("critical", "high", "moderate", "low").index
    )


def test_every_kind_has_a_severity():
    for kind in EstateFindingKind:
        from sentinel.domain.mcp_estate import ESTATE_SEVERITY

        assert kind in ESTATE_SEVERITY, f"{kind} has no severity"


def test_the_estate_view_decides_nothing():
    """These are findings for an operator and inputs to policy, not refusals. A
    collision between two legitimately enrolled servers is a configuration
    problem, and blocking both would take out the trusted one as well.
    """
    import inspect

    from sentinel.domain import mcp_estate

    source = inspect.getsource(mcp_estate)
    for verb in ("def block", "def refuse", "def contain", "raise "):
        assert verb not in source, f"mcp_estate takes an action: {verb!r}"
