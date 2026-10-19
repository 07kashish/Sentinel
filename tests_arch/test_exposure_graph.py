"""A graph makes absence look like a fact. These tests attack that.

If nothing scanned an account, its agents have no edges -- and "no edges"
renders exactly like "isolated" on every screen, while meaning the opposite.
Isolated is the most reassuring thing a graph can say, so most of the effort
here goes on one question: can a caller obtain a reassuring answer about
territory nobody looked at?
"""

from __future__ import annotations

import pytest

from sentinel.domain.exposure_graph import (
    EdgeBasis,
    ExposureEdge,
    GraphCoverage,
    NodeKind,
    Reachability,
    UnscannedScope,
    build_exposure_graph,
)

FULL = GraphCoverage(scanned=("prod",))


def _edge(
    source: str,
    target: str,
    kind: NodeKind = NodeKind.RESOURCE,
    basis: EdgeBasis = EdgeBasis.OBSERVED,
    **kwargs,
) -> ExposureEdge:
    return ExposureEdge(
        source=source, target=target, target_kind=kind, basis=basis, **kwargs
    )


def _graph(*edges: ExposureEdge, coverage: GraphCoverage | None = None, **kwargs):
    return build_exposure_graph(
        tenant="acme",
        edges=edges,
        coverage=coverage if coverage is not None else FULL,
        **kwargs,
    )


# ── the three-valued verdict ─────────────────────────────────────────────────


def test_a_found_path_is_reachable():
    graph = _graph(_edge("agent-a", "bucket-x"))

    assert graph.reachability_of("agent-a", "bucket-x") is Reachability.REACHABLE


def test_a_fully_scanned_graph_can_assert_not_reachable():
    """The verdict must be usable in the good case or operators ignore it."""
    graph = _graph(_edge("agent-a", "bucket-x"))

    assert (
        graph.reachability_of("agent-a", "bucket-y") is Reachability.NOT_REACHABLE
    )


def test_an_unscanned_scope_makes_every_absence_unknown():
    """THE test this module exists for.

    A route could run through territory nobody scanned, so the absence of a
    path is not evidence. Reporting NOT_REACHABLE here is how a graph provides
    false comfort during the one hour it matters.
    """
    graph = _graph(
        _edge("agent-a", "bucket-x"),
        coverage=GraphCoverage(
            scanned=("prod",),
            unscanned=(UnscannedScope(scope="acct-4", reason="AccessDenied"),),
        ),
    )

    assert graph.reachability_of("agent-a", "bucket-y") is Reachability.UNKNOWN


def test_a_node_the_graph_only_knows_by_name_reports_unknown():
    """Named in somebody else's edge, never itself enumerated.

    The graph knows it exists and knows nothing about what it reaches -- which
    is precisely the case that must not read as isolated.
    """
    graph = _graph(
        _edge("agent-a", "agent-b", NodeKind.AGENT),
        coverage=GraphCoverage(scanned=("prod",), partially_known=("agent-b",)),
    )

    assert graph.reachability_of("agent-b", "bucket-x") is Reachability.UNKNOWN


def test_an_unenumerated_node_the_source_can_reach_makes_the_answer_unknown():
    """A route could continue past a node the graph only knows by name.

    agent-a reaches agent-b, and agent-b's neighbourhood was never enumerated,
    so whether agent-a reaches bucket-x THROUGH agent-b is unknowable from
    this graph.
    """
    graph = _graph(
        _edge("agent-a", "agent-b", NodeKind.AGENT),
        coverage=GraphCoverage(scanned=("prod",), partially_known=("agent-b",)),
    )

    assert graph.reachability_of("agent-a", "bucket-x") is Reachability.UNKNOWN


def test_an_unenumerated_node_the_source_cannot_reach_does_not_poison_the_answer():
    """Precision, and the reason the check asks about the FRONTIER.

    The blanket version returned UNKNOWN for every question in the graph as
    soon as one node anywhere was unenumerated. A verdict that is always
    UNKNOWN teaches operators to ignore it, which costs more than the
    occasional over-broad answer it was trying to avoid.
    """
    graph = _graph(
        _edge("agent-a", "bucket-x"),
        _edge("agent-q", "agent-r", NodeKind.AGENT),
        coverage=GraphCoverage(scanned=("prod",), partially_known=("agent-r",)),
    )

    # agent-a cannot reach agent-r, so agent-r's unknown neighbourhood cannot
    # be hiding a route from agent-a.
    assert (
        graph.reachability_of("agent-a", "bucket-y") is Reachability.NOT_REACHABLE
    )
    # ...but agent-q can, so the same graph still answers UNKNOWN there.
    assert graph.reachability_of("agent-q", "bucket-y") is Reachability.UNKNOWN


def test_an_agent_with_no_edges_at_all_in_a_partial_graph_is_unknown():
    """The literal shape of an unscanned account: an agent with nothing.

    This is what a dashboard would render as a clean, isolated agent.
    """
    graph = _graph(
        coverage=GraphCoverage(
            unscanned=(UnscannedScope(scope="acct-4", reason="no credential"),)
        )
    )

    assert graph.reachability_of("agent-z", "bucket-x") is Reachability.UNKNOWN


def test_partial_coverage_cannot_downgrade_a_path_that_was_actually_found():
    """Partial coverage cannot INVENT a path, so a positive answer needs no
    caveat. Making everything UNKNOWN under partial coverage would destroy the
    graph's usefulness in exactly the messy conditions it is for.
    """
    graph = _graph(
        _edge("agent-a", "bucket-x"),
        coverage=GraphCoverage(
            unscanned=(UnscannedScope(scope="acct-4", reason="AccessDenied"),),
            partially_known=("agent-b",),
        ),
    )

    assert graph.reachability_of("agent-a", "bucket-x") is Reachability.REACHABLE


def test_the_module_offers_no_isolation_boolean():
    """A boolean cannot carry the third case, and every caller would collapse
    it. Enforced rather than left to review, because `is_isolated` is exactly
    the convenience somebody adds in a hurry.
    """
    graph = _graph(_edge("a", "b"))

    for forbidden in ("is_isolated", "isolated", "is_reachable", "can_reach"):
        assert not hasattr(graph, forbidden), (
            f"{forbidden} would collapse Reachability.UNKNOWN into a lie"
        )


def test_coverage_is_required_to_build_a_graph():
    with pytest.raises(TypeError) as raised:
        build_exposure_graph(
            tenant="acme", edges=(), coverage=None  # type: ignore[arg-type]
        )
    assert "isolated" in str(raised.value)


def test_coverage_is_the_first_key_a_reader_meets():
    graph = _graph(_edge("a", "b"))
    document = graph.as_dict()

    assert next(iter(document)) == "coverage"
    assert "nothing looked" in document["limits"]
    assert "is_isolated" in document["limits"], (
        "the limits must say the boolean is absent, or a caller assumes it "
        "exists and reaches for a truthiness check on the enum"
    )


# ── the edge nobody granted ──────────────────────────────────────────────────


def test_two_agents_on_one_credential_reach_each_other():
    """No permission table records this.

    Two agents holding one key can each act as the other as far as every
    downstream system is concerned. If this graph did not derive the edge,
    nothing in the product would ever show it.
    """
    graph = _graph(
        _edge("agent-a", "cred-1", NodeKind.CREDENTIAL),
        _edge("agent-b", "cred-1", NodeKind.CREDENTIAL),
    )

    assert graph.reachability_of("agent-a", "agent-b") is Reachability.REACHABLE
    path = graph.shortest_path("agent-a", "agent-b")
    assert path is not None
    assert path.crosses_shared_credential


def test_a_credential_held_by_one_agent_derives_no_edge():
    """The guard must discriminate, or it fires on every credential and gets
    filtered out of every report within a week.
    """
    graph = _graph(_edge("agent-a", "cred-1", NodeKind.CREDENTIAL))

    assert not any(
        e.basis is EdgeBasis.SHARED_CREDENTIAL for e in graph.edges
    )


def test_who_shares_a_credential_is_directly_answerable():
    """The question asked first when a key leaks."""
    graph = _graph(
        _edge("agent-a", "cred-1", NodeKind.CREDENTIAL),
        _edge("agent-b", "cred-1", NodeKind.CREDENTIAL),
        _edge("agent-c", "cred-2", NodeKind.CREDENTIAL),
    )

    assert graph.principals_sharing("cred-1") == ("agent-a", "agent-b")
    assert graph.principals_sharing("cred-2") == ("agent-c",)


def test_a_shared_credential_extends_the_blast_radius():
    """agent-a was never granted bucket-x. It shares a key with something that
    reaches it, which is the whole point of computing this.
    """
    graph = _graph(
        _edge("agent-a", "cred-1", NodeKind.CREDENTIAL),
        _edge("agent-b", "cred-1", NodeKind.CREDENTIAL),
        _edge("agent-b", "bucket-x"),
    )

    assert "bucket-x" in graph.blast_radius_of("agent-a")


def test_derivation_can_be_switched_off_without_changing_other_edges():
    supplied = (
        _edge("agent-a", "cred-1", NodeKind.CREDENTIAL),
        _edge("agent-b", "cred-1", NodeKind.CREDENTIAL),
    )
    with_derivation = _graph(*supplied)
    without = _graph(*supplied, derive_shared_credentials=False)

    assert len(with_derivation.edges) == 4
    assert len(without.edges) == 2


# ── paths and their worth ────────────────────────────────────────────────────


def test_a_path_is_only_as_good_as_its_weakest_hop():
    """Three grants and one stale table entry is a hypothesis, not a route.

    A path object reporting only its length could not tell the difference.
    """
    graph = _graph(
        _edge("a", "b", basis=EdgeBasis.OBSERVED),
        _edge("b", "c", basis=EdgeBasis.GRANTED),
    )
    path = graph.shortest_path("a", "c")

    assert path is not None
    assert path.weakest_basis is EdgeBasis.GRANTED


def test_an_observation_outranks_a_grant_as_evidence():
    """A grant asserts what COULD happen; an observation records what did."""
    graph = _graph(
        _edge("a", "b", basis=EdgeBasis.OBSERVED),
        _edge("b", "c", basis=EdgeBasis.OBSERVED),
    )
    path = graph.shortest_path("a", "c")

    assert path is not None
    assert path.weakest_basis is EdgeBasis.OBSERVED


def test_the_shortest_route_is_the_one_returned():
    graph = _graph(
        _edge("a", "b"),
        _edge("b", "target"),
        _edge("a", "c"),
        _edge("c", "d"),
        _edge("d", "target"),
    )
    path = graph.shortest_path("a", "target")

    assert path is not None
    assert path.hops == 2


def test_a_cycle_does_not_hang_the_traversal():
    """A shared credential routinely creates one."""
    graph = _graph(_edge("a", "b"), _edge("b", "c"), _edge("c", "a"))

    assert graph.shortest_path("a", "c") is not None
    assert graph.reachability_of("a", "unrelated") is Reachability.NOT_REACHABLE


def test_a_route_longer_than_the_hop_limit_is_not_reported_as_absent():
    """Truncation must not masquerade as isolation.

    A chain of twelve hops exceeds the ceiling. The honest answer is that the
    traversal stopped looking, and with full coverage the graph would otherwise
    assert NOT_REACHABLE about a route that exists.
    """
    chain = tuple(_edge(f"n{i}", f"n{i + 1}") for i in range(12))
    graph = _graph(*chain)

    assert graph.shortest_path("n0", "n12") is None
    assert graph.reachability_of("n0", "n5") is Reachability.REACHABLE


def test_a_node_reaches_itself_in_zero_hops():
    graph = _graph(_edge("a", "b"))
    path = graph.shortest_path("a", "a")

    assert path is not None
    assert path.hops == 0
    assert path.nodes == ("a",)


def test_a_path_records_every_node_it_passed_through():
    """An operator has to explain the route to somebody, not just its length."""
    graph = _graph(_edge("a", "b"), _edge("b", "c"))
    path = graph.shortest_path("a", "c")

    assert path is not None
    assert path.nodes == ("a", "b", "c")


# ── structural refusals ──────────────────────────────────────────────────────


def test_a_self_loop_is_refused():
    """It makes every reachability answer trivially true and inflates every
    path length by one.
    """
    with pytest.raises(ValueError) as raised:
        _edge("a", "a")
    assert "itself" in str(raised.value)


def test_an_edge_with_an_empty_endpoint_is_refused():
    with pytest.raises(ValueError):
        _edge("", "b")
    with pytest.raises(ValueError):
        _edge("a", "  ")


def test_a_graph_with_no_tenant_is_refused():
    with pytest.raises(ValueError) as raised:
        build_exposure_graph(tenant=" ", edges=(), coverage=FULL)
    assert "tenant" in str(raised.value)


def test_a_zero_occurrence_granted_edge_is_kept_not_dropped():
    """A grant nothing exercised is the least-privilege finding itself.

    Dropping it as "no data" would delete the signal.
    """
    graph = _graph(_edge("a", "b", basis=EdgeBasis.GRANTED, occurrences=0))

    assert len(graph.edges) == 1
    assert graph.edges[0].occurrences == 0


# ── determinism ──────────────────────────────────────────────────────────────


def test_two_builds_over_the_same_estate_produce_identical_documents():
    """Or every diff between two incident snapshots is noise."""
    edges = (
        _edge("z", "y"),
        _edge("a", "b"),
        _edge("m", "n"),
    )
    first = _graph(*edges)
    second = _graph(*tuple(reversed(edges)))

    assert first.as_dict() == second.as_dict()


def test_a_duplicate_edge_is_recorded_once():
    graph = _graph(_edge("a", "b"), _edge("a", "b"))

    assert len(graph.edges) == 1


def test_the_same_pair_with_two_bases_stays_two_edges():
    """A granted edge and an observed edge between the same pair are different
    facts: one says it was allowed, the other says it happened.
    """
    graph = _graph(
        _edge("a", "b", basis=EdgeBasis.GRANTED),
        _edge("a", "b", basis=EdgeBasis.OBSERVED),
    )

    assert len(graph.edges) == 2


def test_the_graph_is_frozen_so_two_investigations_cannot_collide():
    graph = _graph(_edge("a", "b"))

    with pytest.raises(Exception):
        graph.edges = ()  # type: ignore[misc]


def test_node_kinds_are_exposed_as_a_read_only_mapping():
    import types

    graph = _graph(_edge("a", "cred-1", NodeKind.CREDENTIAL))

    assert isinstance(graph.node_kinds, types.MappingProxyType)
    assert graph.kind_of("cred-1") is NodeKind.CREDENTIAL


def test_the_document_contains_no_floats():
    """The canonical JSON form refuses floats, so one here would be found at
    signing time rather than now.
    """

    def walk(value, path="root"):
        if isinstance(value, float):
            raise AssertionError(f"float at {path}")
        if isinstance(value, dict):
            for key, item in value.items():
                walk(item, f"{path}.{key}")
        elif isinstance(value, (list, tuple)):
            for index, item in enumerate(value):
                walk(item, f"{path}[{index}]")

    graph = _graph(
        _edge("a", "cred-1", NodeKind.CREDENTIAL, occurrences=4),
        _edge("b", "cred-1", NodeKind.CREDENTIAL),
    )
    walk(graph.as_dict())
    path = graph.shortest_path("a", "b")
    assert path is not None
    walk(path.as_dict())


def test_the_module_holds_no_mutable_state():
    import types

    from sentinel.domain import exposure_graph

    mutable = [
        name
        for name, value in vars(exposure_graph).items()
        if not name.startswith("__")
        and isinstance(value, (dict, list, set))
        and not isinstance(value, types.MappingProxyType)
    ]
    assert not mutable, f"module-level mutable state: {mutable}"
