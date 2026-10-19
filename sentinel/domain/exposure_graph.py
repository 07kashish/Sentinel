"""One graph over agents, credentials, tools and assets -- with its own blind spots.

WHAT THIS UNIFIES, AND WHY IT HAD TO BE UNIFIED
-----------------------------------------------
Four modules each answer part of one question. `inventory` knows which agents
exist and what they were seen doing. `effective_permissions` knows what a grant
transitively confers. `blast_radius` knows which assets matter. `ai_bom` knows
which models and servers are in play. An operator during an incident does not
have four questions; they have one:

    "This credential leaked. What can reach what, and how bad is it?"

Answering it from four separate reports means a human doing the join under
pressure, at three in the morning, and the join is where the mistake happens.

THE FAILURE MODE THIS MODULE IS BUILT AROUND
--------------------------------------------
A graph makes absence look like a fact.

If nothing scanned an AWS account, that account's agents have no edges. On
every screen, "no edges" renders exactly like "isolated" -- and isolated is
the single most reassuring thing a graph can say. So `reachability_of` returns
a THREE-valued verdict and `UNKNOWN` is a real member: an agent in unscanned
territory is reported as unknown, never as isolated. There is deliberately no
`is_isolated` boolean anywhere in this module, because a boolean cannot carry
the third case and every caller would collapse it.

This is the same defect class as an empty inventory reading as a clean estate,
which is why it gets the same treatment: coverage is a required argument, and
the optimistic answer is unreachable without it.

EDGES CARRY WHY THEY EXIST
--------------------------
`GRANTED` came from a grant table. `OBSERVED` was seen in traffic. `DELEGATED`
came from a delegation chain. `SHARED_CREDENTIAL` is the one nobody granted --
two agents on one key reach each other's world, and that edge appears in no
permission system's UI. Keeping them distinct matters because they fail
differently: a stale grant table produces phantom `GRANTED` edges, while a
missing `OBSERVED` edge means only that nothing watched.

WHAT THIS IS NOT
----------------
Not a store, not a renderer, not a traversal service. A pure structure and the
queries an incident actually asks, so "could this agent have reached that
bucket" is answerable by reading one file and running its tests.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence

__all__ = [
    "EdgeBasis",
    "ExposureEdge",
    "ExposureGraph",
    "ExposurePath",
    "GraphCoverage",
    "NodeKind",
    "Reachability",
    "UnscannedScope",
    "build_exposure_graph",
]


class NodeKind(str, Enum):
    """The things an exposure question is asked about.

    Closed, and smaller than the asset vocabulary on purpose: this graph
    answers reachability, and a node type nothing can traverse to or from
    would be decoration that makes every path look longer than it is.
    """

    AGENT = "agent"
    CREDENTIAL = "credential"
    TOOL = "tool"
    MCP_SERVER = "mcp_server"
    RESOURCE = "resource"
    DESTINATION = "destination"


class EdgeBasis(str, Enum):
    """Why this edge is believed to exist.

    They fail in opposite directions, which is why they are never merged. A
    stale grant table invents `GRANTED` edges that do not exist; an unwatched
    period removes `OBSERVED` edges that do. Treating the two as one kind of
    evidence means neither failure is diagnosable.
    """

    #: A grant table says so.
    GRANTED = "granted"
    #: Traffic was seen doing it.
    OBSERVED = "observed"
    #: A delegation chain confers it, with no grant row of its own.
    DELEGATED = "delegated"
    #: Two principals share one credential, so each reaches the other's world.
    #: NOBODY GRANTED THIS and it appears in no permission system's UI.
    SHARED_CREDENTIAL = "shared_credential"


class Reachability(str, Enum):
    """Can A reach B?

    THREE VALUES, AND THE THIRD IS THE POINT. An agent in an unscanned scope
    has no edges, and "no edges" renders identically to "isolated" on every
    screen while meaning the opposite. A boolean cannot carry that, so this
    module offers no boolean -- see the module docstring.
    """

    REACHABLE = "reachable"
    #: Scanned, and genuinely no path exists.
    NOT_REACHABLE = "not_reachable"
    #: Nothing looked. The absence of a path is not evidence here.
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class UnscannedScope:
    """Somewhere the graph has no information about, and why.

    `reason` is required. "acct-4 returned AccessDenied" is actionable;
    "coverage partial" is a shrug wearing a data structure.
    """

    scope: str
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {"scope": self.scope, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class GraphCoverage:
    """What was looked at, so a missing edge can be interpreted.

    A REQUIRED argument to `build_exposure_graph`. A graph without it cannot
    distinguish "isolated" from "unobserved", and that distinction is the only
    reason this module is more than a dictionary of lists.
    """

    #: Scopes actually examined: accounts, namespaces, clusters.
    scanned: tuple[str, ...] = ()
    unscanned: tuple[UnscannedScope, ...] = ()
    #: Nodes named by an edge but never themselves examined. A path THROUGH one
    #: of these is real -- something was seen using it -- but paths BEYOND it
    #: are unknown rather than absent.
    partially_known: tuple[str, ...] = ()
    observed_from: str = ""
    observed_to: str = ""

    @property
    def is_partial(self) -> bool:
        return bool(self.unscanned) or bool(self.partially_known)

    def covers(self, node: str) -> bool:
        """Was this node's neighbourhood actually enumerated?

        A node reached only by being named in somebody else's edge is NOT
        covered: the graph knows it exists and knows nothing about what it
        reaches, which is precisely the case that must not read as isolated.
        """
        return node not in self.partially_known

    def as_dict(self) -> dict[str, Any]:
        return {
            "scanned": list(self.scanned),
            "unscanned": [u.as_dict() for u in self.unscanned],
            "partially_known": list(self.partially_known),
            "observed_from": self.observed_from,
            "observed_to": self.observed_to,
            "is_partial": self.is_partial,
        }


@dataclass(frozen=True, slots=True)
class ExposureEdge:
    """One directed relationship, with its basis and its weight."""

    source: str
    target: str
    target_kind: NodeKind
    basis: EdgeBasis
    #: How many times it was seen. Zero for a `GRANTED` edge nothing exercised
    #: -- which is itself the least-privilege finding, not missing data.
    occurrences: int = 0
    last_seen: str = ""

    def __post_init__(self) -> None:
        if not self.source.strip() or not self.target.strip():
            raise ValueError(
                "an edge with an empty endpoint cannot be traversed or "
                "explained; refusing to record one"
            )
        if self.source == self.target:
            raise ValueError(
                f"{self.source!r} cannot be an edge to itself. A self-loop "
                "makes every reachability answer trivially true and inflates "
                "every path length by one."
            )

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "target_kind": self.target_kind.value,
            "basis": self.basis.value,
            "occurrences": self.occurrences,
            "last_seen": self.last_seen,
        }


@dataclass(frozen=True, slots=True)
class ExposurePath:
    """A route from one node to another, and what makes each hop believable.

    `weakest_basis` is carried because a path is only as trustworthy as its
    least trustworthy hop. A four-hop route that is `GRANTED, GRANTED,
    GRANTED, OBSERVED` is a real route; one that is three grants and a stale
    table entry is a hypothesis, and a path object that reported only its
    length could not tell them apart.
    """

    nodes: tuple[str, ...]
    edges: tuple[ExposureEdge, ...]

    @property
    def hops(self) -> int:
        return len(self.edges)

    @property
    def weakest_basis(self) -> EdgeBasis:
        """The least-corroborated hop, which is what the path is worth.

        `GRANTED` ranks weakest deliberately: a grant table is an assertion
        about what COULD happen, while an observation is a record of what did.
        """
        if not self.edges:
            return EdgeBasis.OBSERVED
        return min(self.edges, key=lambda e: _BASIS_STRENGTH[e.basis]).basis

    @property
    def crosses_shared_credential(self) -> bool:
        """Does this route pass through a key two principals hold?

        Surfaced separately because it is the hop nobody granted and no
        permission system's UI displays, so it is the hop an operator has not
        already considered.
        """
        return any(
            edge.basis is EdgeBasis.SHARED_CREDENTIAL for edge in self.edges
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "nodes": list(self.nodes),
            "hops": self.hops,
            "weakest_basis": self.weakest_basis.value,
            "crosses_shared_credential": self.crosses_shared_credential,
            "edges": [e.as_dict() for e in self.edges],
        }


#: How much a basis is worth as evidence. An observation is a record of what
#: happened; a grant is an assertion about what could. MappingProxyType because
#: `Mapping` is an annotation and annotations enforce nothing at runtime.
_BASIS_STRENGTH: Mapping[EdgeBasis, int] = MappingProxyType(
    {
        EdgeBasis.GRANTED: 0,
        EdgeBasis.DELEGATED: 1,
        EdgeBasis.SHARED_CREDENTIAL: 2,
        EdgeBasis.OBSERVED: 3,
    }
)

#: Traversal ceiling. A graph with a wide shared credential can otherwise walk
#: the entire estate, and a path of forty hops is not a finding anybody acts
#: on. Reaching the limit is REPORTED rather than silently truncated -- see
#: `Reachability.UNKNOWN` in `reachability_of`.
_MAX_HOPS = 8


@dataclass(frozen=True, slots=True)
class ExposureGraph:
    """The estate as one directed graph, with coverage attached.

    Frozen. Queries return new objects and nothing mutates the graph, so two
    concurrent incident investigations cannot alter each other's picture.
    """

    tenant: str
    edges: tuple[ExposureEdge, ...]
    coverage: GraphCoverage
    node_kinds: Mapping[str, NodeKind] = field(default_factory=dict)

    limits: str = field(
        default=(
            "A missing edge means one of two things: nothing connects these, or "
            "nothing looked. Read `coverage` before reading any absence. This "
            "module offers no `is_isolated` -- ask `reachability_of`, which can "
            "answer UNKNOWN, because a boolean would force the caller to guess."
        ),
        compare=False,
    )

    def __post_init__(self) -> None:
        if not isinstance(self.coverage, GraphCoverage):
            raise TypeError(
                "a graph without coverage cannot distinguish an isolated node "
                "from an unobserved one, and 'isolated' is the most reassuring "
                "thing a graph can say"
            )

    @property
    def nodes(self) -> tuple[str, ...]:
        seen: set[str] = set()
        for edge in self.edges:
            seen.add(edge.source)
            seen.add(edge.target)
        return tuple(sorted(seen))

    def kind_of(self, node: str) -> NodeKind:
        return self.node_kinds.get(node, NodeKind.RESOURCE)

    def _adjacency(self) -> Mapping[str, tuple[ExposureEdge, ...]]:
        out: dict[str, list[ExposureEdge]] = {}
        for edge in self.edges:
            out.setdefault(edge.source, []).append(edge)
        return MappingProxyType(
            {source: tuple(items) for source, items in out.items()}
        )

    def neighbours_of(self, node: str) -> tuple[ExposureEdge, ...]:
        return tuple(e for e in self.edges if e.source == node)

    def shortest_path(self, source: str, target: str) -> ExposurePath | None:
        """The fewest-hop route, or None if none was found within the limit.

        None means "not found", NOT "does not exist" -- the distinction is
        `reachability_of`'s job, because it is the one that reads coverage.
        Callers wanting a verdict must ask that instead, and this method's
        return type is deliberately not a boolean so the difference is hard to
        ignore.
        """
        if source == target:
            return ExposurePath(nodes=(source,), edges=())

        adjacency = self._adjacency()
        # BFS: fewest hops, and a visited set so a shared credential that
        # creates a cycle cannot loop forever.
        queue: deque[tuple[str, tuple[ExposureEdge, ...]]] = deque([(source, ())])
        visited = {source}

        while queue:
            node, trail = queue.popleft()
            if len(trail) >= _MAX_HOPS:
                continue
            for edge in adjacency.get(node, ()):
                if edge.target in visited:
                    continue
                extended = trail + (edge,)
                if edge.target == target:
                    return ExposurePath(
                        nodes=(source,) + tuple(e.target for e in extended),
                        edges=extended,
                    )
                visited.add(edge.target)
                queue.append((edge.target, extended))

        return None

    def reachability_of(self, source: str, target: str) -> Reachability:
        """Three-valued. THE function this module exists for.

        `NOT_REACHABLE` is asserted only when the graph actually looked at
        everywhere a path could have come from. If coverage is partial in any
        way that could hide a route, the answer is `UNKNOWN` -- because
        reporting an unscanned agent as isolated is how a graph provides
        false comfort during the one hour it matters.
        """
        if self.shortest_path(source, target) is not None:
            # A found path is a found path. Partial coverage cannot invent one,
            # so a positive answer needs no coverage caveat.
            return Reachability.REACHABLE

        if not self.coverage.covers(source):
            # The source's own neighbourhood was never enumerated, so nothing
            # is known about what it reaches -- including whether it reaches
            # this target directly.
            return Reachability.UNKNOWN
        if self.coverage.unscanned:
            # A route could run through territory nobody scanned. This cannot
            # be narrowed the way the frontier check below is: an unscanned
            # scope has no nodes in the graph at all, so there is nothing to
            # test for reachability.
            return Reachability.UNKNOWN

        # A node the graph knows only by name can hide a route ONLY IF the
        # source can reach it. Asking about the frontier rather than about the
        # whole coverage record is what makes this answer worth reading: the
        # blanket version returned UNKNOWN for every question in the graph as
        # soon as one node anywhere was unenumerated, and a verdict that is
        # always UNKNOWN trains operators to ignore it.
        frontier = set(self.blast_radius_of(source))
        if any(node in frontier for node in self.coverage.partially_known):
            return Reachability.UNKNOWN

        return Reachability.NOT_REACHABLE

    def blast_radius_of(self, source: str) -> tuple[str, ...]:
        """Everything reachable from one node, for scoping a leaked credential.

        Nodes only, deliberately: the paths are available through
        `shortest_path`, and returning both invites a reader to treat the set
        as complete when coverage says otherwise.
        """
        adjacency = self._adjacency()
        reached: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(source, 0)])
        seen = {source}

        while queue:
            node, depth = queue.popleft()
            if depth >= _MAX_HOPS:
                continue
            for edge in adjacency.get(node, ()):
                if edge.target in seen:
                    continue
                seen.add(edge.target)
                reached.add(edge.target)
                queue.append((edge.target, depth + 1))

        return tuple(sorted(reached))

    def principals_sharing(self, credential: str) -> tuple[str, ...]:
        """Which agents' traffic arrived under one credential.

        The question asked first when a key leaks, and the one a permission
        system cannot answer: sharing is not a grant, so nothing in an IAM
        console lists it.
        """
        return tuple(
            sorted(
                {
                    edge.source
                    for edge in self.edges
                    if edge.target == credential
                    and edge.target_kind is NodeKind.CREDENTIAL
                }
            )
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            # Coverage first: a reader who stops early must not stop before the
            # line that says how to interpret an absence.
            "coverage": self.coverage.as_dict(),
            "tenant": self.tenant,
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "edges": [e.as_dict() for e in self.edges],
            "limits": self.limits,
        }


def _shared_credential_edges(
    edges: Sequence[ExposureEdge],
) -> tuple[ExposureEdge, ...]:
    """Derive agent-to-agent edges from credentials two agents both used.

    THE EDGE NOBODY GRANTED. Two agents on one key can each act as the other as
    far as every downstream system is concerned, and no permission table
    records it -- so if this graph did not derive it, nothing in the product
    would ever show it.

    Derived rather than stored so it cannot go stale relative to the
    credential edges it is computed from.
    """
    holders: dict[str, set[str]] = {}
    for edge in edges:
        if edge.target_kind is NodeKind.CREDENTIAL:
            holders.setdefault(edge.target, set()).add(edge.source)

    derived: list[ExposureEdge] = []
    for credential, principals in sorted(holders.items()):
        if len(principals) < 2:
            continue
        for source in sorted(principals):
            for target in sorted(principals):
                if source == target:
                    continue
                derived.append(
                    ExposureEdge(
                        source=source,
                        target=target,
                        target_kind=NodeKind.AGENT,
                        basis=EdgeBasis.SHARED_CREDENTIAL,
                        last_seen=credential,
                    )
                )
    return tuple(derived)


def build_exposure_graph(
    *,
    tenant: str,
    edges: Iterable[ExposureEdge],
    coverage: GraphCoverage,
    node_kinds: Mapping[str, NodeKind] | None = None,
    derive_shared_credentials: bool = True,
) -> ExposureGraph:
    """Assemble the graph. `coverage` is required, not optional.

    Requiring it is the whole design. A caller who has no coverage information
    must construct an explicitly empty `GraphCoverage`, at which point every
    absence in the resulting graph correctly reports `UNKNOWN` rather than
    quietly reporting isolation.
    """
    if not tenant.strip():
        raise ValueError(
            "an exposure graph with no tenant cannot be kept out of another "
            "tenant's incident review"
        )
    if not isinstance(coverage, GraphCoverage):
        raise TypeError(
            "coverage is required. Without it the graph cannot tell an "
            "isolated node from an unobserved one."
        )

    supplied = tuple(edges)
    derived = (
        _shared_credential_edges(supplied) if derive_shared_credentials else ()
    )

    # Deduplicate on identity, keeping the first occurrence, and order the
    # result so two builds over the same estate produce identical bytes.
    unique: dict[tuple[str, str, str], ExposureEdge] = {}
    for edge in supplied + derived:
        unique.setdefault(
            (edge.source, edge.target, edge.basis.value), edge
        )

    kinds: dict[str, NodeKind] = dict(node_kinds or {})
    for edge in unique.values():
        kinds.setdefault(edge.target, edge.target_kind)

    return ExposureGraph(
        tenant=tenant,
        edges=tuple(
            sorted(
                unique.values(),
                key=lambda e: (e.source, e.target, e.basis.value),
            )
        ),
        coverage=coverage,
        node_kinds=MappingProxyType(dict(sorted(kinds.items()))),
    )
