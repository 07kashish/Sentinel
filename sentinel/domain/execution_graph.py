"""The agent execution graph: one security story, not a pile of events.

WHY EVENT-AT-A-TIME DETECTION IS NOT ENOUGH
---------------------------------------------
Every step in this chain is individually defensible:

    user asks for a quarterly report
      -> agent reads a document
      -> the document contains an injected instruction
      -> agent queries the CRM
      -> agent exports records
      -> agent uploads the export somewhere external

Reading a document is not an attack. Querying a CRM is the agent's job.
Exporting records is a feature. Uploading a file is a feature. A detector that
scores each event alone sees six ordinary actions and raises nothing -- and the
sequence is a data exfiltration that a human reading the trail would recognise
immediately.

The graph exists so that trail can be reconstructed and reasoned about as a
whole. `sequence detection must operate on the execution graph`, and intent
divergence compares what an agent SAID it would do against everything it then
DID -- neither question can be asked of an isolated event.

WHAT MAKES THE CHAIN POSSIBLE, AND WHAT IT COSTS
--------------------------------------------------
Three correlation fields: an event's own id, the session it belongs to, and the
parent it followed from. All three are SELF-REPORTED, and that is a real
limitation rather than a footnote:

  * A truthful agent produces an accurate graph.
  * A confused agent produces a wrong graph.
  * A hostile agent can draw whatever arrows it likes.

So the graph is EVIDENCE, never AUTHORITY. It orders and connects what was
reported; it does not prove what happened. Nothing in the enforcement path
consults it, for the same reason the trust score does not: a control an attacker
can shape by lying is not a control.

What it cannot be lied about is absence. An agent that omits a step does not
erase the step's effects, and the events it does send still carry actions,
resources and destinations that the baseline and sequence rules read directly.

NO SESSION MEANS NO CHAIN, DELIBERATELY
-----------------------------------------
An event without a session id is recorded as an unlinked node rather than being
guessed into a story by time proximity. Two agents working concurrently, or one
agent handling two requests, would be merged by any time-window heuristic -- and
a fabricated causal link is worse than a missing one, because it invents a
security story that did not happen. `ExecutionGraph.coverage` reports how many
nodes are unlinked so an operator can see how much of their estate is actually
traceable rather than assuming all of it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterator, Mapping, Sequence

#: Cap on the instruction and result text a node stores.
#:
#: Attacker-supplied text that ends up in an API response, a CLI table and
#: every trace an analyst opens. Enough to see what the instruction SAID --
#: an injection announces itself in its first line -- without letting one
#: event carry a megabyte into every read of the session.
MAX_NODE_TEXT: int = 2048

__all__ = [
    "MAX_NODE_TEXT",
    "ExecutionNode",
    "ExecutionGraph",
    "GraphCoverage",
    "NodeKind",
]


class NodeKind(str, Enum):
    """What a node in the chain represents.

    Derived from the event's own type rather than invented, so a node cannot
    claim to be something the event never said it was.
    """

    #: A request from a human, delegated to an agent.
    REQUEST = "request"
    #: The agent invoking a tool.
    TOOL_CALL = "tool_call"
    #: A prompt the agent processed.
    PROMPT = "prompt"
    #: An agent spawning or delegating to another agent.
    DELEGATION = "delegation"
    #: Anything else the pipeline admitted. Kept rather than dropped: an
    #: unrecognised step is still part of the story, and silently omitting it
    #: would leave a gap that reads as "nothing happened".
    OTHER = "other"

    @classmethod
    def of(cls, event_type: str) -> "NodeKind":
        mapping = {
            "request": cls.REQUEST,
            "user_request": cls.REQUEST,
            "tool_call": cls.TOOL_CALL,
            "prompt": cls.PROMPT,
            "delegation": cls.DELEGATION,
            "sub_agent": cls.DELEGATION,
        }
        return mapping.get((event_type or "").strip().lower(), cls.OTHER)


@dataclass(frozen=True, slots=True)
class ExecutionNode:
    """One step, carrying everything the specification asks a node to preserve.

    Flat rather than nested. A node is read during an investigation, often
    quickly, and a shape that requires walking into sub-objects to answer "what
    did this touch" costs time exactly when there is none.
    """

    tenant_id: str
    event_id: str
    agent_id: str
    session_id: str = ""
    parent_id: str = ""
    kind: NodeKind = NodeKind.OTHER
    occurred_at: str = ""
    #: What the step did and to what.
    action: str = ""
    resource: str = ""
    destination: str = ""
    tool: str = ""
    #: Who it presented as. A fingerprint, never key material.
    credential: str = ""
    principal: str = ""
    #: What Sentinel decided about it.
    policy: str = ""
    decision: str = ""
    severity: int = 0
    incident_id: str = ""
    #: The prompt or instruction text the step carried. THE field that makes
    #: "the document contained an injected instruction" visible as a step rather
    #: than as an unexplained turn in the story -- without it, a reader sees the
    #: agent change behaviour and cannot see why.
    #:
    #: Truncated, because it is attacker-supplied text that ends up in an API
    #: response and a CLI table.
    input_text: str = ""
    #: What the step returned. The other half of "what happened here": a read
    #: whose OUTPUT contained an instruction is the indirect-injection case, and
    #: an input-only node cannot show it.
    output_text: str = ""
    #: The approval that authorised this step, if a human authorised one. The
    #: first question an auditor asks about an executed action, and previously
    #: answerable only by joining through an incident that might not exist.
    approval_id: str = ""

    @property
    def is_linked(self) -> bool:
        return bool(self.session_id)

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "parent_id": self.parent_id,
            "kind": self.kind.value,
            "occurred_at": self.occurred_at,
            "action": self.action,
            "resource": self.resource,
            "destination": self.destination,
            "tool": self.tool,
            "credential": self.credential,
            "principal": self.principal,
            "policy": self.policy,
            "decision": self.decision,
            "severity": self.severity,
            "incident_id": self.incident_id,
            "input_text": self.input_text,
            "output_text": self.output_text,
            "approval_id": self.approval_id,
        }


@dataclass(frozen=True, slots=True)
class GraphCoverage:
    """How much of a tenant's activity is actually traceable.

    Reported because an execution graph over 3% of events looks identical to one
    over 100% until somebody asks. A story assembled from a fraction of the
    steps is not a story, and an operator deciding whether to trust a causal
    trace needs to know which they are looking at.
    """

    total_nodes: int = 0
    linked_nodes: int = 0
    sessions: int = 0

    @property
    def linked_fraction(self) -> float:
        if not self.total_nodes:
            return 0.0
        return self.linked_nodes / self.total_nodes

    def as_dict(self) -> dict[str, Any]:
        return {
            "total_nodes": self.total_nodes,
            "linked_nodes": self.linked_nodes,
            "unlinked_nodes": self.total_nodes - self.linked_nodes,
            "sessions": self.sessions,
            "linked_fraction": round(self.linked_fraction, 4),
        }


@dataclass(frozen=True, slots=True)
class ExecutionGraph:
    """One session's nodes, ordered, with the parent links they declared.

    A session rather than a whole tenant: the unit an investigation works in is
    "what happened during this piece of work", and a graph spanning every agent
    for a month answers no question anybody asks.
    """

    tenant_id: str
    session_id: str
    nodes: tuple[ExecutionNode, ...] = ()

    def __iter__(self) -> Iterator[ExecutionNode]:
        return iter(self.nodes)

    def __len__(self) -> int:
        return len(self.nodes)

    @property
    def agents(self) -> tuple[str, ...]:
        """Every agent that took part. More than one means delegation."""
        return tuple(sorted({n.agent_id for n in self.nodes if n.agent_id}))

    def by_id(self) -> Mapping[str, ExecutionNode]:
        return {n.event_id: n for n in self.nodes}

    def path_to(self, event_id: str) -> tuple[ExecutionNode, ...]:
        """The causal path from the root down to one node.

        Walks parent links upward and reverses, so the result reads in the order
        things happened -- which is how a person tells the story, and the
        opposite of how the pointers run.

        A cycle terminates the walk rather than hanging. Parent ids are
        self-reported, so an agent CAN report a loop, whether by confusion or on
        purpose, and a traversal that trusted them would be a denial of service
        reachable from one malformed event.
        """
        index = self.by_id()
        seen: set[str] = set()
        path: list[ExecutionNode] = []

        current = index.get(event_id)
        while current is not None and current.event_id not in seen:
            seen.add(current.event_id)
            path.append(current)
            current = index.get(current.parent_id) if current.parent_id else None

        return tuple(reversed(path))

    def roots(self) -> tuple[ExecutionNode, ...]:
        """Nodes with no parent inside this session.

        A node whose declared parent is absent counts as a root: the parent may
        have been dropped, never sent, or belong to another session, and
        pretending the link exists would draw an arrow to nothing.
        """
        index = self.by_id()
        return tuple(n for n in self.nodes if not n.parent_id or n.parent_id not in index)

    def action_sequence(self) -> tuple[str, ...]:
        """Actions in the order they occurred. What sequence rules match on."""
        return tuple(n.action for n in self.nodes if n.action)

    def as_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "session_id": self.session_id,
            "agents": list(self.agents),
            "node_count": len(self.nodes),
            "nodes": [n.as_dict() for n in self.nodes],
        }


def order_nodes(nodes: Sequence[ExecutionNode]) -> tuple[ExecutionNode, ...]:
    """Order by time, then by event id as a tiebreaker.

    The tiebreaker is not cosmetic. Two events in the same millisecond -- common
    when an agent fires tool calls in a loop -- would otherwise order
    differently on each read, and a sequence rule matching `A -> B` would fire
    intermittently on the same data. A detector whose result depends on retrieval
    order is not a detector.
    """
    return tuple(sorted(nodes, key=lambda n: (n.occurred_at, n.event_id)))
