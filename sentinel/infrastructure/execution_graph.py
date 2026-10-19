"""Persisting execution nodes, and deriving baselines from what was persisted.

WHY THE BASELINE IS DERIVED, NOT ACCUMULATED
----------------------------------------------
A running baseline -- counters updated on every event -- would be cheaper, and
it would be a stored fact that drifts from the events it summarises. Worse, it
could not be recomputed: an operator who disagrees with "this agent has never
used that tool" would have no way to check, because the evidence would have been
folded into a number and discarded.

Deriving it from `execution_nodes` on read means the baseline is always exactly
what the retained history says, and any finding it produces can be re-derived by
somebody who wants to argue with it. That costs a scan per query, which is
acceptable for an operator-facing read and would not be on the ingest path --
which is precisely why nothing calls it from there.

THE COST OF THE HISTORY WINDOW
--------------------------------
Baselines are computed over whatever `execution_nodes` still holds, and the
retention sweep reaps that table on age. So a baseline silently narrows as
history ages out, and an agent that was busy six months ago looks new again.
`sessions_observed` is reported alongside every baseline so a reader can see how
much history is behind it rather than assuming the number covers all time.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from sentinel.domain.baseline import BehaviourBaseline
from sentinel.domain.execution_graph import (
    ExecutionGraph,
    ExecutionNode,
    GraphCoverage,
    NodeKind,
    order_nodes,
)
from sentinel.infrastructure.sql.engine import ConnectionPool

__all__ = [
    "SqlExecutionGraph",
    "MAX_SESSION_NODES",
    "PRIVILEGED_ACTIONS",
    "WORKFLOW_SIGNATURE_STEPS",
]

#: Canonical actions that touch credentials or privilege. A first-ever
#: privileged action is a different fact from a first-ever ordinary one, and
#: folding them together hides the one that matters.
PRIVILEGED_ACTIONS = frozenset(
    {"credential_access", "cloud_login", "privilege_change"}
)

#: How many opening steps make up a workflow signature. An agent's twentieth
#: step varies with whatever data it happened to get back; its opening moves
#: are what the agent is FOR, and a signature over the whole session would
#: make every run unique and the dimension useless.
WORKFLOW_SIGNATURE_STEPS = 5

#: Nodes returned for one session. A session with more steps than this is
#: truncated rather than refused, and the truncation is REPORTED -- a causal
#: trace that silently stops halfway tells a story that did not happen, which is
#: worse than one that says where it ran out.
MAX_SESSION_NODES = 1000


class SqlExecutionGraph:
    """Execution nodes: written on ingest, read for tracing and baselines."""

    __slots__ = ("_pool",)

    def __init__(self, *, pool: ConnectionPool) -> None:
        self._pool = pool

    # ── Write: the ingest path ───────────────────────────────────────────────

    def record(self, node: ExecutionNode) -> None:
        """Persist one step.

        Idempotent on `(tenant_id, event_id)`: an event redelivered by a retry
        must not appear twice in a causal trace, because a duplicated step turns
        one read into two and can push a session over a sequence rule's gap
        bound or a baseline's volume threshold. A replayed event would otherwise
        manufacture the very finding it should not.
        """
        if not node.event_id.strip() or not node.agent_id.strip():
            # No identity, no node. An event that cannot be referred to cannot
            # be a parent or a child, so storing it would add a step to the
            # story that nothing can ever link to.
            return

        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(node.tenant_id)
            p = conn.p
            conn.execute_rowcount(
                f"DELETE FROM execution_nodes WHERE tenant_id={p} AND event_id={p}",
                (node.tenant_id, node.event_id),
            )
            conn.execute_rowcount(
                f"INSERT INTO execution_nodes (tenant_id, event_id, session_id, "
                f"parent_id, agent_id, kind, occurred_at, action, resource, "
                f"destination, tool, credential, principal, policy, decision, "
                f"severity, incident_id, input_text, output_text, approval_id) "
                # TWENTY placeholders for twenty columns, one per line group of
                # five so they can be counted by eye. The first attempt was
                # hand-typed in one run and was short by one -- every event
                # failed with "19 values for 20 columns", caught only because
                # the fail-safe logs rather than swallows.
                #
                # A `",".join([p] * 20)` would be shorter and is exactly what
                # the SQL security rules refuse: a computed expression
                # interpolated into a statement. They cannot tell a safe join
                # from an unsafe one, and a rule with exceptions is not a rule.
                f"VALUES ({p},{p},{p},{p},{p},"
                f"{p},{p},{p},{p},{p},"
                f"{p},{p},{p},{p},{p},"
                f"{p},{p},{p},{p},{p})",
                (
                    node.tenant_id, node.event_id, node.session_id, node.parent_id,
                    node.agent_id, node.kind.value, node.occurred_at, node.action,
                    node.resource, node.destination, node.tool, node.credential,
                    node.principal, node.policy, node.decision, node.severity,
                    node.incident_id,
                    node.input_text,
                    node.output_text,
                    node.approval_id,
                ),
            )
            conn.commit()

    # ── Read: tracing ────────────────────────────────────────────────────────

    def _row_to_node(self, tenant_id: str, row: Mapping[str, Any]) -> ExecutionNode:
        try:
            kind = NodeKind(str(row["kind"]))
        except ValueError:
            # A kind this build does not know reads as OTHER rather than
            # raising. One unrecognised step must not make a whole trace
            # unavailable -- the investigation needs the other nine.
            kind = NodeKind.OTHER
        return ExecutionNode(
            tenant_id=tenant_id,
            event_id=str(row["event_id"]),
            agent_id=str(row["agent_id"]),
            session_id=str(row["session_id"] or ""),
            parent_id=str(row["parent_id"] or ""),
            kind=kind,
            occurred_at=str(row["occurred_at"] or ""),
            action=str(row["action"] or ""),
            resource=str(row["resource"] or ""),
            destination=str(row["destination"] or ""),
            tool=str(row["tool"] or ""),
            credential=str(row["credential"] or ""),
            principal=str(row["principal"] or ""),
            policy=str(row["policy"] or ""),
            decision=str(row["decision"] or ""),
            severity=int(row["severity"] or 0),
            incident_id=str(row["incident_id"] or ""),
            input_text=str(row["input_text"] or ""),
            output_text=str(row["output_text"] or ""),
            approval_id=str(row["approval_id"] or ""),
        )

    def session(self, tenant_id: str, session_id: str) -> ExecutionGraph:
        """One session's steps, in the order they happened."""
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            p = conn.p
            rows = conn.execute(
                f"SELECT * FROM execution_nodes WHERE tenant_id={p} AND session_id={p} "
                f"ORDER BY occurred_at, event_id",
                (tenant_id, session_id),
            )
            conn.commit()

        nodes = [self._row_to_node(tenant_id, r) for r in rows][:MAX_SESSION_NODES]
        return ExecutionGraph(
            tenant_id=tenant_id,
            session_id=session_id,
            nodes=order_nodes(nodes),
        )

    def sessions_for_agent(
        self, tenant_id: str, agent_id: str, *, limit: int = 100
    ) -> tuple[str, ...]:
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            p = conn.p
            rows = conn.execute(
                f"SELECT DISTINCT session_id FROM execution_nodes "
                f"WHERE tenant_id={p} AND agent_id={p} AND session_id<>'' "
                f"ORDER BY session_id",
                (tenant_id, agent_id),
            )
            conn.commit()
        return tuple(str(r["session_id"]) for r in rows)[:limit]

    def coverage(self, tenant_id: str) -> GraphCoverage:
        """How much of this tenant's activity is actually traceable.

        Reported because a graph over 3% of events looks identical to one over
        100% until somebody asks, and a causal trace assembled from a fraction
        of the steps is not a trace.
        """
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            p = conn.p
            total = conn.one(
                f"SELECT COUNT(*) AS n FROM execution_nodes WHERE tenant_id={p}",
                (tenant_id,),
            )
            linked = conn.one(
                f"SELECT COUNT(*) AS n FROM execution_nodes "
                f"WHERE tenant_id={p} AND session_id<>''",
                (tenant_id,),
            )
            sessions = conn.one(
                f"SELECT COUNT(DISTINCT session_id) AS n FROM execution_nodes "
                f"WHERE tenant_id={p} AND session_id<>''",
                (tenant_id,),
            )
            conn.commit()
        return GraphCoverage(
            total_nodes=int(total["n"] if total else 0),
            linked_nodes=int(linked["n"] if linked else 0),
            sessions=int(sessions["n"] if sessions else 0),
        )

    # ── Read: the baseline ───────────────────────────────────────────────────

    def baseline_for(
        self, tenant_id: str, agent_id: str, *, exclude_session: str = ""
    ) -> BehaviourBaseline:
        """Build this agent's baseline from its retained history.

        `exclude_session` matters more than it looks. Comparing a session
        against a baseline that INCLUDES that session guarantees nothing looks
        unusual: the anomalous tool is in the "usual tools" set because the
        anomalous session put it there. Every deviation would be silently
        absorbed by the thing meant to detect it -- a gate that cannot fire.
        """
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            p = conn.p
            if exclude_session:
                rows = conn.execute(
                    f"SELECT * FROM execution_nodes WHERE tenant_id={p} "
                    f"AND agent_id={p} AND session_id<>{p}",
                    (tenant_id, agent_id, exclude_session),
                )
            else:
                rows = conn.execute(
                    f"SELECT * FROM execution_nodes WHERE tenant_id={p} AND agent_id={p}",
                    (tenant_id, agent_id),
                )
            conn.commit()

        nodes = [self._row_to_node(tenant_id, r) for r in rows]
        return build_baseline(agent_id, nodes)


def build_baseline(agent_id: str, nodes: Sequence[ExecutionNode]) -> BehaviourBaseline:
    """Fold observed steps into a baseline. Pure, so it is testable without a database."""
    if not nodes:
        return BehaviourBaseline(agent_id=agent_id)

    per_session: dict[str, int] = {}
    hours: set[int] = set()
    for node in nodes:
        if node.session_id:
            per_session[node.session_id] = per_session.get(node.session_id, 0) + 1
        # Hour is parsed from the timestamp rather than stored separately: a
        # second copy of the same fact is a second thing to keep correct.
        stamp = node.occurred_at
        if len(stamp) >= 13 and stamp[10] in ("T", " "):
            try:
                hours.add(int(stamp[11:13]))
            except ValueError:
                pass

    # ── The five dimensions derived rather than stored ───────────────────────
    #
    # All from the same node rows already read, so none of these costs a second
    # query. Derived on read for the reason the whole baseline is: a stored
    # aggregate drifts from its evidence and cannot be recomputed by somebody
    # who wants to argue with it.
    from sentinel.domain.sequences import canonical_action

    sequences: dict[str, list[str]] = {}
    for node in nodes:
        if node.session_id and node.action:
            sequences.setdefault(node.session_id, []).append(
                canonical_action(node.action)
            )

    # A WORKFLOW is the ordered signature of a session's actions. Truncated to
    # the first few steps: an agent's twentieth step varies with the data it
    # happened to get, while its opening moves are what it is FOR.
    workflows = {
        " -> ".join(actions[:WORKFLOW_SIGNATURE_STEPS])
        for actions in sequences.values()
        if actions
    }

    # A QUERY PATTERN is (action, first path segment), not the resource itself.
    # An agent reading `tickets/1` through `tickets/900` has ONE pattern and nine
    # hundred resources; tracking only resources makes every ordinary day look
    # like a thousand new things and buries the one that matters.
    patterns = set()
    for node in nodes:
        if not node.action or not node.resource:
            continue
        head = node.resource.replace("\\", "/").split("/")[0].split("?")[0]
        patterns.add(f"{canonical_action(node.action)}:{head[:64]}")

    privileged = {
        canonical_action(node.action)
        for node in nodes
        if canonical_action(node.action) in PRIVILEGED_ACTIONS
    }

    # SPAWNED AGENTS: other agents seen in the same sessions. Delegation
    # OBSERVED rather than declared -- an agent cannot avoid appearing in a
    # session by not mentioning it, only by not being reported at all.
    own_sessions = {n.session_id for n in nodes if n.session_id}
    spawned = {
        n.agent_id
        for n in nodes
        if n.agent_id and n.agent_id != agent_id and n.session_id in own_sessions
    }

    counts = list(per_session.values())
    return BehaviourBaseline(
        agent_id=agent_id,
        sessions_observed=len(per_session),
        tools=frozenset(n.tool for n in nodes if n.tool),
        resources=frozenset(n.resource for n in nodes if n.resource),
        destinations=frozenset(n.destination for n in nodes if n.destination),
        credentials=frozenset(n.credential for n in nodes if n.credential),
        active_hours=frozenset(hours),
        users=frozenset(n.principal for n in nodes if n.principal),
        spawned_agents=frozenset(spawned),
        privileged_actions=frozenset(privileged),
        query_patterns=frozenset(patterns),
        workflows=frozenset(workflows),
        mean_steps_per_session=(sum(counts) / len(counts)) if counts else 0.0,
        max_steps_per_session=max(counts) if counts else 0,
    )
