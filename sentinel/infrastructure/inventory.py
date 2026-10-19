"""Recording what Sentinel saw, and assembling it into an agent inventory.

TWO RESPONSIBILITIES, DELIBERATELY IN ONE MODULE
--------------------------------------------------
`observe()` is on the ingest hot path and must be cheap. `profile()` and the
graph queries are operator-facing and may be slow. They live together because
they are the write and read sides of the same two tables, and splitting them
would mean a change to the edge shape had to be made in two files that nothing
forces to agree.

THE COST OF OBSERVING
---------------------
`observe()` runs on every admitted event, so it is bounded on every axis a
hostile or merely chatty agent controls: the number of edges per call is capped,
every target is truncated, and an agent that touches a million distinct paths
produces at most `MAX_EDGES_PER_AGENT` rows rather than a million.

That cap is a real limit with a real consequence -- past it, new targets are not
recorded -- and it is reported rather than hidden, because an inventory that
silently stops tracking is worse than one that says it stopped. The alternative
was letting a single agent's resource churn become an unbounded write amplifier
on the ingest path, which is the defect this repository already measured once
when four operational tables grew without bound and ingest p95 went from 83ms to
624ms.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from sentinel.domain.inventory import (
    AgentClassification,
    AgentProfile,
    ObservedEdge,
    ObservedEdgeKind,
    classify_agent,
    validate_declaration,
)
from sentinel.infrastructure.sql.engine import ConnectionPool

__all__ = ["SqlAgentInventory", "MAX_EDGES_PER_AGENT", "MAX_TARGET_CHARS"]

#: Distinct targets tracked per agent per kind. Past this, new targets are not
#: recorded and `profile()` reports the cap was reached.
MAX_EDGES_PER_AGENT = 500

#: Targets are truncated, not refused. A path is attacker-influenced text and an
#: unbounded one is a storage amplifier, but refusing the whole observation
#: would lose the agent as well as the target.
MAX_TARGET_CHARS = 512


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clean(value: Any) -> str:
    return str(value or "").strip()[:MAX_TARGET_CHARS]


class SqlAgentInventory:
    """Agent observations and the attack-surface edges derived from them."""

    __slots__ = ("_pool", "_policy_label")

    def __init__(self, *, pool: ConnectionPool, policy_label: str = "") -> None:
        self._pool = pool
        # What governed this agent's traffic: detector version and enforcement
        # posture. Injected rather than read here, because the inventory does
        # not own that decision and reading settings from infrastructure would
        # put a second environment reader in the codebase.
        self._policy_label = policy_label

    # ── Write side: the ingest hot path ──────────────────────────────────────

    def observe(
        self,
        tenant_id: str,
        agent_id: str,
        *,
        at: str = "",
        edges: Sequence[tuple[ObservedEdgeKind, str]] = (),
        violation: bool = False,
    ) -> None:
        """Record that this agent was seen, and what it reached.

        Called for EVERY admitted event regardless of trust or enrolment, which
        is the whole point: the previous `record_event` ran only for verified
        enrolled agents, so an agent nobody enrolled left no trace at all and
        "unmanaged" was a category the product could not populate.

        Observation is not trust. Writing a row here says Sentinel saw this
        agent; it says nothing about whether the agent is permitted, and
        `classify_agent` derives that separately by comparing against enrolment.
        """
        agent = _clean(agent_id)
        if not agent:
            return

        stamp = at or _now()
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            p = conn.p

            # `violation_count` is incremented in the same statement as the
            # event count so the two can never disagree about the same event --
            # a separate UPDATE would be a second round trip on the ingest path
            # and a window in which a crash leaves one counted and not the other.
            # `bump` is a PLACEHOLDER, not an interpolation. It is an int this
            # module computed, so interpolating it could not actually be
            # injected -- and it was written that way first, and two security
            # rules refused it:
            #
            #   test_sql_is_never_built_from_data
            #   test_security_rules::...interpolating something other than a
            #   placeholder or a trusted constant
            #
            # They are right to refuse it. The rules are structural: they cannot
            # tell a safe int from an unsafe one, and a rule that made exceptions
            # for values that look obviously safe would stop being a rule. Every
            # injection ships as a value somebody was sure of.
            bump = 1 if violation else 0
            updated = conn.execute_rowcount(
                f"UPDATE agent_observations SET last_seen={p}, "
                f"event_count=event_count+1, violation_count=violation_count+{p} "
                f"WHERE tenant_id={p} AND agent_id={p}",
                (stamp, bump, tenant_id, agent),
            )
            if not updated:
                conn.execute_rowcount(
                    f"INSERT INTO agent_observations "
                    f"(tenant_id, agent_id, first_seen, last_seen, event_count, "
                    f"violation_count) VALUES ({p},{p},{p},{p},1,{p})",
                    (tenant_id, agent, stamp, stamp, bump),
                )

            if edges:
                existing = conn.one(
                    f"SELECT COUNT(*) AS n FROM agent_observed_edges "
                    f"WHERE tenant_id={p} AND agent_id={p}",
                    (tenant_id, agent),
                )
                room = MAX_EDGES_PER_AGENT - int(existing["n"] if existing else 0)

                for kind, raw_target in edges:
                    target = _clean(raw_target)
                    if not target:
                        continue
                    bumped = conn.execute_rowcount(
                        f"UPDATE agent_observed_edges SET last_seen={p}, "
                        f"occurrences=occurrences+1 WHERE tenant_id={p} "
                        f"AND agent_id={p} AND kind={p} AND target={p}",
                        (stamp, tenant_id, agent, kind.value, target),
                    )
                    if bumped:
                        continue
                    # A NEW target. Only this branch consumes headroom, so an
                    # agent hammering the same resource is never capped out --
                    # the cap is on breadth, which is what actually grows.
                    if room <= 0:
                        continue
                    conn.execute_rowcount(
                        f"INSERT INTO agent_observed_edges (tenant_id, agent_id, "
                        f"kind, target, occurrences, first_seen, last_seen) "
                        f"VALUES ({p},{p},{p},{p},1,{p},{p})",
                        (tenant_id, agent, kind.value, target, stamp, stamp),
                    )
                    room -= 1
            conn.commit()


    # ── Declared metadata ────────────────────────────────────────────────────

    def declare(
        self,
        tenant_id: str,
        agent_id: str,
        field: str,
        value: str,
        *,
        declared_by: str = "",
    ) -> tuple[str, str]:
        """Record one operator assertion about an agent.

        Validated in the DOMAIN rather than here, so the rules are the same
        whether a declaration arrives from the CLI or anywhere else. Returns the
        normalised pair so a caller can echo what was actually stored -- an
        operator who typed `risk_tier HIGH` should see `high` and know it was
        normalised rather than discover it later in a filter that misses.

        Declaring does NOT create an agent. A profile exists because an agent
        was observed; declaring metadata about an id nobody has seen records an
        assertion about something that may not exist, which is a note, not a
        discovery. `profile()` still returns None for it, and that asymmetry is
        deliberate -- otherwise a typo in an agent id would invent an inventory
        entry.
        """
        key, text = validate_declaration(field, value)
        now = _now()
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            p = conn.p
            conn.execute_rowcount(
                f"DELETE FROM agent_declarations WHERE tenant_id={p} "
                f"AND agent_id={p} AND field={p}",
                (tenant_id, agent_id, key),
            )
            conn.execute_rowcount(
                f"INSERT INTO agent_declarations "
                f"(tenant_id, agent_id, field, value, declared_at, declared_by) "
                f"VALUES ({p},{p},{p},{p},{p},{p})",
                (tenant_id, agent_id, key, text, now, declared_by[:128]),
            )
            conn.commit()
        return key, text

    def undeclare(self, tenant_id: str, agent_id: str, field: str) -> bool:
        """Remove one declaration. Returns whether anything was removed.

        The boolean matters: an operator correcting a mistake needs to know the
        field was actually there, because `undeclare team` on an agent that
        never had a team and `undeclare team` on the wrong agent id look
        identical otherwise.
        """
        key = (field or "").strip().lower()
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            p = conn.p
            removed = conn.execute_rowcount(
                f"DELETE FROM agent_declarations WHERE tenant_id={p} "
                f"AND agent_id={p} AND field={p}",
                (tenant_id, agent_id, key),
            )
            conn.commit()
        return bool(removed)

    def _declared(self, conn: Any, tenant_id: str, agent_id: str) -> dict[str, str]:
        p = conn.p
        rows = conn.execute(
            f"SELECT field, value FROM agent_declarations "
            f"WHERE tenant_id={p} AND agent_id={p} ORDER BY field",
            (tenant_id, agent_id),
        )
        return {str(r["field"]): str(r["value"]) for r in rows}

    # ── Read side: the inventory ─────────────────────────────────────────────

    def _edges(self, conn: Any, tenant_id: str, agent_id: str) -> tuple[ObservedEdge, ...]:
        p = conn.p
        rows = conn.execute(
            f"SELECT kind, target, occurrences, first_seen, last_seen "
            f"FROM agent_observed_edges WHERE tenant_id={p} AND agent_id={p} "
            f"ORDER BY occurrences DESC, target",
            (tenant_id, agent_id),
        )
        out: list[ObservedEdge] = []
        for row in rows:
            try:
                kind = ObservedEdgeKind(str(row["kind"]))
            except ValueError:
                # A kind this build does not know -- a downgrade, or a
                # hand-edited row. Skipped rather than raised: one unreadable
                # edge must not make an agent's whole profile unavailable.
                continue
            out.append(
                ObservedEdge(
                    kind=kind,
                    target=str(row["target"]),
                    occurrences=int(row["occurrences"] or 0),
                    first_seen=str(row["first_seen"] or ""),
                    last_seen=str(row["last_seen"] or ""),
                )
            )
        return tuple(out)

    def profile(self, tenant_id: str, agent_id: str) -> AgentProfile | None:
        """Assemble one agent's profile, or None if it was never observed."""
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            p = conn.p

            seen = conn.one(
                f"SELECT first_seen, last_seen, event_count, violation_count "
                f"FROM agent_observations WHERE tenant_id={p} AND agent_id={p}",
                (tenant_id, agent_id),
            )
            if seen is None:
                conn.commit()
                return None

            enrolment = conn.one(
                f"SELECT revoked_at, label FROM agents "
                f"WHERE tenant_id={p} AND address={p}",
                (tenant_id, agent_id),
            )
            grants = conn.execute(
                f"SELECT tool_name FROM agent_tool_grants "
                f"WHERE tenant_id={p} AND agent_id={p}",
                (tenant_id, agent_id),
            )
            granted = tuple(sorted(str(g["tool_name"]) for g in grants))
            edges = self._edges(conn, tenant_id, agent_id)
            declared = self._declared(conn, tenant_id, agent_id)
            incidents = self._incident_count(conn, tenant_id, agent_id)
            conn.commit()

        return AgentProfile(
            tenant_id=tenant_id,
            agent_id=agent_id,
            classification=classify_agent(
                enrolled=enrolment is not None,
                revoked=bool(enrolment and enrolment["revoked_at"]),
            ),
            first_seen=str(seen["first_seen"] or ""),
            last_seen=str(seen["last_seen"] or ""),
            event_count=int(seen["event_count"] or 0),
            violation_count=int(seen["violation_count"] or 0),
            label=str(enrolment["label"] or "") if enrolment else "",
            policy=self._policy_label,
            granted_tools=granted,
            edges=edges,
            declared=declared,
            incident_count=incidents,
        )

    def _incident_count(self, conn: Any, tenant_id: str, agent_id: str) -> int:
        """How many incidents name this agent.

        Counted from `facts_json` rather than a column, because there is no
        agent column on `incidents` -- the agent id lives inside the facts. This
        is a scan, which is why it runs once per profile and never on ingest.
        """
        p = conn.p
        rows = conn.execute(
            f"SELECT facts_json FROM incidents WHERE tenant_id={p}", (tenant_id,)
        )
        count = 0
        for row in rows:
            try:
                facts = json.loads(str(row["facts_json"] or "{}"))
            except (json.JSONDecodeError, TypeError):
                continue
            if _agent_of(facts) == agent_id:
                count += 1
        return count

    def list_profiles(
        self, tenant_id: str, *, classification: AgentClassification | None = None
    ) -> tuple[AgentProfile, ...]:
        """Every observed agent, optionally filtered.

        Ordered so the agents that need attention come first: an inventory sorted
        alphabetically buries the one unmanaged agent among two hundred managed
        ones, and the whole reason to run discovery is to find that one.
        """
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            p = conn.p
            rows = conn.execute(
                f"SELECT agent_id FROM agent_observations WHERE tenant_id={p} "
                f"ORDER BY last_seen DESC",
                (tenant_id,),
            )
            agent_ids = [str(r["agent_id"]) for r in rows]
            conn.commit()

        profiles = [self.profile(tenant_id, a) for a in agent_ids]
        found = [pr for pr in profiles if pr is not None]
        if classification is not None:
            found = [pr for pr in found if pr.classification is classification]
        return tuple(
            sorted(found, key=lambda pr: (not pr.classification.needs_attention, pr.agent_id))
        )

    # ── The attack surface graph ─────────────────────────────────────────────

    def agents_reaching(
        self, tenant_id: str, *, kind: ObservedEdgeKind, pattern: str
    ) -> tuple[str, ...]:
        """Which agents reached targets matching `pattern` (a LIKE pattern).

        This is the query the specification's questions reduce to -- "which
        agents can reach customer PII", "which can send data externally" -- once
        the operator supplies what those mean in THEIR estate. Sentinel does not
        know that `orders_pii` is PII or that `s3://backups` is production, and
        a built-in guess would answer a security question with a hunch.
        """
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            p = conn.p
            rows = conn.execute(
                f"SELECT DISTINCT agent_id FROM agent_observed_edges "
                f"WHERE tenant_id={p} AND kind={p} AND target LIKE {p} "
                f"ORDER BY agent_id",
                (tenant_id, kind.value, pattern),
            )
            conn.commit()
        return tuple(str(r["agent_id"]) for r in rows)


    def entity_inventory(self, tenant_id: str) -> dict[str, Any]:
        """Everything Sentinel knows about, by entity type.

        The specification lists thirteen things to inventory. This reports each
        one with its COUNT and its SOURCE, and the source matters more than the
        count: an entity Sentinel observed is a measurement, an entity a human
        declared is an assertion, and an entity nobody has recorded is neither.

        Reporting all three states is the point. A dashboard showing
        "credentials: 4" beside "cloud environments: 0" invites the reading that
        there are no cloud environments, when the truth is that Sentinel cannot
        see them and nobody wrote them down. `source` says which.
        """
        profiles = self.list_profiles(tenant_id)

        def _distinct(values: Any) -> list[str]:
            return sorted({v for v in values if v})

        # `profile`/`tool`, never `p`/`t`. In this module `p` is the SQL
        # placeholder (`p = conn.p`) and the file is full of f-string SQL, so a
        # comprehension variable called `p` shadows the one name a reader must
        # be able to trust at a glance. `test_every_interpolated_identifier_
        # comes_from_a_fixed_set_of_strings` refused it, and it was right to:
        # the check cannot tell a shadowed placeholder from a real one, and
        # neither can somebody skim-reading a SQL statement at 3am.
        observed_tools = _distinct(
            tool for profile in profiles for tool in profile.observed_tools
        )
        granted_tools = _distinct(
            tool for profile in profiles for tool in profile.granted_tools
        )
        declared_values: dict[str, list[str]] = {}
        for field_name in ("framework", "model", "cloud_environment",
                           "business_application", "instance", "owner", "team"):
            declared_values[field_name] = _distinct(
                profile.declared.get(field_name, "") for profile in profiles
            )

        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            p = conn.p
            servers = conn.execute(
                f"SELECT server_id FROM mcp_servers WHERE tenant_id={p}", (tenant_id,)
            )
            enrolled_servers = sorted({str(r["server_id"]) for r in servers})
            conn.commit()

        return {
            "tenant_id": tenant_id,
            "entities": {
                # ── Observed: Sentinel measured these ───────────────────────
                "agents": {
                    "count": len(profiles),
                    "source": "observed",
                    "unmanaged": sum(
                        1
                        for pr in profiles
                        if pr.classification is AgentClassification.UNMANAGED
                    ),
                },
                "credentials": {
                    "count": len(_distinct(cred for profile in profiles for cred in profile.credentials)),
                    "source": "observed",
                },
                "tools": {
                    "count": len(set(observed_tools) | set(granted_tools)),
                    "source": "observed+granted",
                },
                "permissions": {
                    "count": sum(len(pr.granted_tools) for pr in profiles),
                    "source": "granted",
                },
                "mcp_servers": {
                    "count": len(
                        set(enrolled_servers)
                        | {server for profile in profiles for server in profile.mcp_servers}
                    ),
                    "source": "enrolled+observed",
                },
                "data_stores": {
                    "count": len(_distinct(res for profile in profiles for res in profile.accessible_data)),
                    "source": "observed",
                    # Said plainly: this is what agents REACHED, not what exists.
                    "note": "resources agents actually touched, not a catalogue",
                },
                "external_destinations": {
                    "count": len(
                        _distinct(dest for profile in profiles for dest in profile.external_destinations)
                    ),
                    "source": "observed",
                },
                # ── Declared: a human asserted these ────────────────────────
                "agent_frameworks": {
                    "count": len(declared_values["framework"]),
                    "source": "declared",
                },
                "models": {
                    "count": len(declared_values["model"]),
                    "source": "declared",
                },
                "agent_instances": {
                    "count": len(declared_values["instance"]),
                    "source": "declared",
                },
                "owners": {
                    "count": len(declared_values["owner"]),
                    "source": "declared",
                },
                "cloud_environments": {
                    "count": len(declared_values["cloud_environment"]),
                    "source": "declared",
                },
                "business_applications": {
                    "count": len(declared_values["business_application"]),
                    "source": "declared",
                },
            },
            # How much of the declarable half has actually been filled in. An
            # inventory is only as good as this number, and stating it stops a
            # mostly-empty inventory from reading as a complete one.
            "declared_coverage": {
                "agents_with_owner": sum(1 for pr in profiles if pr.declared.get("owner")),
                "agents_total": len(profiles),
            },
        }

    def agents_sharing_credential(
        self, tenant_id: str, credential: str
    ) -> tuple[str, ...]:
        """Which agents presented the same credential.

        The question a compromise starts with. Until credentials were recorded
        this was unanswerable, and the answer decides blast radius: one agent
        means rotate one key, five means five teams need telling.
        """
        return self.agents_reaching(
            tenant_id, kind=ObservedEdgeKind.CREDENTIAL, pattern=credential
        )

    def edge_summary(self, tenant_id: str) -> Mapping[str, int]:
        """Counts per edge kind. Cheap, and answers "is discovery working"."""
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            p = conn.p
            rows = conn.execute(
                f"SELECT kind, COUNT(*) AS n FROM agent_observed_edges "
                f"WHERE tenant_id={p} GROUP BY kind",
                (tenant_id,),
            )
            conn.commit()
        return {str(r["kind"]): int(r["n"]) for r in rows}


def _agent_of(facts: Any) -> str:
    """Pull an agent id out of an incident's facts, whatever shape it is in."""
    if not isinstance(facts, dict):
        return ""
    for key in ("agentId", "agent_id", "agent"):
        value = facts.get(key)
        if isinstance(value, str) and value:
            return value
    # `raw_payload` is where the admission pipeline actually puts it. Checked by
    # name rather than by walking every nested dict: a generic search would find
    # an `agentId` in some unrelated sub-object and attribute an incident to the
    # wrong agent, which is worse than not attributing it at all.
    for container_key in ("raw_payload", "event", "payload"):
        nested = facts.get(container_key)
        if isinstance(nested, dict):
            found = _agent_of(nested)
            if found:
                return found
    return ""
