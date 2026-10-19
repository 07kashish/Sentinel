"""Retention sweep for operational tables.

WHAT WAS WRONG
--------------
`SENTINEL_RETENTION_DAYS` has been a documented setting, parsed into
`Settings.retention_days`, and read by **nothing**. The Helm chart sets it, and
sets `SENTINEL_RETENTION_INTERVAL` too, which `Settings` did not even parse. The
schema module opens by explaining that `incident_transitions` and `audit_log` are
partitioned "for retention", and `MaintenanceLoop`'s own docstring refers to "its
retention job". There was no retention job.

The consequences are not hypothetical. `complete()` sets a work item's state to
`done` and leaves the row; `mark_delivered` does the same for the outbox. There
is no `DELETE` anywhere for either. `inbox` has `purge_before()` and
`replay_nonces` has `purge_expired()` -- both with indexes built specifically to
serve them (`ix_inbox_age`, `ix_nonces_expiry`) -- and neither had a single
production caller. Four tables grew without bound for the life of a deployment,
and a 40-minute soak measured ingest p95 degrading from 83 ms to 624 ms against a
<500 ms target as they did.

WHAT THIS DELETES, AND WHAT IT DELIBERATELY DOES NOT
-----------------------------------------------------
Only *operational* rows: finished queue work, delivered outbox records, the
message-dedup journal past its redelivery window, and expired replay nonces.
Every one of those is derived state whose purpose has already been served.

It does NOT touch `incidents`, `domain_events`, `incident_transitions`,
`ledger_entries` or `audit_log`. Those are the security record. How long a SOC
keeps incident history is a compliance decision with legal weight, it is not
interchangeable with "when can we reclaim disk", and an agent should not pick a
number for it. If those tables need trimming, that is a separate policy with a
separate setting and a human's signature on it.

THE SEPARATE POLICY, NOW IMPLEMENTED (AND STILL OFF BY DEFAULT)
---------------------------------------------------------------
`sweep_incident_history` is that separate policy. It is gated on
`SENTINEL_INCIDENT_RETENTION_DAYS`, which has **no default**: unset means nothing
is ever deleted, which is the shipped behaviour and the only behaviour an agent
is entitled to choose. Setting it is the operator asserting a retention period
they are willing to defend to an auditor.

Three further constraints, each of which is a test:

* **Only TERMINAL incidents.** An in-flight incident older than the window is a
  stuck pipeline to investigate, not garbage -- the same reasoning that keeps
  `state='pending'` work out of the operational sweep.
* **The evidence ledger is never touched.** `ledger_entries`, `ledger_batches`
  and `security_audit` are hash chains. Trimming one destroys the
  non-repudiation it exists to provide, so deleting an incident deliberately
  leaves its ledger commitment standing. The commitment outliving the record is
  the correct asymmetry: it proves something existed without retaining its
  content.
* **Children first.** `incident_transitions` and `domain_events` are deleted
  before the `incidents` row they describe, inside one transaction, so a crash
  mid-sweep cannot leave an incident whose audit trail is half gone.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from types import MappingProxyType
from typing import Mapping, Sequence

from sentinel.domain.incident import IncidentState
from sentinel.domain.primitives import TenantId, Timestamp
from sentinel.infrastructure.enterprise import SqlTenantSettings
from sentinel.infrastructure.sql.engine import ConnectionPool

__all__ = [
    "APPEND_ONLY_TABLES",
    "INCIDENT_CHILD_TABLES",
    "IncidentHistorySweep",
    "RetentionSweep",
    "SqlRetention",
]

#: Deleted with their incident, in this order: children before the parent.
#:
#: A named constant rather than a literal list inside the loop, because the
#: declared-or-reaped gate in `tests_arch/test_retention_sweep.py` reads it. A
#: table added to the sweep is therefore visible to the gate by construction, and
#: cannot be swept while still claiming to be append-only.
INCIDENT_CHILD_TABLES: tuple[str, ...] = (
    "incident_transitions",
    "domain_events",
    "execution_steps",
    "reports",
)

#: Tables that are deliberately never reaped, each with the reason.
#:
#: `tests_arch/test_retention_sweep.py::test_every_table_is_either_reaped_or_declared_append_only`
#: reads this and fails if a table in the schema appears in neither this mapping
#: nor a DELETE issued by this module. A new table therefore cannot be added
#: without someone deciding, in writing, which of the two it is -- which is the
#: control that was missing when four tables grew for the life of a deployment.
#:
#: The reasons are checked for length as well as presence, because "n/a" is how a
#: declaration requirement gets satisfied without a decision being made.
#:
#: `MappingProxyType`, not a bare dict, and not as a style preference:
#: `tests_arch/test_architecture_rules.py::test_there_is_no_mutable_module_level_state`
#: rejects a module-level `dict` literal outright. A writable mapping here would
#: be a process global that any import could edit -- and this one decides which
#: tables are allowed to grow for ever, so "any import could edit it" is the
#: wrong property for it to have. Same treatment as `REQUIRED_AGENT_LABELS` and
#: `domain/incident.py::_EDGES`.
APPEND_ONLY_TABLES: Mapping[str, str] = MappingProxyType({
    "execution_receipts": (
        "The binding record: which authorization permitted an execution, what "
        "parameter digest was approved, and what was actually executed. "
        "`SqlReceiptStore` contains no UPDATE and no DELETE at all, so the "
        "table is append-only by construction rather than by policy -- and a "
        "retention sweep would be the one code path able to remove a receipt, "
        "which is precisely the row somebody would want gone. A receipt whose "
        "execution is disputed is needed longest, so any sweep would delete "
        "the evidence in inverse order of its importance. How long to keep "
        "authorization evidence is a compliance decision and nothing here "
        "should pick that number."
    ),
    "evidence_commitments": (
        "Which transparency leaf commits to which execution receipt. It is the "
        "index that lets an export hand a verifier a receipt together with its "
        "proof; reaping a row would leave a leaf nobody can attribute, and the "
        "leaves themselves are never reaped."
    ),
    "transparency_leaves": (
        "The transparency log itself. Reaping a leaf would rewrite history, "
        "which is the exact thing `verify_consistency` exists to detect -- and "
        "worse, a retention sweep would do it in a way that produces a "
        "CONSISTENT-looking log afterwards, because the tree the proof is "
        "checked against would have changed too. There is no retention policy "
        "that can safely delete from this table; a deployment that needs the "
        "log bounded must start a NEW log and publish the transition, so the "
        "gap is visible rather than silent."
    ),
    "transparency_roots": (
        "Which roots were published, where, and what reference the sink "
        "returned. An auditor checking a root from last year needs the row "
        "from last year; deleting it destroys the only record that the "
        "publication happened, and an unpublished-looking root is "
        "indistinguishable from one that was never published."
    ),
    "mcp_tool_provenance": (
        "Which definition versions an MCP server actually served, and when. "
        "This is the record a rug-pull investigation reads first, and it stays "
        "small by construction: one row per (tool, definition version), not "
        "per call -- a re-served version bumps counters on its existing row. "
        "How long to keep supply-chain forensics is a compliance decision, "
        "like the incident record; nothing here should pick that number."
    ),
    "mcp_tool_changes": (
        "The drift log: every tool addition, removal and definition change "
        "the gateway observed. Rows exist only when a server's tool surface "
        "actually changed, so growth tracks drift events, not traffic. It is "
        "evidence of supply-chain tampering in progress and is retained for "
        "the same reason the audit trail is."
    ),
    "ledger_entries": (
        "Hash chain. Every entry commits to its predecessor, so deleting one "
        "breaks verification of every entry after it and destroys the "
        "non-repudiation the ledger exists to provide. Redaction nulls the body "
        "and keeps the commitment; it never removes the row."
    ),
    "ledger_batches": (
        "Merkle roots over ledger entries, and the anchor an external attestation "
        "points at. Removing a batch orphans the third-party timestamp that proves "
        "when the batch existed."
    ),
    "security_audit": (
        "Per-tenant hash-chained audit trail with a dense `seq`, specifically so a "
        "deleted row is detectable as a gap. A trail that can be trimmed is not an "
        "audit trail, and this is the table an attacker would most want to edit."
    ),
    "evidence": (
        "The artifact an incident's ledger commitment is over. Its lifecycle is "
        "the ledger's redaction path -- body NULL, digest retained -- not age, "
        "because a deleted row would make chain verification fail rather than "
        "pass over a redacted one. KNOWN CONSEQUENCE: it therefore survives its "
        "incident and keeps growing with incident volume. That is a named "
        "residual in docs/PRODUCTION_READINESS_REPORT.md, not an oversight."
    ),
    "approvals": (
        "The record of a human authorising a remediation. Deleting it would leave "
        "an executed action with no recorded approver, which is the shape of "
        "finding a SOC 2 audit exists to catch. Like `evidence`, it outlives the "
        "incident it belongs to and is a named residual rather than a bound."
    ),
    "connected_apps": (
        "Administrator-managed registrations (sealed credentials) of the applications an "
        "agent may call. Configuration, not a log: deleted by an administrator, never by age."
    ),
    "policy_versions": (
        "A stored version is what an operator reviewed and what a rollback "
        "returns to. Reaping old versions on age would silently remove the "
        "rollback targets -- and the version an operator wants is precisely the "
        "old one, on the night the new one turned out to be wrong."
    ),
    "mode_transitions": (
        "The record of who moved this tenant between OBSERVE and LOCKDOWN and "
        "why. Deleting it leaves an estate whose enforcement posture changed "
        "with nobody's name against the change, which is the question an "
        "incident review asks first."
    ),
    "tenant_key_versions": (
        "Deleting a key version does two irreversible things: it makes every "
        "record encrypted under that version unreadable, and it destroys the "
        "evidence that a customer revoked their key -- the one operation a BYOK "
        "customer may later need to prove they performed."
    ),
    "tenant_settings": (
        "One row per tenant, so it is bounded by customer count rather than by "
        "event volume and does not grow. Reaping it would silently revert a "
        "tenant to default retention and default region -- a residency change "
        "performed by a housekeeping job, which is the worst way for one to "
        "happen."
    ),
    "tenants": (
        "The directory used to establish a scope. Reaping it on age would delete "
        "live customers; offboarding is an operator action, not housekeeping."
    ),
    "agents": (
        "Enrolment roster. An agent absent from this table is an agent Sentinel "
        "cannot tell from an unenrolled one, so ageing rows out would silently "
        "widen the bypass surface `detect_possible_bypasses` watches."
    ),
    "users": "Human identity. Removing it is an offboarding decision with its own approval path.",
    "user_credentials": "Authenticators for a live user; deleting one locks that human out.",
    "user_sessions": (
        "Bounded by its own `expires_at` and cleared on logout, so it does not "
        "grow with traffic; ageing it out separately would only add a second, "
        "disagreeing expiry."
    ),
    "enrolment_tickets": (
        "Single-use and short-lived by construction; consumed on redemption "
        "rather than swept."
    ),
    "organizations": "One row per tenant organisation. Bounded by tenant count, not by traffic.",
    "leader_locks": "One row per named job. Bounded by the number of jobs, which is a constant.",
    "schema_migrations": "One row per applied migration. Deleting one would re-run it.",
    "a2a_agent_cards": (
        "The trust anchor for A2A enrolment, and the same decision as "
        "`mcp_servers` for the same reasons. Bounded by the number of agents a "
        "tenant enrolled, not by traffic: one row per agent, updated in place "
        "on re-enrolment rather than appended. Time-reaping it would be "
        "actively unsafe -- an aged-out card silently makes an enrolled agent "
        "read as UNENROLLED, which refuses every delegation to a peer that was "
        "working yesterday, and it takes the pinned fingerprint with it so "
        "drift detection stops rather than fires."
    ),
    "mcp_servers": (
        "The trust anchor for MCP and OpenAPI enrolment: which servers an "
        "operator decided about, and what they decided. Bounded by the number of "
        "servers a tenant enrolled, not by traffic. Time-reaping it would be "
        "actively unsafe in both directions -- an aged-out ENROLLED row silently "
        "becomes UNKNOWN and breaks a working agent, and an aged-out BLOCKED row "
        "silently un-blocks a server someone deliberately distrusted."
    ),
    "agent_declarations": (
        "What a human ASSERTED about an agent -- owner, team, purpose, risk "
        "tier. Bounded by agents times a closed field list, not by traffic, and "
        "it is the only part of a profile a machine cannot reconstruct. Ageing "
        "it out would silently discard the answer to 'who owns this agent', "
        "which is the first question asked during an incident and the one that "
        "costs the most time when nobody recorded it."
    ),
    "agent_tool_grants": (
        "Which tools each agent is authorised to invoke. Bounded by agents "
        "times tools, not by traffic. Time-reaping it would silently REVOKE an "
        "authorisation nobody decided to revoke -- under enforcement that stops "
        "a working agent, and the operator sees a refusal with no corresponding "
        "action in the audit trail, because ageing out leaves no record."
    ),
    "mcp_tool_pins": (
        "The reviewed tool definitions a server was enrolled with. Bounded by "
        "servers times tools, not by traffic, and replaced wholesale on "
        "re-enrolment rather than accumulating. Deleting a pin does not merely "
        "lose history: it removes the only record of what an operator approved, "
        "so the drift check has nothing to compare against and a rug pull stops "
        "being detectable."
    ),
})


#: The terminal states, spelled from the domain enum rather than copied.
#: A copy here would drift the day a new terminal state is added, and the drift
#: would be silent: the sweep would simply stop reaping that state's incidents.
TERMINAL_STATES: tuple[str, ...] = tuple(
    sorted(state.value for state in IncidentState if state.is_terminal)
)


@dataclass(frozen=True, slots=True)
class RetentionSweep:
    """What one sweep removed, per table."""

    work_queue_done: int
    outbox_delivered: int
    inbox_entries: int
    replay_nonces: int
    webauthn_challenges: int = 0
    agent_observations: int = 0
    agent_observed_edges: int = 0
    execution_nodes: int = 0
    remediation_idempotency: int = 0
    execution_nonces: int = 0
    execution_authorizations: int = 0
    execution_operations: int = 0
    protect_control_state: int = 0
    device_discovery: int = 0

    @property
    def total(self) -> int:
        return (
            self.work_queue_done
            + self.outbox_delivered
            + self.inbox_entries
            + self.replay_nonces
            + self.webauthn_challenges
            + self.agent_observations
            + self.agent_observed_edges
            + self.execution_nodes
            + self.remediation_idempotency
            + self.execution_nonces
            + self.execution_authorizations
            + self.execution_operations
            + self.protect_control_state
            + self.device_discovery
        )

    def as_dict(self) -> Mapping[str, int]:
        return {
            "retention_work_queue_done": self.work_queue_done,
            "retention_outbox_delivered": self.outbox_delivered,
            "retention_inbox_entries": self.inbox_entries,
            "retention_replay_nonces": self.replay_nonces,
            "retention_webauthn_challenges": self.webauthn_challenges,
            "retention_agent_observations": self.agent_observations,
            "retention_agent_observed_edges": self.agent_observed_edges,
            "retention_execution_nodes": self.execution_nodes,
            "retention_remediation_idempotency": self.remediation_idempotency,
            "retention_execution_nonces": self.execution_nonces,
            "retention_execution_authorizations": self.execution_authorizations,
            "retention_execution_operations": self.execution_operations,
            "retention_protect_control_state": self.protect_control_state,
            "retention_device_discovery": self.device_discovery,
            "retention_rows_deleted": self.total,
        }


@dataclass(frozen=True, slots=True)
class IncidentHistorySweep:
    """What one incident-history sweep removed. Separate type, separate policy.

    Folding these counts into `RetentionSweep` would let an operator reading
    `retention_rows_deleted` in a log line believe the number covered only
    operational housekeeping when it had in fact deleted incident records. The
    two policies have different owners and different legal weight, so they report
    separately.

    `configured` is False when `SENTINEL_INCIDENT_RETENTION_DAYS` is unset. A
    sweep that did nothing because it is switched off and a sweep that did
    nothing because there was nothing to delete are different facts, and only one
    of them is worth an operator's attention.
    """

    configured: bool
    incidents: int = 0
    domain_events: int = 0
    incident_transitions: int = 0
    execution_steps: int = 0
    reports: int = 0

    @property
    def total(self) -> int:
        return (
            self.incidents
            + self.domain_events
            + self.incident_transitions
            + self.execution_steps
            + self.reports
        )

    def as_dict(self) -> Mapping[str, int | bool]:
        return {
            "incident_retention_configured": self.configured,
            "incident_retention_incidents": self.incidents,
            "incident_retention_domain_events": self.domain_events,
            "incident_retention_transitions": self.incident_transitions,
            "incident_retention_execution_steps": self.execution_steps,
            "incident_retention_reports": self.reports,
            "incident_retention_rows_deleted": self.total,
        }


class SqlRetention:
    """Deletes finished operational rows older than the retention window."""

    __slots__ = ("_pool",)

    def __init__(self, *, pool: ConnectionPool) -> None:
        self._pool = pool

    def sweep(
        self, *, now: Timestamp, retention_days: int, tenants: Sequence[TenantId]
    ) -> RetentionSweep:
        """Delete finished operational rows, ONE TENANT AT A TIME.

        WHY `tenants` IS A REQUIRED ARGUMENT
        -------------------------------------
        The first revision of this method took a pooled connection and issued
        `DELETE FROM work_queue WHERE state='done' AND enqueued_at<?` with no
        tenant anywhere in it. On SQLite that deleted the rows. On PostgreSQL it
        deleted **nothing at all** -- and reported zero rather than failing.

        Every one of these tables is in `PROTECTED_TABLES` under
        `FORCE ROW LEVEL SECURITY`, whose policy is
        `tenant_id = current_setting('sentinel.tenant_id', true)`. A pooled
        connection has no tenant context, so that setting is NULL, `tenant_id =
        NULL` evaluates to NULL for every row, and the DELETE matches none of
        them. This is the identical shape of the `delivery_queue` defect this
        codebase's own module docstrings describe: invisible on the development
        engine, total on the production one. Measured before the fix:

            before: work_queue = 1  inbox = 1
            sweep reported: {... 'retention_rows_deleted': 0}
            after : work_queue = 1  inbox = 1

        So the sweep now runs per tenant, establishing the RLS context with
        `set_tenant` AND carrying an explicit `tenant_id = ?` predicate. Both,
        not either: the predicate keeps the statement correct on SQLite, which
        has no RLS to fall back on, and the context keeps it correct on
        PostgreSQL. Belt and braces is the right posture for the one code path
        in the system whose job is to delete things.

        `retention_days` must be positive; a zero or negative window would delete
        rows the system still depends on (the inbox stops deduplicating, and the
        replay guard stops guarding), so it is refused rather than clamped.
        """
        if retention_days <= 0:
            raise ValueError(
                f"retention_days must be positive, got {retention_days}; a "
                "non-positive window would purge the dedup journal and the "
                "replay guard while they are still in use"
            )
        cutoff = Timestamp(now.value - timedelta(days=retention_days)).isoformat()
        stamp = now.isoformat()
        totals = dict.fromkeys(
            (
                "work_queue",
                "outbox",
                "inbox",
                "replay_nonces",
                "agent_observations",
                "agent_observed_edges",
                "execution_nodes",
                "containments",
                "remediation_idempotency",
                "execution_nonces",
                "execution_authorizations",
                "execution_operations",
                "protect_control_state",
                "device_discovery",
            ),
            0,
        )

        for tenant in tenants:
            with self._pool.acquire() as conn:
                p = conn.p
                conn.begin()
                conn.set_tenant(tenant.value)
                # Finished work. The primary key is (tenant_id, work_id), so the
                # tenant equality is an index prefix; `state` and `enqueued_at`
                # filter within it.
                totals["work_queue"] += conn.execute_rowcount(
                    f"DELETE FROM work_queue WHERE tenant_id={p} "
                    f"AND state='done' AND enqueued_at<{p}",
                    (tenant.value, cutoff),
                )
                # Delivered outbox records. The idempotency key is unique per
                # tenant, so removing a delivered row after the window also
                # releases the key -- which is correct: redelivery protection is
                # only meaningful for as long as a duplicate could still arrive.
                totals["outbox"] += conn.execute_rowcount(
                    f"DELETE FROM outbox WHERE tenant_id={p} "
                    f"AND state='delivered' AND updated_at<{p}",
                    (tenant.value, cutoff),
                )
                # Message dedup journal. `ix_inbox_age` exists for exactly this.
                totals["inbox"] += conn.execute_rowcount(
                    f"DELETE FROM inbox WHERE tenant_id={p} AND accepted_at<{p}",
                    (tenant.value, cutoff),
                )
                # Replay nonces carry their own expiry, so they are purged on
                # that rather than on the retention window -- a nonce past
                # `expires_at` is already refused by the guard, and keeping it
                # only costs space.
                totals["replay_nonces"] += conn.execute_rowcount(
                    f"DELETE FROM replay_nonces WHERE tenant_id={p} AND expires_at<{p}",
                    (tenant.value, stamp),
                )
                # Remediation idempotency receipts. One row per approval that
                # reached an integration, so bounded by approvals -- but an
                # approval is itself reaped with its incident, and a key whose
                # approval is gone protects nothing. Reaped on the retention
                # window: a retry arriving AFTER the window would re-execute,
                # and that is the same trade the outbox makes above.
                totals["remediation_idempotency"] += conn.execute_rowcount(
                    f"DELETE FROM remediation_idempotency WHERE tenant_id={p} "
                    f"AND created_at<{p}",
                    (tenant.value, cutoff),
                )
                # Burned execution nonces. An authorization's window is
                # minutes; a nonce older than the retention window belongs to
                # an authorization that expired long ago and could not be
                # presented again, so the row no longer prevents anything.
                totals["execution_nonces"] += conn.execute_rowcount(
                    f"DELETE FROM execution_nonces WHERE tenant_id={p} "
                    f"AND claimed_at<{p}",
                    (tenant.value, cutoff),
                )
                # Issued authorizations carry their own expiry, like replay
                # nonces: past `expires_at` the token is refused on
                # presentation, and the row only costs space.
                totals["execution_authorizations"] += conn.execute_rowcount(
                    f"DELETE FROM execution_authorizations WHERE tenant_id={p} "
                    f"AND expires_at<{p}",
                    (tenant.value, stamp),
                )
                # Operations that reached a DECIDED state are reaped on the
                # window. `unknown_after_effect` and `pending` are NOT: an
                # operation nobody has reconciled is the row an investigation
                # needs most, and deleting it would convert "we do not know"
                # into "nothing happened". The receipt, which is append-only,
                # keeps the binding evidence for a succeeded operation.
                totals["execution_operations"] += conn.execute_rowcount(
                    f"DELETE FROM execution_operations WHERE tenant_id={p} "
                    f"AND state IN ('succeeded', 'failed', 'refused') "
                    f"AND started_at<{p}",
                    (tenant.value, cutoff),
                )
                # Control rows whose budget window is long past and whose
                # breaker is closed hold no decision; a missing row reads as
                # a fresh window, which is what it would be anyway.
                totals["protect_control_state"] += conn.execute_rowcount(
                    f"DELETE FROM protect_control_state WHERE tenant_id={p} "
                    f"AND window_start<{p} AND circuit_opened_at=''",
                    (tenant.value, cutoff),
                )
                # Discovery edges. REAPED rather than declared append-only, and
                # the distinction is not bookkeeping: `agent_tool_grants` is
                # bounded by agents times tools, while an edge exists per
                # DISTINCT TARGET -- one row for every file path, URL and table
                # an agent has ever touched. That is unbounded by construction,
                # which is precisely the shape the declared-or-reaped gate
                # exists to catch.
                #
                # Reaped on `last_seen`, so an edge stays for as long as it
                # keeps being observed. Attack surface is what an agent can
                # reach NOW; a path it read once, ninety days ago, and never
                # again is history rather than exposure.
                totals["agent_observed_edges"] += conn.execute_rowcount(
                    f"DELETE FROM agent_observed_edges WHERE tenant_id={p} "
                    f"AND last_seen<{p}",
                    (tenant.value, cutoff),
                )
                # The agent record goes only when nothing is left to describe.
                # Deleting an observation while its edges survive would orphan
                # them and make an agent's reach unattributable -- the graph
                # would still say "something reads /etc/shadow" and no longer
                # say what.
                # Execution nodes are ONE ROW PER EVENT -- the most
                # traffic-driven table in the schema, and the only one that
                # grows with throughput rather than with the size of the
                # estate. Reaped on `occurred_at`: a causal trace is for
                # investigating recent activity, and a six-month-old session
                # nobody opened is storage rather than evidence. The incident
                # it produced, if any, is kept by its own separate policy.
                # PER-TENANT RETENTION (section 78).
                #
                # `retention_days` is the deployment-wide default and remains the
                # floor. A tenant that configured a SHORTER window gets it; a
                # tenant that configured a longer one does not, because the
                # deployment operator's storage budget is not the tenant's to
                # override. Stated here because "tenant-configurable" without a
                # bound is how one tenant fills a shared disk.
                #
                # An unconfigured tenant returns conservative defaults rather
                # than raising -- a sweep that raised on the first unconfigured
                # tenant would stop sweeping every tenant after it, turning a
                # missing row into unbounded growth estate-wide.
                tenant_policy = SqlTenantSettings(conn, tenant).retention()
                node_cutoff = _tighter_cutoff(
                    now, cutoff, tenant_policy.days_for("execution_nodes")
                )
                totals["execution_nodes"] += conn.execute_rowcount(
                    f"DELETE FROM execution_nodes WHERE tenant_id={p} "
                    f"AND occurred_at<{p}",
                    (tenant.value, node_cutoff),
                )
                totals["agent_observations"] += conn.execute_rowcount(
                    f"DELETE FROM agent_observations WHERE tenant_id={p} "
                    f"AND last_seen<{p}",
                    (tenant.value, cutoff),
                )
                # Self-reported device inventory: a dated snapshot; reaped, not kept forever.
                totals["device_discovery"] += conn.execute_rowcount(
                    f"DELETE FROM device_discovery WHERE tenant_id={p} "
                    f"AND received_at<{p}",
                    (tenant.value, cutoff),
                )
                # Containments are reaped, but ONLY once they are no longer in
                # force. The `revoked_at<>''` predicate is load-bearing: without
                # it the sweep would delete an ACTIVE containment whose
                # `created_at` had aged past the cutoff, silently un-blocking an
                # agent an operator had stopped indefinitely. A retention job
                # that lifts a kill switch is the worst possible way to discover
                # a missing WHERE clause.
                #
                # Expired-but-unrevoked rows are left alone for the same reason
                # in miniature: they are cheap, and the predicate stays simple
                # enough to read correctly.
                #
                # The permanent record is not lost. `security_audit` holds
                # `containment.activate` and `containment.lift` for every one of
                # these, is hash-chained, and is declared append-only -- so "who
                # stopped production, when, and why" outlives the row here.
                totals["containments"] += conn.execute_rowcount(
                    f"DELETE FROM containments WHERE tenant_id={p} "
                    f"AND revoked_at<>'' AND revoked_at<{p}",
                    (tenant.value, cutoff),
                )
                conn.commit()

        # `webauthn_challenges` is deliberately NOT tenant-protected -- a
        # challenge is issued before the caller is known, so there is no tenant
        # to scope it to (see migrate.py v7). It is therefore swept ONCE, outside
        # the per-tenant loop, and correctly needs no context.
        #
        # It is here at all because the declared-or-reaped gate found it: it
        # ships `ix_challenges_issued ON webauthn_challenges(issued_at)`, an index
        # whose only possible purpose is an age purge, and had no caller -- the
        # same signature as `ix_inbox_age` and `ix_nonces_expiry` before this
        # module existed. It has no writer in the tree TODAY, so this deletes
        # nothing today; it means the table is bounded on the day a writer is
        # added rather than six months after.
        with self._pool.acquire() as conn:
            conn.begin()
            webauthn_challenges = conn.execute_rowcount(
                f"DELETE FROM webauthn_challenges WHERE issued_at<{conn.p}", (cutoff,)
            )
            conn.commit()

        return RetentionSweep(
            work_queue_done=totals["work_queue"],
            outbox_delivered=totals["outbox"],
            inbox_entries=totals["inbox"],
            replay_nonces=totals["replay_nonces"],
            webauthn_challenges=webauthn_challenges,
            agent_observations=totals["agent_observations"],
            agent_observed_edges=totals["agent_observed_edges"],
            execution_nodes=totals["execution_nodes"],
            remediation_idempotency=totals["remediation_idempotency"],
            execution_nonces=totals["execution_nonces"],
            execution_authorizations=totals["execution_authorizations"],
            execution_operations=totals["execution_operations"],
            protect_control_state=totals["protect_control_state"],
            device_discovery=totals["device_discovery"],
        )

    def sweep_incident_history(
        self,
        *,
        now: Timestamp,
        incident_retention_days: int | None,
        tenants: Sequence[TenantId],
    ) -> IncidentHistorySweep:
        """Delete TERMINAL incident records past an OPERATOR-CONFIGURED window.

        `incident_retention_days is None` means the operator has not set
        `SENTINEL_INCIDENT_RETENTION_DAYS`, and this returns immediately having
        issued no statement at all. That is the shipped default and it is not a
        placeholder: no number here is defensible without a named human, so the
        code declines to pick one rather than choosing a plausible-looking 90.

        WHAT IS DELETED, IN ONE TRANSACTION, CHILDREN FIRST
        ---------------------------------------------------
        `incident_transitions`, `domain_events`, `execution_steps` and `reports`
        for the selected incidents, then the `incidents` rows themselves. One
        transaction, so a crash cannot leave an incident whose audit trail is
        half gone -- an incident with a partial transition history is worse than
        either keeping or deleting it, because it reads as a complete record of
        something that did not happen that way.

        WHAT IS NOT DELETED, EVER
        --------------------------
        `ledger_entries`, `ledger_batches`, `security_audit` and `evidence`. The
        first three are hash chains whose value is that they cannot be trimmed;
        the fourth is governed by the ledger's redaction path. The commitment
        outliving the record is the correct asymmetry: it still proves an
        incident existed and what its evidence hashed to, without retaining the
        content. `test_the_evidence_ledger_survives_an_incident_history_sweep`
        holds this.

        ONLY TERMINAL INCIDENTS
        ------------------------
        Selection is `state IN (terminal) AND updated_at < cutoff`. An in-flight
        incident older than the window is a stuck pipeline to investigate, not
        garbage, and deleting it would make the stall disappear instead of the
        cause -- the same reasoning that keeps pending work out of the
        operational sweep.

        PER TENANT, FOR THE SAME REASON `sweep` IS
        -------------------------------------------
        Every table touched here is under FORCE row-level security, so a sweep on
        an unscoped pooled connection silently deletes nothing on PostgreSQL. See
        `sweep` above for the measurement that established that.
        """
        if incident_retention_days is None:
            return IncidentHistorySweep(configured=False)
        if incident_retention_days <= 0:
            raise ValueError(
                f"incident_retention_days must be positive, got "
                f"{incident_retention_days}; leave the setting UNSET to disable "
                "deletion entirely rather than expressing it as a zero window"
            )
        cutoff = Timestamp(
            now.value - timedelta(days=incident_retention_days)
        ).isoformat()
        counts = dict.fromkeys((*INCIDENT_CHILD_TABLES, "incidents"), 0)

        for tenant in tenants:
            with self._pool.acquire() as conn:
                p = conn.p
                states = ",".join(p for _ in TERMINAL_STATES)
                conn.begin()
                conn.set_tenant(tenant.value)
                # The set of incidents in scope, resolved ONCE. Re-evaluating the
                # predicate per child table would let a concurrent transition move
                # an incident in or out of scope between statements, and leave
                # exactly the half-deleted record this transaction prevents.
                # `ix_incidents_state` leads with (tenant_id, state, updated_at).
                doomed = [
                    str(row["incident_id"])
                    for row in conn.execute(
                        f"SELECT incident_id FROM incidents "  # noqa: S608 - placeholders only
                        f"WHERE tenant_id={p} AND state IN ({states}) AND updated_at<{p}",
                        (tenant.value, *TERMINAL_STATES, cutoff),
                    )
                ]
                if not doomed:
                    conn.commit()
                    continue

                # Children before parents. Issued per incident rather than as one
                # giant IN list: the primary key on every child table leads with
                # (tenant_id, incident_id), so each of these is an index range
                # delete and the sweep does not slow down as history grows.
                # `domain_events` is the exception -- its key is
                # (tenant_id, event_id) -- which is why migration 12 adds
                # `ix_events_incident`; without it this statement is a sequential
                # scan per incident, i.e. quadratic in history size.
                for table in INCIDENT_CHILD_TABLES:
                    for incident_id in doomed:
                        counts[table] += conn.execute_rowcount(
                            f"DELETE FROM {table} WHERE tenant_id={p} AND incident_id={p}",  # noqa: S608 - fixed names
                            (tenant.value, incident_id),
                        )
                for incident_id in doomed:
                    counts["incidents"] += conn.execute_rowcount(
                        f"DELETE FROM incidents WHERE tenant_id={p} AND incident_id={p}",
                        (tenant.value, incident_id),
                    )
                conn.commit()

        return IncidentHistorySweep(
            configured=True,
            incidents=counts["incidents"],
            domain_events=counts["domain_events"],
            incident_transitions=counts["incident_transitions"],
            execution_steps=counts["execution_steps"],
            reports=counts["reports"],
        )


def _tighter_cutoff(now: Timestamp, default_cutoff: str, tenant_days: int) -> str:
    """The later of the deployment cutoff and the tenant's own.

    "Later" means "deletes more". The deployment-wide window is a floor on how
    much is kept and therefore a ceiling on how long data survives; a tenant may
    ask for less retention but not for more, or one tenant's preference becomes
    every tenant's storage bill.

    Compared as ISO-8601 strings, sound because every timestamp in this system is
    UTC with a `Z`-equivalent offset and fixed-width fields.
    """
    tenant_cutoff = Timestamp(now.value - timedelta(days=tenant_days)).isoformat()
    return max(default_cutoff, tenant_cutoff)
