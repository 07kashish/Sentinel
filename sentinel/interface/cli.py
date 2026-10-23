"""Operator entry points. The only place in this codebase that writes to stdout.

WHY THIS LIVES IN THE INTERFACE LAYER
--------------------------------------
`migrate()` is infrastructure; deciding to run it, reading the environment for a
DSN and printing the result is a delivery concern. Putting the entry point in
`sentinel/infrastructure/sql/migrate.py` meant infrastructure imported
`sentinel.composition.settings` -- an outward dependency, caught by
`tests_arch/test_architecture_rules.py::test_every_dependency_points_inward`
rather than by review.

The interface layer may import composition and infrastructure. Nothing imports
the interface layer.

Usage:
    python -m sentinel.interface.cli migrate
    python -m sentinel.interface.cli verify
    python -m sentinel.interface.cli enrol <tenant> <address> [label]
    python -m sentinel.interface.cli mcp-enrol <tenant> <server> <tools.json>
"""

from __future__ import annotations

# Capability.MANAGE_USERS is enforced over HTTP for SCIM/org routes; agent
# enrol/revoke remain CLI (host access) for trust-anchor changes.

import sys
from typing import Any, Sequence, TextIO

from sentinel.composition.preflight import validate_production_configuration
from sentinel.composition.settings import ConfigurationError, Settings
from sentinel.infrastructure.identity import SqlAgentRegistry
from sentinel.infrastructure.outbound import HardenedHttpClient, OutboundPolicy
from sentinel.domain.effective_permissions import compute_effective_reach
from sentinel.infrastructure.platforms.discovery import (
    discover_kubernetes_workloads,
    reconcile,
)
from sentinel.infrastructure.platforms.kubernetes import KubernetesCredentials
from sentinel.domain.inventory import (
    DECLARABLE_FIELDS,
    AgentClassification,
    DeclarationRejected,
    ObservedEdgeKind,
)
from sentinel.domain.sequences import detect_sequences
from sentinel.infrastructure.execution_graph import SqlExecutionGraph
from sentinel.infrastructure.inventory import SqlAgentInventory
from sentinel.infrastructure.agent_capabilities import SqlAgentCapabilities
from sentinel.infrastructure.siem import SUPPORTED_FORMATS, SiemEvent, render
from sentinel.interface.evidence_cli import evidence_reseal_command
from sentinel.interface.mcp_cli import mcp_command
from sentinel.interface.passport_cli import passport_command
from sentinel.infrastructure.runtime import SystemClock
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.migrate import (
    CURRENT_VERSION,
    SchemaOutOfDate,
    migrate,
    verify,
)
from sentinel.domain.primitives import Address, InvalidValue, TenantId

__all__ = ["main"]

USAGE = """sentinel — operator commands

  migrate                          apply every pending schema migration
  verify                           check the schema is the expected version
  enrol <tenant> <address> [label] enrol an agent signing address for a tenant
  revoke <tenant> <address>        revoke an enrolled address
  mcp-enrol <tenant> <server> <tools.json> [endpoint]
                                   pin an MCP server's reviewed tool definitions
  mcp-block <tenant> <server>      refuse every call to an MCP server
  mcp-list <tenant>                show enrolled MCP servers and pin counts
  mcp-provenance <tenant> <server> definition versions served + drift log\n  mcp-discover <tenant> <server> <endpoint> [out.json]\n                                   contact a candidate server, record what it\n                                   serves, and write a file to review. Never enrols.
  openapi-enrol <tenant> <api> <openapi.json> [endpoint]
                                   pin an OpenAPI spec's reviewed operations
  agent-grant <tenant> <agent> <tool>...
                                   authorise an agent to invoke tools
  agent-revoke <tenant> <agent> <tool>...
                                   withdraw an agent's tool authorisation
  agent-grants <tenant>            show every agent's granted tools
  agent-inventory <tenant> [class] every agent SEEN, managed or not
  agent-reach <tenant> <kind> <pattern>
                                   which agents reached matching targets
  agent-declare <tenant> <agent> <field> <value>
                                   record what a human asserts about an agent
  agent-undeclare <tenant> <agent> <field>
  agent-fields                     list what may be declared
  agent-entities <tenant>          count every inventoried entity type
  agent-discover <tenant> <namespace>...
                                   list agent workloads the CLUSTER reports,
                                   not the ones that sent telemetry, and
                                   reconcile them against enrolment
  passport-inspect <passport.json> what it says + every keyless check
  passport-verify <passport.json> <key.pem>
                                   signature, key window, structure. Offline.
  agent-effective-reach <tenant> <agent>
                                   what this agent can ACTUALLY reach, and by
                                   what route -- grants are a floor, not a
                                   ceiling
  graph-trace <tenant> <session>   causal trace + sequence findings
  graph-coverage <tenant>          how much activity is traceable
  agent-baseline <tenant> <agent>  what this agent usually does
  preflight                        report EVERY production configuration
                                   problem at once (SENTINEL_ENV=production)
  evidence-reseal <tenant>         seal plaintext evidence; rewrap under the active key
  siem-export <tenant> [cef|ecs] [since]
                                   write the audit trail as SIEM lines on stdout
  backup-preflight                 report PITR readiness (Postgres only)
  backup-help                      print disaster-recovery command outline
"""


def main(argv: Sequence[str] | None = None, *, out: TextIO | None = None) -> int:
    """Run one operator command. Returns a process exit code.

    `out` is a parameter so this is testable without capturing global stdout.
    """
    stream = out or sys.stdout
    args = list(argv if argv is not None else sys.argv[1:])
    if not args or args[0] in {"-h", "--help", "help"}:
        stream.write(USAGE)
        return 0

    # `preflight` is dispatched BEFORE Settings is parsed, and that ordering is
    # the entire point of the command. `Settings.from_environment` raises on the
    # FIRST problem, so a preflight placed after this block would die on that
    # first error -- delivering exactly the one-at-a-time experience the command
    # exists to replace.
    if args[0] == "preflight":
        report = validate_production_configuration()
        stream.write(report.render())
        return 0 if report.ok else 78  # EX_CONFIG

    try:
        settings = Settings.from_environment()
    except ConfigurationError as exc:
        stream.write(f"configuration is invalid: {exc}\n")
        return 78  # EX_CONFIG

    command, rest = args[0], args[1:]
    pool = build_engine(settings.engine)
    try:
        if command == "migrate":
            version = migrate(pool)
            stream.write(
                f"schema at version {version} ({settings.engine.safe_description()})\n"
            )
            return 0

        if command == "verify":
            try:
                version = verify(pool)
            except SchemaOutOfDate as exc:
                stream.write(f"{exc}\n")
                return 1
            stream.write(f"schema at version {version} (expected {CURRENT_VERSION})\n")
            return 0

        if command in {"enrol", "revoke"}:
            if len(rest) < 2:
                stream.write(f"usage: {command} <tenant> <address> [label]\n")
                return 64  # EX_USAGE
            try:
                tenant, address = TenantId(rest[0]), Address(rest[1])
            except InvalidValue as exc:
                stream.write(f"invalid argument: {exc}\n")
                return 64
            registry = SqlAgentRegistry(pool=pool)
            if command == "enrol":
                registry.enrol(
                    tenant,
                    address=address,
                    label=rest[2] if len(rest) > 2 else "",
                    at=SystemClock().now(),
                )
                stream.write(f"enrolled {address} for {tenant}\n")
            else:
                registry.revoke(tenant, address=address)
                stream.write(f"revoked {address} for {tenant}\n")
            return 0

        if command in {"graph-trace", "graph-coverage", "agent-baseline"}:
            return _graph_command(command, rest, pool=pool, stream=stream)

        if command in {"agent-declare", "agent-undeclare", "agent-fields"}:
            return _declare_command(command, rest, pool=pool, stream=stream)

        if command in {"agent-inventory", "agent-reach", "agent-entities"}:
            return _inventory_command(command, rest, pool=pool, stream=stream)

        if command in {"passport-inspect", "passport-verify"}:
            # Dispatched BEFORE the pool is used: verification needs no database
            # and no running Sentinel, which is the whole point of the artifact.
            return passport_command(command, rest, stream=stream)

        if command == "agent-effective-reach":
            return _effective_reach_command(rest, pool=pool, stream=stream)

        if command == "agent-discover":
            return _discover_command(rest, pool=pool, stream=stream, settings=settings)

        if command in {"agent-grant", "agent-revoke", "agent-grants"}:
            return _capability_command(command, rest, pool=pool, stream=stream)

        if command in {"mcp-enrol", "mcp-block", "mcp-list", "mcp-provenance", "mcp-discover", "openapi-enrol"}:
            return mcp_command(command, rest, pool=pool, stream=stream, settings=settings)

        if command == "evidence-reseal":
            return evidence_reseal_command(rest, settings=settings, stream=stream)

        if command == "siem-export":
            return _siem_export(rest, pool=pool, stream=stream)

        if command == "backup-help":
            stream.write(
                "Disaster recovery outline (see docs/OPERATIONS.md):\n"
                "  1. Scale writers to 0\n"
                "  2. Restore base backup + WAL (PostgresBackup.restore_to)\n"
                "  3. python -m sentinel.interface.cli verify\n"
                "  4. Start one API; confirm /health/ready\n"
                "  5. Reap leases; scale workers\n"
                "Live restore drill status: UNVERIFIED until operated.\n"
            )
            return 0

        if command == "backup-preflight":
            dialect = getattr(settings.engine.dialect, "value", str(settings.engine.dialect))
            if dialect != "postgres":
                stream.write(
                    "backup-preflight requires PostgreSQL "
                    f"(current: {settings.engine.safe_description()}). "
                    "Code path covered by tests_arch/test_persistence_backup_pitr.py. "
                    "Live restore drill: UNVERIFIED.\n"
                )
                return 0
            stream.write(
                "Configure PostgresBackup against the live DSN and run preflight(); "
                "see sentinel/infrastructure/persistence/backup.py. "
                "Live restore drill: UNVERIFIED.\n"
            )
            return 0

        stream.write(f"unknown command {command!r}\n\n{USAGE}")
        return 64
    finally:
        pool.close()

def _graph_command(
    command: str, rest: Sequence[str], *, pool: Any, stream: TextIO
) -> int:
    """Read a causal trace, its coverage, or an agent's baseline.

    On the CLI as well as the API because the first question after an incident
    is "what else happened in that session", and an operator with shell access
    should not need a working API and a valid key to answer it during an
    outage -- which is exactly when they will be asking.
    """
    graph_store = SqlExecutionGraph(pool=pool)

    if command == "graph-coverage":
        if len(rest) < 1:
            stream.write("usage: graph-coverage <tenant>\n")
            return 64
        coverage = graph_store.coverage(rest[0]).as_dict()
        stream.write(f"execution graph coverage for {rest[0]}\n")
        stream.write(f"  nodes recorded : {coverage['total_nodes']}\n")
        stream.write(f"  linked         : {coverage['linked_nodes']}\n")
        stream.write(f"  unlinked       : {coverage['unlinked_nodes']}\n")
        stream.write(f"  sessions       : {coverage['sessions']}\n")
        if coverage["total_nodes"] == 0:
            # Said out loud. Zero nodes means either nothing has been sent or
            # nothing is reaching this database, and those need opposite
            # responses.
            stream.write(
                "  -- nothing recorded. Either no events have arrived, or they "
                "are not reaching this database.\n"
            )
        elif coverage["unlinked_nodes"]:
            stream.write(
                f"  -- {coverage['unlinked_nodes']} node(s) arrived with no sessionId "
                "and cannot be placed in a causal chain. Sequence detection "
                "cannot see them.\n"
            )
        return 0

    if command == "agent-baseline":
        if len(rest) < 2:
            stream.write("usage: agent-baseline <tenant> <agent>\n")
            return 64
        baseline = graph_store.baseline_for(rest[0], rest[1]).as_dict()
        stream.write(f"baseline for {rest[1]} in {rest[0]}\n")
        stream.write(f"  sessions observed : {baseline['sessions_observed']}\n")
        stream.write(f"  established       : {baseline['established']}\n")
        if not baseline["established"]:
            # The most important line when it applies. An unestablished
            # baseline produces no deviations for the uninteresting reason,
            # and reading that as "nothing unusual" is exactly backwards for
            # an agent somebody introduced yesterday.
            stream.write(
                "  -- TOO LITTLE HISTORY TO JUDGE. Comparisons against this "
                "baseline will find nothing, and that is not reassurance.\n"
            )
        for label in ("tools", "resources", "destinations", "active_hours"):
            values = baseline[label]
            if values:
                shown = ", ".join(str(v) for v in values[:8])
                more = f" (+{len(values) - 8} more)" if len(values) > 8 else ""
                stream.write(f"  usual {label:<13}: {shown}{more}\n")
        stream.write(
            f"  steps per session : mean {baseline['mean_steps_per_session']}, "
            f"max {baseline['max_steps_per_session']}\n"
        )
        return 0

    # graph-trace
    if len(rest) < 2:
        stream.write("usage: graph-trace <tenant> <session>\n")
        return 64

    graph = graph_store.session(rest[0], rest[1])
    if not len(graph):
        stream.write(f"no session {rest[1]!r} has been observed for {rest[0]}\n")
        return 1

    stream.write(f"session {rest[1]} -- {len(graph)} step(s), agents: {', '.join(graph.agents)}\n")
    for node in graph:
        flag = "!" if node.severity else " "
        stream.write(
            f"{flag} {node.event_id}\t{node.action}\t"
            f"sev={node.severity}\t{node.resource or node.destination or ''}\n"
        )

    matches = detect_sequences(graph)
    if not matches:
        stream.write("no sequence rule matched this session\n")
        return 0

    stream.write("\nSEQUENCE FINDINGS\n")
    for match in matches:
        stream.write(f"  {match.rule.name} (severity {match.severity})\n")
        stream.write(f"    steps : {' -> '.join(n.action for n in match.matched_nodes)}\n")
        stream.write(f"    events: {', '.join(n.event_id for n in match.matched_nodes)}\n")
        stream.write(f"    why   : {match.rule.rationale}\n")
    return 0


def _declare_command(
    command: str, rest: Sequence[str], *, pool: Any, stream: TextIO
) -> int:
    """Record or remove what a human ASSERTS about an agent.

    Separate from `agent-inventory` because these are the only agent facts
    Sentinel cannot work out for itself. Everything the inventory reports is
    measured; everything here was typed by somebody, and the two are kept apart
    in the profile so a guess is never mistaken for a measurement.
    """
    inventory = SqlAgentInventory(pool=pool)

    if command == "agent-fields":
        stream.write("Declarable fields (everything else is observed):\n")
        for name, description in sorted(DECLARABLE_FIELDS.items()):
            stream.write(f"  {name:<22} {description}\n")
        return 0

    if command == "agent-undeclare":
        if len(rest) < 3:
            stream.write("usage: agent-undeclare <tenant> <agent> <field>\n")
            return 64
        removed = inventory.undeclare(rest[0], rest[1], rest[2])
        if not removed:
            # Reported rather than treated as success. "no such field" and "wrong
            # agent id" look identical to an operator otherwise, and the second
            # means their correction did not land.
            stream.write(
                f"{rest[1]} had no {rest[2]!r} declaration in {rest[0]}; "
                "nothing removed. Check the agent id.\n"
            )
            return 1
        stream.write(f"removed {rest[2]} from {rest[1]} in {rest[0]}\n")
        return 0

    if len(rest) < 4:
        stream.write(
            "usage: agent-declare <tenant> <agent> <field> <value>\n"
            "  `agent-fields` lists what may be declared\n"
        )
        return 64

    tenant, agent_id, field = rest[0], rest[1], rest[2]
    value = " ".join(rest[3:])
    try:
        key, stored = inventory.declare(tenant, agent_id, field, value)
    except DeclarationRejected as exc:
        stream.write(f"{exc}\n")
        return 64

    stream.write(f"declared {key}={stored!r} for {agent_id} in {tenant}\n")
    if stored != value.strip():
        # Say so. An operator who typed HIGH and got `high` should learn it now
        # rather than when a filter on "HIGH" returns nothing.
        stream.write(f"  (normalised from {value.strip()!r})\n")

    if inventory.profile(tenant, agent_id) is None:
        # Declaring does not create an agent, and silence here would let a typo
        # in an agent id look like a successful declaration for ever.
        stream.write(
            f"  NOTE: no agent called {agent_id!r} has been observed in "
            f"{tenant}. The declaration is stored and will attach itself if one "
            "appears -- but if that id is a typo, nothing will ever use it.\n"
        )
    return 0


def _inventory_command(
    command: str, rest: Sequence[str], *, pool: Any, stream: TextIO
) -> int:
    """Report discovered agents and answer attack-surface questions.

    Read-only, unlike every other command in this file. It is here rather than
    only on the HTTP API because the first question after an incident is "what
    else does that agent touch", and an operator with shell access should not
    need a working API and a valid key to answer it.
    """
    inventory = SqlAgentInventory(pool=pool)

    if command == "agent-entities":
        if len(rest) < 1:
            stream.write("usage: agent-entities <tenant>\n")
            return 64
        report = inventory.entity_inventory(rest[0])
        stream.write(f"entity inventory for {rest[0]}\n")
        for name, entity in report["entities"].items():
            extra = f"  ({entity['unmanaged']} unmanaged)" if "unmanaged" in entity else ""
            stream.write(
                f"  {name:<24} {entity['count']:>4}  [{entity['source']}]{extra}\n"
            )
        coverage = report["declared_coverage"]
        # Stated because an inventory is only as good as this number: a column
        # of zeroes in the declared half is not an estate with nothing in it,
        # it is one nobody has described.
        stream.write(
            f"  -- {coverage['agents_with_owner']} of {coverage['agents_total']} "
            "agents have a declared owner\n"
        )
        return 0

    if command == "agent-inventory":
        if len(rest) < 1:
            stream.write("usage: agent-inventory <tenant> [managed|unmanaged|revoked_but_active]\n")
            return 64
        wanted = None
        if len(rest) > 1:
            try:
                wanted = AgentClassification(rest[1].strip().lower())
            except ValueError:
                stream.write(
                    f"unknown classification {rest[1]!r}; valid: "
                    f"{', '.join(c.value for c in AgentClassification)}\n"
                )
                return 64

        profiles = inventory.list_profiles(rest[0], classification=wanted)
        if not profiles:
            # Said out loud. An empty inventory means "no agent has sent an
            # event", which for a security product is either a quiet estate or a
            # broken integration -- and those need opposite responses.
            stream.write(
                f"no agents observed for {rest[0]}.\n"
                "Either nothing has sent an event, or events are not reaching "
                "this database. Both look identical here.\n"
            )
            return 0

        for profile in profiles:
            flag = "!" if profile.classification.needs_attention else " "
            trust = profile.trust
            stream.write(
                f"{flag} {profile.name}\t{profile.classification.value}\t"
                f"trust={trust.score}({trust.band})\tevents={profile.event_count}\t"
                f"violations={profile.violation_count}\t"
                f"incidents={profile.incident_count}\tlast_seen={profile.last_seen}\n"
            )
            if profile.credentials:
                stream.write(f"    credentials: {', '.join(profile.credentials)}\n")
            if profile.declared:
                # Printed on its own line and labelled, because these are the
                # only lines in this report that a human asserted rather than
                # Sentinel measuring. Mixing them into the same row as
                # `events=` and `incidents=` would make a guess look like a
                # measurement.
                stream.write(
                    "    declared: "
                    + ", ".join(f"{k}={v}" for k, v in sorted(profile.declared.items()))
                    + "\n"
                )
            if profile.ungranted_tools_used:
                stream.write(
                    f"    used without a grant: "
                    f"{', '.join(profile.ungranted_tools_used)}\n"
                )
            if profile.external_destinations:
                stream.write(
                    f"    sent data to: {', '.join(profile.external_destinations)}\n"
                )
        return 0

    # agent-reach
    if len(rest) < 3:
        stream.write(
            "usage: agent-reach <tenant> <"
            + "|".join(k.value for k in ObservedEdgeKind)
            + "> <pattern>\n"
            "  pattern is a SQL LIKE pattern, e.g. '%pii%' or 'https://%'\n"
        )
        return 64

    try:
        kind = ObservedEdgeKind(rest[1].strip().lower())
    except ValueError:
        stream.write(
            f"unknown edge kind {rest[1]!r}; valid: "
            f"{', '.join(k.value for k in ObservedEdgeKind)}\n"
        )
        return 64

    agents = inventory.agents_reaching(rest[0], kind=kind, pattern=rest[2])
    if not agents:
        stream.write(f"no agent reached a {kind.value} matching {rest[2]!r}\n")
        return 0
    for agent in agents:
        stream.write(f"{agent}\n")
    return 0


def _capability_command(
    command: str, rest: Sequence[str], *, pool: Any, stream: TextIO
) -> int:
    """Grant, revoke and report what an agent may INVOKE.

    CLI-only, for the same reason agent enrolment and MCP enrolment are: this is
    an authorisation decision, and `sentinel/domain/authorization.py` records
    that trust-anchor changes are guarded by shell access to the host rather
    than by a bearer token. A credential that could grant its own capabilities
    would make the grant meaningless.
    """
    store = SqlAgentCapabilities(pool=pool)

    if command == "agent-grants":
        if len(rest) < 1:
            stream.write("usage: agent-grants <tenant>\n")
            return 64
        grants = store.list_grants(rest[0])
        if not grants:
            # Said out loud rather than printing nothing. With enforcement OFF
            # an empty set means "every agent may invoke every tool"; with it ON
            # the same empty set means "no agent may invoke any". Those are
            # opposites, and a blank screen looks identical for both.
            stream.write(
                f"no tool grants recorded for {rest[0]}.\n"
                "With SENTINEL_AGENT_REQUIRE_GRANT unset every agent may invoke "
                "every registered tool; with it set none may invoke any.\n"
            )
            return 0
        for row in grants:
            stream.write(
                f"{row['agent_id']}\t{row['tool_name']}\t{row['granted_at']}\n"
            )
        return 0

    if len(rest) < 3:
        stream.write(f"usage: {command} <tenant> <agent> <tool> [tool...]\n")
        return 64

    tenant, agent_id, tools = rest[0], rest[1], frozenset(rest[2:])
    if command == "agent-grant":
        store.grant(tenant, agent_id, tools)
        verb = "granted"
    else:
        store.revoke(tenant, agent_id, tools)
        verb = "revoked"

    stream.write(f"{verb} {', '.join(sorted(tools))} for {agent_id} in {tenant}\n")
    remaining = sorted(store.granted(tenant, agent_id))
    # The resulting set, not just the delta. An operator revoking one capability
    # needs to see what the agent can still do, and a message that reports only
    # the change invites the assumption that nothing else remains.
    stream.write(f"  now granted: {', '.join(remaining) or '(none)'}\n")
    return 0


def _siem_export(
    rest: Sequence[str], *, pool: Any, stream: TextIO
) -> int:
    """Write one tenant's audit trail to stdout as SIEM lines.

    Stdout rather than a network push. A built-in pusher would need credentials,
    retry policy and a delivery guarantee, and getting those wrong means
    silently dropping security events -- the failure this product exists to
    prevent. Every SIEM already ingests a line stream, so piping to a collector
    that solves delivery properly is both the smaller claim and the safer one:

        python -m sentinel.interface.cli siem-export acme cef | logger -t sentinel

    The read is tenant-scoped on the connection AND in the predicate. On SQLite
    there is no row-level security, so the predicate is the only boundary; an
    export that quietly emitted another tenant's audit trail into a shared SIEM
    would be a cross-tenant disclosure that looks like a successful run.
    """
    if not rest:
        stream.write("usage: siem-export <tenant> [cef|ecs] [since-iso8601]\n")
        return 64  # EX_USAGE

    tenant = rest[0]
    fmt = (rest[1] if len(rest) > 1 else "cef").strip().lower()
    if fmt not in SUPPORTED_FORMATS:
        stream.write(
            f"unknown format {fmt!r}; supported: {', '.join(SUPPORTED_FORMATS)}\n"
        )
        return 64
    since = rest[2] if len(rest) > 2 else ""

    with pool.acquire() as conn:
        conn.begin()
        conn.set_tenant(tenant)
        p = conn.p
        if since:
            rows = conn.execute(
                f"SELECT * FROM security_audit WHERE tenant_id={p} "
                f"AND occurred_at >= {p} ORDER BY seq",
                (tenant, since),
            )
        else:
            rows = conn.execute(
                f"SELECT * FROM security_audit WHERE tenant_id={p} ORDER BY seq",
                (tenant,),
            )
        conn.commit()

    events = [SiemEvent.from_audit_row(dict(row)) for row in rows]
    for line in render(events, fmt=fmt):
        stream.write(line + "\n")

    # The count goes to stderr, never stdout: stdout is the event stream, and a
    # summary line mixed into it becomes a malformed event in the SIEM.
    # `sys.stderr.write` rather than `print(file=...)` because the architecture
    # rule forbids print() outright -- a bare print is how output ends up on
    # stdout by accident, which here would mean corrupting the export.
    sys.stderr.write(f"exported {len(events)} audit events for {tenant}\n")
    return 0


def _discover_command(
    rest: Sequence[str], *, pool: Any, stream: TextIO, settings: Settings
) -> int:
    """Ask the cluster what is running, rather than asking the telemetry.

    WHY THIS IS A CLI COMMAND AND NOT A ROUTE
    -------------------------------------------
    It reads with the deployment's Kubernetes credential across whole
    namespaces. That is a broader read than anything the HTTP surface does, and
    the codebase already puts operations of that weight behind shell access to
    the host rather than behind a bearer token -- MCP enrolment is CLI-only for
    the same reason. An analyst who can call `/v1/incidents` should not thereby
    be able to enumerate every workload in production.

    The report is printed with its SCOPE and its HOLES, never as a bare list.
    "We found two agents" and "we found two agents in the one namespace we could
    read, out of forty" are different statements, and only the second is true.
    """
    if len(rest) < 2:
        stream.write("usage: agent-discover <tenant> <namespace>...\n")
        return 64  # EX_USAGE

    tenant, namespaces = rest[0], list(rest[1:])
    configured = settings.platform_adapters.get("kubernetes")
    if configured is None:
        # NOT_SUPPORTED, said plainly. A deployment with no cluster credential
        # cannot do this, and printing an empty result would read as "nothing is
        # running" -- the single most dangerous wrong answer this command has.
        stream.write(
            "agent-discover needs a Kubernetes credential "
            "(SENTINEL_KUBERNETES_API_SERVER and SENTINEL_KUBERNETES_TOKEN). "
            "None is configured, so nothing was examined. This is NOT_SUPPORTED "
            "for this deployment, not an empty cluster.\n"
        )
        return 78  # EX_CONFIG

    report = discover_kubernetes_workloads(
        client=HardenedHttpClient(
            policy=OutboundPolicy(
                allow_private_destinations=True,
                allowed_hosts=settings.tool_http_allowed_hosts,
            )
        ),
        credentials=KubernetesCredentials(
            api_server=configured["api_server"], token=configured["token"]
        ),
        namespaces=namespaces,
    )

    inventory = SqlAgentInventory(pool=pool)
    try:
        enrolled = tuple(
            str(getattr(profile, "agent_id", "") or "")
            # Was `inventory.agents(tenant)`, which never existed; the broad
            # except below made it report zero enrolled agents in silence.
            for profile in inventory.list_profiles(tenant)
        )
    except Exception as exc:  # noqa: BLE001 - reconciliation is best-effort
        enrolled = ()
        stream.write(f"note: enrolment could not be read ({type(exc).__name__}); "
                     "every workload below is reported as unreconciled\n")

    classified = reconcile(report, enrolled=enrolled)

    stream.write(f"examined {report.examined} workloads in {len(report.scope)} namespace(s)\n")
    for workload in report.workloads:
        kind = classified.get(workload.agent_id)
        confidence = "declared" if workload.identity_is_declared else "inferred from name"
        stream.write(
            f"  {workload.location:44s} {getattr(kind, 'value', 'unknown'):20s} "
            f"({confidence}; {', '.join(workload.markers)})\n"
        )
    if not report.workloads:
        stream.write("  no workload carried an agent marker\n")

    for target, reason in report.unreachable:
        stream.write(f"  UNREACHABLE {target}: {reason}\n")

    stream.write("\n" + report.limits + "\n")
    # A run that could not read part of its scope is not a clean run, and the
    # exit code says so -- a script that greps the output would otherwise treat
    # a half-read cluster as a pass.
    return 0 if not report.unreachable else 1


def _effective_reach_command(rest: Sequence[str], *, pool: Any, stream: TextIO) -> int:
    """What an agent can ACTUALLY reach, and by what route.

    `agent-reach` answers "which agents touched matching targets". This answers
    the access-review question instead: given everything recorded, what is
    within this agent's reach whether or not a grant says so.

    The grant table is a FLOOR, not a ceiling. An agent holds scopes through
    delegation with no grant row existing, and two agents presenting the same
    credential are one principal to every system downstream -- a fact that lives
    in the pairing of two innocent rows and appears nowhere on its own.

    Every line prints the ROUTE, because that is the actionable part: revoking a
    grant does nothing when the reach came from a shared credential.
    """
    if len(rest) < 2:
        stream.write("usage: agent-effective-reach <tenant> <agent>\n")
        return 64  # EX_USAGE

    tenant, agent_id = rest[0], rest[1]

    # `list_grants` returns one row per (agent, tool); fold them into the
    # agent -> capabilities shape the closure takes.
    # `tool_name`, not `tool`. Reading the wrong key returns "" for every row,
    # which folds to an empty grant map and prints "nothing reachable" for an
    # agent that holds grants -- a silently WRONG access review rather than a
    # failed one. Found by running the command, not by reading the code.
    folded: dict[str, list[str]] = {}
    for row in SqlAgentCapabilities(pool=pool).list_grants(tenant):
        tool = str(row.get("tool_name", ""))
        if tool:
            folded.setdefault(str(row.get("agent_id", "")), []).append(tool)

    reach = compute_effective_reach(agent_id, grants={k: tuple(v) for k, v in folded.items()})

    stream.write(
        f"{agent_id}: {len(reach.capabilities)} reachable "
        f"({len(reach.direct)} granted, {len(reach.indirect)} indirect), "
        f"concern {reach.concern}\n"
    )
    for path in reach.paths:
        route = " -> ".join(path.via) if path.via else "direct"
        stream.write(f"  {path.capability:28s} {path.source.value:18s} {route}\n")
    if not reach.paths:
        stream.write("  nothing reachable from the recorded facts\n")
    for chain in reach.truncated_at:
        stream.write(f"  TRUNCATED beyond the hop limit: {chain}\n")

    # NOT a clean bill of health, and the output says so rather than leaving a
    # reader to infer it from an empty list.
    stream.write("\n" + reach.limits + "\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - process entry point
    raise SystemExit(main())
