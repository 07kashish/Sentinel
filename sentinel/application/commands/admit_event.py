"""The single admission path. Every event that becomes an incident passes here.

WHY THIS IS ONE HANDLER AND NOT SIX ROUTES
------------------------------------------
The predecessor had six HTTP endpoints that reached the pipeline:
`/events/ingest`, `/ingest-event`, `/analyze`, `/ingest/agent-tool-call`,
`/ingest/prompt-event` and `/ingest/wallet-event`. Exactly one of them performed
identity verification, replay defence, content-addressed deduplication, and
policy evaluation with the unverified-severity cap.

The other five called `build_base_incident(..., severity=event.severity)` with
the client's own number and enqueued it. An `ingest`-role key — documented as
"write telemetry only… this is what an instrumented agent gets" — could POST
`severity: 100` and manufacture a CRITICAL incident, bypassing every control the
cap existed to provide.

The cause was not that five routes forgot a check. It was that the checks lived
in a route instead of in an admission use case, so writing a new route meant
re-deriving the entire security posture from scratch, and nothing failed when a
new route got it wrong.

Here the routes are payload adapters. They normalise a shape and dispatch this
command. There is no other way to create an incident, `Incident.admit` applies
the trust cap in the domain, and `tests_arch/test_architecture_rules.py` fails
the build if any interface module constructs an `Incident` directly.

ORDER OF OPERATIONS
-------------------
Verify identity, then check replay, then deduplicate, then evaluate policy, then
admit. Each step's output feeds the next, and every one of them can refuse — an
admission that is refused writes nothing to the incident store, so a rejected
event cannot appear as a half-formed incident.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from sentinel.application.messages import Command, Result
from sentinel.application.ports import (
    AgentObserver,
    AgentRegistry,
    ExecutionRecorder,
    Clock,
    DetectionPolicy,
    IdentityVerifier,
    IdGenerator,
    Logger,
    ReplayGuard,
    UnitOfWorkFactory,
    WorkQueue,
)
from sentinel.domain.incident import Incident
from sentinel.domain.execution_graph import (
    MAX_NODE_TEXT,
    ExecutionNode,
    NodeKind,
)
from sentinel.domain.inventory import ObservedEdgeKind
from sentinel.domain.baseline import (
    assess_intent_divergence,
    compare_to_baseline,
)
from sentinel.domain.sequences import (
    could_complete_a_sequence,
    detect_sequences,
)
from sentinel.domain.primitives import Severity, Timestamp, TrustLevel

__all__ = ["AdmitEvent", "AdmitEventHandler"]


@dataclass(frozen=True, slots=True)
class AdmitEvent(Command):
    """An event offered for admission. Carries no trust: everything is verified."""

    payload: Mapping[str, Any] = field(default_factory=dict)
    signature: str | None = None
    source: str = "unknown"
    #: Set only by internal producers (simulation, replay). Never client-settable.
    trusted_source: bool = False
    #: A short fingerprint of the CREDENTIAL this event arrived under, set by the
    #: interface layer from the authenticated principal and never by the client.
    #:
    #: It is the link the attack-surface chain was missing -- Human -> Agent ->
    #: CREDENTIAL -> Tool -- and it answers the question a compromise actually
    #: starts with: if this key leaked, which agents are affected. A prefix of a
    #: hash, never key material.
    credential: str = ""


class AdmitEventHandler:
    """Verify, deduplicate, evaluate and admit. One reason to change.

    Every collaborator is injected. There are no module-level lookups, no
    `os.getenv` at call time, and no import-time configuration — so this handler
    can be exercised with in-memory doubles and no database, which is what
    "independently testable" has to mean.
    """

    __slots__ = (
        "_uow_factory",
        "_agents",
        "_inventory",
        "_graph",
        "_identity",
        "_replay",
        "_policy",
        "_queue",
        "_clock",
        "_ids",
        "_logger",
    )

    def __init__(
        self,
        *,
        uow_factory: UnitOfWorkFactory,
        agents: AgentRegistry,
        identity: IdentityVerifier,
        inventory: AgentObserver | None = None,
        graph: ExecutionRecorder | None = None,
        replay: ReplayGuard,
        policy: DetectionPolicy,
        queue: WorkQueue,
        clock: Clock,
        ids: IdGenerator,
        logger: Logger,
    ) -> None:
        self._uow_factory = uow_factory
        self._agents = agents
        # Optional so every existing construction keeps working. `None` means
        # discovery is not recording -- which is the state this product was in
        # before, and the reason an unenrolled agent left no trace at all.
        self._inventory = inventory
        self._graph = graph
        self._identity = identity
        self._replay = replay
        self._policy = policy
        self._queue = queue
        self._clock = clock
        self._ids = ids
        self._logger = logger

    def handle(self, command: AdmitEvent) -> Result:
        now = self._clock.now()
        tenant = command.tenant

        # 1. Identity. An unsigned event is still admitted for visibility, but
        #    its self-reported fields are not authoritative and the domain caps
        #    its severity accordingly.
        enrolled = self._agents.enrolled_addresses(tenant)
        identity = self._identity.verify(
            payload=command.payload, signature=command.signature, enrolled=enrolled
        )
        digest = self._identity.digest(command.payload)

        # Observed contact from a verified enrolled agent. Silence detection
        # (possible_bypass) depends on this; agents that never call remain invisible.
        if identity.trust is TrustLevel.VERIFIED and identity.address is not None:
            self._agents.record_event(tenant, address=identity.address, at=now)

        # 2. Replay. Only signed events are checked: a valid signature proves
        #    authorship, never freshness, and an unsigned event is already
        #    non-authoritative so content dedupe below is sufficient for it.
        if identity.trust is TrustLevel.VERIFIED and identity.address is not None:
            claimed_at = self._claimed_timestamp(command.payload)
            accepted, reason = self._replay.check_and_consume(
                tenant=tenant,
                agent=identity.address,
                event_digest=digest,
                claimed_at=claimed_at,
                now=now,
            )
            if not accepted:
                self._logger.warning(
                    "replay_rejected", tenant=str(tenant), digest=digest.value, reason=reason
                )
                return Result.refused("replay_rejected", reason=reason, event_digest=digest.value)

        # 3. Policy. The raw verdict; the trust cap is applied by the domain.
        verdict = self._policy.evaluate(payload=command.payload, trust=identity.trust)

        # DISCOVERY. Recorded for EVERY event that reaches here, whatever its
        # trust and whether or not the agent was ever enrolled -- which is the
        # difference between this and `record_event` above.
        #
        # `record_event` issues `UPDATE agents ... WHERE address=?`, so for an
        # agent nobody enrolled it updates zero rows and the agent leaves no
        # trace. Demonstrated on a live build: an unenrolled agent sent one
        # event, Sentinel raised a HIGH severity incident about it, and the
        # `agents` table stayed empty.
        #
        # Placed AFTER the verdict rather than before it so `violation` is a
        # fact rather than a guess: an event that tripped policy is a violation
        # whether or not it went on to become an incident, and counting only
        # incidents undercounts exactly the cases where enforcement worked.
        #
        # Failure here must never reject an event. Discovery is visibility, not
        # enforcement: losing an inventory row is a degraded inventory, while
        # losing the event is a blind spot in the thing this product is for.
        if self._inventory is not None:
            try:
                self._inventory.observe(
                    str(tenant),
                    self._claimed_agent(command.payload),
                    at=now.isoformat(),
                    edges=_observed_edges(command.payload, command.credential),
                    violation=verdict.fired,
                )
            except Exception as exc:  # noqa: BLE001 - visibility must not gate ingest
                self._logger.warning(
                    "agent_discovery_failed",
                    tenant=str(tenant),
                    error=str(exc)[:200],
                )
        # THE EXECUTION GRAPH. One node per admitted event, carrying what the
        # step did and what Sentinel decided about it.
        #
        # Recorded here rather than beside the inventory above because the
        # verdict is what makes a node useful during an investigation: a trace
        # showing six actions is a list, and a trace showing six actions with
        # the severity each one drew is a story. `verdict` exists by this point
        # and does not before it.
        #
        # Same failure posture as discovery: a node that cannot be written
        # degrades a causal trace, while an event that cannot be admitted is a
        # blind spot in the product itself.
        if self._graph is not None:
            try:
                payload = command.payload
                metadata = payload.get("metadata")
                metadata = metadata if isinstance(metadata, Mapping) else {}
                self._graph.record(
                    ExecutionNode(
                        tenant_id=str(tenant),
                        event_id=str(payload.get("eventId") or digest.value[:32]),
                        agent_id=self._claimed_agent(payload),
                        session_id=str(payload.get("sessionId") or ""),
                        parent_id=str(payload.get("parentEventId") or ""),
                        kind=NodeKind.of(str(payload.get("eventType") or "")),
                        occurred_at=now.isoformat(),
                        action=str(payload.get("action") or ""),
                        resource=str(payload.get("resource") or ""),
                        destination=str(payload.get("destination") or ""),
                        tool=str(payload.get("tool") or metadata.get("tool") or ""),
                        credential=command.credential,
                        principal=str(metadata.get("principal") or ""),
                        policy=verdict.detector_version,
                        # The instruction text the step carried. THIS is what
                        # makes "the document contained an injected
                        # instruction" a visible step: without it a reader sees
                        # the agent change behaviour and cannot see why.
                        #
                        # Truncated -- attacker-supplied text that ends up in an
                        # API response and a CLI table -- and never used for a
                        # decision. `ProtectGate` already read the same field
                        # and reached its own verdict; storing it here is for
                        # the human reading the trace afterwards.
                        input_text=str(metadata.get("prompt") or "")[:MAX_NODE_TEXT],
                        output_text=str(
                            metadata.get("output") or metadata.get("result") or ""
                        )[:MAX_NODE_TEXT],
                        approval_id=str(metadata.get("approvalId") or "")[:128],
                        decision="fired" if verdict.fired else "clean",
                        # `.value`, not `int(...)`. `Severity` is a value object
                        # with an int inside, and `int()` on it raises -- which
                        # the fail-safe caught and logged as
                        # `execution_graph_record_failed` while the event was
                        # still admitted, exactly as intended. The trace was
                        # lost; the security decision was not.
                        severity=verdict.severity.value if verdict.fired else 0,
                    )
                )
            except Exception as exc:  # noqa: BLE001 - visibility must not gate ingest
                self._logger.warning(
                    "execution_graph_record_failed",
                    tenant=str(tenant),
                    error=str(exc)[:200],
                )

        # PLACED BEFORE THE `not verdict.fired` RETURN BELOW, and that
        # ordering is the entire point. Recorded after it, the graph would
        # contain ONLY events that already tripped the detector -- and the
        # reason the graph exists is that individually-innocuous steps form
        # dangerous sequences. A trace of six ordinary actions is what makes
        # `read -> compress -> upload` visible; a trace of the one action
        # that already fired can never find anything the detector missed.
        #
        # Measured, not assumed: with the hook after the return, the
        # specification's own six-step attack story recorded ONE node.

        # SEQUENCE ESCALATION. The only place in this handler where the graph
        # changes an outcome, and the reason it is worth the cost.
        #
        # Five of the six steps in the specification's attack story score ZERO
        # individually. If a matched sequence only produced a log line, the
        # exfiltration would be detected and invisible -- so a match ADMITS an
        # incident even when the per-event verdict found nothing, and raises the
        # severity when it found something smaller.
        #
        # WHAT THIS DELIBERATELY DOES NOT DO: reach `ProtectGate`. Correlation
        # is self-reported -- an agent chooses its own `parentEventId` -- so a
        # forged chain could raise an incident for a human to read, and can
        # never cause a request to be blocked. Evidence, never authority.
        #
        # The graph is read only when the incoming action could COMPLETE a rule.
        # Detection is O(session) per event, so running it on every event makes
        # a session quadratic in its own length, and for any step that is not a
        # rule's last one the answer cannot have changed.
        sequence_matches: tuple[Any, ...] = ()
        session_id = str(command.payload.get("sessionId") or "")
        if (
            self._graph is not None
            and session_id
            and could_complete_a_sequence(str(command.payload.get("action") or ""))
        ):
            try:
                sequence_matches = detect_sequences(
                    self._graph.session(str(tenant), session_id)
                )
            except Exception as exc:  # noqa: BLE001 - detection must not gate ingest
                self._logger.warning(
                    "sequence_detection_failed",
                    tenant=str(tenant),
                    session=session_id[:64],
                    error=str(exc)[:200],
                )

        # BASELINE DEVIATION AND INTENT DIVERGENCE.
        #
        # Both were built in Phase 3, both had tests, and NEITHER had a caller --
        # `compare_to_baseline` and `assess_intent_divergence` were reachable
        # from nothing, so an agent could depart from its own history or
        # contradict its declared intent and no part of the running system would
        # notice. `tests_arch/test_components_are_reachable.py` now fails the
        # build on that.
        #
        # EVIDENCE, NEVER AUTHORITY, AND WEAKER THAN A SEQUENCE RULE
        # ------------------------------------------------------------
        # A baseline is built from the agent's OWN history, so a patient
        # attacker can drift one, and intent is a string the agent writes. Both
        # are therefore attached as findings and allowed to RAISE the severity of
        # an incident that some other signal already justified -- they never
        # raise one alone.
        #
        # That restraint is deliberate and is the difference between this and an
        # alert nobody reads. This codebase measured a detector firing on 51.7%
        # of ordinary tool calls; "this agent did something it has not done
        # before" is true of most legitimate sessions on most days.
        baseline_findings: tuple[Any, ...] = ()
        intent_finding: Any = None
        if self._graph is not None and session_id:
            try:
                baseline_findings, intent_finding = self._assess_behaviour(
                    tenant=str(tenant),
                    agent_id=str(command.payload.get("agentId") or ""),
                    session_id=session_id,
                    declared_intent=str(command.payload.get("declaredIntent") or ""),
                )
            except Exception as exc:  # noqa: BLE001 - intelligence must not gate ingest
                self._logger.warning(
                    "baseline_assessment_failed",
                    tenant=str(tenant),
                    session=session_id[:64],
                    error=str(exc)[:200],
                )

        sequence_severity = max(
            (match.severity for match in sequence_matches), default=0
        )
        effective_severity = verdict.severity
        if sequence_severity > effective_severity.value:
            # The domain still applies the unverified-trust cap below, so an
            # unsigned event cannot manufacture a CRITICAL incident by claiming
            # a chain -- the cap that protects per-event severity protects this
            # too, and for the same reason.
            effective_severity = Severity(sequence_severity)

        if not verdict.fired and not sequence_matches:
            return Result.accepted(
                "no_incident", event_digest=digest.value, detector_version=verdict.detector_version
            )


        # 4. Admit and enqueue in ONE transaction. Returning from this handler
        #    means both the incident row and its queue item are committed, so a
        #    caller may truthfully be told the work is queued. The predecessor
        #    created the incident and enqueued it in two transactions, with the
        #    enqueue deferred until after the response was written.
        incident_id = self._ids.incident_id()
        with self._uow_factory.begin(tenant) as uow:
            incident = Incident.admit(
                tenant_id=tenant,
                incident_id=incident_id,
                severity=effective_severity,
                trust_level=identity.trust,
                source=command.source,
                now=now,
                event_digest=digest,
                facts={
                    "detector_version": verdict.detector_version,
                    "incident_type": verdict.incident_type,
                    "description": verdict.description,
                    "matched_rules": list(verdict.matched_rules),
                    "detection_signals": dict(verdict.signals),
                    "trust_reason": identity.reason,
                    "signer_address": identity.address.value if identity.address else None,
                    "raw_payload": dict(command.payload),
                    # The matched steps travel WITH the incident. An
                    # analyst's first question is "which events", and a
                    # finding that cannot be checked is an opinion.
                    "sequence_findings": [m.as_dict() for m in sequence_matches],
                    # Section-32 approval context reads these, and an analyst
                    # opening an incident sees WHY it was unusual, not only that
                    # a rule matched.
                    "baseline_deviations": [d.as_dict() for d in baseline_findings],
                    "intent_divergence": (
                        intent_finding.as_dict() if intent_finding is not None else None
                    ),
                    "session_id": session_id,
                },
            )
            uow.incidents.add(incident)
            self._queue.submit(
                tenant=tenant,
                incident_id=incident_id,
                payload={"event_digest": digest.value},
                priority=incident.priority.value,
                uow=uow,
            )
            uow.collect(incident.pull_events())
            uow.commit()

        self._logger.info(
            "incident_admitted",
            tenant=str(tenant),
            incident_id=incident_id.value,
            severity=incident.severity.value,
            priority=incident.priority.value,
            trust=identity.trust.value,
            capped=incident.fact("severity_capped"),
        )
        return Result.accepted(
            "incident_admitted",
            incident_id=incident_id.value,
            severity=incident.severity.value,
            priority=incident.priority.value,
            trust_level=identity.trust.value,
            severity_capped=bool(incident.fact("severity_capped")),
        )

    # ── helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _claimed_agent(payload: Mapping[str, Any]) -> str:
        """The agent id the event CLAIMS, used for discovery only.

        Self-reported and therefore not authoritative -- which is exactly why it
        is safe to record here and would not be safe to act on. An unsigned
        event can claim any id it likes, so a discovered agent is evidence that
        SOMETHING is using that name, never proof of who.

        That asymmetry is the point of separating discovery from enrolment: the
        inventory reports what turned up, `identity.verify` decides who is
        trusted, and an attacker who forges an id gets themselves listed as an
        unmanaged agent rather than promoted to a managed one.
        """
        for key in ("agentId", "agent_id", "agent"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return ""

    @staticmethod
    def _claimed_timestamp(payload: Mapping[str, Any]) -> Timestamp | None:
        raw = payload.get("timestamp")
        if not isinstance(raw, str) or not raw.strip():
            return None
        try:
            return Timestamp.parse(raw)
        except Exception:  # noqa: BLE001
            # A malformed client timestamp is not a reason to refuse the event;
            # it is a reason to treat it as absent, which the replay guard
            # handles by falling back to its own freshness window.
            return None


    def _assess_behaviour(
        self, *, tenant: str, agent_id: str, session_id: str, declared_intent: str
    ) -> tuple[tuple[Any, ...], Any]:
        """Compare this session against the agent's history and its declaration.

        `exclude_session` is the load-bearing argument. Comparing a session
        against a baseline that INCLUDES it guarantees nothing looks unusual:
        the anomalous tool is in the "usual tools" set because this session put
        it there. Every deviation would be absorbed by the thing meant to detect
        it -- a gate that cannot fire.
        """
        if self._graph is None:
            # A method cannot rely on its caller's guard. Returning empty is
            # correct here: no recorder means no history to compare against,
            # which is the absence of evidence rather than the absence of
            # deviation. An `assert` would be wrong twice -- the architecture
            # rules ban it for runtime invariants because -O strips it.
            return (), None

        graph = self._graph.session(tenant, session_id)
        facts = _session_facts(graph)

        divergence = (
            assess_intent_divergence(
                declared_intent,
                actions=facts["actions"],
                resources=facts["resources"],
                destinations=facts["destinations"],
            )
            if declared_intent
            else None
        )

        baseline_for = getattr(self._graph, "baseline_for", None)
        if baseline_for is None:
            # The recorder in use does not build baselines. Reported rather than
            # skipped silently, because "no deviations" and "nothing looked"
            # are different answers and only one of them is reassuring.
            return (), divergence

        baseline = baseline_for(tenant, agent_id, exclude_session=session_id)
        if not baseline.is_established:
            # Too little history to say anything is unusual. Comparing against
            # two prior sessions makes every third session anomalous.
            return (), divergence

        deviations = compare_to_baseline(
            baseline,
            tools=facts["tools"],
            resources=facts["resources"],
            destinations=facts["destinations"],
            mcp_servers=(),
            credentials=(),
            users=(),
            spawned_agents=(),
            privileged_actions=(),
            query_patterns=(),
            workflows=(),
            step_count=len(facts["actions"]),
            hour=-1,
        )
        return tuple(deviations), divergence


def _observed_edges(
    payload: Mapping[str, Any], credential: str = ""
) -> tuple[tuple[ObservedEdgeKind, str], ...]:
    """Project an event onto attack-surface edges.

    Only fields the event actually carries. There is no HUMAN or CLOUD
    ENVIRONMENT edge because Sentinel does not observe those, and a graph with
    invented nodes answers "which agents can reach production" wrongly in the
    direction that gets somebody hurt.

    `destination` is the edge that matters most: it is what answers "can this
    agent send data out", and it is the only one of these that describes where
    data GOES rather than what was touched.
    """
    if not isinstance(payload, Mapping):
        return ()

    metadata = payload.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}

    candidates: list[tuple[ObservedEdgeKind, Any]] = [
        (ObservedEdgeKind.ACTION, payload.get("action")),
        (ObservedEdgeKind.RESOURCE, payload.get("resource")),
        (ObservedEdgeKind.DESTINATION, payload.get("destination")),
        (ObservedEdgeKind.TOOL, payload.get("tool") or metadata.get("tool")),
        (ObservedEdgeKind.MCP_SERVER, metadata.get("mcp_server_id")),
        # From the authenticated principal, never from the payload -- a client
        # that could name its own credential could attribute its traffic to
        # somebody else's key and make a compromise unscopeable.
        (ObservedEdgeKind.CREDENTIAL, credential),
    ]
    return tuple(
        (kind, str(value).strip())
        for kind, value in candidates
        if isinstance(value, (str, int, float)) and str(value).strip()
    )


def _session_facts(graph: Any) -> dict[str, list[str]]:
    """Collapse a session's nodes into the axes a baseline compares on.

    Kept module-level and pure so the mapping from nodes to axes can be tested
    without a handler, a database or a container.
    """
    facts: dict[str, list[str]] = {
        "tools": [],
        "resources": [],
        "destinations": [],
        "actions": [],
    }
    for node in graph:
        if node.tool:
            facts["tools"].append(node.tool)
        if node.resource:
            facts["resources"].append(node.resource)
        if node.destination:
            facts["destinations"].append(node.destination)
        if node.action:
            facts["actions"].append(node.action)
    return facts
