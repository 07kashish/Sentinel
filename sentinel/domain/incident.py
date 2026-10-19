"""The Incident aggregate and its lifecycle. The heart of the domain.

WHY THIS EXISTS IN THIS SHAPE
-----------------------------
The predecessor's lifecycle was already good: states were an enum, edges were a
fixed table, and each state declared facts that had to be durable before entry.
It is the one module of that architecture worth carrying forward, and most of
what follows is its design.

Three things are different, and each closes a defect the old shape permitted.

**1. `COMPLETED` no longer exists.**

The old `_REQUIRED_FACTS[COMPLETED]` demanded that `attestation_status` be
*non-empty*. `publish_attestation` returned the string `"Skipped"` both when an
agent had no verified identity (deterministic, will never succeed) and when the
attestation gateway was unreachable (transient, would succeed on retry). Both
satisfied "non-empty", so both reached COMPLETED with `is_anchored=false`.

A transient RPC outage therefore produced an incident indistinguishable from a
successfully attested one -- in a product whose entire proposition is
non-repudiable attestation, at the one moment a buyer needs it.

The fix is not a check before the transition. It is that the three outcomes are
now three different things:

    ANCHORED        -> ATTESTED -> COMPLETED_ATTESTED   (terminal, success)
    NOT_ANCHORABLE  -> COMPLETED_UNATTESTED             (terminal, honest)
    UNAVAILABLE     -> ATTESTATION_UNAVAILABLE          (NOT TERMINAL, resumable)

`ATTESTATION_UNAVAILABLE` being non-terminal is the load-bearing part: a
transient failure cannot reach any completed state, so a retry resumes into the
attestation stage instead of finding a finished incident. There is no string a
caller can pass that collapses the second and third cases, because the
disposition is an enum on a value object rather than a status string.

**2. Fencing is a required argument, not a defaulted one.**

The old `repository.transition(..., epoch: int | None = None)` skipped the fence
when epoch was None, and `repository.fail()` -- a transition under another name --
defaulted it. Two call sites (`pipeline._terminalise` and
`main._handle_pipeline_failure`) therefore wrote unfenced, in the same codebase
whose module docstring asserted "a helper that can be called without the epoch is
a call site that will eventually be called without it". No AST guard enforcing
that assertion ever existed.

Here every mutator takes a `Fence` as a required keyword argument. Running
unfenced is still possible -- maintenance jobs legitimately need it -- but it
must be spelled `Fence.unfenced(reason=...)`, which is greppable, reviewable, and
carries its own justification. An omission is a TypeError at the call site.

**3. Facts are validated by predicate, not by emptiness.**

`check_transition` used to test `known_facts.get(fact) not in (None, "", [])`, so
`report_id="r"` satisfied REPORTED. The repository later added artifact-existence
proofs inside the transition transaction, which fixed the instance. Here the
requirement is a predicate over the merged facts, so a state can demand that a
value be *correct*, not merely present.

PURITY
------
This module imports nothing outside `sentinel.domain`. No I/O, no clock, no
database, no framework. Time is passed in. That is what makes every rule here
testable without a fixture, and what makes it impossible for a storage change to
alter a business rule.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping

from sentinel.domain.attestation import AttestationDisposition, AttestationOutcome
from sentinel.domain.errors import (
    ExecutionFenceLost,
    IllegalTransition,
    MissingRequiredFact,
)
from sentinel.domain.events import (
    AttestationRecorded,
    DomainEvent,
    EvidenceStored,
    IncidentAdmitted,
    IncidentClosedWithoutAction,
    IncidentCompleted,
    IncidentFailed,
    IncidentStateChanged,
    ReportStored,
)
from sentinel.domain.primitives import (
    Digest,
    IncidentId,
    Priority,
    Severity,
    TenantId,
    Timestamp,
    TrustLevel,
)

__all__ = [
    "AttestationDisposition",
    "AttestationOutcome",
    "Fence",
    "Incident",
    "IncidentState",
    "allowed_next",
    "required_facts",
]


class IncidentState(str, Enum):
    """Every state an incident may occupy. There are no others."""

    RECEIVED = "received"
    VALIDATED = "validated"
    IDENTITY_CHECKED = "identity_checked"
    REPLAY_CHECKED = "replay_checked"
    POLICY_EVALUATED = "policy_evaluated"
    DETECTED = "detected"
    INVESTIGATED = "investigated"
    EVIDENCE_STORED = "evidence_stored"
    REPORTED = "reported"
    AWAITING_APPROVAL = "awaiting_approval"

    # The external anchor exists. Provable, third-party-timestamped.
    ATTESTED = "attested"

    # The gateway could not be reached. TRANSIENT AND NON-TERMINAL: the incident
    # is parked here and a retry resumes into the attestation stage. This state
    # is the structural reason a transient outage can no longer masquerade as a
    # completed incident.
    ATTESTATION_UNAVAILABLE = "attestation_unavailable"

    # Terminal. Attestation succeeded and was anchored.
    COMPLETED_ATTESTED = "completed_attested"

    # Terminal. Attestation was DETERMINISTICALLY impossible -- no verified agent
    # identity, or no attestation capability is configured. Honest and distinct:
    # a dashboard can never present this as an attested incident, because it is
    # not the same value.
    COMPLETED_UNATTESTED = "completed_unattested"

    FAILED = "failed"
    CLOSED_NO_ACTION = "closed_no_action"

    @property
    def is_terminal(self) -> bool:
        return self in _TERMINAL

    @property
    def is_attested(self) -> bool:
        """True only when an external anchor provably exists."""
        return self in {IncidentState.ATTESTED, IncidentState.COMPLETED_ATTESTED}


_TERMINAL: frozenset[IncidentState] = frozenset(
    {
        IncidentState.COMPLETED_ATTESTED,
        IncidentState.COMPLETED_UNATTESTED,
        IncidentState.FAILED,
        IncidentState.CLOSED_NO_ACTION,
    }
)


_EDGES: Mapping[IncidentState, frozenset[IncidentState]] = MappingProxyType({
    IncidentState.RECEIVED: frozenset({IncidentState.VALIDATED}),
    IncidentState.VALIDATED: frozenset({IncidentState.IDENTITY_CHECKED}),
    IncidentState.IDENTITY_CHECKED: frozenset({IncidentState.REPLAY_CHECKED}),
    IncidentState.REPLAY_CHECKED: frozenset({IncidentState.POLICY_EVALUATED}),
    IncidentState.POLICY_EVALUATED: frozenset(
        {IncidentState.DETECTED, IncidentState.CLOSED_NO_ACTION}
    ),
    IncidentState.DETECTED: frozenset(
        {IncidentState.INVESTIGATED, IncidentState.EVIDENCE_STORED}
    ),
    IncidentState.INVESTIGATED: frozenset({IncidentState.EVIDENCE_STORED}),
    IncidentState.EVIDENCE_STORED: frozenset({IncidentState.REPORTED}),
    IncidentState.REPORTED: frozenset(
        {
            IncidentState.AWAITING_APPROVAL,
            IncidentState.ATTESTED,
            IncidentState.ATTESTATION_UNAVAILABLE,
            IncidentState.COMPLETED_UNATTESTED,
        }
    ),
    IncidentState.AWAITING_APPROVAL: frozenset(
        {
            IncidentState.ATTESTED,
            IncidentState.ATTESTATION_UNAVAILABLE,
            IncidentState.COMPLETED_UNATTESTED,
        }
    ),
    # Re-entrant on purpose: repeated gateway outages park here again rather than
    # falling through to a completed state.
    IncidentState.ATTESTATION_UNAVAILABLE: frozenset(
        {
            IncidentState.ATTESTED,
            IncidentState.ATTESTATION_UNAVAILABLE,
            IncidentState.COMPLETED_UNATTESTED,
        }
    ),
    IncidentState.ATTESTED: frozenset({IncidentState.COMPLETED_ATTESTED}),
    IncidentState.COMPLETED_ATTESTED: frozenset(),
    IncidentState.COMPLETED_UNATTESTED: frozenset(),
    IncidentState.FAILED: frozenset(),
    IncidentState.CLOSED_NO_ACTION: frozenset(),
})


def _present(value: Any) -> bool:
    return value not in (None, "", [], {})


def _is_anchored_outcome(value: Any) -> bool:
    """The fact that makes COMPLETED_ATTESTED honest.

    A predicate rather than a presence check, because presence is exactly what
    let `"Skipped"` satisfy the old `attestation_status` requirement.
    """
    return value == AttestationDisposition.ANCHORED.value


def _is_unanchorable_outcome(value: Any) -> bool:
    return value == AttestationDisposition.NOT_ANCHORABLE.value


def _is_unavailable_outcome(value: Any) -> bool:
    return value == AttestationDisposition.UNAVAILABLE.value


# Facts that must already hold before a state may be entered, as predicates over
# the merged fact set.
_REQUIRED_FACTS: Mapping[
    IncidentState, tuple[tuple[str, Callable[[Any], bool], str], ...]
] = MappingProxyType({
    IncidentState.IDENTITY_CHECKED: (("trust_level", _present, "a trust level"),),
    IncidentState.POLICY_EVALUATED: (("detector_version", _present, "a detector version"),),
    IncidentState.DETECTED: (
        ("severity", _present, "a severity"),
        ("priority", _present, "a priority"),
    ),
    IncidentState.EVIDENCE_STORED: (
        ("evidence_digest", _present, "an evidence digest"),
        ("evidence_uri", _present, "an evidence uri"),
    ),
    IncidentState.REPORTED: (
        ("evidence_digest", _present, "an evidence digest"),
        ("report_id", _present, "a report id"),
    ),
    IncidentState.ATTESTED: (
        ("evidence_digest", _present, "an evidence digest"),
        (
            "attestation_outcome",
            _is_anchored_outcome,
            f"attestation_outcome == {AttestationDisposition.ANCHORED.value!r}",
        ),
    ),
    IncidentState.ATTESTATION_UNAVAILABLE: (
        (
            "attestation_outcome",
            _is_unavailable_outcome,
            f"attestation_outcome == {AttestationDisposition.UNAVAILABLE.value!r}",
        ),
    ),
    IncidentState.COMPLETED_ATTESTED: (
        ("evidence_digest", _present, "an evidence digest"),
        ("report_id", _present, "a report id"),
        (
            "attestation_outcome",
            _is_anchored_outcome,
            f"attestation_outcome == {AttestationDisposition.ANCHORED.value!r} "
            "(a completed-attested incident must carry a real anchor)",
        ),
    ),
    IncidentState.COMPLETED_UNATTESTED: (
        ("evidence_digest", _present, "an evidence digest"),
        ("report_id", _present, "a report id"),
        (
            "attestation_outcome",
            _is_unanchorable_outcome,
            f"attestation_outcome == {AttestationDisposition.NOT_ANCHORABLE.value!r} "
            "(a transient outage must park at attestation_unavailable, never complete)",
        ),
    ),
    IncidentState.FAILED: (("failure_reason", _present, "a failure reason"),),
    IncidentState.CLOSED_NO_ACTION: (("closure_reason", _present, "a closure reason"),),
})


def allowed_next(state: IncidentState) -> frozenset[IncidentState]:
    """States reachable from `state`, excluding FAILED which is always reachable."""
    return _EDGES[state]


def required_facts(state: IncidentState) -> tuple[str, ...]:
    return tuple(name for name, _predicate, _description in _REQUIRED_FACTS.get(state, ()))


# ── Attestation outcome ──────────────────────────────────────────────────────


# ── Execution fence ──────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Fence:
    """Authority to write to an incident.

    A worker holds a monotonically increasing epoch taken from its queue lease. A
    newer epoch revokes an older worker's right to write, so a paused worker
    cannot resume and overwrite the state of whoever legitimately reclaimed the
    item.

    Running unfenced is legitimate for maintenance and administrative paths, but
    it must be SPELLED: `Fence.unfenced(reason="retention sweep")`. The
    predecessor made unfenced the default (`epoch: int | None = None`) and two
    call sites took it by omission. Here omission is a TypeError and the choice
    leaves a searchable justification in the source.
    """

    epoch: int | None
    reason: str = ""

    @classmethod
    def worker(cls, epoch: int) -> "Fence":
        if isinstance(epoch, bool) or not isinstance(epoch, int):
            raise IllegalTransition(f"lease epoch must be an int, got {type(epoch).__name__}")
        if epoch < 0:
            raise IllegalTransition("lease epoch must be non-negative")
        return cls(epoch=epoch)

    @classmethod
    def unfenced(cls, *, reason: str) -> "Fence":
        if not reason.strip():
            raise IllegalTransition(
                "an unfenced write must state why it is safe to make without a lease"
            )
        return cls(epoch=None, reason=reason)

    @property
    def is_fenced(self) -> bool:
        return self.epoch is not None


# ── The aggregate ────────────────────────────────────────────────────────────


@dataclass
class Incident:
    """The aggregate root. The ONLY thing that may change incident state.

    Loaded by a repository, mutated in memory, persisted atomically with the
    events it raised. Events are collected rather than published so that a
    transition which is rolled back cannot leave a published fact behind.
    """

    tenant_id: TenantId
    incident_id: IncidentId
    state: IncidentState
    facts: dict[str, Any] = field(default_factory=dict)
    version: int = 0
    execution_epoch: int = 0
    #: The version this aggregate was READ at. Optimistic locking compares
    #: against this, not against the current version.
    #:
    #: An earlier form of the predicate was `WHERE version < new_version`, which
    #: silently assumed every save follows at least one transition. Claiming the
    #: execution fence changes `execution_epoch` and no lifecycle state, so it
    #: leaves the version untouched -- and the save was refused as a phantom
    #: conflict. Comparing against the loaded version is both correct and the
    #: textbook form: "nobody has written since I read".
    loaded_version: int = 0
    _events: list[DomainEvent] = field(default_factory=list, repr=False)

    # ── Construction ─────────────────────────────────────────────────────────

    @classmethod
    def admit(
        cls,
        *,
        tenant_id: TenantId,
        incident_id: IncidentId,
        severity: Severity,
        trust_level: TrustLevel,
        source: str,
        now: Timestamp,
        event_digest: Digest | None = None,
        facts: Mapping[str, Any] | None = None,
    ) -> "Incident":
        """Create an incident in RECEIVED. The only way one comes into existence.

        Severity is capped here, in the domain, against the trust level. The
        predecessor applied the cap in one HTTP route's detection call and five
        other routes reached the same pipeline without it, so an `ingest`-role
        key could post a client-supplied severity of 100. A rule enforced in the
        aggregate cannot be bypassed by adding a route.
        """
        effective = severity.capped_for(trust_level)
        merged: dict[str, Any] = dict(facts or {})
        merged.update(
            {
                "severity": effective.value,
                "priority": effective.priority.value,
                "trust_level": trust_level.value,
                "source": source,
                "severity_capped": effective != severity,
            }
        )
        if event_digest is not None:
            merged["event_digest"] = event_digest.value

        incident = cls(
            tenant_id=tenant_id,
            incident_id=incident_id,
            state=IncidentState.RECEIVED,
            facts=merged,
        )
        incident._raise(
            IncidentAdmitted(
                tenant_id=tenant_id,
                incident_id=incident_id,
                occurred_at=now,
                severity=effective,
                priority=effective.priority,
                source=source,
                event_digest=event_digest,
            )
        )
        return incident

    @classmethod
    def rehydrate(
        cls,
        *,
        tenant_id: TenantId,
        incident_id: IncidentId,
        state: IncidentState,
        facts: Mapping[str, Any],
        version: int,
        execution_epoch: int,
    ) -> "Incident":
        """Reconstruct from storage. Raises no events: nothing has happened."""
        return cls(
            tenant_id=tenant_id,
            incident_id=incident_id,
            state=state,
            facts=dict(facts),
            version=version,
            execution_epoch=execution_epoch,
            loaded_version=version,
        )

    # ── Fence ────────────────────────────────────────────────────────────────

    def claim_execution(self, epoch: int) -> None:
        """Take the fence for the FIRST time at `epoch`. Strictly increasing.

        Refuses an epoch that is not strictly newer, including one equal to the
        current owner's. That strictness is deliberate and is the reason
        `acquire_execution` exists separately: two DIFFERENT work items for the
        same incident can each carry lease epoch 1, so "equal" cannot be assumed
        to mean "the same worker". A caller that means "take it" gets the strict
        check; a caller that means "take it or keep it" must say so.
        """
        if epoch <= self.execution_epoch:
            raise ExecutionFenceLost(
                f"incident {self.incident_id} is owned at execution epoch "
                f"{self.execution_epoch}; refusing to hand it to epoch {epoch}. "
                "A newer worker holds the lease; abandon rather than duplicate its work."
            )
        self.execution_epoch = epoch

    def acquire_execution(self, epoch: int) -> bool:
        """Take the fence, or confirm this worker already holds it.

        Returns True if the fence moved. Used by the engine, which runs each step
        in its own transaction and therefore re-reads the aggregate between
        steps: the first step of an invocation TAKES the fence, and every
        subsequent step CONFIRMS it.

        Calling `claim_execution` for every step instead made the second step of
        every run raise `ExecutionFenceLost` against the epoch it had just taken
        -- correct code refusing itself, which is the most confusing shape a
        concurrency bug can have.

        A strictly newer epoch still wins, so a genuine reclaim is unaffected.
        """
        if epoch < self.execution_epoch:
            raise ExecutionFenceLost(
                f"worker holds execution epoch {epoch} for incident "
                f"{self.incident_id}, but it is now owned at epoch "
                f"{self.execution_epoch}. Another worker reclaimed it."
            )
        if epoch == self.execution_epoch:
            return False
        self.execution_epoch = epoch
        return True

    def assert_holds(self, fence: Fence) -> None:
        """Refuse an external side effect unless this worker still owns the fence."""
        if not fence.is_fenced:
            raise ExecutionFenceLost(
                f"incident {self.incident_id} cannot publish under an unfenced capability"
            )
        self._guard(fence)

    def _guard(self, fence: Fence) -> None:
        if not fence.is_fenced:
            return
        if fence.epoch != self.execution_epoch:
            raise ExecutionFenceLost(
                f"worker holds execution epoch {fence.epoch} for incident "
                f"{self.incident_id}, but it is now owned at epoch "
                f"{self.execution_epoch}. Another worker reclaimed it."
            )

    # ── Transition core ──────────────────────────────────────────────────────

    def _check(self, to_state: IncidentState, merged: Mapping[str, Any]) -> None:
        current = self.state
        if current.is_terminal:
            raise IllegalTransition(
                f"{current.value} is terminal; cannot transition to {to_state.value}"
            )
        if to_state is not IncidentState.FAILED and to_state not in _EDGES[current]:
            legal = ", ".join(sorted(s.value for s in _EDGES[current])) or "(none)"
            raise IllegalTransition(
                f"illegal transition {current.value} -> {to_state.value}. "
                f"Legal next states: {legal}, or failed."
            )
        unmet = [
            description
            for name, predicate, description in _REQUIRED_FACTS.get(to_state, ())
            if not predicate(merged.get(name))
        ]
        if unmet:
            raise MissingRequiredFact(
                f"cannot enter {to_state.value} without {'; '.join(unmet)}. This "
                "state asserts those hold; entering it without them would make the "
                "system misreport its own work."
            )

    def _transition(
        self,
        to_state: IncidentState,
        *,
        fence: Fence,
        actor: str,
        now: Timestamp,
        new_facts: Mapping[str, Any] | None = None,
    ) -> None:
        self._guard(fence)
        added = dict(new_facts or {})
        merged = {**self.facts, **added}
        self._check(to_state, merged)

        previous = self.state
        self.state = to_state
        self.facts = merged
        self.version += 1
        self._raise(
            IncidentStateChanged(
                tenant_id=self.tenant_id,
                incident_id=self.incident_id,
                occurred_at=now,
                from_state=previous.value,
                to_state=to_state.value,
                actor=actor,
            )
        )

    # ── Behaviour ────────────────────────────────────────────────────────────

    def advance(
        self,
        to_state: IncidentState,
        *,
        fence: Fence,
        now: Timestamp,
        actor: str = "pipeline",
        **new_facts: Any,
    ) -> None:
        """Advance through a stage that produces no artifact."""
        self._transition(to_state, fence=fence, actor=actor, now=now, new_facts=new_facts)

    def record_evidence(
        self,
        *,
        digest: Digest,
        uri: str,
        ledger_sequence: int,
        chain_hash: Digest,
        fence: Fence,
        now: Timestamp,
        extra_facts: Mapping[str, Any] | None = None,
    ) -> None:
        """Enter EVIDENCE_STORED. Callable only from DETECTED or INVESTIGATED."""
        if self.state not in {IncidentState.DETECTED, IncidentState.INVESTIGATED}:
            raise IllegalTransition(
                f"incident {self.incident_id} is {self.state.value}; evidence may "
                "only be committed from detected or investigated"
            )
        self._transition(
            IncidentState.EVIDENCE_STORED,
            fence=fence,
            actor="pipeline:evidence",
            now=now,
            new_facts={
                **dict(extra_facts or {}),
                "evidence_digest": digest.value,
                "evidence_uri": uri,
                "ledger_sequence": ledger_sequence,
                "ledger_chain_hash": chain_hash.value,
            },
        )
        self._raise(
            EvidenceStored(
                tenant_id=self.tenant_id,
                incident_id=self.incident_id,
                occurred_at=now,
                evidence_digest=digest,
                ledger_sequence=ledger_sequence,
                chain_hash=chain_hash,
            )
        )

    def record_report(self, *, report_bytes: int, fence: Fence, now: Timestamp) -> None:
        self._transition(
            IncidentState.REPORTED,
            fence=fence,
            actor="pipeline:report",
            now=now,
            new_facts={"report_id": self.incident_id.value},
        )
        self._raise(
            ReportStored(
                tenant_id=self.tenant_id,
                incident_id=self.incident_id,
                occurred_at=now,
                report_bytes=report_bytes,
            )
        )

    def request_approvals(
        self, *, approval_ids: Iterable[str], fence: Fence, now: Timestamp
    ) -> None:
        """Enter AWAITING_APPROVAL. Refuses to wait for nobody."""
        ids = [str(a) for a in approval_ids]
        if not ids:
            raise MissingRequiredFact(
                "cannot await approval with no proposals; 'waiting for a human' "
                "must never mean 'waiting for nobody'"
            )
        self._transition(
            IncidentState.AWAITING_APPROVAL,
            fence=fence,
            actor="pipeline:approvals",
            now=now,
            new_facts={"pending_approvals": ids},
        )

    def record_attestation(
        self, outcome: AttestationOutcome, *, fence: Fence, now: Timestamp
    ) -> None:
        """Record the attestation attempt and move where its disposition dictates.

        The destination comes from the outcome, not from the caller. A caller
        cannot ask for COMPLETED_UNATTESTED while holding an UNAVAILABLE outcome,
        because it does not choose the target at all.
        """
        self._transition(
            IncidentState(outcome.next_state_name),
            fence=fence,
            actor="pipeline:attestation",
            now=now,
            new_facts=outcome.as_facts(),
        )
        self._raise(
            AttestationRecorded(
                tenant_id=self.tenant_id,
                incident_id=self.incident_id,
                occurred_at=now,
                outcome=outcome.disposition.value,
                anchored=outcome.is_anchored,
                transaction_hash=outcome.transaction_hash,
                subject=outcome.subject,
            )
        )
        if outcome.disposition is AttestationDisposition.NOT_ANCHORABLE:
            self._raise(
                IncidentCompleted(
                    tenant_id=self.tenant_id,
                    incident_id=self.incident_id,
                    occurred_at=now,
                    attested=False,
                    final_state=IncidentState.COMPLETED_UNATTESTED.value,
                )
            )

    def complete(self, *, fence: Fence, now: Timestamp) -> None:
        """Enter COMPLETED_ATTESTED. Reachable only from ATTESTED."""
        self._transition(
            IncidentState.COMPLETED_ATTESTED, fence=fence, actor="pipeline:complete", now=now
        )
        self._raise(
            IncidentCompleted(
                tenant_id=self.tenant_id,
                incident_id=self.incident_id,
                occurred_at=now,
                attested=True,
                final_state=IncidentState.COMPLETED_ATTESTED.value,
            )
        )

    def close_without_action(self, *, reason: str, fence: Fence, now: Timestamp) -> None:
        """Policy found nothing. An explicit end, never presentable as completed."""
        self._transition(
            IncidentState.CLOSED_NO_ACTION,
            fence=fence,
            actor="pipeline:policy",
            now=now,
            new_facts={"closure_reason": reason},
        )
        self._raise(
            IncidentClosedWithoutAction(
                tenant_id=self.tenant_id,
                incident_id=self.incident_id,
                occurred_at=now,
                reason=reason,
            )
        )

    def fail(self, *, reason: str, fence: Fence, now: Timestamp, actor: str = "pipeline") -> None:
        """Move to FAILED with a mandatory reason. Never a silent dead end.

        Takes the same required `fence` as every other mutator. In the
        predecessor this was `repository.fail()`, a transition alias whose epoch
        defaulted to None, and it was the single most-called unfenced write path.
        """
        self._transition(
            IncidentState.FAILED,
            fence=fence,
            actor=actor,
            now=now,
            new_facts={"failure_reason": reason},
        )
        self._raise(
            IncidentFailed(
                tenant_id=self.tenant_id,
                incident_id=self.incident_id,
                occurred_at=now,
                reason=reason,
            )
        )

    # ── Projections ──────────────────────────────────────────────────────────

    @property
    def is_terminal(self) -> bool:
        return self.state.is_terminal

    @property
    def is_attested(self) -> bool:
        return self.state.is_attested

    @property
    def severity(self) -> Severity:
        return Severity(int(self.facts.get("severity") or 0))

    @property
    def priority(self) -> Priority:
        return Priority(str(self.facts.get("priority") or Priority.LOW.value))

    @property
    def trust_level(self) -> TrustLevel:
        return TrustLevel(str(self.facts.get("trust_level") or TrustLevel.UNSIGNED.value))

    def fact(self, name: str, default: Any = None) -> Any:
        return self.facts.get(name, default)

    # ── Events ───────────────────────────────────────────────────────────────

    def _raise(self, event: DomainEvent) -> None:
        self._events.append(event)

    def pull_events(self) -> tuple[DomainEvent, ...]:
        """Hand over the events raised so far and forget them.

        Called by the unit of work inside the transaction that persists the
        aggregate, so an event is published if and only if the change it
        describes committed.
        """
        drained = tuple(self._events)
        self._events.clear()
        return drained
