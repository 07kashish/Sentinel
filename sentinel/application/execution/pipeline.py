"""The incident pipeline as a saga: plan, handlers, compensators, hydrators.

THE PLAN'S SHAPE
----------------
    validate · identity · replay · policy · detect · evidence · report · approvals
                                        [ compensatable ]
    attest                              [ PIVOT — irreversible ]
    complete                            [ retriable — forward only ]

`attest` is the pivot because an external anchor cannot be un-published. Every
step before it can be undone; nothing after it can. `ExecutionPlan` refuses to
construct a plan that violates that ordering, so this shape is checked rather
than intended.

WHY THE COMPENSATIONS LOOK THE WAY THEY DO
-------------------------------------------
The ledger is append-only, so "undo an entry" is not deletion -- deletion would
break the hash chain and destroy the property the ledger exists to provide.
Compensating an append means appending a REVERSAL, which is what a ledger has
always meant by a correction. The evidence body is separately mutable and
erasable (that is what makes lawful erasure possible without breaking proofs), so
its compensation redacts the body and leaves the commitment intact.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from sentinel.application.execution.engine import (
    Compensator,
    ExecutionContext,
    StepHandler,
    StepResult,
)
from sentinel.application.ports import (
    AttestationGateway,
    EvidenceBuilder,
    IdGenerator,
    Logger,
    ModelAdvisor,
    RemediationPlanner,
    ReportRenderer,
)
from sentinel.application.records import ModelAdvice
from sentinel.domain.execution import (
    ExecutionPlan,
    StepDefinition,
    StepKind,
    StepName,
)
from sentinel.domain.incident import AttestationDisposition, IncidentState
from sentinel.domain.primitives import Address

__all__ = ["INCIDENT_PLAN", "PipelineSteps", "STEP"]


class _Steps:
    """Named step constants. Typed once so a typo is an AttributeError, not a
    silently-never-runs step whose journal row nobody looks for."""

    VALIDATE = StepName("validate")
    IDENTITY = StepName("identity")
    REPLAY = StepName("replay")
    POLICY = StepName("policy")
    DETECT = StepName("detect")
    EVIDENCE = StepName("evidence")
    REPORT = StepName("report")
    APPROVALS = StepName("approvals")
    ATTEST = StepName("attest")
    COMPLETE = StepName("complete")

    UNDO_VALIDATE = StepName("undo_validate")
    UNDO_IDENTITY = StepName("undo_identity")
    UNDO_REPLAY = StepName("undo_replay")
    UNDO_POLICY = StepName("undo_policy")
    UNDO_DETECT = StepName("undo_detect")
    UNDO_EVIDENCE = StepName("undo_evidence")
    UNDO_REPORT = StepName("undo_report")
    UNDO_APPROVALS = StepName("undo_approvals")

    #: Not a plan step. It names the SIEM export effect so that effect gets its
    #: OWN stable idempotency key, distinct from the attestation's. Two effects
    #: sharing one key would let a collector's deduplication swallow an export
    #: because an anchor with the same key already succeeded.
    SIEM_EXPORT = StepName("siem_export")


STEP = _Steps()


INCIDENT_PLAN = ExecutionPlan(
    (
        StepDefinition(STEP.VALIDATE, StepKind.COMPENSATABLE, compensation=STEP.UNDO_VALIDATE),
        StepDefinition(STEP.IDENTITY, StepKind.COMPENSATABLE, compensation=STEP.UNDO_IDENTITY),
        StepDefinition(STEP.REPLAY, StepKind.COMPENSATABLE, compensation=STEP.UNDO_REPLAY),
        StepDefinition(STEP.POLICY, StepKind.COMPENSATABLE, compensation=STEP.UNDO_POLICY),
        StepDefinition(STEP.DETECT, StepKind.COMPENSATABLE, compensation=STEP.UNDO_DETECT),
        StepDefinition(
            STEP.EVIDENCE,
            StepKind.COMPENSATABLE,
            produces_artifact=True,
            compensation=STEP.UNDO_EVIDENCE,
        ),
        StepDefinition(
            STEP.REPORT,
            StepKind.COMPENSATABLE,
            produces_artifact=True,
            compensation=STEP.UNDO_REPORT,
        ),
        StepDefinition(
            STEP.APPROVALS, StepKind.COMPENSATABLE, compensation=STEP.UNDO_APPROVALS
        ),
        # The point of no return. An anchor cannot be withdrawn.
        StepDefinition(STEP.ATTEST, StepKind.PIVOT),
        # Past the pivot: must go forward, never unwind.
        StepDefinition(STEP.COMPLETE, StepKind.RETRIABLE),
    )
)


class PipelineSteps:
    """Constructs the handler, compensator and hydrator maps for the engine.

    A class rather than module functions purely so its collaborators are injected
    once and shared by every step, instead of each step reaching for them.
    """

    __slots__ = (
        "_advisor",
        "_evidence_builder",
        "_report_renderer",
        "_planner",
        "_attestation",
        "_ids",
        "_logger",
        "_siem_export",
    )

    def __init__(
        self,
        *,
        advisor: ModelAdvisor,
        evidence_builder: EvidenceBuilder,
        report_renderer: ReportRenderer,
        planner: RemediationPlanner,
        attestation: AttestationGateway,
        ids: IdGenerator,
        logger: Logger,
        siem_export: bool = False,
    ) -> None:
        self._advisor = advisor
        self._evidence_builder = evidence_builder
        self._report_renderer = report_renderer
        self._planner = planner
        self._attestation = attestation
        self._ids = ids
        self._logger = logger
        # Whether to commit an export intent alongside the attestation intent.
        # OFF unless a collector is configured: an export row with no deliverer
        # is refused by name in `dispatch_outbox`, which is correct behaviour
        # for a misconfiguration and would be a permanent dead-letter stream
        # for a deployment that simply does not use SIEM.
        self._siem_export = bool(siem_export)

    # ── Wiring ───────────────────────────────────────────────────────────────

    def handlers(self) -> Mapping[StepName, StepHandler]:
        return {
            STEP.VALIDATE: self._validate,
            STEP.IDENTITY: self._identity,
            STEP.REPLAY: self._replay,
            STEP.POLICY: self._policy,
            STEP.DETECT: self._detect,
            STEP.EVIDENCE: self._evidence,
            STEP.REPORT: self._report,
            STEP.APPROVALS: self._approvals,
            STEP.ATTEST: self._attest,
            STEP.COMPLETE: self._complete,
        }

    def compensators(self) -> Mapping[StepName, Compensator]:
        return {
            STEP.VALIDATE: _no_effect_to_undo,
            STEP.IDENTITY: _no_effect_to_undo,
            STEP.REPLAY: _no_effect_to_undo,
            STEP.POLICY: _no_effect_to_undo,
            STEP.DETECT: _no_effect_to_undo,
            STEP.EVIDENCE: self._undo_evidence,
            STEP.REPORT: self._undo_report,
            STEP.APPROVALS: self._undo_approvals,
        }

    def hydrators(self) -> Sequence[Any]:
        """Reload every artifact the incident's durable state asserts exists.

        Runs BEFORE any step, on every invocation. This is the guarantee that a
        resumed run never sees `None` where the first run saw an artifact.
        """
        return (self._hydrate_evidence, self._hydrate_report, self._hydrate_approvals)

    # ── Hydration ────────────────────────────────────────────────────────────

    def _hydrate_evidence(self, ctx: ExecutionContext) -> None:
        if ctx.incident.state in _EVIDENCE_DURABLE_FROM:
            ctx.evidence = ctx.uow.ledger.get_evidence(ctx.incident_id)
            ctx.require_evidence()

    def _hydrate_report(self, ctx: ExecutionContext) -> None:
        if ctx.incident.state in _REPORT_DURABLE_FROM:
            ctx.report = ctx.uow.ledger.get_report(ctx.incident_id)
            ctx.require_report()

    def _hydrate_approvals(self, ctx: ExecutionContext) -> None:
        ctx.approvals = tuple(ctx.uow.approvals.pending_for_incident(ctx.incident_id))

    # ── Steps ────────────────────────────────────────────────────────────────

    def _validate(self, ctx: ExecutionContext) -> StepResult:
        ctx.incident.advance(IncidentState.VALIDATED, fence=ctx.fence, now=ctx.now)
        return StepResult()

    def _identity(self, ctx: ExecutionContext) -> StepResult:
        trust = ctx.incident.trust_level
        ctx.incident.advance(
            IncidentState.IDENTITY_CHECKED,
            fence=ctx.fence,
            now=ctx.now,
            trust_level=trust.value,
        )
        return StepResult({"trust_level": trust.value})

    def _replay(self, ctx: ExecutionContext) -> StepResult:
        ctx.incident.advance(IncidentState.REPLAY_CHECKED, fence=ctx.fence, now=ctx.now)
        return StepResult()

    def _policy(self, ctx: ExecutionContext) -> StepResult:
        version = str(ctx.incident.fact("detector_version") or "unknown")
        ctx.incident.advance(
            IncidentState.POLICY_EVALUATED,
            fence=ctx.fence,
            now=ctx.now,
            detector_version=version,
        )
        return StepResult({"detector_version": version})

    def _detect(self, ctx: ExecutionContext) -> StepResult:
        """Deterministic triage plus an ADVISORY second opinion.

        Priority is already a pure function of severity, computed by the domain.
        The model reads attacker-influenced text, and a system whose priority can
        be argued down by its input has no priority at all -- so its view is
        recorded under `advisory_*` and can never move triage.
        """
        try:
            advice = self._advisor.advise(incident=dict(ctx.incident.facts))
        except Exception as exc:  # noqa: BLE001 - advisory: never fatal, always stated
            advice = ModelAdvice.unavailable(f"{type(exc).__name__}: {exc}")
            self._logger.warning(
                "advisor_unavailable",
                incident_id=str(ctx.incident_id),
                error=f"{type(exc).__name__}: {exc}",
            )
        ctx.advice = advice

        if not ctx.incident.severity.is_actionable:
            ctx.incident.close_without_action(
                reason="policy evaluated the event and found nothing to action",
                fence=ctx.fence,
                now=ctx.now,
            )
            # Terminal. Halt rather than settle-and-continue: the plan has more
            # steps and none of them applies to a closed incident.
            return StepResult({"closed": True}, halt=True)

        ctx.incident.advance(
            IncidentState.DETECTED,
            fence=ctx.fence,
            now=ctx.now,
            advisory_available=advice.available,
            advisory_detail=advice.detail,
            advisory_priority=advice.suggested_priority,
            advisory_escalation=advice.escalation,
            advisory_recommendations=list(advice.recommendations),
            advisory_model=advice.model_receipt,
            advisory_reasoning=advice.reasoning,
            priority_basis="deterministic_policy",
        )
        return StepResult({"advisory_available": advice.available})

    def _evidence(self, ctx: ExecutionContext) -> StepResult:
        record, leaf_hash, manifest = self._evidence_builder.build(
            tenant=ctx.tenant,
            incident_id=ctx.incident_id,
            incident_facts=dict(ctx.incident.facts),
            approvals=ctx.approvals,
            advice=_advice(ctx),
            detector_version=str(ctx.incident.fact("detector_version") or "unknown"),
            at=ctx.now,
        )
        sequence, chain_hash = ctx.uow.ledger.append(
            incident_id=ctx.incident_id, entry_hash=leaf_hash, manifest=manifest
        )
        ctx.uow.ledger.store_evidence(record)
        ctx.incident.record_evidence(
            digest=record.digest,
            uri=record.uri,
            ledger_sequence=sequence,
            chain_hash=chain_hash,
            fence=ctx.fence,
            now=ctx.now,
        )
        ctx.evidence = record
        return StepResult(
            {
                "evidence_digest": record.digest.value,
                "ledger_sequence": sequence,
                "chain_hash": chain_hash.value,
            }
        )

    def _report(self, ctx: ExecutionContext) -> StepResult:
        evidence = ctx.require_evidence()
        report = self._report_renderer.render(
            incident_facts=dict(ctx.incident.facts),
            evidence=evidence,
            approvals=ctx.approvals,
            advice=_advice(ctx),
            at=ctx.now,
        )
        ctx.uow.ledger.store_report(
            incident_id=ctx.incident_id, content=report, at=ctx.now
        )
        ctx.incident.record_report(
            report_bytes=len(report.encode("utf-8")), fence=ctx.fence, now=ctx.now
        )
        ctx.report = report
        return StepResult({"report_bytes": len(report.encode("utf-8"))})

    def _approvals(self, ctx: ExecutionContext) -> StepResult:
        """Propose mitigations for a human. Executes nothing.

        Proposing nothing is a REAL outcome, journaled as such. The predecessor
        could not distinguish "approvals ran and found none" from "approvals never
        ran", because it inferred execution from the absence of a transition.
        """
        proposals = self._planner.propose(
            incident_facts=dict(ctx.incident.facts),
            advice=_advice(ctx),
            incident_id=ctx.incident_id,
            ids=self._ids,
            at=ctx.now,
        )
        if not proposals:
            return StepResult({"proposed": 0})
        ctx.uow.approvals.propose(proposals)
        ctx.incident.request_approvals(
            approval_ids=[p.approval_id.value for p in proposals],
            fence=ctx.fence,
            now=ctx.now,
        )
        ctx.approvals = tuple(proposals)
        return StepResult(
            {"proposed": len(proposals), "ids": [p.approval_id.value for p in proposals]}
        )

    def _attest(self, ctx: ExecutionContext) -> StepResult:
        """THE PIVOT. Record durable intent, anchor, record the receipt.

        The idempotency key is derived from (tenant, incident, step) and contains
        NO epoch, so every retry presents the same key and the gateway collapses
        duplicates. That is the third layer of the exactly-once story, and the
        only one that covers a crash between the effect and its journal entry.
        """
        evidence = ctx.require_evidence()
        key = ctx.idempotency_key(STEP.ATTEST)
        ctx.uow.outbox.enqueue(
            incident_id=ctx.incident_id,
            kind="attestation",
            payload={
                "evidence_digest": evidence.digest.value,
                "incident_id": ctx.incident_id.value,
                "subject": ctx.incident.fact("signer_address"),
            },
            idempotency_key=key,
            at=ctx.now,
        )
        if self._siem_export:
            # Committed in the SAME transaction as the incident and the
            # attestation intent, which is what makes "never silently discard a
            # security event" true rather than aspirational: there is no window
            # in which the incident exists and the intent to export it does not.
            # Delivery, retry and dead-lettering are the outbox's job from here.
            ctx.uow.outbox.enqueue(
                incident_id=ctx.incident_id,
                kind="siem",
                payload={
                    "tenant_id": ctx.tenant.value,
                    "occurred_at": ctx.now.value,
                    "actor": str(ctx.incident.fact("agent_id") or ""),
                    "action": str(ctx.incident.fact("action") or ""),
                    "resource_type": "incident",
                    "resource_id": ctx.incident_id.value,
                    "outcome": "detected",
                    "detail": {
                        "severity": ctx.incident.severity.value,
                        "evidence_digest": evidence.digest.value,
                    },
                },
                idempotency_key=ctx.idempotency_key(STEP.SIEM_EXPORT),
                at=ctx.now,
            )

        raw_subject = ctx.incident.fact("signer_address")
        subject = (
            Address(raw_subject) if isinstance(raw_subject, str) and raw_subject else None
        )
        if ctx.reentry:
            # This step was entered before and never reported back, so the
            # anchor MAY already exist. Ask before acting. Re-sending would
            # also be safe -- the key is stable and the gateway deduplicates
            # -- but asking establishes the guarantee here instead of relying
            # on someone else's correctness for it.
            settled = self._attestation.reconcile(idempotency_key=key)
            if settled is not None:
                self._logger.info(
                    "attestation_reconciled",
                    incident_id=str(ctx.incident_id),
                    disposition=settled.disposition.value,
                    detail="a previous attempt was already applied; its recorded "
                    "outcome is adopted rather than re-sent",
                )
                ctx.incident.record_attestation(
                    settled, fence=ctx.fence, now=ctx.now
                )
                if settled.disposition is AttestationDisposition.UNAVAILABLE:
                    return StepResult(
                        {"disposition": settled.disposition.value, "reconciled": True},
                        settled=False,
                    )
                return StepResult(
                    {
                        "disposition": settled.disposition.value,
                        "reconciled": True,
                        "transaction_hash": settled.transaction_hash,
                    },
                    halt=settled.disposition
                    is AttestationDisposition.NOT_ANCHORABLE,
                )

        # Fence check immediately before the irreversible external effect. A
        # reclaim between journal.enter and this call must abandon, not publish.
        ctx.incident.assert_holds(ctx.fence)
        outcome = self._attestation.anchor(
            tenant=ctx.tenant,
            incident_id=ctx.incident_id,
            evidence_digest=evidence.digest,
            subject=subject,
            idempotency_key=key,
        )
        ctx.incident.record_attestation(outcome, fence=ctx.fence, now=ctx.now)

        if outcome.disposition is AttestationDisposition.UNAVAILABLE:
            # The transition to ATTESTATION_UNAVAILABLE is TRUE and commits. The
            # step does NOT settle, so the next delivery re-enters it. Settling it
            # would advance the plan to `complete`, whose precondition the
            # lifecycle refuses -- turning a transient outage into a deterministic
            # failure and an unnecessary unwind.
            self._logger.warning(
                "attestation_unavailable",
                incident_id=str(ctx.incident_id),
                detail=outcome.detail,
                note="parked for retry; the incident is NOT completed",
            )
            return StepResult({"disposition": outcome.disposition.value}, settled=False)

        if outcome.disposition is AttestationDisposition.NOT_ANCHORABLE:
            # Terminal and honest: COMPLETED_UNATTESTED. Nothing after this
            # applies, so halt rather than run `complete` against a terminal
            # incident.
            return StepResult({"disposition": outcome.disposition.value}, halt=True)

        return StepResult(
            {
                "disposition": outcome.disposition.value,
                "transaction_hash": outcome.transaction_hash,
            }
        )

    def _complete(self, ctx: ExecutionContext) -> StepResult:
        ctx.incident.complete(fence=ctx.fence, now=ctx.now)
        return StepResult({"final_state": ctx.incident.state.value})

    # ── Compensations ────────────────────────────────────────────────────────

    def _undo_evidence(self, ctx: ExecutionContext, result: Mapping[str, Any]) -> None:
        """Redact the evidence body; APPEND a reversal to the ledger.

        The ledger is append-only and hash-chained. Deleting the entry would
        break the chain and destroy the property the ledger exists to provide, so
        a correction is an appended reversal -- which is what a ledger has always
        meant by one. The commitment survives; the body does not.
        """
        digest = result.get("evidence_digest")
        ctx.uow.ledger.redact_evidence(
            incident_id=ctx.incident_id,
            reason="saga compensation: the incident that produced this evidence "
            "failed before the point of no return",
            actor="system:compensation",
            at=ctx.now,
        )
        self._logger.warning(
            "evidence_compensated",
            incident_id=str(ctx.incident_id),
            evidence_digest=digest,
            detail="body redacted; the ledger commitment and chain remain intact",
        )

    def _undo_report(self, ctx: ExecutionContext, result: Mapping[str, Any]) -> None:
        ctx.uow.ledger.withdraw_report(
            incident_id=ctx.incident_id,
            reason="saga compensation: the incident this report described failed",
            at=ctx.now,
        )

    def _undo_approvals(self, ctx: ExecutionContext, result: Mapping[str, Any]) -> None:
        """Withdraw proposals a human has not yet acted on.

        Only PENDING approvals are withdrawn. One a human already decided is a
        record of a human decision, and a compensation must not erase that -- the
        action may already have reached the world.
        """
        for approval in ctx.uow.approvals.pending_for_incident(ctx.incident_id):
            ctx.uow.approvals.withdraw(
                approval.approval_id,
                reason="saga compensation: the incident that proposed this action failed",
                at=ctx.now,
            )


def _no_effect_to_undo(ctx: ExecutionContext, result: Mapping[str, Any]) -> None:
    """A step whose only output was a lifecycle transition.

    Nothing external happened, so there is nothing to undo. The compensation
    exists as a named no-op rather than being absent because
    `StepDefinition.__post_init__` requires a compensatable step to name one --
    which forces the author to decide, per step, whether an unwind is possible.
    A missing compensation would otherwise read as "not thought about".
    """


#: States from which each artifact is asserted durable. Declared explicitly
#: rather than derived from a rank table, so adding a lifecycle state cannot
#: silently change which artifacts a resumed run reloads.
_EVIDENCE_DURABLE_FROM = frozenset(
    {
        IncidentState.EVIDENCE_STORED,
        IncidentState.REPORTED,
        IncidentState.AWAITING_APPROVAL,
        IncidentState.ATTESTED,
        IncidentState.ATTESTATION_UNAVAILABLE,
        IncidentState.COMPLETED_ATTESTED,
        IncidentState.COMPLETED_UNATTESTED,
    }
)

_REPORT_DURABLE_FROM = frozenset(
    {
        IncidentState.REPORTED,
        IncidentState.AWAITING_APPROVAL,
        IncidentState.ATTESTED,
        IncidentState.ATTESTATION_UNAVAILABLE,
        IncidentState.COMPLETED_ATTESTED,
        IncidentState.COMPLETED_UNATTESTED,
    }
)


def _advice(ctx: ExecutionContext) -> ModelAdvice | None:
    """The advice for this incident, whichever execution recorded it.

    `ctx.advice` lives in memory, and the steps after detection run in a LATER
    execution with a fresh context -- so the evidence body, the report and the
    approval context all saw `None` and wrote "Not consulted" about an advisor
    that had answered. The facts are the durable copy; rebuild from them.
    """
    if ctx.advice is not None:
        return ctx.advice
    facts = ctx.incident.facts
    if "advisory_available" not in facts:
        return None
    return ModelAdvice(
        available=bool(facts.get("advisory_available")),
        detail=str(facts.get("advisory_detail") or ""),
        model_receipt=str(facts.get("advisory_model") or "unknown"),
        suggested_priority=facts.get("advisory_priority"),
        escalation=bool(facts.get("advisory_escalation")),
        recommendations=tuple(facts.get("advisory_recommendations") or ()),
        reasoning=str(facts.get("advisory_reasoning") or ""),
    )
