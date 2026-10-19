"""Execution operations and enforcement coverage over HTTP.

Two questions an operator asks that a receipt list cannot answer:

  * "Did that action happen?" -- answered by the OPERATION, which is written
    before the effect and settled after it. An operation still `pending` past
    its deadline is moved to `unknown_after_effect`, and this module is where
    a human records how the outcome was established.
  * "How much of my estate is actually under this control?" -- answered by the
    COVERAGE model, which reports discovered, observed, routed, evaluated,
    enforced and unknown as SEPARATE numbers with their sources, so an empty
    incident list is never read as safety.
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Query, status
from pydantic import BaseModel, Field

from sentinel.application.bypass_detection import detect_possible_bypasses
from sentinel.domain.authorization import Capability
from sentinel.domain.slo import SloKind, SloTarget, evaluate_slo
from sentinel.domain.value_metrics import measure as measure_value
from sentinel.domain.operations import OperationState
from sentinel.infrastructure.persistence.audit import Outcome

__all__ = ["register_operations_routes"]


class ReconcileRequest(BaseModel):
    resolved_state: Literal["succeeded", "failed"]
    note: str = Field(min_length=8, max_length=2000)


#: The first workflow's targets, from COMMERCIAL_METRICS_TEMPLATE.csv. Judged by
#: `domain.slo`, which answers UNVERIFIED until the sample supports a verdict.
WORKFLOW_SLOS = (
    SloTarget(name="approval_latency_p95", kind=SloKind.LATENCY_PERCENTILE, threshold=3_600_000.0, percentile=95),
    SloTarget(name="unknown_outcome_settled_p95", kind=SloKind.LATENCY_PERCENTILE, threshold=86_400_000.0, percentile=95),
)


def judged(summary: dict, *, days: int, committed: int) -> dict:
    """Add the value report and SLO verdicts to a counted summary.

    Both come from domain modules that refuse to produce a number the sample
    does not support: `value_metrics` reports UNMEASURABLE rather than a vanity
    figure, and `slo` reports UNVERIFIED rather than MET on four samples.
    """
    samples = summary.pop("_samples")
    executions = summary["executions"]
    summary["value"] = measure_value(
        window_days=days, executions_total=executions["attempted"],
        executions_bound=executions["attempted"], substitutions_refused=executions["refused"],
        approval_wait_seconds=samples["approval_seconds"], evidence_verified=committed,
    ).as_dict()
    series = {"approval_latency_p95": samples["approval_seconds"],
              "unknown_outcome_settled_p95": samples["reconcile_seconds"]}
    summary["slo"] = [
        evaluate_slo(target, latencies_ms=[s * 1000.0 for s in series[target.name]],
                     observed_seconds=samples["window_seconds"]).as_dict()
        for target in WORKFLOW_SLOS
    ]
    return summary


def register_operations_routes(app: FastAPI, container: Any, *, require: Any) -> None:
    audit = container.security_audit

    @app.get("/v1/executions/operations")
    def list_operations(
        state: str | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=500),
        principal=Depends(require(Capability.READ_INCIDENT)),
    ):
        """Operations for this tenant, newest first. `state` filters."""
        states: tuple[OperationState, ...] = ()
        if state:
            try:
                states = (OperationState(state.strip().lower()),)
            except ValueError as exc:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    detail=(
                        f"unknown state {state!r}; valid: "
                        + ", ".join(s.value for s in OperationState)
                    ),
                ) from exc
        tenant = str(principal.tenant)
        rows = container.operations.list(tenant, states=states, limit=limit)
        counts = container.operations.counts(tenant)
        return {
            "operations": [op.as_dict() for op in rows],
            "counts": counts,
            "needs_reconciliation": counts.get(
                OperationState.UNKNOWN_AFTER_EFFECT.value, 0
            ),
            "note": (
                "unknown_after_effect means the effect was invoked and its "
                "outcome was not recorded. It is not a failure and not a "
                "success; somebody must establish which and reconcile it."
            ),
        }

    @app.get("/v1/executions/operations/{operation_id}")
    def get_operation(
        operation_id: str,
        principal=Depends(require(Capability.READ_INCIDENT)),
    ):
        op = container.operations.get(str(principal.tenant), operation_id)
        if op is None:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                detail=f"no operation {operation_id!r} for this tenant",
            )
        return op.as_dict()

    @app.post("/v1/executions/operations/{operation_id}/reconcile")
    def reconcile_operation(
        operation_id: str,
        body: ReconcileRequest,
        principal=Depends(require(Capability.DECIDE_APPROVAL)),
    ):
        """Settle an UNKNOWN outcome, with a note saying how it was established.

        `DECIDE_APPROVAL`: the same people who may let an action happen may
        say whether it did. Audited unconditionally; a reconciliation is a
        statement about the world that the evidence chain will rely on.
        """
        tenant = str(principal.tenant)
        actor = f"key:{principal.key_hash[:12]}"
        now = container.clock.now().isoformat()
        existing = container.operations.get(tenant, operation_id)
        if existing is None:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                detail=f"no operation {operation_id!r} for this tenant",
            )
        ok = container.operations.reconcile(
            tenant,
            operation_id,
            resolved_state=OperationState(body.resolved_state),
            by=actor,
            at=now,
            note=body.note,
        )
        audit.record(
            tenant=principal.tenant,
            actor=actor,
            action="operation.reconcile",
            resource_type="execution_operation",
            resource_id=operation_id,
            outcome=Outcome.SUCCESS if ok else Outcome.FAILED,
            detail={
                "from_state": existing.state.value,
                "resolved_state": body.resolved_state,
                "role": principal.role,
            },
        )
        if not ok:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                detail={
                    "outcome": "not_reconcilable",
                    "state": existing.state.value,
                    "detail": (
                        "only an operation in unknown_after_effect can be "
                        "reconciled; this one already has a recorded outcome"
                    ),
                },
            )
        return {
            "outcome": "reconciled",
            "operation_id": operation_id,
            "state": body.resolved_state,
        }

    @app.get("/v1/evidence/export")
    def export_evidence(
        after_sequence: int = Query(default=-1, ge=-1),
        limit: int = Query(default=200, ge=1, le=500),
        principal=Depends(require(Capability.READ_INCIDENT)),
    ):
        """A portable evidence bundle: receipts, their leaves, and inclusion proofs.

        Everything `standard/execution-passport-v1/verify_evidence_bundle.py`
        needs to check the receipts WITHOUT this service: the receipt fields
        the leaf commits to, the leaf, its position, and the path to the root.
        Keep the bundle, and a root obtained from outside this environment, and
        the evidence outlives the environment. Page with `after_sequence`.
        """
        from sentinel.domain.transparency import empty_root

        tenant = str(principal.tenant)
        log = container.transparency.load(tenant)
        entries = container.evidence.export(tenant, after_sequence=after_sequence, limit=limit)
        for entry in entries:
            entry["proof"] = log.inclusion_proof(entry["sequence"]).as_dict()
        published = [root.as_dict() for root in container.transparency.published_roots(tenant)]
        return {
            "schema": "sentinel.evidence-bundle/v1",
            "tenant_id": tenant,
            "generated_at": container.clock.now().value.isoformat(),
            "tree_size": log.size,
            "root": (log.root() if log.size else empty_root()).hex(),
            "entries": entries,
            "next_after_sequence": entries[-1]["sequence"] if entries else after_sequence,
            "receipts_not_yet_committed": container.evidence.pending(tenant),
            "published_roots": published,
            "independently_anchored": any(r.get("independently_verifiable") for r in published),
            "verify_with": "standard/execution-passport-v1/verify_evidence_bundle.py --trusted-root <hex> --trusted-size <n>",
            "note": (
                "A bundle proves its receipts are in THIS root. Whether this root is the "
                "log's true history is proven only by comparing it with a root held outside "
                "this environment; `independently_anchored` says whether one was ever published."
            ),
        }

    @app.get("/v1/workflow/metrics")
    def workflow_metrics(
        days: int = Query(default=7, ge=1, le=90),
        principal=Depends(require(Capability.READ_INCIDENT)),
    ):
        """Counted facts about this tenant's protected changes over `days`.

        Approval latency, interruptions per hundred attempts, refusals, unknown
        outcomes and how they were settled, effect duration, adoption. Every
        percentile carries its sample size. Nothing here is estimated.
        """
        from datetime import timedelta

        since = (container.clock.now().value - timedelta(days=days)).isoformat()
        summary = container.workflow_metrics.summary(str(principal.tenant), since=since)
        return judged(summary, days=days, committed=len(container.evidence.export(str(principal.tenant), limit=500)))

    @app.get("/v1/coverage")
    def coverage(principal=Depends(require(Capability.READ_INCIDENT))):
        """What this control actually covers, as separate counts with sources.

        The one thing this route must never do is fold these into a score.
        A perfect bound-receipt ratio over three executions and an empty
        incident list say nothing about the forty agents that never routed
        through the gate; each number below carries the question it answers.
        """
        tenant = str(principal.tenant)
        now = container.clock.now()
        profiles = container.inventory.list_profiles(tenant)
        discovered = len(profiles)
        graph = container.execution_graph.coverage(tenant).as_dict()
        operation_counts = container.operations.counts(tenant)
        receipts = container.receipts.coverage(tenant)
        evaluated = container.coverage_reader.protect_evaluations(tenant)
        bypass = detect_possible_bypasses(
            agents=container.agents.list_activity(principal.tenant),
            now=now,
            idle_threshold_seconds=container.settings.bypass_idle_seconds,
        )
        routed_agents = container.coverage_reader.agents_with_operations(tenant)
        observed_agents = {p.agent_id for p in profiles}
        never_routed = sorted(observed_agents - routed_agents)
        enforced_refusals = operation_counts.get(OperationState.REFUSED.value, 0)
        bound = sum(
            operation_counts.get(s, 0)
            for s in ("succeeded", "failed", "pending", "unknown_after_effect")
        )
        return {
            "discovered_agents": {
                "count": discovered,
                "source": "GET /v1/inventory/agents (observed traffic + connectors)",
            },
            "observed_traffic": {
                "events": int(graph.get("total_nodes", 0)),
                "sessions": int(graph.get("sessions", 0)),
                "source": "GET /v1/graph/coverage",
            },
            "policy_evaluated_actions": {
                "count": evaluated,
                "source": "security_audit rows with action=protect.evaluate",
            },
            "routed_executions": {
                "bound_operations": bound,
                "receipts": int(receipts.get("receipts", 0)),
                "source": "execution_operations + execution_receipts",
            },
            "enforced_refusals": {
                "count": enforced_refusals,
                "source": "execution_operations with state=refused",
            },
            "enforcement_configured": {
                "protect_enforce": bool(container.settings.protect_enforcement),
                "require_execution_binding": bool(
                    container.settings.require_execution_binding
                ),
                "kill_switch": bool(container.settings.protect_kill_switch),
            },
            "bypass_signals": {
                "count": len(bypass),
                "source": "GET /v1/protect/bypass-signals",
            },
            "unknown_coverage": {
                "agents_observed_but_never_routed": never_routed,
                "count": len(never_routed),
                "note": (
                    "an agent that emits events but never executes through the "
                    "gate is OUTSIDE enforcement. Traffic that never reaches "
                    "Sentinel at all is not counted anywhere on this page and "
                    "cannot be; see the deployment contract in "
                    "docs/PROTECT_ENFORCEMENT.md."
                ),
            },
            "operations_needing_reconciliation": operation_counts.get(
                OperationState.UNKNOWN_AFTER_EFFECT.value, 0
            ),
            "warning": (
                "these are separate denominators and must not be combined into "
                "a single coverage percentage; an empty incident list and a "
                "perfect receipt ratio are consistent with zero enforcement"
            ),
        }
