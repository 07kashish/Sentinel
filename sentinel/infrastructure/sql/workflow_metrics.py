"""Measured facts about the protected-change workflow, from stored records.

Every number here is COUNTED from rows that already exist for other reasons:
operations, authorizations, the audit trail, receipts. Nothing is sampled,
estimated or self-reported, and a quantity that cannot be derived from a
record is absent rather than approximated.

Percentiles use the nearest-rank method on the full set in the window, and
the sample size is returned beside every percentile: a p95 of four samples is
not a p95, and the reader is given what they need to see that.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Sequence

from sentinel.infrastructure.sql.engine import ConnectionPool

__all__ = ["SqlWorkflowMetrics", "percentile"]


def percentile(values: Sequence[float], fraction: float) -> float | None:
    """Nearest-rank percentile, or None for an empty set."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(fraction * len(ordered)))
    return round(ordered[rank - 1], 3)


def _seconds(start: str, end: str) -> float | None:
    try:
        return (datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds()
    except (TypeError, ValueError):
        return None


def _distribution(values: list[float]) -> dict[str, Any]:
    return {"samples": len(values), "p50": percentile(values, 0.50), "p95": percentile(values, 0.95),
            "max": round(max(values), 3) if values else None}


@dataclass(frozen=True, slots=True)
class SqlWorkflowMetrics:
    pool: ConnectionPool

    def summary(self, tenant: str, *, since: str) -> dict[str, Any]:
        with self.pool.acquire() as conn:
            p = conn.p
            conn.begin()
            conn.set_tenant(tenant)
            operations = conn.execute(
                "SELECT state, agent_identity, started_at, completed_at, reconciled_by, reconciled_at "
                f"FROM execution_operations WHERE tenant_id={p} AND started_at>={p}",
                (tenant, since),
            )
            authorizations = conn.execute(
                "SELECT authorization_id, state, issued_at, document FROM execution_authorizations "
                f"WHERE tenant_id={p} AND issued_at>={p}",
                (tenant, since),
            )
            decisions = conn.execute(
                "SELECT resource_id, action, occurred_at, outcome FROM security_audit "
                f"WHERE tenant_id={p} AND resource_type={p} AND occurred_at>={p} ORDER BY seq",
                (tenant, "execution_authorization", since),
            )
            conn.commit()

        states: dict[str, int] = {}
        effect_seconds: list[float] = []
        reconcile_seconds: list[float] = []
        automatic = human = 0
        agents: set[str] = set()
        first_success = ""
        for row in operations:
            state = str(row["state"])
            states[state] = states.get(state, 0) + 1
            if state == "succeeded":
                agents.add(str(row["agent_identity"]))
                started = str(row["started_at"])
                first_success = min(first_success, started) if first_success else started
                if not row["reconciled_by"]:
                    elapsed = _seconds(started, str(row["completed_at"] or ""))
                    if elapsed is not None:
                        effect_seconds.append(elapsed)
            if row["reconciled_by"]:
                if str(row["reconciled_by"]).startswith("reconciler:"):
                    automatic += 1
                else:
                    human += 1
                elapsed = _seconds(str(row["completed_at"] or row["started_at"]), str(row["reconciled_at"] or ""))
                if elapsed is not None:
                    reconcile_seconds.append(elapsed)

        needed_approval = {
            str(row["authorization_id"]): str(row["issued_at"])
            for row in authorizations
            if json.loads(str(row["document"] or "{}")).get("policy_decision") == "require_approval"
        }
        approval_seconds: list[float] = []
        approved = rejected = refused_decisions = 0
        activated: set[str] = set()
        for row in decisions:
            authorization_id, action = str(row["resource_id"]), str(row["action"])
            if str(row["outcome"]).lower() not in {"success", "outcome.success"}:
                refused_decisions += 1
                continue
            if action == "authorization.reject":
                rejected += 1
            elif action == "authorization.approve" and authorization_id in needed_approval:
                activated.add(authorization_id)
        by_id = {str(r["authorization_id"]): str(r["state"]) for r in authorizations}
        for authorization_id in activated:
            if by_id.get(authorization_id) != "active":
                continue  # a quorum still open: not an approval yet
            approved += 1
            last = max(str(r["occurred_at"]) for r in decisions
                       if str(r["resource_id"]) == authorization_id and str(r["action"]) == "authorization.approve")
            elapsed = _seconds(needed_approval[authorization_id], last)
            if elapsed is not None:
                approval_seconds.append(elapsed)

        attempts = sum(states.values())
        refused = states.get("refused", 0)
        return {
            "since": since,
            "executions": {"attempted": attempts, **{s: states.get(s, 0) for s in
                           ("succeeded", "failed", "refused", "pending", "unknown_after_effect")}},
            # An interruption is an action an agent wanted that did not simply
            # proceed: it needed a human, or it was refused.
            "interruptions": {
                "needed_approval": len(needed_approval),
                "refused_at_execution": refused,
                "per_100_attempts": round(100 * (len(needed_approval) + refused) / attempts, 2) if attempts else None,
            },
            "approvals": {"requested": len(needed_approval), "approved": approved, "rejected": rejected,
                          "still_waiting": sum(1 for a in needed_approval if by_id.get(a) == "pending_approval"),
                          "decisions_refused": refused_decisions,
                          "latency_seconds": _distribution(approval_seconds)},
            "effect_duration_seconds": _distribution(effect_seconds),
            "unknown_outcomes": {"open": states.get("unknown_after_effect", 0),
                                 "settled_automatically": automatic, "settled_by_human": human,
                                 "time_to_settle_seconds": _distribution(reconcile_seconds)},
            "adoption": {"agents_with_a_successful_execution": len(agents),
                         "first_successful_execution_at": first_success},
            # Raw samples for the domain judges (value report, SLO verdicts). The
            # route consumes and removes this key; it is never returned.
            "_samples": {"approval_seconds": approval_seconds, "reconcile_seconds": reconcile_seconds,
                         "window_seconds": _seconds(since, max([since, *(str(r["started_at"]) for r in operations)])) or 0.0},
            "not_measured_here": [
                "gateway overhead per request (see the sentinel_http_request_duration_seconds histogram)",
                "whether a refusal was later judged legitimate (needs the customer's review)",
                "onboarding and support hours (needs the engagement log)",
            ],
        }
