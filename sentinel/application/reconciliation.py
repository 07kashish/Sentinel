"""Settle unknown outcomes by asking the target, not a human.

An operation becomes `unknown_after_effect` when Sentinel cannot say whether
the side effect happened: the response was lost, the process died, the outcome
write failed. The honest first move is to look at the target. Each side effect
may register a RECONCILER that, given the identifiers recorded with the intent
(never the parameters), returns one of three verdicts:

    succeeded   the target shows THIS operation landed
    failed      the target shows it did not, and the approved precondition
                still holds, so nothing of ours is in flight
    unknown     the target cannot say; try again later, then ask a human

Rules this module holds to:

* It never re-runs an effect. Reconciliation reads.
* A verdict needs evidence, recorded as the reconciliation note.
* Attempts are bounded. After the bound the operation stays unknown and is
  listed for a human, exactly as before this module existed.
* A reconciler that raises is an `unknown` verdict, not a crash and not a guess.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Mapping, Protocol

from sentinel.domain.operations import ExecutionOperation, OperationState

__all__ = ["OperationReconciler", "ReconcileVerdict", "Reconciler"]

ATTEMPTS_KEY = "reconcile_attempts"
HINT_KEY = "reconcile_hint"


@dataclass(frozen=True, slots=True)
class ReconcileVerdict:
    state: OperationState
    evidence: str

    def __post_init__(self) -> None:
        allowed = {OperationState.SUCCEEDED, OperationState.FAILED, OperationState.UNKNOWN_AFTER_EFFECT}
        if self.state not in allowed:
            raise ValueError("a reconcile verdict is succeeded, failed or still unknown")
        if not self.evidence.strip():
            raise ValueError("a verdict without evidence is a guess")

    @property
    def settled(self) -> bool:
        return self.state is not OperationState.UNKNOWN_AFTER_EFFECT


Reconciler = Callable[[str, Mapping[str, Any]], ReconcileVerdict]


class _Store(Protocol):
    def list(self, tenant: str, *, states: Any = ..., limit: int = ...) -> list[ExecutionOperation]: ...
    def reconcile(self, tenant: str, operation_id: str, *, resolved_state: OperationState,
                  by: str, at: str, note: str) -> bool: ...
    def note_reconcile_attempt(self, tenant: str, operation_id: str, *, attempts: int, note: str) -> None: ...


@dataclass(frozen=True, slots=True)
class OperationReconciler:
    """Runs registered reconcilers over a tenant's unknown operations."""

    store: _Store
    #: tool name -> reconciler. Looked up per call so late registration works.
    reconcilers: Callable[[str], Reconciler | None]
    max_attempts: int = 5
    #: A `failed` verdict is accepted only this long after the effect started:
    #: longer than any outbound timeout, so no request of ours is still in
    #: flight and able to land after the target was read.
    quiescence_seconds: int = 120

    def run(self, tenant: str, *, now: datetime, limit: int = 50) -> dict[str, int]:
        totals = {"examined": 0, "succeeded": 0, "failed": 0, "still_unknown": 0,
                  "no_reconciler": 0, "exhausted": 0}
        unknown = self.store.list(tenant, states=(OperationState.UNKNOWN_AFTER_EFFECT,), limit=limit)
        for operation in unknown:
            totals["examined"] += 1
            attempts = int(operation.attributes.get(ATTEMPTS_KEY, 0) or 0)
            hint = operation.attributes.get(HINT_KEY)
            reconciler = self.reconcilers(operation.tool_identity)
            if reconciler is None or not isinstance(hint, Mapping):
                totals["no_reconciler"] += 1
                continue
            if attempts >= self.max_attempts:
                totals["exhausted"] += 1
                continue
            try:
                verdict = reconciler(operation.operation_id, hint)
            except Exception as exc:  # noqa: BLE001 - a broken lookup is not a verdict
                verdict = ReconcileVerdict(
                    OperationState.UNKNOWN_AFTER_EFFECT, f"target lookup failed ({type(exc).__name__})"
                )
            if verdict.state is OperationState.FAILED and not self._quiet(operation, now):
                totals["still_unknown"] += 1
                continue  # too early to rule out an in-flight write; not an attempt
            if verdict.settled and self.store.reconcile(
                tenant, operation.operation_id, resolved_state=verdict.state,
                by=f"reconciler:{operation.tool_identity}", at=now.isoformat(), note=verdict.evidence,
            ):
                totals[verdict.state.value] += 1
                continue
            totals["still_unknown"] += 1
            self.store.note_reconcile_attempt(
                tenant, operation.operation_id, attempts=attempts + 1, note=verdict.evidence
            )
        return totals

    def _quiet(self, operation: ExecutionOperation, now: datetime) -> bool:
        try:
            started = datetime.fromisoformat(operation.started_at)
        except ValueError:
            return False
        return (now - started).total_seconds() >= self.quiescence_seconds
