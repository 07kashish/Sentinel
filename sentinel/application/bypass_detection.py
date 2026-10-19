"""Detect enrolled agents that have gone silent toward Sentinel.

This is NOT packet interception. It only sees agents that already enrolled and
then stopped producing events Sentinel observes. Under the F-11 deployment
contract (`deploy/agent-egress/` NetworkPolicy + admission + SDK/proxy),
non-contract agents are preventably fail-closed; silence here pages on-call for
enrolled agents that stop calling in.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from sentinel.domain.primitives import Timestamp

__all__ = [
    "AgentActivity",
    "DEFAULT_BYPASS_IDLE_SECONDS",
    "PossibleBypassSignal",
    "detect_possible_bypasses",
]

#: Default silence window before a `possible_bypass` signal is raised.
DEFAULT_BYPASS_IDLE_SECONDS = 15 * 60

#: Page-level severity for SLA breach (zero observed calls within idle window).
BYPASS_PAGE_SEVERITY = "page"


@dataclass(frozen=True, slots=True)
class AgentActivity:
    """One enrolled agent's last observed contact with Sentinel."""

    address: str
    enrolled_at: Timestamp
    last_event_at: Timestamp | None
    label: str = ""


@dataclass(frozen=True, slots=True)
class PossibleBypassSignal:
    """Loud signal: a registered agent has produced zero observed events in N minutes.

    Fields are sized for on-call paging (severity, pageable, recommended_action),
    not just log scraping.
    """

    kind: str
    address: str
    idle_seconds: float
    enrolled_at: str
    last_event_at: str | None
    detail: str
    severity: str
    pageable: bool
    sla_seconds: int
    zero_observed_calls: bool
    recommended_action: str
    agent_label: str

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "address": self.address,
            "idle_seconds": self.idle_seconds,
            "enrolled_at": self.enrolled_at,
            "last_event_at": self.last_event_at,
            "detail": self.detail,
            "severity": self.severity,
            "pageable": self.pageable,
            "sla_seconds": self.sla_seconds,
            "zero_observed_calls": self.zero_observed_calls,
            "recommended_action": self.recommended_action,
            "agent_label": self.agent_label,
        }


def detect_possible_bypasses(
    *,
    agents: Sequence[AgentActivity],
    now: Timestamp,
    idle_threshold_seconds: int = DEFAULT_BYPASS_IDLE_SECONDS,
) -> tuple[PossibleBypassSignal, ...]:
    """Return `possible_bypass` for enrolled agents silent for the threshold.

    Newly enrolled agents do not alert until they have been enrolled at least
    `idle_threshold_seconds` (otherwise every enrol would be an instant false
    positive). Silence is measured from `last_event_at` when present, otherwise
    from `enrolled_at`. Agents with zero observed calls after the SLA raise a
    pageable signal.
    """
    if idle_threshold_seconds <= 0:
        raise ValueError("idle_threshold_seconds must be positive")

    signals: list[PossibleBypassSignal] = []
    for agent in agents:
        enrolled_age = (now.value - agent.enrolled_at.value).total_seconds()
        if enrolled_age < idle_threshold_seconds:
            continue
        anchor = agent.last_event_at or agent.enrolled_at
        idle = (now.value - anchor.value).total_seconds()
        if idle < idle_threshold_seconds:
            continue
        zero_calls = agent.last_event_at is None
        signals.append(
            PossibleBypassSignal(
                kind="possible_bypass",
                address=agent.address,
                idle_seconds=idle,
                enrolled_at=agent.enrolled_at.isoformat(),
                last_event_at=(
                    agent.last_event_at.isoformat() if agent.last_event_at is not None else None
                ),
                detail=(
                    "enrolled agent produced no observed events within the idle "
                    "threshold; Sentinel cannot see traffic that never reaches it"
                ),
                severity=BYPASS_PAGE_SEVERITY,
                pageable=True,
                sla_seconds=idle_threshold_seconds,
                zero_observed_calls=zero_calls,
                recommended_action=(
                    "page on-call: verify agent runtime still routes through "
                    "/v1/events or /v1/tools/execute; confirm agent-egress "
                    "NetworkPolicy (deploy/agent-egress) is applied; revoke "
                    "enrolment if the agent is abandoned"
                ),
                agent_label=agent.label,
            )
        )
    return tuple(signals)
