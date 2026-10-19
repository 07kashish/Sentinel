"""F-11 deployment-contract admission checks (in-repo, no live apiserver).

Operators must run agent workloads under the documented contract in
`deploy/agent-egress/`. This module encodes the admit/reject rules so tests
prove fail-closed behaviour without claiming OS-level wire interception.

Bypass of Sentinel then requires breaking the contract (wrong labels, no
sidecar/SDK path, or cluster policy disabled) — an operator choice, not a
product gap under the remediation-matrix bar.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

__all__ = [
    "AdmissionDecision",
    "CONTRACT_VERSION",
    "REQUIRED_AGENT_LABELS",
    "REQUIRED_TOOL_PATH_ANNOTATION",
    "TOOL_PATH_VALUES",
    "admit_agent_workload",
]

CONTRACT_VERSION = "protect-egress-v1"

#: Mandatory labels for any pod that may run agent tool traffic. Immutable:
#: a plain dict here is a process global a caller could edit, which would
#: silently widen the admission contract for every later pod.
REQUIRED_AGENT_LABELS: Mapping[str, str] = MappingProxyType(
    {
        "sentinel.io/role": "agent",
        "sentinel.io/enrolled": "true",
    }
)

REQUIRED_TOOL_PATH_ANNOTATION = "sentinel.io/tool-path"
TOOL_PATH_VALUES = frozenset(
    {
        "sdk",  # InterceptedToolClient
        "execute",  # POST /v1/tools/execute
        "egress-proxy",  # deploy/agent-egress/egress-proxy sidecar
    }
)


@dataclass(frozen=True, slots=True)
class AdmissionDecision:
    """Result of evaluating a candidate agent workload against the contract."""

    allowed: bool
    reason: str
    contract_version: str = CONTRACT_VERSION

    def as_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "contract_version": self.contract_version,
        }


def admit_agent_workload(
    *,
    labels: Mapping[str, str] | None,
    annotations: Mapping[str, str] | None = None,
    has_egress_sidecar: bool = False,
) -> AdmissionDecision:
    """Fail-closed: reject workloads that are not under the Protect contract.

    A workload is admitted only when:
    - it carries `sentinel.io/role=agent` and `sentinel.io/enrolled=true`
    - it declares a tool path via annotation `sentinel.io/tool-path` in
      {sdk, execute, egress-proxy}, OR a Sentinel egress-proxy sidecar is
      present (`has_egress_sidecar=True`)
    """
    labels = dict(labels or {})
    annotations = dict(annotations or {})

    for key, expected in REQUIRED_AGENT_LABELS.items():
        actual = labels.get(key)
        if actual != expected:
            return AdmissionDecision(
                allowed=False,
                reason=(
                    f"missing or incorrect label {key}={expected!r} "
                    f"(got {actual!r}); refusing non-contract agent pod"
                ),
            )

    tool_path = (annotations.get(REQUIRED_TOOL_PATH_ANNOTATION) or "").strip()
    if has_egress_sidecar:
        return AdmissionDecision(
            allowed=True,
            reason="admitted: enrolled agent with Sentinel egress-proxy sidecar",
        )
    if tool_path in TOOL_PATH_VALUES:
        return AdmissionDecision(
            allowed=True,
            reason=f"admitted: enrolled agent tool-path={tool_path}",
        )
    return AdmissionDecision(
        allowed=False,
        reason=(
            f"missing {REQUIRED_TOOL_PATH_ANNOTATION} in {sorted(TOOL_PATH_VALUES)} "
            "and no egress-proxy sidecar; refusing off-contract agent"
        ),
    )
