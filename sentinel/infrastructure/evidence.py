"""Evidence construction, report rendering and remediation planning.

The evidence leaf is IDENTITY-BOUND: it commits to `tenant_id + incident_id +
body digest`, not the body alone. Hashing only the body lets a genuine signed
proof be relabelled onto a different incident and still verify.

The report renderer takes explicit arguments rather than a mutable context, so
there is no way to render one from `None` -- which is what produced the
predecessor's durable, auditable reports reading "Not available" throughout after
any retry.
"""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from typing import Any, Final, Mapping, Sequence

from sentinel.application.records import ApprovalRecord, EvidenceRecord, ModelAdvice
from sentinel.domain.primitives import (
    Digest,
    IncidentId,
    Severity,
    TenantId,
    Timestamp,
)
from sentinel.domain.remediation import (
    EvidenceOrigin,
    UnknownRemediationAction,
    decide_response,
)

__all__ = ["CanonicalEvidenceBuilder", "MarkdownReportRenderer", "RuleBasedPlanner"]


class CanonicalEvidenceBuilder:
    """Builds the evidence body and its IDENTITY-BOUND leaf hash.

    The leaf commits to `tenant_id + incident_id + body digest`, not the body
    alone. Hashing only the body lets a genuine signed proof be relabelled onto a
    different incident and still verify; binding the identity into the leaf makes
    relabelling change the hash and break the signature.
    """

    __slots__ = ("_manifest_version",)

    def __init__(self, *, manifest_version: int = 2) -> None:
        self._manifest_version = manifest_version

    def build(
        self,
        *,
        tenant: TenantId,
        incident_id: IncidentId,
        incident_facts: Mapping[str, Any],
        approvals: Sequence[ApprovalRecord],
        advice: ModelAdvice | None,
        detector_version: str,
        at: Timestamp,
    ) -> tuple[EvidenceRecord, Digest, Mapping[str, Any]]:
        content: dict[str, Any] = {
            "schema": "sentinel.evidence/v2",
            "tenant_id": tenant.value,
            "incident_id": incident_id.value,
            "created_at": at.isoformat(),
            "detector_version": detector_version,
            "severity": incident_facts.get("severity"),
            "priority": incident_facts.get("priority"),
            "trust_level": incident_facts.get("trust_level"),
            "trust_reason": incident_facts.get("trust_reason"),
            "signer_address": incident_facts.get("signer_address"),
            "event_digest": incident_facts.get("event_digest"),
            "matched_rules": list(incident_facts.get("matched_rules") or []),
            "detection_signals": incident_facts.get("detection_signals") or {},
            "raw_payload": incident_facts.get("raw_payload") or {},
            # Approvals are recorded EXPLICITLY, including their absence. The
            # predecessor swallowed every exception while reading them and
            # returned an empty list, so an evidence package could silently
            # claim no human decisions existed when in fact the query failed.
            "approvals": [
                {
                    "approval_id": a.approval_id.value,
                    "action": a.action,
                    "target": a.target,
                    "state": a.state,
                    "decided_by": a.decided_by,
                }
                for a in approvals
            ],
            "advisory": {
                "available": bool(advice and advice.available),
                "detail": advice.detail if advice else "no advisory layer was consulted",
                "model": advice.model_receipt if advice else None,
                "authoritative": False,
            },
        }
        canonical = json.dumps(content, sort_keys=True, separators=(",", ":"), default=str)
        body_digest = Digest(hashlib.sha256(canonical.encode("utf-8")).hexdigest())

        manifest = {
            "v": self._manifest_version,
            "tenant_id": tenant.value,
            "incident_id": incident_id.value,
            "body_digest": body_digest.value,
            "created_at": at.isoformat(),
        }
        manifest_bytes = json.dumps(
            manifest, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        # Domain-separated: a leaf can never be confused with an internal node.
        leaf = Digest(hashlib.sha256(b"\x00" + manifest_bytes).hexdigest())

        record = EvidenceRecord(
            incident_id=incident_id,
            uri=f"sentinel://evidence/{tenant}/{incident_id}",
            digest=body_digest,
            content=content,
            created_at=at,
        )
        return record, leaf, manifest


class MarkdownReportRenderer:
    """Renders the analyst report from durable artifacts only.

    Every field comes from an argument. There is no context object with optional
    artifacts, so there is no way to render a report from `None` -- which is what
    produced the predecessor's durable, auditable reports reading "Not available"
    throughout after any retry.
    """

    __slots__ = ()

    def render(
        self,
        *,
        incident_facts: Mapping[str, Any],
        evidence: EvidenceRecord,
        approvals: Sequence[ApprovalRecord],
        advice: ModelAdvice | None,
        at: Timestamp,
    ) -> str:
        lines = [
            f"# Incident {evidence.incident_id}",
            "",
            f"- **Generated:** {at.isoformat()}",
            f"- **Severity:** {incident_facts.get('severity')} "
            f"({incident_facts.get('priority')})",
            f"- **Trust level:** {incident_facts.get('trust_level')} "
            f"— {incident_facts.get('trust_reason')}",
            f"- **Detector version:** {incident_facts.get('detector_version')}",
            f"- **Evidence digest:** `{evidence.digest}`",
            f"- **Evidence URI:** `{evidence.uri}`",
            "",
            "## Deterministic findings",
            "",
        ]
        rules = list(incident_facts.get("matched_rules") or [])
        if rules:
            lines.extend(f"- `{rule}`" for rule in rules)
        else:
            lines.append("- No policy rule matched; this incident was raised by another path.")

        lines.extend(["", "## Description", "", str(incident_facts.get("description") or "—")])

        lines.extend(["", "## Proposed actions awaiting a human", ""])
        if approvals:
            lines.extend(
                f"- `{a.approval_id}` — **{a.action}** on `{a.target}` ({a.state})"
                for a in approvals
            )
        else:
            lines.append("- None proposed.")

        lines.extend(["", "## Advisory second opinion (NOT authoritative)", ""])
        if advice and advice.available:
            lines.extend(
                [
                    f"- **Model:** `{advice.model_receipt}`",
                    f"- **Suggested priority:** {advice.suggested_priority} "
                    "(recorded only; it cannot move triage)",
                    f"- **Reasoning:** {advice.reasoning or '—'}",
                ]
            )
            lines.extend(f"- **Recommendation:** {r}" for r in advice.recommendations)
        else:
            lines.append(f"- {advice.detail if advice else 'Not consulted.'}")

        lines.extend(
            [
                "",
                "---",
                "",
                "*Priority is a deterministic function of severity. The advisory "
                "layer reads attacker-influenced text and is recorded for context "
                "only; it cannot influence triage in either direction.*",
                "",
            ]
        )
        return "\n".join(lines)


#: How long a proposed remediation stays executable.
#:
#: Twenty-four hours: long enough to survive a handover and a night, short
#: enough that approving one is a decision about a live situation rather than a
#: standing grant. An approval outliving the incident it was raised for is
#: approved against an estate that has since changed.
APPROVAL_WINDOW: Final[timedelta] = timedelta(hours=24)


class RuleBasedPlanner:
    """Proposes remediation for a human to approve. Executes nothing.

    The model's recommendations are deliberately NOT a source of proposals. An
    action list derived from attacker-influenced text, presented to an analyst as
    a one-click approval, is a confused-deputy primitive. Proposals come from the
    deterministic incident type; the advisory text is shown alongside as context.
    """

    __slots__ = ("_actions",)

    def __init__(self, *, actions: Mapping[str, str] | None = None) -> None:
        # THE NAMES HERE MUST BE CATALOGUE NAMES.
        #
        # They used to be `quarantine_agent_session`, `revoke_tool_grant`,
        # `isolate_agent` and `require_human_review` -- none of which exist in
        # `domain/remediation.py`. That was invisible while the deployment ran
        # `NullRemediationExecutor`, which supports nothing and refuses
        # everything identically. The moment a real executor is wired, a
        # proposal naming an action the catalogue has never heard of is refused
        # as `unsupported_action` -- an approval an analyst can click and which
        # can never do anything.
        #
        # The same failure Phase 3 hit with sequence rules written for action
        # names no agent emits. `test_every_proposed_action_is_in_the_catalogue`
        # fails the build if this drifts again.
        self._actions = dict(
            actions
            or {
                # Contain the workload rather than killing it: reversible, and
                # an injected agent is evidence worth keeping alive to inspect.
                "prompt_injection_suspected": "quarantine_workload",
                # Remove the grant that reached the resource, not the agent.
                "sensitive_resource_access": "remove_tool_access",
                "unexpected_code_execution": "quarantine_workload",
                "privilege_abuse_suspected": "revoke_agent_credential",
                "context_disclosure_attempt": "remove_tool_access",
                # ASSERTED, not observed -- the agent said so about itself. The
                # response is to tell a human, never to act on the claim.
                "asserted_high_risk": "notify_owner",
            }
        )

    def propose(
        self,
        *,
        incident_facts: Mapping[str, Any],
        advice: ModelAdvice | None,
        incident_id: IncidentId,
        ids: Any,
        at: Timestamp,
    ) -> Sequence[ApprovalRecord]:
        incident_type = str(incident_facts.get("incident_type") or "")
        action = self._actions.get(incident_type)
        if action is None:
            return ()
        target = str(
            incident_facts.get("signer_address")
            or (incident_facts.get("raw_payload") or {}).get("agentId")
            or ""
        ).strip()
        if not target:
            # No resolvable target means no proposal. Proposing an action with an
            # empty target invites an analyst to approve something undefined.
            return ()
        # SECTION 33, APPLIED AT THE ONE PLACE PROPOSALS ARE MADE.
        #
        # `decide_response` is the deterministic strategy: severity plus the
        # action's own properties decide how much autonomy the response gets. It
        # is consulted here rather than at execution time because the answer is
        # what the approval is FOR -- an analyst opening a request needs to see
        # what the system would have done and why it did not just do it.
        #
        # Provenance is SELF_REPORTED unless the incident records that Sentinel
        # observed the activity in its own enforcement path. That default is the
        # restrictive one: an incident raised from execution-graph correlation or
        # a declared intent is evidence an agent can shape, and it must not reach
        # an automatic disposition. See `domain/remediation.py`.
        severity = Severity(int(incident_facts.get("severity") or 0))
        origin = (
            EvidenceOrigin.OBSERVED
            if str(incident_facts.get("evidence_origin") or "") == "observed"
            else EvidenceOrigin.SELF_REPORTED
        )
        try:
            decision = decide_response(action, severity, origin=origin)
        except UnknownRemediationAction:
            # A configured action outside the catalogue. Refuse to propose rather
            # than raise an approval nothing can execute.
            return ()

        context: dict[str, Any] = {
            "severity": severity.value,
            "priority": decision.priority.value,
            "agent_id": target,
            "incident_type": incident_type,
            # Section 32's named fields.
            "risk_factors": list(incident_facts.get("risk_factors") or ()),
            "business_impact": decision.action.summary,
            "blast_radius": decision.action.blast_radius.value,
            "reversible": decision.action.reversible,
            "rollback_action": decision.action.rollback,
            "recommended_decision": decision.disposition.value,
            "recommendation_reason": decision.reason,
            "restrained": decision.restrained,
            "evidence_origin": origin.value,
            # The execution graph session, so an approver can open the causal
            # trail instead of taking the summary on trust.
            "session_id": str(
                (incident_facts.get("raw_payload") or {}).get("sessionId") or ""
            ),
        }
        if advice is not None:
            # Advisory only, and labelled as such. It is derived from
            # attacker-influenced text; it informs a human and decides nothing.
            context["advisory_summary"] = str(advice.reasoning or advice.detail)[:1024]

        return (
            ApprovalRecord(
                approval_id=ids.approval_id(),
                incident_id=incident_id,
                action=action,
                target=target,
                state="pending",
                proposed_at=at,
                # THE EXPIRY. Previously absent, which made every approval a
                # standing authorization to act on production and made the
                # expiry branch in `DecideApprovalHandler` unreachable.
                expires_at=Timestamp(at.value + APPROVAL_WINDOW),
                context=context,
            ),
        )
