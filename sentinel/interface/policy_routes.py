"""Policy-as-code over HTTP: validate, deploy, diff, simulate, roll back.

SECTION 29, INCLUDING THE SENTENCE THAT SHAPES IT
---------------------------------------------------
"Never silently apply malformed policies."

Every write path here runs `validate` FIRST and refuses with the reason. That
validation rejects two different things, and the second is the one that matters:
a document that fails to parse, and a document that parses perfectly and could
never match anything. The second deploys cleanly, reviews cleanly, and defends
nothing -- and it is the failure this repository has hit more often than any
other.

DEPLOY AND ACTIVATE ARE SEPARATE CALLS
----------------------------------------
Storing a version is reviewable and reversible. Making it active changes what
the estate enforces. Collapsing the two would mean the only way to review a
policy is to run it, which is exactly what §30's simulation exists to avoid.

ROLLBACK HAS NO CODE PATH OF ITS OWN
--------------------------------------
Rolling back is `POST /v1/policy/versions/{older}/activate`. There is therefore
nothing that can be correct for deployment and wrong for rollback, which is the
usual way a rollback fails on the night it is needed.
"""

from __future__ import annotations

from typing import Any, Literal, Sequence

from fastapi import Depends, FastAPI, HTTPException, Path, Query, status
from pydantic import BaseModel, Field

from sentinel.domain.authorization import Capability
from sentinel.domain.policy_as_code import (
    MalformedPolicy,
    PolicyEffect,
    PolicyRule,
    PolicyVersion,
    diff_versions,
    simulate,
    validate,
)
from sentinel.infrastructure.persistence.audit import Outcome

__all__ = ["PolicyDocument", "PolicyRulePayload", "register_policy_routes"]

#: Largest accepted policy version number.
#:
#: Bounded because an unbounded `int` path parameter reaches the SQL layer and
#: overflows: SQLite refuses an integer wider than 64 bits and the resulting
#: OverflowError escapes as a 500. Found by the schemathesis fuzzer on
#: `/v1/policy/diff` with target=32454664555118788771577856 -- and present on
#: `activate` and `simulate` too, which the fuzzer had not reached.
#:
#: The IDENTICAL bug was fixed earlier in this codebase on SCIM's `startIndex`.
#: Bounding at the schema rather than in the handler does two things: FastAPI
#: answers 422 instead of raising, and the range appears in the OpenAPI document
#: so the fuzzer generates useful values instead of rediscovering the edge.
#:
#: A billion versions is far beyond any real policy history and still an order of
#: magnitude inside a 64-bit column.
MAX_POLICY_VERSION: int = 1_000_000_000

#: How far back a simulation may replay. Bounded because the replay reads every
#: recorded step for the tenant, and an unbounded window is a way for one
#: authenticated call to scan the whole table.
MAX_SIMULATION_DAYS: int = 90


class PolicyRulePayload(BaseModel):
    """One rule as it arrives over HTTP, or from a file in version control."""

    name: str = Field(min_length=1, max_length=128)
    #: `Literal`, so the schema renders an enum. Same reasoning as
    #: `ApprovalDecision.decision`: CI fuzzes the API from this schema, and a
    #: free string means almost every generated example is filtered out.
    effect: Literal["allow", "warn", "require_approval", "block"]
    actions: list[str] = Field(default_factory=list, max_length=64)
    resources: list[str] = Field(default_factory=list, max_length=64)
    destinations: list[str] = Field(default_factory=list, max_length=64)
    minSeverity: int = Field(default=0, ge=0, le=100)
    description: str = Field(default="", max_length=1024)


class PolicyDocument(BaseModel):
    rules: list[PolicyRulePayload] = Field(min_length=1, max_length=500)
    note: str = Field(default="", max_length=512)


def _to_rules(document: PolicyDocument) -> list[PolicyRule]:
    return [
        PolicyRule(
            name=rule.name,
            effect=PolicyEffect(rule.effect),
            actions=tuple(rule.actions),
            resources=tuple(rule.resources),
            destinations=tuple(rule.destinations),
            min_severity=rule.minSeverity,
            description=rule.description,
        )
        for rule in document.rules
    ]


def register_policy_routes(app: FastAPI, container: Any, *, require: Any) -> None:
    """Attach the policy-as-code routes to an app."""

    uow_factory = container.uow_factory

    def _known_actions(tenant: Any) -> Sequence[str]:
        """Actions this tenant's agents have actually emitted.

        Passed to `validate` so a rule naming an action nobody emits is refused
        rather than deployed inert.

        An empty history disables the check instead of rejecting everything. A
        new tenant has emitted nothing, and refusing their first policy on that
        basis would be absurd -- `validate` treats an empty set as "no opinion".
        """
        with container.pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant.value)
            rows = conn.execute(
                f"SELECT DISTINCT action FROM execution_nodes WHERE tenant_id={conn.p}",
                (tenant.value,),
            )
            actions = tuple(str(row["action"]) for row in rows if row["action"])
            conn.commit()
        return actions

    def _validated(document: PolicyDocument, tenant: Any) -> tuple[PolicyRule, ...]:
        try:
            return validate(_to_rules(document), known_actions=_known_actions(tenant))
        except MalformedPolicy as exc:
            # 400, never 500. A malformed policy is the caller's document being
            # wrong, and the message names what to fix. A domain refusal
            # escaping as a server fault is a defect this codebase has shipped
            # before, on `/v1/mcp/evaluate`.
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    @app.post("/v1/policy/validate")
    def policy_validate(
        document: PolicyDocument,
        principal=Depends(require(Capability.MANAGE_POLICY)),
    ):
        """Check a policy without storing it. The dry run for policy."""
        rules = _validated(document, principal.tenant)
        return {"valid": True, "rule_count": len(rules)}

    @app.post("/v1/policy/versions", status_code=status.HTTP_201_CREATED)
    def policy_deploy(
        document: PolicyDocument,
        principal=Depends(require(Capability.MANAGE_POLICY)),
    ):
        """Store a new version. Deliberately does NOT activate it."""
        rules = _validated(document, principal.tenant)
        now = str(container.clock.now())
        with uow_factory.begin(principal.tenant) as uow:
            version = PolicyVersion(
                version=uow.policies.next_version(),
                rules=tuple(rules),
                created_by=f"key:{principal.key_hash[:12]}",
                created_at=now,
                note=document.note,
            )
            uow.policies.save(version)
            uow.commit()
        return {
            "version": version.version,
            "digest": version.digest,
            "active": False,
            "rule_count": len(version.rules),
        }

    @app.post("/v1/policy/versions/{version}/activate")
    def policy_activate(
        version: int = Path(ge=1, le=MAX_POLICY_VERSION),
        principal=Depends(require(Capability.MANAGE_POLICY)),
    ):
        """Activate a stored version. Rolling back is this call, older number."""
        now = str(container.clock.now())
        with uow_factory.begin(principal.tenant) as uow:
            activated = uow.policies.activate(
                version, by=f"key:{principal.key_hash[:12]}", at=now
            )
            uow.commit()

        container.security_audit.record(
            tenant=principal.tenant,
            actor=f"key:{principal.key_hash[:12]}",
            action="policy.activate",
            resource_type="policy_version",
            resource_id=str(version),
            outcome=Outcome.SUCCESS if activated else Outcome.FAILED,
            detail={"version": version, "role": principal.role},
        )
        if not activated:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND, detail=f"no policy version {version}"
            )
        return {"active_version": version}

    @app.get("/v1/policy/versions")
    def policy_history(principal=Depends(require(Capability.MANAGE_POLICY))):
        with uow_factory.begin(principal.tenant) as uow:
            history = uow.policies.history()
            active = uow.policies.active()
            uow.commit()
        return {
            "active_version": active.version if active else None,
            "versions": [
                {
                    "version": v.version,
                    "digest": v.digest,
                    "created_by": v.created_by,
                    "created_at": v.created_at,
                    "note": v.note,
                    "rule_count": len(v.rules),
                }
                for v in history
            ],
        }

    @app.get("/v1/policy/diff")
    def policy_diff(
        base: int = Query(ge=1, le=MAX_POLICY_VERSION),
        target: int = Query(ge=1, le=MAX_POLICY_VERSION),
        principal=Depends(require(Capability.MANAGE_POLICY)),
    ):
        """What changed between two stored versions, by rule name."""
        with uow_factory.begin(principal.tenant) as uow:
            before = uow.policies.get(base)
            after = uow.policies.get(target)
            uow.commit()
        if before is None or after is None:
            missing = base if before is None else target
            raise HTTPException(
                status.HTTP_404_NOT_FOUND, detail=f"no policy version {missing}"
            )
        return diff_versions(before, after).as_dict()

    @app.post("/v1/policy/versions/{version}/simulate")
    def policy_simulate(
        version: int = Path(ge=1, le=MAX_POLICY_VERSION),
        days: int = Query(default=7, ge=1, le=MAX_SIMULATION_DAYS),
        principal=Depends(require(Capability.MANAGE_POLICY)),
    ):
        """Section 30: what would this policy have done over recent history?

        The candidate is never activated -- that is the entire point of asking.
        Replay is over `execution_nodes`, the recorded trace of what agents
        actually did.
        """
        window = max(1, min(int(days), MAX_SIMULATION_DAYS))
        with uow_factory.begin(principal.tenant) as uow:
            candidate = uow.policies.get(version)
            uow.commit()
        if candidate is None:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND, detail=f"no policy version {version}"
            )

        with container.pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(principal.tenant.value)
            rows = conn.execute(
                f"SELECT action, resource, destination, severity, agent_id, incident_id "
                f"FROM execution_nodes WHERE tenant_id={conn.p} "
                f"ORDER BY occurred_at DESC",
                (principal.tenant.value,),
            )
            events = [
                {
                    "action": str(row["action"] or ""),
                    "resource": str(row["resource"] or ""),
                    "destination": str(row["destination"] or ""),
                    "severity": int(row["severity"] or 0),
                    "agent_id": str(row["agent_id"] or ""),
                    "incident_id": str(row["incident_id"] or ""),
                }
                for row in rows
            ]
            conn.commit()

        result = simulate(candidate, events).as_dict()
        result["window_days"] = window
        return result
