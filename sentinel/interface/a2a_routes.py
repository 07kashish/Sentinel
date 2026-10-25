"""A2A delegation over HTTP: evaluate a chain, enrol an agent card.

WHY THESE ARE SEPARATE ROUTES AND NOT A FIELD ON /v1/protect/evaluate
-----------------------------------------------------------------------
A delegation is not a richer tool call. It carries an authority chain whose
validity is a property of the WHOLE sequence -- amplification at hop 2 is
invisible when hop 2 is examined alone -- so the request body is a chain, and a
route that accepted one hop at a time could never see the thing worth seeing.

CAPABILITIES, AND WHY ENROLMENT IS NOT `EVALUATE_PROTECT`
-----------------------------------------------------------
Evaluating a delegation asks the same question `/v1/protect/evaluate` asks about
a richer subject, so it takes the same capability.

Enrolling an agent card DECIDES WHAT THE TRUST ANCHOR IS -- it pins the
fingerprint every later drift check compares against -- so it takes
`MANAGE_POLICY`, which is admin-only. A caller able to enrol is a caller able to
re-pin a drifted card as the new normal, and that is the one operation that can
silence drift detection permanently: durable, silent, and undetectable for
months, which is exactly the failure shape `MANAGE_POLICY` exists for rather
than the minutes-to-notice shape `MANAGE_CONTAINMENT` covers.

`MANAGE_AGENTS` would read as the natural name and does not exist. It was
removed as a capability that was defined, granted and enforced nowhere -- see
`test_every_capability_is_actually_guarded_by_a_route` -- and reintroducing it
for one route would recreate the table an access review misreads.

WHAT THIS IS NOT
----------------
Not an A2A wire proxy. `interface/mcp_proxy_routes.py` speaks MCP; nothing here
speaks A2A. An agent framework that never calls Sentinel stays outside
enforcement -- the same residual risk F-11 records for the inline tool proxy.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel, Field, model_validator

from sentinel.domain.a2a import (
    A2ARuleViolated,
    AgentCard,
    DelegationChain,
    DelegationHop,
)
from sentinel.domain.authorization import Capability
from sentinel.infrastructure.persistence.audit import Outcome
from sentinel.interface.delegation_verification import (
    passport_from_documents,
    verify_presented_chain,
)
from sentinel.interface.http_models import refuse_trust_level

__all__ = ["register_a2a_routes"]

#: Bounds on the request body. A chain arrives from a caller and every field in
#: it is interpolated into findings an analyst reads, so each is capped rather
#: than trusted. The hop cap is generous relative to `MAX_DELEGATION_DEPTH`
#: DELIBERATELY: a chain over the limit must be REPORTED as depth-exceeded, not
#: rejected as malformed, or the finding an operator needs never gets produced.
MAX_HOPS = 64
MAX_SCOPES_PER_HOP = 64


class HopPayload(BaseModel):
    """One delegation hop, described entirely by an untrusted caller."""

    fromAgent: str = Field(min_length=1, max_length=128)
    toAgent: str = Field(min_length=1, max_length=128)
    granted: Sequence[str] = Field(default_factory=tuple, max_length=MAX_SCOPES_PER_HOP)
    taskId: str = Field(default="", max_length=128)
    #: Attacker-influenced prose on the instruction path. Bounded like
    #: `McpCallPayload.description`, and for the same reason: it reaches the
    #: injection detector.
    instruction: str = Field(default="", max_length=8192)


class SignedHopPayload(BaseModel):
    """One SIGNED hop: the document its issuer signed, and the signature."""

    document: Mapping[str, Any]
    signature: str = Field(min_length=1, max_length=1024)
    key_id: str = Field(min_length=1, max_length=256)
    signed_at: str = Field(min_length=1, max_length=64)


class DelegationPayload(BaseModel):
    """A delegation chain.

    NOTE WHAT IS ABSENT: there is no field for whether the principal is known.
    That is resolved from the tenant's directory, so a caller cannot assert its
    own chain into attributability -- which, since an unattributable principal
    is a CRITICAL finding, is the field most worth making unreachable from the
    wire.

    ALSO ABSENT: `trustLevel`. The agent's trust is the credential's.

    `signedHops`, when present, is the chain AS SIGNED by each issuer. It is
    verified against the deployment's key ring before anything else is
    evaluated, and any finding refuses the request: a described chain says a
    delegation happened, a signed one proves who agreed to it.
    """

    principal: str = Field(min_length=1, max_length=256)
    principalScopes: Sequence[str] = Field(
        default_factory=tuple, max_length=MAX_SCOPES_PER_HOP
    )
    hops: Sequence[HopPayload] = Field(default_factory=tuple, max_length=MAX_HOPS)
    resource: str = Field(default="", max_length=2048)
    signedHops: Sequence[SignedHopPayload] = Field(
        default_factory=tuple, max_length=MAX_HOPS
    )

    @model_validator(mode="before")
    @classmethod
    def _no_asserted_trust(cls, data: Any) -> Any:
        return refuse_trust_level(data)


class AgentCardPayload(BaseModel):
    """An agent card to enrol. Enrolment PINS its fingerprint."""

    agentId: str = Field(min_length=1, max_length=128)
    version: str = Field(default="", max_length=64)
    endpoint: str = Field(default="", max_length=2048)
    capabilities: Sequence[str] = Field(
        default_factory=tuple, max_length=MAX_SCOPES_PER_HOP
    )
    description: str = Field(default="", max_length=8192)


def _chain_from(payload: DelegationPayload) -> DelegationChain:
    """Build the domain object, letting its own validation do the refusing.

    A DOMAIN INVARIANT VIOLATED BY CALLER INPUT IS A 400, NOT A 500. Pydantic
    accepts `" "` for a scope -- `min_length` is satisfied by one character --
    and `DelegationHop.__post_init__` then refuses it. The refusal is correct;
    without translation it would look like a server fault. Same lesson the MCP
    route learned from its schema fuzzer.
    """
    return DelegationChain(
        principal=payload.principal,
        principal_scopes=frozenset(payload.principalScopes),
        hops=tuple(
            DelegationHop(
                from_agent=hop.fromAgent,
                to_agent=hop.toAgent,
                granted=frozenset(hop.granted),
                task_id=hop.taskId,
                instruction=hop.instruction,
            )
            for hop in payload.hops
        ),
    )


def register_a2a_routes(app: FastAPI, container: Any, *, require: Any) -> None:
    """Attach the A2A delegation routes to an app."""

    audit = container.security_audit

    def _known_principals(tenant: Any) -> tuple[str, ...] | None:
        """Human identities this tenant has provisioned, or None to skip.

        `None` -- not an empty tuple -- when the directory holds nobody. An
        empty set would make every chain UNKNOWN_PRINCIPAL, which is a CRITICAL
        finding, so a deployment that has not wired SCIM yet would have every
        delegation refused. That is not a safe default, it is an unusable one,
        and an unusable control gets switched off. `inspect_chain` treats None
        as "no opinion" for exactly this case.
        """
        try:
            users = container.directory.list_users(tenant.value)
        except Exception:  # noqa: BLE001 - a directory outage must not decide this
            return None
        names = tuple(
            str(getattr(u, "user_name", "") or getattr(u, "id", "")) for u in users
        )
        return names or None

    @app.post("/v1/a2a/evaluate")
    def a2a_evaluate(
        payload: DelegationPayload,
        principal=Depends(require(Capability.EVALUATE_PROTECT)),
    ):
        """Decide whether a delegation chain may proceed.

        Four checks a single tool call cannot raise, then the SAME deterministic
        policy: did any hop grant authority its delegator did not hold, is any
        target unenrolled or drifted, is the chain a loop, and is the
        instruction text itself an injection.

        A chain presented WITH signatures is verified first. Any defect --
        an unknown key, a key that is not the issuer's, a broken link, a
        widened scope -- refuses the request with every finding named.
        """
        trust = principal.trust
        chain_verdict = None
        if payload.signedHops:
            try:
                passport = passport_from_documents(
                    [hop.model_dump() for hop in payload.signedHops]
                )
            except ValueError as exc:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST, detail=str(exc)
                ) from exc
            presenter = payload.hops[-1].toAgent if payload.hops else ""
            try:
                chain_verdict = verify_presented_chain(
                    container.delegation_verifier,
                    passport=passport,
                    tenant_id=principal.tenant.value,
                    presenter=presenter,
                    now=container.clock.now().value,
                )
            except ValueError as exc:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST, detail=str(exc)
                ) from exc
            if not chain_verdict.established:
                audit.record(
                    tenant=principal.tenant,
                    actor=f"key:{principal.key_hash[:12]}",
                    action="a2a.evaluate",
                    resource_type="delegation_chain",
                    resource_id=presenter or payload.principal,
                    outcome=Outcome.DENIED,
                    detail={
                        "reason": "signed_chain_refused",
                        "findings": [f.as_dict() for f in chain_verdict.findings],
                    },
                )
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN,
                    detail={
                        "reason": "the signed delegation chain does not establish authority",
                        "findings": [f.as_dict() for f in chain_verdict.findings],
                        "explanation": chain_verdict.explain(),
                    },
                )

        try:
            evaluation = container.a2a_gateway.evaluate(
                tenant_id=principal.tenant.value,
                chain=_chain_from(payload),
                trust=trust,
                known_principals=_known_principals(principal.tenant),
                resource=payload.resource,
            )
        except (A2ARuleViolated, ValueError) as exc:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, detail=str(exc)
            ) from exc

        # Audited on both outcomes. A refusal is the more interesting record:
        # "an agent granted authority it did not hold" leaves no other trace.
        audit.record(
            tenant=principal.tenant,
            actor=f"key:{principal.key_hash[:12]}",
            action="a2a.evaluate",
            resource_type="delegation_chain",
            resource_id=evaluation.chain.terminal_agent or payload.principal,
            outcome=(
                Outcome.DENIED if evaluation.blocked_structurally else Outcome.SUCCESS
            ),
            detail={
                "principal": payload.principal,
                "depth": evaluation.chain.depth,
                "severity": evaluation.severity.value,
                "findings": [f.kind.value for f in evaluation.findings],
                "decision": evaluation.outcome.decision.value,
                "trust": trust.value,
                "signed_chain_verified": chain_verdict is not None,
            },
        )
        response = evaluation.as_dict()
        response["signed_chain"] = (
            {
                "verified": True,
                "effective_capabilities": sorted(chain_verdict.effective_capabilities),
                "effective_scope": list(chain_verdict.effective_scope),
                "chain_digest": passport.digest,
            }
            if chain_verdict is not None
            else None
        )
        return response

    @app.post("/v1/a2a/cards", status_code=status.HTTP_201_CREATED)
    def a2a_enrol(
        payload: AgentCardPayload,
        principal=Depends(require(Capability.MANAGE_POLICY)),
    ):
        """Enrol an agent card and PIN its fingerprint.

        `MANAGE_POLICY`, not `EVALUATE_PROTECT`: a caller able to enrol is a
        caller able to re-pin a drifted card as the new normal, which is the one
        operation that can silence drift detection permanently.

        THE IN-PROCESS LIMIT, STATED HERE BECAUSE IT IS A SECURITY PROPERTY.
        The card store is per-process. A card enrolled through one replica is
        not visible to the next, so a multi-replica deployment does NOT have
        working A2A drift detection until the SQL-backed store exists. That is
        why this is not yet claimed as a production control.
        """
        try:
            card = container.a2a_gateway.enrol(
                principal.tenant.value,
                AgentCard(
                    agent_id=payload.agentId,
                    version=payload.version,
                    endpoint=payload.endpoint,
                    capabilities=frozenset(payload.capabilities),
                    description=payload.description,
                ),
            )
        except (A2ARuleViolated, ValueError) as exc:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, detail=str(exc)
            ) from exc

        audit.record(
            tenant=principal.tenant,
            actor=f"key:{principal.key_hash[:12]}",
            action="a2a.enrol",
            resource_type="agent_card",
            resource_id=card.agent_id,
            outcome=Outcome.SUCCESS,
            detail={"fingerprint": card.fingerprint, "version": card.version},
        )
        return card.as_dict()
