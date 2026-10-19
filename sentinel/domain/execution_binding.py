"""Bind an authorization to the execution it authorized.

THE GAP THIS CLOSES
-------------------
Everything else in this codebase attests to a DECISION. The policy engine
evaluates a payload, the passport records what was decided, the signature
covers the passport and the transparency log proves the record was not altered
afterwards. All of it verifies. None of it says the executed action was the
action that was approved.

`ProtectedToolRunner.execute` shows the shape of the hole exactly. It takes a
description of the intended action and, separately, a zero-argument closure:

    self._gate.run_if_allowed(payload=payload, trust=trust, action=side_effect)

The gate decides over `payload`. Then it calls `side_effect()`, which can do
anything at all. The payload is a DESCRIPTION, not a binding, and the two are
only connected by the caller having been honest. So an agent authorized to
write to one bucket could write to another, and the passport, the signature and
the inclusion proof would all still verify -- because they are true statements
about the decision, and the decision was never about what ran.

Question 12 of the eighteen -- "did approved and executed parameters differ?"
-- is the one this module exists to be able to answer.

HOW IT IS ANSWERED
------------------
`ExecutionAuthorization` commits to `approved_parameter_digest`, a
domain-separated digest over the canonicalised parameters. Immediately before
execution the caller must present the parameters it is ACTUALLY about to use;
`verify_binding` recomputes the digest and refuses on any difference. The
authorization also pins tool, MCP server, action, resource, tenant and agent,
so substituting any of those is the same class of refusal rather than a
separate feature.

WHY THE DIGEST IS DOMAIN-SEPARATED
-----------------------------------
`digest_of({...parameters})` alone would be a bare hash of a JSON object, and
this codebase already hashes policies, passports and Merkle leaves the same
way. A digest that could be mistaken for a digest of something else is a
cross-protocol substitution waiting to happen -- the reason RFC 6962 prefixes
leaves with 0x00 and nodes with 0x01, which `transparency.py` already does. So
parameters are wrapped in a context envelope before hashing.

BOUNDED MUTATION IS OPT-IN AND NAMED
-------------------------------------
Some parameters legitimately change between approval and execution: a
request id, a timestamp, a pagination cursor. `mutable_parameters` lists the
keys policy has explicitly permitted to differ, BY NAME. There is no "allow
mutation" boolean, because a boolean would be set once by somebody in a hurry
and would then permit substituting the destination bucket. Anything not named
must match exactly, and every mutation that was allowed is recorded on the
verdict so the receipt can show what changed.

WHY REPLAY IS CHECKED INSIDE THE VERIFICATION AND NOT BY THE CALLER
--------------------------------------------------------------------
A pure function plus a caller who remembers to mark the nonce used is a
time-of-check-to-time-of-use race: two concurrent requests both read "unused",
both pass, both execute. So `verify_binding` claims the nonce itself, through a
`NonceLedger` whose `claim` must be atomic. The claim happens only after every
other check has passed -- a refused attempt does not burn the authorization,
because a refused attempt executed nothing and a legitimate retry after a
network failure should still work.

WHAT THIS MODULE DOES NOT DO
-----------------------------
It does not sign anything and it does not decide anything. Signing lives in
`passport_signing`, deciding lives in the policy engine. This is the comparison
in between, and it is deliberately dull: a security check whose logic is
interesting is a security check nobody can review.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping, Protocol

from sentinel.domain.passport import digest_of

__all__ = [
    "DEFAULT_AUTHORIZATION_TTL_SECONDS",
    "PARAMETER_CONTEXT",
    "BindingDefect",
    "BindingVerdict",
    "ExecutionAuthorization",
    "ExecutionReceipt",
    "ExecutionRequest",
    "NonceLedger",
    "RejectingNonceLedger",
    "issue_authorization",
    "parameter_digest",
    "verify_binding",
]

#: Prepended to parameters before hashing so a parameter digest can never be
#: mistaken for a digest of a passport, a policy bundle or a Merkle leaf. The
#: version is in the string: changing the canonical form MUST change this, or
#: old and new digests would silently compare unequal with no explanation.
PARAMETER_CONTEXT = "sentinel.execution.parameters.v1"

_DIGEST_LENGTH = 64
_HEX = frozenset("0123456789abcdef")


def parameter_digest(parameters: Mapping[str, Any]) -> str:
    """The digest an authorization commits to, and execution is checked against.

    Rejects floats through the canonicaliser it borrows: 0.1 does not round-trip
    identically across languages, so a float in a signed document is a
    signature that verifies on one runtime and fails on another.
    """
    return digest_of({"context": PARAMETER_CONTEXT, "parameters": dict(parameters)})


def _is_digest(value: str) -> bool:
    return len(value) == _DIGEST_LENGTH and set(value.lower()) <= _HEX


def _parse_instant(value: str, *, field_name: str) -> datetime:
    """An ISO-8601 instant that MUST carry a timezone.

    A naive timestamp in an expiry is an expiry that means different moments in
    different deployments, which is how a credential outlives its window.
    """
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(
            f"{field_name}={value!r} is not an ISO-8601 instant"
        ) from error
    if parsed.tzinfo is None:
        raise ValueError(
            f"{field_name}={value!r} has no timezone. A naive expiry means a "
            "different moment in every deployment that reads it."
        )
    return parsed.astimezone(timezone.utc)


class BindingDefect(str, Enum):
    """Why an execution was refused.

    Every member is truthy and non-empty. An enum with a falsy member gets used
    in a boolean test somewhere and then the most serious case is the one that
    reads as "no problem" -- the defect this codebase already found in an SDK
    decision enum.
    """

    NOT_AUTHORIZED = "not_authorized"
    PARAMETERS_DIFFER = "parameters_differ"
    TOOL_SUBSTITUTED = "tool_substituted"
    MCP_SERVER_SUBSTITUTED = "mcp_server_substituted"
    ACTION_SUBSTITUTED = "action_substituted"
    RESOURCE_SUBSTITUTED = "resource_substituted"
    AGENT_SUBSTITUTED = "agent_substituted"
    CROSS_TENANT = "cross_tenant"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    REPLAYED = "replayed"
    DELEGATION_SUBSTITUTED = "delegation_substituted"

    @property
    def explanation(self) -> str:
        return _EXPLANATIONS[self]


# MappingProxyType, not a plain dict. The `Mapping` annotation is a promise to
# a type checker and nothing at all at runtime -- a module-level dict stays
# writable, and a security explanation an attacker-influenced code path could
# rewrite is a refusal message that can be made to say the wrong thing. The
# architecture fitness rule catches this, and caught it here.
_EXPLANATIONS: Mapping[BindingDefect, str] = MappingProxyType({
    BindingDefect.NOT_AUTHORIZED: (
        "no authorization was presented for this execution, so there is nothing "
        "to bind it to"
    ),
    BindingDefect.PARAMETERS_DIFFER: (
        "the parameters about to be executed do not match the parameters that "
        "were approved"
    ),
    BindingDefect.TOOL_SUBSTITUTED: (
        "a different tool is about to run than the one authorized"
    ),
    BindingDefect.MCP_SERVER_SUBSTITUTED: (
        "the call is about to be routed through a different MCP server than the "
        "one authorized"
    ),
    BindingDefect.ACTION_SUBSTITUTED: (
        "a different action is about to be performed than the one authorized"
    ),
    BindingDefect.RESOURCE_SUBSTITUTED: (
        "a different resource is about to be affected than the one authorized"
    ),
    BindingDefect.AGENT_SUBSTITUTED: (
        "a different agent is presenting this authorization than the one it was "
        "issued to, which is privilege amplification by reuse"
    ),
    BindingDefect.CROSS_TENANT: (
        "the authorization belongs to a different tenant"
    ),
    BindingDefect.EXPIRED: "the authorization has expired",
    BindingDefect.NOT_YET_VALID: (
        "the authorization is not valid yet, which usually means clock skew "
        "between the issuer and the enforcement point"
    ),
    BindingDefect.REPLAYED: (
        "this authorization has already been used; it is single-use"
    ),
    BindingDefect.DELEGATION_SUBSTITUTED: (
        "the delegation chain presented is not the one this authorization was "
        "issued against. A different chain may grant the same capability and "
        "come from a different principal, which is whose authority is being "
        "exercised"
    ),
})


class NonceLedger(Protocol):
    """Single-use enforcement for authorizations.

    `claim` MUST be atomic across every process that can enforce, or two
    concurrent requests both observe an unused nonce and both execute. That is
    why this is a port and not a set: a set in a worker process makes replay
    prevention per-process, which is the same defect class as a per-process rate
    limiter.
    """

    def claim(self, *, tenant_id: str, nonce: str) -> bool:
        """True if this nonce was unused and is now claimed. False if replayed."""
        ...


@dataclass(frozen=True, slots=True)
class RejectingNonceLedger:
    """A ledger that claims nothing, so every execution reads as replayed.

    The default where no real ledger is configured. It fails CLOSED, which makes
    a missing ledger an immediate and obvious outage rather than a silent loss
    of replay protection -- the alternative default, an in-process set, would
    work perfectly in every test and protect nothing in production.
    """

    reason: str = "no nonce ledger is configured, so single-use cannot be enforced"

    def claim(self, *, tenant_id: str, nonce: str) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class ExecutionAuthorization:
    """What was approved. Immutable, and committing to a parameter digest.

    Frozen because an authorization that can be edited after issuance is a
    description of intent rather than a commitment, and the entire value here is
    that it is a commitment.
    """

    authorization_id: str
    tenant_id: str
    #: The human or workload on whose behalf this runs.
    actor_identity: str
    #: The agent this authorization was ISSUED TO. Anyone else presenting it is
    #: amplifying privilege by reuse.
    agent_identity: str
    tool_identity: str
    action: str
    target_resource: str
    #: The commitment. `parameter_digest` of the approved parameters.
    approved_parameter_digest: str
    issued_at: str
    expires_at: str
    #: Single-use. Claimed through the ledger during verification.
    nonce: str

    parent_agent_identity: str = ""
    delegation_chain: tuple[Mapping[str, Any], ...] = ()
    mcp_server_identity: str = ""
    policy_bundle_digest: str = ""
    policy_decision: str = ""
    conditions: Mapping[str, Any] = field(default_factory=dict)
    #: Digest of the SIGNED delegation chain this authorization was issued
    #: against, from `delegation_passport.chain_digest`. Empty means no chain
    #: was bound, which `verify_binding` reports rather than treats as "any
    #: chain will do".
    #:
    #: A digest and not a copy of the chain: an authorization that embedded the
    #: hops would double their size and, worse, give a caller two places to
    #: present a chain from -- and the two could disagree.
    delegation_passport_digest: str = ""
    #: Parameter names policy has EXPLICITLY permitted to differ at execution.
    #: Named individually on purpose: a boolean would be switched on once and
    #: would then permit substituting the destination.
    mutable_parameters: frozenset[str] = frozenset()
    signature: str = ""

    def __post_init__(self) -> None:
        required = {
            "authorization_id": self.authorization_id,
            "tenant_id": self.tenant_id,
            "agent_identity": self.agent_identity,
            "tool_identity": self.tool_identity,
            "action": self.action,
            "nonce": self.nonce,
        }
        missing = sorted(name for name, value in required.items() if not value.strip())
        if missing:
            raise ValueError(
                f"an authorization without {', '.join(missing)} cannot be bound "
                "to an execution, so it would authorize anything"
            )
        if not _is_digest(self.approved_parameter_digest):
            raise ValueError(
                f"approved_parameter_digest="
                f"{self.approved_parameter_digest!r} is not a sha256 hex digest. "
                "An empty or malformed commitment would compare unequal to every "
                "execution, or -- worse, if a caller defaulted it -- equal to "
                "all of them."
            )
        issued = _parse_instant(self.issued_at, field_name="issued_at")
        expires = _parse_instant(self.expires_at, field_name="expires_at")
        if expires <= issued:
            raise ValueError(
                f"expires_at ({self.expires_at}) is not after issued_at "
                f"({self.issued_at}), so this authorization was never valid"
            )

    @property
    def expiry(self) -> datetime:
        return _parse_instant(self.expires_at, field_name="expires_at")

    @property
    def issuance(self) -> datetime:
        return _parse_instant(self.issued_at, field_name="issued_at")

    def as_document(self) -> dict[str, Any]:
        """The body a signature covers. Excludes the signature itself."""
        return {
            "context": "sentinel.execution.authorization.v1",
            "authorization_id": self.authorization_id,
            "tenant_id": self.tenant_id,
            "actor_identity": self.actor_identity,
            "agent_identity": self.agent_identity,
            "parent_agent_identity": self.parent_agent_identity,
            "delegation_chain": [dict(hop) for hop in self.delegation_chain],
            "tool_identity": self.tool_identity,
            "mcp_server_identity": self.mcp_server_identity,
            "action": self.action,
            "target_resource": self.target_resource,
            "approved_parameter_digest": self.approved_parameter_digest,
            "delegation_passport_digest": self.delegation_passport_digest,
            "policy_bundle_digest": self.policy_bundle_digest,
            "policy_decision": self.policy_decision,
            "conditions": dict(self.conditions),
            "mutable_parameters": sorted(self.mutable_parameters),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
        }

    @property
    def digest(self) -> str:
        return digest_of(self.as_document())

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> "ExecutionAuthorization":
        """Rebuild an authorization from the body `as_document` produced.

        The inverse of `as_document`, so a stored authorization round-trips
        through a durable store and its digest is the digest that was issued.
        `__post_init__` re-runs, so a tampered or truncated row is refused at
        construction rather than compared against an execution.
        """
        return cls(
            authorization_id=str(document["authorization_id"]),
            tenant_id=str(document["tenant_id"]),
            actor_identity=str(document.get("actor_identity", "")),
            agent_identity=str(document["agent_identity"]),
            tool_identity=str(document["tool_identity"]),
            action=str(document["action"]),
            target_resource=str(document.get("target_resource", "")),
            approved_parameter_digest=str(document["approved_parameter_digest"]),
            issued_at=str(document["issued_at"]),
            expires_at=str(document["expires_at"]),
            nonce=str(document["nonce"]),
            parent_agent_identity=str(document.get("parent_agent_identity", "")),
            delegation_chain=tuple(
                dict(hop) for hop in document.get("delegation_chain", ())
            ),
            mcp_server_identity=str(document.get("mcp_server_identity", "")),
            policy_bundle_digest=str(document.get("policy_bundle_digest", "")),
            policy_decision=str(document.get("policy_decision", "")),
            conditions=dict(document.get("conditions", {}) or {}),
            delegation_passport_digest=str(
                document.get("delegation_passport_digest", "")
            ),
            mutable_parameters=frozenset(document.get("mutable_parameters", ())),
        )


#: How long an issued authorization stays valid. Short on purpose: an
#: authorization is a decision about ONE call an agent is about to make, and a
#: window long enough to survive a coffee break is a window in which the
#: estate it was decided against has changed.
DEFAULT_AUTHORIZATION_TTL_SECONDS = 300


def issue_authorization(
    *,
    authorization_id: str,
    nonce: str,
    tenant_id: str,
    actor_identity: str,
    agent_identity: str,
    tool_identity: str,
    action: str,
    target_resource: str,
    parameters: Mapping[str, Any],
    now: datetime,
    policy_decision: str,
    mcp_server_identity: str = "",
    ttl_seconds: int = DEFAULT_AUTHORIZATION_TTL_SECONDS,
    policy_bundle_digest: str = "",
    delegation_passport_digest: str = "",
    conditions: Mapping[str, Any] | None = None,
) -> ExecutionAuthorization:
    """Commit to exactly one execution: these parameters, this tool, this agent.

    The id and nonce are PASSED IN rather than generated here so this module
    stays free of randomness and clocks -- the composition root supplies both,
    which is what lets a test issue a deterministic authorization and what
    keeps the domain replayable against historical evidence.
    """
    if ttl_seconds < 1:
        raise ValueError("an authorization must be valid for at least one second")
    issued = now.astimezone(timezone.utc)
    expires = issued + timedelta(seconds=int(ttl_seconds))
    return ExecutionAuthorization(
        authorization_id=authorization_id,
        tenant_id=tenant_id,
        actor_identity=actor_identity,
        agent_identity=agent_identity,
        tool_identity=tool_identity,
        action=action,
        target_resource=target_resource,
        approved_parameter_digest=parameter_digest(parameters),
        issued_at=issued.isoformat(),
        expires_at=expires.isoformat(),
        nonce=nonce,
        mcp_server_identity=mcp_server_identity,
        policy_bundle_digest=policy_bundle_digest,
        policy_decision=policy_decision,
        conditions=dict(conditions or {}),
        delegation_passport_digest=delegation_passport_digest,
    )


@dataclass(frozen=True, slots=True)
class ExecutionRequest:
    """What is ACTUALLY about to run, captured immediately before it runs.

    The parameters here are the ones that will be passed to the tool, not a
    description of them. If a caller can build this from something other than
    the values it is about to use, the binding is decorative -- which is why
    `ProtectedToolRunner` passes the verified parameters INTO the side effect
    rather than trusting a closure to have used them.
    """

    tenant_id: str
    agent_identity: str
    tool_identity: str
    action: str
    target_resource: str
    parameters: Mapping[str, Any] = field(default_factory=dict)
    mcp_server_identity: str = ""
    #: Digest of the chain the caller is ACTUALLY presenting. Compared against
    #: the authorization's, so a valid chain from a different principal is
    #: refused rather than accepted for granting the same capability.
    delegation_passport_digest: str = ""

    @property
    def parameter_digest(self) -> str:
        return parameter_digest(self.parameters)


@dataclass(frozen=True, slots=True)
class BindingVerdict:
    """Refused or permitted, with every reason rather than the first.

    All defects are reported together because an operator debugging a refusal
    needs to fix the configuration once, and because a report that stops at the
    first problem hides whether the others exist.
    """

    defects: tuple[BindingDefect, ...]
    actual_parameter_digest: str
    approved_parameter_digest: str
    #: False when the authorization committed to no delegation chain. Reported
    #: rather than inferred: "the chain matched" and "there was no chain to
    #: match" are different facts and only one of them is authority.
    delegation_bound: bool = False
    #: Parameters that differed and were permitted to, by name. Recorded so a
    #: receipt can show what changed rather than only that nothing forbidden
    #: did.
    bounded_mutations: tuple[str, ...] = ()

    @property
    def permitted(self) -> bool:
        """True only when nothing was found. Derived, never set."""
        return not self.defects

    @property
    def parameters_matched(self) -> bool:
        return BindingDefect.PARAMETERS_DIFFER not in self.defects

    def explain(self) -> str:
        if self.permitted:
            mutated = (
                f" Bounded mutation permitted for: "
                f"{', '.join(self.bounded_mutations)}."
                if self.bounded_mutations
                else ""
            )
            return (
                "the execution matches its authorization: parameter digest "
                f"{self.actual_parameter_digest[:16]}…{mutated}"
            )
        lines = [
            f"execution REFUSED, {len(self.defects)} defect(s):",
            *(f"  - {d.value}: {d.explanation}" for d in self.defects),
        ]
        if BindingDefect.PARAMETERS_DIFFER in self.defects:
            lines.append(
                f"  approved digest {self.approved_parameter_digest[:16]}…, "
                f"actual {self.actual_parameter_digest[:16]}…"
            )
        return "\n".join(lines)


def _mutation_defects(
    *,
    authorization: ExecutionAuthorization,
    request: ExecutionRequest,
    approved_parameters: Mapping[str, Any] | None,
) -> tuple[bool, tuple[str, ...]]:
    """Whether the parameters are acceptable, and which mutations were allowed.

    Returns (matched, mutated_keys).

    The exact-digest path needs no approved parameters at all, which is the
    point of committing to a digest: the enforcement point can check the match
    without being told what was approved. Bounded mutation is the exception --
    comparing key by key requires the values -- so `approved_parameters` is
    OPTIONAL and its absence means only the exact check is available. An
    authorization that permits mutation and is verified without the approved
    values is refused rather than waved through, because the alternative is
    accepting an unchecked difference.
    """
    if request.parameter_digest == authorization.approved_parameter_digest:
        return True, ()
    if not authorization.mutable_parameters:
        return False, ()
    if approved_parameters is None:
        # Cannot compare key by key. Refuse rather than assume.
        return False, ()

    approved = dict(approved_parameters)
    if parameter_digest(approved) != authorization.approved_parameter_digest:
        # The supplied "approved" parameters are not the ones committed to, so
        # they cannot be used as the baseline for a comparison.
        return False, ()

    actual = dict(request.parameters)
    mutated: list[str] = []
    for key in sorted(set(approved) | set(actual)):
        if approved.get(key) == actual.get(key):
            continue
        if key not in authorization.mutable_parameters:
            return False, ()
        mutated.append(key)
    return True, tuple(mutated)


def verify_binding(
    *,
    authorization: ExecutionAuthorization | None,
    request: ExecutionRequest,
    now: datetime,
    nonces: NonceLedger,
    approved_parameters: Mapping[str, Any] | None = None,
    clock_skew_seconds: int = 60,
) -> BindingVerdict:
    """Refuse unless this execution is the one that was authorized.

    Called immediately before the side effect, never earlier: anything that can
    change between the check and the call is unchecked, which is the whole
    failure being closed here.

    The nonce is claimed LAST, and only if nothing else was wrong. A refused
    attempt executed nothing, so burning the authorization would turn a
    transient failure into a permanent one while preventing no attack -- each
    retry is refused on its own merits anyway.
    """
    if authorization is None:
        return BindingVerdict(
            defects=(BindingDefect.NOT_AUTHORIZED,),
            actual_parameter_digest=request.parameter_digest,
            approved_parameter_digest="",
        )

    defects: list[BindingDefect] = []

    # Tenant first. A cross-tenant authorization must not have its parameters
    # compared at all -- the comparison would be meaningless and the log line
    # would name another tenant's resource.
    if authorization.tenant_id != request.tenant_id:
        defects.append(BindingDefect.CROSS_TENANT)

    if authorization.agent_identity != request.agent_identity:
        defects.append(BindingDefect.AGENT_SUBSTITUTED)
    if authorization.tool_identity != request.tool_identity:
        defects.append(BindingDefect.TOOL_SUBSTITUTED)
    if authorization.mcp_server_identity != request.mcp_server_identity:
        defects.append(BindingDefect.MCP_SERVER_SUBSTITUTED)
    if authorization.action != request.action:
        defects.append(BindingDefect.ACTION_SUBSTITUTED)
    if authorization.target_resource != request.target_resource:
        defects.append(BindingDefect.RESOURCE_SUBSTITUTED)

    # THE DELEGATION CHAIN, compared rather than merely present.
    #
    # Only when the authorization committed to one. An authorization with an
    # empty chain digest was issued without a bound chain, and comparing it to
    # whatever the caller presents would refuse every legitimate call -- while
    # comparing it to nothing would accept any chain. So the absence is a
    # DELEGATION_UNBOUND state the caller can see in `delegation_bound`, not a
    # silent pass.
    if (
        authorization.delegation_passport_digest
        and authorization.delegation_passport_digest
        != request.delegation_passport_digest
    ):
        defects.append(BindingDefect.DELEGATION_SUBSTITUTED)

    matched, mutations = _mutation_defects(
        authorization=authorization,
        request=request,
        approved_parameters=approved_parameters,
    )
    if not matched:
        defects.append(BindingDefect.PARAMETERS_DIFFER)

    moment = now.astimezone(timezone.utc)
    if moment > authorization.expiry:
        defects.append(BindingDefect.EXPIRED)
    elif (authorization.issuance - moment).total_seconds() > clock_skew_seconds:
        defects.append(BindingDefect.NOT_YET_VALID)

    if not defects and not nonces.claim(
        tenant_id=authorization.tenant_id, nonce=authorization.nonce
    ):
        defects.append(BindingDefect.REPLAYED)

    return BindingVerdict(
        defects=tuple(defects),
        actual_parameter_digest=request.parameter_digest,
        approved_parameter_digest=authorization.approved_parameter_digest,
        bounded_mutations=mutations if not defects else (),
        delegation_bound=bool(authorization.delegation_passport_digest),
    )


@dataclass(frozen=True, slots=True)
class ExecutionReceipt:
    """What actually ran, bound to what authorized it.

    The chain is authorization digest -> executed request digest -> result
    digest. Each link is a digest and not an id, for the reason the passport
    already gives: an id says which record came before, a digest says what it
    SAID.

    `result_digest` may legitimately be empty -- a tool that returns nothing has
    nothing to hash -- so it is not required. `outcome` is, because a receipt
    that does not say whether the action succeeded records a fact nobody needs.
    """

    receipt_id: str
    tenant_id: str
    authorization_digest: str
    executed_request_digest: str
    actual_parameter_digest: str
    execution_identity: str
    started_at: str
    completed_at: str
    outcome: str
    result_digest: str = ""
    target_digest: str = ""
    side_effect: str = ""
    bounded_mutations: tuple[str, ...] = ()
    signature: str = ""

    def __post_init__(self) -> None:
        if not self.outcome.strip():
            raise ValueError(
                "a receipt without an outcome does not record whether the "
                "action happened, which is the one thing it is for"
            )
        for name in (
            "authorization_digest",
            "executed_request_digest",
            "actual_parameter_digest",
        ):
            value = getattr(self, name)
            if not _is_digest(value):
                raise ValueError(
                    f"{name}={value!r} is not a sha256 hex digest, so this "
                    "receipt does not bind to anything"
                )

    def as_document(self) -> dict[str, Any]:
        return {
            "context": "sentinel.execution.receipt.v1",
            "receipt_id": self.receipt_id,
            "tenant_id": self.tenant_id,
            "authorization_digest": self.authorization_digest,
            "executed_request_digest": self.executed_request_digest,
            "actual_parameter_digest": self.actual_parameter_digest,
            "execution_identity": self.execution_identity,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "outcome": self.outcome,
            "result_digest": self.result_digest,
            "target_digest": self.target_digest,
            "side_effect": self.side_effect,
            "bounded_mutations": list(self.bounded_mutations),
        }

    @property
    def digest(self) -> str:
        return digest_of(self.as_document())
