"""Phase 5: the Execution Passport. One consequential action, provable later.

WHAT THIS IS FOR
----------------
Every other record in this system answers a question for Sentinel. A passport
answers questions for somebody who does not trust Sentinel: an auditor, a
customer's security team, a regulator, the other side of an incident. It is a
canonical, signed statement of one consequential action -- who acted, under
whose authority, through what, against what, under which policy, with what
outcome -- verifiable with a public key and nothing else.

"And nothing else" is the whole design constraint. A verifier that has to call
the control plane is a verifier that trusts the control plane, which defeats the
purpose. `verify` below takes a passport and a key. It opens no database, makes
no network call, and reads no configuration.

WHY CANONICAL SERIALISATION IS THE CRUX
-----------------------------------------
A signature is over bytes. If two honest implementations serialise the same
passport differently, one of them cannot verify the other's signature and the
format is worthless as an interchange standard. So `canonical_bytes` is strict
about the things JSON leaves open:

  * keys sorted, no insignificant whitespace -- the usual pair;
  * non-ASCII left as UTF-8 rather than \\u-escaped, so a Cyrillic agent name
    has ONE representation instead of two that differ only in escaping;
  * FLOATS REFUSED OUTRIGHT. `0.1 + 0.2` does not round-trip, and a risk score
    that serialises as 96.00000000000001 on one platform and 96.0 on another
    produces two different signatures for one passport. Scores are integers
    here for exactly that reason.
  * `None` is serialised, never dropped. An absent field and a field that is
    explicitly unknown are different claims, and a canonicaliser that silently
    omitted nulls would let the two collapse into one signature.

WHY THE LINEAGE IS A COMMITMENT AND NOT A POINTER
---------------------------------------------------
`previous_passport_digest` holds the DIGEST of the parent, not its id. An id is
a claim about which record came before; a digest is a claim about what that
record SAID. Editing a parent after the fact breaks every child that committed
to it, which is the property that makes a chain evidence rather than a list.

WHAT THIS MODULE DELIBERATELY DOES NOT DO
-------------------------------------------
It does not sign. Signing needs a key, a key needs a store, and a domain module
that reaches for either stops being testable in isolation and starts being
infrastructure. `passport_signing.py` holds the crypto; this holds the shape,
the canonical form and the verification of everything that is not a signature.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping, Sequence

__all__ = [
    "PASSPORT_SCHEMA",
    "ExecutionPassport",
    "PassportDefect",
    "PassportFinding",
    "canonical_bytes",
    "digest_of",
    "verify_structure",
]

#: The schema this build writes and understands. A passport carrying anything
#: else is REFUSED rather than best-effort parsed: a verifier that guesses at an
#: unknown version is a verifier that can be told a field means something it
#: does not.
PASSPORT_SCHEMA = "sentinel.passport/v1"


class PassportDefect(str, Enum):
    """Everything `verify` can conclude other than "this is sound"."""

    UNRECOGNISED_SCHEMA = "unrecognised_schema"
    MODIFIED = "modified"
    BROKEN_LINEAGE = "broken_lineage"
    MISSING_PARENT = "missing_parent"
    POLICY_MISMATCH = "policy_mismatch"
    TOOL_DEFINITION_CHANGED = "tool_definition_changed"
    DELEGATION_INVALID = "delegation_invalid"
    ATTESTATION_MISMATCH = "attestation_mismatch"
    INCOMPLETE = "incomplete"

    @property
    def explanation(self) -> str:
        return _EXPLANATIONS[self]


#: `MappingProxyType`, not a bare dict: these strings are what a reader is
#: told when a passport fails to verify, and "any import could edit it" is
#: not a property an evidence explanation should have.
_EXPLANATIONS: Mapping["PassportDefect", str] = MappingProxyType({
    PassportDefect.UNRECOGNISED_SCHEMA: (
        "the passport declares a schema this verifier does not implement; "
        "refused rather than parsed on the assumption fields mean what they "
        "used to"
    ),
    PassportDefect.MODIFIED: (
        "the recomputed digest does not match the one recorded: the passport "
        "has been altered since it was written"
    ),
    PassportDefect.BROKEN_LINEAGE: (
        "the parent's digest does not match what this passport committed to, so "
        "the parent has been edited since"
    ),
    PassportDefect.MISSING_PARENT: (
        "this passport names a parent that was not supplied, so the chain "
        "cannot be walked to its root"
    ),
    PassportDefect.POLICY_MISMATCH: (
        "the policy digest does not match the policy version named, so the "
        "decision cannot be reproduced against the rules it claims"
    ),
    PassportDefect.TOOL_DEFINITION_CHANGED: (
        "the tool's definition fingerprint differs from the one approved, so "
        "what executed is not what was authorised"
    ),
    PassportDefect.DELEGATION_INVALID: (
        "the delegation chain does not lead from the named principal to the "
        "acting agent"
    ),
    PassportDefect.ATTESTATION_MISMATCH: (
        "the attestation names a digest other than this passport's"
    ),
    PassportDefect.INCOMPLETE: (
        "a field required to attribute this action is empty; a passport that "
        "cannot say who acted proves nothing"
    ),
})


@dataclass(frozen=True, slots=True)
class PassportFinding:
    defect: PassportDefect
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "defect": self.defect.value,
            "detail": self.detail,
            "explanation": self.defect.explanation,
        }


#: Largest integer an IEEE-754 double holds exactly: 2**53 - 1. The bound is
#: not Python's -- Python has no bound -- it is every OTHER runtime's, and a
#: canonical form is only canonical if it means the same thing in all of them.
_MAX_EXACT_INT = 2**53 - 1


class _CanonicalError(ValueError):
    pass


def _check_canonical(value: Any, *, path: str = "$") -> None:
    """Refuse anything JSON does not represent identically everywhere.

    Raising here rather than at signature-comparison time means the failure
    lands on whoever WROTE the passport, with a path to the offending field --
    instead of on an auditor a year later holding two byte-different documents
    that both look correct.
    """
    if isinstance(value, float):
        raise _CanonicalError(
            f"{path}: floats are refused. 0.1 + 0.2 does not round-trip, so a "
            "score serialising as 96.00000000000001 here and 96.0 elsewhere "
            "would produce two signatures for one passport. Use an integer."
        )
    if isinstance(value, int) and not isinstance(value, bool):
        # Python's integers are arbitrary-precision, so this check is invisible
        # here and load-bearing everywhere else. Past 2^53 a JSON number cannot
        # be represented exactly by an IEEE-754 double, which is what every
        # JavaScript parser and most others use -- so the document round-trips
        # to a DIFFERENT value and its digest changes, in a verifier the issuer
        # does not control.
        #
        # Found by writing the second implementation in `verify.mjs`: JS has one
        # number type and refused this immediately, while Python accepted it
        # happily. That disagreement is exactly what a second implementation of
        # a specification is for.
        if abs(value) > _MAX_EXACT_INT:
            raise _CanonicalError(
                f"{path}: {value} is outside the range an integer survives a "
                f"JSON round trip in (+/-{_MAX_EXACT_INT}). Beyond that a "
                "double cannot hold it exactly, so a verifier using one would "
                "compute a different digest than this one did. Use a string."
            )
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise _CanonicalError(f"{path}: object keys must be strings")
            _check_canonical(item, path=f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _check_canonical(item, path=f"{path}[{index}]")
    elif not isinstance(value, (str, int, bool, type(None))):
        raise _CanonicalError(
            f"{path}: {type(value).__name__} has no canonical JSON form. "
            "Convert it at the edge, where the conversion is visible."
        )


def canonical_bytes(document: Mapping[str, Any]) -> bytes:
    """The exact bytes a signature covers.

    `ensure_ascii=False` on purpose: escaping non-ASCII gives a Cyrillic agent
    name two representations that differ only in escaping, and a canonical form
    with two representations is not one.
    """
    _check_canonical(document)
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def digest_of(document: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(document)).hexdigest()


#: Fields without which a passport cannot attribute an action. Absence of any
#: one makes the document a record of something, not evidence about somebody.
REQUIRED_FIELDS: tuple[str, ...] = (
    "execution_id",
    "tenant_id",
    "occurred_at",
    "agent_id",
    "action",
    "decision",
)


@dataclass(frozen=True, slots=True)
class ExecutionPassport:
    """One consequential action, in the form somebody else can check.

    Almost every field is optional and defaults to empty. That is deliberate: a
    passport recording what was actually known beats one that could not be
    written because a field nobody had was mandatory. `REQUIRED_FIELDS` is the
    short list without which the document attributes nothing, and
    `verify_structure` reports their absence rather than the constructor
    refusing -- so a partial passport can still be read and its gaps named.
    """

    # ── identity of the execution ────────────────────────────────────────────
    execution_id: str
    tenant_id: str
    occurred_at: str
    #: Digest of the passport this one causally follows. A DIGEST, not an id:
    #: an id says which record came before, a digest says what it SAID.
    previous_passport_digest: str = ""
    parent_execution_id: str = ""
    session_id: str = ""

    # ── who ──────────────────────────────────────────────────────────────────
    human_principal: str = ""
    agent_id: str = ""
    agent_instance: str = ""
    agent_version: str = ""
    agent_framework: str = ""
    model_identity: str = ""
    delegation_chain: tuple[Mapping[str, Any], ...] = ()

    # ── through what ─────────────────────────────────────────────────────────
    mcp_server_id: str = ""
    mcp_server_fingerprint: str = ""
    tool_name: str = ""
    tool_definition_fingerprint: str = ""
    skill_ids: tuple[str, ...] = ()
    credential_id: str = ""

    # ── against what ─────────────────────────────────────────────────────────
    action: str = ""
    action_semantics: Mapping[str, Any] = field(default_factory=dict)
    resource: str = ""
    environment: str = ""
    data_classifications: tuple[str, ...] = ()
    destination: str = ""

    # ── under which rules ────────────────────────────────────────────────────
    policy_id: str = ""
    policy_version: str = ""
    policy_digest: str = ""
    decision: str = ""
    #: An INTEGER. See the float refusal in `_check_canonical`.
    risk_score: int = 0
    risk_reasons: tuple[str, ...] = ()

    # ── human involvement ────────────────────────────────────────────────────
    approval_required: bool = False
    approval_actor: str = ""
    approval_at: str = ""

    # ── what happened ────────────────────────────────────────────────────────
    idempotency_key: str = ""
    execution_fence: str = ""
    outcome: str = ""
    side_effect: str = ""

    # ── proof ────────────────────────────────────────────────────────────────
    evidence_digest: str = ""
    attestation_status: str = "unattested"
    attestation_reference: str = ""

    def as_document(self) -> dict[str, Any]:
        """The signed body. Excludes the signature, which cannot cover itself."""
        return {
            "schema": PASSPORT_SCHEMA,
            "execution_id": self.execution_id,
            "tenant_id": self.tenant_id,
            "occurred_at": self.occurred_at,
            "previous_passport_digest": self.previous_passport_digest,
            "parent_execution_id": self.parent_execution_id,
            "session_id": self.session_id,
            "human_principal": self.human_principal,
            "agent_id": self.agent_id,
            "agent_instance": self.agent_instance,
            "agent_version": self.agent_version,
            "agent_framework": self.agent_framework,
            "model_identity": self.model_identity,
            "delegation_chain": [dict(h) for h in self.delegation_chain],
            "mcp_server_id": self.mcp_server_id,
            "mcp_server_fingerprint": self.mcp_server_fingerprint,
            "tool_name": self.tool_name,
            "tool_definition_fingerprint": self.tool_definition_fingerprint,
            "skill_ids": list(self.skill_ids),
            "credential_id": self.credential_id,
            "action": self.action,
            "action_semantics": dict(self.action_semantics),
            "resource": self.resource,
            "environment": self.environment,
            "data_classifications": list(self.data_classifications),
            "destination": self.destination,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
            "decision": self.decision,
            "risk_score": self.risk_score,
            "risk_reasons": list(self.risk_reasons),
            "approval_required": self.approval_required,
            "approval_actor": self.approval_actor,
            "approval_at": self.approval_at,
            "idempotency_key": self.idempotency_key,
            "execution_fence": self.execution_fence,
            "outcome": self.outcome,
            "side_effect": self.side_effect,
            "evidence_digest": self.evidence_digest,
            "attestation_status": self.attestation_status,
            "attestation_reference": self.attestation_reference,
        }

    @property
    def digest(self) -> str:
        return digest_of(self.as_document())

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> "ExecutionPassport":
        """Rebuild from a document, ignoring fields this version does not know.

        Unknown keys are DROPPED rather than rejected, so a v1 verifier can read
        the shared fields of a later passport. `verify_structure` still refuses
        an unrecognised SCHEMA -- the difference is that a newer minor with extra
        keys is readable, while a document claiming a different format is not.
        """
        known = {f for f in cls.__slots__}
        payload = {k: v for k, v in document.items() if k in known}
        for name in ("delegation_chain",):
            if name in payload:
                payload[name] = tuple(payload[name] or ())
        for name in ("skill_ids", "data_classifications", "risk_reasons"):
            if name in payload:
                payload[name] = tuple(payload[name] or ())
        return cls(**payload)


def verify_structure(
    passport: ExecutionPassport,
    *,
    document: Mapping[str, Any] | None = None,
    parents: Mapping[str, ExecutionPassport] | None = None,
    expected_policy_digest: str = "",
    approved_tool_fingerprint: str = "",
    attestation_digest: str = "",
) -> tuple[PassportFinding, ...]:
    """Everything checkable WITHOUT a key. Signature checking is elsewhere.

    Split from signature verification on purpose: a passport can be structurally
    sound and unsigned, or perfectly signed and internally incoherent, and the
    two failures send a reader to different places. A caller wanting both calls
    both; `passport_signing.verify` composes them.

    Every argument beyond the passport is OPTIONAL, and an omitted one means the
    corresponding check DOES NOT RUN rather than passes. A verifier that had no
    policy digest to compare against must not report "policy verified".
    """
    findings: list[PassportFinding] = []

    def add(defect: PassportDefect, detail: str) -> None:
        findings.append(PassportFinding(defect=defect, detail=detail))

    if document is not None:
        declared = str(document.get("schema", ""))
        if declared != PASSPORT_SCHEMA:
            add(
                PassportDefect.UNRECOGNISED_SCHEMA,
                f"declares {declared!r}; this verifier implements "
                f"{PASSPORT_SCHEMA!r}",
            )
            # Everything below reads fields whose meaning depends on the schema.
            # Continuing would be interpreting an unknown format.
            return tuple(findings)

        if digest_of(dict(document)) != passport.digest:
            add(
                PassportDefect.MODIFIED,
                "the supplied document does not canonicalise to the same digest "
                "as the parsed passport",
            )

    missing = [
        name for name in REQUIRED_FIELDS if not str(getattr(passport, name, "")).strip()
    ]
    if missing:
        add(
            PassportDefect.INCOMPLETE,
            f"empty required field(s): {', '.join(missing)}",
        )

    if passport.previous_passport_digest:
        if parents is None:
            add(
                PassportDefect.MISSING_PARENT,
                f"commits to parent digest "
                f"{passport.previous_passport_digest[:16]}… and no parents were "
                "supplied, so the chain cannot be walked",
            )
        else:
            parent = parents.get(passport.previous_passport_digest)
            if parent is None:
                add(
                    PassportDefect.MISSING_PARENT,
                    f"no supplied parent has digest "
                    f"{passport.previous_passport_digest[:16]}…",
                )
            elif parent.digest != passport.previous_passport_digest:
                add(
                    PassportDefect.BROKEN_LINEAGE,
                    "the supplied parent's digest differs from the commitment, "
                    "so the parent has been edited since this was written",
                )

    if expected_policy_digest and passport.policy_digest != expected_policy_digest:
        add(
            PassportDefect.POLICY_MISMATCH,
            f"recorded {passport.policy_digest[:16]}…, expected "
            f"{expected_policy_digest[:16]}…",
        )

    if (
        approved_tool_fingerprint
        and passport.tool_definition_fingerprint != approved_tool_fingerprint
    ):
        add(
            PassportDefect.TOOL_DEFINITION_CHANGED,
            f"executed {passport.tool_definition_fingerprint[:16]}…, approved "
            f"{approved_tool_fingerprint[:16]}…",
        )

    if attestation_digest and attestation_digest != passport.digest:
        add(
            PassportDefect.ATTESTATION_MISMATCH,
            "the attestation commits to a digest other than this passport's",
        )

    findings.extend(_delegation_findings(passport))
    return tuple(findings)


def _delegation_findings(passport: ExecutionPassport) -> Sequence[PassportFinding]:
    """Does the recorded chain actually lead from the principal to the actor?

    A passport can name a human, name an agent, and carry a chain that connects
    neither -- which reads as full attribution and proves nothing. This is the
    check that says so.
    """
    chain = passport.delegation_chain
    if not chain:
        return ()

    hops = [(str(h.get("from_agent", "")), str(h.get("to_agent", ""))) for h in chain]

    if passport.human_principal and hops[0][0] != passport.human_principal:
        return (
            PassportFinding(
                defect=PassportDefect.DELEGATION_INVALID,
                detail=(
                    f"the chain starts at {hops[0][0]!r} but the passport names "
                    f"{passport.human_principal!r} as the principal"
                ),
            ),
        )
    if passport.agent_id and hops[-1][1] != passport.agent_id:
        return (
            PassportFinding(
                defect=PassportDefect.DELEGATION_INVALID,
                detail=(
                    f"the chain ends at {hops[-1][1]!r} but {passport.agent_id!r} "
                    "is recorded as the acting agent"
                ),
            ),
        )
    for index in range(1, len(hops)):
        if hops[index][0] != hops[index - 1][1]:
            return (
                PassportFinding(
                    defect=PassportDefect.DELEGATION_INVALID,
                    detail=(
                        f"hop {index + 1} is delegated by {hops[index][0]!r}, "
                        f"but hop {index} handed authority to "
                        f"{hops[index - 1][1]!r}: the chain does not connect"
                    ),
                ),
            )
    return ()
