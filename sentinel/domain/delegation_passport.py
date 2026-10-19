"""A delegation chain each hop of which is signed by the party granting it.

WHAT WAS MISSING
----------------
`delegation_constraints.py` evaluates whether a delegation is valid where it is
presented -- expiry, environment rank, resource scope. That is the right check
and it rests on the control plane having recorded the chain honestly. The
`delegation_chain` field on an `ExecutionPassport` is a tuple of plain
mappings: an independent verifier reading one has to take the platform's word
for who delegated what, on precisely the question the platform exists to
answer.

So each hop is now signed by its ISSUER, with the issuer's own key. A verifier
holding the issuer public keys can reconstruct the chain from signatures alone.
The control plane cannot add a hop, widen one, or reorder them without holding
a key it does not have.

THE CHAIN IS A HASH CHAIN, NOT A LIST
--------------------------------------
Each hop commits to `previous_hop_digest`. A list of independently signed
grants can be reordered or have a middle element dropped and every individual
signature still verifies -- the same reason `previous_passport_digest` is a
digest and not an id. Committing to the parent's digest makes the ORDER part of
what was signed.

MONOTONICITY IS THE ANTI-AMPLIFICATION PROPERTY
------------------------------------------------
A child hop may grant only what its parent held: capabilities a subset,
resource scope no wider, environment no higher, expiry no later. Checked hop by
hop rather than end to end, because the interesting attack is a chain where
every hop is individually well-formed and hop 3 grants something hop 2 never
had.

`prohibited_capabilities` is checked in the other direction: a parent that
forbids something cannot have a child grant it, even if the parent's permitted
set is broad. Deny beats allow, down the chain.

WHY ISSUER KEYS AND NOT ONE PLATFORM KEY
-----------------------------------------
Signing every hop with the platform's key would produce a chain that verifies
cryptographically and proves nothing about delegation: the platform could mint
any chain it liked. The whole value is that hop N was signed by the party named
as its issuer, so `verify_chain` REFUSES a hop whose key id does not belong to
its issuer rather than accepting any valid signature.

WHAT THIS MODULE DOES NOT DO
-----------------------------
It does not sign -- signing needs a key store, and a domain module that reaches
for one stops being testable in isolation. `sentinel/infrastructure/
delegation_signing.py` holds the crypto. This holds the shape, the canonical
form, and the verification of everything the signature does not itself prove.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from sentinel.domain.passport import digest_of

__all__ = [
    "HOP_CONTEXT",
    "PASSPORT_CONTEXT",
    "ChainVerdict",
    "DelegationDefect",
    "DelegationFinding",
    "DelegationHop",
    "DelegationPassport",
    "SignedHop",
    "chain_digest",
    "key_owner",
    "verify_chain",
]

#: Domain separation. A hop digest must never be mistakable for a passport
#: digest, a parameter digest or a Merkle leaf -- the same reason RFC 6962
#: prefixes leaves with 0x00 and nodes with 0x01.
HOP_CONTEXT = "sentinel.delegation.hop.v1"
PASSPORT_CONTEXT = "sentinel.delegation.passport.v1"

#: Beyond this a chain is refused outright. Not a policy knob with a generous
#: default: each hop is an opportunity to widen scope by a rounding error, and
#: a twenty-hop chain is not something anybody audits.
DEFAULT_MAX_DEPTH = 5

#: Environments by blast radius, least first. Mirrors
#: `delegation_constraints.ENVIRONMENT_RANK` deliberately -- and
#: `test_the_two_environment_tables_agree` holds them equal, because two
#: tables of environment names are two tables that can disagree.
ENVIRONMENT_RANK: Mapping[str, int] = MappingProxyType({
    "test": 0,
    "dev": 1,
    "development": 1,
    "sandbox": 1,
    "qa": 2,
    "staging": 3,
    "stage": 3,
    "preprod": 3,
    "production": 4,
    "prod": 4,
})

#: An environment nobody declared ranks ABOVE production. The safe reading of
#: an unknown blast radius is the worst one.
UNKNOWN_ENVIRONMENT_RANK = 5


def environment_rank(name: str) -> int:
    return ENVIRONMENT_RANK.get(name.strip().lower(), UNKNOWN_ENVIRONMENT_RANK)


class DelegationDefect(str, Enum):
    """Every way a signed chain can fail to establish authority.

    No member is falsy and every one has an explanation. An enum with a falsy
    member gets used in a boolean test and the most serious case reads as "no
    problem" -- already shipped once in this codebase, in an SDK decision type.
    """

    EMPTY_CHAIN = "empty_chain"
    UNKNOWN_KEY = "unknown_key"
    SIGNATURE_INVALID = "signature_invalid"
    KEY_NOT_ISSUERS = "key_not_issuers"
    KEY_OUT_OF_WINDOW = "key_out_of_window"
    BROKEN_CHAIN = "broken_chain"
    SUBJECT_MISMATCH = "subject_mismatch"
    ROOT_MISMATCH = "root_mismatch"
    CAPABILITY_EXPANSION = "capability_expansion"
    PROHIBITED_CAPABILITY_GRANTED = "prohibited_capability_granted"
    SCOPE_EXPANSION = "scope_expansion"
    ENVIRONMENT_ESCALATION = "environment_escalation"
    LIFETIME_EXTENSION = "lifetime_extension"
    DEPTH_EXCEEDED = "depth_exceeded"
    DELEGATION_LOOP = "delegation_loop"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    CROSS_TENANT = "cross_tenant"
    SUBJECT_IS_NOT_THE_PRESENTER = "subject_is_not_the_presenter"

    @property
    def explanation(self) -> str:
        return _EXPLANATIONS[self]


_EXPLANATIONS: Mapping[DelegationDefect, str] = MappingProxyType({
    DelegationDefect.EMPTY_CHAIN: (
        "no hops were presented, so no authority is established. An empty "
        "chain is not a chain that grants everything"
    ),
    DelegationDefect.UNKNOWN_KEY: (
        "the key that signed this hop was not supplied, so the signature was "
        "NOT checked -- which is not the same as it being valid"
    ),
    DelegationDefect.SIGNATURE_INVALID: (
        "the signature does not verify against the hop's canonical bytes: the "
        "hop was altered after it was signed"
    ),
    DelegationDefect.KEY_NOT_ISSUERS: (
        "the hop was signed by a key belonging to somebody other than its "
        "named issuer. A cryptographically valid signature by the wrong party "
        "is the whole failure this design exists to stop"
    ),
    DelegationDefect.KEY_OUT_OF_WINDOW: (
        "the signing key was outside its validity window when it signed, so "
        "the signature is cryptographically perfect and evidentially worthless"
    ),
    DelegationDefect.BROKEN_CHAIN: (
        "this hop does not commit to the digest of the hop before it, so the "
        "order was not signed and the chain could have been reordered"
    ),
    DelegationDefect.SUBJECT_MISMATCH: (
        "this hop is issued by somebody who was not the subject of the "
        "previous hop, so authority does not flow from one to the next"
    ),
    DelegationDefect.ROOT_MISMATCH: (
        "the first hop is not issued by the expected root principal"
    ),
    DelegationDefect.CAPABILITY_EXPANSION: (
        "this hop grants a capability its issuer did not hold. Privilege "
        "amplification through delegation"
    ),
    DelegationDefect.PROHIBITED_CAPABILITY_GRANTED: (
        "a parent hop explicitly PROHIBITED a capability this hop grants. Deny "
        "beats allow down the chain"
    ),
    DelegationDefect.SCOPE_EXPANSION: (
        "this hop's resource scope is wider than its issuer's, so it reaches "
        "resources the issuer could not"
    ),
    DelegationDefect.ENVIRONMENT_ESCALATION: (
        "this hop targets an environment with a larger blast radius than its "
        "issuer's"
    ),
    DelegationDefect.LIFETIME_EXTENSION: (
        "this hop outlives its issuer's grant, so revoking the parent would "
        "not revoke the child"
    ),
    DelegationDefect.DEPTH_EXCEEDED: (
        "the chain is longer than the permitted depth. Each hop is an "
        "opportunity to widen scope, and a long chain is one nobody audits"
    ),
    DelegationDefect.DELEGATION_LOOP: (
        "a principal appears twice in the chain, which is either a cycle or an "
        "attempt to launder scope through a round trip"
    ),
    DelegationDefect.EXPIRED: (
        "a hop in the chain has expired, so the authority it granted has run "
        "out rather than never having existed"
    ),
    DelegationDefect.NOT_YET_VALID: (
        "a hop is not valid yet, usually clock skew between issuer and "
        "enforcement point"
    ),
    DelegationDefect.CROSS_TENANT: (
        "a hop belongs to a different tenant. Authority that never existed, "
        "rather than authority that ran out"
    ),
    DelegationDefect.SUBJECT_IS_NOT_THE_PRESENTER: (
        "the agent presenting this chain is not the subject of its final hop, "
        "so it is holding somebody else's delegation"
    ),
})


def _parse_instant(value: str, *, field_name: str) -> datetime:
    """An ISO-8601 instant that MUST carry a timezone."""
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


@dataclass(frozen=True, slots=True)
class DelegationHop:
    """One grant: `issuer` permits `subject` to do a bounded set of things."""

    issuer: str
    subject: str
    tenant_id: str
    #: 1 for the first hop. Signed, so it cannot be renumbered.
    depth: int
    permitted_capabilities: frozenset[str]
    #: fnmatch patterns. `arn:aws:s3:::acme/*` is one prefix, not the estate.
    resource_scope: tuple[str, ...]
    environment: str
    issued_at: str
    expires_at: str
    #: Digest of the hop before this one. Empty for the first.
    previous_hop_digest: str = ""
    #: Capabilities this hop forbids its descendants, whatever they permit.
    prohibited_capabilities: frozenset[str] = frozenset()
    purpose: str = ""

    def __post_init__(self) -> None:
        required = {
            "issuer": self.issuer,
            "subject": self.subject,
            "tenant_id": self.tenant_id,
        }
        missing = sorted(name for name, value in required.items() if not value.strip())
        if missing:
            raise ValueError(
                f"a delegation hop without {', '.join(missing)} names no "
                "parties, so it grants nothing to nobody"
            )
        if self.issuer == self.subject:
            raise ValueError(
                f"{self.issuer!r} cannot delegate to itself; a self-hop adds a "
                "link to the chain and no authority, which is how a depth "
                "limit gets consumed by nothing"
            )
        if self.depth < 1:
            raise ValueError(
                f"depth={self.depth} is not a position in a chain; the first "
                "hop is 1"
            )
        if not self.permitted_capabilities:
            raise ValueError(
                "a hop permitting no capabilities grants nothing. Refused at "
                "construction rather than left to read as a valid grant that "
                "happens to fail every check"
            )
        overlap = self.permitted_capabilities & self.prohibited_capabilities
        if overlap:
            raise ValueError(
                f"{sorted(overlap)} are both permitted and prohibited by this "
                "hop. Which one wins is exactly the ambiguity a reader would "
                "resolve differently from the enforcement path"
            )
        issued = _parse_instant(self.issued_at, field_name="issued_at")
        expires = _parse_instant(self.expires_at, field_name="expires_at")
        if expires <= issued:
            raise ValueError(
                f"expires_at ({self.expires_at}) is not after issued_at "
                f"({self.issued_at}), so this hop was never valid"
            )

    @property
    def issuance(self) -> datetime:
        return _parse_instant(self.issued_at, field_name="issued_at")

    @property
    def expiry(self) -> datetime:
        return _parse_instant(self.expires_at, field_name="expires_at")

    def as_document(self) -> dict[str, Any]:
        """The signed body. Sets are sorted, so the bytes are canonical."""
        return {
            "context": HOP_CONTEXT,
            "issuer": self.issuer,
            "subject": self.subject,
            "tenant_id": self.tenant_id,
            "depth": self.depth,
            "permitted_capabilities": sorted(self.permitted_capabilities),
            "prohibited_capabilities": sorted(self.prohibited_capabilities),
            "resource_scope": list(self.resource_scope),
            "environment": self.environment,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "previous_hop_digest": self.previous_hop_digest,
            "purpose": self.purpose,
        }

    @property
    def digest(self) -> str:
        return digest_of(self.as_document())

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> "DelegationHop":
        return cls(
            issuer=str(document["issuer"]),
            subject=str(document["subject"]),
            tenant_id=str(document["tenant_id"]),
            depth=int(document["depth"]),
            permitted_capabilities=frozenset(
                document.get("permitted_capabilities", ())
            ),
            prohibited_capabilities=frozenset(
                document.get("prohibited_capabilities", ())
            ),
            resource_scope=tuple(document.get("resource_scope", ())),
            environment=str(document.get("environment", "")),
            issued_at=str(document["issued_at"]),
            expires_at=str(document["expires_at"]),
            previous_hop_digest=str(document.get("previous_hop_digest", "")),
            purpose=str(document.get("purpose", "")),
        )


@dataclass(frozen=True, slots=True)
class SignedHop:
    """A hop document plus the detached signature of its ISSUER.

    The signature is not inside the document, for the reason
    `SignedPassport` already gives: a signature cannot cover itself, and
    blanking a field before hashing means the bytes a verifier hashes are not
    the bytes it received.
    """

    document: Mapping[str, Any]
    signature: str
    #: Whose key signed it. Checked against the issuer, not merely used to
    #: look one up -- a valid signature by the wrong party is the failure.
    key_id: str
    signed_at: str

    @property
    def hop(self) -> DelegationHop:
        return DelegationHop.from_document(self.document)

    @property
    def digest(self) -> str:
        return digest_of(dict(self.document))


@dataclass(frozen=True, slots=True)
class DelegationPassport:
    """The whole chain, in order, each hop signed by its issuer."""

    hops: tuple[SignedHop, ...] = ()

    @property
    def depth(self) -> int:
        return len(self.hops)

    @property
    def subject(self) -> str:
        """Who this chain ultimately authorises. Empty for an empty chain."""
        return self.hops[-1].hop.subject if self.hops else ""

    def as_document(self) -> dict[str, Any]:
        return {
            "context": PASSPORT_CONTEXT,
            "hops": [
                {
                    "document": dict(signed.document),
                    "signature": signed.signature,
                    "key_id": signed.key_id,
                    "signed_at": signed.signed_at,
                }
                for signed in self.hops
            ],
        }

    @property
    def digest(self) -> str:
        return chain_digest(self)


def chain_digest(passport: DelegationPassport) -> str:
    """The digest an `ExecutionAuthorization` commits to.

    Over the SIGNED hops rather than the bare documents, so an authorization
    that names a chain digest is naming a chain including its signatures --
    swapping in a differently-signed but identical-looking hop changes it.
    """
    return digest_of(passport.as_document())


@dataclass(frozen=True, slots=True)
class DelegationFinding:
    defect: DelegationDefect
    detail: str
    #: 1-indexed hop. 0 means the chain as a whole.
    hop: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "defect": self.defect.value,
            "detail": self.detail,
            "hop": self.hop,
            "explanation": self.defect.explanation,
        }


@dataclass(frozen=True, slots=True)
class ChainVerdict:
    """Every defect, not the first.

    A chain that is expired AND expands scope is two problems with two
    remedies, and reporting one hides the other from whoever fixes it.
    """

    findings: tuple[DelegationFinding, ...]
    #: Capabilities the chain actually establishes: the INTERSECTION down the
    #: chain, minus anything prohibited anywhere in it.
    effective_capabilities: frozenset[str] = frozenset()
    effective_scope: tuple[str, ...] = ()

    @property
    def established(self) -> bool:
        """True only when nothing was found. Derived, never set."""
        return not self.findings

    def explain(self) -> str:
        if self.established:
            return (
                f"chain establishes {sorted(self.effective_capabilities)} "
                f"over {list(self.effective_scope)}"
            )
        return "\n".join(
            [f"delegation REFUSED, {len(self.findings)} defect(s):"]
            + [
                f"  hop {finding.hop}: {finding.defect.value} -- {finding.detail}"
                for finding in self.findings
            ]
        )


class HopVerifier:
    """Checks one hop's signature. Implemented in infrastructure.

    A protocol rather than a concrete class so this module stays free of a key
    store, and so `verify_chain` can be tested against a verifier that refuses
    everything -- which is how the "unknown key is not a valid key" property
    gets asserted.
    """

    def verify(self, signed: SignedHop, *, when: datetime) -> DelegationDefect | None:
        """None when the signature is sound, or the specific defect."""
        raise NotImplementedError


def _scope_is_narrower(child: Sequence[str], parent: Sequence[str]) -> bool:
    """Is every child pattern covered by some parent pattern?

    Pattern CONTAINMENT, not string comparison. `acme/*` covers `acme/q3/*`;
    `acme-evil/*` is not covered by `acme/*` even though it shares a prefix.
    Implemented by requiring each child pattern to be a prefix-with-wildcard
    refinement of a parent -- deliberately conservative: a pattern language
    rich enough to need a solver is a pattern language whose containment
    nobody can review.
    """
    import fnmatch

    if not parent:
        # A parent with no scope granted no resources, so no child scope can
        # be narrower than it.
        return not child
    for pattern in child:
        literal = pattern.rstrip("*")
        covered = any(
            fnmatch.fnmatchcase(literal, candidate)
            or fnmatch.fnmatchcase(literal.rstrip("/"), candidate)
            or (candidate.endswith("*") and literal.startswith(candidate[:-1]))
            or candidate == pattern
            for candidate in parent
        )
        if not covered:
            return False
    return True


def key_owner(key_id: str) -> str | None:
    """The principal a hop key id belongs to, or None if it names nobody.

    A key id is `issuer#version`, minted only by `issuer_key_id` in the signing
    adapter. This is the inverse: split on the LAST separator, require both
    halves to be present, and return the issuer half. Everything else -- an
    empty id, a bare issuer with no version, a bare version with no issuer --
    is owned by nobody, and `verify_chain` treats "nobody" as "not the issuer".

    Written as a parse rather than as `key_id.startswith(issuer)` because a
    prefix check accepted `alice-evil#1` as one of alice's keys: any principal
    whose name began with the issuer's name could sign on the issuer's behalf,
    which is the binding this whole module exists to prove.
    """
    if not key_id:
        return None
    issuer, separator, version = key_id.rpartition("#")
    if not separator or not issuer or not version:
        return None
    return issuer


def verify_chain(
    passport: DelegationPassport,
    *,
    verifier: HopVerifier,
    now: datetime,
    tenant_id: str,
    presenter: str = "",
    root_issuer: str = "",
    max_depth: int = DEFAULT_MAX_DEPTH,
    clock_skew_seconds: int = 60,
) -> ChainVerdict:
    """Does this chain establish authority, from signatures alone?

    `presenter` is the agent about to act. Supplying it is what turns "this is
    a valid chain" into "this is a valid chain BELONGING TO THIS AGENT", and
    omitting it leaves the holder unchecked -- so it is checked when given and
    reported as unchecked by its absence rather than assumed.
    """
    findings: list[DelegationFinding] = []

    def add(defect: DelegationDefect, detail: str, hop: int = 0) -> None:
        findings.append(DelegationFinding(defect=defect, detail=detail, hop=hop))

    if not passport.hops:
        add(
            DelegationDefect.EMPTY_CHAIN,
            "no hops presented; an empty chain grants nothing rather than "
            "everything",
        )
        return ChainVerdict(findings=tuple(findings))

    if passport.depth > max_depth:
        add(
            DelegationDefect.DEPTH_EXCEEDED,
            f"{passport.depth} hops exceeds the permitted {max_depth}",
        )

    moment = now.astimezone(timezone.utc)
    # Seeded with the root, so a chain that hands authority back to where it
    # started is a loop rather than a fresh grant.
    seen_principals: set[str] = {passport.hops[0].hop.issuer} if passport.hops else set()
    effective: frozenset[str] | None = None
    prohibited: set[str] = set()
    scope: tuple[str, ...] = ()
    previous: DelegationHop | None = None

    for index, signed in enumerate(passport.hops, start=1):
        try:
            hop = signed.hop
        except (KeyError, ValueError) as error:
            add(
                DelegationDefect.SIGNATURE_INVALID,
                f"the hop document is malformed and cannot be read: {error}",
                index,
            )
            continue

        # ── the signature, first ────────────────────────────────────────────
        #
        # Before any semantic check, because a hop whose signature does not
        # verify is a hop whose CONTENTS are not evidence -- evaluating its
        # capabilities would be reading an attacker's assertions.
        defect = verifier.verify(signed, when=moment)
        if defect is not None:
            add(
                defect,
                f"hop {index} signed by key {signed.key_id!r} for issuer "
                f"{hop.issuer!r}",
                index,
            )

        if key_owner(signed.key_id) != hop.issuer:
            # The key id is namespaced by its owner. A signature that verifies
            # under somebody else's key is the exact attack this design stops,
            # and it is a SEPARATE finding from an invalid signature because
            # the remedy is different.
            #
            # The owner is PARSED, not prefix-matched. `startswith` accepted
            # `alice-evil#1` as one of alice's keys, so a principal whose name
            # merely began with the issuer's could sign on the issuer's behalf.
            # An empty key id is refused for the same reason: it belongs to
            # nobody, so it cannot belong to the issuer.
            add(
                DelegationDefect.KEY_NOT_ISSUERS,
                f"key {signed.key_id!r} does not belong to issuer "
                f"{hop.issuer!r}",
                index,
            )

        # ── tenancy, then the chain's shape ────────────────────────────────
        if hop.tenant_id != tenant_id:
            add(
                DelegationDefect.CROSS_TENANT,
                f"hop names tenant {hop.tenant_id!r}, presented for "
                f"{tenant_id!r}",
                index,
            )

        if hop.depth != index:
            add(
                DelegationDefect.BROKEN_CHAIN,
                f"hop claims depth {hop.depth} at position {index}",
                index,
            )

        if previous is None:
            if root_issuer and hop.issuer != root_issuer:
                add(
                    DelegationDefect.ROOT_MISMATCH,
                    f"chain starts at {hop.issuer!r}, expected {root_issuer!r}",
                    index,
                )
            if hop.previous_hop_digest:
                add(
                    DelegationDefect.BROKEN_CHAIN,
                    "the first hop commits to a predecessor, so a hop before "
                    "it was removed",
                    index,
                )
        else:
            if hop.previous_hop_digest != passport.hops[index - 2].digest:
                add(
                    DelegationDefect.BROKEN_CHAIN,
                    "does not commit to the digest of the hop before it, so "
                    "the order was not signed",
                    index,
                )
            if hop.issuer != previous.subject:
                add(
                    DelegationDefect.SUBJECT_MISMATCH,
                    f"issued by {hop.issuer!r}, but the previous hop delegated "
                    f"to {previous.subject!r}",
                    index,
                )

        # SUBJECTS ONLY, plus the root issuer.
        #
        # The first version tracked issuers as well, and fired on every
        # legitimate chain: hop N's issuer IS hop N-1's subject -- that is
        # correct authority flow, not a cycle -- so the principal necessarily
        # appears twice. It reported DELEGATION_LOOP on the sound fixture,
        # which is the loudest possible way for a check to be wrong and the
        # reason the positive control exists.
        #
        # A real loop is a principal receiving authority twice: A -> B -> C -> B
        # launders scope through a round trip, and A -> B -> A hands it back to
        # the root.
        if hop.subject in seen_principals:
            add(
                DelegationDefect.DELEGATION_LOOP,
                f"{hop.subject!r} is delegated to twice in this chain",
                index,
            )
        seen_principals.add(hop.subject)

        # ── validity in time ───────────────────────────────────────────────
        if moment > hop.expiry:
            add(
                DelegationDefect.EXPIRED,
                f"expired at {hop.expires_at}",
                index,
            )
        elif (hop.issuance - moment).total_seconds() > clock_skew_seconds:
            add(
                DelegationDefect.NOT_YET_VALID,
                f"not valid until {hop.issued_at}",
                index,
            )

        # ── monotonicity: the anti-amplification checks ────────────────────
        if previous is not None:
            granted = hop.permitted_capabilities - previous.permitted_capabilities
            if granted:
                add(
                    DelegationDefect.CAPABILITY_EXPANSION,
                    f"grants {sorted(granted)}, which its issuer did not hold",
                    index,
                )
            if not _scope_is_narrower(hop.resource_scope, previous.resource_scope):
                add(
                    DelegationDefect.SCOPE_EXPANSION,
                    f"scope {list(hop.resource_scope)} is not within "
                    f"{list(previous.resource_scope)}",
                    index,
                )
            if environment_rank(hop.environment) > environment_rank(
                previous.environment
            ):
                add(
                    DelegationDefect.ENVIRONMENT_ESCALATION,
                    f"targets {hop.environment!r} from an issuer scoped to "
                    f"{previous.environment!r}",
                    index,
                )
            if hop.expiry > previous.expiry:
                add(
                    DelegationDefect.LIFETIME_EXTENSION,
                    f"outlives its issuer's grant ({hop.expires_at} > "
                    f"{previous.expires_at}), so revoking the parent would not "
                    "revoke this",
                    index,
                )

        # Deny beats allow, and it accumulates DOWN the chain: a capability
        # prohibited at hop 1 cannot be granted at hop 3, whatever hop 2 said.
        forbidden = hop.permitted_capabilities & prohibited
        if forbidden:
            add(
                DelegationDefect.PROHIBITED_CAPABILITY_GRANTED,
                f"grants {sorted(forbidden)}, prohibited earlier in the chain",
                index,
            )
        prohibited |= set(hop.prohibited_capabilities)

        effective = (
            hop.permitted_capabilities
            if effective is None
            else effective & hop.permitted_capabilities
        )
        scope = hop.resource_scope
        previous = hop

    if presenter and previous is not None and previous.subject != presenter:
        add(
            DelegationDefect.SUBJECT_IS_NOT_THE_PRESENTER,
            f"{presenter!r} presented a chain delegating to "
            f"{previous.subject!r}",
            passport.depth,
        )

    established = frozenset((effective or frozenset()) - prohibited)
    return ChainVerdict(
        findings=tuple(findings),
        effective_capabilities=established if not findings else frozenset(),
        effective_scope=scope if not findings else (),
    )
