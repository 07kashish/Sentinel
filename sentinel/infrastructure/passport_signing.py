"""Signing and independent verification of an Execution Passport.

WHY THIS IS SEPARATE FROM `domain/passport.py`
------------------------------------------------
Signing needs a key; a key needs a store; a domain module that reaches for
either stops being testable in isolation and starts being infrastructure. The
domain owns the shape, the canonical bytes and every check that needs no key.
This owns the four lines of cryptography and the key handling around them.

The split also makes the important property inspectable: a passport can be
structurally sound and unsigned, or perfectly signed and internally incoherent.
Those are different failures that send a reader to different places, and a
single `verify` returning one boolean would have hidden the distinction.

ED25519, NOT RSA
----------------
Small keys, small signatures, no parameter choices to get wrong, and no
padding mode to select incorrectly. RSA-PSS is fine and RSA-PKCS1v15 is not,
which is a decision this module would otherwise be inviting somebody to make
under time pressure. `cryptography` is already a dependency.

VERIFICATION NEEDS NOTHING BUT A KEY
------------------------------------
`verify` takes a passport document, a public key, and optional comparison
values. It opens no database, makes no network call and reads no configuration.
That is the point of the artifact: a verifier that has to ask Sentinel whether a
passport is genuine is a verifier that trusts Sentinel, which is the trust the
passport exists to remove.

KEY VALIDITY IS CHECKED, NOT ASSUMED
------------------------------------
A signature made by a key that had been revoked or had not yet been issued is
cryptographically perfect and evidentially worthless. `SigningKey` carries a
validity window and `verify` refuses a signature timestamped outside it -- the
"expired certificate" case the specification names, without requiring a full
X.509 chain this project does not run.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from sentinel.domain.passport import (
    ExecutionPassport,
    PassportDefect,
    PassportFinding,
    canonical_bytes,
    verify_structure,
)

__all__ = [
    "SIGNATURE_ALGORITHM",
    "SignedPassport",
    "SigningKey",
    "VerifyingKey",
    "sign",
    "verify",
]

SIGNATURE_ALGORITHM = "ed25519"


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


@dataclass(frozen=True, slots=True)
class SigningKey:
    """A private key and the window in which it was authorised to sign."""

    key_id: str
    private_key: Ed25519PrivateKey
    not_before: datetime | None = None
    not_after: datetime | None = None

    @classmethod
    def generate(cls, key_id: str, **window: Any) -> "SigningKey":
        return cls(key_id=key_id, private_key=Ed25519PrivateKey.generate(), **window)

    def valid_at(self, when: datetime) -> bool:
        """The same window test the public half applies.

        Duplicated rather than shared through a base class: two small dataclasses
        with an identical three-line predicate is less machinery than a hierarchy,
        and `test_a_signing_key_and_its_verifying_key_agree_on_validity` holds
        them equal so the duplication cannot drift.
        """
        if self.not_before is not None and when < self.not_before:
            return False
        if self.not_after is not None and when > self.not_after:
            return False
        return True

    def verifying_key(self) -> "VerifyingKey":
        return VerifyingKey(
            key_id=self.key_id,
            public_key=self.private_key.public_key(),
            not_before=self.not_before,
            not_after=self.not_after,
        )


@dataclass(frozen=True, slots=True)
class VerifyingKey:
    """A public key, its identifier and the window it was valid for.

    The window travels WITH the key rather than being looked up, so a verifier
    holding a key file can check it without asking anybody -- which is the
    independence the passport is for.
    """

    key_id: str
    public_key: Ed25519PublicKey
    not_before: datetime | None = None
    not_after: datetime | None = None

    def valid_at(self, when: datetime) -> bool:
        if self.not_before is not None and when < self.not_before:
            return False
        if self.not_after is not None and when > self.not_after:
            return False
        return True


@dataclass(frozen=True, slots=True)
class SignedPassport:
    """A passport document plus the detached signature over its canonical bytes.

    The signature is NOT inside the document. A signature that covered itself is
    impossible, and the usual workaround -- signing the document with the
    signature field blanked -- means the bytes a verifier hashes are not the
    bytes it received, which is one more place for two implementations to
    disagree.
    """

    document: Mapping[str, Any]
    signature: str
    key_id: str
    signed_at: str
    algorithm: str = SIGNATURE_ALGORITHM

    def as_dict(self) -> dict[str, Any]:
        return {
            "passport": dict(self.document),
            "signature": {
                "algorithm": self.algorithm,
                "key_id": self.key_id,
                "signed_at": self.signed_at,
                "value": self.signature,
            },
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "SignedPassport":
        signature = payload.get("signature") or {}
        return cls(
            document=dict(payload.get("passport") or {}),
            signature=str(signature.get("value", "")),
            key_id=str(signature.get("key_id", "")),
            signed_at=str(signature.get("signed_at", "")),
            algorithm=str(signature.get("algorithm", SIGNATURE_ALGORITHM)),
        )


def sign(
    passport: ExecutionPassport, *, key: SigningKey, signed_at: datetime
) -> SignedPassport:
    """Sign a passport's canonical bytes.

    `signed_at` is passed in rather than read from the clock, for the same
    reason every other timestamp in this codebase is: a signature whose time
    came from the wall clock cannot be reproduced in a test at a key-validity
    boundary, and those boundaries are exactly what needs testing.
    """
    if not key.valid_at(signed_at):
        raise ValueError(
            f"key {key.key_id!r} was not valid at {signed_at.isoformat()}; "
            "signing with an out-of-window key produces a cryptographically "
            "perfect and evidentially worthless signature"
        )
    document = passport.as_document()
    return SignedPassport(
        document=document,
        signature=_b64(key.private_key.sign(canonical_bytes(document))),
        key_id=key.key_id,
        signed_at=signed_at.isoformat(),
    )


def verify(
    signed: SignedPassport,
    *,
    key: VerifyingKey,
    parents: Mapping[str, ExecutionPassport] | None = None,
    expected_policy_digest: str = "",
    approved_tool_fingerprint: str = "",
    attestation_digest: str = "",
) -> tuple[PassportFinding, ...]:
    """Every defect in this passport: signature, key window, and structure.

    Returns findings rather than a boolean. "Invalid" is not actionable; "the
    tool definition changed between approval and execution" is, and a verifier
    that collapsed the two would be throwing away the reason somebody is
    reading a passport in the first place.
    """
    findings: list[PassportFinding] = []

    def add(defect: PassportDefect, detail: str) -> None:
        findings.append(PassportFinding(defect=defect, detail=detail))

    if signed.algorithm != SIGNATURE_ALGORITHM:
        add(
            PassportDefect.MODIFIED,
            f"signed with {signed.algorithm!r}; this verifier implements "
            f"{SIGNATURE_ALGORITHM!r} and will not guess at another",
        )
        return tuple(findings)

    if signed.key_id != key.key_id:
        add(
            PassportDefect.MODIFIED,
            f"signed by key {signed.key_id!r}, verified against "
            f"{key.key_id!r}: the wrong key proves nothing about this document",
        )
        return tuple(findings)

    try:
        key.public_key.verify(_unb64(signed.signature), canonical_bytes(signed.document))
    except (InvalidSignature, ValueError, TypeError):
        add(
            PassportDefect.MODIFIED,
            "the signature does not verify over this document's canonical bytes",
        )
        # No further structural reporting. Once the bytes are untrustworthy,
        # every field read out of them is a claim by whoever altered it, and
        # listing those claims as findings dresses attacker input as analysis.
        return tuple(findings)

    # Checked AFTER the signature, deliberately: an out-of-window signature on a
    # forged document is a forgery, not an expiry, and reporting the expiry
    # first would send somebody to renew a key when they should be investigating.
    if signed.signed_at:
        try:
            when = datetime.fromisoformat(signed.signed_at)
        except ValueError:
            when = None
        if when is None:
            add(PassportDefect.MODIFIED, "signed_at is not a parseable timestamp")
        elif not key.valid_at(when):
            add(
                PassportDefect.MODIFIED,
                f"signed at {signed.signed_at} with key {key.key_id!r}, which "
                "was not valid then",
            )

    passport = ExecutionPassport.from_document(signed.document)
    findings.extend(
        verify_structure(
            passport,
            document=signed.document,
            parents=parents,
            expected_policy_digest=expected_policy_digest,
            approved_tool_fingerprint=approved_tool_fingerprint,
            attestation_digest=attestation_digest,
        )
    )
    return tuple(findings)
