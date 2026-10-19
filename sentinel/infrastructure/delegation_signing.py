"""Sign and verify delegation hops. Ed25519, one key per issuer.

WHY THE KEY ID IS NAMESPACED BY ITS OWNER
------------------------------------------
`verify_chain` refuses a hop whose `key_id` does not begin with its issuer.
That check only means anything if key ids are actually namespaced, so
`issuer_key_id` is the one place that constructs them and
`test_a_key_id_is_namespaced_by_its_issuer` holds the two together.

The alternative -- a key registry mapping issuer to key id -- puts the binding
in a lookup table the control plane owns, which is the thing the whole design
is trying not to depend on. A verifier holding `user:priya#1` can tell whose
key it is by reading it.

WHY VERIFICATION RETURNS A DEFECT AND NOT A BOOLEAN
----------------------------------------------------
"The signature is invalid" and "the key was not supplied" and "the key was
outside its window when it signed" call for three different responses, and a
caller that only sees False cannot tell them apart. In particular an UNKNOWN
KEY must never read as a valid one: a verifier handed no key for a hop has not
checked that hop, and the difference between that and a good signature is the
difference between evidence and an assumption.

WHAT A HOP SIGNATURE PROVES
---------------------------
That the named issuer authorised exactly these capabilities, over exactly this
scope, in exactly this position in the chain, before this expiry. It does not
prove the issuer was entitled to -- that is what the monotonicity checks in
`verify_chain` are for, and they are separate because a well-signed hop that
widens scope is the interesting attack.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from sentinel.domain.delegation_passport import (
    DelegationDefect,
    DelegationHop,
    SignedHop,
)
from sentinel.domain.passport import canonical_bytes

__all__ = [
    "SIGNATURE_ALGORITHM",
    "HopSigningKey",
    "HopVerifyingKey",
    "KeyRingVerifier",
    "issuer_key_id",
    "sign_hop",
]

#: Ed25519. Fixed, and named in the signed envelope so a verifier refuses an
#: algorithm it does not implement rather than guessing at another.
SIGNATURE_ALGORITHM = "ed25519"


def issuer_key_id(issuer: str, *, version: int = 1) -> str:
    """The only place a hop key id is constructed.

    `issuer#version`. The namespace is what lets `verify_chain` tell whose key
    signed a hop by READING the id, rather than by consulting a registry the
    control plane owns -- which would put the issuer-to-key binding back under
    the platform's control, and that binding is the thing being proved.
    """
    if not issuer.strip():
        raise ValueError("an unnamed issuer cannot own a key")
    if "#" in issuer:
        raise ValueError(
            f"issuer {issuer!r} contains '#', which is the namespace separator. "
            "An issuer whose name embeds one could forge a key id for another "
            "issuer by naming itself 'victim#1'."
        )
    if version < 1:
        raise ValueError(f"version={version} is not a key version; the first is 1")
    return f"{issuer}#{version}"


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


@dataclass(frozen=True, slots=True)
class HopSigningKey:
    """An issuer's private key and the window it was authorised to sign in."""

    issuer: str
    private_key: Ed25519PrivateKey
    version: int = 1
    not_before: datetime | None = None
    not_after: datetime | None = None

    @classmethod
    def generate(cls, issuer: str, **window) -> "HopSigningKey":
        return cls(
            issuer=issuer, private_key=Ed25519PrivateKey.generate(), **window
        )

    @property
    def key_id(self) -> str:
        return issuer_key_id(self.issuer, version=self.version)

    def valid_at(self, when: datetime) -> bool:
        if self.not_before is not None and when < self.not_before:
            return False
        if self.not_after is not None and when > self.not_after:
            return False
        return True

    def verifying_key(self) -> "HopVerifyingKey":
        return HopVerifyingKey(
            issuer=self.issuer,
            public_key=self.private_key.public_key(),
            version=self.version,
            not_before=self.not_before,
            not_after=self.not_after,
        )


@dataclass(frozen=True, slots=True)
class HopVerifyingKey:
    """An issuer's public key, its window, and who it belongs to.

    The window travels WITH the key rather than being looked up, so a verifier
    holding a key file can check a hop without asking anybody -- which is the
    independence the delegation passport exists for.
    """

    issuer: str
    public_key: Ed25519PublicKey
    version: int = 1
    not_before: datetime | None = None
    not_after: datetime | None = None

    @property
    def key_id(self) -> str:
        return issuer_key_id(self.issuer, version=self.version)

    def valid_at(self, when: datetime) -> bool:
        if self.not_before is not None and when < self.not_before:
            return False
        if self.not_after is not None and when > self.not_after:
            return False
        return True


def sign_hop(
    hop: DelegationHop, *, key: HopSigningKey, signed_at: datetime
) -> SignedHop:
    """Sign a hop's canonical bytes with its ISSUER's key.

    Refuses to sign a hop whose issuer is not this key's owner. Producing that
    signature would be trivial and the result is what `verify_chain` exists to
    reject, so it is refused at the point of creation as well -- a forgery that
    can only be made deliberately is better than one that can be made by
    passing the wrong key.
    """
    if hop.issuer != key.issuer:
        raise ValueError(
            f"key belongs to {key.issuer!r} and this hop is issued by "
            f"{hop.issuer!r}. A signature by the wrong party is exactly what "
            "verify_chain refuses, so it is not produced here either."
        )
    if not key.valid_at(signed_at):
        raise ValueError(
            f"key {key.key_id!r} was not valid at {signed_at.isoformat()}; "
            "signing with an out-of-window key produces a cryptographically "
            "perfect and evidentially worthless signature"
        )

    document = hop.as_document()
    return SignedHop(
        document=document,
        signature=_b64(key.private_key.sign(canonical_bytes(document))),
        key_id=key.key_id,
        signed_at=signed_at.isoformat(),
    )


@dataclass(frozen=True, slots=True)
class KeyRingVerifier:
    """Verifies hops against a set of issuer public keys.

    Frozen and holding no mutable state, so one verifier is safe to share
    across tenants -- there is nothing per-request here.
    """

    keys: Mapping[str, HopVerifyingKey]

    @classmethod
    def of(cls, *keys: HopVerifyingKey) -> "KeyRingVerifier":
        return cls(keys={key.key_id: key for key in keys})

    def verify(
        self, signed: SignedHop, *, when: datetime
    ) -> DelegationDefect | None:
        """None when sound, or the SPECIFIC defect.

        An unknown key yields UNKNOWN_KEY and never None. A verifier handed no
        key for a hop has not checked that hop, and reporting that as valid is
        the single most dangerous thing this function could do -- the output
        would be indistinguishable from a real verification.
        """
        key = self.keys.get(signed.key_id)
        if key is None:
            return DelegationDefect.UNKNOWN_KEY

        # The window is checked against when the hop was SIGNED, not against
        # now. A key that has since expired still signed validly at the time;
        # a key that was not yet valid then did not.
        try:
            signed_at = datetime.fromisoformat(
                signed.signed_at.replace("Z", "+00:00")
            )
        except ValueError:
            return DelegationDefect.SIGNATURE_INVALID
        if signed_at.tzinfo is None:
            # A naive signing time cannot be compared to a key window without
            # assuming a zone, and assuming one is how a signature passes a
            # boundary it should have failed.
            return DelegationDefect.SIGNATURE_INVALID
        if not key.valid_at(signed_at):
            return DelegationDefect.KEY_OUT_OF_WINDOW

        try:
            key.public_key.verify(
                _unb64(signed.signature), canonical_bytes(dict(signed.document))
            )
        except (InvalidSignature, ValueError, TypeError):
            return DelegationDefect.SIGNATURE_INVALID

        return None
