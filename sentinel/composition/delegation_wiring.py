"""The delegation key ring: which issuers' signatures a chain may rest on.

WHY THIS IS NOT IN `container.py`
----------------------------------
`verify_chain` and `KeyRingVerifier` existed with no production caller -- a
signed delegation chain could be constructed, tested and never checked by any
route. Wiring them means deciding WHOSE public keys this deployment trusts,
which is a security decision with its own reason to change, so it gets a file
of its own for the same reason the two wire clients do.

WHERE THE KEYS COME FROM, AND THE LIMIT STATED
----------------------------------------------
`SENTINEL_DELEGATION_KEYS`, parsed by `Settings._delegation_keys` into
`(issuer#version, base64 public key)` pairs and decoded here. Enrolled agent
cards would be the natural home for an agent's signing key, and they carry no
key field today -- `AgentCard` is owned by the A2A domain module and changing
its shape re-pins every enrolled fingerprint. Until a card can carry a key,
the ring is deployment configuration. An EMPTY ring is a working ring that
refuses every signed hop as UNKNOWN_KEY, which is the correct reading of "no
issuer has been trusted yet".

A malformed key fails HERE, at startup, rather than at the first chain that
names it: a key ring with one undecodable entry would otherwise refuse one
issuer's chains for a reason that looked like forgery.
"""

from __future__ import annotations

import base64
import binascii

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sentinel.composition.settings import ConfigurationError, Settings
from sentinel.infrastructure.delegation_signing import (
    HopVerifyingKey,
    KeyRingVerifier,
)

__all__ = ["build_delegation_verifier"]


def build_delegation_verifier(settings: Settings) -> KeyRingVerifier:
    """A verifier over every configured issuer key. Empty is allowed."""
    keys: list[HopVerifyingKey] = []
    for key_id, material in settings.delegation_keys:
        issuer, _separator, version = key_id.rpartition("#")
        try:
            raw = base64.b64decode(material.encode("ascii"), validate=True)
            public_key = Ed25519PublicKey.from_public_bytes(raw)
            version_number = int(version)
        except (binascii.Error, ValueError, TypeError) as exc:
            raise ConfigurationError(
                f"SENTINEL_DELEGATION_KEYS entry {key_id!r} does not decode to "
                f"an Ed25519 public key with an integer version: {exc}"
            ) from exc
        if version_number < 1:
            raise ConfigurationError(
                f"SENTINEL_DELEGATION_KEYS entry {key_id!r}: versions start at 1"
            )
        keys.append(
            HopVerifyingKey(
                issuer=issuer, public_key=public_key, version=version_number
            )
        )
    return KeyRingVerifier.of(*keys)
