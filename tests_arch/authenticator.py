"""A software WebAuthn authenticator, for testing the verifier against real crypto.

WHY BUILD ONE RATHER THAN USE FIXTURES
--------------------------------------
Captured fixtures test that the verifier still parses the bytes it parsed yesterday.
They cannot test that it REJECTS anything, because producing a hostile variant means
re-signing -- which means having a signing authenticator anyway.

This one holds a real P-256 or RSA key, CBOR-encodes an attestation object the way a
platform authenticator does, and signs over `authData || SHA256(clientDataJSON)`.
That means every negative test below is a genuinely valid-except-for-one-thing
response, which is the only kind that proves a check is load-bearing.

It also doubles as a check on the CBOR decoder: the encoder here is independent of
it, so a disagreement between them shows up as a test failure rather than as
compatibility with itself.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from sentinel.infrastructure.webauthn import ES256, RS256, b64url_encode

__all__ = ["SoftwareAuthenticator", "cbor_encode"]


def cbor_encode(value: Any) -> bytes:
    """Minimal canonical CBOR encoder. Independent of the decoder under test."""
    if isinstance(value, bool):
        return bytes([0xF5 if value else 0xF4])
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        if value >= 0:
            return _head(0, value)
        return _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _head(3, len(raw)) + raw
    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(cbor_encode(item) for item in value)
    if isinstance(value, dict):
        # Canonical order: integer keys before text keys, each ascending. Matters
        # because the bytes are hashed.
        integer_keys = sorted(k for k in value if isinstance(k, int))
        text_keys = sorted(k for k in value if isinstance(k, str))
        body = b"".join(
            cbor_encode(k) + cbor_encode(value[k]) for k in [*integer_keys, *text_keys]
        )
        return _head(5, len(value)) + body
    raise TypeError(f"cannot CBOR-encode {type(value).__name__}")


def _head(major: int, argument: int) -> bytes:
    if argument < 24:
        return bytes([(major << 5) | argument])
    for additional, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if argument < 256**width:
            return bytes([(major << 5) | additional]) + argument.to_bytes(width, "big")
    raise ValueError("argument too large")


class SoftwareAuthenticator:
    """Produces registration and assertion responses indistinguishable from a device."""

    def __init__(
        self,
        *,
        rp_id: str = "sentinel.example",
        algorithm: int = ES256,
        credential_id: bytes | None = None,
        aaguid: bytes = b"\x00" * 16,
    ) -> None:
        self.rp_id = rp_id
        self.algorithm = algorithm
        self.credential_id = credential_id or secrets.token_bytes(32)
        self.aaguid = aaguid
        self.sign_count = 0
        if algorithm == ES256:
            self._private = ec.generate_private_key(ec.SECP256R1())
        elif algorithm == RS256:
            self._private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        else:
            raise ValueError(f"unsupported algorithm {algorithm}")

    # ── Key material ─────────────────────────────────────────────────────────

    def cose_key(self) -> dict[int, Any]:
        public = self._private.public_key()
        if self.algorithm == ES256:
            numbers = public.public_numbers()
            return {
                1: 2,  # kty: EC2
                3: ES256,
                -1: 1,  # crv: P-256
                -2: numbers.x.to_bytes(32, "big"),
                -3: numbers.y.to_bytes(32, "big"),
            }
        numbers = public.public_numbers()
        modulus = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
        exponent = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
        return {1: 3, 3: RS256, -1: modulus, -2: exponent}

    def _sign(self, payload: bytes) -> bytes:
        if self.algorithm == ES256:
            return self._private.sign(payload, ec.ECDSA(hashes.SHA256()))
        return self._private.sign(payload, padding.PKCS1v15(), hashes.SHA256())

    # ── Structures ───────────────────────────────────────────────────────────

    def client_data(
        self,
        *,
        challenge: str,
        origin: str,
        ceremony: str,
        cross_origin: bool = False,
    ) -> bytes:
        return json.dumps(
            {
                "type": ceremony,
                "challenge": challenge,
                "origin": origin,
                "crossOrigin": cross_origin,
            },
            separators=(",", ":"),
        ).encode("utf-8")

    def authenticator_data(
        self,
        *,
        include_credential: bool,
        user_present: bool = True,
        user_verified: bool = True,
        sign_count: int | None = None,
        rp_id: str | None = None,
    ) -> bytes:
        flags = 0
        if user_present:
            flags |= 0x01
        if user_verified:
            flags |= 0x04
        if include_credential:
            flags |= 0x40
        counter = self.sign_count if sign_count is None else sign_count
        data = (
            hashlib.sha256((rp_id or self.rp_id).encode("utf-8")).digest()
            + bytes([flags])
            + counter.to_bytes(4, "big")
        )
        if include_credential:
            data += (
                self.aaguid
                + len(self.credential_id).to_bytes(2, "big")
                + self.credential_id
                + cbor_encode(self.cose_key())
            )
        return data

    # ── Ceremonies ───────────────────────────────────────────────────────────

    def register(
        self,
        *,
        challenge: str,
        origin: str = "https://sentinel.example",
        fmt: str = "none",
        user_verified: bool = True,
        user_present: bool = True,
        rp_id: str | None = None,
        ceremony: str = "webauthn.create",
        cross_origin: bool = False,
    ) -> dict[str, Any]:
        client_data = self.client_data(
            challenge=challenge,
            origin=origin,
            ceremony=ceremony,
            cross_origin=cross_origin,
        )
        auth_data = self.authenticator_data(
            include_credential=True,
            user_present=user_present,
            user_verified=user_verified,
            rp_id=rp_id,
        )
        attestation: dict[str, Any] = {"fmt": fmt, "authData": auth_data}
        if fmt == "packed":
            signed = auth_data + hashlib.sha256(client_data).digest()
            attestation["attStmt"] = {"alg": self.algorithm, "sig": self._sign(signed)}
        else:
            attestation["attStmt"] = {}
        return {
            "client_data_json": client_data,
            "attestation_object": cbor_encode(attestation),
        }

    def assert_(
        self,
        *,
        challenge: str,
        origin: str = "https://sentinel.example",
        user_verified: bool = True,
        user_present: bool = True,
        sign_count: int | None = None,
        rp_id: str | None = None,
        ceremony: str = "webauthn.get",
        tamper_signature: bool = False,
    ) -> dict[str, Any]:
        if sign_count is None:
            self.sign_count += 1
            counter = self.sign_count
        else:
            counter = sign_count
        client_data = self.client_data(
            challenge=challenge, origin=origin, ceremony=ceremony
        )
        auth_data = self.authenticator_data(
            include_credential=False,
            user_present=user_present,
            user_verified=user_verified,
            sign_count=counter,
            rp_id=rp_id,
        )
        signature = self._sign(auth_data + hashlib.sha256(client_data).digest())
        if tamper_signature:
            signature = bytes([signature[0] ^ 0xFF]) + signature[1:]
        return {
            "client_data_json": client_data,
            "authenticator_data": auth_data,
            "signature": signature,
        }

    def credential_identifier(self) -> str:
        return b64url_encode(self.credential_id)
