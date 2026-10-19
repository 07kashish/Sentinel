"""Passkeys. Server-side WebAuthn registration and assertion verification.

WHY PASSKEYS AND NOT A PASSWORD
-------------------------------
This service has no password store and is not getting one. A password requires
hashing choices, a reset flow, breach-list checks, and a rate-limited guessing
surface -- and it remains phishable, which is the failure mode that actually
compromises accounts.

A passkey is a key pair whose private half never leaves the authenticator, and the
signature is bound to the ORIGIN by the browser. A convincing replica of this
service's login page cannot obtain a usable assertion, because the browser computes
`clientData.origin` itself and the authenticator scopes the credential to the RP id.
That is phishing resistance as a property of the protocol rather than of the user's
attention.

WHAT THE VERIFIER MUST CHECK, AND WHAT GOES WRONG IF IT DOES NOT
---------------------------------------------------------------
Each of these is a real bypass in implementations that skipped it:

  * **type** -- `webauthn.get` vs `webauthn.create`. Without it, a registration
    ceremony's signature is replayable as a login.
  * **challenge** -- compared to the one WE issued, single-use. Without it every
    assertion is replayable forever.
  * **origin** -- exact match against a configured allowlist. Substring or suffix
    matching is why `sentinel.example.attacker.com` works against a check for
    `sentinel.example`.
  * **rpIdHash** -- SHA-256 of the RP id, inside the signed `authData`. This is the
    authenticator's own statement of which site it signed for, and it is the one
    field a malicious *client* cannot forge.
  * **user present / user verified** -- UV proves a gesture on the device (PIN,
    biometric), which is what makes a single assertion two factors.
  * **signature** -- over `authData || SHA256(clientDataJSON)`, with the credential's
    registered public key. Verifying with a key taken from the ASSERTION rather
    than from storage is a complete bypass, and it is an easy mistake because the
    registration response does carry a key.
  * **sign count** -- must not go backwards. A cloned authenticator reveals itself
    by replaying a counter, and a counter of 0 means the authenticator does not
    implement one (which many passkey platforms do not) and must be tolerated
    rather than treated as a failure.

WHAT THIS DELIBERATELY DOES NOT DO
----------------------------------
No attestation-certificate chain validation. Attestation tells you the make and
model of the authenticator, which only matters if you intend to REFUSE some models.
This deployment does not, so the honest choice is to accept `none` and self-attested
`packed` and not to pretend a trust decision is being made. Verifying a chain we
would never act on would be code that looks like a control and is not one.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from sentinel.domain.errors import DomainRuleViolated
from sentinel.infrastructure.cbor import CborError, decode, decode_prefix

__all__ = [
    "AuthenticatorData",
    "PasskeyError",
    "RegisteredCredential",
    "WebAuthnVerifier",
    "b64url_decode",
    "b64url_encode",
    "new_challenge",
]

#: COSE algorithm identifiers this verifier accepts.
#:
#: ES256 first, because it is what every platform authenticator produces. RS256 is
#: accepted for older Windows Hello. Nothing else: an algorithm nobody sends is an
#: algorithm whose verification path is never exercised.
ES256 = -7
RS256 = -257
SUPPORTED_ALGORITHMS = (ES256, RS256)

#: Flag bits in authenticator data.
_FLAG_USER_PRESENT = 0x01
_FLAG_USER_VERIFIED = 0x04
_FLAG_ATTESTED_CREDENTIAL_DATA = 0x40

#: Challenge size. 16 bytes is the spec minimum; 32 removes any argument.
CHALLENGE_BYTES = 32


class PasskeyError(DomainRuleViolated):
    """A registration or assertion failed verification. Never retried as-is."""



def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    """Strict base64url. `urlsafe_b64decode` silently DISCARDS stray characters.

    Without `validate=True`, `"!!!"` decodes to empty bytes and is accepted as a
    valid field -- the same defect found in the envelope cipher's wire format
    earlier in this codebase.
    """
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except Exception as exc:  # noqa: BLE001 - binascii raises several types
        raise PasskeyError(f"not valid base64url: {exc}") from exc


def new_challenge() -> str:
    """A fresh challenge. Must be stored and consumed exactly once."""
    return b64url_encode(secrets.token_bytes(CHALLENGE_BYTES))


@dataclass(frozen=True, slots=True)
class AuthenticatorData:
    """The parsed `authData` structure, which is the part the signature covers."""

    rp_id_hash: bytes
    flags: int
    sign_count: int
    credential_id: bytes | None
    credential_public_key: Mapping[int, Any] | None
    raw: bytes

    @property
    def user_present(self) -> bool:
        return bool(self.flags & _FLAG_USER_PRESENT)

    @property
    def user_verified(self) -> bool:
        return bool(self.flags & _FLAG_USER_VERIFIED)


@dataclass(frozen=True, slots=True)
class RegisteredCredential:
    """What a successful registration produces, to be stored and looked up later."""

    credential_id: bytes
    #: The COSE public key, as CBOR bytes exactly as the authenticator sent them.
    #: Stored raw rather than re-encoded, because re-encoding is an opportunity to
    #: change bytes that a signature was computed over.
    public_key_cose: bytes
    algorithm: int
    sign_count: int
    user_verified: bool
    #: The authenticator model, recorded for the audit trail and NOT acted on --
    #: see the module docstring on attestation.
    aaguid: str

    def identifier(self) -> str:
        return b64url_encode(self.credential_id)


def _parse_authenticator_data(raw: bytes) -> AuthenticatorData:
    if len(raw) < 37:
        raise PasskeyError(
            f"authenticator data is {len(raw)} bytes; the fixed header alone is 37"
        )
    rp_id_hash = raw[:32]
    flags = raw[32]
    sign_count = int.from_bytes(raw[33:37], "big")
    credential_id: bytes | None = None
    public_key: Mapping[int, Any] | None = None

    if flags & _FLAG_ATTESTED_CREDENTIAL_DATA:
        if len(raw) < 55:
            raise PasskeyError("attested credential data is truncated")
        length = int.from_bytes(raw[53:55], "big")
        if length == 0 or length > 1023:
            # The spec caps a credential id at 1023 bytes. A zero length would make
            # the credential unlookupable.
            raise PasskeyError(f"credential id length {length} is out of range 1-1023")
        end = 55 + length
        if end > len(raw):
            raise PasskeyError("credential id runs past the end of authenticator data")
        credential_id = raw[55:end]
        # The COSE key is followed by nothing in practice, but `decode_prefix` is
        # used rather than `decode` because extensions may follow, and the length of
        # the key is not stated anywhere.
        try:
            parsed, _consumed = decode_prefix(raw[end:])
        except CborError as exc:
            raise PasskeyError(f"credential public key is not valid CBOR: {exc}") from exc
        if not isinstance(parsed, dict):
            raise PasskeyError("credential public key is not a CBOR map")
        public_key = parsed

    return AuthenticatorData(
        rp_id_hash=rp_id_hash,
        flags=flags,
        sign_count=sign_count,
        credential_id=credential_id,
        credential_public_key=public_key,
        raw=raw,
    )


def _public_key_from_cose(cose: Mapping[int, Any]):
    """Turn a COSE_Key into a `cryptography` public key, or refuse.

    Only the two algorithms above, and the key type must AGREE with the algorithm.
    A COSE key claiming ES256 with RSA parameters is a confusion attempt, and
    trusting the algorithm label while reading the other type's fields is how
    verification ends up succeeding against the wrong key.
    """
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    key_type = cose.get(1)
    algorithm = cose.get(3)
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise PasskeyError(
            f"unsupported COSE algorithm {algorithm!r}; accepted: {SUPPORTED_ALGORITHMS}"
        )
    if algorithm == ES256:
        if key_type != 2:
            raise PasskeyError(
                f"COSE algorithm ES256 with key type {key_type!r}: the label and the "
                "parameters disagree, which is a type-confusion attempt"
            )
        if cose.get(-1) != 1:
            raise PasskeyError("ES256 requires curve P-256")
        x, y = cose.get(-2), cose.get(-3)
        if not isinstance(x, bytes) or not isinstance(y, bytes):
            raise PasskeyError("ES256 key is missing its coordinates")
        if len(x) != 32 or len(y) != 32:
            raise PasskeyError(
                f"P-256 coordinates must be 32 bytes, got {len(x)} and {len(y)}"
            )
        try:
            return ec.EllipticCurvePublicNumbers(
                int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
            ).public_key()
        except ValueError as exc:
            # A point not on the curve. `cryptography` checks this; relying on it is
            # deliberate rather than reimplementing the check.
            raise PasskeyError(f"ES256 key is not a valid P-256 point: {exc}") from exc
    if key_type != 3:
        raise PasskeyError(
            f"COSE algorithm RS256 with key type {key_type!r}: the label and the "
            "parameters disagree"
        )
    modulus, exponent = cose.get(-1), cose.get(-2)
    if not isinstance(modulus, bytes) or not isinstance(exponent, bytes):
        raise PasskeyError("RS256 key is missing its modulus or exponent")
    if len(modulus) * 8 < 2048:
        raise PasskeyError(
            f"RSA modulus is {len(modulus) * 8} bits; under 2048 is refused"
        )
    return rsa.RSAPublicNumbers(
        int.from_bytes(exponent, "big"), int.from_bytes(modulus, "big")
    ).public_key()


def _verify_signature(cose: Mapping[int, Any], signed: bytes, signature: bytes) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding

    key = _public_key_from_cose(cose)
    try:
        if cose.get(3) == ES256:
            key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        else:
            key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature as exc:
        raise PasskeyError("the assertion signature is not valid") from exc


@dataclass(frozen=True, slots=True)
class WebAuthnVerifier:
    """Verifies registration and assertion responses for one relying party.

    `origins` is an exact-match allowlist. Not a suffix or substring check: that is
    precisely why `sentinel.example.attacker.com` passes a naive test for
    `sentinel.example`.
    """

    rp_id: str
    origins: tuple[str, ...]
    #: Require the authenticator to have verified the user (PIN, biometric). ON by
    #: default: user verification is what makes one assertion two factors, and a
    #: deployment turning it off should have to say so.
    require_user_verification: bool = True

    def __post_init__(self) -> None:
        if not self.rp_id:
            raise PasskeyError("an RP id is required")
        if not self.origins:
            raise PasskeyError(
                "at least one expected origin is required. An empty allowlist would "
                "accept an assertion from any site."
            )
        for origin in self.origins:
            if not origin.startswith("https://") and not origin.startswith("http://localhost"):
                raise PasskeyError(
                    f"origin {origin!r} must be https (or http://localhost for "
                    "development). WebAuthn over cleartext is not a secure context."
                )

    @property
    def rp_id_hash(self) -> bytes:
        return hashlib.sha256(self.rp_id.encode("utf-8")).digest()

    # ── Shared client-data checks ────────────────────────────────────────────

    def _client_data(
        self, client_data_json: bytes, *, expected_type: str, challenge: str
    ) -> Mapping[str, Any]:
        try:
            parsed = json.loads(client_data_json.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PasskeyError(f"clientDataJSON is not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise PasskeyError("clientDataJSON is not an object")

        if parsed.get("type") != expected_type:
            # Without this, a registration signature is replayable as a login.
            raise PasskeyError(
                f"clientData.type is {parsed.get('type')!r}, expected "
                f"{expected_type!r}. A ceremony's response must not be usable in a "
                "different ceremony."
            )

        presented = parsed.get("challenge")
        if not isinstance(presented, str):
            raise PasskeyError("clientData.challenge is missing")
        # Compared as decoded BYTES, so an encoding difference in padding cannot
        # cause a false mismatch or a false match.
        import hmac as _hmac

        if not _hmac.compare_digest(b64url_decode(presented), b64url_decode(challenge)):
            raise PasskeyError(
                "the challenge does not match the one issued. Every assertion would "
                "otherwise be replayable forever."
            )

        origin = parsed.get("origin")
        if origin not in self.origins:
            raise PasskeyError(
                f"origin {origin!r} is not in the expected set {self.origins}. "
                "Matched exactly, never by suffix -- suffix matching is why "
                "'site.example.attacker.com' passes a check for 'site.example'."
            )
        if parsed.get("crossOrigin") is True:
            raise PasskeyError(
                "the ceremony was performed cross-origin, in an iframe. Refused: the "
                "user cannot see which site they are authenticating to."
            )
        return parsed

    def _check_authenticator_data(self, data: AuthenticatorData) -> None:
        import hmac as _hmac

        if not _hmac.compare_digest(data.rp_id_hash, self.rp_id_hash):
            # The authenticator's own statement of which site it signed for. The one
            # field a malicious client cannot forge.
            raise PasskeyError(
                "the authenticator signed for a different relying party. This field "
                "is produced by the authenticator, so a mismatch means the "
                "credential does not belong to this service."
            )
        if not data.user_present:
            raise PasskeyError("the user-present flag is not set")
        if self.require_user_verification and not data.user_verified:
            raise PasskeyError(
                "the authenticator did not verify the user. User verification (a PIN "
                "or biometric on the device) is what makes one assertion two "
                "factors, so it is required unless a deployment says otherwise."
            )

    # ── Registration ─────────────────────────────────────────────────────────

    def verify_registration(
        self,
        *,
        client_data_json: bytes,
        attestation_object: bytes,
        challenge: str,
    ) -> RegisteredCredential:
        """Verify a `navigator.credentials.create()` response."""
        self._client_data(
            client_data_json, expected_type="webauthn.create", challenge=challenge
        )
        try:
            attestation = decode(attestation_object)
        except CborError as exc:
            raise PasskeyError(f"attestationObject is not valid CBOR: {exc}") from exc
        if not isinstance(attestation, dict):
            raise PasskeyError("attestationObject is not a CBOR map")

        fmt = attestation.get("fmt")
        if fmt not in ("none", "packed"):
            # See the module docstring: accepting only what we can meaningfully
            # check, rather than validating a chain we would never act on.
            raise PasskeyError(
                f"attestation format {fmt!r} is not accepted. This deployment does "
                "not restrict authenticator models, so it accepts 'none' and "
                "self-attested 'packed' rather than validating a certificate chain "
                "it would not act on."
            )
        raw_auth_data = attestation.get("authData")
        if not isinstance(raw_auth_data, bytes):
            raise PasskeyError("attestationObject has no authData")

        data = _parse_authenticator_data(raw_auth_data)
        self._check_authenticator_data(data)
        if data.credential_id is None or data.credential_public_key is None:
            raise PasskeyError(
                "the attested-credential-data flag is not set, so this response "
                "carries no credential to register"
            )

        cose = data.credential_public_key
        algorithm = cose.get(3)
        # Parsing the key proves it is well-formed and on-curve before it is stored.
        # Storing an unusable key turns a registration problem into a login problem.
        _public_key_from_cose(cose)

        if fmt == "packed":
            self._verify_packed_self_attestation(
                attestation, raw_auth_data, client_data_json, cose
            )

        # The key is re-encoded from the raw bytes it arrived in, not from the parsed
        # map: a round trip through a decoder and encoder is an opportunity to change
        # bytes that a future signature will be verified against.
        offset = 55 + len(data.credential_id)
        _key, consumed = decode_prefix(raw_auth_data[offset:])
        public_key_cose = raw_auth_data[offset : offset + consumed]

        return RegisteredCredential(
            credential_id=data.credential_id,
            public_key_cose=public_key_cose,
            algorithm=_require_algorithm(algorithm),
            sign_count=data.sign_count,
            user_verified=data.user_verified,
            aaguid=raw_auth_data[37:53].hex(),
        )

    def _verify_packed_self_attestation(
        self,
        attestation: Mapping[str, Any],
        raw_auth_data: bytes,
        client_data_json: bytes,
        cose: Mapping[int, Any],
    ) -> None:
        """Self-attestation: the signature is by the credential key itself.

        Refused if a certificate is present, because that is full attestation and
        verifying it would mean making a trust decision about the authenticator
        model -- which this deployment does not make, so claiming to would be worse
        than declining.
        """
        statement = attestation.get("attStmt")
        if not isinstance(statement, dict):
            raise PasskeyError("packed attestation has no attStmt")
        if "x5c" in statement:
            raise PasskeyError(
                "packed attestation with a certificate chain is refused. Validating "
                "it would imply a trust decision about the authenticator model that "
                "this deployment does not make; register with 'none' or self "
                "attestation."
            )
        signature = statement.get("sig")
        if not isinstance(signature, bytes):
            raise PasskeyError("packed attestation has no signature")
        if statement.get("alg") != cose.get(3):
            raise PasskeyError(
                "the attestation statement's algorithm disagrees with the credential "
                "key's"
            )
        signed = raw_auth_data + hashlib.sha256(client_data_json).digest()
        _verify_signature(cose, signed, signature)

    # ── Assertion ────────────────────────────────────────────────────────────

    def verify_assertion(
        self,
        *,
        client_data_json: bytes,
        authenticator_data: bytes,
        signature: bytes,
        challenge: str,
        credential: RegisteredCredential,
    ) -> int:
        """Verify a `navigator.credentials.get()` response. Returns the new sign count.

        `credential` comes from STORAGE. Verifying with a key taken from the
        assertion would accept a signature by any key the caller chose, which is a
        complete bypass -- and it is an easy mistake, because a registration
        response does carry a key and an assertion response looks similar.
        """
        self._client_data(
            client_data_json, expected_type="webauthn.get", challenge=challenge
        )
        data = _parse_authenticator_data(authenticator_data)
        self._check_authenticator_data(data)

        try:
            cose = decode(credential.public_key_cose)
        except CborError as exc:
            raise PasskeyError(f"the stored credential key is unreadable: {exc}") from exc
        if not isinstance(cose, dict):
            raise PasskeyError("the stored credential key is not a CBOR map")

        signed = authenticator_data + hashlib.sha256(client_data_json).digest()
        _verify_signature(cose, signed, signature)

        # A counter that goes backwards means two authenticators share one
        # credential, i.e. one was cloned. A counter that stays at zero means the
        # authenticator does not implement one, which most passkey platforms do not
        # -- so zero is tolerated and a decrease is not.
        if data.sign_count == 0 and credential.sign_count == 0:
            return 0
        if data.sign_count <= credential.sign_count:
            raise PasskeyError(
                f"the signature counter did not advance ({data.sign_count} <= "
                f"{credential.sign_count}). This is the signal a credential has been "
                "cloned onto a second authenticator."
            )
        return data.sign_count

    def allowed_credentials(
        self, credentials: Sequence[RegisteredCredential]
    ) -> list[Mapping[str, Any]]:
        """The `allowCredentials` list for a login challenge."""
        return [
            {"type": "public-key", "id": credential.identifier()}
            for credential in credentials
        ]

def _require_algorithm(algorithm: object) -> int:
    """The COSE algorithm identifier, or a named refusal.

    The attestation object may omit it. `int(None)` would raise TypeError deep
    inside registration, which reads as a bug rather than as a malformed
    credential -- and a credential registered with an unknown algorithm cannot
    be verified later.
    """
    if algorithm is None:
        raise PasskeyError(
            "the attestation statement declares no COSE algorithm. Refusing to "
            "register a credential whose signature algorithm is unknown: it "
            "could not be verified at authentication time."
        )
    return int(algorithm)  # type: ignore[call-overload]
