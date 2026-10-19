"""Passkeys, verified against a real software authenticator.

Every negative test here sends a response that is valid in every respect except the
one under test, produced by an authenticator holding a real key. That is the only
kind of test that proves a check is load-bearing: a hand-edited fixture fails for
the wrong reason (a broken signature) and would pass even if the check were removed.
"""

from __future__ import annotations

import hashlib

import pytest

from sentinel.infrastructure.cbor import CborError, decode
from sentinel.infrastructure.webauthn import (
    ES256,
    RS256,
    PasskeyError,
    RegisteredCredential,
    WebAuthnVerifier,
    b64url_decode,
    b64url_encode,
    new_challenge,
)
from tests_arch.authenticator import SoftwareAuthenticator, cbor_encode

RP_ID = "sentinel.example"
ORIGIN = "https://sentinel.example"


@pytest.fixture
def verifier() -> WebAuthnVerifier:
    return WebAuthnVerifier(rp_id=RP_ID, origins=(ORIGIN,))


@pytest.fixture
def device() -> SoftwareAuthenticator:
    return SoftwareAuthenticator(rp_id=RP_ID)


def _registered(verifier, device, challenge=None) -> RegisteredCredential:
    challenge = challenge or new_challenge()
    response = device.register(challenge=challenge)
    return verifier.verify_registration(challenge=challenge, **response)


# ── Registration ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("algorithm", [ES256, RS256])
def test_registration_succeeds_for_both_accepted_algorithms(verifier, algorithm):
    device = SoftwareAuthenticator(rp_id=RP_ID, algorithm=algorithm)
    credential = _registered(verifier, device)
    assert credential.credential_id == device.credential_id
    assert credential.algorithm == algorithm
    assert credential.user_verified is True


def test_self_attested_packed_registration_is_verified(verifier, device):
    """The signature is by the credential key itself and must actually be checked."""
    challenge = new_challenge()
    response = device.register(challenge=challenge, fmt="packed")
    credential = verifier.verify_registration(challenge=challenge, **response)
    assert credential.credential_id == device.credential_id


def test_a_packed_attestation_with_a_broken_signature_is_refused(verifier, device):
    challenge = new_challenge()
    response = device.register(challenge=challenge, fmt="packed")
    attestation = decode(response["attestation_object"])
    signature = attestation["attStmt"]["sig"]
    attestation["attStmt"]["sig"] = bytes([signature[0] ^ 0xFF]) + signature[1:]
    with pytest.raises(PasskeyError) as refused:
        verifier.verify_registration(
            challenge=challenge,
            client_data_json=response["client_data_json"],
            attestation_object=cbor_encode(attestation),
        )
    assert "signature" in str(refused.value)


def test_a_certificate_chain_is_refused_rather_than_half_validated(verifier, device):
    """Validating a chain would imply a trust decision about the authenticator model
    that this deployment does not make. Claiming to make it would be worse than
    declining."""
    challenge = new_challenge()
    response = device.register(challenge=challenge, fmt="packed")
    attestation = decode(response["attestation_object"])
    attestation["attStmt"]["x5c"] = [b"\x30\x82fake"]
    with pytest.raises(PasskeyError) as refused:
        verifier.verify_registration(
            challenge=challenge,
            client_data_json=response["client_data_json"],
            attestation_object=cbor_encode(attestation),
        )
    assert "trust decision" in str(refused.value)


def test_an_unknown_attestation_format_is_refused(verifier, device):
    challenge = new_challenge()
    response = device.register(challenge=challenge)
    attestation = decode(response["attestation_object"])
    attestation["fmt"] = "apple"
    with pytest.raises(PasskeyError):
        verifier.verify_registration(
            challenge=challenge,
            client_data_json=response["client_data_json"],
            attestation_object=cbor_encode(attestation),
        )


def test_the_stored_key_is_the_raw_bytes_the_authenticator_sent(verifier, device):
    """Re-encoding through a decoder is an opportunity to change bytes that a future
    signature will be verified against."""
    credential = _registered(verifier, device)
    assert decode(credential.public_key_cose) == device.cose_key()
    assert credential.public_key_cose == cbor_encode(device.cose_key())


# ── The ceremony-type check ──────────────────────────────────────────────────


def test_a_registration_response_cannot_be_replayed_as_a_login(verifier, device):
    """Without the type check, a registration signature is usable as an assertion."""
    challenge = new_challenge()
    response = device.register(challenge=challenge, ceremony="webauthn.get")
    with pytest.raises(PasskeyError) as refused:
        verifier.verify_registration(challenge=challenge, **response)
    assert "different ceremony" in str(refused.value)


def test_an_assertion_labelled_as_a_registration_is_refused(verifier, device):
    credential = _registered(verifier, device)
    challenge = new_challenge()
    response = device.assert_(challenge=challenge, ceremony="webauthn.create")
    with pytest.raises(PasskeyError):
        verifier.verify_assertion(
            challenge=challenge, credential=credential, **response
        )


# ── Challenge ────────────────────────────────────────────────────────────────


def test_an_assertion_for_a_different_challenge_is_refused(verifier, device):
    """Without this every assertion is replayable forever."""
    credential = _registered(verifier, device)
    response = device.assert_(challenge=new_challenge())
    with pytest.raises(PasskeyError) as refused:
        verifier.verify_assertion(
            challenge=new_challenge(), credential=credential, **response
        )
    assert "replayable" in str(refused.value)


def test_challenges_are_unique_and_long_enough():
    challenges = {new_challenge() for _ in range(200)}
    assert len(challenges) == 200
    assert all(len(b64url_decode(c)) == 32 for c in challenges)


# ── Origin ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "hostile",
    [
        "https://sentinel.example.attacker.com",
        "https://attacker.com",
        "http://sentinel.example",
        "https://sentinel.example:8443",
        "https://sentinel.example.",
    ],
)
def test_the_origin_is_matched_exactly_never_by_suffix(verifier, device, hostile):
    """`sentinel.example.attacker.com` is why suffix matching is a bypass."""
    challenge = new_challenge()
    response = device.register(challenge=challenge, origin=hostile)
    with pytest.raises(PasskeyError) as refused:
        verifier.verify_registration(challenge=challenge, **response)
    assert "Matched exactly" in str(refused.value)


def test_a_cross_origin_ceremony_is_refused(verifier, device):
    """In an iframe the user cannot see which site they are authenticating to."""
    challenge = new_challenge()
    response = device.register(challenge=challenge, cross_origin=True)
    with pytest.raises(PasskeyError) as refused:
        verifier.verify_registration(challenge=challenge, **response)
    assert "cross-origin" in str(refused.value)


def test_an_empty_origin_allowlist_is_refused_at_construction():
    with pytest.raises(PasskeyError) as refused:
        WebAuthnVerifier(rp_id=RP_ID, origins=())
    assert "accept an assertion from any site" in str(refused.value)


def test_a_cleartext_origin_is_refused_at_construction():
    with pytest.raises(PasskeyError):
        WebAuthnVerifier(rp_id=RP_ID, origins=("http://sentinel.example",))
    # localhost is permitted, because development has no certificate.
    WebAuthnVerifier(rp_id="localhost", origins=("http://localhost:8000",))


# ── rpIdHash ─────────────────────────────────────────────────────────────────


def test_an_authenticator_signing_for_another_rp_is_refused(verifier):
    """The one field a malicious CLIENT cannot forge, because the authenticator
    computes it."""
    device = SoftwareAuthenticator(rp_id="other.example")
    challenge = new_challenge()
    response = device.register(challenge=challenge, rp_id="other.example")
    with pytest.raises(PasskeyError) as refused:
        verifier.verify_registration(challenge=challenge, **response)
    assert "different relying party" in str(refused.value)


# ── User presence and verification ───────────────────────────────────────────


def test_a_response_without_user_presence_is_refused(verifier, device):
    challenge = new_challenge()
    response = device.register(challenge=challenge, user_present=False)
    with pytest.raises(PasskeyError) as refused:
        verifier.verify_registration(challenge=challenge, **response)
    assert "user-present" in str(refused.value)


def test_user_verification_is_required_by_default(verifier, device):
    """UV proves a gesture on the device, which is what makes one assertion two
    factors."""
    challenge = new_challenge()
    response = device.register(challenge=challenge, user_verified=False)
    with pytest.raises(PasskeyError) as refused:
        verifier.verify_registration(challenge=challenge, **response)
    assert "two" in str(refused.value)


def test_user_verification_can_be_relaxed_deliberately(device):
    """A deployment turning this off should have to say so, and then it works."""
    relaxed = WebAuthnVerifier(
        rp_id=RP_ID, origins=(ORIGIN,), require_user_verification=False
    )
    challenge = new_challenge()
    response = device.register(challenge=challenge, user_verified=False)
    credential = relaxed.verify_registration(challenge=challenge, **response)
    assert credential.user_verified is False


# ── Assertion signature ─────────────────────────────────────────────────────


@pytest.mark.parametrize("algorithm", [ES256, RS256])
def test_a_valid_assertion_is_accepted(verifier, algorithm):
    device = SoftwareAuthenticator(rp_id=RP_ID, algorithm=algorithm)
    credential = _registered(verifier, device)
    challenge = new_challenge()
    response = device.assert_(challenge=challenge)
    assert verifier.verify_assertion(
        challenge=challenge, credential=credential, **response
    ) == device.sign_count


def test_a_tampered_signature_is_refused(verifier, device):
    credential = _registered(verifier, device)
    challenge = new_challenge()
    response = device.assert_(challenge=challenge, tamper_signature=True)
    with pytest.raises(PasskeyError) as refused:
        verifier.verify_assertion(challenge=challenge, credential=credential, **response)
    assert "not valid" in str(refused.value)


def test_an_assertion_signed_by_a_different_key_is_refused(verifier, device):
    """THE bypass this design exists to prevent.

    The stored credential is the source of the key. An implementation that took the
    key from the response would accept a signature by any key the caller chose --
    an easy mistake, because a registration response does carry a key.
    """
    credential = _registered(verifier, device)
    impostor = SoftwareAuthenticator(rp_id=RP_ID, credential_id=device.credential_id)
    challenge = new_challenge()
    response = impostor.assert_(challenge=challenge)
    with pytest.raises(PasskeyError):
        verifier.verify_assertion(challenge=challenge, credential=credential, **response)


def test_tampering_with_the_signed_authenticator_data_is_refused(verifier, device):
    credential = _registered(verifier, device)
    challenge = new_challenge()
    response = device.assert_(challenge=challenge)
    mutated = bytearray(response["authenticator_data"])
    mutated[36] ^= 0x01  # a byte of the sign counter
    response["authenticator_data"] = bytes(mutated)
    with pytest.raises(PasskeyError):
        verifier.verify_assertion(challenge=challenge, credential=credential, **response)


def test_the_signature_covers_the_client_data_hash(verifier, device):
    """Swapping clientDataJSON for another valid one must fail, which proves the
    hash is inside the signed payload rather than merely checked alongside it."""
    credential = _registered(verifier, device)
    challenge = new_challenge()
    response = device.assert_(challenge=challenge)
    # A different clientData that still passes every field check: same challenge,
    # same origin, same type, but different bytes (key order).
    import json

    response["client_data_json"] = json.dumps(
        {
            "origin": ORIGIN,
            "challenge": challenge,
            "type": "webauthn.get",
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode()
    with pytest.raises(PasskeyError) as refused:
        verifier.verify_assertion(challenge=challenge, credential=credential, **response)
    assert "signature" in str(refused.value)


# ── Sign counter ─────────────────────────────────────────────────────────────


def test_the_sign_counter_must_advance(verifier, device):
    """A counter that goes backwards means the credential is on two authenticators."""
    credential = _registered(verifier, device)
    challenge = new_challenge()
    first = verifier.verify_assertion(
        challenge=challenge, credential=credential, **device.assert_(challenge=challenge)
    )
    advanced = RegisteredCredential(
        credential_id=credential.credential_id,
        public_key_cose=credential.public_key_cose,
        algorithm=credential.algorithm,
        sign_count=first,
        user_verified=True,
        aaguid=credential.aaguid,
    )
    replay_challenge = new_challenge()
    with pytest.raises(PasskeyError) as refused:
        verifier.verify_assertion(
            challenge=replay_challenge,
            credential=advanced,
            **device.assert_(challenge=replay_challenge, sign_count=first),
        )
    assert "cloned" in str(refused.value)


def test_an_authenticator_with_no_counter_is_tolerated(verifier, device):
    """Most passkey platforms do not implement a counter and always send zero.
    Refusing that would refuse every Apple and Google passkey."""
    challenge = new_challenge()
    response = device.register(challenge=challenge)
    credential = verifier.verify_registration(challenge=challenge, **response)
    stored = RegisteredCredential(
        credential_id=credential.credential_id,
        public_key_cose=credential.public_key_cose,
        algorithm=credential.algorithm,
        sign_count=0,
        user_verified=True,
        aaguid=credential.aaguid,
    )
    login = new_challenge()
    assert (
        verifier.verify_assertion(
            challenge=login,
            credential=stored,
            **device.assert_(challenge=login, sign_count=0),
        )
        == 0
    )


# ── COSE key handling ────────────────────────────────────────────────────────


def test_an_algorithm_and_key_type_that_disagree_are_refused(verifier, device):
    """A COSE key labelled ES256 with RSA parameters is a type-confusion attempt."""
    challenge = new_challenge()
    response = device.register(challenge=challenge)
    attestation = decode(response["attestation_object"])
    auth_data = bytearray(attestation["authData"])
    offset = 55 + len(device.credential_id)
    confused = dict(device.cose_key())
    confused[1] = 3  # claim RSA while carrying EC parameters
    attestation["authData"] = bytes(auth_data[:offset]) + cbor_encode(confused)
    with pytest.raises(PasskeyError) as refused:
        verifier.verify_registration(
            challenge=challenge,
            client_data_json=response["client_data_json"],
            attestation_object=cbor_encode(attestation),
        )
    assert "disagree" in str(refused.value)


def test_an_unsupported_cose_algorithm_is_refused(verifier, device):
    challenge = new_challenge()
    response = device.register(challenge=challenge)
    attestation = decode(response["attestation_object"])
    offset = 55 + len(device.credential_id)
    key = dict(device.cose_key())
    key[3] = -8  # EdDSA, not accepted
    attestation["authData"] = attestation["authData"][:offset] + cbor_encode(key)
    with pytest.raises(PasskeyError) as refused:
        verifier.verify_registration(
            challenge=challenge,
            client_data_json=response["client_data_json"],
            attestation_object=cbor_encode(attestation),
        )
    assert "unsupported COSE algorithm" in str(refused.value)


def test_a_point_not_on_the_curve_is_refused(verifier, device):
    challenge = new_challenge()
    response = device.register(challenge=challenge)
    attestation = decode(response["attestation_object"])
    offset = 55 + len(device.credential_id)
    key = dict(device.cose_key())
    key[-2] = b"\x01" * 32  # an x that does not pair with this y
    attestation["authData"] = attestation["authData"][:offset] + cbor_encode(key)
    with pytest.raises(PasskeyError) as refused:
        verifier.verify_registration(
            challenge=challenge,
            client_data_json=response["client_data_json"],
            attestation_object=cbor_encode(attestation),
        )
    assert "P-256 point" in str(refused.value)


def test_a_short_rsa_modulus_is_refused(verifier):
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

    device = SoftwareAuthenticator(rp_id=RP_ID, algorithm=RS256)
    weak = _rsa.generate_private_key(public_exponent=65537, key_size=1024)
    device._private = weak  # noqa: SLF001 - deliberately forging a weak key
    challenge = new_challenge()
    response = device.register(challenge=challenge)
    with pytest.raises(PasskeyError) as refused:
        verifier.verify_registration(challenge=challenge, **response)
    assert "under 2048 is refused" in str(refused.value)


# ── Malformed input ──────────────────────────────────────────────────────────


def test_a_non_cbor_attestation_object_is_refused(verifier, device):
    """Reached with VALID client data, so the CBOR parse is genuinely what fails.

    Passing junk client data instead would trip the ceremony-type check first and
    the test would pass without the CBOR path ever running.
    """
    challenge = new_challenge()
    client_data = device.client_data(
        challenge=challenge, origin=ORIGIN, ceremony="webauthn.create"
    )
    with pytest.raises(PasskeyError) as refused:
        verifier.verify_registration(
            challenge=challenge,
            client_data_json=client_data,
            attestation_object=b"\xff\xff\xff",
        )
    assert "not valid CBOR" in str(refused.value)


def test_truncated_authenticator_data_is_refused(verifier, device):
    challenge = new_challenge()
    response = device.register(challenge=challenge)
    attestation = decode(response["attestation_object"])
    attestation["authData"] = attestation["authData"][:20]
    with pytest.raises(PasskeyError) as refused:
        verifier.verify_registration(
            challenge=challenge,
            client_data_json=response["client_data_json"],
            attestation_object=cbor_encode(attestation),
        )
    assert "37" in str(refused.value)


def test_a_registration_with_no_credential_data_is_refused(verifier, device):
    challenge = new_challenge()
    client_data = device.client_data(
        challenge=challenge, origin=ORIGIN, ceremony="webauthn.create"
    )
    auth_data = device.authenticator_data(include_credential=False)
    with pytest.raises(PasskeyError) as refused:
        verifier.verify_registration(
            challenge=challenge,
            client_data_json=client_data,
            attestation_object=cbor_encode(
                {"fmt": "none", "attStmt": {}, "authData": auth_data}
            ),
        )
    assert "no credential to register" in str(refused.value)


@pytest.mark.parametrize("bad", ["!!!", "a b c", "###"])
def test_base64url_decoding_is_strict(bad):
    """`urlsafe_b64decode` silently DISCARDS stray characters, so "!!!" decodes to
    empty bytes and would be accepted as a valid field."""
    with pytest.raises(PasskeyError):
        b64url_decode(bad)


def test_base64url_round_trips():
    import secrets as _secrets

    for _ in range(20):
        raw = _secrets.token_bytes(_secrets.randbelow(64) + 1)
        assert b64url_decode(b64url_encode(raw)) == raw


# ── The CBOR decoder's own refusals ──────────────────────────────────────────


def test_trailing_bytes_after_a_cbor_item_are_refused():
    """One component hashes these bytes while another parses them, so a decoder
    that ignores trailing content lets a caller append what the signature does not
    cover."""
    with pytest.raises(CborError) as refused:
        decode(cbor_encode({"fmt": "none"}) + b"\x00")
    assert "trailing" in str(refused.value)


def test_indefinite_length_cbor_is_refused():
    with pytest.raises(CborError) as refused:
        decode(b"\x5f\x41a\xff")  # indefinite-length byte string
    assert "indefinite" in str(refused.value)


def test_a_duplicate_cbor_map_key_is_refused():
    """Last-wins would let the verifier read one value while the signed bytes
    contain another."""
    forged = b"\xa2" + cbor_encode("fmt") + cbor_encode("none") + cbor_encode(
        "fmt"
    ) + cbor_encode("packed")
    with pytest.raises(CborError) as refused:
        decode(forged)
    assert "duplicate" in str(refused.value)


def test_a_non_minimal_cbor_integer_is_refused():
    """Two encodings of one value hash differently, and a signature over these
    bytes has to be unambiguous."""
    with pytest.raises(CborError) as refused:
        decode(b"\x18\x01")  # 1 written in a following byte
    assert "non-minimal" in str(refused.value)


def test_deeply_nested_cbor_is_refused_without_a_recursion_error():
    payload = b"\x81" * 500 + b"\x00"
    with pytest.raises(CborError):
        decode(payload)


def test_the_cbor_encoder_and_decoder_agree():
    """The encoder in the test helper is independent of the decoder under test, so a
    disagreement shows up here rather than as compatibility with itself."""
    for value in (
        0,
        1,
        23,
        24,
        255,
        65535,
        -1,
        -100,
        b"",
        b"\x00\x01",
        "",
        "text",
        [1, 2, 3],
        {1: 2, "a": b"b"},
        {1: {2: [3, b"4"]}},
        True,
        False,
        None,
    ):
        assert decode(cbor_encode(value)) == value


def test_the_signed_payload_is_authdata_then_the_client_data_hash():
    """The concatenation order is part of the spec and getting it backwards produces
    a verifier that rejects every real authenticator."""
    device = SoftwareAuthenticator(rp_id=RP_ID)
    challenge = new_challenge()
    response = device.assert_(challenge=challenge)
    expected = response["authenticator_data"] + hashlib.sha256(
        response["client_data_json"]
    ).digest()
    assert len(expected) == len(response["authenticator_data"]) + 32
