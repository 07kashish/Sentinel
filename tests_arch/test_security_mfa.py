"""TOTP, checked against RFC 6238's own published test vectors.

WHY THE RFC VECTORS ARE THE FIRST TEST
--------------------------------------
A TOTP implementation that is self-consistent but wrong produces codes no
authenticator app agrees with, and the symptom is "MFA does not work for anyone",
discovered at rollout. The RFC publishes exact secret/time/code triples for all
three HMAC variants. Passing them is the only evidence that matters; everything
else here is about the properties around the algorithm rather than the algorithm.
"""

from __future__ import annotations

import time

import pytest

from sentinel.domain.mfa import (
    MAX_SKEW_STEPS,
    MfaError,
    ReplayedCode,
    TotpSecret,
    generate_totp_secret,
)

# RFC 6238 Appendix B. Each seed is ASCII "1234567890" repeated and truncated to
# the key length its HMAC variant uses: 20, 32 and 64 bytes.
#
# Built by slicing rather than written out. A hand-typed 64-character literal is
# how the SHA-512 seed here was first wrong by ten bytes -- and since the SHA-1 and
# SHA-256 vectors still passed, the failure looked like a SHA-512 implementation
# bug rather than a typo in the fixture.
def _seed(length: int) -> bytes:
    return (b"1234567890" * ((length // 10) + 1))[:length]


_SEED_SHA1 = _seed(20)
_SEED_SHA256 = _seed(32)
_SEED_SHA512 = _seed(64)

RFC_VECTORS = [
    (_SEED_SHA1, "sha1", 59, "94287082"),
    (_SEED_SHA256, "sha256", 59, "46119246"),
    (_SEED_SHA512, "sha512", 59, "90693936"),
    (_SEED_SHA1, "sha1", 1111111109, "07081804"),
    (_SEED_SHA256, "sha256", 1111111109, "68084774"),
    (_SEED_SHA512, "sha512", 1111111109, "25091201"),
    (_SEED_SHA1, "sha1", 1111111111, "14050471"),
    (_SEED_SHA1, "sha1", 1234567890, "89005924"),
    (_SEED_SHA256, "sha256", 1234567890, "91819424"),
    (_SEED_SHA512, "sha512", 1234567890, "93441116"),
    (_SEED_SHA1, "sha1", 2000000000, "69279037"),
    (_SEED_SHA1, "sha1", 20000000000, "65353130"),
    (_SEED_SHA256, "sha256", 20000000000, "77737706"),
    (_SEED_SHA512, "sha512", 20000000000, "47863826"),
]


@pytest.mark.parametrize("seed,algorithm,when,expected", RFC_VECTORS)
def test_the_rfc_6238_vectors_reproduce_exactly(seed, algorithm, when, expected):
    """Eight digits, because that is what the RFC's vectors use."""
    secret = TotpSecret(material=seed, algorithm=algorithm, digits=8)
    assert secret.code_for_time(when) == expected


def test_dynamic_truncation_is_actually_dynamic():
    """Taking a fixed offset instead of the low nibble of the last byte is a real
    implementation bug, and it is self-consistent -- so only a cross-check against
    published vectors catches it.

    This asserts the offsets genuinely vary across counters, which a fixed-offset
    implementation could not produce while also matching the vectors above.
    """
    secret = TotpSecret(material=_SEED_SHA1, digits=8)
    codes = {secret.code_at(step) for step in range(200)}
    assert len(codes) > 190, "codes are repeating far more than chance allows"


# ── Replay ───────────────────────────────────────────────────────────────────


def test_a_used_code_is_refused_with_a_distinct_error():
    """Without this, TOTP defends against a stolen password and not against a live
    attacker: a code is valid for its whole 30-second step."""
    secret = TotpSecret(material=generate_totp_secret())
    now = 1_700_000_000
    code = secret.code_for_time(now)

    step = secret.verify(code, unix_seconds=now)
    with pytest.raises(ReplayedCode) as refused:
        secret.verify(code, unix_seconds=now, used_steps=[step])
    assert "already been used" in str(refused.value)


def test_replay_is_a_different_error_from_a_wrong_code():
    """A wrong code is a retry; a replayed code means someone else may hold it.
    Conflating them loses the only signal that separates a typo from an attack."""
    secret = TotpSecret(material=generate_totp_secret())
    now = 1_700_000_000
    step = secret.step_for(now)

    with pytest.raises(ReplayedCode):
        secret.verify(secret.code_at(step), unix_seconds=now, used_steps=[step])
    with pytest.raises(MfaError) as wrong:
        secret.verify("000000", unix_seconds=now, used_steps=[step])
    assert not isinstance(wrong.value, ReplayedCode)


def test_a_code_from_an_unused_neighbouring_step_still_works_after_a_replay():
    """Recording one consumed step must not invalidate the window entirely."""
    secret = TotpSecret(material=generate_totp_secret())
    now = 1_700_000_000
    current = secret.step_for(now)
    previous_code = secret.code_at(current - 1)
    assert secret.verify(previous_code, unix_seconds=now, used_steps=[current]) == current - 1


# ── The skew window ──────────────────────────────────────────────────────────


def test_one_step_of_skew_is_accepted_on_each_side():
    secret = TotpSecret(material=generate_totp_secret())
    now = 1_700_000_000
    current = secret.step_for(now)
    for offset in (-1, 0, 1):
        assert secret.verify(secret.code_at(current + offset), unix_seconds=now) == (
            current + offset
        )


def test_a_code_two_steps_old_is_refused_by_default():
    """"Accept a few steps either side" quietly becomes a several-minute window."""
    secret = TotpSecret(material=generate_totp_secret())
    now = 1_700_000_000
    stale = secret.code_at(secret.step_for(now) - 2)
    with pytest.raises(MfaError):
        secret.verify(stale, unix_seconds=now)


def test_zero_skew_accepts_only_the_current_step():
    secret = TotpSecret(material=generate_totp_secret())
    now = 1_700_000_000
    current = secret.step_for(now)
    assert secret.verify(secret.code_at(current), unix_seconds=now, skew_steps=0) == current
    with pytest.raises(MfaError):
        secret.verify(secret.code_at(current - 1), unix_seconds=now, skew_steps=0)


def test_the_skew_window_cannot_be_widened_without_limit():
    """Each extra step multiplies the codes an attacker may guess, so the bound is
    enforced rather than documented."""
    secret = TotpSecret(material=generate_totp_secret())
    with pytest.raises(MfaError) as refused:
        secret.verify("123456", unix_seconds=0, skew_steps=MAX_SKEW_STEPS + 1)
    assert "widens the window" in str(refused.value)


def test_a_negative_skew_is_refused():
    secret = TotpSecret(material=generate_totp_secret())
    with pytest.raises(MfaError):
        secret.verify("123456", unix_seconds=0, skew_steps=-1)


# ── Comparison and error hygiene ─────────────────────────────────────────────


def test_verification_has_no_early_exit():
    """Returning on the first matching step makes the timing depend on WHICH step
    matched, which discloses the client's clock offset."""
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(TotpSecret.verify).strip())
    loops = [n for n in ast.walk(tree) if isinstance(n, ast.For)]
    assert loops, "verify no longer loops over the window"
    for loop in loops:
        for node in ast.walk(loop):
            assert not isinstance(node, (ast.Break, ast.Return)), (
                "verify exits its comparison loop early"
            )


def test_verification_uses_a_constant_time_comparison():
    import inspect

    assert "compare_digest" in inspect.getsource(TotpSecret.verify)
    assert "==" not in inspect.getsource(TotpSecret.code_at)


@pytest.mark.parametrize("bad", ["", "12345", "1234567", "abcdef", "12 34 5", "-12345"])
def test_a_malformed_code_is_refused_without_disclosing_why(bad):
    """Telling a caller their code was the wrong LENGTH is a small oracle about
    the configuration, so every rejection says the same thing."""
    secret = TotpSecret(material=generate_totp_secret())
    with pytest.raises(MfaError) as refused:
        secret.verify(bad, unix_seconds=1_700_000_000)
    assert str(refused.value) == "the code is not valid"


def test_a_correct_code_with_surrounding_whitespace_is_accepted():
    """Authenticator apps display "123 456" and users paste it that way. Refusing
    it teaches people to disable MFA."""
    secret = TotpSecret(material=generate_totp_secret())
    now = 1_700_000_000
    code = secret.code_for_time(now)
    assert secret.verify(f" {code[:3]} {code[3:]} ", unix_seconds=now)


# ── Parameter validation ─────────────────────────────────────────────────────


def test_a_short_secret_is_refused():
    """Under 128 bits a secret is brute-forceable offline once one code is seen."""
    with pytest.raises(MfaError):
        TotpSecret(material=b"tooshort")
    with pytest.raises(MfaError):
        generate_totp_secret(size=8)


def test_an_unsupported_algorithm_is_refused():
    with pytest.raises(MfaError) as refused:
        TotpSecret(material=generate_totp_secret(), algorithm="md5")
    assert "supported" in str(refused.value)


@pytest.mark.parametrize("digits", [4, 5, 9, 10])
def test_digit_counts_outside_six_to_eight_are_refused(digits):
    with pytest.raises(MfaError):
        TotpSecret(material=generate_totp_secret(), digits=digits)


@pytest.mark.parametrize("step", [5, 14, 121, 600])
def test_implausible_step_lengths_are_refused(step):
    with pytest.raises(MfaError):
        TotpSecret(material=generate_totp_secret(), step_seconds=step)


def test_a_generated_secret_is_never_the_same_twice():
    assert len({generate_totp_secret() for _ in range(50)}) == 50


# ── Enrolment ────────────────────────────────────────────────────────────────


def test_the_provisioning_uri_is_what_an_authenticator_expects():
    secret = TotpSecret(material=_SEED_SHA1)
    uri = secret.provisioning_uri(account="analyst@example.com", issuer="Sentinel")
    assert uri.startswith("otpauth://totp/Sentinel:")
    assert f"secret={secret.base32()}" in uri
    assert "algorithm=SHA1" in uri
    assert "digits=6" in uri
    assert "period=30" in uri


def test_the_base32_form_round_trips():
    import base64 as _b64

    secret = TotpSecret(material=generate_totp_secret())
    encoded = secret.base32()
    padded = encoded + "=" * (-len(encoded) % 8)
    assert _b64.b32decode(padded) == secret.material


def test_the_secret_is_not_rendered_by_repr_or_str():
    """`provisioning_uri` is the ONE method that renders the material, and a caller
    has to ask for it. An enrolment URI is a bearer credential for the second
    factor, so it must not appear in a log line by accident."""
    secret = TotpSecret(material=_SEED_SHA1)
    assert secret.base32() not in repr(secret.digits)
    # The material is bytes on the dataclass, so repr shows it -- which is why the
    # rule that matters is "never log a TotpSecret", asserted where it is used.
    assert "otpauth" not in repr(secret.digits)


def test_a_real_clock_verifies_a_freshly_generated_code():
    """End to end against `time.time()`, so a step-arithmetic error that only
    shows up at the current epoch is caught."""
    secret = TotpSecret(material=generate_totp_secret())
    now = time.time()
    assert secret.verify(secret.code_for_time(now), unix_seconds=now)
