"""TOTP second factor. RFC 6238, verified against the RFC's own vectors.

WHY THIS IS IN THE DOMAIN
-------------------------
A one-time code is a pure function of a shared secret and a time step. There is no
I/O, no storage and no framework in it, so it belongs where it can be tested
exhaustively and reasoned about without a database.

THE THREE THINGS IMPLEMENTATIONS GET WRONG
------------------------------------------
1. **No replay defence.** A TOTP code is valid for its whole step -- typically 30
   seconds -- so an attacker who observes one (shoulder-surfing, a phishing proxy,
   a logged request body) can use it until the step rolls. `verify` therefore
   returns the time step it matched, and the caller is REQUIRED to record it:
   `ReplayedCode` is raised when a step is reused. Without this, TOTP defends
   against a stolen password and not against a live attacker.

2. **Comparison that leaks.** `==` on the digits is not constant time. The
   comparison here is `hmac.compare_digest`, and it runs over every candidate step
   with no early exit, so the timing does not reveal WHICH step matched -- which
   would otherwise disclose the client's clock offset.

3. **An unbounded window.** "Accept a few steps either side" quietly becomes a
   several-minute validity window, and each extra step multiplies the codes an
   attacker can guess. One step of skew each way is the RFC's own suggestion and is
   the default here; the window is a parameter so a deployment can tighten it, and
   it is validated so it cannot be widened without limit.

WHY SHA-1 IS THE DEFAULT
------------------------
Not because SHA-1 is a good hash. Because HMAC-SHA1 is what every authenticator app
implements, and an MFA implementation nobody can enrol into is an MFA implementation
nobody uses. HMAC does not depend on collision resistance, so HMAC-SHA1 is not
broken by the SHA-1 collision work. SHA-256 and SHA-512 are supported for a
deployment whose authenticators handle them.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from sentinel.domain.errors import DomainRuleViolated

__all__ = [
    "DEFAULT_DIGITS",
    "DEFAULT_STEP_SECONDS",
    "MfaError",
    "ReplayedCode",
    "TotpSecret",
    "generate_totp_secret",
]

DEFAULT_STEP_SECONDS = 30
DEFAULT_DIGITS = 6
#: Steps of clock skew tolerated on each side. One is the RFC's suggestion.
#:
#: Each extra step widens the validity window by 30 seconds AND multiplies the
#: codes an attacker may guess, so this is capped rather than merely defaulted.
DEFAULT_SKEW_STEPS = 1
MAX_SKEW_STEPS = 3
#: 160 bits, matching HMAC-SHA1's block-independent key size and every app's QR
#: expectations. Below 128 bits a secret is brute-forceable offline once observed.
SECRET_BYTES = 20
#: Immutable. A mutable algorithm table is a downgrade attack any imported module
#: can perform at runtime by rebinding one entry -- and the result would still
#: verify against itself, so nothing would look wrong.
_SUPPORTED: Mapping[str, Any] = MappingProxyType(
    {"sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha512": hashlib.sha512}
)


class MfaError(DomainRuleViolated):
    """A second factor could not be established or verified."""


class ReplayedCode(MfaError):
    """This time step has already been used. The code is correct and refused.

    A distinct type because the response differs: a wrong code is a retry, a
    replayed code means someone else may be holding it, and conflating them loses
    the only signal that distinguishes a typo from an attack.
    """


def generate_totp_secret(*, size: int = SECRET_BYTES) -> bytes:
    """A fresh secret from the CSPRNG. Never derived from a password or an id."""
    if size < 16:
        raise MfaError(
            f"a TOTP secret of {size} bytes is under 128 bits and is brute-forceable "
            "offline once a single code is observed"
        )
    return secrets.token_bytes(size)


@dataclass(frozen=True, slots=True)
class TotpSecret:
    """One enrolled authenticator.

    Frozen and slotted, and it does not implement `__str__` to render its own
    material -- the base32 form is available only from `provisioning_uri`, which a
    caller has to ask for explicitly at enrolment time.
    """

    material: bytes
    algorithm: str = "sha1"
    digits: int = DEFAULT_DIGITS
    step_seconds: int = DEFAULT_STEP_SECONDS

    def __post_init__(self) -> None:
        if len(self.material) < 16:
            raise MfaError("a TOTP secret must be at least 128 bits")
        if self.algorithm not in _SUPPORTED:
            raise MfaError(
                f"unsupported TOTP algorithm {self.algorithm!r}; "
                f"supported: {', '.join(sorted(_SUPPORTED))}"
            )
        if not 6 <= self.digits <= 8:
            # Six is universal, eight is the RFC's maximum. Fewer than six is
            # guessable inside one step at any plausible rate limit.
            raise MfaError(f"TOTP digits must be 6-8, got {self.digits}")
        if self.step_seconds < 15 or self.step_seconds > 120:
            raise MfaError(
                f"TOTP step must be 15-120 seconds, got {self.step_seconds}. A very "
                "short step breaks on ordinary clock skew; a long one widens the "
                "window an observed code stays valid for."
            )

    # ── Code generation ──────────────────────────────────────────────────────

    def code_at(self, step: int) -> str:
        """The code for a counter value. RFC 4226 dynamic truncation."""
        digest = hmac.new(
            self.material, struct.pack(">Q", step), _SUPPORTED[self.algorithm]
        ).digest()
        # The low nibble of the last byte selects the 4-byte window. This is the
        # dynamic-truncation step, and taking a fixed offset instead is a real
        # implementation bug that produces codes no authenticator agrees with.
        offset = digest[-1] & 0x0F
        truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFF_FFFF
        return str(truncated % (10**self.digits)).zfill(self.digits)

    def step_for(self, unix_seconds: float) -> int:
        return int(unix_seconds) // self.step_seconds

    def code_for_time(self, unix_seconds: float) -> str:
        return self.code_at(self.step_for(unix_seconds))

    # ── Verification ─────────────────────────────────────────────────────────

    def verify(
        self,
        presented: str,
        *,
        unix_seconds: float,
        skew_steps: int = DEFAULT_SKEW_STEPS,
        used_steps: Iterable[int] = (),
    ) -> int:
        """Return the time step that matched. Raises `MfaError` if none does.

        `used_steps` is REQUIRED to be supplied by any caller that cares about
        replay -- which is every caller. A code is valid for its whole step, so
        without a record of consumed steps an observed code can be used again
        until the step rolls. Passing the steps in rather than storing them here
        keeps this a pure function; the storage is the caller's, because only the
        caller knows the scope replay must be prevented across.
        """
        if not 0 <= skew_steps <= MAX_SKEW_STEPS:
            raise MfaError(
                f"skew of {skew_steps} steps is outside 0-{MAX_SKEW_STEPS}. Each "
                "extra step widens the window an observed code stays valid for and "
                "multiplies the codes an attacker may guess."
            )
        cleaned = presented.strip().replace(" ", "")
        if len(cleaned) != self.digits or not cleaned.isdigit():
            # Shape checked before any HMAC, so a malformed input costs nothing.
            # Deliberately the same error as a wrong code: telling a caller their
            # code was the wrong LENGTH is a small oracle about the configuration.
            raise MfaError("the code is not valid")

        current = self.step_for(unix_seconds)
        consumed = set(used_steps)
        matched: int | None = None
        replayed = False
        # No early exit: returning on the first match makes the timing depend on
        # which step matched, disclosing the client's clock offset.
        for candidate in range(current - skew_steps, current + skew_steps + 1):
            if hmac.compare_digest(cleaned, self.code_at(candidate)):
                if candidate in consumed:
                    replayed = True
                else:
                    matched = candidate
        if replayed and matched is None:
            raise ReplayedCode(
                "this one-time code has already been used. A TOTP code is valid "
                "for its whole time step, so reuse is refused -- if you did not "
                "just authenticate, someone else has your code."
            )
        if matched is None:
            raise MfaError("the code is not valid")
        return matched

    # ── Enrolment ────────────────────────────────────────────────────────────

    def base32(self) -> str:
        """The base32 form an authenticator expects, unpadded."""
        return base64.b32encode(self.material).decode("ascii").rstrip("=")

    def provisioning_uri(self, *, account: str, issuer: str) -> str:
        """An `otpauth://` URI for enrolment.

        Contains the secret, so this is the one method that renders it and a caller
        has to ask for it deliberately. It must never be logged, stored, or
        returned twice -- an enrolment URI is a bearer credential for the second
        factor.
        """
        from urllib.parse import quote

        label = f"{quote(issuer)}:{quote(account)}"
        return (
            f"otpauth://totp/{label}?secret={self.base32()}"
            f"&issuer={quote(issuer)}&algorithm={self.algorithm.upper()}"
            f"&digits={self.digits}&period={self.step_seconds}"
        )
