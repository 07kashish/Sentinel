"""OIDC / JWT access-token verification.

FAIL CLOSED
-----------
- Rejects `alg=none`, HMAC, and unknown algorithms. Only RS256/ES256.
- Tenant claim is REQUIRED. Never substitutes ``"default"`` (council H-2).
- Issuer and audience must match configured values when set.
- Expired / not-yet-valid tokens are refused.

This is a verification library, not a full IdP or SCIM product. Wire it from
HTTP auth when OIDC settings are present; API keys remain the primary path.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from sentinel.domain.errors import DomainRuleViolated

__all__ = ["OidcClaims", "OidcError", "OidcVerifier", "b64url_decode"]

_ALLOWED_ALGS = frozenset({"RS256", "ES256"})

#: Tolerated clock difference between the issuer and this process. Issuers
#: run on other hosts; a Kubernetes API server four seconds ahead of the
#: verifier minted tokens whose `nbf` was in the future and every one was
#: refused as "not yet valid" (found 2026-09-25). Sixty seconds is the
#: conventional allowance; it does not extend a token's life meaningfully.
CLOCK_SKEW_SECONDS = 60.0


class OidcError(DomainRuleViolated):
    """Token verification failed. Always treated as authentication failure."""

    is_retryable = False


@dataclass(frozen=True, slots=True)
class OidcClaims:
    subject: str
    tenant_id: str
    role: str
    issuer: str
    audience: str
    raw: Mapping[str, Any]


def b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def _int_from_b64(segment: str) -> int:
    return int.from_bytes(b64url_decode(segment), "big")


def _public_key_from_jwk(jwk: Mapping[str, Any]):
    kty = jwk.get("kty")
    if kty == "RSA":
        n = _int_from_b64(jwk["n"])
        e = _int_from_b64(jwk["e"])
        return rsa.RSAPublicNumbers(e, n).public_key()
    if kty == "EC" and jwk.get("crv") == "P-256":
        x = _int_from_b64(jwk["x"])
        y = _int_from_b64(jwk["y"])
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    raise OidcError(f"unsupported JWK kty/crv: {kty!r}/{jwk.get('crv')!r}")


def _verify_rs256(key, message: bytes, signature: bytes) -> None:
    key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())


def _verify_es256(key, message: bytes, signature: bytes) -> None:
    if len(signature) != 64:
        raise OidcError("ES256 signature must be 64 raw bytes")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    der = encode_dss_signature(r, s)
    key.verify(der, message, ec.ECDSA(hashes.SHA256()))


class OidcVerifier:
    """Verify compact JWTs against a static JWKS document."""

    __slots__ = (
        "_issuer", "_audience", "_tenant_claim", "_role_claim", "_keys",
        "_fixed_tenant", "_fixed_role",
    )

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks: Mapping[str, Any],
        tenant_claim: str = "tenant_id",
        role_claim: str = "role",
        fixed_tenant: str = "",
        fixed_role: str = "",
    ) -> None:
        """`fixed_tenant` / `fixed_role` bind the token to a REGISTRATION.

        A human IdP names the tenant and role in claims Sentinel configured.
        An AGENT identity provider -- Okta Agent SSO, Entra Agent ID -- knows
        nothing about Sentinel's tenants or roles: its token proves which agent
        is calling, and the operator who registered that issuer said which
        tenant it belongs to. So the tenant and role come from the registration
        and the claims are not consulted for them; a token could not promote
        itself to admin by carrying a `role` claim, because the claim is never
        read.
        """
        if not issuer or not audience:
            raise OidcError("OIDC issuer and audience are required")
        if not tenant_claim.strip():
            raise OidcError("OIDC tenant claim name is required")
        self._issuer = issuer
        self._audience = audience
        self._tenant_claim = tenant_claim
        self._role_claim = role_claim
        self._fixed_tenant = fixed_tenant.strip()
        self._fixed_role = fixed_role.strip()
        keys: dict[str, Any] = {}
        for jwk in jwks.get("keys") or ():
            kid = jwk.get("kid") or f"anon-{len(keys)}"
            keys[kid] = jwk
        if not keys:
            raise OidcError("JWKS contains no keys")
        self._keys = keys

    def knows(self, kid: str) -> bool:
        return bool(kid) and kid in self._keys

    def replace_keys(self, jwks: Mapping[str, Any]) -> int:
        """Swap the trusted key set for a freshly fetched one. Returns its size.

        Refuses an empty or oversized set and anything that is not an RSA or EC
        public key, so a broken or hostile JWKS response cannot leave the
        verifier trusting nothing, or trusting a symmetric key.
        """
        keys: dict[str, Any] = {}
        for jwk in (jwks.get("keys") or ()) if isinstance(jwks, Mapping) else ():
            if not isinstance(jwk, Mapping) or jwk.get("kty") not in {"RSA", "EC"} or "d" in jwk:
                continue
            keys[str(jwk.get("kid") or f"anon-{len(keys)}")] = jwk
        if not keys or len(keys) > 32:
            raise OidcError("fetched JWKS has no usable keys, or too many")
        self._keys = keys
        return len(keys)

    @classmethod
    def from_jwks_json(
        cls,
        *,
        issuer: str,
        audience: str,
        jwks_json: str,
        tenant_claim: str = "tenant_id",
        role_claim: str = "role",
    ) -> "OidcVerifier":
        try:
            jwks = json.loads(jwks_json)
        except json.JSONDecodeError as exc:
            raise OidcError("JWKS JSON is invalid") from exc
        if not isinstance(jwks, dict):
            raise OidcError("JWKS must be a JSON object")
        return cls(
            issuer=issuer,
            audience=audience,
            jwks=jwks,
            tenant_claim=tenant_claim,
            role_claim=role_claim,
        )

    def verify(self, token: str, *, now: float | None = None) -> OidcClaims:
        parts = token.split(".")
        if len(parts) != 3:
            raise OidcError("token is not a compact JWT")
        try:
            header = json.loads(b64url_decode(parts[0]))
            payload = json.loads(b64url_decode(parts[1]))
            signature = b64url_decode(parts[2])
        except (ValueError, json.JSONDecodeError) as exc:
            raise OidcError("token encoding is invalid") from exc

        alg = header.get("alg")
        if alg not in _ALLOWED_ALGS:
            raise OidcError(f"algorithm {alg!r} is not allowed")

        kid = header.get("kid")
        jwk = self._keys.get(kid) if kid else None
        if jwk is None and len(self._keys) == 1:
            jwk = next(iter(self._keys.values()))
        if jwk is None:
            raise OidcError("no matching JWKS key for token kid")

        message = f"{parts[0]}.{parts[1]}".encode("ascii")
        try:
            key = _public_key_from_jwk(jwk)
            if alg == "RS256":
                _verify_rs256(key, message, signature)
            else:
                _verify_es256(key, message, signature)
        except (InvalidSignature, KeyError, ValueError, TypeError) as exc:
            raise OidcError("token signature is invalid") from exc

        now_ts = time.time() if now is None else now
        if payload.get("iss") != self._issuer:
            raise OidcError("issuer mismatch")
        aud = payload.get("aud")
        audiences = aud if isinstance(aud, list) else [aud]
        if self._audience not in audiences:
            raise OidcError("audience mismatch")
        exp = payload.get("exp")
        if not isinstance(exp, (int, float)) or now_ts >= float(exp) + CLOCK_SKEW_SECONDS:
            raise OidcError("token expired or missing exp")
        nbf = payload.get("nbf")
        if nbf is not None and (
            not isinstance(nbf, (int, float)) or now_ts + CLOCK_SKEW_SECONDS < float(nbf)
        ):
            raise OidcError("token not yet valid")

        if self._fixed_tenant:
            tenant = self._fixed_tenant
        else:
            tenant = payload.get(self._tenant_claim)
            if not isinstance(tenant, str) or not tenant.strip():
                # THE load-bearing refusal: never invent a tenant.
                raise OidcError(
                    f"missing required tenant claim {self._tenant_claim!r}"
                )
            if tenant.strip().lower() in {"default", "unknown", "*"}:
                raise OidcError("tenant claim value is forbidden")

        if self._fixed_role:
            role = self._fixed_role
        else:
            role = payload.get(self._role_claim, "viewer")
            if not isinstance(role, str) or not role.strip():
                raise OidcError("role claim is invalid")
        sub = payload.get("sub")
        if not isinstance(sub, str) or not sub.strip():
            raise OidcError("missing sub")

        return OidcClaims(
            subject=sub,
            tenant_id=tenant.strip(),
            role=role.strip(),
            issuer=str(payload.get("iss")),
            audience=self._audience,
            raw=payload,
        )
