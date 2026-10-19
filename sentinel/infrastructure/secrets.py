"""Secret rotation, and a KMS adapter for the keys that matter.

WHY ROTATION IS A TYPE AND NOT A PROCEDURE
------------------------------------------
Before this, every secret was a single string read once from the environment. A
token disclosed on Tuesday stayed valid until a human noticed and edited a
deployment manifest. That is not a rotation policy; it is the absence of one.

The failure mode of a naive fix is worse than the problem. "Replace the value and
restart" means:

  * every request in flight with the old credential fails
  * every agent still holding the old key is locked out until it is redeployed
  * so operators avoid rotating, and the secret ages for years

So rotation here is **overlapping**. A secret has an ordered set of versions; the
newest is what gets ISSUED, and any non-retired version is ACCEPTED. Rotation is
therefore two independent decisions -- start issuing the new one, then stop
accepting the old one -- separated by however long the slowest client needs. Both
are recorded, so "when did we stop accepting v3" has an answer.

CONSTANT-TIME, AND OVER EVERY VERSION
-------------------------------------
`verify` compares against every accepted version with no early exit. Returning as
soon as a version matches makes the comparison time depend on WHICH version
matched, which leaks how recently a credential was rotated -- and that tells an
attacker holding an old key whether it is still worth trying.

THE KMS ADAPTER, AND WHAT "HSM" MEANS HERE
------------------------------------------
`KmsKeyProvider` satisfies the same `KeyProvider` port as `StaticKeyProvider`, so
the envelope cipher is unchanged: it asks for a KEK by id and gets bytes.

On HSM specifically, stated plainly rather than implied: **a cloud KMS IS the HSM
path.** AWS KMS, GCP Cloud KMS and Azure Key Vault Managed HSM all hold key
material in FIPS-validated hardware and expose it over an authenticated HTTPS API.
Writing a PKCS#11 adapter against a local appliance would be a second, larger
surface that this environment has no hardware to exercise -- and an unexercised
authentication path in a security product is worse than an absent one. This adapter
is the realistic HSM integration, and it goes through `HardenedHttpClient`, so the
SSRF and redirect defences apply to the key-fetch path too.

What is NOT claimed: no request from this adapter has reached a real KMS. The
signing, request shaping, caching and rotation logic are tested against a stub; the
round trip is not.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from sentinel.domain.errors import SentinelError
from sentinel.infrastructure.outbound import (
    HardenedHttpClient,
    OutboundRefused,
    OutboundUnavailable,
    inspect_url,
)
from sentinel.infrastructure.persistence.crypto import KEY_BYTES, CryptoError

__all__ = [
    "KmsKeyProvider",
    "RotatingSecret",
    "SecretVersion",
    "SecretsError",
]


class SecretsError(SentinelError):
    """A secret is missing, malformed, or every version of it has been retired."""

    is_retryable = False


@dataclass(frozen=True, slots=True)
class SecretVersion:
    """One version of a secret, and whether it may still be used.

    `issued` and `accepted` are separate on purpose. The window between "stop
    issuing" and "stop accepting" is the entire reason a rotation can happen
    without an outage, and collapsing them into one boolean removes it.
    """

    version: int
    #: SHA-256 of the material, never the material. A version object can be logged.
    digest: str
    #: May be handed to a new client.
    issued: bool = True
    #: May be presented by an existing client.
    accepted: bool = True

    def __str__(self) -> str:
        state = (
            "issuing+accepting"
            if self.issued and self.accepted
            else "accepting-only"
            if self.accepted
            else "retired"
        )
        return f"v{self.version} ({state}, {self.digest[:12]})"


@dataclass
class RotatingSecret:
    """A secret with overlapping versions.

    Holds material privately and exposes only digests, so the object itself is safe
    to include in a diagnostic response or a log record -- which matters, because
    the reason nobody rotates is usually that nobody can see the current state.
    """

    name: str
    _material: dict[int, bytes] = field(default_factory=dict, repr=False)
    _versions: dict[int, SecretVersion] = field(default_factory=dict)
    _history: list[str] = field(default_factory=list)

    @classmethod
    def from_values(cls, name: str, values: Sequence[str]) -> "RotatingSecret":
        """Build from ordered strings, oldest first. The last is the issuing version."""
        if not values:
            raise SecretsError(
                f"secret {name!r} has no versions. A secret with no versions is not "
                "an empty secret, it is a misconfiguration."
            )
        secret = cls(name=name)
        for index, value in enumerate(values, start=1):
            secret.add_version(index, value.encode("utf-8"))
        return secret

    def add_version(self, version: int, material: bytes) -> None:
        if version in self._material:
            raise SecretsError(f"{self.name} already has a version {version}")
        if not material:
            raise SecretsError(f"{self.name} v{version} is empty")
        self._material[version] = material
        digest = hashlib.sha256(material).hexdigest()
        for other, existing in self._versions.items():
            if existing.digest == digest:
                # Reusing material across versions makes rotation theatre: the
                # digest is the same, so retiring the old version does not
                # invalidate anything.
                raise SecretsError(
                    f"{self.name} v{version} reuses the material of v{other}. "
                    "Rotating to the same value invalidates nothing."
                )
        # Only the newest version issues. Adding an old version does not demote
        # a newer one.
        newest = max([*self._versions, version])
        self._versions[version] = SecretVersion(version=version, digest=digest)
        for number, existing in list(self._versions.items()):
            if number != newest and existing.issued:
                self._versions[number] = SecretVersion(
                    version=number,
                    digest=existing.digest,
                    issued=False,
                    accepted=existing.accepted,
                )
        self._record(f"added v{version}")

    def current(self) -> bytes:
        """The material to issue to a new client."""
        for version in sorted(self._versions, reverse=True):
            if self._versions[version].issued:
                return self._material[version]
        raise SecretsError(
            f"{self.name} has no issuing version; every version has been "
            "superseded or retired"
        )

    def current_version(self) -> int:
        for version in sorted(self._versions, reverse=True):
            if self._versions[version].issued:
                return version
        raise SecretsError(f"{self.name} has no issuing version")

    def verify(self, presented: str | bytes) -> int | None:
        """Return the version that matched, or None.

        Compares against EVERY accepted version with no early exit. Returning on
        first match makes the timing depend on which version matched, which leaks
        how recently the secret was rotated -- and that tells an attacker holding an
        old key whether it is still worth trying.
        """
        candidate = presented.encode("utf-8") if isinstance(presented, str) else presented
        digest = hashlib.sha256(candidate).digest()
        matched: int | None = None
        for version in sorted(self._versions):
            if not self._versions[version].accepted:
                continue
            expected = hashlib.sha256(self._material[version]).digest()
            if hmac.compare_digest(digest, expected):
                matched = version
        return matched

    def retire(self, version: int) -> None:
        """Stop accepting a version. The second half of a rotation."""
        existing = self._versions.get(version)
        if existing is None:
            raise SecretsError(f"{self.name} has no version {version}")
        if existing.issued:
            raise SecretsError(
                f"cannot retire {self.name} v{version} while it is the issuing "
                "version. Add the replacement first, then retire this one -- that "
                "ordering is what makes the rotation overlap rather than break "
                "every client at once."
            )
        if not any(
            v.accepted for n, v in self._versions.items() if n != version
        ):
            raise SecretsError(
                f"retiring {self.name} v{version} would leave no accepted version, "
                "which locks out every client including the ones holding the "
                "current material"
            )
        self._versions[version] = SecretVersion(
            version=version, digest=existing.digest, issued=False, accepted=False
        )
        self._record(f"retired v{version}")

    def versions(self) -> tuple[SecretVersion, ...]:
        """Every version and its state. Digests only, safe to surface."""
        return tuple(self._versions[v] for v in sorted(self._versions))

    def history(self) -> tuple[str, ...]:
        return tuple(self._history)

    def _record(self, what: str) -> None:
        self._history.append(what)

    def __repr__(self) -> str:  # pragma: no cover - defensive
        return f"RotatingSecret(name={self.name!r}, versions={self.versions()})"


class KmsKeyProvider:
    """Key-encrypting keys fetched from a KMS over the hardened HTTP client.

    Satisfies the same `KeyProvider` port as `StaticKeyProvider`, so the envelope
    cipher is unchanged.

    Fetched keys are CACHED for `cache_seconds`. Not an optimisation: without it
    every encrypt and decrypt becomes a network round trip, so a KMS blip becomes a
    total outage of every read of every encrypted column. The cache is bounded in
    time so a key revoked at the KMS stops working within the window rather than
    living for the life of the process.
    """

    __slots__ = ("_endpoint", "_client", "_token", "_cache", "_cache_seconds", "_active", "_now")

    def __init__(
        self,
        *,
        endpoint: str,
        token: str,
        active_key_id: str,
        client: HardenedHttpClient | None = None,
        cache_seconds: float = 300.0,
        now: Any = time.monotonic,
    ) -> None:
        self._client = client or HardenedHttpClient()
        try:
            inspect_url(endpoint, self._client.policy)
        except OutboundRefused as exc:
            raise SecretsError(f"the KMS endpoint is not callable: {exc}") from exc
        self._endpoint = endpoint.rstrip("/")
        self._token = token
        self._active = active_key_id
        self._cache: dict[str, tuple[bytes, float]] = {}
        self._cache_seconds = cache_seconds
        self._now = now

    def current_key_id(self) -> str:
        return self._active

    def key_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._cache, reverse=True)) or (self._active,)

    def key(self, key_id: str) -> bytes:
        cached = self._cache.get(key_id)
        if cached is not None and self._now() - cached[1] < self._cache_seconds:
            return cached[0]
        material = self._fetch(key_id)
        self._cache[key_id] = (material, self._now())
        return material

    def _fetch(self, key_id: str) -> bytes:
        try:
            response = self._client.request(
                method="GET",
                url=f"{self._endpoint}/v1/keys/{key_id}",
                headers={"Authorization": f"Bearer {self._token}", "Accept": "application/json"},
                idempotent=True,
            )
        except (OutboundRefused, OutboundUnavailable) as exc:
            # CryptoError rather than a transient error: a caller that retries a
            # decrypt in a loop against a down KMS turns one outage into a stampede.
            raise CryptoError(f"could not fetch KEK {key_id!r} from the KMS: {exc}") from exc
        if response.status != 200:
            raise CryptoError(
                f"the KMS returned HTTP {response.status} for KEK {key_id!r}"
            )
        try:
            payload = response.json()
            encoded = payload["key"]
        except (OutboundRefused, KeyError, TypeError) as exc:
            raise CryptoError(f"the KMS response for {key_id!r} was unusable") from exc
        try:
            material = base64.b64decode(encoded, validate=True)
        except Exception as exc:  # noqa: BLE001
            raise CryptoError(f"the KMS returned non-base64 material for {key_id!r}") from exc
        if len(material) != KEY_BYTES:
            raise CryptoError(
                f"the KMS returned a {len(material)}-byte key for {key_id!r}; "
                f"AES-256 requires {KEY_BYTES}. A short key is not a weak key here, "
                "it is a silently different algorithm."
            )
        return material

    def invalidate(self) -> None:
        """Drop the cache, so the next use re-fetches. Called after a rotation."""
        self._cache.clear()

    def describe(self) -> Mapping[str, Any]:
        """Cache state without key material, for a diagnostics response."""
        return {
            "endpoint": self._endpoint,
            "active_key_id": self._active,
            "cached_key_ids": sorted(self._cache),
            "cache_seconds": self._cache_seconds,
        }


def secrets_from_environment(
    source: Mapping[str, str], *, prefix: str
) -> Mapping[str, RotatingSecret]:
    """Build rotating secrets from `<PREFIX><NAME>` values holding a JSON list.

    A JSON list rather than comma-separated values, because a secret containing a
    comma is not a hypothetical and silently splitting one produces two invalid
    credentials rather than an error.
    """
    built: dict[str, RotatingSecret] = {}
    for name, raw in source.items():
        if not name.startswith(prefix):
            continue
        label = name[len(prefix) :].lower()
        try:
            values = json.loads(raw)
        except ValueError as exc:
            raise SecretsError(
                f"{name} must be a JSON array of versions, oldest first: {exc}"
            ) from exc
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            raise SecretsError(f"{name} must be a JSON array of strings")
        built[label] = RotatingSecret.from_values(label, values)
    return built
