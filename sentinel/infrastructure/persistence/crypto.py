"""Envelope encryption at the application layer, not in the database.

WHY NOT pgcrypto
----------------
`pgcrypto` encrypts inside the database, which means the database can decrypt.
An attacker with a database connection, a stolen backup, or a replica has the
ciphertext AND the engine that unwraps it; the key travels in the query text and
lands in `pg_stat_activity` and the query log.

Encrypting in the application inverts that. The database stores ciphertext it
cannot read, the key never reaches it, and a compromised backup or replica yields
nothing. It also removes the dependency on an extension the deployment may not be
allowed to install -- this build has only `plpgsql` and `vector` available, which
is exactly the situation a pgcrypto design fails in.

THE ENVELOPE, AND WHY IT IS ONE
--------------------------------
A single key encrypting every record has two problems: rotating it means
re-encrypting everything, and one leaked key exposes everything.

So each record gets its own random **data key** (DEK). The payload is encrypted
with the DEK; the DEK is then wrapped by a **key-encrypting key** (KEK) held by
the provider and stored beside the ciphertext.

    rotate a KEK   -> unwrap and re-wrap each DEK. Cheap: 60 bytes per record.
    without it     -> re-encrypt every payload. Hours, and a write storm.

`rewrap` does exactly that, and never touches the plaintext -- so a rotation can
run against a replica-sized dataset without decrypting a single record.

AUTHENTICATED ASSOCIATED DATA
-----------------------------
AES-GCM authenticates but does not, by itself, bind a ciphertext to its context.
A blob lifted from tenant A's evidence row and written into tenant B's decrypts
perfectly -- the key is the same, the tag still verifies. The record simply now
claims to belong to someone else.

Every payload here is sealed with AAD over `tenant_id | record_type | record_id`.
Moving a ciphertext to another tenant, another table, or another row makes the
tag fail. That is the same defect class the ledger's identity-bound Merkle leaves
close, at a different layer.
"""

from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass
from typing import Mapping, Protocol, runtime_checkable

from sentinel.domain.errors import SentinelError

__all__ = [
    "CipherText",
    "CryptoError",
    "EnvelopeCipher",
    "EnvironmentKeyProvider",
    "KeyProvider",
    "StaticKeyProvider",
]

#: AES-256. Both the DEK and every KEK are this size.
KEY_BYTES = 32
#: 96 bits, the size AES-GCM is specified for. A different length is legal in the
#: standard and slower, and reusing a nonce with one key is catastrophic -- so the
#: nonce is always freshly random and never derived from a counter that could
#: repeat after a restore.
NONCE_BYTES = 12


class CryptoError(SentinelError):
    """Encryption or decryption failed. Never retried: the input is wrong."""

    is_retryable = False


@runtime_checkable
class KeyProvider(Protocol):
    """Supplies key-encrypting keys by id.

    A port, so a KMS, an HSM, or a mounted file are interchangeable. The
    application never sees a KEK's bytes leave this boundary except to wrap and
    unwrap a DEK, which is the whole reason the boundary exists.
    """

    def current_key_id(self) -> str:
        """The key new records are sealed with. Rotation changes this."""
        ...

    def key(self, key_id: str) -> bytes:
        """The KEK for `key_id`. Raises `CryptoError` if it is not held.

        Old key ids must remain resolvable after rotation, or every record sealed
        before the rotation becomes unreadable. That is the single most common way
        a key rotation destroys data.
        """
        ...

    def key_ids(self) -> tuple[str, ...]:
        """Every key id this provider can resolve, newest first."""
        ...


@dataclass(frozen=True, slots=True)
class StaticKeyProvider:
    """Keys supplied directly. For tests and for a file-mounted secret."""

    keys: Mapping[str, bytes]
    active: str

    def __post_init__(self) -> None:
        if self.active not in self.keys:
            raise CryptoError(
                f"active key id {self.active!r} is not among the supplied keys "
                f"{sorted(self.keys)}"
            )
        for key_id, material in self.keys.items():
            if len(material) != KEY_BYTES:
                raise CryptoError(
                    f"key {key_id!r} is {len(material)} bytes; AES-256 requires "
                    f"{KEY_BYTES}. A short key is not a weak key here, it is a "
                    "silently different algorithm."
                )

    def current_key_id(self) -> str:
        return self.active

    def key(self, key_id: str) -> bytes:
        try:
            return self.keys[key_id]
        except KeyError:
            raise CryptoError(
                f"no key material for id {key_id!r}. Every key id that has ever "
                "sealed a record must remain resolvable, or those records are "
                "unreadable."
            ) from None

    def key_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self.keys, reverse=True))


class EnvironmentKeyProvider:
    """Keys from the environment, as `SENTINEL_DATA_KEY_<id>` base64 values.

    Reads the mapping ONCE, at construction, so a key rotated in the environment
    mid-process cannot make an in-flight decrypt fail halfway. Rotation is a
    restart or an explicit reload, never a race.
    """

    __slots__ = ("_provider",)

    _PREFIX = "SENTINEL_DATA_KEY_"
    _ACTIVE = "SENTINEL_ACTIVE_KEY_ID"

    def __init__(self, environ: Mapping[str, str]) -> None:
        """`environ` is REQUIRED. There is no `os.environ` default.

        A default that reads the process environment is ambient configuration with
        extra steps: it lets any caller anywhere obtain keys without the wiring
        being visible, and it is invisible to the fitness rule that asserts only
        the composition root reads the environment. The composition root passes
        `os.environ` in; everything else passes a dict, which is also what makes
        this testable without mutating process state.
        """
        source = environ
        keys: dict[str, bytes] = {}
        for name, value in source.items():
            if not name.startswith(self._PREFIX):
                continue
            key_id = name[len(self._PREFIX) :].lower()
            try:
                keys[key_id] = base64.b64decode(value, validate=True)
            except Exception as exc:  # noqa: BLE001
                raise CryptoError(
                    f"{name} is not valid base64: {exc}. A malformed key is "
                    "refused at startup rather than at the first write."
                ) from exc
        if not keys:
            raise CryptoError(
                f"no data keys configured. Set {self._PREFIX}<id> to a base64 "
                f"32-byte value and {self._ACTIVE} to the id new records use."
            )
        active = source.get(self._ACTIVE, "").strip().lower()
        if not active:
            raise CryptoError(
                f"{self._ACTIVE} is unset. Which key seals new records must be "
                "stated, not guessed from ordering."
            )
        self._provider = StaticKeyProvider(keys=keys, active=active)

    def current_key_id(self) -> str:
        return self._provider.current_key_id()

    def key(self, key_id: str) -> bytes:
        return self._provider.key(key_id)

    def key_ids(self) -> tuple[str, ...]:
        return self._provider.key_ids()


@dataclass(frozen=True, slots=True)
class CipherText:
    """A sealed payload, self-describing enough to be decrypted years later.

    Every field needed to unwrap is carried WITH the ciphertext. A record that
    depends on external configuration to identify its own algorithm becomes
    unreadable the first time that configuration changes.
    """

    key_id: str
    wrapped_dek: bytes
    dek_nonce: bytes
    nonce: bytes
    payload: bytes
    #: Bumped if the construction ever changes. Version 1 is
    #: AES-256-GCM(DEK) over the plaintext, AES-256-GCM(KEK) over the DEK.
    version: int = 1

    def to_wire(self) -> str:
        """Compact, URL-safe, and stable. Stored in a TEXT column."""
        return ".".join(
            (
                str(self.version),
                self.key_id,
                _b64(self.wrapped_dek),
                _b64(self.dek_nonce),
                _b64(self.nonce),
                _b64(self.payload),
            )
        )

    @classmethod
    def from_wire(cls, wire: str) -> "CipherText":
        parts = wire.split(".")
        if len(parts) != 6:
            raise CryptoError(
                f"ciphertext has {len(parts)} fields, expected 6. This is not a "
                "sealed payload."
            )
        version, key_id, wrapped, dek_nonce, nonce, payload = parts
        try:
            parsed_version = int(version)
        except ValueError:
            raise CryptoError(f"ciphertext version {version!r} is not an integer") from None
        if parsed_version != 1:
            raise CryptoError(
                f"ciphertext version {parsed_version} is not supported by this "
                "build. Refusing to guess at an unknown construction."
            )
        return cls(
            version=parsed_version,
            key_id=key_id,
            wrapped_dek=_unb64(wrapped),
            dek_nonce=_unb64(dek_nonce),
            nonce=_unb64(nonce),
            payload=_unb64(payload),
        )


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    """Strict base64. Rejects a corrupt field rather than decoding around it.

    `urlsafe_b64decode` DISCARDS characters outside the alphabet, so a field of
    `!!!` decodes to empty bytes and the corruption surfaces later as an
    authentication failure that points at the wrong cause. `validate=True` makes
    it an error where it happens.
    """
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except Exception as exc:  # noqa: BLE001
        raise CryptoError(f"ciphertext field is not valid base64: {exc}") from exc


class EnvelopeCipher:
    """Seals and opens payloads, binding each to the record it belongs to."""

    __slots__ = ("_provider",)

    def __init__(self, provider: KeyProvider) -> None:
        self._provider = provider

    # ── Sealing ──────────────────────────────────────────────────────────────

    @property
    def active_key_id(self) -> str:
        """The key id new records are sealed under; used to find rows needing rotation."""
        return self._provider.current_key_id()

    def seal(
        self,
        plaintext: bytes,
        *,
        tenant_id: str,
        record_type: str,
        record_id: str,
    ) -> CipherText:
        """Encrypt, binding the result to this tenant, table and row."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        key_id = self._provider.current_key_id()
        kek = AESGCM(self._provider.key(key_id))

        dek = secrets.token_bytes(KEY_BYTES)
        nonce = secrets.token_bytes(NONCE_BYTES)
        dek_nonce = secrets.token_bytes(NONCE_BYTES)

        aad = _aad(tenant_id, record_type, record_id)
        payload = AESGCM(dek).encrypt(nonce, plaintext, aad)
        # The DEK is wrapped under the SAME associated data, so a wrapped DEK
        # cannot be transplanted onto another record either.
        wrapped = kek.encrypt(dek_nonce, dek, aad)

        return CipherText(
            key_id=key_id,
            wrapped_dek=wrapped,
            dek_nonce=dek_nonce,
            nonce=nonce,
            payload=payload,
        )

    def seal_json(
        self, value: object, *, tenant_id: str, record_type: str, record_id: str
    ) -> str:
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
        return self.seal(
            canonical.encode("utf-8"),
            tenant_id=tenant_id,
            record_type=record_type,
            record_id=record_id,
        ).to_wire()

    # ── Opening ──────────────────────────────────────────────────────────────

    def open(
        self,
        sealed: CipherText,
        *,
        tenant_id: str,
        record_type: str,
        record_id: str,
    ) -> bytes:
        """Decrypt, verifying the payload belongs where it was found.

        A tag failure here is not a corrupt disk. It means the ciphertext, the
        key, or the CONTEXT is wrong -- and the third is the interesting one,
        because it is what a ciphertext moved between tenants looks like.
        """
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        aad = _aad(tenant_id, record_type, record_id)
        kek = AESGCM(self._provider.key(sealed.key_id))
        try:
            dek = kek.decrypt(sealed.dek_nonce, sealed.wrapped_dek, aad)
        except InvalidTag as exc:
            raise CryptoError(
                f"could not unwrap the data key for {record_type}/{record_id} under "
                f"key {sealed.key_id!r}. Either the key is wrong or this ciphertext "
                "belongs to a different tenant, table or row."
            ) from exc
        try:
            return AESGCM(dek).decrypt(sealed.nonce, sealed.payload, aad)
        except InvalidTag as exc:
            raise CryptoError(
                f"authentication failed for {record_type}/{record_id}. The "
                "ciphertext has been altered or does not belong here."
            ) from exc

    def open_json(
        self, wire: str, *, tenant_id: str, record_type: str, record_id: str
    ) -> object:
        plaintext = self.open(
            CipherText.from_wire(wire),
            tenant_id=tenant_id,
            record_type=record_type,
            record_id=record_id,
        )
        return json.loads(plaintext.decode("utf-8"))

    # ── Rotation ─────────────────────────────────────────────────────────────

    def rewrap(
        self,
        sealed: CipherText,
        *,
        tenant_id: str,
        record_type: str,
        record_id: str,
    ) -> CipherText:
        """Re-wrap the DEK under the current KEK. The payload is untouched.

        This is the entire point of the envelope. Rotating a KEK rewrites ~60
        bytes per record instead of the whole payload, so a rotation over a large
        dataset is bounded work -- and the plaintext is never materialised, so it
        can run with no access to the data it is re-keying.
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        aad = _aad(tenant_id, record_type, record_id)
        old = AESGCM(self._provider.key(sealed.key_id))
        dek = old.decrypt(sealed.dek_nonce, sealed.wrapped_dek, aad)

        new_id = self._provider.current_key_id()
        if new_id == sealed.key_id:
            return sealed  # already current; rewrapping would only spend entropy

        dek_nonce = secrets.token_bytes(NONCE_BYTES)
        wrapped = AESGCM(self._provider.key(new_id)).encrypt(dek_nonce, dek, aad)
        return CipherText(
            key_id=new_id,
            wrapped_dek=wrapped,
            dek_nonce=dek_nonce,
            nonce=sealed.nonce,
            payload=sealed.payload,
        )


def _aad(tenant_id: str, record_type: str, record_id: str) -> bytes:
    """Associated data binding a ciphertext to exactly one row.

    Length-prefixed rather than delimiter-joined. `("a|b", "c")` and
    `("a", "b|c")` produce the same string under a delimiter, so a tenant id
    containing the delimiter could make two different records share AAD.
    """
    parts = (tenant_id, record_type, record_id)
    return b"".join(
        len(p.encode("utf-8")).to_bytes(4, "big") + p.encode("utf-8") for p in parts
    )
