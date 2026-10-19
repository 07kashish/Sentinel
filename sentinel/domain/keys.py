"""Customer-managed keys: whose key protects a tenant's data, and who can revoke it.

    BYOK / customer KMS / tenant-specific signing keys / rotation / revocation
    Do not hard-code encryption implementation into domain logic.

WHAT THIS MODULE IS, AND WHAT ALREADY EXISTED
-----------------------------------------------
`infrastructure/persistence/crypto.py` already implements envelope encryption
with a `KeyProvider` port, and `secrets.py` already has a `KmsKeyProvider` that
fetches key-encrypting keys from a KMS. That layer does the cryptography and it
is not duplicated here -- a second `KeyProvider` would be a second answer to
"which key wraps this", which is the duplication this codebase removed from
severity-to-priority and will not reintroduce.

What that layer does NOT have is a tenant dimension. Its keys belong to the
deployment: `current_key_id()` takes no tenant, and there is no state in which a
key exists but may no longer be used. Deployment-wide keys are fine for a vendor
-managed service and are exactly what BYOK is bought to replace.

So this module adds the missing half: WHICH key a given tenant's data is under,
what state that key is in, and what each state permits. There is no AES here and
no KMS SDK, because the adapter below it already has both.

THE PROPERTY BYOK ACTUALLY SELLS
----------------------------------
BYOK is bought for one guarantee: **the customer can make their data
unreadable, unilaterally, without asking the vendor.** Everything else --
rotation, audit, per-tenant separation -- is table stakes that a vendor-managed
key also provides.

That guarantee is the reason `REVOKED` is terminal and `revoke` has no inverse.
A revocation that support can undo is not a revocation, it is a suspension with
a misleading name, and a customer who believed the first would be wrong in a way
that matters legally. Restoring access after a revocation requires the customer
to supply key material again -- which is exactly right, because that is them
choosing, not us.

ROTATION IS NOT REVOCATION, AND CONFLATING THEM LOSES DATA
------------------------------------------------------------
Rotating produces a new key version and keeps the old one readable, because data
encrypted under the old version still exists. Revoking makes everything under
that key unreadable, deliberately. A system that treats rotation as
"revoke then create" destroys the tenant's history on a routine operation, and
this has happened to real products.

So `rotate` returns a new `KeyVersion` and leaves prior versions in
`DECRYPT_ONLY`: new writes use the new version, old reads still work, and
nothing is lost by doing the hygienic thing.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from sentinel.domain.errors import DomainRuleViolated

__all__ = [
    "KeyState",
    "KeyVersion",
    "KeyUnavailable",
    "TenantKey",
    "UnusableKey",
]


class UnusableKey(DomainRuleViolated):
    """An operation was attempted against a key whose state forbids it."""

    is_retryable = False


class KeyUnavailable(DomainRuleViolated):
    """The customer's KMS could not be reached.

    Distinct from `UnusableKey`: this is transient and about reachability, that
    is permanent and about state. Conflating them would have an operator
    investigating a revocation when their network is down, or worse, treating a
    deliberate revocation as an outage to be worked around.
    """

    is_retryable = True


class KeyState(str, Enum):
    """What may be done with a key version.

    Three states, and the transitions between them are one-way. A state machine
    that can go backwards would let a revoked key become active again, which is
    precisely the guarantee BYOK is bought for.
    """

    #: Encrypts new data and decrypts existing data. Exactly one per tenant.
    ACTIVE = "active"
    #: Decrypts existing data; will not encrypt new data. Where a version lands
    #: after rotation, so history stays readable.
    DECRYPT_ONLY = "decrypt_only"
    #: Does nothing. Terminal, by design -- see the module docstring.
    REVOKED = "revoked"

    @property
    def can_encrypt(self) -> bool:
        return self is KeyState.ACTIVE

    @property
    def can_decrypt(self) -> bool:
        return self in {KeyState.ACTIVE, KeyState.DECRYPT_ONLY}


@dataclass(frozen=True, slots=True)
class KeyVersion:
    """One version of a tenant's key. Never holds key material.

    `key_ref` is a reference the provider understands -- an ARN, a Key Vault
    URI, an HSM label. The material itself never enters this process, which is
    what makes "customer-managed" true rather than decorative: a vendor that
    holds the bytes can decrypt after revocation regardless of what its state
    machine says.
    """

    version: int
    key_ref: str
    state: KeyState
    created_at: str
    #: Which system holds it: `aws_kms`, `azure_key_vault`, `gcp_kms`, `vendor`.
    provider: str = "vendor"
    revoked_at: str = ""
    revoked_by: str = ""

    def __post_init__(self) -> None:
        if self.version < 1:
            raise UnusableKey("key versions start at 1")
        if not self.key_ref.strip():
            raise UnusableKey(
                "a key version must reference material somewhere; an empty "
                "reference would silently mean 'no encryption'"
            )
        if self.state is KeyState.REVOKED and not self.revoked_by.strip():
            raise UnusableKey(
                "a revoked key must record who revoked it; revocation is the "
                "operation a customer will later need to prove they performed"
            )

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "key_ref": self.key_ref,
            "state": self.state.value,
            "provider": self.provider,
            "created_at": self.created_at,
            "revoked_at": self.revoked_at,
            "revoked_by": self.revoked_by,
        }


@dataclass(frozen=True, slots=True)
class TenantKey:
    """Every version of one tenant's key, and the rules for moving between them.

    Frozen, and every operation returns a new `TenantKey`. Key state is the
    thing an auditor reconstructs after an incident, and a structure that
    mutates in place cannot answer "what was the state at 03:14".
    """

    tenant_id: str
    versions: tuple[KeyVersion, ...] = ()

    def __post_init__(self) -> None:
        active = [v for v in self.versions if v.state is KeyState.ACTIVE]
        if len(active) > 1:
            # Two active versions means two answers to "which key encrypts this
            # write", and the loser's data becomes undecryptable by whichever
            # bookkeeping wins.
            raise UnusableKey(
                f"tenant {self.tenant_id!r} has {len(active)} active key "
                f"versions; exactly one may encrypt new data"
            )
        numbers = [v.version for v in self.versions]
        if len(numbers) != len(set(numbers)):
            raise UnusableKey("duplicate key version numbers")

    @property
    def active(self) -> KeyVersion | None:
        return next((v for v in self.versions if v.state is KeyState.ACTIVE), None)

    @property
    def is_revoked(self) -> bool:
        """True when nothing can decrypt any more.

        The customer's kill switch, observed. A tenant in this state is not
        broken -- it is doing exactly what its owner asked for -- and callers
        must report it as such rather than as a fault.
        """
        return bool(self.versions) and all(
            v.state is KeyState.REVOKED for v in self.versions
        )

    def version_numbered(self, version: int) -> KeyVersion | None:
        return next((v for v in self.versions if v.version == version), None)

    def rotate(self, *, key_ref: str, at: str, provider: str = "vendor") -> "TenantKey":
        """Introduce a new active version; demote the previous one.

        The previous version becomes DECRYPT_ONLY rather than REVOKED. Data
        encrypted under it still exists, and destroying the ability to read that
        data is not what anyone means by "rotate the key".
        """
        if self.is_revoked:
            raise UnusableKey(
                f"tenant {self.tenant_id!r} has revoked its key; rotation would "
                f"restore access the customer deliberately removed. New material "
                f"must be supplied as a new key, by the customer."
            )
        next_version = max((v.version for v in self.versions), default=0) + 1
        demoted = tuple(
            KeyVersion(
                version=v.version,
                key_ref=v.key_ref,
                state=KeyState.DECRYPT_ONLY if v.state is KeyState.ACTIVE else v.state,
                created_at=v.created_at,
                provider=v.provider,
                revoked_at=v.revoked_at,
                revoked_by=v.revoked_by,
            )
            for v in self.versions
        )
        fresh = KeyVersion(
            version=next_version,
            key_ref=key_ref,
            state=KeyState.ACTIVE,
            created_at=at,
            provider=provider,
        )
        return TenantKey(tenant_id=self.tenant_id, versions=demoted + (fresh,))

    def revoke(self, *, at: str, by: str) -> "TenantKey":
        """Revoke EVERY version. Terminal.

        All versions, not just the active one. Revoking only the active version
        would leave prior versions DECRYPT_ONLY and the tenant's history still
        readable -- which is not what a customer means, and is the difference
        between a compliance control and a misleading button.
        """
        if not self.versions:
            raise UnusableKey(
                f"tenant {self.tenant_id!r} has no key to revoke"
            )
        if not by.strip():
            raise UnusableKey("revocation must record who performed it")
        return TenantKey(
            tenant_id=self.tenant_id,
            versions=tuple(
                KeyVersion(
                    version=v.version,
                    key_ref=v.key_ref,
                    state=KeyState.REVOKED,
                    created_at=v.created_at,
                    provider=v.provider,
                    revoked_at=v.revoked_at or at,
                    revoked_by=v.revoked_by or by,
                )
                for v in self.versions
            ),
        )

    def assert_can_encrypt(self) -> KeyVersion:
        """The version new writes must use, or a refusal explaining why not."""
        if self.is_revoked:
            raise UnusableKey(
                f"tenant {self.tenant_id!r} revoked its key; new data cannot be "
                f"written and this is the customer's decision, not a fault"
            )
        active = self.active
        if active is None:
            raise UnusableKey(
                f"tenant {self.tenant_id!r} has no active key version"
            )
        return active

    def assert_can_decrypt(self, version: int) -> KeyVersion:
        found = self.version_numbered(version)
        if found is None:
            raise UnusableKey(
                f"tenant {self.tenant_id!r} has no key version {version}; the "
                f"data referencing it cannot be read"
            )
        if not found.state.can_decrypt:
            raise UnusableKey(
                f"key version {version} for tenant {self.tenant_id!r} is "
                f"{found.state.value} and cannot decrypt"
            )
        return found

    def as_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "is_revoked": self.is_revoked,
            "active_version": self.active.version if self.active else None,
            "versions": [v.as_dict() for v in self.versions],
        }
