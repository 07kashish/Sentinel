"""Identity, freshness and enrolment.

`Secp256k1IdentityVerifier` is the ONLY sanctioned source of an `Address`. If the
recovery backend is unavailable it reports every signed event as INVALID with a
stated reason rather than treating it as verified: it fails closed, and it says
why.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence

from sentinel.application.bypass_detection import AgentActivity
from sentinel.application.records import VerifiedIdentity
from sentinel.domain.primitives import Address, Digest, TenantId, Timestamp, TrustLevel

__all__ = [
    "Secp256k1IdentityVerifier",
    "SqlAgentRegistry",
    "SqlReplayGuard",
    "canonical_payload",
]


def canonical_payload(payload: Mapping[str, Any]) -> bytes:
    """The exact bytes a signature covers.

    Canonicalisation is part of the security boundary: if the signer and the
    verifier serialise differently, a valid signature fails or -- far worse -- a
    payload can be mutated in a way the canonical form does not see. Sorted keys,
    no whitespace, UTF-8, and the `signature` field excluded because it cannot
    cover itself.
    """
    body = {k: v for k, v in payload.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


class Secp256k1IdentityVerifier:
    """Recovers a signer address from an secp256k1 signature.

    The ONLY sanctioned source of an `Address`. If `eth_keys` is unavailable the
    verifier reports every signed event as INVALID with a stated reason rather
    than treating it as verified -- it fails closed, and it says why.
    """

    __slots__ = ("_recover",)

    def __init__(self) -> None:
        self._recover = _load_recovery_backend()

    def digest(self, payload: Mapping[str, Any]) -> Digest:
        return Digest(hashlib.sha256(canonical_payload(payload)).hexdigest())

    def verify(
        self, *, payload: Mapping[str, Any], signature: str | None, enrolled: frozenset[str]
    ) -> VerifiedIdentity:
        if not signature:
            return VerifiedIdentity(TrustLevel.UNSIGNED, "no signature presented")
        if self._recover is None:
            return VerifiedIdentity(
                TrustLevel.INVALID,
                "signature verification is unavailable: the eth_keys backend is "
                "not installed. Failing closed rather than trusting the claim.",
            )
        try:
            recovered = self._recover(canonical_payload(payload), signature)
        except Exception as exc:  # noqa: BLE001 - any recovery failure is INVALID
            return VerifiedIdentity(
                TrustLevel.INVALID, f"signature did not recover: {type(exc).__name__}"
            )
        if recovered is None:
            return VerifiedIdentity(TrustLevel.INVALID, "signature did not recover")

        normalised = {a.lower() for a in enrolled}
        if recovered.value not in normalised:
            return VerifiedIdentity(
                TrustLevel.INVALID,
                "recovered address is not enrolled for this tenant; enrol the "
                "agent before its events can be treated as authoritative",
            )
        return VerifiedIdentity(TrustLevel.VERIFIED, "signature verified", recovered)


def _load_recovery_backend():
    """Return a callable (message, signature) -> Address | None, or None."""
    try:
        from eth_keys import keys  # type: ignore[import-not-found]
        from eth_utils import keccak  # type: ignore[import-not-found]
    except ImportError:
        return None

    def recover(message: bytes, signature: str) -> Address | None:
        raw = signature[2:] if signature.startswith("0x") else signature
        blob = bytes.fromhex(raw)
        if len(blob) != 65:
            return None
        # Ethereum personal-sign framing, so a wallet signature verifies here.
        prefixed = b"\x19Ethereum Signed Message:\n" + str(len(message)).encode() + message
        digest = keccak(prefixed)
        v = blob[64]
        normalised = bytes(blob[:64]) + bytes([v - 27 if v >= 27 else v])
        public = keys.Signature(normalised).recover_public_key_from_msg_hash(digest)
        return Address(public.to_checksum_address())

    return recover


class SqlReplayGuard:
    """Freshness, enforced by a durable single-use nonce per (tenant, agent, digest).

    A valid signature proves authorship, never recency: without this a captured
    signed event could be resubmitted forever and would verify as VERIFIED every
    time.
    """

    __slots__ = ("_pool", "_window")

    def __init__(self, *, pool: Any, window_seconds: int = 300) -> None:
        self._pool = pool
        self._window = window_seconds

    def check_and_consume(
        self,
        *,
        tenant: TenantId,
        agent: Address,
        event_digest: Digest,
        claimed_at: Timestamp | None,
        now: Timestamp,
    ) -> tuple[bool, str]:
        if claimed_at is not None:
            skew = abs((now.value - claimed_at.value).total_seconds())
            if skew > self._window:
                return False, (
                    f"event timestamp is {skew:.0f}s from now, outside the "
                    f"{self._window}s freshness window"
                )
        expires = Timestamp(now.value + timedelta(seconds=self._window * 4))
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant.value)
            p = conn.p
            inserted = conn.execute_rowcount(
                f"INSERT INTO replay_nonces (tenant_id, agent, event_digest, seen_at, "
                f"expires_at) VALUES ({p},{p},{p},{p},{p}) ON CONFLICT DO NOTHING",
                (
                    tenant.value,
                    agent.value,
                    event_digest.value,
                    now.isoformat(),
                    expires.isoformat(),
                ),
            )
            conn.commit()
        if inserted == 0:
            return False, "this exact signed event was already consumed for this agent"
        return True, "fresh"

    def purge_expired(self, *, tenant: TenantId, now: Timestamp) -> int:
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant.value)
            removed = conn.execute_rowcount(
                f"DELETE FROM replay_nonces WHERE tenant_id={conn.p} AND expires_at<{conn.p}",
                (tenant.value, now.isoformat()),
            )
            conn.commit()
        return removed


class SqlAgentRegistry:
    """Which addresses a tenant has enrolled."""

    __slots__ = ("_pool",)

    def __init__(self, *, pool: Any) -> None:
        self._pool = pool

    def enrolled_addresses(self, tenant: TenantId) -> frozenset[str]:
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant.value)
            rows = conn.execute(
                f"SELECT address FROM agents WHERE tenant_id={conn.p} AND revoked_at IS NULL",
                (tenant.value,),
            )
            conn.commit()
        return frozenset(str(r["address"]).lower() for r in rows)

    def enrol(self, tenant: TenantId, *, address: Address, label: str, at: Timestamp) -> None:
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant.value)
            p = conn.p
            conn.execute_rowcount(
                f"INSERT INTO agents (tenant_id, address, label, enrolled_at) "
                f"VALUES ({p},{p},{p},{p}) ON CONFLICT (tenant_id, address) "
                f"DO UPDATE SET revoked_at=NULL, label=EXCLUDED.label",
                (tenant.value, address.value, label, at.isoformat()),
            )
            conn.commit()

    def revoke(self, tenant: TenantId, *, address: Address) -> None:
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant.value)
            p = conn.p
            conn.execute_rowcount(
                f"UPDATE agents SET revoked_at={p} WHERE tenant_id={p} AND address={p}",
                (datetime.now(timezone.utc).isoformat(), tenant.value, address.value),
            )
            conn.commit()

    def record_event(self, tenant: TenantId, *, address: Address, at: Timestamp) -> None:
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant.value)
            p = conn.p
            conn.execute_rowcount(
                f"UPDATE agents SET last_event_at={p} "
                f"WHERE tenant_id={p} AND address={p} AND revoked_at IS NULL",
                (at.isoformat(), tenant.value, address.value),
            )
            conn.commit()

    def list_activity(self, tenant: TenantId) -> Sequence[AgentActivity]:
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant.value)
            p = conn.p
            rows = conn.execute(
                f"SELECT address, label, enrolled_at, last_event_at FROM agents "
                f"WHERE tenant_id={p} AND revoked_at IS NULL",
                (tenant.value,),
            )
            conn.commit()
        out: list[AgentActivity] = []
        for row in rows:
            last_raw = row["last_event_at"]
            out.append(
                AgentActivity(
                    address=str(row["address"]).lower(),
                    enrolled_at=Timestamp.parse(str(row["enrolled_at"])),
                    last_event_at=(
                        Timestamp.parse(str(last_raw)) if last_raw is not None else None
                    ),
                    label=str(row["label"] or ""),
                )
            )
        return out
