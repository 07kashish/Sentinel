"""Attestation gateways.

`UnconfiguredAttestationGateway` is not a stand-in. It is the truthful
description of a deployment with no anchoring capability: it returns
NOT_ANCHORABLE -- a permanent property of that deployment -- and never
UNAVAILABLE, because there is no gateway that might come back.

That distinction is the entire point of `AttestationDisposition`. The predecessor
returned the string `"Skipped"` for both, so a transient outage and a permanent
incapacity were indistinguishable, and both completed the incident.
"""

from __future__ import annotations

import json

from sentinel.domain.attestation import AttestationDisposition, AttestationOutcome
from sentinel.infrastructure.outbound import (
    HardenedHttpClient,
    OutboundPolicy,
    OutboundRefused,
    OutboundUnavailable,
    inspect_url,
)
from sentinel.domain.primitives import (
    Address,
    Digest,
    IdempotencyKey,
    IncidentId,
    InvalidValue,
    TenantId,
)

__all__ = ["HttpAttestationGateway", "UnconfiguredAttestationGateway"]


class UnconfiguredAttestationGateway:
    """The gateway for a deployment that has none configured.

    Not a stand-in: it is the truthful description of a deployment with no
    attestation capability. It returns NOT_ANCHORABLE -- a permanent property of
    this deployment, which is exactly right -- and never UNAVAILABLE, because
    there is no gateway that might come back. That distinction is the whole point
    of `AttestationDisposition`.
    """

    __slots__ = ("_reason",)

    def __init__(self, *, reason: str = "no attestation gateway is configured") -> None:
        self._reason = reason

    def anchor(
        self,
        *,
        tenant: TenantId,
        incident_id: IncidentId,
        evidence_digest: Digest,
        subject: Address | None,
        idempotency_key: IdempotencyKey,
    ) -> AttestationOutcome:
        if subject is None:
            return AttestationOutcome(
                AttestationDisposition.NOT_ANCHORABLE,
                "no signature-recovered agent identity for this incident; "
                "attestation requires a verified signer",
            )
        return AttestationOutcome(AttestationDisposition.NOT_ANCHORABLE, self._reason)

    def reconcile(
        self, *, idempotency_key: IdempotencyKey
    ) -> AttestationOutcome | None:
        """Nothing was ever sent, so there is nothing to reconcile."""
        return None

    def capability(self) -> tuple[bool, str]:
        return False, self._reason


class HttpAttestationGateway:
    """Submits an anchor request to a KMS/HSM-backed attestation gateway.

    Two properties are load-bearing:

    **The idempotency key is sent.** It is a required argument and it goes in the
    request body and the `Idempotency-Key` header. The predecessor generated a
    key, persisted it, returned it, and never transmitted it -- so the outbox
    could not deduplicate at the only place deduplication mattered.

    **Transient failure is returned, not raised.** A timeout, a connection error
    or a 5xx becomes `UNAVAILABLE`, which parks the incident at
    `ATTESTATION_UNAVAILABLE` for a retry. A 4xx becomes `NOT_ANCHORABLE`,
    because the gateway is telling us this request will never succeed. This
    adapter is the only component positioned to know which of the two happened,
    so it is the component that decides.

    **Every request goes through `HardenedHttpClient`.** Not `urlopen`. That is
    not a style preference: with `urlopen`, a gateway answering `302 ->
    http://127.0.0.1/` received this adapter's `Authorization` header, because
    urllib rebuilds a redirected request with the original headers and permits an
    https downgrade. The attestation token is a bearer credential for a signing
    service, so that was a one-redirect key exfiltration. See `outbound.py`.
    """

    __slots__ = ("_endpoint", "_token", "_client")

    def __init__(
        self,
        *,
        endpoint: str,
        token: str,
        timeout_seconds: float = 20.0,
        client: HardenedHttpClient | None = None,
    ) -> None:
        self._client = client or HardenedHttpClient(
            policy=OutboundPolicy(read_timeout_seconds=timeout_seconds)
        )
        # Vetted at CONSTRUCTION, so a deployment configured with a scheme or host
        # this process will never call refuses to start rather than failing during
        # the first incident it was installed to handle. Resolution is left to
        # request time: a name that is public now can be private later, and only
        # the pre-connect check sees that.
        try:
            inspect_url(endpoint, self._client.policy)
        except OutboundRefused as exc:
            raise InvalidValue(
                f"the attestation gateway endpoint is not callable: {exc}. "
                "Anchoring evidence over plaintext, or to an internal address, "
                "defeats the purpose of anchoring it."
            ) from exc
        self._endpoint = endpoint.rstrip("/")
        self._token = token

    def anchor(
        self,
        *,
        tenant: TenantId,
        incident_id: IncidentId,
        evidence_digest: Digest,
        subject: Address | None,
        idempotency_key: IdempotencyKey,
    ) -> AttestationOutcome:
        if subject is None:
            # Deterministic and permanent for this incident: no retry can invent
            # an identity, and inventing one is precisely what must not happen.
            return AttestationOutcome(
                AttestationDisposition.NOT_ANCHORABLE,
                "no signature-recovered agent identity for this incident; "
                "enrol the agent and sign its events to enable attestation",
            )

        body = json.dumps(
            {
                "tenant_id": tenant.value,
                "incident_id": incident_id.value,
                "evidence_digest": evidence_digest.value,
                "subject": subject.value,
                "idempotency_key": idempotency_key.value,
            },
            sort_keys=True,
        ).encode("utf-8")

        try:
            response = self._client.request(
                method="POST",
                url=f"{self._endpoint}/v1/anchor",
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self._token}",
                    "Idempotency-Key": idempotency_key.value,
                },
                # Safe to re-send: the gateway deduplicates on the key above.
                idempotent=True,
            )
        except OutboundRefused as exc:
            # OUR policy blocked this, not the gateway. UNAVAILABLE rather than
            # NOT_ANCHORABLE deliberately: marking the incident permanently
            # unanchorable because of a local misconfiguration would destroy the
            # evidence trail for a problem an operator can fix in a minute. Parked
            # for retry, with the reason stated.
            return AttestationOutcome(
                AttestationDisposition.UNAVAILABLE,
                f"the attestation request was refused by outbound policy: {exc}",
            )
        except OutboundUnavailable as exc:
            return AttestationOutcome(
                AttestationDisposition.UNAVAILABLE,
                f"attestation gateway unreachable: {exc}",
            )

        if 400 <= response.status < 500:
            return AttestationOutcome(
                AttestationDisposition.NOT_ANCHORABLE,
                f"gateway returned HTTP {response.status}: the gateway rejected "
                "this request permanently",
            )
        if response.status >= 500:
            return AttestationOutcome(
                AttestationDisposition.UNAVAILABLE,
                f"gateway returned HTTP {response.status}",
            )
        try:
            payload = response.json()
        except OutboundRefused:
            return AttestationOutcome(
                AttestationDisposition.UNAVAILABLE,
                "attestation gateway returned a malformed response",
            )
        if not isinstance(payload, dict):
            return AttestationOutcome(
                AttestationDisposition.UNAVAILABLE,
                "attestation gateway returned a non-object response",
            )

        transaction_hash = payload.get("transaction_hash")
        if not transaction_hash:
            return AttestationOutcome(
                AttestationDisposition.UNAVAILABLE,
                "gateway accepted the request but returned no transaction hash; "
                "treating as not-yet-anchored so a retry can confirm",
            )
        return AttestationOutcome(
            AttestationDisposition.ANCHORED,
            f"anchored via {self._endpoint}",
            transaction_hash=str(transaction_hash),
            subject=subject,
        )

    def reconcile(
        self, *, idempotency_key: IdempotencyKey
    ) -> AttestationOutcome | None:
        """Ask the gateway what it already recorded under this key.

        A GET, deliberately: reconciliation must never create the thing it is
        asking about. 404 means nothing was applied. Anything the gateway
        cannot answer returns None, and the caller falls back to re-sending
        under the same key.
        """
        try:
            response = self._client.request(
                method="GET",
                url=f"{self._endpoint}/v1/anchor/{idempotency_key.value}",
                headers={"Authorization": f"Bearer {self._token}"},
                idempotent=True,
            )
        except (OutboundRefused, OutboundUnavailable):
            # Cannot answer. The caller re-sends under the same key, which the
            # gateway deduplicates -- so an unanswerable reconciliation is safe.
            return None
        if response.status != 200:
            # 404 is definitively not-applied; anything else we simply cannot
            # interpret. Both mean "re-send under the same key".
            return None
        try:
            payload = response.json()
        except OutboundRefused:
            return None
        if not isinstance(payload, dict):
            return None

        transaction_hash = payload.get("transaction_hash")
        if not transaction_hash:
            return None
        subject_value = payload.get("subject")
        return AttestationOutcome(
            AttestationDisposition.ANCHORED,
            "reconciled: this anchor was already applied under the same key",
            transaction_hash=str(transaction_hash),
            subject=Address(subject_value) if subject_value else None,
        )

    def capability(self) -> tuple[bool, str]:
        return True, f"KMS/HSM attestation gateway configured at {self._endpoint}"
