"""Signed delegation chains at the edge: parse, verify, refuse.

WHY THIS EXISTS
---------------
`verify_chain` and `KeyRingVerifier` were written, tested and called by
nothing in production. A chain could be described to `/v1/a2a/evaluate` as
prose -- who delegated what to whom -- and the route had no way to check that
any of it had been SIGNED by the parties it named. This module is the one
place a wire payload becomes a `DelegationPassport` and is verified against
the deployment's key ring; both A2A routes call it.

WHAT IS REFUSED, AND HOW
------------------------
Any finding. `verify_chain` reports every defect rather than the first, and
the refusal carries all of them, because an operator fixing a chain needs to
fix it once. A malformed hop document is a refusal too, not a 500: the
document is caller-supplied and "cannot be read" is a fact about the caller's
chain.

THE PRESENTER IS CHECKED
------------------------
The agent about to act is passed as `presenter`, so a valid chain delegating
to somebody else is refused as SUBJECT_IS_NOT_THE_PRESENTER. Without that a
chain is proof that a delegation happened, not proof that this caller holds
it.
"""

from __future__ import annotations

import base64
import binascii
import json
from datetime import datetime
from typing import Any, Mapping, Sequence

from sentinel.domain.delegation_passport import (
    ChainVerdict,
    DelegationPassport,
    SignedHop,
    verify_chain,
)

__all__ = [
    "passport_from_documents",
    "passport_from_header",
    "verify_presented_chain",
]

#: Bounds on a presented chain. Generous relative to the depth limit for the
#: reason `a2a_routes.MAX_HOPS` gives: a chain over the limit must be
#: REPORTED as depth-exceeded rather than rejected as malformed.
MAX_SIGNED_HOPS = 64
MAX_HEADER_BYTES = 65_536


def passport_from_documents(hops: Sequence[Mapping[str, Any]]) -> DelegationPassport:
    """Build a passport from wire-shaped hops. Raises ValueError when malformed."""
    if len(hops) > MAX_SIGNED_HOPS:
        raise ValueError(f"a chain of {len(hops)} signed hops exceeds {MAX_SIGNED_HOPS}")
    signed: list[SignedHop] = []
    for index, entry in enumerate(hops, start=1):
        if not isinstance(entry, Mapping):
            raise ValueError(f"signed hop {index} is not an object")
        document = entry.get("document")
        if not isinstance(document, Mapping):
            raise ValueError(f"signed hop {index} has no `document` object")
        signed.append(
            SignedHop(
                document=dict(document),
                signature=str(entry.get("signature") or ""),
                key_id=str(entry.get("key_id") or entry.get("keyId") or ""),
                signed_at=str(entry.get("signed_at") or entry.get("signedAt") or ""),
            )
        )
    return DelegationPassport(hops=tuple(signed))


def passport_from_header(raw: str) -> DelegationPassport | None:
    """A passport from a base64url JSON header value, or None when absent.

    Raises ValueError when present and unreadable. The header carries
    `{"hops": [...]}` -- the shape `DelegationPassport.as_document` produces
    -- so a passport an issuer serialised can be presented verbatim.
    """
    text = (raw or "").strip()
    if not text:
        return None
    if len(text) > MAX_HEADER_BYTES:
        raise ValueError("the delegation passport header is too large")
    padded = text + "=" * (-len(text) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        body = json.loads(decoded.decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise ValueError(f"the delegation passport header is not base64url JSON: {exc}") from exc
    if not isinstance(body, Mapping) or not isinstance(body.get("hops"), list):
        raise ValueError("the delegation passport must be an object with a `hops` list")
    return passport_from_documents(body["hops"])


def verify_presented_chain(
    verifier: Any,
    *,
    passport: DelegationPassport,
    tenant_id: str,
    presenter: str,
    now: datetime,
) -> ChainVerdict:
    """Every defect in the chain, against the deployment's key ring.

    A hop document the caller shaped wrongly -- a missing `issuer`, a depth
    that is not an integer -- is a MALFORMED REQUEST, not a server fault. The
    domain reads documents lazily, so the shape error surfaces here rather than
    at parse time; it is turned into `ValueError` so the route answers 400.
    Found by the schema fuzzer in CI: `{"document": {}}` produced a 500.
    """
    try:
        return verify_chain(
            passport,
            verifier=verifier,
            now=now,
            tenant_id=tenant_id,
            presenter=presenter,
        )
    except KeyError as exc:
        raise ValueError(
            f"a signed hop document is missing the required field {exc.args[0]!r}"
        ) from exc
    except (TypeError, ValueError) as exc:
        raise ValueError(f"a signed hop document is malformed: {exc}") from exc
