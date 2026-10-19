#!/usr/bin/env python3
"""Verify an Execution Passport. A SECOND implementation, on purpose.

WHY THIS FILE IS NOT ALLOWED TO IMPORT SENTINEL
--------------------------------------------------
A passport is supposed to be checkable by someone who does not run Sentinel,
does not trust Sentinel, and may be auditing Sentinel. If the only program that
can verify one is the program that issued it, the passport proves that Sentinel
agrees with itself.

So this is written from the specification, not from the producer's code. It
shares no canonicaliser, no constant and no helper with `sentinel.domain.
passport`. When the two agree on a signature, that agreement is evidence the
format is unambiguous. When they disagree, the specification has a hole -- and
finding that hole is the entire purpose of writing this twice.

`tests_arch/test_passport_standard.py` enforces the independence by refusing
any import of `sentinel` from this directory, and cross-checks Sentinel's
signer against this verifier over the conformance vectors.

WHAT IT DEPENDS ON
------------------
The Python standard library, plus `cryptography` for Ed25519. An auditor can
read this file top to bottom in a few minutes, which is a property worth more
here than any amount of shared code.

USAGE
-----
    python verify_passport.py --passport signed.json --key pubkey.json
    python verify_passport.py --passport signed.json --key pubkey.json --at 2026-01-01T00:00:00+00:00

Exit status is 0 only when there are no findings. Every finding is printed with
its code, so a caller can act on WHICH thing was wrong rather than on "invalid".
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

#: The only schema value this verifier claims to understand.
#:
#: A verifier that accepted an unknown schema string would be guessing at the
#: meaning of fields it has never seen, and reporting "valid" for a document
#: whose semantics it does not know is worse than reporting nothing.
SCHEMA = "sentinel.passport/v1"

#: The only signature algorithm implemented here.
ALGORITHM = "ed25519"

#: Without any one of these a passport records that something happened, not who
#: is answerable for it.
REQUIRED_FIELDS: tuple[str, ...] = (
    "execution_id",
    "tenant_id",
    "occurred_at",
    "agent_id",
    "action",
    "decision",
)


class Finding:
    """One defect. Codes are stable; wording is not."""

    __slots__ = ("code", "detail")

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail

    def __repr__(self) -> str:  # pragma: no cover - diagnostic only
        return f"Finding({self.code!r}, {self.detail!r})"


# ── canonical form ───────────────────────────────────────────────────────────


def _reject_uncanonical(value: Any, path: str = "$") -> None:
    """Refuse any value JSON does not represent identically everywhere.

    FLOATS ARE THE IMPORTANT CASE. `0.1 + 0.2` serialises as
    `0.30000000000000004` in one runtime and `0.3` in another, so a passport
    carrying a float has two canonical forms and therefore two valid
    signatures -- which means a verifier can be shown the one that matches. The
    specification forbids them; this refuses them rather than hashing whatever
    the local float repr happens to produce.
    """
    if isinstance(value, bool):
        # Checked before int, because bool IS an int in Python and a bare
        # isinstance(value, int) would accept it as a number.
        return
    if isinstance(value, float):
        raise ValueError(
            f"{path}: floats have no canonical JSON form; the specification "
            "forbids them"
        )
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path}: object keys must be strings")
            _reject_uncanonical(item, f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_uncanonical(item, f"{path}[{index}]")
        return
    if value is None or isinstance(value, (str, int)):
        return
    raise ValueError(f"{path}: {type(value).__name__} has no canonical JSON form")


def canonical_bytes(document: Mapping[str, Any]) -> bytes:
    """The exact bytes a signature covers.

    Four rules, each one closing a way two implementations could disagree:

      sort_keys=True        object order is not semantic, so it must be fixed
      separators=(",",":")  no insignificant whitespace
      ensure_ascii=False    a Cyrillic agent name has ONE representation, not
                            one escaped and one not
      allow_nan=False       NaN and Infinity are not JSON

    Nulls are serialised rather than dropped: a field explicitly set to null
    says something different from a field that is absent, and a canonicaliser
    that erased the distinction would let those two documents share a signature.
    """
    _reject_uncanonical(document)
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def digest_of(document: Mapping[str, Any]) -> str:
    """SHA-256 over the canonical bytes, lowercase hex."""
    return hashlib.sha256(canonical_bytes(document)).hexdigest()


# ── verification ─────────────────────────────────────────────────────────────


def _parse_time(text: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(text)
    except (TypeError, ValueError):
        return None
    # A naive timestamp is treated as UTC rather than refused, but it is not
    # silently equivalent: `check_structure` reports the missing offset, so the
    # reader learns the document was ambiguous even though the check proceeded.
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def check_structure(document: Mapping[str, Any]) -> list[Finding]:
    """Everything wrong with the document itself, signature aside."""
    findings: list[Finding] = []

    schema = document.get("schema")
    if schema != SCHEMA:
        findings.append(
            Finding(
                "unrecognised_schema",
                f"schema is {schema!r}; this verifier implements {SCHEMA!r} and "
                "will not guess at the meaning of fields it has not seen",
            )
        )
        # Returned early: every check below reads fields whose meaning is
        # defined by the schema that was just rejected.
        return findings

    for field in REQUIRED_FIELDS:
        value = document.get(field)
        if value is None or (isinstance(value, str) and not value.strip()):
            findings.append(
                Finding(
                    "missing_required_field",
                    f"{field!r} is absent or empty; without it this document "
                    "records that something happened, not who is answerable",
                )
            )

    occurred = document.get("occurred_at")
    if isinstance(occurred, str) and occurred.strip():
        if _parse_time(occurred) is None:
            findings.append(
                Finding("malformed_timestamp", f"occurred_at {occurred!r} is not ISO-8601")
            )
        elif "+" not in occurred and "Z" not in occurred.upper():
            findings.append(
                Finding(
                    "naive_timestamp",
                    f"occurred_at {occurred!r} carries no UTC offset, so the "
                    "moment it names depends on who reads it",
                )
            )

    chain = document.get("delegation_chain")
    if chain is not None and not isinstance(chain, list):
        findings.append(
            Finding("malformed_delegation_chain", "delegation_chain must be an array")
        )

    return findings


def check_signature(
    payload: Mapping[str, Any],
    *,
    public_key_b64: str,
    key_id: str,
    not_before: str = "",
    not_after: str = "",
) -> list[Finding]:
    """Whether this key signed these exact bytes, inside its validity window."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    findings: list[Finding] = []
    envelope = payload.get("signature")
    document = payload.get("passport")

    if not isinstance(envelope, dict) or not isinstance(document, dict):
        return [
            Finding(
                "malformed_envelope",
                "expected an object with 'passport' and 'signature' members",
            )
        ]

    algorithm = str(envelope.get("algorithm", ""))
    if algorithm != ALGORITHM:
        # Returned rather than accumulated: with an unknown algorithm there is
        # no signature check left to perform, and continuing would produce a
        # report whose other rows imply the signature was examined.
        return [
            Finding(
                "unsupported_algorithm",
                f"signed with {algorithm!r}; this verifier implements {ALGORITHM!r}",
            )
        ]

    signed_by = str(envelope.get("key_id", ""))
    if signed_by != key_id:
        return [
            Finding(
                "wrong_key",
                f"signed by {signed_by!r}, verified against {key_id!r}: the "
                "wrong key proves nothing about this document",
            )
        ]

    signed_at = _parse_time(str(envelope.get("signed_at", "")))
    if signed_at is None:
        findings.append(
            Finding("malformed_timestamp", "signature.signed_at is not ISO-8601")
        )
    else:
        lower = _parse_time(not_before) if not_before else None
        upper = _parse_time(not_after) if not_after else None
        if (lower and signed_at < lower) or (upper and signed_at > upper):
            # NOT a cryptographic failure. The maths can be perfect and the
            # evidence still worthless: a key used outside its window signs
            # something nobody agreed it could speak for.
            findings.append(
                Finding(
                    "key_outside_validity_window",
                    f"key {key_id!r} signed at {signed_at.isoformat()}, outside "
                    f"[{not_before or 'unbounded'}, {not_after or 'unbounded'}]",
                )
            )

    try:
        signature = base64.b64decode(
            str(envelope.get("value", "")).encode("ascii"), validate=True
        )
        key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(public_key_b64.encode("ascii"), validate=True)
        )
    except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
        return findings + [
            Finding("malformed_signature", f"signature or key is not valid base64: {exc}")
        ]

    try:
        body = canonical_bytes(document)
    except ValueError as exc:
        return findings + [
            Finding("uncanonical_document", f"document cannot be canonicalised: {exc}")
        ]

    try:
        key.verify(signature, body)
    except InvalidSignature:
        findings.append(
            Finding(
                "modified",
                "the signature does not cover these bytes: the document was "
                "altered after signing, or was never signed by this key",
            )
        )
    return findings


def verify(
    payload: Mapping[str, Any], key_material: Mapping[str, Any]
) -> list[Finding]:
    """Every defect in this signed passport. Empty means sound."""
    findings = check_signature(
        payload,
        public_key_b64=str(key_material.get("public_key", "")),
        key_id=str(key_material.get("key_id", "")),
        not_before=str(key_material.get("not_before", "")),
        not_after=str(key_material.get("not_after", "")),
    )
    document = payload.get("passport")
    if isinstance(document, dict):
        findings.extend(check_structure(document))
    return findings


# ── chain ────────────────────────────────────────────────────────────────────


def check_chain(passports: Sequence[Mapping[str, Any]]) -> list[Finding]:
    """Whether each passport's `previous_passport_digest` names its parent.

    Verified over the PARENT'S OWN canonical bytes rather than over anything the
    child asserts. A child that carried both the digest and a copy of the parent
    would let one forger write both halves and agree with itself.
    """
    findings: list[Finding] = []
    by_id: dict[str, Mapping[str, Any]] = {}
    for entry in passports:
        execution_id = str(entry.get("execution_id", ""))
        if execution_id:
            by_id[execution_id] = entry

    for entry in passports:
        claimed = str(entry.get("previous_passport_digest", ""))
        parent_id = str(entry.get("parent_execution_id", ""))
        if not claimed:
            continue
        if not parent_id:
            findings.append(
                Finding(
                    "broken_lineage",
                    f"{entry.get('execution_id')!r} claims a previous digest but "
                    "names no parent execution",
                )
            )
            continue
        parent = by_id.get(parent_id)
        if parent is None:
            findings.append(
                Finding(
                    "missing_parent",
                    f"parent {parent_id!r} was not supplied, so the digest "
                    f"claimed by {entry.get('execution_id')!r} cannot be checked "
                    "-- this is UNKNOWN, not sound",
                )
            )
            continue
        actual = digest_of(parent)
        if actual != claimed:
            findings.append(
                Finding(
                    "broken_lineage",
                    f"{entry.get('execution_id')!r} claims parent digest "
                    f"{claimed[:16]}... but {parent_id!r} hashes to {actual[:16]}...",
                )
            )
    return findings


# ── cli ──────────────────────────────────────────────────────────────────────


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify an Execution Passport against a public key."
    )
    parser.add_argument("--passport", required=True, type=Path)
    parser.add_argument(
        "--key",
        required=True,
        type=Path,
        help='JSON: {"key_id":..., "public_key": <base64 raw Ed25519>, '
        '"not_before":..., "not_after":...}',
    )
    parser.add_argument(
        "--chain",
        type=Path,
        help="JSON array of passport documents to check lineage across",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    findings = verify(_load(args.passport), _load(args.key))
    if args.chain:
        findings.extend(check_chain(_load(args.chain)))

    if not findings:
        print("SOUND: signature verifies and no structural defect found")
        return 0
    for finding in findings:
        print(f"{finding.code}: {finding.detail}")
    print(f"\n{len(findings)} finding(s)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
