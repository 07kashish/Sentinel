#!/usr/bin/env python3
"""Verify a Sentinel evidence bundle with nothing from Sentinel. Standard library only.

    python verify_evidence_bundle.py bundle.json \
        --trusted-root <hex> --trusted-size <n>

WHAT IS CHECKED, FOR EVERY ENTRY
--------------------------------
1. The leaf is recomputed from the receipt's own fields (canonical JSON,
   SHA-256). A receipt edited after it was committed fails here.
2. The inclusion proof is walked from that leaf to the bundle's root
   (RFC 6962 hashing: 0x00 leaves, 0x01 nodes). A receipt that was never in
   the log, or a proof for another tree size, fails here.
3. If a trusted root is given, the bundle's root and tree size must equal it.

WHY THE TRUSTED ROOT MATTERS
----------------------------
Without it this proves the bundle is internally consistent, which an operator
who rewrote the whole log could also produce. With a root YOU obtained from
somewhere the operator cannot rewrite -- the object-lock bucket the roots are
published to, a copy in your SIEM, a printout -- it proves these receipts are
in the log as it stood then. Keep that root outside the environment it
describes; that is what makes the evidence survive the loss of it.

Exit 0: every entry verified (and the root matched, if one was given).
Exit 1: something failed; each failure is printed.   Exit 2: unreadable input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys

FIELDS = (
    "receipt_id", "authorization_id", "authorization_digest", "executed_request_digest",
    "approved_parameter_digest", "actual_parameter_digest", "delegation_passport_digest",
    "execution_identity", "side_effect", "outcome", "started_at", "completed_at",
)


def leaf_digest(tenant_id: str, receipt: dict) -> bytes:
    material = {"tenant_id": tenant_id, **{f: str(receipt.get(f, "") or "") for f in FIELDS}}
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).digest()


def _split(size: int) -> int:
    split = 1
    while split * 2 < size:
        split *= 2
    return split


def root_from_proof(digest: bytes, index: int, size: int, path: list[bytes]) -> bytes | None:
    if size <= 0 or not 0 <= index < size:
        return None
    sides = []
    while size > 1:
        split = _split(size)
        if index < split:
            sides.append(True)
            size = split
        else:
            sides.append(False)
            index -= split
            size -= split
    if len(sides) != len(path):
        return None
    computed = hashlib.sha256(b"\x00" + digest).digest()
    for sibling, on_left in zip(path, reversed(sides)):
        computed = hashlib.sha256(b"\x01" + (computed + sibling if on_left else sibling + computed)).digest()
    return computed


def verify(bundle: dict, trusted_root: str = "", trusted_size: int | None = None) -> list[str]:
    failures: list[str] = []
    tenant, root, size = bundle.get("tenant_id", ""), bundle.get("root", ""), int(bundle.get("tree_size", 0))
    if trusted_root:
        if root != trusted_root.lower() or (trusted_size is not None and size != trusted_size):
            failures.append("the bundle's root or tree size is not the trusted one; the log was extended or rewritten")
    for entry in bundle.get("entries", []):
        receipt = entry.get("receipt", {})
        name = receipt.get("receipt_id", "?")
        digest = leaf_digest(tenant, receipt)
        if digest.hex() != entry.get("leaf_digest"):
            failures.append(f"{name}: the receipt does not hash to its committed leaf; it was altered")
            continue
        proof = entry.get("proof", {})
        try:
            path = [bytes.fromhex(h) for h in proof.get("path", [])]
        except ValueError:
            failures.append(f"{name}: malformed proof")
            continue
        computed = root_from_proof(digest, int(proof.get("index", -1)), int(proof.get("tree_size", 0)), path)
        if int(proof.get("tree_size", 0)) != size or computed is None or computed.hex() != root:
            failures.append(f"{name}: the inclusion proof does not reach the bundle's root")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("bundle")
    parser.add_argument("--trusted-root", default="")
    parser.add_argument("--trusted-size", type=int, default=None)
    args = parser.parse_args(argv)
    try:
        with open(args.bundle, encoding="utf-8") as handle:
            bundle = json.load(handle)
    except (OSError, ValueError) as exc:
        print(f"cannot read the bundle: {exc}", file=sys.stderr)
        return 2
    failures = verify(bundle, args.trusted_root, args.trusted_size)
    for failure in failures:
        print("FAIL  " + failure)
    checked = len(bundle.get("entries", []))
    anchored = "against the trusted root" if args.trusted_root else "INTERNALLY ONLY (no trusted root given)"
    print(f"{checked - len(failures)} of {checked} receipts verified {anchored}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
