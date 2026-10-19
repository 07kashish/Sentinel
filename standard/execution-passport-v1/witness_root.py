#!/usr/bin/env python3
"""Be your own witness to a Sentinel transparency log. Standard library only.

    python witness_root.py https://sentinel.example --token-file token \
        --witness-file acme-roots.jsonl

Run it on a schedule, on a machine the Sentinel operator does not control,
and keep the witness file there. Each run:

1. fetches the current root and tree size;
2. if you have witnessed this log before, fetches a CONSISTENCY PROOF from the
   size you last saw to the current size and VERIFIES IT HERE (RFC 6962,
   section 2.1.2). A log that was rewritten, truncated or forked since your
   last visit cannot produce that proof, and the run fails loudly;
3. appends the new root to your witness file.

A root in your witness file is a root held outside the environment it
describes. Hand it to `verify_evidence_bundle.py --trusted-root` and the
receipts in a bundle are proven to have been in the log as you saw it, no
matter what has happened to Sentinel's database since -- including its loss
and restoration.

Exit 0: witnessed (or unchanged).  Exit 1: THE LOG IS NOT A CONSISTENT
EXTENSION OF WHAT YOU SAW; keep the witness file and escalate.  Exit 2: could
not reach or read the service; nothing was recorded.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

EMPTY_ROOT = hashlib.sha256(b"").hexdigest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def consistent(old_root: bytes, old_size: int, new_root: bytes, new_size: int, proof: list[bytes]) -> bool:
    """Is the log of `old_size` a prefix of the log of `new_size`? RFC 6962 2.1.2."""
    if new_size < old_size:
        return False
    if old_size == new_size:
        return old_root == new_root and not proof
    if old_size == 0:
        return not proof
    nodes = list(proof)
    if not nodes:
        return False
    node, last = old_size - 1, new_size - 1
    while node & 1:
        node >>= 1
        last >>= 1
    if node:
        old_computed = new_computed = nodes.pop(0)
    else:
        old_computed = new_computed = old_root
    while node:
        if node & 1:
            if not nodes:
                return False
            sibling = nodes.pop(0)
            old_computed, new_computed = _node(sibling, old_computed), _node(sibling, new_computed)
        elif node < last:
            if not nodes:
                return False
            new_computed = _node(new_computed, nodes.pop(0))
        node >>= 1
        last >>= 1
    while last:
        if not nodes:
            return False
        new_computed = _node(new_computed, nodes.pop(0))
        last >>= 1
    return not nodes and old_computed == old_root and new_computed == new_root


def last_witnessed(path: Path) -> dict | None:
    if not path.is_file():
        return None
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return json.loads(lines[-1]) if lines else None


def witness(fetch, path: Path) -> tuple[int, str]:
    """`fetch(relative_url) -> dict`. Returns (exit code, message)."""
    current = fetch("/v1/transparency/root")
    size, root = int(current["tree_size"]), str(current["root"])
    previous = last_witnessed(path)
    if previous is not None:
        if size == previous["tree_size"] and root == previous["root"]:
            return 0, f"unchanged at size {size}"
        if previous["tree_size"] > 0:
            if size < previous["tree_size"]:
                return 1, f"THE LOG SHRANK from {previous['tree_size']} to {size} entries"
            answer = fetch(f"/v1/transparency/consistency?old_size={previous['tree_size']}")
            try:
                proof = [bytes.fromhex(node) for node in answer.get("proof", [])]
            except ValueError:
                proof = []
            ok = (answer.get("consistent") is True and answer.get("new_root") == root
                  and consistent(bytes.fromhex(previous["root"]), previous["tree_size"], bytes.fromhex(root), size, proof))
            if not ok:
                return 1, (f"THE LOG AT SIZE {size} IS NOT AN EXTENSION OF THE ROOT YOU WITNESSED AT SIZE "
                           f"{previous['tree_size']}; it was rewritten or forked")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"tree_size": size, "root": root,
                                 "witnessed_at": datetime.now(timezone.utc).isoformat()}) + "\n")
    return 0, f"witnessed size {size} root {root[:16]}..."


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("base_url")
    parser.add_argument("--token-file", type=Path, required=True, help="a file holding a read-capable API token")
    parser.add_argument("--witness-file", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        token = args.token_file.read_text(encoding="utf-8").strip()
    except OSError as exc:
        print(f"cannot read the token file: {exc}", file=sys.stderr)
        return 2

    def fetch(relative: str) -> dict:
        request = urllib.request.Request(args.base_url.rstrip("/") + relative, headers={"Authorization": "Bearer " + token})
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - operator-supplied URL
            return json.load(response)

    try:
        code, message = witness(fetch, args.witness_file)
    except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
        print(f"could not witness: {type(exc).__name__}", file=sys.stderr)
        return 2
    print(message)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
