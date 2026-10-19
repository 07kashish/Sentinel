"""An append-only log of passport digests, and proofs about what it contains.

WHAT THIS ADDS THAT A SIGNATURE DOES NOT
------------------------------------------
A signed passport proves the record was not modified. It cannot prove the
record was not DELETED, because a deletion leaves nothing to check. Nor can it
prove that two readers were shown the same history: a server can hand one
auditor a log containing an execution and another a log without it, and both
copies verify perfectly on their own.

So a signature answers "is this record intact" and a transparency log answers
"is this the whole story, and is it the same story you were told". Those are
different questions and the second is the one an auditor actually asks.

THREE PROPERTIES, AND WHAT EACH CATCHES
-----------------------------------------
1. INCLUSION. A proof that one digest sits at one position under a root. Catches
   a passport being quietly dropped: the proof no longer verifies against the
   root the operator publishes.

2. CONSISTENCY. A proof that an older root is a prefix of a newer one. This is
   the property that catches a FORK -- a server that rewrote history produces a
   new root with no consistency proof from the old one, and no amount of
   re-signing manufactures one.

3. APPEND-ONLY. Enforced structurally rather than by policy: `append` returns a
   new log and `MerkleLog` is frozen, so there is no method that edits an
   existing entry. A caller who wants to rewrite history has to construct a
   different log, and then the consistency proof fails.

RFC 6962 HASHING, AND WHY THE PREFIXES MATTER
-----------------------------------------------
Leaves are hashed with a `0x00` prefix and internal nodes with `0x01`. Without
those, a leaf whose value happens to equal a concatenation of two hashes could
be presented as an internal node -- the second-preimage attack that Certificate
Transparency's design exists to prevent. It costs one byte and closes an entire
class of forgery, so it is not optional here either.

WHAT THIS IS NOT
----------------
Not a service, not a gossip protocol, not a blockchain. It is the data structure
and the proofs, kept pure so "can this log have been rewritten" is answerable by
reading one file and running its tests.

A real deployment still needs somewhere to publish roots that the operator
cannot silently change -- S3 Object Lock, a WORM store, an external
timestamping service, or an optional blockchain anchor. **A transparency log
whose roots are only ever served by the same party that writes the log proves
nothing about that party.** That is stated here rather than left implied,
because the structure is the easy half.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Sequence

__all__ = [
    "ConsistencyFailure",
    "InclusionProof",
    "MerkleLog",
    "ProofFailure",
    "empty_root",
    "verify_consistency",
    "verify_inclusion",
]

#: RFC 6962 domain separation. One byte, and it closes the second-preimage
#: attack where a leaf is presented as an internal node.
_LEAF = b"\x00"
_NODE = b"\x01"


def _leaf_hash(digest: bytes) -> bytes:
    return hashlib.sha256(_LEAF + digest).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_NODE + left + right).digest()


def empty_root() -> bytes:
    """The root of a log with nothing in it.

    SHA-256 of the empty string, per RFC 6962. Defined rather than left
    undefined because "the log is empty" and "the log has been emptied" must
    produce the same root -- otherwise an operator could claim a fresh log to
    explain away a deletion.
    """
    return hashlib.sha256(b"").digest()


class ProofFailure(str, Enum):
    """Why an inclusion proof does not verify."""

    WRONG_ROOT = "wrong_root"
    INDEX_OUT_OF_RANGE = "index_out_of_range"
    MALFORMED_PATH = "malformed_path"
    EMPTY_LOG = "empty_log"


class ConsistencyFailure(str, Enum):
    """Why two roots are not consistent.

    `FORKED` is the finding that matters. The others are input errors; this one
    means somebody rewrote history.
    """

    FORKED = "forked"
    SHRANK = "shrank"
    MALFORMED_PATH = "malformed_path"


@dataclass(frozen=True, slots=True)
class InclusionProof:
    """One entry, its position, and the sibling hashes above it.

    `tree_size` is part of the proof rather than looked up. A Merkle path is
    only meaningful against a tree of a known size -- the same path can verify
    against two different roots at two different sizes, so omitting it would let
    a proof be replayed against a later tree that no longer contains the entry.
    """

    index: int
    tree_size: int
    #: Sibling hashes, leaf-adjacent first.
    path: tuple[bytes, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "index": self.index,
            "tree_size": self.tree_size,
            "path": [h.hex() for h in self.path],
        }


@dataclass(frozen=True, slots=True)
class MerkleLog:
    """An append-only log of digests.

    FROZEN, and `append` returns a new log. There is deliberately no method
    that edits an entry: append-only is a structural property here, not a rule
    somebody has to remember. A caller who wants to rewrite history must build
    a different log, and `verify_consistency` then refuses it.
    """

    entries: tuple[bytes, ...] = field(default=())

    def __post_init__(self) -> None:
        for position, digest in enumerate(self.entries):
            if len(digest) != 32:
                raise ValueError(
                    f"entry {position} is {len(digest)} bytes; every entry must "
                    "be a 32-byte SHA-256 digest. A log that accepts arbitrary "
                    "lengths cannot distinguish a digest from a concatenation "
                    "of two, which is the shape the leaf prefix exists to stop."
                )

    def append(self, digest: bytes) -> "MerkleLog":
        return MerkleLog(entries=self.entries + (digest,))

    def extend(self, digests: Iterable[bytes]) -> "MerkleLog":
        return MerkleLog(entries=self.entries + tuple(digests))

    @property
    def size(self) -> int:
        return len(self.entries)

    def root(self) -> bytes:
        """The Merkle Tree Hash of the whole log."""
        return _root_of(self.entries)

    def inclusion_proof(self, index: int) -> InclusionProof:
        """The path proving `entries[index]` is in this log."""
        if not 0 <= index < self.size:
            raise IndexError(
                f"index {index} is outside a log of {self.size} entries"
            )
        return InclusionProof(
            index=index,
            tree_size=self.size,
            path=tuple(_inclusion_path(self.entries, index)),
        )

    def consistency_proof(self, old_size: int) -> tuple[bytes, ...]:
        """The nodes proving a log of `old_size` is a prefix of this one."""
        if not 0 <= old_size <= self.size:
            raise ValueError(
                f"cannot prove consistency with size {old_size} from a log of "
                f"{self.size}: a log never shrinks, so this is either a "
                "corrupted record of the old size or evidence of a rewrite"
            )
        if old_size == 0:
            # RFC 6962 section 2.1.2: PROOF(0, D[n]) is empty, because every
            # log is consistent with the empty log and there is nothing to
            # send. Stated here rather than left to `_subproof`, which has no
            # base case for it: descending towards a subtree of size zero
            # never arrives, because `_split_point(1)` is 1 and `entries[:1]`
            # is the same tree again. `consistency_proof(0)` on any non-empty
            # log recursed until the interpreter gave up.
            return ()
        return tuple(_consistency_path(self.entries, old_size))


def _root_of(entries: Sequence[bytes]) -> bytes:
    if not entries:
        return empty_root()
    if len(entries) == 1:
        return _leaf_hash(entries[0])
    split = _split_point(len(entries))
    return _node_hash(_root_of(entries[:split]), _root_of(entries[split:]))


def _split_point(size: int) -> int:
    """The largest power of two strictly less than `size`.

    RFC 6962's split, not `size // 2`. The difference is what makes a proof
    from a tree of size 5 verify against the same structure when the tree grows
    to 6 -- a balanced split would reshape the whole tree on every append and
    invalidate every previously issued proof.
    """
    power = 1
    while power * 2 < size:
        power *= 2
    return power


def _inclusion_path(entries: Sequence[bytes], index: int) -> list[bytes]:
    if len(entries) <= 1:
        return []
    split = _split_point(len(entries))
    if index < split:
        return _inclusion_path(entries[:split], index) + [_root_of(entries[split:])]
    return _inclusion_path(entries[split:], index - split) + [_root_of(entries[:split])]


def _consistency_path(entries: Sequence[bytes], old_size: int) -> list[bytes]:
    """RFC 6962 PROOF(m, D[n]) = SUBPROOF(m, D[n], true).

    The `complete` flag is the part that is easy to get wrong and that I did
    get wrong: it records whether the old tree is exactly the subtree being
    descended into. When it is, the old root is NOT included in the path,
    because the verifier already holds it. When it is not, the subtree root
    must be sent so the verifier can rebuild the old root from it.

    Dropping that distinction produces proofs that verify for no input at all.
    """
    return _subproof(entries, old_size, complete=True)


def _subproof(
    entries: Sequence[bytes], old_size: int, *, complete: bool
) -> list[bytes]:
    size = len(entries)
    if old_size == size:
        # The old tree IS this subtree. Send its root only when the verifier
        # does not already have it.
        return [] if complete else [_root_of(entries)]

    split = _split_point(size)
    if old_size <= split:
        return _subproof(entries[:split], old_size, complete=complete) + [
            _root_of(entries[split:])
        ]
    return _subproof(entries[split:], old_size - split, complete=False) + [
        _root_of(entries[:split])
    ]


def verify_inclusion(
    *,
    digest: bytes,
    proof: InclusionProof,
    root: bytes,
) -> ProofFailure | None:
    """Does `digest` sit at `proof.index` in a tree of `proof.tree_size`?

    Returns None when it does, and a named failure when it does not.
    Deliberately not a boolean: "the proof failed" and "the entry was deleted
    from a tree that has since grown" call for different responses, and a
    caller that only sees False cannot tell them apart.
    """
    if proof.tree_size == 0:
        return ProofFailure.EMPTY_LOG
    if not 0 <= proof.index < proof.tree_size:
        return ProofFailure.INDEX_OUT_OF_RANGE

    expected_depth = _path_length(proof.tree_size, proof.index)
    if len(proof.path) != expected_depth:
        # A path of the wrong length cannot be evaluated safely: padding or
        # truncating it would let a forger choose a depth that happens to
        # produce the target root.
        return ProofFailure.MALFORMED_PATH

    # Two walks in opposite directions, deliberately separated.
    #
    # The descent that decides orientation runs TOP-DOWN: at each level the
    # tree is split and the index tells you which half holds the entry. The
    # fold that combines hashes runs BOTTOM-UP: a leaf pairs with its nearest
    # sibling first, and `path` is ordered leaf-adjacent first to match.
    #
    # Doing both in one loop was the bug here. It applied the OUTERMOST
    # orientation to the INNERMOST sibling, which is correct only when the
    # entry is a left child at every level -- so index 0 verified in every
    # tree and indices 1, 3, 4, 6 did not. A single loop looks like the
    # obvious implementation and passes the first test anyone writes.
    entry_in_left_half: list[bool] = []
    index, size = proof.index, proof.tree_size
    while size > 1:
        split = _split_point(size)
        if index < split:
            entry_in_left_half.append(True)
            size = split
        else:
            entry_in_left_half.append(False)
            index -= split
            size -= split

    computed = _leaf_hash(digest)
    for sibling, on_left in zip(proof.path, reversed(entry_in_left_half)):
        computed = (
            _node_hash(computed, sibling)
            if on_left
            else _node_hash(sibling, computed)
        )

    return None if computed == root else ProofFailure.WRONG_ROOT


def _path_length(size: int, index: int) -> int:
    if size <= 1:
        return 0
    split = _split_point(size)
    if index < split:
        return _path_length(split, index) + 1
    return _path_length(size - split, index - split) + 1


def verify_consistency(
    *,
    old_root: bytes,
    old_size: int,
    new_root: bytes,
    new_size: int,
    proof: Sequence[bytes],
) -> ConsistencyFailure | None:
    """Is the log of `old_size` a prefix of the log of `new_size`?

    THIS IS THE CHECK THAT CATCHES A REWRITE. An operator who removed an entry,
    reordered two, or served a second history cannot produce a proof that the
    old root is a prefix of the new one -- the mathematics does not admit it,
    and re-signing does not help.

    The algorithm is RFC 6962 section 2.1.2, walked bit by bit over the index of
    the last old entry. It reconstructs BOTH roots from the same nodes; that
    simultaneous reconstruction is what "is a prefix of" means structurally, and
    it is why a forged proof cannot satisfy it -- one root can be forced, not
    both.
    """
    if new_size < old_size:
        return ConsistencyFailure.SHRANK
    if old_size == 0:
        # Every log extends the empty log. Verifying nothing is correct, and is
        # why `empty_root()` is defined: an operator cannot claim a fresh start
        # to explain a deletion, because the root they published was not empty.
        #
        # The old root and the proof are still checked for SHAPE. A caller who
        # presents a non-empty root at size zero is describing a log that
        # cannot exist, and a proof with nodes in it does not describe this
        # pair of sizes -- accepting either would let "I started from nothing"
        # be asserted with material the walk never examines.
        if old_root != empty_root():
            return ConsistencyFailure.FORKED
        if len(proof):
            return ConsistencyFailure.MALFORMED_PATH
        return None
    if old_size == new_size:
        return None if old_root == new_root else ConsistencyFailure.FORKED

    nodes = list(proof)
    if not nodes:
        return ConsistencyFailure.MALFORMED_PATH

    node, last = old_size - 1, new_size - 1

    # Climb out of any right-child positions. Those levels are already fully
    # determined by the old tree, so the proof carries nothing for them.
    while node & 1:
        node >>= 1
        last >>= 1

    if node:
        # The old tree is not a complete subtree, so the proof opens with the
        # node the verifier needs in order to rebuild the old root.
        first = nodes.pop(0)
        old_computed = first
        new_computed = first
    else:
        # It is a complete subtree: the verifier already holds its root.
        old_computed = old_root
        new_computed = old_root

    while node:
        if node & 1:
            if not nodes:
                return ConsistencyFailure.MALFORMED_PATH
            sibling = nodes.pop(0)
            old_computed = _node_hash(sibling, old_computed)
            new_computed = _node_hash(sibling, new_computed)
        elif node < last:
            if not nodes:
                return ConsistencyFailure.MALFORMED_PATH
            sibling = nodes.pop(0)
            new_computed = _node_hash(new_computed, sibling)
        node >>= 1
        last >>= 1

    # Whatever remains extends the new tree beyond the old one.
    while last:
        if not nodes:
            return ConsistencyFailure.MALFORMED_PATH
        sibling = nodes.pop(0)
        new_computed = _node_hash(new_computed, sibling)
        last >>= 1

    if nodes:
        # Unused nodes mean the proof does not describe this pair of sizes.
        # Accepting it would let a forger append material the walk ignores.
        return ConsistencyFailure.MALFORMED_PATH
    if old_computed != old_root or new_computed != new_root:
        return ConsistencyFailure.FORKED
    return None
