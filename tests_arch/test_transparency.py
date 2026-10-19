"""A signature proves a record was not modified. This proves none was deleted.

WHAT IS BEING PROVEN
--------------------
A signed passport cannot show that a passport was DROPPED -- a deletion leaves
nothing to check. Nor can it show two auditors were given the same history: a
server can serve one log containing an execution and another without it, and
both copies verify perfectly on their own.

So these tests are about the two things a signature cannot do:

  * an entry cannot be removed without the inclusion proof breaking;
  * a history cannot be rewritten without the consistency proof breaking.

The second is the one that matters. It is the only check in the system that
catches an operator serving two different pasts.
"""

from __future__ import annotations

import hashlib

import pytest

from sentinel.domain.transparency import (
    ConsistencyFailure,
    MerkleLog,
    ProofFailure,
    empty_root,
    verify_consistency,
    verify_inclusion,
)


def _d(label: str) -> bytes:
    """A 32-byte digest, as a passport digest would be."""
    return hashlib.sha256(label.encode()).digest()


def _log(count: int) -> MerkleLog:
    return MerkleLog().extend(_d(f"passport-{n}") for n in range(count))


# ── the structure ────────────────────────────────────────────────────────────


def test_an_empty_log_has_a_defined_root():
    """Defined rather than undefined, so an operator cannot claim a fresh log
    to explain away a deletion: the root they published earlier was not this.
    """
    assert MerkleLog().root() == empty_root()
    assert MerkleLog().size == 0


def test_the_log_is_append_only_by_construction():
    """Not a rule somebody has to remember.

    `append` returns a NEW log and the dataclass is frozen, so there is no
    method that edits an entry. Rewriting history requires building a different
    log -- and `verify_consistency` then refuses it.
    """
    log = _log(3)
    grown = log.append(_d("passport-3"))

    assert log.size == 3, "append mutated the original"
    assert grown.size == 4
    with pytest.raises(Exception):
        log.entries = ()  # type: ignore[misc]


def test_an_entry_that_is_not_a_sha256_digest_is_refused():
    """A log accepting arbitrary lengths cannot distinguish a digest from a
    concatenation of two, which is the shape the leaf prefix exists to stop.
    """
    with pytest.raises(ValueError) as raised:
        MerkleLog(entries=(b"short",))
    assert "32-byte" in str(raised.value)


def test_leaves_and_nodes_are_domain_separated():
    """RFC 6962's one-byte prefixes.

    Without them, a leaf whose value equals a concatenation of two hashes could
    be presented as an internal node. This checks the prefixes are actually
    applied rather than trusting the comment that says they are: a single-entry
    root must be the LEAF hash, not the bare digest.
    """
    digest = _d("only")
    root = MerkleLog(entries=(digest,)).root()

    assert root != digest, "the leaf prefix is not being applied"
    assert root == hashlib.sha256(b"\x00" + digest).digest()


def test_the_node_prefix_is_applied_and_differs_from_the_leaf_prefix():
    """The half the test above does not reach.

    That test builds a ONE-ENTRY log, which has no internal node -- so setting
    `_NODE` equal to `_LEAF` left it passing. A mutation run caught it: the
    test's name promised domain separation and its body only checked the leaf
    side. Two entries are the smallest tree containing an internal node, so
    this is where the node prefix becomes observable at all.
    """
    left, right = _d("a"), _d("b")
    leaf_l = hashlib.sha256(b"\x00" + left).digest()
    leaf_r = hashlib.sha256(b"\x00" + right).digest()
    root = MerkleLog(entries=(left, right)).root()

    assert root == hashlib.sha256(b"\x01" + leaf_l + leaf_r).digest()
    assert root != hashlib.sha256(b"\x00" + leaf_l + leaf_r).digest(), (
        "an internal node hashes identically to a leaf, which is exactly the "
        "second-preimage confusion the two prefixes exist to prevent"
    )


# ── inclusion ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("size", [1, 2, 3, 4, 5, 7, 8, 9, 16, 33, 100])
def test_every_entry_in_a_log_of_any_size_proves_its_own_inclusion(size):
    """Sizes that are not powers of two are the interesting ones: RFC 6962's
    split is the largest power of two BELOW the size, not the midpoint, and a
    midpoint split would reshape the tree on every append.
    """
    log = _log(size)
    root = log.root()
    for index in range(size):
        proof = log.inclusion_proof(index)
        assert verify_inclusion(
            digest=log.entries[index], proof=proof, root=root
        ) is None, f"entry {index} of {size} failed to prove inclusion"


def test_a_digest_that_is_not_in_the_log_does_not_verify():
    log = _log(8)
    proof = log.inclusion_proof(3)
    assert verify_inclusion(
        digest=_d("never-appended"), proof=proof, root=log.root()
    ) is ProofFailure.WRONG_ROOT


def test_a_proof_replayed_against_a_later_root_does_not_verify():
    """THE deletion check.

    An operator who drops an entry publishes a new root. The proofs they issued
    against the old root stop verifying against the new one -- which is how an
    auditor holding an old proof learns the log changed underneath them.
    """
    log = _log(8)
    proof = log.inclusion_proof(2)
    digest = log.entries[2]

    # A log with entry 2 removed.
    rewritten = MerkleLog(entries=log.entries[:2] + log.entries[3:])

    assert verify_inclusion(digest=digest, proof=proof, root=log.root()) is None
    assert verify_inclusion(
        digest=digest, proof=proof, root=rewritten.root()
    ) is ProofFailure.WRONG_ROOT


def test_reordering_two_entries_breaks_inclusion():
    """A reorder changes no digest and changes the root. Nothing else in the
    system would notice it.
    """
    log = _log(6)
    swapped = MerkleLog(
        entries=log.entries[:2] + (log.entries[3], log.entries[2]) + log.entries[4:]
    )
    assert swapped.root() != log.root()

    proof = log.inclusion_proof(2)
    assert verify_inclusion(
        digest=log.entries[2], proof=proof, root=swapped.root()
    ) is ProofFailure.WRONG_ROOT


def test_a_path_of_the_wrong_length_is_refused_rather_than_padded():
    """Padding or truncating would let a forger pick a depth that happens to
    produce the target root.
    """
    log = _log(8)
    proof = log.inclusion_proof(3)
    truncated = type(proof)(
        index=proof.index, tree_size=proof.tree_size, path=proof.path[:-1]
    )
    assert verify_inclusion(
        digest=log.entries[3], proof=truncated, root=log.root()
    ) is ProofFailure.MALFORMED_PATH


def test_an_index_outside_the_tree_is_named_rather_than_returning_false():
    log = _log(4)
    proof = log.inclusion_proof(1)
    bad = type(proof)(index=99, tree_size=proof.tree_size, path=proof.path)
    assert verify_inclusion(
        digest=log.entries[1], proof=bad, root=log.root()
    ) is ProofFailure.INDEX_OUT_OF_RANGE


def test_an_empty_log_proves_nothing_and_says_so():
    proof = MerkleLog(entries=(_d("x"),)).inclusion_proof(0)
    empty = type(proof)(index=0, tree_size=0, path=())
    assert verify_inclusion(
        digest=_d("x"), proof=empty, root=empty_root()
    ) is ProofFailure.EMPTY_LOG


def test_the_tree_size_is_part_of_the_proof():
    """A Merkle path is only meaningful against a tree of a known size.

    Omitting it would let the same path verify against a later tree that no
    longer contains the entry.
    """
    proof = _log(8).inclusion_proof(3)
    assert proof.tree_size == 8
    assert "tree_size" in proof.as_dict()


# ── consistency: the fork check ──────────────────────────────────────────────


@pytest.mark.parametrize(
    "old,new",
    [(1, 2), (1, 8), (2, 3), (3, 4), (4, 8), (5, 9), (7, 8), (8, 16), (6, 100)],
)
def test_a_log_that_only_grew_is_consistent(old, new):
    grown = _log(new)
    older = MerkleLog(entries=grown.entries[:old])

    assert verify_consistency(
        old_root=older.root(),
        old_size=old,
        new_root=grown.root(),
        new_size=new,
        proof=grown.consistency_proof(old),
    ) is None, f"a log that grew from {old} to {new} was reported inconsistent"


def test_a_rewritten_history_cannot_produce_a_consistency_proof():
    """THE property that catches a fork.

    An operator who removed an entry and re-signed everything still cannot show
    the old root is a prefix of the new one. The mathematics does not admit it.
    """
    original = _log(8)
    old_root = MerkleLog(entries=original.entries[:5]).root()

    # Entry 1 replaced -- a rewrite, not an append.
    forked = MerkleLog(
        entries=original.entries[:1] + (_d("substituted"),) + original.entries[2:]
    )

    failure = verify_consistency(
        old_root=old_root,
        old_size=5,
        new_root=forked.root(),
        new_size=8,
        proof=forked.consistency_proof(5),
    )
    assert failure is ConsistencyFailure.FORKED


def test_two_different_histories_served_to_two_readers_are_detectable():
    """The split-view attack, which a signature cannot see at all.

    Both logs verify perfectly in isolation. Only comparing roots and demanding
    a consistency proof reveals that they diverge.
    """
    shared = _log(4)
    left = shared.append(_d("shown-to-auditor-a"))
    right = shared.append(_d("shown-to-auditor-b"))

    assert left.root() != right.root()
    # Neither is a prefix of the other, so no proof reconciles them.
    failure = verify_consistency(
        old_root=left.root(),
        old_size=5,
        new_root=right.root(),
        new_size=5,
        proof=(),
    )
    assert failure is ConsistencyFailure.FORKED


def test_a_log_that_shrank_is_refused():
    """A log never shrinks. This is either a corrupted record of the old size
    or evidence of a rewrite, and both deserve a name.
    """
    assert verify_consistency(
        old_root=_log(8).root(),
        old_size=8,
        new_root=_log(3).root(),
        new_size=3,
        proof=(),
    ) is ConsistencyFailure.SHRANK


def test_every_log_extends_the_empty_log():
    """Verifying nothing here is correct, and is why `empty_root` is defined.

    An operator cannot claim a fresh start to explain a deletion, because the
    root they published earlier was not the empty root.
    """
    assert verify_consistency(
        old_root=empty_root(),
        old_size=0,
        new_root=_log(5).root(),
        new_size=5,
        proof=(),
    ) is None


def test_an_unchanged_log_is_consistent_with_itself():
    log = _log(6)
    assert verify_consistency(
        old_root=log.root(),
        old_size=6,
        new_root=log.root(),
        new_size=6,
        proof=log.consistency_proof(6),
    ) is None


def test_the_same_size_with_a_different_root_is_a_fork():
    """Same length, different content. Only the root comparison catches it."""
    assert verify_consistency(
        old_root=_log(4).root(),
        old_size=4,
        new_root=MerkleLog().extend(_d(f"other-{n}") for n in range(4)).root(),
        new_size=4,
        proof=(),
    ) is ConsistencyFailure.FORKED


def test_a_missing_proof_is_not_silently_accepted():
    grown = _log(8)
    assert verify_consistency(
        old_root=MerkleLog(entries=grown.entries[:3]).root(),
        old_size=3,
        new_root=grown.root(),
        new_size=8,
        proof=(),
    ) is ConsistencyFailure.MALFORMED_PATH


def test_a_consistency_proof_with_nodes_left_over_is_refused():
    """Unused nodes mean the proof does not describe this pair of sizes.

    Nothing tested this until a mutation run tolerated leftover nodes and the
    whole suite still passed. It matters because the walk is driven by the two
    SIZES, not by the proof's length: a forger who appends material the walk
    never reads would otherwise get a proof accepted with attacker-chosen
    trailing content.
    """
    grown = _log(8)
    genuine = grown.consistency_proof(3)

    assert verify_consistency(
        old_root=MerkleLog(entries=grown.entries[:3]).root(),
        old_size=3,
        new_root=grown.root(),
        new_size=8,
        proof=genuine + (_d("appended-by-a-forger"),),
    ) is ConsistencyFailure.MALFORMED_PATH


def test_proving_consistency_with_an_impossible_size_raises():
    with pytest.raises(ValueError) as raised:
        _log(4).consistency_proof(9)
    assert "never shrinks" in str(raised.value)


# ── the honest limit ─────────────────────────────────────────────────────────


def test_the_module_states_that_self_served_roots_prove_nothing():
    """The structure is the easy half.

    A log whose roots are only ever published by the same party that writes it
    proves nothing about that party. Left implied, somebody would ship the data
    structure and call the problem solved.
    """
    import inspect

    from sentinel.domain import transparency

    # Whitespace-normalised: the sentence wraps in the source, and a literal
    # substring search would fail on the line break rather than on the claim
    # being absent -- a test that breaks when the prose is reflowed is a test
    # about formatting.
    doc = " ".join((inspect.getdoc(transparency) or "").split())
    assert "proves nothing about that party" in doc
    assert "Object Lock" in doc or "WORM" in doc


def test_the_module_holds_no_mutable_state():
    import types

    from sentinel.domain import transparency

    mutable = [
        name
        for name, value in vars(transparency).items()
        if not name.startswith("__")
        and isinstance(value, (dict, list, set))
        and not isinstance(value, types.MappingProxyType)
    ]
    assert not mutable, f"module-level mutable state: {mutable}"


# ── consistency with the empty log: the recursion that never returned ────────


@pytest.mark.parametrize("size", [1, 2, 3, 4, 5, 8, 9])
def test_a_consistency_proof_from_the_empty_log_is_empty_and_terminates(size):
    """`consistency_proof(0)` recursed forever on every non-empty log.

    `_subproof` had no base case for an old size of zero: descending towards a
    zero-sized subtree of a one-entry tree re-entered the same one-entry tree,
    because `_split_point(1)` is 1. RFC 6962 says PROOF(0, D[n]) is empty --
    every log extends the empty log -- and that is what is asserted here,
    together with the verifier accepting it against the defined empty root.
    """
    log = _log(size)

    proof = log.consistency_proof(0)

    assert proof == ()
    assert verify_consistency(
        old_root=empty_root(),
        old_size=0,
        new_root=log.root(),
        new_size=size,
        proof=proof,
    ) is None


def test_the_empty_log_is_consistent_with_itself():
    empty = MerkleLog()
    assert empty.consistency_proof(0) == ()
    assert verify_consistency(
        old_root=empty_root(),
        old_size=0,
        new_root=empty.root(),
        new_size=0,
        proof=(),
    ) is None


def test_claiming_an_empty_start_with_a_non_empty_root_is_a_fork():
    """The empty log has exactly one root. A caller who presents some other
    root at size zero is describing a history that never existed, and letting
    it through would make "I started from nothing" a way to launder a deletion.
    """
    assert verify_consistency(
        old_root=_log(3).root(),
        old_size=0,
        new_root=_log(5).root(),
        new_size=5,
        proof=(),
    ) is ConsistencyFailure.FORKED


def test_a_non_empty_proof_for_the_empty_log_is_malformed():
    assert verify_consistency(
        old_root=empty_root(),
        old_size=0,
        new_root=_log(5).root(),
        new_size=5,
        proof=(_log(5).root(),),
    ) is ConsistencyFailure.MALFORMED_PATH
