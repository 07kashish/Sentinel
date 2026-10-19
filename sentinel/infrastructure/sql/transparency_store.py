"""Durable storage for the transparency log, and for the roots it published.

WHY THE LOG NEEDED STORAGE AT ALL
----------------------------------
`domain/transparency.py` is a pure Merkle structure. Without persistence its
roots could only ever describe whatever happened to be in one process's memory,
and the single question a transparency log exists to answer -- "is this the
same history you showed me last week" -- requires last week's leaves to still
exist.

APPEND-ONLY IS THE DATABASE'S PROPERTY, NOT THIS MODULE'S
----------------------------------------------------------
`(tenant_id, sequence)` is the primary key, so writing a second row at an
occupied position is a constraint violation. This class offers no `update` and
no `delete`; there is no method to remove a leaf, and adding one would require
writing SQL that does not exist here.

That matters more than the usual argument for immutability. A rewritten log is
exactly what `verify_consistency` exists to detect, and a store that could
overwrite a leaf would let an operator rewrite history and then produce a
CONSISTENT-looking log from the new state -- the proof would verify, because
the thing it was checked against had changed too.

PUBLICATION IS RECORDED, WITH ITS SINK
---------------------------------------
`record_publication` writes the root together with WHERE it went. A root stored
with `sink = "none"` proves nothing about the operator, and the column exists
so that fact is visible in the data rather than inferred from its absence.

Publishing a DIFFERENT root at a size already published violates the primary
key. That is a fork, and it is refused here rather than detected later.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sentinel.domain.transparency import MerkleLog

__all__ = [
    "PublishedRoot",
    "SqlTransparencyStore",
    "TransparencyStoreConflict",
]


class TransparencyStoreConflict(RuntimeError):
    """A write that would have rewritten history, or forked it.

    A distinct type because the two callers respond differently: an append
    conflict usually means two workers raced on the same sequence and one
    should retry with a fresh size, while a publication conflict means two
    different roots exist for one tree size -- which is not a race, it is a
    fork, and no retry is correct.
    """


@dataclass(frozen=True, slots=True)
class PublishedRoot:
    """A root that was published, and the evidence of where."""

    tree_size: int
    root_hash: str
    published_at: str
    #: Where it went. `"none"` means it was only ever served by the party that
    #: wrote the log, which proves nothing about that party.
    sink: str = "none"
    #: What the sink returned -- an S3 version id, an object-lock retention
    #: timestamp, a timestamping token. Empty for `"none"`.
    external_reference: str = ""

    @property
    def is_independently_verifiable(self) -> bool:
        """Could a third party check this root without asking the operator?

        The question that decides whether the log is evidence or decoration. A
        sink of `"none"`, or one that returned no reference, means no.
        """
        return self.sink != "none" and bool(self.external_reference.strip())

    def as_dict(self) -> dict[str, Any]:
        return {
            "tree_size": self.tree_size,
            "root_hash": self.root_hash,
            "published_at": self.published_at,
            "sink": self.sink,
            "external_reference": self.external_reference,
            "is_independently_verifiable": self.is_independently_verifiable,
        }


class SqlTransparencyStore:
    """Reads and appends the log for one tenant at a time.

    Takes a pool rather than joining a caller's transaction: a log read must
    not be able to extend, or be rolled back with, the operation that
    triggered it.
    """

    __slots__ = ("_pool",)

    def __init__(self, *, pool: Any) -> None:
        self._pool = pool

    # ── reads ───────────────────────────────────────────────────────────────

    def size(self, tenant_id: str) -> int:
        with self._pool.acquire() as conn:
            # A transaction even for a read: on PostgreSQL `set_tenant` sets a
            # transaction-local setting, so a read outside one would run with
            # no RLS predicate applied -- which is how a tenant-scoped query
            # quietly becomes a cross-tenant one.
            conn.begin()
            conn.set_tenant(tenant_id)
            row = conn.one(
                "SELECT COUNT(*) AS n FROM transparency_leaves "
                f"WHERE tenant_id = {conn.p}",
                (tenant_id,),
            )
            conn.commit()
        return int(row["n"]) if row else 0

    def load(self, tenant_id: str, *, up_to: int | None = None) -> MerkleLog:
        """Rebuild the log from storage, optionally truncated to `up_to` leaves.

        `up_to` is what makes a consistency proof possible: proving that the
        log at size 40 is a prefix of the log at size 900 needs the size-40
        tree, and the only honest way to get it is to rebuild from the same
        leaves rather than to have trusted a stored root.

        ORDER BY sequence, always. A log rebuilt in insertion order would be a
        different tree the moment the storage engine reordered a page, and
        every previously issued proof would stop verifying for no reason
        anybody could explain.
        """
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            if up_to is None:
                rows = conn.execute(
                    "SELECT digest FROM transparency_leaves "
                    f"WHERE tenant_id = {conn.p} ORDER BY sequence ASC",
                    (tenant_id,),
                )
            else:
                rows = conn.execute(
                    "SELECT digest FROM transparency_leaves "
                    f"WHERE tenant_id = {conn.p} AND sequence < {conn.p} "
                    "ORDER BY sequence ASC",
                    (tenant_id, int(up_to)),
                )
            conn.commit()

        return MerkleLog(
            entries=tuple(bytes.fromhex(str(row["digest"])) for row in rows)
        )

    def published_roots(self, tenant_id: str) -> tuple[PublishedRoot, ...]:
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            rows = conn.execute(
                "SELECT tree_size, root_hash, published_at, sink, "
                "external_reference FROM transparency_roots "
                f"WHERE tenant_id = {conn.p} ORDER BY tree_size ASC",
                (tenant_id,),
            )
            conn.commit()
        return tuple(
            PublishedRoot(
                tree_size=int(row["tree_size"]),
                root_hash=str(row["root_hash"]),
                published_at=str(row["published_at"]),
                sink=str(row["sink"]),
                external_reference=str(row["external_reference"]),
            )
            for row in rows
        )

    # ── the one write that adds history ─────────────────────────────────────

    def append(self, tenant_id: str, *, digest: bytes, at: str) -> int:
        """Add one leaf. Returns its sequence.

        The sequence is derived from the current count INSIDE the transaction,
        so two concurrent appends cannot both claim it -- the second violates
        the primary key and raises `TransparencyStoreConflict` rather than
        silently overwriting the first.

        There is deliberately no `append_many`: a batch would have to decide
        what to do when leaf three of five conflicts, and the honest answers
        are "roll back all of it" or "stop and report", both of which the
        caller can build from this.
        """
        if len(digest) != 32:
            raise ValueError(
                f"a leaf is {len(digest)} bytes; every entry must be a 32-byte "
                "SHA-256 digest. A log that accepted arbitrary lengths could "
                "not distinguish a digest from a concatenation of two, which "
                "is the shape the leaf prefix exists to stop."
            )

        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            row = conn.one(
                "SELECT COALESCE(MAX(sequence), -1) AS last FROM "
                f"transparency_leaves WHERE tenant_id = {conn.p}",
                (tenant_id,),
            )
            sequence = (int(row["last"]) if row else -1) + 1
            try:
                conn.execute_rowcount(
                    "INSERT INTO transparency_leaves "
                    "(tenant_id, sequence, digest, appended_at) "
                    f"VALUES ({conn.p},{conn.p},{conn.p},{conn.p})",
                    (tenant_id, sequence, digest.hex(), at),
                )
            except Exception as error:  # noqa: BLE001 - narrowed by the message
                conn.rollback()
                raise TransparencyStoreConflict(
                    f"could not append at sequence {sequence} for tenant "
                    f"{tenant_id!r}: {error}. Another writer almost certainly "
                    "took this position. Re-read the size and retry; do NOT "
                    "overwrite, because an overwritten leaf is a rewritten "
                    "history that would still produce a verifying proof."
                ) from error
            conn.commit()
        return sequence

    def record_publication(
        self,
        tenant_id: str,
        *,
        tree_size: int,
        root_hash: str,
        at: str,
        sink: str = "none",
        external_reference: str = "",
    ) -> None:
        """Record that a root was published, and where.

        A second publication of the SAME root at the same size is accepted as
        a no-op -- republishing after a transient sink failure is ordinary. A
        publication of a DIFFERENT root at a size already published raises:
        that is a fork, and no retry is the right response to one.
        """
        existing = {
            root.tree_size: root for root in self.published_roots(tenant_id)
        }
        already = existing.get(int(tree_size))
        if already is not None:
            if already.root_hash == root_hash:
                return
            raise TransparencyStoreConflict(
                f"tenant {tenant_id!r} already published root "
                f"{already.root_hash} at size {tree_size}, and this call "
                f"publishes {root_hash} at the same size. Two different roots "
                "for one tree size is a FORK, not a race -- refusing rather "
                "than recording both, because a reader given both has no way "
                "to know which history was served to whom."
            )

        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant_id)
            conn.execute_rowcount(
                "INSERT INTO transparency_roots (tenant_id, tree_size, "
                "root_hash, published_at, sink, external_reference) "
                f"VALUES ({conn.p},{conn.p},{conn.p},{conn.p},{conn.p},{conn.p})",
                (
                    tenant_id,
                    int(tree_size),
                    root_hash,
                    at,
                    sink,
                    external_reference,
                ),
            )
            conn.commit()
