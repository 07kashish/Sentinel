"""Where a transparency root goes so the operator cannot change it afterwards.

THE HALF THAT IS NOT MATHEMATICS
--------------------------------
The Merkle log detects deletion, reordering and forked histories. All of that
holds against everyone EXCEPT the party that runs the log, because that party
serves both the history and the root you check it against. Rewrite both and
every proof verifies.

Closing that requires putting the root somewhere its writer cannot later alter:
S3 with Object Lock in compliance mode, a WORM appliance, an RFC 3161
timestamping authority, a public transparency service, or a blockchain anchor.
Which one is a deployment decision with cost and jurisdiction attached, so this
module defines the CONTRACT and refuses by default rather than choosing.

WHY THE DEFAULT REFUSES INSTEAD OF WRITING LOCALLY
---------------------------------------------------
A local file sink would be the obvious "something is better than nothing", and
it is worse than nothing: it produces a `sink` value and an
`external_reference` that make `is_independently_verifiable` return True while
the file sits on a disk the operator owns. The flag would then mean nothing, and
a flag that means nothing is read as if it meant something.

So `RefusingRootSink` raises, publication does not happen, and
`/v1/transparency/root` keeps answering `independently_verifiable: false` with
a reason naming what is missing. An honest "not yet" beats a green tick.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

__all__ = [
    "PublicationReceipt",
    "RefusingRootSink",
    "RootSink",
    "RootSinkUnavailable",
]


class RootSinkUnavailable(RuntimeError):
    """The root could not be published. NOT a successful publication.

    A distinct exception so a caller cannot mistake failure for success by
    ignoring a return value. The transparency store records only what a sink
    actually confirmed, so a raise here leaves the root unpublished and the
    verifiability flag false -- which is the truth.
    """


@dataclass(frozen=True, slots=True)
class PublicationReceipt:
    """What a sink returned, and what a third party can do with it.

    `reference` is required and must be something a third party can FETCH: an
    S3 version id, a timestamp token, a transaction hash. A sink that returned
    only "ok" has given the operator a word, not evidence, and
    `SqlTransparencyStore.record_publication` would store that word as though
    it were checkable.
    """

    sink: str
    reference: str
    published_at: str

    def __post_init__(self) -> None:
        if not self.sink.strip() or self.sink == "none":
            raise ValueError(
                "a receipt must name a real sink. 'none' is the value the "
                "store uses for an UNPUBLISHED root, so a receipt claiming it "
                "would record an absence as a publication."
            )
        if not self.reference.strip():
            raise ValueError(
                f"the {self.sink} sink returned no reference. A publication "
                "with nothing a third party can fetch is the operator's word, "
                "and recording it would make is_independently_verifiable "
                "return True for a root only the operator can produce."
            )


@runtime_checkable
class RootSink(Protocol):
    """Publishes one root and returns proof of where it went.

    One method wide, deliberately. Every additional capability is another thing
    an implementation can get wrong on the far side of the boundary that makes
    the log worth anything.
    """

    @property
    def name(self) -> str:
        """Stable identifier recorded against every root this sink publishes."""
        ...

    def publish(self, *, tenant_id: str, tree_size: int, root_hash: str) -> PublicationReceipt:
        """Write the root somewhere the caller cannot later alter.

        Must RAISE `RootSinkUnavailable` rather than return anything on
        failure. A sink that returned a receipt it had not obtained would put a
        green tick on a root nobody can check.
        """
        ...


class RefusingRootSink:
    """What a deployment with no configured sink gets. Refuses, loudly.

    The alternative shape -- write the root to a local file and call it
    published -- is worse than having nothing. It would set
    `is_independently_verifiable` to True for a file on a disk the operator
    owns, and that flag is the only thing standing between "this log is
    evidence" and "this log is an assertion".
    """

    __slots__ = ("_reason",)

    def __init__(self, *, reason: str = "no root sink is configured") -> None:
        self._reason = reason

    @property
    def name(self) -> str:
        return "none"

    def publish(
        self, *, tenant_id: str, tree_size: int, root_hash: str
    ) -> PublicationReceipt:
        raise RootSinkUnavailable(
            f"{self._reason}; refusing to record root {root_hash[:16]}... at "
            f"size {tree_size} for tenant {tenant_id!r} as published. There is "
            "no local-file fallback on purpose: a root on a disk the operator "
            "owns would set independently_verifiable to True while proving "
            "nothing, and that flag is the only thing separating evidence from "
            "an assertion.\n\n"
            "Configure one of: S3 with Object Lock in compliance mode, a WORM "
            "appliance, an RFC 3161 timestamping authority, or a public "
            "transparency service. Until then the log still detects mistakes, "
            "partial restores and diverging replicas -- it does not detect a "
            "determined operator, and /v1/transparency/root says so."
        )
