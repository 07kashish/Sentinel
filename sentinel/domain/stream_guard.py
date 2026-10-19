"""Phase 10: streaming, and the exact boundary it can and cannot hold.

A CORRECTION TO AN EARLIER REFUSAL
------------------------------------
`a2a_proxy_routes.py` refuses `message/stream` outright, on the reasoning that a
gate in front of an SSE stream must either buffer the whole thing -- which is
not streaming -- or forward chunks nobody evaluated. That framing was wrong: it
named two options and there are three.

The third is to evaluate EACH CHUNK as it arrives, release it only if it passes,
and abort the stream the moment one does not. That is what a streaming DLP proxy
does, and it is honest -- provided the thing it cannot do is stated as plainly
as the thing it can.

WHAT THIS CAN AND CANNOT DO, PRECISELY
----------------------------------------
BEFORE THE FIRST BYTE, the full pre-flight runs unchanged: delegation validity,
privilege amplification, card drift against what the peer serves now, tenant and
environment constraints. A stream that should not have started does not start.

PER CHUNK, each fragment's text goes through the same detector the non-streaming
path uses, and a chunk that fires is never released.

WHAT CANNOT BE UNDONE: every chunk already released. If chunk 7 carries an
injection, chunks 1-6 are already in the calling agent's context and may already
have been acted on. Aborting at 7 stops the rest; it does not retract the first
six. That is the irreducible cost of streaming and it is why
`StreamOutcome.released_before_abort` exists as a field rather than a footnote.

TERMINATION: on the first failing chunk the stream is closed and the caller is
told which chunk index failed and why. No further chunks are read from upstream
-- a peer that has begun sending an injection does not get to finish.

PARTIAL RESPONSES: a caller that receives an aborted stream holds a TRUNCATED
answer that its model may treat as complete. `StreamOutcome.aborted` is what a
caller must check; a client that ignores it and uses the partial text has been
handed exactly the fragment an attacker chose to send first.

WHY A SEPARATE MODULE
---------------------
This is pure: it takes chunks and a verdict function and decides what may be
released. No SSE parsing, no HTTP, no sockets -- so the boundary can be tested
at chunk granularity without a peer, and the transport can change without the
security argument changing with it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Iterable, Iterator, Mapping

__all__ = [
    "MAX_CHUNKS",
    "MAX_STREAM_BYTES",
    "RelayGuard",
    "StreamAbortReason",
    "StreamOutcome",
    "guard_stream",
]

#: Chunks read from one stream before it is closed. A peer that streams for
#: ever is a peer holding a connection and a worker for ever, and "the model
#: stopped talking" is not a bound this process controls.
MAX_CHUNKS = 2_000

#: Total bytes released before the stream is closed. Separate from the chunk
#: bound because ten thousand tiny chunks and one enormous one are different
#: exhaustion shapes and neither bounds the other.
MAX_STREAM_BYTES = 4 * 1024 * 1024


class StreamAbortReason(str, Enum):
    """Why a stream stopped early. `NONE` means it did not."""

    NONE = "none"
    CHUNK_REFUSED = "chunk_refused"
    CHUNK_LIMIT = "chunk_limit"
    BYTE_LIMIT = "byte_limit"
    UPSTREAM_ERROR = "upstream_error"

    @property
    def explanation(self) -> str:
        return _EXPLANATIONS[self]


#: `MappingProxyType`, not a bare dict: these strings are what a caller is
#: told when a stream stops, and "any import could edit it" is not a
#: property an abort explanation should have.
_EXPLANATIONS: Mapping["StreamAbortReason", str] = MappingProxyType({
    StreamAbortReason.NONE: "the stream completed",
    StreamAbortReason.CHUNK_REFUSED: (
        "a chunk matched a detection rule and was not released; no further "
        "chunks were read from the peer"
    ),
    StreamAbortReason.CHUNK_LIMIT: (
        "the peer sent more chunks than this gateway will relay; a stream "
        "without a bound is a worker held for ever"
    ),
    StreamAbortReason.BYTE_LIMIT: (
        "the peer sent more bytes than this gateway will relay"
    ),
    StreamAbortReason.UPSTREAM_ERROR: "the peer's stream failed mid-flight",
})


@dataclass(frozen=True, slots=True)
class StreamOutcome:
    """What happened to a stream, including what escaped before it stopped."""

    aborted: bool
    reason: StreamAbortReason = StreamAbortReason.NONE
    #: Index of the chunk that caused the abort, 0-based. -1 when none did.
    failed_at: int = -1
    detail: str = ""
    #: THE field that makes this honest. Chunks already handed to the caller
    #: when the stream aborted -- text that is in the calling agent's context
    #: and may already have been acted on. Aborting does not retract them.
    released_before_abort: int = 0
    released_bytes: int = 0

    limits: str = field(
        default=(
            "Aborting stops what has not been sent. It does not retract what "
            "has. A caller holding an aborted stream has a TRUNCATED answer its "
            "model may treat as complete, and the fragment it holds is the one "
            "an attacker chose to send first. Check `aborted` before using the "
            "text."
        ),
        compare=False,
    )

    def as_dict(self) -> dict[str, Any]:
        return {
            "aborted": self.aborted,
            "reason": self.reason.value,
            "reason_explanation": self.reason.explanation,
            "failed_at": self.failed_at,
            "detail": self.detail,
            "released_before_abort": self.released_before_abort,
            "released_bytes": self.released_bytes,
            "limits": self.limits,
        }


def guard_stream(
    chunks: Iterable[str],
    *,
    inspect: Callable[[str], str],
    max_chunks: int = MAX_CHUNKS,
    max_bytes: int = MAX_STREAM_BYTES,
) -> Iterator[tuple[str | None, StreamOutcome | None]]:
    """Relay chunks that pass, stop at the first that does not.

    Yields `(chunk, None)` for each released chunk and finally
    `(None, outcome)`. A generator rather than a list because the whole point is
    that a chunk reaches the caller before the next one is read; collecting them
    would be the buffering this exists to avoid.

    `inspect` returns an empty string for a chunk that may be released, or a
    reason it may not. A predicate returning a bool would force the caller to
    invent the reason, and "a chunk was refused" without which rule fired is not
    something an operator can act on.

    THE ORDER MATTERS. A chunk is inspected BEFORE it is yielded, so a failing
    chunk is never released -- but chunks already yielded are gone, and the
    outcome says how many. Inspecting after yielding would make the check
    decorative.
    """
    released = 0
    released_bytes = 0

    def _stop(
        reason: StreamAbortReason, index: int, detail: str
    ) -> tuple[None, StreamOutcome]:
        return None, StreamOutcome(
            aborted=True,
            reason=reason,
            failed_at=index,
            detail=detail,
            released_before_abort=released,
            released_bytes=released_bytes,
        )

    index = -1
    try:
        for index, chunk in enumerate(chunks):
            if index >= max_chunks:
                yield _stop(
                    StreamAbortReason.CHUNK_LIMIT,
                    index,
                    f"stopped after {max_chunks} chunks",
                )
                return

            size = len(chunk.encode("utf-8", errors="replace"))
            if released_bytes + size > max_bytes:
                yield _stop(
                    StreamAbortReason.BYTE_LIMIT,
                    index,
                    f"stopped at {max_bytes} bytes",
                )
                return

            refusal = inspect(chunk)
            if refusal:
                # Not released. No further chunks are read from the peer: one
                # that has begun sending an injection does not get to finish.
                yield _stop(StreamAbortReason.CHUNK_REFUSED, index, refusal)
                return

            released += 1
            released_bytes += size
            yield chunk, None
    except Exception as exc:  # noqa: BLE001 - a peer failing mid-flight is data
        yield _stop(
            StreamAbortReason.UPSTREAM_ERROR,
            index,
            f"{type(exc).__name__}: {exc}",
        )
        return

    yield None, StreamOutcome(
        aborted=False,
        reason=StreamAbortReason.NONE,
        released_before_abort=released,
        released_bytes=released_bytes,
    )


class RelayGuard:
    """The same rules as `guard_stream`, for a producer that PUSHES chunks.

    `guard_stream` pulls from an iterator it owns. A proxy relaying events from
    inside somebody else's read loop cannot hand over that loop, so it offers
    each chunk instead: `offer` returns True when the chunk may be released.
    After the first refusal or limit NOTHING further is released -- a stream
    that has shown one hostile chunk does not get to try again -- but the
    caller may keep reading the peer, because abandoning a request whose
    effect is already under way would turn a known outcome into an unknown one.
    """

    __slots__ = ("_inspect", "_max_chunks", "_max_bytes", "_released", "_bytes", "_seen", "_outcome")

    def __init__(self, *, inspect: Callable[[str], str], max_chunks: int = MAX_CHUNKS,
                 max_bytes: int = MAX_STREAM_BYTES) -> None:
        self._inspect = inspect
        self._max_chunks = max_chunks
        self._max_bytes = max_bytes
        self._released = 0
        self._bytes = 0
        self._seen = 0
        self._outcome: StreamOutcome | None = None

    def offer(self, chunk: str) -> bool:
        index = self._seen
        self._seen += 1
        if self._outcome is not None:
            return False
        size = len(chunk.encode("utf-8"))
        if self._released >= self._max_chunks:
            return self._stop(StreamAbortReason.CHUNK_LIMIT, index, f"more than {self._max_chunks} chunks")
        if self._bytes + size > self._max_bytes:
            return self._stop(StreamAbortReason.BYTE_LIMIT, index, f"more than {self._max_bytes} bytes")
        reason = self._inspect(chunk)
        if reason:
            return self._stop(StreamAbortReason.CHUNK_REFUSED, index, reason)
        self._released += 1
        self._bytes += size
        return True

    def _stop(self, reason: StreamAbortReason, index: int, detail: str) -> bool:
        self._outcome = StreamOutcome(aborted=True, reason=reason, failed_at=index, detail=detail,
                                      released_before_abort=self._released, released_bytes=self._bytes)
        return False

    @property
    def outcome(self) -> StreamOutcome:
        return self._outcome or StreamOutcome(aborted=False, released_before_abort=self._released,
                                              released_bytes=self._bytes)
