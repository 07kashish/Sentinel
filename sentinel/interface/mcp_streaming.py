"""Relay an MCP server's notifications to the client as they arrive, under guard.

WHAT CHANGED, AND WHAT DID NOT
------------------------------
Until now the proxy discarded everything an upstream server streamed before
its response and returned only the response. With
`SENTINEL_MCP_PROXY_STREAMING=true`, a client that asks for `text/event-stream`
on `tools/call` receives the server's progress and log notifications while the
tool runs, and then the response as the last event.

The control path is untouched. The tool call still goes through the bound
runner; the receipt, the inspection of the final result and the audit row are
produced by exactly the code that produces them for a buffered call, because
streaming is implemented as a CALLBACK handed to that code, not as a second
path around it.

WHAT IS RELAYED
---------------
Only `notifications/progress` and `notifications/message`, each inspected
BEFORE release by the same detector that inspects tool results. Everything
else is dropped and counted:

  * a server-initiated REQUEST (an object with both `method` and `id` --
    `sampling/createMessage`, `elicitation/create`, `roots/list`) is never
    relayed. Those ask the CLIENT to act: to run its model on text the server
    chose, or to ask its user a question the server wrote. Forwarding them
    would make the proxy the delivery mechanism for the attack it exists to
    stop, and answering them is not something this gateway has been taught.
  * after the first refused chunk or exceeded limit NOTHING further is
    relayed, but the upstream is still read to its response. Abandoning a tool
    call whose effect is under way would turn a known outcome into an unknown
    one to punish a log line.

A stream that produced nothing relayable is answered as an ordinary JSON
response with its real status code, so an authorization challenge still
arrives as a 401 and not as an event inside a 200.
"""

from __future__ import annotations

import contextvars
import json
import queue
import threading
from typing import Any, Callable, Iterator, Mapping

from fastapi import HTTPException
from fastapi.responses import Response, StreamingResponse

from sentinel.domain.stream_guard import RelayGuard

__all__ = ["RELAYED_METHODS", "RelayPolicy", "stream_through"]

RELAYED_METHODS = frozenset({"notifications/progress", "notifications/message"})
#: How long the worker waits for a slow or departed client before it stops relaying.
CLIENT_STALL_SECONDS = 30.0


class RelayPolicy:
    """Decides, per upstream message, whether the client sees it. Counts the rest."""

    __slots__ = ("_guard", "_sink", "dropped_requests", "dropped_other", "client_gone")

    def __init__(self, *, inspect: Callable[[str], str], sink: Callable[[Mapping[str, Any]], bool]) -> None:
        self._guard = RelayGuard(inspect=inspect)
        self._sink = sink
        self.dropped_requests = 0
        self.dropped_other = 0
        self.client_gone = False

    def __call__(self, message: Mapping[str, Any]) -> None:
        if "id" in message:
            self.dropped_requests += 1
            return
        if message.get("method") not in RELAYED_METHODS:
            self.dropped_other += 1
            return
        text = json.dumps(message.get("params") or {}, sort_keys=True, default=str)
        if self.client_gone or not self._guard.offer(text):
            return
        if not self._sink(message):
            self.client_gone = True

    def as_detail(self) -> dict[str, Any]:
        return {"stream": {**self._guard.outcome.as_dict(), "server_requests_not_relayed": self.dropped_requests,
                           "other_messages_not_relayed": self.dropped_other, "client_stopped_reading": self.client_gone}}


def _final_message(result: Any, request_id: Any) -> Mapping[str, Any]:
    if isinstance(result, Mapping):
        return result
    if isinstance(result, Response):
        try:
            parsed = json.loads(bytes(result.body).decode("utf-8")) if result.body else None
        except (ValueError, UnicodeDecodeError):
            parsed = None
        if isinstance(parsed, Mapping):
            return parsed
        return {"jsonrpc": "2.0", "id": request_id,
                "error": {"code": -32000, "message": f"upstream answered HTTP {result.status_code} with no JSON-RPC body"}}
    detail = result.detail if isinstance(result, HTTPException) else "the proxied call failed"
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32000, "message": str(detail)}}


def _sse(message: Mapping[str, Any]) -> bytes:
    return b"event: message\ndata: " + json.dumps(message, separators=(",", ":")).encode("utf-8") + b"\n\n"


def stream_through(call: Callable[[Callable[[Mapping[str, Any]], bool]], Any], *, request_id: Any) -> Any:
    """Run `call(sink)` on a worker and relay what it sinks; answer plainly if it sinks nothing."""
    events: queue.Queue = queue.Queue(maxsize=256)

    def sink(message: Mapping[str, Any]) -> bool:
        try:
            events.put(("event", message), timeout=CLIENT_STALL_SECONDS)
            return True
        except queue.Full:
            return False

    def work() -> None:
        try:
            result: Any = call(sink)
        except Exception as exc:  # noqa: BLE001 - delivered to the waiting request, never lost in a thread
            result = exc
        events.put(("final", result))

    threading.Thread(target=contextvars.copy_context().run, args=(work,), daemon=True).start()
    kind, first = events.get()
    if kind == "final":
        if isinstance(first, Exception):
            raise first
        return first

    def relay() -> Iterator[bytes]:
        item = (kind, first)
        while True:
            if item[0] == "final":
                yield _sse(_final_message(item[1], request_id))
                return
            yield _sse(item[1])
            item = events.get()

    return StreamingResponse(relay(), media_type="text/event-stream", headers={"Cache-Control": "no-store"})
