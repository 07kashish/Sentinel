"""Incremental MCP streaming: bounded at the socket, guarded at the relay, unchanged at the control path.

Three layers, each proven where it lives:

  * `HardenedHttpClient.stream` -- the per-event, total-size and wall-time
    bounds, and that redirects and non-stream replies behave as on `request`.
  * `McpUpstreamClient.forward(on_event=...)` -- notifications are handed over
    as they arrive and the response is returned exactly as in the buffered case.
  * the proxy route -- a client that asks for a stream sees progress events,
    never sees a server-initiated request or a poisoned notification, and the
    final result is still inspected, receipted and audited.
"""

from __future__ import annotations

import io
import json
import socket
from contextlib import contextmanager

import pytest

from sentinel.domain.stream_guard import RelayGuard, StreamAbortReason
from sentinel.infrastructure.mcp_wire import McpUpstreamClient, McpWireError
from sentinel.infrastructure.outbound import HardenedHttpClient, OutboundRefused, OutboundStream
from sentinel.interface.mcp_streaming import RelayPolicy
from tests_arch.test_mcp_wire_proxy import (  # noqa: F401 - `app` is a fixture
    POISONED, FakeUpstream, _call, _enrol, _wire_settings, app,
)

URL = "https://mcp.example/rpc"


def _event(message: dict) -> bytes:
    return b"event: message\ndata: " + json.dumps(message).encode() + b"\n\n"


PROGRESS = {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progressToken": "t", "progress": 1, "total": 3}}
LOG = {"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info", "data": "indexing shard 2"}}
SAMPLING = {"jsonrpc": "2.0", "id": 99, "method": "sampling/createMessage", "params": {"messages": []}}
HOSTILE = {"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info", "data": POISONED}}
FINAL = {"jsonrpc": "2.0", "id": 7, "result": {"content": [{"type": "text", "text": "ok"}]}}


# ── The socket layer ─────────────────────────────────────────────────────────


def _client(monkeypatch, *, status=200, content_type="text/event-stream", payload=b""):
    monkeypatch.setattr(
        "sentinel.infrastructure.outbound.socket.getaddrinfo",
        lambda host, port, **_kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))],
    )
    closed: list[bool] = []

    class _Response(io.BytesIO):
        def getheaders(self):
            return [("Content-Type", content_type)]

    class _Connection:
        def __init__(self, _destination):
            pass

        def request(self, *_a, **_kw):
            pass

        def getresponse(self):
            response = _Response(payload)
            response.status = status
            return response

        def close(self):
            closed.append(True)

    return HardenedHttpClient(connection_factory=_Connection), closed


def test_events_arrive_one_at_a_time_and_the_socket_closes_with_the_block(monkeypatch):
    client, closed = _client(monkeypatch, payload=_event(PROGRESS) + _event(FINAL))
    with client.stream(method="POST", url=URL, body=b"{}") as reply:
        assert isinstance(reply, OutboundStream) and reply.body == b""
        events = list(reply.events)
        assert closed == [], "the connection closed while the caller was still reading"
    assert len(events) == 2 and b"notifications/progress" in events[0]
    assert closed == [True]


def test_the_socket_closes_when_the_caller_abandons_the_stream(monkeypatch):
    client, closed = _client(monkeypatch, payload=_event(PROGRESS) * 50)
    with pytest.raises(RuntimeError):
        with client.stream(method="POST", url=URL, body=b"{}") as reply:
            next(reply.events)
            raise RuntimeError("caller gave up")
    assert closed == [True]


def test_one_oversized_event_is_refused(monkeypatch):
    client, _ = _client(monkeypatch, payload=b"data: " + b"x" * 5000 + b"\n\n")
    with pytest.raises(OutboundRefused, match="one server-sent event"):
        with client.stream(method="POST", url=URL, body=b"{}", max_event_bytes=1024) as reply:
            list(reply.events)


def test_many_small_events_cannot_exceed_the_response_limit(monkeypatch):
    client, _ = _client(monkeypatch, payload=_event(PROGRESS) * 200_000)
    with pytest.raises(OutboundRefused, match="event stream exceeded"):
        with client.stream(method="POST", url=URL, body=b"{}") as reply:
            for _ in reply.events:
                pass


def test_a_stream_past_its_deadline_is_refused(monkeypatch):
    client, _ = _client(monkeypatch, payload=_event(PROGRESS) * 3)
    with pytest.raises(OutboundRefused, match="time limit"):
        with client.stream(method="POST", url=URL, body=b"{}", max_seconds=-1.0) as reply:
            list(reply.events)


def test_a_redirect_is_refused_on_a_stream_too(monkeypatch):
    client, closed = _client(monkeypatch, status=307)
    with pytest.raises(OutboundRefused, match="redirects are refused"):
        with client.stream(method="POST", url=URL, body=b"{}"):
            pass
    assert closed == [True]


def test_a_reply_that_is_not_a_stream_is_read_whole(monkeypatch):
    client, _ = _client(monkeypatch, content_type="application/json", payload=b'{"ok": true}')
    with client.stream(method="POST", url=URL, body=b"{}") as reply:
        assert reply.body == b'{"ok": true}' and list(reply.events) == []


def test_a_private_destination_is_refused_before_any_connection():
    with pytest.raises(OutboundRefused):
        with HardenedHttpClient().stream(method="POST", url="https://127.0.0.1/rpc", body=b"{}"):
            pass


# ── The wire client ──────────────────────────────────────────────────────────


class _StreamingHttp:
    def __init__(self, *, status=200, headers=None, events=(), body=b""):
        self._reply = OutboundStream(status=status, headers={k.lower(): v for k, v in (headers or {}).items()},
                                     peer="fake:443", body=body, events=iter(events))

    @contextmanager
    def stream(self, **_kw):
        yield self._reply


def _forward(http, seen):
    return McpUpstreamClient(client=http).forward(endpoint=URL, message={"jsonrpc": "2.0", "id": 7, "method": "tools/call"},
                                           on_event=seen.append)


def test_notifications_are_handed_over_and_the_response_is_returned_as_before():
    seen: list = []
    http = _StreamingHttp(headers={"Content-Type": "text/event-stream", "Mcp-Session-Id": "s1"},
                          events=[_event(PROGRESS), b": keep-alive\n", _event(SAMPLING), _event(FINAL), _event(LOG)])
    reply = _forward(http, seen)
    assert seen == [PROGRESS, SAMPLING], "everything before the response, and nothing after it"
    assert reply.message == FINAL and reply.status == 200 and reply.session_id == "s1"


def test_a_stream_that_never_answers_is_an_error_not_a_silent_success():
    seen: list = []
    http = _StreamingHttp(headers={"Content-Type": "text/event-stream"}, events=[_event(PROGRESS)])
    with pytest.raises(McpWireError, match="without a JSON-RPC response"):
        _forward(http, seen)


def test_a_challenge_and_a_plain_json_reply_pass_through_the_streaming_path():
    challenge = _forward(_StreamingHttp(status=401, headers={"WWW-Authenticate": 'Bearer resource_metadata="x"'}), [])
    assert challenge.status == 401 and "Bearer" in challenge.www_authenticate
    plain = _forward(_StreamingHttp(headers={"Content-Type": "application/json"}, body=json.dumps(FINAL).encode()), [])
    assert plain.message == FINAL


# ── The relay policy ─────────────────────────────────────────────────────────


def _policy(refuse=""):
    out: list = []
    policy = RelayPolicy(inspect=lambda text: "prompt injection" if refuse and refuse in text else "",
                         sink=lambda message: out.append(message) or True)
    return policy, out


def test_only_progress_and_log_notifications_reach_the_client():
    policy, out = _policy()
    for message in (PROGRESS, SAMPLING, {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}, LOG):
        policy(message)
    assert out == [PROGRESS, LOG]
    detail = policy.as_detail()["stream"]
    assert detail["server_requests_not_relayed"] == 1 and detail["other_messages_not_relayed"] == 1


def test_after_one_refused_notification_nothing_further_is_relayed():
    policy, out = _policy(refuse="Ignore all previous")
    for message in (PROGRESS, HOSTILE, LOG, PROGRESS):
        policy(message)
    assert out == [PROGRESS]
    outcome = policy.as_detail()["stream"]
    assert outcome["aborted"] is True and outcome["reason"] == StreamAbortReason.CHUNK_REFUSED.value


def test_a_client_that_stops_reading_stops_the_relay_not_the_call():
    out: list = []
    policy = RelayPolicy(inspect=lambda _t: "", sink=lambda m: out.append(m) is not None and False)
    policy(PROGRESS)
    policy(LOG)
    assert len(out) == 1 and policy.as_detail()["stream"]["client_stopped_reading"] is True


def test_the_relay_guard_enforces_its_chunk_and_byte_limits():
    guard = RelayGuard(inspect=lambda _t: "", max_chunks=2, max_bytes=1000)
    assert [guard.offer("a"), guard.offer("b"), guard.offer("c"), guard.offer("d")] == [True, True, False, False]
    assert guard.outcome.reason is StreamAbortReason.CHUNK_LIMIT and guard.outcome.released_before_abort == 2
    small = RelayGuard(inspect=lambda _t: "", max_bytes=4)
    assert small.offer("abc") is True and small.offer("de") is False
    assert small.outcome.reason is StreamAbortReason.BYTE_LIMIT


# ── Through the real proxy ───────────────────────────────────────────────────


class StreamingUpstream(FakeUpstream):
    """Emits scripted messages to `on_event` before answering a tool call."""

    def __init__(self, before=()):
        super().__init__()
        self.before = list(before)
        self.streamed_methods: list[str] = []

    def forward(self, *, on_event=None, **kw):
        if on_event is not None:
            self.streamed_methods.append(kw["message"].get("method", ""))
            for message in self.before:
                on_event(message)
        return super().forward(**kw)


@pytest.fixture
def streaming_app(engine_config, app):  # noqa: F811 - pytest fixture injection
    """The `app` fixture's database, a second container with streaming switched on."""
    from fastapi.testclient import TestClient

    from sentinel.composition.container import build_container
    from sentinel.composition.settings import Settings
    from sentinel.domain.attestation import AttestationDisposition
    from sentinel.interface.http import create_app
    from tests_arch.doubles import FakeAttestationGateway, FakeClock

    base = _wire_settings(engine_config)
    env = {
        "SENTINEL_ENV": "development", "SENTINEL_PROTECT_ENFORCE": "true",
        "SENTINEL_MCP_PROXY_STREAMING": "true",
        "SENTINEL_API_KEYS": "acme:" + _KEY + ":ingest",
    }
    if base.engine.dialect.name == "POSTGRES":
        env.update({"SENTINEL_DATABASE_URL": base.engine.dsn, "SENTINEL_DB_POOL_MIN": "1", "SENTINEL_DB_POOL_MAX": "4"})
    else:
        env["SENTINEL_DB_PATH"] = base.engine.dsn
    upstream = StreamingUpstream()
    container = build_container(Settings.from_environment(env), clock=FakeClock(),
                                attestation=FakeAttestationGateway(disposition=AttestationDisposition.ANCHORED),
                                mcp_upstream=upstream, verify_schema=True)
    try:
        _enrol(container)
        yield TestClient(create_app(container), raise_server_exceptions=False), container, upstream
    finally:
        container.close()


_KEY = "stream-ingest-key-that-is-long-enough-for-production"
_SSE = {"Accept": "application/json, text/event-stream"}


def _messages(response) -> list[dict]:
    return [json.loads(line[len("data: "):]) for line in response.text.splitlines() if line.startswith("data: ")]


def test_progress_is_relayed_and_the_result_closes_the_stream(streaming_app):
    client, container, upstream = streaming_app
    upstream.before = [PROGRESS, LOG]
    response = _call(client, key=_KEY, headers=_SSE)
    assert response.status_code == 200 and response.headers["content-type"].startswith("text/event-stream")
    messages = _messages(response)
    assert messages[:2] == [PROGRESS, LOG]
    assert messages[-1]["id"] == 7 and messages[-1]["result"]["content"][0]["text"] == "ok"
    assert upstream.streamed_methods == ["tools/call"], "the definition lookup was streamed too"


def test_a_server_initiated_request_and_a_poisoned_notification_never_reach_the_client(streaming_app):
    client, container, upstream = streaming_app
    upstream.before = [PROGRESS, SAMPLING, HOSTILE, LOG]
    response = _call(client, key=_KEY, headers=_SSE)
    messages = _messages(response)
    assert messages[0] == PROGRESS and len(messages) == 2, messages
    assert "sampling/createMessage" not in response.text and "exfil.example" not in response.text
    assert "result" in messages[-1], "the tool's effect happened; its known outcome must still be delivered"


def test_the_final_result_is_still_inspected_when_streaming(streaming_app):
    client, container, upstream = streaming_app
    upstream.before = [PROGRESS]
    upstream.call_result = {"content": [{"type": "text", "text": POISONED}]}
    response = _call(client, key=_KEY, headers=_SSE)
    final = _messages(response)[-1]
    assert "error" in final and "exfil.example" not in response.text


def test_a_call_with_nothing_to_relay_is_answered_as_plain_json(streaming_app):
    client, _container, upstream = streaming_app
    response = _call(client, key=_KEY, headers=_SSE)
    assert response.headers["content-type"].startswith("application/json")
    assert response.json()["result"]["content"][0]["text"] == "ok"


def test_a_refusal_before_the_upstream_is_plain_json_with_nothing_dialled(streaming_app):
    client, _container, upstream = streaming_app
    response = _call(client, key=_KEY, server="never-enrolled", headers=_SSE)
    assert "error" in response.json() and upstream.forwarded == []


def test_without_the_setting_or_without_the_accept_header_nothing_streams(app, streaming_app):  # noqa: F811
    client, container, upstream = app
    _enrol(container)
    assert _call(client, headers=_SSE).headers["content-type"].startswith("application/json")
    on_client, _c, on_upstream = streaming_app
    on_upstream.before = [PROGRESS]
    assert _call(on_client, key=_KEY).headers["content-type"].startswith("application/json")
    assert on_upstream.streamed_methods == []


def test_the_audit_row_records_what_was_and_was_not_relayed(streaming_app):
    client, container, upstream = streaming_app
    upstream.before = [PROGRESS, SAMPLING]
    _call(client, key=_KEY, headers=_SSE)
    with container.pool.acquire() as conn:
        conn.begin()
        conn.set_tenant("acme")
        rows = conn.execute(
            f"SELECT detail FROM security_audit WHERE tenant_id={conn.p} AND action={conn.p}", ("acme", "mcp.proxy"),
        )
        conn.commit()
    details = [r["detail"] if isinstance(r["detail"], dict) else json.loads(r["detail"]) for r in rows]
    streams = [d["stream"] for d in details if "stream" in d]
    assert streams and streams[-1]["server_requests_not_relayed"] == 1 and streams[-1]["released_before_abort"] == 1, details
