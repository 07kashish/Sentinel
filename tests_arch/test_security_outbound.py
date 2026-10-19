"""SSRF and credential-exfiltration defences, driven against real sockets.

WHY THIS SUITE IS ADVERSARIAL RATHER THAN ILLUSTRATIVE
------------------------------------------------------
The finding that motivated `outbound.py` was proven, not theorised: a local
server answering `302 -> http://127.0.0.1/stolen` received the attestation
bearer token, because urllib rebuilds the redirected request with the original
headers and permits an https downgrade.

So the first test here is that exact attack, replayed against the hardened
client. If it ever passes silently again, the build fails. Every other test is a
variant an attacker would reach for once the obvious one is closed: obfuscated
address literals, a hostname with one good and one bad record, a resolver that
answers differently the second time, an endpoint that streams forever.
"""

from __future__ import annotations

import http.client
import http.server
import json
import socket
import threading

import pytest

from sentinel.infrastructure.outbound import (
    HardenedHttpClient,
    OutboundPolicy,
    OutboundRefused,
    OutboundUnavailable,
    validate_destination,
)

TOKEN = "Bearer SUPERSECRET-ATTESTATION-TOKEN"


# ── A local server that records what it was sent ─────────────────────────────


class _Recorder:
    """Captures every request any handler receives, across both servers."""

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.lock = threading.Lock()

    def record(self, handler) -> None:
        with self.lock:
            self.requests.append(
                {
                    "path": handler.path,
                    "method": handler.command,
                    "headers": {k.lower(): v for k, v in handler.headers.items()},
                }
            )

    def saw_authorization(self) -> list[str]:
        with self.lock:
            return [
                r["headers"]["authorization"]
                for r in self.requests
                if "authorization" in r["headers"]
            ]


def _serve(build_handler):
    server = http.server.HTTPServer(("127.0.0.1", 0), build_handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, server.server_address[1]


def _handler(recorder: _Recorder, *, redirect_to: str | None = None, body: bytes = b"{}",
             status: int = 200, redirect_status: int = 302, extra_headers: int = 0,
             stream_bytes: int = 0):
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *_a):
            pass

        def _respond(self):
            recorder.record(self)
            # Drain the request body BEFORE responding. A server that replies and
            # closes while the client is still writing produces a connection
            # reset on Windows, which would surface here as OutboundUnavailable
            # and hide whatever the test was actually asserting.
            pending = int(self.headers.get("Content-Length") or 0)
            if pending:
                self.rfile.read(pending)
            if redirect_to is not None:
                self.send_response(redirect_status)
                self.send_header("Location", redirect_to)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if stream_bytes:
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.end_headers()
                self.wfile.write(b"A" * stream_bytes)
                return
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            for n in range(extra_headers):
                self.send_header(f"X-Filler-{n}", "x")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = _respond
        do_POST = _respond

    return H


@pytest.fixture
def recorder():
    return _Recorder()


@pytest.fixture
def loopback_policy():
    """Loopback permitted ONLY so the tests can use a local server.

    Production policy refuses it. Stated here because a test fixture that
    silently relaxes the control under test is how a suite comes to prove
    nothing.
    """
    return OutboundPolicy(
        allowed_schemes=frozenset({"http"}),
        allow_private_destinations=True,
        max_response_bytes=4096,
    )


@pytest.fixture
def client(loopback_policy):
    return HardenedHttpClient(policy=loopback_policy)


# ── The proven attack, replayed ──────────────────────────────────────────────


def test_a_redirect_never_carries_the_bearer_token_onward(recorder, client):
    """THE regression test. This exact flow leaked the token before outbound.py.

    A gateway answering 302 to a plain-HTTP loopback address received
    `Authorization: Bearer <attestation token>` from urllib. One open redirect at
    the gateway, or one compromised gateway, was a credential exfiltration.
    """
    sink_server, sink_port = _serve(_handler(recorder))
    sink = f"http://127.0.0.1:{sink_port}/stolen"
    redirector, redirect_port = _serve(_handler(recorder, redirect_to=sink))

    try:
        with pytest.raises(OutboundRefused) as refused:
            client.request(
                method="POST",
                url=f"http://127.0.0.1:{redirect_port}/v1/anchor",
                headers={"Authorization": TOKEN, "Content-Type": "application/json"},
                body=json.dumps({"tenant_id": "t"}).encode(),
            )
    finally:
        sink_server.shutdown()
        redirector.shutdown()

    message = str(refused.value)
    assert "Redirects are refused" in message
    assert "302" in message
    assert sink in message, "the refusal should name where it was being sent"

    leaked = recorder.saw_authorization()
    assert leaked == [TOKEN], (
        "the token should have reached the gateway exactly once and gone nowhere "
        f"else; instead it was sent {len(leaked)} times"
    )
    assert not any(r["path"] == "/stolen" for r in recorder.requests), (
        "the redirect was followed: the exfiltration sink received a request"
    )


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_every_redirect_class_is_refused(recorder, client, status):
    """307/308 preserve the method and body, so they are the dangerous ones."""
    server, port = _serve(
        _handler(recorder, redirect_to="http://127.0.0.1:1/x", redirect_status=status)
    )
    try:
        with pytest.raises(OutboundRefused) as refused:
            client.request(
                method="POST",
                url=f"http://127.0.0.1:{port}/v1/anchor",
                headers={"Authorization": TOKEN},
                body=b"{}",
            )
    finally:
        server.shutdown()
    assert str(status) in str(refused.value)
    assert not recorder.saw_authorization()[1:], "the token was sent more than once"


# ── Destination validation ───────────────────────────────────────────────────


@pytest.mark.parametrize(
    "host,expected",
    [
        ("127.0.0.1", "loopback"),
        ("localhost", "loopback"),
        ("169.254.169.254", "link-local"),
        ("10.0.0.1", "private"),
        ("172.16.0.1", "private"),
        ("192.168.1.1", "private"),
        ("0.0.0.0", "unspecified"),
        ("[::1]", "loopback"),
        ("[fe80::1]", "link-local"),
        ("[fc00::1]", "private"),
        ("224.0.0.1", "multicast"),
    ],
)
def test_internal_destinations_are_refused_with_a_named_reason(host, expected):
    """The reason has to be specific, or an operator disables the check wholesale."""
    policy = OutboundPolicy(allowed_schemes=frozenset({"https", "http"}))
    with pytest.raises(OutboundRefused) as refused:
        validate_destination(f"https://{host}/v1/anchor", policy)
    assert expected in str(refused.value).lower(), str(refused.value)


@pytest.mark.parametrize(
    "literal",
    [
        "0177.0.0.1",  # octal
        "2130706433",  # decimal 127.0.0.1
        "0x7f.0.0.1",  # hex
        "[::ffff:127.0.0.1]",  # IPv4-mapped IPv6
        "127.1",  # short form
    ],
)
def test_obfuscated_address_literals_do_not_bypass_validation(literal):
    """Validation happens AFTER resolution, so these are 4 bytes by then.

    A string-based check has to enumerate every encoding the resolver accepts and
    will always be one encoding behind. Judging the resolved bytes is not a
    better blocklist, it is a different and finite problem.
    """
    policy = OutboundPolicy(allowed_schemes=frozenset({"https", "http"}))
    try:
        destination = validate_destination(f"http://{literal}/", policy)
    except (OutboundRefused, OutboundUnavailable) as caught:
        # It resolved to loopback and was refused, or the platform would not
        # resolve it at all. Both are acceptable; silently reaching loopback
        # is not.
        assert "loopback" in str(caught).lower() or "resolve" in str(caught).lower()
    else:
        # Resolvers disagree on these literals. glibc reads "0177.0.0.1" with
        # octal octets and lands on 127.0.0.1; macOS getaddrinfo reads the same
        # string as decimal and produces 177.0.0.1 — a PUBLIC address. When the
        # platform's own resolver yields a public address there is no bypass to
        # refuse: the client dials the bytes that were validated, never the
        # literal, so loopback is not reachable through it. The property under
        # test is "no private address is silently reached" — assert it directly
        # on what resolution produced instead of assuming every platform maps
        # the literal to loopback.
        import ipaddress

        for address in destination.addresses:
            parsed = ipaddress.ip_address(address)
            assert parsed.is_global, (
                f"{literal!r} resolved to non-global {address} and validation "
                "let it through — that IS the bypass this test exists to catch"
            )


def test_a_split_horizon_hostname_is_refused_on_its_worst_record(monkeypatch):
    """One public and one private record must not be a coin flip.

    If only the address we happen to pick is validated, an attacker with control
    of a DNS zone re-tosses that coin on every request until it lands inside.
    """
    def both(host, port, **_kw):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port)),
        ]

    monkeypatch.setattr("sentinel.infrastructure.outbound.socket.getaddrinfo", both)
    with pytest.raises(OutboundRefused) as refused:
        validate_destination("https://split.example/v1/anchor", OutboundPolicy())
    assert "169.254.169.254" in str(refused.value)


def test_the_connection_uses_the_address_that_was_validated(monkeypatch):
    """DNS rebinding has nothing to rebind if there is no second lookup.

    The classic bypass is a resolver that answers public during the check and
    loopback during the connect. Asserting the dialled address equals the vetted
    one is what forecloses it.
    """
    calls: list[str] = []

    def once(host, port, **_kw):
        calls.append(host)
        # A second lookup would get the internal answer. There must not be one.
        address = "93.184.216.34" if len(calls) == 1 else "127.0.0.1"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]

    monkeypatch.setattr("sentinel.infrastructure.outbound.socket.getaddrinfo", once)

    dialled: list[str] = []

    class _Fake:
        def __init__(self, destination):
            dialled.append(destination.addresses[0])

        def request(self, *_a, **_kw):
            pass

        def getresponse(self):
            class R:
                status = 200

                def getheader(self, *_a, **_kw):
                    return None

                def getheaders(self):
                    return [("Content-Type", "application/json")]

                def read(self, _n):
                    return b"{}"

            return R()

        def close(self):
            pass

    client = HardenedHttpClient(connection_factory=_Fake)
    client.request(method="GET", url="https://rebind.example/v1/anchor")

    assert dialled == ["93.184.216.34"]
    assert len(calls) == 1, f"the hostname was resolved {len(calls)} times, not once"


def test_credentials_in_a_url_are_refused():
    """https://trusted.example@attacker.example reads as trusted to a human."""
    with pytest.raises(OutboundRefused) as refused:
        validate_destination("https://user:pw@example.com/v1/anchor", OutboundPolicy())
    assert "credentials embedded" in str(refused.value)


def test_plain_http_is_refused_by_default():
    with pytest.raises(OutboundRefused) as refused:
        validate_destination("http://example.com/v1/anchor", OutboundPolicy())
    assert "not permitted" in str(refused.value)


def test_an_allowlist_narrows_a_private_grant():
    """allow_private_destinations plus an allowlist is a far smaller grant."""
    policy = OutboundPolicy(
        allow_private_destinations=True, allowed_hosts=frozenset({"gateway.internal"})
    )
    with pytest.raises(OutboundRefused) as refused:
        validate_destination("https://10.0.0.5/v1/anchor", policy)
    assert "allowlist" in str(refused.value)


# ── Response bounds and header hygiene ───────────────────────────────────────


def test_an_unbounded_response_body_is_refused(recorder, loopback_policy):
    """A config value must not become a memory-exhaustion primitive."""
    client = HardenedHttpClient(policy=loopback_policy)
    server, port = _serve(_handler(recorder, stream_bytes=loopback_policy.max_response_bytes * 4))
    try:
        with pytest.raises(OutboundRefused) as refused:
            client.request(method="GET", url=f"http://127.0.0.1:{port}/big")
    finally:
        server.shutdown()
    assert "exceeded" in str(refused.value)


def test_a_response_at_exactly_the_limit_is_accepted(recorder):
    """The bound must be off-by-none, or it is a bound nobody trusts."""
    policy = OutboundPolicy(
        allowed_schemes=frozenset({"http"}),
        allow_private_destinations=True,
        max_response_bytes=64,
    )
    body = b"x" * 64
    server, port = _serve(_handler(recorder, body=body))
    try:
        response = HardenedHttpClient(policy=policy).request(
            method="GET", url=f"http://127.0.0.1:{port}/exact"
        )
    finally:
        server.shutdown()
    assert response.body == body


def test_too_many_response_headers_are_refused(recorder):
    policy = OutboundPolicy(
        allowed_schemes=frozenset({"http"}),
        allow_private_destinations=True,
        max_response_headers=5,
    )
    server, port = _serve(_handler(recorder, extra_headers=40))
    try:
        with pytest.raises(OutboundRefused) as refused:
            HardenedHttpClient(policy=policy).request(
                method="GET", url=f"http://127.0.0.1:{port}/headers"
            )
    finally:
        server.shutdown()
    assert "headers" in str(refused.value)


@pytest.mark.parametrize("name", ["Host", "Cookie", "Transfer-Encoding", "Connection"])
def test_forbidden_request_headers_are_refused_not_dropped(client, name):
    """Silently dropping a header a caller set is a silent bug.

    Host in particular: letting a caller set it is how an internal virtual host is
    reached through a permitted edge.
    """
    with pytest.raises(OutboundRefused) as refused:
        client.request(
            method="GET", url="http://127.0.0.1:1/x", headers={name: "evil.internal"}
        )
    assert name.lower() in str(refused.value).lower()


def test_a_header_value_containing_crlf_is_refused(client):
    """Request splitting. Refused here so the refusal is ours and auditable."""
    with pytest.raises(OutboundRefused) as refused:
        client.request(
            method="GET",
            url="http://127.0.0.1:1/x",
            headers={"X-Trace": "a\r\nX-Injected: yes"},
        )
    assert "newline" in str(refused.value)


@pytest.mark.parametrize("method", ["TRACE", "CONNECT", "PATCH", "OPTIONS"])
def test_unexpected_methods_are_refused(client, method):
    with pytest.raises(OutboundRefused):
        client.request(method=method, url="http://127.0.0.1:1/x")


# ── Failure classification ───────────────────────────────────────────────────


def test_an_unreachable_destination_is_transient_not_a_policy_refusal():
    """The distinction drives retry, and conflating them either retries an
    attack forever or gives up on a blip."""
    policy = OutboundPolicy(
        allowed_schemes=frozenset({"http"}), allow_private_destinations=True
    )
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]
    with pytest.raises(OutboundUnavailable):
        HardenedHttpClient(policy=policy).request(
            method="GET", url=f"http://127.0.0.1:{dead_port}/x"
        )


def test_dns_failure_is_transient_not_an_attack():
    """DNS being down must not read as a request-forgery attempt in the audit."""
    with pytest.raises(OutboundUnavailable) as caught:
        validate_destination(
            "https://this-host-does-not-exist.invalid/v1/anchor", OutboundPolicy()
        )
    assert "resolve" in str(caught.value)


def test_non_json_bodies_raise_rather_than_returning_none(recorder, client):
    server, port = _serve(_handler(recorder, body=b"<html>not json</html>"))
    try:
        response = client.request(method="GET", url=f"http://127.0.0.1:{port}/x")
        with pytest.raises(OutboundRefused):
            response.json()
    finally:
        server.shutdown()


def test_the_peer_address_is_reported_for_the_audit_trail(recorder, client):
    """"We called the gateway" is not auditable. An address is."""
    server, port = _serve(_handler(recorder))
    try:
        response = client.request(method="GET", url=f"http://127.0.0.1:{port}/x")
    finally:
        server.shutdown()
    assert response.peer == f"127.0.0.1:{port}"


def test_http_client_exceptions_do_not_escape_as_themselves(monkeypatch, client):
    """Callers handle SentinelError. A leaked http.client exception is one no
    caller catches, which turns a transport blip into a 500."""

    class _Boom:
        def __init__(self, _destination):
            pass

        def request(self, *_a, **_kw):
            raise http.client.BadStatusLine("garbage")

        def close(self):
            pass

    broken = HardenedHttpClient(
        policy=OutboundPolicy(
            allowed_schemes=frozenset({"http"}), allow_private_destinations=True
        ),
        connection_factory=_Boom,
    )
    with pytest.raises(OutboundUnavailable):
        broken.request(method="GET", url="http://127.0.0.1:1/x")


# ── DNS64 / NAT64 (found on the first real STS run, 2026-09-24) ──────────────


def _resolving_to(monkeypatch, *addresses):
    def fake(host, port, **_kw):
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in addresses]
    monkeypatch.setattr("sentinel.infrastructure.outbound.socket.getaddrinfo", fake)


def test_a_nat64_translation_of_a_public_address_is_permitted(monkeypatch):
    """On a DNS64 network every AAAA is 64:ff9b:: plus the IPv4. Python calls the
    prefix reserved; refusing it refused every public host, STS included."""
    _resolving_to(monkeypatch, "209.54.180.124", "64:ff9b::d136:b47c")
    destination = validate_destination("https://sts.amazonaws.com/", OutboundPolicy())
    assert destination.addresses == ("209.54.180.124", "64:ff9b::d136:b47c")


@pytest.mark.parametrize("translated, reason", [
    ("64:ff9b::7f00:1", "loopback"),                 # 127.0.0.1
    ("64:ff9b::a9fe:a9fe", "link-local"),            # 169.254.169.254, the metadata service
    ("64:ff9b::a00:1", "private"),                   # 10.0.0.1
])
def test_a_nat64_translation_of_an_internal_address_is_still_refused(monkeypatch, translated, reason):
    """Unwrapping must judge the embedded address, or the prefix becomes a bypass."""
    _resolving_to(monkeypatch, translated)
    with pytest.raises(OutboundRefused) as refused:
        validate_destination("https://internal.example/", OutboundPolicy())
    assert reason in str(refused.value)


def test_the_local_use_nat64_prefix_is_not_unwrapped(monkeypatch):
    """64:ff9b:1::/48 (RFC 8215) is for a site's own translator; it stays refused."""
    _resolving_to(monkeypatch, "64:ff9b:1::d136:b47c")
    with pytest.raises(OutboundRefused):
        validate_destination("https://sts.amazonaws.com/", OutboundPolicy())
