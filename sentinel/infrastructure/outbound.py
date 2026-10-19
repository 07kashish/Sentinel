r"""The only sanctioned way this process makes an outbound HTTP request.

WHY THIS MODULE EXISTS
----------------------
`urllib.request.urlopen` is not safe to point at a configured URL, and the reason
is not obvious from reading it. Proven against this codebase before this module
existed:

    a gateway that answers 302 -> http://127.0.0.1/stolen receives the request,
    and the redirect target receives `Authorization: Bearer <attestation token>`

urllib's `HTTPRedirectHandler` builds the follow-up request with the original
headers intact, and it permits an https -> http downgrade. So one open redirect
at the attestation gateway -- or one compromised gateway, or one operator typo in
`SENTINEL_ATTESTATION_ENDPOINT` -- is simultaneously a credential exfiltration and
a request-forgery primitive aimed at the internal network. `startswith("https://")`
on the configured endpoint does not touch either half of that.

THE FOUR DEFENCES, AND WHY EACH ONE IS LOAD-BEARING
---------------------------------------------------
1. **Redirects are refused, never followed.** A 3xx is an error. This is the
   defence that closes the proven leak, and it is a refusal rather than a
   "follow but strip Authorization" because a redirect an attestation gateway did
   not intend is itself the signal that something is wrong. There is no legitimate
   reason for an anchoring API to redirect a POST.

2. **The destination address is validated AFTER resolution, and the connection
   goes to the address that was validated.** Validating the hostname is
   theatre: `metadata.attacker.example` resolves to 169.254.169.254 and passes
   any string check. Validating post-resolution also neutralises every
   obfuscated literal (octal, decimal, IPv4-mapped IPv6, NAT64) for free,
   because by then it is 4 or 16 bytes and no longer a string.

   Then `connect()` dials the pre-validated IP rather than re-resolving. A
   resolver that answers "public" to the check and "127.0.0.1" to the connect --
   DNS rebinding -- has nothing to rebind, because there is no second lookup.

3. **Every resolved address must pass, not just the one used.** A hostname with
   both a public and a private A record would otherwise be a coin flip that the
   attacker gets to re-toss.

4. **The response is bounded.** An endpoint that streams forever is a memory
   exhaustion primitive reachable from a config value.

WHAT THIS DELIBERATELY DOES NOT DO
----------------------------------
No connection pooling, no keep-alive, no retry. Retry policy belongs to the
caller that knows whether the operation is idempotent -- the attestation gateway
carries an idempotency key precisely so that decision can be made there. A
transport that silently retries a non-idempotent POST is a duplicate-execution
bug wearing a helpful hat.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Iterator, Mapping, Sequence
from urllib.parse import urlsplit

from sentinel.domain.errors import SentinelError, TransientFailure

__all__ = [
    "OutboundStream",
    "HardenedHttpClient",
    "OutboundPolicy",
    "OutboundRefused",
    "OutboundResponse",
    "OutboundUnavailable",
    "assert_reachable",
    "inspect_url",
    "validate_destination",
]


class OutboundRefused(SentinelError):
    """The request was refused before or during transmission on policy grounds.

    Never retried. A refusal means the destination or the response violated a
    security rule, and retrying an identical request reaches the same verdict --
    while a caller that retries a refusal turns a blocked SSRF attempt into a
    blocked SSRF attempt repeated until something gives.
    """

    is_retryable = False


class OutboundUnavailable(TransientFailure):
    """The destination was permitted but could not be reached. Retryable."""


#: Header names this client will never transmit, whatever a caller passes.
#:
#: `Host` is computed from the URL -- letting a caller set it is how you reach an
#: internal vhost through a permitted edge. Hop-by-hop headers are meaningless on
#: a fresh connection and are a request-smuggling toolkit. `Cookie` is refused
#: because nothing here is cookie-authenticated and an outbound cookie is either
#: a mistake or an exfiltration channel.
_FORBIDDEN_HEADERS = frozenset(
    {
        "host",
        "cookie",
        "connection",
        "proxy-connection",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "keep-alive",
        "expect",
    }
)


@dataclass(frozen=True, slots=True)
class OutboundPolicy:
    """What this client is permitted to do. Explicit, because defaults get shipped."""

    #: Schemes allowed. `https` only: a bearer token on a cleartext hop is a
    #: disclosed bearer token, and the attestation payload is evidence.
    allowed_schemes: frozenset[str] = frozenset({"https"})

    #: Permit RFC1918 / loopback destinations. OFF by default and ON only as a
    #: deliberate deployment decision -- an on-prem gateway on 10.0.0.0/8 is a
    #: real configuration, and pretending otherwise would push operators to
    #: disable validation wholesale. Narrow it with `allowed_hosts`.
    allow_private_destinations: bool = False

    #: If non-empty, the host must appear here. This is the control to reach for
    #: when `allow_private_destinations` has to be on: an allowlist of one
    #: internal hostname is a far smaller grant than "all of RFC1918".
    allowed_hosts: frozenset[str] = frozenset()

    #: Refuse a response body larger than this rather than buffering it.
    max_response_bytes: int = 1_048_576

    #: Refuse more response headers than this. A response with ten thousand
    #: headers costs memory before any body is read.
    max_response_headers: int = 100

    connect_timeout_seconds: float = 5.0
    read_timeout_seconds: float = 20.0

    #: Minimum TLS version. 1.2 floor; 1.0/1.1 are withdrawn.
    minimum_tls: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2

    def describe(self) -> str:
        scope = ",".join(sorted(self.allowed_hosts)) or "any public address"
        return (
            f"schemes={'/'.join(sorted(self.allowed_schemes))} "
            f"private={'allowed' if self.allow_private_destinations else 'refused'} "
            f"scope={scope}"
        )


@dataclass(frozen=True, slots=True)
class OutboundResponse:
    """A bounded, fully-read response. No streaming handle escapes this module."""

    status: int
    headers: Mapping[str, str]
    body: bytes
    #: The address actually connected to, for the audit trail. "we called the
    #: gateway" is not an auditable statement; "we called 203.0.113.7:443" is.
    peer: str

    def json(self) -> Any:
        try:
            return json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OutboundRefused(f"response was not valid JSON: {exc}") from exc


@dataclass(frozen=True, slots=True)
class _Destination:
    scheme: str
    host: str
    port: int
    path: str
    addresses: tuple[str, ...] = field(default_factory=tuple)


def inspect_url(url: str, policy: OutboundPolicy) -> _Destination:
    """Vet everything about a URL that does NOT require a name lookup.

    Split out from `validate_destination` so an adapter can reject a malformed or
    disallowed endpoint in its CONSTRUCTOR -- fail at boot, not at the first
    incident -- without making object construction depend on DNS. Resolution is
    deliberately left to request time, because a name that was public at boot can
    be private by the time it is used, and only the pre-connect check catches that.
    """
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise OutboundRefused(f"unparseable URL: {exc}") from exc

    if parts.scheme not in policy.allowed_schemes:
        raise OutboundRefused(
            f"scheme {parts.scheme!r} is not permitted; allowed: "
            f"{', '.join(sorted(policy.allowed_schemes))}"
        )
    if parts.username or parts.password:
        # Credentials in a URL are both a disclosure (they land in logs and
        # metrics labels) and a classic parser-confusion trick, where
        # https://trusted.example@attacker.example reads as trusted to a human
        # and resolves to the attacker for the machine.
        raise OutboundRefused("credentials embedded in a URL are refused")
    host = parts.hostname
    if not host:
        raise OutboundRefused("URL has no host")
    if policy.allowed_hosts and host.lower() not in policy.allowed_hosts:
        raise OutboundRefused(
            f"host {host!r} is not in the outbound allowlist "
            f"({', '.join(sorted(policy.allowed_hosts))})"
        )
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise OutboundRefused(f"invalid port: {exc}") from exc

    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    return _Destination(scheme=parts.scheme, host=host, port=port, path=path)


def validate_destination(url: str, policy: OutboundPolicy) -> _Destination:
    """Inspect, resolve and vet a URL. Raises `OutboundRefused` with the reason.

    Every resolved address must pass, not merely the one that will be used: a
    hostname carrying both a public and a private record would otherwise be a
    coin flip the attacker gets to re-toss on every request.
    """
    inspected = inspect_url(url, policy)
    addresses = _resolve(inspected.host, inspected.port)
    for raw in addresses:
        verdict = _classify(raw)
        if verdict is not None and not policy.allow_private_destinations:
            raise OutboundRefused(
                f"{inspected.host} resolves to {raw}, which is {verdict}. "
                "Refusing: a configured hostname that resolves inside the network "
                "is the shape of a request-forgery or cloud-metadata attempt. Set "
                "allow_private_destinations with an explicit allowed_hosts entry "
                "if this destination is genuinely internal."
            )
    return _Destination(
        scheme=inspected.scheme,
        host=inspected.host,
        port=inspected.port,
        path=inspected.path,
        addresses=addresses,
    )


def _resolve(host: str, port: int) -> tuple[str, ...]:
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        # Resolution failure is transient-shaped, not a policy refusal: DNS being
        # down must not look like an attack in the audit trail.
        raise OutboundUnavailable(f"could not resolve {host}: {exc}") from exc
    seen: list[str] = []
    for info in infos:
        # getaddrinfo's sockaddr is typed as a union because AF_INET6 carries
        # scope and flow fields. Element 0 is always the address string; str()
        # states that rather than leaving the union to be appended to a
        # list[str].
        address = str(info[4][0])
        if address not in seen:
            seen.append(address)
    if not seen:
        raise OutboundUnavailable(f"{host} resolved to no addresses")
    return tuple(seen)


_NAT64_WELL_KNOWN = ipaddress.ip_network("64:ff9b::/96")


def _classify(raw: str) -> str | None:
    """Name why an address is not a permitted public destination, or None.

    Returns a reason string rather than a bool so the refusal can say
    "link-local (cloud metadata)" instead of "not allowed", which is the
    difference between an operator fixing config and an operator disabling the
    check.
    """
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return "not a valid IP address"

    # ::ffff:127.0.0.1 is loopback wearing an IPv6 costume. Unwrap before
    # judging, or every v4 rule is bypassable by prefixing ::ffff:.
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    sixtofour = getattr(address, "sixtofour", None)
    if sixtofour is not None:
        address = sixtofour
    # DNS64 answers every AAAA query with the NAT64 well-known prefix (RFC
    # 6052, 64:ff9b::/96) and the IPv4 address in the low 32 bits. Python
    # counts the prefix as IETF-reserved, so on such a network -- a phone
    # tether, several ISPs, the first real STS run of this repository -- the
    # client refused every public host. Judge the EMBEDDED address instead:
    # a translation of a private or loopback IPv4 is still refused, a
    # translation of a public one is that public host reached through the
    # translator. The local-use prefix 64:ff9b:1::/48 is not unwrapped.
    if address.version == 6 and address in _NAT64_WELL_KNOWN:
        address = ipaddress.ip_address(int(address) & 0xFFFF_FFFF)

    if address.is_unspecified:
        return "the unspecified address"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        # 169.254.169.254 and fe80::/10. The single most valuable SSRF target in
        # any cloud, because it hands out credentials without authentication.
        return "link-local (cloud instance metadata lives here)"
    if address.is_multicast:
        return "multicast"
    if address.is_reserved:
        return "IETF-reserved"
    if address.is_private:
        return "private (RFC1918 / unique-local)"
    if not address.is_global:
        return "not globally routable"
    return None


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """An HTTPS connection that dials a pre-validated IP with correct SNI.

    This is the whole DNS-rebinding defence. `HTTPSConnection(host)` resolves the
    hostname itself, which reopens the window between "we checked the address" and
    "we connected to an address". Here `connect()` uses the address that was
    already vetted, while TLS still verifies the certificate against the
    HOSTNAME -- so pinning the address costs nothing in authentication strength.
    """

    def __init__(self, host: str, port: int, *, address: str, context, timeout: float):
        super().__init__(host, port, timeout=timeout, context=context)
        self._pinned_address = address

    def connect(self) -> None:  # pragma: no cover - exercised through request()
        sock = socket.create_connection(
            (self._pinned_address, self.port), timeout=self.timeout
        )
        # Nagle off: these are small single-shot request/response exchanges and
        # coalescing only adds latency to an operation on the incident path.
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # `_context` is set by HTTPSConnection.__init__ and is absent from the
        # typeshed stub for it. Narrowly ignored rather than restructured: the
        # alternative is reimplementing the pinning handshake to avoid touching
        # a private attribute the stdlib itself relies on.
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)  # type: ignore[attr-defined]


class HardenedHttpClient:
    """Makes one request, refuses redirects, returns a bounded response.

    Injectable via `connection_factory` so tests drive it without a network, and
    so the loopback-only test server used by the SSRF suite can be reached
    without weakening the policy that production runs.
    """

    __slots__ = ("_policy", "_context", "_factory")

    def __init__(
        self,
        *,
        policy: OutboundPolicy | None = None,
        connection_factory: Any = None,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self._policy = policy or OutboundPolicy()
        self._factory = connection_factory
        if ssl_context is not None:
            self._context = ssl_context
        else:
            context = ssl.create_default_context()
            context.minimum_version = self._policy.minimum_tls
            # Belt and braces: these are the defaults, and they are the two
            # settings whose accidental removal turns TLS into obfuscation.
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            self._context = context

    @property
    def policy(self) -> OutboundPolicy:
        return self._policy

    def request(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        idempotent: bool = False,
    ) -> OutboundResponse:
        """Perform one request. `idempotent` is recorded, never acted on.

        It exists so the call site states the property explicitly, and so an
        audit of "what can this process re-send" is a grep rather than an
        archaeology exercise.
        """
        if method.upper() not in {"GET", "POST", "PUT", "HEAD", "DELETE"}:
            raise OutboundRefused(f"method {method!r} is not permitted")
        destination = validate_destination(url, self._policy)
        vetted = _reject_forbidden(headers or {})

        connection = self._connect(destination)
        try:
            connection.request(method.upper(), destination.path, body=body, headers=vetted)
            response = connection.getresponse()
            status = response.status
            if 300 <= status < 400:
                location = response.getheader("Location", "")
                # THE defence. Following this is how the attestation token
                # reached a plain-HTTP loopback address in the PoC that
                # motivated this module.
                raise OutboundRefused(
                    f"destination answered HTTP {status} redirecting to "
                    f"{location or '(no Location)'}. Redirects are refused: "
                    "following one forwards the Authorization header to whatever "
                    "the redirect names, which is a credential-exfiltration and "
                    "request-forgery primitive. No legitimate API redirects here."
                )
            collected = response.getheaders()
            if len(collected) > self._policy.max_response_headers:
                raise OutboundRefused(
                    f"response carried {len(collected)} headers, over the "
                    f"{self._policy.max_response_headers} limit"
                )
            # Read one byte past the limit so "exactly at the limit" and "over
            # it" are distinguishable without trusting Content-Length, which the
            # peer controls and can understate.
            payload = response.read(self._policy.max_response_bytes + 1)
            if len(payload) > self._policy.max_response_bytes:
                raise OutboundRefused(
                    f"response body exceeded {self._policy.max_response_bytes} "
                    "bytes; refusing to buffer an unbounded response"
                )
        except OutboundRefused:
            raise
        except (TimeoutError, socket.timeout) as exc:
            raise OutboundUnavailable(f"{destination.host} timed out") from exc
        except ssl.SSLError as exc:
            # A TLS failure is a policy refusal, not a transient one: retrying an
            # unverifiable certificate just repeats the same wrong answer.
            raise OutboundRefused(f"TLS verification failed for {destination.host}: {exc}") from exc
        except (http.client.HTTPException, OSError) as exc:
            raise OutboundUnavailable(
                f"{destination.host} unreachable: {type(exc).__name__}: {exc}"
            ) from exc
        finally:
            connection.close()

        return OutboundResponse(
            status=status,
            headers={k.lower(): v for k, v in collected},
            body=payload,
            peer=f"{destination.addresses[0]}:{destination.port}",
        )

    @contextmanager
    def stream(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        max_event_bytes: int = 65_536,
        max_seconds: float = 120.0,
    ) -> Iterator["OutboundStream"]:
        """One request whose `text/event-stream` reply is read event by event.

        THE GUARANTEE THIS KEEPS. `request` promises that no streaming handle
        escapes this module, and that is still true: what the caller receives
        is an iterator of BOUNDED byte strings, one per server-sent event. The
        socket stays here, is read only while the caller is inside the `with`
        block, and is closed when the block ends for any reason, including the
        caller abandoning the iterator. Every other protection is the same code
        path as `request`: destination vetting after resolution, header vetting,
        no redirects, the TLS floor, the header-count limit.

        THE BOUNDS. One event may not exceed `max_event_bytes`; the stream as a
        whole may not exceed the policy's response limit or `max_seconds` of
        wall time, so a server cannot hold a worker by trickling bytes. A reply
        that is not an event stream is read whole, under the usual limit, and
        returned in `body` with no events.
        """
        if method.upper() not in {"GET", "POST"}:
            raise OutboundRefused(f"method {method!r} is not permitted for a streamed request")
        destination = validate_destination(url, self._policy)
        vetted = _reject_forbidden(headers or {})
        connection = self._connect(destination)
        try:
            connection.request(method.upper(), destination.path, body=body, headers=vetted)
            response = connection.getresponse()
            if 300 <= response.status < 400:
                raise OutboundRefused(
                    f"destination answered HTTP {response.status}; redirects are refused for the "
                    "same reason as on every other request: they forward the Authorization header"
                )
            collected = response.getheaders()
            if len(collected) > self._policy.max_response_headers:
                raise OutboundRefused(f"response carried {len(collected)} headers, over the limit")
            lowered = {k.lower(): v for k, v in collected}
            peer = f"{destination.addresses[0]}:{destination.port}"
            if "text/event-stream" not in lowered.get("content-type", "").lower():
                payload = response.read(self._policy.max_response_bytes + 1)
                if len(payload) > self._policy.max_response_bytes:
                    raise OutboundRefused("response body exceeded the limit; refusing to buffer it")
                yield OutboundStream(status=response.status, headers=lowered, peer=peer, body=payload, events=iter(()))
            else:
                yield OutboundStream(
                    status=response.status, headers=lowered, peer=peer, body=b"",
                    events=_sse_events(response, max_event_bytes=max_event_bytes,
                                       max_total_bytes=self._policy.max_response_bytes,
                                       deadline=time.monotonic() + max_seconds),
                )
        except OutboundRefused:
            raise
        except (TimeoutError, socket.timeout) as exc:
            raise OutboundUnavailable(f"{destination.host} timed out") from exc
        except ssl.SSLError as exc:
            raise OutboundRefused(f"TLS verification failed for {destination.host}: {exc}") from exc
        except (http.client.HTTPException, OSError) as exc:
            raise OutboundUnavailable(f"{destination.host} unreachable: {type(exc).__name__}: {exc}") from exc
        finally:
            connection.close()

    def _connect(self, destination: _Destination):
        if self._factory is not None:
            return self._factory(destination)
        if destination.scheme != "https":
            # Reachable only when a policy explicitly allows http, which the
            # default does not.
            return http.client.HTTPConnection(
                destination.addresses[0],
                destination.port,
                timeout=self._policy.read_timeout_seconds,
            )
        return _PinnedHTTPSConnection(
            destination.host,
            destination.port,
            address=destination.addresses[0],
            context=self._context,
            timeout=self._policy.read_timeout_seconds,
        )


@dataclass(frozen=True, slots=True)
class OutboundStream:
    """A streamed reply: its status and headers, and its events or its body."""

    status: int
    headers: Mapping[str, str]
    peer: str
    body: bytes
    #: One bounded byte string per server-sent event. Valid only inside the
    #: `with` block that produced this object.
    events: Iterator[bytes]


def _sse_events(response: Any, *, max_event_bytes: int, max_total_bytes: int, deadline: float) -> Iterator[bytes]:
    """Split an event stream on blank lines, refusing anything unbounded."""
    total = 0
    pending: list[bytes] = []
    size = 0
    while True:
        if time.monotonic() > deadline:
            raise OutboundRefused("event stream exceeded its time limit; refusing to hold a worker open")
        line = response.readline(max_event_bytes + 1)
        if not line:
            if pending:
                yield b"".join(pending)
            return
        total += len(line)
        size += len(line)
        if size > max_event_bytes:
            raise OutboundRefused(f"one server-sent event exceeded {max_event_bytes} bytes")
        if total > max_total_bytes:
            raise OutboundRefused(f"event stream exceeded {max_total_bytes} bytes")
        if line in (b"\n", b"\r\n"):
            if pending:
                yield b"".join(pending)
            pending, size = [], 0
        else:
            pending.append(line)


def _reject_forbidden(headers: Mapping[str, str]) -> dict[str, str]:
    """Refuse rather than silently drop. A dropped Host header is a silent bug."""
    vetted: dict[str, str] = {}
    for name, value in headers.items():
        if name.lower() in _FORBIDDEN_HEADERS:
            raise OutboundRefused(
                f"header {name!r} may not be set by a caller; it is computed or "
                "forbidden by this client"
            )
        if "\n" in value or "\r" in value or "\n" in name or "\r" in name:
            # CRLF in a header value is request splitting. http.client checks
            # this too; doing it here means the refusal is ours and is auditable.
            raise OutboundRefused(f"header {name!r} contains a newline")
        vetted[name] = value
    return vetted


def assert_reachable(url: str, policy: OutboundPolicy) -> Sequence[str]:
    """Vet a configured endpoint at STARTUP and return the addresses it resolves to.

    Called from configuration validation so a deployment pointed at
    169.254.169.254 refuses to boot, rather than discovering it during the first
    incident it was installed to handle.
    """
    return validate_destination(url, policy).addresses
