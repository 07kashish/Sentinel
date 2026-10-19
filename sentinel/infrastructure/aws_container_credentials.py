"""Credentials from the container credential endpoint that ECS and Fargate provide.

A task on Fargate has no access key. Its IAM task role is reached through an
HTTP endpoint the agent exposes to the container -- `169.254.170.2` plus the
path in `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` -- which answers a JSON
document holding a short-lived key, secret and session token with an expiry.
Every AWS SDK does this quietly; this codebase has no SDK, so it is done here,
in the open, with the same restrictions the rest of the outbound code keeps:

  * ONLY the documented hosts are dialled: the ECS agent's link-local
    address (v4 and v6) and loopback, which the FULL_URI variant permits.
    This is the one place link-local is reached on purpose, and it is reached
    by exact address, never by a name that resolves to it.
  * plain `http.client`, no redirects, a two-second timeout, a bounded body.
  * the document is cached and refreshed five minutes before it expires;
    nothing here is written to disk or included in any message.

The environment variables themselves are read by `settings_parsers`, like
every other configuration value; this module is handed the resolved URI.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from urllib.parse import urlsplit

__all__ = ["AwsCredential", "ContainerCredentialSource", "ContainerCredentialsUnavailable"]

#: Where an ECS agent serves task-role credentials (RFC 3927 v4, and the v6
#: address AWS documents), plus loopback for the FULL_URI variant.
PERMITTED_HOSTS = frozenset({"169.254.170.2", "169.254.170.23", "fd00:ec2::23", "127.0.0.1", "::1", "localhost"})
REFRESH_BEFORE = timedelta(minutes=5)
MAX_BODY_BYTES = 16 * 1024


class ContainerCredentialsUnavailable(RuntimeError):
    """The endpoint did not yield a usable credential."""


@dataclass(frozen=True, slots=True)
class AwsCredential:
    access_key_id: str
    secret_access_key: str = field(repr=False)
    session_token: str = field(default="", repr=False)
    expires_at: datetime | None = None


class ContainerCredentialSource:
    """`current()` returns a live task-role credential, fetching when needed."""

    __slots__ = ("_uri", "_authorization", "_timeout", "_connect", "_now", "_lock", "_cached")

    def __init__(
        self,
        uri: str,
        *,
        authorization: str = "",
        timeout_seconds: float = 2.0,
        connection_factory: Callable[..., Any] | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        parts = urlsplit(uri)
        host = (parts.hostname or "").strip("[]").lower()
        if parts.scheme != "http" or host not in PERMITTED_HOSTS or not parts.path:
            raise ContainerCredentialsUnavailable(
                "the container credential URI must be plain http to the ECS agent's "
                "address or loopback with a path; refusing anything else"
            )
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if host != "localhost":
                raise ContainerCredentialsUnavailable("the credential host must be an address, not a name") from None
        self._uri = uri
        self._authorization = authorization
        self._timeout = timeout_seconds
        self._connect = connection_factory or http.client.HTTPConnection
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._lock = threading.Lock()
        self._cached: AwsCredential | None = None

    def current(self) -> AwsCredential:
        with self._lock:
            cached = self._cached
            if cached is not None and (cached.expires_at is None or cached.expires_at - self._now() > REFRESH_BEFORE):
                return cached
            self._cached = self._fetch()
            return self._cached

    def _fetch(self) -> AwsCredential:
        parts = urlsplit(self._uri)
        headers = {"accept": "application/json"}
        if self._authorization:
            headers["authorization"] = self._authorization
        try:
            connection = self._connect(str(parts.hostname), parts.port or 80, timeout=self._timeout)
            try:
                connection.request("GET", parts.path + (f"?{parts.query}" if parts.query else ""), headers=headers)
                response = connection.getresponse()
                status, body = response.status, response.read(MAX_BODY_BYTES + 1)
            finally:
                connection.close()
        except OSError as exc:
            raise ContainerCredentialsUnavailable(f"the container credential endpoint is unreachable: {type(exc).__name__}") from exc
        if status != 200 or len(body) > MAX_BODY_BYTES:
            raise ContainerCredentialsUnavailable(f"the container credential endpoint answered HTTP {status}")
        try:
            document = json.loads(body)
        except ValueError as exc:
            raise ContainerCredentialsUnavailable("the container credential endpoint returned something other than JSON") from exc
        key, secret, token = (str(document.get(k) or "") for k in ("AccessKeyId", "SecretAccessKey", "Token"))
        if not key or not secret or not token:
            raise ContainerCredentialsUnavailable("the container credential document is incomplete")
        expires = None
        raw = str(document.get("Expiration") or "")
        if raw:
            try:
                expires = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ContainerCredentialsUnavailable("the container credential expiry is unreadable") from exc
        return AwsCredential(access_key_id=key, secret_access_key=secret, session_token=token, expires_at=expires)
