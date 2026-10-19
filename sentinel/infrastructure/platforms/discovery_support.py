"""Shared machinery for the second wave of discovery connectors.

WHY A SECOND SUPPORT MODULE
---------------------------
`ai_discovery.py` carries what the first five connectors share: a bearer
credential, `_get_json`, the page cap. The nine connectors added after it
(Copilot Studio, Agentforce, ServiceNow, Databricks, Slack, GitLab, Okta,
Entra Agent ID, local MCP client configs) need three more things, and each of
them was about to be written nine times:

  * `paginate()` -- one loop with a hard page cap, a same-cursor guard and a
    truncation record, so no connector can follow a cursor forever or stop at
    the cap without saying so;
  * `HostCredentials` -- a token bound to the ONE host it may be presented to,
    validated at construction, because most of these platforms are tenant
    hosts (`org.my.salesforce.com`, `acme.service-now.com`, `dev.okta.com`) and
    a hostname interpolated into a URL is a hostname that must be checked;
  * `_get_json` with a status-aware reason. `HTTP 401`, `HTTP 403` and
    `HTTP 429` are three different operator actions (rotate, grant, wait) and
    a reason that says only "HTTP 4xx" makes the operator look it up.

Everything here is private to the package (underscored, exported) exactly as
`ai_discovery.py` does it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence

from sentinel.domain.assets import Unreachable
from sentinel.infrastructure.outbound import (
    HardenedHttpClient,
    OutboundRefused,
    OutboundResponse,
    OutboundUnavailable,
)
from sentinel.infrastructure.platforms.ai_discovery import (
    EXTERNAL_VALIDATION_NOTE,
    MAX_PAGES,
    _now,
    _text,
)

__all__ = [
    "EXTERNAL_VALIDATION_NOTE",
    "MAX_PAGES",
    "HostCredentials",
    "Paged",
    "paginate",
    "validate_host",
    "_decode_json",
    "_get_json",
    "_get_response",
    "_now",
    "_text",
]

#: A DNS hostname with at least one dot: label rules from RFC 1123, and the
#: dot because every platform here is reached at a tenant subdomain of a
#: vendor domain. A bare label would be an intranet name this connector was
#: never meant to be pointed at.
_HOST_RE = re.compile(
    r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)

#: Reasons keyed by the statuses an operator acts on differently. Anything
#: else is reported as its bare status, which is still a reason.
_STATUS_REASONS: Mapping[int, str] = MappingProxyType({
    401: "HTTP 401: the credential was rejected (expired, revoked or wrong audience)",
    403: "HTTP 403: the credential is valid but lacks permission for this listing",
    404: "HTTP 404: the endpoint does not exist on this host",
    429: "HTTP 429: rate limited; the request was NOT retried, so this is a subset",
})


def validate_host(host: str, *, what: str = "host") -> str:
    """The host lowercased, or `ValueError`.

    A host is interpolated into every request URL a connector builds, so an
    invalid one is refused at construction rather than sent. Refusing at
    construction means the connector is never built -- absent, not
    present-and-failing.
    """
    lowered = str(host).strip().lower()
    if not _HOST_RE.match(lowered):
        raise ValueError(
            f"refusing to build a connector for {what} {host!r}: it is "
            "interpolated into the request URL and must be a DNS hostname "
            "with at least one dot"
        )
    return lowered


@dataclass(frozen=True, slots=True)
class HostCredentials:
    """A token and the ONE host it may be presented to.

    The host is part of the credential, not a separate setting, because a
    token presented to the wrong host is a disclosed token. `__repr__` names
    the host and scope and never the token: a credential in a traceback ends
    up in a log.
    """

    token: str
    host: str
    #: Tenant, org or workspace label for `coverage.scope`. Defaults to host.
    scope: str = ""

    def __post_init__(self) -> None:
        if not str(self.token).strip():
            raise ValueError(
                "a host credential with an empty token would produce an "
                "unauthenticated request that returns 401, and a 401 recorded "
                "as `unreachable` reads as an outage rather than as a missing "
                "credential. Refusing to construct one."
            )
        object.__setattr__(self, "host", validate_host(self.host))
        if not self.scope:
            object.__setattr__(self, "scope", self.host)

    def __repr__(self) -> str:
        return (
            f"HostCredentials(host={self.host!r}, scope={self.scope!r}, "
            "token=<redacted>)"
        )

    @property
    def base_url(self) -> str:
        return f"https://{self.host}"


def _get_response(
    client: HardenedHttpClient,
    *,
    url: str,
    headers: Mapping[str, str],
    target: str,
    unreachable: list[Unreachable],
    method: str = "GET",
    body: bytes = b"",
) -> OutboundResponse | None:
    """One request, returning the 200 response or None with the reason recorded.

    Every non-200 is None, including 429: a rate-limited page is a page this
    scan did not see, and retrying inside a discovery pass turns one connector
    into a load generator against a tenant that just asked it to slow down.
    """
    try:
        return_value = client.request(
            method=method,
            url=url,
            headers=dict(headers),
            body=body,
            idempotent=True,
        )
    except (OutboundRefused, OutboundUnavailable) as exc:
        unreachable.append(
            Unreachable(target=target, reason=f"{type(exc).__name__}: {exc}")
        )
        return None
    if return_value.status != 200:
        unreachable.append(
            Unreachable(
                target=target,
                reason=_STATUS_REASONS.get(
                    return_value.status, f"HTTP {return_value.status}"
                ),
            )
        )
        return None
    return return_value


def _decode_json(
    response: OutboundResponse,
    *,
    target: str,
    unreachable: list[Unreachable],
) -> Any | None:
    """The body as JSON, or None with the parse failure recorded.

    A body that will not parse is NOT an empty result. That is the defect
    shape this codebase keeps meeting: a scan reporting zero because the parse
    failed, indistinguishable from a clean estate.
    """
    try:
        return response.json()
    except OutboundRefused as exc:
        unreachable.append(
            Unreachable(
                target=target,
                reason=(
                    f"the response body did not parse as JSON ({exc}). "
                    "Recorded as unreachable rather than as an empty page."
                ),
            )
        )
        return None


def _get_json(
    client: HardenedHttpClient,
    *,
    url: str,
    headers: Mapping[str, str],
    target: str,
    unreachable: list[Unreachable],
    method: str = "GET",
    body: bytes = b"",
) -> Any | None:
    """`_get_response` then `_decode_json`; None for every failure."""
    response = _get_response(
        client,
        url=url,
        headers=headers,
        target=target,
        unreachable=unreachable,
        method=method,
        body=body,
    )
    if response is None:
        return None
    return _decode_json(response, target=target, unreachable=unreachable)


@dataclass(frozen=True, slots=True)
class Paged:
    """What `paginate` collected and whether it collected all of it."""

    items: tuple[Any, ...]
    #: False when a page failed or the cap was hit with a cursor outstanding.
    complete: bool
    pages: int


def paginate(
    fetch_page: Callable[[str], tuple[Sequence[Any], str] | None],
    *,
    target: str,
    unreachable: list[Unreachable],
    max_pages: int = MAX_PAGES,
) -> Paged:
    """Follow cursors until none is left, a page fails, or the cap is hit.

    `fetch_page(cursor)` returns `(items, next_cursor)` -- an empty
    `next_cursor` meaning "last page" -- or None when the page failed, in
    which case the fetcher has ALREADY recorded why. A fetcher that records
    an `Unreachable` and still returns rows (a page whose continuation could
    not be followed) keeps its rows and the result is marked incomplete. This
    helper records the two failures only it can see: the cap, and a cursor
    that repeats, which would otherwise be an infinite loop against a tenant
    API.
    """
    collected: list[Any] = []
    cursor = ""
    seen: set[str] = set()
    pages = 0
    flawless = True
    for _ in range(max_pages):
        recorded_before = len(unreachable)
        result = fetch_page(cursor)
        pages += 1
        if len(unreachable) > recorded_before:
            # The fetcher recorded a problem but may still have returned the
            # rows it did get. Keep the rows; the listing is a subset.
            flawless = False
        if result is None:
            return Paged(items=tuple(collected), complete=False, pages=pages)
        items, next_cursor = result
        collected.extend(items)
        if not next_cursor:
            return Paged(items=tuple(collected), complete=flawless, pages=pages)
        if next_cursor == cursor or next_cursor in seen:
            unreachable.append(
                Unreachable(
                    target=target,
                    reason=(
                        "the platform returned a continuation cursor it had "
                        "already returned; following it would loop, so the "
                        "listing stopped here and is a subset"
                    ),
                )
            )
            return Paged(items=tuple(collected), complete=False, pages=pages)
        seen.add(next_cursor)
        cursor = next_cursor
    unreachable.append(
        Unreachable(
            target=target,
            reason=(
                f"stopped after {max_pages} pages with a continuation still "
                "outstanding; this is a subset"
            ),
        )
    )
    return Paged(items=tuple(collected), complete=False, pages=pages)
