"""Shared machinery for the agent-platform discovery connectors.

WHY THIS IS SEPARATE FROM `ai_connectors.py`
---------------------------------------------
The module size cap. Five connectors plus their shared request handling came
to 897 lines against a 800-line fitness limit, so the parts every connector
uses live here. A split, not a migration: `ai_connectors.py` re-exports the
names its callers already reach for.

WHAT IS ACTUALLY SHARED
------------------------
`_get_json` is the important one. Every connector needs the same three
failures -- refused, non-200, and a body that will not parse -- collapsed to
"record the reason and do not pretend the page was empty". Writing that five
times is five chances to get the third case wrong, and the third case is the
one that turns a broken scan into a clean estate.
"""

from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass
from typing import Any, Mapping

from sentinel.domain.assets import Unreachable
from sentinel.infrastructure.outbound import (
    HardenedHttpClient,
    OutboundRefused,
    OutboundUnavailable,
)

__all__ = [
    "EXTERNAL_VALIDATION_NOTE",
    "MAX_PAGES",
    "BearerCredentials",
    "McpEndpoint",
    # Underscored but exported: private to the PACKAGE, not to the module.
    # They are shared implementation for the connectors and nothing outside
    # this package should reach for them, which the underscore says and the
    # export does not contradict.
    "_get_json",
    "_now",
    "_text",
]

#: Stated in the module that produces the evidence, not only in a document.
#: A reader who finds an inventory from one of these connectors needs to know
#: what has and has not been validated, and a note in a separate file is a
#: note nobody reads at the moment it matters.
EXTERNAL_VALIDATION_NOTE = (
    "REQUIRES EXTERNAL VALIDATION: this connector has never authenticated "
    "against a real tenant. Request shapes and scopes come from the vendor's "
    "published contract, which is not the same as a successful call."
)

#: Cap on pages followed in one discovery pass. A connector that followed
#: tokens indefinitely turns a paginated endpoint into an unbounded outbound
#: loop -- and the honest handling of hitting the cap is
#: `pagination_complete=False`, which this sets, rather than a silent stop.
MAX_PAGES = 20


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


@dataclass(frozen=True, slots=True)
class BearerCredentials:
    """A bearer token and the tenant or project it is scoped to.

    The token is NOT exposed by `__repr__`: a credential in a traceback ends up
    in a log, and a log is the one place this codebase's rules say a secret may
    never be. `dataclass(repr=False)` would drop every field, so the repr is
    written explicitly and names the scope only.
    """

    token: str
    #: Tenant id, project id or organisation id -- whatever the platform scopes
    #: by. Recorded because it belongs in `coverage.scope`.
    scope: str = ""

    def __post_init__(self) -> None:
        if not self.token.strip():
            raise ValueError(
                "a bearer credential with an empty token would produce an "
                "unauthenticated request that returns 401, and a 401 recorded "
                "as `unreachable` reads as an outage rather than as a missing "
                "credential. Refusing to construct one."
            )

    def __repr__(self) -> str:
        return f"BearerCredentials(scope={self.scope!r}, token=<redacted>)"


@dataclass(frozen=True, slots=True)
class McpEndpoint:
    """One MCP server to enumerate. `token` may be empty for an open server."""

    url: str
    token: str = ""
    label: str = ""

    def __repr__(self) -> str:
        return (
            f"McpEndpoint(url={self.url!r}, label={self.label!r}, "
            f"token={'<redacted>' if self.token else '<none>'})"
        )


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
    """One request, returning parsed JSON or None with the reason recorded.

    Returns None for every failure mode -- refusal, non-200 and unparseable
    body alike -- because the caller's correct response to all three is the
    same: record it as unreachable and do not pretend the page was empty.

    A body that will not parse is NOT treated as an empty result. That is the
    defect shape this codebase has hit repeatedly: a scan that reports zero
    findings because the parse failed, indistinguishable from a clean estate.
    """
    try:
        response = client.request(
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
    if response.status != 200:
        unreachable.append(
            Unreachable(target=target, reason=f"HTTP {response.status}")
        )
        return None
    try:
        return json.loads(response.body.decode("utf-8", errors="replace"))
    except (ValueError, UnicodeDecodeError) as exc:
        unreachable.append(
            Unreachable(
                target=target,
                reason=(
                    f"the response body did not parse as JSON ({exc}). "
                    "Recorded as unreachable rather than as an empty page, "
                    "because a parse failure that reads as 'nothing found' is "
                    "indistinguishable from a clean estate."
                ),
            )
        )
        return None


def _text(value: Any) -> str:
    """A field's value as a string, or empty. Never `str(None)`."""
    return value.strip() if isinstance(value, str) else ""

