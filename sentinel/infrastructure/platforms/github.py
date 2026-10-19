"""GitHub: one REST call, under a tier ceiling.

THE SINGLE-SOURCE RULE
----------------------
The pair `(method, path)` is what gets classified and what gets sent. There is
no `action` label alongside it that could say something different, and no URL
argument through which a caller could choose the host -- `api_host` is operator
configuration, because a token presented to a host an agent chose is a disclosed
token.

The path is validated to be a path: absolute, no scheme, no authority, no
traversal, no query string. The query is a separate argument and is
percent-encoded, so it cannot smuggle a second path onto the end of the first.

WHY THE CLASSIFIER SEES api.github.com EVEN ON GITHUB ENTERPRISE
------------------------------------------------------------------
`action_semantics._classify_github` recognises the canonical `api.github.com`
grammar. An Enterprise deployment's host is not in that grammar, so the
classification is computed against the canonical form while the REQUEST goes to
the configured host. Both derive from the same `(method, path)`, so this does
not open the gap the single-source rule closes -- the only thing that varies is
which server answers, which is the operator's decision and not the agent's.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, Mapping

from sentinel.application.tool_proxy import RegisteredSideEffect
from sentinel.infrastructure.outbound import HardenedHttpClient
from sentinel.infrastructure.platforms.ceiling import (
    DEFAULT_CEILING,
    bounded,
    classify_or_refuse,
    enforce_ceiling,
    call_settled,
    hardened_call,
    normalise_ceiling,
)
from sentinel.infrastructure.platforms.github_app import app_jwt, installation_scope
from sentinel.infrastructure.platforms.github_outcome import github_hint, github_reconciler
from sentinel.infrastructure.tool_adapters import ToolAdapterNotAttempted, ToolAdapterRefused

__all__ = ["GithubCredentials", "github_api_adapter"]


@dataclass(frozen=True, slots=True)
class GithubCredentials:
    """A GitHub token and the single API host it may be presented to."""

    token: str = ""
    api_host: str = "api.github.com"
    #: GitHub App mode. With all three set there is NO standing token: each
    #: operation mints an installation token scoped to the one repository and
    #: the one permission family its path names, valid for an hour at most and
    #: discarded after the call. The App's private key can sign token requests
    #: and nothing else; it cannot itself read or write a repository.
    app_id: str = ""
    installation_id: str = ""
    app_private_key: str = ""

    @property
    def brokered(self) -> bool:
        return bool(self.app_id)

    def __post_init__(self) -> None:
        app = (self.app_id, self.installation_id, self.app_private_key)
        if any(app) and not all(str(part).strip() for part in app):
            raise ToolAdapterRefused("GitHub App mode needs app_id, installation_id and app_private_key together")
        if any(app) and not (str(self.app_id).isdigit() and str(self.installation_id).isdigit()):
            raise ToolAdapterRefused("GitHub app_id and installation_id are numeric")
        if not any(app) and not str(self.token).strip():
            raise ToolAdapterRefused("GitHub token is required")
        if not re.fullmatch(r"[a-z0-9.-]{3,253}", str(self.api_host).lower()):
            raise ToolAdapterRefused(
                f"GitHub api_host {self.api_host!r} is not a valid hostname"
            )


_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"})

#: An absolute GitHub API path. The `(?!/)` matters: a protocol-relative
#: `//attacker.example` does not actually escape this adapter (the configured
#: host is prepended, so it resolves to `api.github.com//attacker.example` and
#: `validate_destination` still sees `api.github.com`) -- but it is a shape that
#: means "another host" to some URL parsers and "a path" to others, and an input
#: whose meaning depends on which parser reads it is one to refuse rather than
#: to reason about.
_PATH_RE = re.compile(r"^/(?!/)[A-Za-z0-9._~%/-]{0,512}$")


def github_api_adapter(
    *,
    client: HardenedHttpClient,
    credentials: GithubCredentials,
    ceiling: str = DEFAULT_CEILING,
) -> RegisteredSideEffect:
    """Call one GitHub REST endpoint under a tier ceiling.

    Arguments: `method`, `path`, optional `query` and `body`.
    """
    limit = normalise_ceiling(ceiling)
    host = str(credentials.api_host).lower()

    def mint(method: str, path: str) -> tuple[str, dict[str, Any]]:
        """The bearer for ONE call, and what may be said about it."""
        if not credentials.brokered:
            return credentials.token, {"mode": "static"}
        scope = installation_scope(method, path)
        issued = hardened_call(
            client, method="POST",
            url=f"https://{host}/app/installations/{credentials.installation_id}/access_tokens",
            headers={"authorization": f"Bearer {app_jwt(credentials.app_id, credentials.app_private_key)}",
                     "accept": "application/vnd.github+json", "x-github-api-version": "2022-11-28",
                     "user-agent": "sentinel-platform-adapter", "content-type": "application/json"},
            body=json.dumps(scope, separators=(",", ":")).encode("utf-8"),
        )
        body = issued["body"] if isinstance(issued["body"], Mapping) else {}
        if not 200 <= issued["status"] < 300 or not isinstance(body.get("token"), str) or not body["token"]:
            raise ToolAdapterRefused(f"github did not grant an installation token (HTTP {issued['status']})")
        return body["token"], {"mode": "installation_token", "expires_at": str(body.get("expires_at", "")), **scope}

    def run(args: Mapping[str, Any]) -> dict[str, Any]:
        method = str(args.get("method", "GET")).strip().upper()
        if method not in _METHODS:
            raise ToolAdapterRefused(f"github method {method!r} is not permitted")
        if method == "PATCH":
            # PATCH is a GitHub verb and not one `HardenedHttpClient` allows.
            # Refused here with a reason rather than by widening the hardened
            # client's method allowlist for this adapter's convenience -- that
            # allowlist protects every other caller in the process too.
            raise ToolAdapterRefused(
                "github PATCH is not available: the hardened outbound client "
                "permits GET/HEAD/POST/PUT/DELETE only. Use PUT where the "
                "endpoint supports it."
            )

        path = str(args.get("path", "")).strip()
        if not _PATH_RE.fullmatch(path) or ".." in path:
            raise ToolAdapterRefused(
                f"github path {path!r} must be an absolute API path with no "
                "host, no query string and no traversal"
            )

        query = args.get("query")
        if query is not None and not isinstance(query, Mapping):
            raise ToolAdapterRefused("github query must be an object")
        encoded = urllib.parse.urlencode(
            {str(k): str(v) for k, v in dict(query or {}).items()}
        )

        semantics = classify_or_refuse(
            platform="github",
            action=method.lower(),
            resource=f"https://api.github.com{path}",
            metadata={"method": method.lower()},
        )
        enforce_ceiling(semantics, limit)

        body = args.get("body")
        if body is not None and not isinstance(body, Mapping):
            raise ToolAdapterRefused("github body must be an object")
        payload = (
            json.dumps(dict(body), separators=(",", ":")).encode("utf-8")
            if body is not None
            else None
        )

        try:
            bearer, credential = mint(method, path)
        except ToolAdapterRefused as exc:
            # The token request precedes the call; nothing has touched the repository.
            raise ToolAdapterNotAttempted(str(exc)) from exc
        headers = {
            "authorization": f"Bearer {bearer}",
            "accept": "application/vnd.github+json",
            "x-github-api-version": "2022-11-28",
            "user-agent": "sentinel-platform-adapter",
        }
        if payload is not None:
            headers["content-type"] = "application/json"

        result = call_settled(
            client, semantics, platform="github",
            method=method,
            url=f"https://{host}{path}" + (f"?{encoded}" if encoded else ""),
            headers=headers,
            body=payload,
        )
        return bounded(
            {
                "platform": "github",
                "operation": f"{method} {path}",
                "credential": credential,
                "semantics": semantics.as_metadata(),
                **result,
            }
        )

    def read_target(hint: Mapping[str, Any]) -> tuple[int, Any]:
        ref = f"?{urllib.parse.urlencode({'ref': hint['ref']})}" if hint.get("ref") else ""
        found = hardened_call(
            client, method="GET", url=f"https://{host}{hint.get('path', '')}{ref}", body=None,
            headers={"authorization": f"Bearer {mint('GET', str(hint.get('path', '')))[0]}",
                     "accept": "application/vnd.github+json",
                     "x-github-api-version": "2022-11-28", "user-agent": "sentinel-platform-adapter"},
        )
        return int(found["status"]), found["body"]

    return RegisteredSideEffect(
        name="github_api", runner=run, hint=github_hint, reconciler=github_reconciler(read_target),
    )
