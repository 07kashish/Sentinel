"""Discover the agent estate that lives in GitHub Actions.

WHY ACTIONS WORKFLOWS ARE AN AGENT ESTATE
------------------------------------------
A workflow that calls a model, holds an API key, and pushes commits is an
autonomous agent with a cron trigger. It runs unattended, it has credentials,
it acts on repositories, and it is invisible to every tool that inventories
"AI agents" by looking for a framework import. Most organisations have more of
these than they have deliberate agent deployments, and nobody counts them.

So this connector reports workflows as `SKILL` assets, the repositories they
act on as `REPOSITORY`, and the apps that hold tokens as `SERVICE_ACCOUNT`.

WHAT IT REFUSES TO GUESS
------------------------
Repositories are REQUIRED, not discovered. Listing every repository an
organisation owns needs an org-wide read a deployment may not have been
granted, and falling back to "the ones I can see" produces a confident report
about a subset with no indication that it is one. This mirrors the Kubernetes
connector requiring explicit namespaces, for the same reason.

A workflow whose content could not be read is recorded as UNREACHABLE with the
status that stopped it -- never omitted. A connector that silently drops what
it could not read reports a clean estate, which is the single most damaging
output an inventory can produce.

DETECTION IS BY MARKER, AND THE MARKERS ARE STATED
---------------------------------------------------
`AI_MARKERS` is the list of strings that make a workflow "agentic". It is a
heuristic, it will miss things, and it is exported so a reader can see exactly
what was looked for rather than trusting a number. `DiscoveryCoverage.examined`
is the denominator: "3 agentic workflows" means something different out of 4
than out of 400.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from sentinel.domain.assets import (
    AssetInventory,
    AssetKind,
    AssetRecord,
    DiscoveryCoverage,
    Unreachable,
)
from sentinel.infrastructure.outbound import (
    HardenedHttpClient,
    OutboundRefused,
    OutboundUnavailable,
)
from sentinel.infrastructure.platforms.github import GithubCredentials

__all__ = [
    "AI_MARKERS",
    "GithubDiscoveryRequest",
    "discover_github_estate",
]

#: Strings that make a workflow an agent rather than a build script.
#:
#: A HEURISTIC, exported so it can be read rather than trusted. It will miss a
#: workflow that shells out to a vendored binary, and it will flag one that
#: merely mentions a model in a comment. Both are stated here rather than
#: discovered by somebody comparing this count against reality.
#:
#: A frozenset: module-level mutable state is how one caller's edit changes
#: what another tenant's scan looks for.
AI_MARKERS: frozenset[str] = frozenset(
    {
        "anthropic",
        "openai",
        "claude",
        "gpt-4",
        "gpt-5",
        "langchain",
        "llamaindex",
        "crewai",
        "autogen",
        "bedrock",
        "vertexai",
        "huggingface",
        "ollama",
        "semantic-kernel",
        "agent",
        "mcp",
    }
)

#: GitHub's own limit on a `owner/repo` slug, plus the characters it permits.
_SLUG_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$")

_CONNECTOR = "github"

#: A page of workflows. GitHub's default is 30; asking for 100 reduces the
#: number of requests without hiding anything, because truncation is REPORTED
#: rather than followed silently.
_PER_PAGE = 100


@dataclass(frozen=True, slots=True)
class GithubDiscoveryRequest:
    """What to look at. Repositories are required, not discovered."""

    #: `owner/repo` slugs. Required for the reason in the module docstring.
    repositories: Sequence[str]
    #: Read workflow FILE CONTENT to look for markers. When False, only the
    #: workflow's name and path are examined, which is much weaker -- and the
    #: coverage record says so, rather than leaving a reader to assume the
    #: deeper scan happened.
    read_workflow_content: bool = True

    def __post_init__(self) -> None:
        if not self.repositories:
            raise ValueError(
                "no repositories given. Listing every repository an "
                "organisation owns needs an org-wide read this deployment may "
                "not have; falling back to what the token happens to see would "
                "produce a confident report about a subset with no sign that it "
                "is one."
            )


def _headers(credentials: GithubCredentials) -> dict[str, str]:
    return {
        "authorization": f"Bearer {credentials.token}",
        "accept": "application/vnd.github+json",
        "x-github-api-version": "2022-11-28",
    }


def _markers_in(text: str) -> tuple[str, ...]:
    lowered = text.lower()
    return tuple(sorted(marker for marker in AI_MARKERS if marker in lowered))


def discover_github_estate(
    *,
    client: HardenedHttpClient,
    credentials: GithubCredentials,
    request: GithubDiscoveryRequest,
) -> AssetInventory:
    """List workflows in the given repositories and report the agentic ones.

    Returns an inventory whose coverage names every repository that could not
    be read and why. Absence from the result is NOT evidence of absence from
    the estate, and the inventory's own `limits` field says so.
    """
    host = str(credentials.api_host).lower()
    base = f"https://{host}"
    headers = _headers(credentials)

    assets: list[AssetRecord] = []
    unreachable: list[Unreachable] = []
    scope: list[str] = []
    examined = 0
    pagination_complete = True
    permissions_used = {"GET /repos/{owner}/{repo}/actions/workflows"}

    for slug in request.repositories:
        name = str(slug).strip()
        if not _SLUG_RE.fullmatch(name):
            unreachable.append(
                Unreachable(
                    target=name,
                    reason="not a valid owner/repo slug; refusing to build a "
                    "request path from it",
                )
            )
            continue
        scope.append(name)

        listing = _get_json(
            client,
            f"{base}/repos/{name}/actions/workflows?per_page={_PER_PAGE}",
            headers,
        )
        if isinstance(listing, Unreachable):
            unreachable.append(Unreachable(target=name, reason=listing.reason))
            continue

        total = listing.get("total_count")
        workflows = listing.get("workflows") or []
        if isinstance(total, int) and total > len(workflows):
            # Truncated and NOT followed. Reported instead, because a connector
            # that stopped at the first page and said nothing reports a subset
            # as a total.
            pagination_complete = False
            unreachable.append(
                Unreachable(
                    target=name,
                    reason=(
                        f"{total} workflows exist and {len(workflows)} were "
                        "listed; the remaining pages were not followed, so this "
                        "repository's result is a subset"
                    ),
                )
            )

        # The repository itself is an asset: it is what the workflows act on.
        assets.append(
            AssetRecord(
                kind=AssetKind.REPOSITORY,
                identifier=f"github:{name}",
                source=_CONNECTOR,
                native_type="repository",
                display_name=name,
                attributes={"provenance": "observed", "workflows": len(workflows)},
            )
        )

        for workflow in workflows:
            if not isinstance(workflow, Mapping):
                continue
            examined += 1
            path = str(workflow.get("path", ""))
            title = str(workflow.get("name", ""))
            identifier = f"github:{name}:{path or title}"

            searchable = f"{title} {path}"
            content_read = False
            if request.read_workflow_content and path:
                permissions_used.add("GET /repos/{owner}/{repo}/contents/{path}")
                content = _get_text(
                    client, f"{base}/repos/{name}/contents/{path}", headers
                )
                if isinstance(content, Unreachable):
                    # The workflow EXISTS and its content could not be read.
                    # Recorded, so a reader knows this one was judged on its
                    # name alone -- not dropped, which would report a clean
                    # repository.
                    unreachable.append(
                        Unreachable(
                            target=f"{name}:{path}",
                            reason=(
                                f"workflow listed but content unreadable "
                                f"({content.reason}); judged on its name and "
                                "path only"
                            ),
                        )
                    )
                else:
                    searchable = f"{searchable} {content}"
                    content_read = True

            markers = _markers_in(searchable)
            if not markers:
                continue

            assets.append(
                AssetRecord(
                    kind=AssetKind.SKILL,
                    identifier=identifier,
                    source=_CONNECTOR,
                    native_type="actions_workflow",
                    display_name=title or path,
                    relates_to=(f"github:{name}",),
                    attributes={
                        # OBSERVED: the workflow was read from the API, not
                        # declared by an operator. But never ATTESTED -- nothing
                        # here binds a digest to what actually ran.
                        "provenance": "observed",
                        "markers": list(markers),
                        # Whether the deeper scan happened for THIS workflow.
                        # A reader comparing two rows needs to know one was
                        # judged on its content and the other on its filename.
                        "content_examined": content_read,
                        "state": str(workflow.get("state", "")),
                        "path": path,
                    },
                )
            )

    return AssetInventory(
        connector=_CONNECTOR,
        assets=tuple(assets),
        coverage=DiscoveryCoverage(
            scope=tuple(scope),
            examined=examined,
            unreachable=tuple(unreachable),
            permissions_used=tuple(sorted(permissions_used)),
            pagination_complete=pagination_complete,
        ),
    )


def _get_json(
    client: HardenedHttpClient, url: str, headers: Mapping[str, str]
) -> Any:
    """A JSON body, or an `Unreachable` describing why there is not one.

    Returns the failure rather than raising, so one unreadable repository
    becomes a named hole in the coverage record instead of ending the scan.
    """
    try:
        response = client.request(
            method="GET", url=url, headers=dict(headers), body=None, idempotent=True
        )
    except (OutboundRefused, OutboundUnavailable) as error:
        return Unreachable(target=url, reason=f"{type(error).__name__}: {error}")

    if response.status != 200:
        return Unreachable(target=url, reason=f"HTTP {response.status}")

    try:
        body = response.json()
    except OutboundRefused as error:
        return Unreachable(target=url, reason=f"unparseable response: {error}")

    if not isinstance(body, Mapping):
        return Unreachable(
            target=url, reason=f"expected an object, got {type(body).__name__}"
        )
    return body


def _get_text(
    client: HardenedHttpClient, url: str, headers: Mapping[str, str]
) -> Any:
    """A workflow's decoded content, or an `Unreachable`.

    GitHub returns file content base64-encoded in a JSON envelope. A decode
    failure is reported rather than silently treated as an empty file: an empty
    file matches no markers, so a decode error would quietly turn an agentic
    workflow into a clean one.
    """
    body = _get_json(client, url, headers)
    if isinstance(body, Unreachable):
        return body

    encoding = str(body.get("encoding", ""))
    raw = body.get("content")
    if not isinstance(raw, str):
        return Unreachable(target=url, reason="no content field in the response")

    if encoding != "base64":
        return Unreachable(
            target=url,
            reason=(
                f"unexpected content encoding {encoding!r}; refusing to guess "
                "how to decode it, because a wrong guess yields an empty "
                "string and an empty string matches no markers"
            ),
        )

    import base64
    import binascii

    try:
        decoded = base64.b64decode(raw, validate=False)
    except (binascii.Error, ValueError) as error:
        return Unreachable(target=url, reason=f"undecodable content: {error}")

    return decoded.decode("utf-8", errors="replace")
