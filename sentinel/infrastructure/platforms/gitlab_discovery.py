"""Discover agentic GitLab CI pipelines.

This mirrors the GitHub Actions heuristic: a CI config that references model or
agent tooling is reported as a SKILL, and recent pipeline runs are runtimes
related to that skill. The marker list is exported so the heuristic can be
audited instead of trusted.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from sentinel.domain.assets import (
    AssetInventory,
    AssetKind,
    AssetRecord,
    DiscoveryCoverage,
    Unreachable,
)
from sentinel.infrastructure.outbound import HardenedHttpClient
from sentinel.infrastructure.platforms.discovery_support import (
    EXTERNAL_VALIDATION_NOTE,
    HostCredentials,
    _decode_json,
    _get_response,
    _now,
    _text,
    paginate,
)
from sentinel.infrastructure.platforms.github_discovery import AI_MARKERS

__all__ = [
    "AI_MARKERS",
    "GitlabProject",
    "gitlab_ci_connector",
]

_CONNECTOR = "gitlab_ci"
_CI_FILE = ".gitlab-ci.yml"


@dataclass(frozen=True, slots=True)
class GitlabProject:
    """One project and ref to inspect."""

    project: str
    ref: str = "main"

    def __post_init__(self) -> None:
        if not self.project.strip():
            raise ValueError("a GitLab project id or path is required")
        if not self.ref.strip():
            raise ValueError("a GitLab ref is required")


def _markers_in(text: str) -> tuple[str, ...]:
    lowered = text.lower()
    return tuple(sorted(marker for marker in AI_MARKERS if marker in lowered))


def _encoded_project(project: str) -> str:
    return urllib.parse.quote(project, safe="")


def gitlab_ci_connector(
    *,
    client: HardenedHttpClient,
    credentials: HostCredentials,
    projects: Sequence[GitlabProject],
) -> Any:
    """GitLab projects, CI configs and recent pipelines."""
    if not projects:
        raise ValueError("GitLab CI discovery needs at least one project")
    base = credentials.base_url
    headers = {
        "authorization": f"Bearer {credentials.token}",
        "accept": "application/json",
    }

    class _GitlabCiConnector:
        name = _CONNECTOR
        external_validation = EXTERNAL_VALIDATION_NOTE

        def discover(self) -> AssetInventory:
            assets: list[AssetRecord] = []
            unreachable: list[Unreachable] = []
            examined = 0
            complete = True

            for request in projects:
                repo_id = f"gitlab://{credentials.host}/{request.project}"
                assets.append(
                    AssetRecord(
                        kind=AssetKind.REPOSITORY,
                        identifier=repo_id,
                        source=_CONNECTOR,
                        native_type="Project",
                        display_name=request.project,
                        environment=credentials.scope,
                    )
                )
                ci_text = self._ci_config(request, unreachable)
                if ci_text is None:
                    complete = False
                    continue
                examined += 1
                markers = _markers_in(ci_text)
                if not markers:
                    continue
                skill_id = f"{repo_id}/ci/{_CI_FILE}@{request.ref}"
                assets.append(
                    AssetRecord(
                        kind=AssetKind.SKILL,
                        identifier=skill_id,
                        source=_CONNECTOR,
                        native_type="GitLabCIConfig",
                        display_name=f"{request.project}:{_CI_FILE}",
                        relates_to=(repo_id,),
                        attributes={
                            "ref": request.ref,
                            "markers": list(markers),
                            "content_examined": True,
                        },
                    )
                )
                pipelines = self._pipelines(request, unreachable)
                if not pipelines.complete:
                    complete = False
                for pipeline in pipelines.items:
                    examined += 1
                    pipeline_id = str(pipeline.get("id") or "").strip()
                    if not pipeline_id:
                        continue
                    assets.append(
                        AssetRecord(
                            kind=AssetKind.AGENT_RUNTIME,
                            identifier=f"{repo_id}/pipeline/{pipeline_id}",
                            source=_CONNECTOR,
                            native_type="Pipeline",
                            display_name=f"pipeline {pipeline_id}",
                            relates_to=(skill_id,),
                            attributes={
                                "status": _text(pipeline.get("status")),
                                "source": _text(pipeline.get("source")),
                                "ref": _text(pipeline.get("ref")),
                                "web_url": _text(pipeline.get("web_url")),
                            },
                        )
                    )

            return AssetInventory(
                connector=_CONNECTOR,
                assets=tuple(assets),
                coverage=DiscoveryCoverage(
                    scope=tuple(
                        f"gitlab:{credentials.host}/{p.project}@{p.ref}"
                        for p in projects
                    ),
                    examined=examined,
                    unreachable=tuple(unreachable),
                    permissions_used=(
                        "GET /api/v4/projects/:id/repository/files/.gitlab-ci.yml/raw",
                        "GET /api/v4/projects/:id/pipelines",
                    ),
                    retrieved_at=_now(),
                    pagination_complete=complete,
                ),
            )

        @staticmethod
        def _ci_config(
            project: GitlabProject, unreachable: list[Unreachable]
        ) -> str | None:
            encoded = _encoded_project(project.project)
            path = urllib.parse.quote(_CI_FILE, safe="")
            query = urllib.parse.urlencode({"ref": project.ref})
            target = f"gitlab:{project.project}:{_CI_FILE}"
            response = _get_response(
                client,
                url=(
                    f"{base}/api/v4/projects/{encoded}/repository/files/"
                    f"{path}/raw?{query}"
                ),
                headers=headers,
                target=target,
                unreachable=unreachable,
            )
            if response is None:
                return None
            return response.body.decode("utf-8", errors="replace")

        @staticmethod
        def _pipelines(project: GitlabProject, unreachable: list[Unreachable]) -> Any:
            encoded = _encoded_project(project.project)
            target = f"gitlab:{project.project}:pipelines"

            def fetch(cursor: str) -> tuple[list[Mapping[str, Any]], str] | None:
                query = {"per_page": "100"}
                if cursor:
                    query["page"] = cursor
                response = _get_response(
                    client,
                    url=(
                        f"{base}/api/v4/projects/{encoded}/pipelines?"
                        f"{urllib.parse.urlencode(query)}"
                    ),
                    headers=headers,
                    target=target,
                    unreachable=unreachable,
                )
                if response is None:
                    return None
                document = _decode_json(
                    response, target=target, unreachable=unreachable
                )
                if not isinstance(document, list):
                    if document is not None:
                        unreachable.append(
                            Unreachable(
                                target=target,
                                reason="the response was not a JSON array",
                            )
                        )
                    return None
                rows = [row for row in document if isinstance(row, Mapping)]
                return rows, _text(response.headers.get("x-next-page"))

            return paginate(fetch, target=target, unreachable=unreachable)

    return _GitlabCiConnector()
