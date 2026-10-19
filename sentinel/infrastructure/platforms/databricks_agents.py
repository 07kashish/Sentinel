"""Databricks Mosaic AI agents and serving endpoints.

Serving endpoints are documented at `/api/2.0/serving-endpoints`. The agent
deployment registry path is deliberately one `UNVALIDATED` constant: it has not
been exercised against a workspace, so a tenant test can correct exactly one
place instead of hunting through composed strings.
"""

from __future__ import annotations

import urllib.parse
from typing import Any, Mapping

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
    _get_json,
    _now,
    _text,
    paginate,
)

__all__ = [
    "AGENT_DEPLOYMENTS_PATH",
    "SERVING_ENDPOINTS_PATH",
    "databricks_agents_connector",
]

_CONNECTOR = "databricks_agents"
SERVING_ENDPOINTS_PATH = "/api/2.0/serving-endpoints"
AGENT_DEPLOYMENTS_PATH = "/api/2.0/agents/deployments"  # UNVALIDATED


def databricks_agents_connector(
    *,
    client: HardenedHttpClient,
    credentials: HostCredentials,
) -> Any:
    """Serving endpoints as runtimes and registry deployments as agents."""
    base = credentials.base_url
    headers = {
        "authorization": f"Bearer {credentials.token}",
        "accept": "application/json",
    }
    workspace_id = f"databricks://{credentials.host}"

    class _DatabricksConnector:
        name = _CONNECTOR
        external_validation = EXTERNAL_VALIDATION_NOTE

        def discover(self) -> AssetInventory:
            assets: list[AssetRecord] = []
            unreachable: list[Unreachable] = []
            examined = 0

            endpoints = self._paged(
                path=SERVING_ENDPOINTS_PATH,
                list_key="endpoints",
                token_key="page_token",
                next_key="next_page_token",
                target="databricks:serving-endpoints",
                unreachable=unreachable,
            )
            deployments = self._paged(
                path=AGENT_DEPLOYMENTS_PATH,
                list_key="deployments",
                token_key="page_token",
                next_key="next_page_token",
                target="databricks:agent-deployments",
                unreachable=unreachable,
            )

            for endpoint in endpoints.items:
                examined += 1
                name = _text(endpoint.get("name"))
                if not name:
                    continue
                state = endpoint.get("state") if isinstance(endpoint, Mapping) else {}
                assets.append(
                    AssetRecord(
                        kind=AssetKind.AGENT_RUNTIME,
                        identifier=f"{workspace_id}/serving-endpoint/{name}",
                        source=_CONNECTOR,
                        native_type="ServingEndpoint",
                        display_name=name,
                        environment=credentials.scope,
                        attributes={
                            "creator": _text(endpoint.get("creator")),
                            "ready": (
                                _text(state.get("ready"))
                                if isinstance(state, Mapping)
                                else ""
                            ),
                            "config_version": endpoint.get("config_version"),
                        },
                    )
                )

            for deployment in deployments.items:
                examined += 1
                deployment_id = (
                    _text(deployment.get("id"))
                    or _text(deployment.get("deployment_id"))
                    or _text(deployment.get("name"))
                )
                if not deployment_id:
                    continue
                endpoint_name = _text(deployment.get("endpoint_name"))
                assets.append(
                    AssetRecord(
                        kind=AssetKind.AGENT,
                        identifier=f"{workspace_id}/agent-deployment/{deployment_id}",
                        source=_CONNECTOR,
                        native_type="AgentDeployment",
                        display_name=_text(deployment.get("name")) or deployment_id,
                        environment=credentials.scope,
                        relates_to=(
                            (f"{workspace_id}/serving-endpoint/{endpoint_name}",)
                            if endpoint_name
                            else ()
                        ),
                        attributes={
                            "agent_name": _text(deployment.get("agent_name")),
                            "model_name": _text(deployment.get("model_name")),
                            "status": _text(deployment.get("status")),
                            "registry_path": f"UNVALIDATED {AGENT_DEPLOYMENTS_PATH}",
                        },
                    )
                )

            return AssetInventory(
                connector=_CONNECTOR,
                assets=tuple(assets),
                coverage=DiscoveryCoverage(
                    scope=(f"databricks:{credentials.scope}",),
                    examined=examined,
                    unreachable=tuple(unreachable),
                    permissions_used=(
                        "GET /api/2.0/serving-endpoints",
                        f"GET {AGENT_DEPLOYMENTS_PATH} (UNVALIDATED)",
                    ),
                    retrieved_at=_now(),
                    pagination_complete=endpoints.complete and deployments.complete,
                ),
            )

        @staticmethod
        def _paged(
            *,
            path: str,
            list_key: str,
            token_key: str,
            next_key: str,
            target: str,
            unreachable: list[Unreachable],
        ) -> Any:
            def fetch(cursor: str) -> tuple[list[Mapping[str, Any]], str] | None:
                query = {"page_size": "100"}
                if cursor:
                    query[token_key] = cursor
                document = _get_json(
                    client,
                    url=f"{base}{path}?{urllib.parse.urlencode(query)}",
                    headers=headers,
                    target=target,
                    unreachable=unreachable,
                )
                if not isinstance(document, Mapping):
                    if document is not None:
                        unreachable.append(
                            Unreachable(
                                target=target,
                                reason="the response was not a JSON object",
                            )
                        )
                    return None
                rows = document.get(list_key)
                items = (
                    [row for row in rows if isinstance(row, Mapping)]
                    if isinstance(rows, list)
                    else []
                )
                return items, _text(document.get(next_key))

            return paginate(fetch, target=target, unreachable=unreachable)

    return _DatabricksConnector()
