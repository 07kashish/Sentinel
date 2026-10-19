"""Identity-platform agent discovery for Okta and Microsoft Entra Agent ID."""

from __future__ import annotations

import re
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
from sentinel.infrastructure.platforms.ai_discovery import BearerCredentials
from sentinel.infrastructure.platforms.discovery_support import (
    EXTERNAL_VALIDATION_NOTE,
    HostCredentials,
    _decode_json,
    _get_json,
    _get_response,
    _now,
    _text,
    paginate,
)

__all__ = [
    "ENTRA_AGENT_ID_PATH_TEMPLATE",
    "ENTRA_AGENT_SERVICE_PRINCIPALS_URL",
    "OKTA_AI_AGENTS_PATH",
    "OKTA_API_TOKENS_PATH",
    "OKTA_APPS_PATH",
    "entra_agent_id_connector",
    "okta_agents_connector",
]

_OKTA_CONNECTOR = "okta_agents"
_ENTRA_CONNECTOR = "entra_agent_id"
OKTA_AI_AGENTS_PATH = "/api/v1/secures-ai/ai-agents"  # UNVALIDATED beta path
OKTA_APPS_PATH = "/api/v1/apps"
OKTA_API_TOKENS_PATH = "/api/v1/api-tokens"
ENTRA_AGENT_SERVICE_PRINCIPALS_URL = (
    "https://graph.microsoft.com/v1.0/servicePrincipals?"
    + urllib.parse.urlencode(
        {
            "$select": (
                "id,appId,displayName,servicePrincipalType,accountEnabled,tags"
            ),
            "$filter": "servicePrincipalType eq 'ServiceIdentity'",
            "$top": "100",
        }
    )
)
ENTRA_AGENT_ID_PATH_TEMPLATE = (
    "https://graph.microsoft.com/v1.0/servicePrincipals/{id}/"
    "microsoft.graph.agentIdentity"
)

_LINK_NEXT = re.compile(r"<([^>]+)>;\s*rel=\"next\"")


def _next_link(headers: Mapping[str, str]) -> str:
    value = headers.get("link") or headers.get("Link") or ""
    match = _LINK_NEXT.search(value)
    return match.group(1) if match else ""


def okta_agents_connector(
    *,
    client: HardenedHttpClient,
    credentials: HostCredentials,
) -> Any:
    """Okta AI agents where exposed, plus apps and API-token metadata."""
    base = credentials.base_url
    headers = {
        "authorization": f"SSWS {credentials.token}",
        "accept": "application/json",
    }
    org_id = f"okta://{credentials.host}"

    class _OktaConnector:
        name = _OKTA_CONNECTOR
        external_validation = EXTERNAL_VALIDATION_NOTE

        def discover(self) -> AssetInventory:
            assets: list[AssetRecord] = []
            unreachable: list[Unreachable] = []
            examined = 0

            agents = self._json_pages(
                path=OKTA_AI_AGENTS_PATH,
                target="okta:ai-agents",
                unreachable=unreachable,
            )
            apps = self._json_pages(
                path=OKTA_APPS_PATH,
                target="okta:apps",
                unreachable=unreachable,
                first_query={"limit": "200"},
            )
            tokens = self._json_pages(
                path=OKTA_API_TOKENS_PATH,
                target="okta:api-tokens",
                unreachable=unreachable,
                first_query={"limit": "200"},
            )

            for row in agents.items:
                examined += 1
                agent_id = _text(row.get("id"))
                if not agent_id:
                    continue
                assets.append(
                    AssetRecord(
                        kind=AssetKind.AGENT,
                        identifier=f"{org_id}/ai-agent/{agent_id}",
                        source=_OKTA_CONNECTOR,
                        native_type="OktaAIAgent",
                        display_name=_text(row.get("name"))
                        or _text(row.get("displayName")),
                        environment=credentials.scope,
                        attributes={
                            "status": _text(row.get("status")),
                            "path": f"UNVALIDATED {OKTA_AI_AGENTS_PATH}",
                        },
                    )
                )

            for app in apps.items:
                examined += 1
                app_id = _text(app.get("id"))
                if not app_id:
                    continue
                assets.append(
                    AssetRecord(
                        kind=AssetKind.SAAS_APPLICATION,
                        identifier=f"{org_id}/app/{app_id}",
                        source=_OKTA_CONNECTOR,
                        native_type="Application",
                        display_name=_text(app.get("label"))
                        or _text(app.get("name")),
                        environment=credentials.scope,
                        attributes={
                            "name": _text(app.get("name")),
                            "status": _text(app.get("status")),
                            "sign_on_mode": _text(app.get("signOnMode")),
                        },
                    )
                )

            for token in tokens.items:
                examined += 1
                token_id = _text(token.get("id"))
                if not token_id:
                    continue
                user_id = _text(token.get("userId"))
                assets.append(
                    AssetRecord(
                        kind=AssetKind.CREDENTIAL,
                        identifier=f"{org_id}/api-token/{token_id}",
                        source=_OKTA_CONNECTOR,
                        native_type="ApiToken",
                        display_name=_text(token.get("name")),
                        environment=credentials.scope,
                        relates_to=((f"{org_id}/user/{user_id}",) if user_id else ()),
                        attributes={
                            "client_name": _text(token.get("clientName")),
                            "created": _text(token.get("created")),
                            "expires_at": _text(token.get("expiresAt")),
                        },
                    )
                )

            return AssetInventory(
                connector=_OKTA_CONNECTOR,
                assets=tuple(assets),
                coverage=DiscoveryCoverage(
                    scope=(f"okta:{credentials.scope}",),
                    examined=examined,
                    unreachable=tuple(unreachable),
                    permissions_used=(
                        f"GET {OKTA_AI_AGENTS_PATH} (UNVALIDATED beta path)",
                        "GET /api/v1/apps",
                        "GET /api/v1/api-tokens",
                    ),
                    retrieved_at=_now(),
                    pagination_complete=(
                        agents.complete and apps.complete and tokens.complete
                    ),
                ),
            )

        @staticmethod
        def _json_pages(
            *,
            path: str,
            target: str,
            unreachable: list[Unreachable],
            first_query: Mapping[str, str] | None = None,
        ) -> Any:
            def fetch(cursor: str) -> tuple[list[Mapping[str, Any]], str] | None:
                url = cursor
                if not url:
                    query = urllib.parse.urlencode(dict(first_query or {}))
                    url = f"{base}{path}{'?' + query if query else ''}"
                elif not url.lower().startswith(f"{base.lower()}/"):
                    unreachable.append(
                        Unreachable(
                            target=target,
                            reason="next link pointed off the Okta org host",
                        )
                    )
                    return None
                response = _get_response(
                    client,
                    url=url,
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
                return rows, _next_link(response.headers)

            return paginate(fetch, target=target, unreachable=unreachable)

    return _OktaConnector()


def entra_agent_id_connector(
    *,
    client: HardenedHttpClient,
    credentials: BearerCredentials,
) -> Any:
    """Microsoft Graph Agent ID identities backed by service principals."""
    headers = {
        "authorization": f"Bearer {credentials.token}",
        "accept": "application/json",
    }
    tenant = credentials.scope or "tenant"

    class _EntraAgentIdConnector:
        name = _ENTRA_CONNECTOR
        external_validation = EXTERNAL_VALIDATION_NOTE

        def discover(self) -> AssetInventory:
            assets: list[AssetRecord] = []
            unreachable: list[Unreachable] = []
            examined = 0
            list_pages = self._service_principals(unreachable)
            complete = list_pages.complete

            for principal in list_pages.items:
                examined += 1
                principal_id = _text(principal.get("id"))
                if not principal_id:
                    continue
                agent = self._agent_identity(principal_id, unreachable)
                if agent is None:
                    complete = False
                    assets.append(_service_principal_asset(principal, tenant))
                    continue
                assets.append(
                    AssetRecord(
                        kind=AssetKind.AGENT,
                        identifier=f"entra-agent-id://{tenant}/agent/{principal_id}",
                        source=_ENTRA_CONNECTOR,
                        native_type="agentIdentity",
                        display_name=_text(agent.get("displayName"))
                        or _text(principal.get("displayName")),
                        environment=tenant,
                        relates_to=(f"entra://{tenant}/servicePrincipal/{principal_id}",),
                        attributes={
                            "app_id": _text(agent.get("createdByAppId"))
                            or _text(principal.get("appId")),
                            "account_enabled": bool(
                                agent.get("accountEnabled")
                                if "accountEnabled" in agent
                                else principal.get("accountEnabled")
                            ),
                            "blueprint_id": _text(
                                agent.get("agentIdentityBlueprintId")
                            ),
                        },
                    )
                )

            return AssetInventory(
                connector=_ENTRA_CONNECTOR,
                assets=tuple(assets),
                coverage=DiscoveryCoverage(
                    scope=(f"entra-agent-id:{tenant}",),
                    examined=examined,
                    unreachable=tuple(unreachable),
                    permissions_used=(
                        "AgentIdentity.Read.All",
                        "GET /servicePrincipals/{id}/microsoft.graph.agentIdentity",
                    ),
                    retrieved_at=_now(),
                    pagination_complete=complete,
                ),
            )

        @staticmethod
        def _service_principals(unreachable: list[Unreachable]) -> Any:
            url = ENTRA_AGENT_SERVICE_PRINCIPALS_URL
            target = "graph:servicePrincipals:agent-identity"

            def fetch(cursor: str) -> tuple[list[Mapping[str, Any]], str] | None:
                document = _get_json(
                    client,
                    url=cursor or url,
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
                rows = document.get("value")
                principals = (
                    [row for row in rows if isinstance(row, Mapping)]
                    if isinstance(rows, list)
                    else []
                )
                return principals, _text(document.get("@odata.nextLink"))

            return paginate(fetch, target=target, unreachable=unreachable)

        @staticmethod
        def _agent_identity(
            principal_id: str, unreachable: list[Unreachable]
        ) -> Mapping[str, Any] | None:
            target = f"graph:agentIdentity:{principal_id}"
            document = _get_json(
                client,
                url=ENTRA_AGENT_ID_PATH_TEMPLATE.format(
                    id=urllib.parse.quote(principal_id, safe="")
                ),
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
            return document

    return _EntraAgentIdConnector()


def _service_principal_asset(
    principal: Mapping[str, Any], tenant: str
) -> AssetRecord:
    principal_id = _text(principal.get("id"))
    return AssetRecord(
        kind=AssetKind.SERVICE_ACCOUNT,
        identifier=f"entra://{tenant}/servicePrincipal/{principal_id}",
        source=_ENTRA_CONNECTOR,
        native_type=_text(principal.get("servicePrincipalType")) or "ServicePrincipal",
        display_name=_text(principal.get("displayName")),
        environment=tenant,
        attributes={
            "app_id": _text(principal.get("appId")),
            "account_enabled": bool(principal.get("accountEnabled")),
            "fallback_reason": "agentIdentity relationship was not readable",
        },
    )
