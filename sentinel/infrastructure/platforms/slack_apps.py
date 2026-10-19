"""Slack apps and bot users.

Slack's Web API reports method failures as `{"ok": false}` even with HTTP
200, so this connector treats that as unreachable rather than as an empty page.
"""

from __future__ import annotations

import urllib.parse
from typing import Any, Mapping, Sequence

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
    _get_json,
    _now,
    _text,
    paginate,
)

__all__ = [
    "APPROVED_APPS_METHOD",
    "BOTS_INFO_METHOD",
    "slack_apps_connector",
]

_CONNECTOR = "slack_apps"
_BASE = "https://slack.com/api"
APPROVED_APPS_METHOD = "admin.apps.approved.list"
BOTS_INFO_METHOD = "bots.info"


def slack_apps_connector(
    *,
    client: HardenedHttpClient,
    credentials: BearerCredentials,
    team_id: str = "",
    enterprise_id: str = "",
    bot_ids: Sequence[str] = (),
) -> Any:
    """Approved apps as service accounts and supplied bot IDs as agents."""
    headers = {
        "authorization": f"Bearer {credentials.token}",
        "accept": "application/json",
    }
    scope = credentials.scope or team_id or enterprise_id or "workspace"

    class _SlackConnector:
        name = _CONNECTOR
        external_validation = EXTERNAL_VALIDATION_NOTE

        def discover(self) -> AssetInventory:
            assets: list[AssetRecord] = []
            unreachable: list[Unreachable] = []
            examined = 0

            apps = self._approved_apps(unreachable)
            for row in apps.items:
                examined += 1
                app = row.get("app") if isinstance(row, Mapping) else None
                if not isinstance(app, Mapping):
                    continue
                app_id = _text(app.get("id"))
                if not app_id:
                    continue
                scopes = row.get("scopes")
                scope_names = (
                    sorted(
                        _text(s.get("name"))
                        for s in scopes
                        if isinstance(s, Mapping) and _text(s.get("name"))
                    )
                    if isinstance(scopes, list)
                    else []
                )
                assets.append(
                    AssetRecord(
                        kind=AssetKind.SERVICE_ACCOUNT,
                        identifier=f"slack://{scope}/app/{app_id}",
                        source=_CONNECTOR,
                        native_type="SlackApp",
                        display_name=_text(app.get("name")),
                        environment=scope,
                        attributes={
                            "developer_type": _text(app.get("developer_type")),
                            "is_internal": bool(app.get("is_internal")),
                            "bot_scope_present": "bot" in scope_names,
                            "scopes": scope_names,
                        },
                    )
                )

            complete = apps.complete
            for bot_id in bot_ids:
                bot = self._bot_info(bot_id, unreachable)
                if bot is None:
                    complete = False
                    continue
                examined += 1
                assets.append(
                    AssetRecord(
                        kind=AssetKind.AGENT,
                        identifier=f"slack://{scope}/bot/{_text(bot.get('id'))}",
                        source=_CONNECTOR,
                        native_type="SlackBotUser",
                        display_name=_text(bot.get("name")),
                        environment=scope,
                        relates_to=(
                            (f"slack://{scope}/app/{_text(bot.get('app_id'))}",)
                            if _text(bot.get("app_id"))
                            else ()
                        ),
                        attributes={
                            "app_id": _text(bot.get("app_id")),
                            "user_id": _text(bot.get("user_id")),
                            "deleted": bool(bot.get("deleted")),
                            "updated": bot.get("updated"),
                        },
                    )
                )

            return AssetInventory(
                connector=_CONNECTOR,
                assets=tuple(assets),
                coverage=DiscoveryCoverage(
                    scope=(f"slack:{scope}",),
                    examined=examined,
                    unreachable=tuple(unreachable),
                    permissions_used=(
                        "admin.apps:read",
                        "users:read (only for supplied bot ids)",
                    ),
                    retrieved_at=_now(),
                    pagination_complete=complete,
                ),
            )

        @staticmethod
        def _approved_apps(unreachable: list[Unreachable]) -> Any:
            target = f"slack:{APPROVED_APPS_METHOD}"

            def fetch(cursor: str) -> tuple[list[Mapping[str, Any]], str] | None:
                query = {"limit": "1000"}
                if cursor:
                    query["cursor"] = cursor
                if team_id:
                    query["team_id"] = team_id
                if enterprise_id:
                    query["enterprise_id"] = enterprise_id
                document = _slack_json(
                    client,
                    url=f"{_BASE}/{APPROVED_APPS_METHOD}?{urllib.parse.urlencode(query)}",
                    headers=headers,
                    target=target,
                    unreachable=unreachable,
                )
                if document is None:
                    return None
                rows = document.get("approved_apps")
                apps = (
                    [row for row in rows if isinstance(row, Mapping)]
                    if isinstance(rows, list)
                    else []
                )
                metadata = document.get("response_metadata")
                next_cursor = (
                    _text(metadata.get("next_cursor"))
                    if isinstance(metadata, Mapping)
                    else ""
                )
                return apps, next_cursor

            return paginate(fetch, target=target, unreachable=unreachable)

        @staticmethod
        def _bot_info(
            bot_id: str, unreachable: list[Unreachable]
        ) -> Mapping[str, Any] | None:
            target = f"slack:{BOTS_INFO_METHOD}:{bot_id}"
            query = {"bot": bot_id}
            if team_id:
                query["team_id"] = team_id
            document = _slack_json(
                client,
                url=f"{_BASE}/{BOTS_INFO_METHOD}?{urllib.parse.urlencode(query)}",
                headers=headers,
                target=target,
                unreachable=unreachable,
            )
            bot = document.get("bot") if isinstance(document, Mapping) else None
            if not isinstance(bot, Mapping):
                if document is not None:
                    unreachable.append(
                        Unreachable(target=target, reason="no bot object returned")
                    )
                return None
            return bot

    return _SlackConnector()


def _slack_json(
    client: HardenedHttpClient,
    *,
    url: str,
    headers: Mapping[str, str],
    target: str,
    unreachable: list[Unreachable],
) -> Mapping[str, Any] | None:
    document = _get_json(
        client,
        url=url,
        headers=headers,
        target=target,
        unreachable=unreachable,
    )
    if not isinstance(document, Mapping):
        if document is not None:
            unreachable.append(
                Unreachable(target=target, reason="the response was not a JSON object")
            )
        return None
    if document.get("ok") is not True:
        unreachable.append(
            Unreachable(
                target=target,
                reason=f"Slack Web API returned ok=false: {_text(document.get('error'))}",
            )
        )
        return None
    return document
