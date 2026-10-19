"""ServiceNow AI Agents (Now Assist / AI Agent Studio) via the Table API.

WHERE SERVICENOW KEEPS ITS AGENTS
---------------------------------
AI Agent Studio stores agents, their tools and the links between them as
ordinary records in scoped tables, and the Table API reads any table a role
can see. So the inventory is three listings against one instance and the
platform's own tables say what is an agent -- an `sn_aia_agent` row is an
agent because ServiceNow put it there, not because its name says so.

THE TABLE NAMES ARE UNVALIDATED
-------------------------------
`AGENT_TABLE`, `TOOL_TABLE` and `AGENT_TOOL_TABLE` are the `sn_aia` scope
tables as remembered. Each is one constant, and an instance that answers
404 or 403 for one of them records that listing as unreachable rather than
as an empty table -- which matters here more than elsewhere, because a wrong
table name is the single most likely defect and an empty answer would hide
it perfectly.

PAGING IS BY OFFSET, AND THE COUNT IS TRUSTED ONLY WHEN GIVEN
-------------------------------------------------------------
The Table API pages with `sysparm_limit` and `sysparm_offset`. The next page
is requested only when a page came back full; a short page is the last one.
`X-Total-Count`, when the instance sends it, decides whether the page cap
left rows behind.

Tool `description` and agent `instructions` are the text a planner model
reads. Neither is in `sysparm_fields`.

REQUIRES EXTERNAL VALIDATION -- never run against a real instance.
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
    _decode_json,
    _get_response,
    _now,
    _text,
    paginate,
)

__all__ = [
    "AGENT_TABLE",
    "AGENT_TOOL_TABLE",
    "TABLE_API_PATH",
    "TOOL_TABLE",
    "servicenow_agents_connector",
]

_CONNECTOR = "servicenow_agents"

TABLE_API_PATH = "/api/now/table/"
#: UNVALIDATED table names -- see the module docstring.
AGENT_TABLE = "sn_aia_agent"
TOOL_TABLE = "sn_aia_tool"
AGENT_TOOL_TABLE = "sn_aia_agent_tool_m2m"

_AGENT_FIELDS = "sys_id,name,active,sys_updated_on,sys_scope"
_TOOL_FIELDS = "sys_id,name,type,active,sys_updated_on,sys_scope"
_LINK_FIELDS = "sys_id,agent,tool"
_PAGE_SIZE = 100


def _reference(value: Any) -> str:
    """A reference field's sys_id, whichever shape the instance returned.

    With `sysparm_exclude_reference_link=true` a reference is a bare string;
    without it, `{"value": ..., "link": ...}`. Both are handled because the
    parameter is a request and the instance's answer is the instance's.
    """
    if isinstance(value, Mapping):
        return _text(value.get("value"))
    return _text(value)


def servicenow_agents_connector(
    *,
    client: HardenedHttpClient,
    credentials: HostCredentials,
) -> Any:
    """Agents as AGENT, tools as SKILL, with agent->tool edges from the m2m."""
    base = credentials.base_url
    headers = {
        "authorization": f"Bearer {credentials.token}",
        "accept": "application/json",
    }
    instance_id = f"servicenow://{credentials.host}"

    class _ServiceNowConnector:
        name = _CONNECTOR
        external_validation = EXTERNAL_VALIDATION_NOTE

        def discover(self) -> AssetInventory:
            assets: list[AssetRecord] = []
            unreachable: list[Unreachable] = []
            examined = 0
            complete = True

            # Tools and links first, so an agent record can carry its edges.
            tools = self._table(TOOL_TABLE, _TOOL_FIELDS, unreachable)
            links = self._table(AGENT_TOOL_TABLE, _LINK_FIELDS, unreachable)
            agents = self._table(AGENT_TABLE, _AGENT_FIELDS, unreachable)
            complete = tools.complete and links.complete and agents.complete

            edges: dict[str, list[str]] = {}
            for row in links.items:
                examined += 1
                agent_ref = _reference(row.get("agent"))
                tool_ref = _reference(row.get("tool"))
                if agent_ref and tool_ref:
                    edges.setdefault(agent_ref, []).append(
                        f"{instance_id}/{TOOL_TABLE}/{tool_ref}"
                    )

            for row in tools.items:
                examined += 1
                sys_id = _text(row.get("sys_id"))
                if not sys_id:
                    continue
                assets.append(
                    AssetRecord(
                        kind=AssetKind.SKILL,
                        identifier=f"{instance_id}/{TOOL_TABLE}/{sys_id}",
                        source=_CONNECTOR,
                        native_type=TOOL_TABLE,
                        display_name=_text(row.get("name")),
                        attributes={
                            "tool_type": _text(row.get("type")),
                            "active": _text(row.get("active")),
                            "scope": _reference(row.get("sys_scope")),
                            "updated_at": _text(row.get("sys_updated_on")),
                        },
                    )
                )

            for row in agents.items:
                examined += 1
                sys_id = _text(row.get("sys_id"))
                if not sys_id:
                    continue
                assets.append(
                    AssetRecord(
                        kind=AssetKind.AGENT,
                        identifier=f"{instance_id}/{AGENT_TABLE}/{sys_id}",
                        source=_CONNECTOR,
                        native_type=AGENT_TABLE,
                        display_name=_text(row.get("name")),
                        relates_to=tuple(sorted(edges.get(sys_id, ()))),
                        attributes={
                            "active": _text(row.get("active")),
                            "scope": _reference(row.get("sys_scope")),
                            "updated_at": _text(row.get("sys_updated_on")),
                            # Whether the edges above could be trusted at all.
                            "tool_links_examined": links.complete,
                        },
                    )
                )

            return AssetInventory(
                connector=_CONNECTOR,
                assets=tuple(assets),
                coverage=DiscoveryCoverage(
                    scope=(f"servicenow:{credentials.scope}",),
                    examined=examined,
                    unreachable=tuple(unreachable),
                    permissions_used=tuple(
                        f"table read: {table} (UNVALIDATED table name)"
                        for table in (AGENT_TABLE, TOOL_TABLE, AGENT_TOOL_TABLE)
                    ),
                    retrieved_at=_now(),
                    pagination_complete=complete,
                ),
            )

        @staticmethod
        def _table(table: str, fields: str, unreachable: list[Unreachable]) -> Any:
            target = f"servicenow:{table}"

            def fetch(cursor: str) -> tuple[list[Mapping[str, Any]], str] | None:
                offset = int(cursor) if cursor else 0
                query = urllib.parse.urlencode(
                    {
                        "sysparm_fields": fields,
                        "sysparm_limit": str(_PAGE_SIZE),
                        "sysparm_offset": str(offset),
                        "sysparm_query": "ORDERBYsys_id",
                        "sysparm_display_value": "false",
                        "sysparm_exclude_reference_link": "true",
                    }
                )
                response = _get_response(
                    client,
                    url=f"{base}{TABLE_API_PATH}{table}?{query}",
                    headers=headers,
                    target=target,
                    unreachable=unreachable,
                )
                if response is None:
                    return None
                document = _decode_json(
                    response, target=target, unreachable=unreachable
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
                result = document.get("result")
                rows = (
                    [r for r in result if isinstance(r, Mapping)]
                    if isinstance(result, list)
                    else []
                )
                if len(rows) < _PAGE_SIZE:
                    return rows, ""
                total = _text(response.headers.get("x-total-count"))
                if total.isdigit() and int(total) <= offset + len(rows):
                    return rows, ""
                return rows, str(offset + len(rows))

            return paginate(fetch, target=target, unreachable=unreachable)

    return _ServiceNowConnector()
