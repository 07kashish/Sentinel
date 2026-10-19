"""Salesforce Agentforce agents and their actions, via SOQL over the REST API.

WHAT SALESFORCE CALLS AN AGENT
------------------------------
An Agentforce agent is a `BotDefinition` -- the same object Einstein Bots
have always used, which is why this reports every `BotDefinition` as AGENT:
that is the platform's own word for it. `BotUserId` is the user the agent
runs as, and it is recorded as a relationship rather than dropped, because
"which identity does this agent act through" is the question an operator
asks next.

Actions and topics are `GenAiFunctionDefinition` and `GenAiPluginDefinition`.
Those two object names are UNVALIDATED: they are the sObject forms of the
`GenAiFunction` / `GenAiPlugin` metadata types as remembered, each query is a
single constant, and an org that answers `INVALID_TYPE` records that as an
unreachable listing rather than as "no actions".

`GenAiFunctionDefinition.Description` and the plugin's description are the
text a planner model reads to choose an action. Neither is selected: that is
authored prose, and the inventory carries names.

REQUIRES EXTERNAL VALIDATION
-----------------------------
Never run against a real org. The query endpoint, the `nextRecordsUrl`
paging and the `BotDefinition` columns are from the REST API reference; the
GenAi object names are the part most likely to need a correction.
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
    "API_VERSION",
    "BOT_SOQL",
    "FUNCTION_SOQL",
    "PLUGIN_SOQL",
    "QUERY_PATH",
    "salesforce_agentforce_connector",
]

_CONNECTOR = "salesforce_agentforce"

API_VERSION = "v62.0"
QUERY_PATH = f"/services/data/{API_VERSION}/query"

#: `BotDefinition` is documented; these columns are on it in every release
#: that has bots at all.
BOT_SOQL = (
    "SELECT Id, DeveloperName, MasterLabel, BotUserId, LastModifiedDate "
    "FROM BotDefinition"
)
#: UNVALIDATED object names. See the module docstring.
FUNCTION_SOQL = (
    "SELECT Id, DeveloperName, MasterLabel, LastModifiedDate "
    "FROM GenAiFunctionDefinition"
)
PLUGIN_SOQL = (
    "SELECT Id, DeveloperName, MasterLabel, LastModifiedDate "
    "FROM GenAiPluginDefinition"
)


def salesforce_agentforce_connector(
    *,
    client: HardenedHttpClient,
    credentials: HostCredentials,
) -> Any:
    """Agents (AGENT), actions and topics (SKILL) in one org.

    The org is the credential's host: `myorg.my.salesforce.com`. One org per
    connector, because one access token is one org.
    """
    base = credentials.base_url
    headers = {
        "authorization": f"Bearer {credentials.token}",
        "accept": "application/json",
    }
    org_id = f"salesforce://{credentials.host}"

    class _SalesforceConnector:
        name = _CONNECTOR
        external_validation = EXTERNAL_VALIDATION_NOTE

        def discover(self) -> AssetInventory:
            assets: list[AssetRecord] = []
            unreachable: list[Unreachable] = []
            examined = 0
            complete = True

            for soql, kind, native, label in (
                (BOT_SOQL, AssetKind.AGENT, "BotDefinition", "agents"),
                (FUNCTION_SOQL, AssetKind.SKILL, "GenAiFunctionDefinition", "actions"),
                (PLUGIN_SOQL, AssetKind.SKILL, "GenAiPluginDefinition", "topics"),
            ):
                paged = self._query(soql, label, unreachable)
                if not paged.complete:
                    complete = False
                for record in paged.items:
                    examined += 1
                    record_id = _text(record.get("Id"))
                    if not record_id:
                        continue
                    relates: tuple[str, ...] = ()
                    attributes: dict[str, Any] = {
                        "developer_name": _text(record.get("DeveloperName")),
                        "modified_at": _text(record.get("LastModifiedDate")),
                    }
                    if kind is AssetKind.AGENT:
                        run_as = _text(record.get("BotUserId"))
                        if run_as:
                            relates = (f"{org_id}/user/{run_as}",)
                            attributes["bot_user_id"] = run_as
                    assets.append(
                        AssetRecord(
                            kind=kind,
                            identifier=f"{org_id}/{native}/{record_id}",
                            source=_CONNECTOR,
                            native_type=native,
                            display_name=_text(record.get("MasterLabel")),
                            relates_to=relates,
                            attributes=attributes,
                        )
                    )

            return AssetInventory(
                connector=_CONNECTOR,
                assets=tuple(assets),
                coverage=DiscoveryCoverage(
                    scope=(f"salesforce:{credentials.scope}",),
                    examined=examined,
                    unreachable=tuple(unreachable),
                    permissions_used=(
                        "API Enabled",
                        "SOQL: BotDefinition",
                        "SOQL: GenAiFunctionDefinition (UNVALIDATED)",
                        "SOQL: GenAiPluginDefinition (UNVALIDATED)",
                    ),
                    retrieved_at=_now(),
                    pagination_complete=complete,
                ),
            )

        @staticmethod
        def _query(soql: str, label: str, unreachable: list[Unreachable]) -> Any:
            target = f"salesforce:{label}"
            first = f"{base}{QUERY_PATH}?{urllib.parse.urlencode({'q': soql})}"

            def fetch(cursor: str) -> tuple[list[Mapping[str, Any]], str] | None:
                if cursor and not cursor.startswith("/services/data/"):
                    unreachable.append(
                        Unreachable(
                            target=target,
                            reason=(
                                "nextRecordsUrl was not a /services/data/ "
                                "path; not followed, so this is a subset"
                            ),
                        )
                    )
                    return None
                document = _get_json(
                    client,
                    url=f"{base}{cursor}" if cursor else first,
                    headers=headers,
                    target=target,
                    unreachable=unreachable,
                )
                if document is None:
                    return None
                if not isinstance(document, Mapping):
                    # Salesforce reports errors as a JSON ARRAY of
                    # `{message, errorCode}` -- with a non-200, normally, but
                    # a list where an object was expected must not become
                    # zero records.
                    unreachable.append(
                        Unreachable(
                            target=target,
                            reason="the response was not a query result object",
                        )
                    )
                    return None
                records = document.get("records")
                rows = (
                    [r for r in records if isinstance(r, Mapping)]
                    if isinstance(records, list)
                    else []
                )
                if document.get("done") is True:
                    return rows, ""
                next_url = _text(document.get("nextRecordsUrl"))
                if not next_url:
                    unreachable.append(
                        Unreachable(
                            target=target,
                            reason=(
                                "done was false and no nextRecordsUrl was "
                                "given; the listing cannot continue and is a "
                                "subset"
                            ),
                        )
                    )
                    # Rows from this page are kept; `paginate` marks the
                    # listing incomplete because a reason was recorded.
                    return rows, ""
                return rows, next_url

            return paginate(fetch, target=target, unreachable=unreachable)

    return _SalesforceConnector()
