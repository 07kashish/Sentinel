"""Microsoft Copilot Studio agents, read from Dataverse.

WHERE COPILOT STUDIO KEEPS ITS AGENTS
-------------------------------------
A Copilot Studio agent is a row in the Dataverse `bot` table of the Power
Platform environment it was authored in, and everything the agent is made of
-- topics, actions, connectors, knowledge sources -- is a row in
`botcomponent` with a `parentbotid` lookup back to the bot. So the inventory
is two OData listings per environment, with the platform's own vocabulary
saying which rows are agents. Nothing is inferred from a name.

ENVIRONMENTS ARE REQUIRED, NOT DISCOVERED
------------------------------------------
The Power Platform admin API can list every environment in a tenant, but an
app-only token is minted for ONE audience, and each Dataverse instance is its
own audience. One token cannot read two environments, so an operator supplies
each environment with its own token -- the same shape as the MCP endpoint
list, and the same rule as the Kubernetes namespaces: what is scanned is
stated, never guessed.

`ADMIN_ENVIRONMENTS_URL` is kept as a named constant for the day this grows an
enumeration step. It is UNVALIDATED and nothing calls it.

WHAT IS AND IS NOT STORED
-------------------------
Names, schema names, types and state. NOT `botcomponent.data` -- that column
holds the component's YAML, which for a topic is the prompt and for an action
is the description a model reads. Both are text written by whoever built the
agent, and the inventory does not carry attacker-authored prose. The
`$select` projection never asks for it.

REQUIRES EXTERNAL VALIDATION
-----------------------------
Never run against a real environment. The entity set names, the `$select`
columns and the OData paging header come from the Dataverse Web API and the
Copilot Studio table reference; `COMPONENT_TYPES` is the option set as
remembered and is the part most likely to need correcting against a tenant.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from types import MappingProxyType
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
    _get_json,
    _now,
    _text,
    paginate,
    validate_host,
)

__all__ = [
    "ADMIN_ENVIRONMENTS_URL",
    "BOTS_PATH",
    "BOT_COMPONENTS_PATH",
    "COMPONENT_TYPES",
    "DataverseEnvironment",
    "copilot_studio_connector",
]

_CONNECTOR = "copilot_studio"

#: Dataverse Web API entity sets. `bot` and `botcomponent` are the Copilot
#: Studio tables; the entity-set (plural) form is what the URL takes.
BOTS_PATH = "/api/data/v9.2/bots"
BOT_COMPONENTS_PATH = "/api/data/v9.2/botcomponents"

#: UNVALIDATED and UNUSED: the Power Platform admin listing of environments,
#: named here so a future enumeration step corrects one constant.
ADMIN_ENVIRONMENTS_URL = (
    "https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform"
    "/scopes/admin/environments?api-version=2021-04-01"
)

#: `botcomponent.componenttype` option set, as remembered from the table
#: reference. UNVALIDATED: a real tenant may disagree, and a reader comparing
#: this against a console is the correction path. Values not listed are
#: reported as `BotComponent:<n>` rather than guessed.
COMPONENT_TYPES: Mapping[int, str] = MappingProxyType(
    {
        0: "Topic",
        1: "Skill",
        2: "BotVariable",
        3: "BotEntity",
        4: "Dialog",
        5: "Trigger",
        6: "LanguageUnderstandingModel",
        7: "SkillManifest",
        8: "BotTranslations",
        9: "KnowledgeSource",
        10: "Connector",
        15: "Prompt",
        16: "Flow",
    }
)

#: Component types that are the agent's own conversation structure or state
#: rather than something it can reach out through. Counted in `examined`,
#: not reported as SKILL. Only the types this module is confident about.
_STRUCTURAL_TYPES = frozenset({0, 2, 3})

_BOT_SELECT = "botid,name,schemaname,statecode,statuscode,modifiedon,_ownerid_value"
_COMPONENT_SELECT = (
    "botcomponentid,name,schemaname,componenttype,statecode,_parentbotid_value"
)
_PAGE_SIZE = 100


@dataclass(frozen=True, slots=True)
class DataverseEnvironment:
    """One environment: a label, its Dataverse instance host, and its token."""

    label: str
    host: str
    token: str

    def __post_init__(self) -> None:
        if not str(self.label).strip():
            raise ValueError("a Dataverse environment needs a label")
        if not str(self.token).strip():
            raise ValueError(
                f"environment {self.label!r} has an empty token; refusing to "
                "build a connector that would report a 401 as an outage"
            )
        object.__setattr__(
            self, "host", validate_host(self.host, what="Dataverse instance")
        )

    def __repr__(self) -> str:
        return (
            f"DataverseEnvironment(label={self.label!r}, host={self.host!r}, "
            "token=<redacted>)"
        )


def _headers(token: str) -> dict[str, str]:
    return {
        "authorization": f"Bearer {token}",
        "accept": "application/json",
        "odata-maxversion": "4.0",
        "odata-version": "4.0",
        # Server-driven paging: Dataverse answers with `@odata.nextLink`.
        "prefer": f"odata.maxpagesize={_PAGE_SIZE}",
    }


def copilot_studio_connector(
    *,
    client: HardenedHttpClient,
    environments: Sequence[DataverseEnvironment],
) -> Any:
    """Bots as AGENT and their components as SKILL, per environment.

    Each environment is also reported as an ENVIRONMENT asset, so a bot has a
    container to relate to and an operator can see which environments were
    scanned even when they held nothing.
    """
    if not environments:
        raise ValueError(
            "no Dataverse environments given. Environments are supplied, not "
            "discovered, because each is its own token audience."
        )

    class _CopilotStudioConnector:
        name = _CONNECTOR
        external_validation = EXTERNAL_VALIDATION_NOTE

        def discover(self) -> AssetInventory:
            assets: list[AssetRecord] = []
            unreachable: list[Unreachable] = []
            examined = 0
            complete = True

            for env in environments:
                env_id = f"powerplatform://{env.label}"
                assets.append(
                    AssetRecord(
                        kind=AssetKind.ENVIRONMENT,
                        identifier=env_id,
                        source=_CONNECTOR,
                        native_type="DataverseEnvironment",
                        display_name=env.label,
                        environment=env.label,
                        attributes={"host": env.host},
                    )
                )
                headers = _headers(env.token)

                bots = self._listing(
                    env, headers, BOTS_PATH, _BOT_SELECT, unreachable
                )
                if not bots.complete:
                    complete = False
                for row in bots.items:
                    examined += 1
                    bot_id = _text(row.get("botid"))
                    if not bot_id:
                        continue
                    assets.append(
                        AssetRecord(
                            kind=AssetKind.AGENT,
                            identifier=f"{env_id}/bot/{bot_id}",
                            source=_CONNECTOR,
                            native_type="bot",
                            display_name=_text(row.get("name")),
                            environment=env.label,
                            relates_to=(env_id,),
                            attributes={
                                "schema_name": _text(row.get("schemaname")),
                                "state": row.get("statecode"),
                                "status": row.get("statuscode"),
                                "modified_at": _text(row.get("modifiedon")),
                                "owner_id": _text(row.get("_ownerid_value")),
                            },
                        )
                    )

                components = self._listing(
                    env, headers, BOT_COMPONENTS_PATH, _COMPONENT_SELECT, unreachable
                )
                if not components.complete:
                    complete = False
                for row in components.items:
                    examined += 1
                    component_id = _text(row.get("botcomponentid"))
                    raw_type = row.get("componenttype")
                    kind_number = raw_type if isinstance(raw_type, int) else -1
                    if not component_id or kind_number in _STRUCTURAL_TYPES:
                        continue
                    parent = _text(row.get("_parentbotid_value"))
                    assets.append(
                        AssetRecord(
                            kind=AssetKind.SKILL,
                            identifier=f"{env_id}/botcomponent/{component_id}",
                            source=_CONNECTOR,
                            native_type=COMPONENT_TYPES.get(
                                kind_number, f"BotComponent:{raw_type}"
                            ),
                            display_name=_text(row.get("name")),
                            environment=env.label,
                            relates_to=(
                                (f"{env_id}/bot/{parent}",) if parent else ()
                            ),
                            attributes={
                                "schema_name": _text(row.get("schemaname")),
                                "component_type": raw_type,
                                "state": row.get("statecode"),
                            },
                        )
                    )

            return AssetInventory(
                connector=_CONNECTOR,
                assets=tuple(assets),
                coverage=DiscoveryCoverage(
                    scope=tuple(f"powerplatform:{e.label}" for e in environments),
                    examined=examined,
                    unreachable=tuple(unreachable),
                    permissions_used=("prvReadbot", "prvReadbotcomponent"),
                    retrieved_at=_now(),
                    pagination_complete=complete,
                ),
            )

        @staticmethod
        def _listing(
            env: DataverseEnvironment,
            headers: Mapping[str, str],
            path: str,
            select: str,
            unreachable: list[Unreachable],
        ) -> Any:
            first = (
                f"https://{env.host}{path}?"
                + urllib.parse.urlencode({"$select": select})
            )
            target = f"{env.label}:{path.rsplit('/', 1)[-1]}"

            def fetch(cursor: str) -> tuple[list[Mapping[str, Any]], str] | None:
                url = cursor or first
                if cursor and not cursor.lower().startswith(f"https://{env.host}/"):
                    # A nextLink that points somewhere other than the instance
                    # it came from would carry this environment's token there.
                    unreachable.append(
                        Unreachable(
                            target=target,
                            reason=(
                                "the @odata.nextLink pointed off the instance "
                                "host; not followed, so this is a subset"
                            ),
                        )
                    )
                    return None
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
                            Unreachable(
                                target=target,
                                reason="the response was not a JSON object",
                            )
                        )
                    return None
                values = document.get("value")
                rows = [v for v in values if isinstance(v, Mapping)] if isinstance(
                    values, list
                ) else []
                return rows, _text(document.get("@odata.nextLink"))

            return paginate(fetch, target=target, unreachable=unreachable)

    return _CopilotStudioConnector()
