"""Discovery connectors for the platforms that actually host agents.

WHY THESE FIVE
--------------
`connectors.py` covers Kubernetes and AWS IAM, which discover the identities an
agent could act as. Neither knows what an agent IS. These five talk to the
control planes where agents are declared, so what comes back is an agent
because the platform says so -- not because a name matched a pattern.

  * Bedrock Agents (AgentCore) -- `bedrock-agent:ListAgents`
  * Microsoft Entra -- Graph `servicePrincipals`
  * Vertex AI -- `reasoningEngines`
  * OpenAI -- `assistants`
  * Generic MCP -- JSON-RPC `tools/list`

REQUIRES EXTERNAL VALIDATION
-----------------------------
None of these has ever authenticated against a real tenant. The request
shapes, auth headers, pagination fields and permission scopes are written from
each vendor's published API contract, and a published contract is not a
successful call. What is claimed here is that the code exists and refuses
honestly; what is NOT claimed is that any of it has spoken to a live account.
That gate closes when somebody runs it with real credentials, and it cannot
close from a repository.

The tests exercise each connector against a stub transport, which proves the
parsing, the pagination honesty and the refusal behaviour. It does not prove
the endpoint is right. Those are different claims and this module does not
blur them.

THE RULE EVERY ONE OF THESE FOLLOWS
------------------------------------
An unconfigured connector is ABSENT, never present-and-empty. An empty
inventory is indistinguishable from a clean estate, and a discovery product
whose "no agents found" might mean "no credential configured" has taught its
operator to ignore it. `build_ai_connectors` returns only what it has
credentials for.

And a truncated listing sets `pagination_complete=False` with the reason. A
connector that stopped at the first page and said nothing reports a subset as
a total -- which is the same lie as the empty inventory, arriving later.

WHY THE KINDS ARE WHAT THEY ARE
--------------------------------
Entra service principals are SERVICE_ACCOUNT, not AGENT. Graph has no concept
of an agent, and an app registration called `prod-agent-sync` is an app
registration. Inferring identity from a naming convention is what
`aws_iam_connector` already refuses to do, and doing it here would make the
AGENT count unusable for exactly the operators who most need it.

Bedrock agents, Vertex reasoning engines and OpenAI assistants ARE agents in
their platform's own vocabulary, so those are AGENT.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import urllib.parse
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
)
from sentinel.infrastructure.platforms.ai_discovery import (
    EXTERNAL_VALIDATION_NOTE,
    MAX_PAGES,
    BearerCredentials,
    McpEndpoint,
    _get_json,
    _now,
    _text,
)
from sentinel.infrastructure.platforms.aws import AwsCredentials, sign_request

__all__ = [
    "EXTERNAL_VALIDATION_NOTE",
    "BearerCredentials",
    "McpEndpoint",
    "bedrock_agent_connector",
    "build_ai_connectors",
    "entra_connector",
    "generic_mcp_connector",
    "openai_connector",
    "vertex_connector",
]

# ── Bedrock Agents (AgentCore) ───────────────────────────────────────────────


def bedrock_agent_connector(
    *,
    client: HardenedHttpClient,
    credentials: AwsCredentials,
    clock: Any = None,
) -> Any:
    """Amazon Bedrock Agents in one region.

    `ListAgents` is a POST to `/agents/` on the `bedrock-agent` control plane,
    REST-JSON rather than either AWS query protocol -- so it needs both the
    path and the content type that `sign_request` gained for it. The content
    type is a signed header, so getting it wrong fails the signature rather
    than the parse, which is why it is passed explicitly instead of defaulted.
    """
    region = credentials.region
    host = f"bedrock-agent.{region}.amazonaws.com"

    class _BedrockAgentConnector:
        name = "bedrock_agent"
        external_validation = EXTERNAL_VALIDATION_NOTE

        def discover(self) -> AssetInventory:
            assets: list[AssetRecord] = []
            unreachable: list[Unreachable] = []
            examined = 0
            complete = True
            token = ""

            for page in range(MAX_PAGES):
                request: dict[str, Any] = {"maxResults": 100}
                if token:
                    request["nextToken"] = token
                payload = json.dumps(request).encode("utf-8")
                now = (
                    clock()
                    if clock is not None
                    else _dt.datetime.now(_dt.timezone.utc)
                )
                headers = sign_request(
                    credentials=credentials,
                    service="bedrock",
                    host=host,
                    amz_target="",
                    payload=payload,
                    now=now,
                    path="/agents/",
                    content_type="application/json",
                )
                document = _get_json(
                    client,
                    url=f"https://{host}/agents/",
                    headers=headers,
                    target=f"bedrock-agent:ListAgents:page{page}",
                    unreachable=unreachable,
                    method="POST",
                    body=payload,
                )
                if document is None:
                    complete = False
                    break
                summaries = document.get("agentSummaries")
                if not isinstance(summaries, list):
                    summaries = []
                for summary in summaries:
                    if not isinstance(summary, Mapping):
                        continue
                    examined += 1
                    agent_id = _text(summary.get("agentId"))
                    if not agent_id:
                        # No identifier means nothing can correlate or act on
                        # it. Counted in `examined` so the denominator stays
                        # honest, and recorded so the absence is visible.
                        unreachable.append(
                            Unreachable(
                                target="bedrock-agent:agent",
                                reason=(
                                    "an agent summary carried no agentId, so "
                                    "it cannot be referred to; skipped"
                                ),
                            )
                        )
                        continue
                    assets.append(
                        AssetRecord(
                            kind=AssetKind.AGENT,
                            identifier=(
                                f"aws://bedrock-agent/{region}/agent/{agent_id}"
                            ),
                            source="bedrock_agent",
                            native_type="BedrockAgent",
                            display_name=_text(summary.get("agentName")),
                            attributes={
                                "region": region,
                                "status": _text(summary.get("agentStatus")),
                                "updated_at": _text(summary.get("updatedAt")),
                            },
                        )
                    )
                token = _text(document.get("nextToken"))
                if not token:
                    break
            else:
                # The for-else fires only when the page cap was exhausted with
                # a token still outstanding.
                complete = False
                unreachable.append(
                    Unreachable(
                        target="bedrock-agent:ListAgents",
                        reason=(
                            f"stopped after {MAX_PAGES} pages with more "
                            "results outstanding; this is a subset"
                        ),
                    )
                )

            return AssetInventory(
                connector="bedrock_agent",
                assets=tuple(assets),
                coverage=DiscoveryCoverage(
                    scope=(f"bedrock-agent:{region}",),
                    examined=examined,
                    unreachable=tuple(unreachable),
                    permissions_used=("bedrock:ListAgents",),
                    retrieved_at=_now(),
                    pagination_complete=complete,
                ),
            )

    return _BedrockAgentConnector()


# ── Microsoft Entra ──────────────────────────────────────────────────────────

#: Graph fields requested. An explicit projection rather than the default,
#: which returns far more about each principal than discovery needs -- and
#: every extra field is data pulled into this system that nobody asked for.
_ENTRA_SELECT = (
    "id,appId,displayName,servicePrincipalType,accountEnabled,"
    "servicePrincipalNames"
)


def entra_connector(
    *,
    client: HardenedHttpClient,
    credentials: BearerCredentials,
) -> Any:
    """Entra service principals: the workload identities in a tenant.

    Reported as SERVICE_ACCOUNT, never AGENT. Graph has no concept of an
    agent, and an app registration named `prod-agent-sync` is an app
    registration -- inferring otherwise from the name is the exact thing
    `aws_iam_connector` refuses to do.
    """

    class _EntraConnector:
        name = "entra"
        external_validation = EXTERNAL_VALIDATION_NOTE

        def discover(self) -> AssetInventory:
            assets: list[AssetRecord] = []
            unreachable: list[Unreachable] = []
            examined = 0
            complete = True
            url = (
                "https://graph.microsoft.com/v1.0/servicePrincipals?"
                + urllib.parse.urlencode(
                    {"$select": _ENTRA_SELECT, "$top": "100"}
                )
            )

            for page in range(MAX_PAGES):
                document = _get_json(
                    client,
                    url=url,
                    headers={
                        "authorization": f"Bearer {credentials.token}",
                        "accept": "application/json",
                    },
                    target=f"graph:servicePrincipals:page{page}",
                    unreachable=unreachable,
                )
                if document is None:
                    complete = False
                    break
                values = document.get("value")
                if not isinstance(values, list):
                    values = []
                for item in values:
                    if not isinstance(item, Mapping):
                        continue
                    examined += 1
                    principal_id = _text(item.get("id"))
                    if not principal_id:
                        continue
                    assets.append(
                        AssetRecord(
                            kind=AssetKind.SERVICE_ACCOUNT,
                            identifier=(
                                f"entra://{credentials.scope or 'tenant'}"
                                f"/servicePrincipal/{principal_id}"
                            ),
                            source="entra",
                            native_type=_text(item.get("servicePrincipalType"))
                            or "ServicePrincipal",
                            display_name=_text(item.get("displayName")),
                            attributes={
                                "app_id": _text(item.get("appId")),
                                "enabled": bool(item.get("accountEnabled")),
                            },
                        )
                    )
                next_link = _text(document.get("@odata.nextLink"))
                if not next_link:
                    break
                url = next_link
            else:
                complete = False
                unreachable.append(
                    Unreachable(
                        target="graph:servicePrincipals",
                        reason=(
                            f"stopped after {MAX_PAGES} pages with an "
                            "@odata.nextLink outstanding; this is a subset"
                        ),
                    )
                )

            return AssetInventory(
                connector="entra",
                assets=tuple(assets),
                coverage=DiscoveryCoverage(
                    scope=(f"entra:{credentials.scope or 'tenant'}",),
                    examined=examined,
                    unreachable=tuple(unreachable),
                    permissions_used=("Application.Read.All",),
                    retrieved_at=_now(),
                    pagination_complete=complete,
                ),
            )

    return _EntraConnector()


# ── Vertex AI ────────────────────────────────────────────────────────────────

_GCP_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,62}$")


def vertex_connector(
    *,
    client: HardenedHttpClient,
    credentials: BearerCredentials,
    location: str = "us-central1",
) -> Any:
    """Vertex AI reasoning engines: deployed agents in one project + location.

    The project id and location are interpolated into the URL, so both are
    validated against `_GCP_ID` first. They come from operator configuration
    rather than from a request, but a path built by interpolation is a path
    built by interpolation, and validating it costs one regex.
    """
    project = credentials.scope
    if not _GCP_ID.match(project):
        raise ValueError(
            f"refusing to build a Vertex connector for project {project!r}: "
            "the project id is interpolated into the request URL and must "
            "match a GCP project id, or the connector would issue a request "
            "to a path this module did not intend."
        )
    if not _GCP_ID.match(location):
        raise ValueError(
            f"refusing to build a Vertex connector for location {location!r}"
        )

    class _VertexConnector:
        name = "vertex"
        external_validation = EXTERNAL_VALIDATION_NOTE

        def discover(self) -> AssetInventory:
            assets: list[AssetRecord] = []
            unreachable: list[Unreachable] = []
            examined = 0
            complete = True
            base = (
                f"https://{location}-aiplatform.googleapis.com/v1/projects/"
                f"{project}/locations/{location}/reasoningEngines"
            )
            token = ""

            for page in range(MAX_PAGES):
                query = {"pageSize": "100"}
                if token:
                    query["pageToken"] = token
                document = _get_json(
                    client,
                    url=f"{base}?{urllib.parse.urlencode(query)}",
                    headers={
                        "authorization": f"Bearer {credentials.token}",
                        "accept": "application/json",
                    },
                    target=f"vertex:reasoningEngines:page{page}",
                    unreachable=unreachable,
                )
                if document is None:
                    complete = False
                    break
                engines = document.get("reasoningEngines")
                if not isinstance(engines, list):
                    engines = []
                for engine in engines:
                    if not isinstance(engine, Mapping):
                        continue
                    examined += 1
                    # Vertex returns the fully qualified resource name, which
                    # is already a stable global identifier -- so it is used
                    # rather than a locally composed one.
                    resource = _text(engine.get("name"))
                    if not resource:
                        continue
                    assets.append(
                        AssetRecord(
                            kind=AssetKind.AGENT,
                            identifier=f"gcp://aiplatform/{resource}",
                            source="vertex",
                            native_type="ReasoningEngine",
                            display_name=_text(engine.get("displayName")),
                            attributes={
                                "project": project,
                                "location": location,
                                "updated_at": _text(engine.get("updateTime")),
                            },
                        )
                    )
                token = _text(document.get("nextPageToken"))
                if not token:
                    break
            else:
                complete = False
                unreachable.append(
                    Unreachable(
                        target="vertex:reasoningEngines",
                        reason=(
                            f"stopped after {MAX_PAGES} pages with a "
                            "nextPageToken outstanding; this is a subset"
                        ),
                    )
                )

            return AssetInventory(
                connector="vertex",
                assets=tuple(assets),
                coverage=DiscoveryCoverage(
                    scope=(f"vertex:{project}/{location}",),
                    examined=examined,
                    unreachable=tuple(unreachable),
                    permissions_used=("aiplatform.reasoningEngines.list",),
                    retrieved_at=_now(),
                    pagination_complete=complete,
                ),
            )

    return _VertexConnector()


# ── OpenAI ───────────────────────────────────────────────────────────────────


def openai_connector(
    *,
    client: HardenedHttpClient,
    credentials: BearerCredentials,
) -> Any:
    """OpenAI assistants in one organisation.

    Paginated by cursor rather than token: the response carries `has_more` and
    the caller passes the last id as `after`. `has_more` is trusted for the
    stop decision and the id is taken from the last record, because inferring
    "no more" from a short page would report a total from a partial listing the
    moment the page size changed.
    """

    class _OpenAiConnector:
        name = "openai"
        external_validation = EXTERNAL_VALIDATION_NOTE

        def discover(self) -> AssetInventory:
            assets: list[AssetRecord] = []
            unreachable: list[Unreachable] = []
            examined = 0
            complete = True
            after = ""

            for page in range(MAX_PAGES):
                query = {"limit": "100", "order": "asc"}
                if after:
                    query["after"] = after
                headers = {
                    "authorization": f"Bearer {credentials.token}",
                    "accept": "application/json",
                    # Required by the Assistants API. Sent explicitly because
                    # its absence is a 400 that reads like a malformed request.
                    "openai-beta": "assistants=v2",
                }
                if credentials.scope:
                    headers["openai-organization"] = credentials.scope
                document = _get_json(
                    client,
                    url=(
                        "https://api.openai.com/v1/assistants?"
                        + urllib.parse.urlencode(query)
                    ),
                    headers=headers,
                    target=f"openai:assistants:page{page}",
                    unreachable=unreachable,
                )
                if document is None:
                    complete = False
                    break
                data = document.get("data")
                if not isinstance(data, list):
                    data = []
                for item in data:
                    if not isinstance(item, Mapping):
                        continue
                    examined += 1
                    assistant_id = _text(item.get("id"))
                    if not assistant_id:
                        continue
                    after = assistant_id
                    assets.append(
                        AssetRecord(
                            kind=AssetKind.AGENT,
                            identifier=f"openai://assistant/{assistant_id}",
                            source="openai",
                            native_type="Assistant",
                            display_name=_text(item.get("name")),
                            attributes={
                                "model": _text(item.get("model")),
                                # The tool TYPES an assistant may call. Names
                                # only: a tool definition can carry a
                                # description written by whoever created the
                                # assistant, and that is untrusted text this
                                # system has no reason to store.
                                "tool_types": sorted(
                                    {
                                        _text(defn.get("type"))
                                        for defn in item.get("tools", [])
                                        if isinstance(defn, Mapping)
                                        and _text(defn.get("type"))
                                    }
                                ),
                            },
                        )
                    )
                if not document.get("has_more"):
                    break
                if not after:
                    # `has_more` is true and there is no cursor to advance on.
                    # Following it would re-request the same page forever.
                    complete = False
                    unreachable.append(
                        Unreachable(
                            target="openai:assistants",
                            reason=(
                                "has_more was true but no record carried an "
                                "id to page after, so the listing cannot be "
                                "continued; this is a subset"
                            ),
                        )
                    )
                    break
            else:
                complete = False
                unreachable.append(
                    Unreachable(
                        target="openai:assistants",
                        reason=(
                            f"stopped after {MAX_PAGES} pages with has_more "
                            "still true; this is a subset"
                        ),
                    )
                )

            return AssetInventory(
                connector="openai",
                assets=tuple(assets),
                coverage=DiscoveryCoverage(
                    scope=(f"openai:{credentials.scope or 'default-org'}",),
                    examined=examined,
                    unreachable=tuple(unreachable),
                    permissions_used=("api.openai.com/v1/assistants:read",),
                    retrieved_at=_now(),
                    pagination_complete=complete,
                ),
            )

    return _OpenAiConnector()


# ── Generic MCP ──────────────────────────────────────────────────────────────


def generic_mcp_connector(
    *,
    client: HardenedHttpClient,
    endpoints: Sequence[McpEndpoint],
) -> Any:
    """Any MCP server, enumerated by its own `tools/list` method.

    Each endpoint becomes one MCP_SERVER and each tool one MCP_TOOL related to
    it. The relationship is recorded as an edge on the tool, not assembled
    into a graph here -- `effective_permissions` owns that, and a connector
    that built one would be deciding reachability from a single vantage.

    TOOL DESCRIPTIONS ARE DELIBERATELY NOT STORED.
    An MCP tool description is text written by whoever runs that server, and
    this codebase already treats it as an injection vector: the whole
    `test_mcp_attacks.py` suite exists because a description is a place to put
    instructions aimed at a model. Storing it in an inventory would put
    attacker-authored prose into the records an analyst reads and a model
    summarises. The NAME is what discovery needs.
    """

    class _GenericMcpConnector:
        name = "generic_mcp"
        external_validation = EXTERNAL_VALIDATION_NOTE

        def discover(self) -> AssetInventory:
            assets: list[AssetRecord] = []
            unreachable: list[Unreachable] = []
            examined = 0
            complete = True

            for index, endpoint in enumerate(endpoints):
                label = endpoint.label or endpoint.url
                server_id = f"mcp://{label}"
                assets.append(
                    AssetRecord(
                        kind=AssetKind.MCP_SERVER,
                        identifier=server_id,
                        source="generic_mcp",
                        native_type="McpServer",
                        display_name=label,
                        attributes={"url": endpoint.url},
                    )
                )
                headers = {
                    "content-type": "application/json",
                    "accept": "application/json",
                }
                if endpoint.token:
                    headers["authorization"] = f"Bearer {endpoint.token}"
                body = json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": index + 1,
                        "method": "tools/list",
                        "params": {},
                    }
                ).encode("utf-8")
                document = _get_json(
                    client,
                    url=endpoint.url,
                    headers=headers,
                    target=f"mcp:{label}:tools/list",
                    unreachable=unreachable,
                    method="POST",
                    body=body,
                )
                if document is None:
                    complete = False
                    continue
                if isinstance(document, Mapping) and "error" in document:
                    error = document.get("error")
                    code = (
                        error.get("code") if isinstance(error, Mapping) else ""
                    )
                    # A JSON-RPC error arrives with HTTP 200, so it would
                    # otherwise parse cleanly into zero tools -- a failure
                    # recorded as a clean scan.
                    unreachable.append(
                        Unreachable(
                            target=f"mcp:{label}:tools/list",
                            reason=(
                                f"the server returned a JSON-RPC error "
                                f"(code {code!r}). HTTP was 200, so this "
                                "would otherwise read as a server with no "
                                "tools."
                            ),
                        )
                    )
                    complete = False
                    continue
                result = (
                    document.get("result")
                    if isinstance(document, Mapping)
                    else None
                )
                tools = (
                    result.get("tools") if isinstance(result, Mapping) else None
                )
                if not isinstance(tools, list):
                    tools = []
                for tool in tools:
                    if not isinstance(tool, Mapping):
                        continue
                    examined += 1
                    tool_name = _text(tool.get("name"))
                    if not tool_name:
                        continue
                    assets.append(
                        AssetRecord(
                            kind=AssetKind.MCP_TOOL,
                            identifier=f"{server_id}/tool/{tool_name}",
                            source="generic_mcp",
                            native_type="McpTool",
                            display_name=tool_name,
                            relates_to=(server_id,),
                            # No `description`: see the docstring. It is
                            # attacker-authored text.
                            attributes={"server": label},
                        )
                    )

            return AssetInventory(
                connector="generic_mcp",
                assets=tuple(assets),
                coverage=DiscoveryCoverage(
                    scope=tuple(e.label or e.url for e in endpoints),
                    examined=examined,
                    unreachable=tuple(unreachable),
                    permissions_used=("mcp:tools/list",),
                    retrieved_at=_now(),
                    pagination_complete=complete,
                ),
            )

    return _GenericMcpConnector()


# ── Composition ──────────────────────────────────────────────────────────────


def build_ai_connectors(
    *,
    http_client: HardenedHttpClient | None = None,
    bedrock: AwsCredentials | None = None,
    entra: BearerCredentials | None = None,
    vertex: BearerCredentials | None = None,
    vertex_location: str = "us-central1",
    openai: BearerCredentials | None = None,
    mcp_endpoints: Sequence[McpEndpoint] = (),
) -> dict[str, Any]:
    """Exactly the connectors an operator supplied credentials for.

    Same rule as `build_connectors`: an unconfigured connector is ABSENT, not
    present-and-empty, because an empty inventory is indistinguishable from a
    clean estate.
    """
    connectors: dict[str, Any] = {}
    client = http_client or HardenedHttpClient()

    if bedrock is not None:
        connector = bedrock_agent_connector(client=client, credentials=bedrock)
        connectors[connector.name] = connector
    if entra is not None:
        connector = entra_connector(client=client, credentials=entra)
        connectors[connector.name] = connector
    if vertex is not None:
        connector = vertex_connector(
            client=client, credentials=vertex, location=vertex_location
        )
        connectors[connector.name] = connector
    if openai is not None:
        connector = openai_connector(client=client, credentials=openai)
        connectors[connector.name] = connector
    if mcp_endpoints:
        connector = generic_mcp_connector(client=client, endpoints=mcp_endpoints)
        connectors[connector.name] = connector
    return connectors
