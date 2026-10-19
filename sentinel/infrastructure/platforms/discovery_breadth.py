"""Second-wave discovery connector registry and environment parsing."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from sentinel.infrastructure.outbound import HardenedHttpClient
from sentinel.infrastructure.platforms.ai_discovery import BearerCredentials
from sentinel.infrastructure.platforms.copilot_studio import (
    DataverseEnvironment,
    copilot_studio_connector,
)
from sentinel.infrastructure.platforms.databricks_agents import (
    databricks_agents_connector,
)
from sentinel.infrastructure.platforms.discovery_support import HostCredentials
from sentinel.infrastructure.platforms.gitlab_discovery import (
    GitlabProject,
    gitlab_ci_connector,
)
from sentinel.infrastructure.platforms.identity_agents import (
    entra_agent_id_connector,
    okta_agents_connector,
)
from sentinel.infrastructure.platforms.local_mcp_configs import (
    LocalMcpConfigPath,
    local_mcp_config_connector,
)
from sentinel.infrastructure.platforms.salesforce_agentforce import (
    salesforce_agentforce_connector,
)
from sentinel.infrastructure.platforms.servicenow_agents import (
    servicenow_agents_connector,
)
from sentinel.infrastructure.platforms.slack_apps import slack_apps_connector

__all__ = [
    "BREADTH_CONFIGURATION",
    "build_breadth_connectors",
]

BREADTH_CONFIGURATION = (
    (
        "copilot_studio",
        "SENTINEL_DISCOVERY_COPILOT_ENVIRONMENTS=label=host + _TOKEN_LABEL",
    ),
    (
        "salesforce_agentforce",
        "SENTINEL_DISCOVERY_SALESFORCE_HOST + _TOKEN [+ _ORG]",
    ),
    (
        "servicenow_agents",
        "SENTINEL_DISCOVERY_SERVICENOW_HOST + _TOKEN [+ _INSTANCE]",
    ),
    (
        "databricks_agents",
        "SENTINEL_DISCOVERY_DATABRICKS_HOST + _TOKEN [+ _WORKSPACE]",
    ),
    (
        "local_mcp_configs",
        "SENTINEL_DISCOVERY_MCP_CONFIG_PATHS=client=/path,client2=/path",
    ),
    (
        "slack_apps",
        "SENTINEL_DISCOVERY_SLACK_TOKEN + _TEAM_ID|_ENTERPRISE_ID [+ _BOT_IDS]",
    ),
    (
        "gitlab_ci",
        "SENTINEL_DISCOVERY_GITLAB_HOST + _TOKEN + _PROJECTS=path[@ref],...",
    ),
    ("okta_agents", "SENTINEL_DISCOVERY_OKTA_HOST + _TOKEN [+ _ORG]"),
    (
        "entra_agent_id",
        "SENTINEL_DISCOVERY_ENTRA_AGENT_ID_TOKEN + _TENANT",
    ),
)


def _text(source: Mapping[str, str], name: str) -> str:
    return (source.get(name) or "").strip()


def _list(source: Mapping[str, str], name: str) -> tuple[str, ...]:
    return tuple(
        part.strip() for part in _text(source, name).split(",") if part.strip()
    )


def _label_key(prefix: str, label: str) -> str:
    safe = "".join(ch if ch.isalnum() else "_" for ch in label.upper())
    return f"{prefix}_{safe}"


def _host_credentials(
    source: Mapping[str, str],
    *,
    prefix: str,
    scope_name: str,
) -> HostCredentials | None:
    host = _text(source, f"{prefix}_HOST")
    token = _text(source, f"{prefix}_TOKEN")
    if not (host and token):
        return None
    return HostCredentials(
        host=host,
        token=token,
        scope=_text(source, scope_name),
    )


def _copilot_environments(
    source: Mapping[str, str],
) -> tuple[DataverseEnvironment, ...]:
    environments: list[DataverseEnvironment] = []
    for entry in _list(source, "SENTINEL_DISCOVERY_COPILOT_ENVIRONMENTS"):
        label, _, host = entry.partition("=")
        if not (label.strip() and host.strip()):
            continue
        token = _text(
            source,
            _label_key("SENTINEL_DISCOVERY_COPILOT_TOKEN", label),
        )
        if not token:
            continue
        environments.append(
            DataverseEnvironment(
                label=label.strip(),
                host=host.strip(),
                token=token,
            )
        )
    return tuple(environments)


def _local_mcp_paths(source: Mapping[str, str]) -> tuple[LocalMcpConfigPath, ...]:
    paths: list[LocalMcpConfigPath] = []
    for entry in _list(source, "SENTINEL_DISCOVERY_MCP_CONFIG_PATHS"):
        client, _, path = entry.partition("=")
        if not (client.strip() and path.strip()):
            continue
        paths.append(LocalMcpConfigPath(client=client.strip(), path=Path(path)))
    return tuple(paths)


def _gitlab_projects(source: Mapping[str, str]) -> tuple[GitlabProject, ...]:
    projects: list[GitlabProject] = []
    for entry in _list(source, "SENTINEL_DISCOVERY_GITLAB_PROJECTS"):
        project, _, ref = entry.partition("@")
        if not project.strip():
            continue
        projects.append(GitlabProject(project=project.strip(), ref=ref or "main"))
    return tuple(projects)


def build_breadth_connectors(
    source: Mapping[str, str],
    *,
    http_client: HardenedHttpClient | None = None,
) -> dict[str, Any]:
    """Every second-wave connector this deployment supplied credentials for."""
    client = http_client or HardenedHttpClient()
    connectors: dict[str, Any] = {}

    copilot = _copilot_environments(source)
    if copilot:
        connector = copilot_studio_connector(client=client, environments=copilot)
        connectors[connector.name] = connector

    for key, prefix, scope_name, factory in (
        (
            "salesforce_agentforce",
            "SENTINEL_DISCOVERY_SALESFORCE",
            "SENTINEL_DISCOVERY_SALESFORCE_ORG",
            salesforce_agentforce_connector,
        ),
        (
            "servicenow_agents",
            "SENTINEL_DISCOVERY_SERVICENOW",
            "SENTINEL_DISCOVERY_SERVICENOW_INSTANCE",
            servicenow_agents_connector,
        ),
        (
            "databricks_agents",
            "SENTINEL_DISCOVERY_DATABRICKS",
            "SENTINEL_DISCOVERY_DATABRICKS_WORKSPACE",
            databricks_agents_connector,
        ),
        (
            "okta_agents",
            "SENTINEL_DISCOVERY_OKTA",
            "SENTINEL_DISCOVERY_OKTA_ORG",
            okta_agents_connector,
        ),
    ):
        credentials = _host_credentials(source, prefix=prefix, scope_name=scope_name)
        if credentials is not None:
            connectors[key] = factory(client=client, credentials=credentials)

    mcp_paths = _local_mcp_paths(source)
    if mcp_paths:
        connector = local_mcp_config_connector(paths=mcp_paths)
        connectors[connector.name] = connector

    slack = _text(source, "SENTINEL_DISCOVERY_SLACK_TOKEN")
    if slack:
        connector = slack_apps_connector(
            client=client,
            credentials=BearerCredentials(
                token=slack,
                scope=_text(source, "SENTINEL_DISCOVERY_SLACK_WORKSPACE"),
            ),
            team_id=_text(source, "SENTINEL_DISCOVERY_SLACK_TEAM_ID"),
            enterprise_id=_text(source, "SENTINEL_DISCOVERY_SLACK_ENTERPRISE_ID"),
            bot_ids=_list(source, "SENTINEL_DISCOVERY_SLACK_BOT_IDS"),
        )
        connectors[connector.name] = connector

    gitlab_credentials = _host_credentials(
        source,
        prefix="SENTINEL_DISCOVERY_GITLAB",
        scope_name="SENTINEL_DISCOVERY_GITLAB_GROUP",
    )
    gitlab_projects = _gitlab_projects(source)
    if gitlab_credentials is not None and gitlab_projects:
        connector = gitlab_ci_connector(
            client=client,
            credentials=gitlab_credentials,
            projects=gitlab_projects,
        )
        connectors[connector.name] = connector

    entra_agent_token = _text(source, "SENTINEL_DISCOVERY_ENTRA_AGENT_ID_TOKEN")
    if entra_agent_token:
        connector = entra_agent_id_connector(
            client=client,
            credentials=BearerCredentials(
                token=entra_agent_token,
                scope=_text(source, "SENTINEL_DISCOVERY_ENTRA_AGENT_ID_TENANT"),
            ),
        )
        connectors[connector.name] = connector

    return connectors
