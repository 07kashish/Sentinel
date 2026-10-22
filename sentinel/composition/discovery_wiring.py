"""Assemble the discovery connectors this deployment has credentials for.

WHY THIS EXISTS
---------------
`build_connectors` (Kubernetes, AWS IAM) and `build_ai_connectors` (Bedrock,
Entra, Vertex, OpenAI, MCP) both had tests and NO production caller. The
connectors were cited in the gap ledger and audited by
the archived state audit, which is how a subsystem comes to look
delivered while being unreachable -- the same defect as the detonation
subsystem, found the same way.

So this is the one place that builds them, and the container holds the result.

WHY THIS MODULE DOES NOT READ THE ENVIRONMENT
----------------------------------------------
It used to, and `test_only_the_settings_module_reads_the_environment` was
right to refuse it. One module reads the environment and everything else
receives values -- that rule is the whole reason `Settings` exists, and my
argument for breaking it (ten optional fields would bloat a frozen dataclass
at its size limit) is answered by carrying ONE field,
`settings.discovery_credentials`, instead.

So `source` is REQUIRED here. There is no default that falls back to
`os.environ`, because a default like that is how the rule gets broken again by
someone who does not know it exists.

ABSENT IS NOT EMPTY
-------------------
A connector with no credential is not built. That rule is in
`build_connectors` and `build_ai_connectors` already; this module must not
undo it by substituting a default. An empty inventory is indistinguishable
from a clean estate, and a discovery product whose "no agents found" might
mean "no credential configured" has taught its operator to ignore it.

NO CREDENTIAL VALUE IS EVER LOGGED OR RETURNED
-----------------------------------------------
`describe` reports which connectors were CONFIGURED, by name. It exists so an
operator can tell "nothing configured" from "configured and found nothing",
which is the distinction the whole module is arranged around -- and it reports
names only, never a token, a key or a URL with credentials in it.
"""

from __future__ import annotations

from typing import Any, Mapping

from sentinel.infrastructure.outbound import HardenedHttpClient
from sentinel.infrastructure.platforms.ai_connectors import (
    BearerCredentials,
    McpEndpoint,
    build_ai_connectors,
)
from sentinel.infrastructure.platforms.aws import AwsCredentials
from sentinel.infrastructure.platforms.connectors import build_connectors
from sentinel.infrastructure.platforms.kubernetes import KubernetesCredentials

__all__ = [
    "build_discovery_connectors",
    "describe_discovery",
    "run_discovery",
]


def _text(source: Mapping[str, str], name: str) -> str:
    return (source.get(name) or "").strip()


def _list(source: Mapping[str, str], name: str) -> tuple[str, ...]:
    return tuple(
        part.strip() for part in _text(source, name).split(",") if part.strip()
    )


def _aws(source: Mapping[str, str], prefix: str) -> AwsCredentials | None:
    """AWS credentials from a prefixed triple, or None.

    All THREE must be present. A partial credential is refused rather than
    completed from a default: a connector built with a key and no region
    fails at request time and is recorded as `unreachable`, which reads as an
    outage rather than as a configuration mistake.
    """
    key = _text(source, f"{prefix}_ACCESS_KEY_ID")
    secret = _text(source, f"{prefix}_SECRET_ACCESS_KEY")
    region = _text(source, f"{prefix}_REGION")
    if not (key and secret and region):
        return None
    return AwsCredentials(
        access_key_id=key,
        secret_access_key=secret,
        region=region,
        session_token=_text(source, f"{prefix}_SESSION_TOKEN"),
    )


def _bearer(
    source: Mapping[str, str], token_name: str, scope_name: str
) -> BearerCredentials | None:
    token = _text(source, token_name)
    if not token:
        return None
    return BearerCredentials(token=token, scope=_text(source, scope_name))


def _mcp_endpoints(source: Mapping[str, str]) -> tuple[McpEndpoint, ...]:
    """MCP endpoints from `label=url` pairs, comma separated.

    A bare URL is accepted and labelled by its own URL. An entry with an
    empty URL is SKIPPED rather than defaulted, because a connector pointed at
    nothing would report a server that does not exist.
    """
    endpoints: list[McpEndpoint] = []
    for entry in _list(source, "SENTINEL_DISCOVERY_MCP_ENDPOINTS"):
        label, _, url = entry.partition("=")
        if not url:
            label, url = "", label
        if not url.strip():
            continue
        token = _text(
            source, f"SENTINEL_DISCOVERY_MCP_TOKEN_{label.upper()}"
        ) if label else ""
        endpoints.append(
            McpEndpoint(url=url.strip(), token=token, label=label.strip())
        )
    return tuple(endpoints)


def build_discovery_connectors(
    source: Mapping[str, str],
    *,
    http_client: HardenedHttpClient | None = None,
) -> dict[str, Any]:
    """Every connector this deployment supplied credentials for.

    Returns an EMPTY dict when nothing is configured, which is correct and
    load-bearing: the caller must be able to tell "no connectors" from "no
    findings", and `describe_discovery` is how that reaches an operator.
    """
    env = source
    client = http_client or HardenedHttpClient()

    connectors = build_connectors(
        http_client=client,
        kubernetes=_kubernetes(env),
        kubernetes_namespaces=_list(env, "SENTINEL_DISCOVERY_K8S_NAMESPACES"),
        aws=_aws(env, "SENTINEL_DISCOVERY_AWS"),
        aws_path_prefix=_text(env, "SENTINEL_DISCOVERY_AWS_PATH_PREFIX") or "/",
    )
    connectors.update(
        build_ai_connectors(
            http_client=client,
            bedrock=_aws(env, "SENTINEL_DISCOVERY_BEDROCK"),
            entra=_bearer(
                env,
                "SENTINEL_DISCOVERY_ENTRA_TOKEN",
                "SENTINEL_DISCOVERY_ENTRA_TENANT",
            ),
            vertex=_bearer(
                env,
                "SENTINEL_DISCOVERY_VERTEX_TOKEN",
                "SENTINEL_DISCOVERY_VERTEX_PROJECT",
            ),
            vertex_location=(
                _text(env, "SENTINEL_DISCOVERY_VERTEX_LOCATION") or "us-central1"
            ),
            openai=_bearer(
                env,
                "SENTINEL_DISCOVERY_OPENAI_TOKEN",
                "SENTINEL_DISCOVERY_OPENAI_ORG",
            ),
            mcp_endpoints=_mcp_endpoints(env),
        )
    )
    return connectors


def _kubernetes(source: Mapping[str, str]) -> KubernetesCredentials | None:
    server = _text(source, "SENTINEL_DISCOVERY_K8S_SERVER")
    token = _text(source, "SENTINEL_DISCOVERY_K8S_TOKEN")
    if not (server and token):
        return None
    # `KubernetesCredentials` refuses a non-https api_server and an empty
    # token itself, raising `ToolAdapterRefused`. That refusal is left to
    # propagate rather than caught and turned into None: a cleartext api_server
    # in configuration is an operator mistake worth failing startup over, and
    # swallowing it here would silently drop the connector -- reporting an
    # unscanned cluster as a clean one.
    return KubernetesCredentials(api_server=server, token=token)


def describe_discovery(connectors: Mapping[str, Any]) -> dict[str, Any]:
    """What is configured, for a readiness endpoint or a CLI.

    Names and validation status only -- never a credential, and never a URL
    that might carry one. The `unvalidated` list is not decoration: five of
    these connectors have never authenticated against a real tenant, and an
    operator reading a discovery report needs that in the report rather than
    in a document.
    """
    unvalidated = sorted(
        name
        for name, connector in connectors.items()
        if "REQUIRES EXTERNAL VALIDATION"
        in getattr(connector, "external_validation", "")
    )
    return {
        "configured": sorted(connectors),
        "configured_count": len(connectors),
        "unvalidated": unvalidated,
        "note": (
            "An absent connector means NO CREDENTIAL WAS CONFIGURED, not that "
            "the platform is clean. Connectors listed under `unvalidated` "
            "have never authenticated against a real tenant, so a zero result "
            "from one of them says nothing at all."
            if connectors
            else "No discovery connector is configured, so this deployment "
            "has observed nothing. An empty estate and an unconfigured "
            "scanner are different facts and this is the second one."
        ),
    }


def run_discovery(connectors: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Run each connector, keeping a failure as a failure.

    A connector that raises is recorded with its error rather than omitted.
    Omitting it would shorten the report by exactly the entries that went
    wrong, which is how a broken scan comes to look like a clean one.
    """
    reports: list[dict[str, Any]] = []
    for name in sorted(connectors):
        connector = connectors[name]
        try:
            inventory = connector.discover()
        except Exception as exc:  # noqa: BLE001 - reported, never swallowed
            reports.append(
                {
                    "connector": name,
                    "failed": True,
                    "error": f"{type(exc).__name__}: {exc}",
                    "note": (
                        "recorded as a failure rather than omitted: dropping "
                        "it would shorten the report by exactly the entries "
                        "that went wrong"
                    ),
                }
            )
            continue
        reports.append(
            {
                "connector": name,
                "failed": False,
                "assets": len(inventory.assets),
                "coverage": inventory.coverage.as_dict(),
            }
        )
    return reports
