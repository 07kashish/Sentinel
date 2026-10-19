"""Tier-1 platform side effects: AWS, GitHub, Kubernetes, PostgreSQL.

WHY THESE EXIST
---------------
`action_semantics.py` is five hundred lines that know `iam:AttachUserPolicy` is
privilege escalation, that `kubectl exec` is code execution, that
`DELETE /repos/o/r` destroys a repository. Until this package it was pure
classification of events that had ALREADY happened somewhere else: Sentinel
could name the consequence and could not stand in front of it.
`build_tool_adapters` registered exactly three effects -- read a file, write a
file, fetch a URL -- so the only actions the enforcement path had ever governed
were ones no enterprise buys a control plane for.

These four adapters make the classification load-bearing. Every one runs behind
the same `ProtectedToolRunner` the file adapters do: kill switch, budget,
circuit breaker, ProtectGate, capability grant.

THE ONE DESIGN RULE
-------------------
    THE CLASSIFIED LABEL AND THE TRANSMITTED REQUEST ARE BUILT FROM ONE INPUT.

Nothing here accepts a raw URL, a raw host, or a label sitting alongside a
request that could contradict it. See `aws.py` for the full statement of the
confused-deputy problem this defeats, and `ceiling.py` for what the tier ceiling
is and why it is containment rather than policy.

NO NEW DEPENDENCIES
-------------------
No boto3, no kubernetes client, no PyGithub. Each of those brings its own HTTP
stack, which would route the highest-privilege egress in the product around
`HardenedHttpClient` -- no post-resolution address validation, no connection
pinning, redirects followed by default. SigV4 is an HMAC ladder over stdlib.
PostgreSQL uses `psycopg`, which is already a dependency because Sentinel's own
store is PostgreSQL.
"""

from __future__ import annotations

from sentinel.application.tool_proxy import RegisteredSideEffect
from sentinel.infrastructure.outbound import HardenedHttpClient
from sentinel.infrastructure.platforms.aws import AwsCredentials, aws_api_adapter
from sentinel.infrastructure.platforms.ceiling import (
    DEFAULT_CEILING,
    MAX_RESULT_BYTES,
    TIERS,
)
from sentinel.infrastructure.platforms.github import (
    GithubCredentials,
    github_api_adapter,
)
from sentinel.infrastructure.platforms.kubernetes import (
    KubernetesCredentials,
    kubernetes_api_adapter,
)
from sentinel.infrastructure.platforms.postgres import (
    MAX_SQL_ROWS,
    PostgresCredentials,
    sql_query_adapter,
)

__all__ = [
    "AwsCredentials",
    "DEFAULT_CEILING",
    "GithubCredentials",
    "KubernetesCredentials",
    "MAX_RESULT_BYTES",
    "MAX_SQL_ROWS",
    "PostgresCredentials",
    "TIERS",
    "aws_api_adapter",
    "build_platform_adapters",
    "github_api_adapter",
    "kubernetes_api_adapter",
    "sql_query_adapter",
]


def build_platform_adapters(
    *,
    http_client: HardenedHttpClient | None = None,
    aws: AwsCredentials | None = None,
    aws_ceiling: str = DEFAULT_CEILING,
    github: GithubCredentials | None = None,
    github_ceiling: str = DEFAULT_CEILING,
    kubernetes: KubernetesCredentials | None = None,
    kubernetes_ceiling: str = DEFAULT_CEILING,
    kubernetes_client: HardenedHttpClient | None = None,
    postgres: PostgresCredentials | None = None,
    postgres_ceiling: str = DEFAULT_CEILING,
) -> dict[str, RegisteredSideEffect]:
    """Build exactly the platform adapters the operator supplied credentials for.

    Same rule as `build_tool_adapters`: an unconfigured adapter is ABSENT, not
    present-and-disabled, so `InlineToolProxy.execute` refuses it as an
    unregistered tool. There is no deployment in which an agent reaches AWS
    because a flag defaulted wrong, because there is no flag -- there are
    credentials, or there is no adapter.
    """
    adapters: dict[str, RegisteredSideEffect] = {}
    client = http_client or HardenedHttpClient()

    if aws is not None:
        effect = aws_api_adapter(client=client, credentials=aws, ceiling=aws_ceiling)
        adapters[effect.name] = effect
    if github is not None:
        effect = github_api_adapter(
            client=client, credentials=github, ceiling=github_ceiling
        )
        adapters[effect.name] = effect
    if kubernetes is not None:
        effect = kubernetes_api_adapter(
            # Its own client when one is given: scoped to the API server's host
            # and CA, so the grant does not leak to the AWS or GitHub adapters.
            client=kubernetes_client or client, credentials=kubernetes, ceiling=kubernetes_ceiling
        )
        adapters[effect.name] = effect
    if postgres is not None:
        effect = sql_query_adapter(credentials=postgres, ceiling=postgres_ceiling)
        adapters[effect.name] = effect

    return adapters
