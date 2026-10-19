"""Turn `Settings.platform_adapters` into built Tier-1 platform side effects.

WHY THIS IS NOT IN `container.py`
----------------------------------
The container was already near the size at which a module stops having one
reason to change, and this has its own reason to change: a new Tier-1 platform
is an edit here and nowhere else. `container.py` calls one function.

WHY IT IS NOT IN `platforms/`
------------------------------
`build_platform_adapters` takes credential objects. Turning STRINGS into those
objects is a composition concern -- it is where configuration meets code, which
is this package's whole job -- and doing it in `infrastructure` would put
`Settings` knowledge in the layer that must not have it.

THE ONE RULE THAT IS ENFORCED HERE AND NOWHERE ELSE
-----------------------------------------------------
The SQL adapter's DSN may not be Sentinel's own store. Nothing inside
`platforms/postgres.py` can check that, because it has never heard of
`Settings.engine`. Left unchecked, an operator who reuses the obvious
environment variable hands agents a read-only cursor over the incidents, the
evidence, the approvals and the audit trail that exist to describe those agents.
Read-only does not help: the value of that data is in reading it.
"""

from __future__ import annotations

from typing import Any, Mapping

from sentinel.application.tool_proxy import RegisteredSideEffect
from sentinel.composition.settings import ConfigurationError, Settings
from sentinel.infrastructure.outbound import HardenedHttpClient, OutboundPolicy
from sentinel.infrastructure.platforms.remediation import build_native_integrations
from sentinel.infrastructure.platforms import (
    AwsCredentials,
    GithubCredentials,
    KubernetesCredentials,
    PostgresCredentials,
    build_platform_adapters,
)
from sentinel.infrastructure.tool_adapters import ToolAdapterRefused

__all__ = ["build_native_remediation", "build_platform_effects"]

#: The ceiling used when a platform is configured without one. Restated from
#: `platforms.ceiling.DEFAULT_CEILING` deliberately: this is the value an
#: operator gets by omission, and it should be visible at the site where the
#: omission is handled rather than inherited from a default two layers down.
_CEILING_BY_OMISSION = "low"


def _ceiling(config: Mapping[str, str]) -> str:
    return str(config.get("ceiling") or _CEILING_BY_OMISSION)


def _kubernetes_client(config: Mapping[str, str]) -> HardenedHttpClient:
    """An outbound client that may reach exactly ONE host: the API server.

    A cluster API server is almost always on a private address behind a CA
    the public trust store does not contain. The default hardened client
    refuses both, correctly, so without this the Kubernetes tool could not
    work in any real cluster. The grant is as small as it can be: private
    destinations are allowed only together with an allowlist of that single
    host, and the only additional trust anchor is the named CA bundle.
    Verification is never disabled.
    """
    import ssl
    from urllib.parse import urlsplit

    host = urlsplit(config["api_server"]).hostname or ""
    if not host:
        raise ConfigurationError("SENTINEL_KUBERNETES_API_SERVER has no host")
    context = None
    if ca_file := config.get("ca_file", ""):
        try:
            context = ssl.create_default_context(cafile=ca_file)
        except (OSError, ssl.SSLError) as exc:
            raise ConfigurationError(f"SENTINEL_KUBERNETES_CA_FILE could not be loaded: {type(exc).__name__}") from exc
    return HardenedHttpClient(
        ssl_context=context,
        policy=OutboundPolicy(allowed_hosts=frozenset({host}), allow_private_destinations=True),
    )


def _integer(values: Mapping[str, str], field: str, default: int) -> int:
    try:
        return int(values.get(field) or default)
    except ValueError as exc:
        raise ConfigurationError(f"SENTINEL_KUBERNETES_{field.upper()} must be an integer") from exc


def build_platform_effects(
    settings: Settings, *, http_client: HardenedHttpClient | None = None
) -> dict[str, RegisteredSideEffect]:
    """Build the platform adapters this deployment configured. Absent otherwise.

    Every `ToolAdapterRefused` raised during construction is re-raised as a
    `ConfigurationError`. A credential that cannot build an adapter is a start-up
    problem, and start-up is where an operator is looking; surfacing it later as
    a tool refusal would mean discovering the region was malformed during an
    incident.
    """
    configured = settings.platform_adapters
    if not configured:
        return {}

    kwargs: dict[str, Any] = {"http_client": http_client}

    if (aws := configured.get("aws")) is not None:
        kwargs["aws"] = AwsCredentials(
            access_key_id=aws["access_key_id"],
            secret_access_key=aws["secret_access_key"],
            region=aws["region"],
            session_token=aws.get("session_token", ""),
            executor_role_arn=aws.get("executor_role_arn", ""),
        )
        kwargs["aws_ceiling"] = _ceiling(aws)

    if (github := configured.get("github")) is not None:
        kwargs["github"] = GithubCredentials(
            token=github.get("token", ""),
            api_host=github.get("api_host") or "api.github.com",
            app_id=github.get("app_id", ""),
            installation_id=github.get("installation_id", ""),
            app_private_key=github.get("app_private_key", ""),
        )
        kwargs["github_ceiling"] = _ceiling(github)

    if (kubernetes := configured.get("kubernetes")) is not None:
        kwargs["kubernetes"] = KubernetesCredentials(
            api_server=kubernetes["api_server"], token=kubernetes["token"],
            executor_service_account=kubernetes.get("executor_service_account", ""),
            executor_namespace=kubernetes.get("executor_namespace", ""),
            token_ttl_seconds=_integer(kubernetes, "token_ttl_seconds", 600),
            token_audience=kubernetes.get("token_audience", ""),
        )
        kwargs["kubernetes_ceiling"] = _ceiling(kubernetes)
        if http_client is None:
            kwargs["kubernetes_client"] = _kubernetes_client(kubernetes)

    if (postgres := configured.get("postgres")) is not None:
        dsn = postgres["dsn"]
        if _same_database(dsn, settings.engine.dsn):
            raise ConfigurationError(
                "SENTINEL_POSTGRES_DSN names Sentinel's own store. Refusing: "
                "the SQL tool adapter would give agents a cursor over the "
                "incidents, evidence and audit trail that exist to describe "
                "them. Read-only is not a mitigation -- the value of that data "
                "is in reading it. Point this at the database agents are meant "
                "to query."
            )
        try:
            timeout = int(postgres.get("statement_timeout_ms") or 5_000)
        except ValueError as exc:
            raise ConfigurationError(
                "SENTINEL_POSTGRES_STATEMENT_TIMEOUT_MS must be an integer "
                f"number of milliseconds, not {postgres.get('statement_timeout_ms')!r}"
            ) from exc
        kwargs["postgres"] = PostgresCredentials(dsn=dsn, statement_timeout_ms=timeout)
        kwargs["postgres_ceiling"] = _ceiling(postgres)

    try:
        return build_platform_adapters(**kwargs)
    except ToolAdapterRefused as exc:
        raise ConfigurationError(f"platform adapter configuration: {exc}") from exc


def _same_database(candidate: str, store: str) -> bool:
    """Compare two DSNs ignoring credentials, driver suffix and query string.

    A string comparison would be defeated by `postgresql+psycopg://` versus
    `postgresql://`, by a different username against the same database, or by a
    trailing `?sslmode=require` -- and each of those is a way to reach the same
    rows while looking like a different setting.
    """
    from urllib.parse import urlsplit

    def _identity(dsn: str) -> tuple[str, str, str]:
        parts = urlsplit(dsn.strip())
        host = (parts.hostname or "").lower()
        port = str(parts.port or 5432)
        path = (parts.path or "").strip("/").lower()
        return host, port, path

    if not candidate.strip() or not store.strip():
        return False
    left, right = _identity(candidate), _identity(store)
    # A DSN with no host is a SQLite path; those never collide with a
    # PostgreSQL tool DSN, and treating ("", "5432", "") as equal to itself
    # would refuse every configuration in a development deployment.
    if not left[0] or not right[0]:
        return False
    return left == right


def build_native_remediation(
    settings: Settings, *, http_client: HardenedHttpClient | None = None
) -> dict[str, Any]:
    """Native containment integrations, from the SAME platform credentials.

    Deliberately NOT gated on the tool adapters' ceilings. A ceiling limits what
    an AGENT may drive; these are driven by `DecideApprovalHandler` after a human
    approved a named action against a named target. An operator who sets the
    Kubernetes ceiling to `low` -- agents may read the cluster and nothing more --
    still wants containment to be able to delete a compromised pod, and reading
    the agent-facing ceiling here would silently disarm it.

    Credentials being present is the grant. `SENTINEL_KUBERNETES_*` set means the
    deployment handed this process a cluster credential; what it may do with it
    on a human's approval is the remediation catalogue's decision, not a second
    configuration knob nobody would find.
    """
    configured = settings.platform_adapters
    if not configured:
        return {}

    kubernetes = configured.get("kubernetes")
    aws = configured.get("aws")
    return build_native_integrations(
        client=http_client or HardenedHttpClient(),
        kubernetes=(
            KubernetesCredentials(
                api_server=kubernetes["api_server"], token=kubernetes["token"]
            )
            if kubernetes is not None
            else None
        ),
        aws=(
            AwsCredentials(
                access_key_id=aws["access_key_id"],
                secret_access_key=aws["secret_access_key"],
                region=aws["region"],
                session_token=aws.get("session_token", ""),
            )
            if aws is not None
            else None
        ),
    )
