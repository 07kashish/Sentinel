"""Endpoint-map parsers for `Settings`, moved out verbatim when the module hit
the size fitness cap.

These read only the `source` mapping they are handed — never `os.environ`,
which `test_only_the_settings_module_reads_the_environment` reserves for
`settings.py` itself. That is what makes this split safe: the one-parser-one-
place rule is about who reads the ENVIRONMENT, not about how many files hold
pure functions over an already-captured mapping.

`ConfigurationError` is imported from `settings` at call time inside each
function rather than at module top, because `settings` imports this module —
the import cycle is broken by deferring, exactly as `_remediation_endpoints`
already deferred its domain import for its own reasons.
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dc_field

from pathlib import Path
from types import MappingProxyType
from typing import Mapping

__all__ = [
    "discovery_credentials",
    "metrics_token_from",
    "platform_adapters",
    "siem_transports",
    "remediation_endpoints",
    "soar_endpoints",
]

#: Prefix for every discovery-connector credential. One prefix rather than an
#: enumerated list because the connectors each own their own variable names,
#: and a list here would be a second place to update when one is added -- which
#: is how a connector comes to be silently unconfigurable.
DISCOVERY_PREFIX = "SENTINEL_DISCOVERY_"


def discovery_credentials(source: Mapping[str, str]) -> Mapping[str, str]:
    """Every `SENTINEL_DISCOVERY_*` variable, as an immutable mapping.

    WHY THIS LIVES HERE AND NOT IN THE WIRING
    ------------------------------------------
    `discovery_wiring.py` read `os.environ` directly, and
    `test_only_the_settings_module_reads_the_environment` was right to refuse
    it. One module reads the environment; everything else receives values. That
    rule is the reason `Settings` exists, and the argument I had made for
    breaking it -- ten optional integration fields would bloat a frozen
    dataclass at its size limit -- is answered by carrying ONE field instead.

    The precedent is `tenant_siem_credentials`, which already resolves and
    holds secrets on `Settings` for the same reason.

    Values are NOT validated or coerced here. Which combination of variables
    constitutes a usable credential is the connector's own rule -- AWS needs a
    triple, a bearer needs one token -- and duplicating that judgement here
    would create two places to disagree about whether a connector is
    configured.
    """
    return MappingProxyType(
        {
            name: value
            for name, value in source.items()
            if name.startswith(DISCOVERY_PREFIX) and str(value).strip()
        }
    )

#: Which settings each Tier-1 platform adapter needs, and which of them are
#: REQUIRED for that adapter to be built at all. A platform with none of its
#: settings present is absent; a platform with some but not all of its required
#: settings is a `ConfigurationError`, never a partially-configured adapter.
#:
#: `secret` names the settings that also accept a `_FILE` variant, so a
#: Kubernetes secret mount works without putting the credential in the process
#: environment where every child process inherits it.
_PLATFORM_SETTINGS: Mapping[str, Mapping[str, tuple[str, ...]]] = MappingProxyType({
    "aws": MappingProxyType({
        "required": ("access_key_id", "secret_access_key", "region"),
        # With `executor_role_arn` set, the access key is a BROKER that may only
        # assume that role (and look up CloudTrail); each operation runs under
        # its own fifteen-minute session named after the operation.
        "optional": ("session_token", "ceiling", "executor_role_arn"),
        "secret": ("secret_access_key", "session_token"),
    }),
    "github": MappingProxyType({
        # Either `token`, or GitHub App mode: `app_id`, `installation_id` and
        # `app_private_key` together, in which case there is no standing token
        # and each operation mints one scoped to its repository and permission.
        "required": (),
        "optional": ("token", "api_host", "ceiling", "app_id", "installation_id", "app_private_key"),
        "secret": ("token", "app_private_key"),
    }),
    "kubernetes": MappingProxyType({
        "required": ("api_server", "token"),
        # With `executor_service_account` set, `token` is a BROKER credential
        # that may only mint short-lived tokens for that account (TokenRequest);
        # every mutation then runs under a per-operation token, not this one.
        # `ca_file`: the cluster CA bundle. An API server presents a certificate
        # the public trust store has never heard of, and the honest fix is to
        # trust THAT CA for THAT host, not to stop verifying.
        "optional": ("ceiling", "executor_service_account", "executor_namespace",
                     "token_ttl_seconds", "token_audience", "ca_file"),
        "secret": ("token",),
    }),
    "postgres": MappingProxyType({
        "required": ("dsn",),
        "optional": ("ceiling", "statement_timeout_ms"),
        "secret": ("dsn",),
    }),
})


def metrics_token_from(source: Mapping[str, str]) -> str:
    """Load metrics scraper token from env or a file path (k8s secret mount)."""
    from sentinel.composition.settings import ConfigurationError

    direct = source.get("SENTINEL_METRICS_TOKEN", "").strip()
    if direct:
        return direct
    path = source.get("SENTINEL_METRICS_TOKEN_FILE", "").strip()
    if not path:
        return ""
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ConfigurationError(
            f"SENTINEL_METRICS_TOKEN_FILE {path!r} could not be read: {exc}"
        ) from exc


def soar_endpoints(source: Mapping[str, str]) -> Mapping[str, str]:
    """Parse `connector=url,connector=url`.

    Connector names are validated here for the same reason remediation
    actions are: a typo would otherwise configure a connector nothing
    constructs, and the deployment would believe its SOC was wired up.
    """
    from sentinel.composition.settings import ConfigurationError

    raw = (source.get("SENTINEL_SOAR_ENDPOINTS") or "").strip()
    if not raw:
        return MappingProxyType({})
    known = {"servicenow", "jira", "pagerduty", "slack", "teams", "webhook"}
    parsed: dict[str, str] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        name, _, url = entry.partition("=")
        name, url = name.strip().lower(), url.strip()
        if name not in known:
            raise ConfigurationError(
                f"SENTINEL_SOAR_ENDPOINTS names unknown connector {name!r}; "
                f"known connectors are {', '.join(sorted(known))}"
            )
        if not url.lower().startswith("https://"):
            raise ConfigurationError(
                f"SOAR endpoint for {name!r} must be https; incident details "
                f"are sensitive and a plaintext webhook leaks them"
            )
        parsed[name] = url
    return MappingProxyType(parsed)


def remediation_endpoints(source: Mapping[str, str]) -> Mapping[str, str]:
    """Parse `action=url,action=url` into a mapping.

    Every action is checked against the catalogue at parse time rather than
    at execution time. A typo in an environment variable would otherwise
    register an integration under a name no proposal can ever produce, and
    the deployment would look configured while being unable to remediate
    anything -- discovered during an incident.

    Non-HTTPS endpoints are refused. A remediation endpoint is a URL that can
    disable production agents; sending the request in the clear lets anyone
    on the path forge one.
    """
    from sentinel.composition.settings import ConfigurationError
    from sentinel.domain.remediation import UnknownRemediationAction, action_named

    raw = (source.get("SENTINEL_REMEDIATION_ENDPOINTS") or "").strip()
    if not raw:
        return MappingProxyType({})

    parsed: dict[str, str] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        action, _, url = entry.partition("=")
        action, url = action.strip(), url.strip()
        if not action or not url:
            raise ConfigurationError(
                f"SENTINEL_REMEDIATION_ENDPOINTS entry {entry!r} must be "
                f"'action=https://...'"
            )
        try:
            action_named(action)
        except UnknownRemediationAction as exc:
            raise ConfigurationError(
                f"SENTINEL_REMEDIATION_ENDPOINTS names {action!r}, which is "
                f"not a known remediation action"
            ) from exc
        if not url.lower().startswith("https://"):
            raise ConfigurationError(
                f"remediation endpoint for {action!r} must be https; "
                f"a plaintext endpoint that disables production agents can "
                f"be forged by anyone on the path"
            )
        parsed[action] = url
    return MappingProxyType(parsed)


def _read_setting(
    source: Mapping[str, str], *, env_name: str, allow_file: bool
) -> str:
    """Read one setting, preferring the direct value over a `_FILE` mount.

    Same shape as `metrics_token_from`, generalised. The direct variable wins
    when both are set rather than the file, because the file is the deployment
    default and an operator who sets the variable explicitly is overriding on
    purpose.
    """
    from sentinel.composition.settings import ConfigurationError

    direct = (source.get(env_name) or "").strip()
    if direct or not allow_file:
        return direct
    path = (source.get(f"{env_name}_FILE") or "").strip()
    if not path:
        return ""
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ConfigurationError(
            f"{env_name}_FILE {path!r} could not be read: {exc}"
        ) from exc


def platform_adapters(
    source: Mapping[str, str],
) -> Mapping[str, Mapping[str, str]]:
    """Collect Tier-1 platform adapter credentials, keyed by platform.

    Returns PLAIN DATA, not credential objects. `Settings` stays free of
    infrastructure types -- the same reason `remediation_endpoints` returns
    `action -> url` and lets the container build the executor -- and the
    credential classes keep their own validation in the layer that uses them.

    ABSENT, NOT DISABLED. A platform whose settings are entirely unset is not in
    the returned mapping, so `build_platform_adapters` never constructs it and
    `InlineToolProxy.execute` refuses the tool as unregistered. There is no
    enable flag, because a flag is one boolean away from granting an agent AWS.

    PARTIAL IS AN ERROR. A deployment that sets `SENTINEL_AWS_ACCESS_KEY_ID` and
    forgets the region has said what it wanted; silently building nothing would
    leave an operator believing the adapter is live until the first refusal
    during an incident, which is precisely when nobody is reading logs.
    """
    from sentinel.composition.settings import ConfigurationError

    collected: dict[str, Mapping[str, str]] = {}
    for platform, spec in _PLATFORM_SETTINGS.items():
        prefix = f"SENTINEL_{platform.upper()}_"
        secrets = set(spec["secret"])
        values: dict[str, str] = {}
        for field in (*spec["required"], *spec["optional"]):
            value = _read_setting(
                source,
                env_name=f"{prefix}{field.upper()}",
                allow_file=field in secrets,
            )
            if value:
                values[field] = value

        if not values:
            continue
        missing = [f for f in spec["required"] if f not in values]
        if missing:
            raise ConfigurationError(
                f"{platform} platform adapter is partially configured: "
                + ", ".join(f"{prefix}{f.upper()}" for f in missing)
                + " is required. Set it, or unset the others -- a partially "
                "configured adapter is not built, and an operator who believes "
                "it is finds out during an incident."
            )
        collected[platform] = MappingProxyType(dict(values))

    return MappingProxyType(collected)


#: SIEM transports this build can actually perform, and the settings each needs.
#: A transport named here is implemented; one that is not is refused by name at
#: configuration time rather than accepted and silently not performed.
_SIEM_TRANSPORTS: Mapping[str, Mapping[str, tuple[str, ...]]] = MappingProxyType({
    "otlp": MappingProxyType({
        "required": ("url",),
        "optional": ("token", "service_name"),
        "secret": ("token",),
    }),
    "syslog": MappingProxyType({
        "required": ("host",),
        "optional": ("port", "app_name"),
        "secret": (),
    }),
})

#: Transports an operator may plausibly configure that this build cannot do.
#: Listed so the refusal can name the reason instead of reading as a typo.
_SIEM_UNSUPPORTED: Mapping[str, str] = MappingProxyType({
    "kafka": (
        "a Kafka producer is a broker-protocol client with its own pooling, "
        "partitioner and retry semantics, and there is no honest way to add one "
        "without a dependency. A transport that quietly posted to a REST proxy "
        "would not be Kafka. Use SENTINEL_SIEM_OTLP_URL or "
        "SENTINEL_SIEM_SYSLOG_HOST, or ship to Kafka from your collector."
    ),
})


def siem_transports(source: Mapping[str, str]) -> Mapping[str, Mapping[str, str]]:
    """Collect the additional SIEM transports, keyed by transport name.

    The webhook stays on its own settings (`SENTINEL_SIEM_WEBHOOK_URL`) because
    it predates this and moving it would break every existing deployment for no
    gain. These are ADDITIONAL sinks; configuring one alongside the webhook
    fans out to both.

    An unsupported transport is refused BY NAME. `SENTINEL_SIEM_KAFKA_BROKERS`
    set on a build that cannot speak Kafka must not start quietly, or a year of
    events goes somewhere the operator never checks.
    """
    from sentinel.composition.settings import ConfigurationError

    for name, reason in _SIEM_UNSUPPORTED.items():
        prefix = f"SENTINEL_SIEM_{name.upper()}_"
        if any(key.startswith(prefix) and (source.get(key) or "").strip() for key in source):
            raise ConfigurationError(
                f"SIEM transport {name!r} is NOT_SUPPORTED by this build: {reason}"
            )

    collected: dict[str, Mapping[str, str]] = {}
    for transport, spec in _SIEM_TRANSPORTS.items():
        prefix = f"SENTINEL_SIEM_{transport.upper()}_"
        secrets = set(spec["secret"])
        values: dict[str, str] = {}
        for field in (*spec["required"], *spec["optional"]):
            value = _read_setting(
                source,
                env_name=f"{prefix}{field.upper()}",
                allow_file=field in secrets,
            )
            if value:
                values[field] = value

        if not values:
            continue
        missing = [f for f in spec["required"] if f not in values]
        if missing:
            raise ConfigurationError(
                f"SIEM transport {transport!r} is partially configured: "
                + ", ".join(f"{prefix}{f.upper()}" for f in missing)
                + " is required. A half-configured export sink is not built, and "
                "an operator who believes it is finds out during an audit."
            )
        collected[transport] = MappingProxyType(dict(values))

    return MappingProxyType(collected)


def tenant_siem_sinks(source: Mapping[str, str]) -> tuple[tuple[str, str, str], ...]:
    """`SENTINEL_TENANT_SIEM_SINKS` -> (tenant, endpoint, credential_ref) rows.

    Format, semicolon-separated:

        acme=https://acme.example/ingest|secrets/acme-siem;globex=https://...

    WHY CONFIGURATION AND NOT A TABLE
    ---------------------------------
    A database-backed store with an API is the right long-term home -- an
    operator should be able to onboard a tenant without a restart. This closes
    the cross-tenant defect NOW without another migration, and the registry it
    feeds takes its rows from anywhere, so moving to a table later changes the
    source and not the rule.

    A row with no endpoint is REFUSED rather than skipped. A silently dropped
    row means a tenant an operator believed was configured is not, and the
    symptom is events that quietly go nowhere.
    """
    # Deferred, per the module docstring: `settings` imports this module, so a
    # top-level import would be a cycle.
    from sentinel.composition.settings import ConfigurationError

    raw = source.get("SENTINEL_TENANT_SIEM_SINKS", "").strip()
    if not raw:
        return ()

    rows: list[tuple[str, str, str]] = []
    for entry in (e.strip() for e in raw.split(";") if e.strip()):
        tenant, separator, remainder = entry.partition("=")
        if not separator or not tenant.strip():
            raise ConfigurationError(
                f"SENTINEL_TENANT_SIEM_SINKS entry {entry!r} is not "
                "'tenant=endpoint' or 'tenant=endpoint|credential_ref'"
            )
        endpoint, _, credential = remainder.partition("|")
        if not endpoint.strip():
            raise ConfigurationError(
                f"SENTINEL_TENANT_SIEM_SINKS entry for {tenant.strip()!r} has "
                "no endpoint. Refused rather than skipped: a dropped row means "
                "a tenant somebody believed was configured is not, and the "
                "symptom is events that quietly go nowhere."
            )
        rows.append((tenant.strip(), endpoint.strip(), credential.strip()))
    return tuple(rows)


#: How a `credential_ref` becomes an environment variable name.
#:
#: `secrets/acme-siem` -> `SENTINEL_TENANT_SIEM_SECRET_SECRETS_ACME_SIEM`.
#: `credential_ref` permits `.`, `/` and `-`, none of which are legal in an
#: environment variable name, so the mapping has to exist somewhere. Written
#: down here rather than left for an operator to guess, and applied by the same
#: function on both sides so the two cannot drift.
_REF_TO_ENV_PREFIX = "SENTINEL_TENANT_SIEM_SECRET_"


def credential_env_name(credential_ref: str) -> str:
    """The variable a `credential_ref` resolves to."""
    safe = "".join(
        ch if ch.isalnum() else "_" for ch in credential_ref.strip()
    ).upper()
    return f"{_REF_TO_ENV_PREFIX}{safe}"


def tenant_siem_credentials(source: Mapping[str, str]) -> Mapping[str, str]:
    """Resolve every `credential_ref` named in the sinks to its secret.

    WHY THIS IS NOT OPTIONAL RESOLUTION
    ------------------------------------
    Before this existed, `credential_ref` was parsed, carried through the
    registry, handed to the deliverer factory -- and dropped. Every per-tenant
    sink was unauthenticated, and an operator who had written
    `acme=https://...|secrets/acme-siem` had every reason to believe otherwise.
    A configuration field that is accepted and ignored is worse than one that is
    rejected: it produces confident, wrong belief about where security events
    are going and who can read them.

    So a ref that names no secret is a REFUSAL, raised by the caller, not a
    silent fallback to an empty token. A tenant that genuinely wants an
    unauthenticated sink writes no ref at all, which is a decision somebody made
    rather than a gap nobody noticed.

    The values are the raw tokens. They are not logged, not included in any
    diagnostic response, and live in the same place `siem_webhook_token`
    already does -- this adds no new class of exposure, and the alternative of
    a bespoke holder here would be a second secret-handling convention in one
    process.
    """
    resolved: dict[str, str] = {}
    for _tenant, _endpoint, credential in tenant_siem_sinks(source):
        if not credential:
            continue
        value = (source.get(credential_env_name(credential), "") or "").strip()
        if value:
            resolved[credential] = value
    return MappingProxyType(resolved)


# ── scalar coercion ─────────────────────────────────────────────────────────
#
# Moved here for the same reason the endpoint parsers above were: `settings.py`
# reached the 800-line fitness cap. Deleting comments to get under a line limit
# leaves the same module with less explanation, which is the opposite of what
# the rule is for.
#
# These are the right things to move because none of them is production-gated.
# `settings.py` carries a structural ratchet -- a test counts its
# `production`-gated branches and requires one declared preflight requirement
# per branch -- so relocating a production check would silently change that
# count and weaken the ratchet.
#
# The recurring failure in configuration parsing is a value silently read as
# something else: `raw.lower() in ("1", "true")` reads "yes", "on" and "True "
# as FALSE. For a flag governing whether an unauthenticated surface is
# published, quietly choosing a value is unacceptable in either direction. So
# an unrecognised value is an error, an absent value takes the caller's stated
# default, and nothing is guessed.

_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off"})


def positive_int(
    source: Mapping[str, str], name: str, default: int, *, allow_zero: bool = False
) -> int:
    from sentinel.composition.settings import ConfigurationError

    raw = source.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer, got {raw!r}") from exc
    floor = 0 if allow_zero else 1
    if value < floor:
        raise ConfigurationError(f"{name} must be >= {floor}, got {value}")
    return value


def optional_positive_int(source: Mapping[str, str], name: str) -> int | None:
    """A setting whose absence is a POLICY, not a missing value.

    Distinct from `positive_int` with a default, because there is no defensible
    default: unset means "never delete", and that must be representable as
    itself rather than as a very large number that reads like a chosen
    retention period. `0` is refused rather than treated as "unset" -- an
    operator who typed a zero meant something, and guessing which thing is
    exactly the failure this setting exists to avoid.
    """
    from sentinel.composition.settings import ConfigurationError

    raw = source.get(name, "").strip()
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(
            f"{name} must be an integer number of days, or be unset to mean "
            f"'never delete'; got {raw!r}"
        ) from exc
    if value < 1:
        raise ConfigurationError(
            f"{name} must be >= 1 day, got {value}. Leave it UNSET to disable "
            "deletion; 0 is not a way to spell 'keep forever' and is refused "
            "so it cannot be read as one."
        )
    return value


def host_set(source: Mapping[str, str], name: str) -> frozenset[str]:
    """One parser for every comma-separated host allowlist.

    Two copies had already appeared, and parsers that disagree about whitespace
    make an allowlist entry that silently never matches.
    """
    return frozenset(h.strip() for h in source.get(name, "").split(",") if h.strip())


def flag(source: Mapping[str, str], name: str, *, default: bool) -> bool:
    """Parse a boolean STRICTLY. An unrecognised value is a configuration error.

    The usual `raw.lower() in ("1", "true")` idiom silently reads "yes", "on"
    and "True " as false. For a flag that governs whether an unauthenticated
    surface is published, silently choosing a value is not acceptable in either
    direction.
    """
    from sentinel.composition.settings import ConfigurationError

    raw = source.get(name, "").strip().lower()
    if not raw:
        return default
    if raw in _TRUE:
        return True
    if raw in _FALSE:
        return False
    raise ConfigurationError(
        f"{name} must be a boolean (true/false, 1/0, yes/no, on/off); "
        f"got {raw!r}. Refusing to guess."
    )


def float_value(source: Mapping[str, str], name: str, default: float) -> float:
    from sentinel.composition.settings import ConfigurationError

    raw = source.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a number, got {raw!r}") from exc
    if value <= 0:
        raise ConfigurationError(f"{name} must be positive, got {value}")
    return value


def first_of(source: Mapping[str, str], *names: str) -> str:
    """The first non-empty value among `names`, stripped; "" when none is set.

    Lets the SENTINEL_-prefixed name win over a standard one (AWS_REGION and
    friends) without forcing an operator to duplicate a secret into a second
    variable -- duplicated secrets rot, and the failure looks like permissions.
    """
    for name in names:
        value = source.get(name, "").strip()
        if value:
            return value
    return ""


@dataclass(frozen=True, slots=True)
class RootSinkSettings:
    """Where transparency roots go, and when. All empty = no sink, never publish."""

    bucket: str = ""
    region: str = ""
    access_key_id: str = ""
    secret_access_key: str = dc_field(default="", repr=False)
    session_token: str = dc_field(default="", repr=False)
    #: The ECS/Fargate container credential endpoint, when the deployment runs
    #: under a task role instead of a static key. Built from the agent's
    #: `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` (or `_FULL_URI`); the sink
    #: fetches a short-lived credential from it per request.
    container_credentials_uri: str = ""
    container_authorization: str = dc_field(default="", repr=False)
    retention_days: int = 3650
    #: Tenants to publish for; `("*",)` means every tenant. EMPTY means never:
    #: publication under COMPLIANCE retention is irreversible, so it is a
    #: decision an operator makes by name rather than a default.
    publish_tenants: tuple[str, ...] = ()
    publish_interval_seconds: int = 86400

    @property
    def configured(self) -> bool:
        return bool(self.bucket)


def root_sink_settings(source: Mapping[str, str]) -> RootSinkSettings:
    """Parse the S3 Object Lock root sink and its publication schedule.

    The standard AWS names work as well as the SENTINEL_ ones, and the
    SENTINEL_ name wins, so the sink can live in a different account from the
    rest of a deployment's AWS usage without unsetting anything. Raises
    `ValueError` on an inconsistent configuration; the caller turns that into
    a refusal to start.
    """
    settings = RootSinkSettings(
        bucket=first_of(source, "SENTINEL_S3_ROOT_BUCKET", "AWS_S3_ROOT_BUCKET"),
        region=first_of(source, "SENTINEL_S3_ROOT_REGION", "AWS_REGION", "AWS_DEFAULT_REGION"),
        access_key_id=first_of(source, "SENTINEL_S3_ROOT_ACCESS_KEY_ID", "AWS_ACCESS_KEY_ID"),
        secret_access_key=first_of(
            source, "SENTINEL_S3_ROOT_SECRET_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY"
        ),
        session_token=first_of(source, "SENTINEL_S3_ROOT_SESSION_TOKEN", "AWS_SESSION_TOKEN"),
        container_credentials_uri=_container_credentials_uri(source),
        container_authorization=source.get("AWS_CONTAINER_AUTHORIZATION_TOKEN", "").strip(),
        retention_days=positive_int(source, "SENTINEL_S3_ROOT_RETENTION_DAYS", 3650),
        publish_tenants=tuple(
            t.strip()
            for t in source.get("SENTINEL_ROOT_PUBLISH_TENANTS", "").split(",")
            if t.strip()
        ),
        publish_interval_seconds=positive_int(
            source, "SENTINEL_ROOT_PUBLISH_INTERVAL_SECONDS", 86400
        ),
    )
    if settings.publish_tenants and not settings.bucket:
        raise ValueError(
            "SENTINEL_ROOT_PUBLISH_TENANTS names tenants to publish roots for, but no "
            "root sink is configured (SENTINEL_S3_ROOT_BUCKET). A publication job "
            "that can only refuse is a misconfiguration."
        )
    if settings.bucket and not settings.region:
        raise ValueError(
            "SENTINEL_S3_ROOT_BUCKET is set without a region "
            "(SENTINEL_S3_ROOT_REGION or AWS_REGION)."
        )
    return settings


def _container_credentials_uri(source: Mapping[str, str]) -> str:
    """The ECS agent's credential endpoint, or empty. FULL_URI wins over RELATIVE_URI."""
    full = source.get("AWS_CONTAINER_CREDENTIALS_FULL_URI", "").strip()
    if full:
        return full
    relative = source.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "").strip()
    return f"http://169.254.170.2{relative}" if relative.startswith("/") else ""


def agent_idp_json(source: Mapping[str, str]) -> str:
    """`SENTINEL_AGENT_IDP_JSON`, validated by parsing it once.

    Parsed at startup so a malformed registration is a refusal to start rather
    than a 401 for every agent at 03:00. Returns the raw text; the container
    parses it again into live verifiers. Raises `ValueError` when malformed.
    """
    text = source.get("SENTINEL_AGENT_IDP_JSON", "").strip()
    if not text:
        return ""
    from sentinel.infrastructure.agent_identity_providers import (
        AgentIdentityProviderError,
        AgentIdentityProviders,
    )

    try:
        AgentIdentityProviders.from_json(text)
    except AgentIdentityProviderError as exc:
        raise ValueError(f"SENTINEL_AGENT_IDP_JSON: {exc}") from exc
    return text


@dataclass(frozen=True, slots=True)
class WorkflowSettings:
    """Controls of the protected-change workflow. Every default is the strict
    reading except workload identity, whose default is a recorded exception
    (DECISION_LOG FCX-006) because it needs a customer identity integration."""

    #: Refuse the agent path (events, evaluate, execute) to any caller whose
    #: credential is not an IdP- or workload-issued agent identity. With this
    #: on, an API key can no longer speak for an agent by typing its name.
    require_workload_identity: bool = False
    #: Distinct approvers required before a pending authorization activates.
    approval_quorum: int = 1
    #: The requester of an authorization may not also approve it.
    approval_separation_of_duties: bool = True
    #: Automatic target lookups per unknown operation before a human is needed.
    reconcile_max_attempts: int = 5
    #: Relay an MCP server's progress and log notifications to the client AS
    #: THEY ARRIVE, each inspected before release, instead of discarding them
    #: and returning only the final response. Off unless stated.
    mcp_proxy_streaming: bool = False
    #: Data keys for sealing evidence bodies: key id -> base64 32-byte key, and
    #: which id seals new records. Empty means bodies are stored as plaintext
    #: JSON, which production accepts only when stated explicitly.
    evidence_keys: Mapping[str, str] = dc_field(default_factory=dict, repr=False)
    evidence_active_key: str = ""
    #: A VIEWER API key the console may publish on its sign-in page, so a
    #: link can be shared with people who hold no credential. Empty (default)
    #: publishes nothing. The app refuses to start if it names any other role.
    console_demo_token: str = dc_field(default="", repr=False)


def workflow_settings(source: Mapping[str, str]) -> WorkflowSettings:
    quorum = positive_int(source, "SENTINEL_APPROVAL_QUORUM", default=1)
    if quorum > 5:
        from sentinel.composition.settings import ConfigurationError

        raise ConfigurationError("SENTINEL_APPROVAL_QUORUM above 5 is a process nobody completes")
    prefix = "SENTINEL_DATA_KEY_"
    keys = {name[len(prefix):].lower(): value.strip() for name, value in source.items()
            if name.startswith(prefix) and value.strip()}
    active = source.get("SENTINEL_ACTIVE_KEY_ID", "").strip().lower()
    stated = source.get("SENTINEL_EVIDENCE_ENCRYPTION", "").strip().lower()
    from sentinel.composition.settings import ConfigurationError

    if stated not in {"", "required", "off"}:
        raise ConfigurationError("SENTINEL_EVIDENCE_ENCRYPTION must be 'required' or 'off'")
    if keys and active not in keys:
        raise ConfigurationError(
            "SENTINEL_ACTIVE_KEY_ID must name one of the configured SENTINEL_DATA_KEY_<id> keys; "
            "which key seals new evidence is stated, never guessed"
        )
    if stated == "off" and keys:
        raise ConfigurationError("SENTINEL_EVIDENCE_ENCRYPTION=off contradicts the configured data keys")
    production = source.get("SENTINEL_ENV", "").strip().lower() == "production"
    if not keys and (stated == "required" or (production and stated != "off")):
        raise ConfigurationError(
            "evidence bodies would be stored as readable JSON. Set SENTINEL_DATA_KEY_<id> (base64, 32 bytes) "
            "and SENTINEL_ACTIVE_KEY_ID, or state SENTINEL_EVIDENCE_ENCRYPTION=off to accept storage-level "
            "encryption only. Production refuses to choose this for you."
        )
    return WorkflowSettings(
        evidence_keys=MappingProxyType(keys), evidence_active_key=active,
        require_workload_identity=flag(source, "SENTINEL_REQUIRE_WORKLOAD_IDENTITY", default=False),
        approval_quorum=quorum,
        approval_separation_of_duties=flag(source, "SENTINEL_APPROVAL_SEPARATION_OF_DUTIES", default=True),
        reconcile_max_attempts=positive_int(source, "SENTINEL_RECONCILE_MAX_ATTEMPTS", default=5),
        mcp_proxy_streaming=flag(source, "SENTINEL_MCP_PROXY_STREAMING", default=False),
        console_demo_token=source.get("SENTINEL_CONSOLE_DEMO_TOKEN", "").strip(),
    )
