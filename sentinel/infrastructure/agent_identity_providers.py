"""Agent identities issued by the customer's identity provider, consumed here.

WHY THIS EXISTS
---------------
Okta Agent SSO and Microsoft Entra Agent ID register an AI agent as a
first-class directory identity and issue it short-lived tokens. Until now the
only way an agent reached `verified` trust in Sentinel was to hold a
Sentinel-minted signing key, which meant every customer ran two agent
directories -- theirs and ours -- and the second one was always the stale one.

This module makes Sentinel a CONSUMER of agent identity rather than a second
issuer. An operator registers one entry per issuer:

    SENTINEL_AGENT_IDP_JSON='[{"name": "okta-prod", "kind": "okta",
        "issuer": "https://acme.okta.com/oauth2/aus1agents",
        "audience": "https://sentinel.acme.example",
        "tenant": "acme", "jwks": {"keys": [...]}}]'

and a token from that issuer authenticates as the agent it names. Three
properties are load-bearing:

  * **The tenant comes from the registration, never from the token.** An IdP
    knows nothing about Sentinel's tenants. Whoever registered the issuer said
    which tenant its agents belong to, and a token cannot say otherwise.
  * **The role is always the agent role.** An agent token authenticates an
    AGENT: it may ingest, ask the gate, and execute through the proxy. It can
    never read incidents, decide approvals or manage policy, no matter what
    claims it carries, because the role claim is never read.
  * **The agent id is bound to the credential.** The verified `sub` (or the
    registered claim) becomes `Principal.agent_id`, and every route that
    takes an `agentId` in its body refuses a value that differs. A credential
    issued to `agent:payments-reconciler` cannot submit events as
    `agent:infra-writer`.

WORKLOAD IDENTITY
-----------------
Two kinds identify a WORKLOAD rather than a directory entry, which is what
stops another process from presenting an agent's name:

  * `spiffe` -- a JWT-SVID. The subject must be a SPIFFE ID inside the
    registered `trust_domain` (and under `spiffe_path_prefix` when given). The
    SPIFFE ID is the agent id, so an agent's name is whatever the customer's
    SPIRE, Teleport or mesh attested, never what the caller typed.
  * `kubernetes` -- a projected service-account token. The subject must be
    `system:serviceaccount:<namespace>:<name>` with the namespace in
    `allowed_namespaces`, the `kubernetes.io` claim must agree with it, and by
    default the token must be BOUND TO A POD (name and uid). A legacy
    long-lived secret token carries no pod and is refused: it identifies
    whoever copied it, not a running workload.

Both are short-lived by construction and both are verified against keys
supplied at registration.

KEY ROTATION
------------
A registration may carry `jwks_uri` (https only) instead of, or as well as, a
pinned `jwks`. Keys are then refreshed when they are older than
`jwks_refresh_seconds`, and once, rate-limited, when a token names a key id
nobody has seen -- which is what an issuer's rotation looks like from here. A
failed or malformed fetch keeps the last good keys: an outage at the issuer
must not become an outage of every agent, and must not widen trust either.
The fetch goes through the hardened outbound client, so a `jwks_uri` cannot be
pointed at an internal address unless the operator sets `jwks_private_host`.
With only a pinned `jwks` nothing is ever fetched, exactly as before.

DISCOVERY
---------
`"discover": true` reads `<issuer>/.well-known/openid-configuration` and takes
the `jwks_uri` from it, which is how SPIRE's OIDC Discovery Provider, Okta,
Entra and most issuers publish their keys. The document must name EXACTLY the
registered issuer and an https `jwks_uri`, or it is refused: a discovery
document is the issuer's statement about itself, and one that names a
different issuer is somebody else's. Discovery is repeated on every refresh,
so an issuer that moves its keys is followed.

WHAT IS NOT CLAIMED
-------------------
The SPIRE Workload API (gRPC over a unix socket) is not spoken; SPIRE is
consumed through its OIDC Discovery Provider. A Kubernetes API server's JWKS
endpoint needs a credential and the cluster CA
and is not fetched here; pin it or front it. Token exchange (RFC 8693) is recognised only to the extent of reading
an `act.sub` claim as "on behalf of"; nothing is exchanged.
"""

from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from sentinel.infrastructure.oidc import OidcError, OidcVerifier, b64url_decode

__all__ = [
    "AGENT_ROLE",
    "AgentIdentity",
    "AgentIdentityProvider",
    "AgentIdentityProviderError",
    "AgentIdentityProviders",
    "WORKLOAD_KINDS",
    "discovered_jwks_uri",
    "hardened_jwks_fetch",
]

#: The one role an IdP-issued agent token can hold. Ingest, evaluate, execute.
AGENT_ROLE = "ingest"

_KINDS = frozenset({"okta", "entra", "generic", "spiffe", "kubernetes"})
#: Kinds whose token identifies a running workload, not a directory entry.
WORKLOAD_KINDS = frozenset({"spiffe", "kubernetes"})
_TRUST_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9._-]{0,253}[a-z0-9])?$")
_SPIFFE_PATH_RE = re.compile(r"^(/[A-Za-z0-9._-]+)+$")
_K8S_SUBJECT_RE = re.compile(
    r"^system:serviceaccount:([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?):([a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?)$"
)


class AgentIdentityProviderError(ValueError):
    """The registration is malformed. Raised at startup, never at request time."""


@dataclass(frozen=True, slots=True)
class AgentIdentity:
    """Who the IdP says is calling."""

    provider: str
    kind: str
    tenant_id: str
    agent_id: str
    subject: str
    issuer: str
    #: The human (or upstream agent) this agent acts for, when the token
    #: carries an RFC 8693 `act` claim. Empty when it does not.
    on_behalf_of: str = ""
    #: The attested workload behind the token, for `WORKLOAD_KINDS`:
    #: `pod:<namespace>/<name>#<uid>` or the SPIFFE ID. Empty otherwise.
    workload: str = ""

    @property
    def is_workload(self) -> bool:
        return self.kind in WORKLOAD_KINDS


@dataclass(frozen=True, slots=True)
class AgentIdentityProvider:
    name: str
    kind: str
    issuer: str
    audience: str
    tenant_id: str
    verifier: OidcVerifier
    agent_id_claim: str = "sub"
    trust_domain: str = ""
    spiffe_path_prefix: str = ""
    allowed_namespaces: tuple[str, ...] = ()
    require_pod_binding: bool = True
    jwks_uri: str = ""
    discover: bool = False
    jwks_refresh_seconds: int = 3600
    jwks_private_host: bool = False
    #: Mutable bookkeeping for the refresh; the registration itself is frozen.
    refresh_state: dict = field(default_factory=dict, compare=False, repr=False)


def _peek_kid(token: str) -> str:
    try:
        header = json.loads(b64url_decode(token.split(".")[0]))
    except (ValueError, IndexError, json.JSONDecodeError):
        return ""
    return str(header.get("kid") or "") if isinstance(header, dict) else ""


def _peek_issuer(token: str) -> str:
    """The unverified `iss`, used only to pick WHICH verifier to run.

    Nothing is trusted from this read: the chosen verifier checks the signature
    and then compares `iss` again against its own configured issuer, so a token
    that lies here is refused by the verifier it steered itself to.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return ""
    try:
        payload = json.loads(b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError):
        return ""
    issuer = payload.get("iss") if isinstance(payload, dict) else None
    return issuer if isinstance(issuer, str) else ""


class AgentIdentityProviders:
    """Every registered agent issuer, keyed by issuer URL."""

    __slots__ = ("_by_issuer", "_fetch", "_lock")

    def __init__(self, providers: Iterable[AgentIdentityProvider], *, fetch: Any = None) -> None:
        #: `(provider) -> JWKS mapping`. None means keys are never fetched, which
        #: is also what validation at startup uses: parsing must not touch a network.
        self._fetch = fetch
        self._lock = threading.Lock()
        by_issuer: dict[str, AgentIdentityProvider] = {}
        for provider in providers:
            if provider.issuer in by_issuer:
                raise AgentIdentityProviderError(
                    f"two agent identity providers claim issuer {provider.issuer!r} "
                    f"({by_issuer[provider.issuer].name!r} and {provider.name!r}); "
                    "an issuer must map to exactly one tenant"
                )
            by_issuer[provider.issuer] = provider
        if not by_issuer:
            raise AgentIdentityProviderError("no agent identity providers were registered")
        self._by_issuer = by_issuer

    @classmethod
    def from_json(cls, text: str, *, fetch: Any = None) -> "AgentIdentityProviders":
        try:
            entries = json.loads(text)
        except json.JSONDecodeError as exc:
            raise AgentIdentityProviderError(
                f"SENTINEL_AGENT_IDP_JSON is not valid JSON: {exc}"
            ) from exc
        if not isinstance(entries, list):
            raise AgentIdentityProviderError(
                "SENTINEL_AGENT_IDP_JSON must be a JSON list of provider objects"
            )
        providers = [cls._provider_from(entry, index) for index, entry in enumerate(entries)]
        return cls(providers, fetch=fetch)

    @staticmethod
    def _provider_from(entry: Any, index: int) -> AgentIdentityProvider:
        if not isinstance(entry, dict):
            raise AgentIdentityProviderError(f"provider #{index} is not an object")
        missing = [k for k in ("name", "issuer", "audience", "tenant") if not entry.get(k)]
        if not entry.get("jwks") and not entry.get("jwks_uri") and entry.get("discover") is not True:
            missing.append("jwks, jwks_uri or discover")
        if missing:
            raise AgentIdentityProviderError(
                f"provider #{index} is missing {', '.join(missing)}"
            )
        kind = str(entry.get("kind") or "generic").strip().lower()
        if kind not in _KINDS:
            raise AgentIdentityProviderError(
                f"provider {entry['name']!r} has kind {kind!r}; expected one of "
                + ", ".join(sorted(_KINDS))
            )
        tenant = str(entry["tenant"]).strip()
        if tenant.lower() in {"default", "unknown", "*", ""}:
            raise AgentIdentityProviderError(
                f"provider {entry['name']!r} names a forbidden tenant {tenant!r}"
            )
        jwks_uri = str(entry.get("jwks_uri") or "").strip()
        discover = entry.get("discover") is True
        if discover and not str(entry["issuer"]).startswith("https://"):
            raise AgentIdentityProviderError(f"provider {entry['name']!r}: discovery needs an https issuer")
        if jwks_uri and not jwks_uri.startswith("https://"):
            raise AgentIdentityProviderError(
                f"provider {entry['name']!r}: jwks_uri must be https; keys fetched in cleartext are whatever the network says"
            )
        try:
            refresh = int(entry.get("jwks_refresh_seconds") or 3600)
        except (TypeError, ValueError) as exc:
            raise AgentIdentityProviderError(f"provider {entry['name']!r}: jwks_refresh_seconds must be an integer") from exc
        if not 300 <= refresh <= 86_400:
            raise AgentIdentityProviderError(f"provider {entry['name']!r}: jwks_refresh_seconds must be 300 to 86400")
        # With only a jwks_uri the verifier starts from a placeholder that matches
        # no token, and the first verification fetches the real keys.
        jwks = entry.get("jwks") or {"keys": [{"kty": "EC", "kid": "unfetched-placeholder", "crv": "P-256", "x": "", "y": ""}]}
        if isinstance(jwks, str):
            try:
                jwks = json.loads(jwks)
            except json.JSONDecodeError as exc:
                raise AgentIdentityProviderError(
                    f"provider {entry['name']!r} has an unparsable jwks string"
                ) from exc
        if not isinstance(jwks, dict):
            raise AgentIdentityProviderError(
                f"provider {entry['name']!r} jwks must be a JWKS object"
            )
        agent_id_claim = str(entry.get("agent_id_claim") or "sub").strip() or "sub"
        workload = _workload_constraints(entry, kind)
        if kind in WORKLOAD_KINDS and agent_id_claim != "sub":
            raise AgentIdentityProviderError(
                f"provider {entry['name']!r}: a {kind} identity IS its subject; "
                "agent_id_claim cannot be redirected to another claim"
            )
        try:
            verifier = OidcVerifier(
                issuer=str(entry["issuer"]),
                audience=str(entry["audience"]),
                jwks=jwks,
                fixed_tenant=tenant,
                fixed_role=AGENT_ROLE,
            )
        except OidcError as exc:
            raise AgentIdentityProviderError(
                f"provider {entry['name']!r}: {exc}"
            ) from exc
        return AgentIdentityProvider(
            name=str(entry["name"]),
            kind=kind,
            issuer=str(entry["issuer"]),
            audience=str(entry["audience"]),
            tenant_id=tenant,
            verifier=verifier,
            agent_id_claim=agent_id_claim,
            jwks_uri=jwks_uri,
            discover=discover,
            jwks_refresh_seconds=refresh,
            jwks_private_host=entry.get("jwks_private_host") is True,
            **workload,
        )

    def __len__(self) -> int:
        return len(self._by_issuer)

    def tenants(self) -> frozenset[str]:
        """Every tenant a registered issuer's agents belong to."""
        return frozenset(p.tenant_id for p in self._by_issuer.values())

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(p.name for p in self._by_issuer.values()))

    def provider_for(self, token: str) -> AgentIdentityProvider | None:
        """The registration whose issuer the token NAMES. Verification is separate."""
        issuer = _peek_issuer(token)
        return self._by_issuer.get(issuer) if issuer else None

    def _refresh_if_due(self, provider: AgentIdentityProvider, token: str, now: float) -> None:
        """Fetch the issuer's keys when stale, or when the token names an unseen key."""
        if not (provider.jwks_uri or provider.discover) or self._fetch is None:
            return
        state = provider.refresh_state
        unseen = not provider.verifier.knows(_peek_kid(token))
        stale = now - state.get("fetched_at", 0.0) >= provider.jwks_refresh_seconds
        # An unseen key id may be a rotation or an attacker spraying kids; either
        # way it buys at most one fetch a minute.
        if not stale and not (unseen and now - state.get("attempted_at", 0.0) >= 60):
            return
        with self._lock:
            if now - state.get("attempted_at", 0.0) < 1:
                return  # another thread just tried
            state["attempted_at"] = now
            try:
                state["keys"] = provider.verifier.replace_keys(self._fetch(provider))
                state["fetched_at"] = now
                state["last_error"] = ""
            except Exception as exc:  # noqa: BLE001 - keep the last good keys; never widen trust
                state["last_error"] = type(exc).__name__
                state["failures"] = state.get("failures", 0) + 1

    def refresh_status(self) -> dict[str, dict]:
        """Per provider: when keys were last fetched and the last error, for diagnostics."""
        return {p.name: {k: p.refresh_state.get(k) for k in ("fetched_at", "keys", "last_error", "failures")}
                for p in self._by_issuer.values() if p.jwks_uri or p.discover}

    def verify(self, token: str, *, now: float | None = None) -> AgentIdentity:
        provider = self.provider_for(token)
        if provider is None:
            raise OidcError("no agent identity provider is registered for this issuer")
        self._refresh_if_due(provider, token, time.time() if now is None else now)
        claims = provider.verifier.verify(token, now=now)
        raw: Mapping[str, Any] = claims.raw
        agent_id = raw.get(provider.agent_id_claim)
        if not isinstance(agent_id, str) or not agent_id.strip():
            raise OidcError(
                f"agent token carries no usable {provider.agent_id_claim!r} claim"
            )
        if len(agent_id.strip()) > 128:
            raise OidcError("agent identity exceeds 128 characters; shorten the subject")
        workload = _attested_workload(provider, claims.subject, raw)
        on_behalf_of = ""
        actor = raw.get("act")
        if isinstance(actor, Mapping):
            candidate = actor.get("sub")
            if isinstance(candidate, str):
                on_behalf_of = candidate.strip()
        return AgentIdentity(
            provider=provider.name,
            kind=provider.kind,
            tenant_id=claims.tenant_id,
            agent_id=agent_id.strip(),
            subject=claims.subject,
            issuer=claims.issuer,
            on_behalf_of=on_behalf_of,
            workload=workload,
        )


def _workload_constraints(entry: Mapping[str, Any], kind: str) -> dict[str, Any]:
    """Registration-time constraints for the workload kinds. Fail at startup."""
    name = entry.get("name")
    if kind == "spiffe":
        domain = str(entry.get("trust_domain") or "").strip().lower()
        if not _TRUST_DOMAIN_RE.fullmatch(domain):
            raise AgentIdentityProviderError(
                f"provider {name!r}: kind spiffe requires a valid trust_domain"
            )
        prefix = str(entry.get("spiffe_path_prefix") or "").strip()
        if prefix and not _SPIFFE_PATH_RE.fullmatch(prefix.rstrip("/") or "/x"):
            raise AgentIdentityProviderError(
                f"provider {name!r}: spiffe_path_prefix must look like /ns/agents"
            )
        return {"trust_domain": domain, "spiffe_path_prefix": prefix.rstrip("/")}
    if kind == "kubernetes":
        namespaces = entry.get("allowed_namespaces")
        if not isinstance(namespaces, list) or not namespaces or not all(
            isinstance(n, str) and n.strip() for n in namespaces
        ):
            raise AgentIdentityProviderError(
                f"provider {name!r}: kind kubernetes requires a non-empty "
                "allowed_namespaces list; every namespace is not a default"
            )
        return {
            "allowed_namespaces": tuple(sorted({n.strip() for n in namespaces})),
            "require_pod_binding": entry.get("require_pod_binding", True) is not False,
        }
    return {}


def _attested_workload(
    provider: AgentIdentityProvider, subject: str, raw: Mapping[str, Any]
) -> str:
    """Check the workload constraints; return what was attested, or raise."""
    if provider.kind == "spiffe":
        prefix = f"spiffe://{provider.trust_domain}"
        path = subject[len(prefix):] if subject.startswith(prefix + "/") else ""
        # The SPIFFE specification forbids `.` and `..` segments; a verifier that
        # accepted them would let a prefix check be walked out of.
        if not path or not _SPIFFE_PATH_RE.fullmatch(path) or {".", ".."} & set(path.split("/")):
            raise OidcError("subject is not a SPIFFE ID in the registered trust domain")
        scope = provider.spiffe_path_prefix
        if scope and not (path == scope or path.startswith(scope + "/")):
            raise OidcError("SPIFFE ID is outside the registered path prefix")
        return subject
    if provider.kind == "kubernetes":
        match = _K8S_SUBJECT_RE.fullmatch(subject)
        if match is None:
            raise OidcError("subject is not a Kubernetes service account")
        namespace, account = match.group(1), match.group(3)
        if namespace not in provider.allowed_namespaces:
            raise OidcError("service account namespace is not registered for agents")
        claim = raw.get("kubernetes.io")
        if not isinstance(claim, Mapping):
            raise OidcError("token carries no kubernetes.io claim; not a projected token")
        bound_account = claim.get("serviceaccount")
        if claim.get("namespace") != namespace or not isinstance(bound_account, Mapping) \
                or bound_account.get("name") != account:
            raise OidcError("kubernetes.io claim disagrees with the token subject")
        pod = claim.get("pod")
        if isinstance(pod, Mapping) and pod.get("name") and pod.get("uid"):
            return f"pod:{namespace}/{pod['name']}#{pod['uid']}"
        if provider.require_pod_binding:
            raise OidcError(
                "service-account token is not bound to a pod; a copied long-lived "
                "token identifies whoever holds it, not a running workload"
            )
        return f"serviceaccount:{namespace}/{account}"
    return ""


def _hardened_get(url: str, *, private: bool) -> Any:
    from urllib.parse import urlsplit

    from sentinel.infrastructure.outbound import HardenedHttpClient, OutboundPolicy

    client = HardenedHttpClient(policy=OutboundPolicy(
        allowed_hosts=frozenset({urlsplit(url).hostname or ""}), allow_private_destinations=private,
        max_response_bytes=262_144,
    ))
    response = client.request(method="GET", url=url, headers={"accept": "application/json"}, body=None, idempotent=True)
    document = response.json() if response.status == 200 else None
    if not isinstance(document, Mapping):
        raise OidcError(f"{urlsplit(url).path} answered HTTP {response.status} without a JSON object")
    return document


def discovered_jwks_uri(provider: AgentIdentityProvider, document: Mapping[str, Any]) -> str:
    """The `jwks_uri` a discovery document names, if the document is this issuer's."""
    if document.get("issuer") != provider.issuer:
        raise OidcError("the discovery document names a different issuer than the registration")
    uri = document.get("jwks_uri")
    if not isinstance(uri, str) or not uri.startswith("https://"):
        raise OidcError("the discovery document carries no https jwks_uri")
    return uri


def hardened_jwks_fetch(provider: AgentIdentityProvider) -> Mapping[str, Any]:
    """GET one provider's JWKS through the hardened outbound client.

    One host per request, https, a bounded body, and private addresses only
    when the registration says the issuer is internal. Anything but a 200 with
    a JSON object raises, and the caller keeps its last good keys.
    """
    uri = provider.jwks_uri
    if not uri:
        configuration = _hardened_get(provider.issuer.rstrip("/") + "/.well-known/openid-configuration",
                                      private=provider.jwks_private_host)
        uri = discovered_jwks_uri(provider, configuration)
    return _hardened_get(uri, private=provider.jwks_private_host)
