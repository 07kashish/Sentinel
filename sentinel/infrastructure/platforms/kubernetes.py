"""Kubernetes: one API call, under a tier ceiling.

THE SINGLE-SOURCE RULE
----------------------
`verb`, `kind`, `namespace` and `name` are the only inputs. The API path is
BUILT from them here and the classification is COMPUTED from the same fields, so
`kubectl delete` in `kube-system` cannot be described to policy as a read. There
is no path argument, so there is nothing to describe it with.

WHAT IS ABSENT, AND WHY THAT IS STRONGER THAN BLOCKED
------------------------------------------------------
`exec`, `attach` and `port-forward` have no entry in the verb table, so no code
path builds one. They are SPDY/WebSocket upgrades that `HardenedHttpClient`
refuses anyway, and `action_semantics` rates them critical for the reason that
they are a shell inside a running workload. An operator who raises the ceiling
to `critical` still cannot reach them: the ceiling governs what is classified,
and absence is not a tier.

CONSTRAINED CREDENTIALS
-----------------------
With `executor_service_account` set, the configured token is a BROKER: its only
use is the TokenRequest API for that one service account. Every operation
mints its own token, short-lived and optionally audience-bound, uses it once
and discards it. What the executor may touch is that account's RBAC, so the
blast radius of a stolen in-flight token is one namespace role for minutes,
and the broker credential itself can change nothing in the cluster.

The resource table is explicit rather than discovered from the cluster's own
`/apis`. What an agent may reach in a production cluster is exactly the sort of
decision that should be readable in a diff, not dependent on which CRDs happen
to be installed this week.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from sentinel.application.tool_proxy import RegisteredSideEffect
from sentinel.infrastructure.outbound import HardenedHttpClient
from sentinel.infrastructure.platforms.ceiling import (
    DEFAULT_CEILING,
    bounded,
    classify_or_refuse,
    enforce_ceiling,
    hardened_call,
    normalise_ceiling,
)
from sentinel.application.operation_context import current_operation_id
from sentinel.infrastructure.platforms.kubernetes_outcome import (
    DELETE_MARK,
    field_manager,
    kubernetes_hint,
    kubernetes_reconciler,
)
from sentinel.infrastructure.tool_adapters import (
    ToolAdapterNotAttempted,
    ToolAdapterRefused,
    ToolAdapterRejectedByTarget,
)

__all__ = ["KubernetesCredentials", "kubernetes_api_adapter"]


@dataclass(frozen=True, slots=True)
class KubernetesCredentials:
    """A cluster API server and the bearer token to present to it.

    The API server is usually on a private address, which `HardenedHttpClient`
    refuses by default. That is NOT worked around here. The operator turns on
    `allow_private_destinations` with an `allowed_hosts` entry naming this one
    server -- a far smaller grant than "all of RFC1918", and one that is visible
    in the policy the client reports.
    """

    api_server: str
    token: str
    #: Set together: mint a per-operation token for this account instead of
    #: presenting `token` to the resource APIs. See CONSTRAINED CREDENTIALS.
    executor_service_account: str = ""
    executor_namespace: str = ""
    token_ttl_seconds: int = 600
    token_audience: str = ""

    @property
    def brokered(self) -> bool:
        return bool(self.executor_service_account)

    def __post_init__(self) -> None:
        if bool(self.executor_service_account) != bool(self.executor_namespace):
            raise ToolAdapterRefused(
                "Kubernetes executor_service_account and executor_namespace are set together"
            )
        for label, value in (("executor_service_account", self.executor_service_account),
                             ("executor_namespace", self.executor_namespace)):
            if value and not re.fullmatch(r"[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?", value):
                raise ToolAdapterRefused(f"Kubernetes {label} {value!r} is not a valid name")
        # The API server refuses less than ten minutes; more than an hour is
        # not "per operation" any more.
        if not 600 <= int(self.token_ttl_seconds) <= 3600:
            raise ToolAdapterRefused("Kubernetes token_ttl_seconds must be between 600 and 3600")
        if not str(self.token).strip():
            raise ToolAdapterRefused("Kubernetes token is required")
        server = str(self.api_server).strip()
        if not server.startswith("https://"):
            raise ToolAdapterRefused(
                f"Kubernetes api_server {server!r} must be https; a bearer token "
                "on a cleartext hop is a disclosed bearer token"
            )


#: Verb -> HTTP method. `list` and `get` differ in path shape, not in method.
#: `exec`, `attach` and `port-forward` are deliberately absent; see the module
#: docstring.
METHODS: Mapping[str, str] = MappingProxyType({
    "get": "GET",
    "list": "GET",
    "create": "POST",
    "update": "PUT",
    "delete": "DELETE",
})

#: kind -> (apiGroup path, plural, namespaced).
RESOURCES: Mapping[str, tuple[str, str, bool]] = MappingProxyType({
    "pod": ("/api/v1", "pods", True),
    "service": ("/api/v1", "services", True),
    "configmap": ("/api/v1", "configmaps", True),
    "secret": ("/api/v1", "secrets", True),
    "namespace": ("/api/v1", "namespaces", False),
    "node": ("/api/v1", "nodes", False),
    "serviceaccount": ("/api/v1", "serviceaccounts", True),
    "deployment": ("/apis/apps/v1", "deployments", True),
    "statefulset": ("/apis/apps/v1", "statefulsets", True),
    "daemonset": ("/apis/apps/v1", "daemonsets", True),
    "job": ("/apis/batch/v1", "jobs", True),
    "cronjob": ("/apis/batch/v1", "cronjobs", True),
    "role": ("/apis/rbac.authorization.k8s.io/v1", "roles", True),
    "rolebinding": ("/apis/rbac.authorization.k8s.io/v1", "rolebindings", True),
    "clusterrole": ("/apis/rbac.authorization.k8s.io/v1", "clusterroles", False),
    "clusterrolebinding": (
        "/apis/rbac.authorization.k8s.io/v1", "clusterrolebindings", False,
    ),
    "networkpolicy": ("/apis/networking.k8s.io/v1", "networkpolicies", True),
})

#: Singular and plural spellings both resolve to the same entry. Built FROM the
#: table rather than by stripping a trailing "s", because that heuristic turns
#: `networkpolicies` into `networkpolicie` and silently makes a kind
#: unreachable -- the sort of gap nobody notices until an operator needs it.
ALIASES: Mapping[str, str] = MappingProxyType(
    {alias: kind for kind, (_group, plural, _ns) in RESOURCES.items()
     for alias in (kind, plural)}
)

#: RFC 1123 label, which is what Kubernetes names and namespaces are. Applied to
#: both, because they are interpolated into the API path.
_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def _require_target_preconditions(
    verb: str, body: Mapping[str, Any] | None, *, name: str, namespace: str,
) -> None:
    """Bind an existing-object mutation to the version the caller approved.

    These fields stay in the approved parameter digest and are sent unchanged
    to the API server, which performs the atomic check. A separate GET followed
    by an unconditional write would leave a race. Never refresh a stale version
    and retry silently; a changed object requires a new approval.
    """
    if verb not in {"update", "delete"}:
        return
    section = "metadata" if verb == "update" else "preconditions"
    expected = body.get(section) if body is not None else None
    if not isinstance(expected, Mapping):
        raise ToolAdapterRefused(f"kubernetes {verb} requires {section} with uid and resourceVersion")
    for field in ("uid", "resourceVersion"):
        value = expected.get(field)
        if not isinstance(value, str) or not value.strip() or len(value) > 256:
            raise ToolAdapterRefused(f"kubernetes {verb} requires a nonempty {section}.{field}")
        if value != value.strip() or (field == "resourceVersion" and re.fullmatch(r"0+", value)):
            raise ToolAdapterRefused("kubernetes mutation requires an exact nonzero resourceVersion and unpadded uid")
    if verb == "update":
        if expected.get("name") != name or expected.get("namespace", "") != namespace:
            raise ToolAdapterRefused("kubernetes update metadata must match the named target and namespace")


def kubernetes_api_adapter(
    *,
    client: HardenedHttpClient,
    credentials: KubernetesCredentials,
    ceiling: str = DEFAULT_CEILING,
) -> RegisteredSideEffect:
    """Call one Kubernetes API operation under a tier ceiling.

    Arguments: `verb`, `kind`, optional `name`, `namespace` and `body`.
    """
    limit = normalise_ceiling(ceiling)
    server = str(credentials.api_server).rstrip("/")

    def mint() -> tuple[str, dict[str, Any]]:
        """The bearer for ONE operation, and what may be said about it."""
        if not credentials.brokered:
            return credentials.token, {"mode": "static"}
        spec: dict[str, Any] = {"expirationSeconds": int(credentials.token_ttl_seconds)}
        if credentials.token_audience:
            spec["audiences"] = [credentials.token_audience]
        issued = hardened_call(
            client, method="POST",
            url=(f"{server}/api/v1/namespaces/{credentials.executor_namespace}"
                 f"/serviceaccounts/{credentials.executor_service_account}/token"),
            headers={"authorization": f"Bearer {credentials.token}", "accept": "application/json",
                     "content-type": "application/json"},
            body=json.dumps({"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest",
                             "spec": spec}, separators=(",", ":")).encode("utf-8"),
        )
        status = issued["body"].get("status") if isinstance(issued["body"], Mapping) else None
        token = status.get("token") if isinstance(status, Mapping) else None
        if not 200 <= issued["status"] < 300 or not isinstance(token, str) or not token:
            raise ToolAdapterRefused(f"kubernetes token request was not granted (HTTP {issued['status']})")
        return token, {
            "mode": "token_request",
            "service_account": f"{credentials.executor_namespace}/{credentials.executor_service_account}",
            "expires_at": str(status.get("expirationTimestamp", "")),
            "audience": credentials.token_audience,
        }

    def read_target(hint: Mapping[str, Any]) -> tuple[int, Any]:
        resource = RESOURCES.get(ALIASES.get(str(hint.get("kind", "")), ""))
        if resource is None:
            return 0, None
        group_path, plural, namespaced = resource
        path = group_path + (f"/namespaces/{hint.get('namespace', '')}" if namespaced else "")
        bearer, _ = mint()
        found = hardened_call(client, method="GET", url=f"{server}{path}/{plural}/{hint.get('name', '')}",
                              headers={"authorization": f"Bearer {bearer}", "accept": "application/json"}, body=None)
        return int(found["status"]), found["body"]

    def run(args: Mapping[str, Any]) -> dict[str, Any]:
        try:
            prepared = prepare(args)
            bearer, credential = mint()
        except ToolAdapterRefused as exc:
            # Validation, the ceiling and the token request all precede the
            # mutating call; nothing has touched the target.
            raise ToolAdapterNotAttempted(str(exc)) from exc
        return send(prepared, bearer, credential)

    def prepare(args: Mapping[str, Any]) -> dict[str, Any]:
        verb = str(args.get("verb", "")).strip().lower()
        if verb not in METHODS:
            raise ToolAdapterRefused(
                f"kubernetes verb {verb!r} is not addressable by this adapter "
                f"(supported: {', '.join(sorted(METHODS))}). exec, attach and "
                "port-forward are deliberately absent."
            )

        spelled = str(args.get("kind", "")).strip().lower()
        kind = ALIASES.get(spelled, "")
        resource = RESOURCES.get(kind) if kind else None
        if resource is None:
            raise ToolAdapterRefused(
                f"kubernetes kind {args.get('kind')!r} is not addressable by "
                "this adapter"
            )
        group_path, plural, namespaced = resource

        namespace = str(args.get("namespace", "")).strip()
        name = str(args.get("name", "")).strip()
        for label, value in (("namespace", namespace), ("name", name)):
            if value and not _NAME_RE.fullmatch(value):
                raise ToolAdapterRefused(
                    f"kubernetes {label} {value!r} is not a valid RFC 1123 name"
                )
        if namespaced and not namespace:
            raise ToolAdapterRefused(
                f"kubernetes kind {kind!r} is namespaced; a namespace is "
                "required rather than defaulted, because the obvious default is "
                "'default' and that is a blast radius nobody chose"
            )
        if verb in {"get", "update", "delete"} and not name:
            raise ToolAdapterRefused(f"kubernetes {verb} requires a name")

        # Classified from the same verb/kind/namespace the path is built from.
        # `-n <namespace>` is the shape `_classify_kubernetes` reads to notice
        # kube-system, which is what makes a delete there critical.
        semantics = classify_or_refuse(
            platform="kubernetes",
            # API PUT is an update; the classifier's Kubernetes vocabulary
            # spells this write "apply". Never feed the unrecognized bare
            # "update" verb (also used by SQL) into generic classification.
            action="apply" if verb == "update" else verb,
            resource=f"{plural} -n {namespace}" if namespace else plural,
            metadata={},
        )
        enforce_ceiling(semantics, limit)

        path = group_path
        if namespaced:
            path += f"/namespaces/{namespace}"
        path += f"/{plural}"
        if name:
            path += f"/{name}"

        body = args.get("body")
        if body is not None and not isinstance(body, Mapping):
            raise ToolAdapterRefused("kubernetes body must be an object")
        _require_target_preconditions(verb, body, name=name, namespace=namespace)
        payload = (
            json.dumps(dict(body), separators=(",", ":")).encode("utf-8")
            if body is not None
            else None
        )
        operation_id = current_operation_id()
        if operation_id and verb in {"create", "update"}:
            # The target records which operation wrote it; the body is untouched.
            path += f"?fieldManager={field_manager(operation_id)}"
        return {"verb": verb, "plural": plural, "namespace": namespace, "path": path,
                "payload": payload, "semantics": semantics}

    def mark_for_deletion(prepared: Mapping[str, Any], headers: Mapping[str, str], options: dict) -> bytes:
        """Stamp the approved version for deletion; return options naming the stamped version.

        DELETE carries no field manager, so a delete cannot say which operation
        it belongs to. The object says it instead: the APPROVED version is
        rewritten, unchanged except for `sentinel.io/delete-operation`, with
        the approved resourceVersion as the write's precondition and this
        operation's field manager. The delete that follows names the version
        that write produced. The admission policy refuses an executor delete of
        an object that does not carry the mark, so an executor token used by
        hand cannot delete, and every admitted delete is attributable.

        Everything here precedes the delete. A refusal is therefore a known
        absence of the effect; the only residue is an annotation.
        """
        expected = options.get("preconditions") or {}
        url = f"{server}{prepared['path']}"
        found = hardened_call(client, method="GET", url=url, headers=dict(headers), body=None)
        current = found["body"] if isinstance(found["body"], Mapping) else {}
        metadata = dict(current.get("metadata") or {})
        if found["status"] != 200 or metadata.get("uid") != expected.get("uid") \
                or str(metadata.get("resourceVersion")) != str(expected.get("resourceVersion")):
            raise ToolAdapterRejectedByTarget(
                "kubernetes target is absent or is no longer the approved version; nothing was deleted"
            )
        stamp = field_manager(current_operation_id())
        metadata.pop("managedFields", None)
        metadata["annotations"] = {**(metadata.get("annotations") or {}), DELETE_MARK: stamp}
        marked = hardened_call(
            client, method="PUT", url=f"{url}?fieldManager={stamp}",
            headers={**headers, "content-type": "application/json"},
            body=json.dumps({**current, "metadata": metadata}, separators=(",", ":")).encode("utf-8"),
        )
        version = (marked["body"].get("metadata") or {}).get("resourceVersion") if isinstance(marked["body"], Mapping) else None
        if not 200 <= marked["status"] < 300 or not version:
            raise ToolAdapterRejectedByTarget(
                f"kubernetes API did not accept the deletion mark (HTTP {marked['status']}); nothing was deleted"
            )
        return json.dumps({**options, "preconditions": {"uid": expected["uid"], "resourceVersion": str(version)}},
                          separators=(",", ":")).encode("utf-8")

    def send(prepared: Mapping[str, Any], bearer: str, credential: Mapping[str, Any]) -> dict[str, Any]:
        verb, plural, namespace = prepared["verb"], prepared["plural"], prepared["namespace"]
        semantics, payload = prepared["semantics"], prepared["payload"]
        headers = {"authorization": f"Bearer {bearer}", "accept": "application/json"}
        if payload is not None:
            headers["content-type"] = "application/json"
        if verb == "delete" and credentials.brokered and current_operation_id():
            payload = mark_for_deletion(prepared, headers, json.loads(payload or b"{}"))

        result = hardened_call(
            client,
            method=METHODS[verb],
            url=f"{server}{prepared['path']}",
            headers=headers,
            body=payload,
        )
        if 400 <= result["status"] < 500:
            # The API server answered and refused: a conflict with the approved
            # resourceVersion, RBAC, admission or validation. Nothing was
            # admitted. The body is withheld; it may echo object data.
            raise ToolAdapterRejectedByTarget(
                f"kubernetes API rejected the operation (HTTP {result['status']}); nothing was changed"
            )
        if not 200 <= result["status"] < 300:
            # A 5xx does not prove absence of an effect. The operation tracker
            # keeps it unknown and the reconciler asks the target.
            raise ToolAdapterRefused(f"kubernetes API did not confirm the operation (HTTP {result['status']})")
        return bounded(
            {
                "platform": "kubernetes",
                "operation": f"{verb} {plural}",
                "namespace": namespace,
                "confirmation": "api_response_only",
                "credential": dict(credential),
                "semantics": semantics.as_metadata(),
                **result,
            }
        )

    return RegisteredSideEffect(
        name="kubernetes_api", runner=run, hint=kubernetes_hint,
        reconciler=kubernetes_reconciler(read_target),
    )
