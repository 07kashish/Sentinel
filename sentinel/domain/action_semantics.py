"""What a platform action MEANS: deterministic semantics for enterprise tools.

WHY THIS EXISTS
---------------
The policy engine matches text. Text matching knows that `.env` is sensitive; it
does not know that `iam:AttachUserPolicy` is privilege escalation while
`iam:ListUsers` is inventory, that `kubectl exec` is code execution while
`kubectl logs` is reading, or that `PUT /repos/o/r/branches/main/protection`
rewrites who may ship code. Those judgements are SEMANTIC: they come from what
the platform's own verb grammar says the operation does, not from any substring.

This module encodes that grammar for the Tier-1 platforms — AWS, Kubernetes,
GitHub, SQL — as pure classification. Given the action/resource of an event it
answers: which platform, which operation, what CATEGORY of consequence
(read / write / destructive / privilege / credential / execution / export), and
what TIER of concern (low / moderate / high / critical), with the reasons.

HOW IT REACHES A DECISION PATH WITHOUT BECOMING ONE
---------------------------------------------------
It never decides ALLOW or BLOCK. `enrich_payload` writes the classification into
`metadata.semantics`, and `config/default_policy.json` carries ordinary rules
that match on `metadata.semantics.tier` — so the deterministic policy engine
remains the single decision-maker, the classification arrives in the verdict as
a matched rule an analyst can read, and a deployment that disagrees edits policy
rather than code. Exactly the projection pattern the MCP gateway set.

Caller-supplied `metadata.semantics` is ALWAYS discarded before enrichment. The
field is an input to policy, so a caller allowed to assert it would be a caller
allowed to pre-classify its own actions.

WHAT THIS DELIBERATELY DOES NOT CLAIM
-------------------------------------
Classification is by recognised form: an AWS action string, a kubectl-shaped
command or Kubernetes verb+kind pair, a GitHub API URL or well-known GitHub tool
name, a SQL statement. An action in none of those forms classifies as nothing at
all — no guess, no default tier — because a wrong "low" here would be an
attacker's favourite label. Renaming and encoding evade this module exactly as
they evade any static analysis; it raises the floor for the common honest
shapes, it is not a model of intent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from sentinel.domain.event_normaliser import NormalisedAction, normalise_event

__all__ = [
    "OperationSemantics",
    "classify_action",
    "enrich_payload",
]

#: Tier ordering, lowest to highest concern. Used only to take a maximum.
_TIERS = ("low", "moderate", "high", "critical")


@dataclass(frozen=True, slots=True)
class OperationSemantics:
    """One classified operation: what it is, what it does, how much it matters."""

    platform: str
    operation: str
    category: str
    tier: str
    reasons: tuple[str, ...] = ()

    def as_metadata(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "operation": self.operation,
            "category": self.category,
            "tier": self.tier,
            "reasons": list(self.reasons),
        }


def _worst(a: str, b: str) -> str:
    return a if _TIERS.index(a) >= _TIERS.index(b) else b


# ── AWS ──────────────────────────────────────────────────────────────────────

_AWS_ACTION = re.compile(r"^([a-z0-9-]{2,40}):([A-Za-z0-9]{2,80})$")

#: Operations whose meaning is too specific for the verb-prefix fallback.
#: Category and tier, keyed by the canonical action string, lowercased.
#: `MappingProxyType`, not a bare dict:
#: `tests_arch/test_architecture_rules.py::test_there_is_no_mutable_module_level_state`
#: rejects a module-level dict literal outright, and the reason bites here --
#: this table decides which AWS operations are critical, so "any import could
#: edit it" would make the severity of a privilege escalation editable at
#: runtime. Same treatment as `retention.py::APPEND_ONLY_TABLES`.
_AWS_EXACT: Mapping[str, tuple[str, str, str]] = MappingProxyType({
    # (category, tier, reason)
    "iam:createaccesskey": ("credential", "critical", "creates a long-lived credential"),
    "iam:createloginprofile": ("credential", "critical", "creates a console password"),
    "iam:updateaccesskey": ("credential", "high", "re-activates or rotates a credential"),
    "secretsmanager:getsecretvalue": ("credential", "critical", "reads a stored secret"),
    "ssm:getparameter": ("credential", "high", "may read a SecureString parameter"),
    "kms:decrypt": ("credential", "high", "decrypts protected material"),
    "iam:attachuserpolicy": ("privilege", "critical", "attaches a policy to a user"),
    "iam:attachrolepolicy": ("privilege", "critical", "attaches a policy to a role"),
    "iam:putuserpolicy": ("privilege", "critical", "writes an inline user policy"),
    "iam:putrolepolicy": ("privilege", "critical", "writes an inline role policy"),
    "iam:createpolicyversion": ("privilege", "critical", "rewrites a policy's meaning"),
    "iam:setdefaultpolicyversion": ("privilege", "critical", "activates a policy version"),
    "iam:passrole": ("privilege", "critical", "hands a role to another service"),
    "iam:addusertogroup": ("privilege", "high", "changes group membership"),
    "s3:putbucketpolicy": ("privilege", "critical", "rewrites bucket access"),
    "s3:putbucketacl": ("privilege", "critical", "rewrites bucket ACL"),
    "s3:putobjectacl": ("privilege", "high", "rewrites object ACL"),
    "ec2:authorizesecuritygroupingress": ("privilege", "high", "opens network ingress"),
    "lambda:addpermission": ("privilege", "high", "grants invoke permission"),
    "cloudtrail:stoplogging": ("destructive", "critical", "stops the audit trail"),
    "cloudtrail:deletetrail": ("destructive", "critical", "deletes the audit trail"),
    "guardduty:deletedetector": ("destructive", "critical", "disables threat detection"),
    "config:deleteconfigurationrecorder": (
        "destructive",
        "critical",
        "disables configuration recording",
    ),
})

#: Verb prefixes for the fallback, most specific first.
_AWS_VERBS: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (("delete", "terminate", "remove", "deregister", "disable", "detach"),
     "destructive", "high"),
    (("create", "put", "update", "attach", "run", "start", "invoke", "modify",
      "tag", "untag", "set", "enable", "authorize", "register", "associate"),
     "write", "moderate"),
    (("get", "list", "describe", "head", "lookup", "search"), "read", "low"),
)


def _classify_aws(action: str) -> OperationSemantics | None:
    matched = _AWS_ACTION.match(action.strip())
    if not matched:
        return None
    service, operation = matched.group(1).lower(), matched.group(2)
    canonical = f"{service}:{operation}"
    exact = _AWS_EXACT.get(canonical.lower())
    if exact:
        category, tier, reason = exact
        return OperationSemantics(
            platform="aws",
            operation=canonical,
            category=category,
            tier=tier,
            reasons=(reason,),
        )
    lowered = operation.lower()
    for prefixes, category, tier in _AWS_VERBS:
        if lowered.startswith(prefixes):
            return OperationSemantics(
                platform="aws",
                operation=canonical,
                category=category,
                tier=tier,
                reasons=(f"{service} {category} operation by verb",),
            )
    # A well-formed action string with an unrecognised verb: recorded as an
    # AWS operation of unknown consequence. "moderate" and not "low", because
    # the verbs this table does not know skew towards the interesting ones.
    return OperationSemantics(
        platform="aws",
        operation=canonical,
        category="write",
        tier="moderate",
        reasons=("unrecognised AWS verb; treated as a state change",),
    )


# ── Kubernetes ───────────────────────────────────────────────────────────────

_K8S_VERBS = frozenset(
    {
        "get", "list", "watch", "logs", "top", "describe",
        "create", "apply", "patch", "edit", "scale", "annotate", "label",
        "delete", "drain", "cordon", "uncordon", "taint",
        "exec", "attach", "port-forward", "cp", "proxy", "run",
    }
)

_K8S_KINDS = frozenset(
    {
        "pod", "pods", "deployment", "deployments", "replicaset", "replicasets",
        "statefulset", "statefulsets", "daemonset", "daemonsets", "job", "jobs",
        "cronjob", "cronjobs", "service", "services", "ingress", "ingresses",
        "configmap", "configmaps", "secret", "secrets", "namespace", "namespaces",
        "node", "nodes", "serviceaccount", "serviceaccounts",
        "role", "roles", "rolebinding", "rolebindings",
        "clusterrole", "clusterroles", "clusterrolebinding", "clusterrolebindings",
        "networkpolicy", "networkpolicies",
        "validatingwebhookconfiguration", "validatingwebhookconfigurations",
        "mutatingwebhookconfiguration", "mutatingwebhookconfigurations",
    }
)

_K8S_KIND_ALIASES: Mapping[str, str] = MappingProxyType({
    "ns": "namespace",
    "sa": "serviceaccount",
    "deploy": "deployment",
    "svc": "service",
    "cm": "configmap",
    "cr": "clusterrole",
    "crb": "clusterrolebinding",
    "ds": "daemonset",
})

_K8S_RBAC = frozenset(
    {
        "role", "roles", "rolebinding", "rolebindings", "clusterrole",
        "clusterroles", "clusterrolebinding", "clusterrolebindings",
        "serviceaccount", "serviceaccounts",
    }
)

_K8S_ADMISSION = frozenset(
    {
        "validatingwebhookconfiguration", "validatingwebhookconfigurations",
        "mutatingwebhookconfiguration", "mutatingwebhookconfigurations",
    }
)

_READ_VERBS = frozenset({"get", "list", "watch", "logs", "top", "describe"})
_DELETE_VERBS = frozenset({"delete", "drain"})
_EXEC_VERBS = frozenset({"exec", "attach", "port-forward", "cp", "run"})


def _k8s_word(word: str) -> str:
    return _K8S_KIND_ALIASES.get(word.lower(), word.lower())


def _argument_text(arguments: Mapping[str, Any], *keys: str) -> str:
    pieces: list[str] = []
    for key in keys:
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            pieces.append(value.strip())
        elif isinstance(value, (int, float)):
            pieces.append(str(value))
    return " ".join(pieces)


def _verb_kind_from_action(action: str) -> tuple[str, str]:
    lowered = action.strip().lower()
    if lowered.startswith("kubectl "):
        tokens = lowered.split()
        verb = tokens[1] if len(tokens) > 1 else ""
        kind = next(
            (_k8s_word(word) for word in tokens[2:] if _k8s_word(word) in _K8S_KINDS), ""
        )
        return verb, kind

    # `word`, not `t`: `t` is one of the two names the SQL-identifier guard
    # tracks (`tests_arch/test_sql_is_never_built_from_data.py`), and this
    # module counts as a SQL module because its classifier names SQL verbs.
    tokens = [word for word in re.split(r"[^a-z0-9-]+", lowered) if word]
    verb = next((word for word in tokens if word in _K8S_VERBS), "")
    kind = next((_k8s_word(word) for word in tokens if _k8s_word(word) in _K8S_KINDS), "")
    return verb, kind


def _classify_kubernetes(
    action: str,
    resource: str,
    arguments: Mapping[str, Any],
    normalised: NormalisedAction,
) -> OperationSemantics | None:
    text = action.strip()
    if text.lower().startswith("kubectl "):
        tokens = text.split()
        verb = tokens[1].lower() if len(tokens) > 1 else ""
        # The kind may ride in the command OR in the event's resource field --
        # "kubectl apply" with resource "clusterrolebinding admin" is a real
        # caller shape, and dropping the resource here misread it as kindless.
        remainder = " ".join(tokens[2:]) + " " + resource
    else:
        verb, action_kind = _verb_kind_from_action(text)
        remainder = " ".join(
            (
                action_kind,
                resource,
                _argument_text(arguments, "kind", "resource", "namespace", "name"),
                normalised.command_text,
            )
        )
    if verb not in _K8S_VERBS:
        return None
    words = [_k8s_word(w) for w in re.split(r"[\s/,=]+", remainder.lower())]
    kind = next((w for w in words if w in _K8S_KINDS), "")
    if not kind and verb not in _EXEC_VERBS:
        # A bare verb like "get" with no Kubernetes kind anywhere in sight is
        # ordinary English, not an API call. Refusing to classify it is what
        # keeps this from firing on every event whose action is "list".
        return None
    operation = f"{verb} {kind}".strip()
    namespace = ""
    ns_match = re.search(r"(?:-n|--namespace)[=\s]+(\S+)", f"{text} {resource}")
    if ns_match:
        namespace = ns_match.group(1)

    if verb in _EXEC_VERBS:
        return OperationSemantics(
            platform="kubernetes", operation=operation or verb,
            category="execution", tier="critical",
            reasons=("code execution or tunnel into a running workload",),
        )
    if kind in {"secret", "secrets"}:
        tier = "high" if verb in _READ_VERBS else "high"
        category = "credential" if verb in _READ_VERBS else "write"
        return OperationSemantics(
            platform="kubernetes", operation=operation, category=category,
            tier=tier, reasons=("touches Secret objects",),
        )
    if kind in _K8S_RBAC and verb not in _READ_VERBS:
        return OperationSemantics(
            platform="kubernetes", operation=operation, category="privilege",
            tier="critical", reasons=("rewrites RBAC",),
        )
    if kind in _K8S_ADMISSION and verb not in _READ_VERBS:
        return OperationSemantics(
            platform="kubernetes", operation=operation, category="privilege",
            tier="critical", reasons=("rewrites admission control",),
        )
    if kind in {"networkpolicy", "networkpolicies"} and verb not in _READ_VERBS:
        return OperationSemantics(
            platform="kubernetes", operation=operation, category="privilege",
            tier="high", reasons=("rewrites network segmentation",),
        )
    if verb in _DELETE_VERBS:
        tier = "critical" if namespace == "kube-system" else "high"
        reasons = ("deletes a cluster object",)
        if namespace == "kube-system":
            reasons = ("deletes inside kube-system",)
        return OperationSemantics(
            platform="kubernetes", operation=operation, category="destructive",
            tier=tier, reasons=reasons,
        )
    if verb in _READ_VERBS:
        return OperationSemantics(
            platform="kubernetes", operation=operation, category="read",
            tier="low", reasons=("read-only verb",),
        )
    return OperationSemantics(
        platform="kubernetes", operation=operation, category="write",
        tier="moderate", reasons=("mutates a cluster object",),
    )


# ── GitHub ───────────────────────────────────────────────────────────────────

_HTTP_VERBS = frozenset({"get", "head", "post", "put", "patch", "delete"})

#: Well-known GitHub tool names (the vocabulary GitHub's own MCP server and
#: most agent frameworks use). Only consulted when the event says github
#: somewhere — a bare `delete_file` could belong to anything.
_GITHUB_TOOLS: Mapping[str, tuple[str, str, str]] = MappingProxyType({
    "delete_repository": ("destructive", "critical", "deletes a repository"),
    "update_branch_protection": ("privilege", "critical", "rewrites branch protection"),
    "delete_branch_protection": ("privilege", "critical", "removes branch protection"),
    "merge_pull_request": ("write", "high", "merges into a protected line"),
    "create_release": ("write", "high", "publishes a release"),
    "create_workflow_dispatch": ("execution", "high", "triggers CI execution"),
    "push_files": ("write", "moderate", "pushes commits"),
    "create_or_update_file": ("write", "moderate", "writes repository content"),
    "delete_file": ("write", "moderate", "deletes repository content"),
    "create_branch": ("write", "moderate", "creates a branch"),
    "create_pull_request": ("write", "moderate", "opens a pull request"),
    "create_issue": ("write", "low", "opens an issue"),
    "add_issue_comment": ("write", "low", "comments on an issue"),
})


def _classify_github(
    action: str, resource: str, metadata: Mapping[str, Any]
) -> OperationSemantics | None:
    blob = f"{action} {resource}".lower()
    if "github" not in blob:
        return None

    lowered_action = action.strip().lower()
    tool = _GITHUB_TOOLS.get(lowered_action)
    if tool:
        category, tier, reason = tool
        # A content write that lands in .github/workflows is not a content
        # write; it is CI code that runs with the repository's credentials.
        path_hint = f"{resource} {metadata.get('path', '')}".lower()
        if category == "write" and ".github/workflows" in path_hint:
            return OperationSemantics(
                platform="github", operation=lowered_action,
                category="privilege", tier="critical",
                reasons=("modifies a workflow file",),
            )
        return OperationSemantics(
            platform="github", operation=lowered_action,
            category=category, tier=tier, reasons=(reason,),
        )

    method = ""
    if lowered_action in _HTTP_VERBS:
        method = lowered_action
    else:
        meta_method = str(metadata.get("method", "")).lower()
        if meta_method in _HTTP_VERBS:
            method = meta_method
    if not method or "api.github.com" not in resource.lower():
        return None
    path = resource.lower().split("api.github.com", 1)[1].split("?", 1)[0]
    operation = f"{method.upper()} {path}"

    def _sem(category: str, tier: str, reason: str) -> OperationSemantics:
        return OperationSemantics(
            platform="github", operation=operation,
            category=category, tier=tier, reasons=(reason,),
        )

    if method == "get" or method == "head":
        if "/actions/secrets" in path:
            return _sem("credential", "high", "reads Actions secret metadata")
        return _sem("read", "low", "read-only API call")
    if re.fullmatch(r"/repos/[^/]+/[^/]+/?", path) and method == "delete":
        return _sem("destructive", "critical", "deletes a repository")
    if "/branches/" in path and path.endswith("/protection"):
        return _sem("privilege", "critical", "rewrites branch protection")
    if "/actions/secrets" in path:
        return _sem("credential", "critical", "writes an Actions secret")
    if "/.github/workflows" in path or "/actions/workflows" in path:
        return _sem("privilege", "critical", "modifies CI workflow surface")
    if path.endswith("/merges") or re.search(r"/pulls/\d+/merge$", path):
        return _sem("write", "high", "merges commits")
    if "/releases" in path:
        return _sem("write", "high", "publishes a release")
    if "/collaborators/" in path or "/teams/" in path:
        return _sem("privilege", "high", "changes repository access")
    if method == "delete":
        return _sem("destructive", "high", "deletes a repository object")
    return _sem("write", "moderate", "mutating API call")


# ── SQL ──────────────────────────────────────────────────────────────────────

_SQL_FIRST = re.compile(
    r"^\s*(select|with|insert|update|delete|drop|truncate|alter|create|grant|"
    r"revoke|copy|merge)\b",
    re.IGNORECASE,
)


def _classify_sql(
    action: str,
    metadata: Mapping[str, Any],
    arguments: Mapping[str, Any],
    normalised: NormalisedAction,
) -> OperationSemantics | None:
    def _is_statement(text: str) -> bool:
        # The keyword alone is not a statement. A bare "delete" or "create" is
        # an HTTP verb or a tool name far more often than it is SQL, and
        # letting it through here would steal those events from the classifiers
        # that actually understand them.
        return bool(_SQL_FIRST.match(text or "")) and len(text.split()) >= 2

    statement = action
    if not _is_statement(statement):
        for source in (metadata, arguments):
            for key in ("query", "sql", "statement"):
                candidate = source.get(key)
                if isinstance(candidate, str) and _is_statement(candidate):
                    statement = candidate
                    break
            if _is_statement(statement):
                break
        if not _is_statement(statement):
            candidate = normalised.sql_text
            if isinstance(candidate, str) and _is_statement(candidate):
                statement = candidate
        if not _is_statement(statement):
            return None
    keyword = _SQL_FIRST.match(statement).group(1).upper()  # type: ignore[union-attr]
    body = statement.strip()
    upper = body.upper()
    reasons: list[str] = []

    # A statement smuggling a second statement is judged by its worst half.
    trailing = body.rstrip().rstrip(";")
    multi = ";" in trailing
    if multi:
        reasons.append("multiple statements in one call")

    if keyword in {"GRANT", "REVOKE"} or (
        keyword in {"CREATE", "ALTER"}
        and re.search(r"\b(USER|ROLE)\b", upper)
    ):
        category, tier = "privilege", "critical"
        reasons.append("changes database principals or grants")
    elif keyword in {"DROP", "TRUNCATE"}:
        category, tier = "destructive", "critical"
        reasons.append("irreversibly removes schema or data")
    elif keyword == "ALTER":
        category, tier = "destructive", "high"
        reasons.append("rewrites schema")
    elif keyword == "COPY" or "INTO OUTFILE" in upper or "INTO DUMPFILE" in upper:
        category, tier = "export", "high"
        reasons.append("bulk data movement")
    elif keyword in {"UPDATE", "DELETE"}:
        if not re.search(r"\bWHERE\b", upper):
            category, tier = "write", "high"
            # Phrased without the word this clause is detecting, deliberately.
            # `tests_arch/test_sql_is_never_built_from_data.py` decides whether
            # an f-string is SQL by looking for markers like " WHERE " in its
            # literal parts, and an analyst-facing REASON that reads as a query
            # trips it. The honest fix is prose that is not shaped like SQL --
            # not adding `keyword` to that test's global allowlist, which would
            # permit the same interpolation inside real statements elsewhere.
            reasons.append(f"unbounded {keyword}: no row filter, every row is affected")
        else:
            category, tier = "write", "moderate"
            reasons.append(f"bounded {keyword}")
    elif keyword in {"INSERT", "MERGE", "CREATE"}:
        category, tier = "write", "moderate"
        reasons.append("adds data or schema")
    else:  # SELECT / WITH
        category, tier = "read", "low"
        reasons.append("read-only query")

    if multi:
        tier = _worst(tier, "high")

    return OperationSemantics(
        platform="sql",
        operation=keyword,
        category=category,
        tier=tier,
        reasons=tuple(reasons),
    )


# ── Entry points ─────────────────────────────────────────────────────────────


def classify_action(payload: Mapping[str, Any]) -> OperationSemantics | None:
    """Classify one event's action, or return None rather than guess.

    Order: the most self-identifying grammars first. An AWS action string and a
    SQL statement cannot be confused; the looser shapes (kubectl verbs, GitHub
    tool names) carry their own guards inside.
    """
    normalised = normalise_event(payload)
    action = normalised.action or str(payload.get("action") or "")
    resource = str(payload.get("resource") or "")
    metadata = payload.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    arguments = normalised.arguments

    return (
        _classify_aws(action)
        or _classify_sql(action, metadata, arguments, normalised)
        or _classify_kubernetes(action, resource, arguments, normalised)
        or _classify_github(action, resource, metadata)
    )


def enrich_payload(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return the payload with `metadata.semantics` derived here and only here.

    Any caller-supplied `semantics` key is dropped unconditionally — it is an
    input to policy, so a caller allowed to assert it would be a caller allowed
    to pre-classify its own actions. When nothing classifies, the key is absent
    rather than present-with-a-default, so a policy rule can never match a
    label this module did not write.
    """
    metadata = payload.get("metadata")
    cleaned = dict(metadata) if isinstance(metadata, Mapping) else {}
    cleaned.pop("semantics", None)
    enriched = dict(payload)
    enriched.pop("normalised", None)
    enriched["metadata"] = cleaned

    normalised = normalise_event(enriched)
    enriched["normalised"] = normalised.as_fields()

    semantics = classify_action(enriched)
    if semantics is not None:
        cleaned["semantics"] = semantics.as_metadata()

    return enriched
