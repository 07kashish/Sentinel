"""Derive risk from an OpenAPI spec, and generate policy a human then edits.

WHAT THIS IS FOR (specification section 47)
--------------------------------------------
`openapi.py` turns a spec into pinnable tool definitions -- what the API CAN
do. This module answers the next question: which of those operations matter.
An operator handed a 200-operation spec cannot write policy for it by hand, and
the first thing they need is not a model, it is the obvious things sorted out:
which operations delete, which touch credentials, which are read-only.

WHAT IT DERIVES FROM, AND WHY THAT IS DEFENSIBLE
--------------------------------------------------
Three signals, all structural, all present in the document itself:

  * THE METHOD. `DELETE` removes, `GET` reads. The weakest signal alone and the
    most reliable in combination.
  * THE PATH. `/users/{id}/password`, `/tokens`, `/keys`, `/admin` -- names
    chosen by the API's own authors to describe what the endpoint governs.
  * THE PARAMETERS AND BODY. A parameter called `password` or `role` says what
    the operation writes.

That is it. There is no model, no scoring of prose, and no attempt to infer
intent. The output is a STARTING POINT the operator edits, and the generated
document says so in its own `_readme` rather than in documentation the reader
of the file may never see.

WHY THE OUTPUT IS A TEMPLATE AND NOT AN ACTIVE POLICY
-------------------------------------------------------
Generated rules are written to a file for review; nothing here installs them.
A tool that both invents rules and enables them is a tool that changes what a
deployment blocks without a human deciding -- and the failure mode is silent,
because a rule that fires on ordinary traffic looks exactly like a rule that
works until somebody's workflow stops. `docs/TOOL_GATEWAY.md` states the same
limit for the same reason.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

__all__ = [
    "OperationRisk",
    "derive_risks",
    "policy_template",
]

_READ_METHODS = frozenset({"get", "head", "options"})
_DESTRUCTIVE_METHODS = frozenset({"delete"})
_WRITE_METHODS = frozenset({"post", "put", "patch"})

#: Path segments that name what an endpoint governs, by the API's own authors.
#: Ordered most-specific first: a match stops the search, so `/admin/tokens`
#: reports the credential reading rather than the administrative one.
_PATH_SIGNALS: tuple[tuple[re.Pattern[str], str, str, str], ...] = (
    (re.compile(r"(?:^|/)(secrets?|credentials?|tokens?|api[-_]?keys?|passwords?)(?:/|$)"),
     "credential", "critical", "the path names a credential"),
    (re.compile(r"(?:^|/)(permissions?|roles?|policies|policy|grants?|acls?|iam)(?:/|$)"),
     "privilege", "critical", "the path names an authorisation object"),
    (re.compile(r"(?:^|/)(admin|superuser|sudo)(?:/|$)"),
     "privilege", "high", "the path is an administrative surface"),
    (re.compile(r"(?:^|/)(exports?|dumps?|backups?|downloads?)(?:/|$)"),
     "export", "high", "the path names bulk data movement"),
    (re.compile(r"(?:^|/)(exec|execute|run|commands?|shell)(?:/|$)"),
     "execution", "critical", "the path names code execution"),
    (re.compile(r"(?:^|/)(users?|accounts?|members?)(?:/|$)"),
     "identity", "moderate", "the path names an identity object"),
)

#: Parameter and property names that say what an operation writes.
_SENSITIVE_FIELDS = re.compile(
    r"^(password|passwd|secret|token|api[-_]?key|credential|role|roles|"
    r"permission|permissions|scope|scopes|is[-_]?admin|admin)$",
    re.IGNORECASE,
)

_TIERS = ("low", "moderate", "high", "critical")


def _worst(left: str, right: str) -> str:
    return left if _TIERS.index(left) >= _TIERS.index(right) else right


@dataclass(frozen=True, slots=True)
class OperationRisk:
    """One operation, its derived tier, and every reason that produced it.

    `reasons` is not decoration. A tier with no reasons attached is the magic
    number this codebase refuses elsewhere: an operator who cannot see why an
    operation was called critical cannot tell a correct derivation from a
    coincidence of path naming, and will either trust it blindly or ignore it.
    """

    operation_id: str
    method: str
    path: str
    category: str
    tier: str
    reasons: tuple[str, ...]
    sensitive_parameters: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "method": self.method,
            "path": self.path,
            "category": self.category,
            "tier": self.tier,
            "reasons": list(self.reasons),
            "sensitive_parameters": list(self.sensitive_parameters),
        }


def _sensitive_parameters(operation: Mapping[str, Any]) -> tuple[str, ...]:
    """Parameter and request-body property names that look sensitive.

    Reads the shapes a spec actually uses and gives up quietly on the rest:
    a `$ref` is not followed, for the same reason `openapi.py` does not follow
    one -- resolution means trusting a document nobody has reviewed. An
    unresolved reference yields no finding rather than a guess.
    """
    found: list[str] = []
    for parameter in operation.get("parameters") or []:
        if isinstance(parameter, Mapping):
            name = str(parameter.get("name", ""))
            if _SENSITIVE_FIELDS.match(name):
                found.append(name)

    body = operation.get("requestBody")
    if isinstance(body, Mapping):
        content = body.get("content")
        if isinstance(content, Mapping):
            for media in content.values():
                if not isinstance(media, Mapping):
                    continue
                schema = media.get("schema")
                if not isinstance(schema, Mapping):
                    continue
                properties = schema.get("properties")
                if isinstance(properties, Mapping):
                    for name in properties:
                        if _SENSITIVE_FIELDS.match(str(name)):
                            found.append(str(name))
    return tuple(dict.fromkeys(found))


def _classify(method: str, path: str, operation: Mapping[str, Any]) -> OperationRisk:
    lowered = method.lower()
    reasons: list[str] = []
    category = "read" if lowered in _READ_METHODS else "write"
    tier = "low" if lowered in _READ_METHODS else "moderate"

    if lowered in _DESTRUCTIVE_METHODS:
        category, tier = "destructive", "high"
        reasons.append("DELETE removes a resource")
    elif lowered in _WRITE_METHODS:
        reasons.append(f"{method.upper()} changes state")
    else:
        reasons.append(f"{method.upper()} is read-only")

    for pattern, signal_category, signal_tier, reason in _PATH_SIGNALS:
        if pattern.search(path.lower()):
            # A read of a credential path is still a credential operation --
            # reading a secret IS the risk -- so the category is taken from the
            # path, and the tier is the worse of the two rather than a
            # replacement. `GET /secrets` must not inherit `low` from its verb.
            category = signal_category
            tier = _worst(tier, signal_tier)
            reasons.append(reason)
            break

    sensitive = _sensitive_parameters(operation)
    if sensitive and lowered not in _READ_METHODS:
        tier = _worst(tier, "high")
        reasons.append(
            "writes sensitive parameters: " + ", ".join(sorted(sensitive))
        )

    operation_id = str(
        operation.get("operationId") or f"{method.lower()}_{path.strip('/').replace('/', '_')}"
    )
    return OperationRisk(
        operation_id=operation_id,
        method=method.upper(),
        path=path,
        category=category,
        tier=tier,
        reasons=tuple(reasons),
        sensitive_parameters=sensitive,
    )


def derive_risks(spec: Mapping[str, Any]) -> tuple[OperationRisk, ...]:
    """Every operation in the spec with its derived category, tier and reasons."""
    paths = spec.get("paths")
    if not isinstance(paths, Mapping):
        return ()
    risks: list[OperationRisk] = []
    for path, item in paths.items():
        if not isinstance(item, Mapping):
            continue
        for method, operation in item.items():
            if method.lower() not in (
                _READ_METHODS | _WRITE_METHODS | _DESTRUCTIVE_METHODS
            ):
                continue
            if not isinstance(operation, Mapping):
                continue
            risks.append(_classify(method, str(path), operation))
    return tuple(risks)


def policy_template(
    risks: Iterable[OperationRisk], *, api_name: str = "api"
) -> dict[str, Any]:
    """A reviewable policy document. Nothing installs it; a human does.

    One rule per tier rather than one per operation, because a rule per
    operation produces a file nobody reads and a diff nobody can review -- and
    the operations that share a tier share it for reasons the `reasons` field
    already records. The generated `_readme` repeats the limits inside the
    artifact, where the person editing it will actually see them.
    """
    by_tier: dict[str, list[OperationRisk]] = {}
    for risk in risks:
        by_tier.setdefault(risk.tier, []).append(risk)

    severity_for = {"critical": 85, "high": 70, "moderate": 45, "low": 20}
    rules: list[dict[str, Any]] = []
    for tier in ("critical", "high"):
        entries = by_tier.get(tier, [])
        if not entries:
            continue
        rules.append(
            {
                "id": f"{api_name}-{tier}-operation",
                "description": (
                    f"DERIVED, NOT REVIEWED. {len(entries)} {tier}-tier "
                    f"operations in the {api_name} spec, by HTTP method, path "
                    f"naming and sensitive parameters. Edit before enabling."
                ),
                "field": "resource",
                "mode": "regex",
                "values": sorted({_path_regex(risk.path) for risk in entries}),
                "severity": severity_for[tier],
                "incident_type": f"{api_name}_{tier}_operation",
                "_derived_from": [
                    {
                        "operation": risk.operation_id,
                        "method": risk.method,
                        "path": risk.path,
                        "reasons": list(risk.reasons),
                    }
                    for risk in sorted(entries, key=lambda r: r.path)
                ],
            }
        )

    return {
        "policy_id": f"{api_name}-derived",
        "version": "0.1.0",
        "_readme": [
            "GENERATED FROM AN OPENAPI SPEC. THIS IS A STARTING POINT.",
            "",
            "Rules here were derived from the document's own structure -- HTTP",
            "method, path naming, and sensitive parameter names -- and nothing",
            "more. There is no model and no understanding of what the API does.",
            "",
            "Before enabling any of this:",
            "  - read `_derived_from` on each rule and check the reasoning",
            "  - a path that merely CONTAINS 'admin' is not necessarily",
            "    administrative, and one that does not may still be",
            "  - operations this missed are missing, not safe",
            "",
            "Nothing installed these. Point SENTINEL_POLICY_PATH at the file",
            "only after you have edited it.",
        ],
        "rules": rules,
    }


def _path_regex(path: str) -> str:
    """Turn `/users/{id}/keys` into a regex matching a real request URL.

    Templated segments become a non-slash wildcard, and every other character
    is escaped -- a path is data from a document, and pasting it into a regex
    unescaped would let a spec author write the matcher.
    """
    parts = re.split(r"\{[^}]*\}", path)
    return "[^/]+".join(re.escape(part) for part in parts)
