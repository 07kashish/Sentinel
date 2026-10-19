"""What an approver is being asked to approve, without the secrets in it.

An approver shown a digest approves a digest. They need the change: which
object, which fields, how big, how dangerous, under which rule, until when.
They must not need the secret values, and the evidence store must not hold
them. So the summary is STRUCTURAL:

  * every leaf of the parameters is listed by path and type;
  * a value is shown only when its key is not sensitive AND the value is a
    boolean, a number, or a short string from a conservative alphabet that
    does not look random;
  * everything else is `[redacted <type> <length>]` -- including every env
    value, command, argument and anything under a Secret's or ConfigMap's
    `data`, because those are where credentials live in practice;
  * the list is capped, and the cap is stated.

The summary is computed once, when the authorization is issued, from the same
parameters the digest commits to, and stored with the authorization. It is
never recomputed from anything the approver-side could influence.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any, Mapping

from sentinel.domain.action_semantics import classify_action

__all__ = ["summarise_change"]

MAX_FIELDS = 60
_SENSITIVE_KEY = re.compile(
    r"(?i)(secret|token|passw|credential|private|apikey|api_key|auth|cert|signature|cookie|session|"
    r"^key$|_key$|-key$|^data$|^stringdata$|^binarydata$|^env$|^envfrom$|^command$|^args$|^value$)"
)
_PLAIN_VALUE = re.compile(r"^[A-Za-z0-9._:/@+\-]{1,96}$")


def _entropy(text: str) -> float:
    counts = Counter(text)
    return -sum((c / len(text)) * math.log2(c / len(text)) for c in counts.values())


_CONTENT_DIGEST = re.compile(r"sha(256|384|512):[0-9a-f]{64,128}")


def _looks_random(text: str) -> bool:
    """Judged per token, so `registry.example/payments:1.4.2` is readable while
    a credential embedded anywhere in a string is not. A content digest is an
    identifier an approver NEEDS (it pins the image), so it is allowed by shape.
    """
    for token in re.split(r"[/:.@+_\-]", _CONTENT_DIGEST.sub("", text)):
        if (len(token) >= 20 and any(c.isdigit() for c in token) and any(c.isalpha() for c in token)
                and _entropy(token) >= 3.5):
            return True
    return False


def _display(value: Any, *, sensitive: bool) -> str:
    if isinstance(value, bool) or value is None:
        return str(value).lower() if value is not None else "null"
    if isinstance(value, (int, float)) and not sensitive:
        return str(value)
    if isinstance(value, str) and not sensitive and _PLAIN_VALUE.fullmatch(value) and not _looks_random(value):
        return value
    kind = type(value).__name__
    size = len(value) if isinstance(value, (str, bytes)) else ""
    return f"[redacted {kind}{(' ' + str(size)) if size != '' else ''}]"


def _walk(value: Any, path: str, sensitive: bool, out: list[dict[str, str]]) -> None:
    if isinstance(value, Mapping):
        for key in sorted(value, key=str):
            child = f"{path}.{key}" if path else str(key)
            _walk(value[key], child, sensitive or bool(_SENSITIVE_KEY.search(str(key))), out)
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _walk(item, f"{path}[{index}]", sensitive, out)
        return
    out.append({"path": path, "type": type(value).__name__, "value": _display(value, sensitive=sensitive)})


def _headline(tool: str, action: str, resource: str, parameters: Mapping[str, Any]) -> str:
    verb, kind = str(parameters.get("verb", "")).strip(), str(parameters.get("kind", "")).strip()
    if verb and kind:
        namespace, name = str(parameters.get("namespace", "")).strip(), str(parameters.get("name", "")).strip()
        target = "/".join(part for part in (namespace, name) if part) or "(cluster scope)"
        return f"{verb} {kind} {target}"
    return f"{action or tool} on {resource or '(no resource named)'}"


def summarise_change(
    *, tool: str, action: str, resource: str, parameters: Mapping[str, Any]
) -> dict[str, Any]:
    """The approver's view of one requested change. Contains no secret values."""
    fields: list[dict[str, str]] = []
    _walk(parameters, "", False, fields)
    semantics = classify_action(
        {"tool": tool, "action": action, "resource": resource, "arguments": dict(parameters)}
    )
    raw_body = parameters.get("body")
    body: Mapping[str, Any] = raw_body if isinstance(raw_body, Mapping) else {}
    candidate = body.get("metadata") if isinstance(body.get("metadata"), Mapping) else body.get("preconditions")
    expected: Mapping[str, Any] = candidate if isinstance(candidate, Mapping) else {}
    return {
        "headline": _headline(tool, action, resource, parameters),
        "tool": tool,
        "action": action or tool,
        "resource": resource,
        "impact": semantics.as_metadata() if semantics is not None else {
            "tier": "unclassified", "reasons": ["no classifier recognises this action; treat as high"]},
        "target_precondition": {k: str(expected[k]) for k in ("uid", "resourceVersion") if expected.get(k)},
        "fields": fields[:MAX_FIELDS],
        "fields_total": len(fields),
        "fields_truncated": max(0, len(fields) - MAX_FIELDS),
        "redacted": sum(1 for f in fields if f["value"].startswith("[redacted")),
    }
