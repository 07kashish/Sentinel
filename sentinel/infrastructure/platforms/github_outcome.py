"""Ask GitHub whether an operation landed. Reads only.

GitHub's REST API has no operation stamp, so attribution is weaker than on
Kubernetes and this module says so in every verdict. What CAN be decided from
the target alone:

    DELETE <path>              GET 404 ............................ succeeded
                               GET 200, still the approved blob ... failed
    PUT  .../contents/<file>   GET blob sha == the approved content  succeeded
                               GET blob sha == the sha being replaced failed
                               GET 404 for a create ................ failed
    anything else              ..................................... unknown

A contents write carries the blob sha it replaces, which is GitHub's own
optimistic-concurrency precondition; an unchanged sha therefore proves the
write did not land. POST (issues, comments, pull requests) is not idempotent
and carries nothing to correlate on, so it is never settled here: a human
looks. The hint stores digests and the path, never the file content.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from typing import Any, Callable, Mapping

from sentinel.application.reconciliation import ReconcileVerdict
from sentinel.domain.operations import OperationState

__all__ = ["github_hint", "github_reconciler"]

_UNKNOWN = OperationState.UNKNOWN_AFTER_EFFECT
_CONTENTS = re.compile(r"^/repos/[^/]+/[^/]+/contents/.+")


def _blob_sha(content_b64: str) -> str:
    """The git blob id GitHub will report for this content."""
    try:
        raw = base64.b64decode(content_b64, validate=False)
    except (binascii.Error, ValueError):
        return ""
    return hashlib.sha1(b"blob %d\x00" % len(raw) + raw, usedforsecurity=False).hexdigest()


def github_hint(args: Mapping[str, Any]) -> Mapping[str, Any]:
    method = str(args.get("method", "GET")).strip().upper()
    if method not in {"PUT", "DELETE"}:
        return {}
    body = args.get("body") if isinstance(args.get("body"), Mapping) else {}
    path = str(args.get("path", "")).strip()
    hint: dict[str, Any] = {"method": method, "path": path, "replaced_sha": str(body.get("sha", ""))}
    if method == "PUT" and _CONTENTS.match(path) and isinstance(body.get("content"), str):
        hint["expected_blob_sha"] = _blob_sha(body["content"])
    if isinstance(body.get("branch"), str):
        hint["ref"] = body["branch"]
    return hint


def github_reconciler(
    read: Callable[[Mapping[str, Any]], tuple[int, Any]],
) -> Callable[[str, Mapping[str, Any]], ReconcileVerdict]:
    """`read(hint) -> (status, body)` performs one GET of the hinted path."""

    def reconcile(operation_id: str, hint: Mapping[str, Any]) -> ReconcileVerdict:
        method, path = str(hint.get("method", "")), str(hint.get("path", ""))
        if method not in {"PUT", "DELETE"} or not path:
            return ReconcileVerdict(_UNKNOWN, "GitHub offers nothing to correlate this operation on; a human must look")
        status, body = read(hint)
        current = str(body.get("sha", "")) if isinstance(body, Mapping) else ""
        replaced = str(hint.get("replaced_sha", ""))
        if method == "DELETE":
            if status == 404:
                return ReconcileVerdict(OperationState.SUCCEEDED, "target absent; approved end state holds (actor not attributed)")
            if status == 200 and replaced and current == replaced:
                return ReconcileVerdict(OperationState.FAILED, "the approved blob is still present; the delete did not land")
            return ReconcileVerdict(_UNKNOWN, f"target lookup returned HTTP {status}; cannot attribute")
        expected = str(hint.get("expected_blob_sha", ""))
        if not expected:
            return ReconcileVerdict(_UNKNOWN, "only contents writes can be verified from the target")
        if status == 200 and current == expected:
            return ReconcileVerdict(OperationState.SUCCEEDED, "target holds exactly the approved content (actor not attributed)")
        if (status == 200 and replaced and current == replaced) or (status == 404 and not replaced):
            return ReconcileVerdict(OperationState.FAILED, "target is unchanged from before the approved write")
        return ReconcileVerdict(_UNKNOWN, "target holds other content; cannot attribute")

    return reconcile
