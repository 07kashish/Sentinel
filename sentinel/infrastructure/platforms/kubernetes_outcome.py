"""Ask the cluster whether an operation landed. Reads only.

CORRELATION
-----------
Every create and update is sent with `fieldManager=<field_manager(op)>`. The
API server records that name in `metadata.managedFields`, so the target itself
says which operation wrote it -- without adding anything to the approved body,
which must reach the server byte for byte as it was digested.

VERDICTS (see `sentinel.application.reconciliation`)
----------------------------------------------------
    create   object present with our manager ............ succeeded
             object absent .............................. failed
             object present without our manager ......... unknown
    update   our manager present, same uid .............. succeeded
             same uid, resourceVersion unchanged ........ failed
             anything else .............................. unknown
    delete   absent, or a different uid has the name .... succeeded
             same uid, not terminating .................. failed
             same uid, terminating ...................... unknown

"failed" is only safe once no request of ours can still be in flight. The
caller enforces that with a quiescence window; this module reports what the
target shows and nothing more. A delete that finds the target gone reports
success because the approved end state holds; the evidence text says that the
deleting actor is not attributed.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

from sentinel.application.operation_context import operation_stamp
from sentinel.application.reconciliation import ReconcileVerdict
from sentinel.domain.operations import OperationState

__all__ = ["DELETE_MARK", "field_manager", "kubernetes_hint", "kubernetes_reconciler"]

#: Annotation a protected delete writes on the approved version before deleting it.
DELETE_MARK = "sentinel.io/delete-operation"

_UNKNOWN = OperationState.UNKNOWN_AFTER_EFFECT


def field_manager(operation_id: str) -> str:
    """A field-manager name for an operation: printable, under 128 characters."""
    return operation_stamp(operation_id)


def kubernetes_hint(args: Mapping[str, Any]) -> Mapping[str, Any]:
    """Identifiers only. Never the body: that is the approved, private payload."""
    verb = str(args.get("verb", "")).strip().lower()
    if verb not in {"create", "update", "delete"}:
        return {}
    body = args.get("body") if isinstance(args.get("body"), Mapping) else {}
    section = body.get("metadata") if verb != "delete" else body.get("preconditions")
    section = section if isinstance(section, Mapping) else {}
    name = str(args.get("name", "")).strip() or str(section.get("name", "")).strip()
    return {
        "verb": verb,
        "kind": str(args.get("kind", "")).strip().lower(),
        "namespace": str(args.get("namespace", "")).strip(),
        "name": name,
        "uid": str(section.get("uid", "")),
        "resourceVersion": str(section.get("resourceVersion", "")),
    }


def kubernetes_reconciler(
    read: Callable[[Mapping[str, Any]], tuple[int, Any]],
) -> Callable[[str, Mapping[str, Any]], ReconcileVerdict]:
    """`read(hint) -> (status, object)` performs one GET of the named target."""

    def reconcile(operation_id: str, hint: Mapping[str, Any]) -> ReconcileVerdict:
        verb = str(hint.get("verb", ""))
        if verb not in {"create", "update", "delete"} or not hint.get("name"):
            return ReconcileVerdict(_UNKNOWN, "the intent recorded no addressable target")
        status, obj = read(hint)
        if status == 404:
            if verb == "delete":
                return ReconcileVerdict(OperationState.SUCCEEDED,
                                        "target absent; approved end state holds (deleting actor not attributed)")
            if verb == "create":
                return ReconcileVerdict(OperationState.FAILED, "target absent; the create did not land")
            return ReconcileVerdict(_UNKNOWN, "target absent; an update cannot be attributed")
        if status != 200 or not isinstance(obj, Mapping):
            return ReconcileVerdict(_UNKNOWN, f"target lookup returned HTTP {status}")

        metadata = obj.get("metadata") if isinstance(obj.get("metadata"), Mapping) else {}
        uid = str(metadata.get("uid", ""))
        version = str(metadata.get("resourceVersion", ""))
        managers = {
            str(entry.get("manager", ""))
            for entry in metadata.get("managedFields", []) or []
            if isinstance(entry, Mapping)
        }
        ours = field_manager(operation_id) in managers
        approved_uid = str(hint.get("uid", ""))

        if verb == "delete":
            if approved_uid and uid != approved_uid:
                return ReconcileVerdict(OperationState.SUCCEEDED,
                                        "approved object is gone; a different uid now holds the name")
            marked = (metadata.get("annotations") or {}).get(DELETE_MARK) == field_manager(operation_id)
            if metadata.get("deletionTimestamp"):
                return ReconcileVerdict(_UNKNOWN, "target is terminating; finalizers have not completed")
            note = "; it carries this operation's deletion mark, which is harmless residue" if marked else ""
            return ReconcileVerdict(OperationState.FAILED, f"approved object still present at resourceVersion {version}{note}")
        if ours and (verb == "create" or uid == approved_uid):
            return ReconcileVerdict(OperationState.SUCCEEDED,
                                    f"target records this operation's field manager at resourceVersion {version}")
        if verb == "update" and uid == approved_uid and version == str(hint.get("resourceVersion", "")):
            return ReconcileVerdict(OperationState.FAILED,
                                    f"target unchanged at the approved resourceVersion {version}; the update did not land")
        return ReconcileVerdict(_UNKNOWN, "target changed without this operation's field manager; cannot attribute")

    return reconcile
