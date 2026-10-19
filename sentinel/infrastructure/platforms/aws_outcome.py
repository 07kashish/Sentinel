"""Per-operation AWS credentials, and asking CloudTrail whether an operation landed.

CONSTRAINED CREDENTIALS
-----------------------
With `executor_role_arn` set, the configured access key is a BROKER: its only
use is `sts:AssumeRole` on that one role (and `cloudtrail:LookupEvents` for
reconciliation). Every operation assumes the role for fifteen minutes, the
shortest STS allows, under a session name that is the operation's stamp. What
the operation may touch is the role's policy; the long-lived key can change
nothing. The session name is also the attribution: CloudTrail records it as
the caller of everything done with those credentials.

RECONCILIATION
--------------
CloudTrail `LookupEvents`, filtered by that session name, is read for the
operation's event:

    event present, no errorCode ....... succeeded
    event present with an errorCode ... failed (AWS refused it)
    no event .......................... unknown

"No event" is never read as failure: CloudTrail delivery lags by minutes,
`LookupEvents` covers management events only, and an absent record cannot
distinguish "did not happen" from "not recorded". Without a brokered session
there is nothing to correlate on and no reconciler runs at all.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Mapping

from defusedxml import ElementTree

from sentinel.application.operation_context import operation_stamp
from sentinel.application.reconciliation import ReconcileVerdict
from sentinel.domain.operations import OperationState
from sentinel.infrastructure.tool_adapters import ToolAdapterRefused

__all__ = ["aws_hint", "aws_reconciler", "parse_assumed_role"]

_UNKNOWN = OperationState.UNKNOWN_AFTER_EFFECT


def parse_assumed_role(status: int, body: Any) -> dict[str, str]:
    """Temporary credentials from an `AssumeRole` response, or a refusal."""
    if not 200 <= status < 300 or not isinstance(body, str):
        raise ToolAdapterRefused(f"AWS STS did not grant the executor role (HTTP {status})")
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError as exc:
        raise ToolAdapterRefused("AWS STS returned an unreadable AssumeRole response") from exc
    found = {el.tag.rsplit("}", 1)[-1]: (el.text or "") for el in root.iter()}
    wanted = ("AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration")
    if not all(found.get(name) for name in wanted):
        raise ToolAdapterRefused("AWS STS response carried no temporary credentials")
    return {name: found[name] for name in wanted}


def aws_hint(brokered: bool) -> Callable[[Mapping[str, Any]], Mapping[str, Any]]:
    def hint(args: Mapping[str, Any]) -> Mapping[str, Any]:
        action = str(args.get("action", "")).strip()
        if not brokered or ":" not in action:
            return {}
        # The action name only. Parameters are the approved, private payload.
        return {"action": action}
    return hint


def aws_reconciler(
    lookup: Callable[[str], tuple[int, Any]],
) -> Callable[[str, Mapping[str, Any]], ReconcileVerdict]:
    """`lookup(session_name) -> (status, LookupEvents body)`."""

    def reconcile(operation_id: str, hint: Mapping[str, Any]) -> ReconcileVerdict:
        action = str(hint.get("action", ""))
        if ":" not in action:
            return ReconcileVerdict(_UNKNOWN, "the intent recorded no AWS action to look for")
        operation = action.split(":", 1)[1]
        status, body = lookup(operation_stamp(operation_id))
        if status != 200 or not isinstance(body, Mapping):
            return ReconcileVerdict(_UNKNOWN, f"CloudTrail lookup returned HTTP {status}")
        for event in body.get("Events") or ():
            if not isinstance(event, Mapping) or event.get("EventName") != operation:
                continue
            try:
                detail = json.loads(event.get("CloudTrailEvent") or "{}")
            except json.JSONDecodeError:
                detail = {}
            error = str(detail.get("errorCode") or "")
            event_id = str(event.get("EventId") or "")
            if error:
                return ReconcileVerdict(OperationState.FAILED,
                                        f"CloudTrail event {event_id} records {operation} refused: {error[:80]}")
            return ReconcileVerdict(OperationState.SUCCEEDED,
                                    f"CloudTrail event {event_id} records {operation} by this operation's session")
        return ReconcileVerdict(
            _UNKNOWN, "no CloudTrail management event for this operation's session yet; absence is not proof"
        )

    return reconcile
