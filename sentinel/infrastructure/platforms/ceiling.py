"""The containment every Tier-1 platform adapter shares.

WHAT A CEILING IS, AND WHY IT IS NOT POLICY
--------------------------------------------
Each adapter carries a `ceiling`: the highest semantic tier it will perform.
This is CONTAINMENT, not policy, and the distinction is the one `FileSandbox`
draws in `tool_adapters.py`.

`ProtectGate` decides whether an action is permitted given what it was TOLD --
an action string, a resource, some prompt text. The ceiling decides what the
adapter will do given what the request RESOLVED to, and it is checked after the
gate has already said ALLOW. An ALLOW means "policy permits this action". It has
never meant "this is inside the blast radius the operator granted these
credentials", and treating those as the same sentence is how a prompt injection
that talks the gate into one ALLOW gets to create an IAM access key.

An operator who wants agents to read from IAM and never write sets the ceiling
to `low` and gets a hard stop that survives a policy misconfiguration, an
injection, and a rule someone deleted last Tuesday.

UNCLASSIFIABLE IS REFUSED
-------------------------
`classify_or_refuse` refuses when `action_semantics` returns None. That is the
opposite of the usual default and it is deliberate: the ceiling is the only
containment these adapters have, and an action nobody could classify cannot be
checked against it. "We could not tell what this does, so we did it" is not a
sentence an incident review should ever have to read.
"""

from __future__ import annotations

import json
from typing import Any, Mapping

from sentinel.domain.action_semantics import OperationSemantics, classify_action
from sentinel.infrastructure.outbound import (
    HardenedHttpClient,
    OutboundRefused,
    OutboundUnavailable,
)
from sentinel.infrastructure.tool_adapters import (
    ToolAdapterNotAttempted,
    ToolAdapterRefused,
    ToolAdapterRejectedByTarget,
)

__all__ = [
    "DEFAULT_CEILING",
    "MAX_RESULT_BYTES",
    "TIERS",
    "bounded",
    "classify_or_refuse",
    "enforce_ceiling",
    "hardened_call",
    "normalise_ceiling",
]

#: Tier ordering, lowest to highest. Mirrors `action_semantics._TIERS`, which is
#: private there; restated rather than imported so a change to the domain's
#: private ordering cannot silently re-rank what an adapter will execute.
TIERS: tuple[str, ...] = ("low", "moderate", "high", "critical")

#: The default ceiling. `low` means read-only operations only. Chosen because
#: the alternative default -- whatever the credential happens to be able to do --
#: is how an agent ends up with `iam:CreateAccessKey` on its first day. Raising
#: it is one setting and a deliberate act.
DEFAULT_CEILING = "low"

#: Cap on the serialised size of any adapter result. Results travel back through
#: the API response and into an incident's evidence; an unbounded one is a
#: memory-exhaustion primitive and an exfiltration primitive at once.
MAX_RESULT_BYTES = 1_048_576


def _rank(tier: str) -> int:
    try:
        return TIERS.index(tier)
    except ValueError:
        # An unrecognised tier ranks as critical, not as low. The only way to
        # reach this is a classifier change that adds a tier this module has not
        # been taught, and the safe reading of an unknown severity is the worst
        # one.
        return len(TIERS) - 1


def normalise_ceiling(ceiling: str) -> str:
    value = (ceiling or "").strip().lower()
    if value not in TIERS:
        raise ToolAdapterRefused(
            f"ceiling {ceiling!r} is not one of {'/'.join(TIERS)}; refusing to "
            "build an adapter whose containment limit nobody can read"
        )
    return value


def classify_or_refuse(
    *, platform: str, action: str, resource: str, metadata: Mapping[str, Any]
) -> OperationSemantics:
    """Classify the request, or refuse it. Never returns an unclassified pass."""
    semantics = classify_action(
        {"action": action, "resource": resource, "metadata": dict(metadata)}
    )
    if semantics is None:
        raise ToolAdapterRefused(
            f"{platform}: {action!r} against {resource!r} did not classify as a "
            "recognised operation. Refused, because the tier ceiling is this "
            "adapter's only containment and an unclassified action cannot be "
            "checked against it."
        )
    if semantics.platform != platform:
        # A GitHub-shaped request that came back classified as Kubernetes means
        # the inputs reached the wrong grammar -- a repository named `job` is
        # enough to do it -- and the tier returned describes an operation on a
        # different platform than the one about to be called. Enforcing a
        # ceiling against that is enforcing it against the wrong question.
        raise ToolAdapterRefused(
            f"{platform}: request classified as {semantics.platform!r}, not "
            f"{platform!r}. Refusing rather than enforcing the ceiling against "
            "a classification of the wrong platform."
        )
    return semantics


def enforce_ceiling(semantics: OperationSemantics, ceiling: str) -> None:
    if _rank(semantics.tier) > _rank(ceiling):
        raise ToolAdapterRefused(
            f"{semantics.platform}: {semantics.operation!r} classifies as "
            f"{semantics.category}/{semantics.tier} "
            f"({'; '.join(semantics.reasons) or 'no reason recorded'}), above "
            f"this adapter's {ceiling!r} ceiling. Refused after the gate "
            "allowed it: the gate judged the request as described, this checks "
            "what it resolved to."
        )


def bounded(payload: Any) -> Any:
    """Refuse a result too large to carry into a response and into evidence."""
    try:
        size = len(json.dumps(payload, default=str).encode("utf-8"))
    except (TypeError, ValueError):  # pragma: no cover - defensive
        raise ToolAdapterRefused("adapter result was not serialisable") from None
    if size > MAX_RESULT_BYTES:
        raise ToolAdapterRefused(
            f"adapter result is {size} bytes, over the {MAX_RESULT_BYTES}-byte "
            "limit; refusing to carry an unbounded result into evidence"
        )
    return payload


def hardened_call(
    client: HardenedHttpClient,
    *,
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes | None,
) -> dict[str, Any]:
    """One hardened request, with both failure modes turned into refusals.

    `OutboundUnavailable` becomes a refusal rather than staying transient on
    purpose. A half-performed platform mutation retried by an agent is worse
    than one that did not happen: the caller re-decides with a fresh gate
    evaluation, and the adapter never retries a side effect on its own.
    """
    try:
        response = client.request(
            method=method,
            url=url,
            headers=dict(headers),
            body=body,
            idempotent=method in {"GET", "HEAD"},
        )
    except OutboundRefused as exc:
        raise ToolAdapterRefused(f"outbound request refused: {exc}") from exc
    except OutboundUnavailable as exc:
        raise ToolAdapterRefused(f"destination unreachable: {exc}") from exc

    text = response.body.decode("utf-8", errors="replace")
    parsed: Any = None
    if text.strip().startswith(("{", "[")):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
    return {
        "status": response.status,
        # The address actually dialled. "we called GitHub" is not an auditable
        # statement; "we connected to 140.82.121.6:443" is.
        "peer": response.peer,
        "body": parsed if parsed is not None else text,
    }


def no_effect_possible(run: Any) -> Any:
    """Wrap an adapter runner whose every refusal PRECEDES any mutation.

    For a runner that only reads -- a SQL adapter inside a READ ONLY
    transaction -- no failure can leave an effect behind, so every refusal is
    a known absence and the operation is FAILED rather than unknown.
    """
    def guarded(args: Mapping[str, Any]) -> Any:
        try:
            return run(args)
        except ToolAdapterNotAttempted:
            raise
        except ToolAdapterRefused as exc:
            raise ToolAdapterNotAttempted(str(exc)) from exc

    return guarded


def settle(
    result: Mapping[str, Any], semantics: OperationSemantics, *, platform: str
) -> Mapping[str, Any]:
    """Turn a mutation's HTTP status into the outcome it actually proves.

    A READ returns whatever the platform said; a 404 is an answer, and a read
    changes nothing. For anything else: 2xx is the effect confirmed; 4xx is
    the platform REFUSING it, which is proof it did not happen; and a 5xx
    proves nothing either way, so it stays an unknown outcome for the
    reconciler. Returning a 4xx or 5xx as a normal result recorded a failed
    change as a succeeded operation with a receipt.
    """
    status = int(result.get("status", 0))
    if semantics.category == "read" or 200 <= status < 300:
        return result
    if 400 <= status < 500:
        raise ToolAdapterRejectedByTarget(
            f"{platform} refused the operation (HTTP {status}); nothing was changed"
        )
    raise ToolAdapterRefused(f"{platform} did not confirm the operation (HTTP {status})")


def call_settled(
    client: HardenedHttpClient, semantics: OperationSemantics, *, platform: str, **request: Any
) -> Mapping[str, Any]:
    """`hardened_call` plus `settle`, with a failed READ marked as a known absence."""
    try:
        return settle(hardened_call(client, **request), semantics, platform=platform)
    except ToolAdapterRejectedByTarget:
        raise
    except ToolAdapterRefused as exc:
        if semantics.category == "read":
            raise ToolAdapterNotAttempted(f"{exc} (a read; nothing could have changed)") from exc
        raise
