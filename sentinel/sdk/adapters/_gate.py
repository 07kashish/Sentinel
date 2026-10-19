"""The shared core every adapter runs a tool call through.

ONE RULE
--------
The tool does not run unless the gate said it may. That is enforced by shape:
`gate()` either returns a `GatedCall` or raises. `GateRefused` when the gate
answered with a stop decision; `SentinelUnavailable` (from the client) when it
could not be consulted; `NotCanonical` when the arguments cannot be given the
canonical form the server digests. There is no return value that means "not
sure", so an adapter cannot fall through to the tool on a failure it forgot
to handle.

THE CANONICALISER IS COPIED, NOT IMPORTED
-----------------------------------------
`canonical_bytes`, `digest_of` and `parameter_digest` are transcriptions of
`sentinel.domain.passport` and `sentinel.domain.execution_binding`. Copied,
because the SDK must import nothing but the standard library and this package
-- a customer's agent runtime is not the place for the domain package -- and
because the digest an adapter sends MUST be the digest the server computes, so
the two are pinned to each other by `tests_arch/test_sdk_gate_canonical.py`,
which asserts byte-equality against the domain versions over a fixed corpus.
When one changes, that test is what says so.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from sentinel.sdk.remote import Authorization, GateResponse, SentinelClient

__all__ = [
    "PARAMETER_CONTEXT",
    "GateRefused",
    "GatedCall",
    "NotCanonical",
    "canonical_bytes",
    "digest_of",
    "gate",
    "parameter_digest",
    "run_gated",
]

#: Prepended to parameters before hashing so a parameter digest can never be
#: mistaken for a digest of a passport or an authorization. Must match
#: `sentinel.domain.execution_binding.PARAMETER_CONTEXT` byte for byte.
PARAMETER_CONTEXT = "sentinel.execution.parameters.v1"

#: Largest integer an IEEE-754 double holds exactly: 2**53 - 1. Python has no
#: bound; every other runtime a digest may be recomputed in does.
_MAX_EXACT_INT = 2**53 - 1


class NotCanonical(ValueError):
    """The arguments have no canonical JSON form, so no digest can be honest.

    Floats are the usual cause. Convert them at the edge -- to an integer, or
    to a string -- where the conversion is visible, rather than letting a
    digest be computed over a representation the server may not share.
    """


class GateRefused(RuntimeError):
    """The gate answered, and the answer stops the action.

    Carries the full `GateResponse` so a host can tell `require_approval`
    from `contain` and act accordingly: one waits for a person, the other
    removes an actor.
    """

    def __init__(self, response: GateResponse, *, tool: str) -> None:
        super().__init__(
            f"Sentinel stopped tool {tool!r}: {response.decision.value}"
            + (f" ({response.reason})" if response.reason else "")
        )
        self.response = response
        self.tool = tool


@dataclass(frozen=True, slots=True)
class GatedCall:
    """A tool call the gate permitted, with the arguments it permitted."""

    tool: str
    action: str
    arguments: Mapping[str, Any]
    parameter_digest: str
    response: GateResponse

    @property
    def requires_redaction(self) -> bool:
        return self.response.requires_redaction

    @property
    def authorization(self) -> Authorization | None:
        return self.response.authorization


# ── canonical form (transcribed from sentinel.domain.passport) ──────────────


def _check_canonical(value: Any, *, path: str = "$") -> None:
    if isinstance(value, float):
        raise NotCanonical(
            f"{path}: floats are refused. 0.1 + 0.2 does not round-trip, so a "
            "score serialising as 96.00000000000001 here and 96.0 elsewhere "
            "would produce two signatures for one passport. Use an integer."
        )
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > _MAX_EXACT_INT:
            raise NotCanonical(
                f"{path}: {value} is outside the range an integer survives a "
                f"JSON round trip in (+/-{_MAX_EXACT_INT}). Beyond that a "
                "double cannot hold it exactly, so a verifier using one would "
                "compute a different digest than this one did. Use a string."
            )
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise NotCanonical(f"{path}: object keys must be strings")
            _check_canonical(item, path=f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _check_canonical(item, path=f"{path}[{index}]")
    elif not isinstance(value, (str, int, bool, type(None))):
        raise NotCanonical(
            f"{path}: {type(value).__name__} has no canonical JSON form. "
            "Convert it at the edge, where the conversion is visible."
        )


def canonical_bytes(document: Mapping[str, Any]) -> bytes:
    """The exact bytes a digest covers: sorted keys, no whitespace, no escaping."""
    _check_canonical(document)
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def digest_of(document: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(document)).hexdigest()


def parameter_digest(parameters: Mapping[str, Any]) -> str:
    """The digest an authorization commits to, and execution is checked against."""
    return digest_of({"context": PARAMETER_CONTEXT, "parameters": dict(parameters)})


# ── the gate ────────────────────────────────────────────────────────────────


def gate(
    client: SentinelClient,
    *,
    agent_id: str,
    tool: str,
    arguments: Mapping[str, Any] | None,
    action: str = "",
    resource: str = "",
    metadata: Mapping[str, Any] | None = None,
    trust_level: str = "",
) -> GatedCall:
    """Consult the gate for one tool call. Returns only when it may proceed.

    The parameter digest is computed BEFORE the request and sent in the
    metadata, so the server's record of what was asked and the client's record
    of what it was about to do are the same digest -- and so a `NotCanonical`
    argument set fails here, on the caller, with a path to the field, rather
    than at the proxy with a 400.
    """
    if not str(tool).strip():
        raise ValueError("a tool call needs a tool name")
    if arguments is None:
        canonical: dict[str, Any] = {}
    elif isinstance(arguments, Mapping):
        canonical = dict(arguments)
    else:
        raise NotCanonical(
            f"tool arguments must be an object, not {type(arguments).__name__}"
        )
    digest = parameter_digest(canonical)
    response = client.check(
        agent_id=agent_id,
        action=action or tool,
        resource=resource,
        tool=tool,
        arguments=canonical,
        metadata={**dict(metadata or {}), "parameter_digest": digest},
        trust_level=trust_level,
    )
    if response.stops_action:
        raise GateRefused(response, tool=tool)
    return GatedCall(
        tool=tool,
        action=action or tool,
        arguments=canonical,
        parameter_digest=digest,
        response=response,
    )


def run_gated(
    client: SentinelClient,
    *,
    agent_id: str,
    tool: str,
    arguments: Mapping[str, Any] | None,
    invoke: Callable[[Mapping[str, Any]], Any],
    action: str = "",
    resource: str = "",
    metadata: Mapping[str, Any] | None = None,
    trust_level: str = "",
    execute_remotely: bool = False,
) -> Any:
    """Gate, then run: locally through `invoke`, or through Sentinel's proxy.

    `execute_remotely=True` sends the call to `POST /v1/tools/execute` with
    whatever authorization the gate issued, and the proxy runs the registered
    side effect. That is the path with a receipt. When False the tool runs in
    this process, after the gate and with the arguments the gate saw.
    """
    call = gate(
        client,
        agent_id=agent_id,
        tool=tool,
        arguments=arguments,
        action=action,
        resource=resource,
        metadata=metadata,
        trust_level=trust_level,
    )
    if execute_remotely:
        return client.execute(
            agent_id=agent_id,
            tool=tool,
            action=call.action,
            arguments=call.arguments,
            resource=resource,
            metadata=metadata,
            trust_level=trust_level or "unsigned",
            authorization=call.authorization,
        ).result
    return invoke(call.arguments)
