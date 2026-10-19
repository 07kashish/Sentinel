"""The SDK's decision vocabulary and response shapes, in one dependency-free module.

Split out of `remote.py` so the client module holds transport and parsing
only. Everything here is a value type: no I/O, no state, no imports beyond
the standard library -- which is also why an agent that only needs to READ a
`GateResponse` (a framework adapter, the stdio bridge, a test) can import this
without pulling in the HTTP client.

`Decision` is the server's vocabulary verbatim; see the class docstring for
the one property that matters (no falsy member). `stops_action` is an
allowlist of what PROCEEDS, mirroring `sentinel.domain.protect`, so a decision
the server adds and this SDK has not classified stops by default.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

__all__ = [
    "Authorization",
    "Decision",
    "ExecutionResult",
    "FailureMode",
    "GateResponse",
    "McpProxyReply",
    "SentinelRefused",
    "SentinelUnavailable",
    "UnsafeFailOpenWarning",
]


class SentinelUnavailable(RuntimeError):
    """The gate could not be consulted. NOT a decision.

    A separate exception type rather than a sentinel return value, because a
    return value gets truthiness-tested and an exception does not. Every
    transport, protocol and parse failure in this module ends here.
    """


class SentinelRefused(RuntimeError):
    """Sentinel answered, and the answer was no. A DECISION, not an outage.

    Raised by `execute` when the inline proxy refused to run the tool (HTTP
    403). Kept distinct from `SentinelUnavailable` so a caller can tell "the
    gate said no" from "nobody answered" -- collapsing them is how an outage
    becomes a deny somebody retries around.
    """

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


class UnsafeFailOpenWarning(UserWarning):
    """Raised on every allow granted because the gate was unreachable.

    Every time, not once. A control that has silently stopped working is
    precisely the thing nobody notices, and a warning that fires once per
    process is a warning that scrolled past during startup.
    """


class Decision(str, Enum):
    """What the gate said. The server's vocabulary, verbatim.

    NO FALSY MEMBER, and the class defines no `__bool__`. `if decision:` must
    not be the way anybody reads this -- every member is a non-empty string, so
    a truthiness test is always True and a caller who writes one gets a bug
    that always allows.
    """

    ALLOW = "allow"
    WARN = "warn"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"
    #: Proceed, but the caller must redact the tool's output before the model
    #: sees it. The action HAPPENS; the response is transformed on the way back.
    ALLOW_WITH_REDACTION = "allow_with_redaction"
    #: Stop until the human re-authenticates.
    STEP_UP_AUTH = "step_up_auth"
    #: Stop until a short-lived credential is issued for this specific action.
    REQUIRE_JIT_CREDENTIAL = "require_jit_credential"
    #: Stop AND contain: an actor to remove, not a call to refuse.
    CONTAIN = "contain"

    @property
    def stops_action(self) -> bool:
        """Whether the caller must NOT proceed.

        An allowlist of the decisions that PROCEED, not a list of the ones that
        stop -- the same inversion as the server's `ProtectDecision`. A
        decision added and forgotten here stops by default, which is the safe
        direction for that bug.
        """
        return self not in _PROCEEDS

    @property
    def permits_execution(self) -> bool:
        """Spelled out, so the check reads as a decision and not as a cast."""
        return not self.stops_action

    @property
    def requires_redaction(self) -> bool:
        return self is Decision.ALLOW_WITH_REDACTION

    @property
    def requires_human(self) -> bool:
        """Stops, and a PERSON must act before it can proceed."""
        return self in _NEEDS_A_HUMAN


#: The decisions under which the action MAY proceed. Everything else stops.
_PROCEEDS: frozenset[Decision] = frozenset(
    {Decision.ALLOW, Decision.WARN, Decision.ALLOW_WITH_REDACTION}
)

_NEEDS_A_HUMAN: frozenset[Decision] = frozenset(
    {Decision.REQUIRE_APPROVAL, Decision.STEP_UP_AUTH, Decision.CONTAIN}
)


class FailureMode(str, Enum):
    """What to do when the gate cannot be reached."""

    #: Raise. The default, and the only safe choice for anything with a side
    #: effect.
    REFUSE = "refuse"
    #: Allow, warn loudly, and record that the decision was never made. For
    #: deployments that genuinely prefer availability to enforcement.
    ALLOW_AND_RECORD = "allow_and_record"


@dataclass(frozen=True, slots=True)
class Authorization:
    """An execution binding the gate issued alongside an allow.

    `token` is what `POST /v1/tools/execute` consumes; the rest is what the
    token commits to, so a caller can check the digest of the parameters it is
    about to send against the digest that was approved BEFORE the network
    round trip tells it they differ.
    """

    token: str
    authorization_id: str = ""
    expires_at: str = ""
    approved_parameter_digest: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "authorization_id": self.authorization_id,
            "expires_at": self.expires_at,
            "approved_parameter_digest": self.approved_parameter_digest,
        }


@dataclass(frozen=True, slots=True)
class GateResponse:
    """One decision, and whether it was actually made by the gate.

    `consulted` is the field that matters. A response produced by fail-open has
    `consulted=False`, so a caller logging or auditing these can tell an allow
    the gate issued from an allow the network issued.
    """

    decision: Decision
    #: False when the gate was never reached and the mode allowed anyway.
    consulted: bool = True
    reason: str = ""
    incident_id: str = ""
    request_id: str = ""
    #: True only when the deployment enforces AND the decision stops. An
    #: advisory deployment never claims enforcement, even on `block`.
    enforced: bool = False
    severity: int = 0
    capped_severity: int = 0
    detector_version: str = ""
    matched_rules: tuple[str, ...] = ()
    authorization: Authorization | None = None

    @property
    def stops_action(self) -> bool:
        return self.decision.stops_action

    @property
    def permits_execution(self) -> bool:
        return self.decision.permits_execution

    @property
    def requires_redaction(self) -> bool:
        return self.decision.requires_redaction

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "consulted": self.consulted,
            "reason": self.reason,
            "incident_id": self.incident_id,
            "request_id": self.request_id,
            "enforced": self.enforced,
            "severity": self.severity,
            "capped_severity": self.capped_severity,
            "detector_version": self.detector_version,
            "matched_rules": list(self.matched_rules),
            "authorization": (
                self.authorization.as_dict() if self.authorization else None
            ),
        }


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """What `POST /v1/tools/execute` returned: the tool ran, and this is proof.

    `protect` is the decision the proxy made before running the tool. `receipt`
    is the execution-binding receipt when one was issued, and `capability` the
    grant check -- both are the server's documents, passed through unchanged
    so a caller can forward evidence it did not have to interpret.
    """

    tool: str
    result: Any
    protect: GateResponse
    receipt: Mapping[str, Any] | None = None
    capability: Mapping[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class McpProxyReply:
    """One answer from `POST /v1/mcp/proxy/{server_id}`, transport included.

    The MCP proxy is not a decision endpoint: it relays JSON-RPC, answers a
    notification with an empty 202, and relays an upstream authorization
    challenge as a bare 401/403 with `WWW-Authenticate`. All three shapes are
    represented rather than collapsed, because the stdio wrapper has to turn
    each into a different thing on the wire.
    """

    status: int
    message: Mapping[str, Any] | None
    session_id: str = ""
    www_authenticate: str = ""
