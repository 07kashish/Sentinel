"""The client an agent outside this process imports to reach a deployed Sentinel.

WHAT THIS IS FOR
----------------
`ProtectClient` in this package wraps an IN-PROCESS gate: the agent and the
authorization logic share a Python process. That is the wrong shape for most
deployments, where the agent runs in a customer's own runtime and Sentinel runs
somewhere else. This is the HTTP client for that case.

THE ONE PROPERTY THAT MATTERS MORE THAN THE REST
-------------------------------------------------
**A network error must never look like an allow.**

This is the failure that turns a security control into decoration. The gate is
unreachable -- DNS fails, the deployment is mid-rollout, a certificate expired,
a proxy returns a 502 HTML page -- and the client returns something falsy, or
None, or an empty dict, and the calling agent reads "not denied" and proceeds.
Every request during the outage is permitted, nothing is recorded, and the
graphs look quiet because no events arrived.

So every failure path in this module RAISES `SentinelUnavailable`. There is no
return value that can be mistaken for a decision:

  * connection refused, DNS failure, timeout -> raise
  * any 5xx -> raise
  * a body that is not JSON, or JSON without a decision -> raise
  * an unrecognised decision string -> raise
  * an `authorization` object this client cannot use -> raise
  * ANY REDIRECT -> raise, by `HardenedHttpClient`. This is the one that
    matters most and the one I got wrong first: `urllib.request.urlopen`
    follows redirects AND forwards the Authorization header to the target.
    That has already been proven against this codebase -- a 302 to a loopback
    address received an attestation bearer token. So a redirect here would
    have handed the customer's API key to whoever answered it, and returned
    that server's `{"decision": "allow"}` as a decision from the gate.

`Decision` deliberately has NO falsy member and no `__bool__`, so
`if client.check(...)` is a type error rather than a subtle allow.

THE DECISION VOCABULARY IS THE SERVER'S, ALL EIGHT OF IT
--------------------------------------------------------
The gate answers with one of `allow`, `warn`, `allow_with_redaction`,
`require_approval`, `block`, `step_up_auth`, `require_jit_credential` or
`contain` -- the vocabulary of `sentinel.domain.protect.ProtectDecision`. An
earlier client knew three of those and raised on the other five, which was
fail-closed but also meant a deployment that turned on redaction stopped
working for every SDK caller. `Decision.stops_action` mirrors the server's
rule exactly: the three that PROCEED are listed, and anything else stops, so a
decision added to the server and not yet classified here stops by default.

An authorization may ride with an allow. When the server has issued an
execution binding -- a single-use token committing to the tool, the action and
a digest of the approved parameters -- it arrives as an `authorization` object
and is parsed into `GateResponse.authorization`, to be presented back to
`POST /v1/tools/execute` through `SentinelClient.execute`.

FAIL-OPEN IS AVAILABLE AND IS NAMED HONESTLY
---------------------------------------------
Some deployments genuinely prefer availability over enforcement -- a recommender
that must not stop serving. They may pass
`on_unreachable=FailureMode.ALLOW_AND_RECORD`, which is spelled out rather than
called "graceful degradation", requires a written `fail_open_reason`, and emits
a warning on EVERY use rather than once, because a control that has silently
stopped working is exactly the thing nobody notices.

The default is `FailureMode.REFUSE`. A caller who configures nothing gets the
safe behaviour. Fail-open covers `check` ONLY: `execute` asks Sentinel to
perform a side effect, and there is no local fallback for a side effect the
remote proxy did not run.

WHAT THIS DOES NOT DO
---------------------
No auto-instrumentation on import. No global state. No retries on anything
non-idempotent -- retrying a side-effecting call after a timeout is how one
containment becomes three.

TRANSPORT
---------
`HardenedHttpClient`, not `urllib`. An earlier version of this module used
`urllib.request` directly and claimed "stdlib only, so installing the SDK
cannot drag a dependency into a customer's runtime". The stdlib-only claim is
now TRUE -- `sentinel/sdk/__init__.py` is lazy and `outbound.py` imports only
the standard library -- but it was never a reason to give up the defences in
`outbound.py`: redirect refusal, post-resolution address validation against
DNS rebinding, connection pinning, bounded bodies.

Loopback still works for local development, as an explicit
`allow_private_destinations` grant narrowed to the single configured host.
That is the control the policy documentation says to reach for, rather than a
hand-written scheme check.
"""

from __future__ import annotations

import json
import warnings
from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import urlsplit

from sentinel.infrastructure.outbound import (
    HardenedHttpClient,
    OutboundPolicy,
    OutboundRefused,
    OutboundResponse,
    OutboundUnavailable,
)

__all__ = [
    "Authorization",
    "Decision",
    "ExecutionResult",
    "FailureMode",
    "GateResponse",
    "McpProxyReply",
    "SentinelClient",
    "SentinelRefused",
    "SentinelUnavailable",
    "UnsafeFailOpenWarning",
    "transport_for",
]


from sentinel.sdk.models import (
    Authorization,
    Decision,
    ExecutionResult,
    FailureMode,
    GateResponse,
    McpProxyReply,
    SentinelRefused,
    SentinelUnavailable,
    UnsafeFailOpenWarning,
)

#: Statuses that mean "the gate answered".
#:
#: `/v1/protect/evaluate` answers 200 for every decision including `block`; a
#: 403 is kept because an ENFORCED refusal may one day be reported that way,
#: and it would still be a decision. 409 is gone: nothing on the protect route
#: emits it, and a status that carries no decision must be treated as an
#: outage rather than guessed at. A 502 is an OUTAGE, and collapsing it with
#: a decision status is how an outage becomes a deny that somebody retries
#: around, or -- far worse -- an outage becomes an allow.
_DECISION_STATUSES = frozenset({200, 403})

_MAX_BODY_BYTES = 256 * 1024

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def transport_for(base_url: str, *, timeout_seconds: float) -> HardenedHttpClient:
    """The hardened client for one Sentinel base URL, built fresh each time.

    `http` is added ONLY for loopback -- `SentinelClient.__post_init__` has
    already refused plaintext to a remote host, so this cannot widen anything
    a caller did not already ask for. Private destinations are a deliberate,
    narrow grant: permitted only for loopback development, and narrowed to
    the single configured host rather than all of RFC1918.
    """
    host = (urlsplit(base_url).hostname or "").lower()
    loopback = host in _LOOPBACK_HOSTS
    return HardenedHttpClient(
        policy=OutboundPolicy(
            allowed_schemes=(
                frozenset({"https", "http"}) if loopback else frozenset({"https"})
            ),
            allow_private_destinations=loopback,
            allowed_hosts=frozenset({host}) if loopback else frozenset(),
            max_response_bytes=_MAX_BODY_BYTES,
            connect_timeout_seconds=timeout_seconds,
            read_timeout_seconds=timeout_seconds,
        )
    )


@dataclass(frozen=True, slots=True)
class SentinelClient:
    """Consults a deployed Sentinel over HTTP. Raises rather than guessing.

    Frozen, and holds no mutable state, so one client can be shared across
    threads without one caller's configuration leaking into another's request.
    """

    base_url: str
    api_key: str
    timeout_seconds: float = 5.0
    on_unreachable: FailureMode = FailureMode.REFUSE
    #: Required when `on_unreachable` is ALLOW_AND_RECORD. A deployment that
    #: turns enforcement off must say why, in a string that appears in the
    #: warning, so the next person reading the logs learns it was deliberate.
    fail_open_reason: str = ""
    verify_tls: bool = True
    #: Injected in tests so the suite drives the real request construction,
    #: header handling and parsing without a network -- the same reason
    #: `HardenedHttpClient` takes a `connection_factory`.
    _transport: Any = field(default=None, compare=False)

    def __post_init__(self) -> None:
        parts = urlsplit(self.base_url)
        if parts.scheme not in {"http", "https"}:
            raise ValueError(
                f"base_url {self.base_url!r} must be http or https; a client "
                "that accepted any scheme could be pointed at a file:// or "
                "gopher:// URL by configuration"
            )
        if not parts.netloc:
            raise ValueError(f"base_url {self.base_url!r} names no host")
        if parts.scheme == "http" and parts.hostname not in _LOOPBACK_HOSTS:
            raise ValueError(
                f"base_url {self.base_url!r} is plaintext HTTP to a remote "
                "host. The API key would cross the network in the clear on "
                "every call; refusing rather than warning, because a warning "
                "would be configured once and never read again."
            )
        if not self.api_key.strip():
            raise ValueError(
                "no api_key. An unauthenticated client cannot be attributed to "
                "a tenant, and Sentinel derives the tenant from the credential "
                "rather than from the request body."
            )
        if (
            self.on_unreachable is FailureMode.ALLOW_AND_RECORD
            and not self.fail_open_reason.strip()
        ):
            raise ValueError(
                "on_unreachable=ALLOW_AND_RECORD requires a fail_open_reason. "
                "Turning enforcement off during an outage is a decision "
                "somebody made; it belongs in writing, in the warning, where "
                "the next person reading the logs will see it."
            )
        if not self.verify_tls:
            raise ValueError(
                "verify_tls=False is not supported. A client that skips "
                "certificate verification will accept a decision from anything "
                "that answers on the port, which makes the gate forgeable by "
                "anyone on the path -- and an ALLOW is the forgery they want."
            )
        if self.timeout_seconds <= 0:
            raise ValueError(
                f"timeout_seconds={self.timeout_seconds} would let a call to "
                "the gate hang indefinitely, which is an outage that looks "
                "like a slow agent"
            )

    # ── the calls ───────────────────────────────────────────────────────────

    def check(
        self,
        *,
        agent_id: str,
        action: str = "",
        resource: str = "",
        tool: str = "",
        arguments: Mapping[str, Any] | None = None,
        metadata: Mapping[str, Any] | None = None,
        trust_level: str = "",
        event_type: str = "tool_call",
    ) -> GateResponse:
        """Ask the gate whether this action may proceed.

        `tool` and `arguments` are TOP-LEVEL fields, which is what
        `ProtectPayload` declares and what the route binds the authorization
        to. This client used to tuck them inside `metadata` -- correct for an
        older route. The current one takes its arguments ONLY from the
        top-level field, so the policy was shown an empty argument set and the
        authorization committed to the digest of nothing: every later
        `execute` with real arguments was refused. `trust_level` is accepted
        for source compatibility and NOT sent: the server refuses a
        caller-asserted trust outright and derives it from the credential.

        Raises `SentinelUnavailable` on ANY failure to obtain a decision, unless
        the client was explicitly configured to fail open. There is no return
        value meaning "could not tell".
        """
        if not (action or tool):
            raise ValueError("check() needs an action or a tool name")
        payload: dict[str, Any] = {
            "agentId": agent_id,
            "eventType": event_type,
            "action": action or tool,
            "resource": resource,
            "metadata": dict(metadata or {}),
        }
        if tool:
            payload["tool"] = tool
        if arguments is not None:
            payload["arguments"] = dict(arguments)

        try:
            status, body = self._post("/v1/protect/evaluate", payload)
        except SentinelUnavailable as unavailable:
            return self._handle_unreachable(unavailable, action=action or tool)

        return _parse_decision(status, body)

    def execute(
        self,
        *,
        agent_id: str,
        tool: str,
        action: str = "",
        arguments: Mapping[str, Any] | None = None,
        resource: str = "",
        metadata: Mapping[str, Any] | None = None,
        trust_level: str = "unsigned",
        authorization: Authorization | str | None = None,
    ) -> ExecutionResult:
        """Have Sentinel's inline proxy run the tool, presenting an authorization.

        Never fails open. A side effect the proxy did not perform has no local
        substitute, so an unreachable Sentinel raises regardless of
        `on_unreachable`. A 403 raises `SentinelRefused` -- the proxy answered
        and refused -- which is a different thing from an outage and is typed
        differently so nobody retries around it.
        """
        if not tool.strip():
            raise ValueError("execute() needs a tool name")
        payload: dict[str, Any] = {
            "agentId": agent_id,
            "tool": tool,
            # No `trustLevel`: the route refuses any body that carries one.
            "arguments": dict(arguments or {}),
            "resource": resource,
            "action": action or tool,
            "metadata": dict(metadata or {}),
        }
        token = (
            authorization.token
            if isinstance(authorization, Authorization)
            else str(authorization or "")
        )
        if token:
            # THE TOKEN ITSELF, a string -- which is what `ToolExecutePayload`
            # declares. This used to send `{"token": ...}`, the shape the gate
            # RETURNS, and the real route answered 422: bound execution through
            # this client never worked against a real server. Every test used a
            # fake transport that accepted either. Found by the first live run
            # of the JavaScript client, which had copied the mistake.
            payload["authorization"] = token

        status, body = self._post("/v1/tools/execute", payload)
        if status == 403:
            raise SentinelRefused(str(body.get("detail", body)))
        if status != 200:
            raise SentinelUnavailable(
                f"the inline proxy answered {status}, which is neither a result "
                "nor a refusal. Treated as an outage rather than guessed at."
            )
        protect = body.get("protect")
        if not isinstance(protect, Mapping):
            raise SentinelUnavailable(
                "the inline proxy returned a result with no protect decision "
                "attached; a result nobody decided on is not one this client "
                "will hand back as if somebody had"
            )
        receipt = body.get("receipt")
        capability = body.get("capability")
        return ExecutionResult(
            tool=str(body.get("tool", tool)),
            result=body.get("result"),
            protect=_parse_decision(200, protect),
            receipt=receipt if isinstance(receipt, Mapping) else None,
            capability=capability if isinstance(capability, Mapping) else None,
        )

    def forward_mcp(
        self,
        *,
        server_id: str,
        message: bytes,
        agent_id: str,
        principal: str = "",
        session_id: str = "",
        trust_level: str = "",
        mcp_session_id: str = "",
        upstream_authorization: str = "",
    ) -> McpProxyReply:
        """Relay one JSON-RPC message through `POST /v1/mcp/proxy/{server_id}`.

        `message` is bytes, forwarded verbatim: the proxy's contract is that the
        forwarded message is untouched, and a re-serialisation here could not
        promise that. Transport failures raise `SentinelUnavailable`; every
        HTTP answer -- including 4xx and 5xx -- is returned for the caller to
        turn into the in-band error its own protocol needs.
        """
        if not server_id.strip() or "/" in server_id:
            raise ValueError(f"server_id {server_id!r} is not a single path segment")
        headers = {"x-sentinel-agent-id": agent_id}
        if principal:
            headers["x-sentinel-principal"] = principal
        if session_id:
            headers["x-sentinel-session-id"] = session_id
        if trust_level:
            headers["x-sentinel-trust-level"] = trust_level
        if mcp_session_id:
            headers["mcp-session-id"] = mcp_session_id
        if upstream_authorization:
            headers["x-sentinel-upstream-authorization"] = upstream_authorization

        response = self._request(f"/v1/mcp/proxy/{server_id}", message, headers)
        decoded: Mapping[str, Any] | None = None
        if response.status == 200 and response.body.strip():
            try:
                parsed = response.json()
            except OutboundRefused as error:
                raise SentinelUnavailable(
                    f"the MCP proxy answered 200 with a body that is not JSON "
                    f"({error}); this is a proxy or load balancer error page"
                ) from error
            if not isinstance(parsed, Mapping):
                raise SentinelUnavailable(
                    "the MCP proxy answered with a JSON "
                    f"{type(parsed).__name__}, not a JSON-RPC object"
                )
            decoded = parsed
        return McpProxyReply(
            status=int(response.status),
            message=decoded,
            session_id=str(response.headers.get("mcp-session-id", "")),
            www_authenticate=str(response.headers.get("www-authenticate", "")),
        )

    def submit_event(self, event: Mapping[str, Any]) -> str:
        """Record one event. Returns the server's event id.

        NOT retried. An event submission is not idempotent unless the caller
        supplies a stable `eventId`, and retrying without one turns a timeout
        into a duplicate incident.
        """
        status, body = self._post("/v1/events", dict(event))
        if status >= 400:
            raise SentinelUnavailable(
                f"event submission returned {status}. The event was NOT "
                "recorded, and this is raised rather than returned so a caller "
                "cannot mistake a dropped event for a quiet estate."
            )
        identifier = body.get("eventId") or body.get("event_id") or ""
        return str(identifier)

    # ── transport ───────────────────────────────────────────────────────────

    def _request(
        self,
        path: str,
        body: bytes,
        extra_headers: Mapping[str, str] | None = None,
    ) -> OutboundResponse:
        """One POST through the hardened client. Raises on transport failure."""
        url = self.base_url.rstrip("/") + path
        headers = {
            "content-type": "application/json",
            # The key travels in a HEADER, never in the URL: a URL reaches
            # access logs, proxy logs and error trackers. The hardened client
            # refuses redirects, so it is not forwarded anywhere either --
            # which is the failure this module's first version had.
            "authorization": f"Bearer {self.api_key}",
            "accept": "application/json",
            **dict(extra_headers or {}),
        }
        try:
            response = self._client().request(
                method="POST",
                url=url,
                headers=headers,
                body=body,
                # NOT idempotent. Recorded rather than acted on, but recorded
                # truthfully: an authorization decision has no side effect and
                # an event submission or a tool execution does.
                idempotent=False,
            )
        except OutboundRefused as error:
            # The client refused to make the call -- a blocked destination, a
            # redirect, a body over the cap. NOT a decision.
            raise SentinelUnavailable(
                f"the request to {_safe_url(url)} was refused by the outbound "
                f"policy: {error}. Raised, never returned: a caller that "
                "received a value here would read it as 'not denied'."
            ) from error
        except OutboundUnavailable as error:
            raise SentinelUnavailable(
                f"could not reach the gate at {_safe_url(url)}: {error}. "
                "Raised, never returned."
            ) from error
        return response

    def _post(
        self, path: str, payload: Mapping[str, Any]
    ) -> tuple[int, dict[str, Any]]:
        url = self.base_url.rstrip("/") + path
        encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        response = self._request(path, encoded)

        status = int(response.status)
        if status >= 500:
            raise SentinelUnavailable(
                f"the gate returned {status}. A 5xx is an OUTAGE, not a "
                "decision, and is deliberately not collapsed with a 403 -- one "
                "means 'no' and the other means 'nobody answered'."
            )

        try:
            decoded = response.json()
        except OutboundRefused as error:
            # A proxy's HTML error page lands here. Very much not a decision.
            raise SentinelUnavailable(
                f"the response from {_safe_url(url)} was not JSON ({error}). "
                "This is usually a proxy or load balancer error page, which is "
                "an outage wearing a 200."
            ) from error

        if not isinstance(decoded, dict):
            raise SentinelUnavailable(
                f"the response from {_safe_url(url)} was a "
                f"{type(decoded).__name__}, not an object"
            )

        return status, decoded

    def _client(self) -> HardenedHttpClient:
        """The transport, built per call from this client's configuration.

        Per call rather than cached on the instance: the dataclass is frozen,
        and a cached client would be shared mutable state on an object whose
        whole point is that one caller's configuration cannot leak into
        another's request.
        """
        return self._transport or transport_for(
            self.base_url, timeout_seconds=self.timeout_seconds
        )

    def _handle_unreachable(
        self, unavailable: SentinelUnavailable, *, action: str
    ) -> GateResponse:
        if self.on_unreachable is FailureMode.REFUSE:
            raise unavailable

        # Warned EVERY time. A control that has silently stopped working is the
        # thing nobody notices, and a once-per-process warning scrolled past
        # during startup.
        warnings.warn(
            f"Sentinel was unreachable and this client is configured to allow "
            f"anyway: action={action!r}. Reason on file: "
            f"{self.fail_open_reason}. Underlying failure: {unavailable}",
            UnsafeFailOpenWarning,
            stacklevel=3,
        )
        return GateResponse(
            decision=Decision.ALLOW,
            # THE FIELD THAT KEEPS THIS HONEST. An auditor reading these can
            # separate an allow the gate issued from one the network issued.
            consulted=False,
            reason=(
                "the gate was not consulted; this client is configured to "
                f"allow when unreachable ({self.fail_open_reason})"
            ),
        )


def _parse_decision(status: int, body: Mapping[str, Any]) -> GateResponse:
    """Turn one response into a decision, or refuse to.

    An unrecognised decision string RAISES rather than defaulting. Defaulting
    to allow is obviously wrong; defaulting to deny is also wrong, because it
    would silently mask a protocol mismatch after an upgrade -- and a client
    that denies everything gets configured out of the way rather than fixed.
    """
    if status not in _DECISION_STATUSES:
        raise SentinelUnavailable(
            f"the gate answered {status}, which carries no decision. Treated as "
            "an outage rather than guessed at."
        )

    raw = body.get("decision") or body.get("outcome") or ""
    try:
        decision = Decision(str(raw).strip().lower())
    except ValueError as error:
        raise SentinelUnavailable(
            f"the gate returned decision {raw!r}, which this client version "
            "does not recognise. Raised rather than defaulted: defaulting to "
            "allow is unsafe, and defaulting to deny would mask a protocol "
            "mismatch after an upgrade behind a client that refuses everything."
        ) from error

    rules = body.get("matched_rules", body.get("matchedRules", ()))
    return GateResponse(
        decision=decision,
        consulted=True,
        reason=str(body.get("reason", "")),
        incident_id=str(body.get("incidentId", body.get("incident_id", ""))),
        request_id=str(body.get("requestId", body.get("request_id", ""))),
        enforced=bool(body.get("enforced", False)),
        severity=_int_or_zero(body.get("severity")),
        capped_severity=_int_or_zero(
            body.get("capped_severity", body.get("cappedSeverity"))
        ),
        detector_version=str(
            body.get("detector_version", body.get("detectorVersion", ""))
        ),
        matched_rules=tuple(str(rule) for rule in rules)
        if isinstance(rules, (list, tuple))
        else (),
        authorization=_parse_authorization(body.get("authorization")),
    )


def _parse_authorization(raw: Any) -> Authorization | None:
    """The optional execution binding, or a refusal to pretend there is one.

    Absent or null means the gate issued no binding -- an ordinary allow. But a
    value that IS present and unusable (not an object, or an object with no
    token) is a protocol mismatch, and is raised for the same reason an
    unknown decision is: a caller that got an allow with a broken
    authorization would send garbage to the proxy and be refused there with
    no hint of why.
    """
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise SentinelUnavailable(
            f"the gate attached an authorization that is a "
            f"{type(raw).__name__}, not an object; this client cannot use it"
        )
    token = str(raw.get("token", "")).strip()
    if not token:
        raise SentinelUnavailable(
            "the gate attached an authorization with no token; refused rather "
            "than returned as an allow the proxy would reject"
        )
    return Authorization(
        token=token,
        authorization_id=str(
            raw.get("authorization_id", raw.get("authorizationId", ""))
        ),
        expires_at=str(raw.get("expires_at", raw.get("expiresAt", ""))),
        approved_parameter_digest=str(
            raw.get(
                "approved_parameter_digest",
                raw.get(
                    "parameter_digest",
                    raw.get("parameterDigest", raw.get("digest", "")),
                ),
            )
        ),
    )


def _int_or_zero(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _safe_url(url: str) -> str:
    """A URL fit for an error message: scheme, host and path only.

    Query strings and userinfo are dropped. An exception message reaches logs,
    error trackers and support tickets, and this codebase's rule is that a
    credential must not be one of the things that travels with it.
    """
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{host}{port}{parts.path}"
