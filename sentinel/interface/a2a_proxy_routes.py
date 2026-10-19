"""The A2A wire proxy: JSON-RPC in, delegation policy in the middle, out again.

WHAT THIS ROUTE IS
------------------
`/v1/a2a/proxy/{agent_id}` is an A2A endpoint a calling agent points at INSTEAD
of the remote agent. Sentinel forwards each JSON-RPC message to the enrolled
peer and returns its reply -- with four properties `/v1/a2a/evaluate` cannot
provide, because that route judges a delegation somebody described to it and
this one stands in the path:

  1. THE ENDPOINT COMES FROM THE ENROLMENT RECORD, NEVER THE REQUEST. There is
     no URL parameter. A caller cannot point this process at an agent nobody
     enrolled -- an unknown `agent_id` is refused before any network activity.

  2. THE DELEGATION IS EVALUATED BEFORE THE MESSAGE MOVES. Privilege
     amplification, loops, depth and an unattributable principal are structural
     refusals that happen upstream of the network, so a laundered chain never
     reaches the peer at all.

  3. THE CARD IS DRIFT-CHECKED AGAINST WHAT THE PEER SERVES NOW. The proxy
     fetches the agent card at call time, so the pin comparison is against what
     the agent claims today rather than what the caller cached. The cost is one
     extra round trip per call, stated in `docs/A2A_GATEWAY.md` rather than
     hidden.

  4. THE REPLY IS INSPECTED, NOT ONLY THE REQUEST. A remote agent's answer is
     prose the CALLING agent's model reads and acts on. A proxy that scanned
     only outbound text would miss the entire class of attack where a
     compromised peer answers with instructions -- which is the direction
     cross-agent injection actually travels.

METHODS ARE ALLOWLISTED; STREAMING IS UNWIRED, NOT UNSECURABLE
---------------------------------------------------------------
`message/send`, `tasks/get` and `tasks/cancel` are forwarded. `message/stream`
and `tasks/resubscribe` return `NOT_SUPPORTED`, and the reason has been
CORRECTED: an earlier version of this docstring said a gate in front of SSE must
either buffer everything or forward chunks nobody evaluated. That named two
options where there are three.

The third -- inspect each chunk, release only what passes, abort on the first
failure -- is implemented and tested in `domain/stream_guard.py`. What is
missing here is the SSE transport wiring, not the security argument, and the
refusal now says so. Everything else answers -32601.

REFUSALS TRAVEL IN-BAND
-----------------------
Policy refusals are JSON-RPC error objects, not bare HTTP errors: the caller is
an agent mid-task, and an in-band error is the shape it can handle and show to
its model. Transport-level problems stay HTTP.

DELEGATED IDENTITY
------------------
`X-Sentinel-Principal` and `X-Sentinel-Agent-Id` carry the human and the calling
agent; `X-Sentinel-Scopes` carries what the caller holds. They are Sentinel
headers, not A2A protocol fields, so the forwarded message is untouched.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from fastapi import Depends, FastAPI, Header, HTTPException, status

from sentinel.application.a2a_gateway import A2ADelegationRefused
from sentinel.domain.a2a import (
    A2ARuleViolated,
    AgentCard,
    DelegationChain,
    DelegationHop,
)
from sentinel.domain.authorization import Capability
from sentinel.domain.primitives import TrustLevel
from sentinel.infrastructure.a2a_wire import A2AWireError, text_parts
from sentinel.infrastructure.persistence.audit import Outcome
from sentinel.interface.delegation_verification import (
    passport_from_header,
    verify_presented_chain,
)

__all__ = ["FORWARDABLE_METHODS", "STREAMING_METHODS", "register_a2a_proxy_routes"]

#: Methods this gateway has been taught. Anything outside it is refused rather
#: than passed through: a pass-through of a method nobody evaluated is an
#: unevaluated side channel wearing a security product's badge.
FORWARDABLE_METHODS: frozenset[str] = frozenset(
    {"message/send", "tasks/get", "tasks/cancel"}
)

#: Refused BY NAME, with a reason, rather than falling through to "unknown
#: method". An operator who tries to stream deserves to be told why it cannot
#: work here, not to be told the method does not exist.
STREAMING_METHODS: frozenset[str] = frozenset({"message/stream", "tasks/resubscribe"})

#: In the JSON-RPC server-error range. One code for every Sentinel refusal so a
#: client can branch on it, with specifics in `data.sentinel`.
JSONRPC_SENTINEL_REFUSED = -32050
JSONRPC_METHOD_NOT_FOUND = -32601


def _rpc_error(
    request_id: Any, code: int, message: str, *, sentinel: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if sentinel is not None:
        error["data"] = {"sentinel": dict(sentinel)}
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def _scopes(raw: str) -> frozenset[str]:
    return frozenset(s.strip() for s in raw.split(",") if s.strip())


def register_a2a_proxy_routes(app: FastAPI, container: Any, *, require: Any) -> None:
    """Attach the A2A wire proxy. No-op when it is not configured.

    ABSENT RATHER THAN DISABLED, matching the MCP proxy: an unconfigured proxy
    has no route at all, so the safe state is enforced by the router rather than
    by a flag one boolean away from being on.
    """
    upstream = getattr(container, "a2a_upstream", None)
    if upstream is None:
        return

    gateway = container.a2a_gateway
    audit = container.security_audit

    @app.post("/v1/a2a/proxy/{agent_id}")
    def a2a_proxy(
        agent_id: str,
        message: dict[str, Any],
        principal=Depends(require(Capability.EXECUTE_TOOL)),
        caller: str = Header(default="", alias="X-Sentinel-Agent-Id"),
        human: str = Header(default="", alias="X-Sentinel-Principal"),
        scopes: str = Header(default="", alias="X-Sentinel-Scopes"),
        task_id: str = Header(default="", alias="X-Sentinel-Task-Id"),
        upstream_authorization: str = Header(
            default="", alias="X-Sentinel-Upstream-Authorization"
        ),
        delegation_passport: str = Header(
            default="", alias="X-Sentinel-Delegation-Passport"
        ),
    ):
        """Forward one A2A message to an enrolled agent, through the gate.

        `X-Sentinel-Delegation-Passport` carries the SIGNED chain the caller
        holds, base64url JSON. When present it is verified against the key
        ring before anything else; any finding refuses the message in-band.
        The passport is not forwarded -- it is Sentinel's evidence, not part
        of the A2A message.
        """
        tenant = principal.tenant.value
        request_id = message.get("id")
        method = str(message.get("method", ""))

        # 0. The signed chain, if one was presented. Before the method check,
        #    because a forged passport is a refusal whatever the method.
        chain_digest = ""
        if delegation_passport.strip():
            verifier = getattr(container, "delegation_verifier", None)
            clock = getattr(container, "clock", None)
            now = clock.now().value if clock is not None else datetime.now(timezone.utc)
            try:
                passport = passport_from_header(delegation_passport)
            except ValueError as exc:
                return _rpc_error(
                    request_id, JSONRPC_SENTINEL_REFUSED, str(exc),
                    sentinel={"reason": "delegation_passport_unreadable"},
                )
            if verifier is None:
                _record(audit, principal, agent_id, Outcome.DENIED,
                        {"reason": "no_delegation_key_ring"})
                return _rpc_error(
                    request_id,
                    JSONRPC_SENTINEL_REFUSED,
                    "a signed delegation chain was presented and this "
                    "deployment has no key ring to verify it against",
                    sentinel={"reason": "no_delegation_key_ring"},
                )
            verdict = verify_presented_chain(
                verifier,
                passport=passport,
                tenant_id=tenant,
                presenter=caller,
                now=now,
            )
            if not verdict.established:
                findings = [f.as_dict() for f in verdict.findings]
                _record(audit, principal, agent_id, Outcome.DENIED,
                        {"reason": "signed_chain_refused", "findings": findings})
                return _rpc_error(
                    request_id,
                    JSONRPC_SENTINEL_REFUSED,
                    "the signed delegation chain does not establish authority",
                    sentinel={
                        "reason": "signed_chain_refused",
                        "findings": findings,
                        "explanation": verdict.explain(),
                    },
                )
            chain_digest = passport.digest

        if method in STREAMING_METHODS:
            return _rpc_error(
                request_id,
                JSONRPC_METHOD_NOT_FOUND,
                f"{method} is NOT_SUPPORTED by this proxy",
                sentinel={
                    "reason": (
                        "this proxy does not relay SSE. NOT because the boundary "
                        "cannot be held -- an earlier version of this message "
                        "said that and it was wrong. `domain/stream_guard.py` "
                        "holds it: full pre-flight before the first byte, each "
                        "chunk inspected before release, abort on the first "
                        "failure with no further chunks read from the peer."
                    ),
                    "what_is_missing": (
                        "the SSE transport wiring, not the security argument. "
                        "The guard is implemented and tested; this route has "
                        "not been given a streaming response path."
                    ),
                    "the_cost_when_it_is_wired": (
                        "chunks already released cannot be retracted. If chunk "
                        "7 carries an injection, chunks 1-6 are in the calling "
                        "agent's context and may already have been acted on. "
                        "`StreamOutcome.released_before_abort` reports how many."
                    ),
                    "supported": sorted(FORWARDABLE_METHODS),
                },
            )
        if method not in FORWARDABLE_METHODS:
            return _rpc_error(
                request_id,
                JSONRPC_METHOD_NOT_FOUND,
                f"method {method!r} is not forwarded by this gateway",
                sentinel={"supported": sorted(FORWARDABLE_METHODS)},
            )

        # 1. The endpoint comes from the enrolment record, never the request.
        cards = gateway.cards_for(tenant)
        enrolled = cards.get(agent_id)
        if enrolled is None:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                detail=(
                    f"agent {agent_id!r} is not enrolled for this tenant. The "
                    "endpoint is read from the enrolment record, so there is no "
                    "way to reach an agent nobody registered."
                ),
            )

        # 2. The delegation, evaluated before anything moves.
        #
        # THE CALLER'S AUTHORITY IS NOT CALLER-SUPPLIED, and this is the whole
        # reason the amplification check is worth anything. The first version of
        # this route read one `X-Sentinel-Scopes` header into BOTH what the
        # principal holds and what the hop grants -- so the two sets were equal
        # by construction, no grant could ever exceed the holding, and
        # `find_amplification` could not fire. The check was decorative and the
        # tests said so.
        #
        # Authority comes from the CALLING agent's enrolled card: what an
        # operator recorded it may do. The header says only what it wants to
        # hand on. A caller that is not enrolled holds NOTHING, so any grant it
        # attempts is amplification -- which is the correct reading of an agent
        # nobody approved trying to delegate.
        caller_card = cards.get(caller) if caller else None
        caller_authority = caller_card.capabilities if caller_card else frozenset()

        try:
            chain = DelegationChain(
                principal=human or "unattributed",
                principal_scopes=caller_authority,
                hops=(
                    DelegationHop(
                        from_agent=caller or "unattributed",
                        to_agent=agent_id,
                        granted=_scopes(scopes),
                        task_id=task_id,
                        instruction=" ".join(
                            text_parts(message.get("params", {}).get("message", {}))
                        ),
                    ),
                ),
            )
        except (A2ARuleViolated, ValueError) as exc:
            return _rpc_error(
                request_id, JSONRPC_SENTINEL_REFUSED, str(exc)
            )

        try:
            evaluation = gateway.require_allowed(
                tenant_id=tenant, chain=chain, trust=TrustLevel.UNSIGNED
            )
        except A2ADelegationRefused as exc:
            _record(audit, principal, agent_id, Outcome.DENIED, {"refused": str(exc)})
            return _rpc_error(
                request_id,
                JSONRPC_SENTINEL_REFUSED,
                "delegation refused",
                sentinel={"reason": str(exc)},
            )

        # 3. The card the peer serves NOW, against the pin.
        try:
            live, source = upstream.fetch_card(base_url=enrolled.endpoint)
        except A2AWireError as exc:
            # Refused, not forwarded. Proceeding would mean skipping the drift
            # check while appearing to have performed it.
            return _rpc_error(
                request_id,
                JSONRPC_SENTINEL_REFUSED,
                "the agent card could not be fetched",
                sentinel={"reason": str(exc)},
            )

        drift = _card_drift(enrolled, live)
        if drift:
            _record(audit, principal, agent_id, Outcome.DENIED, {"drift": drift})
            return _rpc_error(
                request_id,
                JSONRPC_SENTINEL_REFUSED,
                "the agent's card changed after it was approved",
                sentinel={
                    "drift": drift,
                    "card_source": source,
                    "remedy": (
                        "re-enrol the agent to accept its current shape, which "
                        "re-pins the fingerprint"
                    ),
                },
            )

        # 4. Forward.
        try:
            reply = upstream.forward(
                endpoint=enrolled.endpoint,
                message=message,
                upstream_authorization=upstream_authorization,
            )
        except A2AWireError as exc:
            return _rpc_error(
                request_id, JSONRPC_SENTINEL_REFUSED, f"upstream error: {exc}"
            )

        # 5. THE REPLY IS INSPECTED TOO. A compromised peer answering with
        #    instructions is the direction cross-agent injection actually
        #    travels, and a proxy that scanned only the request would miss all
        #    of it.
        verdict = _inspect_reply(
            gateway, reply.message, agent_id=agent_id, tenant=tenant
        )
        if verdict is not None:
            _record(audit, principal, agent_id, Outcome.DENIED, {"reply": verdict})
            return _rpc_error(
                request_id,
                JSONRPC_SENTINEL_REFUSED,
                "the remote agent's reply was refused",
                sentinel={
                    "reason": verdict,
                    "note": (
                        "the reply is NOT returned. Handing back a sanitised "
                        "version would be fabricating a peer's response, and "
                        "this codebase does not fabricate upstream state."
                    ),
                },
            )

        _record(
            audit,
            principal,
            agent_id,
            Outcome.SUCCESS,
            {
                "method": method,
                "peer": reply.peer,
                "severity": evaluation.severity.value,
                "findings": [f.kind.value for f in evaluation.findings],
                "delegation_passport_digest": chain_digest,
            },
        )
        if reply.message is None:
            return {"jsonrpc": "2.0", "id": request_id, "result": None}
        return reply.message


def _record(audit, principal, agent_id: str, outcome, detail: Mapping[str, Any]) -> None:
    audit.record(
        tenant=principal.tenant,
        actor=f"key:{principal.key_hash[:12]}",
        action="a2a.proxy",
        resource_type="agent",
        resource_id=agent_id,
        outcome=outcome,
        detail=dict(detail),
    )


def _card_drift(enrolled: AgentCard, live: Mapping[str, Any]) -> list[str]:
    """What changed between the approved card and the one being served.

    Compared field by field rather than by fingerprint alone, because "the
    fingerprint differs" tells an operator nothing they can act on and "it now
    advertises read:customers" tells them everything.
    """
    changes: list[str] = []
    advertised = frozenset(str(c) for c in live.get("capabilities", ()))
    added = sorted(advertised - enrolled.capabilities)
    if added:
        changes.append(f"now advertises {', '.join(added)}")
    live_endpoint = str(live.get("endpoint") or "")
    if live_endpoint and live_endpoint != enrolled.endpoint:
        changes.append(
            f"endpoint moved from {enrolled.endpoint!r} to {live_endpoint!r}"
        )
    live_version = str(live.get("version") or "")
    if live_version and live_version != enrolled.version:
        changes.append(f"version {enrolled.version!r} -> {live_version!r}")
    return changes


def _inspect_reply(
    gateway: Any, reply: Mapping[str, Any] | None, *, agent_id: str, tenant: str
):
    """Run the remote agent's text through the SAME detector the request used.

    Returns a reason string when the reply must not be handed back, or None.

    The reply is projected onto a one-hop chain FROM the remote agent, so the
    text lands in `metadata.prompt` exactly as an outbound instruction does and
    one ruleset governs both directions. Building a second inspection path for
    replies is how the two come to disagree about what an injection looks like.
    """
    if not reply:
        return None
    result = reply.get("result")
    if not isinstance(result, Mapping):
        return None

    # A Task carries its message under `status.message`; a Message is itself the
    # result. Both shapes are read, because a peer chooses which to return.
    candidates = [result]
    status_block = result.get("status")
    if isinstance(status_block, Mapping) and isinstance(
        status_block.get("message"), Mapping
    ):
        candidates.append(status_block["message"])
    for entry in result.get("artifacts", ()) or ():
        if isinstance(entry, Mapping):
            candidates.append(entry)

    text = " ".join(part for c in candidates for part in text_parts(c)).strip()
    if not text:
        return None

    chain = DelegationChain(
        principal="remote",
        principal_scopes=frozenset(),
        hops=(
            DelegationHop(
                from_agent=agent_id, to_agent=agent_id, granted=frozenset(),
                instruction=text,
            ),
        ),
    )
    evaluation = gateway.evaluate(tenant_id=tenant, chain=chain)
    if evaluation.outcome.decision.stops_action:
        return (
            f"the reply from {agent_id} matched "
            f"{', '.join(evaluation.outcome.matched_rules) or 'a detection rule'}"
        )
    # ONLY the detector's verdict is read here. `inspect_chain` would also
    # report SELF_DELEGATION on this projection -- the chain is built
    # agent -> itself so the text has somewhere to sit -- and that finding is an
    # artefact of the projection, not something the peer did. Treating it as a
    # refusal would block every reply.
    return None
