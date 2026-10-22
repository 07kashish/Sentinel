"""The A2A wire client: one JSON-RPC message to one ENROLLED agent, hardened.

WHY THIS MODULE EXISTS
----------------------
`sentinel/application/a2a_gateway.py` decides about delegations that are
*described* to it. That is the evaluation path and it was honest about its
limit: no transport, no JSON-RPC, no live peer. This module is the missing
transport -- the piece that lets Sentinel sit BETWEEN two agents instead of
beside them, so a delegated task passes through the policy gate on its way to
the remote agent rather than being reported after the fact.

Exactly the split `mcp_wire.py` makes, for exactly the same reason, and this
module is deliberately its sibling in shape: a caller who has read one should
recognise the other.

THE ENDPOINT COMES FROM THE ENROLMENT RECORD
----------------------------------------------
There is no "post to a URL" entry point. The endpoint comes from the agent card
an operator enrolled, never from the request. That is the default-deny egress
posture: this process dials agents an operator decided about and nothing else,
and a caller who wants Sentinel to reach a new agent has exactly one path --
enrol it.

WHAT IS FORWARDED AND WHAT IS REFUSED
-------------------------------------
One JSON-RPC 2.0 message per HTTP POST. Batches are refused for the same reason
the MCP proxy refuses them: accepting one would mean evaluating message one and
smuggling message two.

STREAMING IS REFUSED, NOT FAKED
-------------------------------
`message/stream` and `tasks/resubscribe` return Server-Sent Events. A policy
gate in front of a stream has two options and both are dishonest:

  * buffer the whole stream, evaluate it, then release it -- which is not
    streaming, and a client that asked for incremental results gets none;
  * forward chunks as they arrive -- which means forwarding text nobody
    evaluated, through a product whose entire claim is that it evaluated it.

So they are refused by name with a reason, and
`NOT_SUPPORTED` is the honest answer rather than a proxy that silently degrades
one of the two properties a caller is relying on.

PROTOCOL SUPPORT IS VERSIONED, NOT IMPROVISED
---------------------------------------------
`A2A_PROTOCOL_VERSION` names the one revision this gateway targets. Nothing here
invents wire behaviour, and a peer that answers a shape this module has not been
taught produces an error rather than a guess.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from sentinel.domain.errors import SentinelError
from sentinel.infrastructure.outbound import HardenedHttpClient

__all__ = [
    "A2A_PROTOCOL_VERSION",
    "AGENT_CARD_PATHS",
    "A2AUpstreamClient",
    "A2AUpstreamReply",
    "A2AWireError",
    "card_from_document",
    "text_parts",
]

#: The A2A revision this gateway targets. Bump deliberately, with the behaviour
#: changes the new revision requires -- never silently.
A2A_PROTOCOL_VERSION = "0.3.0"

#: Where an agent card lives. Both are tried in order, newest first: the
#: well-known path was renamed between revisions and a deployment may be running
#: either. Trying both is not a guess -- each is a path the specification has
#: defined -- and the one that answers is recorded so drift is compared against
#: the same source next time.
AGENT_CARD_PATHS: tuple[str, ...] = (
    "/.well-known/agent-card.json",
    "/.well-known/agent.json",
)

#: Response bodies larger than the hardened client's cap are already refused
#: there. This is the JSON-nesting bound, which that cap does not cover: a deeply
#: nested document is a parser-exhaustion primitive that fits in a small body.
MAX_PART_DEPTH = 12

#: Text extracted from one message, in total. The extracted text goes to the
#: injection detector and into evidence; unbounded input to either is a cost an
#: attacker chooses.
MAX_TEXT_BYTES = 65_536


class A2AWireError(SentinelError):
    """The upstream agent answered something this gateway cannot act on.

    Not retryable by default: a peer that answered an unparseable body or a
    content type outside the protocol will answer the same way again, and
    retrying is a way to turn one malformed reply into a loop.
    """

    is_retryable = False


@dataclass(frozen=True, slots=True)
class A2AUpstreamReply:
    """What the remote agent said, and how it was reached."""

    status: int
    message: Mapping[str, Any] | None
    #: The address actually dialled. "we called the agent" is not an auditable
    #: statement; "we connected to 203.0.113.7:443" is.
    peer: str = ""
    www_authenticate: str = ""

    @property
    def is_error(self) -> bool:
        return bool(self.message and "error" in self.message)


def text_parts(message: Mapping[str, Any]) -> tuple[str, ...]:
    """Every text part in an A2A message, in order, bounded.

    THIS IS THE INJECTION SURFACE. An A2A message carries `parts`, and a text
    part is prose the receiving agent's model reads and acts on. Inspecting the
    delegated SCOPES will never find a cross-agent injection; the prose is where
    it lives, and this is the function that hands it to the detector.

    Non-text parts (`file`, `data`) are deliberately NOT stringified into the
    detector's input. A base64 blob scored as prose produces noise, and noise is
    how a detector comes to be ignored -- their presence is reported separately
    so a reader knows the message carried more than what was scanned.
    """
    collected: list[str] = []
    budget = MAX_TEXT_BYTES

    def _walk(node: Any, depth: int) -> None:
        nonlocal budget
        if depth > MAX_PART_DEPTH or budget <= 0:
            return
        if isinstance(node, Mapping):
            if str(node.get("kind") or node.get("type") or "") == "text":
                text = node.get("text")
                if isinstance(text, str) and text:
                    clipped = text[:budget]
                    budget -= len(clipped)
                    collected.append(clipped)
                return
            for value in node.values():
                _walk(value, depth + 1)
        elif isinstance(node, (list, tuple)):
            for item in node:
                _walk(item, depth + 1)

    _walk(message.get("parts", ()), 0)
    return tuple(collected)


def card_from_document(document: Mapping[str, Any]) -> dict[str, Any]:
    """Normalise an agent card document into the fields drift is computed over.

    Only the fields that change what the agent can REACH: its id, version,
    endpoint and the skills it advertises. The description and display name are
    left out for the same reason `a2a.card_fingerprint` leaves them out -- a
    publisher rewording a summary would otherwise raise drift nobody can action,
    and that is how a drift alert comes to be ignored.

    A2A calls them `skills`; Sentinel's `AgentCard` calls them capabilities.
    The mapping happens here, once, rather than in every caller.
    """
    skills = document.get("skills")
    capabilities: list[str] = []
    if isinstance(skills, Iterable) and not isinstance(skills, (str, bytes)):
        for skill in skills:
            if isinstance(skill, Mapping):
                identifier = skill.get("id") or skill.get("name")
                if identifier:
                    capabilities.append(str(identifier))
            elif isinstance(skill, str):
                capabilities.append(skill)

    return {
        "agent_id": str(document.get("name") or document.get("id") or ""),
        "version": str(document.get("version") or ""),
        "endpoint": str(document.get("url") or ""),
        "capabilities": sorted(set(capabilities)),
    }


class A2AUpstreamClient:
    """Forwards one JSON-RPC message over HTTPS and parses the reply.

    Built on `HardenedHttpClient` for the same reason `McpUpstreamClient` is: a
    configured URL, a credential in a header, and a peer who controls every byte
    of the response. Redirect-following, unbounded bodies and DNS rebinding are
    already refused there, and this module inherits every one of those refusals
    by construction rather than re-deciding them.
    """

    __slots__ = ("_client",)

    def __init__(self, *, client: HardenedHttpClient) -> None:
        self._client = client

    def forward(
        self,
        *,
        endpoint: str,
        message: Mapping[str, Any],
        upstream_authorization: str = "",
    ) -> A2AUpstreamReply:
        """POST one JSON-RPC message to the enrolled endpoint. Parse the reply.

        `upstream_authorization`, when present, is the credential the CALLER
        holds for the remote agent, passed through verbatim. It is never logged,
        never stored, and never synthesised here -- Sentinel carries a delegated
        credential, it does not mint one.
        """
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            # Only JSON. A peer that answers `text/event-stream` to a
            # non-streaming method is answering a question nobody asked, and
            # accepting it would mean this proxy silently handling a stream it
            # has already refused by name.
            "Accept": "application/json",
            "X-A2A-Protocol-Version": A2A_PROTOCOL_VERSION,
        }
        if upstream_authorization:
            headers["Authorization"] = upstream_authorization

        response = self._client.request(
            method="POST",
            url=endpoint,
            headers=headers,
            body=json.dumps(dict(message)).encode("utf-8"),
        )

        if response.status in (401, 403):
            # An authorization challenge, not a protocol reply. The body is
            # deliberately not parsed: what the caller needs is the status and
            # the challenge header its own auth flow starts from.
            return A2AUpstreamReply(
                status=response.status,
                message=None,
                peer=response.peer,
                www_authenticate=str(
                    response.headers.get("www-authenticate", "") or ""
                ),
            )
        if response.status == 202 or not response.body:
            # Accepted without a reply body. The absence of a message is
            # information, not an error.
            return A2AUpstreamReply(
                status=response.status, message=None, peer=response.peer
            )

        content_type = str(response.headers.get("content-type", "")).lower()
        if "application/json" not in content_type:
            raise A2AWireError(
                f"upstream answered content-type {content_type!r}; this gateway "
                "forwards JSON-RPC over application/json only, and acting on "
                "bytes it cannot classify would be guessing at a peer's intent"
            )
        return A2AUpstreamReply(
            status=response.status,
            message=_parse_json_object(response.body),
            peer=response.peer,
        )

    def fetch_card(self, *, base_url: str) -> tuple[dict[str, Any], str]:
        """Fetch the agent card the peer serves RIGHT NOW.

        This is what makes drift detection live rather than historical. The pin
        recorded at enrolment is compared against what the agent claims at call
        time, so an agent that quietly widened its skills is caught even when
        the caller's cached card is stale -- the same property
        `mcp_proxy_routes` gets by fetching the tool definition per call, and
        the same cost: one extra round trip, stated rather than hidden.

        Returns the normalised card and the path that answered, so the next
        comparison reads the same source rather than silently switching paths.
        """
        errors: list[str] = []
        for path in AGENT_CARD_PATHS:
            url = base_url.rstrip("/") + path
            try:
                response = self._client.request(
                    method="GET",
                    url=url,
                    headers={"Accept": "application/json"},
                    body=None,
                    idempotent=True,
                )
            except Exception as exc:  # noqa: BLE001 - try the next known path
                errors.append(f"{path}: {type(exc).__name__}: {exc}")
                continue
            if response.status != 200:
                errors.append(f"{path}: HTTP {response.status}")
                continue
            return card_from_document(_parse_json_object(response.body)), path

        raise A2AWireError(
            "no agent card could be fetched from any known well-known path "
            f"({'; '.join(errors)}). Refusing: the pin cannot be compared "
            "against a card that was not retrieved, and forwarding anyway would "
            "mean skipping the drift check while appearing to perform it."
        )


def _parse_json_object(raw: bytes) -> dict[str, Any]:
    """Parse one JSON object, or raise. A list is not a message.

    A JSON array here is a BATCH, and a batch is refused rather than iterated:
    evaluating the first element and forwarding the rest is exactly the smuggle
    this gateway exists to prevent.
    """
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise A2AWireError(f"upstream reply was not valid JSON: {exc}") from exc
    if isinstance(parsed, list):
        raise A2AWireError(
            "upstream answered a JSON-RPC batch; batches are refused because "
            "evaluating one element and forwarding the rest is the smuggle this "
            "gateway exists to prevent"
        )
    if not isinstance(parsed, dict):
        raise A2AWireError(
            f"upstream reply was a JSON {type(parsed).__name__}, not an object"
        )
    return parsed
