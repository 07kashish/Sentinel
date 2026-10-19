"""A network error must never look like an allow.

That is the failure that turns a security control into decoration: the gate is
unreachable, the client returns something falsy, the agent reads "not denied"
and proceeds. Every request during the outage is permitted, nothing is
recorded, and the graphs look quiet because no events arrived.

So almost every test here asks one question in a different way: can a caller
obtain permission to proceed without the gate having said so?

WHY THE TRANSPORT IS INJECTED RATHER THAN MONKEYPATCHED
--------------------------------------------------------
This client used to call `urllib.request.urlopen`, and these tests patched it.
`test_security_rules.py` rejected that, and its reason was not stylistic:
`urlopen` follows redirects AND forwards the Authorization header to the
target, which has already been proven against this codebase -- a 302 to a
loopback address received an attestation bearer token. So a redirect would have
handed the customer's API key to whoever answered it.

The client now uses `HardenedHttpClient`, and these tests inject a fake
transport implementing its one method. The real request construction, header
handling, status interpretation and parsing stay under test; only the socket is
replaced -- the same seam `HardenedHttpClient` itself offers.
"""

from __future__ import annotations

import json
import subprocess
import sys
import warnings
from pathlib import Path

import pytest

from sentinel.infrastructure.outbound import (
    HardenedHttpClient,
    OutboundRefused,
    OutboundUnavailable,
)
from sentinel.sdk.remote import (
    Decision,
    FailureMode,
    GateResponse,
    SentinelRefused,
    SentinelClient,
    SentinelUnavailable,
    UnsafeFailOpenWarning,
)

KEY = "sk-test-0000000000000000000000000000"
ROOT = Path(__file__).resolve().parent.parent


class _Response:
    """Stands in for an OutboundResponse."""

    def __init__(self, status: int, body: bytes):
        self.status = status
        self.body = body
        self.headers: dict[str, str] = {}
        self.peer = "203.0.113.7:443"

    def json(self):
        try:
            return json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise OutboundRefused(f"not JSON: {error}") from error


class _FakeTransport:
    """Implements the one method of HardenedHttpClient the SDK calls."""

    def __init__(self, *, response=None, error=None, recorder=None):
        self._response = response
        self._error = error
        self._recorder = recorder

    def request(self, *, method, url, headers=None, body=None, idempotent=False):
        if self._recorder is not None:
            self._recorder.update(
                {
                    "url": url,
                    "headers": dict(headers or {}),
                    "method": method,
                    "idempotent": idempotent,
                    "body": body,
                }
            )
        if self._error is not None:
            raise self._error
        return self._response


def _client(**kwargs) -> SentinelClient:
    defaults = dict(base_url="https://sentinel.example", api_key=KEY)
    defaults.update(kwargs)
    return SentinelClient(**defaults)  # type: ignore[arg-type]


def _serving(status: int = 200, body=None, raw: bytes | None = None, **kwargs):
    payload = raw if raw is not None else json.dumps(body or {}).encode()
    return _client(
        _transport=_FakeTransport(response=_Response(status, payload)), **kwargs
    )


def _broken(error: Exception, **kwargs):
    return _client(_transport=_FakeTransport(error=error), **kwargs)


# ── the outage must not become an allow ──────────────────────────────────────


def test_an_unreachable_gate_raises_rather_than_returning_anything():
    """THE test this module exists for."""
    with pytest.raises(SentinelUnavailable) as raised:
        _broken(OutboundUnavailable("name resolution failed")).check(
            agent_id="a", action="delete_bucket"
        )

    assert "could not reach the gate" in str(raised.value)
    assert "Raised, never returned" in str(raised.value)


def test_a_refused_destination_raises_and_is_not_a_decision():
    """The hardened client refuses blocked destinations, over-large bodies and
    REDIRECTS. None of those is the gate saying no.
    """
    with pytest.raises(SentinelUnavailable) as raised:
        _broken(OutboundRefused("refusing to follow redirect to 127.0.0.1")).check(
            agent_id="a", action="x"
        )

    message = str(raised.value)
    assert "refused by the outbound policy" in message
    assert "not denied" in message


@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_every_5xx_is_an_outage_and_not_a_decision(status):
    """A 502 and a 403 mean opposite things. Collapsing them makes an outage
    into a deny somebody retries around -- or, far worse, into an allow.
    """
    with pytest.raises(SentinelUnavailable) as raised:
        _serving(status=status, body={"decision": "allow"}).check(
            agent_id="a", action="x"
        )

    assert "OUTAGE" in str(raised.value)


def test_a_proxy_error_page_returned_with_200_raises():
    """An outage wearing a 200 -- the likeliest real shape of this bug: a load
    balancer answers with HTML while the gate is down.
    """
    with pytest.raises(SentinelUnavailable) as raised:
        _serving(raw=b"<html><body>502 Bad Gateway</body></html>").check(
            agent_id="a", action="x"
        )

    assert "not JSON" in str(raised.value)


def test_a_json_body_with_no_decision_raises():
    with pytest.raises(SentinelUnavailable):
        _serving(body={"status": "ok"}).check(agent_id="a", action="x")


def test_an_unrecognised_decision_raises_rather_than_defaulting():
    """Defaulting to allow is obviously unsafe. Defaulting to DENY is also
    wrong: it masks a protocol mismatch after an upgrade behind a client that
    refuses everything, and such a client gets configured out of the way
    rather than fixed.
    """
    with pytest.raises(SentinelUnavailable) as raised:
        _serving(body={"decision": "probably_fine"}).check(agent_id="a", action="x")

    assert "does not recognise" in str(raised.value)


def test_a_non_object_body_raises():
    with pytest.raises(SentinelUnavailable):
        _serving(raw=b"[1, 2, 3]").check(agent_id="a", action="x")


def test_a_status_that_carries_no_decision_is_an_outage():
    """204, 301, 418 -- anything outside the decision statuses."""
    with pytest.raises(SentinelUnavailable) as raised:
        _serving(status=204, body={"decision": "allow"}).check(
            agent_id="a", action="x"
        )

    assert "carries no decision" in str(raised.value)


# ── the decision type cannot be truthiness-tested into an allow ─────────────


def test_no_decision_member_is_falsy():
    """`if decision:` must not be how anybody reads this.

    Every member is a non-empty string, so a truthiness test is always True --
    a caller who writes one gets a bug that ALWAYS allows. Stated so nobody
    later "helpfully" adds a falsy member.
    """
    for decision in Decision:
        assert bool(decision) is True


def test_only_allow_permits_execution():
    assert Decision.ALLOW.permits_execution
    assert Decision.WARN.permits_execution
    assert Decision.ALLOW_WITH_REDACTION.permits_execution
    assert not Decision.BLOCK.permits_execution
    assert not Decision.REQUIRE_APPROVAL.permits_execution


def test_require_approval_does_not_permit_execution():
    """An approval that has not been granted is not an approval. The member
    most likely to be read as "allow, with paperwork".
    """
    assert Decision("require_approval").permits_execution is False


# ── the gate's actual answers ────────────────────────────────────────────────


def test_an_allow_is_returned_and_marked_consulted():
    response = _serving(body={"decision": "allow", "reason": "ok"}).check(
        agent_id="a", action="read_file"
    )

    assert response.decision is Decision.ALLOW
    assert response.consulted is True
    assert response.permits_execution


def test_a_403_is_a_decision_not_an_outage():
    """The gate answered, and the answer was no."""
    response = _serving(
        status=403, body={"decision": "block", "reason": "policy"}
    ).check(agent_id="a", action="delete_bucket")

    assert response.decision is Decision.BLOCK
    assert response.consulted is True
    assert not response.permits_execution


def test_a_409_is_an_outage_even_if_it_carries_a_decision():
    with pytest.raises(SentinelUnavailable):
        _serving(
            status=409, body={"decision": "require_approval", "incidentId": "inc-1"}
        ).check(agent_id="a", action="rotate_key")

def test_every_server_decision_is_classified():
    proceeds = {
        Decision.ALLOW,
        Decision.WARN,
        Decision.ALLOW_WITH_REDACTION,
    }
    stops = {
        Decision.REQUIRE_APPROVAL,
        Decision.BLOCK,
        Decision.STEP_UP_AUTH,
        Decision.REQUIRE_JIT_CREDENTIAL,
        Decision.CONTAIN,
    }

    assert {decision.value for decision in Decision} == {
        "allow",
        "warn",
        "require_approval",
        "block",
        "allow_with_redaction",
        "step_up_auth",
        "require_jit_credential",
        "contain",
    }
    assert all(not decision.stops_action for decision in proceeds)
    assert all(decision.stops_action for decision in stops)


# ── fail-open is available, named honestly, and never quiet ─────────────────


def test_fail_open_requires_a_written_reason():
    """Turning enforcement off during an outage is a decision somebody made;
    it belongs in writing, where the next person reading the logs sees it.
    """
    with pytest.raises(ValueError) as raised:
        _client(on_unreachable=FailureMode.ALLOW_AND_RECORD)

    assert "requires a fail_open_reason" in str(raised.value)


def test_fail_open_allows_but_records_that_the_gate_was_never_consulted():
    """`consulted=False` is what keeps this honest: an auditor can separate an
    allow the gate issued from one the network issued.
    """
    client = _broken(
        OutboundUnavailable("down"),
        on_unreachable=FailureMode.ALLOW_AND_RECORD,
        fail_open_reason="recommender must not stop serving",
    )

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        response = client.check(agent_id="a", action="rank_items")

    assert response.decision is Decision.ALLOW
    assert response.consulted is False
    assert "was not consulted" in response.reason
    assert any(w.category is UnsafeFailOpenWarning for w in caught)


def test_the_fail_open_warning_fires_on_every_call_not_once():
    """A control that has silently stopped working is the thing nobody
    notices, and a once-per-process warning scrolled past during startup.
    """
    client = _broken(
        OutboundUnavailable("down"),
        on_unreachable=FailureMode.ALLOW_AND_RECORD,
        fail_open_reason="availability over enforcement, signed off by ops",
    )

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        for _ in range(3):
            client.check(agent_id="a", action="x")

    assert len([w for w in caught if w.category is UnsafeFailOpenWarning]) == 3


def test_the_fail_open_warning_repeats_the_configured_reason():
    client = _broken(
        OutboundUnavailable("down"),
        on_unreachable=FailureMode.ALLOW_AND_RECORD,
        fail_open_reason="ticket OPS-4412",
    )

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        client.check(agent_id="a", action="x")

    assert "OPS-4412" in str(caught[0].message)


def test_refuse_is_the_default():
    """A caller who configures nothing gets the safe behaviour."""
    assert _client().on_unreachable is FailureMode.REFUSE


def test_fail_open_does_not_apply_to_a_gate_that_answered_block():
    """Fail-open covers UNREACHABILITY, not disagreement. Turning a block into
    an allow because the client was configured for availability would be
    ignoring the gate rather than surviving without it.
    """
    client = _serving(
        status=403,
        body={"decision": "block"},
        on_unreachable=FailureMode.ALLOW_AND_RECORD,
        fail_open_reason="availability",
    )

    assert client.check(agent_id="a", action="x").decision is Decision.BLOCK


# ── configuration refusals ───────────────────────────────────────────────────


def test_plaintext_http_to_a_remote_host_is_refused():
    """The API key would cross the network in the clear on every call.
    Refused rather than warned: a warning gets configured once and never read.
    """
    with pytest.raises(ValueError) as raised:
        _client(base_url="http://sentinel.example")

    assert "plaintext HTTP" in str(raised.value)


def test_plaintext_http_to_localhost_is_allowed():
    """Local development must not require a certificate, or everybody disables
    verification instead.
    """
    assert _client(base_url="http://localhost:8000").base_url


def test_a_non_http_scheme_is_refused():
    with pytest.raises(ValueError) as raised:
        _client(base_url="file:///etc/passwd")

    assert "must be http or https" in str(raised.value)


def test_disabling_tls_verification_is_not_supported():
    """A client that skips verification accepts a decision from anything
    answering on the port -- and an ALLOW is the forgery an attacker wants.
    """
    with pytest.raises(ValueError) as raised:
        _client(verify_tls=False)

    assert "forgeable" in str(raised.value)


def test_a_missing_api_key_is_refused():
    """Sentinel derives the tenant from the credential, never from the body."""
    with pytest.raises(ValueError) as raised:
        _client(api_key="   ")

    assert "cannot be attributed to a tenant" in str(raised.value)


def test_a_non_positive_timeout_is_refused():
    with pytest.raises(ValueError) as raised:
        _client(timeout_seconds=0)

    assert "hang indefinitely" in str(raised.value)


# ── the transport is the hardened client, with the right policy ─────────────


def test_the_client_uses_the_hardened_http_client():
    """Not `urllib`. The rule that forced this documents a PROVEN token leak:
    `urlopen` follows redirects and forwards the Authorization header, and a
    302 to a loopback address received an attestation bearer token.
    """
    assert isinstance(_client()._client(), HardenedHttpClient)


def test_the_module_no_longer_touches_urllib_request():
    """The import is the precursor to the call, and the cheaper thing to catch
    -- which is exactly what `test_security_rules.py` says.
    """
    import ast
    import inspect

    from sentinel.sdk import remote

    # AST, not a substring search over the source. The docstring MENTIONS
    # urllib.request while explaining why it is not used, so a text search
    # fails on the explanation -- a test that cannot distinguish code from
    # prose about the code. This mirrors what test_security_rules.py does.
    tree = ast.parse(inspect.getsource(remote))

    imports = [
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    ] + [
        node.module or ""
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    ]
    assert not any(name.startswith("urllib.request") for name in imports), imports

    calls = {
        node.func.attr if isinstance(node.func, ast.Attribute)
        else getattr(node.func, "id", "")
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
    }
    for forbidden in ("urlopen", "build_opener", "install_opener"):
        assert forbidden not in calls, f"{forbidden}() is called"


def test_a_remote_endpoint_gets_an_https_only_policy():
    """No private destinations, no plaintext."""
    policy = _client()._client().policy

    assert policy.allowed_schemes == frozenset({"https"})
    assert policy.allow_private_destinations is False
    assert policy.allowed_hosts == frozenset()


def test_a_loopback_endpoint_gets_a_narrow_explicit_grant():
    """Private destinations permitted only for loopback, and narrowed to the
    single configured host rather than all of RFC1918 -- the control the
    policy documentation says to reach for.
    """
    policy = _client(base_url="http://127.0.0.1:8000")._client().policy

    assert policy.allow_private_destinations is True
    assert policy.allowed_hosts == frozenset({"127.0.0.1"})
    assert "http" in policy.allowed_schemes


def test_the_response_body_is_bounded_by_the_policy():
    """Refusing an unbounded body is the hardened client's job now, and the
    cap must actually be handed to it.
    """
    assert _client()._client().policy.max_response_bytes <= 256 * 1024


def test_the_transport_is_built_per_call_and_not_cached():
    """The dataclass is frozen, and a cached client would be shared mutable
    state on an object whose point is that one caller's configuration cannot
    leak into another's request.
    """
    client = _client()

    assert client._client() is not client._client()


# ── the credential must not leak ─────────────────────────────────────────────


def test_the_api_key_travels_in_a_header_and_never_in_the_url():
    """A URL reaches access logs, proxy logs, browser history and error
    trackers.
    """
    seen: dict[str, object] = {}
    _client(
        _transport=_FakeTransport(
            response=_Response(200, json.dumps({"decision": "allow"}).encode()),
            recorder=seen,
        )
    ).check(agent_id="a", action="x")

    assert KEY not in str(seen["url"])
    assert any(KEY in str(v) for v in seen["headers"].values())


def test_the_api_key_is_absent_from_error_messages():
    """An exception message reaches logs, error trackers and support tickets."""
    with pytest.raises(SentinelUnavailable) as raised:
        _broken(
            OutboundUnavailable("down"),
            base_url="https://sentinel.example/x?token=abc",
        ).check(agent_id="a", action="x")

    message = str(raised.value)
    assert KEY not in message
    assert "token=abc" not in message, "the query string leaked into the error"


# ── event submission ─────────────────────────────────────────────────────────


def test_a_dropped_event_raises_rather_than_returning_empty():
    """A caller must not be able to mistake a dropped event for a quiet
    estate. The same failure as the unreachable gate, one surface over.
    """
    with pytest.raises(SentinelUnavailable) as raised:
        _serving(status=400, body={"error": "bad request"}).submit_event(
            {"eventType": "tool_call"}
        )

    assert "was NOT recorded" in str(raised.value)


def test_a_recorded_event_returns_its_id():
    assert (
        _serving(body={"eventId": "evt-9"}).submit_event({"eventType": "tool_call"})
        == "evt-9"
    )


def test_a_request_is_never_marked_idempotent():
    """An event submission is not idempotent unless the caller supplies a
    stable id, and `idempotent` is recorded rather than acted on -- so it must
    be recorded truthfully.
    """
    seen: dict[str, object] = {}
    _client(
        _transport=_FakeTransport(
            response=_Response(200, json.dumps({"eventId": "e"}).encode()),
            recorder=seen,
        )
    ).submit_event({"eventType": "tool_call"})

    assert seen["idempotent"] is False


# ── shape ────────────────────────────────────────────────────────────────────


def test_the_client_is_frozen_so_config_cannot_leak_between_callers():
    client = _client()

    with pytest.raises(Exception):
        client.on_unreachable = FailureMode.ALLOW_AND_RECORD  # type: ignore[misc]


def test_a_gate_response_serialises_whether_it_was_consulted():
    document = GateResponse(decision=Decision.ALLOW, consulted=False).as_dict()

    assert document["consulted"] is False
    assert document["decision"] == "allow"


def test_authorization_is_parsed_from_the_gate_response():
    response = _serving(
        body={
            "decision": "allow",
            "authorization": {
                "token": "tok-1",
                "authorization_id": "auth-1",
                "expires_at": "2026-09-11T12:00:00+00:00",
                "approved_parameter_digest": "d" * 64,
            },
        }
    ).check(agent_id="a", tool="send_email", arguments={"to": "ops@example.com"})

    assert response.authorization is not None
    assert response.authorization.token == "tok-1"
    assert response.authorization.expires_at == "2026-09-11T12:00:00+00:00"
    assert response.authorization.approved_parameter_digest == "d" * 64


def test_authorization_digest_accepts_the_http_response_alias():
    response = _serving(
        body={
            "decision": "allow",
            "authorization": {"token": "tok-1", "digest": "e" * 64},
        }
    ).check(agent_id="a", tool="send_email", arguments={})

    assert response.authorization is not None
    assert response.authorization.approved_parameter_digest == "e" * 64


def test_execute_posts_to_the_inline_proxy_with_authorization():
    seen: dict[str, object] = {}
    client = _client(
        _transport=_FakeTransport(
            response=_Response(
                200,
                json.dumps(
                    {
                        "tool": "send_email",
                        "result": {"ok": True},
                        "protect": {"decision": "allow"},
                        "receipt": {"id": "receipt-1"},
                    }
                ).encode(),
            ),
            recorder=seen,
        )
    )

    result = client.execute(
        agent_id="agent-1",
        tool="send_email",
        action="send",
        arguments={"to": "ops@example.com"},
        authorization="tok-1",
    )

    payload = json.loads(seen["body"].decode("utf-8"))  # type: ignore[union-attr]
    assert seen["url"] == "https://sentinel.example/v1/tools/execute"
    assert payload["authorization"] == "tok-1"
    # THE REAL ROUTE'S MODEL must accept exactly what the client sent. A fake
    # transport accepts anything, which is how an object-shaped authorization
    # shipped while the server answered 422 to it.
    from sentinel.interface.extra_routes import ToolExecutePayload

    assert ToolExecutePayload.model_validate(payload).authorization == "tok-1"
    assert result.result == {"ok": True}
    assert result.receipt == {"id": "receipt-1"}


def test_execute_403_is_a_refusal_not_an_outage():
    with pytest.raises(SentinelRefused):
        _serving(status=403, body={"detail": "policy refused"}).execute(
            agent_id="agent-1", tool="send_email"
        )


def test_remote_sdk_import_does_not_import_fastapi():
    result = subprocess.run(
        [
            sys.executable,
            "-S",
            "-c",
            (
                "import sys; "
                "from sentinel.sdk.remote import SentinelClient; "
                "raise SystemExit(1 if 'fastapi' in sys.modules else 0)"
            ),
        ],
        cwd=str(ROOT),
        env={"PYTHONPATH": str(ROOT)},
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_importing_the_sdk_instruments_nothing():
    """No auto-instrumentation on import, and no global state: an SDK that
    patched something on import would change a customer's runtime by being
    installed.
    """
    import types

    import sentinel.sdk.remote as module

    mutable = [
        name
        for name, value in vars(module).items()
        if not name.startswith("__")
        and isinstance(value, (dict, list, set))
        and not isinstance(value, (frozenset, types.MappingProxyType))
    ]
    assert not mutable, f"module-level mutable state: {mutable}"


def test_the_module_states_that_an_error_must_not_look_like_an_allow():
    import inspect

    from sentinel.sdk import remote

    doc = " ".join((inspect.getdoc(remote) or "").split())

    assert "must never look like an allow" in doc


def test_the_module_records_why_it_uses_the_hardened_client():
    """The reasoning is the useful part: a redirect would have handed the
    customer's API key to whoever answered it.
    """
    import inspect

    from sentinel.sdk import remote

    doc = " ".join((inspect.getdoc(remote) or "").split())

    assert "ANY REDIRECT -> raise" in doc
    assert "forwards the Authorization header" in doc
    assert "proven against this codebase" in doc


# ── The wire contract, checked against the REAL routes' models ──────────────────
#
# A fake transport accepts anything. These validate what the client actually
# sends against the pydantic models the server parses it with, because three
# mismatches shipped while every test above passed.


def test_what_check_sends_is_what_the_protect_route_binds():
    from sentinel.interface.http_models import ProtectPayload

    seen: dict = {}
    client = _client(_transport=_FakeTransport(
        response=_Response(200, json.dumps({"decision": "allow"}).encode()), recorder=seen))
    client.check(agent_id="agent-1", tool="send_email", action="send", resource="/mail",
                 arguments={"to": "ops@example.com"}, trust_level="verified")
    sent = json.loads(seen["body"].decode("utf-8"))
    parsed = ProtectPayload.model_validate(sent)
    # TOP-LEVEL, because that is the only place the route takes arguments from
    # when it issues the authorization. Inside `metadata` they bound nothing.
    assert parsed.tool == "send_email" and dict(parsed.arguments) == {"to": "ops@example.com"}
    assert "arguments" not in sent["metadata"]
    assert "trustLevel" not in sent, "the server refuses a caller-asserted trust"


def test_what_execute_sends_is_accepted_by_the_execute_route():
    from sentinel.interface.extra_routes import ToolExecutePayload

    seen: dict = {}
    body = {"tool": "t", "result": 1, "protect": {"decision": "allow"}}
    client = _client(_transport=_FakeTransport(response=_Response(200, json.dumps(body).encode()), recorder=seen))
    client.execute(agent_id="agent-1", tool="t", arguments={"x": 1}, authorization="tok-1", trust_level="verified")
    sent = json.loads(seen["body"].decode("utf-8"))
    assert "trustLevel" not in sent
    assert ToolExecutePayload.model_validate(sent).authorization == "tok-1"


def test_the_sdk_completes_the_journey_against_a_real_server():
    """The Python client, a real uvicorn, real routes: allow, approval, execute once, replay refused."""
    root = Path(__file__).resolve().parent.parent
    done = subprocess.run([sys.executable, str(root / "scripts" / "smoke_sdks.py")], capture_output=True, text=True, timeout=300)
    assert done.returncode == 0, done.stdout[-1500:] + done.stderr[-1500:]
    assert '"replayRefused": true' in done.stdout and '"badKeyIsNoDecision": true' in done.stdout, done.stdout
