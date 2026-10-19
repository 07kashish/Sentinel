"""Agent identities issued by Okta Agent SSO / Entra Agent ID, consumed by Sentinel.

The properties under test are the ones that make an IdP-issued agent identity
FIRST-CLASS rather than a second API key:

  * the tenant comes from the registration, never from the token;
  * the role is always the agent role -- a claim cannot promote it;
  * the agent id is BOUND: a body naming another agent is refused;
  * trust is `verified`, so the severity cap that protects against unsigned
    callers manufacturing severity does not apply;
  * a JWT from an issuer nobody registered is a 401, never an API-key fallback;
  * a malformed registration is a refusal to start.
"""

from __future__ import annotations

import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fastapi.testclient import TestClient

from sentinel.composition.container import build_container
from sentinel.composition.settings import ConfigurationError, Settings
from sentinel.infrastructure.agent_identity_providers import (
    AGENT_ROLE,
    AgentIdentityProviderError,
    AgentIdentityProviders,
)
from sentinel.infrastructure.oidc import OidcError
from sentinel.infrastructure.sql.engine import Dialect, build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.interface.http import create_app
from sentinel.interface.principals import tenant_for_jwt

ISSUER = "https://acme.okta.com/oauth2/aus1agents"
AUDIENCE = "https://sentinel.acme.example"
TENANT = "acme"
AGENT = "agent:payments-reconciler"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class _Issuer:
    """A software IdP: one P-256 key, a JWKS, and a way to mint tokens."""

    def __init__(self, issuer: str = ISSUER) -> None:
        self.issuer = issuer
        self.key = ec.generate_private_key(ec.SECP256R1())
        numbers = self.key.public_key().public_numbers()
        self.jwks = {
            "keys": [
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "kid": "agents-1",
                    "x": _b64url(numbers.x.to_bytes(32, "big")),
                    "y": _b64url(numbers.y.to_bytes(32, "big")),
                }
            ]
        }

    def mint(self, *, sub: str = AGENT, exp_in: int = 300, **extra) -> str:
        header = {"alg": "ES256", "kid": "agents-1", "typ": "JWT"}
        now = int(time.time())
        payload = {
            "iss": self.issuer,
            "aud": AUDIENCE,
            "sub": sub,
            "iat": now,
            "exp": now + exp_in,
            **extra,
        }
        signing_input = (
            _b64url(json.dumps(header).encode()) + "." + _b64url(json.dumps(payload).encode())
        )
        der = self.key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return signing_input + "." + _b64url(raw)


def _registration(issuer: _Issuer, *, kind: str = "okta") -> str:
    return json.dumps(
        [
            {
                "name": "okta-prod",
                "kind": kind,
                "issuer": issuer.issuer,
                "audience": AUDIENCE,
                "tenant": TENANT,
                "jwks": issuer.jwks,
            }
        ]
    )


def _app(engine_config, issuer: _Issuer, **extra_env):
    """The app on whichever engine `engine_config` selected (both, over a run)."""
    env = {
        "SENTINEL_ENV": "development",
        "SENTINEL_API_KEYS": (
            f"{TENANT}:" + ("i" * 40) + ":ingest," f"{TENANT}:" + ("v" * 40) + ":viewer"
        ),
        "SENTINEL_PROTECT_ENFORCE": "true",
        "SENTINEL_SOFT_PROMPT_DETECT": "false",
        "SENTINEL_AGENT_IDP_JSON": _registration(issuer),
    }
    if engine_config.dialect is Dialect.SQLITE:
        env["SENTINEL_DB_PATH"] = engine_config.dsn
    else:
        env["SENTINEL_DATABASE_URL"] = engine_config.dsn
    env.update(extra_env)
    settings = Settings.from_environment(env)
    pool = build_engine(settings.engine)
    migrate(pool)
    pool.close()
    container = build_container(settings)
    return TestClient(create_app(container), raise_server_exceptions=False), container


# ── Registration ─────────────────────────────────────────────────────────────


def test_a_malformed_registration_refuses_to_start(tmp_path):
    env = {
        "SENTINEL_ENV": "development",
        "SENTINEL_DB_PATH": str(tmp_path / "x.db"),
        "SENTINEL_API_KEYS": f"{TENANT}:" + ("i" * 40) + ":ingest",
        "SENTINEL_AGENT_IDP_JSON": json.dumps([{"name": "okta", "issuer": ISSUER}]),
    }
    with pytest.raises(ConfigurationError) as caught:
        Settings.from_environment(env)
    assert "missing" in str(caught.value)


def test_two_registrations_cannot_claim_one_issuer():
    issuer = _Issuer()
    entry = json.loads(_registration(issuer))[0]
    other = {**entry, "name": "second", "tenant": "globex"}
    with pytest.raises(AgentIdentityProviderError) as caught:
        AgentIdentityProviders.from_json(json.dumps([entry, other]))
    assert "exactly one tenant" in str(caught.value)


def test_a_forbidden_tenant_name_is_refused_at_registration():
    issuer = _Issuer()
    entry = json.loads(_registration(issuer))[0]
    entry["tenant"] = "default"
    with pytest.raises(AgentIdentityProviderError):
        AgentIdentityProviders.from_json(json.dumps([entry]))


# ── Verification ─────────────────────────────────────────────────────────────


def test_the_tenant_and_role_come_from_the_registration_not_the_token():
    issuer = _Issuer()
    providers = AgentIdentityProviders.from_json(_registration(issuer))
    # The token CLAIMS another tenant and the admin role. Neither is read.
    token = issuer.mint(tenant_id="globex", role="admin")
    identity = providers.verify(token)
    assert identity.tenant_id == TENANT
    assert identity.agent_id == AGENT
    assert identity.provider == "okta-prod"
    assert AGENT_ROLE == "ingest"


def test_an_rfc8693_actor_claim_becomes_on_behalf_of():
    issuer = _Issuer()
    providers = AgentIdentityProviders.from_json(_registration(issuer))
    token = issuer.mint(act={"sub": "user:priya@acme.example"})
    assert providers.verify(token).on_behalf_of == "user:priya@acme.example"


def test_an_unregistered_issuer_is_refused():
    registered = _Issuer()
    stranger = _Issuer(issuer="https://evil.example/oauth2")
    providers = AgentIdentityProviders.from_json(_registration(registered))
    with pytest.raises(OidcError):
        providers.verify(stranger.mint())


def test_a_token_that_lies_about_its_issuer_is_still_refused():
    """The unverified `iss` only picks a verifier; that verifier checks the
    signature against ITS keys, so a stranger naming the registered issuer
    fails on the signature."""
    registered = _Issuer()
    stranger = _Issuer(issuer=ISSUER)  # same issuer string, different key
    providers = AgentIdentityProviders.from_json(_registration(registered))
    with pytest.raises(OidcError):
        providers.verify(stranger.mint())


# ── Over HTTP ────────────────────────────────────────────────────────────────


def test_an_agent_token_authenticates_as_that_agent_with_verified_trust(engine_config):
    issuer = _Issuer()
    client, container = _app(engine_config, issuer)
    try:
        token = issuer.mint()
        response = client.post(
            "/v1/protect/evaluate",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "agentId": AGENT,
                "tool": "fs",
                "action": "read_file",
                "resource": "/home/user/.aws/credentials",
                "arguments": {},
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        # Verified trust: the unsigned severity cap (79) does NOT apply.
        assert body["decision"] == "block"
        assert body["capped_severity"] == body["severity"] >= 80
    finally:
        container.close()


def test_an_agent_token_cannot_speak_for_another_agent(engine_config):
    issuer = _Issuer()
    client, container = _app(engine_config, issuer)
    try:
        token = issuer.mint()
        for path, body in (
            (
                "/v1/events",
                {
                    "eventId": "e-1",
                    "sessionId": "s-1",
                    "agentId": "agent:infra-writer",
                    "eventType": "tool_call",
                    "action": "list_dir",
                    "timestamp": "2026-09-11T10:00:00Z",
                },
            ),
            (
                "/v1/protect/evaluate",
                {"agentId": "agent:infra-writer", "tool": "fs", "action": "list_dir"},
            ),
            (
                "/v1/tools/execute",
                {"agentId": "agent:infra-writer", "tool": "noop", "action": "x"},
            ),
        ):
            response = client.post(
                path, headers={"Authorization": f"Bearer {token}"}, json=body
            )
            assert response.status_code == 403, (path, response.text)
            assert "speaks only for itself" in response.json()["detail"]
    finally:
        container.close()


def test_an_agent_token_holds_the_agent_role_and_nothing_more(engine_config):
    issuer = _Issuer()
    client, container = _app(engine_config, issuer)
    try:
        token = issuer.mint(role="admin")
        response = client.get(
            "/v1/incidents", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 403
    finally:
        container.close()


def test_an_expired_agent_token_is_a_401(engine_config):
    issuer = _Issuer()
    client, container = _app(engine_config, issuer)
    try:
        token = issuer.mint(exp_in=-3600)  # an hour past: beyond any clock-skew allowance
        response = client.post(
            "/v1/protect/evaluate",
            headers={"Authorization": f"Bearer {token}"},
            json={"agentId": AGENT, "tool": "fs", "action": "list_dir"},
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "invalid agent identity token"
    finally:
        container.close()


def test_a_jwt_from_an_unregistered_issuer_never_falls_through_to_api_keys(engine_config):
    issuer = _Issuer()
    stranger = _Issuer(issuer="https://evil.example/oauth2")
    client, container = _app(engine_config, issuer)
    try:
        response = client.post(
            "/v1/protect/evaluate",
            headers={"Authorization": f"Bearer {stranger.mint()}"},
            json={"agentId": AGENT, "tool": "fs", "action": "list_dir"},
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "token issuer is not registered"
    finally:
        container.close()


def test_the_throttle_routes_an_agent_token_to_its_tenant(engine_config):
    """The bucket keyed on the tenant, not the auth-failure bucket that
    throttled every SSO caller at ten requests a minute."""
    issuer = _Issuer()
    _client, container = _app(engine_config, issuer)
    try:
        assert tenant_for_jwt(container, issuer.mint()) == TENANT
        assert tenant_for_jwt(container, "not.a.jwt.at.all") is None
    finally:
        container.close()
