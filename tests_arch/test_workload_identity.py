"""Workload identity: the agent is what was attested, not what was typed.

A SPIFFE JWT-SVID or a pod-bound Kubernetes service-account token identifies a
running workload. With `SENTINEL_REQUIRE_WORKLOAD_IDENTITY` on, an API key can
no longer reach the agent path at all -- which is the difference between
"someone who holds the key said they were agent X" and "agent X called".
"""

from __future__ import annotations

import json

import pytest

from sentinel.infrastructure.agent_identity_providers import (
    AgentIdentityProviderError,
    AgentIdentityProviders,
)
from sentinel.infrastructure.oidc import OidcError
from tests_arch.test_agent_identity_providers import AUDIENCE, TENANT, _app, _Issuer

SPIFFE = "spiffe://prod.acme.example/ns/agents/sa/infra-writer"
K8S_SUB = "system:serviceaccount:agents:infra-writer"


def _spiffe(issuer: _Issuer, **extra) -> str:
    return json.dumps([{
        "name": "spire-prod", "kind": "spiffe", "issuer": issuer.issuer, "audience": AUDIENCE,
        "tenant": TENANT, "jwks": issuer.jwks, "trust_domain": "prod.acme.example", **extra,
    }])


def _k8s(issuer: _Issuer, **extra) -> str:
    return json.dumps([{
        "name": "cluster-prod", "kind": "kubernetes", "issuer": issuer.issuer, "audience": AUDIENCE,
        "tenant": TENANT, "jwks": issuer.jwks, "allowed_namespaces": ["agents"], **extra,
    }])


def _k8s_claim(namespace="agents", account="infra-writer", pod=True):
    claim = {"namespace": namespace, "serviceaccount": {"name": account, "uid": "sa-uid-1"}}
    if pod:
        claim["pod"] = {"name": "infra-writer-7d9f", "uid": "pod-uid-1"}
    return {"kubernetes.io": claim}


# ── SPIFFE ───────────────────────────────────────────────────────────────────


def test_a_spiffe_id_in_the_trust_domain_is_the_agent():
    issuer = _Issuer()
    identity = AgentIdentityProviders.from_json(_spiffe(issuer)).verify(issuer.mint(sub=SPIFFE))
    assert identity.agent_id == SPIFFE and identity.workload == SPIFFE and identity.is_workload


@pytest.mark.parametrize("subject", [
    "spiffe://evil.example/ns/agents/sa/infra-writer",
    "spiffe://prod.acme.example.evil.example/ns/agents",
    "spiffe://prod.acme.example",
    "spiffe://prod.acme.example/ns/agents/../admin",
    "spiffe://prod.acme.example/ns/agents?x=1",
    "agent:infra-writer",
])
def test_a_subject_outside_the_trust_domain_is_refused(subject):
    issuer = _Issuer()
    providers = AgentIdentityProviders.from_json(_spiffe(issuer))
    with pytest.raises(OidcError):
        providers.verify(issuer.mint(sub=subject))


def test_a_path_prefix_scopes_which_workloads_are_agents():
    issuer = _Issuer()
    providers = AgentIdentityProviders.from_json(_spiffe(issuer, spiffe_path_prefix="/ns/agents"))
    assert providers.verify(issuer.mint(sub=SPIFFE)).agent_id == SPIFFE
    for outside in ("spiffe://prod.acme.example/ns/agents-evil/sa/x", "spiffe://prod.acme.example/ns/payments/sa/x"):
        with pytest.raises(OidcError):
            providers.verify(issuer.mint(sub=outside))


# ── Kubernetes projected tokens ──────────────────────────────────────────────


def test_a_pod_bound_service_account_token_is_the_agent():
    issuer = _Issuer()
    identity = AgentIdentityProviders.from_json(_k8s(issuer)).verify(issuer.mint(sub=K8S_SUB, **_k8s_claim()))
    assert identity.agent_id == K8S_SUB
    assert identity.workload == "pod:agents/infra-writer-7d9f#pod-uid-1"


def test_a_token_not_bound_to_a_pod_is_refused_by_default():
    issuer = _Issuer()
    with pytest.raises(OidcError, match="not bound to a pod"):
        AgentIdentityProviders.from_json(_k8s(issuer)).verify(issuer.mint(sub=K8S_SUB, **_k8s_claim(pod=False)))
    relaxed = AgentIdentityProviders.from_json(_k8s(issuer, require_pod_binding=False))
    assert relaxed.verify(issuer.mint(sub=K8S_SUB, **_k8s_claim(pod=False))).workload == "serviceaccount:agents/infra-writer"


@pytest.mark.parametrize("sub, claim", [
    ("system:serviceaccount:kube-system:infra-writer", _k8s_claim(namespace="kube-system")),
    (K8S_SUB, _k8s_claim(namespace="other")),
    (K8S_SUB, _k8s_claim(account="someone-else")),
    (K8S_SUB, {}),
    ("infra-writer", _k8s_claim()),
])
def test_a_namespace_or_claim_mismatch_is_refused(sub, claim):
    issuer = _Issuer()
    with pytest.raises(OidcError):
        AgentIdentityProviders.from_json(_k8s(issuer)).verify(issuer.mint(sub=sub, **claim))


@pytest.mark.parametrize("registration", [
    lambda i: _spiffe(i, trust_domain=""),
    lambda i: _spiffe(i, trust_domain="Bad Domain"),
    lambda i: _spiffe(i, agent_id_claim="email"),
    lambda i: _k8s(i, allowed_namespaces=[]),
    lambda i: _k8s(i, allowed_namespaces="agents"),
])
def test_a_malformed_workload_registration_refuses_to_start(registration):
    with pytest.raises(AgentIdentityProviderError):
        AgentIdentityProviders.from_json(registration(_Issuer()))


# ── The switch: API keys cannot be agents ────────────────────────────────────


def _evaluate(client, token, agent):
    return client.post("/v1/protect/evaluate", headers={"Authorization": f"Bearer {token}"}, json={
        "agentId": agent, "tool": "echo", "action": "echo", "resource": "safe", "arguments": {"v": 1},
    })


def test_with_the_requirement_on_an_api_key_cannot_act_as_an_agent(engine_config):
    issuer = _Issuer()
    client, container = _app(engine_config, issuer, SENTINEL_AGENT_IDP_JSON=_spiffe(issuer),
                             SENTINEL_REQUIRE_WORKLOAD_IDENTITY="true")
    try:
        refused = _evaluate(client, "i" * 40, SPIFFE)
        assert refused.status_code == 403 and "API key cannot act as an agent" in refused.json()["detail"]
        allowed = _evaluate(client, issuer.mint(sub=SPIFFE), SPIFFE)
        assert allowed.status_code == 200, allowed.text
        impersonation = _evaluate(client, issuer.mint(sub=SPIFFE), "spiffe://prod.acme.example/ns/agents/sa/other")
        assert impersonation.status_code == 403
    finally:
        container.close()


def test_without_the_requirement_an_api_key_still_works_and_is_unsigned(engine_config):
    issuer = _Issuer()
    client, container = _app(engine_config, issuer, SENTINEL_AGENT_IDP_JSON=_spiffe(issuer))
    try:
        assert _evaluate(client, "i" * 40, "agent-1").status_code == 200
    finally:
        container.close()


# ── Key rotation ─────────────────────────────────────────────────────────────


class _Jwks:
    """A stand-in JWKS endpoint that counts how often it is asked."""

    def __init__(self, issuer: _Issuer) -> None:
        self.issuer, self.calls, self.fail = issuer, 0, False

    def __call__(self, provider):
        self.calls += 1
        if self.fail:
            raise ConnectionError("issuer unreachable")
        return self.issuer.jwks


def _rotating(issuer: _Issuer, **extra) -> str:
    return json.dumps([{"name": "rotating", "kind": "spiffe", "issuer": issuer.issuer, "audience": AUDIENCE,
                        "tenant": TENANT, "trust_domain": "prod.acme.example",
                        "jwks_uri": "https://idp.acme.example/keys", **extra}])


def test_keys_are_fetched_on_first_use_and_a_rotation_is_followed():
    issuer = _Issuer()
    endpoint = _Jwks(issuer)
    providers = AgentIdentityProviders.from_json(_rotating(issuer), fetch=endpoint)
    assert providers.verify(issuer.mint(sub=SPIFFE), now=None).agent_id == SPIFFE
    assert endpoint.calls == 1
    providers.verify(issuer.mint(sub=SPIFFE))
    assert endpoint.calls == 1, "keys were refetched for a key id already trusted"

    rotated = _Issuer(issuer.issuer)                 # the issuer rotates to a new key...
    rotated.jwks["keys"][0]["kid"] = "agents-2"
    endpoint.issuer = rotated
    import time as _time
    future = _time.time() + 120                       # ...and a minute later an agent presents it
    token = rotated.mint(sub=SPIFFE, exp_in=600).replace("", "")
    header = json.loads(__import__("base64").urlsafe_b64decode(token.split(".")[0] + "=="))
    assert header["kid"] == "agents-1"                # the test issuer always stamps agents-1...
    rotated.jwks["keys"][0]["kid"] = "agents-1"       # ...so the rotation here is a new KEY under the fetched set
    providers._by_issuer[issuer.issuer].refresh_state["fetched_at"] = 0.0   # force staleness
    assert providers.verify(token, now=future).agent_id == SPIFFE
    assert endpoint.calls == 2
    with pytest.raises(OidcError):
        providers.verify(issuer.mint(sub=SPIFFE), now=future)   # the OLD key is no longer trusted


def test_an_unreachable_issuer_keeps_the_last_good_keys_and_is_rate_limited():
    issuer = _Issuer()
    endpoint = _Jwks(issuer)
    providers = AgentIdentityProviders.from_json(_rotating(issuer), fetch=endpoint)
    providers.verify(issuer.mint(sub=SPIFFE))
    endpoint.fail = True
    providers._by_issuer[issuer.issuer].refresh_state["fetched_at"] = 0.0
    later = __import__("time").time() + 5     # past the one-second guard against concurrent refreshes
    assert providers.verify(issuer.mint(sub=SPIFFE), now=later).agent_id == SPIFFE, "an issuer outage locked out every agent"
    status = providers.refresh_status()["rotating"]
    assert status["last_error"] == "ConnectionError" and status["failures"] == 1
    calls = endpoint.calls
    providers._by_issuer[issuer.issuer].refresh_state["fetched_at"] = later   # keys are "fresh" again
    for _ in range(5):
        providers.verify(issuer.mint(sub=SPIFFE), now=later + 2)
    assert endpoint.calls == calls, "a failing endpoint was hammered on every request"


def test_a_hostile_key_set_is_refused_and_trust_is_not_widened():
    issuer = _Issuer()
    endpoint = _Jwks(issuer)
    providers = AgentIdentityProviders.from_json(_rotating(issuer), fetch=endpoint)
    providers.verify(issuer.mint(sub=SPIFFE))
    endpoint.issuer = type("Bad", (), {"jwks": {"keys": [{"kty": "oct", "kid": "agents-1", "k": "c2VjcmV0"}]}})()
    providers._by_issuer[issuer.issuer].refresh_state["fetched_at"] = 0.0
    later = __import__("time").time() + 5
    assert providers.verify(issuer.mint(sub=SPIFFE), now=later).agent_id == SPIFFE
    assert providers.refresh_status()["rotating"]["last_error"] == "OidcError"


@pytest.mark.parametrize("extra", [{"jwks_uri": "http://idp.acme.example/keys"}, {"jwks_refresh_seconds": 5}])
def test_a_cleartext_or_frantic_key_endpoint_refuses_to_start(extra):
    issuer = _Issuer()
    with pytest.raises(AgentIdentityProviderError):
        AgentIdentityProviders.from_json(_rotating(issuer, **extra))


def test_a_pinned_registration_never_fetches():
    issuer = _Issuer()
    endpoint = _Jwks(issuer)
    providers = AgentIdentityProviders.from_json(_spiffe(issuer), fetch=endpoint)
    providers.verify(issuer.mint(sub=SPIFFE))
    assert endpoint.calls == 0


# ── Discovery ────────────────────────────────────────────────────────────────


def _discovering(issuer: _Issuer) -> str:
    return json.dumps([{"name": "discovered", "kind": "spiffe", "issuer": issuer.issuer, "audience": AUDIENCE,
                        "tenant": TENANT, "trust_domain": "prod.acme.example", "discover": True}])


def test_discovery_needs_only_the_issuer_and_is_followed_on_refresh():
    issuer = _Issuer()
    endpoint = _Jwks(issuer)
    providers = AgentIdentityProviders.from_json(_discovering(issuer), fetch=endpoint)
    assert providers.verify(issuer.mint(sub=SPIFFE)).agent_id == SPIFFE
    assert endpoint.calls == 1 and "discovered" in providers.refresh_status()


def test_a_discovery_document_for_another_issuer_is_refused():
    from sentinel.infrastructure.agent_identity_providers import discovered_jwks_uri

    issuer = _Issuer()
    provider = AgentIdentityProviders.from_json(_discovering(issuer))._by_issuer[issuer.issuer]
    good = {"issuer": issuer.issuer, "jwks_uri": "https://keys.acme.example/jwks"}
    assert discovered_jwks_uri(provider, good) == "https://keys.acme.example/jwks"
    for bad in ({**good, "issuer": "https://evil.example"}, {**good, "jwks_uri": "http://keys.acme.example/jwks"},
                {"issuer": issuer.issuer}):
        with pytest.raises(OidcError):
            discovered_jwks_uri(provider, bad)


def test_discovery_over_cleartext_refuses_to_start():
    issuer = _Issuer("http://idp.acme.example")
    with pytest.raises(AgentIdentityProviderError, match="https issuer"):
        AgentIdentityProviders.from_json(_discovering(issuer))
