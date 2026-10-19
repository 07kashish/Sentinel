"""Containment on Sentinel's own state, and the tenant that must reach it.

WHY THIS MODULE EXISTS
----------------------
Eleven catalogue actions declare `provider="sentinel"`, and every one is a write
to a table this process already owns. Until these integrations, each required an
operator to run an HTTP webhook that called back into Sentinel to do what
Sentinel could do directly. Almost nobody did, so `NullRemediationExecutor` was
the executor most deployments got and `decide_response`'s CRITICAL path ended in
`unsupported_action` — the product proposed consequences it could not act on.

THE TENANT IS THE WHOLE RISK
-----------------------------
`RemediationIntegration.execute` carried no tenant, because a webhook does not
need one. These do: every table is tenant-scoped, so an integration that guessed
would be a cross-tenant write dressed as a containment.
`test_a_tenant_scoped_integration_is_refused_without_a_tenant` is the test that
keeps the guess impossible, and
`test_a_webhook_integration_is_still_called_without_a_tenant` is the one that
keeps the old contract intact.
"""

from __future__ import annotations

import pytest

from sentinel.domain.errors import DomainRuleViolated
from sentinel.domain.mcp import McpServerIdentity, McpServerTrust
from sentinel.domain.primitives import IdempotencyKey, Timestamp
from sentinel.infrastructure.remediation import (
    ApprovalPathAuthorizer,
    GuardedRemediationExecutor,
    InMemoryIdempotencyStore,
)
from sentinel.infrastructure.native_containment import (
    NATIVE_SENTINEL_ACTIONS,
    ContainmentTargetInvalid,
    build_sentinel_integrations,
)

AT = Timestamp.parse("2026-08-30T12:00:00+00:00")
KEY = IdempotencyKey("idem-1")
ADDRESS = "0x" + "a" * 40


class _Clock:
    def now(self) -> Timestamp:
        return AT


class _Registry:
    def __init__(self) -> None:
        self.revoked: list[tuple[str, str]] = []
        self.enrolled: list[tuple[str, str]] = []

    def revoke(self, tenant, *, address) -> None:
        self.revoked.append((tenant.value, address.value))

    def enrol(self, tenant, *, address, label, at) -> None:
        self.enrolled.append((tenant.value, address.value))


class _Capabilities:
    def __init__(self) -> None:
        self.revoked: list[tuple[str, str, frozenset]] = []
        self.granted: list[tuple[str, str, frozenset]] = []

    def revoke(self, tenant_id, agent_id, tools) -> None:
        self.revoked.append((tenant_id, agent_id, tools))

    def grant(self, tenant_id, agent_id, tools) -> None:
        self.granted.append((tenant_id, agent_id, tools))


class _McpRegistry:
    def __init__(self, existing=None) -> None:
        self.existing = existing
        self.recorded: list[McpServerIdentity] = []

    def lookup(self, tenant_id, server_id):
        return self.existing

    def record(self, server) -> None:
        self.recorded.append(server)


def _build():
    registry, capabilities, mcp = _Registry(), _Capabilities(), _McpRegistry()
    integrations = build_sentinel_integrations(
        registry=registry, capabilities=capabilities, mcp_registry=mcp, clock=_Clock()
    )
    return integrations, registry, capabilities, mcp


# ── the actions ──────────────────────────────────────────────────────────────


def test_every_declared_native_action_is_built_and_is_in_the_catalogue():
    """An action listed but not built is a claim with nothing behind it. One
    built under a name no proposal can produce is unreachable.
    """
    from sentinel.domain.remediation import action_named

    integrations, *_ = _build()
    assert sorted(integrations) == sorted(NATIVE_SENTINEL_ACTIONS)
    for action in NATIVE_SENTINEL_ACTIONS:
        assert action_named(action).provider == "sentinel"


def test_disabling_an_agent_revokes_its_enrolment_in_that_tenant():
    integrations, registry, *_ = _build()
    integrations["disable_agent"].execute(
        target=ADDRESS, idempotency_key=KEY, tenant="acme"
    )
    assert registry.revoked == [("acme", ADDRESS)]


def test_enable_is_a_separate_class_that_re_enrols():
    """A single class branching on a string it was handed would be one refactor
    away from doing the opposite of what an approval said.
    """
    integrations, registry, *_ = _build()
    integrations["enable_agent"].execute(
        target=ADDRESS, idempotency_key=KEY, tenant="acme"
    )
    assert registry.enrolled == [("acme", ADDRESS)]
    assert registry.revoked == []


def test_removing_tool_access_drops_one_tool_not_all_of_them():
    """The catalogue rates this blast radius SINGLE, and `decide_response` reads
    blast radius to decide what may run without a human. Dropping every grant
    would make that declaration false.
    """
    integrations, _r, capabilities, _m = _build()
    integrations["remove_tool_access"].execute(
        target="finance-agent/http_request", idempotency_key=KEY, tenant="acme"
    )
    assert capabilities.revoked == [("acme", "finance-agent", frozenset({"http_request"}))]


def test_a_bare_agent_id_is_refused_for_a_grant_action():
    """Because it would mean "every tool", which is a different action."""
    integrations, *_ = _build()
    with pytest.raises(ContainmentTargetInvalid, match="agent/tool"):
        integrations["remove_tool_access"].execute(
            target="finance-agent", idempotency_key=KEY, tenant="acme"
        )


def test_blocking_an_mcp_server_writes_a_blocked_trust_record():
    integrations, _r, _c, mcp = _build()
    integrations["block_mcp_server"].execute(
        target="unknown-server", idempotency_key=KEY, tenant="acme"
    )
    assert mcp.recorded[0].trust is McpServerTrust.BLOCKED
    assert mcp.recorded[0].server_id == "unknown-server"


def test_unblocking_restores_unknown_not_enrolled():
    """An operator lifting a block said "we are done investigating", not "this
    server is approved again". Restoring the previous trust would say the second.
    """
    registry = _McpRegistry(
        existing=McpServerIdentity(
            tenant_id="acme",
            server_id="s1",
            endpoint="https://s1.example",
            trust=McpServerTrust.ENROLLED,
        )
    )
    integrations = build_sentinel_integrations(
        registry=_Registry(),
        capabilities=_Capabilities(),
        mcp_registry=registry,
        clock=_Clock(),
    )
    integrations["unblock_mcp_server"].execute(
        target="s1", idempotency_key=KEY, tenant="acme"
    )
    assert registry.recorded[0].trust is McpServerTrust.UNKNOWN
    # The endpoint is preserved, so lifting a block does not lose where the
    # server was -- an operator re-enrolling needs that.
    assert registry.recorded[0].endpoint == "https://s1.example"


def test_a_malformed_address_never_reaches_the_registry():
    integrations, registry, *_ = _build()
    with pytest.raises(ContainmentTargetInvalid):
        integrations["disable_agent"].execute(
            target="not-an-address", idempotency_key=KEY, tenant="acme"
        )
    assert registry.revoked == []


def test_a_malformed_tenant_never_reaches_the_registry():
    integrations, registry, *_ = _build()
    with pytest.raises(ContainmentTargetInvalid, match="invalid tenant"):
        integrations["disable_agent"].execute(
            target=ADDRESS, idempotency_key=KEY, tenant="../../other"
        )
    assert registry.revoked == []


# ── the tenant seam ──────────────────────────────────────────────────────────


class _WebhookLike:
    """An integration written against the ORIGINAL protocol: no tenant."""

    provider = "external"

    def __init__(self) -> None:
        self.calls: list[str] = []

    def execute(self, *, target, idempotency_key):
        self.calls.append(target)
        return {"status": 200}


class _TenantAware:
    provider = "sentinel"

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def execute(self, *, target, idempotency_key, tenant):
        self.calls.append((tenant, target))
        return {"ok": True}


class _Audit:
    def record(self, **_kw) -> None:
        return None


#: `ApprovalPathAuthorizer` is DEFAULT DENY: it permits only actors stamped by
#: `DecideApprovalHandler`, so the module default `actor="system"` is refused.
#: That is the control working, not a test-harness inconvenience -- these tests
#: use a stamped actor because a real containment always has one.
APPROVED_ACTOR = ApprovalPathAuthorizer.APPROVAL_ACTOR_PREFIX + "apr-1"


def _executor(integrations, **kwargs):
    return GuardedRemediationExecutor(
        integrations=integrations,
        authorizer=ApprovalPathAuthorizer(),
        idempotency=InMemoryIdempotencyStore(),
        audit=_Audit(),
        clock=lambda: AT,
        **kwargs,
    )


def test_a_webhook_integration_is_still_called_without_a_tenant():
    """The old contract must keep working untouched. Making `tenant` required
    would have broken every integration written before it existed.
    """
    webhook = _WebhookLike()
    _executor({"disable_agent": webhook}).execute(
        action="disable_agent",
        target=ADDRESS,
        idempotency_key=KEY,
        tenant="acme",
        actor=APPROVED_ACTOR,
    )
    assert webhook.calls == [ADDRESS]


def test_a_tenant_aware_integration_receives_the_tenant():
    aware = _TenantAware()
    _executor({"disable_agent": aware}).execute(
        action="disable_agent",
        target=ADDRESS,
        idempotency_key=KEY,
        tenant="acme",
        actor=APPROVED_ACTOR,
    )
    assert aware.calls == [("acme", ADDRESS)]


def test_a_tenant_scoped_integration_is_refused_without_a_tenant():
    """THE test. An integration that acts on tenant-scoped state and is handed
    no tenant must fail loudly, not default to something. The failure an
    operator needs to see is "no tenant reached the containment", never a row
    written against the wrong estate.
    """
    aware = _TenantAware()
    with pytest.raises(DomainRuleViolated, match="cross-tenant write"):
        _executor({"disable_agent": aware}).execute(
            action="disable_agent",
            target=ADDRESS,
            idempotency_key=KEY,
            actor=APPROVED_ACTOR,
        )
    assert aware.calls == []


def test_the_tenant_is_decided_by_signature_not_by_catching_typeerror():
    """Calling with the keyword and catching `TypeError` would also swallow a
    `TypeError` raised INSIDE a correct integration and silently retry it
    without the tenant. This integration raises one on purpose.
    """

    class _Explodes:
        provider = "sentinel"

        def execute(self, *, target, idempotency_key, tenant):
            raise TypeError("a genuine bug inside the integration")

    with pytest.raises(TypeError, match="a genuine bug"):
        _executor({"disable_agent": _Explodes()}).execute(
            action="disable_agent",
        target=ADDRESS,
        idempotency_key=KEY,
        tenant="acme",
        actor=APPROVED_ACTOR,
        )


def test_a_dry_run_reaches_no_integration_at_all():
    aware = _TenantAware()
    receipt = _executor({"disable_agent": aware}, dry_run=True).execute(
        action="disable_agent",
        target=ADDRESS,
        idempotency_key=KEY,
        tenant="acme",
        actor=APPROVED_ACTOR,
    )
    assert receipt["executed"] is False
    assert aware.calls == []
