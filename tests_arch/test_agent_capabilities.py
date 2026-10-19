"""What an agent may INVOKE: grants, observe mode, and the enforcement seam.

WHY THIS IS A SEPARATE AXIS FROM PROTECT
------------------------------------------
`ProtectGate` asks "is this action dangerous". This asks "is this agent supposed
to be doing it at all", and the answers are independent. A perfectly benign
`echo` from an agent whose only job is summarising text is harmless by content
and still wrong -- no content-based policy will ever catch it, because there is
nothing wrong with the content.

That independence is what the tests below are built around: every enforcement
case uses a tool the deterministic policy has no objection to, so a passing test
means the CAPABILITY check refused it rather than the detector.

OBSERVE MODE IS TESTED AS CAREFULLY AS ENFORCEMENT
----------------------------------------------------
Observe mode allows an ungranted call, which is indistinguishable from a granted
one if you look only at `allowed`. That is exactly the gate-that-executes-
nothing shape this codebase keeps finding, so `enforced` is asserted everywhere
`allowed` is.
"""

from __future__ import annotations

import io
import uuid

import pytest

from sentinel.application.agent_capabilities import (
    AgentCapabilityGate,
    AgentCapabilityRefused,
    InMemoryAgentCapabilities,
)
from sentinel.infrastructure.agent_capabilities import SqlAgentCapabilities
from sentinel.infrastructure.sql.engine import (
    Dialect,
    EngineConfig,
    build_engine,
)
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.interface.cli import main

TENANT_A = "acme"
TENANT_B = "globex"


@pytest.fixture(scope="module")
def module_postgres_dsn(postgres_admin_dsn, postgres_dsn) -> str | None:
    """ONE PostgreSQL database for this whole module, created once.

    NOT `conftest.engine_config`, which creates a fresh database per test. That
    shape costs a `CREATE DATABASE` plus a full `migrate()` every time, and
    across a module parametrised over two engines it does not merely run slowly:
    the embedded server accumulates backends until connections start timing out.

    Measured here, repeatedly. The symptom is a `ConnectionTimeout` in whichever
    test happens to be unlucky -- sometimes at fixture setup, sometimes inside
    the test body, a different test each run -- which reads as flakiness and is
    actually resource exhaustion with a fixed cause.

    `test_retention_sweep.py` hit this first and documented the fix; this is the
    same fix. The isolation that matters for these tests is empty tables, not a
    private catalogue.
    """
    if postgres_dsn is None:
        return None
    from tests_arch.conftest import _fresh_database

    return _fresh_database(postgres_admin_dsn, postgres_dsn)


def _truncate(dsn: str) -> None:
    """Empty every table so each test starts from the same place.

    `TRUNCATE`, not `DELETE`: it keeps the schema and the row-level-security
    policies in place, and it is not itself subject to RLS -- a DELETE here
    would be bounded by the tenant context and could leave rows behind while
    appearing to succeed, which is the exact defect this suite exists to catch
    elsewhere.
    """
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as conn:
        names = [
            r[0]
            for r in conn.execute(
                "SELECT tablename FROM pg_tables WHERE schemaname='public' "
                "AND tablename <> 'schema_migrations'"
            ).fetchall()
        ]
        if names:
            conn.execute(
                "TRUNCATE " + ", ".join(f'"{n}"' for n in names) + " RESTART IDENTITY"
            )


@pytest.fixture(params=["sqlite", "postgres"])
def engine_config(request, tmp_path, module_postgres_dsn) -> EngineConfig:
    """Shadows the conftest fixture of the same name, on purpose.

    Same parametrisation and the same two engines, so the dual-engine fitness
    rule still sees this module as covering both -- but backed by one database
    per module rather than one per test.
    """
    if request.param == "sqlite":
        return EngineConfig(
            dialect=Dialect.SQLITE,
            dsn=str(tmp_path / f"s-{uuid.uuid4().hex[:8]}.db"),
            pool_min=1,
            pool_max=4,
        )
    if module_postgres_dsn is None:
        pytest.skip(
            "no PostgreSQL available: install `pgserver` or set "
            "SENTINEL_TEST_POSTGRES_DSN. Skipping is reported, never silent."
        )
    _truncate(module_postgres_dsn)
    return EngineConfig(
        dialect=Dialect.POSTGRES,
        dsn=module_postgres_dsn,
        pool_min=1,
        pool_max=4,
    )


@pytest.fixture
def pool(engine_config):
    """A migrated pool on whichever engine this parametrisation selected."""
    built = build_engine(engine_config)
    migrate(built)
    for tenant in (TENANT_A, TENANT_B):
        with built.acquire() as conn:
            conn.begin()
            conn.execute_rowcount(
                f"INSERT INTO tenants (tenant_id, name, created_at) "
                f"VALUES ({conn.p},{conn.p},{conn.p})",
                (tenant, tenant, "2026-08-22T00:00:00+00:00"),
            )
            conn.commit()
    yield built
    built.close()


@pytest.fixture
def store(pool) -> SqlAgentCapabilities:
    return SqlAgentCapabilities(pool=pool)


# ── The store ────────────────────────────────────────────────────────────────


def test_a_granted_tool_is_recorded_and_read_back(store):
    """The control case. Without it every refusal below could be a store that
    simply never returns anything."""
    store.grant(TENANT_A, "summariser", frozenset({"echo"}))
    assert store.granted(TENANT_A, "summariser") == frozenset({"echo"})


def test_an_agent_with_no_grants_reads_as_an_empty_set_not_an_error(store):
    assert store.granted(TENANT_A, "never-seen") == frozenset()


def test_granting_is_additive_rather_than_replacing_the_set(store):
    """The OPPOSITE of `SqlMcpRegistry.pin`, and deliberately so.

    A pin is a SNAPSHOT of what a server offered at one moment, so merging would
    leave a stale tool pinned. A grant is a standing authorisation issued one at
    a time, so replacing would make `agent-grant X` silently revoke every
    capability granted before it -- an operator adding one permission would
    remove all the others and get no warning.
    """
    store.grant(TENANT_A, "worker", frozenset({"echo"}))
    store.grant(TENANT_A, "worker", frozenset({"noop"}))
    assert store.granted(TENANT_A, "worker") == frozenset({"echo", "noop"})


def test_re_granting_an_existing_capability_is_idempotent(store):
    store.grant(TENANT_A, "worker", frozenset({"echo"}))
    store.grant(TENANT_A, "worker", frozenset({"echo"}))
    assert store.granted(TENANT_A, "worker") == frozenset({"echo"})
    assert len(store.list_grants(TENANT_A)) == 1, "a duplicate row was written"


def test_revoking_removes_only_the_named_tool(store):
    store.grant(TENANT_A, "worker", frozenset({"echo", "noop"}))
    store.revoke(TENANT_A, "worker", frozenset({"noop"}))
    assert store.granted(TENANT_A, "worker") == frozenset({"echo"})


def test_revoking_something_never_granted_is_not_an_error(store):
    """Revocation must be safe to run twice. An operator responding to an
    incident should not have to check first."""
    store.revoke(TENANT_A, "worker", frozenset({"never-granted"}))
    assert store.granted(TENANT_A, "worker") == frozenset()


def test_grants_are_scoped_per_tenant(store):
    """An agent id is a tenant-local handle, so two tenants may legitimately use
    the same one. A store keyed on agent id alone would let one tenant's grant
    authorise another tenant's agent."""
    store.grant(TENANT_A, "shared-name", frozenset({"echo"}))

    assert store.granted(TENANT_B, "shared-name") == frozenset(), (
        "a grant leaked across tenants through a shared agent id"
    )
    assert store.list_grants(TENANT_B) == ()


def test_list_grants_reports_every_agent_for_operator_review(store):
    store.grant(TENANT_A, "b-agent", frozenset({"noop"}))
    store.grant(TENANT_A, "a-agent", frozenset({"echo"}))

    rows = store.list_grants(TENANT_A)
    assert [(r["agent_id"], r["tool_name"]) for r in rows] == [
        ("a-agent", "echo"),
        ("b-agent", "noop"),
    ]


# ── The gate ─────────────────────────────────────────────────────────────────


def test_observe_mode_allows_an_ungranted_call_and_says_it_did_not_decide():
    """The distinction the whole design rests on.

    `allowed` is True for an agent with no grants at all. If that were the only
    thing reported, a skipped check would be indistinguishable from a passed
    one -- and an operator reading a dashboard would believe capabilities were
    being enforced when nothing was.
    """
    gate = AgentCapabilityGate(store=InMemoryAgentCapabilities(), require_grant=False)
    decision = gate.decide(tenant_id=TENANT_A, agent_id="rogue", tool="echo")

    assert decision.allowed is True
    assert decision.enforced is False
    assert "not an authorisation" in decision.reason


def test_enforcement_refuses_an_ungranted_call():
    gate = AgentCapabilityGate(store=InMemoryAgentCapabilities(), require_grant=True)
    decision = gate.decide(tenant_id=TENANT_A, agent_id="rogue", tool="echo")

    assert decision.allowed is False
    assert decision.enforced is True
    assert "not granted" in decision.reason


def test_enforcement_allows_a_granted_call():
    """The other direction. A gate that refuses everything is not a gate."""
    memory = InMemoryAgentCapabilities()
    memory.grant(TENANT_A, "summariser", frozenset({"echo"}))
    gate = AgentCapabilityGate(store=memory, require_grant=True)

    decision = gate.decide(tenant_id=TENANT_A, agent_id="summariser", tool="echo")
    assert decision.allowed is True
    assert decision.enforced is True
    assert decision.granted == ("echo",)


def test_the_refusal_names_what_the_agent_can_do_and_how_to_fix_it():
    """A refusal that says only "denied" sends an operator to the source."""
    memory = InMemoryAgentCapabilities()
    memory.grant(TENANT_A, "summariser", frozenset({"echo"}))
    gate = AgentCapabilityGate(store=memory, require_grant=True)

    reason = gate.decide(tenant_id=TENANT_A, agent_id="summariser", tool="noop").reason
    assert "echo" in reason, "the refusal does not say what the agent CAN do"
    assert "agent-grant" in reason, "the refusal does not say how to fix it"


def test_require_raises_rather_than_returning_a_falsy_value():
    """`decide` returns a value a caller can forget to check."""
    gate = AgentCapabilityGate(store=InMemoryAgentCapabilities(), require_grant=True)
    with pytest.raises(AgentCapabilityRefused):
        gate.require(tenant_id=TENANT_A, agent_id="rogue", tool="echo")


def test_a_capability_refusal_is_not_retryable():
    gate = AgentCapabilityGate(store=InMemoryAgentCapabilities(), require_grant=True)
    with pytest.raises(AgentCapabilityRefused) as raised:
        gate.require(tenant_id=TENANT_A, agent_id="rogue", tool="echo")
    assert raised.value.is_retryable is False


# ── The proxy seam: capability is checked BEFORE the effect ──────────────────


def _proxy(store, *, require_grant: bool):
    from sentinel.application.protect_gate import ProtectGate
    from sentinel.application.tool_proxy import InlineToolProxy, RegisteredSideEffect
    from sentinel.application.tool_runner import ProtectedToolRunner
    from sentinel.infrastructure.detection import DeterministicPolicy

    ran: list[str] = []
    return ran, InlineToolProxy(
        tool_runner=ProtectedToolRunner(
            gate=ProtectGate(policy=DeterministicPolicy.default(), enforce=True)
        ),
        effects={
            "echo": RegisteredSideEffect(
                name="echo", runner=lambda args: ran.append("echo") or {"ok": True}
            )
        },
        capabilities=AgentCapabilityGate(store=store, require_grant=require_grant),
    )


def test_an_ungranted_tool_never_reaches_the_side_effect(store):
    """Checked before the effect, which is the only ordering that matters."""
    from sentinel.application.tool_proxy import ToolProxyRefused
    from sentinel.domain.primitives import TrustLevel

    ran, proxy = _proxy(store, require_grant=True)
    with pytest.raises(ToolProxyRefused, match="not granted"):
        proxy.execute(
            agent_id="rogue",
            tool="echo",
            trust=TrustLevel.UNSIGNED,
            tenant_id=TENANT_A,
        )
    assert ran == [], "the side effect ran for an agent that was refused"


def test_a_granted_tool_runs_and_reports_the_capability_decision(store):
    from sentinel.domain.primitives import TrustLevel

    store.grant(TENANT_A, "summariser", frozenset({"echo"}))
    ran, proxy = _proxy(store, require_grant=True)

    response = proxy.execute(
        agent_id="summariser",
        tool="echo",
        trust=TrustLevel.UNSIGNED,
        tenant_id=TENANT_A,
    )
    assert ran == ["echo"]
    assert response["capability"]["allowed"] is True
    assert response["capability"]["enforced"] is True


def test_the_capability_check_is_independent_of_the_content_policy(store):
    """`echo` with harmless arguments is something ProtectGate has no objection
    to. If this call is refused, the capability check refused it -- which is the
    claim, and the reason a content-based policy can never cover this axis."""
    from sentinel.application.tool_proxy import ToolProxyRefused
    from sentinel.domain.primitives import TrustLevel

    ran, permissive = _proxy(store, require_grant=False)
    permissive.execute(
        agent_id="rogue", tool="echo", trust=TrustLevel.UNSIGNED,
        tenant_id=TENANT_A, arguments={"message": "hello"},
    )
    assert ran == ["echo"], "the policy objected to a benign call; premise broken"

    ran2, strict = _proxy(store, require_grant=True)
    with pytest.raises(ToolProxyRefused):
        strict.execute(
            agent_id="rogue", tool="echo", trust=TrustLevel.UNSIGNED,
            tenant_id=TENANT_A, arguments={"message": "hello"},
        )
    assert ran2 == []


def test_one_tenants_grant_does_not_authorise_another_tenants_agent(store):
    from sentinel.application.tool_proxy import ToolProxyRefused
    from sentinel.domain.primitives import TrustLevel

    store.grant(TENANT_A, "shared-name", frozenset({"echo"}))
    ran, proxy = _proxy(store, require_grant=True)

    proxy.execute(
        agent_id="shared-name", tool="echo",
        trust=TrustLevel.UNSIGNED, tenant_id=TENANT_A,
    )
    assert ran == ["echo"]

    with pytest.raises(ToolProxyRefused, match="not granted"):
        proxy.execute(
            agent_id="shared-name", tool="echo",
            trust=TrustLevel.UNSIGNED, tenant_id=TENANT_B,
        )


def test_a_proxy_without_a_capability_gate_behaves_exactly_as_before(store):
    """Backward compatibility, asserted rather than assumed.

    `capabilities=None` means the question is not asked at all -- a different
    state from asking it in observe mode, and the response says so by carrying
    no `capability` key.
    """
    from sentinel.application.protect_gate import ProtectGate
    from sentinel.application.tool_proxy import InlineToolProxy, RegisteredSideEffect
    from sentinel.application.tool_runner import ProtectedToolRunner
    from sentinel.domain.primitives import TrustLevel
    from sentinel.infrastructure.detection import DeterministicPolicy

    proxy = InlineToolProxy(
        tool_runner=ProtectedToolRunner(
            gate=ProtectGate(policy=DeterministicPolicy.default(), enforce=True)
        ),
        effects={"echo": RegisteredSideEffect(name="echo", runner=lambda a: {"ok": True})},
    )
    response = proxy.execute(
        agent_id="anyone", tool="echo", trust=TrustLevel.UNSIGNED
    )
    assert response["result"] == {"ok": True}
    assert "capability" not in response


# ── The operator path ────────────────────────────────────────────────────────


def _cli(pool, *argv: str, monkeypatch, engine_config) -> tuple[int, str]:
    if engine_config.dialect is Dialect.POSTGRES:
        monkeypatch.setenv("SENTINEL_DATABASE_URL", engine_config.dsn)
        monkeypatch.delenv("SENTINEL_DB_PATH", raising=False)
        # Small pools: the container is not involved here, but `main` builds an
        # engine per invocation and the production default of 20 exhausts the
        # server across a parametrised module.
        monkeypatch.setenv("SENTINEL_DB_POOL_MIN", "1")
        monkeypatch.setenv("SENTINEL_DB_POOL_MAX", "4")
    else:
        monkeypatch.setenv("SENTINEL_DB_PATH", engine_config.dsn)
        monkeypatch.delenv("SENTINEL_DATABASE_URL", raising=False)
    monkeypatch.setenv("SENTINEL_API_KEYS", f"{TENANT_A}:{'k' * 40}:ingest")
    monkeypatch.delenv("SENTINEL_ENV", raising=False)

    out = io.StringIO()
    return main(list(argv), out=out), out.getvalue()


def test_the_cli_grants_and_the_store_sees_it(pool, monkeypatch, engine_config):
    """Grants are CLI-only, so if this path is broken no capability can ever be
    issued and enforcement would refuse everything for ever."""
    code, output = _cli(
        pool, "agent-grant", TENANT_A, "summariser", "echo", "noop",
        monkeypatch=monkeypatch, engine_config=engine_config,
    )
    assert code == 0, output
    assert "echo" in output and "noop" in output

    assert SqlAgentCapabilities(pool=pool).granted(TENANT_A, "summariser") == frozenset(
        {"echo", "noop"}
    )


def test_the_cli_revoke_reports_what_remains(pool, monkeypatch, engine_config):
    """An operator revoking one capability needs to see what the agent can STILL
    do; a message reporting only the delta invites the assumption that nothing
    else remains."""
    _cli(pool, "agent-grant", TENANT_A, "w", "echo", "noop",
         monkeypatch=monkeypatch, engine_config=engine_config)
    code, output = _cli(pool, "agent-revoke", TENANT_A, "w", "noop",
                        monkeypatch=monkeypatch, engine_config=engine_config)

    assert code == 0
    assert "now granted: echo" in output


def test_an_empty_grant_listing_explains_what_empty_means(
    pool, monkeypatch, engine_config
):
    """"No grants" means opposite things depending on enforcement: every agent
    may invoke everything, or none may invoke anything. A blank screen looks
    identical for both."""
    code, output = _cli(pool, "agent-grants", TENANT_A,
                        monkeypatch=monkeypatch, engine_config=engine_config)

    assert code == 0
    assert "no tool grants recorded" in output
    assert "SENTINEL_AGENT_REQUIRE_GRANT" in output


def test_missing_arguments_return_the_usage_exit_code(
    pool, monkeypatch, engine_config
):
    for argv in (
        ("agent-grant", TENANT_A),
        ("agent-revoke", TENANT_A, "agent-with-no-tool"),
        ("agent-grants",),
    ):
        code, output = _cli(pool, *argv, monkeypatch=monkeypatch,
                            engine_config=engine_config)
        assert code == 64, f"{argv} returned {code}: {output}"
        assert "usage:" in output
