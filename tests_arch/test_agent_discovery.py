"""Agent discovery: seeing agents nobody enrolled, and what they reach.

THE DEFECT, DEMONSTRATED BEFORE IT WAS FIXED
----------------------------------------------
`AdmitEvent` recorded contact only for agents that were both enrolled AND
signed. `record_event` issues `UPDATE agents ... WHERE address=?`, so for an
agent nobody enrolled it updated zero rows and the agent left no trace.

Run against a live build before the fix: an unenrolled agent sent one event,
Sentinel raised a HIGH severity incident (79) about it, and the `agents` table
stayed empty. The product knew something bad had happened and could not say who
did it.

That is what "unknown agents must be classified as unmanaged" is asking for, and
it was not merely unimplemented -- it was unimplementable, because the data was
never recorded.

WHAT THESE TESTS GUARD
----------------------
Mostly that discovery does NOT become authorisation. Recording that an agent was
seen is evidence of existence, never of permission, and the easiest way to ruin
this feature would be to let "we have seen it" quietly imply "it is fine".
"""

from __future__ import annotations

import io
import uuid

import pytest

from sentinel.domain.inventory import (
    DECLARABLE_FIELDS,
    MAX_DECLARED_CHARS,
    AgentClassification,
    DeclarationRejected,
    ObservedEdgeKind,
    classify_agent,
    score_agent_trust,
    validate_declaration,
)
from sentinel.infrastructure.agent_capabilities import SqlAgentCapabilities
from sentinel.infrastructure.inventory import (
    MAX_EDGES_PER_AGENT,
    MAX_TARGET_CHARS,
    SqlAgentInventory,
)
from sentinel.infrastructure.sql.engine import (
    Dialect,
    EngineConfig,
    build_engine,
)
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.interface.cli import main

TENANT_A = "acme"
TENANT_B = "globex"
NOW = "2026-08-23T00:00:00+00:00"


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
    built = build_engine(engine_config)
    migrate(built)
    for tenant in (TENANT_A, TENANT_B):
        with built.acquire() as conn:
            conn.begin()
            conn.execute_rowcount(
                f"INSERT INTO tenants (tenant_id, name, created_at) "
                f"VALUES ({conn.p},{conn.p},{conn.p})",
                (tenant, tenant, NOW),
            )
            conn.commit()
    yield built
    built.close()


@pytest.fixture
def inventory(pool) -> SqlAgentInventory:
    return SqlAgentInventory(pool=pool)


def _enrol(pool, tenant: str, agent: str, *, revoked: bool = False) -> None:
    with pool.acquire() as conn:
        conn.begin()
        conn.set_tenant(tenant)
        p = conn.p
        conn.execute_rowcount(
            f"INSERT INTO agents (tenant_id, address, label, enrolled_at, revoked_at) "
            f"VALUES ({p},{p},{p},{p},{p})",
            (tenant, agent, "", NOW, NOW if revoked else None),
        )
        conn.commit()


# ── Classification is derived, not stored ────────────────────────────────────


def test_classification_covers_the_three_states_it_claims_to():
    assert classify_agent(enrolled=False, revoked=False) is AgentClassification.UNMANAGED
    assert classify_agent(enrolled=True, revoked=False) is AgentClassification.MANAGED
    assert (
        classify_agent(enrolled=True, revoked=True)
        is AgentClassification.REVOKED_BUT_ACTIVE
    )


def test_a_revoked_agent_still_sending_events_is_not_folded_into_either_bucket():
    """The most serious of the three, and the one an enum with two members
    would lose. Somebody deliberately withdrew this agent's standing and it is
    still running; calling that "unmanaged" understates it and calling it
    "managed" is false."""
    revoked = classify_agent(enrolled=True, revoked=True)
    assert revoked is not AgentClassification.MANAGED
    assert revoked is not AgentClassification.UNMANAGED
    assert revoked.needs_attention is True


def test_only_managed_does_not_need_attention():
    needing = {c for c in AgentClassification if c.needs_attention}
    assert needing == {
        AgentClassification.UNMANAGED,
        AgentClassification.REVOKED_BUT_ACTIVE,
    }


# ── Observation ──────────────────────────────────────────────────────────────


def test_an_agent_nobody_enrolled_is_recorded_and_classified_unmanaged(inventory):
    """THE headline case. Before this, the agent left no trace at all."""
    inventory.observe(TENANT_A, "shadow-agent", at=NOW)

    profile = inventory.profile(TENANT_A, "shadow-agent")
    assert profile is not None, "an unenrolled agent was not recorded at all"
    assert profile.classification is AgentClassification.UNMANAGED
    assert profile.event_count == 1


def test_an_enrolled_agent_is_classified_managed(inventory, pool):
    """The other direction. If everything came back unmanaged the field would
    carry no information."""
    _enrol(pool, TENANT_A, "known-agent")
    inventory.observe(TENANT_A, "known-agent", at=NOW)

    profile = inventory.profile(TENANT_A, "known-agent")
    assert profile.classification is AgentClassification.MANAGED
    assert profile.classification.needs_attention is False


def test_a_revoked_agent_that_keeps_calling_is_flagged(inventory, pool):
    _enrol(pool, TENANT_A, "sacked-agent", revoked=True)
    inventory.observe(TENANT_A, "sacked-agent", at=NOW)

    profile = inventory.profile(TENANT_A, "sacked-agent")
    assert profile.classification is AgentClassification.REVOKED_BUT_ACTIVE


def test_repeat_observations_accumulate_rather_than_duplicating(inventory):
    for _ in range(3):
        inventory.observe(TENANT_A, "chatty", at=NOW)

    profile = inventory.profile(TENANT_A, "chatty")
    assert profile.event_count == 3
    assert profile.first_seen == NOW


def test_an_agent_never_seen_has_no_profile(inventory):
    """None, not an empty profile. A profile for an agent that never existed
    would make every reachability query return phantom results."""
    assert inventory.profile(TENANT_A, "never-existed") is None


def test_a_blank_agent_id_is_ignored_rather_than_stored(inventory):
    """An event with no agent id is not an agent. Recording one would put an
    entry called "" at the top of every operator's inventory."""
    inventory.observe(TENANT_A, "", at=NOW)
    inventory.observe(TENANT_A, "   ", at=NOW)
    assert inventory.list_profiles(TENANT_A) == ()


# ── Observation is not authorisation ─────────────────────────────────────────


def test_observing_an_agent_does_not_enrol_it(inventory, pool):
    """The failure that would ruin this feature.

    Discovery must never promote "we have seen this" into "this is known and
    therefore permitted". If observation wrote to `agents`, an attacker could
    enrol themselves by sending one event.
    """
    inventory.observe(TENANT_A, "intruder", at=NOW)

    with pool.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT_A)
        rows = conn.execute(
            f"SELECT address FROM agents WHERE tenant_id={conn.p}", (TENANT_A,)
        )
        conn.commit()
    assert [r["address"] for r in rows] == [], (
        "observing an agent wrote it into the enrolment table; discovery became "
        "an authorisation bypass"
    )


def test_observing_an_agent_grants_it_nothing(inventory):
    inventory.observe(TENANT_A, "intruder", at=NOW)
    assert inventory.profile(TENANT_A, "intruder").granted_tools == ()


# ── Edges: the attack surface graph ──────────────────────────────────────────


def test_edges_record_what_an_agent_reached(inventory):
    inventory.observe(
        TENANT_A,
        "worker",
        at=NOW,
        edges=[
            (ObservedEdgeKind.ACTION, "read_file"),
            (ObservedEdgeKind.RESOURCE, "/etc/passwd"),
            (ObservedEdgeKind.DESTINATION, "https://evil.example"),
        ],
    )
    profile = inventory.profile(TENANT_A, "worker")
    assert {(e.kind, e.target) for e in profile.edges} == {
        (ObservedEdgeKind.ACTION, "read_file"),
        (ObservedEdgeKind.RESOURCE, "/etc/passwd"),
        (ObservedEdgeKind.DESTINATION, "https://evil.example"),
    }
    assert profile.external_destinations == ("https://evil.example",)


def test_a_repeated_edge_bumps_its_count_rather_than_adding_a_row(inventory):
    """An edge seen once and an edge seen four thousand times are different
    facts, and a graph that flattens them makes every agent look equally
    connected."""
    for _ in range(4):
        inventory.observe(
            TENANT_A, "worker", at=NOW,
            edges=[(ObservedEdgeKind.RESOURCE, "/etc/passwd")],
        )
    edges = inventory.profile(TENANT_A, "worker").edges
    assert len(edges) == 1
    assert edges[0].occurrences == 4


def test_the_reachability_query_answers_which_agents_touched_a_pattern(inventory):
    inventory.observe(TENANT_A, "pii-reader", at=NOW,
                      edges=[(ObservedEdgeKind.RESOURCE, "customer_pii_table")])
    inventory.observe(TENANT_A, "harmless", at=NOW,
                      edges=[(ObservedEdgeKind.RESOURCE, "reports/q3.csv")])

    assert inventory.agents_reaching(
        TENANT_A, kind=ObservedEdgeKind.RESOURCE, pattern="%pii%"
    ) == ("pii-reader",)


def test_the_reachability_query_is_scoped_to_the_edge_kind(inventory):
    """An agent whose ACTION is named `customer_pii_sync` has not read PII. A
    query that ignored kind would report it as though it had."""
    inventory.observe(TENANT_A, "misleading", at=NOW,
                      edges=[(ObservedEdgeKind.ACTION, "customer_pii_sync")])

    assert inventory.agents_reaching(
        TENANT_A, kind=ObservedEdgeKind.RESOURCE, pattern="%pii%"
    ) == ()
    assert inventory.agents_reaching(
        TENANT_A, kind=ObservedEdgeKind.ACTION, pattern="%pii%"
    ) == ("misleading",)


def test_ungranted_tools_used_is_the_gap_between_authorised_and_actual(
    inventory, pool
):
    """The most actionable line in a profile, and the check on a rollout: after
    capability enforcement is on this should be empty."""
    SqlAgentCapabilities(pool=pool).grant(TENANT_A, "worker", frozenset({"echo"}))
    inventory.observe(TENANT_A, "worker", at=NOW, edges=[
        (ObservedEdgeKind.TOOL, "echo"),
        (ObservedEdgeKind.TOOL, "http_request"),
    ])

    profile = inventory.profile(TENANT_A, "worker")
    assert profile.granted_tools == ("echo",)
    assert set(profile.observed_tools) == {"echo", "http_request"}
    assert profile.ungranted_tools_used == ("http_request",)


# ── Bounds: this runs on the ingest hot path ─────────────────────────────────


def test_edge_breadth_is_capped_per_agent(inventory):
    """An agent touching a million distinct paths must not become a million
    rows. The cap is on BREADTH because that is what actually grows."""
    inventory.observe(TENANT_A, "crawler", at=NOW, edges=[
        (ObservedEdgeKind.RESOURCE, f"/path/{n}") for n in range(MAX_EDGES_PER_AGENT + 50)
    ])
    profile = inventory.profile(TENANT_A, "crawler")
    assert len(profile.edges) <= MAX_EDGES_PER_AGENT


def test_a_repeated_target_is_never_capped_out(inventory):
    """Only NEW targets consume headroom, so an agent hammering one resource
    keeps being counted however long it runs."""
    inventory.observe(TENANT_A, "crawler", at=NOW, edges=[
        (ObservedEdgeKind.RESOURCE, f"/path/{n}") for n in range(MAX_EDGES_PER_AGENT + 10)
    ])
    for _ in range(3):
        inventory.observe(TENANT_A, "crawler", at=NOW,
                          edges=[(ObservedEdgeKind.RESOURCE, "/path/0")])

    edge = next(e for e in inventory.profile(TENANT_A, "crawler").edges
                if e.target == "/path/0")
    assert edge.occurrences == 4


def test_an_overlong_target_is_truncated_rather_than_refused(inventory):
    """A path is attacker-influenced text. Refusing the observation would lose
    the AGENT as well as the target, which is the more valuable of the two."""
    inventory.observe(TENANT_A, "worker", at=NOW,
                      edges=[(ObservedEdgeKind.RESOURCE, "/" + "a" * (MAX_TARGET_CHARS * 3))])

    edge = inventory.profile(TENANT_A, "worker").edges[0]
    assert len(edge.target) <= MAX_TARGET_CHARS


# ── Tenancy ──────────────────────────────────────────────────────────────────


def test_observations_are_scoped_per_tenant(inventory):
    inventory.observe(TENANT_A, "shared-name", at=NOW,
                      edges=[(ObservedEdgeKind.RESOURCE, "secret")])

    assert inventory.profile(TENANT_B, "shared-name") is None
    assert inventory.list_profiles(TENANT_B) == ()
    assert inventory.agents_reaching(
        TENANT_B, kind=ObservedEdgeKind.RESOURCE, pattern="%"
    ) == ()


def test_one_tenants_enrolment_does_not_classify_another_tenants_agent(
    inventory, pool
):
    """Both tenants have an agent called `shared-name`; only one enrolled it."""
    _enrol(pool, TENANT_A, "shared-name")
    inventory.observe(TENANT_A, "shared-name", at=NOW)
    inventory.observe(TENANT_B, "shared-name", at=NOW)

    assert inventory.profile(TENANT_A, "shared-name").classification is (
        AgentClassification.MANAGED
    )
    assert inventory.profile(TENANT_B, "shared-name").classification is (
        AgentClassification.UNMANAGED
    ), "one tenant's enrolment marked another tenant's agent as managed"


# ── Listing puts the problems first ──────────────────────────────────────────


def test_agents_needing_attention_are_listed_before_managed_ones(inventory, pool):
    """An inventory sorted alphabetically buries the one unmanaged agent among
    two hundred managed ones, and finding that one is the entire point."""
    _enrol(pool, TENANT_A, "aaa-managed")
    inventory.observe(TENANT_A, "aaa-managed", at=NOW)
    inventory.observe(TENANT_A, "zzz-shadow", at=NOW)

    order = [p.agent_id for p in inventory.list_profiles(TENANT_A)]
    assert order == ["zzz-shadow", "aaa-managed"]


def test_listing_can_be_filtered_to_one_classification(inventory, pool):
    _enrol(pool, TENANT_A, "managed-one")
    inventory.observe(TENANT_A, "managed-one", at=NOW)
    inventory.observe(TENANT_A, "shadow-one", at=NOW)

    unmanaged = inventory.list_profiles(
        TENANT_A, classification=AgentClassification.UNMANAGED
    )
    assert [p.agent_id for p in unmanaged] == ["shadow-one"]


# ── The operator path ────────────────────────────────────────────────────────


def _cli(*argv: str, monkeypatch, engine_config) -> tuple[int, str]:
    if engine_config.dialect is Dialect.POSTGRES:
        monkeypatch.setenv("SENTINEL_DATABASE_URL", engine_config.dsn)
        monkeypatch.delenv("SENTINEL_DB_PATH", raising=False)
        monkeypatch.setenv("SENTINEL_DB_POOL_MIN", "1")
        monkeypatch.setenv("SENTINEL_DB_POOL_MAX", "4")
    else:
        monkeypatch.setenv("SENTINEL_DB_PATH", engine_config.dsn)
        monkeypatch.delenv("SENTINEL_DATABASE_URL", raising=False)
    monkeypatch.setenv("SENTINEL_API_KEYS", f"{TENANT_A}:{'k' * 40}:ingest")
    monkeypatch.delenv("SENTINEL_ENV", raising=False)

    out = io.StringIO()
    return main(list(argv), out=out), out.getvalue()


def test_the_cli_lists_discovered_agents(inventory, monkeypatch, engine_config):
    inventory.observe(TENANT_A, "shadow-agent", at=NOW,
                      edges=[(ObservedEdgeKind.DESTINATION, "https://evil.example")])

    code, output = _cli("agent-inventory", TENANT_A,
                        monkeypatch=monkeypatch, engine_config=engine_config)
    assert code == 0, output
    assert "shadow-agent" in output
    assert "unmanaged" in output
    assert "https://evil.example" in output


def test_an_empty_inventory_explains_what_empty_means(
    pool, monkeypatch, engine_config
):
    """"No agents" is either a quiet estate or a broken integration, and those
    need opposite responses."""
    code, output = _cli("agent-inventory", TENANT_A,
                        monkeypatch=monkeypatch, engine_config=engine_config)
    assert code == 0
    assert "no agents observed" in output
    assert "not reaching this database" in output


def test_the_cli_answers_a_reachability_question(
    inventory, monkeypatch, engine_config
):
    inventory.observe(TENANT_A, "pii-reader", at=NOW,
                      edges=[(ObservedEdgeKind.RESOURCE, "customer_pii")])

    code, output = _cli("agent-reach", TENANT_A, "resource", "%pii%",
                        monkeypatch=monkeypatch, engine_config=engine_config)
    assert code == 0, output
    assert "pii-reader" in output


def test_an_unknown_edge_kind_is_refused_with_the_valid_ones(
    pool, monkeypatch, engine_config
):
    code, output = _cli("agent-reach", TENANT_A, "not-a-kind", "%",
                        monkeypatch=monkeypatch, engine_config=engine_config)
    assert code == 64
    assert "destination" in output, "the error does not say what IS valid"


def test_missing_arguments_return_the_usage_exit_code(
    pool, monkeypatch, engine_config
):
    for argv in (("agent-inventory",), ("agent-reach", TENANT_A), ("agent-reach",)):
        code, output = _cli(*argv, monkeypatch=monkeypatch, engine_config=engine_config)
        assert code == 64, f"{argv} returned {code}: {output}"
        assert "usage:" in output


# ── Declared metadata: what a human asserts ──────────────────────────────────


def test_only_the_declared_fields_the_spec_names_are_accepted():
    """A CLOSED set, not free-form keys.

    An inventory where every team invents its own field names cannot be
    queried, and "which agents does the payments team own" is the question this
    exists to answer.
    """
    assert validate_declaration("owner", "payments-oncall") == (
        "owner",
        "payments-oncall",
    )
    with pytest.raises(DeclarationRejected, match="unknown field"):
        validate_declaration("favourite_colour", "blue")


def test_the_refusal_names_the_valid_fields():
    """An error saying only "invalid" sends an operator to the source code."""
    with pytest.raises(DeclarationRejected) as raised:
        validate_declaration("nonsense", "x")
    assert "owner" in str(raised.value)
    assert "risk_tier" in str(raised.value)


def test_a_risk_tier_is_normalised_rather_than_stored_as_typed():
    """Two teams writing "high" and "High" produce an inventory that cannot be
    filtered, and filtering by tier during an incident is the whole point."""
    assert validate_declaration("risk_tier", "HIGH") == ("risk_tier", "high")
    assert validate_declaration("Risk_Tier", " Critical ") == (
        "risk_tier",
        "critical",
    )


def test_an_invented_risk_tier_is_refused_with_the_real_ones_listed():
    with pytest.raises(DeclarationRejected, match="low, medium, high, critical"):
        validate_declaration("risk_tier", "extreme")


def test_a_blank_value_is_refused_rather_than_recorded():
    """Recording a blank is not the same as recording nothing: it reads as
    though somebody answered."""
    with pytest.raises(DeclarationRejected, match="empty"):
        validate_declaration("owner", "   ")


def test_an_overlong_value_is_refused(inventory):
    with pytest.raises(DeclarationRejected, match="longer than"):
        validate_declaration("purpose", "x" * (MAX_DECLARED_CHARS + 1))


def test_a_declaration_appears_in_the_profile_kept_apart_from_observations(
    inventory,
):
    """The separation is the point. A human's guess at "Framework: LangChain"
    must never be indistinguishable from a measurement."""
    inventory.observe(TENANT_A, "worker", at=NOW)
    inventory.declare(TENANT_A, "worker", "owner", "payments-oncall")
    inventory.declare(TENANT_A, "worker", "risk_tier", "HIGH")

    profile = inventory.profile(TENANT_A, "worker")
    assert profile.declared == {"owner": "payments-oncall", "risk_tier": "high"}
    # And the observed half is untouched by it.
    assert profile.event_count == 1
    assert profile.classification is AgentClassification.UNMANAGED


def test_re_declaring_a_field_replaces_it(inventory):
    inventory.observe(TENANT_A, "worker", at=NOW)
    inventory.declare(TENANT_A, "worker", "team", "platform")
    inventory.declare(TENANT_A, "worker", "team", "payments")

    assert inventory.profile(TENANT_A, "worker").declared == {"team": "payments"}


def test_undeclare_removes_the_field_and_reports_whether_it_was_there(inventory):
    """The boolean matters: "no such field" and "wrong agent id" look identical
    to an operator otherwise, and the second means the correction did not
    land."""
    inventory.observe(TENANT_A, "worker", at=NOW)
    inventory.declare(TENANT_A, "worker", "team", "platform")

    assert inventory.undeclare(TENANT_A, "worker", "team") is True
    assert inventory.profile(TENANT_A, "worker").declared == {}
    assert inventory.undeclare(TENANT_A, "worker", "team") is False


def test_declaring_does_not_create_an_agent(inventory):
    """A profile exists because an agent was OBSERVED. Declaring metadata about
    an id nobody has seen records an assertion about something that may not
    exist -- and if the id is a typo, inventing an inventory entry for it would
    hide the mistake for ever."""
    inventory.declare(TENANT_A, "typo-agent", "team", "platform")
    assert inventory.profile(TENANT_A, "typo-agent") is None
    assert inventory.list_profiles(TENANT_A) == ()


def test_declarations_are_scoped_per_tenant(inventory):
    inventory.observe(TENANT_A, "shared-name", at=NOW)
    inventory.observe(TENANT_B, "shared-name", at=NOW)
    inventory.declare(TENANT_A, "shared-name", "owner", "acme-team")

    assert inventory.profile(TENANT_B, "shared-name").declared == {}


def test_the_cli_declares_and_reports_normalisation(
    inventory, monkeypatch, engine_config
):
    inventory.observe(TENANT_A, "worker", at=NOW)
    code, output = _cli("agent-declare", TENANT_A, "worker", "risk_tier", "CRITICAL",
                        monkeypatch=monkeypatch, engine_config=engine_config)
    assert code == 0, output
    assert "critical" in output
    assert "normalised" in output, (
        "an operator who typed CRITICAL should learn it was normalised now, not "
        "when a filter on CRITICAL returns nothing"
    )


def test_the_cli_warns_when_declaring_against_an_unobserved_agent(
    pool, monkeypatch, engine_config
):
    """Silence here would let a typo in an agent id look like success for ever."""
    code, output = _cli("agent-declare", TENANT_A, "typo-agent", "team", "platform",
                        monkeypatch=monkeypatch, engine_config=engine_config)
    assert code == 0
    assert "has been observed" in output


def test_the_cli_lists_the_declarable_fields(pool, monkeypatch, engine_config):
    code, output = _cli("agent-fields", monkeypatch=monkeypatch,
                        engine_config=engine_config)
    assert code == 0
    for name in DECLARABLE_FIELDS:
        assert name in output


def test_the_cli_refuses_an_unknown_field_with_a_usage_exit_code(
    pool, monkeypatch, engine_config
):
    code, output = _cli("agent-declare", TENANT_A, "worker", "nonsense", "x",
                        monkeypatch=monkeypatch, engine_config=engine_config)
    assert code == 64
    assert "unknown field" in output


def test_undeclaring_something_absent_is_reported_as_a_failure(
    pool, monkeypatch, engine_config
):
    code, output = _cli("agent-undeclare", TENANT_A, "worker", "team",
                        monkeypatch=monkeypatch, engine_config=engine_config)
    assert code == 1, "an undeclare that removed nothing reported success"
    assert "nothing removed" in output


# ── Trust score: a number nobody has to take on faith ────────────────────────


def test_an_agent_with_nothing_against_it_scores_full_marks():
    """Starts at 100 and DEDUCTS. Absence of evidence is not evidence of
    misbehaviour, and an inventory that flagged every quiet agent as untrusted
    would train operators to ignore the column."""
    score = score_agent_trust(
        classification=AgentClassification.MANAGED, has_owner=True
    )
    assert score.score == 100
    assert score.band == "trusted"
    assert score.factors == ()


def test_every_deduction_names_the_observation_behind_it():
    """`docs/` has a standing objection to opaque scores. A security product
    that outputs "trust: 42" without saying why asks an operator to act on a
    number they cannot check."""
    score = score_agent_trust(
        classification=AgentClassification.UNMANAGED,
        incident_count=1,
        ungranted_tools=["http_request"],
        external_destinations=["https://evil.example"],
    )
    assert score.score < 100
    assert score.factors, "a score moved with no factors recorded"
    for factor in score.factors:
        assert factor.delta > 0
        assert len(factor.detail) > 10, f"{factor.name} has no explanation"
    # And it reconciles: the score is exactly what the factors say it is.
    assert score.score == 100 - sum(f.delta for f in score.factors)


def test_a_revoked_but_active_agent_scores_worse_than_an_unmanaged_one():
    """Somebody withdrew that agent's standing and it is still running."""
    unmanaged = score_agent_trust(classification=AgentClassification.UNMANAGED)
    revoked = score_agent_trust(classification=AgentClassification.REVOKED_BUT_ACTIVE)
    assert revoked.score < unmanaged.score


def test_one_noisy_agent_cannot_drive_a_single_factor_without_limit():
    """Forty incidents and four incidents must not look identical, but beyond a
    handful more of the same tells an operator nothing new."""
    four = score_agent_trust(classification=AgentClassification.MANAGED,
                             incident_count=4, has_owner=True)
    forty = score_agent_trust(classification=AgentClassification.MANAGED,
                              incident_count=40, has_owner=True)
    assert four.score == forty.score, "the per-factor cap is not applied"
    assert forty.score >= 0


def test_a_score_never_goes_below_zero():
    worst = score_agent_trust(
        classification=AgentClassification.REVOKED_BUT_ACTIVE,
        incident_count=100,
        ungranted_tools=[f"t{n}" for n in range(20)],
        external_destinations=[f"https://x{n}" for n in range(20)],
    )
    assert worst.score == 0
    assert worst.band == "untrusted"


def test_the_trust_score_is_computed_on_read_not_stored(inventory):
    """A stored score drifts from the facts the moment a new incident lands,
    and a stale trust score is worse than none: a number an operator trusts
    that quietly stopped being true."""
    inventory.observe(TENANT_A, "worker", at=NOW)
    before = inventory.profile(TENANT_A, "worker").trust.score

    inventory.declare(TENANT_A, "worker", "owner", "someone")
    after = inventory.profile(TENANT_A, "worker").trust.score

    assert after > before, "declaring an owner did not change the score"


def test_nothing_in_the_enforcement_path_reads_the_trust_score():
    """A score that silently gated traffic would be an unreviewable policy.

    `ProtectGate` decides on content and `AgentCapabilityGate` on grants;
    neither imports the scorer, and this asserts that rather than trusting it.
    """
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "sentinel"
    for module in ("application/protect_gate.py", "application/tool_runner.py",
                   "application/agent_capabilities.py", "application/tool_proxy.py"):
        source = (root / module).read_text(encoding="utf-8")
        assert "score_agent_trust" not in source and "TrustScore" not in source, (
            f"{module} reads the trust score; a triage number must not gate traffic"
        )


# ── Credentials: the missing link in the chain ───────────────────────────────


def test_a_credential_edge_records_a_fingerprint_and_never_a_secret(inventory):
    inventory.observe(TENANT_A, "worker", at=NOW,
                      edges=[(ObservedEdgeKind.CREDENTIAL, "credential-fingerprint-one")])

    profile = inventory.profile(TENANT_A, "worker")
    assert profile.credentials == ("credential-fingerprint-one",)


def test_agents_sharing_a_credential_can_be_listed(inventory):
    """The question a compromise starts with: if this key leaked, who is
    affected. Until credentials were recorded this was unanswerable."""
    for agent in ("agent-a", "agent-b"):
        inventory.observe(TENANT_A, agent, at=NOW,
                          edges=[(ObservedEdgeKind.CREDENTIAL, "credential-fingerprint-shared")])
    inventory.observe(TENANT_A, "agent-c", at=NOW,
                      edges=[(ObservedEdgeKind.CREDENTIAL, "credential-fingerprint-other")])

    assert inventory.agents_sharing_credential(TENANT_A, "credential-fingerprint-shared") == (
        "agent-a",
        "agent-b",
    )


# ── Violations are not incidents ─────────────────────────────────────────────


def test_a_violation_is_counted_separately_from_an_incident(inventory):
    """A violation the gate REFUSED never became an incident, so counting only
    incidents undercounts exactly the cases where enforcement worked."""
    inventory.observe(TENANT_A, "worker", at=NOW, violation=True)
    inventory.observe(TENANT_A, "worker", at=NOW, violation=False)

    profile = inventory.profile(TENANT_A, "worker")
    assert profile.event_count == 2
    assert profile.violation_count == 1
    assert profile.incident_count == 0, (
        "a violation was counted as an incident; the two are different facts"
    )


# ── The remaining profile fields ─────────────────────────────────────────────


def test_the_name_falls_back_to_the_id_for_an_agent_nobody_enrolled(inventory):
    """An unmanaged agent has no label by definition -- nobody enrolled it --
    so its id is the only name it has."""
    inventory.observe(TENANT_A, "shadow", at=NOW)
    assert inventory.profile(TENANT_A, "shadow").name == "shadow"


def test_an_enrolled_agents_label_becomes_its_name(inventory, pool):
    with pool.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT_A)
        p = conn.p
        conn.execute_rowcount(
            f"INSERT INTO agents (tenant_id, address, label, enrolled_at) "
            f"VALUES ({p},{p},{p},{p})",
            (TENANT_A, "svc-1", "Reporting Agent", NOW),
        )
        conn.commit()
    inventory.observe(TENANT_A, "svc-1", at=NOW)

    assert inventory.profile(TENANT_A, "svc-1").name == "Reporting Agent"


def test_accessible_data_and_mcp_servers_are_surfaced_as_named_fields(inventory):
    inventory.observe(TENANT_A, "worker", at=NOW, edges=[
        (ObservedEdgeKind.RESOURCE, "customer_pii"),
        (ObservedEdgeKind.MCP_SERVER, "docs-mcp"),
    ])
    profile = inventory.profile(TENANT_A, "worker")

    assert profile.accessible_data == ("customer_pii",)
    assert profile.mcp_servers == ("docs-mcp",)


def test_the_profile_carries_every_field_the_specification_names(inventory):
    """The audit that caught this being incomplete the first time.

    Behavior Baseline is deliberately absent: it is Phase 3, and claiming it
    here would be the same over-reporting this test exists to prevent.
    """
    inventory.observe(TENANT_A, "worker", at=NOW)
    keys = set(inventory.profile(TENANT_A, "worker").as_dict())

    required = {
        "agent_id", "name", "declared", "credentials", "granted_tools",
        "observed_tools", "mcp_servers", "accessible_data",
        "external_destinations", "last_seen", "trust", "policy",
        "violation_count", "incident_count",
    }
    missing = sorted(required - keys)
    assert not missing, f"the profile is missing specification fields: {missing}"


# ── Entity inventory ─────────────────────────────────────────────────────────


def test_the_entity_inventory_reports_every_type_with_its_source(inventory):
    """`source` matters more than `count`. A dashboard showing
    "cloud environments: 0" invites the reading that there are none, when the
    truth is Sentinel cannot see them and nobody wrote them down."""
    inventory.observe(TENANT_A, "worker", at=NOW, edges=[
        (ObservedEdgeKind.CREDENTIAL, "credential-fingerprint-cli"),
        (ObservedEdgeKind.RESOURCE, "customer_pii"),
        (ObservedEdgeKind.DESTINATION, "https://x.example"),
    ])
    inventory.declare(TENANT_A, "worker", "framework", "langchain")

    report = inventory.entity_inventory(TENANT_A)
    entities = report["entities"]

    for name in ("agents", "credentials", "tools", "permissions", "mcp_servers",
                 "data_stores", "external_destinations", "agent_frameworks",
                 "models", "agent_instances", "owners", "cloud_environments",
                 "business_applications"):
        assert name in entities, f"{name} is missing from the entity inventory"
        assert "source" in entities[name], f"{name} does not say where it came from"

    assert entities["agents"]["count"] == 1
    assert entities["credentials"]["count"] == 1
    assert entities["agent_frameworks"]["count"] == 1
    assert entities["cloud_environments"]["count"] == 0


def test_the_entity_inventory_states_declared_coverage(inventory):
    """An inventory is only as good as this number, and stating it stops a
    mostly-empty one from reading as complete."""
    inventory.observe(TENANT_A, "a", at=NOW)
    inventory.observe(TENANT_A, "b", at=NOW)
    inventory.declare(TENANT_A, "a", "owner", "someone")

    coverage = inventory.entity_inventory(TENANT_A)["declared_coverage"]
    assert coverage == {"agents_with_owner": 1, "agents_total": 2}


def test_the_cli_reports_the_entity_inventory(inventory, monkeypatch, engine_config):
    inventory.observe(TENANT_A, "worker", at=NOW,
                      edges=[(ObservedEdgeKind.CREDENTIAL, "credential-fingerprint-cli")])
    code, output = _cli("agent-entities", TENANT_A,
                        monkeypatch=monkeypatch, engine_config=engine_config)

    assert code == 0, output
    assert "credentials" in output
    assert "declared owner" in output


def test_the_cli_inventory_shows_trust_violations_and_credentials(
    inventory, monkeypatch, engine_config
):
    inventory.observe(TENANT_A, "worker", at=NOW, violation=True,
                      edges=[(ObservedEdgeKind.CREDENTIAL, "credential-fingerprint-cli")])
    code, output = _cli("agent-inventory", TENANT_A,
                        monkeypatch=monkeypatch, engine_config=engine_config)

    assert code == 0, output
    assert "trust=" in output
    assert "violations=1" in output
    assert "credential-fingerprint-cli" in output
