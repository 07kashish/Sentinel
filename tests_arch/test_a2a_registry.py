"""Durable agent cards: the store that makes A2A drift detection real.

WHY THIS IS NOT COVERED BY `test_a2a_delegation.py`
-----------------------------------------------------
That module proves `inspect_chain` reports `card_drift`, `task_replay` and
`unenrolled_agent` correctly. It proves it against `InMemoryAgentCards`, which
holds pins in one worker's memory — so every one of those findings worked in the
test and in a single-process deployment, and silently did not work in any
deployment with a second replica. A card enrolled through one replica was
invisible to the next, so `card_drift` could not fire at all and
`unenrolled_agent` fired for agents that WERE enrolled, just not here.

`test_a_card_enrolled_on_one_replica_is_visible_to_another` is the test that
distinguishes those two situations, and it is the reason this module exists.

Both fixtures run against SQLite AND PostgreSQL via `migrated_pool`, because
RLS only exists on one of them and a store that works on SQLite is not evidence
about the backend production runs.
"""

from __future__ import annotations


from sentinel.application.a2a_gateway import A2AGateway
from sentinel.application.protect_gate import ProtectGate
from sentinel.domain.a2a import (
    A2AFindingKind,
    AgentCard,
    DelegationChain,
    DelegationHop,
)
from sentinel.infrastructure.a2a_registry import SqlAgentCardRegistry, SqlTaskLedger
from sentinel.infrastructure.detection import DeterministicPolicy


def _card(agent_id: str, *capabilities: str, version: str = "1.0") -> AgentCard:
    return AgentCard(
        agent_id=agent_id,
        version=version,
        endpoint=f"https://{agent_id}.internal",
        capabilities=frozenset(capabilities),
    )


def _chain(task: str = "t-1") -> DelegationChain:
    return DelegationChain(
        principal="alice",
        principal_scopes=frozenset({"read:docs"}),
        hops=(
            DelegationHop(
                from_agent="alice",
                to_agent="research-agent",
                granted=frozenset({"read:docs"}),
                task_id=task,
            ),
        ),
    )


def _gateway(pool) -> A2AGateway:
    return A2AGateway(
        gate=ProtectGate(policy=DeterministicPolicy.default(), enforce=False),
        cards=SqlAgentCardRegistry(pool=pool),
        tasks=SqlTaskLedger(pool=pool),
    )


# ── the store ────────────────────────────────────────────────────────────────


def test_a_card_survives_a_round_trip_with_its_capabilities_intact(migrated_pool):
    registry = SqlAgentCardRegistry(pool=migrated_pool)
    registry.enrol("acme", _card("research-agent", "read:docs", "read:reports"))

    stored = registry.cards("acme")["research-agent"]
    assert stored.capabilities == frozenset({"read:docs", "read:reports"})
    assert stored.endpoint == "https://research-agent.internal"


def test_enrolment_pins_the_fingerprint_in_the_same_write(migrated_pool):
    """An enrolled agent whose fingerprint was not recorded could change freely
    and never trip drift detection, which makes the card mechanism decorative.
    """
    registry = SqlAgentCardRegistry(pool=migrated_pool)
    card = _card("research-agent", "read:docs")
    registry.enrol("acme", card)
    assert registry.pins("acme")["research-agent"] == card.fingerprint


def test_a_card_enrolled_on_one_replica_is_visible_to_another(migrated_pool):
    """THE test this module exists for. Two registries over one pool stand in
    for two replicas; the in-process store this replaces failed exactly here.
    """
    SqlAgentCardRegistry(pool=migrated_pool).enrol("acme", _card("a", "read:docs"))
    other_replica = SqlAgentCardRegistry(pool=migrated_pool)
    assert "a" in other_replica.cards("acme")


def test_cards_do_not_cross_a_tenant_boundary(migrated_pool):
    registry = SqlAgentCardRegistry(pool=migrated_pool)
    registry.enrol("acme", _card("a", "read:docs"))
    assert registry.cards("globex") == {}
    assert registry.pins("globex") == {}


def test_re_enrolment_re_pins_and_that_is_the_point(migrated_pool):
    """Enrolling again accepts the current shape as the new normal. That is the
    intended operator action — "I have reviewed this change" — and it is why the
    route requires `manage_policy`: re-pinning is the one operation that can
    silence drift detection permanently.
    """
    registry = SqlAgentCardRegistry(pool=migrated_pool)
    registry.enrol("acme", _card("a", "read:docs"))
    first = registry.pins("acme")["a"]

    registry.enrol("acme", _card("a", "read:docs", "read:customers"))
    assert registry.pins("acme")["a"] != first
    assert registry.cards("acme")["a"].capabilities == frozenset(
        {"read:docs", "read:customers"}
    )


def test_drift_is_detectable_because_the_pin_outlives_the_process(migrated_pool):
    """A card whose live shape differs from its pin. The pin comes from the
    database, so this holds across restarts and replicas rather than only inside
    one worker's lifetime.
    """
    from sentinel.domain.a2a import inspect_chain

    registry = SqlAgentCardRegistry(pool=migrated_pool)
    registry.enrol("acme", _card("research-agent", "read:docs"))
    pinned = dict(registry.pins("acme"))

    # The agent now advertises more than it did when it was approved.
    live = {"research-agent": _card("research-agent", "read:docs", "read:customers")}
    findings = inspect_chain(_chain(), cards=live, pinned=pinned)
    assert A2AFindingKind.CARD_DRIFT in {f.kind for f in findings}


# ── the task ledger ──────────────────────────────────────────────────────────


def test_a_replayed_task_is_caught_by_a_different_replica(migrated_pool):
    gateway = _gateway(migrated_pool)
    gateway.enrol("acme", _card("research-agent", "read:docs"))
    gateway.require_allowed(
        tenant_id="acme", chain=_chain(), known_principals=["alice"]
    )

    replica = _gateway(migrated_pool)
    findings = replica.evaluate(tenant_id="acme", chain=_chain()).findings
    assert A2AFindingKind.TASK_REPLAY in {f.kind for f in findings}


def test_a_task_id_is_namespaced_so_it_cannot_collide_with_an_event_digest(
    migrated_pool,
):
    """`replay_nonces` is shared with signed-event replay protection. Without a
    namespace an A2A task id could collide with an event digest, making a
    legitimate event look like a replayed delegation or the reverse.
    """
    ledger = SqlTaskLedger(pool=migrated_pool)
    ledger.record("acme", ["t-1"])

    with migrated_pool.acquire() as conn:
        conn.begin()
        conn.set_tenant("acme")
        rows = conn.execute(
            f"SELECT agent, event_digest FROM replay_nonces WHERE tenant_id={conn.p}",
            ("acme",),
        )
        conn.commit()
    assert [(str(r["agent"]), str(r["event_digest"])) for r in rows] == [
        (SqlTaskLedger.NAMESPACE, "t-1")
    ]


def test_recording_the_same_task_twice_is_not_an_error(migrated_pool):
    """At-least-once delivery means a retry can present the same task again.
    The second write must be a no-op, not a constraint violation that surfaces
    as a failed containment.
    """
    ledger = SqlTaskLedger(pool=migrated_pool)
    ledger.record("acme", ["t-1"])
    ledger.record("acme", ["t-1"])
    assert tuple(ledger.seen("acme")) == ("t-1",)


def test_recording_nothing_touches_no_connection(migrated_pool):
    ledger = SqlTaskLedger(pool=migrated_pool)
    ledger.record("acme", [])
    assert tuple(ledger.seen("acme")) == ()


def test_task_ids_do_not_cross_a_tenant_boundary(migrated_pool):
    ledger = SqlTaskLedger(pool=migrated_pool)
    ledger.record("acme", ["t-1"])
    assert tuple(ledger.seen("globex")) == ()


# ── failure handling ─────────────────────────────────────────────────────────


def test_one_unparseable_row_does_not_blind_the_rest(migrated_pool):
    """A row this build cannot parse is skipped, so the agent reads as
    UNENROLLED — the fail-closed answer. Raising would let one hand-edited row
    disable delegation checking for every agent in the tenant.
    """
    registry = SqlAgentCardRegistry(pool=migrated_pool)
    registry.enrol("acme", _card("good", "read:docs"))

    with migrated_pool.acquire() as conn:
        conn.begin()
        conn.set_tenant("acme")
        p = conn.p
        conn.execute_rowcount(
            f"INSERT INTO a2a_agent_cards (tenant_id, agent_id, version, endpoint, "
            f"capabilities, description, fingerprint, enrolled_at, updated_at) "
            f"VALUES ({p},{p},{p},{p},{p},{p},{p},{p},{p})",
            ("acme", "bad agent id!", "1", "", "read:docs", "", "x", "t", "t"),
        )
        conn.commit()

    cards = registry.cards("acme")
    assert "good" in cards
    assert "bad agent id!" not in cards
