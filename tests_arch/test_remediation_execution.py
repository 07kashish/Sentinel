"""Executing remediation, notifying a SOC, and the kill switch on real storage.

THE CLAIM THESE TESTS EXIST TO SUPPORT
----------------------------------------
`test_response_and_containment.py` proves the DECISIONS are right. This module
proves the machinery around them cannot quietly lie about what it did.

Three specific lies are possible here, and each has a test:

  * A dry run that reads as a real execution. The predecessor did exactly this
    -- `status="simulated", executed=false` returned from a success path, which
    `executors.py` records as reading "as success to any caller that only checks
    for an exception". Dry run reintroduces the same risk by construction,
    because a dry run IS a successful call that did nothing.

  * A kill switch that was never actually consulted. A containment written to a
    table that no enforcement path reads is indistinguishable, from the
    operator's side, from one that works -- until the moment it matters.

  * An approval that executes long after the situation it was raised about.
    `expires_at` is a column, a hydration line, and a branch in the handler; if
    any of the three is missing the branch can never be taken, and the test that
    proves otherwise has to go through real storage to catch it.

WHY THE STORAGE TESTS RUN ON BOTH ENGINES
-------------------------------------------
The `ON CONFLICT` clause, the empty-string defaults and the conditional UPDATE
in `revoke` all behave differently enough between SQLite and PostgreSQL to be
worth running twice. This repository has already shipped one bug that was
invisible on SQLite and broke every operation on PostgreSQL.
"""

from __future__ import annotations

import pytest

from sentinel.application.records import ApprovalRecord
from sentinel.domain.containment import Containment, ContainmentScope
from sentinel.domain.errors import DomainRuleViolated, TransientFailure
from sentinel.domain.primitives import (
    ApprovalId,
    IdempotencyKey,
    IncidentId,
    TenantId,
    Timestamp,
)
from sentinel.infrastructure.containment import (
    AgentFacts,
    ContainmentReadUnavailable,
    ContainmentGuard,
    SqlContainmentRepository,
)
from sentinel.infrastructure.remediation import (
    AllowListAuthorizer,
    GuardedRemediationExecutor,
    InMemoryIdempotencyStore,
    RemediationAuditFailed,
    RemediationUnauthorized,
    SqlRemediationIdempotencyStore,
)
from sentinel.infrastructure.soar import (
    Delivery,
    SlackConnector,
    SoarDispatcher,
    escape_slack,
    escape_ticket_text,
)
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.migrate import migrate

TENANT = "acme"
NOW = "2026-08-24T12:00:00Z"


# ── Doubles ──────────────────────────────────────────────────────────────────


class _Clock:
    def now(self) -> str:
        return NOW


class _Audit:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    def record(self, **kw) -> None:
        self.rows.append(kw)


class _Logger:
    def __init__(self) -> None:
        self.entries: list[tuple[str, dict]] = []

    def _log(self, event, **kw):
        self.entries.append((event, kw))

    info = warning = error = debug = _log


class _Integration:
    """Records what it was asked to do, and can be told to fail."""

    provider = "test-provider"

    def __init__(self, *, fail: Exception | None = None) -> None:
        self.calls: list[tuple[str, str]] = []
        self._fail = fail

    def execute(self, *, target, idempotency_key):
        self.calls.append((target, idempotency_key.value))
        if self._fail is not None:
            raise self._fail
        return {"ok": True}


def _executor(
    *, integrations=None, grants=None, audit=None, dry_run=False
) -> tuple[GuardedRemediationExecutor, _Integration, _Audit]:
    integration = _Integration()
    audit = audit or _Audit()
    executor = GuardedRemediationExecutor(
        integrations=integrations
        if integrations is not None
        else {"disable_agent": integration, "enable_agent": integration},
        authorizer=AllowListAuthorizer(
            grants=grants if grants is not None else {"analyst": frozenset({"*"})}
        ),
        idempotency=InMemoryIdempotencyStore(),
        audit=audit,
        clock=_Clock(),
        dry_run=dry_run,
    )
    return executor, integration, audit


# ── Dry run: the lie this module exists to prevent ───────────────────────────


def test_a_dry_run_never_reports_that_it_executed():
    """THE headline case. The predecessor returned a success-shaped result from
    a path that changed nothing."""
    executor, integration, _ = _executor()
    receipt = executor.execute(
        action="disable_agent",
        target="agent-1",
        idempotency_key=IdempotencyKey("k-1"),
        actor="analyst",
        dry_run=True,
    )
    assert receipt["executed"] is False
    assert receipt["dry_run"] is True
    assert integration.calls == [], "a dry run reached the integration"


def test_a_dry_run_does_not_satisfy_a_later_real_attempt():
    """Otherwise "preview it, then do it" silently becomes "preview it, then
    think you did it" -- the idempotency store would return the dry-run receipt
    for the real call."""
    executor, integration, _ = _executor()
    key = IdempotencyKey("k-2")
    executor.execute(
        action="disable_agent", target="agent-1", idempotency_key=key,
        actor="analyst", dry_run=True,
    )
    real = executor.execute(
        action="disable_agent", target="agent-1", idempotency_key=key,
        actor="analyst", dry_run=False,
    )
    assert real["executed"] is True
    assert len(integration.calls) == 1


def test_a_real_execution_reports_that_it_executed():
    executor, integration, _ = _executor()
    receipt = executor.execute(
        action="disable_agent",
        target="agent-1",
        idempotency_key=IdempotencyKey("k-3"),
        actor="analyst",
    )
    assert receipt["executed"] is True
    assert receipt["dry_run"] is False
    assert integration.calls == [("agent-1", "k-3")]


# ── Authorization ────────────────────────────────────────────────────────────


def test_an_unauthorized_actor_cannot_execute():
    executor, integration, _ = _executor(grants={"analyst": frozenset({"notify_owner"})})
    with pytest.raises(RemediationUnauthorized):
        executor.execute(
            action="disable_agent",
            target="agent-1",
            idempotency_key=IdempotencyKey("k-4"),
            actor="analyst",
        )
    assert integration.calls == []


def test_an_actor_with_no_grant_at_all_is_denied():
    """Default deny. A missing grant must refuse a remediation, not allow
    anyone with API access to disable anything."""
    executor, _, _ = _executor(grants={})
    with pytest.raises(RemediationUnauthorized):
        executor.execute(
            action="disable_agent",
            target="agent-1",
            idempotency_key=IdempotencyKey("k-5"),
            actor="nobody",
        )


def test_authorization_is_checked_before_a_dry_run():
    """Knowing what an action WOULD do to a named target is itself information
    about the estate."""
    executor, _, _ = _executor(grants={})
    with pytest.raises(RemediationUnauthorized):
        executor.execute(
            action="disable_agent",
            target="agent-1",
            idempotency_key=IdempotencyKey("k-6"),
            actor="nobody",
            dry_run=True,
        )


# ── Idempotency, audit, failure handling ─────────────────────────────────────


def test_a_replayed_key_returns_the_prior_receipt_without_calling_again():
    executor, integration, _ = _executor()
    key = IdempotencyKey("k-7")
    first = executor.execute(
        action="disable_agent", target="agent-1", idempotency_key=key, actor="analyst"
    )
    second = executor.execute(
        action="disable_agent", target="agent-1", idempotency_key=key, actor="analyst"
    )
    assert len(integration.calls) == 1, "the action ran twice under one key"
    assert second["replayed"] is True
    assert first["replayed"] is False


def test_a_refused_attempt_is_audited():
    """"Who tried to disable this agent and was told no" is a question an audit
    trail that only records successes cannot answer."""
    _, _, audit = _executor(grants={})
    executor = GuardedRemediationExecutor(
        integrations={"disable_agent": _Integration()},
        authorizer=AllowListAuthorizer(grants={}),
        idempotency=InMemoryIdempotencyStore(),
        audit=audit,
        clock=_Clock(),
    )
    with pytest.raises(RemediationUnauthorized):
        executor.execute(
            action="disable_agent",
            target="agent-1",
            idempotency_key=IdempotencyKey("k-8"),
            actor="mallory",
        )
    assert [r["outcome"] for r in audit.rows] == ["unauthorized"]
    assert audit.rows[0]["actor"] == "mallory"


def test_a_failing_integration_is_audited_and_the_error_reaches_the_caller():
    """Classification (transient vs refusal) is the integration's judgement.
    Flattening it here would lose the distinction the caller needs to decide
    about retrying."""
    failing = _Integration(fail=TransientFailure("provider down"))
    audit = _Audit()
    executor = GuardedRemediationExecutor(
        integrations={"disable_agent": failing},
        authorizer=AllowListAuthorizer(grants={"analyst": frozenset({"*"})}),
        idempotency=InMemoryIdempotencyStore(),
        audit=audit,
        clock=_Clock(),
    )
    with pytest.raises(TransientFailure):
        executor.execute(
            action="disable_agent",
            target="agent-1",
            idempotency_key=IdempotencyKey("k-9"),
            actor="analyst",
        )
    assert [r["outcome"] for r in audit.rows] == ["failed"]


def test_a_failed_execution_is_not_stored_against_its_idempotency_key():
    """A retry under the same key must actually retry."""
    failing = _Integration(fail=TransientFailure("provider down"))
    executor = GuardedRemediationExecutor(
        integrations={"disable_agent": failing},
        authorizer=AllowListAuthorizer(grants={"analyst": frozenset({"*"})}),
        idempotency=InMemoryIdempotencyStore(),
        audit=_Audit(),
        clock=_Clock(),
    )
    for _ in range(2):
        with pytest.raises(TransientFailure):
            executor.execute(
                action="disable_agent",
                target="agent-1",
                idempotency_key=IdempotencyKey("k-10"),
                actor="analyst",
            )
    assert len(failing.calls) == 2


def test_an_audit_backend_failure_after_a_side_effect_is_typed_and_deduped():
    """The action has already happened, so the retry must replay, not re-run."""

    class _FlakyAudit:
        def __init__(self) -> None:
            self.calls = 0

        def record(self, **kw):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("audit backend down")

    store = InMemoryIdempotencyStore()
    audit = _FlakyAudit()
    integration = _Integration()
    executor = GuardedRemediationExecutor(
        integrations={"disable_agent": integration},
        authorizer=AllowListAuthorizer(grants={"analyst": frozenset({"*"})}),
        idempotency=store,
        audit=audit,
        clock=_Clock(),
    )
    key = IdempotencyKey("k-11")
    with pytest.raises(RemediationAuditFailed) as raised:
        executor.execute(
            action="disable_agent",
            target="agent-1",
            idempotency_key=key,
            actor="analyst",
        )
    assert raised.value.receipt["executed"] is True
    assert raised.value.receipt["provider_response"]["audit_failed"] is True

    replay = executor.execute(
        action="disable_agent", target="agent-1", idempotency_key=key, actor="analyst"
    )

    assert replay["replayed"] is True
    assert replay["provider_response"]["audit_failed"] is True
    assert len(integration.calls) == 1


# ── Rollback ─────────────────────────────────────────────────────────────────


def test_a_rollback_runs_the_catalogued_inverse():
    executor, integration, _ = _executor()
    receipt = executor.execute(
        action="disable_agent",
        target="agent-1",
        idempotency_key=IdempotencyKey("k-12"),
        actor="analyst",
    )
    undone = executor.rollback(receipt, actor="analyst")
    assert undone["action"] == "enable_agent"
    assert undone["executed"] is True


def test_a_rollback_uses_a_distinct_idempotency_key():
    """Sharing the original key would make the rollback look like a replay of
    the action it is undoing, and return that receipt instead of acting."""
    executor, integration, _ = _executor()
    receipt = executor.execute(
        action="disable_agent",
        target="agent-1",
        idempotency_key=IdempotencyKey("k-13"),
        actor="analyst",
    )
    undone = executor.rollback(receipt, actor="analyst")
    assert undone["idempotency_key"] != receipt["idempotency_key"]
    assert undone["replayed"] is False


def test_a_dry_run_cannot_be_rolled_back():
    """It would perform a real action to undo one that never happened."""
    executor, _, _ = _executor()
    receipt = executor.execute(
        action="disable_agent",
        target="agent-1",
        idempotency_key=IdempotencyKey("k-14"),
        actor="analyst",
        dry_run=True,
    )
    with pytest.raises(DomainRuleViolated):
        executor.rollback(receipt, actor="analyst")


def test_an_action_with_no_inverse_refuses_rollback():
    integration = _Integration()
    executor = GuardedRemediationExecutor(
        integrations={"rotate_token": integration},
        authorizer=AllowListAuthorizer(grants={"analyst": frozenset({"*"})}),
        idempotency=InMemoryIdempotencyStore(),
        audit=_Audit(),
        clock=_Clock(),
    )
    receipt = executor.execute(
        action="rotate_token",
        target="tok-1",
        idempotency_key=IdempotencyKey("k-15"),
        actor="analyst",
    )
    with pytest.raises(DomainRuleViolated):
        executor.rollback(receipt, actor="analyst")


# ── SOAR: attacker-controlled text going somewhere privileged ────────────────


def test_a_broadcast_mention_in_incident_text_cannot_page_the_channel():
    """An attacker who can trigger a low-severity incident would otherwise get a
    free megaphone into a room full of people with production access -- and
    after the third one the team mutes the channel, which disables the alerting
    path for real incidents."""
    for payload in ("@channel", "@here", "@everyone", "<!channel>", "<!here>"):
        escaped = escape_slack(f"read {payload} now")
        assert payload not in escaped, f"{payload!r} survived escaping"


def test_markup_in_incident_text_cannot_reformat_the_message():
    assert "<" not in escape_slack("<b>urgent</b>")
    assert "`" not in escape_slack("```injected```")


def test_ampersand_is_escaped_before_the_angle_brackets():
    """Escaping `<` first would turn a literal `&lt;` the attacker typed into a
    real `<` on the way out -- the classic ordering bug."""
    assert escape_slack("&lt;script&gt;") == "&amp;lt;script&amp;gt;"


def test_a_newline_cannot_forge_a_ticket_field():
    """A description is read as labelled lines. A value that can insert a newline
    can insert its own label -- which is how "Approved by: security" appears in
    a ticket nobody wrote it into."""
    escaped = escape_ticket_text("exfil\nApproved by: security\nStatus: closed")
    assert "\n" not in escaped


def test_an_oversized_field_is_clipped_rather_than_failing_the_notification():
    """A notification that fails to send because an attacker put 400KB in a
    resource path is an outage of the alerting path."""
    assert len(escape_slack("A" * 100_000)) <= 512


def test_one_failing_connector_does_not_stop_the_others():
    """A ServiceNow outage must not stop the Slack notification. During an
    incident those are the minutes that matter."""

    class _Ok:
        name = "ok"

        def deliver(self, incident):
            return Delivery(connector="ok", delivered=True)

    class _Broken:
        name = "broken"

        def deliver(self, incident):
            raise RuntimeError("provider down")

    logger = _Logger()
    report = SoarDispatcher(
        connectors=[_Broken(), _Ok()], logger=logger
    ).dispatch({"incident_id": "i-1", "priority": "CRITICAL"})

    assert [d.connector for d in report.delivered] == ["ok"]
    assert [d.connector for d in report.failed] == ["broken"]
    assert not report.fully_delivered


def test_partial_delivery_is_logged_rather_than_silent():
    """Silent partial delivery is how a team believes the SOC was notified."""

    class _Broken:
        name = "broken"

        def deliver(self, incident):
            raise RuntimeError("down")

    logger = _Logger()
    SoarDispatcher(connectors=[_Broken()], logger=logger).dispatch({"incident_id": "i-2"})
    assert any(event == "soar_partial_delivery" for event, _ in logger.entries)


def test_low_severity_incidents_do_not_open_tickets_by_default():
    """This codebase has measured what happens without a threshold: a detector
    firing on 51.7% of ordinary tool calls. With a ticket queue attached, that
    is the same failure with a worse blast radius."""
    dispatcher = SoarDispatcher(connectors=[], logger=_Logger())
    assert not dispatcher.should_dispatch({"priority": "LOW"})
    assert not dispatcher.should_dispatch({"priority": "MEDIUM"})
    assert dispatcher.should_dispatch({"priority": "HIGH"})
    assert dispatcher.should_dispatch({"priority": "CRITICAL"})


def test_a_malformed_severity_does_not_raise_inside_the_notification_path():
    """A notification path's whole job is to work during an incident."""
    connector = SlackConnector(client=_NullClient(), url="https://hooks.example/x")
    delivery = connector.deliver({"incident_id": "i-3", "severity": "not-a-number"})
    assert delivery.delivered


class _NullClient:
    def request(self, **kw):
        class _R:
            status = 200

        return _R()


# ── Storage: both engines ────────────────────────────────────────────────────


@pytest.fixture
def pool(engine_config):
    """Built on the shared `engine_config`, which runs every test on both
    engines and drops the PostgreSQL database it creates in teardown.

    Rolling a private fixture here instead is how the earlier
    `ConnectionTimeout` flakiness happened: databases were created per test and
    nothing removed them."""
    engine = build_engine(engine_config)
    migrate(engine)
    with engine.acquire() as conn:
        conn.begin()
        conn.execute_rowcount(
            f"INSERT INTO tenants (tenant_id, name, created_at) "
            f"VALUES ({conn.p},{conn.p},{conn.p}) "
            f"ON CONFLICT (tenant_id) DO NOTHING",
            (TENANT, "Acme", "2026-08-24T00:00:00+00:00"),
        )
        conn.commit()
    try:
        yield engine
    finally:
        engine.close()


def test_remediation_idempotency_is_durable_across_executor_instances(pool):
    first_integration = _Integration()
    second_integration = _Integration()
    key = IdempotencyKey("sql-k-1")

    first = GuardedRemediationExecutor(
        integrations={"disable_agent": first_integration},
        authorizer=AllowListAuthorizer(grants={"analyst": frozenset({"*"})}),
        idempotency=SqlRemediationIdempotencyStore(pool=pool),
        audit=_Audit(),
        clock=_Clock(),
    )
    second = GuardedRemediationExecutor(
        integrations={"disable_agent": second_integration},
        authorizer=AllowListAuthorizer(grants={"analyst": frozenset({"*"})}),
        idempotency=SqlRemediationIdempotencyStore(pool=pool),
        audit=_Audit(),
        clock=_Clock(),
    )

    first.execute(
        action="disable_agent",
        target="agent-1",
        idempotency_key=key,
        actor="analyst",
        tenant=TENANT,
    )
    replay = second.execute(
        action="disable_agent",
        target="agent-1",
        idempotency_key=key,
        actor="analyst",
        tenant=TENANT,
    )

    assert replay["replayed"] is True
    assert first_integration.calls == [("agent-1", "sql-k-1")]
    assert second_integration.calls == []


def _repo(conn):
    return SqlContainmentRepository(conn, TenantId(TENANT))


def _containment(scope=ContainmentScope.AGENT, selector="agent-1", **kw):
    return Containment(
        containment_id=kw.pop("containment_id", "c-1"),
        tenant_id=TENANT,
        scope=scope,
        selector=selector,
        created_by="analyst@acme.test",
        created_at="2026-08-24T00:00:00Z",
        **kw,
    )


def test_a_containment_survives_a_write_and_a_read(pool):
    with pool.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT)
        repo = _repo(conn)
        repo.create(_containment(reason="suspected exfiltration"))
        conn.commit()

        conn.begin()
        conn.set_tenant(TENANT)
        active = _repo(conn).active(now=NOW)
        conn.commit()

    assert [c.containment_id for c in active] == ["c-1"]
    assert active[0].reason == "suspected exfiltration"
    assert active[0].scope is ContainmentScope.AGENT


def test_revoking_a_containment_takes_it_out_of_the_active_set(pool):
    with pool.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT)
        _repo(conn).create(_containment())
        conn.commit()

        conn.begin()
        conn.set_tenant(TENANT)
        lifted = _repo(conn).revoke("c-1", revoked_by="lead@acme.test", at=NOW)
        conn.commit()

        conn.begin()
        conn.set_tenant(TENANT)
        active = _repo(conn).active(now=NOW)
        history = _repo(conn).all()
        conn.commit()

    assert lifted is True
    assert active == ()
    # The record survives revocation: "what was blocked at 03:14, and by whom"
    # is the question an audit trail exists to answer.
    assert [c.containment_id for c in history] == ["c-1"]
    assert history[0].revoked_by == "lead@acme.test"


def test_revoking_twice_does_not_rewrite_who_lifted_it(pool):
    with pool.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT)
        _repo(conn).create(_containment())
        conn.commit()

        conn.begin()
        conn.set_tenant(TENANT)
        first = _repo(conn).revoke("c-1", revoked_by="lead@acme.test", at=NOW)
        conn.commit()

        conn.begin()
        conn.set_tenant(TENANT)
        second = _repo(conn).revoke("c-1", revoked_by="someone-else", at=NOW)
        history = _repo(conn).all()
        conn.commit()

    assert first is True
    assert second is False, "a second revoke rewrote the audit record"
    assert history[0].revoked_by == "lead@acme.test"


def test_an_expired_containment_is_not_returned_as_active(pool):
    with pool.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT)
        _repo(conn).create(_containment(expires_at="2026-08-24T01:00:00Z"))
        conn.commit()

        conn.begin()
        conn.set_tenant(TENANT)
        active = _repo(conn).active(now=NOW)
        conn.commit()

    assert active == ()


def test_creating_the_same_containment_twice_does_not_duplicate_it(pool):
    with pool.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT)
        repo = _repo(conn)
        repo.create(_containment(reason="first"))
        repo.create(_containment(reason="second, must not overwrite"))
        conn.commit()

        conn.begin()
        conn.set_tenant(TENANT)
        active = _repo(conn).active(now=NOW)
        conn.commit()

    assert len(active) == 1
    assert active[0].reason == "first"


# ── The guard: caching without becoming a hole ───────────────────────────────


class _UowFactory:
    """Minimal factory returning a stub uow whose `containments` is scripted."""

    def __init__(self, containments, *, fail_after: int | None = None, facts=None) -> None:
        self._containments = containments
        self._fail_after = fail_after
        self._facts = facts if facts is not None else AgentFacts()
        self.reads = 0

    def begin(self, tenant):
        factory = self

        class _Uow:
            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *a):
                return False

            @property
            def containments(self_inner):
                return self_inner

            def active(self_inner, *, now):
                factory.reads += 1
                if (
                    factory._fail_after is not None
                    and factory.reads > factory._fail_after
                ):
                    raise RuntimeError("database unavailable")
                return factory._containments

            def agent_facts(self_inner, **kw):
                return factory._facts

            def commit(self_inner):
                pass

        return _Uow()


def test_the_guard_blocks_a_contained_agent():
    guard = ContainmentGuard(
        uow_factory=_UowFactory((_containment(),)), logger=_Logger()
    )
    decision = guard.check(TenantId(TENANT), now=NOW, agent_id="agent-1")
    assert decision.blocked


def test_the_guard_caches_rather_than_reading_on_every_decision():
    factory = _UowFactory((_containment(),))
    guard = ContainmentGuard(uow_factory=factory, logger=_Logger())
    for _ in range(5):
        guard.check(TenantId(TENANT), now=NOW, agent_id="agent-1")
    assert factory.reads == 1


def test_an_unreadable_store_serves_the_cached_set_rather_than_lifting_it():
    """A transient fault must not become a window in which a contained agent
    runs."""
    factory = _UowFactory((_containment(),), fail_after=1)
    logger = _Logger()
    guard = ContainmentGuard(uow_factory=factory, logger=logger, ttl_seconds=0.0)

    assert guard.check(TenantId(TENANT), now=NOW, agent_id="agent-1").blocked
    # TTL is zero, so this re-reads -- and the re-read fails.
    assert guard.check(TenantId(TENANT), now=NOW, agent_id="agent-1").blocked
    assert any(
        event == "containment_read_failed_serving_stale" for event, _ in logger.entries
    )


def test_an_unreadable_store_with_no_cache_fails_closed_and_is_logged_loudly():
    """A kill switch that is silently not working is worse than one that is
    loudly not working."""
    factory = _UowFactory((), fail_after=0)
    logger = _Logger()
    guard = ContainmentGuard(uow_factory=factory, logger=logger)
    with pytest.raises(ContainmentReadUnavailable):
        guard.check(TenantId(TENANT), now=NOW, agent_id="agent-1")
    assert any(
        event == "containment_read_failed_no_cache" for event, _ in logger.entries
    )


def test_invalidating_the_cache_makes_a_new_containment_effective_immediately():
    factory = _UowFactory(())
    guard = ContainmentGuard(uow_factory=factory, logger=_Logger())
    assert not guard.check(TenantId(TENANT), now=NOW, agent_id="agent-1").blocked

    factory._containments = (_containment(),)
    guard.invalidate(TENANT)
    assert guard.check(TenantId(TENANT), now=NOW, agent_id="agent-1").blocked


# ── Approval expiry, through real storage ────────────────────────────────────


def _approval(expires_at: str | None) -> ApprovalRecord:
    return ApprovalRecord(
        approval_id=ApprovalId("apr-1"),
        incident_id=IncidentId("inc-1"),
        action="disable_agent",
        target="agent-1",
        state="pending",
        proposed_at=Timestamp.parse("2026-08-24T00:00:00+00:00"),
        expires_at=Timestamp.parse(expires_at) if expires_at else None,
        context={"recommended_decision": "approve", "business_impact": "one agent"},
    )


def test_an_approval_expiry_survives_a_write_and_a_read(pool):
    """The column, the INSERT, and the hydration line must ALL be present. Miss
    the last one and `expires_at` is permanently None, which makes the handler's
    expiry branch unreachable -- a gate that executes nothing."""
    from sentinel.infrastructure.sql.repositories import ApprovalRepository

    with pool.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT)
        conn.execute_rowcount(
            f"INSERT INTO incidents (tenant_id, incident_id, state, "
            f"created_at, updated_at, version, facts_json) "
            f"VALUES ({conn.p},{conn.p},{conn.p},{conn.p},{conn.p},{conn.p},{conn.p}) "
            f"ON CONFLICT DO NOTHING",
            (TENANT, "inc-1", "open", NOW, NOW, 1, '{"severity": 90}'),
        )
        repo = ApprovalRepository(conn, TenantId(TENANT))
        repo.propose([_approval("2026-08-24T06:00:00+00:00")])
        conn.commit()

        conn.begin()
        conn.set_tenant(TENANT)
        loaded = ApprovalRepository(conn, TenantId(TENANT)).get(ApprovalId("apr-1"))
        conn.commit()

    assert loaded is not None
    assert loaded.expires_at is not None, "expires_at did not survive the round trip"
    assert loaded.is_expired(Timestamp.parse("2026-08-24T12:00:00+00:00"))
    assert not loaded.is_expired(Timestamp.parse("2026-08-24T05:00:00+00:00"))
    assert loaded.context["recommended_decision"] == "approve"


def test_an_approval_with_no_expiry_never_expires(pool):
    """Indefinite must remain possible; the window is a choice made at
    creation."""
    from sentinel.infrastructure.sql.repositories import ApprovalRepository

    with pool.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT)
        conn.execute_rowcount(
            f"INSERT INTO incidents (tenant_id, incident_id, state, "
            f"created_at, updated_at, version, facts_json) "
            f"VALUES ({conn.p},{conn.p},{conn.p},{conn.p},{conn.p},{conn.p},{conn.p}) "
            f"ON CONFLICT DO NOTHING",
            (TENANT, "inc-1", "open", NOW, NOW, 1, '{"severity": 90}'),
        )
        ApprovalRepository(conn, TenantId(TENANT)).propose([_approval(None)])
        conn.commit()

        conn.begin()
        conn.set_tenant(TENANT)
        loaded = ApprovalRepository(conn, TenantId(TENANT)).get(ApprovalId("apr-1"))
        conn.commit()

    assert loaded is not None
    assert loaded.expires_at is None
    assert not loaded.is_expired(Timestamp.parse("2030-01-01T00:00:00+00:00"))


# ── The kill switch on the enforcement path ──────────────────────────────────
#
# The tests above prove a containment can be stored and evaluated. These prove
# something different and more important: that the enforcement path actually
# consults it. A containment nothing reads is indistinguishable, from the
# operator's side, from one that works -- until the moment it matters.


class _AllowingGate:
    """A gate that always permits, so a refusal can only come from containment."""

    def __init__(self) -> None:
        self.ran = 0

    def run_if_allowed(self, *, payload, trust, action):
        self.ran += 1
        return action()


def _runner(containment=None):
    from sentinel.application.tool_runner import ProtectedToolRunner

    return ProtectedToolRunner(
        gate=_AllowingGate(),
        containment=containment,
        tenant=TenantId(TENANT),
        clock=_Clock(),
    )


def test_the_runner_consults_containment_when_one_is_configured():
    """Named in the `ProtectedToolRunner.__init__` docstring. If containment is
    wired but never checked, every test above still passes and the kill switch
    does nothing."""
    from sentinel.application.tool_runner import ToolExecutionRefused
    from sentinel.domain.primitives import TrustLevel

    guard = ContainmentGuard(
        uow_factory=_UowFactory((_containment(),)), logger=_Logger()
    )
    ran = []
    with pytest.raises(ToolExecutionRefused) as caught:
        _runner(guard).execute(
            agent_id="agent-1",
            tool="shell",
            trust=TrustLevel.VERIFIED,
            side_effect=lambda: ran.append(1),
        )
    assert ran == [], "the side effect ran despite an active containment"
    # The refusal names the containment, so the agent's owner sees why their
    # tool stopped rather than a generic denial.
    assert "c-1" in str(caught.value)


def test_an_uncontained_agent_still_runs():
    """The other half. A kill switch that blocks everything is not a kill
    switch."""
    from sentinel.domain.primitives import TrustLevel

    guard = ContainmentGuard(
        uow_factory=_UowFactory((_containment(selector="someone-else"),)),
        logger=_Logger(),
    )
    ran = []
    _runner(guard).execute(
        agent_id="agent-1",
        tool="shell",
        trust=TrustLevel.VERIFIED,
        side_effect=lambda: ran.append(1),
    )
    assert ran == [1]


def test_containing_a_tool_stops_it_for_every_agent():
    from sentinel.application.tool_runner import ToolExecutionRefused
    from sentinel.domain.primitives import TrustLevel

    guard = ContainmentGuard(
        uow_factory=_UowFactory(
            (_containment(scope=ContainmentScope.TOOL, selector="shell"),)
        ),
        logger=_Logger(),
    )
    for agent in ("agent-1", "agent-2", "agent-3"):
        with pytest.raises(ToolExecutionRefused):
            _runner(guard).execute(
                agent_id=agent,
                tool="shell",
                trust=TrustLevel.VERIFIED,
                side_effect=lambda: None,
            )


def test_retention_never_deletes_an_active_containment(pool):
    """The `revoked_at<>''` predicate in the retention sweep is load-bearing.

    Without it, an indefinite containment whose `created_at` had aged past the
    cutoff would be swept away, silently un-blocking an agent an operator had
    stopped. A retention job that lifts a kill switch is the worst possible way
    to discover a missing WHERE clause.
    """

    old = "2020-01-01T00:00:00Z"
    with pool.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT)
        repo = _repo(conn)
        # Ancient, still in force.
        repo.create(
            Containment(
                containment_id="c-active-old",
                tenant_id=TENANT,
                scope=ContainmentScope.AGENT,
                selector="agent-1",
                created_by="analyst@acme.test",
                created_at=old,
            )
        )
        # Ancient, already lifted -- this one is safe to reap.
        repo.create(
            Containment(
                containment_id="c-revoked-old",
                tenant_id=TENANT,
                scope=ContainmentScope.AGENT,
                selector="agent-2",
                created_by="analyst@acme.test",
                created_at=old,
                revoked_at=old,
                revoked_by="lead@acme.test",
            )
        )
        conn.commit()

        # The sweep's own predicate, run directly against both rows.
        conn.begin()
        conn.set_tenant(TENANT)
        p = conn.p
        deleted = conn.execute_rowcount(
            f"DELETE FROM containments WHERE tenant_id={p} "
            f"AND revoked_at<>'' AND revoked_at<{p}",
            (TENANT, "2026-01-01T00:00:00Z"),
        )
        conn.commit()

        conn.begin()
        conn.set_tenant(TENANT)
        survivors = {c.containment_id for c in _repo(conn).all()}
        active = _repo(conn).active(now=NOW)
        conn.commit()

    assert deleted == 1, "the revoked row was not reaped"
    assert survivors == {"c-active-old"}, "an ACTIVE containment was deleted"
    assert [c.containment_id for c in active] == ["c-active-old"]


# ── The two scopes that read Sentinel's own records ──────────────────────────
#
# `agent_group` and `high_risk_agents` cannot be evaluated from the request:
# the request comes from the agent being contained. An earlier draft of this
# feature accepted both over HTTP and could never fire either, because the
# enforcement path had no way to supply the inputs -- an operator would have
# activated a group containment, received a 201, and blocked nothing.


def test_containing_a_group_blocks_its_members_and_nobody_else():
    from sentinel.application.tool_runner import ToolExecutionRefused
    from sentinel.domain.primitives import TrustLevel

    facts = AgentFacts(
        labels={"agent-1": "payments", "agent-2": "payments", "agent-3": "search"}
    )
    guard = ContainmentGuard(
        uow_factory=_UowFactory(
            (_containment(scope=ContainmentScope.AGENT_GROUP, selector="payments"),),
            facts=facts,
        ),
        logger=_Logger(),
    )
    for member in ("agent-1", "agent-2"):
        with pytest.raises(ToolExecutionRefused):
            _runner(guard).execute(
                agent_id=member,
                tool="shell",
                trust=TrustLevel.VERIFIED,
                side_effect=lambda: None,
            )

    ran = []
    _runner(guard).execute(
        agent_id="agent-3",
        tool="shell",
        trust=TrustLevel.VERIFIED,
        side_effect=lambda: ran.append(1),
    )
    assert ran == [1], "an agent outside the group was blocked"


def test_an_agent_cannot_escape_a_group_containment_by_omitting_its_group():
    """The caller IS the agent being contained. If group membership came from
    the request, evading a group pause would be a matter of not mentioning it."""
    from sentinel.application.tool_runner import ToolExecutionRefused
    from sentinel.domain.primitives import TrustLevel

    guard = ContainmentGuard(
        uow_factory=_UowFactory(
            (_containment(scope=ContainmentScope.AGENT_GROUP, selector="payments"),),
            facts=AgentFacts(labels={"agent-1": "payments"}),
        ),
        logger=_Logger(),
    )
    # The runner passes no groups at all -- exactly what a silent agent produces.
    with pytest.raises(ToolExecutionRefused):
        _runner(guard).execute(
            agent_id="agent-1",
            tool="shell",
            trust=TrustLevel.VERIFIED,
            side_effect=lambda: None,
        )


def test_pausing_high_risk_agents_blocks_only_the_ones_sentinel_observed():
    from sentinel.application.tool_runner import ToolExecutionRefused
    from sentinel.domain.primitives import TrustLevel

    guard = ContainmentGuard(
        uow_factory=_UowFactory(
            (
                _containment(
                    scope=ContainmentScope.HIGH_RISK_AGENTS,
                    selector="",
                    containment_id="c-pause",
                ),
            ),
            facts=AgentFacts(high_risk=frozenset({"agent-bad"})),
        ),
        logger=_Logger(),
    )
    with pytest.raises(ToolExecutionRefused):
        _runner(guard).execute(
            agent_id="agent-bad",
            tool="shell",
            trust=TrustLevel.VERIFIED,
            side_effect=lambda: None,
        )

    ran = []
    _runner(guard).execute(
        agent_id="agent-good",
        tool="shell",
        trust=TrustLevel.VERIFIED,
        side_effect=lambda: ran.append(1),
    )
    assert ran == [1]


def test_agent_facts_come_from_storage_and_not_from_the_agent(pool):
    """`agents.label` is set by an operator at enrolment and
    `agent_observations.violation_count` is incremented by Sentinel. Neither is
    writable by the agent, which is what makes these two scopes worth having."""
    with pool.acquire() as conn:
        conn.begin()
        conn.set_tenant(TENANT)
        p = conn.p
        conn.execute_rowcount(
            f"INSERT INTO agents (tenant_id, address, label, enrolled_at) "
            f"VALUES ({p},{p},{p},{p}) ON CONFLICT DO NOTHING",
            (TENANT, "agent-1", "payments", NOW),
        )
        conn.execute_rowcount(
            f"INSERT INTO agent_observations "
            f"(tenant_id, agent_id, first_seen, last_seen, event_count, violation_count) "
            f"VALUES ({p},{p},{p},{p},{p},{p}) ON CONFLICT DO NOTHING",
            (TENANT, "agent-bad", NOW, NOW, 10, 3),
        )
        conn.commit()

        conn.begin()
        conn.set_tenant(TENANT)
        facts = _repo(conn).agent_facts()
        conn.commit()

    assert facts.groups_of("agent-1") == ("payments",)
    assert facts.groups_of("agent-unknown") == ()
    assert facts.is_high_risk("agent-bad")
    assert not facts.is_high_risk("agent-1")


def test_an_integration_registered_under_an_unknown_name_is_reported_unsupported():
    """`DecideApprovalHandler` checks `supports` and turns False into a clear
    `unsupported_action` refusal.

    Without the catalogue half of that check, a misconfigured integration would
    pass `supports`, raise `UnknownRemediationAction` inside `execute`, and be
    converted by the handler's blanket `except Exception` into a
    `TransientFailure` -- which reads as "the provider is having trouble" when
    the deployment is misconfigured, and is RETRYABLE, so the approval would be
    retried for ever against a name that can never work.
    """
    executor = GuardedRemediationExecutor(
        integrations={"disable_agent": _Integration(), "not_an_action": _Integration()},
        authorizer=AllowListAuthorizer(grants={"analyst": frozenset({"*"})}),
        idempotency=InMemoryIdempotencyStore(),
        audit=_Audit(),
        clock=_Clock(),
    )
    assert executor.supports("disable_agent")
    assert not executor.supports("not_an_action")
    assert not executor.supports("never_registered")


def test_an_approval_request_reaches_a_chat_channel_with_its_deadline():
    """Section 32 asks that high-risk approvals reach Slack and Teams. An
    approval sitting in a channel with no visible deadline waits until somebody
    happens to look; one that says when it closes is a decision with a clock on
    it."""
    from sentinel.infrastructure.soar import approval_notification

    notification = approval_notification(
        {
            "approval_id": "apr-1",
            "action": "disable_agent",
            "target": "agent-1",
            "expires_at": "2026-08-24T18:00:00Z",
        },
        context={"recommended_decision": "approve", "business_impact": "one agent"},
    )
    assert "disable_agent" in notification["title"]
    assert "2026-08-24T18:00:00Z" in notification["summary"]
    assert "approve" in notification["summary"]


def test_an_approval_with_no_expiry_says_so_rather_than_showing_a_blank():
    from sentinel.infrastructure.soar import approval_notification

    notification = approval_notification({"approval_id": "apr-2", "action": "x", "target": "y"})
    assert "no expiry set" in notification["summary"]


def test_an_approval_target_cannot_page_the_channel():
    """The target is a resource path the agent chose. It lands in the same place
    as any other incident text and gets the same escaping."""
    from sentinel.infrastructure.soar import approval_notification

    notification = approval_notification(
        {"approval_id": "apr-3", "action": "disable_agent", "target": "@channel urgent"}
    )
    assert "@channel" not in notification["title"]
