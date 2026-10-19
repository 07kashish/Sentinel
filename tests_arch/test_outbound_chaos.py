"""Section 61 for the outbound surfaces Phase 4 added.

    Simulate: MCP server timeout / tool adapter failure / network timeout ...
    Security decisions should degrade safely.

WHY THESE SURFACES SPECIFICALLY
---------------------------------
Phase 4 added three new places where this process calls something it does not
control: remediation integrations, SOAR connectors, and the containment store.
Each sits next to a security decision, and §61's requirement is not "do not
crash" -- it is that the DECISION degrades safely when the dependency does not
answer.

Those two are different, and the difference is the whole module:

  * A SOAR connector that hangs must not prevent the incident from being
    recorded. The incident is the durable artifact; the notification is a
    best-effort copy. Losing the copy is a degraded system, losing the incident
    is a broken one.
  * A remediation endpoint that times out must NOT produce a receipt. A receipt
    is the only record that something happened in the real world, and a
    success-shaped receipt for an action that timed out is worse than no
    receipt at all -- the operator stops looking.
  * The containment store failing must not silently lift containments, and must
    not halt the estate either.

ON "MCP SERVER TIMEOUT"
-------------------------
§61 lists it, and it does not map where you would expect. `McpGateway` is
deliberately transport-free -- its docstring says "no client, no transport, no
server discovery" -- so the gateway itself cannot experience a timeout. The
timeout happens in whatever calls the MCP server, which is the same hardened
outbound client every other integration uses. So the meaningful test is that
the client classifies a hang as TRANSIENT rather than as a refusal, which is
what decides whether the caller retries or gives up.
"""

from __future__ import annotations

import pytest

from sentinel.domain.errors import DomainRuleViolated, TransientFailure
from sentinel.domain.primitives import IdempotencyKey
from sentinel.infrastructure.containment import ContainmentGuard
from sentinel.infrastructure.outbound import OutboundUnavailable
from sentinel.infrastructure.remediation import (
    AllowListAuthorizer,
    GuardedRemediationExecutor,
    HttpRemediationIntegration,
    InMemoryIdempotencyStore,
)
from sentinel.infrastructure.soar import SoarDispatcher

AT = "2026-08-24T12:00:00Z"


class _Clock:
    def now(self) -> str:
        return AT


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


class _HangingClient:
    """A dependency that never answers, the way a real one fails.

    Raises `OutboundUnavailable`, which is what `HardenedHttpClient` raises on a
    socket timeout -- so this exercises the classification the real client
    produces rather than a generic exception the code might handle differently.
    """

    def __init__(self) -> None:
        self.calls = 0

    def request(self, **kw):
        self.calls += 1
        raise OutboundUnavailable("destination timed out")


# ── A timing-out remediation endpoint ────────────────────────────────────────


def _executor(client) -> tuple[GuardedRemediationExecutor, _Audit]:
    audit = _Audit()
    executor = GuardedRemediationExecutor(
        integrations={
            "disable_agent": HttpRemediationIntegration(
                provider="sentinel", client=client, url="https://remediate.test/a"
            )
        },
        authorizer=AllowListAuthorizer(grants={"analyst": frozenset({"*"})}),
        idempotency=InMemoryIdempotencyStore(),
        audit=audit,
        clock=_Clock(),
    )
    return executor, audit


def test_a_timing_out_remediation_endpoint_produces_no_receipt():
    """A success-shaped receipt for an action that timed out is worse than no
    receipt: it is the record that says something happened in the real world,
    and an operator who reads it stops looking."""
    executor, _ = _executor(_HangingClient())
    with pytest.raises(TransientFailure):
        executor.execute(
            action="disable_agent",
            target="agent-1",
            idempotency_key=IdempotencyKey("t-1"),
            actor="analyst",
        )


def test_a_timeout_stays_transient_so_the_caller_knows_to_retry():
    """Classification is the decision that matters. `TransientFailure` means the
    approval claim is released and the action can be retried under the same
    idempotency key; a domain refusal would mean giving up on an action that may
    simply have been slow."""
    executor, _ = _executor(_HangingClient())
    with pytest.raises(TransientFailure):
        executor.execute(
            action="disable_agent",
            target="agent-1",
            idempotency_key=IdempotencyKey("t-2"),
            actor="analyst",
        )


def test_a_timed_out_action_is_audited_as_failed():
    """"We tried to disable this agent and the provider did not answer" is a
    row an investigation needs. An audit trail that only records successes
    cannot distinguish it from never having tried."""
    executor, audit = _executor(_HangingClient())
    with pytest.raises(TransientFailure):
        executor.execute(
            action="disable_agent",
            target="agent-1",
            idempotency_key=IdempotencyKey("t-3"),
            actor="analyst",
        )
    assert [row["outcome"] for row in audit.rows] == ["failed"]


def test_a_timed_out_action_can_be_retried_under_the_same_key():
    """A failure must not be stored against its idempotency key, or the retry
    returns the failure instead of retrying."""
    client = _HangingClient()
    executor, _ = _executor(client)
    for _ in range(2):
        with pytest.raises(TransientFailure):
            executor.execute(
                action="disable_agent",
                target="agent-1",
                idempotency_key=IdempotencyKey("t-4"),
                actor="analyst",
            )
    assert client.calls == 2, "the retry did not reach the integration"


# ── A hanging SOAR connector ─────────────────────────────────────────────────


def test_a_hanging_soar_connector_does_not_raise_into_the_caller():
    """The incident is the durable artifact; the notification is a best-effort
    copy. An incident REJECTED because Slack was down is a broken system."""

    class _Hanging:
        name = "slack"

        def deliver(self, incident):
            raise OutboundUnavailable("hooks.slack.test timed out")

    logger = _Logger()
    report = SoarDispatcher(connectors=[_Hanging()], logger=logger).dispatch(
        {"incident_id": "i-1", "priority": "CRITICAL"}
    )
    assert not report.fully_delivered
    assert [d.connector for d in report.failed] == ["slack"]


def test_one_hanging_connector_does_not_stop_the_rest():
    """During an incident these are the minutes that matter."""

    class _Hanging:
        name = "servicenow"

        def deliver(self, incident):
            raise OutboundUnavailable("timed out")

    class _Working:
        name = "slack"

        def deliver(self, incident):
            from sentinel.infrastructure.soar import Delivery

            return Delivery(connector="slack", delivered=True)

    report = SoarDispatcher(
        connectors=[_Hanging(), _Working()], logger=_Logger()
    ).dispatch({"incident_id": "i-2", "priority": "CRITICAL"})
    assert [d.connector for d in report.delivered] == ["slack"]


def test_a_total_soar_outage_is_reported_rather_than_silent():
    """Silent total failure is how a team believes the SOC was notified."""

    class _Hanging:
        def __init__(self, name):
            self.name = name

        def deliver(self, incident):
            raise OutboundUnavailable("timed out")

    logger = _Logger()
    report = SoarDispatcher(
        connectors=[_Hanging("slack"), _Hanging("jira")], logger=logger
    ).dispatch({"incident_id": "i-3", "priority": "CRITICAL"})

    assert len(report.failed) == 2
    assert report.delivered == ()
    assert any(event == "soar_partial_delivery" for event, _ in logger.entries)


# ── The containment store failing ────────────────────────────────────────────


class _FailingUowFactory:
    """A store that is unreachable from the first call."""

    def begin(self, tenant):
        class _Uow:
            def __enter__(self_inner):
                raise OutboundUnavailable("database unavailable")

            def __exit__(self_inner, *a):
                return False

        return _Uow()


def test_an_unreadable_containment_store_refuses_the_request_rather_than_lifting_the_deny_list():
    """Containment is a DENY list, and the guard is consulted only at
    ENFORCEMENT points -- the tool runner, immediately before a side effect.

    An earlier version of this test asserted the opposite: that an unreadable
    store yields "not blocked", on the argument that failing closed turns a
    database blip into an estate-wide outage. That argument conflated the two
    call sites. Ingest never consults the guard, so it is unaffected. The tool
    runner does, and there "not blocked" means an agent an analyst contained
    at 03:14 keeps executing for as long as the database is unreachable --
    which is exactly the window an attacker who can degrade the database
    would want. A refusal there is scoped to one request, is retryable, and is
    the same answer the runner already gives for every other error of its own.

    So: no cache, store unreadable -> a typed, transient refusal. With a cache,
    the last-known set is served (the next test file covers that path).
    """
    from sentinel.domain.primitives import TenantId
    from sentinel.infrastructure.containment import ContainmentReadUnavailable

    logger = _Logger()
    guard = ContainmentGuard(uow_factory=_FailingUowFactory(), logger=logger)
    with pytest.raises(ContainmentReadUnavailable):
        guard.check(TenantId("acme"), now=AT, agent_id="agent-1")


def test_an_unreadable_containment_store_is_loud_about_it():
    """A kill switch that is silently not working is worse than one that is
    loudly not working -- and one that is loudly refusing must SAY it refused,
    so an operator reading the log knows agents are being stopped for a
    database reason and not a policy one."""
    from sentinel.domain.primitives import TenantId
    from sentinel.infrastructure.containment import ContainmentReadUnavailable

    logger = _Logger()
    guard = ContainmentGuard(uow_factory=_FailingUowFactory(), logger=logger)
    with pytest.raises(ContainmentReadUnavailable):
        guard.check(TenantId("acme"), now=AT, agent_id="agent-1")

    events = [event for event, _ in logger.entries]
    assert "containment_read_failed_no_cache" in events
    detail = next(kw for event, kw in logger.entries if event == "containment_read_failed_no_cache")
    # The message must state the CONSEQUENCE -- the request is refused -- not
    # merely that a read failed.
    assert "refusing" in str(detail.get("detail", ""))


# ── The classification that decides whether anything retries ─────────────────


def test_a_timeout_is_transient_and_a_refusal_is_not():
    """The distinction the whole degradation story rests on.

    `OutboundUnavailable` is a `TransientFailure`: the destination was permitted
    and did not answer, so retrying is reasonable. A domain refusal is not
    retryable, because retrying repeats the same wrong answer -- which is why
    `HardenedHttpClient` classifies a TLS verification failure as a refusal and
    a socket timeout as unavailability.
    """
    assert issubclass(OutboundUnavailable, TransientFailure)
    assert not issubclass(OutboundUnavailable, DomainRuleViolated)
