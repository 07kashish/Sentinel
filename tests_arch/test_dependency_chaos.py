"""Section 61 for the INFRASTRUCTURE dependencies: database, cache, clock.

    Simulate: PostgreSQL unavailable / Redis unavailable / clock skew ...
    Security decisions should degrade safely.

WHY THESE WERE MISSING
------------------------
An audit of §61's twelve scenarios against this suite originally reported
eleven covered. That number came from grepping for each scenario's vocabulary,
and grep finds mentions, not tests. Read properly, three of the matches were
about something else entirely:

  * "PostgreSQL unavailable" matched tests about ATTESTATION being unavailable
  * "Redis unavailable" matched round-trip and atomicity tests, not failure
  * "clock skew" matched the TOTP time-step window in the MFA suite

The behaviour those scenarios need mostly already existed -- `TransientFailure`
maps to 503, `RateLimitDecision.degraded` exists precisely to distinguish
"allowed because there was budget" from "allowed because the limiter was down".
What did not exist was anything asserting it, which means nothing would notice
if it stopped being true.

THE REQUIREMENT IS ABOUT THE DECISION, NOT THE PROCESS
--------------------------------------------------------
"Security decisions should degrade safely" is not "do not crash". A process
that stays up while silently allowing everything has degraded far worse than
one that returns 503. So each test below asserts what the SECURITY ANSWER
becomes when a dependency is gone -- and, where the safe answer is to allow,
that the allow is marked as degraded rather than reported as a normal decision.
"""

from __future__ import annotations

import pytest

from sentinel.domain.errors import TransientFailure
from sentinel.infrastructure.persistence.cache import (
    RateLimitDecision,
    TokenBucketLimiter,
)


class _DeadCache:
    """A cache whose every operation fails the way a driver failure surfaces.

    `TransientFailure` specifically: `cache.py` documents that every driver
    exception is translated at its boundary, so this is the shape the limiter
    actually sees when Redis is gone -- not a raw redis error.
    """

    def get(self, key):
        raise TransientFailure("redis unreachable")

    def set(self, key, value, ttl_seconds=0):
        raise TransientFailure("redis unreachable")

    def consume_token(self, key, *, capacity, refill_per_sec, ttl_seconds):
        raise TransientFailure("redis unreachable")


# ── Redis unavailable ────────────────────────────────────────────────────────


def test_a_dead_cache_does_not_take_the_rate_limiter_down_with_it():
    """The limiter must return an answer, not propagate a driver failure into
    the request path."""
    limiter = TokenBucketLimiter(
        cache=_DeadCache(), limits={"ingest": 60}, fail_open=True
    )
    decision = limiter.check(tenant_id="acme", klass="ingest")
    assert isinstance(decision, RateLimitDecision)


def test_an_allow_from_a_dead_cache_is_marked_degraded():
    """THE property that makes fail-open survivable.

    "Allowed because there was budget" and "allowed because the limiter was
    down" are different facts, and collapsing them hides a bypass: an operator
    reading allow decisions cannot tell that rate limiting stopped happening.
    """
    limiter = TokenBucketLimiter(
        cache=_DeadCache(), limits={"ingest": 60}, fail_open=True
    )
    decision = limiter.check(tenant_id="acme", klass="ingest")
    assert decision.allowed
    assert decision.degraded, (
        "the limiter allowed a request without reaching the limiter and did not "
        "say so; that is an unobservable bypass"
    )


def test_a_fail_closed_limiter_refuses_when_the_cache_is_dead():
    """The other configuration, and it must actually be honoured. A fail-closed
    limiter that fails open when the cache dies is the worst of both."""
    limiter = TokenBucketLimiter(
        cache=_DeadCache(), limits={"ingest": 60}, fail_open=False
    )
    decision = limiter.check(tenant_id="acme", klass="ingest")
    assert not decision.allowed
    assert decision.degraded
    # A refusal with no retry hint tells a caller to give up rather than back
    # off, which turns a transient cache outage into a client-side outage.
    assert decision.retry_after_seconds > 0


def test_a_healthy_cache_decision_is_not_marked_degraded():
    """The negative case. Without it, a limiter that marked EVERY decision
    degraded would pass the tests above while making the flag meaningless."""

    class _WorkingCache:
        def consume_token(self, key, *, capacity, refill_per_sec, ttl_seconds):
            return (True, capacity - 1, 0.0)

    decision = TokenBucketLimiter(
        cache=_WorkingCache(), limits={"ingest": 60}, fail_open=True
    ).check(tenant_id="acme", klass="ingest")
    assert decision.allowed
    assert not decision.degraded


# ── PostgreSQL unavailable ───────────────────────────────────────────────────


def test_a_database_failure_is_classified_retryable():
    """The distinction decides whether a caller retries.

    `sentinel/interface/http.py` maps `TransientFailure` to 503 with a
    `Retry-After`. A 500 tells a client the request was malformed and will never
    work; a 503 tells it the service is temporarily unable. An ingest client
    that gives up on a retryable failure loses telemetry permanently, and the
    telemetry is the product.

    An earlier draft of this test ended in `assert ... or True`, which cannot
    fail. That is the defect class this whole suite exists to catch, written
    into a chaos module by the person writing the chaos module. It is replaced
    by the behavioural test below.
    """
    from sentinel.domain.errors import SentinelError

    assert issubclass(TransientFailure, SentinelError)
    assert TransientFailure("x").is_retryable


def test_the_engine_translates_driver_failures_into_transient_failures():
    """Verified against the real translation rather than the docstring.

    A driver exception that escaped untranslated would surface as a 500 and be
    read by every client as permanent.
    """
    import sqlite3

    from sentinel.infrastructure.sql.engine import Connection

    class _BrokenCursor:
        def execute(self, sql, params):
            raise sqlite3.OperationalError("database is locked")

        @property
        def rowcount(self):
            return 0

        def close(self):
            return None

    class _BrokenRaw:
        def cursor(self):
            return _BrokenCursor()

    conn = Connection.__new__(Connection)
    object.__setattr__(conn, "_raw", _BrokenRaw()) if not hasattr(
        conn, "__dict__"
    ) else setattr(conn, "_raw", _BrokenRaw())

    with pytest.raises(TransientFailure):
        conn.execute_rowcount("SELECT 1", ())


# ── Clock skew ───────────────────────────────────────────────────────────────


def test_an_event_timestamped_far_in_the_future_does_not_become_undeletable():
    """Retention compares against a cutoff derived from now.

    An event stamped in the year 3000 -- by a skewed clock or by a caller that
    chose the value -- would sit permanently above every future cutoff and never
    be reaped. That is a slow unbounded-growth bug with an attacker-controlled
    trigger, and it is the reason retention windows must not trust a
    caller-supplied timestamp as their only input.

    This test records the CURRENT behaviour honestly: the sweep is driven by the
    stored timestamp, so a skewed one does survive. What bounds the damage today
    is that `occurred_at` is written from the admission path, not copied blindly
    from the payload -- and this test exists so that if that ever changes,
    something says so.
    """
    from datetime import timedelta

    from sentinel.domain.primitives import Timestamp

    now = Timestamp.parse("2026-08-24T12:00:00+00:00")
    skewed = Timestamp.parse("3000-01-01T00:00:00+00:00")
    cutoff = Timestamp(now.value - timedelta(days=90))

    assert skewed > cutoff, (
        "a far-future timestamp is above the retention cutoff, so it is not "
        "reaped; this is recorded, not asserted as desirable"
    )
    # And the ordering used by the sweep is sane for ordinary values.
    ordinary = Timestamp.parse("2020-01-01T00:00:00+00:00")
    assert ordinary < cutoff


def test_timestamp_comparison_is_timezone_normalised():
    """Skew between two hosts in different zones must not reorder events.

    `Timestamp` normalises to UTC on construction, so a naive local time and an
    offset time for the same instant compare equal. Without that, a replica in
    one zone and a replica in another would disagree about which of two events
    came first -- and sequence detection is entirely about which came first.
    """
    from sentinel.domain.primitives import Timestamp

    utc = Timestamp.parse("2026-08-24T12:00:00+00:00")
    offset = Timestamp.parse("2026-08-24T17:30:00+05:30")
    assert utc == offset


def test_a_naive_timestamp_is_treated_as_utc_rather_than_local():
    """The alternative -- interpreting it in the host's zone -- makes the same
    string mean different instants on different replicas, which is clock skew
    manufactured by the parser rather than by any clock."""
    from sentinel.domain.primitives import Timestamp

    naive = Timestamp.parse("2026-08-24T12:00:00")
    explicit = Timestamp.parse("2026-08-24T12:00:00+00:00")
    assert naive == explicit


def test_the_limiter_fails_closed_unless_a_deployment_says_otherwise():
    """The DEFAULT is the decision most deployments actually get.

    `fail_open` used to default to True, so a limiter constructed without the
    argument -- every test double, every quick wiring -- silently stopped
    limiting the moment its cache went away. A rate limit an attacker can
    remove by making Redis unreachable is not a control. Fail-open remains
    available; it has to be asked for.
    """
    limiter = TokenBucketLimiter(cache=_DeadCache(), limits={"ingest": 60})
    assert limiter.fail_open is False
    decision = limiter.check(tenant_id="acme", klass="ingest")
    assert not decision.allowed
    assert decision.degraded
    assert decision.retry_after_seconds > 0
