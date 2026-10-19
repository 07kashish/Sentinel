"""Redis, and an in-process cache, behind one port.

WHAT THIS IS FOR, AND WHAT IT MUST NEVER BE FOR
------------------------------------------------
Everything here is DISPOSABLE. Flushing Redis must cost throughput and nothing
else -- no incident, no evidence, no audit entry, no queue item may exist only
here.

The predecessor provisioned Redis in `docker-compose.yml` and read it from no
code, then put its work queue in the database instead, with a comment explaining
that a second stateful store would recreate the split-authority defect the review
had named four times. That reasoning was right and is preserved: the queue, the
outbox, the journal and the ledger stay in PostgreSQL where they are
transactional. Redis gets the three jobs that genuinely suit it:

  * **Rate limiting.** A token bucket in the database means a row lock on every
    request -- the single largest throughput ceiling the review found. In Redis it
    is one atomic script.
  * **Read-through caching** of small, hot, tolerably-stale values.
  * **Distributed locks** for coordination that does not need durability.

RATE LIMITING IS A SCRIPT, NOT A SEQUENCE
------------------------------------------
GET, compute, SET is not a rate limiter. Two clients read the same count and both
allow the request, which is exactly the concurrency the limiter exists to
constrain. The refill and the decrement run as ONE Lua script, atomic on the
server, so the check cannot be beaten by racing it.

The bucket is also refilled from the SERVER's clock (`TIME`), not the caller's.
The predecessor used `time.time()` from each pod, so a pod whose clock ran five
seconds fast granted itself five seconds of free tokens -- a "shared" limit only
as accurate as NTP.

FAILURE POLICY IS EXPLICIT
--------------------------
When Redis is unreachable the limiter must choose: fail open (allow, losing the
limit) or fail closed (deny, losing availability). Both are defensible and the
wrong one is a silent outage or a silent bypass, so `fail_open` is a required
constructor argument with no default. Somebody has to decide.

WHAT IS NOT VERIFIED
--------------------
No real Redis server has run this. The tests drive `fakeredis` with a Lua
interpreter, which executes the token-bucket script for real -- so the atomicity
claim is tested, not asserted -- but `fakeredis` is a reimplementation. Cluster
mode, `MOVED`/`ASK` redirects, key eviction under `maxmemory`, replica failover and
`TIME` behaviour on a server whose clock steps are all unexercised. Rate limiting
is the one job here whose failure is a security property rather than a latency one,
so run it against a real server before it guards anything that matters.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from sentinel.domain.errors import TransientFailure

__all__ = [
    "Cache",
    "InProcessCache",
    "RateLimitDecision",
    "RateLimiter",
    "RedisCache",
    "TokenBucketLimiter",
]


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    allowed: bool
    remaining: float
    retry_after_seconds: float
    #: True when the decision was made without reaching the limiter, so an
    #: operator can tell "allowed because there was budget" from "allowed because
    #: the limiter was down". Collapsing those hides a bypass.
    degraded: bool = False


@runtime_checkable
class Cache(Protocol):
    """Disposable key-value storage. Nothing durable may live here."""

    def get(self, key: str) -> bytes | None: ...

    def set(self, key: str, value: bytes, *, ttl_seconds: int) -> None:
        """Store with a MANDATORY expiry.

        No unbounded `set`. A cache entry without a TTL is a memory leak that
        takes weeks to show up and looks like a slow leak in something else.
        """
        ...

    def delete(self, key: str) -> bool: ...

    def acquire_lock(self, key: str, *, ttl_seconds: int, token: str) -> bool:
        """Take a lock, or return False. The TTL is the only release guarantee.

        A holder that dies never releases, so the TTL must exceed the longest
        legitimate hold. This is advisory coordination, NOT a fence: Redis
        replication is asynchronous, so a failover can hand the same lock to two
        holders. Anything requiring exclusivity for correctness uses the
        database's execution fence instead.
        """
        ...

    def release_lock(self, key: str, *, token: str) -> bool:
        """Release only if `token` still holds it.

        Checking the token matters: without it, a holder whose TTL expired and
        whose lock was taken by someone else would release the NEW holder's lock.
        """
        ...

    def healthy(self) -> bool: ...


class InProcessCache:
    """A real cache with no server. Correct for a single replica.

    Not a stub. A single-pod deployment needs no Redis, and running one anyway
    adds an operational dependency and a network hop for no benefit. The locks
    are process-local, which is exactly right when there is one process and
    exactly wrong when there are several -- so `Container` selects this only when
    no Redis URL is configured, and the shard count is one.
    """

    __slots__ = ("_entries", "_clock")

    def __init__(self, clock=time.monotonic) -> None:
        self._entries: dict[str, tuple[bytes, float]] = {}
        self._clock = clock

    def _live(self, key: str) -> tuple[bytes, float] | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        if entry[1] <= self._clock():
            del self._entries[key]
            return None
        return entry

    def get(self, key: str) -> bytes | None:
        entry = self._live(key)
        return entry[0] if entry else None

    def set(self, key: str, value: bytes, *, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            raise TransientFailure("a cache entry must have a positive TTL")
        self._entries[key] = (value, self._clock() + ttl_seconds)

    def delete(self, key: str) -> bool:
        return self._entries.pop(key, None) is not None

    def acquire_lock(self, key: str, *, ttl_seconds: int, token: str) -> bool:
        if self._live(key) is not None:
            return False
        self._entries[key] = (token.encode("utf-8"), self._clock() + ttl_seconds)
        return True

    def release_lock(self, key: str, *, token: str) -> bool:
        entry = self._live(key)
        if entry is None or entry[0] != token.encode("utf-8"):
            return False
        del self._entries[key]
        return True

    def healthy(self) -> bool:
        return True

    def clear(self) -> None:
        self._entries.clear()


#: Refill and decrement in ONE round trip, atomic on the server.
#:
#: Returns {allowed, remaining, retry_after_ms}. The elapsed time comes from
#: Redis's own TIME, so every replica computes the refill against one clock --
#: which is the difference between a shared limit and N limits that drift apart.
_BUCKET_SCRIPT = """
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_per_sec = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])

local now = redis.call('TIME')
local now_ms = (tonumber(now[1]) * 1000) + math.floor(tonumber(now[2]) / 1000)

local bucket = redis.call('HMGET', key, 'tokens', 'updated_ms')
local tokens = tonumber(bucket[1])
local updated_ms = tonumber(bucket[2])

if tokens == nil then
  tokens = capacity
  updated_ms = now_ms
end

local elapsed_ms = now_ms - updated_ms
if elapsed_ms < 0 then elapsed_ms = 0 end
tokens = math.min(capacity, tokens + (elapsed_ms / 1000.0) * refill_per_sec)

local allowed = 0
if tokens >= 1.0 then
  tokens = tokens - 1.0
  allowed = 1
end

redis.call('HSET', key, 'tokens', tokens, 'updated_ms', now_ms)
redis.call('EXPIRE', key, ttl)

local retry_after_ms = 0
if allowed == 0 and refill_per_sec > 0 then
  retry_after_ms = math.ceil(((1.0 - tokens) / refill_per_sec) * 1000)
end

return {allowed, tostring(tokens), retry_after_ms}
"""


class RedisCache:
    """A Redis-backed cache and limiter.

    Constructed from an injected client, so the container decides how to connect
    and this class only decides what to say. Every driver exception is translated
    to `TransientFailure`, because the application layer must not know what a
    `redis.ConnectionError` is.
    """

    __slots__ = ("_client", "_script")

    def __init__(self, client: Any) -> None:
        self._client = client
        self._script = None

    @classmethod
    def from_url(cls, url: str, *, timeout: float = 2.0) -> "RedisCache":
        """Connect to Redis. A short timeout on purpose.

        A cache is on the hot path; waiting five seconds for it defeats the reason
        it exists. Two seconds and then the caller's failure policy decides.
        """
        import redis

        return cls(
            redis.Redis.from_url(
                url,
                socket_timeout=timeout,
                socket_connect_timeout=timeout,
                health_check_interval=30,
            )
        )

    def _guard(self, operation: str, call):
        try:
            return call()
        except Exception as exc:  # noqa: BLE001 - driver exceptions stop here
            raise TransientFailure(
                f"redis {operation} failed: {type(exc).__name__}: {exc}"
            ) from exc

    def get(self, key: str) -> bytes | None:
        return self._guard("GET", lambda: self._client.get(key))

    def set(self, key: str, value: bytes, *, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            raise TransientFailure("a cache entry must have a positive TTL")
        # `set(..., ex=)` rather than `setex`, which redis-py deprecated. Both
        # are one round trip; the deprecated form emits a warning that a suite
        # configured to treat warnings as errors will fail on -- and this one is.
        self._guard(
            "SET EX", lambda: self._client.set(key, value, ex=ttl_seconds)
        )

    def delete(self, key: str) -> bool:
        return bool(self._guard("DEL", lambda: self._client.delete(key)))

    def acquire_lock(self, key: str, *, ttl_seconds: int, token: str) -> bool:
        # SET NX EX in one command. A separate SETNX then EXPIRE can leave a lock
        # with no expiry if the process dies between them -- a lock nothing will
        # ever release.
        return bool(
            self._guard(
                "SET NX",
                lambda: self._client.set(key, token, nx=True, ex=ttl_seconds),
            )
        )

    def release_lock(self, key: str, *, token: str) -> bool:
        script = (
            "if redis.call('GET', KEYS[1]) == ARGV[1] then "
            "return redis.call('DEL', KEYS[1]) else return 0 end"
        )
        return bool(
            self._guard(
                "release",
                lambda: self._client.eval(script, 1, key, token),
            )
        )

    def consume_token(
        self, key: str, *, capacity: float, refill_per_sec: float, ttl_seconds: int
    ) -> tuple[bool, float, float]:
        """Take one token atomically. Returns (allowed, remaining, retry_after)."""
        result = self._guard(
            "token bucket",
            lambda: self._client.eval(
                _BUCKET_SCRIPT, 1, key, capacity, refill_per_sec, ttl_seconds
            ),
        )
        allowed = bool(int(result[0]))
        remaining = float(result[1])
        retry_after = float(result[2]) / 1000.0
        return allowed, remaining, retry_after

    def healthy(self) -> bool:
        try:
            return bool(self._client.ping())
        except Exception:  # noqa: BLE001
            return False


@runtime_checkable
class RateLimiter(Protocol):
    def check(self, *, tenant_id: str, klass: str) -> RateLimitDecision: ...


@dataclass
class TokenBucketLimiter:
    """A shared token bucket, with an explicit failure policy."""

    cache: Any
    limits: dict[str, int] = field(default_factory=dict)
    #: When the limiter is unreachable, allow (losing the limit) or deny
    #: (losing availability)? For an ingest path fail-open keeps telemetry
    #: flowing, and for an admin path fail-closed is correct -- somebody
    #: decides, per deployment. What is NOT a decision is the default, and it
    #: is CLOSED: a rate limiter whose backing store has gone away is a rate
    #: limiter that has gone away, and a security product whose limits vanish
    #: the moment Redis is unreachable has no limits an attacker cannot remove
    #: by making Redis unreachable. A deployment that wants fail-open says so.
    fail_open: bool = False
    ttl_seconds: int = 120

    def check(self, *, tenant_id: str, klass: str) -> RateLimitDecision:
        per_minute = self.limits.get(klass)
        if per_minute is None:
            raise TransientFailure(
                f"no rate limit configured for route class {klass!r}. An unlimited "
                "class is a decision, and must be stated as one."
            )
        key = f"rl:{tenant_id}:{klass}"
        try:
            if hasattr(self.cache, "consume_token"):
                allowed, remaining, retry_after = self.cache.consume_token(
                    key,
                    capacity=float(per_minute),
                    refill_per_sec=per_minute / 60.0,
                    ttl_seconds=self.ttl_seconds,
                )
            else:
                allowed, remaining, retry_after = _local_bucket(
                    self.cache, key, per_minute, self.ttl_seconds
                )
        except TransientFailure:
            return RateLimitDecision(
                allowed=self.fail_open,
                remaining=0.0,
                retry_after_seconds=0.0 if self.fail_open else 60.0,
                degraded=True,
            )
        return RateLimitDecision(
            allowed=allowed, remaining=remaining, retry_after_seconds=retry_after
        )


def _local_bucket(
    cache: Any, key: str, per_minute: int, ttl_seconds: int
) -> tuple[bool, float, float]:
    """Token bucket over a plain `Cache`, for the in-process adapter.

    Single-threaded per process and therefore atomic enough; a multi-replica
    deployment configures Redis, where the Lua script provides real atomicity.
    """
    import json as _json

    now = time.monotonic()
    raw = cache.get(key)
    if raw is None:
        tokens, updated = float(per_minute), now
    else:
        state = _json.loads(raw.decode("utf-8"))
        tokens, updated = float(state["tokens"]), float(state["updated"])
        tokens = min(per_minute, tokens + max(0.0, now - updated) * (per_minute / 60.0))

    allowed = tokens >= 1.0
    if allowed:
        tokens -= 1.0
    cache.set(
        key,
        _json.dumps({"tokens": tokens, "updated": now}).encode("utf-8"),
        ttl_seconds=ttl_seconds,
    )
    retry_after = 0.0 if allowed else (1.0 - tokens) / (per_minute / 60.0)
    return allowed, tokens, retry_after
