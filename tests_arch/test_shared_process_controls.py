"""Independent local processes share real control stores; not a pod/CNI test."""
from multiprocessing import get_context
import os
import socket
from time import monotonic
from uuid import uuid4

import pytest

from sentinel.infrastructure.persistence.cache import RedisCache, TokenBucketLimiter
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.infrastructure.sql.nonce_ledger import SqlNonceLedger


def _claim_nonces(config, tenants, start, results):
    pool = build_engine(config)
    try:
        ledger = SqlNonceLedger(pool)
        start.wait(20)
        results.put(tuple(sum(ledger.claim(tenant_id=tenant, nonce="same-nonce")
                              for _ in range(8)) for tenant in tenants))
    finally:
        pool.close()


def _consume_limits(url, tenants, start, results):
    limiter = TokenBucketLimiter(RedisCache.from_url(url), {"action": 1}, fail_open=False)
    start.wait(20)
    results.put(tuple(sum(limiter.check(tenant_id=tenant, klass="action").allowed
                          for _ in range(8)) for tenant in tenants))


def _race(target, args):
    context = get_context("spawn")
    start, results = context.Barrier(3), context.Queue()
    processes = [context.Process(target=target, args=(*args, start, results)) for _ in range(2)]
    try:
        for process in processes:
            process.start()
        start.wait(20)
        began = monotonic()
        observed = [results.get(timeout=20) for _ in processes]
        assert monotonic() - began < 30  # below a one-token/minute refill
        for process in processes:
            process.join(5)
            assert process.exitcode == 0
        return observed
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(5)
        results.close()
        results.join_thread()


def test_nonce_claims_are_shared_across_independent_processes(engine_config):
    pool = build_engine(engine_config)
    try:
        migrate(pool)
    finally:
        pool.close()
    tenants = ("tenant-a-" + uuid4().hex, "tenant-b-" + uuid4().hex)
    observed = _race(_claim_nonces, (engine_config, tenants))
    assert [sum(row[i] for row in observed) for i in range(2)] == [1, 1]


def test_real_redis_limits_are_shared_and_tenant_scoped_across_processes():
    url = os.environ.get("SENTINEL_TEST_REDIS_URL", "")
    if not url:
        pytest.skip("isolated real Redis URL required")
    tenants = ("tenant-a-" + uuid4().hex, "tenant-b-" + uuid4().hex)
    cache = RedisCache.from_url(url)
    try:
        observed = _race(_consume_limits, (url, tenants))
        assert [sum(row[i] for row in observed) for i in range(2)] == [1, 1]
    finally:
        for tenant in tenants:
            cache.delete(f"rl:{tenant}:action")


def test_real_connection_refusal_fails_closed():
    # Hold a reserved, non-listening port: no existing service is disrupted.
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        cache = RedisCache.from_url(f"redis://127.0.0.1:{reserved.getsockname()[1]}/0")
        decision = TokenBucketLimiter(cache, {"action": 1}, fail_open=False).check(
            tenant_id="synthetic-outage", klass="action")
    assert not decision.allowed and decision.degraded
