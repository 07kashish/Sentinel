"""Object storage and the cache, including the parts that need no server.

The filesystem object store is exercised end-to-end because a mounted volume is a
real production target. The S3 adapter's signing is verified against AWS's own
published Signature Version 4 test vectors, which checks the only part of the
protocol that is genuinely hard to get right -- `SignatureDoesNotMatch` tells you
nothing about which of the four derivation steps was wrong.

The Redis adapter is exercised against `fakeredis`, a faithful reimplementation of
the Redis command set including server-side Lua. That verifies the client logic
and the atomicity of the token-bucket script; it does not verify behaviour under
failover, which needs a real cluster and is named as unverified rather than
implied.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from sentinel.domain.errors import TransientFailure
from sentinel.infrastructure.outbound import HardenedHttpClient, OutboundPolicy, OutboundResponse
from sentinel.infrastructure.persistence.cache import (
    InProcessCache,
    RedisCache,
    TokenBucketLimiter,
)
from sentinel.infrastructure.persistence.objectstore import (
    BlobKey,
    BlobMissing,
    FilesystemObjectStore,
    S3Credentials,
    S3ObjectStore,
    sigv4_signature,
)


# ── Object storage: the filesystem adapter ──────────────────────────────────


@pytest.fixture
def store(tmp_path):
    return FilesystemObjectStore(tmp_path / "blobs")


def _key(tenant: str = "acme", identifier: str = "inc-1") -> BlobKey:
    return BlobKey(tenant_id=tenant, kind="evidence", identifier=identifier)


def test_a_blob_round_trips_and_reports_its_digest(store):
    digest = store.put(_key(), b"captured payload")
    assert store.get(_key()) == b"captured payload"
    import hashlib

    assert digest == hashlib.sha256(b"captured payload").hexdigest()


def test_writing_the_same_key_twice_is_not_an_error(store):
    """A retried write after an ambiguous failure must be safe."""
    store.put(_key(), b"first")
    store.put(_key(), b"second")
    assert store.get(_key()) == b"second"


def test_a_missing_blob_raises_rather_than_returning_empty(store):
    with pytest.raises(BlobMissing):
        store.get(_key(identifier="never-written"))


def test_delete_is_idempotent(store):
    store.put(_key(), b"x")
    assert store.delete(_key()) is True
    assert store.delete(_key()) is False


def test_a_key_cannot_traverse_out_of_its_tenant_prefix():
    """The tenant is the first path segment, so isolation is a prefix policy.

    A key that can contain a separator can read another tenant's bytes, and an
    object store has no row-level security to fall back on.
    """
    for bad in ("../other", "a/b", "..", ""):
        with pytest.raises(BlobMissing):
            BlobKey(tenant_id=bad, kind="evidence", identifier="x")
        with pytest.raises(BlobMissing):
            BlobKey(tenant_id="acme", kind="evidence", identifier=bad)


def test_listing_is_scoped_to_one_tenant_and_kind(store):
    store.put(BlobKey("acme", "evidence", "a"), b"1")
    store.put(BlobKey("acme", "evidence", "b"), b"2")
    store.put(BlobKey("acme", "reports", "c"), b"3")
    store.put(BlobKey("globex", "evidence", "d"), b"4")

    listed = sorted(k.identifier for k in store.list_prefix(tenant_id="acme", kind="evidence"))
    assert listed == ["a", "b"]


def test_a_partial_write_is_never_visible_under_its_real_key(store, tmp_path):
    """Written to a temporary name and renamed, because rename is atomic.

    A half-written blob visible under its real key is indistinguishable from a
    complete one, and would fail its digest check much later and somewhere
    unhelpful.
    """
    key = _key()
    store.put(key, b"complete")
    # A crash mid-write leaves a `.partial` file, which listing must ignore.
    partial = tmp_path / "blobs" / "acme" / "evidence" / "leftover.partial"
    partial.write_bytes(b"half")
    assert [k.identifier for k in store.list_prefix(tenant_id="acme", kind="evidence")] == [
        "inc-1"
    ]


def test_a_large_blob_survives_the_round_trip(store):
    payload = bytes(range(256)) * 8192  # 2 MiB
    store.put(_key(identifier="big"), payload)
    assert store.get(_key(identifier="big")) == payload


# ── Object storage: S3 signing ──────────────────────────────────────────────


def test_sigv4_matches_the_published_aws_test_vector():
    """AWS's own `get-vanilla` vector from the SigV4 test suite.

    Verifying against a published vector rather than against my own
    implementation is the difference between "the code agrees with itself" and
    "the code agrees with AWS". Signing is the only part of S3 that fails
    opaquely.
    """
    # From AWS documentation: Deriving a signing key, worked example.
    signature = sigv4_signature(
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        date_stamp="20150830",
        region="us-east-1",
        service="iam",
        string_to_sign=(
            "AWS4-HMAC-SHA256\n"
            "20150830T123600Z\n"
            "20150830/us-east-1/iam/aws4_request\n"
            "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"
        ),
    )
    assert signature == (
        "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
    )


class _StubHttpClient:
    """Stands in for `HardenedHttpClient` with the same call contract.

    A stub rather than the real client with a fake connection, because the real
    client resolves the endpoint before connecting -- correctly, that is its
    DNS-rebinding defence -- and a unit test of SigV4 shaping must not depend on
    name resolution. The hardened client's own behaviour is covered exhaustively
    in `test_security_outbound.py` against real sockets.
    """

    def __init__(self, responder) -> None:
        self._responder = responder
        self.calls: list[dict] = []
        self.policy = OutboundPolicy()

    def request(self, *, method, url, headers=None, body=None, idempotent=False):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": {k.lower(): v for k, v in (headers or {}).items()},
                "body": body,
                "idempotent": idempotent,
            }
        )
        return self._responder(len(self.calls) - 1)


def _response(status: int = 200, body: bytes = b"", headers=None) -> OutboundResponse:
    return OutboundResponse(
        status=status, headers=headers or {}, body=body, peer="203.0.113.1:443"
    )


def test_the_s3_adapter_signs_and_shapes_a_request_correctly():
    """Captures the request without a network, and checks its structure."""
    client = _StubHttpClient(lambda _n: _response(200, b"stored"))

    s3 = S3ObjectStore(
        bucket="evidence-bucket",
        credentials=S3Credentials(
            access_key_id="AKIAIOSFODNN7EXAMPLE",
            secret_access_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            region="eu-west-2",
        ),
        endpoint="https://s3.eu-west-2.amazonaws.com",
        client=client,
    )
    s3.put(BlobKey("acme", "evidence", "inc-1"), b"payload")

    captured = client.calls[0]
    assert captured["method"] == "PUT"
    assert str(captured["url"]).endswith("/evidence-bucket/acme/evidence/inc-1")
    headers = captured["headers"]
    assert headers["authorization"].startswith("AWS4-HMAC-SHA256 Credential=")
    assert "eu-west-2/s3/aws4_request" in headers["authorization"]
    # The payload hash must be the real one; UNSIGNED-PAYLOAD would let a
    # man-in-the-middle alter the body without breaking the signature.
    import hashlib

    assert headers["x-amz-content-sha256"] == hashlib.sha256(b"payload").hexdigest()
    assert captured["body"] == b"payload"


def test_a_403_is_treated_as_absent_not_as_an_outage():
    """A locked-down bucket returns 403 for a missing key, not 404.

    Treating only 404 as absent makes `exists` wrong on exactly the buckets that
    are configured correctly.
    """
    s3 = S3ObjectStore(
        bucket="b",
        credentials=S3Credentials("k", "s"),
        client=_StubHttpClient(lambda _n: _response(403, b"Forbidden")),
    )
    assert s3.exists(BlobKey("acme", "evidence", "x")) is False
    with pytest.raises(BlobMissing):
        s3.get(BlobKey("acme", "evidence", "x"))


def test_a_server_error_is_transient_not_absent():
    s3 = S3ObjectStore(
        bucket="b",
        credentials=S3Credentials("k", "s"),
        client=_StubHttpClient(lambda _n: _response(503, b"Slow Down")),
    )
    with pytest.raises(TransientFailure) as caught:
        s3.get(BlobKey("acme", "evidence", "x"))
    assert caught.value.is_retryable is True


def test_a_redirect_from_s3_is_surfaced_rather_than_followed():
    """S3 answers 307 on a region mismatch, carrying a signed Authorization header.

    Following it would forward a replayable signed credential to whatever the
    redirect names. The hardened client refuses, and the adapter must translate
    that refusal into an error an operator can act on rather than swallowing it.
    """
    from sentinel.infrastructure.outbound import OutboundRefused as _Refused

    def refuse(_n):
        raise _Refused("destination answered HTTP 307 redirecting to https://evil.example")

    s3 = S3ObjectStore(
        bucket="b", credentials=S3Credentials("k", "s"), client=_StubHttpClient(refuse)
    )
    with pytest.raises(TransientFailure) as caught:
        s3.get(BlobKey("acme", "evidence", "x"))
    assert "refused" in str(caught.value)
    assert "307" in str(caught.value)


def test_an_object_store_endpoint_that_is_not_https_is_refused_at_construction():
    """Fail at boot, not at the first evidence write."""
    from sentinel.domain.primitives import InvalidValue

    with pytest.raises(InvalidValue) as refused:
        S3ObjectStore(
            bucket="b",
            credentials=S3Credentials("k", "s"),
            endpoint="http://s3.internal",
        )
    assert "not callable" in str(refused.value)


def test_listing_follows_the_continuation_token():
    """A single ListObjectsV2 returns at most 1000 keys.

    Ignoring the token gives a sweep that stops at 1000 and reports success,
    which for an orphan sweep means it never reclaims anything past page one.
    """
    pages = [
        (
            "<ListBucketResult><IsTruncated>true</IsTruncated>"
            "<Key>acme/evidence/a</Key><Key>acme/evidence/b</Key>"
            "<NextContinuationToken>tok-2</NextContinuationToken></ListBucketResult>"
        ),
        (
            "<ListBucketResult><IsTruncated>false</IsTruncated>"
            "<Key>acme/evidence/c</Key></ListBucketResult>"
        ),
    ]
    client = _StubHttpClient(lambda n: _response(200, pages[n].encode()))
    s3 = S3ObjectStore(bucket="b", credentials=S3Credentials("k", "s"), client=client)
    keys = [k.identifier for k in s3.list_prefix(tenant_id="acme", kind="evidence")]

    assert keys == ["a", "b", "c"]
    assert len(client.calls) == 2
    assert "continuation-token=tok-2" in str(client.calls[1]["url"])


# ── Cache: the in-process adapter ───────────────────────────────────────────


def test_the_in_process_cache_expires_entries():
    now = [1000.0]
    cache = InProcessCache(clock=lambda: now[0])
    cache.set("k", b"v", ttl_seconds=10)
    assert cache.get("k") == b"v"
    now[0] += 11
    assert cache.get("k") is None


def test_a_cache_entry_without_a_ttl_is_refused():
    """An unbounded entry is a memory leak that takes weeks to surface."""
    cache = InProcessCache()
    for bad in (0, -1):
        with pytest.raises(TransientFailure):
            cache.set("k", b"v", ttl_seconds=bad)


def test_a_lock_is_exclusive_and_only_its_holder_releases_it():
    cache = InProcessCache()
    assert cache.acquire_lock("job", ttl_seconds=30, token="holder-a") is True
    assert cache.acquire_lock("job", ttl_seconds=30, token="holder-b") is False
    # A different holder must NOT be able to release it: without the token check
    # a holder whose TTL expired would release whoever took the lock next.
    assert cache.release_lock("job", token="holder-b") is False
    assert cache.release_lock("job", token="holder-a") is True
    assert cache.acquire_lock("job", ttl_seconds=30, token="holder-b") is True


def test_an_expired_lock_becomes_available():
    now = [0.0]
    cache = InProcessCache(clock=lambda: now[0])
    cache.acquire_lock("job", ttl_seconds=5, token="dead-holder")
    now[0] += 6
    assert cache.acquire_lock("job", ttl_seconds=5, token="new-holder") is True


# ── Cache: the Redis adapter, against a faithful reimplementation ───────────


@pytest.fixture
def redis_cache():
    fakeredis = pytest.importorskip("fakeredis", reason="fakeredis is a dev dependency")
    return RedisCache(fakeredis.FakeStrictRedis())


@pytest.fixture
def live_redis_cache():
    """Real Redis when SENTINEL_TEST_REDIS_URL is set (CI redis:7 service)."""
    import os

    url = os.getenv("SENTINEL_TEST_REDIS_URL", "").strip()
    if not url:
        pytest.skip(
            "SENTINEL_TEST_REDIS_URL unset — real Redis unexercised in this run "
            "(fakeredis covers unit logic)"
        )
    return RedisCache.from_url(url)


def test_live_redis_adapter_round_trips_without_fakeredis(live_redis_cache):
    key = "sentinel:ci:live-redis:roundtrip"
    live_redis_cache.delete(key)
    live_redis_cache.set(key, b"live-v", ttl_seconds=30)
    assert live_redis_cache.get(key) == b"live-v"
    assert live_redis_cache.delete(key) is True
    assert live_redis_cache.get(key) is None


def test_live_redis_token_bucket_is_atomic(live_redis_cache):
    key = "sentinel:ci:live-redis:bucket"
    live_redis_cache.delete(key)
    allowed = 0
    for _ in range(12):
        ok, _remaining, _retry = live_redis_cache.consume_token(
            key, capacity=5, refill_per_sec=0.0, ttl_seconds=30
        )
        allowed += int(ok)
    assert allowed == 5


def test_the_redis_adapter_round_trips_and_expires(redis_cache):
    redis_cache.set("k", b"v", ttl_seconds=60)
    assert redis_cache.get("k") == b"v"
    assert redis_cache.delete("k") is True
    assert redis_cache.get("k") is None


def test_the_redis_lock_is_set_nx_ex_in_one_command(redis_cache):
    """SETNX then EXPIRE can leave a lock with no expiry if the process dies
    between them -- a lock nothing will ever release."""
    assert redis_cache.acquire_lock("job", ttl_seconds=30, token="a") is True
    assert redis_cache.acquire_lock("job", ttl_seconds=30, token="b") is False
    assert redis_cache.release_lock("job", token="b") is False
    assert redis_cache.release_lock("job", token="a") is True


def test_the_token_bucket_is_atomic_and_bounded(redis_cache):
    """Allows exactly `capacity` requests before refusing.

    GET/compute/SET would let two clients read the same count and both allow, so
    the refill and decrement run as one server-side script.
    """
    allowed = 0
    for _ in range(20):
        ok, _remaining, _retry = redis_cache.consume_token(
            "rl:acme:ingest", capacity=10, refill_per_sec=0.0, ttl_seconds=60
        )
        allowed += int(ok)
    assert allowed == 10


def test_the_token_bucket_reports_a_usable_retry_after(redis_cache):
    for _ in range(5):
        redis_cache.consume_token(
            "rl:acme:read", capacity=5, refill_per_sec=1.0, ttl_seconds=60
        )
    allowed, _remaining, retry_after = redis_cache.consume_token(
        "rl:acme:read", capacity=5, refill_per_sec=1.0, ttl_seconds=60
    )
    assert allowed is False
    assert 0.0 < retry_after <= 2.0


def test_concurrent_consumers_cannot_beat_the_bucket(redis_cache):
    """Sixteen threads, capacity ten. Exactly ten may pass.

    This is the property a database row lock provided at the cost of serialising
    every request, and the Lua script provides without one.
    """
    results: list[bool] = []
    lock = threading.Lock()
    barrier = threading.Barrier(16)

    def attempt(_index: int) -> None:
        barrier.wait(timeout=30)
        ok, _r, _ra = redis_cache.consume_token(
            "rl:acme:burst", capacity=10, refill_per_sec=0.0, ttl_seconds=60
        )
        with lock:
            results.append(ok)

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(attempt, range(16)))

    assert sum(results) == 10, f"{sum(results)} of 16 allowed; expected exactly 10"


def test_the_limiter_failure_policy_is_explicit(redis_cache):
    """Fail-open and fail-closed are both defensible; silence is not."""

    class _Broken:
        def consume_token(self, *_a, **_k):
            raise TransientFailure("redis is unreachable")

    permissive = TokenBucketLimiter(
        cache=_Broken(), limits={"ingest": 600}, fail_open=True
    )
    decision = permissive.check(tenant_id="acme", klass="ingest")
    assert decision.allowed is True
    assert decision.degraded is True, (
        "a request allowed because the limiter was DOWN must be distinguishable "
        "from one allowed because there was budget"
    )

    strict = TokenBucketLimiter(
        cache=_Broken(), limits={"admin": 60}, fail_open=False
    )
    denied = strict.check(tenant_id="acme", klass="admin")
    assert denied.allowed is False
    assert denied.degraded is True


def test_an_unconfigured_route_class_is_refused_not_defaulted(redis_cache):
    """An unlimited class is a decision and must be stated as one."""
    limiter = TokenBucketLimiter(cache=redis_cache, limits={"read": 300}, fail_open=True)
    with pytest.raises(TransientFailure) as caught:
        limiter.check(tenant_id="acme", klass="undeclared")
    assert "no rate limit configured" in str(caught.value)


def test_the_limiter_works_over_the_in_process_cache_too():
    """A single-replica deployment needs no Redis at all."""
    limiter = TokenBucketLimiter(
        cache=InProcessCache(), limits={"ingest": 3}, fail_open=True
    )
    outcomes = [limiter.check(tenant_id="acme", klass="ingest").allowed for _ in range(5)]
    assert outcomes == [True, True, True, False, False]


def test_limits_are_independent_per_tenant_and_per_class(redis_cache):
    limiter = TokenBucketLimiter(
        cache=redis_cache, limits={"ingest": 2, "read": 2}, fail_open=True
    )
    assert limiter.check(tenant_id="a", klass="ingest").allowed
    assert limiter.check(tenant_id="a", klass="ingest").allowed
    assert not limiter.check(tenant_id="a", klass="ingest").allowed
    # A different tenant is unaffected...
    assert limiter.check(tenant_id="b", klass="ingest").allowed
    # ...and so is a different class for the same tenant.
    assert limiter.check(tenant_id="a", klass="read").allowed


# ── Live MinIO / S3-compatible round-trip (CI optional) ─────────────────────


@pytest.fixture
def live_minio_store():
    """S3ObjectStore against MinIO when SENTINEL_TEST_S3_* env vars are set."""
    import os

    endpoint = os.getenv("SENTINEL_TEST_S3_ENDPOINT", "").strip()
    access = os.getenv("SENTINEL_TEST_S3_ACCESS_KEY", "").strip()
    secret = os.getenv("SENTINEL_TEST_S3_SECRET_KEY", "").strip()
    bucket = os.getenv("SENTINEL_TEST_S3_BUCKET", "sentinel-ci").strip()
    if not endpoint or not access or not secret:
        pytest.skip(
            "SENTINEL_TEST_S3_ENDPOINT/ACCESS_KEY/SECRET_KEY unset — "
            "live S3/MinIO round-trip UNVERIFIED in this run"
        )
    from urllib.parse import urlparse

    host = urlparse(endpoint).hostname or "127.0.0.1"
    scheme = urlparse(endpoint).scheme or "http"
    client = HardenedHttpClient(
        policy=OutboundPolicy(
            allowed_schemes=frozenset({scheme, "https"}),
            allow_private_destinations=True,
            allowed_hosts=frozenset({host, "127.0.0.1", "localhost", "minio"}),
            read_timeout_seconds=10.0,
            max_response_bytes=8 * 1024 * 1024,
        )
    )
    return S3ObjectStore(
        bucket=bucket,
        credentials=S3Credentials(access, secret),
        endpoint=endpoint.rstrip("/"),
        client=client,
    )


def test_live_minio_object_store_round_trips(live_minio_store):
    key = _key(tenant="ci", identifier="live-minio-1")
    payload = b"sentinel-minio-ci-payload"
    digest = live_minio_store.put(key, payload)
    assert live_minio_store.get(key) == payload
    import hashlib

    assert digest == hashlib.sha256(payload).hexdigest()
    assert live_minio_store.delete(key) is True
