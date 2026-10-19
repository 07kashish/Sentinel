"""COMPLIANCE mode is the whole point, and GOVERNANCE mode is the trap.

Object Lock in compliance mode puts a root beyond the operator's reach --
nobody can delete it before its retention date, including the account root.
That is the only reason to involve S3 at all.

Governance mode looks identical in the console and can be bypassed by a
principal holding `s3:BypassGovernanceRetention`. A root written that way is
still the operator's to remove, so `is_independently_verifiable` would report
a guarantee that does not exist.

The transport is injected throughout: these tests exercise the real SigV4
signing, header construction and response interpretation without touching AWS.
No test here spends money or needs a credential.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from sentinel.domain.root_sink import RootSink, RootSinkUnavailable
from sentinel.infrastructure.outbound import OutboundRefused, OutboundUnavailable
from sentinel.infrastructure.s3_root_sink import (
    COMPLIANCE_MODE,
    S3ObjectLockRootSink,
    S3SinkConfig,
    estimated_annual_cost_usd,
)

SECRET = "wJalrXUtnFEMI-K7MDENG-bPxRfiCYEXAMPLEKEY"
FIXED = datetime(2026, 9, 3, 12, 0, 0, tzinfo=timezone.utc)


def _config(**kwargs) -> S3SinkConfig:
    defaults = dict(
        bucket="acme-transparency",
        region="eu-west-2",
        access_key_id="AKIAIOSFODNN7EXAMPLE",
        secret_access_key=SECRET,
    )
    defaults.update(kwargs)
    return S3SinkConfig(**defaults)  # type: ignore[arg-type]


class _Response:
    def __init__(self, status: int = 200, headers: dict | None = None):
        self.status = status
        self.headers = headers if headers is not None else {"x-amz-version-id": "v1"}
        self.body = b""

    def json(self):
        return {}


class _Transport:
    def __init__(self, response=None, error=None, recorder=None):
        self._response = response or _Response()
        self._error = error
        self._recorder = recorder

    def request(self, *, method, url, headers=None, body=None, idempotent=False):
        if self._recorder is not None:
            self._recorder.update(
                {
                    "method": method,
                    "url": url,
                    "headers": dict(headers or {}),
                    "body": body,
                }
            )
        if self._error is not None:
            raise self._error
        return self._response


def _sink(**kwargs) -> S3ObjectLockRootSink:
    recorder = kwargs.pop("recorder", None)
    response = kwargs.pop("response", None)
    error = kwargs.pop("error", None)
    return S3ObjectLockRootSink(
        config=_config(**kwargs),
        transport=_Transport(response=response, error=error, recorder=recorder),
        now=lambda: FIXED,
    )


def _publish(sink):
    return sink.publish(tenant_id="acme", tree_size=42, root_hash="a" * 64)


# ── compliance mode, which is the only reason to do this ────────────────────


def test_the_object_is_written_in_compliance_mode():
    """GOVERNANCE looks the same and can be bypassed by a principal holding
    s3:BypassGovernanceRetention -- so a root written that way is still the
    operator's to remove.
    """
    seen: dict = {}
    _publish(_sink(recorder=seen))

    assert seen["headers"]["x-amz-object-lock-mode"] == COMPLIANCE_MODE


def test_a_retention_date_is_sent_and_is_in_the_future():
    seen: dict = {}
    _publish(_sink(recorder=seen, retention_days=3650))

    retain = seen["headers"]["x-amz-object-lock-retain-until-date"]
    assert retain.startswith("2036-"), retain


def test_a_retention_shorter_than_a_day_is_refused():
    """Not a retention guarantee. An auditor checking a root from last year
    needs it still locked.
    """
    with pytest.raises(ValueError) as raised:
        _config(retention_days=0)

    assert "not a retention guarantee" in str(raised.value)


def test_the_module_names_governance_mode_as_the_trap():
    import inspect

    from sentinel.infrastructure import s3_root_sink

    doc = " ".join((inspect.getdoc(s3_root_sink) or "").split())

    assert "GOVERNANCE mode is the trap" in doc
    assert "BypassGovernanceRetention" in doc


# ── a receipt is never manufactured ─────────────────────────────────────────


def test_a_successful_put_returns_a_fetchable_reference():
    """Bucket, key AND version. A key alone names a mutable pointer; the
    version is what is actually locked.
    """
    receipt = _publish(_sink(response=_Response(headers={"x-amz-version-id": "abc"})))

    assert receipt.sink == "s3-object-lock"
    assert "acme-transparency" in receipt.reference
    assert "versionId=abc" in receipt.reference


def test_a_put_with_no_version_id_is_refused():
    """Object Lock REQUIRES versioning, so a locked write always returns a
    version id. Its absence means the object is not locked -- and a receipt
    would claim a guarantee that does not exist.
    """
    with pytest.raises(RootSinkUnavailable) as raised:
        _publish(_sink(response=_Response(headers={})))

    message = str(raised.value)
    assert "NOT locked" in message
    assert "Refusing to record it as published" in message


def test_a_version_id_header_is_read_case_insensitively():
    """S3 has returned both spellings. A case-sensitive lookup would
    intermittently conclude the object was unlocked and refuse a publication
    that had in fact succeeded.
    """
    receipt = _publish(_sink(response=_Response(headers={"X-Amz-Version-Id": "Xyz"})))

    assert "versionId=Xyz" in receipt.reference


@pytest.mark.parametrize("status", [301, 400, 403, 500, 503])
def test_any_non_success_status_refuses(status):
    with pytest.raises(RootSinkUnavailable) as raised:
        _publish(_sink(response=_Response(status=status)))

    assert "NOT published" in str(raised.value)


def test_a_400_explains_that_object_lock_cannot_be_added_later():
    """The single most likely setup mistake, and the one whose fix is "make a
    new bucket" rather than "change a setting".
    """
    with pytest.raises(RootSinkUnavailable) as raised:
        _publish(_sink(response=_Response(status=400)))

    message = str(raised.value)
    assert "CANNOT be enabled after creation" in message


def test_a_403_names_the_permission_people_forget():
    """s3:PutObjectRetention is needed IN ADDITION to s3:PutObject, and a
    policy with only the latter fails with a 403 that reads like a bucket
    problem.
    """
    with pytest.raises(RootSinkUnavailable) as raised:
        _publish(_sink(response=_Response(status=403)))

    assert "s3:PutObjectRetention" in str(raised.value)


def test_a_transport_failure_refuses_rather_than_retrying_silently():
    with pytest.raises(RootSinkUnavailable) as raised:
        _publish(_sink(error=OutboundUnavailable("dns failure")))

    message = str(raised.value)
    assert "NOT published" in message
    assert "rather than a retryable success" in message


def test_a_refused_destination_refuses():
    with pytest.raises(RootSinkUnavailable):
        _publish(_sink(error=OutboundRefused("blocked")))


# ── the credential never leaves the signature ───────────────────────────────


def test_the_secret_key_is_never_in_the_url_or_the_headers():
    seen: dict = {}
    _publish(_sink(recorder=seen))

    assert SECRET not in seen["url"]
    for value in seen["headers"].values():
        assert SECRET not in str(value)


def test_the_secret_key_is_stripped_from_error_messages():
    """An exception message reaches logs, error trackers and support tickets."""
    with pytest.raises(RootSinkUnavailable) as raised:
        _publish(_sink(error=OutboundUnavailable(f"boom {SECRET}")))

    assert SECRET not in str(raised.value)
    assert "[redacted]" in str(raised.value)


def test_the_config_does_not_repr_its_secret():
    """A config logged at startup must not print the key."""
    text = repr(_config())

    assert SECRET not in text


def test_incomplete_credentials_are_refused_before_a_request():
    """An unsigned PUT fails with a 403 that reads like a permissions problem
    rather than a missing credential.
    """
    with pytest.raises(ValueError) as raised:
        _config(secret_access_key="")

    assert "Refusing to attempt an unsigned PUT" in str(raised.value)


# ── the request itself ───────────────────────────────────────────────────────


def test_the_request_is_a_signed_https_put():
    seen: dict = {}
    _publish(_sink(recorder=seen))

    assert seen["method"] == "PUT"
    assert seen["url"].startswith("https://")
    assert seen["headers"]["authorization"].startswith("AWS4-HMAC-SHA256 ")


def test_the_signature_is_deterministic_for_a_fixed_clock():
    """So a signing regression is a diff rather than an intermittent 403."""
    first: dict = {}
    second: dict = {}
    _publish(_sink(recorder=first))
    _publish(_sink(recorder=second))

    assert first["headers"]["authorization"] == second["headers"]["authorization"]


def test_the_payload_hash_matches_the_body_actually_sent():
    """A signature over a different body than the one sent is a 403 that looks
    like a credential problem.
    """
    import hashlib

    seen: dict = {}
    _publish(_sink(recorder=seen))

    assert seen["headers"]["x-amz-content-sha256"] == hashlib.sha256(
        seen["body"]
    ).hexdigest()


def test_a_session_token_is_sent_when_configured():
    """A role is preferable to a long-lived user, so the token path must work."""
    seen: dict = {}
    _publish(_sink(recorder=seen, session_token="tok123"))

    assert seen["headers"]["x-amz-security-token"] == "tok123"


def test_the_body_records_the_root_and_says_what_the_lock_means():
    """An auditor who fetches this object and nothing else must be able to
    tell what it is and what protects it.
    """
    import json

    seen: dict = {}
    _publish(_sink(recorder=seen))
    document = json.loads(seen["body"])

    assert document["root"] == "a" * 64
    assert document["tree_size"] == 42
    assert document["tenant"] == "acme"
    assert "COMPLIANCE" in document["note"]
    assert "without asking the operator" in document["note"]


# ── cost, which is why this is publishable at all ───────────────────────────


def test_one_key_per_tree_size_so_a_retry_adds_no_version():
    """Versions cost storage and a retry after a transient failure is
    ordinary.
    """
    config = _config()
    first = config.key_for(tenant_id="acme", tree_size=42)
    again = config.key_for(tenant_id="acme", tree_size=42)
    later = config.key_for(tenant_id="acme", tree_size=43)

    assert first == again
    assert first != later


def test_the_tenant_is_escaped_in_the_key():
    """A tenant id with a slash would otherwise write outside its prefix."""
    key = _config().key_for(tenant_id="a/../b", tree_size=1)

    assert "/../" not in key


def test_daily_publication_costs_under_a_cent_a_year():
    """The number an operator should see before enabling this, not after a
    bill.
    """
    assert estimated_annual_cost_usd(publications_per_day=1) < 0.01


def test_per_event_publication_is_visibly_more_expensive():
    """And buys nothing: a later root already proves every earlier one via a
    consistency proof. The function exists so that trade-off is a number
    rather than an argument.
    """
    daily = estimated_annual_cost_usd(publications_per_day=1)
    per_event = estimated_annual_cost_usd(publications_per_day=8640)

    assert per_event > daily * 1000


def test_a_zero_publication_rate_is_refused():
    """A sink that never publishes leaves every root unverifiable, which is
    the state RefusingRootSink already represents honestly.
    """
    with pytest.raises(ValueError) as raised:
        estimated_annual_cost_usd(publications_per_day=0)

    assert "never publishes" in str(raised.value)


def test_the_module_explains_why_glacier_would_cost_more():
    """A 40 KB minimum billable size against a 200-byte object. Cheap-sounding
    storage classes are a trap at this size, and somebody will suggest one.
    """
    import inspect

    from sentinel.infrastructure import s3_root_sink

    doc = " ".join((inspect.getdoc(s3_root_sink) or "").split())

    assert "Not Glacier" in doc
    assert "40 KB minimum" in doc


def test_the_sink_never_lists_the_bucket():
    """ListObjects is the call that costs real money as a bucket grows, and
    this sink has no reason to make it.
    """
    import ast
    import inspect

    from sentinel.infrastructure import s3_root_sink

    # Docstrings STRIPPED before searching. The module docstring explains why
    # it never lists, so a plain text search matches the explanation -- a test
    # that cannot tell code from prose about the code. Same mistake I made in
    # the SDK test, so it gets the same fix.
    tree = ast.parse(inspect.getsource(s3_root_sink))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)):
            body = getattr(node, "body", [])
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                body.pop(0)

    code = ast.unparse(tree)
    for forbidden in ("list-type", "ListObjects", "?list"):
        assert forbidden not in code, f"{forbidden} appears in executable code"


# ── shape ────────────────────────────────────────────────────────────────────


def test_the_sink_satisfies_the_root_sink_protocol():
    """So it is substitutable for RefusingRootSink without a caller branching
    on which one it holds.
    """
    assert isinstance(_sink(), RootSink)


def test_the_sink_uses_the_hardened_client_by_default():
    """Not urllib. The rule forbidding it documents a proven token leak: a 302
    forwarded an Authorization header, and an AWS signature is one.
    """
    from sentinel.infrastructure.outbound import HardenedHttpClient

    real = S3ObjectLockRootSink(config=_config())

    assert isinstance(real._client(), HardenedHttpClient)


def test_the_default_policy_pins_the_bucket_host():
    """So a DNS answer pointing elsewhere is refused rather than signed for."""
    policy = S3ObjectLockRootSink(config=_config())._client().policy

    assert policy.allowed_schemes == frozenset({"https"})
    assert "acme-transparency.s3.eu-west-2.amazonaws.com" in policy.allowed_hosts


def test_an_empty_bucket_or_region_is_refused():
    with pytest.raises(ValueError):
        _config(bucket="  ")
    with pytest.raises(ValueError):
        _config(region="")


def test_the_module_holds_no_mutable_state():
    import types

    from sentinel.infrastructure import s3_root_sink

    mutable = [
        name
        for name, value in vars(s3_root_sink).items()
        if not name.startswith("__")
        and isinstance(value, (dict, list, set))
        and not isinstance(value, (frozenset, types.MappingProxyType))
    ]
    assert not mutable, f"module-level mutable state: {mutable}"


# ── Task-role credentials through the container endpoint (Fargate, 2026-09-25) ──


class _Source:
    def __init__(self, key="ASIA" + "TASKROLEKEY00000", secret="task-secret-value-xyz", token="task-session-token"):
        from sentinel.infrastructure.aws_container_credentials import AwsCredential

        self.credential = AwsCredential(access_key_id=key, secret_access_key=secret, session_token=token)
        self.calls = 0

    def current(self):
        self.calls += 1
        return self.credential


def test_a_config_with_a_credential_source_needs_no_static_key():
    config = _config(access_key_id="", secret_access_key="", credentials=_Source())
    assert config.resolved()[0].startswith("ASIA")


def test_the_put_is_signed_with_the_sources_key_and_carries_its_token():
    recorder: dict = {}
    source = _Source()
    sink = S3ObjectLockRootSink(config=_config(access_key_id="", secret_access_key="", credentials=source),
                                transport=_Transport(recorder=recorder), now=lambda: FIXED)
    _publish(sink)
    assert "Credential=ASIA" in recorder["headers"]["authorization"]
    assert recorder["headers"]["x-amz-security-token"] == "task-session-token"
    assert source.calls == 1


def test_a_source_that_fails_makes_the_sink_unavailable_not_a_crash():
    class _Broken:
        def current(self):
            raise RuntimeError("endpoint unreachable")

    sink = S3ObjectLockRootSink(config=_config(access_key_id="", secret_access_key="", credentials=_Broken()),
                                transport=_Transport(), now=lambda: FIXED)
    with pytest.raises(RootSinkUnavailable, match="no credential"):
        _publish(sink)


def _endpoint(document: dict, status: int = 200):
    """A fake http.client connection factory answering the credential document."""
    import json as _json

    seen: dict = {}

    class _Conn:
        def __init__(self, host, port, timeout=None):
            seen.update(host=host, port=port, timeout=timeout)

        def request(self, method, path, headers=None):
            seen.update(method=method, path=path, headers=dict(headers or {}))

        def getresponse(self):
            class R:
                pass
            r = R()
            r.status = status
            r.read = lambda n=-1: _json.dumps(document).encode()
            return r

        def close(self):
            seen["closed"] = True

    return _Conn, seen


def test_the_container_endpoint_is_fetched_once_and_cached_until_near_expiry():
    from sentinel.infrastructure.aws_container_credentials import ContainerCredentialSource

    factory, seen = _endpoint({"AccessKeyId": "ASIA" + "CACHEDKEY0000000", "SecretAccessKey": "s", "Token": "t",
                               "Expiration": "2026-09-25T02:00:00Z"})
    clock = [datetime(2026, 9, 25, 1, 0, tzinfo=timezone.utc)]
    source = ContainerCredentialSource("http://169.254.170.2/v2/credentials/abc", authorization="Basic x",
                                       connection_factory=factory, now=lambda: clock[0])
    first = source.current()
    again = source.current()
    assert first is again and seen["host"] == "169.254.170.2" and seen["path"] == "/v2/credentials/abc"
    assert seen["headers"]["authorization"] == "Basic x" and seen["closed"] is True
    clock[0] = datetime(2026, 9, 25, 1, 57, tzinfo=timezone.utc)   # inside the refresh window
    assert source.current() is not first


@pytest.mark.parametrize("uri", ["http://169.254.169.254/latest/meta-data/", "http://metadata.internal/creds",
                                 "https://169.254.170.2/creds", "http://10.0.0.5/creds", "http://169.254.170.2"])
def test_only_the_documented_credential_hosts_are_dialled(uri):
    from sentinel.infrastructure.aws_container_credentials import ContainerCredentialSource, ContainerCredentialsUnavailable

    with pytest.raises(ContainerCredentialsUnavailable):
        ContainerCredentialSource(uri)


def test_an_incomplete_or_failed_document_is_refused():
    from sentinel.infrastructure.aws_container_credentials import ContainerCredentialSource, ContainerCredentialsUnavailable

    for document, status in (({"AccessKeyId": "x"}, 200), ({"AccessKeyId": "x", "SecretAccessKey": "y", "Token": "z"}, 500)):
        factory, _ = _endpoint(document, status)
        with pytest.raises(ContainerCredentialsUnavailable):
            ContainerCredentialSource("http://169.254.170.2/v2/creds", connection_factory=factory).current()


def test_settings_build_the_endpoint_from_the_agents_relative_uri():
    from sentinel.composition.settings_parsers import root_sink_settings

    from sentinel.composition.root_sink_wiring import build_root_sink
    from sentinel.composition.settings import Settings
    from sentinel.domain.root_sink import RefusingRootSink

    base = {"SENTINEL_S3_ROOT_BUCKET": "b", "SENTINEL_S3_ROOT_REGION": "ap-south-1"}
    no_credential = build_root_sink(Settings.from_environment({"SENTINEL_ENV": "development", **base}))
    assert isinstance(no_credential, RefusingRootSink)
    with pytest.raises(RootSinkUnavailable, match="no credential"):
        no_credential.publish(tenant_id="acme", tree_size=1, root_hash="a" * 64)
    task_role = build_root_sink(Settings.from_environment({"SENTINEL_ENV": "development", **base,
                                                          "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/credentials/id"}))
    assert isinstance(task_role, S3ObjectLockRootSink) and task_role.config.credentials is not None
    parsed = root_sink_settings({**base, "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/credentials/id"})
    assert parsed.container_credentials_uri == "http://169.254.170.2/v2/credentials/id"
    parsed = root_sink_settings({**base, "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/x",
                                 "AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://127.0.0.1:8080/creds"})
    assert parsed.container_credentials_uri == "http://127.0.0.1:8080/creds"
