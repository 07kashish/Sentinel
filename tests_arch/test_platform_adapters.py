"""Tier-1 platform adapters: the confused deputy, and the tier ceiling.

WHAT THIS MODULE IS FOR
-----------------------
`sentinel.infrastructure.platforms` hands an agent the ability to make this
process sign a request to AWS with the deployment's own credentials. Every test
here exists because of one of two failure modes:

  1. THE CONFUSED DEPUTY. The agent describes one operation and causes another.
     Policy judged `iam:ListUsers`; AWS performed `CreateAccessKey`. These tests
     assert there is no input through which the transmitted request can differ
     from the classified one, and no input through which the destination host
     can be chosen by a caller.

  2. THE CEILING THAT WAS NOT CHECKED. `ProtectGate` said ALLOW. That is a
     statement about the request as described. These tests assert the adapter
     re-checks what the request RESOLVED to, and refuses above its ceiling even
     though the gate already allowed it.

The SigV4 test uses the published `aws4_testsuite` `get-vanilla` vector rather
than a value produced by this implementation, because a signing test that signs
with the code under test and compares to what that code produced proves only
that the function is deterministic.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import json

import pytest

from sentinel.infrastructure.outbound import HardenedHttpClient, OutboundPolicy
from sentinel.infrastructure.platforms import (
    AwsCredentials,
    GithubCredentials,
    KubernetesCredentials,
    PostgresCredentials,
    aws_api_adapter,
    build_platform_adapters,
    github_api_adapter,
    kubernetes_api_adapter,
    sql_query_adapter,
)
from sentinel.infrastructure.platforms.aws import sign_request as _aws_sign
from sentinel.infrastructure.tool_adapters import ToolAdapterRefused

AT = _dt.datetime(2015, 8, 30, 12, 36, 0, tzinfo=_dt.timezone.utc)

AWS = AwsCredentials(
    access_key_id="AKIDEXAMPLE",
    secret_access_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    region="us-east-1",
)


class _Recorder:
    """A connection factory that records the request and answers 200 {}."""

    def __init__(self, status: int = 200) -> None:
        self.calls: list[dict] = []
        self.status = status

    def __call__(self, destination):
        recorder = self

        class _Connection:
            def __init__(self) -> None:
                self.destination = destination

            def request(self, method, path, body=None, headers=None):
                recorder.calls.append(
                    {
                        "method": method,
                        "path": path,
                        "host": destination.host,
                        "body": body,
                        "headers": dict(headers or {}),
                    }
                )

            def getresponse(self):
                class _Response:
                    status = recorder.status

                    def getheader(self, *_a, **_kw):
                        return None

                    def getheaders(self):
                        return [("Content-Type", "application/json")]

                    def read(self, _n):
                        return b'{"ok":true}'

                return _Response()

            def close(self):
                pass

        return _Connection()


def _client(recorder: _Recorder, **policy_kwargs) -> HardenedHttpClient:
    return HardenedHttpClient(
        policy=OutboundPolicy(**policy_kwargs), connection_factory=recorder
    )


@pytest.fixture(autouse=True)
def _no_dns(monkeypatch):
    """Resolve every host in this module without asking the network.

    `validate_destination` resolves before it validates -- that ordering is the
    whole DNS-rebinding defence -- so an adapter test reaches a real resolver
    unless one is supplied. These tests were passing on a machine whose DNS
    happened to answer for api.github.com and failing on one whose did not,
    which makes them a test of the network rather than of the adapter.

    The public answer is `93.184.216.34`, the same globally-routable address
    `test_security_outbound.py` uses. TEST-NET-3 (`203.0.113.0/24`) would be the
    tidier choice and does NOT work: Python's `ipaddress` reports it as private,
    so `_classify` refuses it and the test would exercise the SSRF guard instead
    of the adapter. The internal answer is RFC1918, so the Kubernetes tests
    exercise the real `allow_private_destinations` + `allowed_hosts` grant
    rather than bypassing it.
    """
    import socket

    def _resolve(host, port, *_a, **_kw):
        address = "10.0.0.5" if str(host).endswith(".internal") else "93.184.216.34"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]

    monkeypatch.setattr(
        "sentinel.infrastructure.outbound.socket.getaddrinfo", _resolve
    )


# ── SigV4, against the published vector ──────────────────────────────────────


def test_sigv4_matches_the_published_aws_test_vector():
    """`get-vanilla` from `aws4_testsuite`, computed with the module's own
    key-derivation chain. If the HMAC ladder, the credential scope or the
    string-to-sign layout were wrong, this signature would not reproduce.
    """
    secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    stamp, datestamp = "20150830T123600Z", "20150830"
    headers = {"host": "example.amazonaws.com", "x-amz-date": stamp}
    signed = ";".join(sorted(headers))
    canonical_headers = "".join(f"{k}:{headers[k]}\n" for k in sorted(headers))
    canonical = "\n".join(
        ["GET", "/", "", canonical_headers, signed, hashlib.sha256(b"").hexdigest()]
    )
    scope = f"{datestamp}/us-east-1/service/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            stamp,
            scope,
            hashlib.sha256(canonical.encode()).hexdigest(),
        ]
    )

    def _h(key: bytes, message: str) -> bytes:
        return hmac.new(key, message.encode(), hashlib.sha256).digest()

    key = _h(
        _h(_h(_h(f"AWS4{secret}".encode(), datestamp), "us-east-1"), "service"),
        "aws4_request",
    )
    signature = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()

    assert signature == (
        "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    )


def test_the_signed_payload_hash_matches_the_aws_documented_example():
    """The IAM `ListUsers` worked example's payload hash. Pins the body this
    adapter builds for the query protocol to the one AWS documents.
    """
    body = b"Action=ListUsers&Version=2010-05-08"
    assert hashlib.sha256(body).hexdigest() == (
        "b6359072c78d70ebee1e81adcbab4f01bf2c23245fa365ef83fe8f1f955085e2"
    )


def test_the_host_header_participates_in_the_signature_but_is_not_transmitted():
    """`host` is on the hardened client's forbidden-header list, which RAISES
    rather than drops. Leaving it in the returned headers would make every AWS
    call fail at the client; removing it before signing would break the
    signature. It must be signed and then removed, and nothing else notices.
    """
    headers = _aws_sign(
        credentials=AWS,
        service="iam",
        host="iam.amazonaws.com",
        amz_target="",
        payload=b"Action=ListUsers&Version=2010-05-08",
        now=AT,
    )
    assert "host" not in headers
    assert "SignedHeaders=content-type;host;x-amz-date" in headers["authorization"]


# ── AWS: the confused deputy ─────────────────────────────────────────────────


def test_aws_action_drives_both_the_classification_and_the_request():
    recorder = _Recorder()
    adapter = aws_api_adapter(
        client=_client(recorder), credentials=AWS, ceiling="low", clock=lambda: AT
    )
    result = adapter.runner({"action": "iam:ListUsers"})

    assert result["semantics"]["tier"] == "low"
    sent = recorder.calls[0]
    assert sent["host"] == "iam.amazonaws.com"
    assert b"Action=ListUsers" in sent["body"]
    assert b"Version=2010-05-08" in sent["body"]


def test_aws_parameters_may_not_carry_their_own_action():
    """THE confused-deputy case. Declaring a low-tier action and smuggling the
    real one through `parameters` would make policy judge `ListUsers` while AWS
    performed `CreateAccessKey`.
    """
    adapter = aws_api_adapter(
        client=_client(_Recorder()), credentials=AWS, ceiling="critical",
        clock=lambda: AT,
    )
    with pytest.raises(ToolAdapterRefused, match="may not contain 'Action'"):
        adapter.runner(
            {"action": "iam:ListUsers", "parameters": {"Action": "CreateAccessKey"}}
        )


def test_aws_ceiling_refuses_privilege_escalation_the_gate_allowed():
    """`ProtectGate` is not consulted here at all — the adapter is called
    directly, standing in for a gate that returned ALLOW. The refusal is the
    ceiling's, and it is what survives a policy misconfiguration.
    """
    adapter = aws_api_adapter(
        client=_client(_Recorder()), credentials=AWS, ceiling="moderate",
        clock=lambda: AT,
    )
    with pytest.raises(ToolAdapterRefused, match="above this adapter's 'moderate'"):
        adapter.runner({"action": "iam:AttachUserPolicy"})


def test_aws_refuses_a_service_it_cannot_address():
    adapter = aws_api_adapter(
        client=_client(_Recorder()), credentials=AWS, ceiling="critical",
        clock=lambda: AT,
    )
    with pytest.raises(ToolAdapterRefused, match="not addressable"):
        adapter.runner({"action": "s3:GetObject"})


def test_aws_refuses_an_action_it_cannot_classify():
    """Unclassifiable is refused, not defaulted. The ceiling is the only
    containment this adapter has and it cannot be applied to a nameless tier.
    """
    adapter = aws_api_adapter(
        client=_client(_Recorder()), credentials=AWS, ceiling="critical",
        clock=lambda: AT,
    )
    with pytest.raises(ToolAdapterRefused, match="must be 'service:Operation'"):
        adapter.runner({"action": "please just do the thing"})


def test_aws_region_is_validated_because_it_becomes_a_hostname():
    with pytest.raises(ToolAdapterRefused, match="not a valid region"):
        aws_api_adapter(
            client=_client(_Recorder()),
            credentials=AwsCredentials(
                access_key_id="k", secret_access_key="s", region="evil.example.com"
            ),
        )


# ── GitHub ───────────────────────────────────────────────────────────────────


GITHUB = GithubCredentials(token="ghp_example")


def test_github_read_is_allowed_and_the_token_goes_only_to_the_configured_host():
    recorder = _Recorder()
    adapter = github_api_adapter(
        client=_client(recorder), credentials=GITHUB, ceiling="low"
    )
    adapter.runner({"method": "GET", "path": "/repos/acme/widgets"})

    sent = recorder.calls[0]
    assert sent["host"] == "api.github.com"
    assert sent["headers"]["authorization"] == "Bearer ghp_example"


def test_github_path_may_not_carry_a_host():
    """A path that is really a URL would send the token wherever it names."""
    adapter = github_api_adapter(
        client=_client(_Recorder()), credentials=GITHUB, ceiling="critical"
    )
    for path in (
        "https://attacker.example/steal",
        "//attacker.example/steal",
        "/repos/../../attacker",
    ):
        with pytest.raises(ToolAdapterRefused, match="absolute API path"):
            adapter.runner({"method": "GET", "path": path})


def test_github_branch_protection_is_refused_below_critical():
    adapter = github_api_adapter(
        client=_client(_Recorder()), credentials=GITHUB, ceiling="high"
    )
    with pytest.raises(ToolAdapterRefused, match="above this adapter's 'high'"):
        adapter.runner(
            {
                "method": "PUT",
                "path": "/repos/acme/widgets/branches/main/protection",
                "body": {"required_status_checks": None},
            }
        )


def test_github_repository_deletion_is_refused_below_critical():
    adapter = github_api_adapter(
        client=_client(_Recorder()), credentials=GITHUB, ceiling="high"
    )
    with pytest.raises(ToolAdapterRefused, match="above this adapter's 'high'"):
        adapter.runner({"method": "DELETE", "path": "/repos/acme/widgets"})


def test_github_query_cannot_smuggle_a_second_path():
    recorder = _Recorder()
    adapter = github_api_adapter(
        client=_client(recorder), credentials=GITHUB, ceiling="low"
    )
    adapter.runner(
        {"method": "GET", "path": "/repos/acme/widgets", "query": {"x": "/../../admin"}}
    )
    # Percent-encoded into the query string, never joined onto the path.
    assert recorder.calls[0]["path"].startswith("/repos/acme/widgets?")
    assert "/../../admin" not in recorder.calls[0]["path"]


# ── Kubernetes ───────────────────────────────────────────────────────────────


K8S = KubernetesCredentials(api_server="https://cluster.internal:6443", token="tok")


def _k8s_client(recorder: _Recorder) -> HardenedHttpClient:
    # A cluster API server is on a private address. The operator turns that on
    # deliberately and narrows it to one host, which is exactly what a real
    # deployment does.
    return _client(
        recorder,
        allow_private_destinations=True,
        allowed_hosts=frozenset({"cluster.internal"}),
    )


def test_kubernetes_builds_the_path_from_the_fields_it_classified():
    recorder = _Recorder()
    adapter = kubernetes_api_adapter(
        client=_k8s_client(recorder), credentials=K8S, ceiling="low"
    )
    result = adapter.runner({"verb": "list", "kind": "pods", "namespace": "default"})

    assert recorder.calls[0]["path"] == "/api/v1/namespaces/default/pods"
    assert result["semantics"]["tier"] == "low"


def test_kubernetes_exec_is_unreachable():
    """Not "blocked" — absent. `exec` has no entry in the verb table, so there
    is no code path that builds an exec request to refuse.
    """
    adapter = kubernetes_api_adapter(
        client=_k8s_client(_Recorder()), credentials=K8S, ceiling="critical"
    )
    for verb in ("exec", "attach", "port-forward"):
        with pytest.raises(ToolAdapterRefused, match="deliberately absent"):
            adapter.runner({"verb": verb, "kind": "pod", "name": "web", "namespace": "p"})


def test_kubernetes_delete_in_kube_system_is_critical_and_refused_below_it():
    adapter = kubernetes_api_adapter(
        client=_k8s_client(_Recorder()), credentials=K8S, ceiling="high"
    )
    with pytest.raises(ToolAdapterRefused, match="above this adapter's 'high'"):
        adapter.runner(
            {"verb": "delete", "kind": "pod", "name": "etcd", "namespace": "kube-system"}
        )


def test_kubernetes_rbac_writes_are_critical():
    adapter = kubernetes_api_adapter(
        client=_k8s_client(_Recorder()), credentials=K8S, ceiling="high"
    )
    with pytest.raises(ToolAdapterRefused, match="above this adapter's 'high'"):
        adapter.runner(
            {"verb": "create", "kind": "clusterrolebindings", "body": {"kind": "x"}}
        )


def test_kubernetes_namespace_is_required_rather_than_defaulted():
    adapter = kubernetes_api_adapter(
        client=_k8s_client(_Recorder()), credentials=K8S, ceiling="low"
    )
    with pytest.raises(ToolAdapterRefused, match="namespace is required"):
        adapter.runner({"verb": "list", "kind": "pods"})


def test_kubernetes_names_must_be_rfc1123():
    adapter = kubernetes_api_adapter(
        client=_k8s_client(_Recorder()), credentials=K8S, ceiling="low"
    )
    with pytest.raises(ToolAdapterRefused, match="RFC 1123"):
        adapter.runner(
            {"verb": "get", "kind": "pod", "name": "../../secrets", "namespace": "d"}
        )


def test_kubernetes_plural_and_singular_kinds_both_resolve():
    """`networkpolicies` is the case that a naive `rstrip("s")` loses."""
    adapter = kubernetes_api_adapter(
        client=_k8s_client(_Recorder()), credentials=K8S, ceiling="low"
    )
    for spelling in ("networkpolicy", "networkpolicies"):
        with pytest.raises(ToolAdapterRefused) as caught:
            adapter.runner({"verb": "create", "kind": spelling, "namespace": "d"})
        # Refused by the CEILING, which proves the kind resolved. An unresolved
        # kind would have failed earlier with "not addressable".
        assert "above this adapter's" in str(caught.value)


def test_kubernetes_api_server_must_be_https():
    with pytest.raises(ToolAdapterRefused, match="must be https"):
        KubernetesCredentials(api_server="http://cluster.internal:6443", token="t")


@pytest.mark.parametrize("verb,section", [("update", "metadata"), ("delete", "preconditions")])
@pytest.mark.parametrize("missing", ["uid", "resourceVersion"])
def test_kubernetes_existing_object_mutations_require_both_preconditions(verb, section, missing):
    recorder = _Recorder()
    adapter = kubernetes_api_adapter(client=_k8s_client(recorder), credentials=K8S, ceiling="critical")
    fields = {"uid": "fixture-uid", "resourceVersion": "17", "name": "web", "namespace": "pilot"}
    fields.pop(missing)
    with pytest.raises(ToolAdapterRefused, match=missing):
        adapter.runner({"verb": verb, "kind": "configmap", "name": "web", "namespace": "pilot",
                        "body": {section: fields}})
    assert recorder.calls == []


@pytest.mark.parametrize("field,value", [("name", "other"), ("namespace", "other")])
def test_kubernetes_update_body_cannot_substitute_its_target(field, value):
    recorder = _Recorder()
    adapter = kubernetes_api_adapter(client=_k8s_client(recorder), credentials=K8S, ceiling="critical")
    metadata = {"uid": "fixture-uid", "resourceVersion": "17", "name": "web", "namespace": "pilot"}
    metadata[field] = value
    with pytest.raises(ToolAdapterRefused, match="must match"):
        adapter.runner({"verb": "update", "kind": "configmap", "name": "web", "namespace": "pilot",
                        "body": {"metadata": metadata}})
    assert recorder.calls == []


@pytest.mark.parametrize("version", ["0", "000", " 17", "17 ", "", None, 17, True])
def test_kubernetes_cannot_request_an_unconditional_update(version):
    recorder = _Recorder()
    adapter = kubernetes_api_adapter(client=_k8s_client(recorder), credentials=K8S, ceiling="critical")
    with pytest.raises(ToolAdapterRefused):
        adapter.runner({"verb": "update", "kind": "configmap", "name": "web", "namespace": "pilot",
                        "body": {"metadata": {"uid": "fixture-uid", "resourceVersion": version,
                                              "name": "web", "namespace": "pilot"}}})
    assert recorder.calls == []


@pytest.mark.parametrize("verb,section", [("update", "metadata"), ("delete", "preconditions")])
def test_kubernetes_sends_approved_preconditions_without_refresh_or_retry(verb, section):
    recorder = _Recorder(status=409)
    adapter = kubernetes_api_adapter(client=_k8s_client(recorder), credentials=K8S, ceiling="critical")
    fields = {"uid": "fixture-uid", "resourceVersion": "17", "name": "web", "namespace": "pilot"}
    with pytest.raises(ToolAdapterRefused, match="HTTP 409"):
        adapter.runner({"verb": verb, "kind": "configmap", "name": "web", "namespace": "pilot",
                        "body": {section: fields}})
    assert len(recorder.calls) == 1
    assert json.loads(recorder.calls[0]["body"])[section] == fields


# ── PostgreSQL ───────────────────────────────────────────────────────────────


class _FakeCursor:
    def __init__(self, log: list[str]) -> None:
        self._log = log
        self.description = (("id",), ("email",))

    def execute(self, statement, parameters=()):
        self._log.append(statement)

    def fetchmany(self, size):
        return [(1, "a@example.com"), (2, "b@example.com")]

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


class _FakeConnection:
    def __init__(self) -> None:
        self.log: list[str] = []
        self.rolled_back = False

    def cursor(self):
        return _FakeCursor(self.log)

    def rollback(self):
        self.rolled_back = True

    def close(self):
        pass


PG = PostgresCredentials(dsn="postgresql://reader@warehouse/analytics")


def test_sql_select_runs_read_only_with_a_timeout():
    connection = _FakeConnection()
    adapter = sql_query_adapter(
        credentials=PG, ceiling="low", connect=lambda: connection
    )
    result = adapter.runner({"statement": "SELECT id, email FROM customers"})

    assert connection.log[0] == "SET TRANSACTION READ ONLY"
    assert "statement_timeout = 5000" in connection.log[1]
    assert result["columns"] == ["id", "email"]
    assert result["row_count"] == 2
    # Even a successful read is rolled back. Nothing this adapter does commits.
    assert connection.rolled_back is True


def test_sql_multi_statement_is_refused():
    """The classifier reads the first statement; the database would run both."""
    adapter = sql_query_adapter(
        credentials=PG, ceiling="critical", connect=_FakeConnection
    )
    with pytest.raises(ToolAdapterRefused, match="multiple statements"):
        adapter.runner({"statement": "SELECT 1; DROP TABLE customers"})


def test_sql_drop_is_refused_by_the_ceiling():
    adapter = sql_query_adapter(credentials=PG, ceiling="high", connect=_FakeConnection)
    with pytest.raises(ToolAdapterRefused, match="above this adapter's 'high'"):
        adapter.runner({"statement": "DROP TABLE customers"})


def test_sql_parameters_are_bound_not_interpolated():
    connection = _FakeConnection()
    adapter = sql_query_adapter(
        credentials=PG, ceiling="low", connect=lambda: connection
    )
    adapter.runner(
        {"statement": "SELECT id FROM customers WHERE id = %s", "parameters": [7]}
    )
    # The value never appears in the statement text the driver was handed.
    assert "7" not in connection.log[-1]


def test_sql_refuses_a_statement_it_cannot_classify():
    adapter = sql_query_adapter(
        credentials=PG, ceiling="critical", connect=_FakeConnection
    )
    with pytest.raises(ToolAdapterRefused, match="did not classify"):
        adapter.runner({"statement": "VACUUM FULL"})


# ── Composition ──────────────────────────────────────────────────────────────


def test_an_unconfigured_platform_adapter_is_absent_not_disabled():
    """The same rule `build_tool_adapters` follows. Absence is enforced by
    `InlineToolProxy.execute` refusing unregistered tools; a disabled flag is
    one boolean away from being on.
    """
    assert build_platform_adapters() == {}


def test_each_credential_registers_exactly_its_own_adapter():
    adapters = build_platform_adapters(
        aws=AWS,
        github=GITHUB,
        kubernetes=K8S,
        postgres=PG,
    )
    assert sorted(adapters) == ["aws_api", "github_api", "kubernetes_api", "sql_query"]


def test_a_ceiling_nobody_can_read_is_refused_at_build_time():
    with pytest.raises(ToolAdapterRefused, match="not one of"):
        build_platform_adapters(github=GITHUB, github_ceiling="whatever")


def test_the_default_ceiling_is_read_only():
    """A deployment that supplies credentials and forgets the ceiling gets
    read-only, not "everything the credential can do".
    """
    adapters = build_platform_adapters(github=GITHUB)
    with pytest.raises(ToolAdapterRefused, match="above this adapter's 'low'"):
        adapters["github_api"].runner(
            {"method": "POST", "path": "/repos/acme/widgets/issues", "body": {}}
        )


def test_results_are_json_serialisable_for_evidence():
    recorder = _Recorder()
    adapter = github_api_adapter(
        client=_client(recorder), credentials=GITHUB, ceiling="low"
    )
    result = adapter.runner({"method": "GET", "path": "/repos/acme/widgets"})
    # Every adapter result lands in an incident's evidence. One that cannot be
    # serialised is one that silently drops out of the audit trail.
    json.dumps(result)
    assert result["platform"] == "github"
    assert result["semantics"]["platform"] == "github"
