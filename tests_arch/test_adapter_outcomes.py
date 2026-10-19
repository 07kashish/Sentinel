"""What an HTTP status proves, and what GitHub can be asked afterwards.

Before this, the GitHub and AWS adapters returned a 4xx or 5xx as an ordinary
result, so a refused change was recorded as a SUCCEEDED operation with a
receipt. Now a mutation's 2xx is the effect confirmed, a 4xx is proof it did
not happen, a 5xx is unknown, and a read is never an unknown outcome.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field

import pytest

from sentinel.domain.operations import OperationState
from sentinel.infrastructure.platforms.ceiling import no_effect_possible
from sentinel.infrastructure.platforms.github import GithubCredentials, github_api_adapter
from sentinel.infrastructure.platforms.github_outcome import _blob_sha, github_hint
from sentinel.infrastructure.tool_adapters import (
    ToolAdapterNotAttempted,
    ToolAdapterRefused,
    ToolAdapterRejectedByTarget,
)

PATH = "/repos/acme/infra/contents/flags/prod.json"
OLD = base64.b64encode(b'{"flag": false}').decode()
NEW = base64.b64encode(b'{"flag": true}').decode()


@dataclass
class _Response:
    status: int
    body: bytes
    headers: dict = field(default_factory=dict)
    peer: str = "140.82.121.6:443"


class FakeGithub:
    def __init__(self) -> None:
        self.content: str | None = OLD
        self.status_for_mutation: int | None = None
        self.calls: list[str] = []

    def request(self, *, method, url, headers, body, idempotent):
        self.calls.append(method)
        if method == "GET":
            if self.content is None:
                return _Response(404, b"{}")
            return _Response(200, json.dumps({"sha": _blob_sha(self.content), "content": self.content}).encode())
        if self.status_for_mutation is not None:
            return _Response(self.status_for_mutation, b"{}")
        self.content = json.loads(body)["content"] if method == "PUT" else None
        return _Response(200, b"{}")


def _adapter(fake):
    return github_api_adapter(client=fake, credentials=GithubCredentials(token="t" * 40), ceiling="critical")


def _put():
    return {"method": "PUT", "path": PATH, "body": {"message": "flip", "content": NEW, "sha": _blob_sha(OLD), "branch": "main"}}


@pytest.mark.parametrize("status, expected", [(409, ToolAdapterRejectedByTarget), (422, ToolAdapterRejectedByTarget),
                                              (403, ToolAdapterRejectedByTarget), (502, ToolAdapterRefused)])
def test_a_refused_mutation_is_not_returned_as_a_result(status, expected):
    fake = FakeGithub()
    fake.status_for_mutation = status
    with pytest.raises(expected) as caught:
        _adapter(fake).runner(_put())
    assert (type(caught.value) is ToolAdapterRejectedByTarget) == (status < 500), "a 5xx proves nothing; a 4xx proves absence"


def test_a_read_returns_a_404_as_an_answer_and_a_failed_read_is_a_known_absence():
    fake = FakeGithub()
    fake.content = None
    assert _adapter(fake).runner({"method": "GET", "path": PATH})["status"] == 404

    class Down:
        def request(self, **_):
            from sentinel.infrastructure.outbound import OutboundUnavailable
            raise OutboundUnavailable("connection reset")

    with pytest.raises(ToolAdapterNotAttempted):
        _adapter(Down()).runner({"method": "GET", "path": PATH})


def test_the_hint_holds_digests_and_never_the_file_content():
    hint = github_hint(_put())
    assert hint == {"method": "PUT", "path": PATH, "replaced_sha": _blob_sha(OLD),
                    "expected_blob_sha": _blob_sha(NEW), "ref": "main"}
    assert NEW not in json.dumps(hint)
    assert github_hint({"method": "POST", "path": "/repos/acme/infra/issues", "body": {"title": "x"}}) == {}


@pytest.mark.parametrize("landed, state", [(True, OperationState.SUCCEEDED), (False, OperationState.FAILED)])
def test_a_contents_write_is_settled_from_the_blob_sha(landed, state):
    fake = FakeGithub()
    effect = _adapter(fake)
    if landed:
        fake.content = NEW
    verdict = effect.reconciler("op-1", github_hint(_put()))
    assert verdict.state is state
    assert fake.calls == ["GET"], "reconciliation wrote to GitHub"


def test_other_content_a_post_and_a_non_contents_put_stay_unknown():
    fake = FakeGithub()
    effect = _adapter(fake)
    fake.content = base64.b64encode(b"someone else").decode()
    assert effect.reconciler("op-1", github_hint(_put())).state is OperationState.UNKNOWN_AFTER_EFFECT
    assert effect.reconciler("op-2", {}).state is OperationState.UNKNOWN_AFTER_EFFECT
    other = github_hint({"method": "PUT", "path": "/repos/acme/infra/collaborators/bot", "body": {"permission": "push"}})
    assert effect.reconciler("op-3", other).state is OperationState.UNKNOWN_AFTER_EFFECT


def test_a_delete_is_settled_by_end_state():
    fake = FakeGithub()
    effect = _adapter(fake)
    hint = github_hint({"method": "DELETE", "path": PATH, "body": {"message": "rm", "sha": _blob_sha(OLD)}})
    assert effect.reconciler("op-1", hint).state is OperationState.FAILED
    fake.content = None
    assert effect.reconciler("op-1", hint).state is OperationState.SUCCEEDED


def test_a_read_only_runner_never_leaves_an_unknown_outcome():
    def run(_args):
        raise ToolAdapterRefused("statement timeout")

    with pytest.raises(ToolAdapterNotAttempted):
        no_effect_possible(run)({})


# ── AWS: a role session per operation, attributed by CloudTrail ──────────────


# Key ids are assembled, so no key-shaped literal sits in the tree for a scanner to find.
BROKER_ID = "AKIA" + "BROKERKEYID00000"
TEMPORARY_ID = "ASIA" + "TEMPORARYKEYID00"
ROLE = "arn:aws:iam::123456789012:role/sentinel-executor"
ASSUMED = """<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials>
<AccessKeyId>{TEMPORARY_ID}</AccessKeyId><SecretAccessKey>temporary-secret-value</SecretAccessKey>
<SessionToken>temporary-session-token</SessionToken><Expiration>2026-09-20T12:15:00Z</Expiration>
</Credentials></AssumeRoleResult></AssumeRoleResponse>""".replace("{TEMPORARY_ID}", TEMPORARY_ID)


class FakeAws:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []   # (host, action-or-target, access key id used)
        self.sts_status = 200
        self.events: list[dict] = []

    def request(self, *, method, url, headers, body, idempotent):
        host = url.split("/")[2]
        key_id = headers["authorization"].split("Credential=")[1].split("/")[0]
        label = headers.get("x-amz-target") or dict(p.split("=") for p in body.decode().split("&")).get("Action", "")
        self.calls.append((host, label, key_id))
        if host.startswith("sts."):
            return _Response(self.sts_status, ASSUMED.encode() if self.sts_status == 200 else b"<Error/>")
        if host.startswith("cloudtrail."):
            return _Response(200, json.dumps({"Events": self.events}).encode())
        return _Response(200, b"<ok/>")


def _aws(fake, *, brokered=True):
    from sentinel.infrastructure.platforms.aws import AwsCredentials, aws_api_adapter

    return aws_api_adapter(client=fake, ceiling="critical", credentials=AwsCredentials(
        access_key_id=BROKER_ID, secret_access_key="broker-secret", region="eu-west-1",
        executor_role_arn=ROLE if brokered else ""))


def test_each_aws_operation_runs_under_its_own_role_session_named_after_it():
    from sentinel.application.operation_context import operation_scope, operation_stamp

    fake = FakeAws()
    with operation_scope("op-auth-aws-1"):
        result = _aws(fake).runner({"action": "ec2:StopInstances", "parameters": {"InstanceId.1": "i-0abc"}})
    assert result["credential"]["mode"] == "assume_role"
    assert result["credential"]["session"] == operation_stamp("op-auth-aws-1") and len(result["credential"]["session"]) <= 64
    assert "temporary" not in json.dumps(result) and "broker-secret" not in json.dumps(result)
    hosts = {host: key for host, _, key in fake.calls}
    assert hosts["sts.amazonaws.com"] == BROKER_ID
    assert hosts["ec2.eu-west-1.amazonaws.com"] == TEMPORARY_ID, "the change was signed with the broker key"


def test_a_refused_role_assumption_means_nothing_was_attempted():
    fake = FakeAws()
    fake.sts_status = 403
    with pytest.raises(ToolAdapterNotAttempted):
        _aws(fake).runner({"action": "ec2:StopInstances", "parameters": {"InstanceId.1": "i-0abc"}})
    assert [h for h, _, _ in fake.calls] == ["sts.amazonaws.com"]


@pytest.mark.parametrize("detail, state", [
    ({}, OperationState.SUCCEEDED),
    ({"errorCode": "Client.UnauthorizedOperation"}, OperationState.FAILED),
])
def test_cloudtrail_settles_an_unknown_aws_outcome(detail, state):
    fake = FakeAws()
    effect = _aws(fake)
    fake.events = [{"EventName": "DescribeInstances", "EventId": "e-0", "CloudTrailEvent": "{}"},
                   {"EventName": "StopInstances", "EventId": "e-1", "CloudTrailEvent": json.dumps(detail)}]
    verdict = effect.reconciler("op-auth-aws-1", effect.hint({"action": "ec2:StopInstances"}))
    assert verdict.state is state and "e-1" in verdict.evidence
    assert all(label.endswith("LookupEvents") for _, label, _ in fake.calls), "reconciliation did more than read CloudTrail"


def test_no_cloudtrail_event_is_never_read_as_failure():
    fake = FakeAws()
    effect = _aws(fake)
    verdict = effect.reconciler("op-auth-aws-1", effect.hint({"action": "ec2:StopInstances"}))
    assert verdict.state is OperationState.UNKNOWN_AFTER_EFFECT and "absence is not proof" in verdict.evidence


def test_a_static_aws_key_has_no_reconciler_and_says_so():
    fake = FakeAws()
    effect = _aws(fake, brokered=False)
    assert effect.reconciler is None and effect.hint({"action": "ec2:StopInstances"}) == {}
    assert effect.runner({"action": "ec2:DescribeInstances"})["credential"] == {"mode": "static"}


def test_a_malformed_role_arn_is_refused():
    from sentinel.infrastructure.platforms.aws import AwsCredentials

    with pytest.raises(ToolAdapterRefused):
        AwsCredentials(access_key_id="k", secret_access_key="s", region="eu-west-1", executor_role_arn="sentinel-executor")


# ── GitHub App mode: no standing token ───────────────────────────────────────


def _app_key() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


class FakeGithubApp(FakeGithub):
    def __init__(self) -> None:
        super().__init__()
        self.token_requests: list[dict] = []
        self.bearers: list[tuple[str, str]] = []
        self.grant = 201

    def request(self, *, method, url, headers, body, idempotent):
        bearer = headers["authorization"].removeprefix("Bearer ")
        if url.endswith("/access_tokens"):
            self.token_requests.append({"scope": json.loads(body), "assertion": bearer})
            return _Response(self.grant, json.dumps({"token": "installation-token-value", "expires_at": "2026-09-20T13:00:00Z"}
                                                    if self.grant < 300 else {}).encode())
        self.bearers.append((method, bearer))
        return super().request(method=method, url=url, headers=headers, body=body, idempotent=idempotent)


def _app_adapter(fake):
    return github_api_adapter(client=fake, ceiling="critical", credentials=GithubCredentials(
        app_id="12345", installation_id="67890", app_private_key=_app_key()))


def test_each_github_call_mints_a_token_scoped_to_its_repository_and_permission():
    fake = FakeGithubApp()
    result = _app_adapter(fake).runner(_put())
    assert fake.token_requests[0]["scope"] == {"repositories": ["infra"], "permissions": {"contents": "write"}}
    assert result["credential"]["mode"] == "installation_token" and result["credential"]["repositories"] == ["infra"]
    assert "installation-token-value" not in json.dumps(result)
    assert fake.bearers == [("PUT", "installation-token-value")], "the App assertion was presented to a repository endpoint"
    header, claims, _signature = fake.token_requests[0]["assertion"].split(".")
    decoded = json.loads(base64.urlsafe_b64decode(claims + "=="))
    assert decoded["iss"] == "12345" and 0 < decoded["exp"] - decoded["iat"] <= 600


@pytest.mark.parametrize("method, path, expected", [
    ("GET", "/repos/acme/infra/contents/a.json", {"repositories": ["infra"], "permissions": {"contents": "read"}}),
    ("POST", "/repos/acme/infra/issues", {"repositories": ["infra"], "permissions": {"issues": "write"}}),
    ("PUT", "/repos/acme/infra/branches/main/protection", {"repositories": ["infra"], "permissions": {"administration": "write"}}),
    ("GET", "/repos/acme/infra/unknown-family", {"repositories": ["infra"]}),
    ("GET", "/user", {}),
])
def test_the_scope_is_computed_from_the_call(method, path, expected):
    from sentinel.infrastructure.platforms.github_app import installation_scope

    assert installation_scope(method, path) == expected


def test_a_refused_installation_token_means_nothing_was_attempted():
    fake = FakeGithubApp()
    fake.grant = 403
    with pytest.raises(ToolAdapterNotAttempted):
        _app_adapter(fake).runner(_put())
    assert fake.bearers == []


@pytest.mark.parametrize("kwargs", [
    {"app_id": "12345"}, {"app_id": "abc", "installation_id": "1", "app_private_key": "x"}, {},
])
def test_incomplete_github_credentials_are_refused(kwargs):
    with pytest.raises(ToolAdapterRefused):
        GithubCredentials(**kwargs)


def test_a_non_rsa_or_unreadable_app_key_is_refused():
    from sentinel.infrastructure.platforms.github_app import app_jwt

    with pytest.raises(ToolAdapterRefused):
        app_jwt("12345", "not a key")


def test_a_global_endpoint_is_signed_with_the_global_scope_and_a_regional_one_with_its_region():
    """`sts.amazonaws.com` accepts only a us-east-1 credential scope. Signed
    with the configured region it answers `SignatureDoesNotMatch: Credential
    should be scoped to a valid region` -- which is what the first real
    AssumeRole answered (2026-09-24)."""
    scopes: dict[str, str] = {}

    class _Recording(FakeAws):
        def request(self, *, method, url, headers, body, idempotent):
            host = url.split("/")[2]
            scopes[host] = headers["authorization"].split("Credential=")[1].split(",")[0].split("/")[2]
            return super().request(method=method, url=url, headers=headers, body=body, idempotent=idempotent)

    from sentinel.application.operation_context import operation_scope

    with operation_scope("op-auth-aws-scope"):
        _aws(_Recording()).runner({"action": "ec2:DescribeInstances"})
    assert scopes["sts.amazonaws.com"] == "us-east-1"
    assert scopes["ec2.eu-west-1.amazonaws.com"] == "eu-west-1"
