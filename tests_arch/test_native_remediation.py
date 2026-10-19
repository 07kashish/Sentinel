"""Native containment: the request Sentinel actually sends to contain something.

WHY THIS MODULE IS SEPARATE FROM `test_remediation_execution.py`
------------------------------------------------------------------
That module proves `GuardedRemediationExecutor` adds the six properties around
whatever integrations it is given. It has always passed with integrations that
POST a JSON blob to a webhook, because the executor does not care what the
integration does.

These tests care. They assert the WIRE: that `quarantine_workload` sends a
NetworkPolicy that denies egress as well as ingress, that its podSelector is
never empty, that `release_workload` cannot be aimed at an operator's own
policy, and that `revoke_cloud_session` sends the AWS-documented mechanism
rather than something that merely sounds like it.

A containment that sends the wrong body still returns 201 and still produces a
receipt saying `executed: true`. That is the failure this module exists to
catch, and no test of the executor can catch it.
"""

from __future__ import annotations

import datetime as _dt
import json

import pytest

from sentinel.domain.errors import DomainRuleViolated, TransientFailure
from sentinel.domain.primitives import IdempotencyKey
from sentinel.infrastructure.outbound import HardenedHttpClient, OutboundPolicy
from sentinel.infrastructure.platforms.aws import AwsCredentials
from sentinel.infrastructure.platforms.kubernetes import KubernetesCredentials
from sentinel.infrastructure.platforms.remediation import (
    NATIVE_REMEDIATION_ACTIONS,
    AwsSessionRevocation,
    KubernetesPodTermination,
    KubernetesQuarantine,
    KubernetesQuarantineRelease,
    RemediationTargetInvalid,
    build_native_integrations,
)

K8S = KubernetesCredentials(api_server="https://cluster.internal:6443", token="tok")
AWS = AwsCredentials(
    access_key_id="AKIDEXAMPLE",
    secret_access_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    region="us-east-1",
)
KEY = IdempotencyKey("idem-abc")
AT = _dt.datetime(2026, 8, 30, 12, 0, 0, tzinfo=_dt.timezone.utc)


class _Recorder:
    def __init__(self, status: int = 200) -> None:
        self.status = status
        self.calls: list[dict] = []

    def __call__(self, destination):
        recorder = self

        class _Connection:
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
                        return b"{}"

                return _Response()

            def close(self):
                pass

        return _Connection()


@pytest.fixture(autouse=True)
def _no_dns(monkeypatch):
    """Resolve without the network. `.internal` is RFC1918 so the cluster tests
    exercise the real private-destination grant rather than bypassing it.
    """
    import socket

    def _resolve(host, port, *_a, **_kw):
        address = "10.0.0.5" if str(host).endswith(".internal") else "93.184.216.34"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]

    monkeypatch.setattr("sentinel.infrastructure.outbound.socket.getaddrinfo", _resolve)


def _k8s_client(recorder: _Recorder) -> HardenedHttpClient:
    return HardenedHttpClient(
        policy=OutboundPolicy(
            allow_private_destinations=True,
            allowed_hosts=frozenset({"cluster.internal"}),
        ),
        connection_factory=recorder,
    )


def _aws_client(recorder: _Recorder) -> HardenedHttpClient:
    return HardenedHttpClient(connection_factory=recorder)


# ── kill_container ───────────────────────────────────────────────────────────


def test_kill_container_deletes_exactly_that_pod():
    recorder = _Recorder()
    KubernetesPodTermination(
        client=_k8s_client(recorder), credentials=K8S
    ).execute(target="prod/checkout-7d9", idempotency_key=KEY)

    sent = recorder.calls[0]
    assert sent["method"] == "DELETE"
    assert sent["path"] == "/api/v1/namespaces/prod/pods/checkout-7d9"


def test_a_target_that_is_not_namespace_slash_name_is_refused():
    """The target arrives from a proposal built out of incident facts. One that
    does not parse is refused rather than interpolated into a URL.
    """
    integration = KubernetesPodTermination(
        client=_k8s_client(_Recorder()), credentials=K8S
    )
    for target in ("checkout-7d9", "prod/", "/checkout", "prod/../../secrets"):
        with pytest.raises(RemediationTargetInvalid):
            integration.execute(target=target, idempotency_key=KEY)


def test_an_object_that_is_already_gone_is_success_not_failure():
    """404 is the state the action was trying to reach. Treating it as a failure
    would make containment non-idempotent under the at-least-once redelivery the
    executor permits, and burn the approval's retry budget on a pod that is
    already dead.
    """
    receipt = KubernetesPodTermination(
        client=_k8s_client(_Recorder(status=404)), credentials=K8S
    ).execute(target="prod/gone", idempotency_key=KEY)
    assert receipt["already_absent"] is True


def test_a_5xx_is_retryable_and_a_4xx_is_not():
    """Same split `HttpRemediationIntegration` uses, because the executor reads
    those two cases and a second set of rules for one decision is a bug.
    """
    with pytest.raises(TransientFailure):
        KubernetesPodTermination(
            client=_k8s_client(_Recorder(status=503)), credentials=K8S
        ).execute(target="prod/web", idempotency_key=KEY)

    with pytest.raises(DomainRuleViolated):
        KubernetesPodTermination(
            client=_k8s_client(_Recorder(status=403)), credentials=K8S
        ).execute(target="prod/web", idempotency_key=KEY)


# ── quarantine_workload ──────────────────────────────────────────────────────


def _quarantine_body(recorder: _Recorder) -> dict:
    return json.loads(recorder.calls[0]["body"])


def test_quarantine_denies_egress_as_well_as_ingress():
    """THE test. Denying only ingress leaves the exfiltration path open, and
    exfiltration is the thing being contained -- a quarantine that stops the
    attacker reaching in while letting the data flow out is worse than none,
    because it reports success.
    """
    recorder = _Recorder(status=201)
    KubernetesQuarantine(client=_k8s_client(recorder), credentials=K8S).execute(
        target="prod/finance-agent", idempotency_key=KEY
    )
    spec = _quarantine_body(recorder)["spec"]
    assert sorted(spec["policyTypes"]) == ["Egress", "Ingress"]


def test_quarantine_has_no_rule_lists_at_all():
    """An empty rule LIST denies everything; an empty rule OBJECT allows
    everything. One character apart, and the inverse of the intended meaning.
    """
    recorder = _Recorder(status=201)
    KubernetesQuarantine(client=_k8s_client(recorder), credentials=K8S).execute(
        target="prod/finance-agent", idempotency_key=KEY
    )
    spec = _quarantine_body(recorder)["spec"]
    assert "ingress" not in spec and "egress" not in spec


def test_the_pod_selector_is_never_empty():
    """An empty podSelector quarantines the WHOLE NAMESPACE. The catalogue rates
    `quarantine_workload` blast radius SINGLE, and a selector that defaulted to
    empty would make that declaration a lie -- which `decide_response` reads.
    """
    recorder = _Recorder(status=201)
    KubernetesQuarantine(client=_k8s_client(recorder), credentials=K8S).execute(
        target="prod/finance-agent", idempotency_key=KEY
    )
    selector = _quarantine_body(recorder)["spec"]["podSelector"]
    assert selector["matchLabels"] == {"app": "finance-agent"}


def test_the_policy_records_the_approval_it_came_from():
    recorder = _Recorder(status=201)
    KubernetesQuarantine(client=_k8s_client(recorder), credentials=K8S).execute(
        target="prod/finance-agent", idempotency_key=KEY
    )
    metadata = _quarantine_body(recorder)["metadata"]
    assert metadata["annotations"]["sentinel.io/idempotency-key"] == "idem-abc"
    assert metadata["labels"]["app.kubernetes.io/managed-by"] == "sentinel"


def test_release_can_only_delete_sentinels_own_policy():
    """The prefix is added here and is not part of the input, so a target naming
    an operator's own NetworkPolicy cannot reach it.
    """
    recorder = _Recorder()
    KubernetesQuarantineRelease(
        client=_k8s_client(recorder), credentials=K8S
    ).execute(target="prod/finance-agent", idempotency_key=KEY)

    assert recorder.calls[0]["path"].endswith(
        "/networkpolicies/sentinel-quarantine-finance-agent"
    )
    assert recorder.calls[0]["method"] == "DELETE"


def test_quarantine_and_release_agree_on_the_policy_name():
    """They are each other's rollback. A name computed differently in the two
    would leave every quarantine permanently un-releasable.
    """
    applied, released = _Recorder(status=201), _Recorder()
    KubernetesQuarantine(client=_k8s_client(applied), credentials=K8S).execute(
        target="prod/svc", idempotency_key=KEY
    )
    KubernetesQuarantineRelease(
        client=_k8s_client(released), credentials=K8S
    ).execute(target="prod/svc", idempotency_key=KEY)

    created = json.loads(applied.calls[0]["body"])["metadata"]["name"]
    assert released.calls[0]["path"].endswith(f"/networkpolicies/{created}")


# ── revoke_cloud_session ─────────────────────────────────────────────────────


def _revocation_policy(recorder: _Recorder) -> dict:
    import urllib.parse

    fields = urllib.parse.parse_qs(recorder.calls[0]["body"].decode("utf-8"))
    return json.loads(fields["PolicyDocument"][0])


def test_revoke_cloud_session_sends_the_documented_aws_mechanism():
    """Revoking an STS session is not an API call -- the credential is valid
    until it expires. The mechanism is an inline policy denying everything issued
    before a cutoff, and anything else would be a plausible-looking no-op.
    """
    recorder = _Recorder()
    AwsSessionRevocation(
        client=_aws_client(recorder), credentials=AWS, clock=lambda: AT
    ).execute(target="finance-agent", idempotency_key=KEY)

    statement = _revocation_policy(recorder)["Statement"][0]
    assert statement["Effect"] == "Deny"
    assert statement["Condition"]["DateLessThan"]["aws:TokenIssueTime"] == (
        "2026-08-30T12:00:00Z"
    )


def test_the_revocation_is_signed_and_goes_to_iam():
    recorder = _Recorder()
    AwsSessionRevocation(
        client=_aws_client(recorder), credentials=AWS, clock=lambda: AT
    ).execute(target="finance-agent", idempotency_key=KEY)

    sent = recorder.calls[0]
    assert sent["host"] == "iam.amazonaws.com"
    assert sent["headers"]["authorization"].startswith("AWS4-HMAC-SHA256 ")
    assert b"Action=PutUserPolicy" in sent["body"]


def test_an_iam_user_name_is_validated_before_it_is_signed():
    integration = AwsSessionRevocation(
        client=_aws_client(_Recorder()), credentials=AWS, clock=lambda: AT
    )
    with pytest.raises(RemediationTargetInvalid, match="valid IAM user name"):
        integration.execute(target="finance agent/../root", idempotency_key=KEY)


# ── composition ──────────────────────────────────────────────────────────────


def test_no_credentials_means_no_native_integrations():
    assert build_native_integrations(client=_aws_client(_Recorder())) == {}


def test_every_declared_native_action_is_actually_built():
    """`NATIVE_REMEDIATION_ACTIONS` is what the docs and tests read. An action
    listed there but not constructed would be a claim with nothing behind it.
    """
    built = build_native_integrations(
        client=_aws_client(_Recorder()), kubernetes=K8S, aws=AWS
    )
    assert sorted(built) == sorted(NATIVE_REMEDIATION_ACTIONS)


def test_every_native_action_exists_in_the_remediation_catalogue():
    """A native integration registered under a name no proposal can produce is
    unreachable, and the deployment would look armed while being unable to act.
    """
    from sentinel.domain.remediation import action_named

    for action in NATIVE_REMEDIATION_ACTIONS:
        assert action_named(action) is not None


def test_kubernetes_credentials_alone_do_not_build_the_aws_action():
    built = build_native_integrations(client=_aws_client(_Recorder()), kubernetes=K8S)
    assert "revoke_cloud_session" not in built
    assert "kill_container" in built


# ── the executor seam ────────────────────────────────────────────────────────


def test_native_integrations_alone_produce_a_real_executor():
    """Before this, a deployment with no webhook endpoints got
    `NullRemediationExecutor` -- which refuses everything -- even when it had
    handed Sentinel a cluster credential.
    """
    from sentinel.infrastructure.remediation import build_remediation_executor

    executor = build_remediation_executor(
        endpoints={},
        client=_aws_client(_Recorder()),
        audit=None,
        clock=lambda: AT,
        native=build_native_integrations(
            client=_k8s_client(_Recorder()), kubernetes=K8S
        ),
    )
    assert executor.supports("kill_container") is True


def test_nothing_configured_still_produces_the_null_executor():
    """The absence rule is unchanged: no endpoints and no native credentials is
    still a deployment that must refuse with a reason rather than pretend.
    """
    from sentinel.infrastructure.remediation import build_remediation_executor

    executor = build_remediation_executor(
        endpoints={},
        client=_aws_client(_Recorder()),
        audit=None,
        clock=lambda: AT,
        native={},
    )
    assert executor.supports("kill_container") is False


def test_an_explicit_endpoint_wins_over_the_native_integration():
    """An operator who configured a webhook for `kill_container` did so on
    purpose -- their cluster may need an approval workflow this process knows
    nothing about. Silently preferring the native path would override that.
    """
    from sentinel.infrastructure.remediation import (
        HttpRemediationIntegration,
        build_remediation_executor,
    )

    executor = build_remediation_executor(
        endpoints={"kill_container": "https://runbook.example/kill"},
        client=_aws_client(_Recorder()),
        audit=None,
        clock=lambda: AT,
        native=build_native_integrations(
            client=_k8s_client(_Recorder()), kubernetes=K8S
        ),
    )
    chosen = executor._integrations["kill_container"]  # noqa: SLF001
    assert isinstance(chosen, HttpRemediationIntegration)
