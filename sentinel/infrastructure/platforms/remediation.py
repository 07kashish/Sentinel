"""Native containment: remediation that Sentinel performs itself.

WHAT WAS MISSING
----------------
`build_remediation_executor` builds one integration shape:
`HttpRemediationIntegration`, which POSTs `{"target", "idempotency_key"}` to an
operator-run webhook. That is a real and correct design for actions Sentinel
cannot perform -- an ITSM ticket, a GCP service account -- and it is the wrong
one for `kill_container`, because Sentinel now holds a Kubernetes credential and
can delete the pod.

An operator who wanted containment had to stand up a webhook service that
re-implemented the Kubernetes call, hold a second copy of the cluster
credential, and keep the two in sync. Most did not, which is why
`NullRemediationExecutor` was the executor almost every deployment got, and why
`decide_response`'s CRITICAL path -- deterministic emergency containment --
terminated in `unsupported_action`.

THE FOUR THAT ARE GENUINELY NATIVE
------------------------------------
Only actions this process can actually perform appear here:

  * `kill_container`       -- DELETE the pod
  * `quarantine_workload`  -- create a deny-all NetworkPolicy selecting it
  * `release_workload`     -- delete that NetworkPolicy
  * `revoke_cloud_session` -- attach the AWS-documented deny-older-sessions
                              inline policy to the principal

Everything else in `REMEDIATION_ACTIONS` keeps its webhook integration or none
at all. A native integration for an action this process cannot do would be the
fake-remediation failure the whole catalogue is built to avoid: `supports()`
returning True for something that then reports success without acting.

WHY THESE BYPASS THE TIER CEILING, AND WHY THAT IS NOT A HOLE
---------------------------------------------------------------
The Phase-2 tool adapters carry a ceiling because an AGENT drives them. These are
driven by `DecideApprovalHandler` after a HUMAN approved a proposed remediation,
through `ApprovalPathAuthorizer`, inside a `ProtectedToolRunner`. The authority
is different in kind: a human's approval of a named action against a named
target, not an agent's request.

Applying a read-only ceiling here would mean containment could never contain
anything, which is the failure mode this module exists to fix. What replaces the
ceiling is narrowness: each integration performs exactly ONE operation shape
against a target it validates, and there is no argument through which a caller
can ask for a different one.

THE TARGET IS THE ONLY INPUT, AND IT IS VALIDATED
---------------------------------------------------
`RemediationIntegration.execute` receives one string. Every integration here
parses it into typed, validated fields before building a request -- a namespace
and a name that must both be RFC 1123 labels, an IAM user name that must match
the AWS grammar. A target that does not parse is refused rather than
interpolated, because the target reaches this process from a proposal and the
proposal was built from incident facts.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import urllib.parse
from typing import Any, Mapping

from sentinel.domain.errors import DomainRuleViolated, TransientFailure
from sentinel.domain.primitives import IdempotencyKey
from sentinel.infrastructure.outbound import (
    HardenedHttpClient,
    OutboundRefused,
    OutboundUnavailable,
)
from sentinel.infrastructure.platforms.aws import AwsCredentials, sign_request
from sentinel.infrastructure.platforms.kubernetes import KubernetesCredentials

__all__ = [
    "AwsSessionRevocation",
    "KubernetesPodTermination",
    "KubernetesQuarantine",
    "KubernetesQuarantineRelease",
    "NATIVE_REMEDIATION_ACTIONS",
    "build_native_integrations",
]

#: The actions this module can perform natively. Kept as a flat tuple so
#: `build_native_integrations` and any test can agree on the list without one of
#: them enumerating it by hand.
NATIVE_REMEDIATION_ACTIONS: tuple[str, ...] = (
    "kill_container",
    "quarantine_workload",
    "release_workload",
    "revoke_cloud_session",
)

#: The label Sentinel puts on every NetworkPolicy it creates, so an operator can
#: find them all and so `release_workload` deletes only its own.
QUARANTINE_PREFIX = "sentinel-quarantine-"

_RFC1123 = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

#: AWS IAM user names. The grammar AWS documents, applied because the name is
#: interpolated into a signed request this process makes with its own key.
_IAM_NAME = re.compile(r"^[\w+=,.@-]{1,64}$")


class RemediationTargetInvalid(DomainRuleViolated):
    """The target string did not parse into the fields this action needs.

    Not retryable: a malformed target is malformed on the second attempt too,
    and retrying it would burn the approval's budget against a typo.
    """

    is_retryable = False


def _namespaced(target: str, *, action: str) -> tuple[str, str]:
    """Parse `namespace/name`, validating both halves as RFC 1123 labels."""
    namespace, separator, name = str(target).strip().partition("/")
    if not separator or not namespace or not name:
        raise RemediationTargetInvalid(
            f"{action}: target {target!r} must be 'namespace/name'"
        )
    for label, value in (("namespace", namespace), ("name", name)):
        if not _RFC1123.fullmatch(value):
            raise RemediationTargetInvalid(
                f"{action}: {label} {value!r} is not a valid RFC 1123 name"
            )
    return namespace, name


def _call(
    client: HardenedHttpClient,
    *,
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes | None,
    provider: str,
    target: str,
) -> dict[str, Any]:
    """One hardened request, with the status semantics the executor expects.

    5xx is raised as retryable and 4xx as a rule violation, matching
    `HttpRemediationIntegration` exactly -- the executor's retry and receipt
    handling reads those two cases, and an integration that classified them
    differently would be a second set of rules for the same decision.

    404 is the exception, and it is deliberate: an object that is already gone
    is the state the action was trying to reach. Reporting success for it is
    what makes these idempotent under the at-least-once redelivery the executor
    permits.
    """
    try:
        response = client.request(
            method=method, url=url, headers=dict(headers), body=body, idempotent=True
        )
    except OutboundUnavailable:
        raise
    except OutboundRefused as exc:
        raise DomainRuleViolated(
            f"{provider} remediation refused for target {target!r}: {exc}"
        ) from exc

    status = int(getattr(response, "status", 0))
    if status == 404:
        return {"status": status, "provider": provider, "already_absent": True}
    if status >= 500:
        raise TransientFailure(
            f"{provider} returned {status} for target {target!r}"
        )
    if status >= 400:
        raise DomainRuleViolated(
            f"{provider} refused the action for target {target!r} "
            f"with status {status}"
        )
    return {"status": status, "provider": provider, "peer": response.peer}


# ── Kubernetes ───────────────────────────────────────────────────────────────


class _KubernetesIntegration:
    """Shared credential and client handling for the cluster integrations."""

    __slots__ = ("_client", "_credentials", "_server")

    def __init__(
        self, *, client: HardenedHttpClient, credentials: KubernetesCredentials
    ) -> None:
        self._client = client
        self._credentials = credentials
        self._server = str(credentials.api_server).rstrip("/")

    @property
    def provider(self) -> str:
        return "kubernetes"

    def _headers(self, *, json_body: bool = False) -> dict[str, str]:
        headers = {
            "authorization": f"Bearer {self._credentials.token}",
            "accept": "application/json",
        }
        if json_body:
            headers["content-type"] = "application/json"
        return headers


class KubernetesPodTermination(_KubernetesIntegration):
    """`kill_container`: delete one pod. Target is `namespace/pod`.

    The catalogue declares this NOT reversible and that is honest here: the
    replacement the controller starts is a different pod, and the terminated
    one's in-memory state is gone either way.
    """

    __slots__ = ()

    def execute(
        self, *, target: str, idempotency_key: IdempotencyKey
    ) -> Mapping[str, Any]:
        namespace, name = _namespaced(target, action="kill_container")
        result = _call(
            self._client,
            method="DELETE",
            url=f"{self._server}/api/v1/namespaces/{namespace}/pods/{name}",
            headers=self._headers(),
            body=None,
            provider="kubernetes",
            target=target,
        )
        return {**result, "action": "kill_container", "pod": f"{namespace}/{name}"}


class KubernetesQuarantine(_KubernetesIntegration):
    """`quarantine_workload`: deny-all NetworkPolicy over one pod label.

    Target is `namespace/name`, where `name` is BOTH the policy name suffix and
    the value of the `app` label the policy selects. A policy with an empty
    `podSelector` would quarantine the entire namespace, which is a blast radius
    the catalogue rates SINGLE -- so the selector is always specific and never
    defaulted.

    Both `Ingress` and `Egress` are denied. Denying only ingress leaves the
    exfiltration path open, and exfiltration is the thing being contained.
    """

    __slots__ = ()

    def execute(
        self, *, target: str, idempotency_key: IdempotencyKey
    ) -> Mapping[str, Any]:
        namespace, name = _namespaced(target, action="quarantine_workload")
        policy_name = f"{QUARANTINE_PREFIX}{name}"[:63].rstrip("-")
        body = json.dumps(
            {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {
                    "name": policy_name,
                    "namespace": namespace,
                    "labels": {"app.kubernetes.io/managed-by": "sentinel"},
                    "annotations": {
                        # The approval this came from, on the object itself, so
                        # an operator who finds the policy can trace why it
                        # exists without correlating timestamps.
                        "sentinel.io/idempotency-key": idempotency_key.value
                    },
                },
                "spec": {
                    "podSelector": {"matchLabels": {"app": name}},
                    "policyTypes": ["Ingress", "Egress"],
                    # No `ingress` or `egress` rules at all: an empty rule LIST
                    # denies everything, whereas an empty rule OBJECT would
                    # allow everything. The difference is one character and the
                    # inverse of the intended meaning.
                },
            },
            separators=(",", ":"),
        ).encode("utf-8")

        result = _call(
            self._client,
            method="POST",
            url=(
                f"{self._server}/apis/networking.k8s.io/v1"
                f"/namespaces/{namespace}/networkpolicies"
            ),
            headers=self._headers(json_body=True),
            body=body,
            provider="kubernetes",
            target=target,
        )
        return {
            **result,
            "action": "quarantine_workload",
            "network_policy": f"{namespace}/{policy_name}",
        }


class KubernetesQuarantineRelease(_KubernetesIntegration):
    """`release_workload`: delete the NetworkPolicy `quarantine_workload` made.

    Only Sentinel's own policy name is constructed, so this cannot be used to
    delete an operator's network policy by naming it as the target -- the
    prefix is added here and is not part of the input.
    """

    __slots__ = ()

    def execute(
        self, *, target: str, idempotency_key: IdempotencyKey
    ) -> Mapping[str, Any]:
        namespace, name = _namespaced(target, action="release_workload")
        policy_name = f"{QUARANTINE_PREFIX}{name}"[:63].rstrip("-")
        result = _call(
            self._client,
            method="DELETE",
            url=(
                f"{self._server}/apis/networking.k8s.io/v1"
                f"/namespaces/{namespace}/networkpolicies/{policy_name}"
            ),
            headers=self._headers(),
            body=None,
            provider="kubernetes",
            target=target,
        )
        return {
            **result,
            "action": "release_workload",
            "network_policy": f"{namespace}/{policy_name}",
        }


# ── AWS ──────────────────────────────────────────────────────────────────────

#: The AWS-documented way to revoke in-flight sessions: an inline policy denying
#: everything issued before a cutoff. Revoking a session is not an API call --
#: STS credentials are valid until they expire -- so this is the mechanism, not
#: an approximation of one.
_REVOKE_POLICY_NAME = "SentinelRevokeOlderSessions"


class AwsSessionRevocation:
    """`revoke_cloud_session`: deny everything issued before now, for one user.

    Target is the IAM user name. The catalogue declares this NOT reversible, and
    that is right: deleting the policy later would not un-revoke the sessions it
    invalidated, it would only stop denying future ones.

    WHAT THIS DOES NOT DO. It does not delete access keys and it does not touch
    roles. Those are different actions with different blast radii, and folding
    them in here would mean one approved action performing three.
    """

    __slots__ = ("_client", "_credentials", "_clock")

    def __init__(
        self,
        *,
        client: HardenedHttpClient,
        credentials: AwsCredentials,
        clock: Any = None,
    ) -> None:
        self._client = client
        self._credentials = credentials
        self._clock = clock

    @property
    def provider(self) -> str:
        return "aws"

    def execute(
        self, *, target: str, idempotency_key: IdempotencyKey
    ) -> Mapping[str, Any]:
        user = str(target).strip()
        if not _IAM_NAME.fullmatch(user):
            raise RemediationTargetInvalid(
                f"revoke_cloud_session: target {user!r} is not a valid IAM user name"
            )

        now = (
            self._clock() if self._clock is not None
            else _dt.datetime.now(_dt.timezone.utc)
        )
        cutoff = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": ["*"],
                    "Resource": ["*"],
                    "Condition": {"DateLessThan": {"aws:TokenIssueTime": cutoff}},
                }
            ],
        }

        payload = urllib.parse.urlencode(
            {
                "Action": "PutUserPolicy",
                "Version": "2010-05-08",
                "UserName": user,
                "PolicyName": _REVOKE_POLICY_NAME,
                "PolicyDocument": json.dumps(policy, separators=(",", ":")),
            }
        ).encode("utf-8")

        headers = sign_request(
            credentials=self._credentials,
            service="iam",
            host="iam.amazonaws.com",
            amz_target="",
            payload=payload,
            now=now,
        )
        result = _call(
            self._client,
            method="POST",
            url="https://iam.amazonaws.com/",
            headers=headers,
            body=payload,
            provider="aws",
            target=user,
        )
        return {
            **result,
            "action": "revoke_cloud_session",
            "user": user,
            # Recorded because it is the whole semantics of the action: sessions
            # issued before this instant are denied, later ones are not.
            "revoked_before": cutoff,
        }


# ── Composition ──────────────────────────────────────────────────────────────


def build_native_integrations(
    *,
    client: HardenedHttpClient,
    kubernetes: KubernetesCredentials | None = None,
    aws: AwsCredentials | None = None,
) -> dict[str, Any]:
    """Build the native integrations this deployment has credentials for.

    Returns an action -> integration mapping in exactly the shape
    `GuardedRemediationExecutor` takes, so the composition root merges it with
    the webhook integrations rather than choosing between them. Where both are
    configured for one action the operator's explicit webhook wins: they
    configured it on purpose, and silently preferring the native path would
    override a deliberate decision.
    """
    integrations: dict[str, Any] = {}

    if kubernetes is not None:
        integrations["kill_container"] = KubernetesPodTermination(
            client=client, credentials=kubernetes
        )
        integrations["quarantine_workload"] = KubernetesQuarantine(
            client=client, credentials=kubernetes
        )
        integrations["release_workload"] = KubernetesQuarantineRelease(
            client=client, credentials=kubernetes
        )

    if aws is not None:
        integrations["revoke_cloud_session"] = AwsSessionRevocation(
            client=client, credentials=aws
        )

    return integrations
