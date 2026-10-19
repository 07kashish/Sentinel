"""Discovery that does not depend on an agent volunteering its existence.

WHAT THESE TESTS ARE GUARDING
-------------------------------
Two things, and the second is the one that makes the feature honest.

PRECISION. A discovery list an operator has to dismiss forty false entries from
is a list nobody reads, and then the real finding goes unnoticed too. So
`app.kubernetes.io/component` — a label most workloads in a well-labelled
cluster carry — must match on its VALUE, not its key.

THE DENOMINATOR. A count without its scope is how "we have full coverage" gets
said out loud. Every report states which namespaces were listed, which could not
be, and what the marker approach cannot see. A namespace that failed to list is
a hole, and a report that hides its holes is worse than one that admits them.
"""

from __future__ import annotations

import datetime as _dt
import json

import pytest

from sentinel.domain.inventory import AgentClassification
from sentinel.infrastructure.outbound import HardenedHttpClient, OutboundPolicy
from sentinel.infrastructure.platforms.aws import AwsCredentials
from sentinel.infrastructure.platforms.discovery import (
    DiscoveredWorkload,
    DiscoveryReport,
    DiscoverySource,
    discover_aws_principals,
    discover_kubernetes_workloads,
    reconcile,
)
from sentinel.infrastructure.platforms.kubernetes import KubernetesCredentials

K8S = KubernetesCredentials(api_server="https://cluster.internal:6443", token="tok")
AWS = AwsCredentials(
    access_key_id="AKIDEXAMPLE",
    secret_access_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    region="us-east-1",
)
AT = _dt.datetime(2026, 8, 30, 12, 0, 0, tzinfo=_dt.timezone.utc)


def _pod(name, *, labels=None, annotations=None, image="nginx:1.25", sa=""):
    spec = {"containers": [{"image": image}]}
    if sa:
        spec["serviceAccountName"] = sa
    return {
        "metadata": {
            "name": name,
            "labels": labels or {},
            "annotations": annotations or {},
        },
        "spec": spec,
    }


class _Canned:
    """One fixed HTTP response, in the shape `HardenedHttpClient` reads."""

    def __init__(self, *, status: int, body: bytes) -> None:
        self.status = status
        self._body = body

    def getheader(self, *_a, **_kw):
        return None

    def getheaders(self):
        return [("Content-Type", "application/json")]

    def read(self, _n):
        return self._body


class _Api:
    """Answers one canned body per namespace path, or a status for a failure."""

    def __init__(self, bodies, status=200) -> None:
        self.bodies = bodies
        self.status = status
        self.paths: list[str] = []

    def __call__(self, destination):
        api = self

        class _Connection:
            def request(self, method, path, body=None, headers=None):
                api.paths.append(path)
                self._path = path

            def getresponse(self):
                payload = api.bodies.get(self._path)
                # Bound to instance attributes rather than read from the
                # enclosing scope: a CLASS BODY does not close over enclosing
                # locals, so `status = status` inside one is a NameError, not a
                # capture. The first version of this fake made every test fail
                # for a reason that had nothing to do with discovery.
                response = _Canned(
                    status=api.status if payload is None else 200,
                    body=json.dumps(payload or {}).encode("utf-8"),
                )
                return response

            def close(self):
                pass

        return _Connection()


@pytest.fixture(autouse=True)
def _no_dns(monkeypatch):
    import socket

    def _resolve(host, port, *_a, **_kw):
        address = "10.0.0.5" if str(host).endswith(".internal") else "93.184.216.34"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]

    monkeypatch.setattr("sentinel.infrastructure.outbound.socket.getaddrinfo", _resolve)


def _k8s_client(factory) -> HardenedHttpClient:
    return HardenedHttpClient(
        policy=OutboundPolicy(
            allow_private_destinations=True,
            allowed_hosts=frozenset({"cluster.internal"}),
        ),
        connection_factory=factory,
    )


def _aws_client(factory) -> HardenedHttpClient:
    return HardenedHttpClient(connection_factory=factory)


# ── Kubernetes ───────────────────────────────────────────────────────────────


PODS_PATH = "/api/v1/namespaces/prod/pods"


def test_a_declared_agent_is_found_and_an_ordinary_pod_is_not():
    api = _Api(
        {
            PODS_PATH: {
                "items": [
                    _pod("web-1", image="nginx:1.25"),
                    _pod(
                        "finance-agent-1",
                        annotations={"sentinel.io/agent-id": "finance-agent"},
                        image="acme/langgraph-runner:2",
                        sa="finance-sa",
                    ),
                ]
            }
        }
    )
    report = discover_kubernetes_workloads(
        client=_k8s_client(api), credentials=K8S, namespaces=["prod"]
    )

    assert [w.agent_id for w in report.workloads] == ["finance-agent"]
    assert report.examined == 2, "the denominator must count what was looked at"
    found = report.workloads[0]
    assert found.identity_is_declared is True
    assert found.principals == ("finance-sa",)


def test_a_generic_component_label_matches_on_its_value_not_its_key():
    """`app.kubernetes.io/component` is on most workloads in a well-labelled
    cluster. Matching the key alone would report the whole namespace, and a list
    nobody can read is a list the real finding hides in.
    """
    api = _Api(
        {
            PODS_PATH: {
                "items": [
                    _pod("db-1", labels={"app.kubernetes.io/component": "database"}),
                    _pod("a-1", labels={"app.kubernetes.io/component": "agent"}),
                ]
            }
        }
    )
    report = discover_kubernetes_workloads(
        client=_k8s_client(api), credentials=K8S, namespaces=["prod"]
    )
    assert [w.name for w in report.workloads] == ["a-1"]


def test_an_undeclared_identity_is_flagged_as_a_guess():
    """A name-based match is an inference. A reader must be able to tell it from
    an agent that said what it was.
    """
    api = _Api(
        {PODS_PATH: {"items": [_pod("crew-runner", image="ghcr.io/x/crewai:1")]}}
    )
    report = discover_kubernetes_workloads(
        client=_k8s_client(api), credentials=K8S, namespaces=["prod"]
    )
    assert report.workloads[0].identity_is_declared is False
    assert report.workloads[0].markers == ("image:crewai",)


def test_a_namespace_that_cannot_be_listed_is_a_recorded_hole():
    """A report that hides its holes is worse than one that admits them."""
    api = _Api({PODS_PATH: {"items": []}}, status=403)
    report = discover_kubernetes_workloads(
        client=_k8s_client(api), credentials=K8S, namespaces=["prod", "restricted"]
    )
    targets = dict(report.unreachable)
    assert "restricted" in targets
    assert "403" in targets["restricted"]


def test_a_malformed_namespace_never_reaches_the_api():
    api = _Api({})
    report = discover_kubernetes_workloads(
        client=_k8s_client(api), credentials=K8S, namespaces=["../../secrets"]
    )
    assert api.paths == [], "an invalid namespace was interpolated into a URL"
    assert report.unreachable[0][1].startswith("not a valid")


def test_namespaces_are_required_rather_than_defaulted():
    """Silently falling back to `default` would produce a confident report about
    one namespace out of forty.
    """
    report = discover_kubernetes_workloads(
        client=_k8s_client(_Api({})), credentials=K8S, namespaces=[]
    )
    assert report.scope == ()
    assert report.workloads == ()


# ── AWS ──────────────────────────────────────────────────────────────────────


class _Iam:
    def __init__(self, body: str, status: int = 200) -> None:
        self.body = body
        self.status = status
        self.sent: list[dict] = []

    def __call__(self, destination):
        iam = self

        class _Connection:
            def request(self, method, path, body=None, headers=None):
                iam.sent.append({"path": path, "body": body, "headers": dict(headers or {})})

            def getresponse(self):
                class _Response:
                    status = iam.status

                    def getheader(self, *_a, **_kw):
                        return None

                    def getheaders(self):
                        return [("Content-Type", "text/xml")]

                    def read(self, _n):
                        return iam.body.encode("utf-8")

                return _Response()

            def close(self):
                pass

        return _Connection()


def _list_users(*names, truncated=False):
    users = "".join(f"<member><UserName>{n}</UserName></member>" for n in names)
    return (
        "<ListUsersResponse><ListUsersResult>"
        f"<IsTruncated>{'true' if truncated else 'false'}</IsTruncated>"
        f"<Users>{users}</Users>"
        "</ListUsersResult></ListUsersResponse>"
    )


def test_iam_principals_under_a_path_prefix_are_discovered():
    iam = _Iam(_list_users("finance-agent", "research-agent"))
    report = discover_aws_principals(
        client=_aws_client(iam),
        credentials=AWS,
        clock=lambda: AT,
        path_prefix="/agents/",
    )
    assert [w.agent_id for w in report.workloads] == ["finance-agent", "research-agent"]
    assert b"Action=ListUsers" in iam.sent[0]["body"]
    assert iam.sent[0]["headers"]["authorization"].startswith("AWS4-HMAC-SHA256 ")


def test_a_truncated_listing_is_reported_as_incomplete():
    """A partial list presented as complete is the failure this module's whole
    design is arranged against.
    """
    iam = _Iam(_list_users("a", truncated=True))
    report = discover_aws_principals(
        client=_aws_client(iam), credentials=AWS, clock=lambda: AT
    )
    assert report.unreachable, "a truncated page was reported as the full set"
    assert "truncated" in report.unreachable[0][1]


def test_an_unrecognised_response_yields_nothing_and_says_why():
    """If the response shape changes, the result must be an EMPTY list with a
    reason, never a wrong one.
    """
    iam = _Iam("<SomethingElse/>")
    report = discover_aws_principals(
        client=_aws_client(iam), credentials=AWS, clock=lambda: AT
    )
    assert report.workloads == ()
    assert "not a recognised" in report.unreachable[0][1]


def test_an_iam_failure_is_recorded_not_raised():
    iam = _Iam("", status=403)
    report = discover_aws_principals(
        client=_aws_client(iam), credentials=AWS, clock=lambda: AT
    )
    assert report.workloads == ()
    assert "403" in report.unreachable[0][1]


# ── reconciliation ───────────────────────────────────────────────────────────


def _found(agent_id: str) -> DiscoveryReport:
    return DiscoveryReport(
        workloads=(
            DiscoveredWorkload(
                source=DiscoverySource.KUBERNETES,
                agent_id=agent_id,
                name=agent_id,
                location=f"prod/{agent_id}",
            ),
        ),
        scope=("prod",),
    )


def test_a_running_workload_whose_enrolment_was_revoked_is_the_headline():
    """THE finding that justifies this module. Telemetry-based inventory cannot
    see it: the agent stopped reporting, so it stopped appearing.
    """
    assert reconcile(_found("ghost"), enrolled=["ghost"], revoked=["ghost"]) == {
        "ghost": AgentClassification.REVOKED_BUT_ACTIVE
    }


def test_an_enrolled_workload_is_managed_and_an_unknown_one_is_not():
    assert reconcile(_found("known"), enrolled=["known"]) == {
        "known": AgentClassification.MANAGED
    }
    assert reconcile(_found("stranger"), enrolled=["known"]) == {
        "stranger": AgentClassification.UNMANAGED
    }


def test_reconciliation_reuses_the_inventory_vocabulary():
    """Two enums for one concept is two enums that drift, and an operator
    reading 'unmanaged' on one screen and something else on another has to learn
    which is which.
    """
    values = set(reconcile(_found("x"), enrolled=[]).values())
    assert values <= set(AgentClassification)


# ── honesty ──────────────────────────────────────────────────────────────────


def test_every_report_carries_its_own_limits():
    """A report is what gets pasted into a review; a document is not."""
    document = DiscoveryReport(workloads=(), scope=("prod",)).as_dict()
    assert "Absence from this list is NOT evidence" in document["limits"]
    assert document["scope"] == ["prod"]
    assert document["found"] == 0


def test_the_report_states_found_and_examined_separately():
    """`found` without `examined` is a numerator with no denominator."""
    document = DiscoveryReport(
        workloads=(), scope=("prod",), examined=57
    ).as_dict()
    assert document["examined"] == 57 and document["found"] == 0


# ── the CLI seam ─────────────────────────────────────────────────────────────


def test_discovery_without_a_cluster_credential_says_not_supported(tmp_path):
    """THE honesty case. An empty result here would read as "nothing is
    running", which is the single most dangerous wrong answer this command has:
    an operator concludes the cluster is clean when it was never looked at.
    """
    import io

    from sentinel.interface.cli import main

    stream = io.StringIO()
    code = main(
        ["agent-discover", "acme", "prod"],
        out=stream,
    )
    assert code == 78, "a deployment that cannot discover must not exit 0"
    assert "NOT_SUPPORTED" in stream.getvalue()
    assert "not an empty cluster" in stream.getvalue()


def test_discovery_requires_a_namespace(tmp_path):
    import io

    from sentinel.interface.cli import main

    stream = io.StringIO()
    assert main(["agent-discover", "acme"], out=stream) == 64
    assert "usage:" in stream.getvalue()
