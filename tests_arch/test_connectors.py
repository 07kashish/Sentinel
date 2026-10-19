"""Discovery that cannot hide how little it looked at.

THE FAILURE THIS GUARDS AGAINST
---------------------------------
A discovery feature's characteristic failure is not a wrong answer, it is a
CONFIDENT one. "We found 3 agents" reads identically whether the scan covered
one namespace or forty, and the reader has no way to tell which.

So coverage is not a convention here, it is a constructor argument:
`AssetInventory` REFUSES to exist without it, and
`test_an_inventory_cannot_be_built_without_coverage` is the rule. Documentation
saying "connectors should report coverage" produces connectors that do not.

The second half is `build_connectors`: an unconfigured connector is ABSENT, not
present-and-returning-empty. An empty inventory is indistinguishable from a
clean estate, and a product whose "no agents found" might mean "no credential
configured" has taught its operator to ignore it.
"""

from __future__ import annotations

import json

import pytest

from sentinel.domain.assets import (
    AssetInventory,
    AssetKind,
    AssetRecord,
    DiscoveryCoverage,
    Unreachable,
    merge,
)
from sentinel.infrastructure.outbound import HardenedHttpClient, OutboundPolicy
from sentinel.infrastructure.platforms.aws import AwsCredentials
from sentinel.infrastructure.platforms.connectors import (
    Connector,
    aws_iam_connector,
    build_connectors,
    kubernetes_connector,
)
from sentinel.infrastructure.platforms.kubernetes import KubernetesCredentials

K8S = KubernetesCredentials(api_server="https://cluster.internal:6443", token="tok")
AWS = AwsCredentials(
    access_key_id="AKIDEXAMPLE",
    secret_access_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    region="us-east-1",
)


class _Canned:
    def __init__(self, *, status: int, body: bytes, content_type: str) -> None:
        self.status = status
        self._body = body
        self._type = content_type

    def getheader(self, *_a, **_kw):
        return None

    def getheaders(self):
        return [("Content-Type", self._type)]

    def read(self, _n):
        return self._body


class _Api:
    """Answers a canned body per request path, or a status for a failure."""

    def __init__(self, bodies, *, status=200, content_type="application/json") -> None:
        self.bodies = bodies
        self.status = status
        self.content_type = content_type
        self.paths: list[str] = []

    def __call__(self, destination):
        api = self

        class _Connection:
            def request(self, method, path, body=None, headers=None):
                api.paths.append(path)
                self._path = path

            def getresponse(self):
                payload = api.bodies.get(self._path)
                if payload is None:
                    return _Canned(
                        status=api.status, body=b"{}", content_type=api.content_type
                    )
                raw = (
                    payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
                )
                return _Canned(status=200, body=raw, content_type=api.content_type)

            def close(self):
                pass

        return _Connection()


@pytest.fixture(autouse=True)
def _no_dns(monkeypatch):
    import socket

    monkeypatch.setattr(
        "sentinel.infrastructure.outbound.socket.getaddrinfo",
        lambda host, port, *a, **k: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", port))
        ],
    )


def _client(factory, **policy) -> HardenedHttpClient:
    policy.setdefault("allow_private_destinations", True)
    policy.setdefault(
        "allowed_hosts", frozenset({"cluster.internal", "iam.amazonaws.com"})
    )
    return HardenedHttpClient(policy=OutboundPolicy(**policy), connection_factory=factory)


# ── coverage is structural, not documented ───────────────────────────────────


def test_an_inventory_cannot_be_built_without_coverage():
    """THE rule. A count with no denominator is not a discovery result."""
    with pytest.raises(TypeError):
        AssetInventory(connector="x", assets=())  # type: ignore[call-arg]


def test_coverage_that_is_not_coverage_is_refused():
    with pytest.raises(TypeError, match="no denominator"):
        AssetInventory(connector="x", assets=(), coverage={"scope": []})  # type: ignore[arg-type]


def test_unreachable_is_distinguished_from_empty():
    """A namespace that returned 403 and one containing nothing are the same
    length list and completely different facts.
    """
    empty = DiscoveryCoverage(scope=("prod",), examined=0)
    refused = DiscoveryCoverage(
        scope=("prod",),
        examined=0,
        unreachable=(Unreachable(target="prod", reason="HTTP 403"),),
    )
    assert empty.is_partial is False
    assert refused.is_partial is True


def test_an_unfollowed_pagination_makes_a_scan_partial():
    """A connector that stopped at the first page and did not say so reports a
    subset as a total.
    """
    coverage = DiscoveryCoverage(scope=("a",), pagination_complete=False)
    assert coverage.is_partial is True


def test_an_unreachable_target_must_carry_a_reason():
    """"We could not read namespace prod" is actionable; "coverage was partial"
    is a shrug wearing a data structure.
    """
    import dataclasses

    fields = {f.name for f in dataclasses.fields(Unreachable)}
    assert fields == {"target", "reason"}


# ── the asset vocabulary ─────────────────────────────────────────────────────


def test_an_asset_without_an_identifier_is_refused():
    with pytest.raises(ValueError, match="cannot be referred to"):
        AssetRecord(kind=AssetKind.AGENT, identifier="  ", source="kubernetes")


def test_an_asset_without_a_source_is_refused():
    """An asset nobody can attribute to a scan is one nobody can re-check."""
    with pytest.raises(ValueError, match="no source connector"):
        AssetRecord(kind=AssetKind.AGENT, identifier="a", source="")


def test_the_native_type_survives_normalisation():
    """The normalised kind answers cross-connector questions; the native type is
    how somebody finds the thing again in the console it came from.
    """
    record = AssetRecord(
        kind=AssetKind.SERVICE_ACCOUNT,
        identifier="aws://iam/user/svc",
        source="aws_iam",
        native_type="IamUser",
    )
    assert record.as_dict()["native_type"] == "IamUser"


# ── kubernetes ───────────────────────────────────────────────────────────────


PODS = "/api/v1/namespaces/prod/pods"
ACCOUNTS = "/api/v1/namespaces/prod/serviceaccounts"


def test_pods_become_runtimes_and_service_accounts_become_identities():
    """A pod is WHERE an agent runs. Calling it the agent conflates workload
    with identity, and two pods running one agent would read as two agents.
    """
    api = _Api(
        {
            PODS: {
                "items": [
                    {
                        "metadata": {"name": "finance-1"},
                        "spec": {
                            "serviceAccountName": "finance-sa",
                            "containers": [{"image": "acme/agent:2"}],
                        },
                    }
                ]
            },
            ACCOUNTS: {"items": [{"metadata": {"name": "finance-sa"}, "spec": {}}]},
        }
    )
    inventory = kubernetes_connector(
        client=_client(api), credentials=K8S, namespaces=["prod"]
    ).discover()

    assert len(inventory.by_kind(AssetKind.AGENT_RUNTIME)) == 1
    assert len(inventory.by_kind(AssetKind.SERVICE_ACCOUNT)) == 1
    assert inventory.coverage.examined == 2


def test_a_pod_records_the_identity_it_runs_as():
    api = _Api(
        {
            PODS: {
                "items": [
                    {
                        "metadata": {"name": "finance-1"},
                        "spec": {"serviceAccountName": "finance-sa", "containers": []},
                    }
                ]
            },
            ACCOUNTS: {"items": []},
        }
    )
    inventory = kubernetes_connector(
        client=_client(api), credentials=K8S, namespaces=["prod"]
    ).discover()
    runtime = inventory.by_kind(AssetKind.AGENT_RUNTIME)[0]
    assert runtime.relates_to == ("k8s://prod/serviceaccount/finance-sa",)


def test_a_truncated_listing_makes_the_scan_partial():
    """A continuation token means the server had more and this connector did not
    ask for it.
    """
    api = _Api(
        {
            PODS: {"items": [], "metadata": {"continue": "TOKEN"}},
            ACCOUNTS: {"items": []},
        }
    )
    inventory = kubernetes_connector(
        client=_client(api), credentials=K8S, namespaces=["prod"]
    ).discover()
    assert inventory.coverage.pagination_complete is False
    assert inventory.coverage.is_partial is True


def test_an_invalid_namespace_never_reaches_the_api():
    api = _Api({})
    inventory = kubernetes_connector(
        client=_client(api), credentials=K8S, namespaces=["../../secrets"]
    ).discover()
    assert api.paths == []
    assert inventory.coverage.unreachable[0].reason.startswith("not a valid")


def test_a_refused_namespace_is_recorded_rather_than_swallowed():
    api = _Api({}, status=403)
    inventory = kubernetes_connector(
        client=_client(api), credentials=K8S, namespaces=["prod"]
    ).discover()
    assert inventory.assets == ()
    assert any("403" in u.reason for u in inventory.coverage.unreachable)
    assert inventory.coverage.is_partial is True


def test_the_permissions_actually_used_are_reported():
    """An operator reviewing a connector needs what it asked for, not what its
    documentation says it might ask for.
    """
    api = _Api({PODS: {"items": []}, ACCOUNTS: {"items": []}})
    inventory = kubernetes_connector(
        client=_client(api), credentials=K8S, namespaces=["prod"]
    ).discover()
    assert "list pods" in inventory.coverage.permissions_used


# ── aws iam ──────────────────────────────────────────────────────────────────


def _iam(users=(), roles=(), truncated=False) -> str:
    body = "".join(f"<UserName>{u}</UserName>" for u in users)
    body += "".join(f"<RoleName>{r}</RoleName>" for r in roles)
    return (
        "<ListUsersResponse><ListUsersResult>"
        f"<IsTruncated>{'true' if truncated else 'false'}</IsTruncated>"
        f"{body}</ListUsersResult></ListUsersResponse>"
    )


class _Iam:
    def __init__(self, body: str) -> None:
        self.body = body

    def __call__(self, destination):
        body = self.body

        class _Connection:
            def request(self, *a, **kw):
                pass

            def getresponse(self):
                return _Canned(status=200, body=body.encode(), content_type="text/xml")

            def close(self):
                pass

        return _Connection()


def test_iam_identities_are_roles_and_accounts_never_agents():
    """IAM does not know what an agent is. Labelling a user an agent because it
    sits under `/agents/` infers identity from a naming convention, and a
    convention is not an authority.
    """
    inventory = aws_iam_connector(
        client=_client(_Iam(_iam(users=("finance-svc",), roles=("agent-role",)))),
        credentials=AWS,
    ).discover()
    assert AssetKind.AGENT not in inventory.kinds
    assert AssetKind.SERVICE_ACCOUNT in inventory.kinds
    assert AssetKind.CLOUD_ROLE in inventory.kinds


def test_a_truncated_iam_listing_is_reported_as_incomplete():
    inventory = aws_iam_connector(
        client=_client(_Iam(_iam(users=("a",), truncated=True))), credentials=AWS
    ).discover()
    assert inventory.coverage.pagination_complete is False


# ── composition and merging ──────────────────────────────────────────────────


def test_an_unconfigured_connector_is_absent_not_empty():
    """An empty inventory is indistinguishable from a clean estate. A product
    whose "no agents found" might mean "no credential configured" has taught its
    operator to ignore it.
    """
    assert build_connectors() == {}


def test_kubernetes_needs_namespaces_as_well_as_a_credential():
    """A credential with no scope would otherwise silently scan `default`."""
    assert build_connectors(kubernetes=K8S) == {}


def test_each_credential_registers_its_own_connector():
    built = build_connectors(
        kubernetes=K8S, kubernetes_namespaces=["prod"], aws=AWS
    )
    assert sorted(built) == ["aws_iam", "kubernetes"]
    assert all(isinstance(c, Connector) for c in built.values())


def test_merging_keeps_each_connector_s_coverage_apart():
    """One coverage figure for several scopes cannot be honest. The only way to
    summarise "two namespaces scanned, one AWS account unreachable" is to keep
    them separate.
    """
    complete = AssetInventory(
        connector="kubernetes",
        assets=(),
        coverage=DiscoveryCoverage(scope=("prod",), examined=5),
    )
    partial = AssetInventory(
        connector="aws_iam",
        assets=(),
        coverage=DiscoveryCoverage(
            scope=("iam:/",),
            unreachable=(Unreachable(target="iam:ListRoles", reason="HTTP 403"),),
        ),
    )
    document = merge([complete, partial])
    assert document["partial_sources"] == ["aws_iam"]
    assert "floor, never a census" in document["limits"]


def test_an_inventory_states_that_absence_is_not_evidence():
    inventory = AssetInventory(
        connector="kubernetes",
        assets=(),
        coverage=DiscoveryCoverage(scope=("prod",)),
    )
    assert "NOT evidence that nothing is there" in inventory.as_dict()["limits"]
