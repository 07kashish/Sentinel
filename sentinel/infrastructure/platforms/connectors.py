"""Phase 3: the connector port, and the two that are real.

WHAT A CONNECTOR IS
-------------------
One typed function from a credential to an `AssetInventory`. It lists what it
can see, normalises it into the shared vocabulary, and reports what it looked at
-- and it cannot skip that last part, because `AssetInventory` will not
construct without coverage.

WHY ONLY TWO
------------
The specification names roughly thirty connectors across AWS, Microsoft, Google,
five agent frameworks and eight SecOps vendors. Two are implemented here:
Kubernetes and AWS IAM, both built on `HardenedHttpClient` and the SigV4 signer
that already exist. Everything else would need an SDK, a credential type and an
API surface this repository has neither access to nor a way to test against, and
a connector that returned an empty inventory because nobody could exercise it is
worse than an absent one: it reports "nothing found" where the honest answer is
"not implemented".

`docs/INTEGRATIONS.md` lists all of them by name with their real status, so
"which connectors does Sentinel have" is answered by a document that names the
gaps rather than by a slide that lists logos.

THE REGISTRY REFUSES TO INVENT A RESULT
-----------------------------------------
`build_connectors` returns only the ones an operator supplied credentials for.
An unconfigured connector is ABSENT -- not present-and-returning-empty -- for
exactly the reason `build_tool_adapters` uses: absence is enforced by there
being nothing to call, while a disabled flag is one boolean away from being on
and an empty result is indistinguishable from a clean estate.
"""

from __future__ import annotations

import datetime as _dt
import re
import urllib.parse
from typing import Any, Protocol, Sequence, runtime_checkable

from sentinel.domain.assets import (
    AssetInventory,
    AssetKind,
    AssetRecord,
    DiscoveryCoverage,
    Unreachable,
)
from sentinel.infrastructure.outbound import (
    HardenedHttpClient,
    OutboundRefused,
    OutboundUnavailable,
)
from sentinel.infrastructure.platforms.aws import AwsCredentials, sign_request
from sentinel.infrastructure.platforms.kubernetes import KubernetesCredentials

__all__ = [
    "Connector",
    "aws_iam_connector",
    "build_connectors",
    "kubernetes_connector",
]

_RFC1123 = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


@runtime_checkable
class Connector(Protocol):
    """Discover assets from one source.

    One method, and it returns an inventory rather than a bare list, so the
    coverage requirement is in the type rather than in a convention.
    """

    name: str

    def discover(self) -> AssetInventory: ...


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


# ── Kubernetes ───────────────────────────────────────────────────────────────


def kubernetes_connector(
    *,
    client: HardenedHttpClient,
    credentials: KubernetesCredentials,
    namespaces: Sequence[str],
) -> Connector:
    """Pods and service accounts in the named namespaces.

    Namespaces are REQUIRED rather than discovered. Listing every namespace
    needs a cluster-wide read a deployment may not have been granted, and
    silently falling back to `default` produces a confident report about one
    namespace out of forty -- the exact failure `DiscoveryCoverage` exists to
    make visible.

    Pods become AGENT_RUNTIME, not AGENT. A pod is where an agent runs; calling
    it the agent conflates the workload with the identity, and two pods running
    one agent would then read as two agents.
    """
    server = str(credentials.api_server).rstrip("/")
    headers = {
        "authorization": f"Bearer {credentials.token}",
        "accept": "application/json",
    }

    class _KubernetesConnector:
        name = "kubernetes"

        def discover(self) -> AssetInventory:
            assets: list[AssetRecord] = []
            unreachable: list[Unreachable] = []
            scope: list[str] = []
            examined = 0

            for raw in namespaces:
                namespace = str(raw).strip()
                if not _RFC1123.fullmatch(namespace):
                    unreachable.append(
                        Unreachable(
                            target=namespace,
                            reason="not a valid RFC 1123 namespace name",
                        )
                    )
                    continue
                scope.append(namespace)

                for path, kind, native in (
                    (f"/api/v1/namespaces/{namespace}/pods", AssetKind.AGENT_RUNTIME, "Pod"),
                    (
                        f"/api/v1/namespaces/{namespace}/serviceaccounts",
                        AssetKind.SERVICE_ACCOUNT,
                        "ServiceAccount",
                    ),
                ):
                    try:
                        response = client.request(
                            method="GET",
                            url=f"{server}{path}",
                            headers=headers,
                            body=None,
                            idempotent=True,
                        )
                    except (OutboundRefused, OutboundUnavailable) as exc:
                        unreachable.append(
                            Unreachable(
                                target=f"{namespace}/{native}",
                                reason=f"{type(exc).__name__}: {exc}",
                            )
                        )
                        continue
                    if response.status != 200:
                        unreachable.append(
                            Unreachable(
                                target=f"{namespace}/{native}",
                                reason=f"HTTP {response.status}",
                            )
                        )
                        continue

                    try:
                        body = response.json()
                    except OutboundRefused as exc:
                        unreachable.append(
                            Unreachable(
                                target=f"{namespace}/{native}",
                                reason=f"unparseable: {exc}",
                            )
                        )
                        continue

                    items = body.get("items", []) if isinstance(body, dict) else []
                    # `continue` is not `metadata.continue` being empty: a
                    # non-empty token means the server had more and this
                    # connector did not ask for it.
                    if str((body.get("metadata") or {}).get("continue", "")):
                        unreachable.append(
                            Unreachable(
                                target=f"{namespace}/{native}",
                                reason=(
                                    "the listing was truncated and the "
                                    "continuation was not followed"
                                ),
                            )
                        )

                    for item in items:
                        examined += 1
                        metadata = item.get("metadata") or {}
                        spec = item.get("spec") or {}
                        identifier = f"k8s://{namespace}/{native.lower()}/{metadata.get('name','')}"
                        relates: list[str] = []
                        if kind is AssetKind.AGENT_RUNTIME and spec.get(
                            "serviceAccountName"
                        ):
                            relates.append(
                                f"k8s://{namespace}/serviceaccount/"
                                f"{spec['serviceAccountName']}"
                            )
                        assets.append(
                            AssetRecord(
                                kind=kind,
                                identifier=identifier,
                                source="kubernetes",
                                native_type=native,
                                display_name=str(metadata.get("name", "")),
                                environment=namespace,
                                relates_to=tuple(relates),
                                attributes={
                                    "labels": dict(metadata.get("labels") or {}),
                                    "image": (
                                        str((spec.get("containers") or [{}])[0].get("image", ""))
                                        if kind is AssetKind.AGENT_RUNTIME
                                        else ""
                                    ),
                                },
                            )
                        )

            return AssetInventory(
                connector="kubernetes",
                assets=tuple(assets),
                coverage=DiscoveryCoverage(
                    scope=tuple(scope),
                    examined=examined,
                    unreachable=tuple(unreachable),
                    permissions_used=("list pods", "list serviceaccounts"),
                    retrieved_at=_now(),
                    pagination_complete=not any(
                        "truncated" in u.reason for u in unreachable
                    ),
                ),
            )

    return _KubernetesConnector()


# ── AWS IAM ──────────────────────────────────────────────────────────────────


def aws_iam_connector(
    *,
    client: HardenedHttpClient,
    credentials: AwsCredentials,
    path_prefix: str = "/",
    clock: Any = None,
) -> Connector:
    """IAM users and roles: the identities an agent could act as.

    IAM does not know what an agent is, so this reports CLOUD_ROLE and
    SERVICE_ACCOUNT rather than AGENT. Labelling an IAM user an agent because it
    sits under `/agents/` would be inferring identity from a naming convention,
    and a convention is not an authority.
    """

    class _AwsIamConnector:
        name = "aws_iam"

        def discover(self) -> AssetInventory:
            assets: list[AssetRecord] = []
            unreachable: list[Unreachable] = []
            examined = 0
            complete = True

            for action, kind, native, pattern in (
                (
                    "ListUsers",
                    AssetKind.SERVICE_ACCOUNT,
                    "IamUser",
                    r"<UserName>([\w+=,.@-]{1,64})</UserName>",
                ),
                (
                    "ListRoles",
                    AssetKind.CLOUD_ROLE,
                    "IamRole",
                    r"<RoleName>([\w+=,.@-]{1,64})</RoleName>",
                ),
            ):
                payload = urllib.parse.urlencode(
                    {
                        "Action": action,
                        "Version": "2010-05-08",
                        "PathPrefix": path_prefix,
                        "MaxItems": "100",
                    }
                ).encode("utf-8")
                now = (
                    clock()
                    if clock is not None
                    else _dt.datetime.now(_dt.timezone.utc)
                )
                headers = sign_request(
                    credentials=credentials,
                    service="iam",
                    host="iam.amazonaws.com",
                    amz_target="",
                    payload=payload,
                    now=now,
                )
                try:
                    response = client.request(
                        method="POST",
                        url="https://iam.amazonaws.com/",
                        headers=headers,
                        body=payload,
                        idempotent=True,
                    )
                except (OutboundRefused, OutboundUnavailable) as exc:
                    unreachable.append(
                        Unreachable(
                            target=f"iam:{action}",
                            reason=f"{type(exc).__name__}: {exc}",
                        )
                    )
                    continue
                if response.status != 200:
                    unreachable.append(
                        Unreachable(
                            target=f"iam:{action}", reason=f"HTTP {response.status}"
                        )
                    )
                    continue

                body = response.body.decode("utf-8", errors="replace")
                if "<IsTruncated>true</IsTruncated>" in body:
                    complete = False
                    unreachable.append(
                        Unreachable(
                            target=f"iam:{action}",
                            reason=(
                                "the listing was truncated; this covers the "
                                "first page only"
                            ),
                        )
                    )

                for name in re.findall(pattern, body):
                    examined += 1
                    assets.append(
                        AssetRecord(
                            kind=kind,
                            identifier=f"aws://iam/{native.lower()}{path_prefix}{name}",
                            source="aws_iam",
                            native_type=native,
                            display_name=name,
                            attributes={"path_prefix": path_prefix},
                        )
                    )

            return AssetInventory(
                connector="aws_iam",
                assets=tuple(assets),
                coverage=DiscoveryCoverage(
                    scope=(f"iam:{path_prefix}",),
                    examined=examined,
                    unreachable=tuple(unreachable),
                    permissions_used=("iam:ListUsers", "iam:ListRoles"),
                    retrieved_at=_now(),
                    pagination_complete=complete,
                ),
            )

    return _AwsIamConnector()


# ── Composition ──────────────────────────────────────────────────────────────


def build_connectors(
    *,
    http_client: HardenedHttpClient | None = None,
    kubernetes: KubernetesCredentials | None = None,
    kubernetes_namespaces: Sequence[str] = (),
    aws: AwsCredentials | None = None,
    aws_path_prefix: str = "/",
) -> dict[str, Connector]:
    """Exactly the connectors an operator supplied credentials for.

    An unconfigured connector is ABSENT, not present-and-empty. The distinction
    is the whole point: an empty inventory is indistinguishable from a clean
    estate, and a discovery product whose "no agents found" might mean "no
    credential configured" has taught its operator to ignore it.
    """
    connectors: dict[str, Connector] = {}
    client = http_client or HardenedHttpClient()

    if kubernetes is not None and kubernetes_namespaces:
        connector = kubernetes_connector(
            client=client,
            credentials=kubernetes,
            namespaces=kubernetes_namespaces,
        )
        connectors[connector.name] = connector
    if aws is not None:
        connector = aws_iam_connector(
            client=client, credentials=aws, path_prefix=aws_path_prefix
        )
        connectors[connector.name] = connector
    return connectors
