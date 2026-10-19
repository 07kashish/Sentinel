"""Phase 3: the normalised asset vocabulary, and coverage that cannot be omitted.

WHY A SHARED VOCABULARY AT ALL
--------------------------------
Every connector describes the same world in its own words. AWS calls it a Role,
Kubernetes a ServiceAccount, Entra a Service Principal, GitHub an App -- and all
four are "a non-human identity something can act as". Without a normalised type
an operator asking "which identities can reach production" gets four answers in
four shapes and has to reconcile them by hand, which is the work the product is
supposed to do.

THE PART THAT MATTERS MORE THAN THE VOCABULARY
------------------------------------------------
`DiscoveryCoverage` is REQUIRED on every result, and `AssetInventory` cannot be
constructed without one. That is deliberate and it is the whole design.

A discovery feature's characteristic failure is not a wrong answer, it is a
CONFIDENT one: "we found 3 agents" reads identically whether it scanned one
namespace or forty, and an operator has no way to tell. So a connector cannot
return assets without also returning what it looked at, what it could not reach,
which permissions it used and whether pagination completed. Not by convention --
the constructor refuses.

`test_an_inventory_cannot_be_built_without_coverage` is that rule. Documentation
saying "connectors should report coverage" produces connectors that do not.

UNREACHABLE IS NOT EMPTY
------------------------
A namespace that returned 403 and a namespace containing nothing are the same
length list and completely different facts. `unreachable` keeps them apart, and
`is_partial` is true whenever anything could not be read -- so a caller cannot
accidentally treat a half-scan as a scan.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

__all__ = [
    "AssetInventory",
    "AssetKind",
    "AssetRecord",
    "DiscoveryCoverage",
    "Unreachable",
]


class AssetKind(str, Enum):
    """The normalised types. One member per thing an operator asks about.

    Deliberately closed. A connector that meets something outside this list maps
    it to the nearest member and says so in `native_type`, rather than inventing
    a category -- because a vocabulary anyone can extend at discovery time stops
    being a vocabulary and the cross-connector question becomes unanswerable
    again.
    """

    HUMAN_PRINCIPAL = "human_principal"
    AGENT = "agent"
    AGENT_RUNTIME = "agent_runtime"
    MODEL = "model"
    MCP_SERVER = "mcp_server"
    MCP_TOOL = "mcp_tool"
    SKILL = "skill"
    CREDENTIAL = "credential"
    SERVICE_ACCOUNT = "service_account"
    CLOUD_ROLE = "cloud_role"
    DATABASE = "database"
    REPOSITORY = "repository"
    API = "api"
    SAAS_APPLICATION = "saas_application"
    ENVIRONMENT = "environment"
    DATA_ASSET = "data_asset"
    RESOURCE = "resource"


@dataclass(frozen=True, slots=True)
class Unreachable:
    """Something the connector was asked to look at and could not.

    `reason` is required. "We could not read namespace prod" is actionable;
    "coverage was partial" is not, and a partial-scan marker without the reason
    is a shrug wearing a data structure.
    """

    target: str
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {"target": self.target, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class DiscoveryCoverage:
    """What was looked at, so a count means something.

    `examined` is the DENOMINATOR: the number of things inspected, of which the
    returned assets are a subset. Without it "found 3 agents" is a number with
    no scale -- three out of five is a finding, three out of four thousand is a
    scan that barely ran.
    """

    #: What the connector was pointed at: namespaces, accounts, organisations.
    scope: tuple[str, ...]
    #: Objects inspected, whether or not they became assets.
    examined: int = 0
    unreachable: tuple[Unreachable, ...] = ()
    #: The permissions actually used. An operator reviewing a connector needs to
    #: know what it asked for, not what its documentation says it might ask for.
    permissions_used: tuple[str, ...] = ()
    retrieved_at: str = ""
    #: False when a listing was truncated and not followed. A connector that
    #: stopped at the first page and did not say so reports a subset as a total.
    pagination_complete: bool = True

    @property
    def is_partial(self) -> bool:
        return bool(self.unreachable) or not self.pagination_complete

    def as_dict(self) -> dict[str, Any]:
        return {
            "scope": list(self.scope),
            "examined": self.examined,
            "unreachable": [u.as_dict() for u in self.unreachable],
            "permissions_used": list(self.permissions_used),
            "retrieved_at": self.retrieved_at,
            "pagination_complete": self.pagination_complete,
            "is_partial": self.is_partial,
        }


@dataclass(frozen=True, slots=True)
class AssetRecord:
    """One discovered thing, in the shared vocabulary.

    `native_type` is kept alongside `kind` rather than discarded. The normalised
    kind is what makes cross-connector questions answerable; the native type is
    what lets somebody find the thing again in the console it came from, and
    throwing it away makes every finding one step harder to act on.
    """

    kind: AssetKind
    identifier: str
    source: str
    native_type: str = ""
    display_name: str = ""
    environment: str = ""
    #: Identifiers of assets this one can act as or reach. Edges, not a graph:
    #: assembling the graph is `effective_permissions`' job, and a connector
    #: that built one would be deciding reachability from a single vantage.
    relates_to: tuple[str, ...] = ()
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.identifier.strip():
            raise ValueError(
                f"a {self.kind.value} with no identifier cannot be referred to, "
                "correlated or acted on; refusing to record one"
            )
        if not self.source.strip():
            raise ValueError(
                f"asset {self.identifier!r} has no source connector. An asset "
                "nobody can attribute to a scan is one nobody can re-check."
            )

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "identifier": self.identifier,
            "source": self.source,
            "native_type": self.native_type,
            "display_name": self.display_name,
            "environment": self.environment,
            "relates_to": list(self.relates_to),
            "attributes": dict(self.attributes),
        }


@dataclass(frozen=True, slots=True)
class AssetInventory:
    """What one connector found, and what it looked at to find it.

    Coverage is a REQUIRED constructor argument. A connector cannot return
    assets without saying what it scanned, which is the difference between
    discovery and a claim.
    """

    connector: str
    assets: tuple[AssetRecord, ...]
    coverage: DiscoveryCoverage

    limits: str = field(
        default=(
            "A connector sees what its credential can list, in the scope it was "
            "given. Absence from this inventory is NOT evidence that nothing is "
            "there: read `coverage.scope`, `coverage.unreachable` and "
            "`coverage.pagination_complete` before treating a count as a total."
        ),
        compare=False,
    )

    def __post_init__(self) -> None:
        if not isinstance(self.coverage, DiscoveryCoverage):
            raise TypeError(
                "an inventory without coverage is a count with no denominator. "
                "'We found 3 agents' reads identically whether one namespace was "
                "scanned or forty, and the reader cannot tell which."
            )

    def by_kind(self, kind: AssetKind) -> tuple[AssetRecord, ...]:
        return tuple(a for a in self.assets if a.kind is kind)

    @property
    def kinds(self) -> tuple[AssetKind, ...]:
        return tuple(sorted({a.kind for a in self.assets}, key=lambda k: k.value))

    def as_dict(self) -> dict[str, Any]:
        return {
            "connector": self.connector,
            "found": len(self.assets),
            "coverage": self.coverage.as_dict(),
            "kinds": [k.value for k in self.kinds],
            "assets": [a.as_dict() for a in self.assets],
            "limits": self.limits,
        }


def merge(inventories: Sequence[AssetInventory]) -> dict[str, Any]:
    """Combine several connectors' results WITHOUT losing their coverage.

    Deliberately returns a document rather than another `AssetInventory`: a
    merged inventory would need one coverage figure for several different
    scopes, and the only honest way to summarise "we scanned two namespaces and
    could not reach a third AWS account" is to keep them apart.

    `partial_sources` is surfaced at the top so a reader sees which connectors
    returned an incomplete picture before reading any total.
    """
    return {
        "connectors": [i.connector for i in inventories],
        "total_found": sum(len(i.assets) for i in inventories),
        "partial_sources": [i.connector for i in inventories if i.coverage.is_partial],
        "by_connector": [i.as_dict() for i in inventories],
        "limits": (
            "Totals across connectors are sums of independently-scoped scans. A "
            "connector listed in `partial_sources` returned an incomplete "
            "picture, so the total is a floor, never a census."
        ),
    }
