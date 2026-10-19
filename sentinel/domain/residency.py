"""Where a tenant's data is allowed to live, and how long it stays.

    §79  US / EU / India / customer-managed
         Do not centralize tenant data in ways that prevent regional deployment.
    §78  events: 30/90/365 days · incidents: 1-7 years · raw payloads and
         evidence: configurable. Support deletion requirements while preserving
         authorized audit evidence where legally appropriate.

RESIDENCY IS AN ARCHITECTURAL CONSTRAINT, NOT A FIELD
-------------------------------------------------------
Storing a region string on a tenant is easy and proves nothing. What the
requirement actually asks is that no code path *needs* to see every tenant at
once, because such a path is what makes regional deployment impossible: it
forces one database that holds every region's data, and that database can only
be in one place.

So the useful artifact here is not the enum. It is `assert_no_cross_region_read`
and the fitness function that uses it. `Region` exists so a deployment can
declare what it is; the check exists so a deployment cannot quietly stop being
able to split.

The design already helps: every table is tenant-scoped with FORCE ROW LEVEL
SECURITY and every repository takes a `TenantId`. This module makes that
property named and testable instead of incidental.

RETENTION AND DELETION PULL AGAINST EACH OTHER, ON PURPOSE
------------------------------------------------------------
"Support deletion requirements while preserving authorized audit evidence" is
two obligations that genuinely conflict, and pretending otherwise produces a
product that fails one of them silently.

`RetentionPolicy` therefore separates *what a tenant may configure* from *what
the system will not delete regardless*. A tenant can set events to 30 days. A
tenant cannot set the hash-chained audit trail to 30 days, because deleting from
it breaks verification of everything after it -- and a compliance feature that
destroys the evidence chain is not the feature anybody wanted.

When those conflict, this module answers with a refusal that names the reason,
rather than picking one and staying quiet.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Final, Mapping

from sentinel.domain.errors import DomainRuleViolated

__all__ = [
    "CrossRegionAccess",
    "InvalidRetention",
    "IMMUTABLE_CLASSES",
    "Region",
    "RetentionPolicy",
    "assert_no_cross_region_read",
]


class CrossRegionAccess(DomainRuleViolated):
    """An operation tried to span regions.

    Raised rather than filtered. Silently returning the reachable subset would
    give a caller a partial answer they would reasonably treat as complete --
    and "the report showed 4 of 7 regions and said nothing" is worse than an
    error.
    """

    is_retryable = False


class InvalidRetention(DomainRuleViolated):
    """A retention setting that is outside bounds or would destroy evidence."""

    is_retryable = False


class Region(str, Enum):
    """Where a tenant's data physically lives.

    A closed set, so a typo is a startup failure rather than a tenant quietly
    assigned to a region that does not exist and therefore matches nothing.
    """

    US = "us"
    EU = "eu"
    INDIA = "in"
    #: The customer runs the deployment. Sentinel holds nothing, so residency is
    #: whatever the customer's own infrastructure is -- and that is precisely why
    #: it is a distinct value rather than an absence.
    CUSTOMER_MANAGED = "customer"


def assert_no_cross_region_read(*, home: Region, requested: Region) -> None:
    """Refuse a read that would cross a residency boundary.

    Called on any path that resolves data for a tenant in a named region. The
    check is trivial; its value is that it exists at a boundary, so a future
    aggregate query has to argue with it rather than quietly work.
    """
    if home is not requested:
        raise CrossRegionAccess(
            f"data for a tenant resident in {home.value!r} may not be read from "
            f"{requested.value!r}; regional separation is a contractual "
            f"commitment, not a preference"
        )


#: Data classes that survive tenant-configured retention, and why.
#:
#: Not "things we forgot to make configurable". Each of these breaks something
#: verifiable if rows are removed from it, and the specification's own wording --
#: "while preserving authorized audit evidence where legally appropriate" --
#: anticipates exactly this list.
IMMUTABLE_CLASSES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "security_audit": (
            "Hash-chained with a dense sequence so a deleted row is detectable "
            "as a gap. Trimming it does not shorten the trail, it invalidates it."
        ),
        "ledger_entries": (
            "Every entry commits to its predecessor. Deleting one breaks "
            "verification of every entry after it. Redaction nulls the body and "
            "keeps the commitment -- that is the deletion path, and it exists."
        ),
        "ledger_batches": (
            "Merkle roots that external attestations point at. Removing a batch "
            "orphans the third-party timestamp proving when it existed."
        ),
    }
)

#: Per-class bounds. `(minimum_days, maximum_days)`.
#:
#: The maxima are the specification's own numbers. The minima are the point: a
#: tenant that sets incident retention to one day has, in effect, disabled their
#: own incident history, and they will discover it during the investigation that
#: needed it.
_BOUNDS: Final[Mapping[str, tuple[int, int]]] = MappingProxyType(
    {
        "events": (7, 365),
        "incidents": (365, 365 * 7),
        "raw_payloads": (1, 365),
        "evidence": (30, 365 * 7),
        "execution_nodes": (7, 365),
    }
)


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    """One tenant's retention configuration, validated on construction.

    Defaults are the conservative end of each range rather than the permissive
    one. A tenant that never configures retention should not silently accumulate
    seven years of raw payloads, and a default that costs money without being
    chosen is a default nobody would have picked.
    """

    tenant_id: str
    region: Region = Region.US
    events_days: int = 90
    incidents_days: int = 365
    raw_payloads_days: int = 30
    evidence_days: int = 365
    execution_nodes_days: int = 90

    def __post_init__(self) -> None:
        for name, value in self.as_days().items():
            low, high = _BOUNDS[name]
            if not low <= value <= high:
                raise InvalidRetention(
                    f"{name} retention of {value} days is outside the permitted "
                    f"{low}-{high} days for tenant {self.tenant_id!r}"
                )
        if self.raw_payloads_days > self.events_days:
            # A payload outliving the event that references it is an orphan
            # nothing can interpret, and it is the most sensitive thing stored.
            raise InvalidRetention(
                f"raw payloads ({self.raw_payloads_days}d) cannot be kept longer "
                f"than the events that reference them ({self.events_days}d)"
            )

    def as_days(self) -> dict[str, int]:
        return {
            "events": self.events_days,
            "incidents": self.incidents_days,
            "raw_payloads": self.raw_payloads_days,
            "evidence": self.evidence_days,
            "execution_nodes": self.execution_nodes_days,
        }

    def days_for(self, data_class: str) -> int:
        """How long one class is kept, refusing the classes that are immutable."""
        if data_class in IMMUTABLE_CLASSES:
            raise InvalidRetention(
                f"{data_class} is not subject to tenant retention: "
                f"{IMMUTABLE_CLASSES[data_class]}"
            )
        if data_class not in _BOUNDS:
            raise InvalidRetention(f"unknown data class {data_class!r}")
        return self.as_days()[data_class]

    def as_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "region": self.region.value,
            "retention_days": self.as_days(),
            "immutable_classes": dict(IMMUTABLE_CLASSES),
        }
