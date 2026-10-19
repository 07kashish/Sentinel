"""Publish each tenant's current transparency root to the configured sink.

One function, used by two callers: the maintenance loop (daily, in-process)
and `scripts/publish_transparency_root.py` (an operator, on demand). It used
to live only in the script, which meant a deployment that never ran the cron
line served proofs whose `independently_verifiable` was false forever, and
nothing in the running service could tell.

The rules, unchanged from the script:

  * an empty log publishes nothing -- there is no root to publish;
  * a root already recorded at the current size is not re-published;
  * a sink refusal leaves the root UNPUBLISHED and is reported, never masked;
  * a publication the store refuses to record (a fork at that size) is
    reported as "published but not recorded", because the object now exists
    in the sink whether or not the store agrees.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from sentinel.domain.root_sink import RootSink, RootSinkUnavailable
from sentinel.infrastructure.sql.transparency_store import (
    SqlTransparencyStore,
    TransparencyStoreConflict,
)

__all__ = ["RootPublicationReport", "publish_roots"]


@dataclass(frozen=True, slots=True)
class RootPublicationReport:
    published: int = 0
    skipped_empty: int = 0
    skipped_current: int = 0
    failed: int = 0
    details: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "roots_published": self.published,
            "roots_skipped_empty": self.skipped_empty,
            "roots_skipped_current": self.skipped_current,
            "roots_failed": self.failed,
        }


def publish_roots(
    *,
    store: SqlTransparencyStore,
    sink: RootSink,
    tenants: Sequence[str],
) -> RootPublicationReport:
    published = skipped_empty = skipped_current = failed = 0
    details: list[str] = []
    for tenant in tenants:
        log = store.load(tenant)
        if log.size == 0:
            skipped_empty += 1
            continue
        root_hash = log.root().hex()
        already = {r.tree_size: r for r in store.published_roots(tenant)}
        existing = already.get(log.size)
        if existing is not None and existing.root_hash == root_hash:
            skipped_current += 1
            continue
        try:
            receipt = sink.publish(
                tenant_id=tenant, tree_size=log.size, root_hash=root_hash
            )
        except RootSinkUnavailable as error:
            failed += 1
            details.append(f"{tenant}: NOT published -- {error}")
            continue
        try:
            store.record_publication(
                tenant,
                tree_size=log.size,
                root_hash=root_hash,
                at=receipt.published_at,
                sink=receipt.sink,
                external_reference=receipt.reference,
            )
        except TransparencyStoreConflict as error:
            failed += 1
            details.append(f"{tenant}: PUBLISHED BUT NOT RECORDED -- {error}")
            continue
        published += 1
        details.append(
            f"{tenant}: size {log.size} published to {receipt.sink} as {receipt.reference}"
        )
    return RootPublicationReport(
        published=published,
        skipped_empty=skipped_empty,
        skipped_current=skipped_current,
        failed=failed,
        details=tuple(details),
    )
