"""`evidence-reseal`: bring every evidence body under the active data key.

Run it once after configuring `SENTINEL_DATA_KEY_<id>` for the first time, to
seal the bodies written before that, and again after each key rotation, to
rewrap sealed bodies under the new key. Rotation rewraps the per-record data
key only; payloads are never decrypted. It is idempotent and works in batches,
so it can be interrupted and re-run. The retired key must stay configured
until a run reports nothing left to do, then it can be removed.
"""

from __future__ import annotations

from typing import Sequence, TextIO

from sentinel.composition.container import build_container
from sentinel.composition.settings import Settings
from sentinel.domain.primitives import TenantId

__all__ = ["evidence_reseal_command"]


def evidence_reseal_command(rest: Sequence[str], *, settings: Settings, stream: TextIO) -> int:
    if len(rest) != 1:
        stream.write("usage: evidence-reseal <tenant>\n")
        return 64
    if not settings.workflow.evidence_keys:
        stream.write("no data key is configured (SENTINEL_DATA_KEY_<id>, SENTINEL_ACTIVE_KEY_ID); nothing to do\n")
        return 78
    container = build_container(settings)
    try:
        total = 0
        while True:
            with container.uow_factory.begin(TenantId(rest[0])) as uow:
                changed = uow.ledger.reseal_evidence(limit=500)
                uow.commit()
            total += changed
            if changed == 0:
                break
        stream.write(f"{total} evidence bodies sealed or rewrapped under key "
                     f"{settings.workflow.evidence_active_key!r} for tenant {rest[0]!r}\n")
        return 0
    finally:
        container.close()
