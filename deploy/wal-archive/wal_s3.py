#!/usr/bin/env python3
"""PostgreSQL `archive_command`/`restore_command` against S3-compatible storage.

WHY THIS EXISTS
---------------
`docker-compose.yml` archives WAL to `pgwalarchive`, a named Docker volume. That
volume is a directory on the same host, and usually the same physical disk, as
`pgdata`. Losing the database node loses both, which means the archive cannot
recover from the one failure it exists to recover from.
`docs/PRODUCTION_READINESS_REPORT.md` carries that as a `fail` row:
"WAL archive survives loss of the database node".

This script is the documented, working path off that host. It reuses
`S3ObjectStore` -- the same adapter the evidence blob store uses, and the same
one `tests_arch/test_persistence_storage_cache.py::test_live_minio_object_store_round_trips`
exercises against a real MinIO -- so the archive path is not a second, less-tested
implementation of the same protocol.

CONTRACT WITH POSTGRESQL, AND WHY EACH PART MATTERS
----------------------------------------------------
* **Exit 0 means archived and durable.** PostgreSQL is entitled to recycle a
  segment the moment `archive_command` exits 0. Exiting 0 on a partial or
  unverified upload deletes the only other copy of committed transactions.
  So `archive` re-reads the object and compares the SHA-256 before exiting 0.
* **Never overwrite an existing segment.** The manual requires it, and the
  reason is specific: after a timeline change a DIFFERENT segment can be
  presented under a name already in the archive, and clobbering it destroys the
  recovery source for the earlier timeline. `archive` refuses with exit 1 unless
  the stored object is byte-identical, in which case the write is a retry of one
  that already succeeded and exiting 0 is correct.
* **`restore_command` must exit non-zero for a MISSING segment.** That is not an
  error; it is how PostgreSQL learns it has reached the end of the archive and
  should stop replaying. Distinguishing "absent" (exit 1, quiet) from "could not
  reach the store" (exit 2, loud) is the difference between finishing recovery
  and truncating it silently at the first network blip.

KEY LAYOUT
----------
`<cluster>/wal/<segment>` -- `BlobKey`'s three segments, with the cluster id in
the tenant position. WAL is cluster-scoped, not tenant-scoped, so the first
segment is the cluster identifier: it keeps two clusters archiving to one bucket
from colliding, and it is a prefix an IAM policy can be written against.

USAGE (postgresql.conf)
-----------------------
    archive_mode = on
    archive_timeout = 60s
    archive_command = 'python3 /opt/sentinel/wal_s3.py archive %p %f'
    restore_command = 'python3 /opt/sentinel/wal_s3.py restore %f %p'

Configuration comes from the environment, never from the command line, because
`archive_command` ends up in `pg_settings` and in every `SHOW archive_command`:

    SENTINEL_WAL_S3_ENDPOINT     e.g. https://s3.eu-west-1.amazonaws.com
    SENTINEL_WAL_S3_BUCKET
    SENTINEL_WAL_S3_ACCESS_KEY
    SENTINEL_WAL_S3_SECRET_KEY
    SENTINEL_WAL_S3_REGION       default us-east-1
    SENTINEL_WAL_S3_CLUSTER      default "sentinel"; the key prefix
    SENTINEL_WAL_S3_ALLOW_PRIVATE  "true" only for in-cluster or local MinIO
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

#: Exit codes PostgreSQL distinguishes. Named, because `sys.exit(1)` and
#: `sys.exit(2)` at four call sites is how the missing/unreachable distinction
#: gets lost in a later edit.
OK = 0
SEGMENT_ABSENT = 1
STORE_UNREACHABLE = 2


def _store():
    """Build the S3 adapter from the environment, or fail loudly."""
    # Imported here rather than at module scope so `--help`-shaped invocations
    # and a missing PYTHONPATH produce a readable message instead of a traceback
    # in the PostgreSQL log, where it would appear once per segment.
    from sentinel.infrastructure.outbound import HardenedHttpClient, OutboundPolicy
    from sentinel.infrastructure.persistence.objectstore import (
        S3Credentials,
        S3ObjectStore,
    )

    endpoint = os.environ.get("SENTINEL_WAL_S3_ENDPOINT", "").strip()
    bucket = os.environ.get("SENTINEL_WAL_S3_BUCKET", "").strip()
    access = os.environ.get("SENTINEL_WAL_S3_ACCESS_KEY", "").strip()
    secret = os.environ.get("SENTINEL_WAL_S3_SECRET_KEY", "").strip()
    missing = [
        name
        for name, value in (
            ("SENTINEL_WAL_S3_ENDPOINT", endpoint),
            ("SENTINEL_WAL_S3_BUCKET", bucket),
            ("SENTINEL_WAL_S3_ACCESS_KEY", access),
            ("SENTINEL_WAL_S3_SECRET_KEY", secret),
        )
        if not value
    ]
    if missing:
        raise SystemExit(
            f"wal_s3: not configured; missing {', '.join(missing)}. Refusing to "
            "exit 0, because PostgreSQL would then recycle an unarchived segment."
        )

    parsed = urlparse(endpoint)
    allow_private = os.environ.get(
        "SENTINEL_WAL_S3_ALLOW_PRIVATE", ""
    ).strip().lower() in {"1", "true", "yes", "on"}
    policy = OutboundPolicy(
        allowed_schemes=frozenset({parsed.scheme or "https", "https"}),
        allow_private_destinations=allow_private,
        allowed_hosts=frozenset({parsed.hostname or ""}) if parsed.hostname else frozenset(),
        read_timeout_seconds=60.0,
        # A WAL segment is 16 MB by default; `wal_segment_size` can raise it.
        max_response_bytes=256 * 1024 * 1024,
    )
    return S3ObjectStore(
        bucket=bucket,
        credentials=S3Credentials(
            access, secret, region=os.environ.get("SENTINEL_WAL_S3_REGION", "us-east-1")
        ),
        endpoint=endpoint.rstrip("/"),
        client=HardenedHttpClient(policy=policy),
    )


def _key(segment: str):
    from sentinel.infrastructure.persistence.objectstore import BlobKey

    cluster = os.environ.get("SENTINEL_WAL_S3_CLUSTER", "sentinel").strip() or "sentinel"
    return BlobKey(tenant_id=cluster, kind="wal", identifier=segment)


def archive(source: str, segment: str) -> int:
    """Upload one completed segment. Exit 0 ONLY once it is verifiably stored."""
    from sentinel.infrastructure.persistence.objectstore import BlobMissing

    payload = Path(source).read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    store = _store()
    key = _key(segment)

    try:
        existing = store.get(key)
    except BlobMissing:
        existing = None
    except Exception as exc:  # noqa: BLE001 - unreachable store, not a missing key
        print(f"wal_s3: cannot reach the archive to check {segment}: {exc}", file=sys.stderr)
        return STORE_UNREACHABLE

    if existing is not None:
        if hashlib.sha256(existing).hexdigest() == digest:
            # A retry of an upload that already succeeded. Exiting 0 is correct
            # and is not an overwrite.
            return OK
        print(
            f"wal_s3: REFUSING to overwrite {segment}; the archive holds different "
            "bytes under that name. Overwriting an archived segment destroys the "
            "recovery source for the timeline that produced it.",
            file=sys.stderr,
        )
        return SEGMENT_ABSENT

    try:
        store.put(key, payload)
    except Exception as exc:  # noqa: BLE001
        print(f"wal_s3: upload of {segment} failed: {exc}", file=sys.stderr)
        return STORE_UNREACHABLE

    # Read back before reporting success. PostgreSQL may recycle the segment the
    # instant this exits 0, so "the PUT returned 200" is not a strong enough
    # claim to delete the only other copy on.
    try:
        stored = store.get(key)
    except Exception as exc:  # noqa: BLE001
        print(f"wal_s3: {segment} uploaded but could not be read back: {exc}", file=sys.stderr)
        return STORE_UNREACHABLE
    if hashlib.sha256(stored).hexdigest() != digest:
        print(
            f"wal_s3: {segment} read back with a different digest; the archive is "
            "not a faithful copy and this segment is NOT safe to recycle.",
            file=sys.stderr,
        )
        return STORE_UNREACHABLE
    return OK


def restore(segment: str, destination: str) -> int:
    """Fetch one segment during recovery.

    Exit 1 for a segment that is not there -- that is PostgreSQL's signal that
    the archive is exhausted and recovery should end. Exit 2 for anything else,
    so a transport failure never gets read as "end of archive", which would
    truncate recovery early and silently lose every commit after that point.
    """
    from sentinel.infrastructure.persistence.objectstore import BlobMissing

    try:
        store = _store()
        payload = store.get(_key(segment))
    except BlobMissing:
        return SEGMENT_ABSENT
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        print(f"wal_s3: could not fetch {segment}: {exc}", file=sys.stderr)
        return STORE_UNREACHABLE

    target = Path(destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    # Write beside the target and rename: a partially-written segment under its
    # real name is indistinguishable from a complete one and would be replayed.
    staging = target.with_suffix(target.suffix + ".part")
    staging.write_bytes(payload)
    os.replace(staging, target)
    return OK


def main(argv: list[str]) -> int:
    if len(argv) != 4 or argv[1] not in {"archive", "restore"}:
        print(
            "usage: wal_s3.py archive <path-to-segment> <segment-name>\n"
            "       wal_s3.py restore <segment-name> <destination-path>",
            file=sys.stderr,
        )
        return STORE_UNREACHABLE
    if argv[1] == "archive":
        return archive(argv[2], argv[3])
    return restore(argv[2], argv[3])


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
