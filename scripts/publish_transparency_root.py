"""Publish the current transparency root to its configured sink.

RUN THIS ON A SCHEDULE, NOT PER EVENT
--------------------------------------
Once a day is the sensible default. A later root already proves every earlier
one via a consistency proof, so publishing per event costs about $16/year
instead of $0.002 and buys nothing.

  # cron, 02:00 daily
  0 2 * * * cd /srv/sentinel && PYTHONPATH=. python scripts/publish_transparency_root.py

WHAT IT REFUSES TO DO
---------------------
It never records a publication it did not obtain. A receipt is what flips
`is_independently_verifiable` to True on every proof this deployment serves, so
a manufactured one would put a green tick on a root nobody can check. Every
failure path exits non-zero with the root left unpublished -- which is the
truth, and which `/v1/transparency/root` will keep reporting honestly.

It also does nothing when the root has not moved. Publishing the same tree size
twice writes a second object for no new information, and the store treats a
repeat of the SAME root as a no-op anyway.

CREDENTIALS
-----------
Read from the environment. Never logged, never placed in a URL, and stripped
from any error message before it is printed -- an operator pasting this output
into an issue must not be pasting their secret key with it.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel.composition.settings import Settings  # noqa: E402
from sentinel.domain.root_sink import (  # noqa: E402
    RefusingRootSink,
)
from sentinel.infrastructure.s3_root_sink import (  # noqa: E402
    S3ObjectLockRootSink,
    S3SinkConfig,
)
from sentinel.infrastructure.root_publication import publish_roots  # noqa: E402
from sentinel.infrastructure.sql.engine import build_engine  # noqa: E402
from sentinel.infrastructure.sql.transparency_store import (  # noqa: E402
    SqlTransparencyStore,
)


def _load_dotenv() -> None:
    """Read `.env` if present, without overriding a real environment variable.

    Deliberately tiny and dependency-free. `os.environ` wins so a value set by
    a container or a systemd unit is not silently replaced by a stale file --
    that reversal is how a deployment ends up publishing to a bucket somebody
    forgot was in their working copy.
    """
    path = ROOT / ".env"
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, _, value = stripped.partition("=")
        os.environ.setdefault(name.strip(), value.strip())


def _env_first(*names: str) -> str:
    """The first non-empty value among these variable names.

    Exists so the STANDARD AWS names work as well as the SENTINEL_-prefixed
    ones. An operator who already has AWS_ACCESS_KEY_ID set -- from a profile,
    a container role, or a .env they wrote before reading ours -- should not
    have to duplicate a secret into a second variable to use this. Duplicated
    secrets rot: one gets rotated and the other does not, and the failure looks
    like a permissions problem.

    The SENTINEL_-prefixed name wins when both are set, so a deployment can
    point the root sink at a different account from the rest of its AWS usage
    without unsetting anything.
    """
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return ""


def _sink():
    """The configured sink, or the refusing one with the reason it refuses."""
    bucket = _env_first("SENTINEL_S3_ROOT_BUCKET", "AWS_S3_ROOT_BUCKET").strip()
    if not bucket:
        return RefusingRootSink(
            reason=(
                "neither SENTINEL_S3_ROOT_BUCKET nor AWS_S3_ROOT_BUCKET is "
                "set, so no root sink is configured"
            )
        )

    try:
        config = S3SinkConfig(
            bucket=bucket,
            region=_env_first(
                "SENTINEL_S3_ROOT_REGION", "AWS_REGION", "AWS_DEFAULT_REGION"
            ),
            access_key_id=_env_first(
                "SENTINEL_S3_ROOT_ACCESS_KEY_ID", "AWS_ACCESS_KEY_ID"
            ),
            secret_access_key=_env_first(
                "SENTINEL_S3_ROOT_SECRET_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY"
            ),
            session_token=_env_first(
                "SENTINEL_S3_ROOT_SESSION_TOKEN", "AWS_SESSION_TOKEN"
            ),
            retention_days=int(
                _env_first("SENTINEL_S3_ROOT_RETENTION_DAYS") or "3650"
            ),
        )
    except ValueError as error:
        # A misconfiguration, reported as one. Falling back to the refusing
        # sink here would be right in effect and wrong in explanation: the
        # operator meant to configure this and needs to know what is missing.
        raise SystemExit(f"the S3 sink is misconfigured: {error}") from error

    return S3ObjectLockRootSink(config=config)


def main() -> int:
    _load_dotenv()

    settings = Settings.from_environment()
    pool = build_engine(settings.engine)
    store = SqlTransparencyStore(pool=pool)
    sink = _sink()

    tenants = [
        t.strip()
        for t in os.environ.get("SENTINEL_PUBLISH_TENANTS", "").split(",")
        if t.strip()
    ]
    if not tenants:
        print(
            "SENTINEL_PUBLISH_TENANTS is not set. Refusing to guess which "
            "tenants to publish: enumerating every tenant would publish roots "
            "for estates nobody asked about, and each one is irreversible "
            "under COMPLIANCE retention.",
            file=sys.stderr,
        )
        pool.close()
        return 2

    configured_bucket = _env_first(
        "SENTINEL_S3_ROOT_BUCKET", "AWS_S3_ROOT_BUCKET"
    )

    failures = 0
    stale = 0
    try:
        for tenant in tenants:
            # A ROOT PUBLISHED TO A BUCKET WE NO LONGER USE.
            #
            # Switching sinks does not unpublish anything, so the store keeps
            # reporting independently_verifiable: true for a root that lives
            # somewhere the operator may be about to delete. Once that bucket
            # goes, the flag is a green tick on an object nobody can fetch --
            # which is the precise failure every other refusal in this codebase
            # exists to prevent, arriving through the back door of a config
            # change.
            #
            # Reported per run rather than silently, and NOT auto-corrected:
            # the store cannot know whether the old bucket still exists, and
            # rewriting a publication record to say "unverifiable" would
            # destroy the evidence that it once was.
            if configured_bucket:
                for root in store.published_roots(tenant):
                    reference = root.external_reference
                    if (
                        root.sink == "s3-object-lock"
                        and reference
                        and configured_bucket not in reference
                    ):
                        stale += 1
                        print(
                            f"  {tenant}: WARNING size {root.tree_size} was "
                            f"published to a DIFFERENT bucket than the one now "
                            f"configured ({configured_bucket}). Its reference "
                            f"is {reference}. If that bucket is deleted, "
                            "/v1/transparency/root will keep reporting this "
                            "root as independently verifiable while the object "
                            "no longer exists.",
                            file=sys.stderr,
                        )

            # The publication itself is the same code the maintenance loop
            # runs daily in-process; this script is the on-demand operator path
            # to it. One implementation, so the two cannot disagree about what
            # "already published" or "not recorded" means.
            report = publish_roots(store=store, sink=sink, tenants=[tenant])
            failures += report.failed
            if report.skipped_empty:
                print(f"  {tenant}: log is empty, nothing to publish")
            if report.skipped_current:
                print(f"  {tenant}: current root already published, nothing to do")
            for line in report.details:
                stream = sys.stderr if "NOT" in line else sys.stdout
                print(f"  {line}", file=stream)
    finally:
        pool.close()

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if stale:
        print(
            f"{stamp}: {stale} root(s) point at a bucket other than "
            f"{configured_bucket}. Keep that bucket, or accept that those "
            "references will dangle -- there is no third option, because a "
            "published root cannot be un-published.",
            file=sys.stderr,
        )
    if failures:
        print(
            f"\n{stamp}: {failures} tenant(s) NOT published. Their roots stay "
            "unverifiable, and /v1/transparency/root will keep saying so.",
            file=sys.stderr,
        )
        return 1

    print(f"\n{stamp}: done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
