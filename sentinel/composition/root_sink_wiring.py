"""Build the transparency root sink from settings. Refusing unless configured."""

from __future__ import annotations

from sentinel.composition.settings import Settings
from sentinel.domain.root_sink import RefusingRootSink, RootSink
from sentinel.infrastructure.aws_container_credentials import ContainerCredentialSource
from sentinel.infrastructure.s3_root_sink import S3ObjectLockRootSink, S3SinkConfig

__all__ = ["build_root_sink"]


def build_root_sink(settings: Settings) -> RootSink:
    """The S3 Object Lock sink when a bucket is named; otherwise a sink that refuses.

    Refuses rather than writes to local disk: a root on a disk the operator
    owns would set `independently_verifiable` while proving nothing, and that
    flag is the only thing separating evidence from an assertion.
    """
    if not settings.root_sink.configured:
        return RefusingRootSink(
            reason=(
                "no root sink is configured: set SENTINEL_S3_ROOT_BUCKET (and "
                "region and credentials) to publish roots beyond the operator's reach"
            )
        )
    sink = settings.root_sink
    # A static key when one is configured; otherwise the task role, reached
    # through the container credential endpoint the ECS agent exposes. With
    # neither, the sink REFUSES loudly every interval rather than the service
    # dying at boot: the first Fargate deployment crash-looped here.
    source = None
    if not sink.access_key_id:
        if not sink.container_credentials_uri:
            return RefusingRootSink(
                reason=(
                    f"root sink bucket {sink.bucket!r} is configured with no credential: set "
                    "SENTINEL_S3_ROOT_ACCESS_KEY_ID and its secret, or run under an ECS task role"
                )
            )
        source = ContainerCredentialSource(sink.container_credentials_uri, authorization=sink.container_authorization)
    config = S3SinkConfig(
        bucket=sink.bucket,
        region=sink.region,
        access_key_id=sink.access_key_id,
        secret_access_key=sink.secret_access_key,
        session_token=sink.session_token,
        retention_days=sink.retention_days,
        credentials=source,
    )
    return S3ObjectLockRootSink(config=config)
