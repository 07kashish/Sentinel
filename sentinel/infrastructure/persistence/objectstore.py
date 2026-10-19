"""Object storage for evidence bodies too large to live in a row.

WHY BODIES LEAVE THE DATABASE
------------------------------
An evidence body can be megabytes of captured payload. PostgreSQL will store it
out of line and compress it, which works -- but the row is on the path of every
incident read, TOAST fetches are extra random I/O, and the whole thing lands in
every base backup and every WAL segment. A one-megabyte evidence body written
once is a megabyte in the backup, a megabyte of WAL, and a megabyte replicated to
every replica.

So the row keeps the DIGEST and the KEY; the bytes go to object storage. The
commitment stays in the database, where it is cheap and transactional, and the
payload goes where bulk belongs.

WHAT STAYS TRANSACTIONAL, AND WHAT CANNOT
------------------------------------------
Object storage is not in the database transaction. That gap is real and is
handled by ORDERING rather than pretended away:

    write blob  ->  commit row referencing it

A crash between the two leaves an ORPHANED BLOB: bytes nobody references. That is
wasted space, reclaimed by a sweep. The reverse ordering would leave a DANGLING
REFERENCE: a row promising evidence that does not exist -- unrecoverable, and
exactly the "asserts an artifact it does not have" defect this architecture is
organised against. Wasting bytes is always the right side of that trade.

Deletion is the same, inverted: delete the row first, sweep the blob later.

TWO ADAPTERS, BOTH REAL
-----------------------
`FilesystemObjectStore` is not a test stub. A mounted volume -- EBS, EFS, NFS, a
PVC -- is a legitimate production target, and for a single-region deployment it is
often the right one. It writes to a temporary name and renames, because `rename`
within a filesystem is atomic and a partially-written blob that is visible under
its real key is indistinguishable from a complete one.

`S3ObjectStore` speaks S3 over the standard library with SigV4 signing, so it
works against AWS, MinIO, R2 or Ceph without a vendor SDK. The signing is the
only hard part and is verified against AWS's own published test vectors.

WHAT IS NOT VERIFIED
--------------------
No request from `S3ObjectStore` has ever reached a real endpoint. The signature is
proven against AWS's vectors and the error handling is proven against constructed
responses, but the round trip -- redirects, regional endpoints, the exact shape of
a real `ListObjectsV2` continuation, IAM denials that arrive as 403 rather than
404 -- is not. Treat the first deployment against real object storage as the test,
and run it against a scratch bucket before anything depends on it.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import shutil
import tempfile
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Mapping, Protocol, runtime_checkable

from sentinel.domain.errors import SentinelError, TransientFailure
from sentinel.domain.primitives import InvalidValue
from sentinel.infrastructure.outbound import (
    HardenedHttpClient,
    OutboundPolicy,
    OutboundRefused,
    OutboundUnavailable,
    inspect_url,
)

__all__ = [
    "BlobKey",
    "BlobMissing",
    "FilesystemObjectStore",
    "ObjectStore",
    "S3Credentials",
    "S3ObjectStore",
    "sigv4_signature",
]


class BlobMissing(SentinelError):
    """A blob a row references does not exist. Never retried: it is not coming."""

    is_retryable = False


@dataclass(frozen=True, slots=True)
class BlobKey:
    """Where a blob lives. Tenant-prefixed, so isolation survives the storage.

    The tenant is the FIRST path segment. Object stores have no row-level
    security, so isolation there is a prefix convention plus an IAM policy scoped
    to it -- and a key that buries the tenant in the middle cannot be expressed
    as a prefix policy.
    """

    tenant_id: str
    kind: str
    identifier: str

    def __post_init__(self) -> None:
        for name, value in (
            ("tenant_id", self.tenant_id),
            ("kind", self.kind),
            ("identifier", self.identifier),
        ):
            if not value or "/" in value or ".." in value:
                raise BlobMissing(
                    f"blob key {name}={value!r} is empty or contains a path "
                    "separator. A key that can traverse is a key that can read "
                    "another tenant's bytes."
                )

    @property
    def path(self) -> str:
        return f"{self.tenant_id}/{self.kind}/{self.identifier}"

    @classmethod
    def parse(cls, path: str) -> "BlobKey":
        parts = path.split("/")
        if len(parts) != 3:
            raise BlobMissing(f"blob path {path!r} does not have 3 segments")
        return cls(tenant_id=parts[0], kind=parts[1], identifier=parts[2])

    def __str__(self) -> str:
        return self.path


@runtime_checkable
class ObjectStore(Protocol):
    """Content storage outside the database transaction."""

    def put(self, key: BlobKey, data: bytes) -> str:
        """Store bytes. Returns the digest, so the caller can record it.

        Idempotent by key: writing the same key twice is not an error, because a
        retried write after an ambiguous failure must be safe.
        """
        ...

    def get(self, key: BlobKey) -> bytes:
        """Fetch bytes. Raises `BlobMissing` if absent."""
        ...

    def exists(self, key: BlobKey) -> bool: ...

    def delete(self, key: BlobKey) -> bool:
        """Remove a blob. False if it was already gone. Idempotent."""
        ...

    def list_prefix(self, *, tenant_id: str, kind: str) -> Iterator[BlobKey]:
        """Enumerate one tenant's blobs of one kind. Used by the orphan sweep."""
        ...


class FilesystemObjectStore:
    """A mounted volume. Production-valid, not a stand-in."""

    __slots__ = ("_root",)

    def __init__(self, root: Path) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def _resolve(self, key: BlobKey) -> Path:
        target = (self._root / key.path).resolve()
        root = self._root.resolve()
        # Belt and braces over BlobKey's own validation: even if a future key type
        # relaxed its rules, a path escaping the root is refused here.
        if not str(target).startswith(str(root)):
            raise BlobMissing(f"blob key {key} resolves outside the store root")
        return target

    def put(self, key: BlobKey, data: bytes) -> str:
        target = self._resolve(key)
        target.parent.mkdir(parents=True, exist_ok=True)
        # Write to a temporary name in the SAME directory, then rename. Rename
        # within a filesystem is atomic, so a reader never sees a partial blob
        # under its real key -- which would be indistinguishable from a complete
        # one and would fail its digest check much later, somewhere unhelpful.
        handle, temporary = tempfile.mkstemp(dir=str(target.parent), suffix=".partial")
        try:
            with os.fdopen(handle, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise
        return hashlib.sha256(data).hexdigest()

    def get(self, key: BlobKey) -> bytes:
        target = self._resolve(key)
        try:
            return target.read_bytes()
        except FileNotFoundError as exc:
            raise BlobMissing(f"no blob at {key}") from exc
        except OSError as exc:
            raise TransientFailure(f"could not read blob {key}: {exc}") from exc

    def exists(self, key: BlobKey) -> bool:
        return self._resolve(key).is_file()

    def delete(self, key: BlobKey) -> bool:
        try:
            self._resolve(key).unlink()
            return True
        except FileNotFoundError:
            return False

    def list_prefix(self, *, tenant_id: str, kind: str) -> Iterator[BlobKey]:
        directory = self._root / tenant_id / kind
        if not directory.is_dir():
            return
        for entry in sorted(directory.iterdir()):
            if entry.is_file() and not entry.name.endswith(".partial"):
                yield BlobKey(tenant_id=tenant_id, kind=kind, identifier=entry.name)

    def clear(self) -> None:
        """Remove everything. For tests and for a decommission."""
        shutil.rmtree(self._root, ignore_errors=True)
        self._root.mkdir(parents=True, exist_ok=True)


# ── S3 ───────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class S3Credentials:
    access_key_id: str
    secret_access_key: str
    region: str = "us-east-1"
    session_token: str | None = None


def sigv4_signature(
    *,
    secret_key: str,
    date_stamp: str,
    region: str,
    service: str,
    string_to_sign: str,
) -> str:
    """AWS Signature Version 4, as a pure function.

    Extracted and pure so it can be checked against AWS's published test vectors
    without a network, a bucket, or credentials. Signing is the only part of the
    S3 protocol that is easy to get subtly wrong and impossible to debug from the
    error -- `SignatureDoesNotMatch` says nothing about which of the four
    derivation steps was wrong.
    """

    def sign(key: bytes, message: str) -> bytes:
        return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()

    date_key = sign(f"AWS4{secret_key}".encode("utf-8"), date_stamp)
    region_key = sign(date_key, region)
    service_key = sign(region_key, service)
    signing_key = sign(service_key, "aws4_request")
    return hmac.new(
        signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()


class S3ObjectStore:
    """S3-compatible storage over the standard library.

    No vendor SDK. `boto3` pulls in botocore and a bundled CA set for what is,
    here, four HTTP verbs and a signature -- and every dependency in the runtime
    image is dependency-audit and container-scan surface for code that could be
    this file instead.

    Works against AWS, MinIO, Cloudflare R2 and Ceph, because all of them speak
    the same signed REST interface.
    """

    __slots__ = ("_bucket", "_endpoint", "_credentials", "_client")

    def __init__(
        self,
        *,
        bucket: str,
        credentials: S3Credentials,
        endpoint: str = "https://s3.amazonaws.com",
        timeout: float = 30.0,
        client: HardenedHttpClient | None = None,
    ) -> None:
        self._client = client or HardenedHttpClient(
            policy=OutboundPolicy(
                read_timeout_seconds=timeout,
                # Blobs are evidence bundles, not media. Generous, still bounded.
                max_response_bytes=64 * 1024 * 1024,
            )
        )
        try:
            inspect_url(endpoint, self._client.policy)
        except OutboundRefused as exc:
            raise InvalidValue(f"the object-store endpoint is not callable: {exc}") from exc
        self._bucket = bucket
        self._endpoint = endpoint.rstrip("/")
        self._credentials = credentials

    # ── Protocol ─────────────────────────────────────────────────────────────

    def put(self, key: BlobKey, data: bytes) -> str:
        self._request("PUT", key.path, body=data)
        return hashlib.sha256(data).hexdigest()

    def get(self, key: BlobKey) -> bytes:
        try:
            return self._request("GET", key.path)
        except BlobMissing:
            raise
        except TransientFailure:
            raise

    def exists(self, key: BlobKey) -> bool:
        try:
            self._request("HEAD", key.path)
            return True
        except BlobMissing:
            return False

    def delete(self, key: BlobKey) -> bool:
        try:
            self._request("DELETE", key.path)
            return True
        except BlobMissing:
            return False

    def list_prefix(self, *, tenant_id: str, kind: str) -> Iterator[BlobKey]:
        """List by prefix, following continuation tokens.

        A single ListObjectsV2 returns at most 1000 keys. Ignoring the
        continuation token gives a sweep that silently stops at 1000 and reports
        success -- which for an orphan sweep means it never reclaims anything past
        the first page.
        """
        import re

        prefix = f"{tenant_id}/{kind}/"
        token: str | None = None
        while True:
            query = {"list-type": "2", "prefix": prefix, "max-keys": "1000"}
            if token:
                query["continuation-token"] = token
            body = self._request("GET", "", query=query).decode("utf-8")
            for match in re.finditer(r"<Key>([^<]+)</Key>", body):
                yield BlobKey.parse(match.group(1))
            truncated = "<IsTruncated>true</IsTruncated>" in body
            if not truncated:
                return
            next_token = re.search(r"<NextContinuationToken>([^<]+)<", body)
            if not next_token:
                return
            token = urllib.parse.unquote(next_token.group(1))

    # ── Signing and transport ────────────────────────────────────────────────

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: bytes = b"",
        query: Mapping[str, str] | None = None,
    ) -> bytes:
        now = datetime.now(timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")
        host = urllib.parse.urlparse(self._endpoint).netloc

        canonical_uri = "/" + urllib.parse.quote(
            f"{self._bucket}/{path}".rstrip("/"), safe="/"
        )
        canonical_query = "&".join(
            f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}"
            for k, v in sorted((query or {}).items())
        )
        payload_hash = hashlib.sha256(body).hexdigest()

        headers = {
            "host": host,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz_date,
        }
        if self._credentials.session_token:
            headers["x-amz-security-token"] = self._credentials.session_token

        signed_headers = ";".join(sorted(headers))
        canonical_headers = "".join(f"{k}:{headers[k]}\n" for k in sorted(headers))
        canonical_request = "\n".join(
            (
                method,
                canonical_uri,
                canonical_query,
                canonical_headers,
                signed_headers,
                payload_hash,
            )
        )
        scope = f"{date_stamp}/{self._credentials.region}/s3/aws4_request"
        string_to_sign = "\n".join(
            (
                "AWS4-HMAC-SHA256",
                amz_date,
                scope,
                hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
            )
        )
        signature = sigv4_signature(
            secret_key=self._credentials.secret_access_key,
            date_stamp=date_stamp,
            region=self._credentials.region,
            service="s3",
            string_to_sign=string_to_sign,
        )
        headers["authorization"] = (
            f"AWS4-HMAC-SHA256 Credential={self._credentials.access_key_id}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )

        url = f"{self._endpoint}{canonical_uri}"
        if canonical_query:
            url += f"?{canonical_query}"

        # Host is required in the SigV4 canonical request, but HardenedHttpClient
        # forbids callers from setting it (the client computes Host from the URL).
        # Strip it from the wire headers while keeping it in the signed scope.
        wire_headers = {
            name: value for name, value in headers.items() if name.lower() != "host"
        }

        # Through the hardened client, never `urlopen`. S3 answers 307 on a region
        # mismatch, and urllib would follow it while re-sending this request's
        # `Authorization` header -- a signed, replayable credential -- to whatever
        # the redirect names. Refusing the redirect turns a silent credential
        # forward into an operator-visible "use the regional endpoint" error.
        try:
            response = self._client.request(
                method=method,
                url=url,
                body=body or None,
                headers=wire_headers,
                idempotent=method in ("GET", "HEAD"),
            )
        except OutboundRefused as exc:
            raise TransientFailure(f"S3 {method} {path} refused: {exc}") from exc
        except OutboundUnavailable as exc:
            raise TransientFailure(f"S3 {method} {path} failed: {exc}") from exc

        if response.status in (403, 404):
            # 403 is included deliberately: a bucket policy that denies
            # ListBucket returns 403 for a missing key rather than 404, so
            # treating only 404 as absent makes `exists` wrong on a correctly
            # locked-down bucket.
            raise BlobMissing(f"no blob at {path} (HTTP {response.status})")
        if response.status >= 400:
            raise TransientFailure(
                f"S3 {method} {path} failed with HTTP {response.status}: "
                f"{response.body[:200]!r}"
            )
        return response.body
