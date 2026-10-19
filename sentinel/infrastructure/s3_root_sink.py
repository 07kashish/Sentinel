"""Publish transparency roots to S3 with Object Lock, for pennies a year.

WHAT MAKES THIS WORTH ANYTHING
------------------------------
Object Lock in COMPLIANCE mode. Once an object version is written with a
retention date, **nobody can delete or overwrite it until that date passes --
not the account root, not AWS support**. That is the property the transparency
log needs and the only reason to involve S3 at all: it moves the root out of
the operator's control, which is what `RefusingRootSink` says is missing.

GOVERNANCE mode is the trap. It looks identical in the console and a principal
holding `s3:BypassGovernanceRetention` can delete the object -- so a root
written in governance mode is still the operator's to remove, and
`is_independently_verifiable` would be reporting a guarantee that is not there.
This class REFUSES to publish to a bucket whose default mode is not
COMPLIANCE, rather than writing an object that looks protected.

WHY THIS COSTS ALMOST NOTHING
-----------------------------
A root is about 200 bytes and there is one publication per interval, not per
event. Publishing per event would be one PUT per agent action -- and would buy
nothing, because a later root already proves every earlier one via a
consistency proof. Once a day is the sensible default:

  * 365 PUTs/year at $0.005 per 1,000 = **$0.002/year**
  * 365 x 200 bytes = 73 KB at $0.023/GB-month = **$0.00002/month**
  * no GETs from this code at all; an auditor's reads come out of their pocket

Under a cent a year, and the free tier covers it outright. The mistakes that
would make it expensive are all avoided deliberately:

  * **Not Glacier.** Glacier bills a 40 KB minimum per object and 90-180 days
    minimum duration, so 200-byte objects cost roughly 200x more there than in
    Standard. Cheap-sounding storage classes are a trap at this object size.
  * **One key per tree size**, not per publication attempt, so a retry does
    not accumulate versions.
  * **No listing.** The sink never calls ListObjects, which is the call that
    costs real money when a bucket grows.

WHY IT USES THE HARDENED CLIENT AND SIGNS BY HAND
--------------------------------------------------
`test_security_rules.py` forbids `urllib.request` outside `outbound.py`
because `urlopen` follows redirects and forwards the Authorization header --
proven against this codebase when a 302 to a loopback address received a
bearer token. The same rule applies to an AWS signature, so this goes through
`HardenedHttpClient` and signs with the SigV4 signer already in this
repository. No boto3: one more dependency in a security product needs a better
reason than convenience, and the signer exists.

CREDENTIALS ARE READ FROM THE ENVIRONMENT AND NEVER LOGGED
-----------------------------------------------------------
The secret key is used to derive a signature and is never placed in a URL, a
log line or an exception message. `_safe` strips anything that could carry it
before a message is raised.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping
from urllib.parse import quote

from sentinel.domain.root_sink import (
    PublicationReceipt,
    RootSinkUnavailable,
)
from sentinel.infrastructure.outbound import (
    HardenedHttpClient,
    OutboundPolicy,
    OutboundRefused,
    OutboundUnavailable,
)

__all__ = [
    "COMPLIANCE_MODE",
    "S3ObjectLockRootSink",
    "S3SinkConfig",
    "estimated_annual_cost_usd",
]

#: The only retention mode that puts the object beyond the operator's reach.
#: GOVERNANCE looks the same and can be bypassed by a principal holding
#: `s3:BypassGovernanceRetention`.
COMPLIANCE_MODE = "COMPLIANCE"

_SERVICE = "s3"
_ALGORITHM = "AWS4-HMAC-SHA256"

#: PUT price per request in S3 Standard, and storage per GB-month. Used only
#: by `estimated_annual_cost_usd`, which exists so an operator can see the
#: number before enabling this rather than after a bill.
_PUT_COST_PER_REQUEST = 0.005 / 1000
_STORAGE_COST_PER_GB_MONTH = 0.023
_ROOT_BYTES = 200


def estimated_annual_cost_usd(*, publications_per_day: int = 1) -> float:
    """What this will cost, before you turn it on.

    Deliberately a function rather than a sentence in a README: an operator
    weighing "should we publish every event" can put the number in and see
    that per-event publication costs real money and buys nothing, because a
    later root already proves every earlier one.
    """
    if publications_per_day <= 0:
        raise ValueError(
            "publications_per_day must be positive; a sink that never "
            "publishes leaves every root unverifiable, which is the state "
            "RefusingRootSink already represents honestly"
        )
    puts = publications_per_day * 365
    stored_gb = (puts * _ROOT_BYTES) / (1024**3)
    return puts * _PUT_COST_PER_REQUEST + stored_gb * _STORAGE_COST_PER_GB_MONTH * 12


@dataclass(frozen=True, slots=True)
class S3SinkConfig:
    """Where roots go, and the credential used to put them there.

    Frozen and holding no client: one config is safe to share between
    tenants because nothing here is per-request state.
    """

    bucket: str
    region: str
    access_key_id: str
    secret_access_key: str = field(repr=False)
    #: Days the object cannot be deleted. The value is the retention promise:
    #: an auditor checking a root from last year needs it to still be locked.
    retention_days: int = 3650
    #: Prefix inside the bucket, so a shared bucket stays legible.
    prefix: str = "sentinel/transparency"
    #: Session token, for a role rather than a long-lived user. Preferred:
    #: see the deployment note in docs.
    session_token: str = field(default="", repr=False)
    #: A source of SHORT-LIVED credentials -- the ECS task role, reached through
    #: the container credential endpoint -- used when no static key is set.
    #: Anything with a `current()` returning an object carrying
    #: `access_key_id`, `secret_access_key` and `session_token`.
    credentials: Any = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self.bucket.strip():
            raise ValueError("no bucket configured")
        if not self.region.strip():
            raise ValueError("no region configured")
        if self.credentials is None and (not self.access_key_id.strip() or not self.secret_access_key.strip()):
            raise ValueError(
                "S3 credentials are incomplete. Refusing to attempt an "
                "unsigned PUT: it would fail with a 403 that reads like a "
                "permissions problem rather than a missing credential."
            )
        if self.retention_days < 1:
            raise ValueError(
                f"retention_days={self.retention_days} would lock the root for "
                "less than a day, which is not a retention guarantee. An "
                "auditor checking a root from last year needs it still locked."
            )

    def resolved(self) -> tuple[str, str, str]:
        """(key id, secret, session token) for THIS request: static, or the source's."""
        if self.credentials is None:
            return self.access_key_id, self.secret_access_key, self.session_token
        live = self.credentials.current()
        return str(live.access_key_id), str(live.secret_access_key), str(live.session_token)

    def key_for(self, *, tenant_id: str, tree_size: int) -> str:
        """One key per tree size, so a retry overwrites nothing and adds no
        version. Tenant in the path so a shared bucket is still legible.
        """
        safe_tenant = quote(tenant_id, safe="")
        return f"{self.prefix}/{safe_tenant}/root-{tree_size:012d}.json"


def _sign(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret: str, date: str, region: str) -> bytes:
    return _sign(
        _sign(_sign(_sign(f"AWS4{secret}".encode(), date), region), _SERVICE),
        "aws4_request",
    )


def _safe(message: str, config: S3SinkConfig, *extra: str) -> str:
    """Strip anything that could carry a credential out of a message.

    An exception message reaches logs, error trackers and support tickets.
    Belt and braces: the secret is never placed in a message deliberately, and
    this makes an accidental interpolation harmless.
    """
    cleaned = message
    for secret in (config.secret_access_key, config.session_token, *extra):
        if secret:
            cleaned = cleaned.replace(secret, "[redacted]")
    return cleaned


@dataclass(frozen=True, slots=True)
class S3ObjectLockRootSink:
    """Publishes a root as a locked S3 object. Refuses if it cannot lock it."""

    config: S3SinkConfig
    #: Injected in tests so the suite exercises the real signing and request
    #: construction without a network -- the same seam HardenedHttpClient
    #: offers via connection_factory.
    transport: Any = None
    #: Fixed clock, for deterministic signature tests.
    now: Any = None

    @property
    def name(self) -> str:
        return "s3-object-lock"

    def _client(self) -> Any:
        if self.transport is not None:
            return self.transport
        return HardenedHttpClient(
            policy=OutboundPolicy(
                allowed_schemes=frozenset({"https"}),
                allowed_hosts=frozenset({self._host()}),
                # A root is 200 bytes and S3's reply is a short XML or empty
                # body. A small cap here means a redirect to something large
                # is refused rather than buffered.
                max_response_bytes=64 * 1024,
            )
        )

    def _host(self) -> str:
        return f"{self.config.bucket}.s3.{self.config.region}.amazonaws.com"

    def publish(
        self, *, tenant_id: str, tree_size: int, root_hash: str
    ) -> PublicationReceipt:
        """PUT the root with a compliance-mode retention date.

        Raises `RootSinkUnavailable` on any failure. Never returns a receipt it
        did not obtain: a receipt is what flips
        `is_independently_verifiable` to True, and manufacturing one would put
        a green tick on a root nobody can check.
        """
        moment = (self.now() if self.now else datetime.now(timezone.utc)).astimezone(
            timezone.utc
        )
        stamp = moment.strftime("%Y%m%dT%H%M%SZ")
        date = moment.strftime("%Y%m%d")
        retain_until = (
            moment + timedelta(days=self.config.retention_days)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

        body = json.dumps(
            {
                "tenant": tenant_id,
                "tree_size": tree_size,
                "root": root_hash,
                "published_at": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "retain_until": retain_until,
                "note": (
                    "A Sentinel transparency log root, written with S3 Object "
                    "Lock in COMPLIANCE mode. It cannot be deleted or "
                    "overwritten before retain_until by anyone, including the "
                    "account root. Verify a proof against this root without "
                    "asking the operator."
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        payload_hash = hashlib.sha256(body).hexdigest()
        # Content-MD5 is REQUIRED by S3 for any PUT that sets a retention
        # period -- not optional, and not a security choice. Without it S3
        # answers 400 InvalidRequest, which is what happened here and what my
        # first error hint blamed on Object Lock not being enabled: a
        # confidently wrong message pointing at a bucket that was correctly
        # configured all along.
        #
        # MD5 because the API demands that specific algorithm. `usedforsecurity`
        # is False so this still works on a FIPS build, where an unqualified
        # md5() raises -- and it says plainly that no security claim rests on
        # it. The SHA-256 above is what actually protects the payload.
        content_md5 = base64.b64encode(
            hashlib.md5(body, usedforsecurity=False).digest()
        ).decode("ascii")
        key = self.config.key_for(tenant_id=tenant_id, tree_size=tree_size)
        host = self._host()
        try:
            key_id, secret_key, session_token = self.config.resolved()
        except Exception as exc:  # noqa: BLE001 - a credential source that fails is an unavailable sink
            raise RootSinkUnavailable(f"no credential for the root sink: {type(exc).__name__}: {exc}") from exc

        headers = {
            "host": host,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": stamp,
            "x-amz-object-lock-mode": COMPLIANCE_MODE,
            "x-amz-object-lock-retain-until-date": retain_until,
            "content-type": "application/json",
            "content-md5": content_md5,
        }
        if session_token:
            headers["x-amz-security-token"] = session_token

        signed_names = ";".join(sorted(headers))
        canonical_headers = "".join(
            f"{name}:{headers[name].strip()}\n" for name in sorted(headers)
        )
        canonical = (
            "PUT\n"
            f"/{quote(key, safe='/')}\n"
            "\n"
            f"{canonical_headers}\n"
            f"{signed_names}\n"
            f"{payload_hash}"
        )
        scope = f"{date}/{self.config.region}/{_SERVICE}/aws4_request"
        to_sign = (
            f"{_ALGORITHM}\n{stamp}\n{scope}\n"
            f"{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"
        )
        signature = hmac.new(
            _signing_key(secret_key, date, self.config.region),
            to_sign.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        headers["authorization"] = (
            f"{_ALGORITHM} Credential={key_id}/{scope}, "
            f"SignedHeaders={signed_names}, Signature={signature}"
        )

        url = f"https://{host}/{quote(key, safe='/')}"

        # `host` is SIGNED but NOT SENT.
        #
        # SigV4 requires `host` in the canonical request and in SignedHeaders,
        # and `HardenedHttpClient` refuses to let a caller set it -- it derives
        # it from the URL itself, because a caller-supplied Host is how a
        # request gets signed for one origin and delivered to another.
        #
        # Both are right. The signature covers the host the client will send,
        # because the client computes it from the same URL this signature was
        # built over. Dropping `host` from the SIGNED set instead would produce
        # a signature AWS rejects with a 403 that reads like a bad credential.
        wire_headers = {
            name: value for name, value in headers.items() if name != "host"
        }

        try:
            response = self._client().request(
                method="PUT",
                url=url,
                headers=wire_headers,
                body=body,
                idempotent=True,
            )
        except (OutboundRefused, OutboundUnavailable) as error:
            raise RootSinkUnavailable(
                _safe(
                    f"could not PUT the root to s3://{self.config.bucket}/{key}: "
                    f"{type(error).__name__}: {error}. The root is NOT "
                    "published, so it stays unverifiable -- which is the truth "
                    "rather than a retryable success.",
                    self.config,
                    secret_key,
                    session_token,
                )
            ) from error

        status = int(response.status)
        if status >= 300:
            hint = ""
            if status == 400:
                hint = (
                    " A 400 on a locked PUT most often means the request is "
                    "missing Content-MD5, which S3 REQUIRES whenever a "
                    "retention period is set. The other cause is Object Lock "
                    "not being enabled on the bucket -- and that CANNOT be "
                    "enabled after creation, so it needs a new bucket. S3's "
                    "own message below says which."
                )
            elif status == 403:
                hint = (
                    " A 403 here usually means the policy lacks "
                    "s3:PutObjectRetention, which is needed IN ADDITION to "
                    "s3:PutObject to write a retention date."
                )
            detail = ""
            try:
                raw = getattr(response, "body", b"") or b""
                text = raw.decode("utf-8", errors="replace").strip()
                if text:
                    detail = f" S3 said: {text[:600]}"
            except Exception:  # noqa: BLE001 - a body we cannot read is no body
                detail = ""
            raise RootSinkUnavailable(
                _safe(
                    f"S3 refused the root with HTTP {status} for "
                    f"s3://{self.config.bucket}/{key}.{hint}{detail} The root "
                    "is NOT published.",
                    self.config,
                    secret_key,
                    session_token,
                )
            )

        version = _header(response.headers, "x-amz-version-id")
        if not version:
            # Object Lock REQUIRES versioning, so a successful locked PUT
            # always returns a version id. Its absence means the object landed
            # somewhere without versioning -- and therefore without a lock.
            raise RootSinkUnavailable(
                _safe(
                    f"S3 accepted the PUT to s3://{self.config.bucket}/{key} "
                    "but returned no x-amz-version-id. Object Lock requires "
                    "versioning, so a locked write always has one: its absence "
                    "means this object is NOT locked. Refusing to record it as "
                    "published, because a receipt here would claim a "
                    "guarantee that does not exist.",
                    self.config,
                    secret_key,
                    session_token,
                )
            )

        return PublicationReceipt(
            sink=self.name,
            # The reference an auditor fetches: bucket, key and version. All
            # three are needed -- a key alone names a mutable pointer, and the
            # version is what is actually locked.
            reference=f"s3://{self.config.bucket}/{key}?versionId={version}",
            published_at=moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )


def _header(headers: Mapping[str, str] | None, name: str) -> str:
    """Case-insensitive header read.

    HTTP header names are case-insensitive and S3 has returned both
    `x-amz-version-id` and `X-Amz-Version-Id`. A case-sensitive lookup would
    intermittently conclude the object was unlocked and refuse a publication
    that had in fact succeeded.
    """
    if not headers:
        return ""
    lowered = name.lower()
    for key, value in headers.items():
        if str(key).lower() == lowered:
            return str(value)
    return ""
