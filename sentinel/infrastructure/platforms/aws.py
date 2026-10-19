"""AWS: one SigV4-signed API call, under a tier ceiling.

THE CONFUSED DEPUTY, AND THE RULE THAT DEFEATS IT
--------------------------------------------------
This process holds credentials the agent must never aim. An adapter that takes a
caller-supplied path and a caller-supplied label is a confused deputy by
construction: the agent declares `action="iam:ListUsers"` (classified low,
allowed by policy) and supplies `path="/?Action=CreateAccessKey"`, and Sentinel
signs it with the deployment's own key. Policy saw one operation; AWS performed
another.

So this adapter takes NO path, NO method, NO host and NO URL. It is given one
string -- `iam:CreateAccessKey` -- and derives from it, and only from it:

  * the classification, via `action_semantics`;
  * the service, and therefore the endpoint host;
  * the wire protocol;
  * the `Action` parameter AWS actually performs.

There is no second channel through which a caller can describe the request
differently from how it will be sent, because there is no second channel at all.
`_parameters` refuses a caller-supplied `Action` or `Version` explicitly, which
is the same rule stated where someone editing the parameter handling will read
it.

WHY NOT BOTO3
-------------
boto3 brings its own HTTP stack, which would route the highest-privilege egress
in the product around `HardenedHttpClient`: no post-resolution address
validation, no connection pinning against DNS rebinding, redirects followed by
default. SigV4 is an HMAC ladder over a canonical string -- the ninety lines
below -- and the test suite pins it to the published `aws4_testsuite` vector.
The SDK is the convenient choice and it is the one that loses every control the
outbound module was built to provide.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import json
import re
import urllib.parse
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Any, Mapping

from sentinel.application.tool_proxy import RegisteredSideEffect
from sentinel.infrastructure.outbound import HardenedHttpClient
from sentinel.infrastructure.platforms.ceiling import (
    DEFAULT_CEILING,
    bounded,
    classify_or_refuse,
    enforce_ceiling,
    call_settled,
    hardened_call,
    normalise_ceiling,
)
from sentinel.application.operation_context import current_operation_id, operation_stamp
from sentinel.infrastructure.platforms.aws_outcome import aws_hint, aws_reconciler, parse_assumed_role
from sentinel.infrastructure.tool_adapters import ToolAdapterNotAttempted, ToolAdapterRefused

__all__ = ["AwsCredentials", "aws_api_adapter", "sign_request"]


@dataclass(frozen=True, slots=True)
class AwsCredentials:
    """One AWS identity this deployment may act as.

    `session_token` is optional and supported because the correct way to run
    this is with a short-lived assumed role, not a long-lived access key.
    """

    access_key_id: str
    secret_access_key: str
    region: str
    session_token: str = ""
    #: Set to make the key above a BROKER that assumes this role per operation.
    executor_role_arn: str = ""

    @property
    def brokered(self) -> bool:
        return bool(self.executor_role_arn)

    def __post_init__(self) -> None:
        if self.executor_role_arn and not re.fullmatch(
            r"arn:aws[a-z-]*:iam::\d{12}:role/[\w+=,.@/-]{1,128}", self.executor_role_arn
        ):
            raise ToolAdapterRefused("AWS executor_role_arn is not a role ARN")
        for field in ("access_key_id", "secret_access_key", "region"):
            if not str(getattr(self, field)).strip():
                raise ToolAdapterRefused(f"AWS {field} is required")


#: Services this adapter can address, and how. Two AWS wire protocols cover the
#: security-relevant surface:
#:
#:   * `query` -- form-encoded `Action=...&Version=...` (IAM, STS, EC2)
#:   * `json`  -- AWS JSON 1.1 with an `X-Amz-Target` header (Secrets Manager,
#:                KMS, SSM, CloudTrail)
#:
#: `global_endpoint` marks the services whose host carries no region.
#:
#: S3 is deliberately ABSENT. Its REST protocol needs per-operation path and
#: payload signing that does not generalise from the POST-to-`/` shape signed
#: here, and a half-working S3 adapter would be a capability claim this module
#: could not honour. `NOT_SUPPORTED` beats a fake success.
#:
#: `MappingProxyType`, not a bare dict: this table decides which endpoint a
#: signed credential is presented to, and
#: `test_architecture_rules.py::test_there_is_no_mutable_module_level_state`
#: rejects a module-level dict literal for exactly this reason.
SERVICES: Mapping[str, Mapping[str, Any]] = MappingProxyType({
    "iam": {"protocol": "query", "version": "2010-05-08", "global_endpoint": True},
    "sts": {"protocol": "query", "version": "2011-06-15", "global_endpoint": True},
    "ec2": {"protocol": "query", "version": "2016-11-15", "global_endpoint": False},
    "secretsmanager": {
        "protocol": "json", "target_prefix": "secretsmanager", "global_endpoint": False,
    },
    "kms": {"protocol": "json", "target_prefix": "TrentService", "global_endpoint": False},
    "ssm": {"protocol": "json", "target_prefix": "AmazonSSM", "global_endpoint": False},
    "cloudtrail": {
        "protocol": "json",
        "target_prefix": "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101",
        "global_endpoint": False,
    },
})

_ACTION_RE = re.compile(r"^([a-z0-9-]{2,40}):([A-Za-z0-9]{2,80})$")

#: AWS region names, validated by SHAPE rather than by an enumeration that would
#: be wrong the week a region launches -- but validated, because the region goes
#: into the endpoint hostname and into the SigV4 credential scope. An
#: unvalidated region is a caller-controlled hostname.
_REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d$")


#: Paths this signer will sign. Deliberately narrow: an absolute path made of
#: unreserved characters and slashes, with no query, no fragment, no dot
#: segments and no percent-encoding.
#:
#: The point is that such a path needs no canonicalisation, so the string
#: signed here and the string in the transmitted URL are necessarily identical.
#: A signer that normalised its input would produce a signature over a path the
#: request did not use -- and SigV4 fails as an opaque 403, which reads as a
#: permissions problem and gets debugged in IAM for a day.
_SIGNABLE_PATH = re.compile(r"^/(?:[A-Za-z0-9._~-]+/)*[A-Za-z0-9._~-]*$")


def _signable_path(path: str) -> str:
    """Refuse a path this signer cannot sign correctly.

    Fails closed. The alternative -- encode it and hope -- produces a
    signature mismatch at AWS, which is indistinguishable from a wrong
    credential.
    """
    if not _SIGNABLE_PATH.match(path) or ".." in path.split("/"):
        raise ValueError(
            f"refusing to sign path {path!r}. This signer canonicalises "
            "nothing, so it only accepts an absolute path of unreserved "
            "characters with no query, fragment, dot segment or "
            "percent-encoding -- anything else would be signed differently "
            "from how it is sent, and SigV4 reports that as an opaque 403 "
            "that looks like a permissions problem."
        )
    return path


def sign_request(
    *,
    credentials: AwsCredentials,
    service: str,
    host: str,
    amz_target: str,
    payload: bytes,
    now: _dt.datetime,
    path: str = "/",
    content_type: str = "",
) -> dict[str, str]:
    """Produce SigV4 headers for one POST to `host` at `path`.

    Narrowed to POST, which is the only method this codebase's AWS adapters
    construct. That removes every canonical-query edge case generic SigV4
    implementations get wrong, because there is no query to sort.

    `path` defaults to `/` -- the original and only shape until the Bedrock
    Agent connector arrived, whose `ListAgents` is a POST to `/agents/`. It is
    interpolated into the canonical request WITHOUT re-encoding, because the
    caller passes a literal from source rather than anything derived from a
    request, and a normaliser here would be a second opinion about the path
    that the transmitted URL does not share. `_signable_path` refuses anything
    that is not such a literal, so the two cannot drift apart.

    `content_type` overrides the default, which is needed because the Bedrock
    Agent API is REST-JSON (`application/json`) rather than either of the two
    shapes the query and JSON-1.1 protocols use -- and the content type is a
    SIGNED header, so getting it wrong fails the signature rather than the
    parse.
    """
    path = _signable_path(path)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(payload).hexdigest()

    headers: dict[str, str] = {
        "content-type": content_type
        or (
            "application/x-amz-json-1.1"
            if amz_target
            else "application/x-www-form-urlencoded; charset=utf-8"
        ),
        "host": host,
        "x-amz-date": stamp,
    }
    if amz_target:
        headers["x-amz-target"] = amz_target
    if credentials.session_token:
        headers["x-amz-security-token"] = credentials.session_token

    signed_headers = ";".join(sorted(headers))
    canonical_headers = "".join(f"{k}:{headers[k]}\n" for k in sorted(headers))
    canonical_request = "\n".join(
        ["POST", path, "", canonical_headers, signed_headers, payload_hash]
    )

    scope = f"{datestamp}/{credentials.region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            stamp,
            scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )

    def _hmac(key: bytes, message: str) -> bytes:
        return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()

    signing_key = _hmac(
        _hmac(
            _hmac(
                _hmac(f"AWS4{credentials.secret_access_key}".encode("utf-8"), datestamp),
                credentials.region,
            ),
            service,
        ),
        "aws4_request",
    )
    signature = hmac.new(
        signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    headers["authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={credentials.access_key_id}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    # `host` participates in the signature and must NOT be transmitted: it is on
    # `HardenedHttpClient`'s forbidden-header list, which raises rather than
    # drops, so leaving it here would fail every AWS call at the client. Signed,
    # then removed.
    headers.pop("host", None)
    return headers


def _parameters(raw: Any) -> dict[str, str]:
    """Validate caller-supplied request parameters.

    Flat string->scalar only. Nested structures are refused rather than
    flattened: AWS query-protocol nesting (`Filters.member.1.Name`) is a syntax
    a caller can spell explicitly if it needs it, and inventing a flattening
    here would mean this module deciding what a nested value means.
    """
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        raise ToolAdapterRefused("aws parameters must be an object")
    out: dict[str, str] = {}
    for key, value in raw.items():
        name = str(key)
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", name):
            raise ToolAdapterRefused(f"aws parameter name {name!r} is not permitted")
        if isinstance(value, (Mapping, list, tuple, set)):
            raise ToolAdapterRefused(
                f"aws parameter {name!r} is a nested structure; pass the "
                "flattened AWS query form explicitly"
            )
        out[name] = "true" if value is True else "false" if value is False else str(value)
        if len(out[name]) > 2048:
            raise ToolAdapterRefused(f"aws parameter {name!r} is over 2048 characters")
    if "Action" in out or "Version" in out:
        # THE confused-deputy defence, stated as code. `Action` is what AWS
        # performs; it is derived from the classified action string and nothing
        # else may set it, or the label and the request diverge.
        raise ToolAdapterRefused(
            "aws parameters may not contain 'Action' or 'Version'; both are "
            "derived from the classified action so that the operation policy "
            "judged is the operation AWS performs"
        )
    return out


#: The signing scope of a global endpoint. `sts.amazonaws.com` and
#: `iam.amazonaws.com` carry no region in the host and accept only this one in
#: the credential scope; signed with the configured region they answer
#: `SignatureDoesNotMatch: Credential should be scoped to a valid region`.
#: Found by the first real AssumeRole (2026-09-24), exactly where RISK R-021
#: said a documentation-derived signer would be wrong.
GLOBAL_SIGNING_REGION = "us-east-1"


def _signing_identity(acting: AwsCredentials, spec: Mapping[str, Any]) -> AwsCredentials:
    """The credential with the scope region the endpoint will accept."""
    if spec["global_endpoint"] and acting.region != GLOBAL_SIGNING_REGION:
        return replace(acting, region=GLOBAL_SIGNING_REGION)
    return acting


def aws_api_adapter(
    *,
    client: HardenedHttpClient,
    credentials: AwsCredentials,
    ceiling: str = DEFAULT_CEILING,
    clock: Any = None,
) -> RegisteredSideEffect:
    """Call one AWS API operation, SigV4-signed, under a tier ceiling.

    Arguments: `action` (an `iam:CreateAccessKey`-shaped string) and optional
    flat `parameters`.
    """
    limit = normalise_ceiling(ceiling)
    if not _REGION_RE.fullmatch(credentials.region):
        raise ToolAdapterRefused(
            f"AWS region {credentials.region!r} is not a valid region name; it "
            "becomes part of the endpoint host and the signature scope"
        )

    def signed_post(acting: AwsCredentials, service: str, payload: bytes, amz_target: str,
                    now: _dt.datetime) -> Mapping[str, Any]:
        spec = SERVICES[service]
        host = f"{service}.amazonaws.com" if spec["global_endpoint"] else f"{service}.{credentials.region}.amazonaws.com"
        headers = sign_request(credentials=_signing_identity(acting, spec), service=service, host=host,
                               amz_target=amz_target, payload=payload, now=now)
        return hardened_call(client, method="POST", url=f"https://{host}/", headers=headers, body=payload)

    def mint(now: _dt.datetime) -> tuple[AwsCredentials, dict[str, str]]:
        """The identity for ONE operation, and what may be said about it."""
        if not credentials.brokered:
            return credentials, {"mode": "static"}
        session = operation_stamp(current_operation_id() or f"unbound-{now.timestamp()}")
        payload = urllib.parse.urlencode({
            "Action": "AssumeRole", "Version": SERVICES["sts"]["version"],
            "RoleArn": credentials.executor_role_arn, "RoleSessionName": session, "DurationSeconds": "900",
        }).encode("utf-8")
        granted = signed_post(credentials, "sts", payload, "", now)
        temporary = parse_assumed_role(int(granted["status"]), granted["body"])
        acting = AwsCredentials(
            access_key_id=temporary["AccessKeyId"], secret_access_key=temporary["SecretAccessKey"],
            session_token=temporary["SessionToken"], region=credentials.region,
        )
        return acting, {"mode": "assume_role", "role": credentials.executor_role_arn,
                        "session": session, "expires_at": temporary["Expiration"]}

    def lookup(session: str) -> tuple[int, Any]:
        now = clock() if clock is not None else _dt.datetime.now(_dt.timezone.utc)
        payload = json.dumps({"LookupAttributes": [{"AttributeKey": "Username", "AttributeValue": session}],
                              "MaxResults": 50}, separators=(",", ":")).encode("utf-8")
        found = signed_post(credentials, "cloudtrail", payload,
                            f"{SERVICES['cloudtrail']['target_prefix']}.LookupEvents", now)
        return int(found["status"]), found["body"]

    def run(args: Mapping[str, Any]) -> dict[str, Any]:
        action = str(args.get("action", "")).strip()
        matched = _ACTION_RE.match(action)
        if not matched:
            raise ToolAdapterRefused(
                f"aws action {action!r} must be 'service:Operation' shaped"
            )
        service, operation = matched.group(1).lower(), matched.group(2)

        spec = SERVICES.get(service)
        if spec is None:
            raise ToolAdapterRefused(
                f"aws service {service!r} is not addressable by this adapter "
                f"(supported: {', '.join(sorted(SERVICES))})"
            )

        semantics = classify_or_refuse(
            platform="aws", action=action, resource="", metadata={}
        )
        enforce_ceiling(semantics, limit)

        parameters = _parameters(args.get("parameters"))

        host = (
            f"{service}.amazonaws.com"
            if spec["global_endpoint"]
            else f"{service}.{credentials.region}.amazonaws.com"
        )
        if spec["protocol"] == "query":
            payload = urllib.parse.urlencode(
                {"Action": operation, "Version": spec["version"], **parameters}
            ).encode("utf-8")
            amz_target = ""
        else:
            payload = json.dumps(parameters, separators=(",", ":")).encode("utf-8")
            amz_target = f"{spec['target_prefix']}.{operation}"

        now = clock() if clock is not None else _dt.datetime.now(_dt.timezone.utc)
        try:
            acting, credential = mint(now)
        except ToolAdapterRefused as exc:
            # Assuming the role precedes the operation; nothing has touched the target.
            raise ToolAdapterNotAttempted(str(exc)) from exc
        headers = sign_request(
            credentials=_signing_identity(acting, spec),
            service=service,
            host=host,
            amz_target=amz_target,
            payload=payload,
            now=now,
        )
        result = call_settled(
            client, semantics, platform="aws",
            method="POST", url=f"https://{host}/", headers=headers, body=payload,
        )
        return bounded(
            {
                "platform": "aws",
                "operation": action,
                "credential": credential,
                "semantics": semantics.as_metadata(),
                **result,
            }
        )

    return RegisteredSideEffect(
        name="aws_api", runner=run, hint=aws_hint(credentials.brokered),
        reconciler=aws_reconciler(lookup) if credentials.brokered else None,
    )
