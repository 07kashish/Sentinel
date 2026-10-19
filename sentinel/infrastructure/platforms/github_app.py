"""GitHub App credentials: a signed request for a token, and the narrowest scope a path allows.

An installation token request may name the repositories and permissions the
token is good for. The scope is COMPUTED from the same method and path the
call is built from, so a token minted for `PUT /repos/acme/infra/contents/x`
can write contents in `infra` and do nothing else -- not read another
repository of the installation, not change branch protection in this one.

A path outside `/repos/<owner>/<repo>/...`, or a path family this table does
not know, gets NO narrowing on that axis: the token then carries whatever the
installation was granted. That is stated in the result rather than refused,
because refusing would make the App mode unusable for endpoints the table has
not learned yet; the installation's own grant remains the outer bound.
"""

from __future__ import annotations

import base64
import json
import re
import time
from types import MappingProxyType
from typing import Any, Mapping

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from sentinel.infrastructure.tool_adapters import ToolAdapterRefused

__all__ = ["app_jwt", "installation_scope"]

_REPO = re.compile(r"^/repos/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+)(?:/([a-z_-]+))?")

#: First path segment under a repository -> the permission family that governs it.
_FAMILIES: Mapping[str, str] = MappingProxyType({
    "contents": "contents", "git": "contents", "branches": "administration",
    "issues": "issues", "pulls": "pull_requests", "actions": "actions",
    "deployments": "deployments", "environments": "environments", "hooks": "repository_hooks",
    "collaborators": "administration", "secrets": "secrets", "statuses": "statuses",
    "check-runs": "checks", "releases": "contents",
})


def installation_scope(method: str, path: str) -> dict[str, Any]:
    """The `repositories` and `permissions` to ask for, from the call itself."""
    matched = _REPO.match(path)
    if matched is None:
        return {}
    scope: dict[str, Any] = {"repositories": [matched.group(2)]}
    family = _FAMILIES.get(matched.group(3) or "")
    if family:
        scope["permissions"] = {family: "read" if method in {"GET", "HEAD"} else "write"}
    return scope


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def app_jwt(app_id: str, private_key_pem: str, *, now: float | None = None) -> str:
    """The short-lived RS256 assertion GitHub accepts from an App. Nine minutes."""
    try:
        key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    except (ValueError, TypeError) as exc:
        raise ToolAdapterRefused("GitHub App private key could not be loaded") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ToolAdapterRefused("GitHub App private key must be RSA")
    issued = int(time.time() if now is None else now)
    # Backdated a minute for clock drift, as GitHub recommends; ten minutes is the ceiling.
    claims = {"iat": issued - 60, "exp": issued + 540, "iss": str(app_id)}
    signing_input = _b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()) + "." + _b64(json.dumps(claims).encode())
    signature = key.sign(signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return signing_input + "." + _b64(signature)
