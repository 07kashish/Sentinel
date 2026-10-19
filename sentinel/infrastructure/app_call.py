"""`app_call`: run one approved request against a connected application.

The agent names the application, the method, the path and the body. Sentinel
supplies the destination, the credential and the limits the administrator
registered; the agent's request can only land where the registration allows.

OUTCOME CLASSES, because a lost answer is not a failure:

* refused BEFORE anything was sent (unknown app, method or path not allowed,
  resource mismatch, outbound policy): `ToolAdapterNotAttempted` -- a failure
  with a known outcome;
* the target answered 4xx: `ToolAdapterRejectedByTarget` -- proof the change
  was not admitted;
* 5xx, a timeout or a transport error on a mutating method: a plain error, so
  the runner records UNKNOWN_AFTER_EFFECT and a person reconciles. On GET or
  HEAD the same errors are not-attempted, because a read cannot have changed
  anything worth reconciling.

The caller's headers are never forwarded. Response bodies are bounded and the
address actually dialled is recorded.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Callable, Mapping
from urllib.parse import quote, urlencode, urlsplit

from sentinel.application.tool_proxy import RegisteredSideEffect
from sentinel.infrastructure.outbound import HardenedHttpClient, OutboundPolicy, OutboundRefused, OutboundUnavailable
from sentinel.infrastructure.sql.connected_apps import ConnectedAppInvalid, SqlConnectedApps
from sentinel.infrastructure.tool_adapters import ToolAdapterNotAttempted, ToolAdapterRejectedByTarget

__all__ = ["app_call_adapter", "canonical_resource", "AppCallUnknown"]

MAX_BODY_BYTES = 262_144
MAX_RESULT_BODY = 65_536


class AppCallUnknown(RuntimeError):
    """The request may have reached the application; the outcome is not known."""


def canonical_resource(app_id: str, path: str) -> str:
    return f"app://{app_id}{path}"


def _default_client(host: str) -> HardenedHttpClient:
    return HardenedHttpClient(policy=OutboundPolicy(allowed_hosts=frozenset({host}), read_timeout_seconds=20.0,
                                                    max_response_bytes=MAX_BODY_BYTES * 4))


def app_call_adapter(apps: SqlConnectedApps, *, client_factory: Callable[[str], Any] = _default_client) -> RegisteredSideEffect:
    def run(context: Any, args: Mapping[str, Any]) -> dict[str, Any]:
        tenant = str(getattr(context, "tenant_id", "") or "")
        app_id = str(args.get("app", "")).strip()
        method = str(args.get("method", "GET")).upper().strip()
        path = str(args.get("path", "")).strip()
        if not tenant or not app_id or not path.startswith("/") or ".." in path or "?" in path or "#" in path:
            raise ToolAdapterNotAttempted("app_call needs app and a path starting with / (no '..', '?' or '#')")
        # THE AUTHORIZED RESOURCE MUST NAME THIS CALL. The gate decided over
        # `resource`; the arguments could otherwise aim the credential elsewhere.
        expected = canonical_resource(app_id, path)
        if str(getattr(context, "resource", "") or "") != expected:
            raise ToolAdapterNotAttempted(f"app_call refused: the authorized resource must be {expected!r}")
        try:
            app = apps.get(tenant, app_id)
        except ConnectedAppInvalid as exc:
            raise ToolAdapterNotAttempted(str(exc)) from exc
        if app is None:
            raise ToolAdapterNotAttempted(f"no connected application {app_id!r} in this tenant")
        if method not in app["allowed_methods"]:
            raise ToolAdapterNotAttempted(f"method {method} is not allowed for {app_id!r}")
        if not any(path.startswith(prefix) for prefix in app["allowed_path_prefixes"]):
            raise ToolAdapterNotAttempted(f"path is outside what {app_id!r} allows")
        query = args.get("query")
        if query is not None and (not isinstance(query, Mapping) or any(not isinstance(v, (str, int, float, bool)) for v in query.values())):
            raise ToolAdapterNotAttempted("query must be a flat object of scalar values")
        body = args.get("body")
        payload = None
        headers = {"accept": "application/json"}
        if method in {"POST", "PUT", "PATCH", "DELETE"} and body is not None:
            if isinstance(body, str):
                payload = body.encode("utf-8")
                headers["content-type"] = str(args.get("content_type") or "text/plain; charset=utf-8")
            else:
                payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
                headers["content-type"] = "application/json"
            if len(payload) > MAX_BODY_BYTES:
                raise ToolAdapterNotAttempted("body exceeds 256 KiB")
        elif body is not None:
            raise ToolAdapterNotAttempted(f"{method} takes no body")
        kind, secret = app["auth"]["kind"], app.get("secret", "")
        if kind == "bearer":
            headers["authorization"] = f"Bearer {secret}"
        elif kind == "basic":
            headers["authorization"] = "Basic " + base64.b64encode(secret.encode("utf-8")).decode("ascii")
        elif kind == "header":
            headers[str(app["auth"]["header"]).lower()] = secret
        url = app["base_url"] + quote(path, safe="/-._~%:@!$&'()*+,;=")
        if query:
            url += "?" + urlencode({str(k): str(v) for k, v in query.items()})
        host = urlsplit(app["base_url"]).hostname or ""
        mutating = method not in {"GET", "HEAD"}
        try:
            response = client_factory(host).request(method=method, url=url, headers=headers, body=payload, idempotent=not mutating)
        except OutboundRefused as exc:
            raise ToolAdapterNotAttempted(f"outbound request refused: {exc}") from exc
        except OutboundUnavailable as exc:
            if mutating:
                raise AppCallUnknown(f"no answer from {app_id!r}: {type(exc).__name__}") from exc
            raise ToolAdapterNotAttempted(f"{app_id!r} unreachable: {type(exc).__name__}") from exc
        status = int(response.status)
        text = response.body.decode("utf-8", errors="replace")
        result = {"app": app_id, "method": method, "path": path, "status": status, "peer": response.peer,
                  "body": text[:MAX_RESULT_BODY], "body_truncated": len(text) > MAX_RESULT_BODY,
                  "request_digest": hashlib.sha256((method + " " + url + "\n").encode("utf-8") + (payload or b"")).hexdigest()}
        if 400 <= status < 500:
            raise ToolAdapterRejectedByTarget(f"{app_id!r} rejected the request with HTTP {status}")
        if status >= 500:
            if mutating:
                raise AppCallUnknown(f"{app_id!r} answered HTTP {status}; the effect is not known")
            raise ToolAdapterNotAttempted(f"{app_id!r} answered HTTP {status}")
        return result

    def hint(args: Mapping[str, Any]) -> Mapping[str, Any]:
        return {"app": str(args.get("app", "")), "method": str(args.get("method", "GET")).upper(), "path": str(args.get("path", ""))}

    return RegisteredSideEffect(name="app_call", runner=lambda args: run(None, args), hint=hint, tenant_runner=run)
