"""A read-only key the console may publish, so a link can be shared with anyone.

WHY THIS EXISTS
---------------
The console takes a bearer token. A person who was sent the link and holds no
credential sees a sign-in box and nothing else. For a demonstration the owner
may publish ONE key on the sign-in page, and this module is the only place that
decides whether that is allowed.

WHAT IT REFUSES
---------------
The published key must be an API key configured in `SENTINEL_API_KEYS` with the
role `viewer`, which holds only read capabilities. Any other role -- an analyst
key could approve agent actions, an admin key could change policy -- makes the
application refuse to start. A misconfiguration therefore fails at boot, where
an operator sees it, rather than as a publicly posted approver credential.

The key is served at `GET /console/demo.json`, unauthenticated, with
`Cache-Control: no-store`. It is not a secret once configured: that is the
point of it. The throttle gives it one bucket per client address, so one
visitor cannot exhaust it for the rest.
"""

from __future__ import annotations

import hashlib
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse

__all__ = ["DemoKey", "console_demo_key", "register_console_demo"]

#: The only role that may be published.
PUBLISHABLE_ROLE = "viewer"
#: How often a demo visitor's console polls. Slower than the operator default
#: of five seconds because every visitor shares the one key.
DEMO_POLL_SECONDS = 30


class DemoKey:
    __slots__ = ("token", "digest", "tenant_id")

    def __init__(self, token: str, digest: str, tenant_id: str) -> None:
        self.token = token
        self.digest = digest
        self.tenant_id = tenant_id


def console_demo_key(settings: Any) -> DemoKey | None:
    """The configured demo key, validated; None when none is configured."""
    from sentinel.composition.settings import ConfigurationError

    token = str(getattr(settings.workflow, "console_demo_token", "") or "").strip()
    if not token:
        return None
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    binding = settings.api_keys.get(digest)
    if binding is None:
        raise ConfigurationError(
            "SENTINEL_CONSOLE_DEMO_TOKEN is not one of the keys in SENTINEL_API_KEYS; "
            "the console would publish a key that authenticates nothing"
        )
    if binding.role != PUBLISHABLE_ROLE:
        raise ConfigurationError(
            f"SENTINEL_CONSOLE_DEMO_TOKEN has the role {binding.role!r}; only a "
            f"{PUBLISHABLE_ROLE!r} key may be published, because anyone with the "
            "console link would hold it"
        )
    return DemoKey(token=token, digest=digest, tenant_id=binding.tenant_id)


def register_console_demo(app: FastAPI, demo: DemoKey | None) -> None:
    """`GET /console/demo.json`: the published key, or `{"enabled": false}`."""

    @app.get("/console/demo.json", include_in_schema=False)
    def console_demo() -> JSONResponse:
        headers = {"Cache-Control": "no-store"}
        if demo is None:
            return JSONResponse({"enabled": False}, headers=headers)
        return JSONResponse(
            {
                "enabled": True,
                "token": demo.token,
                "tenant": demo.tenant_id,
                "role": PUBLISHABLE_ROLE,
                "poll_seconds": DEMO_POLL_SECONDS,
                "note": "read-only demonstration access; nothing can be approved, contained or changed",
            },
            headers=headers,
        )
