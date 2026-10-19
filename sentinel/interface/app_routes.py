"""Connected applications: register the business systems an agent may call through Sentinel.

Secrets travel in one direction. A registration carries the credential; no
response ever does -- a list shows `credential: "sealed"`, nothing more.
Registering is an administrator's act (MANAGE_USERS), reading the registry
is a viewer's, and calling an application is the `app_call` tool under the
ordinary gate, approval and binding.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request, Response

from sentinel.domain.authorization import Capability
from sentinel.infrastructure.sql.connected_apps import ConnectedAppInvalid, SqlConnectedApps

MAX_REGISTRATION_BYTES = 16_384


def register_app_routes(app, container, *, require):
    store: SqlConnectedApps = container.connected_apps

    @app.get("/v1/apps")
    def list_apps(response: Response, principal=Depends(require(Capability.READ_DASHBOARD))):
        response.headers["Cache-Control"] = "no-store"
        return {"apps": store.list(str(principal.tenant)),
                "how_to_call": {"tool": "app_call", "resource": "app://<app_id><path>",
                                "arguments": {"app": "<app_id>", "method": "POST", "path": "/...", "body": {}, "query": {}}},
                "note": "Credentials are stored sealed and never returned. Calls go through POST /v1/protect/evaluate and "
                        "POST /v1/tools/execute like any other tool; the authorized resource must equal app://<app_id><path>."}

    @app.put("/v1/apps/{app_id}", status_code=201)
    async def register(app_id: str, request: Request, response: Response,
                       principal=Depends(require(Capability.MANAGE_USERS))):
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > MAX_REGISTRATION_BYTES:
                raise HTTPException(413, "registration exceeds the size limit")
        try:
            import json
            spec = json.loads(bytes(body) or b"{}")
            if not isinstance(spec, dict):
                raise ValueError
        except ValueError:
            raise HTTPException(400, "the registration must be a JSON object") from None
        spec["app_id"] = app_id
        try:
            saved = store.save(str(principal.tenant), spec, actor=f"key:{principal.key_hash[:12]}",
                               now=container.clock.now().value.isoformat())
        except ConnectedAppInvalid as exc:
            # The message names the field, never the value: nothing a caller sent is echoed.
            raise HTTPException(400, str(exc)) from None
        response.headers["Cache-Control"] = "no-store"
        return saved

    @app.delete("/v1/apps/{app_id}")
    def remove(app_id: str, principal=Depends(require(Capability.MANAGE_USERS))):
        if not store.delete(str(principal.tenant), app_id):
            raise HTTPException(404, "no such application in this tenant")
        return {"deleted": app_id}
