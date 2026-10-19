"""Pilot setup and explicitly imported local inventory; no automatic enrollment."""
from __future__ import annotations

import json
from importlib.resources import files

from fastapi import Depends, HTTPException, Request, Response

from sentinel.domain.authorization import Capability
from sentinel.infrastructure.sql.device_discovery import SqlDeviceDiscovery
from sentinel.sdk.discovery import MAX_REPORT_BYTES, TOOLS, validate_report


def register_pilot_routes(app, container, *, require):
    store = SqlDeviceDiscovery(container.pool)

    @app.get("/v1/pilot/discovery-script")
    def download(principal=Depends(require(Capability.READ_DASHBOARD))):
        source = files("sentinel.sdk").joinpath("discovery.py").read_bytes()
        return Response(source, media_type="text/x-python", headers={
            "Content-Disposition": 'attachment; filename="sentinel-discover.py"',
            "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
        })

    @app.get("/v1/pilot/setup")
    def setup(response: Response, principal=Depends(require(Capability.READ_DASHBOARD))):
        response.headers["Cache-Control"] = "no-store"
        settings = container.settings
        return {
            "tenant": str(principal.tenant), "role": principal.role,
            "can_import": Capability.MANAGE_USERS in principal.capabilities,
            "tools": dict(TOOLS),
            "protection_mode": settings.protection_mode.value,
            "mcp_proxy_enabled": settings.mcp_proxy_enabled,
            "brain": {"deterministic_policy": "configured",
                      "advisor_configured": container.advisor.model_receipt() != "none",
                      "advisor_model": container.advisor.model_receipt(),
                      "advisor_connectivity": "not_tested_by_setup",
                      "authority": "advisory_only"},
            "limits": ["Presence is self-reported; it proves neither activity nor enforcement.",
                       "Browser and cloud-only AI, custom installs and unlisted tools are outside this scan.",
                       "Imported inventory never grants tool access or enrolls an agent.",
                       "Reports stay until an administrator deletes or replaces them; scan time is client-reported."],
        }

    @app.get("/v1/pilot/devices")
    def devices(response: Response, principal=Depends(require(Capability.READ_DASHBOARD))):
        response.headers["Cache-Control"] = "no-store"
        return store.list(str(principal.tenant))

    @app.post("/v1/pilot/devices", status_code=201)
    async def import_device(request: Request, response: Response,
                            principal=Depends(require(Capability.MANAGE_USERS))):
        # Do not use validation errors that echo arbitrary imported values.
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > MAX_REPORT_BYTES:
                raise HTTPException(413, "Discovery report exceeds the size limit.")
        try:
            report = validate_report(json.loads(body))
        except (ValueError, TypeError, KeyError, AttributeError):
            raise HTTPException(400, "Invalid discovery report; regenerate with sentinel-discover.") from None
        try:
            store.save(str(principal.tenant), report,
                       received_at=container.clock.now().value.isoformat(), actor=principal.key_hash)
        except ValueError:
            raise HTTPException(409, "Device inventory limit reached; remove an old report first.") from None
        response.headers["Cache-Control"] = "no-store"
        return {"device_id": report["device_id"], "trust": "self_reported", "enforced": False}

    @app.delete("/v1/pilot/devices/{device_id}")
    def forget(device_id: str, response: Response, principal=Depends(require(Capability.MANAGE_USERS))):
        if not store.delete(str(principal.tenant), device_id):
            raise HTTPException(404, "Device report not found.")
        response.headers["Cache-Control"] = "no-store"
        return {"deleted": True}
