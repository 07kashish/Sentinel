"""Construct the MCP client with its deployment-scoped egress policy.

The hardened outbound policy remains HTTPS-only, public-only by default,
with explicit private-destination opt-in and a dedicated MCP host allowlist.
Disabled proxies have no client and register no route.
"""

from __future__ import annotations

from sentinel.composition.settings import Settings
from sentinel.infrastructure.mcp_wire import McpUpstreamClient
from sentinel.infrastructure.outbound import HardenedHttpClient, OutboundPolicy

__all__ = ["build_mcp_upstream"]


def build_mcp_upstream(settings: Settings) -> McpUpstreamClient | None:
    """The MCP wire client, or `None` when the proxy is not enabled.

    The outbound policy is the hardened default -- https only, public
    destinations only, no redirects, bounded responses -- narrowed further by
    the deployment's allowlist. `allow_private_destinations` is a deliberate
    operator decision for on-prem MCP servers and defaults off.
    """
    if not settings.mcp_proxy_enabled:
        return None
    return McpUpstreamClient(
        client=HardenedHttpClient(
            policy=OutboundPolicy(
                allowed_hosts=settings.mcp_proxy_allowed_hosts,
                allow_private_destinations=settings.mcp_proxy_allow_private,
            )
        )
    )
