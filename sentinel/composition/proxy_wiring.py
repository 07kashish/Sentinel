"""The two wire clients, and the egress policy each is allowed.

WHY THIS IS NOT IN `container.py`
----------------------------------
Two reasons, and the second is the one that matters.

The mechanical one: adding the A2A client pushed `container.py` past the size at
which a module stops having one reason to change, which
`test_no_module_exceeds_the_size_at_which_it_stops_having_one_reason_to_change`
caught.

The real one: these two functions decide **what this process may dial**. That is
a security decision with its own reason to change, and it deserves a file
somebody can read end to end without scrolling past database pools and metric
registries to find it.

TWO ALLOWLISTS, NOT ONE
-----------------------
`SENTINEL_MCP_PROXY_ALLOWED_HOSTS` and `SENTINEL_A2A_PROXY_ALLOWED_HOSTS` are
separate, and merging them would be a quiet privilege escalation: an operator
enabling the A2A proxy to reach their agents would thereby widen the set of MCP
servers this process could dial, and nothing would say so. Different peers,
reached for different reasons, decided about separately.

ABSENT RATHER THAN DISABLED
---------------------------
Each returns `None` when its proxy is not enabled, and the route registration
functions return without adding a route when they see `None`. So a deployment
that did not ask for a proxy does not have one to reach -- the safe state is
enforced by the router rather than by a flag one boolean away from being on.
"""

from __future__ import annotations

from sentinel.composition.settings import Settings
from sentinel.infrastructure.a2a_wire import A2AUpstreamClient
from sentinel.infrastructure.mcp_wire import McpUpstreamClient
from sentinel.infrastructure.outbound import HardenedHttpClient, OutboundPolicy

__all__ = ["build_a2a_upstream", "build_mcp_upstream"]


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


def build_a2a_upstream(settings: Settings) -> A2AUpstreamClient | None:
    """The A2A wire client, or `None` when the proxy is not enabled.

    Its OWN allowlist, for the reason in the module docstring: sharing the MCP
    one would mean enabling this proxy silently widened what the other could
    dial.
    """
    if not settings.a2a_proxy_enabled:
        return None
    return A2AUpstreamClient(
        client=HardenedHttpClient(
            policy=OutboundPolicy(
                allowed_hosts=settings.a2a_proxy_allowed_hosts,
                allow_private_destinations=settings.a2a_proxy_allow_private,
            )
        )
    )
