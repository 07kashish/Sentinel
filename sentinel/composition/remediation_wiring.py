"""Assemble the remediation executor from every source of containment.

WHY THIS IS NOT IN `container.py`
----------------------------------
There are now three independent sources of integrations -- Sentinel's own state,
the operator's cloud credentials, and their configured webhooks -- and deciding
which wins is a rule with its own reason to change. It also pushed `container.py`
past the size at which a module stops having one reason to change, which
`test_no_module_exceeds_the_size_at_which_it_stops_having_one_reason_to_change`
caught. The container calls one function.

THE PRECEDENCE, AND WHY IT IS THIS WAY ROUND
----------------------------------------------
Later entries overwrite earlier ones, so the order below is the precedence,
weakest first:

  1. SENTINEL-NATIVE   -- actions on this process's own tables. Always present,
                          because a deployment with a database always has them.
  2. PLATFORM-NATIVE   -- pods, IAM. Present where cloud credentials are set.
  3. OPERATOR WEBHOOKS -- explicit `SENTINEL_REMEDIATION_ENDPOINTS`.

An explicitly configured webhook wins over anything Sentinel could do itself.
That is deliberate: an operator who pointed `kill_container` at their own runbook
did it on purpose -- their cluster may need an approval workflow this process
knows nothing about -- and silently preferring the native path would override a
decision somebody made.

WHAT CHANGED ABOUT `NullRemediationExecutor`
----------------------------------------------
It used to be what a deployment without `SENTINEL_REMEDIATION_ENDPOINTS` got,
and that was correct while every action needed an outbound integration. It is no
longer correct, because seven catalogue actions are writes to tables this process
owns and need nothing configured at all.

`NullRemediationExecutor` is now reachable only when there is genuinely nothing:
no webhooks, no cloud credentials, and no store. The distinction it draws --
refuse with a reason rather than return a false receipt -- is unchanged and is
still enforced per action by `supports()`, which returns False for `rotate_token`
whatever else is configured.
"""

from __future__ import annotations

from typing import Any

from sentinel.composition.platform_wiring import build_native_remediation
from sentinel.composition.settings import Settings
from sentinel.infrastructure.native_containment import build_sentinel_integrations
from sentinel.infrastructure.outbound import HardenedHttpClient
from sentinel.infrastructure.remediation import build_remediation_executor

__all__ = ["build_executor"]


def build_executor(
    settings: Settings,
    *,
    registry: Any,
    capabilities: Any,
    mcp_registry: Any,
    audit: Any,
    clock: Any,
    http_client: HardenedHttpClient | None = None,
) -> Any:
    """Build the executor this deployment's configuration and store call for."""
    native: dict[str, Any] = {}

    # Containment on SENTINEL'S OWN state, which needs no integration at all.
    # Every one of these is a write to a table this process already owns -- yet
    # each previously required an operator-run webhook that called back in to do
    # what Sentinel could do directly. Almost nobody stood one up, so
    # `NullRemediationExecutor` was what most deployments got and the CRITICAL
    # containment path ended in `unsupported_action`.
    native.update(
        build_sentinel_integrations(
            registry=registry,
            capabilities=capabilities,
            mcp_registry=mcp_registry,
            clock=clock,
        )
    )

    # Platform containment, from the same credentials the tool adapters use.
    native.update(build_native_remediation(settings, http_client=http_client))

    return build_remediation_executor(
        endpoints=settings.remediation_endpoints,
        client=http_client or HardenedHttpClient(),
        audit=audit,
        clock=clock,
        dry_run=settings.remediation_dry_run,
        native=native,
    )
