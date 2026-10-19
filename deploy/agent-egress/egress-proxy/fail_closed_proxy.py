"""Fail-closed HTTP egress proxy stub for Sentinel agent workloads (F-11).

Agents that cannot use the SDK or POST /v1/tools/execute may run this process
as a sidecar and point HTTP(S)_PROXY at it. The proxy:

1. Probes Sentinel ``/health/live`` before allowing any upstream CONNECT/forward.
2. Refuses all traffic when Sentinel is unreachable (fail closed).
3. Optionally allowlists destinations (default: only the configured Sentinel base).

This is a deployment-contract control, not transparent OS wire interception.
Unit tests cover the gate logic without requiring a live cluster.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlparse

__all__ = [
    "EgressProxyConfig",
    "FailClosedEgressGate",
    "ProxyDenied",
]


class ProxyDenied(RuntimeError):
    """Upstream request refused by the fail-closed gate."""


@dataclass(frozen=True, slots=True)
class EgressProxyConfig:
    sentinel_base_url: str
    health_path: str = "/health/live"
    health_timeout_seconds: float = 2.0
    #: When True, only the Sentinel host (and optional extra hosts) may be dialed.
    restrict_destinations: bool = True
    extra_allowed_hosts: tuple[str, ...] = ()


HealthProbe = Callable[[str, float], bool]


def _default_probe(url: str, timeout: float) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310
            return 200 <= getattr(resp, "status", 200) < 300
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


class FailClosedEgressGate:
    """Decide whether an agent egress request may proceed."""

    __slots__ = ("_cfg", "_probe", "_sentinel_reachable")

    def __init__(
        self,
        config: EgressProxyConfig,
        *,
        probe: HealthProbe | None = None,
    ) -> None:
        if not str(config.sentinel_base_url or "").strip():
            raise ValueError("sentinel_base_url required")
        self._cfg = config
        self._probe = probe or _default_probe
        self._sentinel_reachable = False

    @property
    def sentinel_reachable(self) -> bool:
        return self._sentinel_reachable

    def refresh_sentinel_health(self) -> bool:
        base = self._cfg.sentinel_base_url.rstrip("/")
        path = self._cfg.health_path if self._cfg.health_path.startswith("/") else f"/{self._cfg.health_path}"
        url = f"{base}{path}"
        self._sentinel_reachable = self._probe(url, self._cfg.health_timeout_seconds)
        return self._sentinel_reachable

    def _allowed_hosts(self) -> set[str]:
        host = urlparse(self._cfg.sentinel_base_url).hostname
        allowed = {h.lower() for h in self._cfg.extra_allowed_hosts}
        if host:
            allowed.add(host.lower())
        return allowed

    def allow_request(self, *, method: str, target_host: str, target_port: int) -> None:
        """Raise ProxyDenied unless Sentinel is healthy and destination is allowed."""
        del method, target_port  # reserved for future L7 policy
        if not self.refresh_sentinel_health():
            raise ProxyDenied(
                "Sentinel /health/live unreachable; fail-closed egress proxy denying traffic"
            )
        if not self._cfg.restrict_destinations:
            return
        host = (target_host or "").strip().lower()
        if not host or host not in self._allowed_hosts():
            raise ProxyDenied(
                f"destination host {target_host!r} not in Sentinel allowlist; denied"
            )


def main(argv: list[str] | None = None) -> int:
    """CLI: check gate once (for readiness) or print contract JSON."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sentinel-url",
        default="http://sentinel.sentinel.svc:8000",
        help="Sentinel base URL for health probes",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Probe Sentinel and exit 0 only if healthy (sidecar readiness)",
    )
    parser.add_argument(
        "--print-contract",
        action="store_true",
        help="Print deployment-contract metadata as JSON",
    )
    args = parser.parse_args(argv)
    if args.print_contract:
        print(
            json.dumps(
                {
                    "contract": "protect-egress-v1",
                    "component": "fail-closed-egress-proxy",
                    "fail_closed_when": "sentinel_health_unreachable",
                    "tool_path_annotation": "egress-proxy",
                }
            )
        )
        return 0
    gate = FailClosedEgressGate(EgressProxyConfig(sentinel_base_url=args.sentinel_url))
    if args.check:
        ok = gate.refresh_sentinel_health()
        print("sentinel_reachable" if ok else "sentinel_unreachable")
        return 0 if ok else 2
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
