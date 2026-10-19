"""Local MCP client configuration discovery.

This is "shadow MCP" discovery: it reads client config files from supplied
paths and records the MCP servers they would start or call. It never executes a
command, never connects to a server, and never reads tool descriptions.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from sentinel.domain.assets import (
    AssetInventory,
    AssetKind,
    AssetRecord,
    DiscoveryCoverage,
    Unreachable,
)
from sentinel.infrastructure.platforms.discovery_support import _now, _text

__all__ = [
    "LocalMcpConfigPath",
    "local_mcp_config_connector",
]

_CONNECTOR = "local_mcp_configs"


@dataclass(frozen=True, slots=True)
class LocalMcpConfigPath:
    """One config file to inspect, labelled by the client that owns it."""

    client: str
    path: Path


def _fingerprint(value: Mapping[str, Any]) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()[:24]


def _server_maps(document: Any) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(document, Mapping):
        return ()
    candidates = [
        document.get("mcpServers"),
        document.get("servers"),
        (document.get("mcp") or {}).get("servers")
        if isinstance(document.get("mcp"), Mapping)
        else None,
    ]
    return tuple(c for c in candidates if isinstance(c, Mapping))


def _risks(url: str, command: str, args: Sequence[str]) -> tuple[str, ...]:
    risks: list[str] = []
    parsed = urlsplit(url) if url else None
    if parsed is not None and parsed.scheme == "http":
        risks.append("plain-http")
    host = (parsed.hostname or "").lower() if parsed is not None else ""
    # These literals are what this connector DETECTS, not what it binds: an
    # MCP server configured to listen on every interface is the finding.
    # Bandit's B104 cannot tell a comparison from a bind, so it is silenced
    # on exactly these two lines.
    if host in {"0.0.0.0", "::", "[::]"}:  # nosec B104
        risks.append("public-bind-url")
    lowered_args = [a.lower() for a in args]
    if "--host" in lowered_args:
        index = lowered_args.index("--host")
        if len(lowered_args) > index + 1 and lowered_args[index + 1] in {
            "0.0.0.0",  # nosec B104
            "::",
        }:
            risks.append("public-bind-command")
    if Path(command).name == "npx":
        for index, arg in enumerate(args):
            if arg in {"-y", "--yes"} and len(args) > index + 1:
                package = args[index + 1]
                if not package.startswith(("./", "../", "/")):
                    risks.append(f"npx-y-remote-package:{package}")
                break
    return tuple(risks)


def local_mcp_config_connector(
    *,
    paths: Sequence[LocalMcpConfigPath],
) -> Any:
    """Read supplied MCP client configs and report declared servers."""
    if not paths:
        raise ValueError("local MCP config discovery needs at least one path")

    class _LocalMcpConfigConnector:
        name = _CONNECTOR

        def discover(self) -> AssetInventory:
            assets: list[AssetRecord] = []
            unreachable: list[Unreachable] = []
            examined = 0
            scopes: list[str] = []

            for entry in paths:
                scopes.append(f"{entry.client}:{entry.path}")
                try:
                    raw = entry.path.read_text(encoding="utf-8")
                except OSError as exc:
                    unreachable.append(
                        Unreachable(
                            target=str(entry.path),
                            reason=f"could not read config: {exc}",
                        )
                    )
                    continue
                try:
                    document = json.loads(raw)
                except json.JSONDecodeError as exc:
                    unreachable.append(
                        Unreachable(
                            target=str(entry.path),
                            reason=(
                                f"malformed JSON: {exc}. Recorded as "
                                "unreachable rather than as an empty config."
                            ),
                        )
                    )
                    continue
                maps = _server_maps(document)
                if not maps:
                    unreachable.append(
                        Unreachable(
                            target=str(entry.path),
                            reason="no recognised MCP server map in config",
                        )
                    )
                    continue
                for server_map in maps:
                    for label, config in server_map.items():
                        examined += 1
                        if not isinstance(config, Mapping):
                            unreachable.append(
                                Unreachable(
                                    target=f"{entry.path}:{label}",
                                    reason="server entry was not a JSON object",
                                )
                            )
                            continue
                        command = _text(config.get("command"))
                        raw_args = config.get("args")
                        args = (
                            tuple(str(a) for a in raw_args)
                            if isinstance(raw_args, list)
                            else ()
                        )
                        url = _text(config.get("url"))
                        if not command and not url:
                            unreachable.append(
                                Unreachable(
                                    target=f"{entry.path}:{label}",
                                    reason="server entry has neither command nor url",
                                )
                            )
                            continue
                        evidence = {
                            "client": entry.client,
                            "label": str(label),
                            "command": command,
                            "args": list(args),
                            "url": url,
                        }
                        digest = _fingerprint(evidence)
                        assets.append(
                            AssetRecord(
                                kind=AssetKind.MCP_SERVER,
                                identifier=f"mcp-config://{digest}",
                                source=_CONNECTOR,
                                native_type="McpClientConfigServer",
                                display_name=str(label),
                                attributes={
                                    "client": entry.client,
                                    "path": str(entry.path),
                                    "command": command,
                                    "url": url,
                                    "fingerprint": digest,
                                    "risks": list(_risks(url, command, args)),
                                },
                            )
                        )

            return AssetInventory(
                connector=_CONNECTOR,
                assets=tuple(assets),
                coverage=DiscoveryCoverage(
                    scope=tuple(scopes),
                    examined=examined,
                    unreachable=tuple(unreachable),
                    permissions_used=("read supplied local MCP config files",),
                    retrieved_at=_now(),
                    pagination_complete=True,
                ),
            )

    return _LocalMcpConfigConnector()
