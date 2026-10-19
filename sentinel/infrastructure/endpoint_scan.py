"""Read agent configuration off a machine. Allowlisted paths only.

WHAT IT READS, AND NOTHING ELSE
--------------------------------
`ALLOWLIST` is the complete set. There is no directory walk, no glob over a
home directory, no "and anything that looks like a config". A sensor that
discovers files is a sensor that will one day discover something personal, and
the day after that it is uninstalled everywhere and never reinstalled.

Every path is relative to a scan root that is injected, so:

  * the tests exercise real parsing against a fabricated tree rather than
    against whatever happens to be on the machine running them;
  * a home directory NAME never leaves the endpoint -- findings record the
    allowlisted relative path, not an absolute one containing a username.

CREDENTIALS ARE DIGESTED, NEVER RETAINED
-----------------------------------------
An MCP server block routinely carries an API key in `env`. This records THAT a
secret is present and a 16-character digest, so the same key appearing on
twelve machines is correlatable -- which is the question worth answering --
without the sensor becoming a central store of every developer's credentials.
That would be a worse problem than the one it was deployed to solve.

`_looks_like_a_secret` decides by KEY NAME, not by value entropy. Entropy
misfires both ways: a long base64 project id looks like a key, and `pw=hunter2`
does not. A name-based rule is auditable by reading it.

READ-ONLY, STRUCTURALLY
-----------------------
Nothing here opens a file for writing. There is no quarantine and no repair.
An endpoint tool that can modify a developer's configuration has a blast
radius; containment lives on the server side, where it is authorised and
audited.

PLATFORM
--------
Linux and macOS paths are both in the allowlist because the config locations
differ and a sensor that only works on one is a sensor with a coverage hole
nobody notices. Windows paths are absent deliberately -- they need their own
allowlist and their own review, and `ScanOutcome.UNREADABLE` reports honestly
rather than a Windows machine appearing clean.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from sentinel.domain.endpoint_sensor import (
    AgentKind,
    EndpointFinding,
    SecretPresence,
    SensorScan,
    secret_digest,
)

__all__ = [
    "ALLOWLIST",
    "SECRET_KEY_MARKERS",
    "AllowlistEntry",
    "scan_endpoint",
]


@dataclass(frozen=True, slots=True)
class AllowlistEntry:
    """One path this sensor may read, and how to read it."""

    #: Relative to the scan root. Never absolute, so no username travels.
    path: str
    kind: AgentKind
    #: Which parser handles it. A name rather than a callable so the allowlist
    #: is data somebody can audit by reading it.
    shape: str
    why: str


#: THE COMPLETE SET. Adding an entry is a deliberate act and a reviewable diff.
ALLOWLIST: tuple[AllowlistEntry, ...] = (
    AllowlistEntry(
        path=".mcp.json",
        kind=AgentKind.MCP_SERVER,
        shape="mcp_servers",
        why="project-scoped MCP servers, checked into or beside a repository",
    ),
    AllowlistEntry(
        path=".cursor/mcp.json",
        kind=AgentKind.MCP_SERVER,
        shape="mcp_servers",
        why="Cursor's MCP configuration",
    ),
    AllowlistEntry(
        path=".claude/settings.json",
        kind=AgentKind.CODING_AGENT,
        shape="mcp_servers",
        why="Claude Code settings, which may declare MCP servers",
    ),
    AllowlistEntry(
        path="Library/Application Support/Claude/claude_desktop_config.json",
        kind=AgentKind.MCP_SERVER,
        shape="mcp_servers",
        why="Claude Desktop on macOS",
    ),
    AllowlistEntry(
        path=".config/Claude/claude_desktop_config.json",
        kind=AgentKind.MCP_SERVER,
        shape="mcp_servers",
        why="Claude Desktop on Linux",
    ),
    AllowlistEntry(
        path=".continue/config.json",
        kind=AgentKind.CODING_AGENT,
        shape="mcp_servers",
        why="Continue, which also declares MCP servers",
    ),
    AllowlistEntry(
        path="requirements.txt",
        kind=AgentKind.FRAMEWORK,
        shape="requirements",
        why="declared agent frameworks. Presence is inventory, not use",
    ),
    AllowlistEntry(
        path="pyproject.toml",
        kind=AgentKind.FRAMEWORK,
        shape="pyproject",
        why="the same, for projects that declare dependencies there",
    ),
    AllowlistEntry(
        path="package.json",
        kind=AgentKind.FRAMEWORK,
        shape="package_json",
        why="JavaScript agent frameworks and MCP SDKs",
    ),
    AllowlistEntry(
        path=".github/workflows",
        kind=AgentKind.CI_RUNNER,
        shape="workflow_dir",
        why="CI runners, which execute with credentials nobody watches live",
    ),
)

#: Agent framework packages worth recording. A short, explicit list: a
#: substring match on "agent" would report `useragent` and `pytest-agent`.
FRAMEWORK_MARKERS: frozenset[str] = frozenset({
    "langchain",
    "langgraph",
    "crewai",
    "autogen",
    "pyautogen",
    "llama-index",
    "llama_index",
    "semantic-kernel",
    "haystack-ai",
    "mcp",
    "@modelcontextprotocol/sdk",
    "anthropic",
    "openai",
})

#: A key whose VALUE is a credential. Decided by name, not by entropy: a long
#: base64 project id looks like a key and `pw=hunter2` does not, so an
#: entropy rule misfires in both directions. This list is auditable by reading.
SECRET_KEY_MARKERS: frozenset[str] = frozenset({
    "token",
    "key",
    "secret",
    "password",
    "passwd",
    "credential",
    "auth",
    "apikey",
    "api_key",
    "access_key",
    "private",
    "bearer",
})


def _looks_like_a_secret(name: str) -> bool:
    lowered = name.lower()
    return any(marker in lowered for marker in SECRET_KEY_MARKERS)


def _reachable_hosts(block: Mapping[str, Any]) -> tuple[str, ...]:
    """Hosts this server configuration points at.

    Names only. What a server is reached AT is needed to assess exposure; what
    travels over that connection is not this sensor's business.
    """
    hosts: list[str] = []
    for key in ("url", "endpoint", "baseUrl", "base_url", "host"):
        value = block.get(key)
        if isinstance(value, str) and value.strip():
            hosts.append(value.strip())
    args = block.get("args")
    if isinstance(args, list):
        hosts.extend(
            argument
            for argument in args
            if isinstance(argument, str) and argument.startswith(("http://", "https://"))
        )
    return tuple(dict.fromkeys(hosts))


def _parse_mcp_servers(
    document: Mapping[str, Any], *, entry: AllowlistEntry
) -> list[EndpointFinding]:
    """MCP server blocks, wherever this file shape puts them."""
    servers = document.get("mcpServers") or document.get("mcp_servers") or {}
    if not isinstance(servers, Mapping):
        return []

    findings: list[EndpointFinding] = []
    for name, block in servers.items():
        if not isinstance(block, Mapping):
            continue
        # Narrowed into its own name rather than relying on a boolean flag.
        # `inspected` guarded the access correctly and mypy could not follow
        # it, which is a fair complaint: a reader cannot follow it either, and
        # the flag would keep guarding it after somebody moved the access.
        environment = block.get("env")
        digests: list[str] = []
        inspected = isinstance(environment, Mapping)
        if isinstance(environment, Mapping):
            digests = [
                secret_digest(str(value))
                for key, value in environment.items()
                if _looks_like_a_secret(str(key)) and str(value).strip()
            ]

        command = block.get("command")
        findings.append(
            EndpointFinding(
                kind=entry.kind,
                name=str(name),
                source=entry.path,
                secret_digests=tuple(digests),
                secrets=(
                    SecretPresence.PRESENT
                    if digests
                    else SecretPresence.ABSENT
                    if inspected
                    else SecretPresence.NOT_INSPECTED
                ),
                reaches=_reachable_hosts(block),
                command=str(command) if isinstance(command, str) else "",
            )
        )
    return findings


def _parse_requirements(text: str, *, entry: AllowlistEntry) -> list[EndpointFinding]:
    findings: list[EndpointFinding] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Split on the first version specifier so `langgraph>=0.2` matches.
        name = stripped
        for separator in ("==", ">=", "<=", "~=", ">", "<", "[", ";"):
            name = name.split(separator)[0]
        name = name.strip().lower()
        if name in FRAMEWORK_MARKERS:
            findings.append(
                EndpointFinding(
                    kind=entry.kind,
                    name=name,
                    source=entry.path,
                    secrets=SecretPresence.ABSENT,
                    version=stripped[len(name):].strip() or "",
                )
            )
    return findings


def _parse_package_json(
    document: Mapping[str, Any], *, entry: AllowlistEntry
) -> list[EndpointFinding]:
    findings: list[EndpointFinding] = []
    for section in ("dependencies", "devDependencies"):
        block = document.get(section)
        if not isinstance(block, Mapping):
            continue
        for name, version in block.items():
            if str(name).lower() in FRAMEWORK_MARKERS:
                findings.append(
                    EndpointFinding(
                        kind=entry.kind,
                        name=str(name),
                        source=entry.path,
                        secrets=SecretPresence.ABSENT,
                        version=str(version),
                    )
                )
    return findings


def _parse_pyproject(text: str, *, entry: AllowlistEntry) -> list[EndpointFinding]:
    """Dependencies, without a TOML parser.

    Deliberately crude and deliberately conservative: it looks for a marker
    package name inside a dependency-looking line. A real TOML parse would be
    better and is one more dependency in a component that runs on other
    people's machines, which needs a better reason than tidiness.
    """
    findings: list[EndpointFinding] = []
    for line in text.splitlines():
        stripped = line.strip().strip(",").strip('"').strip("'")
        for marker in FRAMEWORK_MARKERS:
            if stripped.lower().startswith(marker):
                findings.append(
                    EndpointFinding(
                        kind=entry.kind,
                        name=marker,
                        source=entry.path,
                        secrets=SecretPresence.ABSENT,
                        version=stripped[len(marker):].strip() or "",
                    )
                )
                break
    return findings


def _parse_workflow_dir(
    root: Path, *, entry: AllowlistEntry
) -> tuple[list[EndpointFinding], list[str]]:
    """CI workflow files. Names only, contents not parsed.

    The presence of a runner is the finding; what it runs is a repository
    question rather than an endpoint one, and parsing it here would mean
    reading arbitrary YAML off a developer's disk for no additional decision.
    """
    directory = root / entry.path
    findings: list[EndpointFinding] = []
    unreadable: list[str] = []
    try:
        names = sorted(
            path.name
            for path in directory.iterdir()
            if path.suffix in {".yml", ".yaml"}
        )
    except OSError:
        return findings, [entry.path]

    for name in names:
        findings.append(
            EndpointFinding(
                kind=entry.kind,
                name=name,
                source=entry.path,
                secrets=SecretPresence.NOT_INSPECTED,
            )
        )
    return findings, unreadable


def scan_endpoint(
    *,
    root: Path,
    host_id: str,
    now: datetime | None = None,
    allowlist: Iterable[AllowlistEntry] | None = None,
) -> SensorScan:
    """Read the allowlisted paths under `root`. Reads nothing else.

    A path that does not exist is neither inspected nor unreadable -- it is
    simply absent, and counting absence as inspection would make an empty
    machine look thoroughly scanned. A path that exists and cannot be read IS
    unreadable, which is what turns the scan PARTIAL and makes its absences
    stop being evidence.
    """
    entries = tuple(allowlist) if allowlist is not None else ALLOWLIST
    findings: list[EndpointFinding] = []
    inspected: list[str] = []
    unreadable: list[str] = []

    for entry in entries:
        target = root / entry.path

        if entry.shape == "workflow_dir":
            if not target.is_dir():
                continue
            found, failed = _parse_workflow_dir(root, entry=entry)
            inspected.append(entry.path)
            findings.extend(found)
            unreadable.extend(failed)
            continue

        if not target.is_file():
            continue

        try:
            text = target.read_text(encoding="utf-8")
        except OSError:
            # Exists and unreadable. Recorded, because an absence in a scan
            # that could not read is not an absence of agents.
            unreadable.append(entry.path)
            continue

        inspected.append(entry.path)

        try:
            if entry.shape == "mcp_servers":
                findings.extend(
                    _parse_mcp_servers(json.loads(text), entry=entry)
                )
            elif entry.shape == "package_json":
                findings.extend(
                    _parse_package_json(json.loads(text), entry=entry)
                )
            elif entry.shape == "requirements":
                findings.extend(_parse_requirements(text, entry=entry))
            elif entry.shape == "pyproject":
                findings.extend(_parse_pyproject(text, entry=entry))
        except (json.JSONDecodeError, ValueError, TypeError):
            # A malformed file is UNREADABLE rather than empty. A config the
            # sensor could not parse may declare a dozen servers, and treating
            # it as zero is the difference between a gap and a clean bill.
            unreadable.append(entry.path)
            if entry.path in inspected:
                inspected.remove(entry.path)

    moment = now or datetime.now(timezone.utc)
    return SensorScan(
        host_id=host_id,
        findings=tuple(findings),
        unreadable=tuple(unreadable),
        inspected=tuple(inspected),
        scanned_at=moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
