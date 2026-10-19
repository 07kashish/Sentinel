"""Consent-based local presence inventory. Standard library only; no file contents.

This is self-reported inventory, never agent enrollment or enforcement evidence.
The report contains fixed probe identifiers, not paths, hostnames or credentials.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from uuid import UUID, uuid4

SCHEMA = "sentinel.device-discovery/v2"
MAX_REPORT_BYTES = 32_768
TOOLS = MappingProxyType({
    "gemini": "Gemini CLI",
    "antigravity": "Antigravity",
    "claude": "Claude",
    "cursor": "Cursor",
    "codex": "Codex",
    "continue": "Continue",
    "copilot": "GitHub Copilot",
    "windsurf": "Windsurf",
    "zed": "Zed",
    "aider": "Aider",
    "goose": "Goose",
    "opencode": "OpenCode",
    "chatgpt": "ChatGPT",
    "perplexity": "Perplexity",
    "ollama": "Ollama",
    "lmstudio": "LM Studio",
    "jan": "Jan",
    "gpt4all": "GPT4All",
})
# (tool, relative path, expected directory). These paths are checked, never read.
CONFIG_PROBES = MappingProxyType({
    "gemini-settings": ("gemini", ".gemini/settings.json", False),
    "antigravity-mcp": ("antigravity", ".gemini/config/mcp_config.json", False),
    "antigravity-legacy": ("antigravity", ".gemini/antigravity/mcp_config.json", False),
    "antigravity-cli-state": ("antigravity", ".gemini/antigravity-cli", True),
    "claude-settings": ("claude", ".claude/settings.json", False),
    "claude-desktop-config": ("claude", "Library/Application Support/Claude/claude_desktop_config.json", False),
    "cursor-mcp": ("cursor", ".cursor/mcp.json", False),
    "codex-config": ("codex", ".codex/config.toml", False),
    "continue-config": ("continue", ".continue/config.yaml", False),
    "copilot-directory": ("copilot", ".config/github-copilot", True),
    "windsurf-directory": ("windsurf", ".codeium/windsurf", True),
    "zed-settings": ("zed", ".config/zed/settings.json", False),
    "aider-config": ("aider", ".aider.conf.yml", False),
    "goose-directory": ("goose", ".config/goose", True),
    "opencode-directory": ("opencode", ".config/opencode", True),
    "ollama-directory": ("ollama", ".ollama", True),
    "lmstudio-directory": ("lmstudio", ".lmstudio", True),
})
APP_PROBES = MappingProxyType({
    "antigravity-app": ("antigravity", "Antigravity.app", True),
    "claude-app": ("claude", "Claude.app", True),
    "cursor-app": ("cursor", "Cursor.app", True),
    "codex-app": ("codex", "Codex.app", True),
    "windsurf-app": ("windsurf", "Windsurf.app", True),
    "zed-app": ("zed", "Zed.app", True),
    "chatgpt-app": ("chatgpt", "ChatGPT.app", True),
    "perplexity-app": ("perplexity", "Perplexity.app", True),
    "ollama-app": ("ollama", "Ollama.app", True),
    "lmstudio-app": ("lmstudio", "LM Studio.app", True),
    "jan-app": ("jan", "Jan.app", True),
    "gpt4all-app": ("gpt4all", "GPT4All.app", True),
})
# (tool, command name). Looked for by NAME in a fixed list of directories; never executed.
CLI_PROBES = MappingProxyType({
    "antigravity-cli": ("antigravity", "agy"),
    "gemini-cli": ("gemini", "gemini"),
    "claude-cli": ("claude", "claude"),
    "codex-cli": ("codex", "codex"),
    "cursor-cli": ("cursor", "cursor-agent"),
    "aider-cli": ("aider", "aider"),
    "goose-cli": ("goose", "goose"),
    "opencode-cli": ("opencode", "opencode"),
    "ollama-cli": ("ollama", "ollama"),
})
# Windows: per-user install FOLDERS under the home directory, by probe. Presence of the folder only.
WINDOWS_APP_DIRS = MappingProxyType({
    "antigravity-app": ("AppData/Local/Programs/Antigravity",),
    "claude-app": ("AppData/Local/AnthropicClaude", "AppData/Local/Programs/Claude"),
    "cursor-app": ("AppData/Local/Programs/cursor",),
    "codex-app": ("AppData/Local/Programs/Codex",),
    "windsurf-app": ("AppData/Local/Programs/Windsurf",),
    "zed-app": ("AppData/Local/Programs/Zed",),
    "chatgpt-app": ("AppData/Local/Programs/ChatGPT",),
    "perplexity-app": ("AppData/Local/Programs/Perplexity",),
    "ollama-app": ("AppData/Local/Programs/Ollama",),
    "lmstudio-app": ("AppData/Local/Programs/LM Studio",),
    "jan-app": ("AppData/Local/Programs/Jan",),
    "gpt4all-app": ("AppData/Local/Programs/GPT4All",),
})
WINDOWS_BIN_DIRS = ("AppData/Roaming/npm", ".local/bin", "bin", ".bun/bin", ".cargo/bin")
WINDOWS_COMMAND_SUFFIXES = (".exe", ".cmd", ".ps1")
HOME_BIN_DIRS = (".local/bin", "bin", ".npm-global/bin", ".bun/bin", ".cargo/bin")
SYSTEM_BIN_DIRS = ("/usr/local/bin", "/opt/homebrew/bin")
CATEGORIES = ("config_presence", "app_presence", "cli_presence")
PROBES = MappingProxyType({**{k: v[0] for k, v in CONFIG_PROBES.items()}, **{k: v[0] for k, v in APP_PROBES.items()},
                           **{k: v[0] for k, v in CLI_PROBES.items()}})
STATES = frozenset({"present", "not_found", "inaccessible", "unsupported", "not_consented"})


def _presence(root: Path, relative: str, directory: bool, *, link_is_present: bool = False) -> str:
    """Reject symlinks and unusual file types; never open, follow or execute a target.

    A command on PATH is normally a link into a package directory, so for the
    command category a link in the final position counts as present -- it is
    still not followed.
    """
    target = root
    try:
        pieces = Path(relative).parts
        for index, piece in enumerate(pieces):
            target = target / piece
            mode = target.lstat().st_mode
            if stat.S_ISLNK(mode):
                return "present" if link_is_present and index == len(pieces) - 1 else "inaccessible"
        return "present" if (stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)) else "inaccessible"
    except FileNotFoundError:
        return "not_found"
    except OSError:
        return "inaccessible"


def _first(states: list[str]) -> str:
    return "present" if "present" in states else "inaccessible" if "inaccessible" in states else "not_found"


def discover(*, home: Path, system: str, config_presence: bool, app_presence: bool, device_id: str,
             cli_presence: bool = False, applications: Path | None = None,
             system_bin_dirs: tuple[str, ...] = SYSTEM_BIN_DIRS) -> dict:
    """Only caller-approved categories are inspected. No network operations."""
    UUID(device_id)
    system = system if system in {"Darwin", "Linux", "Windows"} else "Other"
    observations = []
    for probe, (tool, path, directory) in CONFIG_PROBES.items():
        state = ("not_consented" if not config_presence else "unsupported" if system == "Other"
                 else _presence(home, path, directory))
        observations.append({"probe": probe, "tool": tool, "state": state})
    for probe, (tool, path, directory) in APP_PROBES.items():
        if not app_presence:
            state = "not_consented"
        elif system == "Windows":
            state = _first([_presence(home, folder, True) for folder in WINDOWS_APP_DIRS[probe]])
        elif system != "Darwin":
            state = "unsupported"
        else:
            state = _first([_presence(applications or Path("/Applications"), path, directory),
                            _presence(home / "Applications", path, directory)])
        observations.append({"probe": probe, "tool": tool, "state": state})
    for probe, (tool, command) in CLI_PROBES.items():
        if not cli_presence:
            state = "not_consented"
        elif system == "Windows":
            state = _first([_presence(home, f"{folder}/{command}{suffix}", False, link_is_present=True)
                            for folder in WINDOWS_BIN_DIRS for suffix in WINDOWS_COMMAND_SUFFIXES])
        elif system not in {"Darwin", "Linux"}:
            state = "unsupported"
        else:
            state = _first([_presence(home, f"{folder}/{command}", False, link_is_present=True) for folder in HOME_BIN_DIRS]
                           + [_presence(Path(folder), command, False, link_is_present=True) for folder in system_bin_dirs])
        observations.append({"probe": probe, "tool": tool, "state": state})
    return {
        "schema": SCHEMA, "device_id": device_id, "platform": system,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "consent": {"config_presence": config_presence, "app_presence": app_presence, "cli_presence": cli_presence},
        "observations": observations,
    }


def summarise(report: dict) -> list[tuple[str, list[str]]]:
    """(tool label, probes found present), for tools with at least one positive check."""
    found: dict[str, list[str]] = {}
    for item in report["observations"]:
        if item["state"] == "present":
            found.setdefault(item["tool"], []).append(item["probe"])
    return [(TOOLS[tool], probes) for tool, probes in found.items()]


def render_html(report: dict) -> str:
    """A self-contained page of the same facts. Every value is from a fixed vocabulary or escaped."""
    from html import escape
    rows = "".join(
        f"<tr><td>{escape(TOOLS[item['tool']])}</td><td>{escape(item['probe'])}</td>"
        f"<td class='{escape(item['state'])}'>{escape(item['state'].replace('_', ' '))}</td></tr>"
        for item in report["observations"])
    found = "".join(f"<li><b>{escape(label)}</b> <span>{escape(', '.join(probes))}</span></li>" for label, probes in summarise(report))
    return (
        "<!doctype html><meta charset='utf-8'><title>AI on this device</title>"
        "<style>body{font:15px/1.5 system-ui,sans-serif;max-width:860px;margin:40px auto;padding:0 16px;color:#16181d}"
        "h1{font-size:22px}table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:6px 10px;border-bottom:1px solid #e3e5ea}"
        ".present{color:#0a7a3d;font-weight:600}.not_found,.not_consented,.unsupported{color:#7a808c}.inaccessible{color:#a15c00}"
        "li span{color:#7a808c;font-size:13px}.note{color:#555b66;font-size:13px}</style>"
        "<h1>AI tools found on this device</h1>"
        f"<p class='note'>Device {escape(report['device_id'])} &middot; {escape(report['platform'])} &middot; scanned {escape(report['scanned_at'])}</p>"
        f"<ul>{found or '<li>No known AI tool was found by the approved checks.</li>'}</ul>"
        "<p class='note'>Presence only: a file, application or command with a known name exists. Nothing was opened, run or sent anywhere. "
        "Browser-based and cloud-only AI, renamed or custom installs are not detected. Presence is not activity and not enforcement.</p>"
        f"<table><tr><th>Tool</th><th>Check</th><th>Result</th></tr>{rows}</table>"
    )


def validate_report(report: object) -> dict:
    """Strict shared wire contract. Never reflect rejected input in errors."""
    def refuse():
        raise ValueError("Invalid discovery report; generate it with sentinel-discover.")
    if not isinstance(report, dict) or set(report) != {
        "schema", "device_id", "platform", "scanned_at", "consent", "observations"
    }:
        refuse()
    if report["schema"] != SCHEMA or report["platform"] not in {"Darwin", "Linux", "Windows", "Other"}:
        refuse()
    try:
        if str(UUID(report["device_id"])) != report["device_id"]:
            refuse()
        when = datetime.fromisoformat(report["scanned_at"])
        if when.tzinfo is None or len(report["scanned_at"]) > 40:
            refuse()
    except (TypeError, ValueError, AttributeError):
        refuse()
    consent = report["consent"]
    if not isinstance(consent, dict) or set(consent) != set(CATEGORIES):
        refuse()
    if any(type(v) is not bool for v in consent.values()) or not any(consent.values()):
        refuse()
    observations = report["observations"]
    if not isinstance(observations, list) or len(observations) != len(PROBES):
        refuse()
    seen = set()
    for item in observations:
        if not isinstance(item, dict) or set(item) != {"probe", "tool", "state"}:
            refuse()
        probe = item["probe"]
        if not isinstance(probe, str) or probe not in PROBES or probe in seen:
            refuse()
        if item["tool"] != PROBES[probe] or not isinstance(item["state"], str) or item["state"] not in STATES:
            refuse()
        category = ("config_presence" if probe in CONFIG_PROBES else "app_presence" if probe in APP_PROBES else "cli_presence")
        if not consent[category] and item["state"] != "not_consented":
            refuse()
        if consent[category] and item["state"] == "not_consented":
            refuse()
        seen.add(probe)
    return report


def _write_new(path: Path, content: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(content)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Find the AI tools on this device by presence. No contents, keys or network access.")
    parser.add_argument("--explain", action="store_true", help="List exactly what would be checked, and exit")
    parser.add_argument("--consent", action="store_true", help="Approve the selected read-only presence checks")
    parser.add_argument("--all", action="store_true", help="Shorthand for the three categories below")
    parser.add_argument("--config-presence", action="store_true", help="Known AI configuration files and folders in your home")
    parser.add_argument("--app-presence", action="store_true", help="Known AI applications (macOS bundles; Windows per-user install folders)")
    parser.add_argument("--cli-presence", action="store_true", help="Known AI commands in the usual command folders")
    parser.add_argument("--device-id", default=None, help="Reuse a report UUID to replace that device's inventory")
    parser.add_argument("--output", type=Path, help="New JSON report file (will never overwrite a file)")
    parser.add_argument("--html", type=Path, help="New readable HTML report file (will never overwrite a file)")
    args = parser.parse_args(argv)
    if args.explain:
        sys.stdout.write("Only these paths are checked for existence and type. File contents are never opened.\n")
        for _, (_, path, _) in CONFIG_PROBES.items():
            sys.stdout.write("  home/" + path + "\n")
        for _, (_, path, _) in APP_PROBES.items():
            sys.stdout.write("  /Applications/ or home/Applications/: " + path + "\n")
        for probe, folders_ in WINDOWS_APP_DIRS.items():
            sys.stdout.write("  Windows only, folder: home/" + " or home/".join(folders_) + "\n")
        folders = ", ".join(["home/" + folder for folder in HOME_BIN_DIRS] + list(SYSTEM_BIN_DIRS)
                            + ["Windows: home/" + folder for folder in WINDOWS_BIN_DIRS])
        for _, (_, command) in CLI_PROBES.items():
            sys.stdout.write("  command named " + command + " in: " + folders + " (never run)\n")
        sys.stdout.write("Report: random device UUID, timestamp, OS family, consent and fixed presence states. No host/user names, credentials, commands or browsing history. No network transmission. Discovery does not enable enforcement.\n")
        return 0
    config, apps, clis = (args.all or args.config_presence, args.all or args.app_presence, args.all or args.cli_presence)
    if not args.consent or not (config or apps or clis):
        parser.error("Review --explain, then pass --consent and --all or at least one presence category.")
    try:
        report = validate_report(discover(home=Path.home(), system=platform.system(), config_presence=config,
                                          app_presence=apps, cli_presence=clis, device_id=args.device_id or str(uuid4())))
        encoded = json.dumps(report, indent=2) + "\n"
        if args.html:
            _write_new(args.html, render_html(report))
        if args.output:
            _write_new(args.output, encoded)
        elif not args.html:
            sys.stdout.write(encoded)
    except (OSError, ValueError):
        sys.stderr.write("Discovery failed: check the device UUID and choose new writable output filenames.\n")
        return 2
    summary = summarise(report)
    lines = [f"  {label}: {', '.join(probes)}" for label, probes in summary] or ["  none of the known AI tools was found by the approved checks"]
    sys.stderr.write("AI tools found on this device (presence only; nothing was opened, run or sent):\n" + "\n".join(lines) + "\n")
    if args.output:
        sys.stderr.write("Report saved. Preview it, then import it under Pilot setup in your Sentinel console.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
