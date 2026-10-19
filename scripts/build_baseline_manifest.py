"""Phase 0: the repository baseline, captured before anything is changed.

WHY A SCRIPT AND NOT A DOCUMENT
--------------------------------
A baseline written by hand is a baseline that drifts the moment somebody edits
the tree, and its numbers cannot be re-derived to check. This produces a
machine-readable manifest keyed by the commit it describes, so "what did the
repository look like before this work" is answerable by running the script at
that commit rather than by trusting prose.

NEVER OVERWRITES
----------------
The manifest is written to `release/baseline/<short-commit>/manifest.json` and
the script REFUSES to overwrite an existing one. A baseline that can be
regenerated in place is a baseline that can be quietly adjusted to match
whatever the current numbers happen to be, which is the opposite of a baseline.
Pass `--force` only to repair a manifest you know to be corrupt, and expect to
explain it.

WHAT IT DELIBERATELY DOES NOT DO
--------------------------------
It does not run the test suite. Test results are their own artifact with their
own runtime and their own failure modes, and folding them in here would mean a
baseline that takes forty minutes and fails when a database is unavailable. The
manifest records WHERE the test evidence should be found and whether it is
present; `--tests <path>` links a junit/summary artifact in.

It also records no performance numbers. Measured latency belongs to a benchmark
run against a known machine, and inventing a number here to fill a field is the
failure this whole codebase is arranged against.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

#: Modules whose presence IS a security control. Listed explicitly rather than
#: pattern-matched: a control inventory assembled by grepping for the word
#: "security" is a list of files that mention it, not a list of controls.
SECURITY_CONTROLS: dict[str, str] = {
    "sentinel/application/protect_gate.py": "deterministic authorization decision",
    "sentinel/application/tool_runner.py": "kill switch, budget, circuit breaker",
    "sentinel/application/tool_proxy.py": "the only sanctioned side-effect path",
    "sentinel/application/agent_capabilities.py": "per-agent tool grants",
    "sentinel/application/a2a_gateway.py": "delegation authorization",
    "sentinel/domain/a2a.py": "privilege amplification, loops, card drift",
    "sentinel/domain/fence.py": "execution fencing",
    "sentinel/domain/action_semantics.py": "platform action classification",
    "sentinel/domain/effective_permissions.py": "transitive reach closure",
    "sentinel/domain/skills.py": "skill provenance and risk",
    "sentinel/infrastructure/outbound.py": "SSRF, DNS rebinding, redirect refusal",
    "sentinel/infrastructure/platforms/ceiling.py": "tier ceiling containment",
    "sentinel/infrastructure/native_containment.py": "containment on own state",
    "sentinel/infrastructure/mcp_registry.py": "MCP enrolment and tool pinning",
    "sentinel/infrastructure/a2a_registry.py": "durable agent cards",
    "sentinel/infrastructure/skill_scanner.py": "static skill analysis",
    "sentinel/infrastructure/sql/schema.py": "row-level security policy",
    "sentinel/infrastructure/remediation.py": "guarded remediation execution",
    "sentinel/infrastructure/evidence.py": "canonical evidence, approval planning",
    "sentinel/interface/mcp_proxy_routes.py": "MCP wire enforcement",
    "sentinel/interface/a2a_proxy_routes.py": "A2A wire enforcement",
}

#: Tables outside row-level security ON PURPOSE, each with the reason. Anything
#: NOT here and not protected is a finding.
#:
#: The distinction matters more than it looks: `PROTECTED_TABLES` says what is
#: covered, and without this table a reader cannot tell "nobody decided about
#: this one" from "somebody decided and wrote down why". Those need opposite
#: responses.
RLS_EXEMPT: dict[str, str] = {
    "tenants": (
        "the directory used to ESTABLISH a scope; scoping it to a context that "
        "has not been established yet would deadlock startup"
    ),
    "schema_migrations": "schema state, owned by the migration runner, not a tenant",
    "leader_locks": "process coordination; holds a job name and a holder id",
    "webauthn_challenges": (
        "a challenge is issued BEFORE the caller is known, so the row exists "
        "before there is a tenant to scope it to. It holds no secret -- a "
        "challenge is a public nonce whose only property is being single-use. "
        "Recorded at sql/migrate.py alongside the identity migrations."
    ),
}

#: Where each honest limitation is recorded. The point of the inventory is that
#: a limitation lives in ONE place a reader can find, not scattered in prose.
LIMITATION_SOURCES: tuple[str, ...] = (
    "README.md",
    "docs/A2A_GATEWAY.md",
    "docs/MCP_GATEWAY.md",
    "docs/TOOL_GATEWAY.md",
    "docs/AGENT_DISCOVERY.md",
    "docs/SKILL_REGISTRY.md",
    "docs/PRODUCTION_READINESS_REPORT.md",
)


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True, check=False
    ).stdout.strip()


def _sha256_of_tree(paths: list[Path]) -> str:
    """One digest over every source file, path-sorted.

    Binds the manifest to the exact source it describes. A manifest whose tree
    digest does not match the working tree is a manifest for a different tree,
    and Phase 1's release gate rejects evidence on exactly that basis.
    """
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(str(path.relative_to(ROOT)).replace("\\", "/").encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _python_files(package: str) -> list[Path]:
    return [
        p
        for p in sorted((ROOT / package).rglob("*.py"))
        if "__pycache__" not in p.parts
    ]


def _dependency_graph(files: list[Path]) -> dict[str, list[str]]:
    """Intra-package imports, from the AST rather than from a regex.

    A regex over `import` lines counts strings inside docstrings and comments;
    the AST counts what the interpreter will actually resolve.
    """
    graph: dict[str, list[str]] = {}
    for path in files:
        module = (
            str(path.relative_to(ROOT))
            .replace("\\", "/")
            .removesuffix(".py")
            .replace("/", ".")
        )
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            graph[module] = ["<unparseable>"]
            continue
        targets: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module.startswith("sentinel."):
                    targets.add(node.module)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("sentinel."):
                        targets.add(alias.name)
        graph[module] = sorted(targets)
    return graph


def _api_inventory() -> list[dict[str, str]]:
    pattern = re.compile(r'@app\.(get|post|put|delete|patch)\(\s*"([^"]+)"')
    found: list[dict[str, str]] = []
    for path in _python_files("sentinel/interface"):
        text = path.read_text(encoding="utf-8")
        for method, route in pattern.findall(text):
            found.append(
                {
                    "method": method.upper(),
                    "path": route,
                    "module": str(path.relative_to(ROOT)).replace("\\", "/"),
                }
            )
    return sorted(found, key=lambda r: (r["path"], r["method"]))


def _schema_inventory() -> dict[str, Any]:
    sys.path.insert(0, str(ROOT))
    from sentinel.infrastructure.sql.migrate import MIGRATIONS, CURRENT_VERSION
    from sentinel.infrastructure.sql.schema import PROTECTED_TABLES, SCHEMA_STATEMENTS

    table = re.compile(
        r"CREATE TABLE IF NOT EXISTS\s+([a-z0-9_]+)", re.IGNORECASE
    )
    declared = sorted(
        {m.group(1) for s in SCHEMA_STATEMENTS if (m := table.search(s))}
    )
    return {
        "current_version": CURRENT_VERSION,
        "migration_count": len(MIGRATIONS),
        "migrations": [
            {"version": v, "description": d} for v, d, _fn in MIGRATIONS
        ],
        "declared_tables": declared,
        "protected_tables": sorted(PROTECTED_TABLES),
        # The gap that matters: a tenant-scoped table NOT under RLS is a
        # cross-tenant read waiting to be noticed.
        #
        # Every table that is unprotected ON PURPOSE is listed in
        # `RLS_EXEMPT` with its reason, so this field means UNEXPECTEDLY
        # unprotected. The first run of this script reported
        # `webauthn_challenges` as a finding when it is a documented decision --
        # and a field that cries wolf is a field a reader learns to skip, which
        # is worse than not having it.
        "declared_but_unprotected": sorted(
            set(declared) - set(PROTECTED_TABLES) - set(RLS_EXEMPT)
        ),
        "rls_exempt_by_decision": RLS_EXEMPT,
    }


def _test_inventory() -> dict[str, Any]:
    modules = sorted(
        p.name for p in (ROOT / "tests_arch").glob("test_*.py")
    )
    counts: dict[str, int] = {}
    total = 0
    for name in modules:
        text = (ROOT / "tests_arch" / name).read_text(encoding="utf-8")
        n = len(re.findall(r"^def test_", text, re.M))
        counts[name] = n
        total += n
    return {
        "module_count": len(modules),
        "declared_test_functions": total,
        "note": (
            "declared functions, NOT collected tests: parametrised tests expand "
            "at collection and this count does not. Use the pytest artifact for "
            "the collected number."
        ),
        "per_module": counts,
    }


def _integration_inventory() -> dict[str, Any]:
    """What this build can actually reach, and by what means.

    Absence is recorded as explicitly as presence. An integration inventory that
    lists only what exists reads as a capability claim.
    """
    return {
        "platform_adapters": sorted(
            p.stem
            for p in (ROOT / "sentinel/infrastructure/platforms").glob("*.py")
            if p.stem not in {"__init__", "ceiling"}
        ),
        "siem_transports": ["webhook", "otlp", "syslog"],
        "attestation": ["http_gateway", "none"],
        "not_supported": {
            "aws_s3": "REST payload signing does not generalise from POST-to-/",
            "kafka_siem": "refused at start-up by name rather than silently absent",
            "a2a_streaming": "a gate cannot buffer or forward-unevaluated honestly",
            "kubectl_exec": "absent from the verb table at any ceiling",
            "azure_discovery": "no connector",
            "gcp_discovery": "no connector",
        },
    }


def _limitation_inventory() -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for name in LIMITATION_SOURCES:
        path = ROOT / name
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = [
            line.strip()
            for line in text.splitlines()
            if re.search(
                r"NOT_SUPPORTED|not claim|does not|UNVERIFIED|limitation|"
                r"deliberately absent|refused",
                line,
                re.I,
            )
        ]
        if lines:
            found[name] = lines[:40]
    return found


def build(*, tests_artifact: str = "") -> dict[str, Any]:
    source = _python_files("sentinel")
    tests = _python_files("tests_arch")
    commit = _git("rev-parse", "HEAD")

    return {
        "schema_version": "1.0.0",
        "kind": "sentinel.baseline.manifest",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repository": {
            "root": str(ROOT),
            "commit": commit,
            "short_commit": commit[:7],
            "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
            "subject": _git("log", "-1", "--pretty=%s"),
            "dirty": bool(_git("status", "--porcelain")),
            "source_tree_sha256": _sha256_of_tree(source),
            "test_tree_sha256": _sha256_of_tree(tests),
        },
        "inventory": {
            "source_modules": len(source),
            "source_lines": sum(
                len(p.read_text(encoding="utf-8").splitlines()) for p in source
            ),
            "test_modules": len(tests),
            "test_lines": sum(
                len(p.read_text(encoding="utf-8").splitlines()) for p in tests
            ),
        },
        "dependency_graph": _dependency_graph(source),
        "api": _api_inventory(),
        "schema": _schema_inventory(),
        "tests": _test_inventory(),
        "security_controls": SECURITY_CONTROLS,
        "integrations": _integration_inventory(),
        "known_limitations": _limitation_inventory(),
        "evidence_links": {
            "tests": tests_artifact or None,
            "note": (
                "No performance numbers are recorded here. A measured latency "
                "belongs to a benchmark run against a named machine; a number "
                "invented to fill a field is the failure this codebase is "
                "arranged against."
            ),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tests", default="", help="path to a test artifact to link")
    parser.add_argument("--force", action="store_true", help="overwrite (explain why)")
    parser.add_argument("--stdout", action="store_true", help="print, do not write")
    args = parser.parse_args(argv)

    manifest = build(tests_artifact=args.tests)
    if args.stdout:
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0

    target = (
        ROOT
        / "release"
        / "baseline"
        / manifest["repository"]["short_commit"]
        / "manifest.json"
    )
    if target.exists() and not args.force:
        print(
            f"refusing to overwrite {target.relative_to(ROOT)}.\n"
            "A baseline that can be regenerated in place is one that can be "
            "quietly adjusted to match the current numbers, which is the "
            "opposite of a baseline. Pass --force only to repair a corrupt "
            "manifest, and expect to explain it.",
            file=sys.stderr,
        )
        return 1

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"baseline written: {target.relative_to(ROOT)}")
    print(f"  commit          {manifest['repository']['commit']}")
    print(f"  source tree     {manifest['repository']['source_tree_sha256'][:16]}…")
    print(f"  source modules  {manifest['inventory']['source_modules']}")
    print(f"  routes          {len(manifest['api'])}")
    print(f"  schema version  {manifest['schema']['current_version']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
