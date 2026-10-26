#!/usr/bin/env python3
"""Every configuration surface names only variables the code reads.

THE DEFECT THIS CATCHES
-----------------------
An operator sets `SENTINEL_RLS_ENABLED=1` in the Helm values, sees the pod
start, and believes row-level security is on. Nothing reads that variable.
The manifest lied by being accepted. This script makes such a line a build
failure, and the reverse too: a variable the code reads in production but no
manifest mentions is a decision an operator never got to make.

SURFACES
--------
    .env.example                 what a developer copies
    deploy/helm/sentinel/        the supported topology
    deploy/k8s/sentinel.yaml     the raw-manifest rendering of the same
    docker-compose.yml           the local stack
    deploy/terraform/            cloud environment variables
    Dockerfile, docker-entrypoint.sh

This static check finds exact string literals in source (excluding prose),
expands the dynamic platform/SIEM parser schemas and scans the entrypoint.
It cannot establish runtime reachability; rendered Settings and integration
tests remain required. Names read by scripts only (the
transparency-root publisher, the load generators) are reported separately so
a manifest that sets them for a script is not mistaken for one that sets them
for the service.

EXIT CODES
----------
0 aligned; 1 orphans or omissions (details printed); 2 could not read a surface.
`--report` prints and never fails, for the status generator.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NAME = re.compile(r"\b(SENTINEL_[A-Z0-9_]+)\b")

SURFACES: dict[str, tuple[str, ...]] = {
    ".env.example": (".env.example",),
    "helm": ("deploy/helm/sentinel",),
    "k8s": ("deploy/k8s/sentinel.yaml",),
    "compose": ("docker-compose.yml",),
    "terraform": ("deploy/terraform",),
    "image": ("Dockerfile", "docker-entrypoint.sh"),
}

#: Prefixes that are documented as families (`SENTINEL_SIEM_KAFKA_*`), read
#: by prefix in code, and therefore legitimately appear with a trailing
#: underscore in templates.
FAMILY_PREFIXES = ("SENTINEL_DATA_KEY_", "SENTINEL_SIEM_KAFKA_", "SENTINEL_WAL_S3_", "SENTINEL_TENANT_SIEM_")

#: Variables production requires an explicit value for, per
#: `sentinel/composition/preflight.py`. Every deployment surface (helm, k8s)
#: must mention them so the operator's choice is on record.
REQUIRED_IN_DEPLOYMENT = (
    "SENTINEL_ENV", "SENTINEL_API_KEYS", "SENTINEL_DATABASE_URL", "SENTINEL_REDIS_URL",
    "SENTINEL_CORS_ORIGINS", "SENTINEL_RATE_LIMIT_FAIL_OPEN", "SENTINEL_REQUIRE_EXECUTION_BINDING",
    "SENTINEL_PROTECT_ENFORCE",
)


def _names_in(path: Path, *, strip_comments: bool = False) -> set[str]:
    """Names in a file. With `strip_comments`, a name that appears only in a
    `#` comment does not count as SET: manifests explain in comments why a
    variable is absent, and that explanation must not read as its presence.
    A name in a comment of `.env.example` does count as documented."""
    if path.is_dir():
        out: set[str] = set()
        for file in path.rglob("*"):
            if file.is_file() and file.suffix in {".yaml", ".yml", ".tf", ".json", ".txt", ".sh", ".tpl", ".example", ""}:
                out |= _names_in(file, strip_comments=strip_comments)
        return out
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise SystemExit(f"cannot read {path}: {exc}") from exc
    if strip_comments:
        text = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
    return set(NAME.findall(text))


def _literal_names(path: Path) -> set[str]:
    # Docstrings and error-message prose cannot establish a configuration reader.
    tree = ast.parse(path.read_text(encoding="utf-8-sig"))
    return {node.value for node in ast.walk(tree) if isinstance(node, ast.Constant)
            and isinstance(node.value, str) and NAME.fullmatch(node.value)
            and not node.value.endswith("_")}


def read_by_code() -> tuple[set[str], set[str]]:
    """Literal settings plus the exact dynamic platform/SIEM parser schemas."""
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from sentinel.composition.settings_parsers import _PLATFORM_SETTINGS, _SIEM_TRANSPORTS
    service = set().union(*(_literal_names(p) for p in (ROOT / "sentinel").rglob("*.py")))
    service |= _names_in(ROOT / "docker-entrypoint.sh", strip_comments=True)
    for prefix, definitions in (("SENTINEL_", _PLATFORM_SETTINGS), ("SENTINEL_SIEM_", _SIEM_TRANSPORTS)):
        for name, fields in definitions.items():
            for field in (*fields["required"], *fields["optional"]):
                key = f"{prefix}{name.upper()}_{field.upper()}"
                service.add(key)
                if field in fields["secret"]:
                    service.add(key + "_FILE")
    scripts_only = set().union(*(_literal_names(p) for p in (ROOT / "scripts").glob("*.py")))
    return service, scripts_only - service


def _is_family(name: str) -> bool:
    return any(name == p or name.startswith(p) for p in FAMILY_PREFIXES)


def analyse() -> dict:
    service, scripts_only = read_by_code()
    known = service | scripts_only
    report: dict = {"read_by_service": sorted(service), "read_by_scripts_only": sorted(scripts_only), "surfaces": {}}
    for surface, paths in SURFACES.items():
        names: set[str] = set()
        for rel in paths:
            names |= _names_in(ROOT / rel, strip_comments=surface != ".env.example")
        readers = known if surface == ".env.example" else service
        orphans = sorted(n for n in names if n not in readers and not _is_family(n))
        for_scripts = sorted(n for n in names if n in scripts_only)
        entry = {"names": sorted(names), "orphans": orphans, "set_for_scripts_only": for_scripts}
        if surface in {"helm", "k8s"}:
            entry["required_missing"] = sorted(n for n in REQUIRED_IN_DEPLOYMENT if n not in names)
        if surface == ".env.example":
            entry["service_names_missing"] = sorted(n for n in service if n not in names and not _is_family(n))
        report["surfaces"][surface] = entry
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--report", action="store_true", help="print the analysis and exit 0")
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args(argv)
    report = analyse()
    if args.json is not None:
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    failures = 0
    for surface, entry in report["surfaces"].items():
        for name in entry["orphans"]:
            print(f"ORPHAN    {surface}: {name} is set but no reader is identified for this surface")
            failures += 1
        for name in entry.get("required_missing", []):
            print(f"MISSING   {surface}: {name} is required in production and not mentioned")
            failures += 1
        for name in entry.get("service_names_missing", []):
            print(f"UNLISTED  {surface}: {name} is read by the service and not documented")
            failures += 1
    print(f"service reads {len(report['read_by_service'])} names; scripts-only {len(report['read_by_scripts_only'])}; "
          f"{failures} alignment problem(s)")
    if args.report:
        return 0
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
