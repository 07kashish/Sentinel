"""Measure cleanup refs with identical Git-blob and runtime definitions."""
from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
NAME = re.compile(r"\bSENTINEL_[A-Z0-9_]+\b")
EXEMPTIONS = {"CHANGES.md", "CLEANUP_PLAN.md", "docs/PARKED.md"}

RUNTIME_PROBE = '''
import contextlib, dataclasses, io, json, sys, tempfile
from pathlib import Path
root = Path(sys.argv[1])
sys.path.insert(0, str(root))
from sentinel.composition.settings import Settings
from sentinel.composition.container import build_container
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.interface.http import create_app
with tempfile.TemporaryDirectory(prefix="sentinel-route-metrics-") as work:
    settings = Settings.from_environment({"SENTINEL_ENV": "development",
        "SENTINEL_DB_PATH": str(Path(work) / "probe.db"),
        "SENTINEL_API_KEYS": "audit:local-metrics-fixture-key:admin"})
    pool = build_engine(settings.engine)
    migrate(pool)
    pool.close()
    variants = {"default": settings}
    for field in dataclasses.fields(settings):
        value = getattr(settings, field.name)
        if isinstance(value, bool):
            variants[field.name] = dataclasses.replace(settings, **{field.name: not value})
    workflow = getattr(settings, "workflow", None)
    if workflow is not None and dataclasses.is_dataclass(workflow):
        for field in dataclasses.fields(workflow):
            value = getattr(workflow, field.name)
            if isinstance(value, bool):
                variants["workflow." + field.name] = dataclasses.replace(settings,
                    workflow=dataclasses.replace(workflow, **{field.name: not value}))
    counts, union = {}, set()
    for name, variant in variants.items():
        with contextlib.redirect_stdout(io.StringIO()):
            container = build_container(variant)
            try:
                app = create_app(container)
                routes = {(tuple(sorted(route.methods or ())), route.path) for route in app.routes}
                counts[name] = len(routes)
                union.update(routes)
            finally:
                container.close()
    print(json.dumps({"default": counts["default"], "optional_union": len(union),
        "variants": counts, "routes": [{"methods": list(methods), "path": path}
        for methods, path in sorted(union)]}))
'''


def git_blobs(ref: str) -> dict[str, bytes]:
    listing = subprocess.check_output(["git", "ls-tree", "-rz", "--full-tree", ref], cwd=ROOT)
    entries = []
    for entry in listing.split(b"\0"):
        if not entry:
            continue
        metadata, name = entry.split(b"\t", 1)
        _mode, kind, oid = metadata.split()
        if kind != b"blob":
            raise ValueError(f"cannot count non-blob {name!r}")
        entries.append((name.decode(), oid))
    result = subprocess.run(["git", "cat-file", "--batch"], cwd=ROOT,
                            input=b"".join(oid + b"\n" for _, oid in entries),
                            stdout=subprocess.PIPE, check=True).stdout
    offset, blobs = 0, {}
    for name, oid in entries:
        end = result.index(b"\n", offset)
        actual, kind, length = result[offset:end].split()
        assert actual == oid and kind == b"blob"
        offset = end + 1
        size = int(length)
        blobs[name] = result[offset:offset + size]
        offset += size + 1
    assert offset == len(result)
    return blobs


def static_metrics(ref: str) -> dict:
    blobs = git_blobs(ref)
    texts, binary_bytes = {}, 0
    for name, value in blobs.items():
        try:
            if b"\0" in value:
                raise UnicodeError("NUL byte")
            texts[name] = value.decode("utf-8")
        except UnicodeError:
            binary_bytes += len(value)
    loc = {prefix or "total": sum(len(text.splitlines()) for name, text in texts.items()
                                 if name.startswith(prefix))
           for prefix in ("sentinel/", "tests_arch/", "")}
    routes = []
    for name, text in texts.items():
        if not (name.startswith("sentinel/interface/") and name.endswith(".py")):
            continue
        for node in ast.walk(ast.parse(text)):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for deco in node.decorator_list:
                if (isinstance(deco, ast.Call) and isinstance(deco.func, ast.Attribute)
                        and deco.func.attr in {"get", "post", "put", "patch", "delete"}
                        and deco.args and isinstance(deco.args[0], ast.Constant)
                        and isinstance(deco.args[0].value, str)):
                    routes.append((deco.func.attr.upper(), deco.args[0].value))
    settings = next(node for node in ast.parse(texts["sentinel/composition/settings.py"]).body
                    if isinstance(node, ast.ClassDef) and node.name == "Settings")
    documented = set()
    for name, text in texts.items():
        if name in EXEMPTIONS:
            continue
        if (name in {"README.md", ".env.example", "docker-compose.yml"}
                or name.startswith("deploy/helm/")
                or (name.startswith("docs/") and name.endswith(".md"))):
            documented.update(NAME.findall(text))
    jobs = {}
    for name, text in texts.items():
        if name.startswith(".github/workflows/") and name.endswith((".yml", ".yaml")):
            doc = yaml.safe_load(text)
            jobs[name] = len(doc.get("jobs", {})) if isinstance(doc, dict) else 0
    requirements = [line.strip() for line in texts["requirements.txt"].splitlines()
                    if re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[|[<=>!~;]|$)", line.strip())]
    return {"ref": ref, "tracked_files": len(blobs), "text_loc": loc,
            "binary_bytes": binary_bytes,
            "python_modules": sum(name.startswith("sentinel/") and name.endswith(".py") for name in blobs),
            "ast_routes": len(routes),
            "settings_fields": sum(isinstance(node, ast.AnnAssign) for node in settings.body),
            "documented_environment_names": len([name for name in documented if not name.endswith("_")]),
            "documented_family_prefixes": sorted(name for name in documented if name.endswith("_")),
            "direct_runtime_dependencies": len(requirements), "runtime_requirements": requirements,
            "ci_jobs": sum(jobs.values()), "workflow_jobs": jobs}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--checkout", type=Path, help="also construct apps and collect tests here")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = static_metrics(args.ref)
    if args.checkout:
        checkout = args.checkout.resolve()
        runtime = subprocess.run([sys.executable, "-c", RUNTIME_PROBE, str(checkout)],
                                 cwd=checkout, text=True, capture_output=True)
        args.out.with_suffix(".routes.log").write_text(runtime.stdout + runtime.stderr)
        if runtime.returncode:
            raise RuntimeError(f"route construction failed; see {args.out.with_suffix('.routes.log')}")
        result["constructed_routes"] = json.loads(runtime.stdout.splitlines()[-1])
        command = [sys.executable, "-m", "pytest", "tests_arch/", "--collect-only", "-q", "-o", "addopts="]
        collection = subprocess.run(command, cwd=checkout, text=True, capture_output=True)
        args.out.with_suffix(".collection.log").write_text(collection.stdout + collection.stderr)
        count = re.search(r"(\d+) tests? collected", collection.stdout)
        if collection.returncode or count is None:
            raise RuntimeError(f"test collection failed; see {args.out.with_suffix('.collection.log')}")
        result["test_cases_collected"] = int(count[1])
        result["collection_command"] = command
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    summary = {key: value for key, value in result.items()
               if key not in {"runtime_requirements", "workflow_jobs", "constructed_routes", "collection_command"}}
    if "constructed_routes" in result:
        summary["constructed_routes"] = {key: result["constructed_routes"][key] for key in ("default", "optional_union")}
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())