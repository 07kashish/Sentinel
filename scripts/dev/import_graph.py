#!/usr/bin/env python3
"""Inventory Sentinel's internal imports without importing application code.

Defaults to the ASGI, HTTP, worker, CLI and SDK entrypoints. LOC means physical
lines, including comments and blanks. Package initializers are modules; namespace
directories are not. Imports inside functions, conditions and TYPE_CHECKING are
included conservatively. Parent initializers and literal dynamic imports count.
Simple literal lazy-export maps (including the SDK's MappingProxyType) are resolved;
other dynamic imports are reported, never silently considered safe to delete.

This is an import graph, not a call graph. A module unreachable here can still be
used by deployment scripts, tests, plugins or external SDK clients. Search those
consumers before deletion. A module with no importers may itself be an entrypoint.

Usage: python scripts/dev/import_graph.py [--json reports/import-graph.json]
Use --check to reject unexplained unreachable modules or unresolved dynamic imports.
Repeat --allow-unreachable MODULE only for documented exceptions; stale allowances
fail the check. Repeat --entrypoint MODULE to replace the default roots.
Exit codes: 0 report/clean check, 1 failed check, 2 unreadable/invalid input.
"""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import sys


ENTRYPOINTS = (
    "sentinel.interface.asgi", "sentinel.interface.http",
    "sentinel.interface.worker", "sentinel.interface.cli", "sentinel.sdk",
)


def _module_name(root: Path, path: Path) -> str:
    parts = list(path.relative_to(root).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _strings(node: ast.AST, bindings: dict, seen: frozenset = frozenset()):
    """Resolve only closed literal expressions; None means not statically known."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, ast.Name) and node.id not in seen and node.id in bindings:
        return _strings(bindings[node.id], bindings, seen | {node.id})
    if isinstance(node, ast.Dict):
        if any(key is None for key in node.keys):
            return None
        groups = [_strings(value, bindings, seen) for value in node.values]
        if all(group is not None for group in groups):
            return set().union(*groups)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == "MappingProxyType" and len(node.args) == 1:
            return _strings(node.args[0], bindings, seen)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "get" and len(node.args) == 1:
            return _strings(node.func.value, bindings, seen)
    if isinstance(node, ast.Subscript):
        return _strings(node.value, bindings, seen)
    return None


def _import_targets(tree: ast.Module, package: str):
    bindings, repeated = {}, set()
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    scope_types = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                   ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)

    def scopes(node):
        while node in parents:
            node = parents[node]
            if isinstance(node, scope_types):
                yield node

    binding_scopes, assigned_names, mutated = {}, set(), set()
    loaders, importlibs = {"__import__"}, set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            importlibs.update(alias.asname or alias.name for alias in node.names if alias.name == "importlib")
        elif isinstance(node, ast.ImportFrom) and node.module == "importlib" and not node.level:
            loaders.update(alias.asname or alias.name for alias in node.names if alias.name == "import_module")
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    assigned_names.add(target)
                    if target.id in bindings:
                        repeated.add(target.id)
                    bindings[target.id] = node.value
                    binding_scopes[target.id] = next(scopes(target))
    for node in ast.walk(tree):
        if isinstance(node, ast.arg):
            repeated.add(node.arg)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            if node not in assigned_names:
                repeated.add(node.id)
        elif isinstance(node, ast.alias):
            repeated.add(node.asname or node.name.split(".")[0])
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            repeated.add(node.name)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            repeated.update(node.names)
        target = None
        if isinstance(node, (ast.Subscript, ast.Attribute)) and isinstance(node.ctx, (ast.Store, ast.Del)):
            target = node.value
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr != "get":
            target = node.func.value
        while isinstance(target, (ast.Subscript, ast.Attribute)):
            target = target.value
        if isinstance(target, ast.Name):
            mutated.add(target.id)
    # Mutation through a simple alias invalidates the original literal too.
    while True:
        expanded = mutated | {name for name, value in bindings.items()
                              if isinstance(value, ast.Name) and value.id in mutated}
        expanded |= {value.id for name, value in bindings.items()
                     if isinstance(value, ast.Name) and name in mutated}
        if expanded == mutated:
            break
        mutated = expanded
    repeated.update(mutated)
    for name in repeated:
        bindings.pop(name, None)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name, node.lineno, "import"
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                parts = package.split(".")
                if node.level > len(parts):
                    raise ValueError(f"relative import escapes package at line {node.lineno}")
                prefix = parts[:len(parts) - node.level + 1]
                base = ".".join(prefix + ([node.module] if node.module else []))
            else:
                base = node.module or ""
            yield base, node.lineno, "from"
            for alias in node.names:
                if alias.name != "*":
                    yield base + "." + alias.name, node.lineno, "member"
        elif isinstance(node, ast.Call):
            func = node.func
            dynamic = (
                isinstance(func, ast.Name) and func.id in loaders
                or isinstance(func, ast.Attribute) and func.attr == "import_module"
                and isinstance(func.value, ast.Name) and func.value.id in importlibs
            )
            if dynamic:
                enclosing = list(scopes(node))
                # Class attributes are not lexical variables inside methods.
                visible = {scope for i, scope in enumerate(enclosing)
                           if i == 0 or not isinstance(scope, ast.ClassDef)}
                local_bindings = {name: value for name, value in bindings.items()
                                  if binding_scopes[name] in visible}
                targets = _strings(node.args[0], local_bindings) if node.args else None
                if targets is None or any(target.startswith(".") for target in targets):
                    yield ast.unparse(node), node.lineno, "unresolved_dynamic"
                else:
                    for target in sorted(targets):
                        yield target, node.lineno, "dynamic"


def analyse(root: Path, entrypoints=ENTRYPOINTS, allowances=()) -> dict:
    root = root.resolve()
    files = sorted(path for path in (root / "sentinel").rglob("*.py")
                   if "__pycache__" not in path.parts and not path.name.startswith("._"))
    modules = {_module_name(root, path): path for path in files}
    if not modules:
        raise ValueError("no Python modules found under sentinel/")
    missing = sorted(set(entrypoints) - modules.keys())
    if missing:
        raise ValueError("missing entrypoints: " + ", ".join(missing))
    edges = {name: set() for name in modules}
    explicit = {name: set() for name in modules}
    details, unresolved, missing_imports = {}, [], []
    for name, path in modules.items():
        source = path.read_text(encoding="utf-8-sig")
        tree = ast.parse(source, filename=str(path))
        package = name if path.name == "__init__.py" else name.rpartition(".")[0]
        details[name] = {"path": path.relative_to(root).as_posix(), "loc": len(source.splitlines())}
        targets = [(name, 0, "initializer"), *_import_targets(tree, package)]
        for target, line, kind in targets:
            if kind == "unresolved_dynamic":
                unresolved.append({"module": name, "line": line, "expression": target})
                continue
            parent = target.rpartition(".")[0]
            namespace_member = (kind == "member" and parent not in modules
                                and any(module.startswith(parent + ".") for module in modules))
            if (kind in {"import", "from", "dynamic"} or namespace_member) and target.startswith("sentinel."):
                if target not in modules and not any(module.startswith(target + ".") for module in modules):
                    missing_imports.append({"module": name, "line": line, "target": target})
            # 'from x import symbol' is an edge to x and, if it exists, x.symbol.
            # Namespace packages have no node; their real ancestors still execute.
            if kind != "initializer" and target in modules and target != name:
                explicit[name].add(target)
            parts = target.split(".")
            for length in range(1, len(parts) + 1):
                ancestor = ".".join(parts[:length])
                if ancestor in modules and ancestor != name:
                    edges[name].add(ancestor)
    reachable, pending = set(), list(entrypoints)
    while pending:
        name = pending.pop()
        if name not in reachable:
            reachable.add(name)
            pending.extend(edges[name] - reachable)
    importers = {name: [] for name in modules}
    for name, dependencies in edges.items():
        for dependency in dependencies:
            importers[dependency].append(name)
    unreachable = sorted(modules.keys() - reachable)
    for name in modules:
        details[name].update(imports=sorted(edges[name]), explicit_imports=sorted(explicit[name]),
                             imported_by=sorted(importers[name]), reachable=name in reachable)
    return {
        "summary": {"modules": len(modules), "non_initializer_modules": sum(p.name != "__init__.py" for p in files),
                    "loc": sum(row["loc"] for row in details.values()),
                    "reachable": len(reachable), "unreachable": len(unreachable)},
        "entrypoints": list(entrypoints), "modules": details,
        "unreachable": unreachable,
        "never_imported": sorted(name for name, users in importers.items() if not users),
        "unresolved_dynamic_imports": unresolved,
        "unresolved_internal_imports": missing_imports,
        "allowances": sorted(allowances),
        "stale_allowances": sorted(set(allowances) - set(unreachable)),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--entrypoint", action="append")
    parser.add_argument("--allow-unreachable", action="append", default=[])
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)
    try:
        report = analyse(args.root, args.entrypoint or ENTRYPOINTS, args.allow_unreachable)
        if args.json:
            args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    except (OSError, SyntaxError, ValueError) as exc:
        print(f"import graph: {exc}", file=sys.stderr)
        return 2
    summary = report["summary"]
    print(f"Modules: {summary['modules']}; LOC: {summary['loc']}; "
          f"reachable: {summary['reachable']}; unreachable: {summary['unreachable']}")
    print("LOC      reachable  importers  module")
    for name, row in report["modules"].items():
        print(f"{row['loc']:7}  {str(row['reachable']):9}  {len(row['imported_by']):9}  {name}")
    for title, key in (("Unreachable", "unreachable"), ("Never imported", "never_imported"),
                       ("Unresolved dynamic imports", "unresolved_dynamic_imports"),
                       ("Unresolved internal imports", "unresolved_internal_imports"),
                       ("Stale allowances", "stale_allowances")):
        print(f"\n{title} ({len(report[key])}):")
        for item in report[key]:
            print(f"  {item}")
    unexplained = set(report["unreachable"]) - set(args.allow_unreachable)
    failed = (unexplained or report["unresolved_dynamic_imports"]
              or report["unresolved_internal_imports"] or report["stale_allowances"])
    return 1 if args.check and failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
