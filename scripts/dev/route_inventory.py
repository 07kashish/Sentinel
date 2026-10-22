"""Read route declarations and capabilities without importing the service."""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
INTERFACE = ROOT / "sentinel" / "interface"
MUTATING = {"post", "put", "patch", "delete"}


def _capability_of(node: ast.FunctionDef) -> str | None:
    """The capability named in `Depends(require(Capability.X))`, if any.

    Read from the DEFAULT of a parameter, which is where FastAPI dependencies
    live. Walking the whole function body instead would also match a capability
    mentioned in a comparison inside the handler -- a check the route performs
    rather than one the framework enforces before entry, and the difference is
    the whole point of the column.
    """
    for default in [*node.args.defaults, *node.args.kw_defaults]:
        if default is None:
            continue
        for inner in ast.walk(default):
            if (
                isinstance(inner, ast.Attribute)
                and isinstance(inner.value, ast.Name)
                and inner.value.id == "Capability"
            ):
                return inner.attr
    return None


def _routes_in(path: Path) -> list[dict[str, Any]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            func = decorator.func
            if not (isinstance(func, ast.Attribute) and func.attr.lower() in
                    {"get", "post", "put", "patch", "delete"}):
                continue
            if not decorator.args or not isinstance(decorator.args[0], ast.Constant):
                continue
            route = decorator.args[0].value
            if not isinstance(route, str):
                continue
            method = func.attr.lower()
            found.append(
                {
                    "method": method.upper(),
                    "path": route,
                    "handler": node.name,
                    "module": str(path.relative_to(ROOT)).replace("\\", "/"),
                    "capability": _capability_of(node),
                    "mutating": method in MUTATING,
                    "path_parameters": [
                        seg.strip("{}")
                        for seg in route.split("/")
                        if seg.startswith("{") and seg.endswith("}")
                    ],
                }
            )
    return found


def collect() -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    for module in sorted(INTERFACE.glob("*.py")):
        routes.extend(_routes_in(module))
    return sorted(routes, key=lambda r: (r["path"], r["method"]))
