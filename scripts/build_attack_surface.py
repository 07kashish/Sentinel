"""Enumerate the HTTP attack surface from the code, for a pentest scope.

WHY GENERATED AND NOT WRITTEN
-----------------------------
A pentest is scoped from a list of endpoints. A hand-written list is wrong the
day after it is written, and the endpoints it omits are the ones nobody
remembers -- which are exactly the ones worth testing. This reads the route
decorators out of `sentinel/interface/` so the inventory cannot fall behind the
code.

WHAT THIS IS NOT
----------------
It is NOT pentest evidence, and nothing here should be read as assurance. It is
the INPUT a tester needs before starting: every path, its method, the capability
the code requires for it, and whether it can change state.

`independent_pentest` stays UNVERIFIED in the readiness report, because a scan
this project runs against itself is not an independent assessment. That gate
needs a contracted third party, an agreed scope, a report and a remediation
cycle. This produces the second of those four and none of the others.

THE INTERESTING COLUMN IS `capability`
-----------------------------------------
Every route is expected to declare one via `Depends(require(Capability.X))`. A
route where this reads NONE DECLARED is either deliberately public -- the
console shell, health -- or an authorization hole. The script cannot tell which,
so it reports the fact and refuses to guess. `test_attack_surface.py` pins the
set of undeclared routes, so a new one cannot appear quietly.
"""

from __future__ import annotations

import ast
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts import release_binding  # noqa: E402

INTERFACE = ROOT / "sentinel" / "interface"
OUT = ROOT / "docs" / "attack_surface.json"

#: Methods that can change state. A pentest scope treats these differently:
#: a GET that leaks is a disclosure, a POST that leaks is also a foothold.
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


def main() -> int:
    routes = collect()
    undeclared = [r for r in routes if r["capability"] is None]
    mutating = [r for r in routes if r["mutating"]]

    document = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "what_this_is": (
            "The HTTP attack surface, read from the route decorators in "
            "sentinel/interface/. This is the INPUT to a penetration test "
            "scope. It is NOT pentest evidence and must not be read as "
            "assurance: `independent_pentest` requires a contracted third "
            "party, an agreed scope, a report and a remediation cycle, and a "
            "scan this project runs against itself is none of those."
        ),
        "route_count": len(routes),
        "mutating_route_count": len(mutating),
        "routes_with_no_declared_capability": len(undeclared),
        "capability_note": (
            "A route reporting no declared capability is either deliberately "
            "public (the console shell, health) or an authorization hole. This "
            "script cannot tell which and does not guess. "
            "tests_arch/test_attack_surface.py pins the set so a new one "
            "cannot appear quietly."
        ),
        "routes": routes,
    }
    OUT.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    release_binding.write_binding(
        OUT,
        release=release_binding.release_identity_from_git(ROOT),
        now=datetime.now(timezone.utc),
    )

    print(f"{len(routes)} routes, {len(mutating)} mutating")
    print(f"{len(undeclared)} with no declared capability:")
    for route in undeclared:
        print(f"  {route['method']:<6} {route['path']:<44} {route['module']}")
    print(f"\nwritten and bound: {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
