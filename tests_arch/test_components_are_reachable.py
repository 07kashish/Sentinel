"""A security control that nothing calls is not a control.

WHY THIS EXISTS
---------------
Phase 4 was written, tested and reported as complete while four of its five
sections were unreachable in production:

  * `decide_response` -- the entire safe-autonomous-response strategy -- had
    twelve passing tests and zero callers.
  * `GuardedRemediationExecutor` implemented dry run, authorization, audit,
    idempotency and rollback, and the container hardcoded
    `NullRemediationExecutor` beside it.
  * `SoarDispatcher` had six connectors and injection escaping, and was
    constructed by nothing, so no incident reached ServiceNow or Slack.
  * `ApprovalRecord.expires_at` had a column, a hydration line and an enforced
    branch in `DecideApprovalHandler` -- and nothing SET it, so every real
    approval had no expiry and the branch could never be taken.

Every unit test passed, because unit tests call the component directly. That is
the whole problem: a passing test proves a component works, never that anything
uses it. It is the same defect as the Phase 3 execution-graph hook placed after
an early `return`, and as `test_every_capability_is_actually_guarded_by_a_route`
catching `MANAGE_AGENTS` -- a capability that was defined, granted, and enforced
nowhere, so an access review would read the table and conclude a control existed.

WHAT THIS CHECKS
----------------
For each entry in `MUST_BE_REACHABLE`, the named symbol must be referenced from
some `sentinel/` module OTHER than the one that defines it. Test references do
not count -- tests are exactly what failed to notice last time.

HOW IT AVOIDS BEING A GATE THAT EXECUTES NOTHING
--------------------------------------------------
The failure mode for a test like this is a registry that quietly matches
nothing. So `test_the_reachability_scanner_actually_resolves_its_registry`
asserts every registry entry resolves to a real definition site; an entry naming
a symbol that no longer exists fails rather than passing vacuously.
"""

from __future__ import annotations

import ast
from pathlib import Path
from pathlib import Path as pathlib_Path

import pytest

ROOT = Path(__file__).resolve().parent.parent / "sentinel"

#: symbol -> the module that defines it.
#:
#: Deliberately a hand-maintained list of load-bearing components rather than
#: every public name. "Everything must be used" is a lint; this is a statement
#: about which components would be dangerous to have unwired, and each entry is
#: here because it was unwired once or would matter if it were.
MUST_BE_REACHABLE = {
    # Phase 4 -- all four were unreachable when first reported complete.
    "decide_response": "sentinel/domain/remediation.py",
    "GuardedRemediationExecutor": "sentinel/infrastructure/remediation.py",
    "SoarDispatcher": "sentinel/infrastructure/soar.py",
    "ContainmentGuard": "sentinel/infrastructure/containment.py",
    "evaluate_containment": "sentinel/domain/containment.py",
    # Phase 3 -- the graph hook was once placed after an early return, which had
    # the same effect as not existing.
    "detect_sequences": "sentinel/domain/sequences.py",
    "compare_to_baseline": "sentinel/domain/baseline.py",
    "assess_intent_divergence": "sentinel/domain/baseline.py",
    # Phase 5. Registered as they are wired, so an unwired one fails the build
    # the way Phase 4's four should have.
    "parse_mode": "sentinel/domain/modes.py",
    "ProtectionMode": "sentinel/domain/modes.py",
    "validate": "sentinel/domain/policy_as_code.py",
    "simulate": "sentinel/domain/policy_as_code.py",
    "diff_versions": "sentinel/domain/policy_as_code.py",
    "TenantKey": "sentinel/domain/keys.py",
    "RetentionPolicy": "sentinel/domain/residency.py",
    "assert_no_cross_region_read": "sentinel/domain/residency.py",

}


def _modules() -> list[tuple[Path, ast.AST]]:
    out = []
    for path in sorted(ROOT.rglob("*.py")):
        try:
            out.append((path, ast.parse(path.read_text(encoding="utf-8"))))
        except SyntaxError:  # pragma: no cover - a parse failure is its own bug
            continue
    return out


def _referenced_names(tree: ast.AST) -> set[str]:
    """Every bare name and attribute tail used in a module.

    Attribute tails are included so `module.thing()` counts as a reference to
    `thing`, and import aliases are included so a re-export is not mistaken for
    a use.
    """
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.alias):
            names.add(node.asname or node.name.rsplit(".", 1)[-1])
    return names


MODULES = _modules()


def test_the_reachability_scanner_actually_resolves_its_registry():
    """A registry entry naming a symbol that no longer exists would make the
    check below pass while testing nothing."""
    assert MODULES, "no modules were parsed; the scanner is broken"
    for symbol, defining in MUST_BE_REACHABLE.items():
        path = ROOT.parent / defining
        assert path.exists(), f"{defining} does not exist"
        source = path.read_text(encoding="utf-8")
        assert (
            f"def {symbol}" in source or f"class {symbol}" in source
        ), f"{symbol} is not defined in {defining}"


def _imports_from(tree: ast.AST, module_dotted: str) -> set[str]:
    """Names another module imports FROM the defining module.

    Matching on bare names is not enough. `KeyProvider` is defined in
    `persistence/crypto.py` AND was briefly defined in `domain/keys.py`, so a
    bare-name scan reported `keys.py` as used when the reference was to the
    other module's class entirely -- a false pass in the test whose whole job is
    to catch false passes. Imports are unambiguous about which module is meant.
    """
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == module_dotted:
            for alias in node.names:
                found.add(alias.name)
    return found


def _dotted(path: pathlib_Path) -> str:
    relative = path.resolve().relative_to(ROOT.parent)
    return ".".join(relative.with_suffix("").parts)


def _module_is_used_elsewhere(defining: pathlib_Path) -> bool:
    """Whether any OTHER module references a name this one defines.

    Used to decide whether a within-module reference counts. A component built
    by a factory in its own module -- `build_remediation_executor` constructing
    `GuardedRemediationExecutor` -- is genuinely reachable, but only if somebody
    calls the factory. If nothing imports the module at all, a within-module
    reference proves nothing.
    """
    tree = next((t for p, t in MODULES if p.resolve() == defining), None)
    if tree is None:
        return False
    defined = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }
    dotted = _dotted(defining)
    for path, other in MODULES:
        if path.resolve() == defining:
            continue
        if defined & _imports_from(other, dotted):
            return True
    return False


@pytest.mark.parametrize("symbol", sorted(MUST_BE_REACHABLE))
def test_a_load_bearing_component_is_reachable_from_production_code(symbol):
    """The symbol must be used somewhere other than where it is defined.

    A within-module reference counts ONLY when something else in the tree
    already reaches that module -- otherwise a module full of components that
    call each other and nothing else would pass while being entirely dead.
    """
    defining = (ROOT.parent / MUST_BE_REACHABLE[symbol]).resolve()
    dotted = _dotted(defining)
    callers = [
        path.relative_to(ROOT.parent).as_posix()
        for path, tree in MODULES
        if path.resolve() != defining
        # Imported BY NAME from the defining module, and then actually used --
        # a re-export alone is not a use.
        and symbol in _imports_from(tree, dotted)
        and symbol in _referenced_names(tree)
    ]
    if not callers and _module_is_used_elsewhere(defining):
        tree = next(t for p, t in MODULES if p.resolve() == defining)
        # A reference inside the defining module, outside the definition itself.
        internal = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and (
                (isinstance(node.func, ast.Name) and node.func.id == symbol)
                or (isinstance(node.func, ast.Attribute) and node.func.attr == symbol)
            )
        ]
        if internal:
            callers = [f"{MUST_BE_REACHABLE[symbol]} (via a factory in the same module)"]
    assert callers, (
        f"{symbol} is defined in {MUST_BE_REACHABLE[symbol]} and referenced by "
        f"NO other module under sentinel/.\n"
        f"It has tests, and nothing in production calls it. A security control "
        f"that nothing calls is not a control -- wire it, or delete it."
    )
