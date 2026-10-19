"""A systematic mutation engine for the pure domain modules.

WHY THIS EXISTS ALONGSIDE THE HAND-WRITTEN MUTATIONS
-----------------------------------------------------
`test_execution_mutation.py` breaks twelve guards that a human judged important.
That catches what the author thought to check, which is exactly the limitation
that made the predecessor's mutation harness give false confidence: it proved its
enumerated guards were load-bearing while the guard everyone cared about had no
probe at all.

This runner does not choose. It walks the AST and applies every applicable
operator at every applicable site, then reports which mutants SURVIVED. A
survivor is a change to production code that no probe noticed — either dead code,
or a gap in the suite. Both are worth knowing and neither is discoverable by
choosing what to test.

WHY IN-PROCESS
--------------
A subprocess per mutant costs ~4 seconds of interpreter startup, which puts a
systematic run at several minutes and therefore out of the inner loop. The domain
modules are PURE — stdlib and each other, nothing else — so a mutant can be
compiled into a fresh module object and probed directly, in about a millisecond.

That purity is not a happy accident. It is enforced by
`test_architecture_rules.py::test_the_domain_imports_nothing_but_itself_and_the_standard_library`,
and this runner is one of the things it buys.
"""

from __future__ import annotations

import ast
import sys
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Sequence

__all__ = ["Mutant", "MutationReport", "generate_mutants", "run_mutation_campaign"]


@dataclass(frozen=True, slots=True)
class Mutant:
    """One single-site change to a module's source."""

    module: str
    operator: str
    line: int
    original: str
    mutated: str
    source: str

    @property
    def label(self) -> str:
        return f"{self.module}:{self.line} {self.operator} ({self.original} -> {self.mutated})"


# ── Mutation operators ───────────────────────────────────────────────────────
#
# Each maps a node to its mutated replacement. Chosen to target the shapes that
# actually encode guards: comparisons, boolean connectives, membership,
# negation, and boundary constants.

_COMPARISON_SWAPS: dict[type, list[type]] = {
    ast.Lt: [ast.LtE, ast.Gt],
    ast.LtE: [ast.Lt, ast.GtE],
    ast.Gt: [ast.GtE, ast.Lt],
    ast.GtE: [ast.Gt, ast.LtE],
    ast.Eq: [ast.NotEq],
    ast.NotEq: [ast.Eq],
    ast.In: [ast.NotIn],
    ast.NotIn: [ast.In],
    ast.Is: [ast.IsNot],
    ast.IsNot: [ast.Is],
}


class _Mutation(ast.NodeTransformer):
    """Applies exactly ONE mutation, identified by a visit counter."""

    def __init__(self, target_index: int) -> None:
        self.target_index = target_index
        self.counter = -1
        self.applied: tuple[str, str, str, int] | None = None

    def _next(self) -> bool:
        self.counter += 1
        return self.counter == self.target_index

    def visit_Compare(self, node: ast.Compare) -> ast.AST:
        self.generic_visit(node)
        for index, op in enumerate(node.ops):
            for replacement in _COMPARISON_SWAPS.get(type(op), []):
                if self._next():
                    node.ops[index] = replacement()
                    self.applied = (
                        "comparison",
                        type(op).__name__,
                        replacement.__name__,
                        node.lineno,
                    )
                    return node
        return node

    def visit_BoolOp(self, node: ast.BoolOp) -> ast.AST:
        self.generic_visit(node)
        if self._next():
            swapped = ast.Or() if isinstance(node.op, ast.And) else ast.And()
            original = type(node.op).__name__
            node.op = swapped
            self.applied = ("boolop", original, type(swapped).__name__, node.lineno)
        return node

    def visit_UnaryOp(self, node: ast.UnaryOp) -> ast.AST:
        self.generic_visit(node)
        if isinstance(node.op, ast.Not) and self._next():
            self.applied = ("drop_not", "not x", "x", node.lineno)
            return node.operand
        return node

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        # Boundary constants only. Mutating every string would generate thousands
        # of mutants whose death proves nothing about a guard.
        if isinstance(node.value, bool):
            if self._next():
                self.applied = ("bool", str(node.value), str(not node.value), node.lineno)
                return ast.copy_location(ast.Constant(value=not node.value), node)
            return node
        if isinstance(node.value, int) and abs(node.value) <= 100:
            for delta in (1, -1):
                if self._next():
                    self.applied = (
                        "boundary",
                        str(node.value),
                        str(node.value + delta),
                        node.lineno,
                    )
                    return ast.copy_location(
                        ast.Constant(value=node.value + delta), node
                    )
        return node


def _count_sites(tree: ast.Module) -> int:
    counter = _Mutation(-1)
    counter.visit(ast.parse(ast.unparse(tree)))
    return counter.counter + 1


def generate_mutants(path: Path, module_name: str) -> Iterator[Mutant]:
    """Every single-site mutant of one module, in a deterministic order."""
    source = path.read_text(encoding="utf-8")
    total = _count_sites(ast.parse(source))
    for index in range(total):
        tree = ast.parse(source)
        mutation = _Mutation(index)
        mutated_tree = mutation.visit(tree)
        if mutation.applied is None:
            continue
        operator, original, replacement, line = mutation.applied
        ast.fix_missing_locations(mutated_tree)
        try:
            mutated_source = ast.unparse(mutated_tree)
            compile(mutated_source, str(path), "exec")
        except (SyntaxError, ValueError):
            continue  # a mutant that will not compile is not a mutant
        yield Mutant(
            module=module_name,
            operator=operator,
            line=line,
            original=original,
            mutated=replacement,
            source=mutated_source,
        )


def _load_mutant(mutant: Mutant) -> types.ModuleType:
    """Compile a mutant into a fresh module object under its real name.

    Registered in `sys.modules` under the real name for the duration of the
    probe, so sibling domain modules resolve to the MUTANT rather than the
    original. Restored by the caller.
    """
    # `types.ModuleType` directly, not `module_from_spec`: with a null loader
    # the latter returns None.
    module = types.ModuleType(mutant.module)
    module.__file__ = mutant.module.replace(".", "/") + ".py"

    # REGISTERED BEFORE exec, not after. The `@dataclass` decorator resolves
    # `sys.modules.get(cls.__module__).__dict__` while it runs, so a module that
    # is not yet registered makes every dataclass definition in it raise
    # `AttributeError: NoneType has no __dict__`.
    #
    # That failure was silent in the worst way: the campaign counted 58 mutants
    # as "did not load", evaluated the 7 that had no dataclass, and reported
    # 100%. A mutation score computed over 11% of the mutants is exactly the
    # vacuous green this runner exists to prevent elsewhere -- which is why
    # `test_the_campaign_generates_a_meaningful_number_of_mutants` now asserts on
    # the number EVALUATED, not the number generated.
    sys.modules[mutant.module] = module
    try:
        exec(compile(mutant.source, module.__file__, "exec"), module.__dict__)
    except BaseException:
        sys.modules.pop(mutant.module, None)
        raise
    return module


def _restore(module_name: str, saved: types.ModuleType | None) -> None:
    """Put `sys.modules` back exactly as it was, present or absent."""
    if saved is not None:
        sys.modules[module_name] = saved
    else:
        sys.modules.pop(module_name, None)


@dataclass
class MutationReport:
    total: int = 0
    killed: int = 0
    survived: list[Mutant] = None  # type: ignore[assignment]
    equivalent: int = 0

    def __post_init__(self) -> None:
        if self.survived is None:
            self.survived = []

    @property
    def score(self) -> float:
        evaluated = self.total - self.equivalent
        return (self.killed / evaluated) if evaluated else 1.0

    def summary(self) -> str:
        return (
            f"{self.killed}/{self.total - self.equivalent} killed "
            f"({self.score:.1%}), {len(self.survived)} survived, "
            f"{self.equivalent} did not compile or load"
        )


def run_mutation_campaign(
    targets: Sequence[tuple[Path, str]],
    probes: Sequence[Callable[[types.ModuleType], None]],
) -> MutationReport:
    """Generate every mutant of every target and run every probe against it.

    A mutant is KILLED if any probe raises. It SURVIVES if all of them pass,
    which means no test in this suite can tell the mutated code from the real
    code.
    """
    report = MutationReport()
    for path, module_name in targets:
        for mutant in generate_mutants(path, module_name):
            report.total += 1
            # The ORIGINAL module is saved and restored around every mutant,
            # including the ones that fail to load. An earlier form restored it
            # only on the success path, so a mutant that raised during exec left
            # `sys.modules` without the real module -- and every later import in
            # the session got a fresh, non-identical copy. Enum members and
            # isinstance checks then compared unequal across unrelated suites,
            # which presents as flakiness somewhere far from here.
            saved = sys.modules.get(module_name)
            try:
                module = _load_mutant(mutant)
            except Exception:  # noqa: BLE001 - a mutant that cannot load is not evaluable
                report.equivalent += 1
                _restore(module_name, saved)
                continue

            sys.modules[mutant.module] = module
            killed = False
            try:
                for probe in probes:
                    try:
                        probe(module)
                    except Exception:  # noqa: BLE001 - a raise IS the detection
                        killed = True
                        break
            finally:
                _restore(module_name, saved)

            if killed:
                report.killed += 1
            else:
                report.survived.append(mutant)
    return report
