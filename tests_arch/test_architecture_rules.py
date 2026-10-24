"""Executable architecture rules. These fail the build, not a review checklist.

WHY THESE EXIST
---------------
The predecessor's most persistent failure mode was not a bug class. It was that
its invariants were asserted in prose and enforced by nobody.

`api/pipeline.py:45-50` stated: "There is no direct `repository.transition(...)`
call in this module: a helper that can be called without the epoch is a call site
that will eventually be called without it." `repository.fail()` was exactly that
helper, in that file, at line 617 -- and a second one lived in `api/main.py:170`.
An archived review claimed "A stage physically cannot make an unfenced write."
The v7 record claimed an "AST call-site guard" enforced it. No such guard existed
anywhere in the test suite.

A docstring that asserts an invariant no test enforces is not documentation. It
is a defect with good handwriting, because the next reviewer trusts it and stops
looking.

Every rule in this file corresponds to a stated architectural property. If a
property is worth stating, it is worth failing the build over.
"""

from __future__ import annotations

import ast
import importlib
from collections import defaultdict
from pathlib import Path
from typing import Iterator


import sentinel

ROOT = Path(sentinel.__file__).resolve().parent
PACKAGE = "sentinel"

# The dependency rule, as a layer index. A module may import from its own layer
# and from every layer BELOW it (lower index = further inward). Importing
# outward is the violation. This single table is the whole architecture: if it
# holds, nothing in the business logic can be reached by a change to a database,
# a transport or a vendor SDK.
LAYERS: dict[str, int] = {
    "sentinel.domain": 0,
    "sentinel.application": 1,
    "sentinel.infrastructure": 2,
    # The composition root imports 0-2 to wire them. It sits BELOW the delivery
    # layer because the delivery layer consumes a built container: an HTTP app
    # and a CLI both ask composition for a wired application, never the reverse.
    "sentinel.composition": 3,
    "sentinel.interface": 4,
    # Thin agent-facing SDK: same delivery layer as HTTP/CLI — may import inward.
    "sentinel.sdk": 4,
}

FRAMEWORKS = {
    "fastapi",
    "starlette",
    "pydantic",
    "flask",
    "django",
    "sqlalchemy",
    "psycopg",
    "sqlite3",
    "requests",
    "httpx",
    "redis",
}


def _modules() -> Iterator[tuple[str, Path, ast.Module]]:
    """Every .py file under the package, found on DISK rather than by import.

    THIS WAS `pkgutil.walk_packages`, AND IT SILENTLY UNDER-COVERED.
    ---------------------------------------------------------------
    `walk_packages` recurses by IMPORTING each subpackage and reading its
    `__path__`, which means a directory with no `__init__.py` is not recursed
    into at all. `sentinel/application/execution/` and
    `sentinel/infrastructure/persistence/` have none -- they import fine as
    namespace packages, so nothing ever complained -- and the result was that
    FOURTEEN modules were invisible to all twenty-two rules in this file.

    Among the invisible: `persistence/crypto.py`, `persistence/audit.py` (the
    tamper-evident trail), and the entire saga engine. The layering rules, the
    "only settings reads the environment" rule and the mutable-global rule all
    reported green on a codebase they were not reading.

    That is this repository's most-named defect shape -- a gate that looks
    connected and runs nothing -- sitting inside the gates themselves. Walking
    the filesystem cannot under-cover for that reason, and
    `test_the_walker_sees_every_module_on_disk` below fails if it ever starts
    to for any other.
    """
    for path in sorted(ROOT.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        relative = path.relative_to(ROOT).with_suffix("")
        parts = [part for part in relative.parts if part != "__init__"]
        name = ".".join([PACKAGE, *parts]) if parts else PACKAGE
        yield name, path, ast.parse(path.read_text(encoding="utf-8"), str(path))


def _layer_of(module: str) -> int | None:
    for prefix, index in LAYERS.items():
        if module == prefix or module.startswith(prefix + "."):
            return index
    return None


def _imports(tree: ast.Module) -> Iterator[tuple[str, int]]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name, node.lineno
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            yield node.module, node.lineno


ALL_MODULES = list(_modules())


def test_the_package_is_not_empty():
    """Guards every other rule here: a typo in ROOT would silently pass them all."""
    assert len(ALL_MODULES) >= 15

def test_the_walker_sees_every_module_on_disk():
    """The coverage guard for the twenty-two rules that share `ALL_MODULES`.

    Every rule in this file is only as good as the module list it iterates, and
    that list was wrong for a long time without any rule failing -- a
    `pkgutil.walk_packages` walker skipped two whole subpackages because they
    have no `__init__.py`. A rule that examines nothing passes.

    So the list is asserted against the filesystem directly. If a future change
    reintroduces an import-based walker, moves the package, or adds a directory
    the walker cannot reach, this fails and names the missing files instead of
    letting twenty-two rules quietly stop checking them.
    """
    walked = {path.resolve() for _name, path, _tree in ALL_MODULES}
    on_disk = {
        path.resolve()
        for path in ROOT.rglob("*.py")
        if "__pycache__" not in path.parts
        # macOS AppleDouble metadata on FAT volumes: not source, not UTF-8.
        # `tests_arch/conftest.py` deletes these before collection; this guard
        # tolerates one appearing between that purge and now.
        and not path.name.startswith("._")
    }
    missing = sorted(str(p.relative_to(ROOT)) for p in on_disk - walked)
    assert not missing, (
        "these modules exist on disk but no architecture rule examines them:\n"
        + "\n".join(missing)
        + "\n\nEvery rule in this file iterates ALL_MODULES. A module absent "
        "from it is a module none of them check."
    )



# ── Dependencies point inward ────────────────────────────────────────────────


def test_every_dependency_points_inward():
    violations: list[str] = []
    for name, path, tree in ALL_MODULES:
        own = _layer_of(name)
        if own is None:
            continue
        for imported, line in _imports(tree):
            target = _layer_of(imported)
            if target is None:
                continue
            if target > own:
                violations.append(
                    f"{path.relative_to(ROOT.parent)}:{line} — layer {own} imports "
                    f"layer {target} ({imported})"
                )
    assert not violations, "outward dependencies:\n" + "\n".join(violations)


def test_the_domain_imports_nothing_but_itself_and_the_standard_library():
    """The domain must be testable with no fixture and no installed package."""
    violations: list[str] = []
    for name, path, tree in ALL_MODULES:
        if not name.startswith("sentinel.domain"):
            continue
        for imported, line in _imports(tree):
            root = imported.split(".")[0]
            if root == "sentinel" and not imported.startswith("sentinel.domain"):
                violations.append(f"{path.name}:{line} — {imported}")
            elif root in FRAMEWORKS:
                violations.append(f"{path.name}:{line} — framework import {imported}")
    assert not violations, "domain purity violations:\n" + "\n".join(violations)


def test_business_logic_never_imports_a_framework():
    """Domain and application must not know a web framework or a driver exists."""
    violations: list[str] = []
    for name, path, tree in ALL_MODULES:
        if not (
            name.startswith("sentinel.domain") or name.startswith("sentinel.application")
        ):
            continue
        for imported, line in _imports(tree):
            if imported.split(".")[0] in FRAMEWORKS:
                violations.append(f"{path.name}:{line} — {imported}")
    assert not violations, "framework leakage into business logic:\n" + "\n".join(violations)


def test_there_are_no_cyclic_dependencies():
    graph: dict[str, set[str]] = defaultdict(set)
    names = {name for name, _p, _t in ALL_MODULES}
    for name, _path, tree in ALL_MODULES:
        for imported, _line in _imports(tree):
            if imported in names:
                graph[name].add(imported)

    colour: dict[str, int] = defaultdict(int)  # 0 unvisited, 1 in-stack, 2 done
    cycle: list[str] = []

    def visit(node: str, stack: list[str]) -> bool:
        colour[node] = 1
        for neighbour in sorted(graph[node]):
            if colour[neighbour] == 1:
                cycle.extend(stack[stack.index(neighbour) :] + [neighbour])
                return True
            if colour[neighbour] == 0 and visit(neighbour, stack + [neighbour]):
                return True
        colour[node] = 2
        return False

    for node in sorted(names):
        if colour[node] == 0 and visit(node, [node]):
            break
    assert not cycle, "import cycle: " + " -> ".join(cycle)


def test_nothing_depends_on_the_delivery_mechanism():
    """No module below the edge may import `sentinel.interface`.

    HTTP, the CLI and the worker loop are delivery mechanisms. If anything below
    them imports one, the business logic has acquired an opinion about how it is
    invoked, and changing the transport stops being a local change.

    An earlier version of this rule flagged any module importing three layers.
    That was wrong, and it is worth recording why: an adapter legitimately uses
    domain types to implement an application port on top of infrastructure.
    Spanning the layers BELOW you is the job. Importing a layer ABOVE you is the
    violation, and `test_every_dependency_points_inward` is what catches it.
    """
    violations: list[str] = []
    for name, path, tree in ALL_MODULES:
        if name.startswith(("sentinel.interface", "sentinel.composition")):
            continue
        for imported, line in _imports(tree):
            if imported.startswith("sentinel.interface"):
                violations.append(f"{path.relative_to(ROOT.parent)}:{line} — {imported}")
    assert not violations, "dependencies on the delivery layer:\n" + "\n".join(violations)


# ── No global state, no hidden singletons ────────────────────────────────────

def _is_constant_name(name: str) -> bool:
    """SCREAMING_CASE, leading underscore permitted."""
    return name.lstrip("_").isupper() or name.startswith("__")


#: Constructors that produce a MUTABLE container. A module-level binding to one
#: of these is shared, writable process state no matter what it is called.
_MUTABLE_CALLS = {"list", "dict", "set", "defaultdict", "Counter", "deque", "OrderedDict"}


def _is_mutable_value(node: ast.expr | None) -> bool:
    """True only for values that can be mutated in place.

    The rule targets STATIC MUTABLE STATE, not every module-level binding. A
    `TypeVar`, a type alias, a frozen dataclass instance and an `int` are all
    module-level and none of them is state anyone can write to. Flagging them
    would train a reader to ignore this test, which is worse than not having it.
    """
    if node is None:
        return False
    if isinstance(node, (ast.List, ast.Dict, ast.Set, ast.ListComp, ast.DictComp, ast.SetComp)):
        return True
    if isinstance(node, ast.Call):
        fn = node.func
        label = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
        return label in _MUTABLE_CALLS
    return False


def test_there_is_no_mutable_module_level_state():
    """A module-level list, dict or set is a global by another name.

    `db._db_path`, `rules._POLICY`, `config._cached`, `INCIDENT_QUEUE`, `MONITOR`
    and `DurableQueue._last_sweep` were all process globals in the predecessor,
    which is why its tests depended on remembering to reset them and could not
    run in parallel.
    """
    violations: list[str] = []
    for name, path, tree in ALL_MODULES:
        for node in tree.body:
            targets: list[ast.expr] = []
            value: ast.expr | None = None
            if isinstance(node, ast.Assign):
                targets, value = list(node.targets), node.value
            elif isinstance(node, ast.AnnAssign):
                targets, value = [node.target], node.value
            for target in targets:
                if not isinstance(target, ast.Name):
                    continue
                if target.id == "__all__":
                    # A language protocol, read by `from x import *`. Exempt by
                    # exact name so the exemption cannot silently widen.
                    continue
                if not _is_mutable_value(value):
                    continue
                violations.append(
                    f"{path.relative_to(ROOT.parent)}:{node.lineno} — "
                    f"module-level mutable binding {target.id!r}"
                )
    assert not violations, "module-level mutable state:\n" + "\n".join(violations)


def test_no_module_declares_a_global_statement():
    """`global` at module scope is the mechanism a hidden singleton is built with."""
    violations: list[str] = []
    for _name, path, tree in ALL_MODULES:
        for node in ast.walk(tree):
            if isinstance(node, ast.Global):
                violations.append(
                    f"{path.relative_to(ROOT.parent)}:{node.lineno} — "
                    f"global {', '.join(node.names)}"
                )
    assert not violations, "global statements:\n" + "\n".join(violations)


def test_no_class_carries_mutable_class_level_state():
    """`DurableQueue._last_sweep` was a class attribute mutated at runtime."""
    violations: list[str] = []
    for _name, path, tree in ALL_MODULES:
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for item in node.body:
                targets: list[ast.expr] = []
                value: ast.expr | None = None
                if isinstance(item, ast.Assign):
                    targets, value = list(item.targets), item.value
                elif isinstance(item, ast.AnnAssign):
                    targets, value = [item.target], item.value
                if not _is_mutable_value(value):
                    continue
                for target in targets:
                    if isinstance(target, ast.Name):
                        violations.append(
                            f"{path.relative_to(ROOT.parent)}:{item.lineno} — "
                            f"{node.name}.{target.id}"
                        )
    assert not violations, "mutable class attributes:\n" + "\n".join(violations)


def test_importing_any_module_has_no_side_effects():
    """Importing must not open a connection, read a clock, or apply a schema.

    Importing `api.main` in the predecessor parsed configuration, validated the
    deployment, applied DDL, ran additive migrations, walked the entire ledger
    and synchronised tenants. Importing the app to read its routes changed the
    database.
    """
    forbidden = {"connect", "getenv", "makedirs", "mkdir", "urlopen", "system", "now"}
    violations: list[str] = []
    for name, path, tree in ALL_MODULES:
        if name.startswith("sentinel.composition"):
            continue  # the root may read the environment, in one function
        for node in tree.body:
            if not isinstance(node, (ast.Expr, ast.Assign, ast.AnnAssign)):
                continue
            for inner in ast.walk(node):
                if isinstance(inner, ast.Call):
                    fn = inner.func
                    label = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
                    if label in forbidden:
                        violations.append(
                            f"{path.relative_to(ROOT.parent)}:{node.lineno} — "
                            f"import-time call to {label}()"
                        )
    assert not violations, "import-time side effects:\n" + "\n".join(violations)


def test_only_the_settings_module_reads_the_environment():
    """One parser, one place. Two parsers of one input eventually disagree."""
    violations: list[str] = []
    for name, path, tree in ALL_MODULES:
        if name == "sentinel.composition.settings":
            continue
        if name == "sentinel.sdk.mcp_stdio":
            # The MCP stdio bridge is not part of the service. Claude Desktop
            # and Cursor spawn it from THEIR config and hand it the API key as
            # an environment variable, because that is the only channel those
            # clients offer; the service's Settings never exist in that
            # process. `main` takes `environ` as a parameter, so the one read
            # is at the edge and the parsing stays testable.
            continue
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and node.attr in {"getenv", "environ"}
                and isinstance(node.value, ast.Name)
                and node.value.id == "os"
            ):
                violations.append(f"{path.relative_to(ROOT.parent)}:{node.lineno}")
    assert not violations, (
        "environment reads outside sentinel.composition.settings:\n" + "\n".join(violations)
    )


# ── Every service is replaceable ─────────────────────────────────────────────


def test_every_application_collaborator_is_injected_through_the_constructor():
    """Handlers may not construct their own adapters.

    A handler that builds its own dependency cannot be given a different one,
    which makes it untestable in isolation and its collaborator irreplaceable.
    """
    concrete = {
        "SystemClock", "UuidIdGenerator", "StructuredLogger", "SqlUnitOfWorkFactory",
        "SqlReadModel", "SqlWorkQueue", "HttpAttestationGateway", "HttpModelAdvisor",
        "ConnectionPool", "DeterministicPolicy", "Secp256k1IdentityVerifier",
    }
    violations: list[str] = []
    for name, path, tree in ALL_MODULES:
        if not name.startswith("sentinel.application"):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in concrete:
                    violations.append(
                        f"{path.relative_to(ROOT.parent)}:{node.lineno} — "
                        f"constructs {node.func.id}"
                    )
    assert not violations, "application constructs concrete adapters:\n" + "\n".join(violations)


def test_every_handler_takes_its_dependencies_keyword_only():
    """Positional coupling transposed this system's arguments three times.

    `dlq.enqueue(tenant_id, incident_id, "pipeline", str(e))` against a signature
    of `(tenant_id, kind, payload, max_attempts)` put an error message in
    `max_attempts`, making every retry comparison meaningless.
    """
    violations: list[str] = []
    for name, path, tree in ALL_MODULES:
        if not name.startswith("sentinel.application"):
            continue
        for node in ast.walk(tree):
            if not (isinstance(node, ast.ClassDef) and node.name.endswith("Handler")):
                continue
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == "__init__":
                    positional = [a.arg for a in item.args.args if a.arg != "self"]
                    if positional:
                        violations.append(
                            f"{path.name}:{item.lineno} — {node.name}.__init__ takes "
                            f"positional {positional}"
                        )
    assert not violations, "handlers with positional dependencies:\n" + "\n".join(violations)


# ── Domain invariants that the predecessor asserted and never enforced ──────


def test_no_incident_mutator_has_a_defaulted_fence():
    """THE regression for the unfenced-write class.

    The predecessor's `repository.transition(..., epoch=None)` and
    `repository.fail(..., epoch=None)` skipped the fence by omission, and two
    call sites took that default. Here `fence` is required on every mutator, so
    an omission is a TypeError rather than a silent unfenced write.
    """
    source = (ROOT / "domain" / "incident.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    aggregate = next(
        n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "Incident"
    )
    mutators = {
        "advance", "record_evidence", "record_report", "request_approvals",
        "record_attestation", "complete", "close_without_action", "fail",
    }
    checked = 0
    for item in aggregate.body:
        if not isinstance(item, ast.FunctionDef) or item.name not in mutators:
            continue
        checked += 1
        names = [a.arg for a in item.args.kwonlyargs]
        assert "fence" in names, f"Incident.{item.name} does not take a fence"
        index = names.index("fence")
        assert item.args.kw_defaults[index] is None, (
            f"Incident.{item.name} gives `fence` a default; an unfenced write "
            "must be spelled Fence.unfenced(reason=...), never taken by omission"
        )
    assert checked == len(mutators), f"expected {len(mutators)} mutators, checked {checked}"


def test_the_engine_rebuilds_context_before_any_step_runs():
    """Hydration must precede execution, structurally.

    The predecessor skipped stages by rank and never rehydrated, so a resumed run
    reached attestation with `evidence=None` and produced a COMPLETED incident
    with no anchor. The guarantee is not "hydration exists" -- it is that
    hydration happens BEFORE the handler is called, on every path that calls one.

    Asserted over the AST rather than by reading the code: a future refactor that
    moves the handler call above the hydration loop fails the build.
    """
    source = (ROOT / "application" / "execution" / "engine.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    engine = next(
        n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "ExecutionEngine"
    )
    run_step = next(
        n for n in engine.body if isinstance(n, ast.FunctionDef) and n.name == "_run_step"
    )

    hydrate_line = None
    handler_line = None
    for node in ast.walk(run_step):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == "hydrate":
                hydrate_line = node.lineno if hydrate_line is None else hydrate_line
            if (
                isinstance(func, ast.Subscript)
                and isinstance(func.value, ast.Attribute)
                and func.value.attr == "_handlers"
            ):
                handler_line = node.lineno

    assert hydrate_line is not None, "_run_step does not hydrate the context at all"
    assert handler_line is not None, "_run_step does not call a step handler"
    assert hydrate_line < handler_line, (
        "the step handler is invoked BEFORE the execution context is rebuilt; a "
        "resumed run would hand it artifacts that are still None"
    )


def test_every_artifact_producing_step_is_declared_as_such():
    """A step that writes a durable artifact must say so in the plan.

    `produces_artifact` is what makes the plan self-describing about which steps
    have output that a resume has to reload.
    """
    from sentinel.application.execution.pipeline import INCIDENT_PLAN

    declared = {name.value for name in INCIDENT_PLAN.artifact_steps()}
    assert declared == {"evidence", "report"}, (
        f"artifact-producing steps drifted from the plan declaration: {sorted(declared)}"
    )


def test_completed_states_require_a_matching_attestation_outcome():
    """`COMPLETED` must be unreachable without a real anchor.

    The predecessor required only that `attestation_status` be non-empty, and
    `"Skipped"` -- returned both for a missing identity and for an unreachable
    gateway -- satisfied it.
    """
    from sentinel.domain.incident import (
        AttestationDisposition,
        IncidentState,
        _REQUIRED_FACTS,
    )

    attested = dict(
        (name, (predicate, description))
        for name, predicate, description in _REQUIRED_FACTS[IncidentState.COMPLETED_ATTESTED]
    )
    predicate, _ = attested["attestation_outcome"]
    assert predicate(AttestationDisposition.ANCHORED.value)
    assert not predicate(AttestationDisposition.UNAVAILABLE.value)
    assert not predicate(AttestationDisposition.NOT_ANCHORABLE.value)
    assert not predicate("skipped")
    assert not predicate("anything-non-empty")


def test_attestation_unavailable_is_not_terminal():
    """A transient outage must park for a retry, never complete."""
    from sentinel.domain.incident import IncidentState

    assert not IncidentState.ATTESTATION_UNAVAILABLE.is_terminal
    assert not IncidentState.ATTESTATION_UNAVAILABLE.is_attested
    assert IncidentState.COMPLETED_UNATTESTED.is_terminal
    assert not IncidentState.COMPLETED_UNATTESTED.is_attested
    assert IncidentState.COMPLETED_ATTESTED.is_attested


def test_the_unit_of_work_cannot_be_opened_without_a_tenant():
    """The RLS defect: an unscoped connection must not be obtainable.

    `dlq.succeed()` and `dlq.fail()` called `db._connect()` with no tenant, so
    under FORCE RLS their statements matched no rows -- silently on SQLite,
    fatally on PostgreSQL.
    """
    import inspect

    from sentinel.infrastructure.sql.unit_of_work import SqlUnitOfWorkFactory

    signature = inspect.signature(SqlUnitOfWorkFactory.begin)
    tenant = signature.parameters["tenant"]
    assert tenant.default is inspect.Parameter.empty, "begin(tenant) must be required"


def test_every_port_is_a_protocol_not_a_base_class():
    """Adapters satisfy ports structurally, so they never import the application."""
    import typing

    from sentinel.application import ports

    checked = 0
    for name in ports.__all__:
        candidate = getattr(ports, name, None)
        if not isinstance(candidate, type) or not name[0].isupper():
            continue
        if candidate.__module__ != ports.__name__:
            continue  # re-exported record type
        checked += 1
        assert typing.Protocol in candidate.__mro__ or getattr(
            candidate, "_is_protocol", False
        ), f"{name} is exported as a port but is not a Protocol"
    assert checked >= 10


# ── Style rules that were defect classes here ────────────────────────────────


def test_nothing_prints_to_stdout():
    """The predecessor mixed `print()` with structured logging in the same module.

    A `print` is invisible to log aggregation, so an operator's view of an
    incident depended on which statement the author happened to reach for.
    """
    violations: list[str] = []
    for _name, path, tree in ALL_MODULES:
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "print"
            ):
                violations.append(f"{path.relative_to(ROOT.parent)}:{node.lineno}")
    assert not violations, "print() calls:\n" + "\n".join(violations)


def test_nothing_uses_assert_for_a_runtime_invariant():
    """`assert` vanishes under `python -O`.

    The predecessor guarded the relationship between its protect-mode block
    threshold and its unverified-severity cap with a module-level `assert`, so
    the guard disappeared in an optimised build.
    """
    violations: list[str] = []
    for _name, path, tree in ALL_MODULES:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assert):
                violations.append(f"{path.relative_to(ROOT.parent)}:{node.lineno}")
    assert not violations, "assert statements in production code:\n" + "\n".join(violations)


def test_no_module_exceeds_the_size_at_which_it_stops_having_one_reason_to_change():
    """`db.py` was 1327 lines with sixty functions; `main.py` was 1201."""
    oversized = [
        f"{path.relative_to(ROOT.parent)} — {len(path.read_text(encoding='utf-8').splitlines())} lines"
        for _name, path, _tree in ALL_MODULES
        if len(path.read_text(encoding="utf-8").splitlines()) > 800
    ]
    assert not oversized, "modules over 800 lines:\n" + "\n".join(oversized)


def test_every_module_is_importable_in_isolation():
    """Independent testability, checked rather than asserted."""
    failures: list[str] = []
    for name, _path, _tree in ALL_MODULES:
        try:
            importlib.import_module(name)
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{name}: {type(exc).__name__}: {exc}")
    assert not failures, "modules that fail to import:\n" + "\n".join(failures)


# ── F-11: remediation side effects must go through ProtectedToolRunner ───────

#: Modules allowed to call RemediationExecutor-shaped \.execute(..., idempotency_key=)\.
#:
#: - infrastructure/executors.py: the inner Integration adapters
#: - application/commands/decide_approval.py: only via tool_runner side_effect
#: - application/tool_runner.py: not a remediation execute, but listed for clarity
_REMEDIATION_EXECUTE_ALLOWLIST = frozenset(
    {
        "sentinel.infrastructure.executors",
        "sentinel.application.commands.decide_approval",
        # The dispatch layer, same role as `executors` above: it routes an action
        # to the integration registered for it and is itself invoked from inside
        # `DecideApprovalHandler`'s ProtectedToolRunner side effect, so the
        # protect gate has already run by the time it is reached.
        #
        # ONE CAVEAT, RECORDED RATHER THAN HIDDEN: `GuardedRemediationExecutor
        # .rollback` calls `self.execute`, and rollback is a public entry point
        # with no ProtectedToolRunner of its own. Nothing in the repository calls
        # it today -- `test_no_application_code_calls_rollback_directly` below
        # keeps that true -- but any future application-layer caller must wrap it
        # the way `decide_approval` wraps the forward action, or protect mode
        # will not see the undo.
        "sentinel.infrastructure.remediation",
    }
)


def test_remediation_side_effects_go_through_protected_tool_runner():
    """No in-repo path may invoke a remediation execute outside the allowlist.

    A call is recognised as remediation-shaped when it is an attribute execute
    with an idempotency_key keyword -- the RemediationExecutor / Integration
    contract. SQL conn.execute and similar are excluded by lacking that kwarg.

    Intentional exceptions (allowlist):
      * infrastructure/executors.py -- Composite/Null/Integration implementations
      * decide_approval.py -- must wrap the call in ProtectedToolRunner.execute
    """
    violations: list[str] = []
    for name, path, tree in ALL_MODULES:
        if name in _REMEDIATION_EXECUTE_ALLOWLIST:
            continue
        if name.startswith("sentinel.application.tool_runner"):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr != "execute":
                continue
            keywords = {kw.arg for kw in node.keywords if kw.arg}
            if "idempotency_key" not in keywords:
                continue
            violations.append(
                f"{path.relative_to(ROOT.parent)}:{node.lineno} — "
                f"remediation-shaped execute() outside allowlist"
            )
    assert not violations, (
        "remediation side effects must go through ProtectedToolRunner / allowlist:\n"
        + "\n".join(violations)
    )


def test_no_application_code_calls_rollback_directly():
    """`GuardedRemediationExecutor.rollback` performs a real side effect.

    It is allowlisted above as part of the dispatch layer, which is only sound
    while nothing calls it outside a ProtectedToolRunner. Today nothing calls it
    at all, so the allowlist entry is honest. The moment an application-layer
    caller appears it must wrap the undo the way `decide_approval` wraps the
    forward action -- otherwise protect mode fails closed on disabling an agent
    and stays silent on re-enabling one, which is the wrong way round.

    This test is what stops the allowlist entry from quietly becoming a lie.
    """
    violations: list[str] = []
    for name, path, tree in ALL_MODULES:
        if not name.startswith("sentinel.application"):
            continue
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "rollback"
                # `uow.rollback()` is the transaction one and is unrelated.
                and not (
                    isinstance(node.func.value, ast.Name)
                    and node.func.value.id in {"uow", "self"}
                )
            ):
                violations.append(f"{path.relative_to(ROOT.parent)}:{node.lineno}")
    assert not violations, (
        "remediation rollback called from application code without a "
        "ProtectedToolRunner wrapper:\n" + "\n".join(violations)
    )


def test_decide_approval_wraps_executor_in_tool_runner():
    """The sole application call site must invoke tool_runner before executor."""
    source = (
        ROOT / "application" / "commands" / "decide_approval.py"
    ).read_text(encoding="utf-8")
    runner_at = source.find("_tool_runner.execute")
    executor_at = source.find("_executor.execute")
    assert runner_at != -1, "DecideApprovalHandler must call _tool_runner.execute"
    assert executor_at != -1, "DecideApprovalHandler must still call _executor.execute"
    assert runner_at < executor_at, (
        "_tool_runner.execute must appear before _executor.execute in source order"
    )
    assert "side_effect=" in source
    assert "ToolExecutionRefused" in source


def test_tool_runner_honours_kill_switch_before_gate():
    """ProtectControls.assert_may_execute must appear before run_if_allowed."""
    source = (ROOT / "application" / "tool_runner.py").read_text(encoding="utf-8")
    controls_at = source.find("self._controls.assert_may_execute")
    gate_at = source.find("self._gate.run_if_allowed")
    assert controls_at != -1 and gate_at != -1 and controls_at < gate_at



# ── Dual-engine coverage for tests that drive the database ───────────────────
#
# THE DEFECT THIS RULE EXISTS FOR
# --------------------------------
# `tests_arch/conftest.py` provides `engine_config`, which parametrises a test
# over BOTH SQLite and PostgreSQL, and its docstring calls that non-optional:
# "a test that only ever runs on SQLite is a test that cannot see that class of
# bug". Nothing enforced it.
#
# `test_retention_sweep.py` then hand-rolled its own SQLite-only fixture, and
# the retention sweep shipped deleting ZERO rows on PostgreSQL while reporting
# zero -- green locally, and on the production engine doing nothing at all. The
# convention existed; the enforcement did not.
#
# WHY THIS IS A RATCHET AND NOT A BLANKET RULE
# ---------------------------------------------
# Sixteen existing modules build a single-engine database, and almost all of
# them are legitimate: they need *a* database to exercise an HTTP route or a
# detection path, not to test SQL behaviour on both engines. Failing all of them
# today would produce a rule someone deletes by Friday, which is worse than no
# rule.
#
# So the existing set is recorded below as a baseline and NEW modules must use a
# dual-engine fixture. The list may shrink -- convert a module and remove its
# entry -- and may not grow.

#: Modules that construct their own engine and run on ONE engine only, as of
#: 2026-08-19. Recorded, not endorsed. Removing an entry (by converting the
#: module to `engine_config`) is always welcome; adding one is not.
SINGLE_ENGINE_BASELINE = frozenset(
    {
        "test_alert_rules",
        "test_detection_mode",
        "test_dlq_http_stub",
        "test_end_to_end",
        "test_gap_closures",
        "test_multi_tenant_soak",
        "test_phase_closures",
        "test_protect_gate",
        "test_security_audit_trail",
        "test_security_bounds",
        "test_security_bypass_detection",
        "test_security_edge",
        "test_security_throttle",
    }
)

#: Anything that means "this module runs on both engines".
DUAL_ENGINE_MARKERS = (
    "engine_config",   # the conftest fixture, parametrised over both
    "migrated_pool",   # built on engine_config, so also both
)


def _builds_its_own_engine(source: str) -> bool:
    return "build_engine(" in source or "EngineConfig(" in source


def _is_dual_engine(source: str) -> bool:
    if any(marker in source for marker in DUAL_ENGINE_MARKERS):
        return True
    # A module may parametrise itself, as test_retention_sweep.py does.
    return 'params=["sqlite", "postgres"]' in source or "'sqlite', 'postgres'" in source


def _single_engine_modules() -> set[str]:
    here = Path(__file__).resolve().parent
    found = set()
    for path in sorted(here.glob("test_*.py")):
        source = path.read_text(encoding="utf-8", errors="replace")
        if _builds_its_own_engine(source) and not _is_dual_engine(source):
            found.add(path.stem)
    return found


def test_the_dual_engine_scan_actually_inspects_modules():
    """A denominator of zero would make the rule below vacuous."""
    here = Path(__file__).resolve().parent
    modules = list(here.glob("test_*.py"))
    assert len(modules) >= 20, f"only {len(modules)} test modules found"
    building = [
        p.stem
        for p in modules
        if _builds_its_own_engine(p.read_text(encoding="utf-8", errors="replace"))
    ]
    assert len(building) >= 10, (
        f"only {len(building)} modules appear to build an engine; the detector "
        "is not matching what the suite actually does"
    )
    # And the detector must recognise the known-good ones, or it would report
    # every module as single-engine and the baseline would be meaningless.
    assert "test_sql_infrastructure" not in _single_engine_modules()
    assert "test_retention_sweep" not in _single_engine_modules()


def test_no_new_test_module_drives_the_database_on_one_engine_only():
    """New SQL-touching tests must run on BOTH engines.

    If this fails you added a module that builds its own database and runs on
    one engine. Use the `engine_config` fixture from `tests_arch/conftest.py`,
    or parametrise your own fixture over both, as `test_retention_sweep.py`
    does. The retention sweep is the reason this rule exists: it was correct on
    SQLite and did nothing at all on PostgreSQL, and no test could see it.
    """
    offenders = sorted(_single_engine_modules() - SINGLE_ENGINE_BASELINE)
    assert not offenders, (
        "these test modules build their own database and run on ONE engine:\n"
        + "\n".join(f"  {name}" for name in offenders)
        + "\n\nUse `engine_config` (conftest) so the test runs on SQLite AND "
        "PostgreSQL. `tests_arch/conftest.py` explains why that is not optional: "
        "the retention sweep passed on SQLite while deleting nothing on "
        "PostgreSQL, and a SQLite-only test cannot see that class of bug."
    )


def test_the_single_engine_baseline_has_not_gone_stale():
    """A baseline listing modules that no longer exist is not a baseline.

    It also catches the good case: if someone converts a module to
    `engine_config`, this fails and asks for the entry to be removed, so the
    ratchet tightens instead of leaving permanent headroom.
    """
    here = Path(__file__).resolve().parent
    existing = {p.stem for p in here.glob("test_*.py")}
    vanished = sorted(SINGLE_ENGINE_BASELINE - existing)
    assert not vanished, (
        f"SINGLE_ENGINE_BASELINE names modules that no longer exist: {vanished}"
    )
    converted = sorted(SINGLE_ENGINE_BASELINE - _single_engine_modules())
    assert not converted, (
        f"these modules now run on both engines and should be removed from "
        f"SINGLE_ENGINE_BASELINE: {converted}"
    )


def test_every_slotted_class_declares_every_attribute_it_assigns():
    """`__slots__` plus a forgotten name is an AttributeError at CONSTRUCTION.

    WHY THIS EXISTS, twice over. Building the SIEM delivery path added
    `self._siem = ...` to `DispatchOutboxHandler` without adding `"_siem"` to
    its `__slots__`, and every container build in the repository began raising
    `AttributeError: no __dict__ for setting new attributes` -- not one test,
    all of them, because nothing could construct an application. The same
    mistake was then made independently on `PipelineSteps` while wiring the
    export flag.

    It is a peculiarly bad failure to catch late. `from __future__ import
    annotations` means the type checker sees nothing wrong, ruff sees nothing
    wrong, and the module imports cleanly -- the class object is fine, it is
    only INSTANTIATION that fails. So the first symptom is every test erroring
    at fixture setup, which reads like an environment problem rather than a
    one-line omission.

    Scoped to `self.<name> = ...` in `__init__` because that is where the
    defect appears and where the check can be exact. A property setter or a
    method assigning to a slot elsewhere is not examined; this is a cheap gate
    on the common shape, not a type system.
    """
    violations: list[str] = []
    for _name, path, tree in ALL_MODULES:
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            slots: set[str] | None = None
            for statement in node.body:
                if (
                    isinstance(statement, ast.Assign)
                    and any(
                        isinstance(t, ast.Name) and t.id == "__slots__"
                        for t in statement.targets
                    )
                    and isinstance(statement.value, (ast.Tuple, ast.List, ast.Set))
                ):
                    slots = {
                        element.value
                        for element in statement.value.elts
                        if isinstance(element, ast.Constant)
                        and isinstance(element.value, str)
                    }
            if slots is None:
                continue
            init = next(
                (
                    item
                    for item in node.body
                    if isinstance(item, ast.FunctionDef) and item.name == "__init__"
                ),
                None,
            )
            if init is None:
                continue
            for inner in ast.walk(init):
                if not isinstance(inner, ast.Assign):
                    continue
                for target in inner.targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == "self"
                        and target.attr not in slots
                    ):
                        violations.append(
                            f"{path.relative_to(ROOT.parent)}:{target.lineno} — "
                            f"{node.name}.__init__ assigns self.{target.attr}, "
                            f"which is not in its __slots__"
                        )

    assert not violations, (
        "classes assign attributes their __slots__ does not declare, which "
        "raises AttributeError the first time the class is CONSTRUCTED:\n"
        + "\n".join(violations)
    )
