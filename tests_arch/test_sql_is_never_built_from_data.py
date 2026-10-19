"""No SQL string in this package may interpolate anything but a placeholder.

WHY THIS REPLACES A BANDIT RULE
--------------------------------
`bandit -r sentinel -ll` reported 99 findings and every one was B608,
`hardcoded_sql_expressions` -- the rule that fires on an f-string containing SQL.
The job could therefore never pass, and a gate that cannot pass gets switched
off, which is how a real finding eventually gets missed. The other finding in
that run, B314, was real and is fixed (see `test_saml_xml_hardening.py`).

B608 fires on this codebase by construction. Every statement is built with an
f-string because the PLACEHOLDER TOKEN differs per dialect -- `?` on SQLite,
`%s` on PostgreSQL -- so `Connection.p` is interpolated and the actual values are
always bound. Enumerating what the 99 sites interpolate:

      316  {p}
       28  {conn.p}
        1  {states}     ",".join(p for _ in TERMINAL_STATES) -- placeholders
        1  {table}      loop variable over INCIDENT_CHILD_TABLES, a constant

Not one of them interpolates caller data. So B608 is a systematic false positive
here, and it is skipped in `bandit.yaml` -- with this file named as the reason.

THIS TEST IS STRICTER THAN THE RULE IT REPLACES
------------------------------------------------
Bandit asks "is there an f-string that looks like SQL?", which is true of every
statement in the package and therefore tells nobody anything. This asks the
question that actually matters -- "what CAN be interpolated?" -- and answers it
with a closed allowlist. A new interpolation of any other shape fails here,
including shapes bandit would rate LOW confidence and pass over.

If you are here because this test failed: you added an interpolation into a SQL
string. That is not automatically wrong -- an identifier genuinely cannot be a
bound parameter -- but it has to be a fixed name the caller cannot influence,
and it has to be added to `ALLOWED_INTERPOLATIONS` below with a reason. If the
thing you want to interpolate is a VALUE, bind it instead.
"""

from __future__ import annotations

import ast
from pathlib import Path

import sentinel

ROOT = Path(sentinel.__file__).resolve().parent

#: Substrings that mark a string literal as SQL. Matched CASE-SENSITIVELY, and
#: that is the load-bearing detail: this codebase writes SQL keywords in upper
#: case and English prose in lower case, so `" WHERE "` finds a query while
#: "where the tenant is unknown" in an error message does not. Matching
#: case-insensitively pulled in a dozen f-string log lines and error messages
#: that contain the word "update" or "from", and an allowlist padded with
#: `{exc}` and `{skew}` to silence them would be worse than no test.
SQL_MARKERS = (
    "SELECT ", "INSERT INTO", "UPDATE ", "DELETE FROM", "CREATE TABLE",
    "CREATE INDEX", "CREATE UNIQUE", "CREATE POLICY", "ALTER TABLE",
    "DROP POLICY", "DROP TABLE", " FROM ", " WHERE ", "VALUES (", "TRUNCATE ",
)

#: The ONLY expressions that may appear inside a SQL f-string, by exact source.
#: Each one is a placeholder token or a fixed identifier, never a value.
ALLOWED_INTERPOLATIONS: dict[str, str] = {
    # The dialect's parameter marker: "?" on SQLite, "%s" on PostgreSQL. This is
    # the entire reason these strings are f-strings at all.
    "p": "the placeholder token from Connection.p",
    "conn.p": "the placeholder token, via a local connection",
    "self.p": "the placeholder token, on Connection itself",
    "self._conn.p": "the placeholder token, via an instance's connection",
    # Row-level-security DDL. An identifier and a SQL fragment cannot be bound
    # parameters, so these are interpolated; both are derived entirely from
    # module-level constants and are proved so by the test below.
    "policy": 'f"{table}_tenant_isolation" — derived from PROTECTED_TABLES',
    "predicate": "a fixed comparison against the TENANT_SETTING constant",
    "t": "loop variable over PROTECTED_TABLES, a module constant",
    # A comma-joined run of placeholders for an IN (...) clause, built from the
    # LENGTH of a module-level constant. No element of it reaches the string.
    "states": 'ate", ".join(p for _ in TERMINAL_STATES) -- placeholders only',
    "placeholders": "a comma-joined run of placeholder tokens",
    # A table name from a module-level constant tuple. An identifier cannot be a
    # bound parameter, and the set of possible values is fixed in source.
    "table": "loop variable over INCIDENT_CHILD_TABLES, a module constant",
    # The receipt store's column list. A comma-joined run of IDENTIFIERS from a
    # module-level constant tuple, held in one place precisely so an INSERT's
    # column order and a SELECT's field order cannot drift apart -- which is
    # the classic way a store starts returning one field's value under
    # another's name. Identifiers cannot be bound parameters, and no element
    # of `_COLUMNS` is reachable from a caller.
    # The receipt store's column lists, joined ONCE at import rather than in
    # each query -- so these are constant NAMES, not calls. An allowlist entry
    # for a call is weaker, because a call can be given a different argument.
    "_COLUMN_LIST": (
        "comma-joined identifiers from _COLUMNS, a module-level constant in "
        "receipt_store.py; asserted below to contain only bare identifiers"
    ),
    "_INSERT_COLUMN_LIST": "the same, with tenant_id prepended",
}


def _sql_modules() -> list[tuple[Path, ast.Module]]:
    out = []
    for path in sorted(ROOT.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        if not any(marker in source for marker in SQL_MARKERS):
            continue
        out.append((path, ast.parse(source)))
    return out


def _looks_like_sql(node: ast.JoinedStr) -> bool:
    literal = "".join(
        part.value for part in node.values if isinstance(part, ast.Constant)
        and isinstance(part.value, str)
    )
    return any(marker in literal for marker in SQL_MARKERS)


def test_the_scan_actually_finds_the_sql_modules():
    """Guards every assertion below: a broken walker would pass them all."""
    modules = _sql_modules()
    assert len(modules) >= 5, f"expected several SQL modules, found {len(modules)}"
    names = {p.name for p, _ in modules}
    assert "repositories.py" in names and "retention.py" in names


def test_no_sql_string_interpolates_anything_but_an_allowlisted_expression():
    """The rule. 344 placeholder interpolations pass; a value would not."""
    violations: list[str] = []
    checked = 0

    for path, tree in _sql_modules():
        for node in ast.walk(tree):
            if not isinstance(node, ast.JoinedStr) or not _looks_like_sql(node):
                continue
            for part in node.values:
                if not isinstance(part, ast.FormattedValue):
                    continue
                checked += 1
                expr = ast.unparse(part.value)
                if expr not in ALLOWED_INTERPOLATIONS:
                    violations.append(
                        f"{path.relative_to(ROOT.parent)}:{part.value.lineno} — "
                        f"{{{expr}}}"
                    )

    assert checked >= 300, (
        f"only {checked} interpolations examined; the walker is not reaching the "
        "statements it is supposed to police"
    )
    assert not violations, (
        "SQL strings interpolate expressions that are not on the allowlist:\n"
        + "\n".join(violations)
        + "\n\nIf it is an IDENTIFIER the caller cannot influence, add it to "
        "ALLOWED_INTERPOLATIONS with a reason. If it is a VALUE, bind it as a "
        "parameter instead — that is what the placeholder is for."
    )


#: Names on the allowlist that are IDENTIFIERS rather than placeholder tokens.
#: Every binding of each must be provably a fixed set of strings.
IDENTIFIER_NAMES = ("table", "t")


def _module_object(path: Path):
    """Import the module a path belongs to, so imported constants can be read."""
    import importlib

    rel = path.relative_to(ROOT.parent).with_suffix("")
    return importlib.import_module(".".join(rel.parts))


def _iterates_only_fixed_strings(iterable: ast.expr, module: ast.Module, obj) -> bool:
    """True when a loop iterable can only ever yield source-fixed strings.

    Three accepted shapes:
      * a literal tuple/list of string constants, written inline
      * a Name assigned exactly once at module level to such a literal
      * a Name that is an IMPORTED module-level constant — resolved against the
        real object, because `PROTECTED_TABLES` lives in `schema.py` and is used
        in `migrate.py`, so no amount of AST work on the using module can see it

    The third case is the reason this takes a module object as well as a tree.
    Resolving it by import is sound here: these are module-level constants
    evaluated at import time, not values that vary per request.
    """
    if isinstance(iterable, (ast.Tuple, ast.List)):
        return all(
            isinstance(el, ast.Constant) and isinstance(el.value, str)
            for el in iterable.elts
        )
    if isinstance(iterable, ast.Name):
        assignments = [
            node
            for node in module.body
            if isinstance(node, (ast.Assign, ast.AnnAssign))
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
            if isinstance(target, ast.Name) and target.id == iterable.id
        ]
        if len(assignments) == 1:
            return _iterates_only_fixed_strings(assignments[0].value, module, obj)
        # Not assigned here: an import. Check the real object is an immutable
        # collection of strings. A list would NOT qualify -- something could
        # append to it at runtime, which is the whole risk being excluded.
        resolved = getattr(obj, iterable.id, None)
        return isinstance(resolved, (tuple, frozenset)) and bool(resolved) and all(
            isinstance(item, str) for item in resolved
        )
    return False


def test_every_interpolated_identifier_comes_from_a_fixed_set_of_strings():
    """The allowlist matches on NAME, so the names must be proved, not trusted.

    Without this, someone could rebind `table` to a request field and the test
    above would still pass — it would see `{table}`, recognise the name, and
    wave it through. Here every binding of every identifier name is walked and
    required to iterate a source-fixed collection of strings.
    """
    checked = 0
    violations: list[str] = []

    for path, tree in _sql_modules():
        for node in ast.walk(tree):
            targets = []
            if isinstance(node, (ast.For, ast.comprehension)):
                target = node.target
                iterable = node.iter
                if isinstance(target, ast.Name) and target.id in IDENTIFIER_NAMES:
                    targets.append((target.id, iterable, getattr(node, "lineno", 0)))
            for name, iterable, lineno in targets:
                checked += 1
                if not _iterates_only_fixed_strings(iterable, tree, _module_object(path)):
                    violations.append(
                        f"{path.relative_to(ROOT.parent)}:{lineno} — `{name}` is "
                        f"bound from {ast.unparse(iterable)}, which this test "
                        "cannot prove is a fixed set of strings"
                    )

    assert checked, "no bindings of the identifier names were found; check is stale"
    assert not violations, (
        "SQL identifiers are interpolated from something other than a fixed set "
        "of strings:\n" + "\n".join(violations)
    )


def test_the_rls_policy_ddl_is_built_only_from_constants():
    """`policy` and `predicate` are interpolated straight into DDL."""
    from sentinel.infrastructure.sql import migrate as sql_migrate
    from sentinel.infrastructure.sql import schema as sql_schema

    schema_source = Path(sql_schema.__file__).read_text(encoding="utf-8")
    assert 'policy = f"{table}_tenant_isolation"' in schema_source, (
        "the RLS policy name is no longer derived from the table name"
    )
    assert "current_setting('{TENANT_SETTING}', true)" in schema_source, (
        "the RLS predicate no longer compares against the TENANT_SETTING constant"
    )
    assert isinstance(sql_schema.PROTECTED_TABLES, (tuple, frozenset, list))
    assert all(isinstance(name, str) for name in sql_schema.PROTECTED_TABLES)

    # `rls_statements(table)` takes its table as an ARGUMENT, so the guarantee
    # rests on its callers. Check them where they actually live.
    migrate_tree = ast.parse(Path(sql_migrate.__file__).read_text(encoding="utf-8"))
    callers = [
        node
        for node in ast.walk(migrate_tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "rls_statements"
    ]
    assert callers, "no call to rls_statements found; this check is stale"
    for call in callers:
        arg = ast.unparse(call.args[0]) if call.args else ""
        assert arg == "table", (
            f"rls_statements is called with {arg!r}; this test can only vouch "
            "for a loop variable named `table` over PROTECTED_TABLES"
        )
    loops = [
        node
        for node in ast.walk(migrate_tree)
        if isinstance(node, ast.For)
        and isinstance(node.target, ast.Name)
        and node.target.id == "table"
    ]
    assert loops, "no `for table in ...` loop in migrate.py"
    for loop in loops:
        assert isinstance(loop.iter, ast.Name) and loop.iter.id == "PROTECTED_TABLES", (
            f"`table` is bound from {ast.unparse(loop.iter)}, not PROTECTED_TABLES"
        )


def test_the_in_clause_joins_placeholders_not_values():
    """`states` must be a run of `?`/`%s`, never the state strings themselves."""
    from sentinel.infrastructure.sql import retention

    source = Path(retention.__file__).read_text(encoding="utf-8")
    assert "join(p for _ in TERMINAL_STATES)" in source, (
        "`states` is no longer built by joining placeholder tokens. If it now "
        "interpolates the state VALUES, that is a SQL injection shape even "
        "though the values happen to be constants today."
    )
    assert isinstance(retention.TERMINAL_STATES, tuple)


def test_bandit_still_runs_every_other_rule():
    """The skip in bandit.yaml must be exactly one rule, not a blanket off-switch.

    A config that quietly grew `skips: [B608, B105, B311, ...]` would turn the
    `security` job green by checking nothing, which is the failure mode this
    repository keeps retracting. B314 -- the real SAML XML finding -- must still
    be reachable.
    """
    import yaml

    config = yaml.safe_load((ROOT.parent / "bandit.yaml").read_text(encoding="utf-8"))
    skips = config.get("skips") or []
    assert skips == ["B608"], (
        f"bandit.yaml skips {skips}; only B608 is justified (see this module's "
        "docstring). Every other rule must stay on."
    )
    assert not config.get("exclude_dirs", []) or "sentinel" not in str(
        config.get("exclude_dirs")
    ), "bandit must still scan sentinel/"


def test_the_receipt_store_columns_are_bare_identifiers():
    """The allowlist entry for `_COLUMNS` claims they are identifiers. An
    allowlist entry nobody checks is a comment, and this is the one that would
    matter: a column name carrying a quote or a space would make the joined
    string a SQL fragment rather than a column list.
    """
    from sentinel.infrastructure.sql.receipt_store import _COLUMNS

    assert len(_COLUMNS) >= 10, "control: the constant is not what was expected"
    for column in _COLUMNS:
        assert column.isidentifier(), column
        assert column.islower(), column
