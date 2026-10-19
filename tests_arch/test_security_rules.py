"""Security rules as fitness functions, checked against the AST.

WHY AST RULES RATHER THAN A REVIEW CHECKLIST
--------------------------------------------
Every finding fixed in this pass was reachable because a rule existed only in
someone's head. `urlopen` was used directly in three adapters, and nothing failed
when a fourth would have been added. Roles were compared with `>=` at each call
site, and nothing failed when a new route got the comparison right for the wrong
reason.

A rule that is not executable is a rule that holds until the next commit. These
fail the build.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "sentinel"


def _modules() -> list[Path]:
    return sorted(p for p in PACKAGE.rglob("*.py") if "__pycache__" not in p.parts)


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _rel(path: Path) -> str:
    return str(path.relative_to(ROOT)).replace("\\", "/")


# ── Outbound HTTP ────────────────────────────────────────────────────────────

#: The only module permitted to reach the network directly. Everything else goes
#: through it, so the SSRF and redirect defences cannot be bypassed by writing a
#: new adapter that reaches for the obvious stdlib call.
_OUTBOUND_OWNER = "sentinel/infrastructure/outbound.py"

_FORBIDDEN_NETWORK_CALLS = {
    "urlopen": "urllib.request.urlopen follows redirects and forwards the "
    "Authorization header to the redirect target. Proven: a 302 to a loopback "
    "address received the attestation bearer token.",
    "build_opener": "a custom opener re-implements the redirect handling that "
    "leaked the token; use HardenedHttpClient",
    "install_opener": "installs process-global HTTP behaviour, which is both "
    "global state and an invisible security policy",
}


def test_no_module_reaches_the_network_except_the_hardened_client():
    """The invariant that makes the SSRF fix hold for code not yet written."""
    offenders: list[str] = []
    for path in _modules():
        if _rel(path) == _OUTBOUND_OWNER:
            continue
        for node in ast.walk(_parse(path)):
            if isinstance(node, ast.Call):
                name = (
                    node.func.attr
                    if isinstance(node.func, ast.Attribute)
                    else getattr(node.func, "id", "")
                )
                if name in _FORBIDDEN_NETWORK_CALLS:
                    offenders.append(
                        f"{_rel(path)}:{node.lineno} calls {name}() -- "
                        f"{_FORBIDDEN_NETWORK_CALLS[name]}"
                    )
    assert not offenders, "\n".join(offenders)


def test_no_module_outside_the_client_imports_urllib_request():
    """An import is the precursor to a call, and it is the cheaper thing to catch."""
    offenders: list[str] = []
    for path in _modules():
        if _rel(path) == _OUTBOUND_OWNER:
            continue
        tree = _parse(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "urllib.request":
                        offenders.append(f"{_rel(path)}:{node.lineno}")
            elif isinstance(node, ast.ImportFrom) and node.module == "urllib.request":
                offenders.append(f"{_rel(path)}:{node.lineno}")
    assert not offenders, (
        "these modules import urllib.request directly, bypassing the SSRF and "
        "redirect defences: " + ", ".join(offenders)
    )


def test_the_hardened_client_never_enables_redirect_following():
    """Guards against the fix being undone by a helpful refactor.

    Checked against the AST, not the text: the module docstring necessarily
    NAMES `HTTPRedirectHandler` to explain the defect it exists to prevent, and a
    substring rule would flag that explanation as the defect.
    """
    path = PACKAGE / "infrastructure" / "outbound.py"
    tree = _parse(path)
    referenced = {
        node.attr if isinstance(node, ast.Attribute) else node.id
        for node in ast.walk(tree)
        if isinstance(node, (ast.Attribute, ast.Name))
    }
    for forbidden in ("HTTPRedirectHandler", "follow_redirects", "allow_redirects"):
        assert forbidden not in referenced, (
            f"outbound.py references {forbidden} in code, not just in prose"
        )

    # The 3xx branch must still RAISE. A log-and-continue would restore the leak.
    raises_on_redirect = any(
        isinstance(node, ast.Raise)
        and "Redirects are refused" in ast.unparse(node)
        for node in ast.walk(tree)
    )
    assert raises_on_redirect, "the redirect branch no longer raises"


# ── Authorisation ────────────────────────────────────────────────────────────


def test_no_route_guards_on_a_role_name():
    """`require("ingest")` was satisfiable by a viewer. Only capabilities now.

    Checked as an AST rule rather than a naming convention because the failure was
    silent: the wrong guard returned 202, not an error.
    """
    offenders: list[str] = []
    for path in _modules():
        if "interface" not in path.parts:
            continue
        for node in ast.walk(_parse(path)):
            if (
                isinstance(node, ast.Call)
                and getattr(node.func, "id", "") == "require"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                offenders.append(
                    f"{_rel(path)}:{node.lineno} guards on the string "
                    f"{node.args[0].value!r} instead of a Capability"
                )
    assert not offenders, "\n".join(offenders)


def test_authorisation_is_never_an_ordered_comparison():
    """A total order cannot express two independent axes, which was the defect.

    AST again, not text: `authorization.py` quotes the old `_ROLE_ORDER` table
    verbatim in its docstring so a reader understands what is being prevented, and
    a substring rule would flag that quotation as a reintroduction.
    """
    for name in ("domain/authorization.py", "interface/http.py", "interface/http_models.py"):
        tree = _parse(PACKAGE / name)
        assignments = [
            target.id
            for node in ast.walk(tree)
            if isinstance(node, (ast.Assign, ast.AnnAssign))
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
            if isinstance(target, ast.Name)
        ]
        assert "_ROLE_ORDER" not in assignments, (
            f"{name} defines a role ORDERING again; grants must be explicit sets"
        )

    # And the predicate must be membership, not comparison. Inspected as Compare
    # nodes rather than text, because `-> bool` contains a `>`.
    http_tree = _parse(PACKAGE / "interface" / "http_models.py")
    for node in ast.walk(http_tree):
        if isinstance(node, ast.FunctionDef) and node.name == "can":
            operators = [
                type(op).__name__
                for compare in ast.walk(node)
                if isinstance(compare, ast.Compare)
                for op in compare.ops
            ]
            assert "In" in operators, "Principal.can no longer tests set membership"
            ordering = {"Gt", "GtE", "Lt", "LtE"} & set(operators)
            assert not ordering, (
                f"Principal.can compares with {sorted(ordering)}; that is the "
                "ordering defect returning"
            )
            break
    else:  # pragma: no cover - the method must exist
        pytest.fail("Principal.can was not found")


def test_every_capability_is_granted_to_at_least_one_role():
    """An ungranted capability is a route nobody can reach, which is a bug that
    presents as a mysterious 403."""
    from sentinel.domain.authorization import Capability, roles_holding

    orphans = [c.value for c in Capability if not roles_holding(c)]
    assert not orphans, f"capabilities no role holds: {orphans}"


def test_every_capability_is_actually_guarded_by_a_route_or_documented():
    """A capability nothing checks is dead policy, and dead policy misleads an
    access review into thinking a control exists."""
    from sentinel.domain.authorization import CLI_ONLY_CAPABILITIES, Capability

    interface_dir = PACKAGE / "interface"
    http_sources = "\n".join(
        p.read_text(encoding="utf-8") for p in interface_dir.glob("*.py")
    )
    cli_source = (interface_dir / "cli.py").read_text(encoding="utf-8")
    unused = []
    for c in Capability:
        token = f"Capability.{c.name}"
        if c in CLI_ONLY_CAPABILITIES:
            assert token in cli_source, (
                f"{c.name} is CLI_ONLY but not referenced in cli.py"
            )
            continue
        if token not in http_sources:
            unused.append(c.name)
    assert not unused, (
        f"these capabilities are defined but guard nothing: {unused}. Either wire "
        "them to a route or remove them; an unenforced grant misleads an access "
        "review into believing a control exists."
    )


# ── Secrets and configuration ────────────────────────────────────────────────


def test_only_the_composition_root_reads_the_environment():
    """Ambient configuration is how two parsers of one string came to disagree
    about duplicate keys, letting a credential authenticate as one tenant and
    inherit another's role.

    This rule caught `EnvironmentKeyProvider` defaulting its `environ` argument to
    `os.environ` -- dependency injection with an ambient escape hatch, which is not
    dependency injection. The default is gone and the composition root passes the
    mapping in.
    """
    allowed = {
        "sentinel/composition/settings.py",
        "sentinel/composition/container.py",
        # The MCP stdio bridge runs in the AGENT'S process -- Claude Desktop or
        # Cursor spawn it from their own config and hand it the API key as an
        # environment variable, because that is the only channel those clients
        # offer. It never imports the service's Settings and never runs inside
        # the service, so the composition root is not available to it. `main`
        # takes `environ` as a parameter so the read is still testable.
        "sentinel/sdk/mcp_stdio.py",
    }
    offenders: list[str] = []
    for path in _modules():
        if _rel(path) in allowed:
            continue
        for node in ast.walk(_parse(path)):
            if isinstance(node, ast.Attribute) and node.attr in ("getenv", "environ"):
                offenders.append(f"{_rel(path)}:{node.lineno} reads os.{node.attr}")
    assert not offenders, "\n".join(offenders)


def test_no_logger_call_passes_a_credential_or_a_whole_settings_object():
    """The log pipeline is a different trust boundary with different retention.

    Scoped to LOGGER calls specifically. A substring rule flagged
    `Container(settings=settings, ...)` -- a dataclass constructor, not a log call --
    which is the kind of false positive that gets a rule deleted rather than fixed.
    """
    suspicious_kwargs = {"settings", "token", "api_key", "secret", "password", "key"}
    offenders: list[str] = []
    for path in _modules():
        for node in ast.walk(_parse(path)):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            receiver = node.func.value
            receiver_name = (
                receiver.attr
                if isinstance(receiver, ast.Attribute)
                else getattr(receiver, "id", "")
            )
            if receiver_name not in ("logger", "log", "_logger", "_log"):
                continue
            for keyword in node.keywords:
                if keyword.arg in suspicious_kwargs:
                    offenders.append(
                        f"{_rel(path)}:{node.lineno} logs {keyword.arg}="
                        f"{ast.unparse(keyword.value)}"
                    )
    assert not offenders, (
        "these logger calls would put a credential or the whole settings object "
        "into a log record: " + "; ".join(offenders)
    )


# ── SQL ──────────────────────────────────────────────────────────────────────


def test_sql_strings_interpolate_only_placeholders_and_safe_constants():
    """Parameterisation is the control; this asserts nothing routes around it.

    An f-string in SQL is permitted ONLY for the driver's placeholder token, an
    enum's `.value`, or an integer setting -- never for a value that could carry a
    request. Anything else is flagged for a human to look at.

    RELATIONSHIP TO `tests_arch/test_sql_is_never_built_from_data.py`
    -----------------------------------------------------------------
    These two overlap and neither subsumes the other, so both are kept.

    THIS test sweeps broadly -- it will flag an f-string anywhere in the package
    -- but its allowlist is a list of NAMES (`{where}`, `{columns}`,
    `{assignments}`), and a name proves nothing about what is bound to it.

    THAT test is narrower in reach but stronger in what it establishes: it
    resolves every interpolated identifier back to a module-level constant or an
    inline tuple of string literals, so `{table}` has to actually iterate
    `PROTECTED_TABLES` rather than merely be spelled "table". It also guards the
    `bandit.yaml` skip list, which exists because B608 fired 99 times on this
    file's subject matter without once finding caller data.

    Read together: this one asks "is anything new being interpolated?", the
    other asks "and can it carry data?".
    """
    allowed_fragments = (
        "{self.p}",
        "{conn.p}",
        "{p}",
        "{p},",
        # `", ".join(p for _ in TERMINAL_STATES)` -- a run of placeholder tokens
        # for an `IN (...)`, sized by the LENGTH of a module constant. The state
        # values themselves are bound, never interpolated; if that ever changes
        # it is a SQL injection shape even though the values are constants
        # today. `test_the_in_clause_joins_placeholders_not_values` holds it.
        "{states}",
        "{isolation.value}",
        "{config.lock_timeout_ms}",
        "{config.statement_timeout_ms}",
        "{config.idle_in_transaction_timeout_ms}",
        "{sql}",
        "{_LOCK_KEY}",
        "{table}",
        "{column}",
        "{name}",
        "{limit}",
        "{clause}",
        "{order}",
        "{placeholders}",
        "{columns}",
        # The receipt store's column lists, joined once at module level rather
        # than at five call sites -- five spellings of the same list is five
        # places for it to disagree with the schema.
        #
        # Allowed here because the STRONGER guard already covers them:
        # `test_sql_is_never_built_from_data.py` resolves both names back to
        # the module-level `_COLUMNS` tuple, and
        # `test_the_receipt_store_columns_are_bare_identifiers` asserts every
        # entry is a bare lowercase identifier. This sweeper's allowlist is a
        # list of NAMES and a name proves nothing on its own, which is exactly
        # why that test exists and why this entry is not a weakening.
        "{_COLUMN_LIST}",
        "{_INSERT_COLUMN_LIST}",
        "{assignments}",
        "{returning}",
        "{lock}",
        "{suffix}",
        "{where}",
    )
    # Multi-word SQL shapes, not bare keywords. A single-keyword match flagged the
    # error message "values of type {type(node).__name__} are not permitted",
    # because "VALUES " appears in it -- a rule that cries wolf on English prose is
    # a rule that gets deleted.
    sql_shapes = (
        "SELECT ",
        "INSERT INTO",
        "UPDATE ",
        "DELETE FROM",
        "CREATE TABLE",
        "ALTER TABLE",
        "DROP TABLE",
    )
    #: A literal must ALSO contain one of these to count as SQL, which rules out
    #: prose that happens to contain a keyword.
    corroborating = (" FROM ", " WHERE ", " SET ", " VALUES ", " INTO ", "(")
    suspicious: list[str] = []
    for path in _modules():
        for node in ast.walk(_parse(path)):
            if not isinstance(node, ast.JoinedStr):
                continue
            literal = "".join(
                part.value for part in node.values if isinstance(part, ast.Constant)
            )
            upper = literal.upper()
            if not any(shape in upper for shape in sql_shapes):
                continue
            if not any(mark in upper for mark in corroborating):
                continue
            rendered = ast.unparse(node)
            interpolations = [
                f"{{{ast.unparse(part.value)}}}"
                for part in node.values
                if isinstance(part, ast.FormattedValue)
            ]
            for slot in interpolations:
                if slot not in allowed_fragments:
                    suspicious.append(
                        f"{_rel(path)}:{node.lineno} interpolates {slot} into SQL: "
                        f"{rendered[:120]}"
                    )
    assert not suspicious, (
        "SQL built by interpolating something other than a placeholder or a "
        "trusted constant:\n" + "\n".join(suspicious)
    )


# ── Response headers ─────────────────────────────────────────────────────────


def test_the_security_header_set_cannot_be_quietly_shrunk():
    """Each of these was absent before this pass and each was a real gap.

    Pinning the list means removing one is a test failure with a name attached,
    rather than a diff nobody questions.
    """
    from sentinel.interface.http import _SECURITY_HEADERS

    required = {
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "X-Frame-Options",
        "Permissions-Policy",
        "Cache-Control",
        "Cross-Origin-Resource-Policy",
        "Cross-Origin-Opener-Policy",
    }
    missing = required - set(_SECURITY_HEADERS)
    assert not missing, f"security headers removed: {sorted(missing)}"


def test_the_csp_has_no_escape_hatches():
    from sentinel.interface.http import _SECURITY_HEADERS

    csp = _SECURITY_HEADERS["Content-Security-Policy"]
    for hatch in ("unsafe-inline", "unsafe-eval", "*", "data:", "http:"):
        assert hatch not in csp, f"the CSP permits {hatch!r}"


# ── Dangerous primitives ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "primitive,why",
    [
        ("eval", "arbitrary code execution from a string"),
        ("exec", "arbitrary code execution from a string"),
        ("compile", "the precursor to exec"),
        ("__import__", "dynamic import by name, driven by data"),
    ],
)
def test_no_module_uses_a_code_execution_primitive(primitive, why):
    offenders: list[str] = []
    for path in _modules():
        for node in ast.walk(_parse(path)):
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == primitive:
                offenders.append(f"{_rel(path)}:{node.lineno}")
    assert not offenders, f"{primitive}() ({why}) at: {', '.join(offenders)}"


def test_no_module_deserialises_with_pickle_or_unsafe_yaml():
    """Both are remote code execution when the input is attacker-influenced, and
    every input here is."""
    offenders: list[str] = []
    for path in _modules():
        tree = _parse(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in ("pickle", "cPickle", "marshal", "shelve"):
                        offenders.append(f"{_rel(path)}:{node.lineno} imports {alias.name}")
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == "load" and getattr(node.func.value, "id", "") == "yaml":
                    offenders.append(f"{_rel(path)}:{node.lineno} yaml.load")
    assert not offenders, "\n".join(offenders)


def test_subprocess_is_never_invoked_through_a_shell():
    """`shell=True` turns any interpolated value into a command."""
    offenders: list[str] = []
    for path in _modules():
        for node in ast.walk(_parse(path)):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                if keyword.arg == "shell" and getattr(keyword.value, "value", False) is True:
                    offenders.append(f"{_rel(path)}:{node.lineno}")
    assert not offenders, f"shell=True at: {', '.join(offenders)}"


def test_tls_verification_is_never_disabled():
    """One `CERT_NONE` turns transport security into obfuscation."""
    offenders: list[str] = []
    for path in _modules():
        source = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(source.splitlines(), start=1):
            if line.strip().startswith("#"):
                continue
            for pattern in (
                "CERT_NONE",
                "check_hostname = False",
                "check_hostname=False",
                "_create_unverified_context",
                "verify=False",
            ):
                if pattern in line:
                    offenders.append(f"{_rel(path)}:{lineno} -> {pattern}")
    assert not offenders, "\n".join(offenders)
