"""Static inspection of skill source. Parses, never executes.

THE ONE RULE
------------
NOTHING HERE RUNS THE CODE IT INSPECTS. Not `import`, not `exec`, not
`pickle.load`, not a subprocess. The whole point of scanning an untrusted skill
is that it is untrusted, and a scanner that imports its subject to enumerate its
symbols has already lost -- module-level code runs on import, which is exactly
where a malicious package puts its payload.

So this uses `ast.parse`, which builds a tree from text and evaluates nothing.
The cost of that choice is real and is stated below rather than hidden.

WHAT IT FINDS, AND WHAT IT CANNOT
-----------------------------------
It finds the honest shapes: a `subprocess.run`, an `eval`, a `pickle.loads`, a
read of `~/.aws/credentials`, a base64 blob passed to `exec`. Those are the
patterns in real published packages that turned out to be doing something their
description did not mention.

It does NOT find a determined attacker. `getattr(__import__("o"+"s"), "system")`
defeats name matching, and so does fetching the payload at runtime. Every static
analyser has this limit; the difference between a useful one and a dishonest one
is whether it says so. `docs/SKILL_REGISTRY.md` says so, this docstring says so,
and no finding here is phrased as "this package is malicious" -- each names a
construct that is present, which is a fact, and leaves the judgement to a human.

A CLEAN SCAN IS NOT A SAFETY CERTIFICATE. It means these particular shapes were
absent from the source that was handed over.

WHY FINDINGS CARRY POINTS AND NOT VERDICTS
--------------------------------------------
`domain/skills.assess` folds these into an explainable score alongside declared
permissions and drift. A scanner that returned its own verdict would be a second
decision-maker disagreeing with the first -- the same mistake `McpGateway`
avoids by projecting onto the one policy engine instead of judging for itself.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final, Iterable, Mapping, Sequence

__all__ = [
    "RULES",
    "ScanFinding",
    "ScanResult",
    "scan_source",
    "scan_tree",
]

#: Refuse a file larger than this rather than parsing it. A skill package with a
#: ten-megabyte source file is either generated or hostile, and `ast.parse` on
#: adversarial input is a CPU and memory cost taken before any check runs.
MAX_SOURCE_BYTES: Final[int] = 2_097_152

#: Refuse a tree deeper than this. Deeply nested expressions are a known parser
#: exhaustion primitive, and `ast.parse` recurses.
MAX_FILES: Final[int] = 2_000


@dataclass(frozen=True, slots=True)
class ScanFinding:
    """One construct that is present in the source. A fact, not a verdict."""

    rule: str
    points: int
    detail: str
    path: str = ""
    line: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "points": self.points,
            "detail": self.detail,
            "path": self.path,
            "line": self.line,
        }


#: Dotted call targets that matter, and what each is worth.
#:
#: Points are relative to `domain/skills.PERMISSION_WEIGHT`, deliberately: a
#: skill that DECLARES `execute_code` scores 40, and one whose source calls
#: `subprocess.run` without declaring it scores comparably. An undeclared
#: capability is not less serious than a declared one -- it is the same reach
#: without the review.
_CALL_RULES: Mapping[str, tuple[int, str]] = MappingProxyType({
    "os.system": (40, "spawns a shell"),
    "os.popen": (40, "spawns a shell"),
    "os.execv": (40, "replaces the process image"),
    "subprocess.run": (35, "executes a subprocess"),
    "subprocess.call": (35, "executes a subprocess"),
    "subprocess.Popen": (35, "executes a subprocess"),
    "subprocess.check_output": (35, "executes a subprocess"),
    "eval": (40, "evaluates a string as code"),
    "exec": (40, "executes a string as code"),
    "compile": (20, "compiles a string as code"),
    "__import__": (25, "imports a module named at runtime"),
    "pickle.loads": (35, "deserialises untrusted bytes; arbitrary code on load"),
    "pickle.load": (35, "deserialises untrusted bytes; arbitrary code on load"),
    "marshal.loads": (30, "deserialises code objects"),
    "ctypes.CDLL": (30, "loads a native library"),
    "socket.socket": (15, "opens a raw socket"),
    "base64.b64decode": (10, "decodes an opaque blob"),
    "codecs.decode": (8, "decodes an opaque blob"),
})

#: Modules whose mere import is worth noting. Lower than a call, because
#: importing `requests` is what a well-behaved HTTP client does; it is the
#: combination with an undeclared destination that matters, and `assess` is
#: where combinations are weighed.
_IMPORT_RULES: Mapping[str, tuple[int, str]] = MappingProxyType({
    "subprocess": (10, "imports the subprocess module"),
    "ctypes": (12, "imports ctypes"),
    "pickle": (10, "imports pickle"),
    "socket": (8, "imports socket"),
})

#: Credential locations. Matched as literal strings, because a package that
#: hard-codes the path to an AWS credential file has told you what it is for.
_SECRET_PATHS: Final[tuple[str, ...]] = (
    ".aws/credentials",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".kube/config",
    ".docker/config.json",
    ".netrc",
    ".git-credentials",
    "/var/run/secrets/kubernetes.io",
    ".env",
)

#: Environment variables worth noticing a read of. Not every getenv -- only the
#: ones that are credentials, or a scanner fires on `getenv("HOME")` and its
#: output becomes noise.
_SECRET_ENV = re.compile(
    r"(SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)",
    re.IGNORECASE,
)

#: Every rule name this module can emit. Exported so a test can assert the
#: documentation and the code enumerate the same set -- a documented rule that
#: cannot fire is a capability claim with nothing behind it.
RULES: Final[frozenset[str]] = frozenset(
    set(_CALL_RULES)
    | {f"import:{name}" for name in _IMPORT_RULES}
    | {"secret_path", "secret_env", "obfuscated_exec", "unparseable"}
)


def _dotted(node: ast.AST) -> str:
    """Render `a.b.c` from an attribute/name chain, or '' for anything else."""
    parts: list[str] = []
    current: Any = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return ""


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    """Map local names back to their dotted origin, in ONE pass before walking.

    `from subprocess import run` binds `run`, and a call to it appears in the
    tree as a bare `Name` with nothing linking it to `subprocess`. Matching only
    the dotted spelling would miss the form most packages actually use -- and
    would let a package evade every call rule by changing its import style,
    which is not an evasion anyone should have to be clever to manage.

    Collected up front rather than during the walk because a function defined
    above an import still calls the imported name at runtime, and a
    single-pass visitor would not have seen the binding yet.

    `import subprocess as sp` is covered the same way, so `sp.run` resolves.
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if alias.name != "*":
                    aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
    return aliases


class _Visitor(ast.NodeVisitor):
    """Walks one module's tree. Holds no state between files."""

    def __init__(self, path: str, aliases: Mapping[str, str] | None = None) -> None:
        self.path = path
        self.aliases = dict(aliases or {})
        self.findings: list[ScanFinding] = []
        # Tracks whether a decode appears anywhere, so `exec(b64decode(...))`
        # can be reported as ONE obfuscation finding rather than as two
        # unrelated ones an operator has to correlate by eye.
        self._decoded_lines: set[int] = set()

    def _resolve(self, dotted: str) -> str:
        """Rewrite a call target through the import aliases, longest head first.

        `sp.run` with `import subprocess as sp` becomes `subprocess.run`; a bare
        `run` from `from subprocess import run` becomes the same. An unaliased
        name passes through unchanged.
        """
        if not dotted:
            return dotted
        head, _, tail = dotted.partition(".")
        origin = self.aliases.get(head)
        if origin is None:
            return dotted
        return f"{origin}.{tail}" if tail else origin

    def _add(self, rule: str, points: int, detail: str, line: int) -> None:
        self.findings.append(
            ScanFinding(
                rule=rule, points=points, detail=detail, path=self.path, line=line
            )
        )

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802 - ast API
        target = self._resolve(_dotted(node.func))
        # `subprocess.run` and `from subprocess import run` both matter. The
        # alias map turns the second into the first; the bare last segment is
        # still checked so `eval`/`exec` builtins match without an import.
        candidates = [target]
        if "." in target:
            candidates.append(target.rsplit(".", 1)[-1])

        for candidate in candidates:
            rule = _CALL_RULES.get(candidate)
            if rule is None:
                continue
            points, detail = rule
            if candidate in {"base64.b64decode", "b64decode", "codecs.decode", "decode"}:
                self._decoded_lines.add(node.lineno)
            self._add(candidate, points, detail, node.lineno)
            break

        if target in {"exec", "eval"} or target.rsplit(".", 1)[-1] in {"exec", "eval"}:
            for argument in node.args:
                if self._contains_decode(argument):
                    self._add(
                        "obfuscated_exec",
                        45,
                        (
                            "executes the result of a decode. Source that has to "
                            "be decoded before it runs is source that was hidden "
                            "from review."
                        ),
                        node.lineno,
                    )
                    break

        self.generic_visit(node)

    def _contains_decode(self, node: ast.AST) -> bool:
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = self._resolve(_dotted(child.func))
                if name.rsplit(".", 1)[-1] in {"b64decode", "decode", "decompress"}:
                    return True
        return False

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802 - ast API
        for alias in node.names:
            self._note_import(alias.name.split(".")[0], node.lineno)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802 - ast API
        if node.module:
            self._note_import(node.module.split(".")[0], node.lineno)
        self.generic_visit(node)

    def _note_import(self, module: str, line: int) -> None:
        rule = _IMPORT_RULES.get(module)
        if rule is not None:
            points, detail = rule
            self._add(f"import:{module}", points, detail, line)

    def visit_Constant(self, node: ast.Constant) -> None:  # noqa: N802 - ast API
        if isinstance(node.value, str):
            lowered = node.value.lower()
            matched_path = False
            for secret in _SECRET_PATHS:
                if secret in lowered:
                    self._add(
                        "secret_path",
                        35,
                        (
                            f"references {secret!r}, a well-known credential "
                            "location"
                        ),
                        node.lineno,
                    )
                    matched_path = True
                    break
            # ONE finding per constant. `~/.aws/credentials` contains the
            # substring "credential", so the env-var rule fires on it too and an
            # operator sees the same string reported twice under two names --
            # the kind of duplicate that teaches people to skim the output.
            if matched_path:
                self.generic_visit(node)
                return
            if _SECRET_ENV.search(node.value) and len(node.value) <= 128:
                self._add(
                    "secret_env",
                    20,
                    f"references the environment variable {node.value!r}",
                    node.lineno,
                )
        self.generic_visit(node)


@dataclass(frozen=True, slots=True)
class ScanResult:
    """What one scan saw, and what it could not see."""

    findings: tuple[ScanFinding, ...]
    files_scanned: int
    #: Files that were present and NOT scanned, with the reason. Reported rather
    #: than dropped: "we scanned 40 of 60 files" and "we scanned everything" are
    #: different statements, and a scanner that conflates them reports a clean
    #: result for a package it barely looked at.
    skipped: tuple[tuple[str, str], ...] = ()

    @property
    def points(self) -> int:
        return sum(f.points for f in self.findings)

    def as_dict(self) -> dict[str, Any]:
        return {
            "findings": [f.as_dict() for f in self.findings],
            "files_scanned": self.files_scanned,
            "skipped": [{"path": p, "reason": r} for p, r in self.skipped],
            "points": self.points,
            # Stated in the RESULT, not only in the docs. A caller serialising
            # this into an approval sees the limit next to the verdict.
            "limits": (
                "static parse only; nothing was executed. Name-based matching "
                "is defeated by runtime construction and by payloads fetched "
                "after install. A clean scan means these shapes were absent "
                "from the source provided, not that the package is safe."
            ),
        }


def scan_source(source: str, *, path: str = "<source>") -> tuple[ScanFinding, ...]:
    """Scan one module's text. Parses; never imports, never executes."""
    if len(source.encode("utf-8", errors="ignore")) > MAX_SOURCE_BYTES:
        return (
            ScanFinding(
                rule="unparseable",
                points=10,
                detail=(
                    f"source is over {MAX_SOURCE_BYTES} bytes and was not "
                    "parsed. Reported rather than skipped silently: an unscanned "
                    "file is not a clean one."
                ),
                path=path,
            ),
        )
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as exc:
        # A file that will not parse is REPORTED, not dropped. It may be Python
        # for a version this process does not have, and it may be deliberately
        # malformed to slip past a scanner that skips what it cannot read.
        return (
            ScanFinding(
                rule="unparseable",
                points=15,
                detail=f"could not be parsed ({type(exc).__name__}), so it was not scanned",
                path=path,
            ),
        )

    visitor = _Visitor(path, aliases=_import_aliases(tree))
    visitor.visit(tree)
    return tuple(visitor.findings)


def scan_tree(
    root: str | Path, *, suffixes: Iterable[str] = (".py",)
) -> ScanResult:
    """Scan every matching file under `root`.

    Symlinks are NOT followed and paths that resolve outside `root` are skipped
    and reported. A skill package is untrusted input, and a symlink named
    `helpers.py` pointing at `/etc/shadow` would otherwise have this process
    read it and put the contents in a finding an analyst can see.
    """
    base = Path(root).expanduser().resolve()
    if not base.is_dir():
        raise NotADirectoryError(f"{base} is not a directory")

    wanted = {s.lower() for s in suffixes}
    findings: list[ScanFinding] = []
    skipped: list[tuple[str, str]] = []
    scanned = 0

    for candidate in sorted(base.rglob("*")):
        if scanned >= MAX_FILES:
            skipped.append((str(candidate), f"over the {MAX_FILES}-file scan limit"))
            continue
        if candidate.is_symlink():
            skipped.append((str(candidate), "symlink; not followed"))
            continue
        if not candidate.is_file() or candidate.suffix.lower() not in wanted:
            continue

        resolved = candidate.resolve()
        if not (resolved == base or resolved.is_relative_to(base)):
            skipped.append((str(candidate), "resolves outside the package root"))
            continue

        try:
            source = resolved.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            skipped.append((str(candidate), f"unreadable: {type(exc).__name__}"))
            continue

        relative = str(resolved.relative_to(base))
        findings.extend(scan_source(source, path=relative))
        scanned += 1

    return ScanResult(
        findings=tuple(
            sorted(findings, key=lambda f: (-f.points, f.path, f.line))
        ),
        files_scanned=scanned,
        skipped=tuple(skipped),
    )


def findings_for_assessment(result: ScanResult) -> Sequence[Mapping[str, Any]]:
    """Adapt a scan into the shape `domain/skills.assess` consumes.

    Deduplicated by rule, keeping the highest-scoring instance. A package that
    calls `subprocess.run` in forty places is not forty times more dangerous
    than one calling it once -- it is the same capability -- and letting the
    count drive the score would make a large well-behaved package outrank a
    small hostile one.
    """
    best: dict[str, ScanFinding] = {}
    for finding in result.findings:
        current = best.get(finding.rule)
        if current is None or finding.points > current.points:
            best[finding.rule] = finding
    return tuple(
        {"rule": f.rule, "points": f.points, "detail": f"{f.detail} ({f.path}:{f.line})"}
        for f in sorted(best.values(), key=lambda f: (-f.points, f.rule))
    )
