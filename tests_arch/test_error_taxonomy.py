"""F-9: retryability is declared on SentinelError, never inferred from builtins."""

from __future__ import annotations

import ast
from pathlib import Path

from sentinel.domain.errors import (
    ArtifactMissing,
    ConcurrencyConflict,
    DomainRuleViolated,
    ExecutionFenceLost,
    IllegalTransition,
    MissingRequiredFact,
    TransientFailure,
)


def test_no_module_classifies_retryability_by_builtin_exception_tuple():
    """The predecessor TERMINAL_ERRORS = (..., ValueError, TypeError, KeyError)."""
    root = Path(__file__).resolve().parents[1] / "sentinel"
    offenders: list[str] = []
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                name = getattr(target, "id", None)
                if name not in {"TERMINAL_ERRORS", "RETRYABLE_ERRORS", "TRANSIENT_ERRORS"}:
                    continue
                offenders.append(f"{path.relative_to(root.parent)}:{node.lineno} defines {name}")
    assert not offenders, (
        "retryability must live on SentinelError.is_retryable, not type tuples: "
        + "; ".join(offenders)
    )


def test_domain_errors_declare_retryability_explicitly():
    assert DomainRuleViolated.is_retryable is False
    assert IllegalTransition.is_retryable is False
    assert MissingRequiredFact.is_retryable is False
    assert ArtifactMissing.is_retryable is False
    assert ConcurrencyConflict.is_retryable is True
    assert TransientFailure.is_retryable is True
    assert ExecutionFenceLost.is_retryable is False
    assert ExecutionFenceLost.is_abandon is True


def test_bus_reads_is_retryable_not_isinstance_builtins():
    source = (
        Path(__file__).resolve().parents[1]
        / "sentinel"
        / "application"
        / "bus.py"
    ).read_text(encoding="utf-8")
    assert "is_retryable" in source
    assert "TERMINAL_ERRORS" not in source
    assert "isinstance(exc, (ValueError" not in source
