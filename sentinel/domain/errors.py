"""The domain's failure taxonomy.

WHY THIS EXISTS
---------------
The predecessor classified retryability by Python exception type:

    TERMINAL_ERRORS = (IllegalTransition, MissingRequiredFact, ArtifactMissing,
                       ValueError, TypeError, KeyError)

`ValueError`, `TypeError` and `KeyError` are the three most common *incidental*
exception types in Python. `json.loads()` on a truncated HTTP body raises
ValueError. A missing field in a degraded provider response raises KeyError. Each
was therefore recorded as a permanent failure with no retry -- the exact collapse
the taxonomy existed to prevent.

The cause is that determinism is a property of ORIGIN, not of type. A failure
raised by the lifecycle rules is deterministic because the rules are a pure
function of durable state; a failure raised at an I/O boundary is not, whatever
type it happens to carry.

So retryability is declared here, by the code that knows why it failed, and the
application layer reads the declaration instead of guessing from a type tuple.
Anything that is not a `SentinelError` is treated as retryable infrastructure
failure, which is the safe default: retrying a deterministic failure wastes a
budget, whereas terminalising a transient one destroys an incident.
"""

from __future__ import annotations

__all__ = [
    "ArtifactMissing",
    "ConcurrencyConflict",
    "DomainRuleViolated",
    "ExecutionFenceLost",
    "IllegalTransition",
    "MissingRequiredFact",
    "SentinelError",
    "TransientFailure",
    "failure_is_retryable",
]


class SentinelError(Exception):
    """Base for every failure this system raises deliberately.

    `is_retryable` is the contract. It is abstract in spirit -- every subclass
    states it -- so a new error type cannot inherit a retry decision by accident.
    """

    #: Whether repeating the operation could plausibly produce a different result.
    is_retryable: bool = False

    #: Whether the caller should abandon entirely rather than retry OR terminalise.
    is_abandon: bool = False


class DomainRuleViolated(SentinelError):
    """A domain invariant was violated. Deterministic: the rules are pure."""

    is_retryable = False


class IllegalTransition(DomainRuleViolated):
    """An edge absent from the lifecycle graph was attempted."""


class MissingRequiredFact(DomainRuleViolated):
    """A state was entered without the evidence that state asserts exists."""


class ArtifactMissing(DomainRuleViolated):
    """A state asserts a durable artifact exists and the row is not there."""


class ConcurrencyConflict(SentinelError):
    """Another writer moved this aggregate first.

    Retryable: the caller should re-read and reapply. Distinct from
    ExecutionFenceLost, and the distinction decides behaviour -- a conflict means
    "you raced and lost, try again"; a lost fence means "you are not entitled to
    write at all".
    """

    is_retryable = True


class ExecutionFenceLost(SentinelError):
    """This worker's lease was reclaimed; it may not write.

    Neither retryable nor terminal. The reclaiming worker is already redoing this
    work, so retrying would duplicate it and terminalising would record a failure
    for an incident that is progressing normally.
    """

    is_retryable = False
    is_abandon = True


class TransientFailure(SentinelError):
    """An I/O boundary failed. Raised BY the boundary, never inferred from a type.

    Adapters wrap their driver exceptions in this so the application layer never
    has to know what a `psycopg.OperationalError` or an `httpx.ConnectError` is.
    That is what keeps the retry decision in the layer that owns the fact.
    """

    is_retryable = True


def failure_is_retryable(exc: BaseException) -> bool:
    """Whether repeating the operation could plausibly produce a different result.

    SentinelError declares the answer. Everything else defaults to retryable:
    incidental builtins (ValueError/TypeError/KeyError) must NEVER be treated as
    permanent failure here -- that was the TERMINAL_ERRORS defect.
    """
    if isinstance(exc, SentinelError):
        return exc.is_retryable
    return True

