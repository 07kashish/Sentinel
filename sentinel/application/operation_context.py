"""The operation an effect is running under, visible to the effect.

An adapter that can see the operation id can stamp it on the target -- a
Kubernetes field manager, an idempotency key, a request tag -- which is what
lets a reconciler later ask the TARGET whether this exact operation landed,
instead of asking a human. A context variable rather than a parameter because
the parameters are the approved, digested payload and must stay exactly that.
"""

from __future__ import annotations

import contextvars
import hashlib
from contextlib import contextmanager
from typing import Iterator

__all__ = ["current_operation_id", "operation_scope", "operation_stamp"]

_operation: contextvars.ContextVar[str] = contextvars.ContextVar("sentinel_operation_id", default="")


def current_operation_id() -> str:
    """The running operation's id, or empty outside a bound execution."""
    return _operation.get()


@contextmanager
def operation_scope(operation_id: str) -> Iterator[None]:
    token = _operation.set(operation_id)
    try:
        yield
    finally:
        _operation.reset(token)


def operation_stamp(operation_id: str) -> str:
    """The name an operation leaves on a target: printable, 52 characters.

    Short and plain enough for every place it has to fit -- a Kubernetes field
    manager, an AWS role session name, a request tag -- and derived, so the
    operation id itself (which embeds an authorization id) is not disclosed to
    the target.
    """
    return "sentinel-op-" + hashlib.sha256(operation_id.encode("utf-8")).hexdigest()[:40]
