"""The domain. Pure, framework-free, dependency-free.

Nothing in this package imports anything outside `sentinel.domain` and the
standard library. That is enforced by `tests_arch/test_architecture_rules.py`,
not by convention: an import added here from `sentinel.infrastructure` or from
`fastapi` fails the build.

The rule exists because in the predecessor architecture the "domain" layer
imported `api.schemas` (the web framework's request models) and
`app.storage.db`, which meant a change to an HTTP contract could alter a business
rule, and no business rule could be tested without a database.
"""

from sentinel.domain.errors import (
    ArtifactMissing,
    ConcurrencyConflict,
    DomainRuleViolated,
    ExecutionFenceLost,
    IllegalTransition,
    MissingRequiredFact,
    SentinelError,
    TransientFailure,
)
from sentinel.domain.attestation import AttestationDisposition, AttestationOutcome
from sentinel.domain.incident import (
    Fence,
    Incident,
    IncidentState,
)
from sentinel.domain.primitives import (
    Address,
    AgentId,
    ApprovalId,
    BatchId,
    Digest,
    IdempotencyKey,
    IncidentId,
    InvalidValue,
    MessageId,
    Priority,
    Severity,
    TenantId,
    Timestamp,
    TrustLevel,
)

__all__ = [
    "Address",
    "AgentId",
    "ApprovalId",
    "ArtifactMissing",
    "AttestationDisposition",
    "AttestationOutcome",
    "BatchId",
    "ConcurrencyConflict",
    "Digest",
    "DomainRuleViolated",
    "ExecutionFenceLost",
    "Fence",
    "IdempotencyKey",
    "IllegalTransition",
    "Incident",
    "IncidentId",
    "IncidentState",
    "InvalidValue",
    "MessageId",
    "MissingRequiredFact",
    "Priority",
    "SentinelError",
    "Severity",
    "TenantId",
    "Timestamp",
    "TransientFailure",
    "TrustLevel",
]
