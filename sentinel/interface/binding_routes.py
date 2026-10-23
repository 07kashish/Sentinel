"""Serve the approved-versus-executed diff, and what it does not cover.

WHY THIS IS THE VIEW WORTH BUILDING
------------------------------------
Every other surface in this product answers "what did we decide". This one
answers "did what ran match what we approved", which is the question the
platform is named for and the one nothing could answer before the execution
binding existed.

An operator looking at a refused execution needs three things at once: which
parameter differed, that the tool was never invoked, and which authorization it
was refused against. A dashboard that shows only a count of refusals sends them
to the logs to reconstruct all three.

WHAT IS SERVED, AND WHAT IS NOT
--------------------------------
Digests, never parameter VALUES. A parameter carries a filename, a query, a
request body -- and this endpoint is read by a console, cached by a browser and
pasted into tickets. So the response says WHICH KEYS differed and what the two
digests were, and an operator who needs the values goes to the tenant's own
system with the authorization id.

That is a deliberate limitation rather than an oversight: an
approved-versus-executed view that disclosed both sets of parameters would be
the most sensitive endpoint in the product, and it would be the one people
screenshot.

THE BLINDNESS IS SERVED ALONGSIDE THE DIFF
-------------------------------------------
An UNBOUND execution produces no receipt at all, so it does not appear here.
That means a small number of receipts is ambiguous: it may mean little activity
or it may mean little binding adoption, and this surface cannot tell them
apart. Every response says so, and reports whether
`SENTINEL_REQUIRE_EXECUTION_BINDING` is set -- which is the setting that
removes the ambiguity.

That framing is a correction. The first version of the coverage endpoint
reported a bound-versus-unbound ratio over receipts, and a test showed it was
structurally always 1.0: `ExecutionReceipt` requires an authorization digest,
so every stored receipt is bound by construction. A metric that can only
report perfect coverage is worse than no metric.
"""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query

from sentinel.domain.authorization import Capability

__all__ = ["register_binding_routes", "COVERAGE_WARNING"]

#: Served in every response. A console reading only the mismatch count would
#: otherwise present an unbound window as a clean one.
COVERAGE_WARNING = (
    "An UNBOUND execution produces no receipt, so it does not appear here. A "
    "small receipt count may mean little activity or little binding adoption, "
    "and this surface cannot tell them apart. Set "
    "SENTINEL_REQUIRE_EXECUTION_BINDING to remove the ambiguity."
)

#: Repeated on every diff. The console is not the place to learn this for the
#: first time.
DISCLOSURE_NOTE = (
    "Parameter VALUES are never served. Only the keys that differed and the "
    "two digests. An operator who needs the values uses the authorization id "
    "against the tenant's own system."
)


def register_binding_routes(
    app: FastAPI, container: Any, *, require: Any
) -> None:
    """Attach the read-only execution-binding surface."""

    receipts = getattr(container, "receipts", None)

    def _store_or_503():
        if receipts is None:
            raise HTTPException(
                status_code=503,
                detail=(
                    "no execution receipt store is configured, so there are no "
                    "bound executions to compare. Returning 503 rather than an "
                    "empty list: an empty list is a statement about a "
                    "deployment's executions, and this one is not recording "
                    "them."
                ),
            )
        return receipts

    @app.get("/v1/executions/binding/coverage")
    def binding_coverage(
        limit: int = Query(default=500, ge=1, le=5000),
        principal=Depends(require(Capability.READ_INCIDENT)),
    ):
        """How much of this window was bound at all.

        Served as its own route as well as inside the diff, because a
        readiness check should be able to ask "is binding actually on here"
        without pulling a page of receipts.
        """
        store = _store_or_503()
        tenant = str(principal.tenant)
        coverage = store.coverage(tenant, limit=limit)

        return {
            **coverage,
            # THE setting that resolves the ambiguity above. Reported here so a
            # reader can tell "few receipts because binding is optional" from
            # "few receipts because little happened".
            "enforced": bool(
                getattr(getattr(container, "settings", None),
                        "require_execution_binding", False)
            ),
            "warning": COVERAGE_WARNING,
        }

    @app.get("/v1/executions/binding/diff")
    def binding_diff(
        limit: int = Query(default=100, ge=1, le=1000),
        only_mismatched: bool = Query(default=False),
        principal=Depends(require(Capability.READ_INCIDENT)),
    ):
        """Approved versus executed, per receipt.

        `only_mismatched` is FALSE by default on purpose. A view that showed
        only mismatches would make an operator's first impression of a healthy
        estate identical to their first impression of a deployment where
        nothing is bound -- both are empty lists.
        """
        store = _store_or_503()
        tenant = str(principal.tenant)
        rows = list(store.recent(tenant, limit=limit))

        entries = []
        for row in rows:
            approved = row.get("approved_parameter_digest", "")
            actual = row.get("actual_parameter_digest", "")
            bound = bool(row.get("authorization_digest"))
            matched = bound and approved == actual and bool(approved)

            if only_mismatched and matched:
                continue

            entries.append({
                "receipt_id": row.get("receipt_id", ""),
                "authorization_id": row.get("authorization_id", ""),
                "occurred_at": row.get("completed_at", ""),
                "tool": row.get("side_effect", ""),
                "outcome": row.get("outcome", ""),
                "bound": bound,
                # THREE states, not two. `null` means this execution carried no
                # authorization, so there was nothing to compare -- which is
                # different from having compared and agreed.
                "parameters_matched": matched if bound else None,
                "approved_parameter_digest": approved,
                "actual_parameter_digest": actual,
                # Which KEYS differed, never the values.
                "differing_keys": list(row.get("differing_keys", ())),
                "bounded_mutations": list(row.get("bounded_mutations", ())),
                "defects": list(row.get("defects", ())),
            })

        comparable = sum(
            1 for row in rows if row.get("approved_parameter_digest")
        )
        return {
            "tenant": tenant,
            "entries": entries,
            "binding_coverage": {
                "receipts": len(rows),
                "comparable": comparable,
                "not_comparable": len(rows) - comparable,
            },
            "mismatched": sum(
                1 for entry in entries if entry["parameters_matched"] is False
            ),
            "unverifiable": sum(
                1 for entry in entries if entry["parameters_matched"] is None
            ),
            "warning": COVERAGE_WARNING,
            "disclosure": DISCLOSURE_NOTE,
        }

    @app.get("/v1/executions/binding/{receipt_id}")
    def binding_detail(
        receipt_id: str,
        principal=Depends(require(Capability.READ_INCIDENT)),
    ):
        """One execution, with the chain it was authorised through.

        The delegation chain digest is served rather than the chain: an
        operator asking "whose authority was this" needs to know WHICH chain,
        and the hops themselves name principals and grants that belong in the
        estate view rather than in an execution record.
        """
        store = _store_or_503()
        tenant = str(principal.tenant)
        row = store.get(tenant, receipt_id)
        if row is None:
            raise HTTPException(
                status_code=404,
                detail=f"no receipt {receipt_id!r} for this tenant",
            )

        approved = row.get("approved_parameter_digest", "")
        actual = row.get("actual_parameter_digest", "")
        bound = bool(row.get("authorization_digest"))

        return {
            "receipt_id": row.get("receipt_id", ""),
            "authorization_id": row.get("authorization_id", ""),
            "authorization_digest": row.get("authorization_digest", ""),
            "executed_request_digest": row.get("executed_request_digest", ""),
            "delegation_passport_digest": row.get(
                "delegation_passport_digest", ""
            ),
            "delegation_bound": bool(row.get("delegation_passport_digest")),
            "bound": bound,
            "parameters_matched": (
                (approved == actual and bool(approved)) if bound else None
            ),
            "approved_parameter_digest": approved,
            "actual_parameter_digest": actual,
            "differing_keys": list(row.get("differing_keys", ())),
            "bounded_mutations": list(row.get("bounded_mutations", ())),
            "defects": list(row.get("defects", ())),
            "outcome": row.get("outcome", ""),
            "started_at": row.get("started_at", ""),
            "completed_at": row.get("completed_at", ""),
            "execution_identity": row.get("execution_identity", ""),
            "disclosure": DISCLOSURE_NOTE,
            "residual": (
                "The tool, action and resource in this record are what the "
                "caller DECLARED, compared against the authorization. A caller "
                "that lied about them and executed something else is not "
                "caught here -- see docs/ARCHITECTURE.md#execution_trust_architecture."
            ),
        }
