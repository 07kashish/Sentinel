"""Serve the transparency log: its root, and proofs about what it contains.

WHAT THESE ROUTES MAKE POSSIBLE
-------------------------------
An auditor holding a root from last month can now ask this deployment for a
consistency proof and find out whether the log they were shown then is a prefix
of the log today. That is the question the whole structure exists for, and
until the log had storage it could not be asked.

THE LIMIT IS SERVED ALONGSIDE THE PROOF, NOT IN A README
---------------------------------------------------------
Every response carries `independently_verifiable`. It is false unless a root
was published to a sink outside the operator's control, because **a
transparency log whose roots are only ever served by the same party that writes
the log proves nothing about that party.**

That sentence is in the domain module, asserted by a test there, and repeated
in the payload here -- because the payload is what a consumer receives, and an
auditor who reads only the JSON must still learn that a proof from an
unpublished log is the operator vouching for themselves.

A proof is still WORTH SERVING in that state: it detects a mistake, a partial
restore, or a second replica diverging. It just does not detect a determined
operator, and the response says which.

NO ROUTE APPENDS
----------------
Appending is a consequence of recording an execution, not something a caller
asks for. A POST here would let anyone with the credential write history, and
the credential that ingests events is the one an agent holds.
"""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query

from sentinel.domain.authorization import Capability
from sentinel.domain.transparency import (
    empty_root,
    verify_consistency,
    verify_inclusion,
)

__all__ = ["register_transparency_routes"]

#: Repeated in every response. The domain module states it and a test there
#: asserts the docstring keeps it; this is the same claim on the wire, where a
#: consumer reading only JSON will see it.
_SELF_SERVED_WARNING = (
    "A transparency log whose roots are only ever served by the same party "
    "that writes the log proves nothing about that party. When "
    "independently_verifiable is false, this proof detects a mistake, a "
    "partial restore or a diverging replica -- it does NOT detect a "
    "determined operator, because the operator served both the log and the "
    "root you are checking it against."
)


def _verifiability(store: Any, tenant: str, tree_size: int) -> dict[str, Any]:
    """Whether a root at this size was published somewhere the operator cannot
    rewrite -- and, if not, exactly what is missing.

    Read from the recorded publications rather than from configuration: a
    configured sink that has never successfully published is not a published
    root, and reporting the configuration would be reporting an intention.
    """
    published = {
        root.tree_size: root for root in store.published_roots(tenant)
    }
    root = published.get(int(tree_size))

    if root is None:
        return {
            "independently_verifiable": False,
            "reason": (
                f"no root has been published for tree size {tree_size}. This "
                "response is the operator describing their own log."
            ),
            "warning": _SELF_SERVED_WARNING,
        }
    if not root.is_independently_verifiable:
        return {
            "independently_verifiable": False,
            "reason": (
                f"the root for size {tree_size} was recorded with sink "
                f"{root.sink!r} and reference {root.external_reference!r}, "
                "which is not something a third party can check."
            ),
            "warning": _SELF_SERVED_WARNING,
            "published_root": root.as_dict(),
        }
    return {
        "independently_verifiable": True,
        "reason": (
            f"the root for size {tree_size} was published to {root.sink} as "
            f"{root.external_reference}, which a third party can fetch "
            "without asking this deployment."
        ),
        "published_root": root.as_dict(),
    }


def register_transparency_routes(
    app: FastAPI, container: Any, *, require: Any
) -> None:
    """Attach the read-only transparency surface."""

    store = getattr(container, "transparency", None)

    @app.get("/v1/transparency/root")
    def current_root(principal=Depends(require(Capability.READ_INCIDENT))):
        """The current root and size, with whether it can be checked.

        An empty log returns the DEFINED empty root rather than null, so an
        operator cannot claim a fresh start to explain a deletion: the root
        they published earlier was not this one.
        """
        if store is None:
            raise HTTPException(
                status_code=503,
                detail=(
                    "no transparency store is configured, so there is no log "
                    "to serve. Returning 503 rather than an empty root: an "
                    "empty root is a statement about a log, and there is none."
                ),
            )

        tenant = str(principal.tenant)
        log = store.load(tenant)
        root = log.root() if log.size else empty_root()

        return {
            "tree_size": log.size,
            "root": root.hex(),
            **_verifiability(store, tenant, log.size),
        }

    @app.get("/v1/transparency/inclusion/{index}")
    def inclusion(
        index: int,
        principal=Depends(require(Capability.READ_INCIDENT)),
    ):
        """A proof that the entry at `index` is in the log.

        Catches a passport being quietly dropped: the proof stops verifying
        against the root the operator publishes afterwards.
        """
        if store is None:
            raise HTTPException(status_code=503, detail="no transparency store")

        tenant = str(principal.tenant)
        log = store.load(tenant)
        if not 0 <= index < log.size:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"index {index} is outside a log of {log.size} entries. "
                    "A 404 rather than an empty proof: an empty proof is a "
                    "document that verifies against nothing and reads like an "
                    "answer."
                ),
            )

        proof = log.inclusion_proof(index)
        root = log.root()
        # Verified HERE before serving. A proof this deployment cannot itself
        # check is a bug in this deployment, and shipping it would move the
        # discovery to whoever tried to use it.
        failure = verify_inclusion(
            digest=log.entries[index], proof=proof, root=root
        )
        if failure is not None:
            raise HTTPException(
                status_code=500,
                detail=(
                    f"this deployment produced an inclusion proof it cannot "
                    f"verify ({failure.value}). Refusing to serve it: a proof "
                    "the issuer cannot check is not a proof."
                ),
            )

        return {
            "digest": log.entries[index].hex(),
            "root": root.hex(),
            "proof": proof.as_dict(),
            **_verifiability(store, tenant, log.size),
        }

    @app.get("/v1/transparency/consistency")
    def consistency(
        old_size: int = Query(..., ge=1),
        principal=Depends(require(Capability.READ_INCIDENT)),
    ):
        """A proof that the log at `old_size` is a prefix of the log now.

        THE route that catches a rewrite. An auditor holding a root from last
        month checks it here; an operator who removed an entry and re-signed
        everything cannot produce a proof that satisfies this, because the
        mathematics does not admit one.

        The earlier tree is rebuilt from the same leaves rather than from a
        stored root -- a stored root is the operator's assertion, and the
        leaves are the evidence.
        """
        if store is None:
            raise HTTPException(status_code=503, detail="no transparency store")

        tenant = str(principal.tenant)
        current = store.load(tenant)
        if old_size > current.size:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"this log has {current.size} entries and cannot prove "
                    f"consistency with a claimed earlier size of {old_size}. A "
                    "log never shrinks, so this is either a corrupted record "
                    "of the old size or evidence of a rewrite -- and both "
                    "deserve to be seen rather than smoothed over."
                ),
            )

        earlier = store.load(tenant, up_to=old_size)
        proof = current.consistency_proof(old_size)
        failure = verify_consistency(
            old_root=earlier.root(),
            old_size=old_size,
            new_root=current.root(),
            new_size=current.size,
            proof=proof,
        )
        if failure is not None:
            # The deployment's own log does not verify against itself. Served
            # as a FINDING rather than a 500: this is the single most important
            # thing an auditor could learn, and hiding it behind an error page
            # would be the worst possible response.
            return {
                "consistent": False,
                "failure": failure.value,
                "old_size": old_size,
                "new_size": current.size,
                "detail": (
                    "THIS LOG DOES NOT VERIFY AGAINST ITSELF. Either the "
                    "stored leaves were altered, or two writers produced "
                    "divergent histories. Reported rather than raised, because "
                    "an error page would hide the finding an auditor came for."
                ),
                **_verifiability(store, tenant, current.size),
            }

        return {
            "consistent": True,
            "old_size": old_size,
            "old_root": earlier.root().hex(),
            "new_size": current.size,
            "new_root": current.root().hex(),
            "proof": [node.hex() for node in proof],
            **_verifiability(store, tenant, current.size),
        }

    @app.get("/v1/transparency/published")
    def published(principal=Depends(require(Capability.READ_INCIDENT))):
        """Every root this deployment has published, and where.

        The list an auditor reads FIRST: it says which sizes can be checked
        without trusting this deployment, and therefore how much of the log's
        history is evidence rather than assertion.
        """
        if store is None:
            raise HTTPException(status_code=503, detail="no transparency store")

        tenant = str(principal.tenant)
        roots = store.published_roots(tenant)
        verifiable = [r for r in roots if r.is_independently_verifiable]

        return {
            "published": [r.as_dict() for r in roots],
            "independently_verifiable_count": len(verifiable),
            "total_count": len(roots),
            "warning": _SELF_SERVED_WARNING,
            "limits": (
                "A root absent from this list was never published anywhere, so "
                "a proof against it is this deployment vouching for itself. "
                "The count that matters is independently_verifiable_count, not "
                "total_count."
            ),
        }
