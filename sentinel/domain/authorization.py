"""What a credential is allowed to do. Explicit grants, never an ordering.

THE DEFECT THIS REPLACES, WHICH WAS PROVEN NOT SUSPECTED
--------------------------------------------------------
Authorisation used to be a total order:

    _ROLE_ORDER = {"ingest": 10, "viewer": 20, "analyst": 30, "admin": 40}
    def can(self, required): return _ROLE_ORDER[self.role] >= _ROLE_ORDER[required]

Read that against `require("ingest")` on `POST /v1/events`. A `viewer` scores 20,
`ingest` requires 10, so a credential documented as read-only could post events.
Confirmed against the running app: `viewer POST /v1/events -> 202 Accepted`.

The bug is not the numbers. It is that a single scalar cannot express two
independent axes. "How much may this credential READ" and "may this credential
WRITE telemetry" are unrelated questions, and any total order forces an answer to
the second whenever you answer the first. Adding a fifth role would have produced
the same class of defect again, somewhere new.

So: no ordering. A role maps to an explicit, enumerated set of capabilities, and a
route asks for a capability. Nothing is implied, nothing is inherited by accident,
and a new role grants exactly what its entry lists.

WHY `admin` CANNOT INGEST EVENTS
--------------------------------
This surprises people, so it is stated rather than buried. `admin` is the most
privileged role and it deliberately does NOT hold `INGEST_EVENT`.

An incident record in this system is evidence. It is hash-chained, attested and
produced for someone to rely on later. A human-held administrative credential that
can fabricate telemetry can fabricate evidence, and the moment that is possible the
evidentiary value of every record drops to "someone with an admin key says so".
Ingestion is a machine capability, held by machine credentials, and separating it
from administration is what keeps the chain worth having.

The practical consequence: a deployment cannot use one admin key for everything.
It needs an `ingest` key for agents and an `admin` key for people. That is the
intended outcome, not an inconvenience to route around -- and it is why this module
raises on an unknown role rather than defaulting to a small grant, because a typo
in `SENTINEL_API_KEYS` must not silently produce a credential that can do nothing
and is debugged for an hour, or worse, one that can do something unintended.
"""

from __future__ import annotations

from enum import Enum
from types import MappingProxyType
from typing import Mapping

from sentinel.domain.errors import DomainRuleViolated

__all__ = [
    "Capability",
    "UnknownRole",
    "VALID_ROLES",
    "capabilities_for",
    "grants",
    "roles_holding",
    "CLI_ONLY_CAPABILITIES",
]


class UnknownRole(DomainRuleViolated):
    """A role with no capability grant. Refused, never defaulted."""


class Capability(str, Enum):
    """One thing a credential may do. Named for the action, not the route.

    Capabilities outlive routes. `READ_INCIDENT` stays meaningful when
    `/v1/incidents` becomes `/v2/incidents`, which is the point: the grant table
    is a security decision and must not need re-deriving every time a path
    changes.
    """

    #: Submit telemetry that can become an incident. A WRITE capability, and the
    #: one that must never be bundled with read access.
    INGEST_EVENT = "ingest_event"

    READ_INCIDENT = "read_incident"

    #: Separate from READ_INCIDENT: a report carries the evidence digest, the
    #: advisory model's output and the attestation receipt. Strictly more than the
    #: incident summary, so it is strictly a different grant.
    READ_REPORT = "read_report"

    READ_DASHBOARD = "read_dashboard"

    #: Approve or reject a remediation. The only capability that can cause an
    #: effect on a system outside this one.
    DECIDE_APPROVAL = "decide_approval"

    # NOTE on agent enrolment, which is deliberately NOT a capability here.
    #
    # Enrolling or revoking an agent identity decides which signatures are treated
    # as authoritative -- effectively "what is the trust anchor". There is no HTTP
    # route for it: it is a deployment operation performed with
    # `python -m sentinel.interface.cli`, guarded by shell access to the host
    # rather than by a bearer token.
    #
    # A `MANAGE_AGENTS` capability was defined here and then removed, because
    # nothing enforced it. An unenforced grant is worse than an absent one: an
    # access review reads the table, sees the capability, and concludes a control
    # exists. `test_every_capability_is_actually_guarded_by_a_route` fails the
    # build on exactly that, which is how this was caught.

    #: Provision, suspend and enrol human users, and issue enrolment tickets.
    #:
    #: Effectively "decide who can log in", so it is the most consequential grant
    #: here and it is held by `admin` alone. Note what it does NOT confer: holding
    #: it does not let you approve a remediation or read an incident. An identity
    #: administrator and an incident responder are different jobs, and a directory
    #: integration holding this capability should not also be able to read evidence.
    MANAGE_USERS = "manage_users"

    #: Ask Sentinel whether a proposed tool call may proceed (protect mode).
    #: Held by machine credentials that gate actions *before* they happen --
    #: distinct from INGEST_EVENT, which records what already happened.
    EVALUATE_PROTECT = "evaluate_protect"

    #: Execute a tool through the inline protect proxy (`POST /v1/tools/execute`).
    #: The only sanctioned remote side-effect path in this product.
    EXECUTE_TOOL = "execute_tool"

    #: Read operational internals -- component health, backend detail. Guarded
    #: because "which database, which gateway, which version" is reconnaissance.
    READ_DIAGNOSTICS = "read_diagnostics"

    #: Activate and lift the granular kill switch (section 35).
    #:
    #: Deliberately NOT folded into DECIDE_APPROVAL, though both are held by
    #: responders. Approving starts an action against one named target that a
    #: policy already proposed; containment stops work across a scope the caller
    #: chooses, including every agent classed high-risk. Different blast radius
    #: is different grant -- and an integration that should be able to approve a
    #: proposed remediation should not thereby be able to halt an estate.
    #:
    #: Not admin-only either. §35 wants this reachable fast by whoever is
    #: handling the incident, and a control that requires finding an
    #: administrator at 3am is one that gets worked around.
    MANAGE_CONTAINMENT = "manage_containment"

    #: Author, review, deploy and roll back policy-as-code (section 29).
    #:
    #: Admin-only, unlike MANAGE_CONTAINMENT. Containment is an emergency
    #: control whose worst outcome is over-blocking that somebody notices in
    #: minutes; a policy change is durable and silent, and a permissive one can
    #: sit undetected for months. Different failure shape, different grant.
    MANAGE_POLICY = "manage_policy"


_READS = frozenset(
    {Capability.READ_INCIDENT, Capability.READ_REPORT, Capability.READ_DASHBOARD}
)

#: The grant table. The whole authorisation policy, in one readable place.
#:
#: Immutable at every level: a `MappingProxyType` of `frozenset`s. A role table
#: that can be mutated at runtime is an authorisation bypass waiting for one
#: careless line, and `frozenset` means a caller cannot `.add()` to a grant it was
#: handed.
_GRANTS: Mapping[str, frozenset[Capability]] = MappingProxyType(
    {
        # A machine credential for agents. Writes telemetry and can read NOTHING:
        # an agent that can read its tenant's incidents can discover which of its
        # own actions were detected, which is reconnaissance handed to the thing
        # being watched.
        "ingest": frozenset(
            {
                Capability.INGEST_EVENT,
                Capability.EVALUATE_PROTECT,
                Capability.EXECUTE_TOOL,
            }
        ),
        # Read-only. Genuinely read-only, which is the fix.
        "viewer": _READS,
        # A human responder. Reads everything a viewer can and may decide
        # approvals. Cannot ingest, cannot change trust anchors.
        "analyst": _READS
        | {
            Capability.DECIDE_APPROVAL,
            Capability.MANAGE_CONTAINMENT,
            Capability.EVALUATE_PROTECT,
            Capability.EXECUTE_TOOL,
        },
        # A human administrator. Everything except fabricating telemetry.
        # `READ_DIAGNOSTICS` is admin-only rather than analyst-and-up: the backend
        # description names the database host, and a responder does not need it to
        # respond. MANAGE_USERS covers SCIM/org HTTP provisioning.
        "admin": _READS
        | {
            Capability.DECIDE_APPROVAL,
            Capability.MANAGE_CONTAINMENT,
            Capability.MANAGE_POLICY,
            Capability.READ_DIAGNOSTICS,
            Capability.MANAGE_USERS,
            Capability.EVALUATE_PROTECT,
        },
    }
)

VALID_ROLES = frozenset(_GRANTS)

#: Agent enrolment remains CLI-only (host access). Directory SCIM uses MANAGE_USERS
#: over HTTP and is therefore NOT listed here.
CLI_ONLY_CAPABILITIES: frozenset[Capability] = frozenset()



def capabilities_for(role: str) -> frozenset[Capability]:
    """The capabilities a role holds. Raises on an unknown role.

    Raising rather than returning an empty set is deliberate. An empty grant is
    indistinguishable from a correctly-configured least-privilege credential, so a
    typo would present as a mysterious 403 hours later. A refusal names the
    problem at the point it can be fixed.
    """
    try:
        return _GRANTS[role]
    except KeyError:
        raise UnknownRole(
            f"role {role!r} has no capability grant. Known roles: "
            f"{', '.join(sorted(_GRANTS))}. A role with no explicit grant is "
            "refused rather than given an empty one, because an empty grant looks "
            "identical to a correct least-privilege credential and gets debugged "
            "as a bug instead of fixed as a typo."
        ) from None


def grants() -> Mapping[str, frozenset[Capability]]:
    """The full table, for tests, documentation and the compliance evidence map."""
    return _GRANTS


def roles_holding(capability: Capability) -> frozenset[str]:
    """Which roles hold a capability. The question an auditor actually asks.

    "Who can approve a remediation" is answerable from here in one call, which is
    the difference between an access review that happens and one that is promised.
    """
    return frozenset(
        role for role, held in _GRANTS.items() if capability in held
    )
