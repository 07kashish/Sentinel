"""Is this deployment actually being used? Computed locally, never phoned home.

WHY A SECURITY PRODUCT NEEDS THIS
----------------------------------
A control nobody routes through is not a control. The most common failure of a
tool like this is not a bug -- it is a deployment that ingests from two agents
out of forty, produces no incidents because it sees nothing, and reports a
quiet dashboard that everybody reads as good news. Twelve months later an
incident happens on one of the thirty-eight.

So this module answers one question from observable facts: how far along the
funnel is this tenant, and what specifically is missing to go further.

NO EGRESS. NOTHING IS SENT ANYWHERE.
-------------------------------------
This is a pure function over counts the deployment already has. It opens no
socket and has no client. A "business instrumentation" module that shipped
usage data off a customer's estate would be an exfiltration channel wearing a
product-analytics label, and in a security product it would be the most
sensitive telemetry in the building -- which agents exist, how many, how often
they act.

An operator reads this about their own deployment. A vendor reads it when a
customer chooses to share it. Those are different acts and only the customer
can perform the second.

THE DISTINCTION THIS MODULE EXISTS TO PRESERVE
-----------------------------------------------
"Zero events" and "not deployed" are the same number and opposite facts.

A tenant with no events might have nothing connected, or might have everything
connected and genuinely idle. `ActivationStage.UNKNOWN` exists for the first,
and `evidence` names which observable fact put the tenant in whichever stage it
is in -- so nobody has to guess from a count.

The same discipline as the AI-BOM's `UNUSABLE`: a zero denominator is not a
measurement, and a funnel chart built from one is a decision aid pointing the
wrong way.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

__all__ = [
    "MIN_WINDOW_DAYS_FOR_ENGAGEMENT",
    "ActivationStage",
    "AdoptionSnapshot",
    "TenantCounts",
    "assess_adoption",
]

#: Below this, "weekly active agents" is a number computed from a few days.
#: Chosen to match the least-privilege recommender's minimum for the same
#: reason: an inference from a short window is a guess with a unit attached.
MIN_WINDOW_DAYS_FOR_ENGAGEMENT = 30


class ActivationStage(str, Enum):
    """How far this tenant has got, in the order the stages actually happen.

    `UNKNOWN` is first and is not a zero. A tenant nothing has been observed
    for might have nothing connected or might have everything connected and be
    idle, and those need opposite responses -- so the funnel refuses to place
    them until something is observed.
    """

    #: Nothing observed at all. NOT the same as "not using it".
    UNKNOWN = "unknown"
    #: A credential exists and no event has arrived under it.
    CONNECTED = "connected"
    #: Events are arriving.
    INGESTING = "ingesting"
    #: The policy has fired at least once, so detection is exercised rather
    #: than merely configured.
    DETECTING = "detecting"
    #: A human has looked at an incident. The first stage that requires a
    #: PERSON, and the one most deployments never reach.
    INVESTIGATING = "investigating"
    #: An action was refused or contained. The product is in the path.
    ENFORCING = "enforcing"


#: Stage order, for "how far along" comparisons. A separate mapping rather than
#: relying on declaration order, so a future member inserted in the middle
#: cannot silently reorder the funnel.
_ORDER: Mapping[ActivationStage, int] = MappingProxyType(
    {
        ActivationStage.UNKNOWN: -1,
        ActivationStage.CONNECTED: 0,
        ActivationStage.INGESTING: 1,
        ActivationStage.DETECTING: 2,
        ActivationStage.INVESTIGATING: 3,
        ActivationStage.ENFORCING: 4,
    }
)


@dataclass(frozen=True, slots=True)
class TenantCounts:
    """The observable facts this assessment is computed from.

    Every field is a count the deployment already stores. Nothing is estimated,
    and `observation_window_days` is required so no rate can be quoted without
    a denominator.
    """

    credentials_configured: int = 0
    agents_observed: int = 0
    events_ingested: int = 0
    incidents_raised: int = 0
    #: Incidents whose state moved past `received` -- somebody looked.
    incidents_triaged: int = 0
    #: Actions refused by policy, plus containments activated.
    actions_refused: int = 0
    containments_activated: int = 0
    #: How many days of history these counts cover. REQUIRED: a count with no
    #: window is not a rate and must not be presented as one.
    observation_window_days: int = 0

    def __post_init__(self) -> None:
        negative = [
            name
            for name in (
                "credentials_configured",
                "agents_observed",
                "events_ingested",
                "incidents_raised",
                "incidents_triaged",
                "actions_refused",
                "containments_activated",
                "observation_window_days",
            )
            if getattr(self, name) < 0
        ]
        if negative:
            raise ValueError(
                f"negative counts are not observations: {negative}. A negative "
                "here means a query returned something unexpected, and "
                "computing a funnel from it would produce a confident wrong "
                "answer rather than an error."
            )
        if self.incidents_triaged > self.incidents_raised:
            raise ValueError(
                f"{self.incidents_triaged} incidents triaged out of "
                f"{self.incidents_raised} raised. More triaged than raised "
                "means the two counts came from different windows or "
                "different tenants; refusing rather than reporting a triage "
                "rate above 100%."
            )

    @property
    def has_any_observation(self) -> bool:
        """Is there ANY signal, of any kind?

        The gate on `UNKNOWN`. Without it, a tenant nobody has configured looks
        identical to one that is configured and idle.

        EVERY count, not just the first three. My first version checked
        credentials, agents and events only -- so a tenant with an activated
        containment and no ingest was reported UNKNOWN, because this gate runs
        before the enforcement branch and swallowed a real signal. A gate that
        can hide the strongest evidence in the record is worse than no gate.
        """
        return any(
            getattr(self, name)
            for name in (
                "credentials_configured",
                "agents_observed",
                "events_ingested",
                "incidents_raised",
                "incidents_triaged",
                "actions_refused",
                "containments_activated",
            )
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "credentials_configured": self.credentials_configured,
            "agents_observed": self.agents_observed,
            "events_ingested": self.events_ingested,
            "incidents_raised": self.incidents_raised,
            "incidents_triaged": self.incidents_triaged,
            "actions_refused": self.actions_refused,
            "containments_activated": self.containments_activated,
            "observation_window_days": self.observation_window_days,
        }


@dataclass(frozen=True, slots=True)
class AdoptionSnapshot:
    """Where this tenant is, why, and what would move it forward."""

    tenant: str
    stage: ActivationStage
    #: The observable fact that put the tenant in this stage. Required, so a
    #: stage is never an opinion -- somebody reading a funnel needs to know
    #: which number produced it.
    evidence: str
    #: What specifically is missing to reach the next stage. Actionable, not a
    #: score: "no incident has been triaged" is something a human can do
    #: something about; "activation score 0.4" is not.
    blocking_next_stage: str
    counts: TenantCounts

    limits: str = field(
        default=(
            "Computed from what this deployment observed. It cannot see agents "
            "that were never connected, so a low stage may mean the product is "
            "not deployed widely rather than not working. UNKNOWN means NO "
            "signal of any kind -- not zero usage. Nothing here is sent "
            "anywhere; this is a local computation over counts the deployment "
            "already holds."
        ),
        compare=False,
    )

    def is_at_least(self, stage: ActivationStage) -> bool:
        return _ORDER[self.stage] >= _ORDER[stage]

    def engagement_rate(self) -> float | None:
        """Triaged incidents over incidents raised, or None.

        REFUSES on a short window or a zero denominator. The number a
        dashboard wants is exactly the one that misleads when the window is
        three days: an incident raised on day three has not been ignored, it
        has not been reached yet.
        """
        if self.counts.observation_window_days < MIN_WINDOW_DAYS_FOR_ENGAGEMENT:
            return None
        if self.counts.incidents_raised == 0:
            return None
        return self.counts.incidents_triaged / self.counts.incidents_raised

    def rate_refusal_reason(self) -> str:
        """Why there is no engagement number, in words."""
        window = self.counts.observation_window_days
        if window < MIN_WINDOW_DAYS_FOR_ENGAGEMENT:
            return (
                f"{window} days of history is under the "
                f"{MIN_WINDOW_DAYS_FOR_ENGAGEMENT}-day minimum. An incident "
                "raised yesterday has not been ignored; it has not been "
                "reached yet, and a triage rate over a short window measures "
                "the window."
            )
        if self.counts.incidents_raised == 0:
            return (
                "no incidents have been raised, so there is no triage rate to "
                "quote. This is NOT a 100% triage rate and not a 0% one."
            )
        return ""

    def as_dict(self) -> dict[str, Any]:
        rate = self.engagement_rate()
        return {
            # Stage and its evidence first: a reader who stops early must not
            # stop before learning which fact produced the stage.
            "stage": self.stage.value,
            "evidence": self.evidence,
            "blocking_next_stage": self.blocking_next_stage,
            "rate_refusal_reason": self.rate_refusal_reason(),
            "tenant": self.tenant,
            # A fixed-precision string, never a float: the canonical JSON form
            # refuses floats, and a snapshot that cannot be signed is one
            # nobody can rely on.
            "engagement_rate": None if rate is None else f"{rate:.4f}",
            "counts": self.counts.as_dict(),
            "limits": self.limits,
        }


def assess_adoption(*, tenant: str, counts: TenantCounts) -> AdoptionSnapshot:
    """Place this tenant on the funnel, from observable facts only.

    Stages are checked from the FAR END BACKWARDS. Enforcement implies
    detection implies ingestion, and checking forwards would report a tenant as
    `INGESTING` because the first matching branch won -- understating a
    deployment that is actually in the path.
    """
    if not tenant.strip():
        raise ValueError(
            "an adoption snapshot with no tenant cannot be compared against "
            "its predecessor or kept out of another tenant's report"
        )

    if not counts.has_any_observation:
        return AdoptionSnapshot(
            tenant=tenant,
            stage=ActivationStage.UNKNOWN,
            evidence=(
                "no credentials configured, no agents observed and no events "
                "ingested. This is the absence of a signal, NOT a measurement "
                "of zero usage: a tenant with nothing connected and one with "
                "everything connected and idle produce the same counts."
            ),
            blocking_next_stage=(
                "configure an ingest credential and point one agent at it"
            ),
            counts=counts,
        )

    if counts.containments_activated or counts.actions_refused:
        return AdoptionSnapshot(
            tenant=tenant,
            stage=ActivationStage.ENFORCING,
            evidence=(
                f"{counts.actions_refused} action(s) refused and "
                f"{counts.containments_activated} containment(s) activated: "
                "the product is in the path, not beside it"
            ),
            blocking_next_stage=(
                "nothing in this funnel. The next question is coverage -- "
                f"{counts.agents_observed} agent(s) are observed, and this "
                "deployment cannot see any that were never connected."
            ),
            counts=counts,
        )

    if counts.incidents_triaged:
        return AdoptionSnapshot(
            tenant=tenant,
            stage=ActivationStage.INVESTIGATING,
            evidence=(
                f"{counts.incidents_triaged} of {counts.incidents_raised} "
                "incident(s) moved past `received`, so a human has looked"
            ),
            blocking_next_stage=(
                "no action has been refused or contained. Detection without "
                "enforcement is the deliberate default for correlation-driven "
                "findings, so this may be correct rather than incomplete -- "
                "see docs/SECURITY_ASSURANCE.md before treating it as a gap."
            ),
            counts=counts,
        )

    if counts.incidents_raised:
        return AdoptionSnapshot(
            tenant=tenant,
            stage=ActivationStage.DETECTING,
            evidence=(
                f"{counts.incidents_raised} incident(s) raised, so the policy "
                "is exercised rather than merely configured"
            ),
            blocking_next_stage=(
                "NO incident has been triaged. This is the stage most "
                "deployments never leave, and it is the one that matters: an "
                "incident nobody opened is a log line with extra steps."
            ),
            counts=counts,
        )

    if counts.events_ingested:
        return AdoptionSnapshot(
            tenant=tenant,
            stage=ActivationStage.INGESTING,
            evidence=f"{counts.events_ingested} event(s) ingested",
            blocking_next_stage=(
                "no incident has been raised. Either the traffic is genuinely "
                "benign, or the policy does not cover what these agents do -- "
                "and those need opposite responses, so check the detector "
                "configuration against the observed actions before concluding "
                "either."
            ),
            counts=counts,
        )

    return AdoptionSnapshot(
        tenant=tenant,
        stage=ActivationStage.CONNECTED,
        evidence=(
            f"{counts.credentials_configured} credential(s) configured and "
            f"{counts.agents_observed} agent(s) known, with no events yet"
        ),
        blocking_next_stage=(
            "no events have arrived. The credential exists and nothing is "
            "using it, which usually means the agent side was never wired up."
        ),
        counts=counts,
    )
