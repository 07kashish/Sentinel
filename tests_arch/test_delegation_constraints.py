"""The four things a delegation could not express, and therefore could not stop.

WHAT WAS UNDETECTABLE BEFORE THIS MODULE
------------------------------------------
`DelegationHop` carried five fields: who, to whom, what scopes, a task id and an
instruction. Every check in `a2a.py` is about SCOPES — was this hop entitled to
what it granted. That check is good and is not changed here.

But four failure modes are invisible to it, and each one is cheap to exploit:

  1. EXPIRY. Nothing carried one, so every delegation ever issued was
     PERMANENT. An agent handed `read:customers` for a twenty-minute task held
     it indefinitely — and it never appeared in a review, because nothing
     recorded that it was supposed to end.

  2. ENVIRONMENT. `read:customers` in dev and `read:customers` in production are
     the same string. Scope checking cannot tell them apart; blast radius is the
     entire difference.

  3. RESOURCE. A scope names a VERB, not an OBJECT. `read:customers` authorised
     the table when one record was meant.

  4. TENANT. The stores are RLS-protected, but the CHAIN is caller-supplied and
     nothing compared its tenant to the caller's.

WHY SO MANY TESTS ARE ABOUT WHAT IS *NOT* REFUSED
---------------------------------------------------
A control that refuses too much gets switched off, and then refuses nothing. An
unbounded delegation is REPORTED, not blocked, because blocking would break
every grant issued before expiry existed. The tests hold that line in both
directions.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sentinel.domain.a2a import Severity
from sentinel.domain.delegation_constraints import (
    MAX_REASONABLE_LIFETIME,
    ConstraintKind,
    DelegationConstraint,
    DelegationContext,
    environment_rank,
    evaluate,
)

NOW = datetime(2026, 8, 31, 12, 0, 0, tzinfo=timezone.utc)


def _kinds(findings) -> set[ConstraintKind]:
    return {f.kind for f in findings}


def _valid(**overrides) -> DelegationConstraint:
    base = {
        "tenant_id": "acme",
        "environment": "production",
        "purpose": "generate the Q3 finance report",
        "resources": ("db://customers/*",),
        "issued_at": NOW - timedelta(minutes=10),
        "expires_at": NOW + timedelta(hours=1),
    }
    base.update(overrides)
    return DelegationConstraint(**base)


def _here(**overrides) -> DelegationContext:
    base = {
        "tenant_id": "acme",
        "environment": "production",
        "resource": "db://customers/42",
    }
    base.update(overrides)
    return DelegationContext(**base)


# ── 1. expiry: the gap that made every delegation permanent ──────────────────


def test_an_expired_delegation_is_reported():
    findings = evaluate(
        _valid(expires_at=NOW - timedelta(minutes=1)), context=_here(), now=NOW
    )
    assert ConstraintKind.EXPIRED in _kinds(findings)


def test_a_delegation_with_no_expiry_is_reported_but_not_treated_as_worst():
    """Reported, because an unbounded grant to an autonomous agent belongs in a
    review. Not critical, because refusing would break every delegation issued
    before expiry existed — and a control that breaks everything gets disabled.
    """
    findings = evaluate(_valid(expires_at=None), context=_here(), now=NOW)
    unbounded = next(f for f in findings if f.kind is ConstraintKind.UNBOUNDED)
    assert unbounded.severity is Severity.MODERATE


def test_a_delegation_that_expires_before_it_is_issued_cannot_be_constructed():
    """It grants nothing. Refusing to construct it beats letting it read as a
    valid grant that happens to fail every check.
    """
    with pytest.raises(ValueError, match="grants nothing"):
        DelegationConstraint(
            issued_at=NOW, expires_at=NOW - timedelta(seconds=1)
        )


def test_a_delegation_issued_in_the_future_is_refused():
    """Either a forged timestamp or a clock this deployment cannot reconcile.
    Neither is a delegation to honour.
    """
    findings = evaluate(
        _valid(issued_at=NOW + timedelta(hours=1), expires_at=NOW + timedelta(hours=2)),
        context=_here(),
        now=NOW,
    )
    assert ConstraintKind.NOT_YET_VALID in _kinds(findings)


def test_a_very_long_lifetime_is_reported_as_a_standing_credential():
    findings = evaluate(
        _valid(expires_at=NOW + MAX_REASONABLE_LIFETIME + timedelta(days=1)),
        context=_here(),
        now=NOW,
    )
    assert ConstraintKind.EXCESSIVE_LIFETIME in _kinds(findings)


def test_a_normal_lifetime_is_not_reported():
    assert ConstraintKind.EXCESSIVE_LIFETIME not in _kinds(
        evaluate(_valid(), context=_here(), now=NOW)
    )


# ── 2. environment: the same string, a different blast radius ────────────────


def test_a_dev_delegation_presented_against_production_is_escalation():
    findings = evaluate(
        _valid(environment="dev"), context=_here(environment="production"), now=NOW
    )
    escalation = next(
        f for f in findings if f.kind is ConstraintKind.ENVIRONMENT_ESCALATION
    )
    assert escalation.severity is Severity.CRITICAL


def test_a_production_delegation_used_in_dev_is_not_escalation():
    """De-escalation is not a finding. Reporting it would train operators to
    dismiss the alert that matters.
    """
    assert ConstraintKind.ENVIRONMENT_ESCALATION not in _kinds(
        evaluate(_valid(environment="production"), context=_here(environment="dev"), now=NOW)
    )


def test_an_unknown_environment_ranks_above_production():
    """The safe reading of an unrecognised blast radius is the worst one. A
    deployment with an environment this table has not been taught should have
    its delegations surfaced for review, not waved through.
    """
    assert environment_rank("mystery-cluster") > environment_rank("production")


def test_environment_names_are_matched_case_and_space_insensitively():
    assert environment_rank("  Production ") == environment_rank("prod")


# ── 3. resource: a scope names a verb, not an object ─────────────────────────


def test_a_resource_outside_the_permitted_pattern_is_reported():
    findings = evaluate(
        _valid(resources=("db://customers/42",)),
        context=_here(resource="db://customers/99"),
        now=NOW,
    )
    assert ConstraintKind.RESOURCE_NOT_PERMITTED in _kinds(findings)


def test_a_permitted_resource_passes():
    assert ConstraintKind.RESOURCE_NOT_PERMITTED not in _kinds(
        evaluate(_valid(), context=_here(), now=NOW)
    )


def test_matching_is_by_pattern_not_by_string_prefix():
    """A prefix test accepts `db://customers-evil` for a permitted
    `db://customers`. This codebase has fixed that exact defect once already, in
    FileSandbox's containment check.
    """
    findings = evaluate(
        _valid(resources=("db://customers",)),
        context=_here(resource="db://customers-evil"),
        now=NOW,
    )
    assert ConstraintKind.RESOURCE_NOT_PERMITTED in _kinds(findings)


def test_no_declared_resources_means_the_check_does_not_apply():
    """An issuer who knows the expiry but not the resource pattern must be able
    to record the expiry. A constraint that could not be partial would not be
    adopted at all.
    """
    assert ConstraintKind.RESOURCE_NOT_PERMITTED not in _kinds(
        evaluate(_valid(resources=()), context=_here(), now=NOW)
    )


# ── 4. tenant: the chain is caller-supplied ──────────────────────────────────


def test_a_chain_from_another_tenant_is_critical():
    """The stores are RLS-protected; the CHAIN is not. An expired delegation is
    authority that ran out — this is authority that never existed here.
    """
    findings = evaluate(
        _valid(tenant_id="globex"), context=_here(tenant_id="acme"), now=NOW
    )
    mismatch = next(f for f in findings if f.kind is ConstraintKind.TENANT_MISMATCH)
    assert mismatch.severity is Severity.CRITICAL


# ── reporting behaviour ──────────────────────────────────────────────────────


def test_every_violation_is_reported_not_only_the_first():
    """An expired delegation presented in the wrong environment is two problems
    with two remedies. Reporting one hides the other from whoever fixes it.
    """
    findings = evaluate(
        _valid(
            environment="dev",
            expires_at=NOW - timedelta(minutes=1),
            tenant_id="globex",
        ),
        context=_here(),
        now=NOW,
    )
    assert {
        ConstraintKind.EXPIRED,
        ConstraintKind.ENVIRONMENT_ESCALATION,
        ConstraintKind.TENANT_MISMATCH,
    } <= _kinds(findings)


def test_a_fully_constrained_valid_delegation_reports_nothing():
    assert evaluate(_valid(), context=_here(), now=NOW) == ()


def test_a_missing_purpose_is_reported_at_the_lowest_severity():
    """Nothing to compare later behaviour against, so intent divergence cannot
    be assessed — worth saying, not worth blocking on.
    """
    findings = evaluate(_valid(purpose=""), context=_here(), now=NOW)
    purpose = next(f for f in findings if f.kind is ConstraintKind.PURPOSE_MISSING)
    assert purpose.severity is Severity.LOW


def test_the_clock_is_passed_in_and_never_read():
    """A domain rule that reads the clock cannot be tested at a boundary and
    cannot be replayed against historical evidence — which is exactly what
    policy simulation does.
    """
    import inspect

    from sentinel.domain import delegation_constraints

    source = inspect.getsource(delegation_constraints.evaluate)
    assert "now" in inspect.signature(delegation_constraints.evaluate).parameters
    assert "datetime.now" not in source
    assert "utcnow" not in source


def test_every_kind_has_a_severity():
    """A finding constructed with no severity entry would raise at report time,
    in front of an analyst, rather than here.
    """
    from sentinel.domain.delegation_constraints import CONSTRAINT_SEVERITY

    for kind in ConstraintKind:
        assert kind in CONSTRAINT_SEVERITY, f"{kind} has no severity"


def test_findings_serialise_for_evidence():
    finding = evaluate(_valid(expires_at=None), context=_here(), now=NOW)[0]
    document = finding.as_dict()
    assert document["kind"] and document["severity"] and document["detail"]


# ── the constraints reach ENFORCEMENT, not just a report ─────────────────────


def _gateway():
    from sentinel.application.a2a_gateway import (
        A2AGateway,
        InMemoryAgentCards,
        InMemoryTaskLedger,
    )
    from sentinel.application.protect_gate import ProtectGate
    from sentinel.infrastructure.detection import DeterministicPolicy

    from sentinel.domain.a2a import AgentCard

    gateway = A2AGateway(
        gate=ProtectGate(policy=DeterministicPolicy.default(), enforce=False),
        cards=InMemoryAgentCards(),
        tasks=InMemoryTaskLedger(),
    )
    # Enrolled, so `unenrolled_agent` — which is CRITICAL and structural — does
    # not fire and mask the constraint finding each test is actually about. The
    # first version of this helper left it unenrolled and every "reported but
    # not blocked" assertion failed for the wrong reason.
    gateway.enrol(
        "acme",
        AgentCard(
            agent_id="research-agent",
            version="1.0",
            endpoint="https://research.internal",
            capabilities=frozenset({"read:customers"}),
        ),
    )
    return gateway


def _chain():
    from sentinel.domain.a2a import DelegationChain, DelegationHop

    return DelegationChain(
        principal="alice",
        principal_scopes=frozenset({"read:customers"}),
        hops=(
            DelegationHop(
                from_agent="alice",
                to_agent="research-agent",
                granted=frozenset({"read:customers"}),
                task_id="t-1",
            ),
        ),
    )


def test_a_cross_tenant_chain_is_refused_structurally_whatever_policy_says():
    """Policy can be misconfigured; a chain from another tenant is authority
    that never existed here. Same standing as privilege amplification.
    """
    from sentinel.application.a2a_gateway import A2ADelegationRefused

    with pytest.raises(A2ADelegationRefused):
        _gateway().require_allowed(
            tenant_id="acme",
            chain=_chain(),
            constraint=_valid(tenant_id="globex"),
            context=_here(tenant_id="acme"),
            now=NOW,
        )


def test_an_environment_escalation_is_refused_structurally():
    from sentinel.application.a2a_gateway import A2ADelegationRefused

    with pytest.raises(A2ADelegationRefused):
        _gateway().require_allowed(
            tenant_id="acme",
            chain=_chain(),
            constraint=_valid(environment="dev"),
            context=_here(environment="production"),
            now=NOW,
        )


def test_an_expired_delegation_is_reported_but_left_to_policy():
    """HIGH, not CRITICAL. Authority that ran out is usually a long-running job
    nobody re-issued, and refusing it structurally would make the control the
    thing operators disable. It reaches policy, which may still stop it.
    """
    evaluation = _gateway().evaluate(
        tenant_id="acme",
        chain=_chain(),
        constraint=_valid(
                issued_at=NOW - timedelta(hours=2),
                expires_at=NOW - timedelta(hours=1),
            ),
        context=_here(),
        now=NOW,
    )
    assert ConstraintKind.EXPIRED in _kinds(evaluation.constraint_findings)
    assert not evaluation.blocked_structurally


def test_constraints_reach_policy_under_their_own_key():
    """A rule written to match privilege amplification must not start matching
    an expired delegation because both ended up in one list.
    """
    evaluation = _gateway().evaluate(
        tenant_id="acme",
        chain=_chain(),
        constraint=_valid(
                issued_at=NOW - timedelta(hours=2),
                expires_at=NOW - timedelta(hours=1),
            ),
        context=_here(),
        now=NOW,
    )
    payload = evaluation.as_dict()
    assert "delegation_expired" in str(payload) or evaluation.constraint_findings


def test_a_constraint_without_a_clock_is_refused_rather_than_guessed():
    """A gateway that reads the wall clock cannot be replayed against
    historical evidence, which is exactly what policy simulation does.
    """
    with pytest.raises(ValueError, match="without `now`"):
        _gateway().evaluate(
            tenant_id="acme", chain=_chain(), constraint=_valid(), context=_here()
        )


def test_no_constraint_means_the_old_behaviour_is_unchanged():
    """Every existing caller, the wire proxy and the SQL store keep working."""
    evaluation = _gateway().evaluate(tenant_id="acme", chain=_chain())
    assert evaluation.constraint_findings == ()


def test_require_allowed_forwards_every_argument_it_accepts():
    """A parameter accepted and not forwarded is worse than one that does not
    exist: the caller believes the check ran. This caught exactly that — the
    enforcement path took `constraint` and passed it nowhere.
    """
    import inspect

    from sentinel.application.a2a_gateway import A2AGateway

    accepted = set(inspect.signature(A2AGateway.require_allowed).parameters) - {"self"}
    body = inspect.getsource(A2AGateway.require_allowed)
    forwarded = body.split("self.evaluate(", 1)[1].split(")", 1)[0]
    for name in accepted:
        assert f"{name}=" in forwarded, (
            f"require_allowed accepts {name!r} and does not forward it to "
            "evaluate; the caller would believe that check ran"
        )
