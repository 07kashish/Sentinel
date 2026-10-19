"""Approved and executed must be the same thing.

WHAT WAS ACTUALLY BROKEN
------------------------
Every other proof in this codebase attests to a DECISION. The policy engine
evaluated a payload, the passport recorded the decision, the signature covered
the passport, the Merkle log proved the record was not altered. All of it
verified, and none of it said the executed action was the approved one --
`ProtectedToolRunner.execute` decides over a `payload` and then invokes an
opaque zero-argument closure, so the two were connected only by the caller
having been honest.

THE DISCIPLINE IN THIS FILE
---------------------------
Every negative test is paired with the positive built from the SAME fixture.
A refusal test alone passes just as happily against a `verify_binding` that
refuses everything, and "it refused" is not evidence that it refused for the
reason claimed -- so each one asserts the specific defect, and
`test_the_baseline_execution_is_permitted` is what stops the whole file from
being vacuous.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from sentinel.domain.execution_binding import (
    PARAMETER_CONTEXT,
    BindingDefect,
    ExecutionAuthorization,
    ExecutionReceipt,
    ExecutionRequest,
    RejectingNonceLedger,
    parameter_digest,
    verify_binding,
)

NOW = datetime(2026, 9, 3, 12, 0, 0, tzinfo=timezone.utc)

APPROVED_PARAMETERS = {
    "bucket": "acme-reports",
    "key": "q3/summary.pdf",
    "acl": "private",
}


class _Ledger:
    """An accepting ledger that records claims, for the happy path."""

    def __init__(self, used: set[tuple[str, str]] | None = None):
        self.used = used if used is not None else set()
        self.claims: list[tuple[str, str]] = []

    def claim(self, *, tenant_id: str, nonce: str) -> bool:
        self.claims.append((tenant_id, nonce))
        if (tenant_id, nonce) in self.used:
            return False
        self.used.add((tenant_id, nonce))
        return True


def _authorization(**overrides) -> ExecutionAuthorization:
    defaults = dict(
        authorization_id="auth-1",
        tenant_id="acme",
        actor_identity="user:priya",
        agent_identity="agent:infra-writer",
        tool_identity="tool:s3.put_object",
        action="s3:PutObject",
        target_resource="arn:aws:s3:::acme-reports/q3/summary.pdf",
        approved_parameter_digest=parameter_digest(APPROVED_PARAMETERS),
        issued_at="2026-09-03T11:59:00+00:00",
        expires_at="2026-09-03T12:05:00+00:00",
        nonce="nonce-abc",
        mcp_server_identity="mcp:aws-prod",
    )
    defaults.update(overrides)
    return ExecutionAuthorization(**defaults)  # type: ignore[arg-type]


def _request(**overrides) -> ExecutionRequest:
    defaults = dict(
        tenant_id="acme",
        agent_identity="agent:infra-writer",
        tool_identity="tool:s3.put_object",
        action="s3:PutObject",
        target_resource="arn:aws:s3:::acme-reports/q3/summary.pdf",
        parameters=dict(APPROVED_PARAMETERS),
        mcp_server_identity="mcp:aws-prod",
    )
    defaults.update(overrides)
    return ExecutionRequest(**defaults)  # type: ignore[arg-type]


#: Distinct from None, because None is a MEANINGFUL argument here -- it is the
#: "no authorization was presented" case. A `None`-means-default helper made
#: `_verify(authorization=None)` silently exercise the happy path instead, and
#: that test passed until it asserted the exact defect tuple.
_DEFAULT = object()


def _verify(*, authorization=_DEFAULT, request=None, ledger=None, now=NOW, **kwargs):
    return verify_binding(
        authorization=_authorization() if authorization is _DEFAULT else authorization,
        request=request if request is not None else _request(),
        now=now,
        nonces=ledger if ledger is not None else _Ledger(),
        **kwargs,
    )


# ── the positive case, without which nothing below is evidence ──────────────


def test_the_baseline_execution_is_permitted():
    """THE anchor. Every refusal test in this file would also pass against a
    verifier that refused unconditionally; this is what rules that out.
    """
    verdict = _verify()

    assert verdict.permitted, verdict.explain()
    assert verdict.defects == ()
    assert verdict.parameters_matched
    assert verdict.actual_parameter_digest == verdict.approved_parameter_digest


def test_a_permitted_verdict_claims_the_nonce_exactly_once():
    ledger = _Ledger()

    assert _verify(ledger=ledger).permitted
    assert ledger.claims == [("acme", "nonce-abc")]


# ── the nine negatives the requirement enumerates ───────────────────────────


def test_1_parameter_substitution_is_refused():
    """The whole point. Same tool, same action, same resource, same agent --
    one parameter changed, and nothing else in the system would have noticed.
    """
    smuggled = dict(APPROVED_PARAMETERS) | {"bucket": "attacker-exfil"}

    verdict = _verify(request=_request(parameters=smuggled))

    assert not verdict.permitted
    assert BindingDefect.PARAMETERS_DIFFER in verdict.defects
    assert "do not match" in verdict.explain()


def test_2_tool_substitution_is_refused():
    verdict = _verify(request=_request(tool_identity="tool:s3.delete_object"))

    assert BindingDefect.TOOL_SUBSTITUTED in verdict.defects


def test_3_mcp_server_substitution_is_refused():
    verdict = _verify(request=_request(mcp_server_identity="mcp:attacker"))

    assert BindingDefect.MCP_SERVER_SUBSTITUTED in verdict.defects


def test_4_an_expired_authorization_is_refused():
    verdict = _verify(now=NOW + timedelta(minutes=10))

    assert BindingDefect.EXPIRED in verdict.defects


def test_5_replay_is_refused():
    """Second use of the same authorization. The first must succeed, or this
    test would pass against a verifier that refused both.
    """
    ledger = _Ledger()

    assert _verify(ledger=ledger).permitted
    second = _verify(ledger=ledger)

    assert not second.permitted
    assert BindingDefect.REPLAYED in second.defects


def test_6_delegated_privilege_amplification_is_refused():
    """An authorization issued to one agent, presented by another. The child
    agent in a delegation chain reusing its parent's authorization is exactly
    this, and it is the quietest of the nine.
    """
    verdict = _verify(request=_request(agent_identity="agent:child-scraper"))

    assert BindingDefect.AGENT_SUBSTITUTED in verdict.defects
    assert "privilege amplification" in BindingDefect.AGENT_SUBSTITUTED.explanation


def test_7_resource_substitution_is_refused():
    verdict = _verify(
        request=_request(target_resource="arn:aws:s3:::acme-secrets/keys.json")
    )

    assert BindingDefect.RESOURCE_SUBSTITUTED in verdict.defects


def test_8_approval_reuse_for_a_different_execution_is_refused():
    """Distinct from plain replay: the authorization is reused AND changed. It
    must fail on both counts, and the parameter defect must be reported even
    though the nonce alone would have stopped it -- an operator needs to see
    that a substitution was attempted, not just that something was reused.
    """
    ledger = _Ledger()
    assert _verify(ledger=ledger).permitted

    verdict = _verify(
        ledger=ledger,
        request=_request(parameters=dict(APPROVED_PARAMETERS) | {"acl": "public-read"}),
    )

    assert not verdict.permitted
    assert BindingDefect.PARAMETERS_DIFFER in verdict.defects


def test_9_cross_tenant_reuse_is_refused():
    verdict = _verify(request=_request(tenant_id="globex"))

    assert BindingDefect.CROSS_TENANT in verdict.defects


# ── the shape of the refusal ────────────────────────────────────────────────


def test_every_defect_is_reported_not_just_the_first():
    """An operator fixing a misconfiguration should fix it once. A report that
    stops at the first problem also hides whether the others exist.
    """
    verdict = _verify(
        request=_request(
            tenant_id="globex",
            tool_identity="tool:other",
            target_resource="other",
            parameters={"bucket": "elsewhere"},
        ),
        now=NOW + timedelta(hours=1),
    )

    assert {
        BindingDefect.CROSS_TENANT,
        BindingDefect.TOOL_SUBSTITUTED,
        BindingDefect.RESOURCE_SUBSTITUTED,
        BindingDefect.PARAMETERS_DIFFER,
        BindingDefect.EXPIRED,
    } <= set(verdict.defects)


def test_a_refused_execution_does_not_burn_the_nonce():
    """A refused attempt executed nothing. Burning the authorization would turn
    a transient failure permanent while preventing no attack, since each retry
    is refused on its own merits.
    """
    ledger = _Ledger()

    refused = _verify(ledger=ledger, request=_request(parameters={"bucket": "x"}))
    assert not refused.permitted
    assert ledger.claims == []

    assert _verify(ledger=ledger).permitted


def test_no_authorization_at_all_is_refused():
    verdict = _verify(authorization=None)

    assert verdict.defects == (BindingDefect.NOT_AUTHORIZED,)
    assert not verdict.permitted


def test_permitted_is_derived_and_cannot_be_set():
    """`permitted` is a property over `defects`. If it were a field, some
    constructor somewhere would eventually set it to True alongside a defect.
    """
    with pytest.raises(TypeError):
        from sentinel.domain.execution_binding import BindingVerdict

        BindingVerdict(  # type: ignore[call-arg]
            defects=(BindingDefect.EXPIRED,),
            actual_parameter_digest="a" * 64,
            approved_parameter_digest="a" * 64,
            permitted=True,
        )


def test_no_defect_member_is_falsy():
    """An enum with a falsy member gets used in a boolean test and the most
    serious case reads as "no problem". That defect was already found in an SDK
    decision enum in this codebase.
    """
    for defect in BindingDefect:
        assert defect.value, defect.name
        assert bool(defect) is True
        assert defect.explanation.strip()


# ── the missing ledger fails closed ─────────────────────────────────────────


def test_the_default_ledger_refuses_everything():
    """A missing ledger must be an outage, not a silent loss of replay
    protection. The tempting default -- an in-process set -- works perfectly in
    every test and protects nothing across replicas.
    """
    verdict = _verify(ledger=RejectingNonceLedger())

    assert not verdict.permitted
    assert BindingDefect.REPLAYED in verdict.defects


# ── bounded mutation, opt-in and named ──────────────────────────────────────


def test_a_named_mutable_parameter_may_differ():
    authorization = _authorization(mutable_parameters=frozenset({"request_id"}))
    approved = dict(APPROVED_PARAMETERS) | {"request_id": "r-1"}
    authorization = replace(
        authorization, approved_parameter_digest=parameter_digest(approved)
    )
    actual = dict(approved) | {"request_id": "r-2"}

    verdict = _verify(
        authorization=authorization,
        request=_request(parameters=actual),
        approved_parameters=approved,
    )

    assert verdict.permitted, verdict.explain()
    assert verdict.bounded_mutations == ("request_id",)
    assert "request_id" in verdict.explain()


def test_an_unnamed_parameter_may_not_differ_even_when_mutation_is_allowed():
    """The reason `mutable_parameters` is a set of names and not a boolean: a
    boolean gets switched on for the request id and then permits substituting
    the destination bucket.
    """
    authorization = _authorization(mutable_parameters=frozenset({"request_id"}))
    approved = dict(APPROVED_PARAMETERS) | {"request_id": "r-1"}
    authorization = replace(
        authorization, approved_parameter_digest=parameter_digest(approved)
    )
    actual = dict(approved) | {"request_id": "r-2", "bucket": "attacker-exfil"}

    verdict = _verify(
        authorization=authorization,
        request=_request(parameters=actual),
        approved_parameters=approved,
    )

    assert not verdict.permitted
    assert BindingDefect.PARAMETERS_DIFFER in verdict.defects


def test_mutation_without_the_approved_values_is_refused_not_assumed():
    """Comparing key by key needs the approved values. Their absence means only
    the exact check is available, and an unchecked difference must refuse.
    """
    authorization = _authorization(mutable_parameters=frozenset({"request_id"}))
    approved = dict(APPROVED_PARAMETERS) | {"request_id": "r-1"}
    authorization = replace(
        authorization, approved_parameter_digest=parameter_digest(approved)
    )

    verdict = _verify(
        authorization=authorization,
        request=_request(parameters=dict(approved) | {"request_id": "r-2"}),
        approved_parameters=None,
    )

    assert not verdict.permitted


def test_falsified_approved_parameters_cannot_become_the_baseline():
    """A caller supplying its own "approved" values would otherwise define the
    comparison it is being held to. They must hash to the committed digest.
    """
    authorization = _authorization(mutable_parameters=frozenset({"bucket"}))
    lie = {"bucket": "attacker-exfil"}

    verdict = _verify(
        authorization=authorization,
        request=_request(parameters=lie),
        approved_parameters=lie,
    )

    assert not verdict.permitted
    assert BindingDefect.PARAMETERS_DIFFER in verdict.defects


# ── the digest itself ───────────────────────────────────────────────────────


def test_the_parameter_digest_is_domain_separated():
    """A bare hash of a JSON object could be mistaken for a digest of a
    passport or a policy bundle, which is a cross-protocol substitution. Same
    reason RFC 6962 prefixes leaves and nodes differently.
    """
    from sentinel.domain.passport import digest_of

    assert parameter_digest(APPROVED_PARAMETERS) != digest_of(APPROVED_PARAMETERS)
    assert parameter_digest(APPROVED_PARAMETERS) == digest_of(
        {"context": PARAMETER_CONTEXT, "parameters": dict(APPROVED_PARAMETERS)}
    )


def test_key_order_does_not_change_the_digest():
    reordered = {"acl": "private", "key": "q3/summary.pdf", "bucket": "acme-reports"}

    assert parameter_digest(reordered) == parameter_digest(APPROVED_PARAMETERS)


def test_a_float_parameter_is_refused():
    """0.1 does not round-trip identically across languages, so a float under a
    signature verifies on one runtime and fails on another.
    """
    with pytest.raises(ValueError):
        parameter_digest({"threshold": 0.1})


def test_an_added_parameter_changes_the_digest():
    """Otherwise an approval could be extended at execution time by adding a
    key nobody approved.
    """
    extended = dict(APPROVED_PARAMETERS) | {"grant_full_control": "everyone"}

    assert parameter_digest(extended) != parameter_digest(APPROVED_PARAMETERS)


# ── an authorization that could not bind is refused at construction ─────────


@pytest.mark.parametrize(
    "field_name",
    ["authorization_id", "tenant_id", "agent_identity", "tool_identity",
     "action", "nonce"],
)
def test_an_authorization_missing_an_identity_field_is_refused(field_name):
    with pytest.raises(ValueError) as raised:
        _authorization(**{field_name: "   "})

    assert field_name in str(raised.value)


@pytest.mark.parametrize("bad", ["", "not-a-digest", "a" * 63, "z" * 64])
def test_a_malformed_parameter_commitment_is_refused(bad):
    """An empty commitment would compare unequal to every execution -- or, if a
    caller defaulted it, equal to all of them.
    """
    with pytest.raises(ValueError) as raised:
        _authorization(approved_parameter_digest=bad)

    assert "sha256 hex digest" in str(raised.value)


def test_an_expiry_before_issuance_is_refused():
    with pytest.raises(ValueError) as raised:
        _authorization(
            issued_at="2026-09-03T12:00:00+00:00",
            expires_at="2026-09-03T11:00:00+00:00",
        )

    assert "never valid" in str(raised.value)


def test_a_naive_timestamp_is_refused():
    """A naive expiry means a different moment in every deployment that reads
    it, which is how a credential outlives its window.
    """
    with pytest.raises(ValueError) as raised:
        _authorization(expires_at="2026-09-03T12:05:00")

    assert "no timezone" in str(raised.value)


def test_clock_skew_within_tolerance_is_permitted():
    """An enforcement point a few seconds behind the issuer must not refuse
    every authorization it is handed.
    """
    verdict = _verify(now=NOW - timedelta(seconds=30))

    assert verdict.permitted, verdict.explain()


def test_an_authorization_from_the_far_future_is_refused():
    verdict = _verify(now=NOW - timedelta(hours=2))

    assert BindingDefect.NOT_YET_VALID in verdict.defects


# ── the receipt binds the chain ─────────────────────────────────────────────


def _receipt(**overrides) -> ExecutionReceipt:
    defaults = dict(
        receipt_id="receipt-1",
        tenant_id="acme",
        authorization_digest=_authorization().digest,
        executed_request_digest="b" * 64,
        actual_parameter_digest=parameter_digest(APPROVED_PARAMETERS),
        execution_identity="worker:ecs-task-7",
        started_at="2026-09-03T12:00:01+00:00",
        completed_at="2026-09-03T12:00:02+00:00",
        outcome="succeeded",
    )
    defaults.update(overrides)
    return ExecutionReceipt(**defaults)  # type: ignore[arg-type]


def test_a_receipt_binds_authorization_request_and_parameters():
    receipt = _receipt()
    document = receipt.as_document()

    assert document["authorization_digest"] == _authorization().digest
    assert document["actual_parameter_digest"] == parameter_digest(
        APPROVED_PARAMETERS
    )
    assert receipt.digest != _authorization().digest


def test_a_receipt_without_an_outcome_is_refused():
    with pytest.raises(ValueError) as raised:
        _receipt(outcome="  ")

    assert "whether the action happened" in str(raised.value)


@pytest.mark.parametrize(
    "field_name",
    ["authorization_digest", "executed_request_digest", "actual_parameter_digest"],
)
def test_a_receipt_that_binds_to_nothing_is_refused(field_name):
    with pytest.raises(ValueError) as raised:
        _receipt(**{field_name: ""})

    assert "does not bind to anything" in str(raised.value)


def test_an_empty_result_digest_is_allowed():
    """A tool that returns nothing has nothing to hash. Requiring it would
    force callers to invent a digest, and an invented digest is worse than an
    absent one.
    """
    assert _receipt(result_digest="").result_digest == ""


def test_the_receipt_document_is_domain_separated_from_the_authorization():
    """Both are canonical JSON signed by the same key. Without distinct
    contexts a receipt could be presented as an authorization.
    """
    assert _receipt().as_document()["context"] != (
        _authorization().as_document()["context"]
    )


def test_the_authorization_digest_covers_the_parameter_commitment():
    """Changing what was approved must change the authorization's identity, or
    a receipt could name an authorization that no longer says what it said.
    """
    other = _authorization(
        approved_parameter_digest=parameter_digest({"bucket": "elsewhere"})
    )

    assert other.digest != _authorization().digest


# ── the delegation chain is bound too ──────────────────────────────────────
#
# Phase 4/7. An authorization commits to the digest of the SIGNED chain it was
# issued against, so a valid chain belonging to a different principal is
# refused rather than accepted for granting the same capability.


CHAIN = "c" * 64
OTHER_CHAIN = "d" * 64


def test_a_matching_delegation_chain_is_permitted():
    """The anchor for the three below."""
    verdict = _verify(
        authorization=_authorization(delegation_passport_digest=CHAIN),
        request=_request(delegation_passport_digest=CHAIN),
    )

    assert verdict.permitted, verdict.explain()
    assert verdict.delegation_bound is True


def test_a_substituted_delegation_chain_is_refused():
    """The attack: a chain that is perfectly valid, grants the same
    capability, and comes from somebody else. Whose authority is being
    exercised is the question.
    """
    verdict = _verify(
        authorization=_authorization(delegation_passport_digest=CHAIN),
        request=_request(delegation_passport_digest=OTHER_CHAIN),
    )

    assert not verdict.permitted
    assert BindingDefect.DELEGATION_SUBSTITUTED in verdict.defects
    assert "whose authority" in BindingDefect.DELEGATION_SUBSTITUTED.explanation


def test_an_absent_chain_at_execution_is_refused_when_one_was_authorized():
    """Presenting no chain against an authorization that named one must not
    pass. Otherwise dropping the chain is a way to skip the check.
    """
    verdict = _verify(
        authorization=_authorization(delegation_passport_digest=CHAIN),
        request=_request(delegation_passport_digest=""),
    )

    assert BindingDefect.DELEGATION_SUBSTITUTED in verdict.defects


def test_an_unbound_authorization_reports_that_rather_than_passing_silently():
    """An authorization issued without a chain cannot compare one. That is a
    real state -- not every action flows through a delegation -- so it is
    REPORTED in `delegation_bound` rather than inferred from an absence.

    Comparing to nothing would accept any chain; comparing to an empty string
    would refuse every legitimate call. Neither is right, so the caller is
    told.
    """
    verdict = _verify(
        authorization=_authorization(),
        request=_request(delegation_passport_digest=CHAIN),
    )

    assert verdict.permitted, verdict.explain()
    assert verdict.delegation_bound is False


def test_the_authorization_digest_covers_the_chain_commitment():
    """Changing which chain was authorized must change the authorization's
    identity, or a receipt could name an authorization that no longer says
    what it said.
    """
    one = _authorization(delegation_passport_digest=CHAIN)
    other = _authorization(delegation_passport_digest=OTHER_CHAIN)

    assert one.digest != other.digest
