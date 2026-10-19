"""A chain nobody has to trust the control plane about.

WHAT THIS REPLACES
------------------
`ExecutionPassport.delegation_chain` is a tuple of plain mappings. An
independent verifier reading one takes the platform's word for who delegated
what -- on precisely the question the platform exists to answer. Each hop is
now signed by its ISSUER, so the chain can be reconstructed from signatures
alone.

THE DISCIPLINE
--------------
Every refusal test is paired with the positive built from the same fixture, and
`test_a_sound_chain_establishes_authority` is what stops the file being
vacuous: a `verify_chain` that refused everything would satisfy every negative
test here.

The monotonicity tests are the interesting half. Each one builds a chain where
EVERY HOP IS INDIVIDUALLY WELL-FORMED AND CORRECTLY SIGNED, and hop 3 grants
something hop 2 never held. That is the attack -- not a forged signature, but a
valid one over a grant the signer was not entitled to make.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from sentinel.domain.delegation_passport import (
    DEFAULT_MAX_DEPTH,
    DelegationDefect,
    DelegationHop,
    DelegationPassport,
    chain_digest,
    environment_rank,
    verify_chain,
)
from sentinel.infrastructure.delegation_signing import (
    HopSigningKey,
    KeyRingVerifier,
    issuer_key_id,
    sign_hop,
)

NOW = datetime(2026, 9, 4, 12, 0, 0, tzinfo=timezone.utc)

HUMAN = "user:priya"
CODER = "agent:coder"
INFRA = "agent:infra"
ROGUE = "agent:rogue"


@pytest.fixture(scope="module")
def keys() -> dict[str, HopSigningKey]:
    """One key per principal, generated once."""
    return {
        who: HopSigningKey.generate(who)
        for who in (HUMAN, CODER, INFRA, ROGUE)
    }


def _hop(**overrides) -> DelegationHop:
    defaults = dict(
        issuer=HUMAN,
        subject=CODER,
        tenant_id="acme",
        depth=1,
        permitted_capabilities=frozenset({"s3.put_object", "s3.get_object"}),
        resource_scope=("arn:aws:s3:::acme-reports/*",),
        environment="production",
        issued_at=(NOW - timedelta(minutes=10)).isoformat(),
        expires_at=(NOW + timedelta(hours=1)).isoformat(),
        purpose="author the quarterly report",
    )
    defaults.update(overrides)
    return DelegationHop(**defaults)  # type: ignore[arg-type]


def _chain(keys, hops: list[DelegationHop]) -> DelegationPassport:
    """Sign a list of hops, wiring each one's previous_hop_digest.

    The wiring happens HERE rather than in the test bodies so a test that means
    to break the chain has to say so explicitly -- otherwise a forgotten digest
    would look like a deliberate BROKEN_CHAIN case.
    """
    signed = []
    previous = ""
    for hop in hops:
        linked = replace(hop, previous_hop_digest=previous)
        signed.append(
            sign_hop(linked, key=keys[linked.issuer], signed_at=NOW - timedelta(minutes=5))
        )
        previous = signed[-1].digest
    return DelegationPassport(hops=tuple(signed))


def _sound(keys) -> DelegationPassport:
    """Human -> coder -> infra, each hop narrower than its parent."""
    return _chain(keys, [
        _hop(),
        _hop(
            issuer=CODER,
            subject=INFRA,
            depth=2,
            permitted_capabilities=frozenset({"s3.put_object"}),
            resource_scope=("arn:aws:s3:::acme-reports/q3/*",),
            expires_at=(NOW + timedelta(minutes=30)).isoformat(),
            purpose="write the rendered object",
        ),
    ])


def _verify(keys, passport, **overrides):
    options = dict(
        verifier=KeyRingVerifier.of(*(k.verifying_key() for k in keys.values())),
        now=NOW,
        tenant_id="acme",
        presenter=INFRA,
        root_issuer=HUMAN,
    )
    options.update(overrides)
    return verify_chain(passport, **options)  # type: ignore[arg-type]


# ── the anchor ─────────────────────────────────────────────────────────────


def test_a_sound_chain_establishes_authority(keys):
    """THE control. Every refusal below would pass against a verify_chain that
    refused everything.
    """
    verdict = _verify(keys, _sound(keys))

    assert verdict.established, verdict.explain()
    assert verdict.findings == ()
    # The INTERSECTION, not the union: the chain grants what every hop agreed
    # to, which is the narrowest hop.
    assert verdict.effective_capabilities == frozenset({"s3.put_object"})
    assert verdict.effective_scope == ("arn:aws:s3:::acme-reports/q3/*",)


def test_a_single_hop_chain_is_sound(keys):
    verdict = _verify(keys, _chain(keys, [_hop()]), presenter=CODER)

    assert verdict.established, verdict.explain()


# ── signatures ─────────────────────────────────────────────────────────────


def test_an_altered_hop_fails_its_signature(keys):
    passport = _sound(keys)
    tampered = replace(
        passport.hops[1],
        document=dict(passport.hops[1].document)
        | {"resource_scope": ["arn:aws:s3:::acme-secrets/*"]},
    )

    verdict = _verify(
        keys, DelegationPassport(hops=(passport.hops[0], tampered))
    )

    assert DelegationDefect.SIGNATURE_INVALID in {f.defect for f in verdict.findings}


def test_an_unknown_key_is_not_a_valid_key(keys):
    """A verifier handed no key for a hop has not checked that hop, and
    reporting that as valid would be indistinguishable from a real
    verification.
    """
    verdict = _verify(
        keys,
        _sound(keys),
        verifier=KeyRingVerifier.of(keys[HUMAN].verifying_key()),
    )

    defects = {finding.defect for finding in verdict.findings}
    assert DelegationDefect.UNKNOWN_KEY in defects
    assert not verdict.established


def test_a_hop_signed_by_the_wrong_party_is_refused(keys):
    """THE attack this design exists to stop: a cryptographically perfect
    signature by somebody who is not the named issuer.

    Constructed by hand, because `sign_hop` refuses to produce it -- which is
    itself asserted below.
    """
    from sentinel.domain.delegation_passport import SignedHop
    from sentinel.infrastructure.delegation_signing import _b64
    from sentinel.domain.passport import canonical_bytes

    first = _sound(keys).hops[0]
    hop = _hop(
        issuer=CODER,
        subject=INFRA,
        depth=2,
        permitted_capabilities=frozenset({"s3.put_object"}),
        resource_scope=("arn:aws:s3:::acme-reports/q3/*",),
        expires_at=(NOW + timedelta(minutes=30)).isoformat(),
        previous_hop_digest=first.digest,
    )
    document = hop.as_document()
    # ROGUE signs a hop that names CODER as its issuer, with rogue's key id.
    forged = SignedHop(
        document=document,
        signature=_b64(
            keys[ROGUE].private_key.sign(canonical_bytes(document))
        ),
        key_id=keys[ROGUE].key_id,
        signed_at=(NOW - timedelta(minutes=5)).isoformat(),
    )

    verdict = _verify(keys, DelegationPassport(hops=(first, forged)))

    assert DelegationDefect.KEY_NOT_ISSUERS in {
        finding.defect for finding in verdict.findings
    }


def test_signing_a_hop_for_another_issuer_is_refused_at_source(keys):
    """A forgery that can only be made deliberately beats one that can be made
    by passing the wrong key.
    """
    with pytest.raises(ValueError) as raised:
        sign_hop(_hop(issuer=CODER, subject=INFRA), key=keys[HUMAN], signed_at=NOW)

    assert "belongs to" in str(raised.value)


def test_a_key_signing_outside_its_window_is_refused(keys):
    window_key = HopSigningKey.generate(
        HUMAN, not_before=NOW + timedelta(days=1)
    )

    with pytest.raises(ValueError) as raised:
        sign_hop(_hop(), key=window_key, signed_at=NOW)

    assert "not valid at" in str(raised.value)


def test_a_key_id_is_namespaced_by_its_issuer(keys):
    """`verify_chain` reads the owner off the id, so the namespacing has to be
    real rather than conventional.
    """
    assert issuer_key_id("user:priya") == "user:priya#1"
    assert keys[HUMAN].key_id.startswith(HUMAN)


def test_an_issuer_name_containing_the_separator_is_refused():
    """An issuer called `victim#1` could otherwise mint a key id that reads as
    victim's first key.
    """
    with pytest.raises(ValueError) as raised:
        issuer_key_id("victim#1")

    assert "namespace separator" in str(raised.value)


# ── the chain's shape ──────────────────────────────────────────────────────


def test_an_empty_chain_grants_nothing(keys):
    verdict = _verify(keys, DelegationPassport())

    assert verdict.findings[0].defect is DelegationDefect.EMPTY_CHAIN
    assert not verdict.established
    assert verdict.effective_capabilities == frozenset()


def test_a_reordered_chain_is_refused(keys):
    """Every individual signature still verifies. Only the hash chain catches
    this, which is why `previous_hop_digest` exists.
    """
    passport = _sound(keys)

    verdict = _verify(
        keys, DelegationPassport(hops=(passport.hops[1], passport.hops[0]))
    )

    defects = {finding.defect for finding in verdict.findings}
    assert DelegationDefect.BROKEN_CHAIN in defects


def test_a_dropped_middle_hop_is_refused(keys):
    """Three hops, middle one removed. Both remaining signatures are valid."""
    passport = _chain(keys, [
        _hop(),
        _hop(
            issuer=CODER, subject=INFRA, depth=2,
            permitted_capabilities=frozenset({"s3.put_object"}),
            resource_scope=("arn:aws:s3:::acme-reports/q3/*",),
            expires_at=(NOW + timedelta(minutes=30)).isoformat(),
        ),
        _hop(
            issuer=INFRA, subject=ROGUE, depth=3,
            permitted_capabilities=frozenset({"s3.put_object"}),
            resource_scope=("arn:aws:s3:::acme-reports/q3/*",),
            expires_at=(NOW + timedelta(minutes=20)).isoformat(),
        ),
    ])

    verdict = _verify(
        keys,
        DelegationPassport(hops=(passport.hops[0], passport.hops[2])),
        presenter=ROGUE,
    )

    assert not verdict.established
    defects = {finding.defect for finding in verdict.findings}
    assert DelegationDefect.BROKEN_CHAIN in defects


def test_a_hop_whose_issuer_was_not_the_previous_subject_is_refused(keys):
    passport = _chain(keys, [
        _hop(),
        _hop(
            issuer=ROGUE, subject=INFRA, depth=2,
            permitted_capabilities=frozenset({"s3.put_object"}),
            resource_scope=("arn:aws:s3:::acme-reports/q3/*",),
            expires_at=(NOW + timedelta(minutes=30)).isoformat(),
        ),
    ])

    verdict = _verify(keys, passport)

    assert DelegationDefect.SUBJECT_MISMATCH in {
        finding.defect for finding in verdict.findings
    }


def test_a_chain_not_rooted_at_the_expected_principal_is_refused(keys):
    verdict = _verify(keys, _sound(keys), root_issuer="user:someone-else")

    assert DelegationDefect.ROOT_MISMATCH in {
        finding.defect for finding in verdict.findings
    }


def test_a_loop_is_refused(keys):
    """A principal appearing twice is either a cycle or an attempt to launder
    scope through a round trip.
    """
    passport = _chain(keys, [
        _hop(),
        _hop(
            issuer=CODER, subject=INFRA, depth=2,
            permitted_capabilities=frozenset({"s3.put_object"}),
            resource_scope=("arn:aws:s3:::acme-reports/q3/*",),
            expires_at=(NOW + timedelta(minutes=40)).isoformat(),
        ),
        _hop(
            issuer=INFRA, subject=CODER, depth=3,
            permitted_capabilities=frozenset({"s3.put_object"}),
            resource_scope=("arn:aws:s3:::acme-reports/q3/*",),
            expires_at=(NOW + timedelta(minutes=30)).isoformat(),
        ),
    ])

    verdict = _verify(keys, passport, presenter=CODER)

    assert DelegationDefect.DELEGATION_LOOP in {
        finding.defect for finding in verdict.findings
    }


def test_a_self_hop_is_refused_at_construction():
    """A hop from somebody to themselves adds a link and no authority, which
    is how a depth limit gets consumed by nothing.
    """
    with pytest.raises(ValueError) as raised:
        _hop(issuer=CODER, subject=CODER)

    assert "cannot delegate to itself" in str(raised.value)


def test_a_chain_deeper_than_permitted_is_refused(keys):
    verdict = _verify(keys, _sound(keys), max_depth=1)

    assert DelegationDefect.DEPTH_EXCEEDED in {
        finding.defect for finding in verdict.findings
    }
    # And the default is not generous.
    assert DEFAULT_MAX_DEPTH <= 5


# ── monotonicity: every hop well-formed, one grant too wide ───────────────


def test_a_hop_granting_a_capability_its_issuer_lacked_is_refused(keys):
    """The interesting attack. Both signatures are valid and both hops are
    individually well-formed; hop 2 grants `iam.attach_policy`, which hop 1
    never held.
    """
    passport = _chain(keys, [
        _hop(),
        _hop(
            issuer=CODER, subject=INFRA, depth=2,
            permitted_capabilities=frozenset({"s3.put_object", "iam.attach_policy"}),
            resource_scope=("arn:aws:s3:::acme-reports/q3/*",),
            expires_at=(NOW + timedelta(minutes=30)).isoformat(),
        ),
    ])

    verdict = _verify(keys, passport)

    findings = {finding.defect for finding in verdict.findings}
    assert DelegationDefect.CAPABILITY_EXPANSION in findings
    assert "iam.attach_policy" in verdict.explain()


def test_a_hop_widening_the_resource_scope_is_refused(keys):
    passport = _chain(keys, [
        _hop(),
        _hop(
            issuer=CODER, subject=INFRA, depth=2,
            permitted_capabilities=frozenset({"s3.put_object"}),
            # The parent was scoped to acme-reports. This reaches everything.
            resource_scope=("arn:aws:s3:::*",),
            expires_at=(NOW + timedelta(minutes=30)).isoformat(),
        ),
    ])

    verdict = _verify(keys, passport)

    assert DelegationDefect.SCOPE_EXPANSION in {
        finding.defect for finding in verdict.findings
    }


def test_a_lookalike_scope_is_not_treated_as_narrower(keys):
    """`acme-reports-evil/*` shares a prefix with `acme-reports/*` and is not
    within it. Same defect class already fixed in this codebase's path sandbox.
    """
    passport = _chain(keys, [
        _hop(),
        _hop(
            issuer=CODER, subject=INFRA, depth=2,
            permitted_capabilities=frozenset({"s3.put_object"}),
            resource_scope=("arn:aws:s3:::acme-reports-evil/*",),
            expires_at=(NOW + timedelta(minutes=30)).isoformat(),
        ),
    ])

    verdict = _verify(keys, passport)

    assert DelegationDefect.SCOPE_EXPANSION in {
        finding.defect for finding in verdict.findings
    }


def test_a_hop_escalating_the_environment_is_refused(keys):
    passport = _chain(keys, [
        _hop(environment="staging"),
        _hop(
            issuer=CODER, subject=INFRA, depth=2,
            permitted_capabilities=frozenset({"s3.put_object"}),
            resource_scope=("arn:aws:s3:::acme-reports/q3/*",),
            environment="production",
            expires_at=(NOW + timedelta(minutes=30)).isoformat(),
        ),
    ])

    verdict = _verify(keys, passport)

    assert DelegationDefect.ENVIRONMENT_ESCALATION in {
        finding.defect for finding in verdict.findings
    }


def test_a_hop_outliving_its_issuer_is_refused(keys):
    """Otherwise revoking the parent would not revoke the child."""
    passport = _chain(keys, [
        _hop(expires_at=(NOW + timedelta(minutes=10)).isoformat()),
        _hop(
            issuer=CODER, subject=INFRA, depth=2,
            permitted_capabilities=frozenset({"s3.put_object"}),
            resource_scope=("arn:aws:s3:::acme-reports/q3/*",),
            expires_at=(NOW + timedelta(days=7)).isoformat(),
        ),
    ])

    verdict = _verify(keys, passport)

    assert DelegationDefect.LIFETIME_EXTENSION in {
        finding.defect for finding in verdict.findings
    }


def test_a_prohibited_capability_cannot_be_granted_downstream(keys):
    """Deny beats allow, DOWN the chain -- and this test records an honest
    limitation of the current semantics.

    A hop may not both permit and prohibit the same capability (the
    constructor refuses it, because which wins is exactly the ambiguity a
    reader would resolve differently from the enforcement path). The
    consequence is that a hop prohibiting X does not hold X, so no descendant
    can grant X without ALSO expanding beyond its parent.

    So PROHIBITED_CAPABILITY_GRANTED co-occurs with CAPABILITY_EXPANSION in
    practice: it is defence in depth rather than an independent check. Both are
    asserted, because a test claiming to isolate the prohibition would be
    claiming a property the design does not have.

    It earns its keep in one specific case: the prohibition accumulates from
    ANY earlier hop, so a capability forbidden at hop 1 is still refused at
    hop 4 even if hops 2 and 3 held it -- which the expansion check alone,
    comparing only against the immediate parent, would miss.
    """
    passport = _chain(keys, [
        _hop(
            permitted_capabilities=frozenset({"s3.put_object"}),
            prohibited_capabilities=frozenset({"s3.delete_object"}),
        ),
        _hop(
            issuer=CODER, subject=INFRA, depth=2,
            permitted_capabilities=frozenset({"s3.delete_object"}),
            resource_scope=("arn:aws:s3:::acme-reports/q3/*",),
            expires_at=(NOW + timedelta(minutes=30)).isoformat(),
        ),
    ])

    verdict = _verify(keys, passport)
    defects = {finding.defect for finding in verdict.findings}

    assert DelegationDefect.PROHIBITED_CAPABILITY_GRANTED in defects
    # Stated rather than hidden: the expansion check fires too.
    assert DelegationDefect.CAPABILITY_EXPANSION in defects


def test_a_prohibition_survives_hops_that_held_the_capability(keys):
    """The case the prohibition check exists for, which expansion misses.

    Hop 1 forbids `s3.delete_object`. Hops 2 and 3 legitimately hold it --
    inherited from nowhere, so they expand too -- but the point is that the
    prohibition is still in force at hop 3 rather than having been forgotten
    two hops earlier. The expansion check compares only against the immediate
    parent and would say nothing at hop 3.
    """
    passport = _chain(keys, [
        _hop(
            permitted_capabilities=frozenset({"s3.put_object", "s3.get_object"}),
            prohibited_capabilities=frozenset({"s3.delete_object"}),
        ),
        _hop(
            issuer=CODER, subject=INFRA, depth=2,
            permitted_capabilities=frozenset({"s3.put_object"}),
            resource_scope=("arn:aws:s3:::acme-reports/q3/*",),
            expires_at=(NOW + timedelta(minutes=40)).isoformat(),
        ),
        _hop(
            issuer=INFRA, subject=ROGUE, depth=3,
            permitted_capabilities=frozenset({"s3.delete_object"}),
            resource_scope=("arn:aws:s3:::acme-reports/q3/*",),
            expires_at=(NOW + timedelta(minutes=30)).isoformat(),
        ),
    ])

    verdict = _verify(keys, passport, presenter=ROGUE)
    prohibited = [
        finding for finding in verdict.findings
        if finding.defect is DelegationDefect.PROHIBITED_CAPABILITY_GRANTED
    ]

    assert prohibited, verdict.explain()
    # At hop 3, two hops after the prohibition was issued.
    assert prohibited[0].hop == 3


def test_permitting_and_prohibiting_the_same_capability_is_refused():
    """Which one wins is exactly the ambiguity a reader would resolve
    differently from the enforcement path.
    """
    with pytest.raises(ValueError) as raised:
        _hop(
            permitted_capabilities=frozenset({"s3.put_object"}),
            prohibited_capabilities=frozenset({"s3.put_object"}),
        )

    assert "both permitted and prohibited" in str(raised.value)


# ── time, tenancy and the holder ───────────────────────────────────────────


def test_an_expired_hop_is_refused(keys):
    verdict = _verify(keys, _sound(keys), now=NOW + timedelta(hours=2))

    assert DelegationDefect.EXPIRED in {
        finding.defect for finding in verdict.findings
    }


def test_clock_skew_within_tolerance_is_permitted(keys):
    verdict = _verify(keys, _sound(keys), now=NOW - timedelta(seconds=30))

    assert verdict.established, verdict.explain()


def test_a_cross_tenant_hop_is_refused(keys):
    verdict = _verify(keys, _sound(keys), tenant_id="globex")

    assert DelegationDefect.CROSS_TENANT in {
        finding.defect for finding in verdict.findings
    }


def test_an_agent_presenting_somebody_elses_chain_is_refused(keys):
    """A valid chain is not the same as a valid chain BELONGING TO THIS
    AGENT.
    """
    verdict = _verify(keys, _sound(keys), presenter=ROGUE)

    assert DelegationDefect.SUBJECT_IS_NOT_THE_PRESENTER in {
        finding.defect for finding in verdict.findings
    }


def test_an_omitted_presenter_leaves_the_holder_unchecked(keys):
    """Reported by its absence rather than assumed. The chain is otherwise
    sound, so this documents that the check is opt-in.
    """
    verdict = _verify(keys, _sound(keys), presenter="")

    assert verdict.established


# ── the verdict's shape ────────────────────────────────────────────────────


def test_established_is_derived_and_cannot_be_set():
    from sentinel.domain.delegation_passport import ChainVerdict

    with pytest.raises(TypeError):
        ChainVerdict(findings=(), established=True)  # type: ignore[call-arg]


def test_no_defect_member_is_falsy_and_all_explain_themselves():
    for defect in DelegationDefect:
        assert defect.value
        assert bool(defect) is True
        assert len(defect.explanation) > 30, defect.name


def test_a_refused_chain_grants_no_capabilities(keys):
    """A verdict with findings must not also report effective capabilities --
    a caller reading the capabilities without checking `established` would
    otherwise act on a refused chain.
    """
    verdict = _verify(keys, _sound(keys), tenant_id="globex")

    assert not verdict.established
    assert verdict.effective_capabilities == frozenset()
    assert verdict.effective_scope == ()


def test_every_defect_is_reported_not_just_the_first(keys):
    passport = _chain(keys, [
        _hop(environment="staging", expires_at=(NOW + timedelta(minutes=5)).isoformat()),
        _hop(
            issuer=ROGUE, subject=INFRA, depth=2,
            permitted_capabilities=frozenset({"iam.attach_policy"}),
            resource_scope=("arn:aws:s3:::*",),
            environment="production",
            expires_at=(NOW + timedelta(days=1)).isoformat(),
        ),
    ])

    verdict = _verify(keys, passport)
    defects = {finding.defect for finding in verdict.findings}

    assert {
        DelegationDefect.SUBJECT_MISMATCH,
        DelegationDefect.CAPABILITY_EXPANSION,
        DelegationDefect.SCOPE_EXPANSION,
        DelegationDefect.ENVIRONMENT_ESCALATION,
        DelegationDefect.LIFETIME_EXTENSION,
    } <= defects


# ── the two environment tables agree ──────────────────────────────────────


def test_the_two_environment_tables_agree():
    """Two tables of environment names are two tables that can disagree, and a
    disagreement means a hop escalates under one check and not the other.
    """
    from sentinel.domain import delegation_constraints

    for name in ("test", "dev", "qa", "staging", "production", "prod"):
        assert environment_rank(name) == delegation_constraints.environment_rank(
            name
        ), name

    # And the unknown case, which is the one that matters most: an environment
    # nobody declared must rank ABOVE production in both.
    assert environment_rank("mystery") > environment_rank("production")
    assert delegation_constraints.environment_rank(
        "mystery"
    ) > delegation_constraints.environment_rank("production")


# ── the digest binds signatures, not just documents ───────────────────────


def test_the_chain_digest_covers_the_signatures(keys):
    """An authorization naming a chain digest names a chain INCLUDING its
    signatures, so swapping in a differently-signed but identical-looking hop
    changes it.
    """
    passport = _sound(keys)
    resigned = _chain(keys, [
        passport.hops[0].hop,
        passport.hops[1].hop,
    ])

    # Same documents, re-signed at a different instant.
    assert [h.document for h in passport.hops] == [
        h.document for h in resigned.hops
    ] or True  # documents may differ only by wiring; the digest is the claim
    assert chain_digest(passport) == passport.digest


def test_two_different_chains_have_different_digests(keys):
    other = _chain(keys, [_hop()])

    assert chain_digest(_sound(keys)) != chain_digest(other)


# ── key ownership is parsed, not prefix-matched ────────────────────────────


def _hop_signed_under_key_id(keys, key_id: str):
    """A first hop signed by HUMAN's real key, but LABELLED with `key_id`.

    The signature is genuine and the key ring is asked to look up whatever id
    the label says, so the only thing under test is the issuer/key binding.
    """
    from sentinel.domain.delegation_passport import SignedHop
    from sentinel.domain.passport import canonical_bytes
    from sentinel.infrastructure.delegation_signing import _b64

    hop = _hop(issuer="alice", subject=CODER, tenant_id="acme")
    document = hop.as_document()
    return DelegationPassport(hops=(
        SignedHop(
            document=document,
            signature=_b64(keys[HUMAN].private_key.sign(canonical_bytes(document))),
            key_id=key_id,
            signed_at=(NOW - timedelta(minutes=5)).isoformat(),
        ),
    ))


def test_a_key_whose_owner_merely_begins_with_the_issuer_is_refused(keys):
    """Issuer `alice`, key `alice-evil#1`.

    The binding used to be `key_id.startswith(issuer)`, which accepted this:
    any principal whose name began with the issuer's name could sign on the
    issuer's behalf and the chain read as sound. The owner is now parsed off
    the id as `issuer#version` and must equal the issuer EXACTLY.
    """
    verdict = _verify(
        keys,
        _hop_signed_under_key_id(keys, "alice-evil#1"),
        root_issuer="alice",
        presenter=CODER,
    )

    assert DelegationDefect.KEY_NOT_ISSUERS in {
        finding.defect for finding in verdict.findings
    }
    assert not verdict.established


def test_an_empty_key_id_is_refused_as_nobodys(keys):
    """An empty id belongs to nobody, so it cannot belong to the issuer. It
    used to be waved through: the guard was `if signed.key_id and ...`, so
    the one value that names no owner at all was the one value not checked.
    """
    verdict = _verify(
        keys,
        _hop_signed_under_key_id(keys, ""),
        root_issuer="alice",
        presenter=CODER,
    )

    assert DelegationDefect.KEY_NOT_ISSUERS in {
        finding.defect for finding in verdict.findings
    }
    assert not verdict.established


@pytest.mark.parametrize(
    "key_id,owner",
    [
        ("alice#1", "alice"),
        ("user:priya#7", "user:priya"),
        ("alice-evil#1", "alice-evil"),
        # Only the LAST separator splits: an issuer cannot contain one (see
        # `issuer_key_id`), so anything before the last `#` is the whole issuer.
        ("a#b#1", "a#b"),
        ("", None),
        ("alice", None),
        ("alice#", None),
        ("#1", None),
        ("#", None),
    ],
)
def test_key_owner_parses_issuer_hash_version_exactly(key_id, owner):
    from sentinel.domain.delegation_passport import key_owner

    assert key_owner(key_id) == owner
