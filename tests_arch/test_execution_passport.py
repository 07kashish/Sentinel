"""The Execution Passport: evidence for somebody who does not trust Sentinel.

WHAT MAKES THIS DIFFERENT FROM EVERY OTHER RECORD HERE
--------------------------------------------------------
Incidents, evidence and the ledger answer questions for Sentinel. A passport
answers questions for an auditor, a customer's security team, or the other side
of an incident — people whose whole position is that Sentinel's word is not
enough.

That gives the tests one organising constraint: **verification must need nothing
but a public key**. `test_verification_opens_no_database_and_makes_no_call` is
the test that keeps it true. A verifier that has to ask Sentinel whether a
passport is genuine is a verifier that trusts Sentinel, which is exactly the
trust the artifact exists to remove.

WHY CANONICALISATION GETS SO MANY TESTS
-----------------------------------------
A signature is over bytes. If two honest implementations serialise the same
passport differently, neither can verify the other and the format is useless as
an interchange standard. Floats, unicode escaping and null-dropping are the
three places JSON leaves that open, and each has a test.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from sentinel.domain.passport import (
    PASSPORT_SCHEMA,
    ExecutionPassport,
    PassportDefect,
    canonical_bytes,
    digest_of,
    verify_structure,
)
from sentinel.infrastructure.passport_signing import (
    SignedPassport,
    SigningKey,
    sign,
    verify,
)

NOW = datetime(2026, 8, 31, 12, 0, 0, tzinfo=timezone.utc)


def _passport(**overrides) -> ExecutionPassport:
    base = {
        "execution_id": "exec-1",
        "tenant_id": "acme",
        "occurred_at": NOW.isoformat(),
        "human_principal": "alice",
        "agent_id": "finance-agent",
        "action": "SELECT * FROM customers",
        "resource": "db://customers",
        "decision": "block",
        "risk_score": 96,
        "policy_digest": "p" * 64,
        "tool_definition_fingerprint": "t" * 64,
        "delegation_chain": (
            {"from_agent": "alice", "to_agent": "finance-agent"},
        ),
    }
    base.update(overrides)
    return ExecutionPassport(**base)


def _defects(findings) -> set[PassportDefect]:
    return {f.defect for f in findings}


# ── canonical serialisation: the crux ────────────────────────────────────────


def test_the_same_passport_always_produces_the_same_bytes():
    assert canonical_bytes(_passport().as_document()) == canonical_bytes(
        _passport().as_document()
    )


def test_key_order_does_not_change_the_bytes():
    """Two implementations building the document in different orders must sign
    identical bytes, or neither can verify the other.
    """
    document = _passport().as_document()
    shuffled = dict(reversed(list(document.items())))
    assert canonical_bytes(document) == canonical_bytes(shuffled)


def test_a_float_is_refused_with_the_field_that_carries_it():
    """`0.1 + 0.2` does not round-trip. A score serialising as
    96.00000000000001 on one platform and 96.0 on another gives one passport two
    signatures — so the failure lands on whoever WRITES it, with a path.
    """
    with pytest.raises(ValueError, match=r"risk\b.*float|float"):
        canonical_bytes({"risk": 0.1 + 0.2})


def test_non_ascii_is_not_escaped():
    """Escaping gives a Cyrillic agent name two representations differing only
    in escaping, and a canonical form with two representations is not one.
    """
    raw = canonical_bytes({"agent": "аналитик"})
    assert "аналитик".encode("utf-8") in raw
    assert b"\\u" not in raw


def test_null_is_serialised_rather_than_dropped():
    """An absent field and a field explicitly unknown are different claims. A
    canonicaliser that dropped nulls would collapse them into one signature.
    """
    assert canonical_bytes({"a": None}) != canonical_bytes({})


def test_an_unserialisable_type_is_refused_rather_than_stringified():
    with pytest.raises(ValueError, match="no canonical JSON form"):
        canonical_bytes({"when": NOW})


# ── signature ────────────────────────────────────────────────────────────────


def test_a_clean_passport_verifies():
    key = SigningKey.generate("k1")
    signed = sign(_passport(), key=key, signed_at=NOW)
    assert verify(signed, key=key.verifying_key()) == ()


def test_one_altered_field_breaks_the_signature():
    key = SigningKey.generate("k1")
    signed = sign(_passport(), key=key, signed_at=NOW)
    tampered = dict(signed.document)
    tampered["decision"] = "allow"

    findings = verify(
        SignedPassport(
            document=tampered,
            signature=signed.signature,
            key_id=signed.key_id,
            signed_at=signed.signed_at,
        ),
        key=key.verifying_key(),
    )
    assert PassportDefect.MODIFIED in _defects(findings)


def test_a_different_key_proves_nothing_about_this_document():
    key, other = SigningKey.generate("k1"), SigningKey.generate("k2")
    signed = sign(_passport(), key=key, signed_at=NOW)
    assert PassportDefect.MODIFIED in _defects(
        verify(signed, key=other.verifying_key())
    )


def test_a_broken_signature_stops_structural_reporting():
    """Once the bytes are untrustworthy, every field read out of them is a claim
    by whoever altered it. Listing those as findings dresses attacker input as
    analysis.
    """
    key = SigningKey.generate("k1")
    signed = sign(_passport(), key=key, signed_at=NOW)
    tampered = dict(signed.document)
    tampered["agent_id"] = ""  # would otherwise report INCOMPLETE too

    findings = verify(
        SignedPassport(
            document=tampered,
            signature=signed.signature,
            key_id=signed.key_id,
            signed_at=signed.signed_at,
        ),
        key=key.verifying_key(),
    )
    assert _defects(findings) == {PassportDefect.MODIFIED}


# ── key validity: the "expired certificate" case ─────────────────────────────


def test_signing_with_an_out_of_window_key_is_refused_at_signing_time():
    key = SigningKey.generate("k1", not_after=NOW - timedelta(days=1))
    with pytest.raises(ValueError, match="not valid at"):
        sign(_passport(), key=key, signed_at=NOW)


def test_a_signature_timestamped_outside_the_key_window_is_reported():
    """Cryptographically perfect, evidentially worthless: the key had been
    retired when this claims to have been signed.
    """
    key = SigningKey.generate("k1")
    signed = sign(_passport(), key=key, signed_at=NOW)
    retired = SigningKey.generate("k1").verifying_key()
    retired = type(retired)(
        key_id="k1",
        public_key=key.private_key.public_key(),
        not_after=NOW - timedelta(days=1),
    )
    assert PassportDefect.MODIFIED in _defects(verify(signed, key=retired))


def test_a_signing_key_and_its_verifying_key_agree_on_validity():
    """The window predicate is duplicated on both halves. This holds them equal
    so the duplication cannot drift.
    """
    key = SigningKey.generate(
        "k1", not_before=NOW - timedelta(days=1), not_after=NOW + timedelta(days=1)
    )
    public = key.verifying_key()
    for when in (NOW - timedelta(days=2), NOW, NOW + timedelta(days=2)):
        assert key.valid_at(when) == public.valid_at(when)


# ── lineage: a commitment, not a pointer ─────────────────────────────────────


def test_editing_a_parent_breaks_every_child_that_committed_to_it():
    """THE property that makes a chain evidence rather than a list."""
    parent = _passport(execution_id="exec-0")
    child = _passport(execution_id="exec-1", previous_passport_digest=parent.digest)

    edited = _passport(execution_id="exec-0", decision="allow")
    findings = verify_structure(child, parents={parent.digest: edited})
    assert PassportDefect.BROKEN_LINEAGE in _defects(findings)


def test_a_named_parent_that_was_not_supplied_is_reported():
    child = _passport(previous_passport_digest="a" * 64)
    assert PassportDefect.MISSING_PARENT in _defects(
        verify_structure(child, parents={})
    )


def test_no_parents_supplied_is_reported_rather_than_silently_skipped():
    """A verifier with no parents did not verify the chain. Saying nothing would
    read as having checked it.
    """
    child = _passport(previous_passport_digest="a" * 64)
    assert PassportDefect.MISSING_PARENT in _defects(verify_structure(child))


def test_a_root_passport_needs_no_parent():
    assert verify_structure(_passport()) == ()


# ── the comparisons a verifier may or may not be able to make ────────────────


def test_an_omitted_comparison_does_not_run_rather_than_passes():
    """A verifier with no policy digest to compare against must not report
    "policy verified". Absence of a check is not a passed check.
    """
    passport = _passport(policy_digest="")
    assert PassportDefect.POLICY_MISMATCH not in _defects(verify_structure(passport))


def test_a_policy_digest_mismatch_is_reported():
    assert PassportDefect.POLICY_MISMATCH in _defects(
        verify_structure(_passport(), expected_policy_digest="q" * 64)
    )


def test_a_tool_definition_that_changed_after_approval_is_reported():
    """What executed is not what was authorised — the rug pull, seen after the
    fact from the passport alone.
    """
    assert PassportDefect.TOOL_DEFINITION_CHANGED in _defects(
        verify_structure(_passport(), approved_tool_fingerprint="z" * 64)
    )


def test_an_attestation_naming_another_digest_is_reported():
    assert PassportDefect.ATTESTATION_MISMATCH in _defects(
        verify_structure(_passport(), attestation_digest="b" * 64)
    )


# ── delegation must actually connect ─────────────────────────────────────────


def test_a_chain_that_does_not_start_at_the_named_principal_is_invalid():
    """A passport can name a human, name an agent, and carry a chain connecting
    neither — which reads as full attribution and proves nothing.
    """
    findings = verify_structure(
        _passport(
            delegation_chain=({"from_agent": "mallory", "to_agent": "finance-agent"},)
        )
    )
    assert PassportDefect.DELEGATION_INVALID in _defects(findings)


def test_a_chain_that_does_not_end_at_the_acting_agent_is_invalid():
    findings = verify_structure(
        _passport(delegation_chain=({"from_agent": "alice", "to_agent": "other"},))
    )
    assert PassportDefect.DELEGATION_INVALID in _defects(findings)


def test_a_chain_with_a_gap_in_the_middle_is_invalid():
    findings = verify_structure(
        _passport(
            delegation_chain=(
                {"from_agent": "alice", "to_agent": "manager-agent"},
                {"from_agent": "SOMEONE-ELSE", "to_agent": "finance-agent"},
            )
        )
    )
    assert PassportDefect.DELEGATION_INVALID in _defects(findings)


def test_a_well_formed_multi_hop_chain_is_accepted():
    assert verify_structure(
        _passport(
            delegation_chain=(
                {"from_agent": "alice", "to_agent": "manager-agent"},
                {"from_agent": "manager-agent", "to_agent": "finance-agent"},
            )
        )
    ) == ()


# ── schema and completeness ──────────────────────────────────────────────────


def test_an_unrecognised_schema_is_refused_not_best_effort_parsed():
    """A verifier that guesses at an unknown version is one that can be told a
    field means something it does not.
    """
    document = _passport().as_document()
    document["schema"] = "sentinel.passport/v99"
    findings = verify_structure(_passport(), document=document)
    assert _defects(findings) == {PassportDefect.UNRECOGNISED_SCHEMA}


def test_a_passport_that_cannot_say_who_acted_is_incomplete():
    assert PassportDefect.INCOMPLETE in _defects(verify_structure(_passport(agent_id="")))


def test_every_defect_explains_itself():
    """"Invalid" is not actionable. A reader holding a passport needs to know
    which of ten things went wrong.
    """
    for defect in PassportDefect:
        assert len(defect.explanation) > 40, f"{defect} explains nothing"


# ── round trip and independence ──────────────────────────────────────────────


def test_a_signed_passport_survives_json_and_still_verifies():
    """The interchange case: written here, read somewhere else, verified there."""
    key = SigningKey.generate("k1")
    signed = sign(_passport(), key=key, signed_at=NOW)

    reloaded = SignedPassport.from_dict(json.loads(json.dumps(signed.as_dict())))
    assert verify(reloaded, key=key.verifying_key()) == ()


def test_unknown_fields_from_a_newer_version_are_dropped_not_rejected():
    """A v1 verifier can read the shared fields of a later passport. Refusing
    would make every schema addition a flag day.
    """
    document = _passport().as_document()
    document["some_future_field"] = "value"
    rebuilt = ExecutionPassport.from_document(document)
    assert rebuilt.execution_id == "exec-1"


def test_verification_opens_no_database_and_makes_no_call():
    """THE constraint. A verifier that must ask Sentinel is one that trusts
    Sentinel, which is the trust a passport exists to remove.
    """
    import inspect

    from sentinel.domain import passport as domain_module
    from sentinel.infrastructure import passport_signing

    for module in (domain_module, passport_signing):
        source = inspect.getsource(module)
        for forbidden in (
            "import requests",
            "urllib",
            "http.client",
            "psycopg",
            "socket",
            "os.environ",
        ):
            assert forbidden not in source, (
                f"{module.__name__} reaches for {forbidden!r}; verification must "
                "need nothing but a public key"
            )


def test_the_digest_is_stable_across_a_document_round_trip():
    passport = _passport()
    assert digest_of(passport.as_document()) == passport.digest
    assert ExecutionPassport.from_document(passport.as_document()).digest == passport.digest


def test_the_schema_constant_is_what_documents_declare():
    assert _passport().as_document()["schema"] == PASSPORT_SCHEMA


# ── the published schema must not drift from the code ────────────────────────


def test_the_published_schema_covers_every_field_the_code_writes():
    """A schema that omits a field is one an external implementer will not
    write, and their passport then fails to verify for a reason the schema does
    not mention. Derived from the dataclass, and checked here so a new field
    cannot land without the schema following it.
    """
    import dataclasses
    from pathlib import Path

    schema = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "docs"
            / "schema"
            / "execution-passport-v1.json"
        ).read_text(encoding="utf-8")
    )
    documented = set(schema["properties"]) - {"schema"}
    coded = {f.name for f in dataclasses.fields(ExecutionPassport)}
    assert coded == documented, (
        f"only in code: {sorted(coded - documented)}; "
        f"only in schema: {sorted(documented - coded)}"
    )


def test_the_published_schema_requires_what_the_verifier_requires():
    from pathlib import Path

    from sentinel.domain.passport import REQUIRED_FIELDS

    schema = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "docs"
            / "schema"
            / "execution-passport-v1.json"
        ).read_text(encoding="utf-8")
    )
    assert set(schema["required"]) == {"schema", *REQUIRED_FIELDS}


def test_the_schema_permits_unknown_fields_for_forward_compatibility():
    """Refusing them would make every schema addition a flag day for every
    external verifier.
    """
    from pathlib import Path

    schema = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "docs"
            / "schema"
            / "execution-passport-v1.json"
        ).read_text(encoding="utf-8")
    )
    assert schema["additionalProperties"] is True
    assert schema["properties"]["schema"]["const"] == PASSPORT_SCHEMA
