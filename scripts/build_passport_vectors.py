"""Generate the conformance corpus.

Digests are COMPUTED by the reference implementation, never typed. A hand-typed
digest in a conformance vector is a number nobody can check that every
implementation is then required to agree with.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel.domain.passport import digest_of  # noqa: E402

VECTORS = ROOT / "standard" / "execution-passport-v1" / "vectors" / "canonical"

VALID = {
    "schema": "sentinel.execution_passport.v1",
    "execution_id": "exec-7f3a",
    "tenant_id": "acme",
    "occurred_at": "2026-09-03T12:00:00+00:00",
    "previous_passport_digest": "",
    "parent_execution_id": "",
    "session_id": "sess-1",
    "human_principal": "user:priya",
    "agent_id": "agent:infra-writer",
    "agent_instance": "i-04",
    "agent_version": "2.1.0",
    "agent_framework": "langgraph",
    "model_identity": "claude-opus-5",
    "delegation_chain": [
        {"issuer": "user:priya", "subject": "agent:infra-writer", "depth": 1}
    ],
    "mcp_server_id": "mcp:aws-prod",
    "mcp_server_fingerprint": "b" * 64,
    "tool_name": "s3.put_object",
    "tool_definition_fingerprint": "c" * 64,
    "skill_ids": [],
    "credential_id": "cred:ci-role",
    "action": "s3:PutObject",
    "action_semantics": {"class": "data_write"},
    "resource": "arn:aws:s3:::acme-reports/q3/summary.pdf",
    "environment": "production",
    "data_classifications": ["internal"],
    "destination": "",
    "policy_id": "pol-baseline",
    "policy_version": "14",
    "policy_digest": "d" * 64,
    "decision": "allow",
    "risk_score": 12,
    "risk_reasons": [],
    "approval_required": False,
    "approval_actor": "",
    "approval_at": "",
    "idempotency_key": "idem-9",
    "execution_fence": "fence-3",
    "outcome": "succeeded",
    "side_effect": "object_written",
    "evidence_digest": "e" * 64,
    "attestation_status": "attested",
    "attestation_reference": "https://transparency.example/1",
}

#: Every vector. `defects` is what BOTH implementations must report; `tolerate`
#: is what either may additionally report without disagreeing -- used for the
#: findings that depend on optional inputs the runner does not supply.
_ALWAYS = ["signature_unverified", "policy_unverified"]


def _write(directory: Path, name: str, why: str, document, defects, **extra):
    payload = {
        "name": name,
        "why": why,
        "document": document,
        "expect": {"defects": defects, "tolerate": _ALWAYS, **extra.pop("expect", {})},
    }
    payload.update(extra)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{name}.json").write_text(
        json.dumps(payload, indent=2, sort_keys=False, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    good = VECTORS / "valid"
    bad = VECTORS / "malicious"

    # ── valid ──────────────────────────────────────────────────────────────
    _write(
        good, "complete-passport",
        "The control. Every refusal vector below would pass against a verifier "
        "that rejected everything, so the corpus is worthless without this.",
        VALID, [], expect={"digest": digest_of(VALID)},
    )

    minimal = {field: VALID[field] for field in (
        "schema", "execution_id", "tenant_id", "occurred_at", "agent_id",
        "action", "decision",
    )}
    _write(
        good, "minimal-required-fields-only",
        "Only the six required fields. A passport recording what was actually "
        "known beats one that could not be written because a field nobody had "
        "was mandatory.",
        minimal, [], expect={"digest": digest_of(minimal)},
    )

    cyrillic = dict(VALID, agent_id="agent:Аркадий")
    _write(
        good, "non-ascii-emitted-not-escaped",
        "A Cyrillic agent name. Escaping it would give one name two "
        "representations differing only in escaping, and a canonical form with "
        "two representations is not one.",
        cyrillic, [], expect={"digest": digest_of(cyrillic)},
    )

    unknown = dict(VALID, some_future_field="value-an-older-verifier-never-saw")
    _write(
        good, "unknown-field-is-preserved-in-the-digest",
        "Forward compatibility and digest stability are the SAME requirement: "
        "a verifier that dropped unknown fields would compute a different "
        "digest than the signer did.",
        unknown, [], expect={"digest": digest_of(unknown)},
    )

    parent = dict(VALID, execution_id="exec-parent", previous_passport_digest="")
    child = dict(VALID, execution_id="exec-child",
                 previous_passport_digest=digest_of(parent))
    _write(
        good, "valid-parent-chain",
        "The child commits to the parent's DIGEST, not its id. An id says which "
        "record came before; a digest says what it said.",
        child, [], parents=[parent], expect={"digest": digest_of(child)},
    )

    # ── malicious ──────────────────────────────────────────────────────────
    _write(
        bad, "float-risk-score",
        "0.1 + 0.2 does not round-trip. A score serialising as "
        "96.00000000000001 on one runtime and 96.0 on another produces two "
        "signatures for one passport, and the failure surfaces a year later as "
        "two byte-different documents that both look correct.",
        dict(VALID, risk_score=96.5), ["not_canonical"],
    )

    _write(
        bad, "digest-does-not-match-document",
        "The document was altered after the digest was recorded. This is the "
        "base case every other tamper reduces to.",
        dict(VALID, resource="arn:aws:s3:::attacker-exfil/everything"),
        ["digest_mismatch"], expect={"digest": digest_of(VALID)},
    )

    _write(
        bad, "missing-required-field",
        "No agent_id. The document records that SOMETHING happened without "
        "attributing it to anybody, which is not evidence.",
        {k: v for k, v in VALID.items() if k != "agent_id"},
        ["missing_required_field"],
    )

    _write(
        bad, "empty-required-field",
        "agent_id present but blank. A presence check alone passes this, which "
        "is why the rule is 'absent OR empty'.",
        dict(VALID, agent_id="   "), ["missing_required_field"],
    )

    orphan = dict(VALID, previous_passport_digest="f" * 64)
    _write(
        bad, "parent-commitment-with-no-parent-supplied",
        "Commits to a parent nobody can produce. Must report that the chain is "
        "unverified rather than treating an uncheckable claim as satisfied.",
        orphan, ["parent_unverified"], expect={"digest": digest_of(orphan)},
    )

    real_parent = dict(VALID, execution_id="exec-parent-2")
    edited_parent = dict(real_parent, decision="deny")
    forged_child = dict(VALID, execution_id="exec-child-2",
                        previous_passport_digest=digest_of(real_parent))
    _write(
        bad, "parent-edited-after-being-committed-to",
        "The chain LOOKS intact -- the child names a digest and a parent is "
        "supplied -- but the parent's content was changed afterwards, so it no "
        "longer hashes to what was committed. This is the attack that using an "
        "id instead of a digest would permit entirely.",
        forged_child, ["parent_digest_mismatch"], parents=[edited_parent],
        expect={"digest": digest_of(forged_child)},
    )

    _write(
        bad, "attestation-names-a-different-passport",
        "A real attestation, over somebody else's passport, attached to this "
        "one. Verifying the attestation's own signature would succeed.",
        VALID, ["attestation_mismatch"],
        expect={"digest": digest_of(VALID), "attestation_digest": "a" * 64},
    )

    nested_float = dict(VALID, action_semantics={"class": "data_write",
                                                 "confidence": 0.87})
    _write(
        bad, "float-nested-deep-in-an-object",
        "The float is two levels down, not in an obvious numeric field. A "
        "top-level type check misses this and the document then has two "
        "serialisations.",
        nested_float, ["not_canonical"],
    )

    array_float = dict(VALID, risk_reasons=[1, 2, 3.5])
    _write(
        bad, "float-inside-an-array",
        "Same failure reached through a list. The canonicaliser has to walk "
        "arrays as well as objects.",
        array_float, ["not_canonical"],
    )

    _write(
        bad, "integer-beyond-the-json-safe-range",
        "Past 2^53 an IEEE-754 double cannot hold the value exactly, so the "
        "document round-trips to a DIFFERENT number and its digest changes in a "
        "verifier the issuer does not control. Python has arbitrary-precision "
        "integers and accepted this happily until verify.mjs refused it -- the "
        "one real disagreement the second implementation found, and the reason "
        "to have written it. Both refuse it now.",
        dict(VALID, risk_score=2**53 + 1), ["not_canonical"],
    )

    _write(
        good, "integer-at-the-exact-safe-boundary",
        "2^53 - 1 is representable and MUST be accepted. Without this the "
        "bound above could be implemented as a much smaller limit, or as "
        "refusing all large integers, and every test would still pass.",
        dict(VALID, risk_score=2**53 - 1), [],
        expect={"digest": digest_of(dict(VALID, risk_score=2**53 - 1))},
    )

    print(f"wrote {len(list(VECTORS.rglob('*.json')))} vectors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
