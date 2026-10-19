"""Two independent implementations must agree, or the format is not a standard.

WHAT THIS MODULE IS FOR
-----------------------
`standard/execution-passport-v1/verify_passport.py` was written from the
specification, not from `sentinel.domain.passport`. It shares no canonicaliser,
no constant and no helper with the producer.

That separation is only worth something if it is enforced and exercised:

  * ENFORCED -- an import of `sentinel` from the standard directory would
    quietly turn the second implementation back into the first, and every
    agreement below would become the producer agreeing with itself.

  * EXERCISED -- Sentinel signs, the independent verifier checks, and every
    tampering the specification says must be caught is actually caught.

WHY AGREEMENT IS THE INTERESTING RESULT
-----------------------------------------
Two implementations agreeing on a signature is evidence the canonical form is
unambiguous. A canonicaliser used by exactly one program cannot be wrong, in the
same way a language with one speaker cannot be misunderstood -- and that is the
condition an "open standard" is supposed to escape.

The properties that make the two agree are the ones a second implementer gets
wrong: sorted keys, no whitespace, unescaped non-ASCII, nulls kept, floats
refused. Each has a test below, driven through BOTH implementations.
"""

from __future__ import annotations

import ast
import base64
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel.domain.passport import ExecutionPassport, canonical_bytes
from sentinel.infrastructure.passport_signing import SigningKey, sign

ROOT = Path(__file__).resolve().parent.parent
STANDARD_DIR = ROOT / "standard" / "execution-passport-v1"
VERIFIER_PATH = STANDARD_DIR / "verify_passport.py"


def _load_independent_verifier():
    """Import the standard's verifier by path, not as part of the package.

    By path deliberately: an auditor copies this one file out of the repository
    and runs it. Importing it the way they would is the only way to notice that
    it had come to depend on sitting inside this tree.
    """
    spec = importlib.util.spec_from_file_location("_passport_std", VERIFIER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


std = _load_independent_verifier()


# ── the independence is real ─────────────────────────────────────────────────


def test_the_standard_verifier_imports_nothing_from_sentinel():
    """The property the whole module rests on.

    Checked by walking the AST for import statements rather than by scanning
    text: this file's own prose says the word "sentinel" many times, and a
    substring search would match the docstring that PROMISES the absence -- a
    test that passes because of the sentence claiming it passes.
    """
    tree = ast.parse(VERIFIER_PATH.read_text(encoding="utf-8"))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)

    offenders = [name for name in imported if name.split(".")[0] == "sentinel"]
    assert not offenders, (
        f"the standard's verifier imports {offenders} from the producer. Every "
        "agreement this module tests would then be Sentinel agreeing with "
        "itself, which proves nothing about the format."
    )


def test_the_standard_verifier_depends_only_on_stdlib_and_cryptography():
    """An auditor must be able to run it without installing this project."""
    allowed = {
        "argparse", "base64", "binascii", "hashlib", "json", "sys",
        "datetime", "pathlib", "typing", "__future__", "cryptography",
    }
    tree = ast.parse(VERIFIER_PATH.read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".")[0])
    assert roots <= allowed, f"unexpected dependencies: {sorted(roots - allowed)}"


# ── fixtures ─────────────────────────────────────────────────────────────────


WHEN = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def keypair():
    private = Ed25519PrivateKey.generate()
    signing = SigningKey(
        key_id="audit-key-1",
        private_key=private,
        not_before=WHEN - timedelta(days=1),
        not_after=WHEN + timedelta(days=1),
    )
    material = {
        "key_id": "audit-key-1",
        "public_key": base64.b64encode(
            private.public_key().public_bytes_raw()
        ).decode("ascii"),
        "not_before": (WHEN - timedelta(days=1)).isoformat(),
        "not_after": (WHEN + timedelta(days=1)).isoformat(),
    }
    return signing, material


def _passport(**overrides) -> ExecutionPassport:
    fields = {
        "execution_id": "exec-1",
        "tenant_id": "acme",
        "occurred_at": WHEN.isoformat(),
        "agent_id": "finance-agent",
        "action": "transfer_funds",
        "decision": "allowed",
    }
    fields.update(overrides)
    return ExecutionPassport(**fields)


# ── the two implementations agree ────────────────────────────────────────────


def test_sentinel_signs_and_the_independent_verifier_accepts(keypair):
    """The headline. A passport this project produced verifies under code that
    shares nothing with it.
    """
    signing, material = keypair
    payload = sign(_passport(), key=signing, signed_at=WHEN).as_dict()
    assert std.verify(payload, material) == []


def test_both_canonicalisers_produce_identical_bytes(keypair):
    """Byte-for-byte, not merely both-verify.

    Signatures agreeing could still hide a divergence that happens not to
    matter for this document. Comparing the bytes is the check that the
    canonical form is one thing.
    """
    document = _passport(
        risk_score=96,
        risk_reasons=["destination_unknown", "amount_above_ceiling"],
        human_principal=None,
    ).as_document()
    assert canonical_bytes(document) == std.canonical_bytes(document)


@pytest.mark.parametrize(
    "document",
    [
        # Non-ASCII: escaped and unescaped are two representations of one value,
        # and a canonical form with two representations is not one.
        {"schema": "sentinel.passport/v1", "agent_id": "агент-финансы"},
        # Explicit null differs from absence, so it must survive.
        {"schema": "sentinel.passport/v1", "human_principal": None},
        # Key order is not semantic.
        {"schema": "sentinel.passport/v1", "z": 1, "a": 2, "m": 3},
        # Nesting, where a shallow canonicaliser stops sorting.
        {"schema": "sentinel.passport/v1", "d": {"z": [{"b": 1, "a": 2}]}},
        # Empty containers.
        {"schema": "sentinel.passport/v1", "delegation_chain": [], "meta": {}},
    ],
)
def test_the_canonicalisers_agree_on_the_cases_implementers_get_wrong(document):
    assert canonical_bytes(document) == std.canonical_bytes(document)


def test_both_implementations_refuse_a_float(keypair):
    """The value that would give one passport two valid signatures.

    `0.1 + 0.2` renders as `0.30000000000000004` in one runtime and `0.3` in
    another. A verifier shown the matching rendering would accept; the other
    would reject the same document. Both implementations refuse before that can
    happen.
    """
    document = {"schema": "sentinel.passport/v1", "risk_score": 96.5}
    with pytest.raises(ValueError):
        canonical_bytes(document)
    with pytest.raises(ValueError):
        std.canonical_bytes(document)


def test_both_implementations_agree_on_the_digest(keypair):
    document = _passport().as_document()
    from sentinel.domain.passport import digest_of

    assert digest_of(document) == std.digest_of(document)


# ── tampering is caught by the independent verifier ──────────────────────────


def test_a_changed_field_is_caught(keypair):
    """The point of signing at all."""
    signing, material = keypair
    payload = sign(_passport(), key=signing, signed_at=WHEN).as_dict()
    payload["passport"]["decision"] = "blocked"

    codes = {f.code for f in std.verify(payload, material)}
    assert "modified" in codes


def test_a_reordered_document_still_verifies(keypair):
    """Key order is not semantic, so reordering must NOT read as tampering.

    The inverse of the test above, and the one that catches a canonicaliser
    that forgot to sort: it would report every re-serialised passport as
    forged, and an auditor who saw that once would stop believing the verifier.
    """
    signing, material = keypair
    payload = sign(_passport(), key=signing, signed_at=WHEN).as_dict()
    document = payload["passport"]
    payload["passport"] = dict(reversed(list(document.items())))

    assert std.verify(payload, material) == []


def test_the_wrong_key_is_reported_as_wrong_key_not_as_tampering(keypair):
    """Two different problems. "Someone altered this" and "you checked it
    against the wrong key" call for different actions, and a verifier that
    said `modified` for both would send an auditor hunting a forgery that
    never happened.
    """
    signing, material = keypair
    payload = sign(_passport(), key=signing, signed_at=WHEN).as_dict()
    other = dict(material, key_id="some-other-key")

    codes = {f.code for f in std.verify(payload, other)}
    assert codes == {"wrong_key"}


def test_a_signature_from_a_different_keypair_is_caught(keypair):
    """Right key_id, wrong key material -- the substitution a key_id check
    alone would wave through.
    """
    signing, material = keypair
    payload = sign(_passport(), key=signing, signed_at=WHEN).as_dict()
    impostor = Ed25519PrivateKey.generate()
    material = dict(
        material,
        public_key=base64.b64encode(
            impostor.public_key().public_bytes_raw()
        ).decode("ascii"),
    )

    codes = {f.code for f in std.verify(payload, material)}
    assert "modified" in codes


def test_a_key_used_outside_its_window_is_reported(keypair):
    """A cryptographically perfect signature can still be worthless evidence."""
    signing, material = keypair
    late = WHEN + timedelta(days=400)
    expired = SigningKey(
        key_id="audit-key-1", private_key=signing.private_key, not_before=None, not_after=None
    )
    payload = sign(_passport(), key=expired, signed_at=late).as_dict()

    codes = {f.code for f in std.verify(payload, material)}
    assert "key_outside_validity_window" in codes
    # And the signature itself is still sound -- the two findings are separate.
    assert "modified" not in codes


def test_an_unknown_algorithm_is_refused_rather_than_guessed(keypair):
    signing, material = keypair
    payload = sign(_passport(), key=signing, signed_at=WHEN).as_dict()
    payload["signature"]["algorithm"] = "rsa-pkcs1"

    codes = {f.code for f in std.verify(payload, material)}
    assert codes == {"unsupported_algorithm"}


def test_an_unknown_schema_is_refused_rather_than_guessed(keypair):
    """A verifier that accepted an unknown schema would be reporting "valid"
    about fields whose meaning it does not know.
    """
    signing, material = keypair
    passport = _passport()
    document = dict(passport.as_document(), schema="sentinel.passport/v99")
    body = std.canonical_bytes(document)
    payload = {
        "passport": document,
        "signature": {
            "algorithm": "ed25519",
            "key_id": "audit-key-1",
            "signed_at": WHEN.isoformat(),
            "value": base64.b64encode(signing.private_key.sign(body)).decode("ascii"),
        },
    }
    codes = {f.code for f in std.verify(payload, material)}
    assert "unrecognised_schema" in codes


def test_a_missing_required_field_is_reported_even_when_the_signature_is_good(
    keypair,
):
    """A correctly signed document that attributes nothing is not sound.

    Signed-and-incomplete is the failure a signature check alone waves through:
    the maths is fine and the document still cannot say who is answerable.
    """
    signing, material = keypair
    document = dict(_passport().as_document(), agent_id="")
    body = std.canonical_bytes(document)
    payload = {
        "passport": document,
        "signature": {
            "algorithm": "ed25519",
            "key_id": "audit-key-1",
            "signed_at": WHEN.isoformat(),
            "value": base64.b64encode(signing.private_key.sign(body)).decode("ascii"),
        },
    }
    codes = {f.code for f in std.verify(payload, material)}
    assert "missing_required_field" in codes
    assert "modified" not in codes


# ── lineage ──────────────────────────────────────────────────────────────────


def test_a_broken_chain_digest_is_caught():
    parent = _passport(execution_id="exec-1").as_document()
    child = _passport(
        execution_id="exec-2",
        parent_execution_id="exec-1",
        previous_passport_digest="0" * 64,
    ).as_document()

    codes = {f.code for f in std.check_chain([parent, child])}
    assert codes == {"broken_lineage"}


def test_a_correct_chain_digest_passes():
    parent = _passport(execution_id="exec-1").as_document()
    child = _passport(
        execution_id="exec-2",
        parent_execution_id="exec-1",
        previous_passport_digest=std.digest_of(parent),
    ).as_document()

    assert std.check_chain([parent, child]) == []


def test_an_absent_parent_is_UNKNOWN_rather_than_sound():
    """The distinction that matters when someone hands over a partial chain.

    Reporting nothing for a link that could not be checked would let a forger
    omit the parent whose digest does not match.
    """
    child = _passport(
        execution_id="exec-2",
        parent_execution_id="exec-1",
        previous_passport_digest="a" * 64,
    ).as_document()

    codes = {f.code for f in std.check_chain([child])}
    assert codes == {"missing_parent"}


# ── the conformance vectors are real, not decorative ─────────────────────────


def test_every_conformance_vector_produces_its_declared_verdict(keypair):
    """The vectors ship with the standard so a third implementation can be
    checked against them. A vector nobody runs is documentation, not a test.
    """
    signing, material = keypair
    vectors = sorted((STANDARD_DIR / "vectors").glob("*.json"))
    assert vectors, "the standard ships no conformance vectors"

    for path in vectors:
        vector = json.loads(path.read_text(encoding="utf-8"))
        document = vector["passport"]
        body = std.canonical_bytes(document)
        signature = base64.b64encode(signing.private_key.sign(body)).decode("ascii")
        payload = {
            "passport": document,
            "signature": {
                "algorithm": vector.get("algorithm", "ed25519"),
                "key_id": vector.get("key_id", "audit-key-1"),
                "signed_at": vector.get("signed_at", WHEN.isoformat()),
                "value": vector.get("signature_override") or signature,
            },
        }
        codes = {f.code for f in std.verify(payload, material)}
        expected = set(vector["expect_codes"])
        assert codes == expected, (
            f"{path.name}: expected {sorted(expected)}, got {sorted(codes)}"
        )


def test_the_specification_documents_every_code_the_verifier_can_emit():
    """A finding table that has drifted is worse than none.

    An implementer works from the table. A code the verifier emits but the
    table omits is one they will not handle; a code the table lists but the
    verifier never emits is one they will write dead code for. Both are found
    by comparing the two mechanically rather than by reading them side by side.
    """
    tree = ast.parse(VERIFIER_PATH.read_text(encoding="utf-8"))
    emitted: set[str] = set()
    for node in ast.walk(tree):
        # `Finding("code", ...)` -- the first positional argument, taken from
        # the call rather than from a scan for quoted strings, so a code named
        # in a comment or docstring does not count as one the verifier emits.
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "Finding"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            emitted.add(node.args[0].value)

    spec = (STANDARD_DIR / "SPEC.md").read_text(encoding="utf-8")
    documented = {
        line.split("`")[1]
        for line in spec.splitlines()
        if line.startswith("| `") and line.count("`") >= 2
    }

    undocumented = emitted - documented
    assert not undocumented, (
        f"the verifier emits codes the specification does not list: "
        f"{sorted(undocumented)}"
    )
