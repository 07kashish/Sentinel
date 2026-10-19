"""A SAML assertion is unauthenticated input parsed before it can be verified.

THE DEFECT
----------
`SamlValidator.validate` called `xml.etree.ElementTree.fromstring` on the
assertion. It has no choice about parsing first -- the signature it needs to
check is *inside* the document -- so that parse is reachable by anyone who can
reach the SSO endpoint, with no credential of any kind.

`xml.etree.ElementTree` expands internal entities. Measured against the stdlib
parser while writing these tests:

    3 nested entities, ~30 bytes of input  ->  1000 characters expanded

Each additional level multiplies by ten. Nine levels is the classic "billion
laughs": a few hundred bytes of input become gigabytes of memory, and the
process dies long before it reaches the signature check that would have thrown
the document out. Bandit flagged it as B314 and it was the only non-B608 finding
in the whole package.

WHAT THESE TESTS HOLD
---------------------
That the bomb is REFUSED rather than expanded, that the refusal is a `SamlError`
(the fail-closed type this module already uses) rather than a crash or a
`MemoryError`, and that the guards sit in front of the signature check rather
than behind it -- a guard that runs after verification protects nothing, because
the attack lands during the parse.

The bombs here are deliberately small. The point is to prove the construction is
rejected, not to allocate gigabytes in CI; a parser that refuses three levels
refuses nine for the same reason.
"""

from __future__ import annotations

import pytest

from sentinel.domain.errors import DomainRuleViolated
from sentinel.infrastructure.saml import SamlError, SamlValidator

#: A self-signed RSA certificate is required just to CONSTRUCT the validator.
#: Generated per-session rather than committed: a private key in a test fixture
#: is a private key in the repository, and `security` scans this tree.
pytest.importorskip("cryptography")


@pytest.fixture(scope="module")
def validator() -> SamlValidator:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-idp")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    return SamlValidator(
        idp_cert_pem=pem, audience="sentinel", issuer="https://idp.example"
    )


def _billion_laughs(levels: int = 3) -> str:
    """The classic construction, kept small on purpose.

    Each entity references the previous one ten times, so the expansion is
    10**levels. Three levels is 1000x -- enough to prove the parser expands, far
    too little to hurt the machine running the test.
    """
    entities = ['<!ENTITY e0 "AAAAAAAAAA">']
    for i in range(1, levels):
        prev = "&e{};".format(i - 1) * 10
        entities.append(f'<!ENTITY e{i} "{prev}">')
    return (
        '<?xml version="1.0"?>'
        f"<!DOCTYPE r [{''.join(entities)}]>"
        f"<r>&e{levels - 1};</r>"
    )


# ── The attack is refused ────────────────────────────────────────────────────


def test_an_entity_expansion_bomb_is_refused_not_expanded(validator):
    """The headline. Before the fix this expanded; now it raises."""
    with pytest.raises(SamlError) as raised:
        validator.validate(_billion_laughs(levels=3))

    # It must NOT have got as far as complaining about a missing signature:
    # that would mean the document was parsed and expanded first.
    message = str(raised.value).lower()
    assert "signature" not in message, (
        f"the bomb was parsed before being rejected -- refusal came from the "
        f"signature check, not the parser: {raised.value}"
    )


def test_a_dtd_declaration_is_refused_on_its_own(validator):
    """No legitimate SAML assertion carries a DTD. Refuse the whole category."""
    with pytest.raises(SamlError):
        validator.validate(
            '<?xml version="1.0"?><!DOCTYPE r SYSTEM "http://evil.example/x.dtd"><r/>'
        )


def test_an_external_entity_reference_is_refused(validator):
    """Classic XXE shape: a local-file entity. Refused before any fetch."""
    with pytest.raises(SamlError):
        validator.validate(
            '<?xml version="1.0"?>'
            '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
            "<r>&x;</r>"
        )


def test_an_oversized_assertion_is_refused_unparsed(validator):
    """The size cap runs FIRST, so a huge document costs nothing to reject."""
    oversized = "<r>" + ("A" * (SamlValidator.MAX_ASSERTION_BYTES + 1)) + "</r>"

    with pytest.raises(SamlError) as raised:
        validator.validate(oversized)

    assert "exceeds" in str(raised.value), (
        f"expected the size guard to fire, got: {raised.value}"
    )


# ── The refusal is the right SHAPE ───────────────────────────────────────────


def test_every_refusal_is_a_domain_error_not_a_crash(validator):
    """A parser exception escaping as-is would be a 500, not a 401.

    `SamlError` is a `DomainRuleViolated` and is non-retryable, so the caller
    rejects the login instead of retrying it. An unclassified `ExpatError` or
    `EntitiesForbidden` reaching the HTTP layer would be an unhandled exception,
    which is both the wrong status code and an information leak.
    """
    for payload in (
        _billion_laughs(levels=2),
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "y">]><r>&x;</r>',
        "not xml at all",
        "",
        "<unclosed>",
    ):
        with pytest.raises(SamlError) as raised:
            validator.validate(payload)
        assert isinstance(raised.value, DomainRuleViolated)
        assert raised.value.is_retryable is False, (
            "a malformed assertion must not be retryable; retrying it would "
            "turn one bad login into a loop"
        )


def test_the_refusal_does_not_disclose_which_guard_fired(validator):
    """An attacker should learn "rejected", not which construct tripped it.

    Distinguishing "entities forbidden" from "DTD forbidden" from "malformed"
    hands over a map of the parser configuration for free.
    """
    messages = set()
    for payload in (
        _billion_laughs(levels=2),
        '<?xml version="1.0"?><!DOCTYPE r SYSTEM "http://evil.example/x.dtd"><r/>',
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
    ):
        with pytest.raises(SamlError) as raised:
            validator.validate(payload)
        messages.add(str(raised.value))

    assert len(messages) == 1, (
        f"forbidden-construct refusals are distinguishable from each other: "
        f"{messages}"
    )


# ── The guard cannot be removed without this failing ─────────────────────────


def test_the_module_does_not_parse_with_the_stdlib_parser():
    """Structural: `ET.fromstring` must not appear as a call in this module.

    The import of `xml.etree.ElementTree` stays -- the exception type and the
    element types come from it -- so a reader could reasonably re-add
    `ET.fromstring(...)` and reintroduce the vulnerability without touching an
    import line. This asserts on the CALL, by AST, rather than on the import.
    """
    import ast
    import inspect

    from sentinel.infrastructure import saml

    tree = ast.parse(inspect.getsource(saml))
    offenders = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"fromstring", "parse", "XML", "fromstringlist"}
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "ET"
    ]
    assert not offenders, (
        f"sentinel/infrastructure/saml.py calls the stdlib XML parser at line(s) "
        f"{offenders}. That parser expands internal entities and this input is "
        "unauthenticated. Use `defused_fromstring`."
    )
