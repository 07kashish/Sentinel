"""SAML 2.0 assertion validation (signature + audience + conditions).

Not a full IdP. Validates a compact assertion document (XML) when IdP metadata
(certificate) is configured. Fail closed on missing signature, bad audience,
expired conditions, or missing tenant attribute.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from xml.etree import ElementTree as ET  # noqa: S405 - types and ParseError only

# PARSING IS DONE BY defusedxml, NOT BY THE STDLIB PARSER ABOVE.
#
# `ET` remains imported for its exception type and element types; every actual
# parse goes through `defused_fromstring`. The distinction matters, so it is
# spelled out rather than left to a reader to notice.
#
# WHY: `validate()` parses an assertion that arrives from an UNAUTHENTICATED
# caller, and it must parse it BEFORE it can check the signature -- the
# signature lives inside the document. `xml.etree.ElementTree` expands internal
# entities, so that parse was a pre-authentication denial of service. Measured
# against the stdlib parser on this machine:
#
#     3 nested entities, ~30 bytes of input -> 1000 characters expanded
#
# Nine levels of the same construction is the classic "billion laughs": a few
# hundred bytes become gigabytes, and the process dies before it ever reaches
# the signature check that would have rejected the document. `defusedxml`
# forbids the DTD/ENTITY declarations that make it possible, and raises rather
# than expanding.
from defusedxml.ElementTree import ParseError as DefusedParseError
from defusedxml.ElementTree import fromstring as defused_fromstring

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography import x509

from sentinel.domain.errors import DomainRuleViolated

__all__ = ["SamlAssertion", "SamlError", "SamlValidator"]


class SamlError(DomainRuleViolated):
    is_retryable = False


@dataclass(frozen=True, slots=True)
class SamlAssertion:
    subject: str
    tenant_id: str
    role: str
    issuer: str
    audience: str
    not_on_or_after: datetime
    attributes: dict[str, str]


def _parse_time(value: str) -> datetime:
    # Accept Zulu and offset forms used in SAML.
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    return datetime.fromisoformat(raw).astimezone(timezone.utc)


class SamlValidator:
    """Validate signed SAML assertions against a configured IdP certificate."""

    __slots__ = ("_audience", "_issuer", "_tenant_attr", "_role_attr", "_public_key")

    def __init__(
        self,
        *,
        audience: str,
        issuer: str,
        idp_cert_pem: str,
        tenant_attribute: str = "tenant_id",
        role_attribute: str = "role",
    ) -> None:
        if not audience or not issuer or not idp_cert_pem.strip():
            raise SamlError("SAML audience, issuer, and IdP certificate are required")
        cert = x509.load_pem_x509_certificate(idp_cert_pem.encode("utf-8"))
        key = cert.public_key()
        if not isinstance(key, rsa.RSAPublicKey):
            raise SamlError("SAML IdP certificate must be RSA")
        self._audience = audience
        self._issuer = issuer
        self._tenant_attr = tenant_attribute
        self._role_attr = role_attribute
        self._public_key = key

    #: Refused before the parser is even reached. A legitimate SAML assertion is
    #: a few kilobytes; this is two orders of magnitude of headroom. The cap is
    #: defence in depth behind `defusedxml` rather than the primary control --
    #: it bounds the cost of the parse itself, which no entity policy can.
    MAX_ASSERTION_BYTES = 512 * 1024

    def validate(self, assertion_xml: str, *, now: datetime | None = None) -> SamlAssertion:
        # Size first: this runs on unauthenticated input, so the cheapest check
        # goes first and nothing expensive happens until it passes.
        if len(assertion_xml.encode("utf-8", errors="ignore")) > self.MAX_ASSERTION_BYTES:
            raise SamlError(
                f"assertion exceeds {self.MAX_ASSERTION_BYTES} bytes and was refused "
                "unparsed; a legitimate assertion is a few kilobytes"
            )
        try:
            # `defused_fromstring`, never `ET.fromstring`. See the import block:
            # this parse happens BEFORE the signature can be checked, because the
            # signature is inside the document, so it is reachable by anyone who
            # can reach the endpoint.
            #
            # `forbid_dtd=True` is set EXPLICITLY and is not the library's
            # default (defusedxml forbids entities and external references but
            # permits a bare DTD). Writing the test for this caught that gap:
            # `<!DOCTYPE r SYSTEM "http://evil.example/x.dtd"><r/>` parsed
            # cleanly and was only rejected later, by the signature check, which
            # means the document reached the parser's DTD handling first.
            #
            # No legitimate SAML assertion carries a doctype. Refusing the whole
            # category is both correct and cheaper than reasoning about which
            # doctypes are harmless.
            root = defused_fromstring(
                assertion_xml,
                forbid_dtd=True,
                forbid_entities=True,
                forbid_external=True,
            )
        except (ET.ParseError, DefusedParseError) as exc:
            raise SamlError("assertion XML is malformed") from exc
        except Exception as exc:  # noqa: BLE001 - defusedxml raises its own family
            # `EntitiesForbidden`, `DTDForbidden`, `ExternalReferenceForbidden`.
            # Caught as one class and reported as one refusal: an attacker learns
            # only that the document was rejected, never which guard fired.
            raise SamlError("assertion XML declares forbidden constructs") from exc

        # Signature value over the assertion Canonical form is complex; for the
        # in-repo validator we require a ds:SignatureValue and verify it over the
        # SignedInfo-free assertion body hash the fixture provides as
        # ds:Reference Digest + SignatureValue of SHA256(assertion without Signature).
        signature_value = root.findtext(".//{http://www.w3.org/2000/09/xmldsig#}SignatureValue")
        if not signature_value or not signature_value.strip():
            raise SamlError("assertion signature is missing")

        # Detached/simple mode used by tests: SignatureValue is RSA-SHA256 over
        # the Assertion element's outer XML with the Signature node removed.
        unsigned = self._strip_signature(assertion_xml)
        try:
            sig = base64.b64decode(signature_value.strip())
            self._public_key.verify(
                sig,
                unsigned.encode("utf-8"),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except (InvalidSignature, ValueError) as exc:
            raise SamlError("assertion signature is invalid") from exc

        issuer = root.findtext(".//{urn:oasis:names:tc:SAML:2.0:assertion}Issuer") or ""
        if issuer != self._issuer:
            raise SamlError("issuer mismatch")

        audience = root.findtext(
            ".//{urn:oasis:names:tc:SAML:2.0:assertion}Audience"
        ) or ""
        if audience != self._audience:
            raise SamlError("audience mismatch")

        not_on_or_after_raw = root.findtext(
            ".//{urn:oasis:names:tc:SAML:2.0:assertion}Conditions[@NotOnOrAfter]"
        )
        # Attribute may be on Conditions element.
        conditions = root.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}Conditions")
        if conditions is None:
            raise SamlError("Conditions element required")
        not_on_or_after_raw = conditions.attrib.get("NotOnOrAfter")
        if not not_on_or_after_raw:
            raise SamlError("NotOnOrAfter required")
        not_on_or_after = _parse_time(not_on_or_after_raw)
        moment = now or datetime.now(timezone.utc)
        if moment >= not_on_or_after:
            raise SamlError("assertion expired")

        name_id = root.findtext(".//{urn:oasis:names:tc:SAML:2.0:assertion}NameID") or ""
        if not name_id.strip():
            raise SamlError("NameID required")

        attrs: dict[str, str] = {}
        for attr in root.findall(".//{urn:oasis:names:tc:SAML:2.0:assertion}Attribute"):
            name = attr.attrib.get("Name") or attr.attrib.get("FriendlyName") or ""
            value = attr.findtext(
                "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue"
            )
            if name and value is not None:
                attrs[name] = value

        tenant = attrs.get(self._tenant_attr, "").strip()
        if not tenant or tenant.lower() in {"default", "unknown", "*"}:
            raise SamlError("tenant attribute missing or forbidden")
        role = attrs.get(self._role_attr, "viewer").strip() or "viewer"

        return SamlAssertion(
            subject=name_id.strip(),
            tenant_id=tenant,
            role=role,
            issuer=issuer,
            audience=audience,
            not_on_or_after=not_on_or_after,
            attributes=attrs,
        )

    @staticmethod
    def _strip_signature(xml: str) -> str:
        # Remove ds:Signature element for the simple verify-over-body contract.
        return re.sub(
            r"<([a-zA-Z0-9_]+:)?Signature\b[^>]*>.*?</([a-zA-Z0-9_]+:)?Signature>",
            "",
            xml,
            flags=re.DOTALL,
        )
