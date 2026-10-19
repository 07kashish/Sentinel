"""The SDK canonicaliser must stay byte-identical to the domain one."""

from __future__ import annotations

import pytest

from sentinel.domain.passport import canonical_bytes as domain_canonical_bytes
from sentinel.sdk.adapters._gate import NotCanonical, canonical_bytes, parameter_digest


@pytest.mark.parametrize(
    "document",
    [
        {"agent_id": "agent:Аркадий"},
        {"outer": {"z": [{"b": 1, "a": 2}], "a": None}},
        {"human_principal": None, "decision": "allow"},
        {"risk_score": 2**53 - 1},
        {"z": 1, "a": 2, "m": 3},
        {"items": [True, False, None, "x"]},
    ],
)
def test_sdk_canonical_bytes_match_the_domain(document):
    assert canonical_bytes(document) == domain_canonical_bytes(document)


@pytest.mark.parametrize(
    "document",
    [
        {"risk_score": 96.5},
        {"nested": [{"risk_score": 0.1}]},
        {"risk_score": 2**53},
    ],
)
def test_sdk_refuses_values_the_domain_refuses(document):
    with pytest.raises(ValueError):
        domain_canonical_bytes(document)
    with pytest.raises(NotCanonical):
        canonical_bytes(document)


def test_parameter_digest_is_context_separated_and_stable():
    digest = parameter_digest({"b": 1, "a": "á"})

    assert len(digest) == 64
    assert digest == parameter_digest({"a": "á", "b": 1})
