"""Deriving risk from an OpenAPI spec (specification section 47).

WHAT IS BEING ASSERTED, AND WHAT DELIBERATELY IS NOT
------------------------------------------------------
The derivation reads three structural signals -- method, path naming, sensitive
parameter names -- and nothing else. So these tests check that those signals
are read correctly and combined in the right direction, NOT that the result is
"right" in some absolute sense. It cannot be: a path containing `admin` may not
be administrative, and one that does not may be.

The load-bearing case is `GET /admin/tokens`. A method-only reading calls it
low (it is a GET); a path-only reading calls it critical. Reading a credential
IS the risk, so the category comes from the path and the tier is the WORSE of
the two. If that combination ever inverts, every credential read in every
generated policy silently drops to `low`.
"""

from __future__ import annotations

import json

import pytest

from sentinel.infrastructure.openapi_risk import derive_risks, policy_template


def _spec(paths: dict) -> dict:
    return {"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": paths}


def _by_path(risks, path, method):
    return next(r for r in risks if r.path == path and r.method == method)


# ── The signals, one at a time ───────────────────────────────────────────────


@pytest.mark.parametrize(
    ("method", "path", "tier"),
    [
        ("get", "/health", "low"),
        ("post", "/reports", "moderate"),
        ("delete", "/reports/{id}", "high"),
        ("delete", "/tokens/{id}", "critical"),
        ("get", "/secrets/db", "critical"),
        ("post", "/pods/{name}/exec", "critical"),
        ("post", "/exports/customers", "high"),
        ("put", "/roles/{id}", "critical"),
    ],
)
def test_the_tier_follows_the_method_and_the_paths_own_naming(method, path, tier):
    risks = derive_risks(_spec({path: {method: {"operationId": "op"}}}))
    assert risks[0].tier == tier, risks[0].as_dict()


def test_reading_a_credential_keeps_the_credential_tier_not_the_read_tier():
    """THE case. A GET of a secret is not a low-risk operation."""
    risks = derive_risks(_spec({"/admin/tokens": {"get": {"operationId": "listTokens"}}}))
    risk = risks[0]
    assert risk.category == "credential", risk.as_dict()
    assert risk.tier == "critical", (
        "a credential read inherited its verb's tier; every secret read in "
        "every generated policy would be labelled low"
    )


def test_writing_a_sensitive_parameter_raises_the_tier():
    spec = _spec(
        {
            "/users/{id}": {
                "patch": {
                    "operationId": "updateUser",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"properties": {"role": {"type": "string"}}}
                            }
                        }
                    },
                }
            }
        }
    )
    risk = derive_risks(spec)[0]
    assert risk.tier in {"high", "critical"}, risk.as_dict()
    assert "role" in risk.sensitive_parameters


def test_a_read_is_not_escalated_by_a_sensitive_parameter_it_only_filters_on():
    """`GET /users?role=admin` filters; it does not grant."""
    spec = _spec(
        {
            "/users": {
                "get": {
                    "operationId": "listUsers",
                    "parameters": [{"name": "role", "in": "query"}],
                }
            }
        }
    )
    risk = derive_risks(spec)[0]
    assert risk.tier == "moderate", risk.as_dict()


# ── Every tier arrives with its reasons ──────────────────────────────────────


def test_no_operation_is_tiered_without_a_stated_reason():
    """A tier with no reasons is the magic number this codebase refuses."""
    spec = _spec(
        {
            "/a": {"get": {}, "post": {}, "delete": {}},
            "/secrets/x": {"get": {}},
            "/exports/y": {"post": {}},
        }
    )
    for risk in derive_risks(spec):
        assert risk.reasons, risk.as_dict()


# ── The generated document ───────────────────────────────────────────────────


def test_the_template_is_valid_json_and_says_it_is_unreviewed():
    spec = _spec(
        {
            "/secrets/{id}": {"delete": {"operationId": "deleteSecret"}},
            "/health": {"get": {"operationId": "health"}},
        }
    )
    document = policy_template(derive_risks(spec), api_name="acme")
    round_tripped = json.loads(json.dumps(document))
    readme = " ".join(round_tripped["_readme"]).lower()
    assert "starting point" in readme
    assert "nothing installed these" in readme
    # The reasoning travels WITH the rule, so a reviewer edits with the
    # derivation in front of them rather than in another window.
    rule = round_tripped["rules"][0]
    assert rule["_derived_from"][0]["reasons"]


def test_low_and_moderate_operations_produce_no_rules():
    """A rule per operation is a file nobody reads and a diff nobody reviews."""
    spec = _spec({"/health": {"get": {}}, "/reports": {"post": {}}})
    assert policy_template(derive_risks(spec))["rules"] == []


def test_a_templated_path_becomes_a_regex_that_matches_a_real_url():
    import re

    spec = _spec({"/users/{id}/keys": {"delete": {"operationId": "deleteKey"}}})
    rule = policy_template(derive_risks(spec), api_name="acme")["rules"][0]
    pattern = rule["values"][0]
    assert re.search(pattern, "https://api.example.com/users/42/keys")
    assert not re.search(pattern, "https://api.example.com/users/42/other")


def test_a_path_cannot_smuggle_a_regex_through_the_template():
    """The spec is an untrusted document; its author must not write the matcher."""
    import re

    spec = _spec({"/repos/.*/delete": {"delete": {"operationId": "sneaky"}}})
    rule = policy_template(derive_risks(spec), api_name="acme")["rules"][0]
    pattern = rule["values"][0]
    # Escaped: the literal path matches, an arbitrary one does not.
    assert re.search(pattern, "/repos/.*/delete")
    assert not re.search(pattern, "/repos/anything-at-all/delete")


def test_a_spec_with_no_paths_derives_nothing_rather_than_guessing():
    assert derive_risks({"openapi": "3.0.0"}) == ()
