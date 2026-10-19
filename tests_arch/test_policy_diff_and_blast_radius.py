"""What would CHANGE, and how much would it matter.

TWO PHASES, ONE TEST MODULE, BECAUSE THEY SHARE A DISCIPLINE
--------------------------------------------------------------
Both answer a question an operator asks before doing something irreversible, and
both are worthless if they overstate their own confidence.

The policy diff exists because a total is not a change. A candidate that blocks
400 events where the active policy blocked 380 could be twenty new blocks, or
four hundred new blocks and three hundred and eighty newly-allowed — opposite
changes with the same summary. `test_two_policies_with_identical_totals_are_not
_identical_policies` is that case.

Blast radius exists because reach is computable and IMPORTANCE IS NOT. Whether
`db://customers` holds PII is a fact about the business, not the topology. So
sensitivity is declared, an undeclared asset is `unclassified` rather than
harmless, and `coverage` is the number a reader must see before quoting `score`.
"""

from __future__ import annotations

import pytest

from sentinel.domain.blast_radius import (
    AssetDeclaration,
    Sensitivity,
    compute_blast_radius,
)
from sentinel.domain.effective_permissions import compute_effective_reach
from sentinel.domain.policy_as_code import (
    PolicyEffect,
    PolicyRule,
    PolicyVersion,
)


def _rule(name: str, effect: PolicyEffect, **matchers) -> PolicyRule:
    return PolicyRule(name=name, effect=effect, **matchers)


def _policy(version: str, *rules: PolicyRule) -> PolicyVersion:
    return PolicyVersion(
        version=version,
        rules=tuple(rules),
        created_by="test",
        created_at="2026-08-31T12:00:00+00:00",
    )


def _event(**overrides):
    base = {
        "event_id": "e1",
        "agent_id": "finance-agent",
        "principal": "alice",
        "action": "read_file",
        "resource": "reports/q3.md",
        "tool": "read_file",
        "severity": 10,
    }
    base.update(overrides)
    return base


# ── blast radius ─────────────────────────────────────────────────────────────


def _reach(agent="finance-agent", **kwargs):
    kwargs.setdefault("grants", {agent: ["db://customers", "db://public-docs"]})
    return compute_effective_reach(agent, **kwargs)


def _declare(asset, sensitivity, **kw):
    return AssetDeclaration(
        asset=asset, sensitivity=sensitivity, declared_by="alice", **kw
    )


def test_an_undeclared_asset_is_unclassified_not_harmless():
    """THE property. Scoring an undeclared asset zero means an estate nobody
    classified reports blast radius 0 — the safest-looking answer produced by
    having done no work.
    """
    radius = compute_blast_radius(_reach(), declarations=[])
    assert radius.score == 0
    assert set(radius.unclassified) == {"db://customers", "db://public-docs"}
    assert radius.coverage == 0.0


def test_coverage_is_what_a_reader_must_see_before_quoting_the_score():
    radius = compute_blast_radius(
        _reach(), declarations=[_declare("db://customers", Sensitivity.RESTRICTED)]
    )
    assert radius.coverage == 0.5
    assert "Read `coverage` before quoting `score`" in radius.as_dict()["limits"]


def test_a_declaration_needs_an_author():
    """Sensitivity is declared rather than inferred precisely so somebody is
    accountable. An unattributed declaration is an inference in human clothes.
    """
    with pytest.raises(ValueError, match="no author"):
        AssetDeclaration(
            asset="db://customers",
            sensitivity=Sensitivity.RESTRICTED,
            declared_by="  ",
        )


def test_declared_public_is_classified_and_worth_nothing():
    """Different from undeclared, and folding the two would make coverage lie."""
    radius = compute_blast_radius(
        _reach(),
        declarations=[
            _declare("db://customers", Sensitivity.PUBLIC),
            _declare("db://public-docs", Sensitivity.PUBLIC),
        ],
    )
    assert radius.unclassified == ()
    assert radius.coverage == 1.0
    assert radius.score == 0


def test_production_multiplies_the_weight():
    plain = compute_blast_radius(
        _reach(), declarations=[_declare("db://customers", Sensitivity.RESTRICTED)]
    )
    production = compute_blast_radius(
        _reach(),
        declarations=[
            _declare("db://customers", Sensitivity.RESTRICTED, production=True)
        ],
    )
    assert production.score > plain.score


def test_production_comes_from_a_declaration_not_from_the_name():
    """A staging database called `prod-mirror` must not rate as production, and
    a production one called `db-7` must not escape it.
    """
    radius = compute_blast_radius(
        compute_effective_reach("a", grants={"a": ["db://prod-mirror"]}),
        declarations=[_declare("db://prod-mirror", Sensitivity.INTERNAL)],
    )
    assert radius.production_paths == ()


def test_an_asset_reachable_several_ways_is_counted_once():
    """An asset reachable three ways is one thing an attacker gets to. Summing
    per path would let a well-connected estate outscore a dangerous one.
    """
    reach = compute_effective_reach(
        "a",
        grants={"a": ["db://customers"], "b": ["db://customers"]},
        credentials={"c1": ["a", "b"]},
    )
    radius = compute_blast_radius(
        reach,
        declarations=[_declare("db://customers", Sensitivity.RESTRICTED)],
    )
    assert radius.score == 30


def test_a_path_through_a_shared_credential_is_still_a_critical_path():
    """The route nobody granted. It reaches the same asset and belongs in the
    blast radius exactly as a direct grant does.
    """
    reach = compute_effective_reach(
        "a", grants={"b": ["db://customers"]}, credentials={"c1": ["a", "b"]}
    )
    radius = compute_blast_radius(
        reach, declarations=[_declare("db://customers", Sensitivity.RESTRICTED)]
    )
    assert radius.critical_paths
    assert radius.critical_paths[0].via == ("b",)


def test_an_agent_that_reaches_nothing_has_full_coverage_and_no_score():
    radius = compute_blast_radius(
        compute_effective_reach("lonely", grants={}), declarations=[]
    )
    assert radius.score == 0
    assert radius.coverage == 1.0


def test_the_score_is_bounded():
    reach = compute_effective_reach(
        "a", grants={"a": [f"db://table-{i}" for i in range(50)]}
    )
    radius = compute_blast_radius(
        reach,
        declarations=[
            _declare(f"db://table-{i}", Sensitivity.RESTRICTED, production=True)
            for i in range(50)
        ],
    )
    assert radius.score == 100


def test_unknown_has_no_weight_entry_at_all():
    """Giving UNKNOWN a weight would be inventing the judgement this module
    refuses to make.
    """
    from sentinel.domain.blast_radius import SENSITIVITY_WEIGHT

    assert Sensitivity.UNKNOWN not in SENSITIVITY_WEIGHT
