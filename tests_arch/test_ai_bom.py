"""An inventory's dangerous output is an EMPTY one, not a wrong one.

"No unpinned models found" and "we could not reach the account" render
identically in any report that shows a count. The first is a clean bill of
health; the second is a scan that did not run.

So these tests spend most of their effort on one question: can a caller obtain
a document that LOOKS clean from a discovery run that saw nothing? Everything
else in the module is bookkeeping by comparison.
"""

from __future__ import annotations

import pytest

from sentinel.domain.ai_bom import (
    AI_KINDS,
    AIComponent,
    BomFindingKind,
    Completeness,
    Provenance,
    compile_ai_bom,
    strongest_of,
)
from sentinel.domain.assets import (
    AssetInventory,
    AssetKind,
    AssetRecord,
    DiscoveryCoverage,
    Unreachable,
)

NOW = "2026-09-03T00:00:00Z"


def _coverage(examined: int = 10, **kwargs) -> DiscoveryCoverage:
    return DiscoveryCoverage(scope=("prod",), examined=examined, **kwargs)


def _record(kind: AssetKind, identifier: str, **attributes) -> AssetRecord:
    return AssetRecord(
        kind=kind,
        identifier=identifier,
        source="test-connector",
        attributes=attributes,
    )


def _inventory(
    *records: AssetRecord,
    connector: str = "test-connector",
    coverage: DiscoveryCoverage | None = None,
) -> AssetInventory:
    return AssetInventory(
        connector=connector,
        assets=tuple(records),
        coverage=coverage if coverage is not None else _coverage(),
    )


# ── completeness: the property the module exists for ─────────────────────────


def test_a_bom_from_no_inventories_is_unusable_not_complete():
    """The failed-discovery case.

    A run whose connectors all errored produces no inventories. If that read as
    COMPLETE, every dashboard would show a clean estate at the exact moment
    visibility was lost.
    """
    bom = compile_ai_bom(tenant="acme", inventories=(), generated_at=NOW)

    assert bom.completeness is Completeness.UNUSABLE
    assert bom.components == ()


def test_a_bom_whose_sources_examined_nothing_is_unusable():
    """A connector can return successfully having inspected zero objects.

    Wrong credential, wrong scope, empty namespace filter -- the call succeeds
    and finds nothing. Indistinguishable from a clean estate unless the
    DENOMINATOR is read, which is why `examined` gates the verdict.
    """
    bom = compile_ai_bom(
        tenant="acme",
        inventories=(_inventory(coverage=_coverage(examined=0)),),
        generated_at=NOW,
    )

    assert bom.completeness is Completeness.UNUSABLE


def test_an_empty_but_genuinely_scanned_estate_is_complete():
    """The other side of the same coin.

    Having established that emptiness can mean failure, emptiness must still be
    allowed to mean emptiness -- otherwise the verdict is useless in the good
    case and operators learn to ignore it.
    """
    bom = compile_ai_bom(
        tenant="acme",
        inventories=(_inventory(coverage=_coverage(examined=40)),),
        generated_at=NOW,
    )

    assert bom.completeness is Completeness.COMPLETE
    assert bom.components == ()


def test_any_unreachable_target_makes_the_document_partial():
    bom = compile_ai_bom(
        tenant="acme",
        inventories=(
            _inventory(
                _record(AssetKind.MODEL, "gpt-4o", version="2024-11-20"),
                coverage=_coverage(
                    unreachable=(Unreachable(target="acct-2", reason="AccessDenied"),)
                ),
            ),
        ),
        generated_at=NOW,
    )

    assert bom.completeness is Completeness.PARTIAL


def test_truncated_pagination_makes_the_document_partial():
    """A connector that stopped at page one reports a subset as a total."""
    bom = compile_ai_bom(
        tenant="acme",
        inventories=(
            _inventory(coverage=_coverage(pagination_complete=False)),
        ),
        generated_at=NOW,
    )

    assert bom.completeness is Completeness.PARTIAL


def test_one_working_connector_does_not_cover_for_one_that_saw_nothing():
    """Two connectors, one blind. The picture is real with a hole in it.

    Reporting COMPLETE here would let an estate hide an entire cloud account
    behind a working Kubernetes scan.
    """
    bom = compile_ai_bom(
        tenant="acme",
        inventories=(
            _inventory(
                _record(AssetKind.MODEL, "claude", version="1"),
                connector="k8s",
                coverage=_coverage(examined=40),
            ),
            _inventory(connector="aws", coverage=_coverage(examined=0)),
        ),
        generated_at=NOW,
    )

    assert bom.completeness is Completeness.PARTIAL


def test_completeness_is_the_first_key_a_reader_meets():
    """This document gets pasted into tickets and questionnaires.

    A caveat that lives outside the payload is a caveat that gets stripped, so
    the verdict is the first key in the serialised form and the limits travel
    inside it.
    """
    bom = compile_ai_bom(tenant="acme", inventories=(), generated_at=NOW)
    document = bom.as_dict()

    assert next(iter(document)) == "completeness"
    assert "NOT evidence of absence" in document["limits"]
    assert "UNUSABLE" in document["limits"]


# ── provenance ───────────────────────────────────────────────────────────────


def test_attested_provenance_without_a_digest_is_refused():
    """Attested means a digest binds it. Without one the word is decoration,
    and decoration in an inventory stops anyone from looking.
    """
    with pytest.raises(ValueError) as raised:
        AIComponent(
            kind=AssetKind.MODEL,
            identifier="gpt-4o",
            sources=("k8s",),
            provenance=Provenance.ATTESTED,
        )
    assert "no digest" in str(raised.value)


def test_a_source_claiming_attested_without_a_digest_is_downgraded():
    """A connector cannot self-certify.

    The record says `provenance: attested` and carries no digest. Honouring it
    would let any connector mint confidence by writing a word into a field.
    """
    bom = compile_ai_bom(
        tenant="acme",
        inventories=(
            _inventory(_record(AssetKind.MODEL, "gpt-4o", provenance="attested")),
        ),
        generated_at=NOW,
    )

    assert bom.components[0].provenance is Provenance.DECLARED


def test_missing_provenance_defaults_to_the_weakest_level():
    """A connector that says nothing about how it knows has said 'declared'.

    Defaulting to anything stronger manufactures confidence from an absent
    field.
    """
    bom = compile_ai_bom(
        tenant="acme",
        inventories=(_inventory(_record(AssetKind.MODEL, "gpt-4o")),),
        generated_at=NOW,
    )

    assert bom.components[0].provenance is Provenance.DECLARED


def test_the_strongest_evidence_wins_when_two_sources_disagree():
    """Observing something does not un-observe it."""
    assert strongest_of((Provenance.DECLARED, Provenance.OBSERVED)) is (
        Provenance.OBSERVED
    )
    assert strongest_of((Provenance.ATTESTED, Provenance.DECLARED)) is (
        Provenance.ATTESTED
    )
    assert strongest_of(()) is Provenance.DECLARED


def test_the_provenance_census_shows_how_little_is_verified():
    """The most useful number in the file and the one no vendor dashboard shows.

    An estate that is 96% DECLARED has an inventory, not an attestation.
    """
    bom = compile_ai_bom(
        tenant="acme",
        inventories=(
            _inventory(
                _record(AssetKind.MODEL, "a", provenance="observed", version="1"),
                _record(AssetKind.MODEL, "b", version="1"),
                _record(AssetKind.MODEL, "c", version="1"),
            ),
        ),
        generated_at=NOW,
    )

    census = bom.provenance_census()
    assert census == {"declared": 2, "observed": 1, "attested": 0}
    # Every level present even at zero: a missing key reads as "not measured".
    assert set(census) == {level.value for level in Provenance}


# ── merging, and the conflict it must not resolve ────────────────────────────


def test_one_component_seen_by_two_connectors_is_not_counted_twice():
    bom = compile_ai_bom(
        tenant="acme",
        inventories=(
            _inventory(
                _record(AssetKind.MODEL, "gpt-4o", version="2024-11-20"),
                connector="k8s",
            ),
            _inventory(
                _record(AssetKind.MODEL, "gpt-4o", provenance="observed"),
                connector="aws",
            ),
        ),
        generated_at=NOW,
    )

    assert len(bom.components) == 1
    component = bom.components[0]
    assert component.sources == ("aws", "k8s")
    assert component.provenance is Provenance.OBSERVED
    assert component.version == "2024-11-20", "the known version was lost"


def test_two_sources_reporting_different_digests_is_a_finding_not_a_choice():
    """Silently picking a winner hides the only signal that says two different
    things are wearing one name.
    """
    bom = compile_ai_bom(
        tenant="acme",
        inventories=(
            _inventory(_record(AssetKind.MODEL, "m", digest="aaa"), connector="k8s"),
            _inventory(_record(AssetKind.MODEL, "m", digest="bbb"), connector="aws"),
        ),
        generated_at=NOW,
    )

    conflicts = [
        f for f in bom.findings if f.kind is BomFindingKind.CONFLICTING_DIGEST
    ]
    assert len(conflicts) == 1
    assert "aaa" in conflicts[0].detail and "bbb" in conflicts[0].detail


def test_the_same_identifier_under_two_kinds_stays_two_components():
    """A tool and a server can legitimately share a name. Merging on the
    identifier alone would fuse them and report one thing that is neither.
    """
    bom = compile_ai_bom(
        tenant="acme",
        inventories=(
            _inventory(
                _record(AssetKind.MCP_SERVER, "files"),
                _record(AssetKind.MCP_TOOL, "files"),
            ),
        ),
        generated_at=NOW,
    )

    assert len(bom.components) == 2


# ── findings ─────────────────────────────────────────────────────────────────


def test_an_unpinned_model_is_reported_with_its_reach():
    """"Unpinned model" is a category. "Reachable by 2 agents" is a priority."""
    record = AssetRecord(
        kind=AssetKind.MODEL,
        identifier="gpt-4o",
        source="k8s",
        relates_to=("agent-a", "agent-b"),
    )
    bom = compile_ai_bom(
        tenant="acme", inventories=(_inventory(record),), generated_at=NOW
    )

    assert bom.unpinned_models[0].identifier == "gpt-4o"
    finding = next(
        f for f in bom.findings if f.kind is BomFindingKind.UNPINNED_MODEL
    )
    assert "2 agent(s)" in finding.detail


def test_a_version_alone_counts_as_pinned():
    bom = compile_ai_bom(
        tenant="acme",
        inventories=(
            _inventory(_record(AssetKind.MODEL, "gpt-4o", version="2024-11-20")),
        ),
        generated_at=NOW,
    )

    assert bom.components[0].is_pinned
    assert bom.unpinned_models == ()


def test_whitespace_is_not_a_version():
    """A field containing a space would otherwise satisfy `is_pinned` and the
    estate would report a pin it does not have.
    """
    bom = compile_ai_bom(
        tenant="acme",
        inventories=(_inventory(_record(AssetKind.MODEL, "m", version="   ")),),
        generated_at=NOW,
    )

    assert not bom.components[0].is_pinned


def test_a_skill_with_no_digest_is_reported_as_unattested():
    bom = compile_ai_bom(
        tenant="acme",
        inventories=(_inventory(_record(AssetKind.SKILL, "summarise")),),
        generated_at=NOW,
    )

    assert any(
        f.kind is BomFindingKind.UNATTESTED_SKILL for f in bom.findings
    )


def test_an_mcp_server_known_only_from_config_is_reported():
    bom = compile_ai_bom(
        tenant="acme",
        inventories=(_inventory(_record(AssetKind.MCP_SERVER, "files")),),
        generated_at=NOW,
    )

    assert any(
        f.kind is BomFindingKind.DECLARED_ONLY_SERVER for f in bom.findings
    )


def test_an_observed_mcp_server_is_not_reported_as_declared_only():
    """The guard above must distinguish, or it fires on every server and gets
    filtered out of every report within a week.
    """
    bom = compile_ai_bom(
        tenant="acme",
        inventories=(
            _inventory(_record(AssetKind.MCP_SERVER, "files", provenance="observed")),
        ),
        generated_at=NOW,
    )

    assert not any(
        f.kind is BomFindingKind.DECLARED_ONLY_SERVER for f in bom.findings
    )


# ── vocabulary ───────────────────────────────────────────────────────────────


def test_non_ai_assets_are_left_out_rather_than_reclassified():
    """A database is an asset, not an AI supply-chain component. Including it
    would turn this into a general asset list and the question it answers --
    what does our agent estate depend on -- stops being answerable.
    """
    bom = compile_ai_bom(
        tenant="acme",
        inventories=(
            _inventory(
                _record(AssetKind.DATABASE, "orders-db"),
                _record(AssetKind.MODEL, "gpt-4o", version="1"),
            ),
        ),
        generated_at=NOW,
    )

    assert [c.identifier for c in bom.components] == ["gpt-4o"]


def test_a_human_principal_is_not_a_supply_chain_component():
    """Including people would make this a staff list."""
    assert AssetKind.HUMAN_PRINCIPAL not in AI_KINDS


def test_constructing_a_component_of_a_non_ai_kind_is_refused():
    with pytest.raises(ValueError) as raised:
        AIComponent(
            kind=AssetKind.DATABASE, identifier="orders", sources=("k8s",)
        )
    assert "not an AI supply-chain component" in str(raised.value)


def test_a_component_with_no_source_is_refused():
    """An inventory of unattributable components is a rumour."""
    with pytest.raises(ValueError) as raised:
        AIComponent(kind=AssetKind.MODEL, identifier="m", sources=())
    assert "no source" in str(raised.value)


def test_a_bom_with_no_tenant_is_refused():
    with pytest.raises(ValueError) as raised:
        compile_ai_bom(tenant="  ", inventories=(), generated_at=NOW)
    assert "tenant" in str(raised.value)


# ── CycloneDX export ─────────────────────────────────────────────────────────


def test_the_cyclonedx_export_admits_it_is_unvalidated():
    """Calling it "CycloneDX compliant" would be a claim with no evidence.

    The disclaimer is a property inside the document rather than prose in a
    README, because the document is what a consumer receives.
    """
    bom = compile_ai_bom(
        tenant="acme",
        inventories=(_inventory(_record(AssetKind.MODEL, "m", version="1")),),
        generated_at=NOW,
    )
    document = bom.as_cyclonedx()
    properties = {p["name"]: p["value"] for p in document["metadata"]["properties"]}

    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.6"
    assert properties["sentinel:schema_validated"] == "false"
    assert "validated against no schema" in properties["sentinel:disclaimer"]


def test_the_cyclonedx_export_carries_the_completeness_verdict():
    """A consumer reading only the CycloneDX form must still learn the estate
    was not fully scanned.
    """
    bom = compile_ai_bom(tenant="acme", inventories=(), generated_at=NOW)
    properties = {
        p["name"]: p["value"] for p in bom.as_cyclonedx()["metadata"]["properties"]
    }

    assert properties["sentinel:completeness"] == "unusable"


def test_a_model_maps_to_the_real_cyclonedx_machine_learning_type():
    bom = compile_ai_bom(
        tenant="acme",
        inventories=(_inventory(_record(AssetKind.MODEL, "m", version="1")),),
        generated_at=NOW,
    )

    assert bom.as_cyclonedx()["components"][0]["type"] == "machine-learning-model"


def test_a_digestless_component_emits_no_hashes_key_at_all():
    """An empty `hashes` array would read as "hashed, value unknown". Omitting
    the key reads as "not hashed", which is what is true.
    """
    bom = compile_ai_bom(
        tenant="acme",
        inventories=(_inventory(_record(AssetKind.MODEL, "m")),),
        generated_at=NOW,
    )
    component = bom.as_cyclonedx()["components"][0]

    assert "hashes" not in component


def test_a_digest_is_exported_as_a_sha256_hash():
    bom = compile_ai_bom(
        tenant="acme",
        inventories=(_inventory(_record(AssetKind.MODEL, "m", digest="abc123")),),
        generated_at=NOW,
    )
    component = bom.as_cyclonedx()["components"][0]

    assert component["hashes"] == [{"alg": "SHA-256", "content": "abc123"}]


# ── serialisation discipline ─────────────────────────────────────────────────


def test_the_document_contains_no_floats():
    """The canonical JSON form refuses floats, so a float anywhere here would
    make the document unsignable -- and it would be found at signing time
    rather than now.
    """

    def walk(value, path="root"):
        if isinstance(value, float):
            raise AssertionError(f"float at {path}")
        if isinstance(value, dict):
            for key, item in value.items():
                walk(item, f"{path}.{key}")
        elif isinstance(value, (list, tuple)):
            for index, item in enumerate(value):
                walk(item, f"{path}[{index}]")

    bom = compile_ai_bom(
        tenant="acme",
        inventories=(
            _inventory(
                _record(AssetKind.MODEL, "m", version="1", digest="d"),
                _record(AssetKind.SKILL, "s"),
            ),
        ),
        generated_at=NOW,
    )
    walk(bom.as_dict())
    walk(bom.as_cyclonedx())


def test_components_are_ordered_deterministically():
    """Two runs over the same estate must produce the same bytes, or every diff
    between BOMs is noise and nobody reads them.
    """
    records = (
        _record(AssetKind.SKILL, "z"),
        _record(AssetKind.MODEL, "b"),
        _record(AssetKind.MODEL, "a"),
    )
    first = compile_ai_bom(
        tenant="acme", inventories=(_inventory(*records),), generated_at=NOW
    )
    second = compile_ai_bom(
        tenant="acme",
        inventories=(_inventory(*tuple(reversed(records))),),
        generated_at=NOW,
    )

    assert first.as_dict() == second.as_dict()
    assert [c.identifier for c in first.components] == ["a", "b", "z"]


def test_coverage_is_kept_per_connector_and_never_summed():
    """Two connectors that each examined 40 objects in different scopes did not
    examine 80 of anything.
    """
    bom = compile_ai_bom(
        tenant="acme",
        inventories=(
            _inventory(connector="k8s", coverage=_coverage(examined=40)),
            _inventory(connector="aws", coverage=_coverage(examined=40)),
        ),
        generated_at=NOW,
    )
    document = bom.as_dict()

    assert len(document["sources"]) == 2
    assert all("examined" in s["coverage"] for s in document["sources"])
    assert "examined" not in document, "a single total invites the wrong reading"


def test_the_module_holds_no_mutable_state():
    import types

    from sentinel.domain import ai_bom

    mutable = [
        name
        for name, value in vars(ai_bom).items()
        if not name.startswith("__")
        and isinstance(value, (dict, list, set))
        and not isinstance(value, types.MappingProxyType)
    ]
    assert not mutable, f"module-level mutable state: {mutable}"
