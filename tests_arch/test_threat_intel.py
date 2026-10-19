"""Nothing that crosses a tenant boundary describes a tenant.

WHAT IS BEING PROVEN
--------------------
Pooled threat intelligence is the fastest way to leak a customer's estate.
"Server X is malicious" tells every reader that somebody runs X, and an
indicator observed by exactly one reporter IS that reporter's inventory with a
security label attached.

So these tests are about ABSENCE: no tenant id, no exact count, no denominator,
no sub-day timestamp, no private hostname, no cloud resource path. Absence is
harder to test than presence, because a field that was never populated and a
field that is correctly withheld look identical from outside -- so several of
these construct the leak deliberately and require the refusal.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from sentinel.domain.threat_intel import (
    MIN_DISTINCT_REPORTERS,
    Confidence,
    IndicatorKind,
    LocalObservation,
    PublishRefusal,
    ReporterBand,
    aggregate,
    fingerprint,
)

WHEN = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)


def _seen(
    value: str,
    tenants: list[str],
    *,
    kind: IndicatorKind = IndicatorKind.MALICIOUS_PACKAGE,
    corroborating: bool = False,
    detail: str = "",
) -> list[LocalObservation]:
    return [
        LocalObservation(
            kind=kind,
            value=value,
            tenant_id=tenant,
            observed_at=WHEN,
            corroborating_mechanism=corroborating,
            detail=detail,
        )
        for tenant in tenants
    ]


# ── k-anonymity ──────────────────────────────────────────────────────────────


def test_one_reporter_is_never_published():
    """THE core rule. A single-source indicator is one tenant's inventory."""
    result = aggregate(_seen("evil-pkg", ["acme"]), population=50)
    assert result.publishable == ()
    assert result.withheld
    assert result.withheld[0][1] is PublishRefusal.TOO_FEW_REPORTERS


def test_two_reporters_are_not_enough():
    """With two, either reporter can subtract themselves and identify the other.

    That is why the threshold is three and not two, and this is the test that
    would fail if somebody lowered it for coverage.
    """
    result = aggregate(_seen("evil-pkg", ["acme", "globex"]), population=50)
    assert result.publishable == ()


def test_the_threshold_is_the_documented_number():
    assert MIN_DISTINCT_REPORTERS == 3
    result = aggregate(_seen("evil-pkg", ["a", "b", "c"]), population=50)
    assert len(result.publishable) == 1


def test_the_same_tenant_reporting_repeatedly_does_not_reach_the_threshold():
    """Counting sightings instead of reporters would let one deployment publish
    its own inventory by observing the same thing three times -- which is what
    a retry loop does.
    """
    result = aggregate(_seen("evil-pkg", ["acme", "acme", "acme"]), population=50)
    assert result.publishable == ()
    assert result.withheld[0][1] is PublishRefusal.TOO_FEW_REPORTERS


def test_nothing_is_published_when_the_population_is_too_small():
    """k-anonymity over four tenants is arithmetic, not privacy."""
    from sentinel.domain.threat_intel import MIN_POPULATION

    assert MIN_POPULATION == 10
    result = aggregate(_seen("evil-pkg", ["a", "b", "c"]), population=4)
    assert result.publishable == ()
    assert {reason for _f, reason in result.withheld} == {
        PublishRefusal.POPULATION_TOO_SMALL
    }


def test_the_population_is_supplied_rather_than_inferred():
    """Inferring it from who reported makes the denominator equal the numerator,
    and every indicator then looks unanimous.
    """
    import inspect

    from sentinel.domain import threat_intel

    signature = inspect.signature(threat_intel.aggregate)
    assert "population" in signature.parameters
    assert signature.parameters["population"].kind is inspect.Parameter.KEYWORD_ONLY


# ── no tenant survives ───────────────────────────────────────────────────────


def test_no_tenant_id_survives_aggregation():
    """The property the whole module rests on.

    Serialised and searched, rather than checked field by field: a field added
    later that happens to carry the tenant would pass an attribute check and
    fail this.
    """
    tenants = ["acme-corp", "globex-industries", "initech-llc"]
    result = aggregate(_seen("evil-pkg", tenants), population=50)
    assert len(result.publishable) == 1

    blob = json.dumps(result.as_dict())
    for tenant in tenants:
        assert tenant not in blob, f"{tenant!r} leaked into the published record"


def test_the_withheld_list_names_no_values_and_no_tenants():
    """A refusal must not disclose what it refused.

    An indicator below the threshold is one tenant's inventory; saying "we
    withheld `billing.acme.internal`" publishes it in the act of declining to.
    """
    result = aggregate(
        _seen(
            "billing.acme.internal",
            ["acme"],
            kind=IndicatorKind.EXFILTRATION_DOMAIN,
        ),
        population=50,
    )
    blob = json.dumps(result.as_dict())
    assert "billing.acme.internal" not in blob
    assert "acme" not in blob


# ── counts and time are coarse ───────────────────────────────────────────────


def test_the_exact_reporter_count_is_never_published():
    """A count that moves by one when a deployment joins tells a watcher
    something about a specific participant.
    """
    result = aggregate(_seen("evil-pkg", [f"t{n}" for n in range(7)]), population=50)
    indicator = result.publishable[0]
    assert indicator.reporters is ReporterBand.SEVERAL
    blob = json.dumps(indicator.as_dict())
    assert "7" not in blob or "6-20" in blob


@pytest.mark.parametrize(
    "count,band",
    [
        (3, ReporterBand.FEW),
        (5, ReporterBand.FEW),
        (6, ReporterBand.SEVERAL),
        (20, ReporterBand.SEVERAL),
        (21, ReporterBand.MANY),
        (150, ReporterBand.WIDESPREAD),
    ],
)
def test_reporter_bands(count, band):
    result = aggregate(
        _seen("evil-pkg", [f"t{n}" for n in range(count)]), population=500
    )
    assert result.publishable[0].reporters is band


def test_no_denominator_is_published():
    """"3 of 4" is close to naming them, and the population is not the reader's
    business in any case.
    """
    result = aggregate(_seen("evil-pkg", ["a", "b", "c"]), population=37)
    assert "37" not in json.dumps(result.as_dict())


def test_only_the_date_is_published_never_the_time():
    """A timestamp to the second correlates an indicator with one deployment's
    activity window.
    """
    result = aggregate(_seen("evil-pkg", ["a", "b", "c"]), population=50)
    record = result.publishable[0].as_dict()
    assert record["first_seen"] == "2026-09-01"
    assert "12:00" not in json.dumps(record)
    assert "T" not in str(record["first_seen"])


# ── value-level refusals ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "host",
    [
        "billing.acme.internal",
        "localhost",
        "10.0.4.11",
        "192.168.1.7",
        "172.20.0.9",
        "169.254.169.254",
        "postgres.svc.cluster.local",
        "runner.corp",
    ],
)
def test_a_private_hostname_is_never_published(host):
    """It describes the reporter's own network, and it is useless to anybody
    else -- the same name means something different in every estate.

    169.254.169.254 is in the list on purpose: the cloud metadata endpoint is
    the single most interesting exfiltration destination and the single least
    publishable, because every deployment has it.
    """
    result = aggregate(
        _seen(host, ["a", "b", "c", "d"], kind=IndicatorKind.EXFILTRATION_DOMAIN),
        population=50,
    )
    assert result.publishable == ()
    assert {r for _f, r in result.withheld} == {PublishRefusal.PRIVATE_HOSTNAME}


@pytest.mark.parametrize(
    "value",
    [
        "arn:aws:iam::123456789012:role/agent",
        "projects/acme-prod-1234/locations/us/agents/x",
        "/subscriptions/8b3f2c1a-4d5e-6f70-8192-a3b4c5d6e7f8/resourceGroups/rg",
        "acme-backups.s3.us-east-1.amazonaws.com",
        "acme-prod.rds.eu-west-1.amazonaws.com",
    ],
)
def test_a_cloud_resource_path_is_never_published(value):
    """Checked on the VALUE, not the kind. The kind cannot stop somebody
    putting an ARN in a package-name field, and that is exactly the mistake a
    connector makes when a field is mis-mapped.
    """
    result = aggregate(_seen(value, ["a", "b", "c", "d"]), population=50)
    assert result.publishable == ()
    assert {r for _f, r in result.withheld} == {PublishRefusal.TENANT_SHAPED_VALUE}


def test_a_public_domain_is_published():
    """The refusals must not be so broad that nothing useful survives."""
    result = aggregate(
        _seen(
            "exfil.attacker-cdn.example",
            ["a", "b", "c"],
            kind=IndicatorKind.EXFILTRATION_DOMAIN,
        ),
        population=50,
    )
    assert len(result.publishable) == 1
    assert result.publishable[0].public_value == "exfil.attacker-cdn.example"


# ── what may appear in the clear ─────────────────────────────────────────────


def test_an_mcp_definition_publishes_a_fingerprint_and_not_the_definition():
    """A tool definition can carry a tenant's internal resource names, and a
    poisoned description is attacker text that may also quote them. The digest
    is what a consumer needs to match on.
    """
    result = aggregate(
        _seen(
            "read_file: reads /srv/acme/prod/secrets",
            ["a", "b", "c"],
            kind=IndicatorKind.MCP_TOOL_DEFINITION,
        ),
        population=50,
    )
    indicator = result.publishable[0]
    assert indicator.public_value == ""
    assert indicator.fingerprint
    assert "acme" not in json.dumps(indicator.as_dict())


def test_a_package_name_is_published_because_it_is_already_public():
    result = aggregate(_seen("reqeusts", ["a", "b", "c"],
                             kind=IndicatorKind.TYPOSQUAT_PACKAGE),
                       population=50)
    assert result.publishable[0].public_value == "reqeusts"


# ── fingerprints ─────────────────────────────────────────────────────────────


def test_the_fingerprint_is_scoped_by_kind():
    """A package name and a domain can coincide. Merging their reporter sets
    would inflate one indicator's count with the other's observers, which is a
    k-anonymity failure disguised as a hash collision.
    """
    same = "corp-utils"
    assert fingerprint(same, kind=IndicatorKind.MALICIOUS_PACKAGE) != fingerprint(
        same, kind=IndicatorKind.EXFILTRATION_DOMAIN
    )


def test_the_fingerprint_is_stable_across_deployments():
    """Unsalted on purpose: the whole mechanism depends on two deployments
    computing the SAME identifier for the same artefact. A per-tenant salt
    would make the reporter count permanently one.
    """
    assert fingerprint("Evil-Pkg ", kind=IndicatorKind.MALICIOUS_PACKAGE) == (
        fingerprint("evil-pkg", kind=IndicatorKind.MALICIOUS_PACKAGE)
    )


# ── the schema cannot grow a tenant-shaped field ─────────────────────────────


def test_no_indicator_kind_describes_a_tenant():
    """The enum is the schema. A member named for an agent id, a credential or
    an internal resource would make a leak the correct use of the type.
    """
    forbidden = (
        "agent", "credential", "secret", "resource", "arn", "host",
        "endpoint", "server_id", "tenant", "user", "principal", "session",
    )
    offenders = [
        kind.value
        for kind in IndicatorKind
        for word in forbidden
        if word in kind.value
    ]
    assert not offenders, (
        f"these indicator kinds name tenant-owned things: {offenders}. An "
        "indicator must describe an artefact that exists independently of who "
        "found it."
    )


def test_an_observation_without_a_tenant_is_refused():
    """An uncounted reporter is how a single-source indicator reaches the
    threshold: three anonymous sightings would look like three tenants.
    """
    with pytest.raises(ValueError):
        LocalObservation(
            kind=IndicatorKind.MALICIOUS_PACKAGE,
            value="x",
            tenant_id="  ",
            observed_at=WHEN,
        )


# ── confidence is advisory, not authority ────────────────────────────────────


def test_a_deterministic_mechanism_is_corroborated():
    result = aggregate(
        _seen("evil-pkg", ["a", "b", "c"], corroborating=True), population=50
    )
    assert result.publishable[0].confidence is Confidence.CORROBORATED


def test_a_heuristic_mechanism_is_only_suspected():
    result = aggregate(_seen("evil-pkg", ["a", "b", "c"]), population=50)
    assert result.publishable[0].confidence is Confidence.SUSPECTED


def test_no_published_field_can_be_read_as_an_authorization_decision():
    """Reputation is input to a human or a policy author. A field named `block`
    or `verdict` would eventually be wired into an enforcement path, and an ML-
    or crowd-derived score must never decide a destructive action by itself.
    """
    result = aggregate(_seen("evil-pkg", ["a", "b", "c"]), population=50)
    keys = set(result.publishable[0].as_dict())
    assert not keys & {"decision", "verdict", "action", "block", "allow", "enforce"}


def test_the_module_holds_no_mutable_state():
    """A shared reputation cache is cross-tenant state by construction."""
    import types

    from sentinel.domain import threat_intel

    mutable = [
        name
        for name, value in vars(threat_intel).items()
        if not name.startswith("__")
        and isinstance(value, (dict, list, set))
        and not isinstance(value, types.MappingProxyType)
    ]
    assert not mutable, f"module-level mutable state: {mutable}"
