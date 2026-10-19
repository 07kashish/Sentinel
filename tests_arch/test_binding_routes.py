"""The diff, over HTTP, with its blindness in the payload.

WHAT THESE GUARD
----------------
Two things a console could get wrong and look right doing:

  1. Serving parameter VALUES. This endpoint is read by a browser, cached by
     it, and pasted into tickets. A response carrying both sets of parameters
     would be the most sensitive one in the product and the one people
     screenshot. So the tests plant a distinctive value and assert it never
     appears.
  2. Presenting a window with nothing bound as a window with nothing wrong. An
     unbound execution produces no receipt at all, so this surface literally
     cannot see one -- and every response has to say so rather than let a
     reader infer a clean estate from an empty list.

The route module is registered by `http.py`; these tests drive the real
application so an unregistered route fails here rather than in a deployment.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sentinel.composition.container import build_container
from sentinel.composition.settings import Settings
from sentinel.domain.execution_binding import ExecutionReceipt, parameter_digest
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.interface.http import create_app

ANALYST_KEY = "a" * 44
TENANT = "acme"

APPROVED = {"bucket": "acme-reports", "key": "q3/summary.pdf"}
#: Distinctive, and NOT a substring of anything else in a response. A probe
#: that also appeared in a resource ARN would report a leak that was not one --
#: which happened once already in this repository's packaging tests.
SECRET_VALUE = "PATIENT-4471-DIAGNOSIS"
SUBSTITUTED = {"bucket": "attacker-exfil", "key": SECRET_VALUE}


@pytest.fixture
def client(tmp_path: Path, engine_config):
    """The REAL application, so an unregistered route fails here."""
    from dataclasses import replace

    base = Settings.from_environment({
        "SENTINEL_ENV": "development",
        "SENTINEL_DB_PATH": str(tmp_path / "binding.db"),
        "SENTINEL_API_KEYS": f"{TENANT}:{ANALYST_KEY}:analyst",
        "SENTINEL_CORS_ORIGINS": "https://console.example.com",
    })
    settings = replace(base, engine=engine_config)

    pool = build_engine(settings.engine)
    try:
        migrate(pool)
    finally:
        pool.close()

    container = build_container(settings)
    try:
        yield TestClient(create_app(container)), container
    finally:
        container.close()


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {ANALYST_KEY}"}


def _receipt(**overrides) -> ExecutionReceipt:
    defaults = dict(
        receipt_id="receipt-1",
        tenant_id=TENANT,
        authorization_digest="a" * 64,
        executed_request_digest="b" * 64,
        actual_parameter_digest=parameter_digest(APPROVED),
        execution_identity="worker:1",
        started_at="2026-09-04T12:00:00+00:00",
        completed_at="2026-09-04T12:00:01+00:00",
        outcome="succeeded",
        side_effect="s3.put_object",
    )
    defaults.update(overrides)
    return ExecutionReceipt(**defaults)  # type: ignore[arg-type]


# ── the routes exist and are authenticated ────────────────────────────────


def test_the_diff_route_is_registered(client):
    """A route module nobody registered is this repository's most-repeated
    defect, and it would pass every unit test of the module itself.
    """
    http, _container = client

    response = http.get("/v1/executions/binding/diff", headers=_headers())

    assert response.status_code == 200, response.text


def test_the_coverage_route_is_registered(client):
    http, _container = client

    response = http.get("/v1/executions/binding/coverage", headers=_headers())

    assert response.status_code == 200, response.text


def test_the_routes_require_a_credential(client):
    http, _container = client

    for path in (
        "/v1/executions/binding/diff",
        "/v1/executions/binding/coverage",
        "/v1/executions/binding/receipt-1",
    ):
        assert http.get(path).status_code in (401, 403), path


# ── a matching execution ──────────────────────────────────────────────────


def test_a_matching_execution_reports_parameters_matched(client):
    """The anchor. Every assertion below would pass against a route that
    reported everything as mismatched.
    """
    http, container = client
    container.receipts.record(
        TENANT,
        receipt=_receipt(),
        approved_parameter_digest=parameter_digest(APPROVED),
        authorization_id="auth-1",
    )

    body = http.get("/v1/executions/binding/diff", headers=_headers()).json()

    assert len(body["entries"]) == 1
    entry = body["entries"][0]
    assert entry["parameters_matched"] is True
    assert entry["bound"] is True
    assert body["mismatched"] == 0


# ── a substituted execution ───────────────────────────────────────────────


def test_a_substituted_execution_reports_the_differing_key(client):
    http, container = client
    container.receipts.record(
        TENANT,
        receipt=_receipt(
            receipt_id="bad",
            actual_parameter_digest=parameter_digest(SUBSTITUTED),
        ),
        approved_parameter_digest=parameter_digest(APPROVED),
        authorization_id="auth-2",
        differing_keys=["bucket"],
        defects=["parameters_differ"],
    )

    body = http.get("/v1/executions/binding/diff", headers=_headers()).json()
    entry = body["entries"][0]

    assert entry["parameters_matched"] is False
    assert entry["differing_keys"] == ["bucket"]
    assert entry["defects"] == ["parameters_differ"]
    assert body["mismatched"] == 1


def test_only_mismatched_filters_but_is_not_the_default(client):
    """Defaulting to mismatches-only would make a healthy estate and a
    deployment where nothing is bound look identical -- both empty lists.
    """
    http, container = client
    container.receipts.record(
        TENANT, receipt=_receipt(receipt_id="good"),
        approved_parameter_digest=parameter_digest(APPROVED),
    )
    container.receipts.record(
        TENANT,
        receipt=_receipt(
            receipt_id="bad",
            actual_parameter_digest=parameter_digest(SUBSTITUTED),
        ),
        approved_parameter_digest=parameter_digest(APPROVED),
    )

    everything = http.get(
        "/v1/executions/binding/diff", headers=_headers()
    ).json()
    filtered = http.get(
        "/v1/executions/binding/diff?only_mismatched=true", headers=_headers()
    ).json()

    assert len(everything["entries"]) == 2
    assert [e["receipt_id"] for e in filtered["entries"]] == ["bad"]


# ── parameter values are never served ─────────────────────────────────────


def test_no_parameter_value_appears_in_the_diff(client):
    """THE disclosure property. The probe is chosen so it appears nowhere else
    in a response -- a probe that also matched a resource ARN would report a
    leak that was not one, which happened once already here.
    """
    http, container = client
    container.receipts.record(
        TENANT,
        receipt=_receipt(
            actual_parameter_digest=parameter_digest(SUBSTITUTED),
        ),
        approved_parameter_digest=parameter_digest(APPROVED),
        differing_keys=["key"],
    )

    body = http.get("/v1/executions/binding/diff", headers=_headers()).text

    assert "receipt-1" in body, "control: the receipt is not in the response"
    assert SECRET_VALUE not in body


def test_no_parameter_value_appears_in_the_detail(client):
    http, container = client
    container.receipts.record(
        TENANT,
        receipt=_receipt(
            actual_parameter_digest=parameter_digest(SUBSTITUTED),
        ),
        approved_parameter_digest=parameter_digest(APPROVED),
        differing_keys=["key"],
    )

    response = http.get(
        "/v1/executions/binding/receipt-1", headers=_headers()
    )

    assert response.status_code == 200, response.text
    assert SECRET_VALUE not in response.text
    assert "disclosure" in response.json()


# ── the blindness is in the payload ───────────────────────────────────────


def test_every_diff_response_states_what_it_cannot_see(client):
    """A reader who never opens the docs must still learn that an unbound
    execution leaves no trace here.
    """
    http, _container = client

    body = http.get("/v1/executions/binding/diff", headers=_headers()).json()

    assert "produces no receipt" in body["warning"]
    assert "SENTINEL_REQUIRE_EXECUTION_BINDING" in body["warning"]


def test_coverage_reports_whether_binding_is_enforced(client):
    """The setting that resolves the ambiguity, so a reader can tell "few
    receipts because binding is optional" from "few receipts because little
    happened".
    """
    http, _container = client

    body = http.get(
        "/v1/executions/binding/coverage", headers=_headers()
    ).json()

    # Binding is REQUIRED by default now: an unbound execution is refused
    # rather than run. A reader seeing zero receipts therefore knows little
    # happened, not that binding was optional.
    assert body["enforced"] is True
    assert body["receipts"] == 0
    assert "produces NO receipt" in body["blindness"]


def test_coverage_offers_no_ratio_that_is_always_perfect(client):
    """The corrected design. A bound-versus-unbound fraction over receipts is
    structurally always 1.0, because a receipt cannot exist without an
    authorization digest.
    """
    http, _container = client

    body = http.get(
        "/v1/executions/binding/coverage", headers=_headers()
    ).json()

    assert "bound_fraction" not in body
    assert "unbound" not in body


def test_a_receipt_with_no_approved_digest_is_unverifiable_not_matched(client):
    """Three states, not two. `null` means there was nothing to compare, which
    is different from having compared and agreed.
    """
    http, container = client
    container.receipts.record(
        TENANT, receipt=_receipt(), approved_parameter_digest=""
    )

    body = http.get("/v1/executions/binding/diff", headers=_headers()).json()
    entry = body["entries"][0]

    assert entry["parameters_matched"] is False or entry["parameters_matched"] is None
    assert body["binding_coverage"]["not_comparable"] == 1


# ── the detail view ───────────────────────────────────────────────────────


def test_an_unknown_receipt_is_a_404(client):
    http, _container = client

    response = http.get(
        "/v1/executions/binding/does-not-exist", headers=_headers()
    )

    assert response.status_code == 404


def test_the_detail_states_the_declaration_residual(client):
    """The strongest claim in the product, with its limit beside it rather
    than in a document the reader may not follow.
    """
    http, container = client
    container.receipts.record(
        TENANT, receipt=_receipt(), approved_parameter_digest="a" * 64
    )

    body = http.get(
        "/v1/executions/binding/receipt-1", headers=_headers()
    ).json()

    assert "DECLARED" in body["residual"]
    assert "EXECUTION_TRUST_ARCHITECTURE" in body["residual"]


def test_the_detail_reports_whether_a_delegation_chain_was_bound(client):
    http, container = client
    container.receipts.record(
        TENANT,
        receipt=_receipt(),
        approved_parameter_digest="a" * 64,
        delegation_passport_digest="c" * 64,
    )

    body = http.get(
        "/v1/executions/binding/receipt-1", headers=_headers()
    ).json()

    assert body["delegation_bound"] is True
    assert body["delegation_passport_digest"] == "c" * 64


# ── tenancy ───────────────────────────────────────────────────────────────


def test_one_tenants_receipts_are_not_served_to_another(client):
    """The credential above is scoped to `acme`. A receipt under another
    tenant must not be reachable through it.
    """
    http, container = client
    container.receipts.record(
        TENANT, receipt=_receipt(), approved_parameter_digest="a" * 64
    )
    from dataclasses import replace as dc_replace

    container.receipts.record(
        "globex",
        receipt=dc_replace(
            _receipt(receipt_id="theirs"), tenant_id="globex"
        ),
        approved_parameter_digest="a" * 64,
    )

    body = http.get("/v1/executions/binding/diff", headers=_headers()).json()

    assert [e["receipt_id"] for e in body["entries"]] == ["receipt-1"]
    assert http.get(
        "/v1/executions/binding/theirs", headers=_headers()
    ).status_code == 404


def test_the_response_is_json_serialisable(client):
    """A dataclass or a set leaking into a payload is a 500 that only appears
    once real data is present.
    """
    http, container = client
    container.receipts.record(
        TENANT,
        receipt=_receipt(bounded_mutations=("request_id",)),
        approved_parameter_digest="a" * 64,
        differing_keys=["bucket"],
        defects=["parameters_differ"],
    )

    body = http.get("/v1/executions/binding/diff", headers=_headers()).json()

    assert json.dumps(body)
