"""The internal red-team suite: every release gets attacked.

    §76  Build an internal red-team suite before creating a commercial
         red-team product. Each release should be attacked. Track:
         attack / expected detection / expected prevention / actual result /
         regression

WHY THIS IS NOT THE SAME AS THE DETECTION TESTS
-------------------------------------------------
Every other test module here asserts that a component behaves correctly. This
one asserts that the ASSEMBLED PRODUCT resists an attack, and the difference is
not academic: Phase 4 shipped five correct components of which four were
unreachable, and every unit test passed throughout. An attacker does not call
your functions directly.

So each case below drives the real HTTP surface with a real container, and the
expectation is written as two SEPARATE claims:

    expected_detection   -- an incident is raised
    expected_prevention  -- the action is refused

Keeping them apart is the point. Sentinel detects far more than it prevents, on
purpose -- correlation is self-reported, so blocking on it would be a control an
attacker can trigger against someone else. A suite with one boolean would force
every case into "did we stop it", and the honest answer for most of them is
"no, deliberately, and here is why".

THE `expected_prevention=False` ROWS ARE THE HONEST PART
---------------------------------------------------------
A red-team report where every row says PREVENTED is a report nobody should
believe. The rows below that expect detection without prevention are the
product's actual posture written down, so that a future change which starts
blocking one of them shows up as a diff in this file and gets argued about --
rather than being discovered by a customer whose agent stopped working.

REGRESSION IS THE WHOLE VALUE
-------------------------------
`RED_TEAM_CASES` is the tracked table §76 asks for. A case that used to be
detected and now is not fails the build. That is the property that makes this a
suite rather than an exercise.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient

from sentinel.composition.container import build_container
from sentinel.composition.settings import Settings
from sentinel.infrastructure.sql.engine import Dialect, build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.interface.http import create_app

TENANT = "acme"
INGEST_KEY = "ingest-key-0000000000000000000000"
VIEW_KEY = "viewer-key-0000000000000000000000"


@dataclass(frozen=True, slots=True)
class RedTeamCase:
    """One attack, and what this release is expected to do about it."""

    name: str
    #: What the attacker is trying to achieve, in one line.
    objective: str
    #: The events the attacker sends, in order.
    steps: tuple[dict, ...]
    #: An incident is raised.
    expected_detection: bool
    #: The request is refused. False is a real answer, not a gap -- see the
    #: module docstring.
    expected_prevention: bool
    #: Why prevention is or is not expected. Required, because a table of
    #: booleans with no reasoning is what turns into a marketing claim.
    rationale: str = ""


def _step(action: str, **kw) -> dict:
    step = {
        "eventId": kw.pop("event_id", "e1"),
        "parentEventId": kw.pop("parent", ""),
        "sessionId": kw.pop("session", "s-red"),
        "agentId": kw.pop("agent", "worker"),
        "eventType": kw.pop("event_type", "tool_call"),
        "action": action,
        "resource": kw.pop("resource", ""),
        "destination": kw.pop("destination", None),
        "metadata": kw.pop("metadata", {}),
        "timestamp": kw.pop("timestamp", "2026-08-24T10:00:00Z"),
    }
    step.update(kw)
    return step


#: The tracked table §76 asks for. Append-only in spirit: removing a row is
#: removing a claim about what this product resists.
RED_TEAM_CASES: tuple[RedTeamCase, ...] = (
    RedTeamCase(
        name="staged_exfiltration",
        objective="Read sensitive data, compress it, ship it outside the estate.",
        steps=(
            _step("read_file", event_id="x1", resource="customers"),
            _step("zip", event_id="x2", parent="x1"),
            _step(
                "http_post",
                event_id="x3",
                parent="x2",
                destination="https://attacker.example",
            ),
        ),
        expected_detection=True,
        expected_prevention=False,
        rationale=(
            "Every step is individually legitimate; only the ORDER is the "
            "attack, and order is reconstructed from self-reported correlation. "
            "Blocking on it would let an attacker halt someone else's agent by "
            "forging a chain, so it raises an incident and does not refuse."
        ),
    ),
    RedTeamCase(
        name="credential_to_privilege",
        objective="Read a secret, log in with it, then grant itself a role.",
        steps=(
            _step("read_secret", event_id="c1"),
            _step("cloud_login", event_id="c2", parent="c1"),
            _step("grant_role", event_id="c3", parent="c2"),
        ),
        expected_detection=True,
        expected_prevention=False,
        rationale=(
            "Scores CRITICAL because the privilege change makes the first two "
            "steps durable. Still self-reported correlation, so same posture: "
            "full-severity evidence to a human, no automatic action."
        ),
    ),
    RedTeamCase(
        name="out_of_order_steps_are_not_an_attack",
        objective="Confirm the detector matches a SEQUENCE and not a set.",
        steps=(
            _step("http_post", event_id="o1"),
            _step("zip", event_id="o2", parent="o1"),
            _step("read_file", event_id="o3", parent="o2"),
        ),
        expected_detection=False,
        expected_prevention=False,
        rationale=(
            "Uploading, then compressing, then reading is not an exfiltration. "
            "A rule that fired here would be matching a set, and would flag "
            "ordinary work constantly."
        ),
    ),
    RedTeamCase(
        name="incomplete_chain_is_not_an_attack",
        objective="Confirm a prefix of a rule does not fire it.",
        steps=(
            _step("read_file", event_id="p1"),
            _step("zip", event_id="p2", parent="p1"),
        ),
        expected_detection=False,
        expected_prevention=False,
        rationale=(
            "Two of three steps is not the pattern. Firing on a prefix would "
            "flag every agent that ever read a file and compressed it."
        ),
    ),
    RedTeamCase(
        name="unverified_caller_claims_critical_severity",
        objective="Manufacture a CRITICAL incident by asserting one.",
        steps=(
            _step(
                "read_file",
                event_id="s1",
                severity=100,
                metadata={"severity": 100, "priority": "CRITICAL"},
            ),
        ),
        expected_detection=False,
        expected_prevention=False,
        rationale=(
            "The predecessor let an ingest-role key post its own severity. "
            "Severity is computed from the policy, never accepted from the "
            "caller, so the claim has no effect at all -- which is why nothing "
            "is detected and nothing is refused."
        ),
    ),
)


@pytest.fixture
def client(engine_config):
    env = {
        "SENTINEL_ENV": "development",
        "SENTINEL_API_KEYS": (
            f"{TENANT}:{INGEST_KEY}:ingest,{TENANT}:{VIEW_KEY}:viewer"
        ),
    }
    if engine_config.dialect is Dialect.POSTGRES:
        env["SENTINEL_DATABASE_URL"] = engine_config.dsn
        env["SENTINEL_DB_POOL_MIN"] = "1"
        env["SENTINEL_DB_POOL_MAX"] = "4"
    else:
        env["SENTINEL_DB_PATH"] = engine_config.dsn

    settings = Settings.from_environment(env)
    pool = build_engine(settings.engine)
    migrate(pool)
    pool.close()

    container = build_container(settings)
    try:
        with container.pool.acquire() as conn:
            conn.begin()
            conn.execute_rowcount(
                f"INSERT INTO tenants (tenant_id, name, created_at) "
                f"VALUES ({conn.p},{conn.p},{conn.p}) "
                f"ON CONFLICT (tenant_id) DO NOTHING",
                (TENANT, "Acme", "2026-08-24T00:00:00+00:00"),
            )
            conn.commit()
        yield TestClient(create_app(container), raise_server_exceptions=False)
    finally:
        container.close()


def _run_attack(client, case: RedTeamCase) -> dict:
    """Send the attack and report what actually happened.

    Returns the §76 row: what was detected, what was refused, and -- added
    after a review found the earlier version conflating them -- whether the app
    ERRORED.

    A 5xx used to be counted as `prevented=True`. It is not a prevention: a
    crashing app produces the same observable as a working refusal, so a case
    whose app fell over would report "prevented" and satisfy every row
    expecting prevention. That was masked by
    `test_no_tracked_attack_returns_a_server_error_on_the_ingest_surface`, but
    a mitigation living in a different test is a mitigation that disappears the
    moment that test is moved, renamed or marked xfail.
    """
    detected = False
    prevented = False
    errored = False
    for step in case.steps:
        response = client.post(
            "/v1/events",
            headers={"Authorization": f"Bearer {INGEST_KEY}"},
            json=step,
        )
        if response.status_code >= 500:
            # Recorded as its own fact. Not a defence, and not a detection.
            errored = True
            continue
        if response.status_code in {401, 403, 409, 422}:
            prevented = True
            continue
        body = response.json()
        if str(body.get("outcome", "")) == "incident_admitted":
            detected = True
    return {
        "attack": case.name,
        "detected": detected,
        "prevented": prevented,
        "errored": errored,
    }


@pytest.mark.parametrize(
    "case", RED_TEAM_CASES, ids=[case.name for case in RED_TEAM_CASES]
)
def test_a_tracked_attack_produces_the_tracked_outcome(client, case):
    """The regression gate. A case that used to be detected and now is not
    fails the build, which is the property that makes this a suite rather than
    an exercise."""
    result = _run_attack(client, case)

    assert not result["errored"], (
        f"{case.name}: the app returned 5xx while under attack. This is a "
        "finding in itself, and it is asserted HERE rather than only in the "
        "separate 5xx test, because a crash produces the same observable as a "
        "refusal -- so a case that errored must not be allowed to satisfy a "
        "row expecting prevention."
    )
    assert result["detected"] == case.expected_detection, (
        f"{case.name}: expected detection={case.expected_detection}, "
        f"got {result['detected']}.\n"
        f"Objective: {case.objective}\n"
        f"Rationale on file: {case.rationale}"
    )
    assert result["prevented"] == case.expected_prevention, (
        f"{case.name}: expected prevention={case.expected_prevention}, "
        f"got {result['prevented']}.\n"
        f"Rationale on file: {case.rationale}"
    )


def test_no_tracked_attack_returns_a_server_error_on_the_ingest_surface(client):
    """A 5xx from an attack is a finding in itself.

    It means the attacker reached an unhandled path, and an unhandled path in an
    ingest endpoint is both a denial-of-service primitive and a signal that the
    input was not understood.

    SCOPE, STATED BECAUSE THE PREVIOUS NAME OVERSTATED IT
    -------------------------------------------------------
    This visits `/v1/events` and nothing else. It was called
    `test_no_attack_ever_returns_a_server_error`, which reads as a claim about
    the whole API -- and that claim was false: schemathesis found a 500 on
    `/v1/policy/diff` from an out-of-range integer while this test was passing.

    A claim is only as wide as the surface it actually visits. Breadth across the
    API is the fuzzer's job in CI (`dynamic-api-security`), which generates
    inputs this hand-written table never would; this test's job is that the
    TRACKED attacks stay handled. Both are needed, and neither substitutes for
    the other.
    """
    for case in RED_TEAM_CASES:
        for step in case.steps:
            response = client.post(
                "/v1/events",
                headers={"Authorization": f"Bearer {INGEST_KEY}"},
                json=step,
            )
            assert response.status_code < 500, (
                f"{case.name} produced {response.status_code}: {response.text[:200]}"
            )


def test_every_tracked_case_records_why_prevention_is_or_is_not_expected():
    """A table of booleans with no reasoning is what turns into a marketing
    claim. Every row must say why."""
    for case in RED_TEAM_CASES:
        assert len(case.rationale) > 60, f"{case.name} has a placeholder rationale"
        assert case.objective, f"{case.name} has no stated objective"


def test_the_suite_contains_cases_that_are_deliberately_not_prevented():
    """A red-team report where every row says PREVENTED is a report nobody
    should believe.

    This asserts the suite is honest about posture rather than curated to look
    good: Sentinel detects far more than it prevents, on purpose, because
    correlation is self-reported and blocking on it would be a control an
    attacker can aim at someone else."""
    detected_not_prevented = [
        case
        for case in RED_TEAM_CASES
        if case.expected_detection and not case.expected_prevention
    ]
    assert detected_not_prevented, (
        "every case claims prevention; either the suite is curated or the "
        "product's posture changed and this file was not updated"
    )


def test_the_suite_contains_negative_cases():
    """Cases expected to produce NOTHING. Without them the suite cannot
    distinguish a detector from a system that flags everything -- which is the
    failure this codebase measured at 51.7% of ordinary tool calls."""
    negatives = [case for case in RED_TEAM_CASES if not case.expected_detection]
    assert len(negatives) >= 2, "too few negative cases to detect over-flagging"
