"""Run the tracked attack table against a real app and write bound evidence.

WHY THIS EXISTS ALONGSIDE THE PYTEST SUITE
-------------------------------------------
`tests_arch/test_red_team_suite.py` is the GATE: it fails the build when a
tracked case regresses. This script is the LEDGER: it records what each case
actually did, as an artifact bound to a commit, so "we used to prevent that" is
a diff between two files rather than somebody's memory.

Both read the same table. The table is imported, never copied -- a second copy
would drift, and the drift would be invisible precisely because both halves
would keep passing.

THE FAILURE THIS SCRIPT IS ARRANGED AROUND
-------------------------------------------
An attack that failed to launch produces the same observable as an attack that
was blocked. So every failure path here records `INCONCLUSIVE`, and a case that
never got as far as executing records `NOT_RUN`. Neither can become `DEFENDED`.

Concretely: if the app will not start, this script writes NO artifact and exits
non-zero. It does not write a document full of `DEFENDED` rows. A gate that did
not run must produce no evidence, which is the rule the release runner already
enforces -- absence becomes UNVERIFIED, never PASS.
"""

from __future__ import annotations

import json
import subprocess
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel.domain.attack_campaign import (  # noqa: E402
    AttackCase,
    AttackOutcome,
    CampaignResult,
    case_from_observations,
    compare_to_baseline,
    summarise,
)

OUT = ROOT / "reports" / "evidence" / "attack_campaign.json"

#: Techniques the table does not attempt. Written down rather than omitted: a
#: campaign of passing cases says nothing about the technique nobody wrote a
#: case for, and a result with no denominator is the same failure as an empty
#: inventory reading as a clean estate.
#:
#: This list is maintained by hand and is itself incomplete -- which is stated
#: in the artifact, because a coverage list that claims to be exhaustive is the
#: same lie one level up.
TECHNIQUES_NOT_ATTEMPTED: tuple[str, ...] = (
    "AML.T0010 ML supply chain compromise (covered by scanners, not by attack)",
    "AML.T0018 backdoor ML model (no model training surface in this product)",
    "AML.T0024 exfiltration via ML inference API (no inference API is exposed)",
    "AML.T0043 craft adversarial data (Sentinel classifies events, not images)",
    "ASI03 identity impersonation at the signature layer (needs a key-custody "
    "test harness that does not exist yet)",
    "ASI10 rogue agent persistence across tenant boundaries (needs a "
    "multi-tenant soak, which is Phase 69 and UNVERIFIED)",
)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _commit() -> str:
    """The commit this campaign describes.

    Refuses rather than guessing. An artifact that cannot name its commit
    cannot be bound to a build, and an unbound artifact is UNVERIFIED -- so
    producing one with a placeholder would be manufacturing evidence.
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
    except (subprocess.SubprocessError, OSError) as error:
        raise SystemExit(
            f"cannot determine the current commit ({error}). Refusing to write "
            "an attack-campaign artifact that cannot be bound to a build: an "
            "unbound artifact is UNVERIFIED, and one with a placeholder commit "
            "would be worse, because it would look bound."
        ) from error
    return result.stdout.strip()


def _run_campaign() -> tuple[AttackCase, ...]:
    """Drive every tracked case, each against its OWN app and database.

    Imports the table and the wiring from the test module so there is exactly
    one definition of both. If the import or an app build fails, this raises --
    and the caller writes no artifact.

    ISOLATION PER CASE IS NOT OPTIONAL. Every tracked case submits into session
    "s-red", so a shared database leaves case 1's read_file/zip/http_post in
    the session when case 3 arrives, and case 3 is "detected" because of case
    1. The first run of this script did exactly that and disagreed with the
    pytest gate, which builds a fresh app per test. A campaign measuring
    cross-case contamination is measuring its own harness.
    """
    from tests_arch.test_red_team_suite import RED_TEAM_CASES

    recorded: list[AttackCase] = []
    for case in RED_TEAM_CASES:
        with _fresh_client() as client:
            recorded.append(_run_one(client, case))
    return tuple(recorded)


@contextmanager
def _fresh_client() -> Iterator[Any]:
    """One app, one migrated database, torn down afterwards."""
    import tempfile

    from fastapi.testclient import TestClient

    from sentinel.composition.container import build_container
    from sentinel.composition.settings import Settings
    from sentinel.infrastructure.sql.engine import build_engine
    from sentinel.infrastructure.sql.migrate import migrate
    from sentinel.interface.http import create_app
    from tests_arch.test_red_team_suite import INGEST_KEY, TENANT, VIEW_KEY

    with tempfile.TemporaryDirectory(prefix="sentinel-campaign-") as staging:
        settings = Settings.from_environment(
            {
                "SENTINEL_DB_PATH": str(Path(staging) / "campaign.db"),
                "SENTINEL_API_KEYS": (
                    f"{TENANT}:{INGEST_KEY}:ingest,{TENANT}:{VIEW_KEY}:viewer"
                ),
                "SENTINEL_SOFT_PROMPT_DETECT": "false",
            }
        )

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

            # raise_server_exceptions=False so a 5xx arrives as a RESPONSE and
            # is classified INCONCLUSIVE, rather than as an exception that
            # aborts the campaign and loses every remaining case.
            client = TestClient(create_app(container), raise_server_exceptions=False)
            with client:
                yield client
        finally:
            container.close()


def _run_one(client: Any, case: Any) -> AttackCase:
    """One case. Every fault path lands on INCONCLUSIVE, never DEFENDED.

    Records detection and prevention as SEPARATE observations, the way the
    pytest gate does, and lets `case_from_observations` derive the summary --
    so the human-readable outcome and the graded booleans cannot disagree.

    Reads the outcome from the response BODY rather than polling an incidents
    endpoint: the body is what the product reports for this submission, and a
    shared endpoint would mix in incidents raised by earlier steps.
    """
    from tests_arch.test_red_team_suite import INGEST_KEY

    detected = False
    prevented = False
    errored = False
    notes: list[str] = []

    try:
        for step in case.steps:
            response = client.post(
                "/v1/events",
                headers={"Authorization": f"Bearer {INGEST_KEY}"},
                json=step,
            )
            if response.status_code >= 500:
                # A crash is not a defence. Its own fact, so the classifier
                # cannot reach DEFENDED from it.
                errored = True
                notes.append(f"{response.status_code} on {step.get('eventId')}")
                continue
            if response.status_code in {401, 403, 409, 422}:
                prevented = True
                notes.append(f"refused {response.status_code}")
                continue
            body = response.json()
            if str(body.get("outcome", "")) == "incident_admitted":
                detected = True
    except Exception as error:  # noqa: BLE001 - any fault is INCONCLUSIVE
        # Deliberately broad. Whatever went wrong, the one thing that must not
        # happen is this case being recorded as a successful defence.
        errored = True
        notes.append(f"{type(error).__name__}: {error}")

    return case_from_observations(
        case_id=case.name,
        technique=case.objective,
        expected_detection=case.expected_detection,
        expected_prevention=case.expected_prevention,
        rationale=case.rationale or "no rationale recorded in the tracked table",
        detected=detected,
        prevented=prevented,
        errored=errored,
        detail="; ".join(notes),
    )


def _load_baseline() -> tuple[AttackCase, ...]:
    """The previous campaign, for regression comparison.

    A missing baseline is not an error: the first run has nothing to compare
    against. It is also not silently treated as "no regressions" -- the caller
    states which of the two it was.
    """
    if not OUT.exists():
        return ()
    try:
        document = json.loads(OUT.read_text(encoding="utf-8"))
        return tuple(
            AttackCase(
                case_id=row["case_id"],
                technique=row["technique"],
                outcome=AttackOutcome(row["outcome"]),
                expected_detection=row["expected_detection"],
                expected_prevention=row["expected_prevention"],
                rationale=row.get("rationale") or "recovered from baseline",
                detail=row.get("detail", ""),
            )
            for row in document.get("cases", [])
        )
    except (OSError, ValueError, KeyError) as error:
        print(
            f"  baseline at {OUT} could not be read ({error}); "
            "treating this as a first run rather than as no regressions",
            file=sys.stderr,
        )
        return ()


def main() -> int:
    print("running the tracked attack table against a real app")

    baseline = _load_baseline()
    try:
        cases = _run_campaign()
    except Exception as error:  # noqa: BLE001
        # NO ARTIFACT IS WRITTEN. A gate that did not run must produce no
        # evidence -- absence becomes UNVERIFIED, never PASS. Writing a
        # document full of DEFENDED rows here is the single worst thing this
        # script could do.
        print(
            f"\nthe campaign could not run: {type(error).__name__}: {error}\n"
            "No artifact written. A campaign that did not run must leave no "
            "evidence behind, because an artifact full of DEFENDED rows is "
            "indistinguishable from a successful run.",
            file=sys.stderr,
        )
        return 1

    result = CampaignResult(
        commit=_commit(),
        ran_at=_now(),
        cases=cases,
        techniques_not_attempted=TECHNIQUES_NOT_ATTEMPTED,
    )
    regressions = compare_to_baseline(baseline=baseline, current=cases)

    document = result.as_dict()
    document["baseline_present"] = bool(baseline)
    document["regressions"] = [r.as_dict() for r in regressions]
    document["coverage_list_is_itself_incomplete"] = True
    document["ok"] = not regressions and not result.uninformative

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False)
        + "\n",
        encoding="utf-8",
    )

    for case in cases:
        mark = "ok " if case.met_expectation else "!! "
        print(f"  {mark}{case.case_id}: {case.outcome.value}")

    print(f"\n{summarise(result)}")
    if not baseline:
        print("no baseline was present, so no regression comparison was made")
    for regression in regressions:
        print(
            f"  REGRESSION {regression.case_id}: {regression.kind.value} "
            f"({regression.was.value} -> {regression.now.value})"
        )
    print(f"\nwritten to {OUT.relative_to(ROOT)}")

    return 0 if document["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
