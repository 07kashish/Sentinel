"""The preflight must agree with startup, or it is worse than nothing.

THE DANGER THIS MODULE GUARDS
------------------------------
`validate_production_configuration` reports problems; `Settings.from_environment`
refuses to start. They are two readings of the same requirements, and the
failure that matters is not "the preflight is noisy" -- it is **the preflight
saying OK on a configuration startup would reject**, because an operator who
trusts a green preflight and then fails a production rollout stops trusting it,
and an operator who trusts it while it is wrong ships a broken deployment.

So agreement is asserted directly, over a corpus that exercises every
requirement, plus a structural ratchet that fails when someone adds a
production check to `settings.py` without adding a requirement here. The corpus
alone is not enough: it only proves the cases it contains.
"""

from __future__ import annotations

import base64

import re
from pathlib import Path

import pytest

from sentinel.composition.preflight import (
    PRODUCTION_REQUIREMENTS,
    validate_production_configuration,
)
from sentinel.composition.settings import ConfigurationError, Settings

ROOT = Path(__file__).resolve().parents[1]

LONG_KEY = "a-production-length-key-that-is-definitely-long-enough"


def _good() -> dict[str, str]:
    """A production environment that should start. The corpus's control case."""
    return {
        "SENTINEL_ENV": "production",
        "SENTINEL_API_KEYS": f"acme:{LONG_KEY}:admin",
        "SENTINEL_DATABASE_URL": "postgresql://sentinel:pw@db:5432/sentinel",
        "SENTINEL_CORS_ORIGINS": "https://console.example.com",
        "SENTINEL_RATE_LIMIT_FAIL_OPEN": "false",
        # Stated, not defaulted, because production refuses to guess: false
        # leaves the unbound `execute` path usable and true stops any call site
        # not yet migrated to `execute_bound`. The control case says false
        # because that is what an existing deployment upgrading to this build
        # would choose, and the corpus should exercise the configuration people
        # will actually run.
        "SENTINEL_REQUIRE_EXECUTION_BINDING": "false",
        # A real data key, because that is the configuration production should run.
        "SENTINEL_DATA_KEY_K1": base64.b64encode(b"0123456789abcdef" * 2).decode(),
        "SENTINEL_ACTIVE_KEY_ID": "k1",
    }


#: Each entry breaks the control case in exactly one way. Named so a failure
#: says which requirement was not honoured.
BREAKAGES: dict[str, dict[str, str | None]] = {
    "api_keys_present": {"SENTINEL_API_KEYS": ""},
    "api_keys_long_enough": {"SENTINEL_API_KEYS": "acme:short:admin"},
    "database_is_postgres": {"SENTINEL_DATABASE_URL": ""},
    "cors_origins_explicit": {"SENTINEL_CORS_ORIGINS": "*"},
    "api_docs_not_exposed": {"SENTINEL_EXPOSE_API_DOCS": "true"},
    "redis_present_for_multi_shard": {"SENTINEL_WORKER_SHARD_COUNT": "4"},
    "rate_limit_fail_open_is_explicit": {"SENTINEL_RATE_LIMIT_FAIL_OPEN": ""},
    "execution_binding_is_explicit": {"SENTINEL_REQUIRE_EXECUTION_BINDING": ""},
    "evidence_encryption_is_explicit": {"SENTINEL_DATA_KEY_K1": "", "SENTINEL_ACTIVE_KEY_ID": ""},
}


def _env(breakage: dict[str, str | None] | None = None) -> dict[str, str]:
    env = _good()
    for key, value in (breakage or {}).items():
        if value is None or value == "":
            env.pop(key, None)
            if value == "":
                env[key] = ""
        else:
            env[key] = value
    return env


def _startup_refuses(env: dict[str, str]) -> bool:
    try:
        Settings.from_environment(env)
    except ConfigurationError:
        return True
    return False


# ── The control case ─────────────────────────────────────────────────────────


def test_a_valid_production_environment_is_reported_clean_and_actually_starts():
    """Both halves. A preflight that fails everything would satisfy every other
    test in this module while being useless."""
    env = _good()
    report = validate_production_configuration(env)

    assert report.ok is True, [f.as_dict() for f in report.findings]
    assert report.checked_production is True
    assert _startup_refuses(env) is False, (
        "the control environment does not actually start, so every 'agrees with "
        "startup' assertion below is comparing two failures"
    )


# ── Agreement ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("name", sorted(BREAKAGES))
def test_each_breakage_is_reported_and_also_refused_by_startup(name: str):
    """One requirement at a time, checked from both sides.

    Breaking exactly one thing is what makes this meaningful: it proves the
    requirement fires on its OWN condition rather than being carried by some
    other problem in a generally-broken environment.
    """
    env = _env(BREAKAGES[name])

    report = validate_production_configuration(env)
    assert report.ok is False, f"preflight passed a configuration broken in {name}"

    assert _startup_refuses(env) is True, (
        f"preflight reports {name} but Settings.from_environment ACCEPTS this "
        "environment. One of the two is wrong, and the preflight is the one "
        "operators read."
    )


@pytest.mark.parametrize("name", sorted(BREAKAGES))
def test_the_expected_requirement_is_the_one_that_fires(name: str):
    """Right answer for the right reason.

    Without this, a requirement that fired on everything would pass the
    agreement test above while telling the operator to fix the wrong variable.
    """
    report = validate_production_configuration(_env(BREAKAGES[name]))
    fired = {f.variable for f in report.findings}

    expected_variable = {
        "api_keys_present": "SENTINEL_API_KEYS",
        "api_keys_long_enough": "SENTINEL_API_KEYS",
        "database_is_postgres": "SENTINEL_DATABASE_URL",
        "cors_origins_explicit": "SENTINEL_CORS_ORIGINS",
        "api_docs_not_exposed": "SENTINEL_EXPOSE_API_DOCS",
        "redis_present_for_multi_shard": "SENTINEL_REDIS_URL",
        "rate_limit_fail_open_is_explicit": "SENTINEL_RATE_LIMIT_FAIL_OPEN",
        "execution_binding_is_explicit": "SENTINEL_REQUIRE_EXECUTION_BINDING",
        "evidence_encryption_is_explicit": "SENTINEL_EVIDENCE_ENCRYPTION",
    }[name]

    assert expected_variable in fired, (
        f"breaking {name} did not produce a finding about {expected_variable}; "
        f"got {sorted(fired)}"
    )


def test_preflight_agrees_with_startup_on_every_environment_in_the_corpus():
    """The whole corpus at once, asserted as an equivalence.

    `report.ok` must equal "startup accepts this". Not implication in one
    direction -- equivalence -- because a preflight that is merely stricter than
    startup blocks rollouts that would have worked, and one that is merely
    looser is the dangerous case.
    """
    corpus = [("valid", _good())] + [
        (name, _env(breakage)) for name, breakage in sorted(BREAKAGES.items())
    ]
    # Several things wrong at once: the case the command exists for.
    corpus.append(
        (
            "everything broken",
            {
                "SENTINEL_ENV": "production",
                "SENTINEL_API_KEYS": "acme:short:admin",
                "SENTINEL_WORKER_SHARD_COUNT": "4",
                "SENTINEL_EXPOSE_API_DOCS": "true",
            },
        )
    )

    disagreements = [
        f"{name}: preflight ok={validate_production_configuration(env).ok} "
        f"but startup refuses={_startup_refuses(env)}"
        for name, env in corpus
        if validate_production_configuration(env).ok is _startup_refuses(env)
    ]
    assert not disagreements, "\n".join(disagreements)


def test_several_problems_are_reported_together_rather_than_one_at_a_time():
    """The reason the command exists.

    `Settings.from_environment` raises on the FIRST problem, so an operator
    fixing a production deployment discovers them one failed rollout at a time.
    """
    env = {
        "SENTINEL_ENV": "production",
        "SENTINEL_API_KEYS": "acme:short:admin",
        "SENTINEL_WORKER_SHARD_COUNT": "4",
        "SENTINEL_EXPOSE_API_DOCS": "true",
    }
    report = validate_production_configuration(env)

    assert len(report.findings) >= 5, (
        f"only {len(report.findings)} of at least 5 problems reported: "
        f"{[f.variable for f in report.findings]}"
    )
    # And startup, for contrast, surfaces exactly one.
    with pytest.raises(ConfigurationError) as raised:
        Settings.from_environment(env)
    assert str(raised.value)


# ── A non-production environment must not read as a clean bill of health ─────


@pytest.mark.parametrize("environment", ["development", "staging"])
def test_a_non_production_environment_says_it_did_not_check(environment: str):
    """`ok` is True and `findings` is empty for a development environment, and
    on its own that reads exactly like "production is fine". It is not, and the
    report has to say so -- otherwise this is a gate that executes nothing while
    returning the same shape as one that passed."""
    report = validate_production_configuration(
        {"SENTINEL_ENV": environment, "SENTINEL_DB_PATH": "x.db"}
    )

    assert report.checked_production is False
    assert "NOT evaluated" in report.render()
    assert environment in report.render()


# ── The structural ratchet ───────────────────────────────────────────────────


def test_every_production_check_in_settings_has_a_requirement_here():
    """Catches the drift the corpus cannot.

    A corpus only proves the cases it contains. If someone adds a
    `production`-gated refusal to `settings.py` and does not add a requirement
    here, the preflight silently becomes looser than startup -- it would report
    a clean configuration that then fails to boot. Counting the branches is
    crude, and crude is the point: it cannot be satisfied by accident.

    If this fails, either add the matching requirement to
    `PRODUCTION_REQUIREMENTS`, or -- if the new branch genuinely is not an
    operator-facing production requirement -- add it to the exclusions below
    with the reason.
    """
    # Both files: `settings_parsers.py` holds refusals that did not fit in
    # `settings.py`, and a production-gated branch there is the same promise.
    source = "\n".join(
        (ROOT / "sentinel" / "composition" / name).read_text("utf-8")
        for name in ("settings.py", "settings_parsers.py")
    )

    branches = [
        line.strip()
        for line in source.splitlines()
        if re.search(r"\bif production\b|\bproduction and\b", line)
    ]
    assert branches, (
        "no production-gated branches found in settings.py; this scanner is "
        "matching nothing and would pass for ever"
    )

    # No delegation filter: `_parse_api_keys(source, production=production)`
    # does not match this pattern, so every line found here is a real check.
    # Measured, not assumed -- a filter that filters nothing is the same kind of
    # decoration this suite exists to catch.
    enforcing = branches

    assert len(enforcing) == len(PRODUCTION_REQUIREMENTS), (
        f"settings.py enforces {len(enforcing)} production requirements but "
        f"preflight.py declares {len(PRODUCTION_REQUIREMENTS)}:\n"
        + "\n".join(f"  settings.py: {b}" for b in enforcing)
        + "\n"
        + "\n".join(f"  preflight:   {r.name}" for r in PRODUCTION_REQUIREMENTS)
        + "\n\nAdd the missing requirement, or the preflight is looser than "
        "startup and will report a configuration clean that then fails to boot."
    )


def test_requirement_names_are_unique():
    names = [r.name for r in PRODUCTION_REQUIREMENTS]
    assert len(names) == len(set(names)), f"duplicate requirement names in {names}"


# ── Findings are actionable ──────────────────────────────────────────────────


def test_every_finding_carries_a_reason_and_a_remedy():
    """A finding that says only "SENTINEL_REDIS_URL is unset" tells an operator
    nothing about why it matters, and they will set it to the first thing that
    silences the error."""
    report = validate_production_configuration(
        {"SENTINEL_ENV": "production", "SENTINEL_WORKER_SHARD_COUNT": "4"}
    )
    assert report.findings

    for finding in report.findings:
        assert finding.variable.startswith("SENTINEL_"), finding
        assert len(finding.why) > 30, f"{finding.variable}: 'why' is not a reason"
        assert len(finding.fix) > 10, f"{finding.variable}: 'fix' is not a remedy"
