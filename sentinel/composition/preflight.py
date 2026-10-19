"""Production preflight: report EVERY configuration problem, not just the first.

WHY THIS EXISTS
---------------
`Settings.from_environment` already refuses to start a misconfigured production
deployment, and those refusals are correct. But it raises on the **first**
problem it meets, which makes bringing up a production deployment a sequence of
one-at-a-time discoveries:

    deploy -> "SENTINEL_CORS_ORIGINS must list explicit origins"
    fix, deploy -> "SENTINEL_REDIS_URL is unset"
    fix, deploy -> "SENTINEL_RATE_LIMIT_FAIL_OPEN must be set explicitly"

Each cycle is a failed rollout. This runs the same requirements and reports all
of them together, before anything starts, so the operator fixes the
configuration once.

THE FAILURE MODE THIS DESIGN HAS TO AVOID
-------------------------------------------
A preflight that says OK while startup refuses -- or, far worse, says OK on a
configuration that startup would have rejected -- is more dangerous than having
no preflight at all, because operators would trust it. A second copy of the
production rules is exactly the "two places to disagree" defect this codebase
keeps finding.

So this module is NOT the enforcement path. `Settings.from_environment` remains
the thing that actually refuses, unchanged, and stays the last line of defence.
This is a reporting tool over the same requirements, and two tests hold the two
together:

  * `test_preflight_agrees_with_startup_on_every_environment_in_the_corpus`
    asserts `report.ok` matches whether `from_environment` raises, across a
    corpus of environments that exercises each requirement.
  * `test_every_production_check_in_settings_has_a_requirement_here` counts the
    `production`-gated branches in `settings.py` and requires one declared
    requirement per branch, so adding a check there and forgetting it here fails
    immediately rather than at the next production rollout.

WHAT IT DELIBERATELY DOES NOT DO
----------------------------------
It does not connect to anything. It does not check that the PostgreSQL DSN
resolves, that Redis answers, or that the OIDC issuer is reachable -- those are
runtime facts, they belong to `/health/ready`, and a preflight that blocks on a
network round trip is one operators learn to skip.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from sentinel.composition.settings import MIN_KEY_LENGTH, read_environment

__all__ = [
    "Finding",
    "PreflightReport",
    "Requirement",
    "PRODUCTION_REQUIREMENTS",
    "validate_production_configuration",
]


@dataclass(frozen=True, slots=True)
class Finding:
    """One thing wrong, with the reason and the remedy.

    `why` is carried rather than left to the reader because every one of these
    refusals exists for a reason that is not obvious from the variable name --
    "set Redis" means nothing until you know that without it the effective rate
    limit is multiplied by the replica count.
    """

    variable: str
    problem: str
    why: str
    fix: str

    def as_dict(self) -> dict[str, str]:
        return {
            "variable": self.variable,
            "problem": self.problem,
            "why": self.why,
            "fix": self.fix,
        }

    def render(self) -> str:
        return (
            f"  {self.variable}\n"
            f"    problem: {self.problem}\n"
            f"    why:     {self.why}\n"
            f"    fix:     {self.fix}\n"
        )


#: Printed under every production report, passing or failing.
#:
#: `require_shared_limiter_or_refuse` can refuse a startup that this preflight
#: passed, and an operator who reads "no problems found" and then watches the
#: service refuse to boot has been misled by this tool -- the exact failure the
#: module docstring warns about. It is not fixable by adding the check here:
#: topology is observed from the process table, and running that observation
#: from a CLI on an operator's laptop would report on the CLI's own process
#: tree. One process, every time, in a deployment of any shape.
#:
#: So the boundary is stated instead of implied. A tool that names what it did
#: not check is trusted; one that quietly returns OK is not.
NOT_CHECKED_HERE = (
    "\nNOT checked here: the number of processes actually serving this "
    "deployment.\nThat is observed from the process table at server startup, "
    "which is the only\nplace the answer is knowable -- running it from this "
    "CLI would report on this\nCLI. If several processes serve traffic without "
    "SENTINEL_REDIS_URL set, startup\nrefuses even when this report is clean.\n"
)


@dataclass(frozen=True, slots=True)
class Requirement:
    """A named production requirement and the check that evaluates it.

    Named so the structural ratchet in the tests can count them against the
    `production`-gated branches in `settings.py`.
    """

    name: str
    check: Callable[[Mapping[str, str]], Finding | None]


@dataclass(frozen=True, slots=True)
class PreflightReport:
    environment: str
    findings: tuple[Finding, ...]

    @property
    def ok(self) -> bool:
        return not self.findings

    @property
    def checked_production(self) -> bool:
        """Whether production requirements were actually evaluated.

        Reported because "0 findings" means two entirely different things for a
        development and a production environment, and a report that does not say
        which one it was is the shape of a gate that executes nothing.
        """
        return self.environment == "production"

    def as_dict(self) -> dict[str, object]:
        return {
            "environment": self.environment,
            "checked_production": self.checked_production,
            "ok": self.ok,
            "findings": [f.as_dict() for f in self.findings],
        }

    def render(self) -> str:
        if not self.checked_production:
            return (
                f"SENTINEL_ENV={self.environment}: production requirements were "
                "NOT evaluated.\nThis says nothing about whether this "
                "configuration would start in production.\nRe-run with "
                "SENTINEL_ENV=production to check it.\n"
            )
        if self.ok:
            return (
                f"SENTINEL_ENV=production: {len(PRODUCTION_REQUIREMENTS)} "
                "requirements checked, no problems found.\n" + NOT_CHECKED_HERE
            )
        head = (
            f"SENTINEL_ENV=production: {len(self.findings)} problem(s) found "
            f"across {len(PRODUCTION_REQUIREMENTS)} requirements.\n"
            "The service would refuse to start.\n\n"
        )
        return head + "\n".join(f.render() for f in self.findings) + NOT_CHECKED_HERE


# ── The requirements ─────────────────────────────────────────────────────────
#
# One per `production`-gated branch in `Settings.from_environment`. Each reads
# the raw environment and nothing else, so a requirement cannot be tripped by
# the order the parser happens to run in.


def _api_keys_present(source: Mapping[str, str]) -> Finding | None:
    entries = [e.strip() for e in source.get("SENTINEL_API_KEYS", "").split(",") if e.strip()]
    if entries:
        return None
    return Finding(
        variable="SENTINEL_API_KEYS",
        problem="no API keys are configured",
        why=(
            "an unconfigured security service that accepts traffic authenticates "
            "nobody and authorises everybody"
        ),
        fix="set SENTINEL_API_KEYS to tenant:key:role entries",
    )


def _api_keys_long_enough(source: Mapping[str, str]) -> Finding | None:
    short = []
    for entry in (e.strip() for e in source.get("SENTINEL_API_KEYS", "").split(",") if e.strip()):
        parts = [p.strip() for p in entry.split(":")]
        if len(parts) in (2, 3) and len(parts[1]) < MIN_KEY_LENGTH:
            short.append(parts[0] or "?")
    if not short:
        return None
    return Finding(
        variable="SENTINEL_API_KEYS",
        problem=(
            f"key material shorter than {MIN_KEY_LENGTH} characters for "
            f"tenant(s): {', '.join(short)}"
        ),
        why="a short bearer token is brute-forceable, and this is the only credential",
        fix=(
            "generate real keys: "
            "python -c \"import secrets; print(secrets.token_urlsafe(32))\""
        ),
    )


def _database_is_postgres(source: Mapping[str, str]) -> Finding | None:
    url = source.get("SENTINEL_DATABASE_URL", "").strip()
    if url.startswith(("postgresql://", "postgresql+psycopg://")):
        return None
    return Finding(
        variable="SENTINEL_DATABASE_URL",
        problem="unset or not a PostgreSQL URL" if not url else f"not a PostgreSQL URL: {url[:32]}...",
        why=(
            "SQLite is single-writer and cannot serve multiple replicas; it also "
            "has no row-level security, which is what enforces tenant isolation"
        ),
        fix="set SENTINEL_DATABASE_URL=postgresql://...",
    )


def _cors_origins_explicit(source: Mapping[str, str]) -> Finding | None:
    origins = [
        o.strip()
        for o in source.get("SENTINEL_CORS_ORIGINS", "").split(",")
        if o.strip() and o.strip() != "*"
    ]
    if origins:
        return None
    return Finding(
        variable="SENTINEL_CORS_ORIGINS",
        problem="no explicit origins (unset, empty, or only '*')",
        why="a wildcard origin on a credentialed API lets any site call it as the user",
        fix="list the exact origins, comma separated",
    )


def _api_docs_not_exposed(source: Mapping[str, str]) -> Finding | None:
    if not _flag(source, "SENTINEL_EXPOSE_API_DOCS", default=False):
        return None
    return Finding(
        variable="SENTINEL_EXPOSE_API_DOCS",
        problem="enabled",
        why=(
            "the docs routes are unauthenticated by construction -- FastAPI serves "
            "them before any dependency runs -- so this publishes every route and "
            "request shape to anyone who can reach the port"
        ),
        fix="unset it, and read the schema from a non-production deployment",
    )


def _redis_present_for_multi_shard(source: Mapping[str, str]) -> Finding | None:
    raw = source.get("SENTINEL_WORKER_SHARD_COUNT", "").strip()
    try:
        shards = int(raw) if raw else 1
    except ValueError:
        return None  # from_environment reports the type error itself
    if shards <= 1 or source.get("SENTINEL_REDIS_URL", "").strip():
        return None
    return Finding(
        variable="SENTINEL_REDIS_URL",
        problem=f"unset while SENTINEL_WORKER_SHARD_COUNT is {shards}",
        why=(
            f"the rate limiter would be per-process, so {shards} replicas permit "
            f"{shards} times the configured rate -- a limiter that looks correct "
            "and is not"
        ),
        fix="set SENTINEL_REDIS_URL, or run a single shard",
    )


def _rate_limit_fail_open_is_explicit(source: Mapping[str, str]) -> Finding | None:
    if source.get("SENTINEL_RATE_LIMIT_FAIL_OPEN", "").strip():
        return None
    return Finding(
        variable="SENTINEL_RATE_LIMIT_FAIL_OPEN",
        problem="not set",
        why=(
            "when the limiter is unreachable, allowing loses the limit and denying "
            "loses availability. Both are defensible and the wrong one is a silent "
            "bypass or a silent outage, so there is no safe default to guess"
        ),
        fix="set it to true or false deliberately",
    )


def _execution_binding_is_explicit(source: Mapping[str, str]) -> Finding | None:
    if source.get("SENTINEL_REQUIRE_EXECUTION_BINDING", "").strip():
        return None
    return Finding(
        variable="SENTINEL_REQUIRE_EXECUTION_BINDING",
        problem="not set",
        why=(
            "false leaves ProtectedToolRunner.execute usable, and that path takes "
            "an opaque closure and binds nothing -- so an agent authorized "
            "against one resource can act on another while every passport and "
            "proof still verifies, because each attests to the decision rather "
            "than to what ran. True refuses that path and stops any call site "
            "not yet migrated to execute_bound. Neither is safe to guess"
        ),
        fix="set it to true or false deliberately",
    )


def _evidence_encryption_is_explicit(source: Mapping[str, str]) -> Finding | None:
    has_key = any(name.startswith("SENTINEL_DATA_KEY_") and value.strip() for name, value in source.items())
    stated = source.get("SENTINEL_EVIDENCE_ENCRYPTION", "").strip().lower()
    if has_key or stated == "off":
        return None
    return Finding(
        variable="SENTINEL_EVIDENCE_ENCRYPTION",
        problem="no data key is configured and plaintext storage was not stated",
        why=(
            "evidence bodies hold the payloads an investigation needs, which is "
            "also what an attacker with a database copy wants. Without a data key "
            "they are readable JSON protected only by whatever encrypts the disk. "
            "That may be an acceptable decision; it is not an acceptable default"
        ),
        fix=(
            "set SENTINEL_DATA_KEY_<id> (base64, 32 bytes) and SENTINEL_ACTIVE_KEY_ID, "
            "or state SENTINEL_EVIDENCE_ENCRYPTION=off"
        ),
    )


PRODUCTION_REQUIREMENTS: tuple[Requirement, ...] = (
    Requirement("api_keys_present", _api_keys_present),
    Requirement("api_keys_long_enough", _api_keys_long_enough),
    Requirement("database_is_postgres", _database_is_postgres),
    Requirement("cors_origins_explicit", _cors_origins_explicit),
    Requirement("api_docs_not_exposed", _api_docs_not_exposed),
    Requirement("redis_present_for_multi_shard", _redis_present_for_multi_shard),
    Requirement("rate_limit_fail_open_is_explicit", _rate_limit_fail_open_is_explicit),
    Requirement("execution_binding_is_explicit", _execution_binding_is_explicit),
    Requirement("evidence_encryption_is_explicit", _evidence_encryption_is_explicit),
)


def _flag(source: Mapping[str, str], name: str, *, default: bool) -> bool:
    raw = source.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def validate_production_configuration(
    env: Mapping[str, str] | None = None,
) -> PreflightReport:
    """Check a candidate production environment and report every problem.

    Returns a report rather than raising. This is the reporting path; refusing
    to start remains `Settings.from_environment`'s job, and it is unchanged.

    When `SENTINEL_ENV` is not `production` the requirements are not evaluated
    and the report says so explicitly -- an empty finding list for a development
    environment would otherwise read as a clean bill of health for a production
    rollout, which is precisely the misreading this module exists to prevent.
    """
    source = dict(env) if env is not None else read_environment()
    environment = source.get("SENTINEL_ENV", "development").strip().lower()
    if environment != "production":
        return PreflightReport(environment=environment, findings=())

    findings = tuple(
        finding
        for requirement in PRODUCTION_REQUIREMENTS
        if (finding := requirement.check(source)) is not None
    )
    return PreflightReport(environment=environment, findings=findings)
