"""Deployment assets must configure the environment variable the app reads.

THE DEFECT (P0, found 2026-08-19)
----------------------------------
`deploy/k8s/sentinel.yaml` and `deploy/helm/sentinel/templates/deployment.yaml`
both set:

    - {name: SENTINEL_MODE, value: live}

**Nothing in `sentinel/` has ever read `SENTINEL_MODE`.** `Settings.from_environment`
reads `SENTINEL_ENV` and defaults it to `"development"`. Neither manifest set
`SENTINEL_ENV`. So every Kubernetes and Helm deployment ran with DEVELOPMENT
safeguards while appearing, to anyone reading the manifest, to be configured for
production.

Demonstrated by feeding the manifest's exact environment to `Settings`:

    environment      : development
    is_production    : False
    engine dialect   : sqlite
    api key 'short'  : ACCEPTED  (5 characters; the production floor is 32)

Every production refusal was therefore inactive: the PostgreSQL requirement,
the 32-character key floor, explicit CORS origins, Redis for a shared rate
limiter across replicas, the explicit limiter fail-open decision, and the
refusal to serve unauthenticated `/docs`.

This is the "gate that executes nothing" shape again, one layer down: the
safeguards existed and were correct, and nothing switched them on.

WHY A TEST AND NOT JUST A FIX
------------------------------
The fix is four lines across four files. The reason it survived is that nothing
connected the variable the manifests set to the variable the code reads, so any
future manifest -- a new overlay, a second chart, a customer's copy -- can
reintroduce it silently. This test is that connection.
"""

from __future__ import annotations

import base64

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

#: Assets that configure a PRODUCTION deployment and must therefore say so.
PRODUCTION_ASSETS = (
    Path("deploy/k8s/sentinel.yaml"),
    Path("deploy/helm/sentinel/templates/deployment.yaml"),
)

#: Assets that configure a LOCAL deployment. These must NOT claim production --
#: compose on a laptop cannot satisfy the production invariants and would simply
#: refuse to start, which teaches people to override the variable rather than
#: respect it.
LOCAL_ASSETS = (
    Path("docker-compose.yml"),
    Path(".env.example"),
)

#: Exclude VCS metadata, bytecode and tests that deliberately construct bad inputs.
EXCLUDED_FROM_SWEEP = (".git/", "__pycache__", "tests_arch/")

#: A real assignment, not prose. Matches `SENTINEL_MODE=x`, `SENTINEL_MODE: x`
#: and `{name: SENTINEL_MODE, ...}` while ignoring a mention inside a comment.
ASSIGNMENT = re.compile(r"(?<!#\s)\bSENTINEL_MODE\s*[:=]|name:\s*SENTINEL_MODE")


def _text(rel: Path) -> str:
    path = ROOT / rel
    if not path.is_file():
        pytest.fail(f"{rel} does not exist; this test's premise is stale")
    return path.read_text(encoding="utf-8")


# ── The application reads exactly one variable ───────────────────────────────


def test_the_application_reads_sentinel_env_and_not_sentinel_mode():
    """Establishes the premise everything below rests on.

    If someone adds a `SENTINEL_MODE` reader to `sentinel/`, the assets are no
    longer wrong and this whole module needs rethinking -- so it fails loudly
    rather than continuing to assert something that stopped being true.
    """
    sources = list((ROOT / "sentinel").rglob("*.py"))
    assert len(sources) >= 20, f"only {len(sources)} modules found under sentinel/"

    readers = [
        f"{p.relative_to(ROOT)}:{n}"
        for p in sources
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
        if "SENTINEL_MODE" in line
    ]
    assert not readers, (
        f"sentinel/ now references SENTINEL_MODE at {readers}. Either the "
        "application grew a second environment variable -- in which case the "
        "canonical-environment decision needs revisiting -- or this is a typo."
    )

    env_readers = [
        p.relative_to(ROOT)
        for p in sources
        if "SENTINEL_ENV" in p.read_text(encoding="utf-8")
    ]
    assert env_readers, "no module reads SENTINEL_ENV; the premise is wrong"


# ── Production assets must switch production on ──────────────────────────────


@pytest.mark.parametrize("rel", PRODUCTION_ASSETS, ids=lambda p: p.name)
def test_a_production_asset_sets_sentinel_env_to_production(rel: Path):
    """The fix. A manifest that omits this runs with development safeguards."""
    text = _text(rel)
    assert re.search(r"SENTINEL_ENV,\s*value:\s*production", text), (
        f"{rel} does not set SENTINEL_ENV=production. Without it "
        "`Settings.from_environment` defaults to development and every "
        "production refusal -- PostgreSQL, 32-char keys, explicit CORS, Redis "
        "for a shared limiter -- is silently inactive."
    )


@pytest.mark.parametrize("rel", PRODUCTION_ASSETS + LOCAL_ASSETS, ids=lambda p: p.name)
def test_no_deployment_asset_assigns_the_phantom_variable(rel: Path):
    """`SENTINEL_MODE` may be DISCUSSED in a comment, never assigned."""
    offenders = [
        f"line {n}: {line.strip()}"
        for n, line in enumerate(_text(rel).splitlines(), 1)
        if ASSIGNMENT.search(line) and not line.strip().startswith("#")
    ]
    assert not offenders, (
        f"{rel} assigns SENTINEL_MODE, which no code reads:\n"
        + "\n".join(offenders)
        + "\n\nUse SENTINEL_ENV. A variable with no reader configures nothing "
        "while looking like it configures something."
    )


# ── Local assets must NOT claim production ───────────────────────────────────


def test_compose_defaults_to_development_rather_than_production():
    """Compose must stay runnable on a laptop.

    Defaulting it to production would make the stack refuse to start without a
    PostgreSQL DSN, 32-character keys, explicit CORS and Redis -- and the
    predictable response is that people set SENTINEL_ENV=development
    permanently, which is worse than an honest default.
    """
    text = _text(Path("docker-compose.yml"))
    assert "SENTINEL_ENV: ${SENTINEL_ENV:-development}" in text, (
        "docker-compose.yml must default SENTINEL_ENV to development and let "
        "the operator override it deliberately"
    )


# ── The sweep: nothing else in the tree assigns it ───────────────────────────


def test_no_asset_anywhere_still_assigns_the_phantom_variable():
    """Catches an overlay or chart the lists above do not name."""
    checked = 0
    offenders: list[str] = []
    for path in ROOT.rglob("*"):
        rel = path.relative_to(ROOT).as_posix()
        if any(skip in rel for skip in EXCLUDED_FROM_SWEEP):
            continue
        if not path.is_file() or path.suffix not in {".yaml", ".yml", ".env", ".example", ".sh", ".ps1"}:
            continue
        checked += 1
        for n, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if ASSIGNMENT.search(line) and not line.strip().startswith("#"):
                offenders.append(f"{rel}:{n}: {line.strip()}")

    assert checked >= 5, (
        f"the sweep examined only {checked} files; it is not reaching the "
        "deployment assets and would pass while checking nothing"
    )
    assert not offenders, (
        "these files assign SENTINEL_MODE, which no code reads:\n"
        + "\n".join(offenders)
    )


# ── The safeguards are real, not decorative ──────────────────────────────────


def test_production_actually_refuses_what_development_permits(tmp_path):
    """Proves the variable MATTERS, so the assertions above are worth making.

    Without this, every test in this module could pass on a build where
    `SENTINEL_ENV=production` did nothing at all.

    THE DB PATH IS `tmp_path`, NOT THE MANIFEST'S `/app/data`. It used to be the
    literal manifest value, which passed on Windows -- where `/app/data` lands on
    the current drive root and is writable -- and failed in CI on Linux with
    `PermissionError: /app`. `Settings._parse_engine` calls `mkdir(parents=True)`
    on the SQLite parent, so simply PARSING a configuration touches the
    filesystem, and a hardcoded absolute path makes that a platform coin flip.

    Nothing is lost: this test's claim is that production refuses a five-character
    key and a SQLite backend. The directory it would have used is incidental, and
    the manifest's actual value is asserted by the tests above, which read the
    file rather than executing it.
    """
    from sentinel.composition.settings import ConfigurationError, Settings

    dev_shaped = {
        "SENTINEL_API_KEYS": "acme:short:admin",
        "SENTINEL_DB_PATH": str(tmp_path / "data" / "sentinel.db"),
    }

    # Development accepts it -- a five-character key and a SQLite file.
    development = Settings.from_environment(dev_shaped)
    assert development.is_production is False
    assert development.engine.dialect.value == "sqlite"

    # Production refuses the very same configuration.
    with pytest.raises(ConfigurationError):
        Settings.from_environment({**dev_shaped, "SENTINEL_ENV": "production"})


# ── Turning production ON is only half the fix ───────────────────────────────


#: Values a manifest supplies from a Secret rather than inline. The preflight
#: reads the ENVIRONMENT, so a `valueFrom.secretKeyRef` is invisible to it --
#: substituting plausible values here is what lets the check see the shape the
#: pod actually gets, instead of reporting every secret as missing.
_SECRET_SHAPED = {
    "SENTINEL_DATABASE_URL": "postgresql://sentinel:pw@postgres:5432/sentinel",
    "SENTINEL_API_KEYS": "acme:" + "k" * 40 + ":admin",
    # The evidence data key arrives from a Secret too (secretKeyRef), so it is
    # not inline in the manifest; the active key id is, and must match this.
    "SENTINEL_DATA_KEY_K1": base64.b64encode(b"0123456789abcdef" * 2).decode(),
}


def _inline_env(text: str) -> dict[str, str]:
    """Every `- {name: X, value: Y}` and `- name: X\n  value: Y` in a manifest.

    Deliberately crude. It only needs to find the variables a manifest states
    INLINE, because those are the ones an author can forget; anything from a
    Secret is supplied above.
    """
    found = dict(
        re.findall(r"-\s*\{name:\s*([A-Z_]+),\s*value:\s*\"?([^\"}\n]*)\"?\}", text)
    )
    found.update(
        re.findall(
            r"-\s*name:\s*([A-Z_]+)\s*\n\s*value:\s*\"([^\"]*)\"", text
        )
    )
    return {k: v.strip() for k, v in found.items()}


def test_a_production_manifest_supplies_what_production_demands():
    """THE DEFECT THIS CLOSES (found in CI, 2026-08-22).

    Correcting `SENTINEL_MODE` to `SENTINEL_ENV=production` switched the
    production refusals ON. It did not supply what they require. The result was
    a pod that started, refused, exited, and crash-looped -- CI reported
    `Deployment/sentinel not ready. status: InProgress, Available: 0/1`, which
    says nothing about the two missing variables.

    `Settings` was right to refuse. The manifest was wrong to ask. This test is
    the connection between the two, so a future manifest that switches
    production on without satisfying it fails HERE -- in seconds, with the
    variable named -- rather than in a rollout.

    ONLY THE RAW MANIFEST IS CHECKED THIS WAY. A Helm template is not a
    manifest until it is rendered -- its values are Go-template expressions, not
    literals -- so scanning it as text answers a different question. The chart
    is covered by `test_the_helm_chart_declares_the_production_variables` below,
    by the `required` guard that fails at render time, and by the
    kind-helm-smoke CI job that renders and actually runs it.
    """
    from sentinel.composition.preflight import validate_production_configuration

    rel = Path("deploy/k8s/sentinel.yaml")
    env = {**_SECRET_SHAPED, **_inline_env(_text(rel))}
    assert env.get("SENTINEL_ENV") == "production", (
        f"{rel} no longer declares production; this test's premise is stale"
    )

    report = validate_production_configuration(env)
    assert report.ok, (
        f"{rel} sets SENTINEL_ENV=production but does not satisfy it. The "
        f"pod would refuse to start and crash-loop:\n\n{report.render()}"
    )


def test_the_manifest_environment_actually_constructs_settings(tmp_path):
    """The preflight is a reporter; `Settings` is what refuses.

    Asserting only the preflight would leave this test one drift away from
    passing on a manifest that still cannot boot, so the real constructor runs.
    """
    from sentinel.composition.settings import Settings

    rel = Path("deploy/k8s/sentinel.yaml")
    env = {**_SECRET_SHAPED, **_inline_env(_text(rel))}

    # Any `*_FILE` variable names a path that exists only inside the pod --
    # `/var/run/secrets/...` mounted from a Secret -- and `Settings` READS those
    # files rather than merely recording the path. Pointing them at real
    # temporary files is what lets this construct the manifest's configuration
    # off-cluster; leaving them alone would fail on a missing mount and say
    # nothing about whether the configuration is valid.
    material = tmp_path / "mounted-secret"
    material.write_text("m" * 64, encoding="utf-8")
    for key in [k for k in env if k.endswith("_FILE")]:
        env[key] = str(material)

    settings = Settings.from_environment(env)  # raises if unsatisfiable
    assert settings.is_production is True


def test_the_manifest_scanner_finds_the_variables_it_claims_to():
    """A denominator guard. A regex that silently matched nothing would make
    both tests above pass against an empty environment.

    This guard has already earned its place: the first version of the scanner
    could not see `SENTINEL_CORS_ORIGINS` in the Helm template, because that
    entry is a `{{ required ... }}` expression rather than a quoted literal. The
    production check would have passed while never examining the variable it
    exists to check.
    """
    env = _inline_env(_text(Path("deploy/k8s/sentinel.yaml")))

    assert len(env) >= 3, f"scanner found only {len(env)} vars: {env}"
    for required_name in (
        "SENTINEL_ENV",
        "SENTINEL_CORS_ORIGINS",
        "SENTINEL_RATE_LIMIT_FAIL_OPEN",
    ):
        assert required_name in env, (
            f"the scanner did not find {required_name}, so the production "
            f"check above is not really examining it. Found: {sorted(env)}"
        )


def test_the_helm_chart_declares_the_production_variables():
    """The chart cannot be preflighted as text, so its STRUCTURE is asserted.

    Both variables must be emitted by the template and both must be declared in
    `values.yaml` -- a template that reads `.Values.corsOrigins` while values.yaml
    never mentions it renders an empty string, which the application refuses at
    startup rather than at install.
    """
    template = _text(Path("deploy/helm/sentinel/templates/deployment.yaml"))
    values = _text(Path("deploy/helm/sentinel/values.yaml"))

    for name, key in (
        ("SENTINEL_CORS_ORIGINS", "corsOrigins"),
        ("SENTINEL_RATE_LIMIT_FAIL_OPEN", "rateLimitFailOpen"),
    ):
        assert name in template, (
            f"the chart sets SENTINEL_ENV=production but never emits {name}. "
            "The pod would refuse to start and crash-loop with Available: 0/1."
        )
        assert key in values, (
            f"{key} is used by the template but not declared in values.yaml"
        )

    assert "required" in template, (
        "corsOrigins must be guarded by Helm's `required`, so a chart installed "
        "without it fails at RENDER time with a readable message rather than at "
        "pod start with CrashLoopBackOff"
    )
