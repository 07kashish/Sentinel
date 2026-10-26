"""The posture checker has to be able to fail.

WHY THIS FILE IS MOSTLY NEGATIVE TESTS
---------------------------------------
`scripts/check_terraform_posture.py` reported "3/3 environments meet their own
bar" the first time it ran. That is exactly what a checker which parses
nothing and returns success would print, and this repository has already
shipped four checks that reported confident success while examining nothing —
a compressed zip searched for a plaintext key, a scanner canary that was
allowlisted by the scanner, a JS runner whose main guard never matched, and a
test helper that substituted a default for the None it was meant to test.

So every requirement is checked by MUTATING the production configuration in a
temporary copy and requiring the checker to notice. A requirement nothing can
break is a requirement nothing is enforcing.

WHAT THESE TESTS DO NOT CLAIM
-----------------------------
They read configuration text. `terraform validate` is a separate and stronger
check, and neither proves that a running deployment matches its Terraform.
Nothing in this repository can prove that, because nothing here has ever been
applied — which is what PRODUCTION_SOAK records as an open external gate.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.check_terraform_posture import (
    MUST_STAY_FALSE,
    PRODUCTION_BAR,
    check,
)

ROOT = Path(__file__).resolve().parent.parent
TERRAFORM = ROOT / "deploy" / "terraform" / "aws"
ENVS = TERRAFORM / "envs"
MODULES = TERRAFORM / "modules"

#: The twelve the requirement enumerates, plus the stack that wires them and
#: the identity module that predates this work.
EXPECTED_MODULES = frozenset({
    "network", "kms", "secrets", "database", "cache", "queue", "storage",
    "ecs", "waf", "observability", "backup", "budgets", "stack",
})


# ── the layer exists and is shaped as claimed ──────────────────────────────


def test_every_enumerated_module_exists():
    """The requirement names thirteen; the ledger claimed one for a while. This
    is what stops that claim drifting back.
    """
    present = {path.name for path in MODULES.iterdir() if path.is_dir()}

    missing = EXPECTED_MODULES - present
    assert missing == set(), f"modules named but absent: {sorted(missing)}"


def test_every_module_declares_a_pinned_provider():
    """An unpinned provider upgrades under you between a plan and an apply,
    and a major AWS provider release changes resource behaviour.
    """
    for name in sorted(EXPECTED_MODULES):
        source = (MODULES / name / "main.tf").read_text(encoding="utf-8")

        assert "required_version" in source, name
        assert 'version = "~> 5.0"' in source, f"{name}: aws provider not pinned"


def test_only_the_dev_environment_is_shipped():
    present = {path.name for path in ENVS.iterdir() if path.is_dir()}

    assert present == {"dev"}


def test_no_environment_commits_a_backend():
    """A committed backend makes `terraform init` in a checkout reach for state
    that may not be this operator's, and it is also what would let a CI job
    with credentials touch real state.
    """
    for environment in sorted(p.name for p in ENVS.iterdir() if p.is_dir()):
        source = (ENVS / environment / "main.tf").read_text(encoding="utf-8")
        # `backend "s3"` etc. A `terraform {}` block is expected; a backend
        # inside it is not.
        assert 'backend "' not in source, environment


def test_no_terraform_state_is_committed():
    """State contains generated passwords in plaintext. `.gitignore` excludes
    it, which is an admission that state is dangerous rather than a solution,
    so this asserts none arrived anyway.
    """
    # TRACKED files, not files on disk: while an environment is applied its
    # state legitimately sits beside the root (ignored by git); the leak this
    # guards against is state that git carries.
    tracked = subprocess.run(  # noqa: S603
        ["git", "-C", str(ROOT), "ls-files", "--", str(TERRAFORM.relative_to(ROOT))],
        capture_output=True, text=True, check=False,
    ).stdout.splitlines()
    leaked = [path for path in tracked if ".tfstate" in Path(path).name]

    assert leaked == [], f"terraform state committed: {leaked}"
    assert "*.tfstate" in (ROOT / ".gitignore").read_text(encoding="utf-8")


# ── the checker can fail: one test per production requirement ─────────────


def _mutated(tmp_path: Path, replacements: dict[str, str]) -> Path:
    """A copy of the whole terraform tree with the production root edited.

    The WHOLE tree, because the checker reads the stack module's constants as
    well as the environment root, and a copy of only one would silently skip
    half the checks.
    """
    destination = tmp_path / "aws"
    shutil.copytree(TERRAFORM, destination, ignore=shutil.ignore_patterns(
        ".terraform", "*.tfstate*", ".terraform.lock.hcl"
    ))

    # Exercise the production bar with a hardened COPY of the retained dev
    # root. No deployable production environment is shipped by this fixture.
    target = destination / "envs" / "production" / "main.tf"
    target.parent.mkdir(parents=True, exist_ok=True)
    source = (destination / "envs" / "dev" / "main.tf").read_text(encoding="utf-8")
    controls = {
        "multi_az": "multi_az                 = true",
        "deletion_protection": "deletion_protection      = true",
        "cache_replica_count": "cache_replica_count = 1",
        "require_execution_binding": "require_execution_binding = true",
        "rate_limit_fail_open": "rate_limit_fail_open = false",
        "enable_vault_lock": "enable_vault_lock = true",
        "certificate_arn": "certificate_arn = var.certificate_arn",
    }
    for field, assignment in controls.items():
        source, count = re.subn(r"(?m)^  " + field + r"\s*=.*$", "  " + assignment, source)
        assert count == 1, field
    source = source.replace('sentinel_env = "development"', 'sentinel_env = "production"')
    source = source.replace('variable "alarm_email" {', 'variable "alarm_email" {\n'
                            '  validation {\n'
                            '    condition = var.alarm_email != ""\n'
                            '    error_message = "alarm_email is required in production"\n'
                            '  }\n')
    source += '\nvariable "certificate_arn" {\n  type = string\n}\n'

    for old, new in replacements.items():
        assert old in source, f"anchor absent, so this test would not mutate: {old}"
        source = source.replace(old, new)
    target.write_text(source, encoding="utf-8")
    return destination


def _check_against(tree: Path, environment: str) -> list[str]:
    """Run the checker against a copied tree.

    `check` takes the tree as a parameter, so this needs no monkeypatching of
    module globals. The first version of this helper did patch them, got the
    path arithmetic wrong, and silently checked the REAL tree instead of the
    mutated copy -- so the honesty-constant mutation reported no problems and
    looked like a checker that could not see it.
    """
    return check(environment, tree=tree)


def test_production_passes_unmutated(tmp_path):
    """THE control. Every mutation test below would pass against a checker that
    failed everything, so this is what makes them evidence.
    """
    tree = _mutated(tmp_path, {})

    assert _check_against(tree, "production") == []


@pytest.mark.parametrize(
    "anchor,broken,field",
    [
        ("multi_az                 = true", "multi_az                 = false", "multi_az"),
        ("deletion_protection      = true", "deletion_protection      = false", "deletion_protection"),
        ("cache_replica_count = 1", "cache_replica_count = 0", "cache_replica"),
        ("require_execution_binding = true", "require_execution_binding = false", "execution_binding"),
        ("rate_limit_fail_open = false", "rate_limit_fail_open = true", "fail_closed"),
        ("enable_vault_lock = true", "enable_vault_lock = false", "vault_lock"),
    ],
)
def test_weakening_a_production_control_is_caught(tmp_path, anchor, broken, field):
    """One test per control. Each mutation is the single line somebody would
    change to save money, and each must be refused with the field named.
    """
    tree = _mutated(tmp_path, {anchor: broken})

    problems = _check_against(tree, "production")

    assert problems, f"weakening {field} was not caught"
    assert any(field in problem for problem in problems), problems


def test_removing_tls_is_caught(tmp_path):
    """A certificate variable replaced by an empty literal. The posture output
    reports `tls_terminated` from what the module PRODUCES, not from what
    somebody intended.
    """
    tree = _mutated(
        tmp_path, {"certificate_arn = var.certificate_arn": 'certificate_arn = ""'}
    )

    problems = _check_against(tree, "production")

    assert any("tls" in problem for problem in problems), problems


def test_removing_the_alarm_email_requirement_is_caught(tmp_path):
    """Dropping the validation block leaves an optional alarm address, and
    alarms firing into an unsubscribed topic is not monitoring.
    """
    tree = _mutated(tmp_path, {
        "alarm_email is required in production": "alarm_email is optional here"
    })

    problems = _check_against(tree, "production")

    assert any("alarm_email" in problem for problem in problems), problems


def test_a_missing_control_is_refused_rather_than_assumed(tmp_path):
    """Deleting the line entirely must fail, not default to the safe value. A
    checker that assumes safety when it cannot find a setting is a checker that
    passes an empty file.
    """
    tree = _mutated(tmp_path, {"enable_vault_lock = true\n": ""})

    problems = _check_against(tree, "production")

    assert any("not set at all" in problem for problem in problems), problems


# ── the honesty constants ──────────────────────────────────────────────────


def test_the_honesty_constants_are_still_false():
    """`restore_verified` and `budget_is_measured` are hardcoded false in their
    modules because they cannot be satisfied from inside this repository.
    """
    for environment in ("dev",):
        assert check(environment) == [], environment


def test_flipping_an_honesty_constant_is_caught(tmp_path):
    """A true here would mean somebody edited a constant rather than closed a
    gate, and it must be refused as loudly as a missing control.
    """
    tree = _mutated(tmp_path, {})
    backup = tree / "modules" / "backup" / "main.tf"
    source = backup.read_text(encoding="utf-8")
    anchor = "output \"restore_is_verified\""
    assert anchor in source
    # Flip the constant the stack output reads.
    stack = tree / "modules" / "stack" / "outputs.tf"
    stack_source = stack.read_text(encoding="utf-8")
    old = "restore_verified     = module.backup.restore_is_verified"
    assert old in stack_source
    stack.write_text(
        stack_source.replace(old, "restore_verified     = true"), encoding="utf-8"
    )

    problems = _check_against(tree, "production")

    assert any("restore_verified" in problem for problem in problems), problems


def test_every_requirement_explains_itself():
    """A refusal an operator cannot act on gets switched off wholesale, which
    is how a crude denylist in the release packager produced three false
    positives earlier in this work.
    """
    for requirement in PRODUCTION_BAR + MUST_STAY_FALSE:
        assert len(requirement.why) > 40, requirement.field


# ── the checker refuses an empty set ───────────────────────────────────────


def test_the_checker_refuses_to_succeed_over_no_environments(tmp_path, monkeypatch):
    """A checker that finds nothing exits zero and reads exactly like one that
    checked everything. This is the JS conformance runner's bug, in Python.
    """
    import scripts.check_terraform_posture as checker

    empty = tmp_path / "envs"
    empty.mkdir()
    monkeypatch.setattr(checker, "ENVS", empty)

    assert checker.main([]) == 2


def test_the_script_runs_as_a_command():
    """The module imports cleanly in these tests; that is not the same as the
    entry point working. Run it.
    """
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check_terraform_posture.py")],
        capture_output=True, text=True, cwd=str(ROOT),
        env={"PYTHONPATH": str(ROOT), "PATH": ""},
    )

    assert "environments meet their own bar" in result.stdout, result.stderr
    assert result.returncode == 0, result.stdout + result.stderr


# ── the thin roots agree with the stack's interface ───────────────────────
#
# `terraform validate` catches this too, and it needs a 646 MB provider
# download per directory. These tests catch the same class in milliseconds, so
# they run on every commit rather than when somebody remembers.
#
# The risk is specific: each root passes ~25 arguments to one module. A
# misspelled argument name is an error terraform reports and nothing else
# does, and a MISSING required argument is worse -- the root silently inherits
# the stack's DEV default, so a production environment quietly gets a
# single-AZ database because somebody deleted a line.


def _stack_variables() -> dict[str, bool]:
    """Declared stack variable -> whether it has a default."""
    source = (MODULES / "stack" / "variables.tf").read_text(encoding="utf-8")
    declared: dict[str, bool] = {}
    for block in source.split('variable "')[1:]:
        name = block.split('"', 1)[0]
        # `default` inside this block, before the next one starts.
        declared[name] = "default" in block.split("\n}")[0]
    return declared


def _root_arguments(environment: str) -> set[str]:
    """Arguments the environment root passes to the stack module."""
    source = (ENVS / environment / "main.tf").read_text(encoding="utf-8")
    block = source.split('module "sentinel" {', 1)[1]
    # Up to the closing brace at column 0.
    block = block.split("\n}", 1)[0]

    # Terraform META-ARGUMENTS, which are not module variables. Counting them
    # made the first version of this test report `source` as undeclared in all
    # three environments -- a flaw in the parser reported as a flaw in the
    # configuration, which is the least useful kind of test failure.
    meta = {"source", "version", "count", "for_each", "providers", "depends_on"}

    passed: set[str] = set()
    for line in block.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name = stripped.split("=", 1)[0].strip()
        if name.isidentifier() and name not in meta:
            passed.add(name)
    return passed


def test_the_stack_declares_variables_at_all():
    """Control. Everything below is vacuous if the parser finds nothing."""
    declared = _stack_variables()

    assert len(declared) >= 20, f"only parsed {len(declared)} variables"
    assert "multi_az" in declared
    # `name` is required; `multi_az` has a dev default. If the default detection
    # is broken both read the same way and the required-argument test below
    # becomes meaningless.
    assert declared["name"] is False
    assert declared["multi_az"] is True


@pytest.mark.parametrize("environment", ["dev"])
def test_no_root_passes_an_undeclared_argument(environment):
    """A misspelled argument name is an error terraform reports and nothing
    else does.
    """
    declared = _stack_variables()
    passed = _root_arguments(environment)

    assert passed, f"{environment}: parsed no arguments, so this checks nothing"
    unknown = passed - set(declared)
    assert unknown == set(), f"{environment} passes undeclared: {sorted(unknown)}"


@pytest.mark.parametrize("environment", ["dev"])
def test_every_required_stack_variable_is_supplied(environment):
    """A missing REQUIRED argument fails the plan, which is fine. A missing
    OPTIONAL one silently inherits the stack's dev default, which is not --
    that is how a production environment gets a single-AZ database because
    somebody deleted a line.
    """
    declared = _stack_variables()
    passed = _root_arguments(environment)
    required = {name for name, has_default in declared.items() if not has_default}

    missing = required - passed
    assert missing == set(), f"{environment} omits required: {sorted(missing)}"


def test_dev_states_every_control_rather_than_inheriting_a_default():
    """Dev must not rely on ANY stack default for a control the posture
    checker cares about, even where the default happens to be correct today.
    Changing a default is otherwise a silent change to dev.
    """
    passed = _root_arguments("dev")

    for name in (
        "multi_az",
        "deletion_protection",
        "cache_replica_count",
        "require_execution_binding",
        "rate_limit_fail_open",
        "enable_vault_lock",
        "certificate_arn",
        "evidence_retention_days",
    ):
        assert name in passed, (
            f"dev inherits the stack default for {name}. Changing that "
            f"default would then change dev silently."
        )


# ── The ECS task definition supplies what production demands ─────────────────
#
# The Helm chart and the raw manifest have this test
# (`test_a_production_manifest_supplies_what_production_demands`). The ECS
# stack did not, and the first plan of it against a real account found the
# omission it would have caught: no evidence data key and no opt-out, so every
# task would have started, refused, and crash-looped behind the load balancer.


def _hcl_map(block_name: str) -> dict[str, str]:
    """`name = value` pairs of one `<block_name> = {` map in the stack's ecs call."""
    source = (MODULES / "stack" / "main.tf").read_text(encoding="utf-8")
    body = source.split(f"{block_name} = {{", 1)[1].split("\n  }", 1)[0]
    pairs: dict[str, str] = {}
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, value = (part.strip() for part in stripped.split("=", 1))
        pairs[name] = value.strip('"')
    return pairs


def _ecs_environment_as_the_task_sees_it() -> dict[str, str]:
    """Literals from `environment`, and a value of the right shape for every
    injected secret; a Terraform expression (`var.x`, `tostring(...)`) is
    replaced by a production configuration of the retained stack."""
    env = _hcl_map("environment")
    production = {"var.sentinel_env": "production", "tostring(var.rate_limit_fail_open)": "false",
             "tostring(var.require_execution_binding)": "true", "var.cors_origins": "https://console.example.com",
             "module.storage.evidence_bucket": "sentinel-test-evidence", "data.aws_region.current.name": "ap-south-1",
             "tostring(var.mcp_proxy.enabled)": "false", 'join(",", sort(tolist(var.mcp_proxy.allowed_hosts)))': "",
             "var.advisor.endpoint": "", "var.advisor.model": "", 'var.brain_host.enabled ? "0" : "4': "4",
             'join(",", var.root_publish_tenants)': ""}
    resolved = {k: production.get(v, v) for k, v in env.items()}
    shaped = {"SENTINEL_DATABASE_URL": "postgresql://sentinel:x@db.internal:5432/sentinel",
              "SENTINEL_REDIS_URL": "rediss://cache.internal:6379/0",
              "SENTINEL_API_KEYS": "acme:" + "k" * 40 + ":ingest", "SENTINEL_METRICS_TOKEN": "m" * 40,
              "SENTINEL_DATA_KEY_K1": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
    for name in _hcl_map("secret_arns"):
        assert name in shaped, f"{name} is injected as a secret but this test does not know its shape"
        resolved[name] = shaped[name]
    return resolved


def test_the_ecs_task_supplies_what_production_demands():
    from sentinel.composition.preflight import validate_production_configuration

    env = _ecs_environment_as_the_task_sees_it()
    assert env["SENTINEL_ENV"] == "production"
    report = validate_production_configuration(env)
    assert report.ok, f"the ECS task would refuse to start:\n\n{report.render()}"


def test_the_ecs_task_environment_actually_constructs_settings():
    from sentinel.composition.settings import Settings

    Settings.from_environment(_ecs_environment_as_the_task_sees_it())


def test_removing_the_data_key_from_the_task_is_caught(monkeypatch):
    from sentinel.composition.preflight import validate_production_configuration

    env = _ecs_environment_as_the_task_sees_it()
    env.pop("SENTINEL_DATA_KEY_K1")
    assert not validate_production_configuration(env).ok
