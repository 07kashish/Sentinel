"""Refuse a Terraform environment whose posture contradicts its name.

WHY THIS EXISTS
---------------
Every strong setting in the stack is a variable with a weak default, because
the weak default is what makes a dev environment cheap. That is the right
design and it has one failure mode: a `production` environment that quietly
ships with the WAF counting, the backups deletable and the rate limiter
failing open. Each of those is one line in a file nobody diffs, and the
resulting deployment looks exactly like a hardened one from the outside.

So the stack exports `posture` as machine-readable data and this script reads
it. A production environment that does not meet the production bar fails, with
the specific field named.

WHAT IT READS, AND WHY NOT THE VARIABLES
-----------------------------------------
It parses the `posture` output out of the environment's Terraform
configuration rather than reading the variables. The distinction matters: a
variable says what somebody asked for, and the posture output says what the
modules actually produce — `tls_terminated` is false when no certificate is
supplied no matter what anybody intended, and `restore_verified` is a
hardcoded false that no configuration can turn on.

WHAT IT CANNOT DO
-----------------
It reads CONFIGURATION, not a deployment. Nothing here proves a running system
matches its Terraform, and `terraform plan` against real state is what would.
This catches the class of mistake where the configuration itself is wrong,
which is the one that ships silently.

The honesty flags are checked too, and they are expected to be FALSE. A
production environment reporting `restore_verified = true` would mean somebody
had edited a hardcoded constant, so the check refuses that as loudly as it
refuses a missing control.
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENVS = ROOT / "deploy" / "terraform" / "aws" / "envs"


@dataclass(frozen=True)
class Requirement:
    """One posture field and what it must be for this environment."""

    field: str
    expected: bool
    why: str


#: The production bar. Each entry is a control whose absence would leave a
#: deployment that looks hardened from the outside and is not.
PRODUCTION_BAR: tuple[Requirement, ...] = (
    Requirement(
        "multi_az", True,
        "a single-AZ production database does not survive an AZ loss, which is "
        "the failure AWS actually has",
    ),
    Requirement(
        "deletion_protection", True,
        "without it, `terraform destroy` deletes the production database and "
        "its automated backups go with it",
    ),
    Requirement(
        "cache_replica", True,
        "with a single cache node, replacing it re-opens every authorization "
        "nonce spent since the last snapshot for replay -- an availability "
        "setting with a security consequence",
    ),
    Requirement(
        "tls", True,
        "agent events carry the parameters of the actions being authorized; "
        "over plain HTTP they are readable in transit",
    ),
    Requirement(
        "execution_binding", True,
        "false leaves the unbound tool path usable, so the deployment is only "
        "as bound as its call sites happen to be and the central claim is "
        "about the code rather than about this system",
    ),
    Requirement(
        "fail_closed", True,
        "a limiter that fails open loses the limit exactly when it is under "
        "pressure",
    ),
    Requirement(
        "vault_lock", True,
        "without it an attacker holding admin credentials deletes the backups "
        "along with the database, which is the threat that makes backups worth "
        "having in a security product",
    ),
    Requirement(
        "alarm_email", True,
        "an alarm firing into an SNS topic nobody has subscribed to is not "
        "monitoring",
    ),
)

#: Constants that must stay false. Each is hardcoded in a module BECAUSE it
#: cannot be satisfied from inside this repository, so a true here means
#: somebody edited the constant rather than closed the gate.
MUST_STAY_FALSE: tuple[Requirement, ...] = (
    Requirement(
        "restore_verified", False,
        "a backup plan is not a restore. This is hardcoded false in the backup "
        "module; a true means the constant was edited, not that a restore was "
        "verified. INDEPENDENT_FAILURE_DOMAIN_DR is an open external gate",
    ),
    Requirement(
        "budget_is_measured", False,
        "no bill for this platform exists, so the budget is a chosen ceiling. "
        "MEASURED_AWS_UNIT_ECONOMICS is an open external gate",
    ),
)


def _field_patterns(field: str) -> tuple[str, ...]:
    """Where each logical field is actually set in the environment root.

    Deliberately a mapping from a SHORT name to the variable assignments that
    determine it, rather than reading the rendered `posture` output — which
    would need `terraform apply` and therefore a bill.
    """
    return {
        "multi_az": (r"multi_az\s*=\s*(\w+)",),
        "deletion_protection": (r"deletion_protection\s*=\s*(\w+)",),
        "cache_replica": (r"cache_replica_count\s*=\s*(\d+)",),
        "tls": (r"certificate_arn\s*=\s*(.+)",),
        "execution_binding": (r"require_execution_binding\s*=\s*(\w+)",),
        "fail_closed": (r"rate_limit_fail_open\s*=\s*(\w+)",),
        "vault_lock": (r"enable_vault_lock\s*=\s*(\w+)",),
        "alarm_email": (r"variable \"alarm_email\"",),
        "restore_verified": (r"restore_verified\s*=\s*(.+)",),
        "budget_is_measured": (r"budget_is_measured\s*=\s*(.+)",),
    }[field]


def _code_only(source: str) -> str:
    """Terraform with comments and heredoc prose removed.

    NECESSARY, not tidiness. The first version of this script matched a
    `restore_verified = (.+)` pattern against the raw file and hit outputs.tf's
    own HEADER COMMENT -- which contains the sentence "an environment that
    reports `restore_verified = false` is telling the truth about itself". So
    the checker read a comment explaining the field as the field, concluded
    false, and reported success no matter what the actual assignment said.

    The same class of defect -- a pattern matching documentation rather than
    code -- has been found twice before in this repository's own tests, which
    is why this strips rather than tries to write a cleverer pattern.
    """
    lines: list[str] = []
    in_heredoc = False
    for line in source.splitlines():
        stripped = line.strip()
        if in_heredoc:
            # `EOT` on its own closes the block. Terraform's indented heredocs
            # allow leading whitespace on the terminator.
            if stripped == "EOT":
                in_heredoc = False
            continue
        if "<<-EOT" in line or "<<EOT" in line:
            in_heredoc = True
            continue
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        # An inline trailing comment cannot be stripped naively, because `#`
        # appears inside strings. Only whole-line comments are removed, which
        # is enough: an assignment and a comment about it are on different
        # lines in formatted Terraform, and `terraform fmt` enforces that.
        lines.append(line)
    return chr(10).join(lines)


def _observe(field: str, source: str) -> bool | None:
    """What this configuration actually says. None when it cannot be read."""
    for pattern in _field_patterns(field):
        match = re.search(pattern, source)
        if match is None:
            continue
        if field == "alarm_email":
            # Required means the variable has a validation block refusing an
            # empty value, not merely that it exists.
            return "alarm_email is required in production" in source
        if field == "tls":
            value = match.group(1).strip()
            # An empty literal means plain HTTP. A variable reference means the
            # operator must supply one, which the production root also
            # validates.
            return value not in {'""', "''"}
        if field == "cache_replica":
            return int(match.group(1)) >= 1
        if field == "fail_closed":
            # Inverted: the variable is fail_OPEN, the requirement is
            # fail_CLOSED. Getting this backwards would produce a check that
            # passes on the dangerous setting, so it is written out rather than
            # folded into a truthiness test.
            return match.group(1).strip() == "false"
        if field in {"restore_verified", "budget_is_measured"}:
            return "true" in match.group(1).lower()
        return match.group(1).strip() == "true"
    return None


def check(environment: str, *, tree: Path | None = None) -> list[str]:
    """Problems with this environment, or an empty list.

    `tree` points at an `aws/` directory containing `envs/` and `modules/`. It
    is a PARAMETER rather than a module global because the tests mutate a
    copied tree and require this to notice -- and a function that reads its
    inputs from module globals is one whose negative cases are awkward to
    write, which in practice means they do not get written.
    """
    base = tree if tree is not None else (ROOT / "deploy" / "terraform" / "aws")
    envs = base / "envs"
    root = envs / environment
    if not root.exists():
        return [f"{environment}: no such environment under {envs}"]

    source = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(root.glob("*.tf"))
    )
    stack = base / "modules" / "stack"
    stack_source = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(stack.glob("*.tf"))
    )

    problems: list[str] = []

    # The honesty constants live in the stack outputs, not the env root.
    for requirement in MUST_STAY_FALSE:
        observed = _observe(requirement.field, _code_only(stack_source))
        if observed is None:
            problems.append(
                f"{environment}: could not find {requirement.field} in the "
                f"stack outputs. It is meant to be a hardcoded constant; its "
                f"absence means the honesty flag was removed."
            )
        elif observed is not requirement.expected:
            problems.append(
                f"{environment}: {requirement.field} is "
                f"{str(observed).lower()} and must be "
                f"{str(requirement.expected).lower()} -- {requirement.why}"
            )

    if environment != "production":
        return problems

    for requirement in PRODUCTION_BAR:
        observed = _observe(requirement.field, _code_only(source))
        if observed is None:
            problems.append(
                f"production: {requirement.field} is not set at all. Refusing "
                f"to assume the safe value -- {requirement.why}"
            )
        elif observed is not requirement.expected:
            problems.append(
                f"production: {requirement.field} is "
                f"{str(observed).lower()} -- {requirement.why}"
            )

    return problems


def _terraform_available() -> bool:
    try:
        subprocess.run(
            ["terraform", "version"], capture_output=True, check=True, timeout=30
        )
        return True
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return False


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    environments = args or sorted(
        path.name for path in ENVS.iterdir() if path.is_dir()
    )

    if not environments:
        print(
            f"no environments found under {ENVS}. Refusing to report success "
            "over an empty set: a checker that finds nothing exits zero and "
            "reads exactly like one that checked everything.",
            file=sys.stderr,
        )
        return 2

    failures = 0
    for environment in environments:
        problems = check(environment)
        if problems:
            failures += 1
            print(f"FAIL {environment}")
            for problem in problems:
                print(f"  {problem}")
        else:
            print(f"ok   {environment}")

    print(
        f"\n{len(environments) - failures}/{len(environments)} environments "
        f"meet their own bar"
    )
    if not _terraform_available():
        print(
            "NOTE: terraform is not installed, so this checked the "
            "CONFIGURATION TEXT only. `terraform validate` is a separate and "
            "stronger check, and neither proves a running deployment matches.",
            file=sys.stderr,
        )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
