"""Run tests and bind their observed outcomes to current release inputs.

This is local/CI test evidence, not independent verification or production evidence.
Collection, skipped cases, job names, and arbitrary sidecars cannot grant a test tier.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from defusedxml import ElementTree

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ("sentinel", "config", "scripts", "tests_arch", "deploy", ".github",
          "sdk-ts", "standard", "evaluation/*.py", "evaluation/artifacts",
          "requirements*.txt", "requirements.lock", "pyproject.toml", "Dockerfile",
          "docker-entrypoint.sh", ".dockerignore", "pytest.ini", ".gitleaks*")


def identity(root: Path = ROOT) -> dict:
    def git(*args: str) -> bytes:
        return subprocess.run(["git", *args], cwd=root, capture_output=True, check=True).stdout
    names = sorted(set(git("ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", *INPUTS).split(b"\0")) - {b""})
    digest = hashlib.sha256()
    for name in names:
        file = root / name.decode("utf-8")
        data = file.read_bytes() if file.is_file() and not file.is_symlink() else b"<missing-or-symlink>"
        digest.update(len(name).to_bytes(8, "big") + name)
        digest.update(len(data).to_bytes(8, "big") + data)
    return {"commit": git("rev-parse", "HEAD").decode().strip(), "inputs_sha256": digest.hexdigest()}


def outcomes(report: Path) -> dict:
    if report.stat().st_size > 50_000_000:
        raise ValueError("test report exceeds limit")
    tree = ElementTree.fromstring(report.read_bytes())
    modules: dict[str, Counter] = {}
    for case in tree.iter("testcase"):
        classname = case.get("classname", "")
        parts = classname.split(".")
        if len(parts) < 2 or parts[0] != "tests_arch" or not parts[1].startswith("test_"):
            continue
        count = modules.setdefault(parts[1], Counter())
        count["total"] += 1
        if case.find("failure") is not None or case.find("error") is not None:
            count["failed"] += 1
        elif case.find("skipped") is not None:
            count["skipped"] += 1
        else:
            count["passed"] += 1
            if "postgres" in case.get("name", ""):
                count["postgres_passed"] += 1
    return {k: dict(v) for k, v in modules.items()}


def read_verified(path: Path, expected: dict) -> dict:
    """Verify binding, report digest and recomputed counts; never trust claimed counts."""
    try:
        data = json.loads(path.read_text())
        if not isinstance(data, dict) or data.get("schema") != "sentinel.test-evidence/v1" or data.get("identity") != expected:
            return {}
        if data.get("exit_code") != 0 or data.get("inputs_changed_during_run") is not False:
            return {}
        report = path.with_suffix(".xml")
        if hashlib.sha256(report.read_bytes()).hexdigest() != data.get("junit_sha256"):
            return {}
        counts = outcomes(report)
        if not counts or counts != data.get("modules"):
            return {}
        if any(c.get("failed", 0) for c in counts.values()):
            return {}
        return counts
    except (OSError, ValueError, TypeError, ElementTree.ParseError):
        return {}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("tests", nargs="*", default=["tests_arch"])
    args = parser.parse_args()
    target = args.out.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    report = target.with_suffix(".xml")
    before = identity()
    started = datetime.now(timezone.utc).isoformat()
    command = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
               "--junitxml=" + str(report), *args.tests]
    result = subprocess.run(command, cwd=ROOT, check=False)
    changed = before != identity()
    counts = outcomes(report) if report.exists() else {}
    payload = {"schema": "sentinel.test-evidence/v1", "identity": before,
               "started_at": started, "completed_at": datetime.now(timezone.utc).isoformat(),
               "python": platform.python_version(), "platform": platform.platform(),
               "command": command[1:], "exit_code": result.returncode,
               "inputs_changed_during_run": changed, "modules": counts,
               "junit_sha256": hashlib.sha256(report.read_bytes()).hexdigest() if report.exists() else "",
               "limitations": ["local or CI test execution; not production observation",
                               "PostgreSQL counts identify executed backend-parametrized tests; not a cloud topology test",
                               "JSON and JUnit checksums do not establish independent signer identity"]}
    target.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"test evidence: exit={result.returncode}, inputs_changed={changed}")
    return result.returncode or (1 if changed or not counts else 0)


if __name__ == "__main__":
    raise SystemExit(main())
