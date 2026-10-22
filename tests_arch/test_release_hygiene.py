"""Release hygiene: what ships, what is pinned, what the scanner catches.

Every check here guards a mechanism that would otherwise fail silently: a
scanner that finds nothing, a lock that drifted from the pins, a wheel that
quietly stopped carrying the policy, an SDK install that quietly grew a
dependency. Each test proves the mechanism can FAIL before trusting its pass.
"""

from __future__ import annotations

import dataclasses
import json
import re
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

import pytest

from scripts import build_release_artifact, scan_release_for_secrets as scanner
from scripts.smoke_clean_install import SDK_IMPORTS, THIN_PROBE

ROOT = Path(__file__).resolve().parents[1]


# ── The scanner can fail, and fails quietly ──────────────────────────────────


def _wheel_with(tmp_path: Path, members: dict[str, bytes]) -> Path:
    wheel = tmp_path / "sentinel_agent_trust-0.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return wheel


def _canary() -> bytes:
    # Derived so the literal never sits in the tree: AKIA + 16 upper/digits.
    return b"AKIA" + b"Q7ZP3M9XK2VL8RTN"


def test_a_planted_cloud_key_in_a_wheel_is_found_and_never_echoed(tmp_path):
    canary = _canary()
    wheel = _wheel_with(tmp_path, {"sentinel/__init__.py": b"KEY = '" + canary + b"'\n"})
    findings, scanned = scanner.scan_artifact(wheel, {})
    assert scanned == 1
    assert [f.rule for f in findings] == ["aws-access-key-id"]
    rendered = "\n".join(f.render() for f in findings) + json.dumps([dataclasses.asdict(f) for f in findings])
    assert canary.decode() not in rendered
    assert findings[0].fingerprint and len(findings[0].fingerprint) == 8


def test_a_known_value_is_found_by_variable_name_only(tmp_path):
    secret = b"z9Q2mV7kP4sX1nL6rT8wB3yH5cJ0dF2g"
    dotenv = tmp_path / ".env"
    dotenv.write_text(f"MY_TOKEN={secret.decode()}\nSENTINEL_ENV=production\nSHORT=abc\n", encoding="utf-8")
    known = scanner.load_known(dotenv)
    assert set(known) == {"MY_TOKEN"}, "short and low-entropy values must not become 'secrets'"
    wheel = _wheel_with(tmp_path, {"sentinel/x.py": b"token = '" + secret + b"'\n"})
    findings, _ = scanner.scan_artifact(wheel, known)
    rules = {f.rule for f in findings}
    assert "known-secret:MY_TOKEN" in rules
    assert secret.decode() not in "\n".join(f.render() for f in findings)


def test_a_low_entropy_test_fixture_is_not_a_finding(tmp_path):
    wheel = _wheel_with(tmp_path, {
        "sentinel/x.py": b'INGEST = "contract-ingest-key-that-is-long-enough-for-production"\n'
                         b'password = "replace-with-a-long-random-key-please"\n',
    })
    findings, _ = scanner.scan_artifact(wheel, {})
    assert findings == []


def test_a_random_credential_assignment_is_a_finding(tmp_path):
    value = b"Kj8mN2pQ7rT4vW9x" + b"Z1cB5dF3gH6jL0nM"
    wheel = _wheel_with(tmp_path, {"sentinel/x.py": b'api_key = "' + value + b'"\n'})
    findings, _ = scanner.scan_artifact(wheel, {})
    assert [f.rule for f in findings] == ["high-entropy-credential-assignment"]


def test_the_published_aws_example_key_is_not_a_finding(tmp_path):
    wheel = _wheel_with(tmp_path, {"sentinel/x.py": b"ID = 'AKIAIOSFODNN7EXAMPLE'\n"})
    assert scanner.scan_artifact(wheel, {})[0] == []


# ── Allowlists ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "member, expected",
    [
        ("sentinel/domain/x.py", ""),
        ("sentinel/infrastructure/default_policy.json", ""),
        ("sentinel_agent_trust-0.1.0.dist-info/METADATA", ""),
        ("sentinel_agent_trust-0.1.0.dist-info/licenses/LICENSE", ""),
        ("sentinel/interface/console/unapproved.js", "non-source"),
        ("sentinel/.env", "credential-shaped"),
        ("sentinel/keys/server.pem", "refused suffix"),
        ("evaluation/artifacts/model.pkl", "outside the package"),
        ("sentinel/other.json", "non-source"),
    ],
)
def test_wheel_allowlist(member, expected):
    reason = scanner.check_wheel_member(member)
    assert (expected in reason) if expected else reason == "", reason


@pytest.mark.parametrize(
    "member, ok",
    [("Chart.yaml", True), ("templates/deployment.yaml", True), ("sentinel/values.yaml", True),
     ("templates/_helpers.tpl", True), ("values.dev.yaml", False), ("secrets/tls.key", False), ("notes.md", False)],
)
def test_chart_allowlist(member, ok):
    assert (scanner.check_chart_member(member) == "") is ok


def test_the_two_refusal_lists_agree_with_the_packager():
    assert scanner.REFUSED_SUFFIXES == build_release_artifact.REFUSED_SUFFIXES
    assert scanner.REFUSED_NAMES <= build_release_artifact.REFUSED_NAMES


def test_every_tree_allowlist_entry_still_matches_something():
    """A stale exception is an exception waiting to cover a real leak."""
    for path, rule, _reason in scanner.TREE_ALLOWLIST:
        data = (ROOT / path).read_bytes()
        pattern = dict(scanner.HIGH_CONFIDENCE)[rule]
        assert pattern.search(data), f"{path} no longer matches {rule}; remove the allowlist entry"


def test_the_tracked_tree_is_clean():
    findings, scanned = scanner.scan_tree(ROOT, {})
    assert scanned > 500
    assert findings == [], "\n".join(f.render() for f in findings)


def test_the_real_wheel_contents_are_allowlisted(tmp_path):
    """Build the wheel the way the release job does and check every member."""
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation", "-q",
         "--disable-pip-version-check", "-w", str(tmp_path), str(ROOT)],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        pytest.fail("wheel build failed; install the pinned build dependencies from requirements-dev.txt")
    wheel = next(tmp_path.glob("*.whl"))
    findings, scanned = scanner.scan_artifact(wheel, {})
    assert scanned > 200
    assert findings == [], "\n".join(f.render() for f in findings)
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
    assert "sentinel/infrastructure/default_policy.json" in names, "the shipped ruleset is not in the wheel"


# ── Pins, lock, packaged data ────────────────────────────────────────────────


def _requirement_pins(text: str) -> dict[str, str]:
    pins = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip().rstrip("\\").strip()
        if "==" in line:
            name, version = line.split("==", 1)
            pins[name.strip().lower()] = version.strip()
    return pins


def test_the_server_extra_matches_requirements_txt():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["dependencies"] == [], "the base install is the SDK and must depend on nothing"
    server = _requirement_pins("\n".join(project["optional-dependencies"]["server"]))
    assert server == _requirement_pins((ROOT / "requirements.txt").read_text(encoding="utf-8"))


def test_the_lock_carries_every_pin_at_the_same_version_with_hashes():
    lock = (ROOT / "requirements.lock").read_text(encoding="utf-8")
    locked = _requirement_pins(lock)
    for name, version in _requirement_pins((ROOT / "requirements.txt").read_text(encoding="utf-8")).items():
        base = name.split("[", 1)[0]
        assert locked.get(base) == version, f"{name}=={version} is not locked at that version"
    entries = re.findall(r"^([a-z0-9_.\-]+)==", lock, flags=re.MULTILINE)
    hashed = re.findall(r"--hash=sha256:[0-9a-f]{64}", lock)
    assert len(entries) >= 20 and len(hashed) >= len(entries), "every locked package needs at least one hash"
    assert "--require-hashes" in (ROOT / "Dockerfile").read_text(encoding="utf-8")


def test_the_packaged_policy_is_the_checkout_policy():
    packaged = ROOT / "sentinel" / "infrastructure" / "default_policy.json"
    checkout = ROOT / "config" / "default_policy.json"
    assert packaged.read_bytes() == checkout.read_bytes(), (
        "config/default_policy.json and the packaged copy differ; a clean install would run a different ruleset"
    )
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert "infrastructure/default_policy.json" in project["tool"]["setuptools"]["package-data"]["sentinel"]


# ── The SDK stays thin ───────────────────────────────────────────────────────


def test_importing_the_sdk_loads_nothing_outside_the_standard_library():
    """Run in a subprocess with the tree on the path and every dev dependency
    installed: if the SDK imported fastapi, this would see it."""
    probe = f"import sys; sys.path.insert(0, {str(ROOT)!r})\n" + THIN_PROBE % (SDK_IMPORTS,)
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-c", probe], cwd=str(ROOT), capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr[-600:]
    line = next(ln for ln in result.stdout.splitlines() if ln.startswith("NONSTDLIB="))
    assert line == "NONSTDLIB=", f"the SDK import pulled in: {line}"


@pytest.mark.parametrize(
    "sdk_source, startup_extra, expected",
    [
        ("pass\n", "", "NONSTDLIB="),
        ("import third_party\n", "", "NONSTDLIB=third_party"),
        ("import third_party\n", "import third_party\n", "NONSTDLIB=third_party"),
        ("import sitecustomize\n", "", "NONSTDLIB=sitecustomize"),
        ("pass\n", "import third_party\n", "NONSTDLIB="),
        (
            "import importlib\nimportlib.import_module('third_party')\n",
            "import third_party\n", "NONSTDLIB=third_party",
        ),
    ],
    ids=(
        "startup-hook", "sdk-dependency", "preloaded-dependency", "sdk-imports-hook",
        "unused-preloaded-module", "preloaded-dynamic-dependency",
    ),
)
def test_thin_probe_distinguishes_startup_hooks_from_sdk_dependencies(
    tmp_path, sdk_source, startup_extra, expected,
):
    """A startup hook is not an SDK dependency; actual dependencies still fail."""
    (tmp_path / "sentinel.py").write_text(sdk_source, encoding="utf-8")
    (tmp_path / "sitecustomize.py").write_text("pass\n", encoding="utf-8")
    (tmp_path / "third_party.py").write_text("pass\n", encoding="utf-8")
    startup = (
        f"import sys\nsys.path.insert(0, {str(tmp_path)!r})\n"
        "sys.modules.pop('sitecustomize', None)\nimport sitecustomize\n"
        + startup_extra
    )
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-c", startup + THIN_PROBE % (("sentinel",),)],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    line = next(ln for ln in result.stdout.splitlines() if ln.startswith("NONSTDLIB="))
    assert line == expected


def test_advertised_console_assets_are_explicitly_allowlisted():
    for name in ("index.html", "app.js", "app.css"):
        assert scanner.check_wheel_member(f"sentinel/interface/console/{name}") == ""
    assert scanner.check_wheel_member("sentinel/interface/console/credentials.json")
