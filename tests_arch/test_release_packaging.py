"""What ships is an allowlist, and the artifact itself gets scanned.

WHY THIS MATTERS HERE SPECIFICALLY
-----------------------------------
This repository contains a real `.env` holding live AWS credentials. Until
`scripts/build_release_artifact.py` existed there was no packaging step at all,
which is safer than a bad one and means the first person to zip the working
directory would have shipped those keys.

TWO DEFECTS THIS FILE ENCODES
------------------------------
Both were made while writing the packager, and both are the kind that passes
review:

1. The first denylist refused `tests_arch/fixtures/strace_*.log` and
   `.terraform.lock.hcl`. The strace logs are real captured output and the only
   evidence the tracer works against reality; the lock file is a version pin
   that should ship. A crude suffix rule produces refusals an operator cannot
   act on, and those get switched off wholesale.

2. The first verification searched the zip's RAW BYTES for `AKIA`. The zip is
   DEFLATE-compressed, so the search could never match anything and reported a
   confident, meaningless pass. `test_the_leak_search_finds_a_control_string`
   exists so that class of check cannot recur silently: if the control is not
   found, the search is broken and every "absent" result below it is worthless.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from scripts.build_release_artifact import (
    INCLUDE,
    PRUNED_DIRS,
    REFUSED_NAMES,
    REFUSED_SUFFIXES,
    _collect,
    _is_refused,
    _scan_artifact,
    _write_zip,
)

ROOT = Path(__file__).resolve().parent.parent


def _tree(base: Path, files: dict[str, str]) -> Path:
    for relative, content in files.items():
        path = base / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return base


# ── the allowlist decides, and absence is the default ───────────────────────


def test_a_file_outside_the_allowlist_does_not_ship(tmp_path):
    """The property an exclude list cannot have: a file nobody thought about is
    absent by default rather than present by default.
    """
    _tree(tmp_path, {
        "sentinel/thing.py": "x = 1",
        "surprise_new_directory/leaked.txt": "whatever",
    })

    selected, refusals = _collect(tmp_path)
    shipped = {str(p.relative_to(tmp_path)).replace("\\", "/") for p in selected}

    assert "sentinel/thing.py" in shipped, "control: the allowlist found nothing"
    assert not any("surprise" in name for name in shipped)
    assert refusals == []


def test_a_dotenv_inside_an_allowlisted_directory_is_refused(tmp_path):
    """The case the denylist exists for. `docs/` is allowlisted as a directory,
    so it carries whatever ends up inside it.
    """
    _tree(tmp_path, {
        "docs/README.md": "fine",
        "docs/.env": "AWS_SECRET_ACCESS_KEY=real",
    })

    selected, refusals = _collect(tmp_path)
    shipped = {p.name for p in selected}

    assert "README.md" in shipped, "control: nothing was collected at all"
    assert ".env" not in shipped
    assert any(".env" in r for r in refusals)


def test_a_refused_file_is_reported_and_not_silently_dropped(tmp_path):
    """A packager that quietly skips files produces artifacts that differ from
    the tree for reasons nobody can reconstruct.
    """
    _tree(tmp_path, {"sentinel/a.py": "x", "sentinel/id_rsa": "KEY"})

    _, refusals = _collect(tmp_path)

    assert len(refusals) == 1
    assert "id_rsa" in refusals[0]


def test_every_refusal_explains_itself(tmp_path):
    _tree(tmp_path, {"sentinel/local.db": "", "sentinel/a.pem": ""})

    _, refusals = _collect(tmp_path)

    assert len(refusals) == 2
    for refusal in refusals:
        assert ":" in refusal and len(refusal.split(":", 1)[1].strip()) > 10


# ── the two false positives, as regressions ────────────────────────────────


def test_captured_strace_fixtures_still_ship():
    """`.log` was refused by the first version of the denylist. These files are
    real captured strace output, and the tests that parse them are the only
    evidence the tracer works against reality -- so refusing them would have
    shipped an artifact whose suite could not run.
    """
    fixtures = sorted((ROOT / "tests_arch" / "fixtures").glob("strace*.log"))

    assert fixtures, "control: the fixtures this test is about have moved"
    for fixture in fixtures:
        assert _is_refused(fixture) == "", fixture.name


def test_a_terraform_lock_file_still_ships():
    """Also refused by the first version, on the grounds that it looked
    credential-shaped. It is a provider VERSION LOCK -- the terraform
    equivalent of requirements.txt. The provider CACHE beside it, `.terraform/`,
    is what should be excluded, and PRUNED_DIRS handles that.
    """
    assert _is_refused(Path("deploy/x/.terraform.lock.hcl")) == ""
    assert ".terraform" in PRUNED_DIRS


def test_the_provider_cache_is_pruned(tmp_path):
    _tree(tmp_path, {
        "deploy/main.tf": "terraform {}",
        "deploy/.terraform/providers/registry/blob.bin": "cache",
    })

    selected, _ = _collect(tmp_path)
    shipped = {str(p.relative_to(tmp_path)).replace("\\", "/") for p in selected}

    assert "deploy/main.tf" in shipped, "control: nothing collected"
    assert not any(".terraform/" in name for name in shipped)


@pytest.mark.parametrize("name", ["data", "__pycache__", ".git", ".pytest_cache"])
def test_local_state_directories_are_pruned(tmp_path, name):
    _tree(tmp_path, {
        "sentinel/real.py": "x = 1",
        f"sentinel/{name}/junk.txt": "local",
    })

    selected, _ = _collect(tmp_path)
    shipped = {str(p.relative_to(tmp_path)).replace("\\", "/") for p in selected}

    assert "sentinel/real.py" in shipped, "control: nothing collected"
    assert not any(f"/{name}/" in name_ for name_ in shipped)


# ── the archive is reproducible ─────────────────────────────────────────────


def test_the_same_inputs_produce_byte_identical_archives(tmp_path):
    """A zip whose bytes change between two builds of the same commit cannot be
    checksummed usefully: anyone comparing two artifacts would see a difference
    that is not one.
    """
    source = _tree(tmp_path / "src", {"sentinel/a.py": "x = 1", "docs/b.md": "hi"})
    selected, _ = _collect(source)

    first, second = tmp_path / "one.zip", tmp_path / "two.zip"
    _write_zip(selected, root=source, destination=first)
    _write_zip(selected, root=source, destination=second)

    assert first.read_bytes() == second.read_bytes()


def test_archive_paths_use_forward_slashes(tmp_path):
    """Built on Windows, extracted on Linux. Backslash entries extract as files
    with a backslash in the name rather than as a directory tree.
    """
    source = _tree(tmp_path / "src", {"sentinel/sub/a.py": "x"})
    selected, _ = _collect(source)
    archive = tmp_path / "out.zip"
    _write_zip(selected, root=source, destination=archive)

    names = zipfile.ZipFile(archive).namelist()

    assert names == ["sentinel/sub/a.py"]


# ── a missing scanner is UNVERIFIED, never a pass ──────────────────────────


def test_a_missing_gitleaks_is_unverified_and_not_a_pass(tmp_path, monkeypatch):
    """"Could not check" and "checked and clean" are different facts and only
    one is a reason to ship. Reporting the first as the second is the specific
    dishonesty the release rules forbid.
    """
    import scripts.build_release_artifact as packager

    archive = tmp_path / "empty.zip"
    _write_zip([], root=tmp_path, destination=archive)
    monkeypatch.setattr(packager.shutil, "which", lambda _name: None)

    status, detail = packager._scan_artifact(archive)

    assert status == "UNVERIFIED"
    assert status != "PASS"
    assert "not a pass" in detail


def _canary() -> tuple[str, str]:
    """A realistic-looking AWS credential, DERIVED rather than written down.

    Three constraints collide here and only derivation satisfies all of them:

      * It must look real enough for gitleaks to flag it. The obvious canary,
        the AKIAIOSFODNN7EXAMPLE from AWS's own documentation, is deliberately
        ALLOWLISTED -- the first version of this test used it, gitleaks
        reported "no leaks found", and the test concluded the scanner was
        broken when the canary was. Verified against gitleaks 8.30.1 with and
        without this repository's config.
      * It must not appear as a literal in this file, or the repository's own
        gitleaks gate flags the test that proves the scanner works.
      * Splitting it into fragments was not enough. `generic-api-key` fired on
        a 16-character fragment assigned to a name containing "SECRET" -- the
        rule reads the variable name as much as the value.

    So there is no high-entropy string in this source at all. It is generated
    from a fixed seed, which also makes it stable across runs: a canary that
    changed every run would make a failure impossible to reproduce.
    """
    import hashlib
    import string

    stream = hashlib.sha256(b"sentinel.packaging.canary.v1").hexdigest()
    upper = string.ascii_uppercase + string.digits
    mixed = string.ascii_letters + string.digits

    identifier = "AKIA" + "".join(
        upper[int(stream[i : i + 2], 16) % len(upper)] for i in range(0, 32, 2)
    )
    tail = hashlib.sha256(b"sentinel.packaging.canary.v1.tail").hexdigest()
    material = "".join(
        mixed[int((stream + tail)[i : i + 2], 16) % len(mixed)]
        for i in range(0, 80, 2)
    )
    return identifier, material


def test_the_real_scanner_reports_a_planted_secret(tmp_path):
    """The scan is only evidence if it can fail.

    Skips rather than passes when gitleaks is absent: a silent pass would leave
    the mechanism untested on exactly the machines that cannot run it.
    """
    import shutil as real_shutil

    if real_shutil.which("gitleaks") is None:
        pytest.skip("gitleaks not installed; reported rather than passed silently")

    identifier, material = _canary()
    planted = tmp_path / "planted"
    planted.mkdir()
    (planted / "creds.py").write_text(
        f'aws_access_key_id = "{identifier}"\n'
        f'aws_secret_access_key = "{material}"\n',
        encoding="utf-8",
    )
    archive = tmp_path / "planted.zip"
    _write_zip(sorted(planted.rglob("*")), root=tmp_path, destination=archive)

    status, detail = _scan_artifact(archive)

    assert status == "FAIL", (
        "the scanner did not notice a planted AWS credential, so the PASS it "
        f"reports for real artifacts means nothing. Detail: {detail}"
    )


def test_the_scan_failure_does_not_echo_the_secret(tmp_path):
    """`--redact` is passed for a reason: an operator pasting this output into
    an issue must not be pasting the credential with it.
    """
    import shutil as real_shutil

    if real_shutil.which("gitleaks") is None:
        pytest.skip("gitleaks not installed; reported rather than passed silently")

    identifier, material = _canary()
    planted = tmp_path / "planted"
    planted.mkdir()
    (planted / "creds.py").write_text(
        f'aws_secret_access_key = "{material}"\n', encoding="utf-8"
    )
    archive = tmp_path / "planted.zip"
    _write_zip(sorted(planted.rglob("*")), root=tmp_path, destination=archive)

    status, detail = _scan_artifact(archive)

    assert status == "FAIL", "control: nothing detected, so nothing to redact"
    assert material not in detail


# ── the live .env, checked by value ────────────────────────────────────────


def test_the_leak_search_finds_a_control_string():
    """Guards the search, not the artifact.

    The first version of this verification searched the zip's RAW BYTES. The
    archive is DEFLATE-compressed, so it could never match and reported a
    confident pass. Any "the secret is absent" result is worthless unless a
    string known to be PRESENT is found by the same method.
    """
    source = ROOT / "scripts" / "publish_transparency_root.py"

    assert source.exists()
    assert b"SENTINEL_S3_ROOT_BUCKET" in source.read_bytes()


def test_no_allowlisted_file_contains_the_live_aws_credentials():
    """Compares against the ACTUAL values in `.env`, not a pattern resembling
    them. A regex for `AKIA...` proves the shape is absent; this proves the
    specific credential is.

    Reads the collection rather than a built archive so it runs without
    invoking the packager, and skips honestly when there is no `.env` to leak.
    """
    env_path = ROOT / ".env"
    if not env_path.exists():
        pytest.skip("no .env in this checkout, so there is nothing to leak")

    secrets: dict[str, bytes] = {}
    for line in env_path.read_text(encoding="utf-8").splitlines():
        name, _, value = line.partition("=")
        if name.strip() in {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"}:
            if value.strip():
                secrets[name.strip()] = value.strip().encode()
    if not secrets:
        pytest.skip(".env holds no AWS credentials in this checkout")

    selected, refusals = _collect(ROOT)

    assert selected, "control: the allowlist collected nothing"
    assert env_path not in selected
    leaked = [
        (path.relative_to(ROOT), name)
        for path in selected
        for name, value in secrets.items()
        if value in path.read_bytes()
    ]
    assert leaked == [], f"live credentials would ship in: {leaked}"


# ── the rules themselves stay coherent ─────────────────────────────────────


def test_dotenv_is_refused_by_prefix_and_not_only_by_exact_name():
    """`.env.pilot` is not in REFUSED_NAMES and must still be refused. An exact
    list of dotenv spellings is a list somebody will extend one short.
    """
    for name in (".env", ".env.local", ".env.pilot", ".env.whatever"):
        assert _is_refused(Path(f"docs/{name}")) != ""


def test_the_allowlist_and_denylist_do_not_contradict_each_other():
    """A top-level allowlist entry that is itself refused would make the
    packager unable to ever ship it, which would be a silent hole.
    """
    for entry in INCLUDE:
        assert _is_refused(Path(entry)) == "", entry


def test_no_refusal_rule_is_empty():
    """An empty string in either set matches nothing or everything depending on
    the comparison, and both are bad.
    """
    for rule in REFUSED_NAMES | REFUSED_SUFFIXES | PRUNED_DIRS:
        assert rule.strip()
