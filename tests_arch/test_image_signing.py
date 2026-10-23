"""Signing an image, and the two ways a signature check reads as a pass.

WHY THIS IS TESTED AT ALL
-------------------------
A signature verifier is the easiest thing in this repository to write wrongly
in a way that looks right. There are exactly two ways, and both produce a
green tick:

  1. `cosign verify` WITHOUT `--certificate-identity-regexp` and
     `--certificate-oidc-issuer` verifies that SOMEBODY signed the image. An
     attacker who signs their own image with their own identity passes it. This
     is the single most common keyless misconfiguration.
  2. Treating a missing cosign as a pass. "Could not check" and "checked and it
     was signed" are different facts and only one is a reason to deploy.

Both are asserted below, and the identity pattern's anchoring is asserted
separately because an unanchored pattern accepts a repository whose name merely
CONTAINS the expected one -- the same prefix-matching defect already fixed in
this codebase's path sandbox and delegation resource check.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest
import yaml

from scripts.verify_image_signature import (
    FAIL,
    GITHUB_OIDC_ISSUER,
    PASS,
    UNVERIFIED,
    _identity_pattern,
    verify,
)

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"

DIGEST = "ghcr.io/acme/sentinel@sha256:" + "a" * 64


class _Cosign:
    """A fake cosign that records its argv and returns a chosen code."""

    def __init__(self, returncode: int = 0, stderr: str = ""):
        self.returncode = returncode
        self.stderr = stderr
        self.argv: list[str] = []

    def __call__(self, command, **_kwargs):
        self.argv = list(command)
        return subprocess.CompletedProcess(
            command, self.returncode, stdout="{}", stderr=self.stderr
        )


@pytest.fixture
def with_cosign(monkeypatch):
    """Pretend cosign is installed, without installing it."""
    import scripts.verify_image_signature as module

    monkeypatch.setattr(module.shutil, "which", lambda _name: "/usr/bin/cosign")


# ── the identity must be pinned ────────────────────────────────────────────


def test_verification_pins_both_the_identity_and_the_issuer(with_cosign):
    """Without both, cosign verifies that SOMEBODY signed the image -- which
    passes for an attacker who signed their own, with a green tick.
    """
    cosign = _Cosign(returncode=0)

    result = verify(image=DIGEST, repository="acme/sentinel", runner=cosign)

    assert result.status == PASS
    assert "--certificate-identity-regexp" in cosign.argv
    assert "--certificate-oidc-issuer" in cosign.argv
    issuer = cosign.argv[cosign.argv.index("--certificate-oidc-issuer") + 1]
    assert issuer == GITHUB_OIDC_ISSUER


def test_the_identity_pattern_is_anchored_at_both_ends():
    """An unanchored pattern matches a repository whose name merely CONTAINS
    the expected one.
    """
    pattern = _identity_pattern("acme/sentinel")

    assert pattern.startswith("^")
    assert pattern.endswith("$")


def test_the_identity_pattern_rejects_a_lookalike_repository():
    """`evil/acme-sentinel-backdoor` must not satisfy `acme/sentinel`. The
    control below matters as much: a pattern that matched nothing would also
    pass this test.
    """
    pattern = re.compile(_identity_pattern("acme/sentinel"))

    legitimate = (
        "https://github.com/acme/sentinel/.github/workflows/"
        "ci.yml@refs/heads/main"
    )
    assert pattern.match(legitimate), "control: the real identity does not match"

    for impostor in (
        "https://github.com/evil/acme-sentinel-backdoor/.github/workflows/"
        "ci.yml@refs/heads/main",
        "https://github.com/acme/sentinel-fork/.github/workflows/"
        "ci.yml@refs/heads/main",
        "https://gitlab.com/acme/sentinel/.github/workflows/"
        "ci.yml@refs/heads/main",
    ):
        assert not pattern.match(impostor), impostor


def test_the_dot_in_github_com_is_escaped():
    """An unescaped dot matches any character, so `githubXcom` would satisfy
    it. Small, and it is the whole hostname check.
    """
    pattern = _identity_pattern("acme/sentinel")

    assert "github\\.com" in pattern


# ── a missing tool is UNVERIFIED, never a pass ─────────────────────────────


def test_a_missing_cosign_is_unverified_and_exits_non_zero(monkeypatch):
    import scripts.verify_image_signature as module

    monkeypatch.setattr(module.shutil, "which", lambda _name: None)

    result = verify(image=DIGEST, repository="acme/sentinel")

    assert result.status == UNVERIFIED
    assert result.status != PASS
    assert result.exit_code != 0
    assert "not a pass" in result.detail


def test_an_unrunnable_cosign_is_unverified(with_cosign):
    """No network to the registry or to Rekor is not a signature failure and
    is certainly not a success.
    """

    def explode(_command, **_kwargs):
        raise OSError("no route to host")

    result = verify(image=DIGEST, repository="acme/sentinel", runner=explode)

    assert result.status == UNVERIFIED
    assert "NOT checked" in result.detail


def test_only_pass_exits_zero():
    from scripts.verify_image_signature import Result

    assert Result(PASS, "x").exit_code == 0
    assert Result(FAIL, "x").exit_code != 0
    assert Result(UNVERIFIED, "x").exit_code != 0


# ── a tag is refused ───────────────────────────────────────────────────────


def test_a_tag_is_refused_before_cosign_is_even_consulted(with_cosign):
    """A tag can be repointed after review, so verifying one proves something
    about whatever it names right now. Refused early, so no network call is
    made for a reference that cannot mean anything.
    """
    cosign = _Cosign(returncode=0)

    result = verify(
        image="ghcr.io/acme/sentinel:latest",
        repository="acme/sentinel",
        runner=cosign,
    )

    assert result.status == FAIL
    assert cosign.argv == [], "cosign was called for a tag"


def test_a_refused_signature_is_a_failure_not_an_unverified(with_cosign):
    """The distinction matters: UNVERIFIED means nobody looked, FAIL means
    somebody looked and it was wrong.
    """
    cosign = _Cosign(returncode=1, stderr="no matching signatures")

    result = verify(image=DIGEST, repository="acme/sentinel", runner=cosign)

    assert result.status == FAIL
    assert "no matching signatures" in result.detail


# ── the CI job ─────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def test_the_signing_job_exists(workflow):
    assert "sign-image" in workflow["jobs"]


def test_the_signing_job_requests_an_oidc_token(workflow):
    """`id-token: write` IS the mechanism. Without it the job has no verifiable
    identity and keyless signing cannot work at all.
    """
    job = workflow["jobs"]["sign-image"]

    assert job["permissions"]["id-token"] == "write"
    assert job["permissions"]["packages"] == "write"
    # And nothing more than it needs.
    assert job["permissions"]["contents"] == "read"


def test_the_signing_job_is_opt_in(workflow):
    """Signing requires PUSHING, and pushing publishes. Merging this workflow
    must not start publishing images on its own.
    """
    job = workflow["jobs"]["sign-image"]
    condition = job["if"]

    assert "SENTINEL_PUBLISH_IMAGES" in condition
    assert "workflow_dispatch" in condition


def test_the_dispatch_input_defaults_to_not_publishing(workflow):
    # PyYAML parses the unquoted key `on` as the boolean True, which is the
    # YAML 1.1 behaviour GitHub Actions files trip over constantly.
    triggers = workflow.get("on") or workflow[True]
    inputs = triggers["workflow_dispatch"]["inputs"]

    assert inputs["publish_image"]["default"] is False


def test_the_job_signs_a_digest_and_never_a_tag(workflow):
    """Signing a tag signs whatever it names at that moment."""
    job = workflow["jobs"]["sign-image"]
    signing = [
        step for step in job["steps"]
        if "cosign sign" in str(step.get("run", ""))
    ]

    assert signing, "control: no cosign sign step found"
    for step in signing:
        assert "@${DIGEST}" in step["run"], step["run"]


def test_the_job_verifies_what_it_just_signed(workflow):
    """A signing step whose output nobody checks can silently produce an
    unverifiable signature, and the failure surfaces later to whoever is
    trying to deploy.
    """
    job = workflow["jobs"]["sign-image"]
    runs = " ".join(str(step.get("run", "")) for step in job["steps"])

    assert "verify_image_signature.py" in runs


def test_the_job_refuses_to_attach_a_missing_sbom(workflow):
    """An empty attestation is worse than none: it looks like an SBOM to
    anything that checks for the presence of one.
    """
    job = workflow["jobs"]["sign-image"]
    runs = " ".join(str(step.get("run", "")) for step in job["steps"])

    assert "NOT attaching an empty one" in runs


def test_the_job_builds_for_arm64(workflow):
    """The ecs Terraform module runs Fargate on ARM64, and a task definition
    claiming ARM64 with an amd64-only image fails with an exec format error
    that never mentions architecture.
    """
    job = workflow["jobs"]["sign-image"]
    build = [
        step for step in job["steps"]
        if "build-push-action" in str(step.get("uses", ""))
    ]

    assert build, "control: no build step found"
    assert "linux/arm64" in build[0]["with"]["platforms"]


def test_the_release_gate_no_longer_blames_a_missing_key():
    """`artifact_signing` was listed as needing "a signing key this runner does
    not hold". Keyless signing has no key, so that reason is now wrong -- and a
    stale reason in a gap list is how a closed gap stays recorded as open.
    """
    source = (ROOT / "scripts" / "run_release_gates.py").read_text(
        encoding="utf-8"
    )

    assert "needs a signing key this runner does not hold" not in source


def test_signed_sbom_is_the_artifact_produced_by_this_build(workflow):
    """Do not sign a checked-in dependency snapshot for a newly built image."""
    from pathlib import PurePosixPath
    import re

    producer = workflow["jobs"]["docker"]
    signer = workflow["jobs"]["sign-image"]
    assert "docker" in signer["needs"]
    uploads = [step["with"] for step in producer["steps"]
               if step.get("uses", "").startswith("actions/upload-artifact@")]
    steps = signer["steps"]
    attach_index = next(i for i, step in enumerate(steps)
                        if "cosign attest" in step.get("run", ""))
    predicate = re.search(r"--predicate\s+([^\s\\]+)",
                          steps[attach_index]["run"]).group(1)
    downloads = [step["with"] for step in steps[:attach_index]
                 if step.get("uses", "").startswith("actions/download-artifact@")]
    candidates = [(upload, download) for upload in uploads for download in downloads
                  if upload["name"] == download["name"]
                  and "run-id" not in download
                  and "repository" not in download
                  and str(PurePosixPath(download.get("path", ".")) /
                          PurePosixPath(upload["path"].strip()).name) == predicate]
    assert candidates, "the attested SBOM must come from this run's docker job"
    upload, _ = candidates[0]
    assert upload.get("if-no-files-found") == "error"
    filename = PurePosixPath(upload["path"].strip()).name
    assert any("cyclonedx-py requirements requirements.txt" in step.get("run", "")
               and "--output-file " + filename in step["run"]
               for step in producer["steps"]), "the artifact needs a current producer"
