"""Verify that a container image was signed by this repository's CI.

WHY KEYLESS, AND WHY THAT CHANGES THE OLD ANSWER
------------------------------------------------
`run_release_gates.py` lists `artifact_signing` under NO_RUNNER with the
reason "needs a signing key this runner does not hold". That was true of
key-based signing and is not true of keyless: with Sigstore there IS no key.
CI proves its identity with a GitHub OIDC token, the signature is recorded in
the public Rekor transparency log, and verification checks the OIDC ISSUER and
the SUBJECT rather than a public key somebody has to distribute and rotate.

So the objection to signing was a key-management objection, and it has gone
away. What remains is that a LOCAL runner has no OIDC identity and no registry,
which is a different and narrower statement -- recorded as such rather than
left as the old one.

WHAT A SIGNATURE HERE ACTUALLY CLAIMS
-------------------------------------
That a specific image DIGEST was signed by a workflow in a named repository on
a named ref. Not that the image is good, not that the code is correct -- only
that this artifact came out of that pipeline and has not been swapped since.

That is the gap it closes. Without it, an image can be replaced between build
and deploy and nothing downstream would know: the tag still resolves, the
deployment still starts, and the only record of what was reviewed is a tag
that now points somewhere else. It is why the ecs Terraform module refuses an
image reference that is not pinned by digest.

VERIFICATION IS BY IDENTITY, NOT BY KEY
---------------------------------------
`--certificate-identity-regexp` and `--certificate-oidc-issuer` are both
REQUIRED here. Cosign will happily verify that *somebody* signed an image; a
verification that does not pin who is a verification that passes for any
signer, including an attacker who signed their own image with their own
identity. That is the single most common way keyless verification is
misconfigured, and it produces a green tick.

MISSING TOOLS YIELD UNVERIFIED
------------------------------
No cosign, no network, no image: status is UNVERIFIED and the exit code is
non-zero. Never PASS. "Could not check" and "checked and it was signed" are
different facts and only one is a reason to deploy.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#: GitHub's OIDC issuer. Pinned rather than accepted from the certificate,
#: because the issuer is half of what identifies the signer.
GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"

PASS, FAIL, UNVERIFIED = "PASS", "FAIL", "UNVERIFIED"


@dataclass(frozen=True)
class Result:
    status: str
    detail: str

    @property
    def exit_code(self) -> int:
        # UNVERIFIED is non-zero. A caller that treats "could not check" as
        # success is the failure this whole module is arranged around.
        return 0 if self.status == PASS else 1


def _identity_pattern(repository: str) -> str:
    """The workflow identity permitted to have signed this image.

    Anchored at both ends. An unanchored pattern matches a repository whose
    name merely CONTAINS the expected one -- `evil/acme-sentinel-backdoor`
    against `acme/sentinel` -- which is the same prefix-matching defect this
    codebase has already fixed in a path sandbox and a delegation resource
    check.
    """
    return f"^https://github\\.com/{repository}/\\.github/workflows/.+@refs/.+$"


def verify(
    *,
    image: str,
    repository: str,
    runner=subprocess.run,
) -> Result:
    """Check the image's signature. Never returns PASS on a missing tool."""
    if "@sha256:" not in image:
        return Result(
            FAIL,
            f"{image} is not pinned by digest. A tag can be repointed after "
            "the image was reviewed, so verifying a tag proves something about "
            "whatever it happens to name right now.",
        )

    if shutil.which("cosign") is None:
        return Result(
            UNVERIFIED,
            "cosign is not installed, so the signature was NOT checked. This "
            "is not a pass: install cosign (https://docs.sigstore.dev) and "
            "re-run before deploying this image.",
        )

    command = [
        "cosign", "verify",
        # BOTH of these are required. Cosign without them verifies that
        # SOMEBODY signed the image, which passes for an attacker who signed
        # their own -- and it produces a green tick while doing so.
        "--certificate-identity-regexp", _identity_pattern(repository),
        "--certificate-oidc-issuer", GITHUB_OIDC_ISSUER,
        "--output", "json",
        image,
    ]

    try:
        completed = runner(command, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as error:
        return Result(
            UNVERIFIED,
            f"cosign could not be run ({error.__class__.__name__}), so the "
            "signature was NOT checked. Verification needs network access to "
            "the registry and to the Rekor transparency log.",
        )

    if completed.returncode == 0:
        return Result(
            PASS,
            f"signed by a workflow in {repository}, verified against "
            f"{GITHUB_OIDC_ISSUER} and the Rekor log",
        )

    stderr = (completed.stderr or "").strip()
    return Result(
        FAIL,
        f"cosign refused the signature: {stderr[:400] or 'no detail returned'}",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify a container image was signed by this repo's CI."
    )
    parser.add_argument(
        "image",
        help="Image reference PINNED BY DIGEST, e.g. ghcr.io/o/r@sha256:...",
    )
    parser.add_argument(
        "--repository",
        required=True,
        help="owner/name whose workflows are permitted to have signed it",
    )
    parser.add_argument(
        "--evidence",
        type=Path,
        default=None,
        help="Write the result as JSON here, for the release bundle.",
    )
    args = parser.parse_args(argv)

    result = verify(image=args.image, repository=args.repository)

    print(f"{result.status}  {args.image}")
    print(f"  {result.detail}")

    if args.evidence is not None:
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(
            json.dumps(
                {
                    "schema": "sentinel.image_signature.v1",
                    "image": args.image,
                    "repository": args.repository,
                    "oidc_issuer": GITHUB_OIDC_ISSUER,
                    "status": result.status,
                    "detail": result.detail,
                    "checked_at": datetime.now(timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    ),
                    "note": (
                        "A signature proves this DIGEST came out of that "
                        "pipeline and has not been swapped since. It does not "
                        "claim the image is good or the code correct."
                    ),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
