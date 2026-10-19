#!/usr/bin/env python3
"""Build the release manifest that gets signed.

    §12  SBOM / build provenance / artifact signing / image digest /
         release manifest.
         Every released container should be traceable to source commit,
         dependencies, build pipeline, test evidence, signature.

WHY A MANIFEST AND NOT JUST A SIGNATURE ON THE IMAGE
------------------------------------------------------
Signing a container image proves the image came from this pipeline. It proves
nothing about the SBOM, the test evidence or the readiness bundle, and those are
the artifacts a customer's security team will actually read.

So the signed object is a MANIFEST: one document that names every released
artifact and its SHA-256. Signing that binds them together — an attacker
swapping the SBOM for a cleaner one has to break the signature, not just replace
a file. The image digest is one entry in it rather than the whole story.

WHAT IS SIGNED WHERE
----------------------
This script produces the manifest and nothing else. It does NOT sign, because
signing needs an OIDC identity that exists only inside the CI run, and a script
that silently produced an unsigned manifest when run locally would be the exact
"looks done, isn't" failure this repository keeps finding.

    this script (anywhere)   ->  manifest.json, with real hashes
    CI, with id-token        ->  cosign sign-blob + SLSA attestation

The manifest carries NO self-reported `signed` boolean. It once did, and CI
flipped it after signing -- which changed the signed bytes and made verification
fail outright. Beyond the bug, the field was circular: a document cannot
credibly attest to its own signedness. The detached signature is the evidence,
and `build_release_evidence.py` resolves the signing gate from `manifest.sig`
rather than from anything the manifest says about itself.

ON HASHING WHAT IS ABSENT
---------------------------
An artifact that was expected and is missing is recorded with `"sha256": null`
and a reason, not skipped. A manifest that silently omits what it could not find
would let a build with no SBOM produce a manifest that looks complete.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

#: Artifacts a release is expected to carry, and where they are looked for.
#:
#: Named explicitly rather than globbed: a glob would quietly produce a smaller
#: manifest when a job failed to emit its artifact, and "smaller" is precisely
#: the case that must be visible.
EXPECTED_ARTIFACTS: tuple[tuple[str, str], ...] = (
    ("sbom", "sbom.json"),
    ("licenses", "licenses.json"),
    ("detection_metrics", "metrics.json"),
    ("readiness", "readiness.json"),
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(*args: str) -> str:
    try:
        return subprocess.run(
            ["git", *args], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout.strip()
    except Exception:  # noqa: BLE001 - a source tarball has no git
        return ""


def _find(name: str, search: list[Path]) -> Path | None:
    """Locate an artifact by filename anywhere under the search roots.

    CI's `download-artifact` nests each job's output in its own directory, so a
    flat lookup would miss everything. Searching is what makes this work against
    a real artifact tree rather than only against a tidy local one.
    """
    for root in search:
        if not root.exists():
            continue
        if (root / name).is_file():
            return root / name
        for found in root.rglob(name):
            if found.is_file():
                return found
    return None


def build_manifest(*, artifacts: Path, image_digest: str = "") -> dict[str, Any]:
    search = [artifacts, ROOT / "release", ROOT / "evaluation"]
    entries: list[dict[str, Any]] = []

    for label, filename in EXPECTED_ARTIFACTS:
        found = _find(filename, search)
        if found is None:
            entries.append(
                {
                    "artifact": label,
                    "filename": filename,
                    "sha256": None,
                    "status": "MISSING",
                    "detail": "no such artifact was produced by this build",
                }
            )
            continue
        entries.append(
            {
                "artifact": label,
                "filename": filename,
                "sha256": _sha256(found),
                "status": "PRESENT",
                "size_bytes": found.stat().st_size,
            }
        )

    present = sum(1 for e in entries if e["status"] == "PRESENT")
    return {
        "schema": "sentinel.release.manifest/v1",
        "commit": _git("rev-parse", "HEAD") or "UNKNOWN",
        "version": _git("describe", "--tags", "--always") or "UNKNOWN",
        "build_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "workflow": os.environ.get("GITHUB_WORKFLOW", "local"),
        "repository": os.environ.get("GITHUB_REPOSITORY", "local"),
        "built_at": datetime.now(timezone.utc).isoformat(),
        # Empty locally: there is no image until the container job builds one.
        "image_digest": image_digest or "",
        "artifacts": entries,
        "artifacts_present": present,
        "artifacts_expected": len(EXPECTED_ARTIFACTS),
        # NO `signed` FIELD, DELIBERATELY.
        #
        # An earlier version carried `"signed": false` and had CI flip it to
        # true after signing. That broke the signature: cosign signs the exact
        # bytes, and editing the file afterwards made `verify-blob` fail with
        # "invalid signature when validating ASN.1 encoded signature". The
        # verification step caught it, which is the reason that step exists --
        # without it the build would have published a signature that did not
        # match its own artifact, which is worse than publishing none.
        #
        # It was also circular. A document asserting its own signedness proves
        # nothing: anyone can write `"signed": true`. The DETACHED SIGNATURE is
        # the evidence, and its absence is the absence of evidence.
        "signature": {
            "detached_signature": "manifest.sig",
            "certificate": "manifest.pem",
            "scheme": "sigstore keyless (cosign sign-blob)",
            "how_to_verify": (
                "cosign verify-blob --certificate manifest.pem "
                "--signature manifest.sig "
                "--certificate-identity-regexp 'https://github.com/<org>/<repo>/.*' "
                "--certificate-oidc-issuer https://token.actions.githubusercontent.com "
                "manifest.json"
            ),
            "note": (
                "This manifest makes no claim about whether it was signed. "
                "Verify the detached signature; a missing or invalid one means "
                "the artifacts are NOT attested, not that attestation was waived."
            ),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", default="artifacts")
    parser.add_argument("--out", default="release/manifest.json")
    parser.add_argument("--image-digest", default="")
    parser.add_argument(
        "--require-all",
        action="store_true",
        help="exit non-zero if any expected artifact is missing",
    )
    args = parser.parse_args(argv)

    manifest = build_manifest(
        artifacts=Path(args.artifacts), image_digest=args.image_digest
    )
    out = ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    sys.stdout.write(
        f"manifest: {manifest['artifacts_present']}/{manifest['artifacts_expected']} "
        f"artifacts present\n"
        f"written to {out} (unsigned; CI applies a detached signature)\n"
    )
    for entry in manifest["artifacts"]:
        mark = "ok " if entry["status"] == "PRESENT" else "MISSING"
        sys.stdout.write(f"  {mark} {entry['artifact']}\n")

    if args.require_all and manifest["artifacts_present"] != manifest["artifacts_expected"]:
        sys.stderr.write("refusing: expected artifacts are missing\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
